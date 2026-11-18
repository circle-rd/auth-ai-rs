//! The sign-in, sign-out and session routes.

use std::sync::Arc;

use serde::Deserialize;
use serde_json::json;
use url::Url;

use crate::error::{AuthAiError, ErrorCode, Result};
use crate::messages::{WebRequest, WebResponse, json_response, redirect_response};
use crate::server::BackchannelLogoutHandler;
use crate::session_user::to_session_user;
use crate::types::{LoginHandshake, Prompt};
use crate::util::random_token;
use crate::web::cookies::{clear_cookie, parse_cookies, serialize_cookie};
use crate::web::handlers::{AuthHandlers, HANDSHAKE_TTL_SECONDS, query_of};
use crate::web::http::{error_response, is_cross_site, safe_redirect_path};
use crate::web::seal::{seal, unseal};

/// What the sealed login cookie carries: the wire names are shared with the TypeScript SDK.
#[derive(Deserialize)]
struct HandshakeCookie {
    state: String,
    nonce: String,
    #[serde(rename = "codeVerifier")]
    code_verifier: String,
    next: String,
}

/// Sealed at sign-out: the state sent to the OP and the page to return to.
#[derive(Deserialize)]
struct LogoutCookie {
    next: String,
}

fn set_cookies(cookies: Vec<String>) -> Vec<(String, String)> {
    cookies
        .into_iter()
        .map(|cookie| ("set-cookie".to_owned(), cookie))
        .collect()
}

impl AuthHandlers {
    pub(super) async fn login(&self, request: &WebRequest) -> Result<WebResponse> {
        let inner = &self.inner;
        let query = query_of(request)?;
        let prompt = query
            .get("prompt")
            .and_then(|value| Prompt::from_wire(value));
        let login = inner.auth.start_login(prompt, None).await?;
        let handshake = &login.handshake;
        let sealed = seal(
            &inner.key,
            &json!({
                "state": handshake.state.expose_secret(),
                "nonce": handshake.nonce.expose_secret(),
                "codeVerifier": handshake.code_verifier.expose_secret(),
                "next": safe_redirect_path(query.get("next").map(String::as_str), &inner.default_redirect),
            }),
            HANDSHAKE_TTL_SECONDS,
        )?;
        let cookie = serialize_cookie(
            &inner.login_cookie,
            &sealed,
            HANDSHAKE_TTL_SECONDS,
            inner.secure,
        )?;
        Ok(redirect_response(
            &login.url,
            302,
            set_cookies(vec![cookie]),
        ))
    }

    async fn complete_callback(&self, request: &WebRequest) -> Result<(String, String)> {
        let inner = &self.inner;
        let cookies = parse_cookies(request.header("cookie"));
        let sealed = cookies
            .get(&inner.login_cookie)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AuthAiError::new(ErrorCode::Ses002))?;
        let cookie: HandshakeCookie = unseal(&inner.key, sealed)?;
        let handshake = LoginHandshake {
            state: cookie.state.into(),
            nonce: cookie.nonce.into(),
            code_verifier: cookie.code_verifier.into(),
        };

        // Rebuilt on the registered URI: the request's own host is not trusted.
        let incoming = Url::parse(&request.url).map_err(|err| {
            AuthAiError::new(ErrorCode::Req001)
                .with_message("The request URL is not absolute")
                .with_source(err)
        })?;
        let mut callback_url = Url::parse(inner.auth.config().redirect_uri()).map_err(|err| {
            AuthAiError::new(ErrorCode::Cfg001)
                .with_message("Invalid redirect_uri")
                .with_source(err)
        })?;
        callback_url.set_query(incoming.query());
        callback_url.set_fragment(None);
        let result = inner
            .auth
            .handle_callback(callback_url.as_str(), &handshake)
            .await?;

        if inner.require_provider_session && result.session_id.is_none() {
            return Err(AuthAiError::new(ErrorCode::Ses003).with_message(
                "The ID token carries no sid: enable end session or a back-channel logout URI on the application",
            ));
        }
        let refresh_token = result.tokens.refresh_token.as_ref();
        if let Some(refresh_token) = refresh_token {
            inner.grants.save(&result.claims.sub, refresh_token).await?;
        }
        let (_, session_cookie) = self
            .create_session(&result.claims, result.id_token()?, refresh_token.is_some())
            .await?;
        Ok((cookie.next, session_cookie))
    }

    pub(super) async fn callback(&self, request: &WebRequest) -> WebResponse {
        let inner = &self.inner;
        let clear = match clear_cookie(&inner.login_cookie, inner.secure) {
            Ok(clear) => clear,
            Err(err) => return error_response(&err, self.on_error(), Vec::new()),
        };
        let outcome = async {
            let (next, session_cookie) = self.complete_callback(request).await?;
            let session = serialize_cookie(
                &inner.session_cookie,
                &session_cookie,
                inner.session_ttl,
                inner.secure,
            )?;
            Ok::<_, AuthAiError>(redirect_response(
                &next,
                303,
                set_cookies(vec![clear.clone(), session]),
            ))
        }
        .await;
        match outcome {
            Ok(response) => response,
            Err(err) => {
                // Whatever failed (state, code, client credentials, claims), the browser learns
                // one thing: the sign-in failed. Telling a rejected client secret from a forged
                // state would help whoever probes the callback; the cause reaches the logs.
                self.report(&err);
                let failure = AuthAiError::new(ErrorCode::Ses005).with_source(err);
                match &inner.error_redirect {
                    Some(target) => redirect_response(
                        &format!("{target}?error={}", failure.code()),
                        303,
                        set_cookies(vec![clear]),
                    ),
                    None => error_response(&failure, None, set_cookies(vec![clear])),
                }
            }
        }
    }

    pub(super) async fn me(&self, request: &WebRequest) -> Result<WebResponse> {
        let session = self.require_session(request).await?;
        Ok(json_response(
            &json!({ "user": to_session_user(&session.claims).to_json(), "expiresAt": session.expires_at }),
            200,
            Vec::new(),
        ))
    }

    pub(super) async fn logout(&self, request: &WebRequest) -> Result<WebResponse> {
        let inner = &self.inner;
        if is_cross_site(request, &inner.origin) {
            return Err(AuthAiError::new(ErrorCode::Ses004));
        }
        let session = self.read_session(request).await?;
        let query = query_of(request)?;
        let state = random_token(32)?;
        let next_path = safe_redirect_path(
            query.get("next").map(String::as_str),
            &inner.default_redirect,
        );
        let logout_cookie = serialize_cookie(
            &inner.logout_cookie,
            &seal(
                &inner.key,
                &json!({ "state": state, "next": next_path }),
                HANDSHAKE_TTL_SECONDS,
            )?,
            HANDSHAKE_TTL_SECONDS,
            inner.secure,
        )?;
        // The SSO session is shared by every application: end it even without a local session.
        let hint = session
            .as_ref()
            .map(|session| session.id_token.expose_secret().to_owned());
        let logout_url = match inner.auth.logout_url(hint.as_deref(), Some(&state)).await {
            Ok(url) => Some(url),
            Err(err) => {
                // A provider without end-session still lets the local session end.
                self.report(&err);
                None
            }
        };
        if let Some(session) = session {
            self.end_sessions(&[session]).await?;
        }
        let headers = set_cookies(vec![
            clear_cookie(&inner.session_cookie, inner.secure)?,
            logout_cookie,
        ]);
        if request
            .header("accept")
            .unwrap_or_default()
            .contains("application/json")
        {
            return Ok(json_response(
                &json!({ "logoutUrl": logout_url }),
                200,
                headers,
            ));
        }
        Ok(redirect_response(
            logout_url.as_deref().unwrap_or(&next_path),
            303,
            headers,
        ))
    }

    /// Handles the OP's post-logout redirect.
    ///
    /// The signed local session is already gone; the sealed cookie only carries
    /// the destination and the state hint. A missing or different state must not
    /// strand the user after the provider has ended the session, so the redirect
    /// still succeeds.
    pub(super) fn logout_callback(&self, request: &WebRequest) -> Result<WebResponse> {
        let inner = &self.inner;
        let cookies = parse_cookies(request.header("cookie"));
        let target = cookies
            .get(&inner.logout_cookie)
            .filter(|sealed| !sealed.is_empty())
            .and_then(|sealed| unseal::<LogoutCookie>(&inner.key, sealed).ok())
            .map_or_else(
                || inner.default_redirect.clone(),
                |cookie| safe_redirect_path(Some(&cookie.next), &inner.default_redirect),
            );
        Ok(redirect_response(
            &target,
            303,
            set_cookies(vec![clear_cookie(&inner.logout_cookie, inner.secure)?]),
        ))
    }

    pub(super) async fn backchannel_logout(&self, request: &WebRequest) -> WebResponse {
        let inner = &self.inner;
        let me = self.clone();
        let mut handler = BackchannelLogoutHandler::new(
            inner.auth.clone(),
            Arc::new(move |event| {
                let me = me.clone();
                Box::pin(async move { me.on_backchannel_logout(event).await })
            }),
        )
        .replay_store(Arc::clone(&inner.replay_store))
        .allow_missing_typ(inner.allow_missing_logout_token_typ);
        if let Some(callback) = &inner.on_error {
            handler = handler.on_error(Arc::clone(callback));
        }
        handler.handle(request).await
    }
}
