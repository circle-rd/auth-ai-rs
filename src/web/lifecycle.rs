//! Reading, renewing and ending sessions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::claims::IdTokenClaims;
use crate::error::{AuthAiError, ErrorCode, Result};
use crate::messages::WebRequest;
use crate::secret::SecretString;
use crate::server::BackchannelLogoutEvent;
use crate::util::{now_unix, random_token, sha256_b64url};
use crate::web::cookies::parse_cookies;
use crate::web::handlers::AuthHandlers;
use crate::web::sessions::Session;

type GateMap = Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>;

fn locked(map: &GateMap) -> MutexGuard<'_, HashMap<String, Arc<tokio::sync::Mutex<()>>>> {
    map.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Drops the renewal gate of a session once nobody else waits on it, even when
/// the request is cancelled half-way.
struct GateCleanup<'a> {
    gates: &'a GateMap,
    session_id: &'a str,
    gate: Arc<tokio::sync::Mutex<()>>,
}

impl Drop for GateCleanup<'_> {
    fn drop(&mut self) {
        let mut gates = locked(self.gates);
        // The map and this guard hold the only references when nobody waits.
        if Arc::strong_count(&self.gate) <= 2 {
            gates.remove(self.session_id);
        }
    }
}

impl AuthHandlers {
    pub(super) async fn read_session(&self, request: &WebRequest) -> Result<Option<Session>> {
        let cookies = parse_cookies(request.header("cookie"));
        match cookies
            .get(&self.inner.session_cookie)
            .filter(|value| !value.is_empty())
        {
            Some(cookie) => self.inner.sessions.get(&sha256_b64url(cookie)).await,
            None => Ok(None),
        }
    }

    /// The session of a request, with claims renewed when due; `None` when signed out.
    ///
    /// Two simultaneous requests of one session share a single renewal.
    ///
    /// # Errors
    /// The store's failure, or the renewal's (`TOK_001`, `OIDC_*`).
    pub async fn get_session(&self, request: &WebRequest) -> Result<Option<Session>> {
        let Some(session) = self.read_session(request).await? else {
            return Ok(None);
        };
        if now_unix() < session.renew_at {
            return Ok(Some(session));
        }
        let gate = Arc::clone(
            locked(&self.inner.renewing)
                .entry(session.id.clone())
                .or_default(),
        );
        let cleanup = GateCleanup {
            gates: &self.inner.renewing,
            session_id: &session.id,
            gate,
        };
        let _turn = cleanup.gate.lock().await;
        // Another request may have renewed the session while this one waited.
        let Some(current) = self.inner.sessions.get(&session.id).await? else {
            return Ok(None);
        };
        if now_unix() < current.renew_at {
            return Ok(Some(current));
        }
        self.renew_claims(&current).await
    }

    async fn renew_claims(&self, session: &Session) -> Result<Option<Session>> {
        let tokens = match self.inner.grants.refresh_tokens(&session.user_id).await {
            Ok(tokens) => tokens,
            Err(err) if err.code() == ErrorCode::Tok002 => {
                self.end_sessions(std::slice::from_ref(session)).await?;
                return Ok(None);
            }
            Err(err) => return Err(err),
        };
        let Some(id_token) = tokens.id_token.clone() else {
            return Err(AuthAiError::new(ErrorCode::Tok001)
                .with_message("The provider returned no ID token on refresh"));
        };
        let mut claims = self
            .inner
            .auth
            .verify_id_token(id_token.expose_secret())
            .await?;
        if claims.sub != session.user_id {
            self.end_sessions(std::slice::from_ref(session)).await?;
            return Err(AuthAiError::new(ErrorCode::Tok001)
                .with_message("The refreshed ID token belongs to another user"));
        }
        match self
            .inner
            .auth
            .apply_userinfo(claims.clone(), tokens.access_token.expose_secret())
            .await
        {
            Ok(enriched) => claims = enriched,
            // UserInfo only enriches the claims: a provider outage must not turn an otherwise
            // valid session renewal into a failure.
            Err(err) if err.code() == ErrorCode::Oidc003 => self.report(&err),
            // Any other error (notably a subject mismatch) is terminal, so drop the session
            // before failing instead of refreshing forever.
            Err(err) => {
                if err.code() == ErrorCode::Tok001 {
                    self.end_sessions(std::slice::from_ref(session)).await?;
                }
                return Err(err);
            }
        }
        let renewed = Session {
            id: session.id.clone(),
            user_id: session.user_id.clone(),
            session_id: session.session_id.clone(),
            claims,
            id_token,
            created_at: session.created_at,
            expires_at: session.expires_at,
            renew_at: (now_unix() + self.inner.renew_seconds).min(session.expires_at),
        };
        self.inner.sessions.update(&renewed).await?;
        Ok(Some(renewed))
    }

    pub(super) async fn create_session(
        &self,
        claims: &IdTokenClaims,
        id_token: &SecretString,
        has_refresh_token: bool,
    ) -> Result<(Session, String)> {
        let now = now_unix();
        let expires_at = if has_refresh_token {
            now + self.inner.session_ttl
        } else {
            // Without a refresh token the session cannot outlive the ID token.
            (now + self.inner.session_ttl).min(claims.exp as i64)
        };
        let cookie = random_token(32)?;
        let session = Session {
            id: sha256_b64url(&cookie),
            user_id: claims.sub.clone(),
            session_id: claims.sid.clone(),
            claims: claims.clone(),
            id_token: id_token.clone(),
            created_at: now,
            expires_at,
            renew_at: if has_refresh_token {
                (now + self.inner.renew_seconds).min(expires_at)
            } else {
                expires_at
            },
        };
        self.inner.sessions.create(&session).await?;
        Ok((session, cookie))
    }

    /// Ends sessions, and revokes the grant of every user left with none.
    pub(super) async fn end_sessions(&self, ended: &[Session]) -> Result<()> {
        for session in ended {
            self.inner.sessions.delete(&session.id).await?;
        }
        self.after_sessions_removed(ended).await
    }

    async fn after_sessions_removed(&self, ended: &[Session]) -> Result<()> {
        let mut handled: Vec<&str> = Vec::new();
        for session in ended {
            let user_id = session.user_id.as_str();
            if handled.contains(&user_id) {
                continue;
            }
            handled.push(user_id);
            if self.inner.sessions.count_by_user(user_id).await? > 0 {
                continue;
            }
            // The grant is already gone locally: the provider will expire it.
            if let Err(err) = self.inner.grants.revoke(user_id).await {
                self.report(&err);
            }
        }
        if !ended.is_empty()
            && let Some(callback) = &self.inner.on_sessions_ended
        {
            callback(ended.to_vec()).await?;
        }
        Ok(())
    }

    pub(super) async fn on_backchannel_logout(&self, event: BackchannelLogoutEvent) -> Result<()> {
        let removed = self
            .inner
            .sessions
            .delete_by_provider_session(&event.sid)
            .await?;
        self.after_sessions_removed(&removed).await
    }
}
