//! Error envelopes, redirect targets and the cross-site test of the browser-facing routes.

use url::Url;

use crate::error::{AuthAiError, ErrorCode};
use crate::messages::{ErrorCallback, WebRequest, WebResponse, json_response};

const PLACEHOLDER_HOST: &str = "placeholder.invalid";

/// The HTTP status each code is answered with.
#[must_use]
pub const fn status_for(code: ErrorCode) -> u16 {
    match code {
        ErrorCode::Req001 | ErrorCode::Ses002 | ErrorCode::Oidc002 => 400,
        ErrorCode::Ses001 | ErrorCode::Tok001 | ErrorCode::Tok002 | ErrorCode::Tok003 => 401,
        ErrorCode::Ses004 | ErrorCode::Ses005 | ErrorCode::Tok004 | ErrorCode::Gw003 => 403,
        ErrorCode::Oidc001
        | ErrorCode::Oidc003
        | ErrorCode::Api001
        | ErrorCode::Api002
        | ErrorCode::Gw005 => 502,
        ErrorCode::Oidc004 => 501,
        ErrorCode::Gw001 => 402,
        ErrorCode::Gw002 => 429,
        ErrorCode::Gw004 => 503,
        ErrorCode::Cfg001 | ErrorCode::Ses003 | ErrorCode::Srv001 => 500,
    }
}

/// Serialises a failure as the same `{ error: { code, message } }` envelope
/// auth-service uses.
///
/// Only the code and a generic message go out: the detailed message and the
/// details stay in the error, for the application's logs. A server-side failure
/// (status 500 and above) is reported to `on_error`.
#[must_use]
pub fn error_response(
    err: &AuthAiError,
    on_error: Option<&ErrorCallback>,
    headers: Vec<(String, String)>,
) -> WebResponse {
    let status = status_for(err.code());
    if status >= 500
        && let Some(callback) = on_error
    {
        callback(err);
    }
    json_response(
        &serde_json::json!({ "error": err.to_public_json() }),
        status,
        headers,
    )
}

/// A redirect target taken from a request, reduced to a same-origin path.
///
/// An absolute URL, a protocol-relative one (`//host`) or anything odd falls
/// back to `fallback`, so a login link cannot bounce users to another site.
#[must_use]
pub fn safe_redirect_path(candidate: Option<&str>, fallback: &str) -> String {
    let Some(path) = candidate.filter(|path| path.starts_with('/') && !path.starts_with("//"))
    else {
        return fallback.to_owned();
    };
    // Control characters and backslashes make browsers read a "path" as another host.
    if path.chars().any(|c| c == '\\' || c.is_ascii_control()) {
        return fallback.to_owned();
    }
    let stays_here = Url::parse(&format!("https://{PLACEHOLDER_HOST}{path}"))
        .is_ok_and(|probe| probe.host_str() == Some(PLACEHOLDER_HOST) && probe.port().is_none());
    if stays_here {
        path.to_owned()
    } else {
        fallback.to_owned()
    }
}

/// Whether a browser sent this state-changing request from another site.
///
/// Requests without `Origin` and `Sec-Fetch-Site` (non-browser clients) carry
/// no ambient cookie to abuse and pass.
#[must_use]
pub fn is_cross_site(request: &WebRequest, expected_origin: &str) -> bool {
    if let Some(origin) = request.header("origin") {
        return origin != expected_origin;
    }
    request
        .header("sec-fetch-site")
        .is_some_and(|site| !matches!(site, "same-origin" | "none"))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn every_code_has_a_status() {
        for code in ErrorCode::ALL {
            assert!((400..=503).contains(&status_for(code)), "{code}");
        }
        assert_eq!(status_for(ErrorCode::Gw001), 402);
        assert_eq!(status_for(ErrorCode::Ses005), 403);
    }

    #[test]
    fn the_envelope_carries_the_code_and_a_generic_message_only() {
        let err = ErrorCode::Oidc003
            .error()
            .with_message("secret provider detail")
            .with_detail("status", 401_u16);
        let response = error_response(&err, None, Vec::new());
        assert_eq!(response.status, 502);
        let body = response.json().unwrap();
        assert_eq!(
            body,
            serde_json::json!({ "error": { "code": "OIDC_003", "message": "Token request failed" } })
        );
        assert_eq!(response.header("cache-control"), Some("no-store"));
    }

    #[test]
    fn only_server_side_failures_reach_on_error() {
        let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
        let sink = std::sync::Arc::clone(&seen);
        let callback: ErrorCallback =
            std::sync::Arc::new(move |err| sink.lock().unwrap().push(err.code()));
        let _ = error_response(&ErrorCode::Ses001.error(), Some(&callback), Vec::new());
        let _ = error_response(&ErrorCode::Api001.error(), Some(&callback), Vec::new());
        let _ = error_response(&ErrorCode::Srv001.error(), Some(&callback), Vec::new());
        assert_eq!(
            *seen.lock().unwrap(),
            [ErrorCode::Api001, ErrorCode::Srv001]
        );
    }

    #[test]
    fn redirects_stay_on_this_origin() {
        for good in ["/", "/app", "/app?x=1#y", "/a/b/../c", "/@not-a-host"] {
            assert_eq!(safe_redirect_path(Some(good), "/home"), good);
        }
        for bad in [
            None,
            Some(""),
            Some("app"),
            Some("//evil.example"),
            Some("https://evil.example"),
            Some("/\\evil.example"),
            Some("/\t/evil.example"),
            Some("/\n"),
            Some("/\u{7f}"),
        ] {
            assert_eq!(safe_redirect_path(bad, "/home"), "/home", "{bad:?}");
        }
    }

    #[test]
    fn cross_site_requests_are_recognised() {
        let origin = "https://app.example.com";
        let request = |headers: &[(&str, &str)]| {
            headers.iter().fold(
                WebRequest::new("POST", "https://app.example.com/auth/logout"),
                |request, (name, value)| request.with_header(name, *value),
            )
        };
        assert!(!is_cross_site(&request(&[]), origin));
        assert!(!is_cross_site(&request(&[("origin", origin)]), origin));
        assert!(is_cross_site(
            &request(&[("origin", "https://evil.example")]),
            origin
        ));
        assert!(is_cross_site(&request(&[("origin", "null")]), origin));
        assert!(!is_cross_site(
            &request(&[("sec-fetch-site", "same-origin")]),
            origin
        ));
        assert!(!is_cross_site(
            &request(&[("sec-fetch-site", "none")]),
            origin
        ));
        assert!(is_cross_site(
            &request(&[("sec-fetch-site", "cross-site")]),
            origin
        ));
        assert!(is_cross_site(
            &request(&[("sec-fetch-site", "same-site")]),
            origin
        ));
        // Origin wins over Sec-Fetch-Site.
        assert!(is_cross_site(
            &request(&[
                ("origin", "https://evil.example"),
                ("sec-fetch-site", "same-origin")
            ]),
            origin
        ));
    }
}
