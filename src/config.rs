//! Validated configuration of an [`AuthClient`](crate::AuthClient).

use std::time::Duration;

use url::{Host, Url};

use crate::error::{AuthAiError, ErrorCode, Result};
use crate::secret::SecretString;

/// Scopes requested at sign-in unless the configuration names others.
pub const DEFAULT_SCOPES: [&str; 7] = [
    "openid",
    "profile",
    "email",
    "roles",
    "permissions",
    "features",
    "offline_access",
];

/// Scope that lets a user token read the user's own wallet.
pub const WALLET_SELF_SCOPE: &str = "wallet:self:read";

/// Scope that lets an application act for a user on their own shared resources.
pub const RESOURCE_SELF_SCOPE: &str = "resources:self:manage";

const DEFAULT_CLOCK_TOLERANCE_SECONDS: u64 = 5;
const MAX_CLOCK_TOLERANCE_SECONDS: u64 = 300;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// How the client authenticates at the token endpoint (RFC 6749 §2.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TokenEndpointAuthMethod {
    /// HTTP Basic credentials.
    #[default]
    ClientSecretBasic,
    /// Credentials in the form body.
    ClientSecretPost,
}

/// Configuration of an [`AuthClient`](crate::AuthClient), built and validated
/// by [`AuthClientConfig::builder`].
///
/// With a gateway URL, the sign-in also asks for the audiences of the gateway
/// and of auth-service (which serves the wallet) and for the wallet scope: this
/// is what the application's "LiteLLM support" switch authorises. With
/// `resource_sharing`, it also asks for `resources:self:manage` and the
/// auth-service audience.
#[derive(Debug, Clone)]
pub struct AuthClientConfig {
    issuer: String,
    client_id: String,
    client_secret: Option<SecretString>,
    token_endpoint_auth_method: TokenEndpointAuthMethod,
    redirect_uri: String,
    post_logout_redirect_uri: Option<String>,
    scopes: Vec<String>,
    resources: Vec<String>,
    gateway_url: Option<String>,
    resource_sharing: bool,
    clock_tolerance_seconds: u64,
    timeout: Duration,
}

impl AuthClientConfig {
    /// Starts a configuration from its three mandatory members.
    #[must_use]
    pub fn builder(
        issuer: impl Into<String>,
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> AuthClientConfigBuilder {
        AuthClientConfigBuilder {
            issuer: issuer.into(),
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            client_secret: None,
            token_endpoint_auth_method: TokenEndpointAuthMethod::default(),
            post_logout_redirect_uri: None,
            scopes: DEFAULT_SCOPES
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect(),
            resources: Vec::new(),
            gateway_url: None,
            resource_sharing: false,
            clock_tolerance_seconds: DEFAULT_CLOCK_TOLERANCE_SECONDS,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// The issuer: an absolute https URL, compared verbatim to `iss`.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The OAuth client id (the application slug).
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// The client secret; absent for a public client, which relies on PKCE alone.
    #[must_use]
    pub const fn client_secret(&self) -> Option<&SecretString> {
        self.client_secret.as_ref()
    }

    /// How the client authenticates at the token endpoint.
    #[must_use]
    pub const fn token_endpoint_auth_method(&self) -> TokenEndpointAuthMethod {
        self.token_endpoint_auth_method
    }

    /// The registered redirect URI.
    #[must_use]
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// The registered post-logout redirect URI.
    #[must_use]
    pub fn post_logout_redirect_uri(&self) -> Option<&str> {
        self.post_logout_redirect_uri.as_deref()
    }

    /// The scopes requested at sign-in.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// The RFC 8707 audiences requested at sign-in; each refresh narrows to one.
    #[must_use]
    pub fn resources(&self) -> &[String] {
        &self.resources
    }

    /// The public URL of the LiteLLM gateway, when it is used.
    #[must_use]
    pub fn gateway_url(&self) -> Option<&str> {
        self.gateway_url.as_deref()
    }

    /// Whether sign-in asks for the resource-sharing scope and audience.
    #[must_use]
    pub const fn resource_sharing(&self) -> bool {
        self.resource_sharing
    }

    /// Allowed clock skew when checking token times.
    #[must_use]
    pub const fn clock_tolerance_seconds(&self) -> u64 {
        self.clock_tolerance_seconds
    }

    /// Timeout of every request to the provider, the API and the gateway.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }
}

/// Collects the options of an [`AuthClientConfig`]; [`build`](Self::build) validates them.
#[derive(Debug, Clone)]
pub struct AuthClientConfigBuilder {
    issuer: String,
    client_id: String,
    redirect_uri: String,
    client_secret: Option<SecretString>,
    token_endpoint_auth_method: TokenEndpointAuthMethod,
    post_logout_redirect_uri: Option<String>,
    scopes: Vec<String>,
    resources: Vec<String>,
    gateway_url: Option<String>,
    resource_sharing: bool,
    clock_tolerance_seconds: u64,
    timeout: Duration,
}

impl AuthClientConfigBuilder {
    /// Sets the client secret of a confidential client.
    #[must_use]
    pub fn client_secret(mut self, secret: impl Into<SecretString>) -> Self {
        self.client_secret = Some(secret.into());
        self
    }

    /// Sets how the client authenticates at the token endpoint.
    #[must_use]
    pub const fn token_endpoint_auth_method(mut self, method: TokenEndpointAuthMethod) -> Self {
        self.token_endpoint_auth_method = method;
        self
    }

    /// Sets the registered post-logout redirect URI.
    #[must_use]
    pub fn post_logout_redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.post_logout_redirect_uri = Some(uri.into());
        self
    }

    /// Replaces the requested scopes; `openid` is mandatory.
    #[must_use]
    pub fn scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Sets the RFC 8707 audiences requested at sign-in.
    #[must_use]
    pub fn resources<I, S>(mut self, resources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.resources = resources.into_iter().map(Into::into).collect();
        self
    }

    /// Sets the public URL of the LiteLLM gateway: turns on the gateway and
    /// wallet audiences and the wallet scope.
    #[must_use]
    pub fn gateway_url(mut self, url: impl Into<String>) -> Self {
        self.gateway_url = Some(url.into());
        self
    }

    /// Asks at sign-in for `resources:self:manage` and the auth-service audience,
    /// which the self-service resource client needs.
    #[must_use]
    pub const fn resource_sharing(mut self, enabled: bool) -> Self {
        self.resource_sharing = enabled;
        self
    }

    /// Sets the allowed clock skew, 0 to 300 seconds.
    #[must_use]
    pub const fn clock_tolerance_seconds(mut self, seconds: u64) -> Self {
        self.clock_tolerance_seconds = seconds;
        self
    }

    /// Sets the timeout of every request.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Validates the options.
    ///
    /// # Errors
    /// `CFG_001`, naming every invalid option.
    pub fn build(self) -> Result<AuthClientConfig> {
        let mut issues = Vec::new();
        check(&mut issues, "issuer", require_issuer(&self.issuer));
        check(&mut issues, "client_id", require_non_empty(&self.client_id));
        check(
            &mut issues,
            "redirect_uri",
            require_redirect_uri(&self.redirect_uri),
        );
        if let Some(uri) = &self.post_logout_redirect_uri {
            check(
                &mut issues,
                "post_logout_redirect_uri",
                require_redirect_uri(uri),
            );
        }
        if let Some(secret) = &self.client_secret {
            check(
                &mut issues,
                "client_secret",
                require_non_empty(secret.expose_secret()),
            );
        }
        if !self.scopes.iter().any(|scope| scope == "openid") {
            issues.push("scopes: must include `openid`".to_owned());
        }
        for scope in &self.scopes {
            check(&mut issues, "scopes", require_non_empty(scope));
        }
        for resource in &self.resources {
            check(&mut issues, "resources", require_url(resource));
        }
        if let Some(url) = &self.gateway_url {
            check(&mut issues, "gateway_url", require_gateway_url(url));
        }
        if self.clock_tolerance_seconds > MAX_CLOCK_TOLERANCE_SECONDS {
            issues.push(format!(
                "clock_tolerance_seconds: must be at most {MAX_CLOCK_TOLERANCE_SECONDS}"
            ));
        }
        if self.timeout.is_zero() {
            issues.push("timeout: must be greater than zero".to_owned());
        }
        if !issues.is_empty() {
            return Err(AuthAiError::new(ErrorCode::Cfg001)
                .with_message(format!("Invalid SDK configuration: {}", issues.join("; "))));
        }

        let mut scopes = dedup(self.scopes);
        let mut resources = dedup(self.resources);
        if let Some(gateway) = &self.gateway_url {
            scopes.push(WALLET_SELF_SCOPE.to_owned());
            resources.push(gateway.clone());
            resources.push(self.issuer.clone());
        }
        if self.resource_sharing {
            scopes.push(RESOURCE_SELF_SCOPE.to_owned());
            resources.push(self.issuer.clone());
        }
        scopes = dedup(scopes);
        resources = dedup(resources);
        Ok(AuthClientConfig {
            issuer: self.issuer,
            client_id: self.client_id,
            client_secret: self.client_secret,
            token_endpoint_auth_method: self.token_endpoint_auth_method,
            redirect_uri: self.redirect_uri,
            post_logout_redirect_uri: self.post_logout_redirect_uri,
            scopes,
            resources,
            gateway_url: self.gateway_url,
            resource_sharing: self.resource_sharing,
            clock_tolerance_seconds: self.clock_tolerance_seconds,
            timeout: self.timeout,
        })
    }
}

fn check(issues: &mut Vec<String>, field: &str, outcome: std::result::Result<(), &'static str>) {
    if let Err(reason) = outcome {
        issues.push(format!("{field}: {reason}"));
    }
}

fn dedup(values: Vec<String>) -> Vec<String> {
    let mut seen = Vec::with_capacity(values.len());
    for value in values {
        if !seen.contains(&value) {
            seen.push(value);
        }
    }
    seen
}

fn require_non_empty(value: &str) -> std::result::Result<(), &'static str> {
    if value.is_empty() {
        Err("must not be empty")
    } else {
        Ok(())
    }
}

fn parse_absolute(value: &str) -> Option<(Url, Host<String>)> {
    let url = Url::parse(value).ok()?;
    let host = url.host()?.to_owned();
    Some((url, host))
}

fn require_url(value: &str) -> std::result::Result<(), &'static str> {
    parse_absolute(value)
        .map(|_| ())
        .ok_or("must be an absolute URL")
}

fn require_issuer(value: &str) -> std::result::Result<(), &'static str> {
    let Some((url, _)) = parse_absolute(value).filter(|(url, _)| url.scheme() == "https") else {
        return Err("must be an absolute https URL");
    };
    if url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("must not contain credentials, a query, or a fragment");
    }
    Ok(())
}

// http is allowed for loopback only, so local development needs no tunnel.
fn require_redirect_uri(value: &str) -> std::result::Result<(), &'static str> {
    let allowed = parse_absolute(value).is_some_and(|(url, host)| {
        url.scheme() == "https" || (url.scheme() == "http" && is_loopback(&host))
    });
    if allowed {
        Ok(())
    } else {
        Err("must be https (http is only accepted for localhost)")
    }
}

fn is_loopback(host: &Host<String>) -> bool {
    match host {
        Host::Domain(name) => name == "localhost",
        Host::Ipv4(address) => address.octets() == [127, 0, 0, 1],
        Host::Ipv6(address) => address.is_loopback(),
    }
}

// An audience is compared verbatim to `aud`: a trailing slash would never match.
fn require_gateway_url(value: &str) -> std::result::Result<(), &'static str> {
    require_redirect_uri(value)?;
    if value.ends_with('/') {
        return Err("must not end with a slash: it is compared verbatim to `aud`");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn builder() -> AuthClientConfigBuilder {
        AuthClientConfig::builder(
            "https://auth.example.com",
            "my-app",
            "https://app.example.com/auth/callback",
        )
    }

    #[test]
    fn defaults_are_applied() {
        let config = builder().build().unwrap();
        assert_eq!(config.scopes(), DEFAULT_SCOPES);
        assert!(config.resources().is_empty());
        assert!(!config.resource_sharing());
        assert_eq!(config.clock_tolerance_seconds(), 5);
        assert_eq!(config.timeout(), Duration::from_secs(10));
        assert!(config.client_secret().is_none());
        assert_eq!(
            config.token_endpoint_auth_method(),
            TokenEndpointAuthMethod::ClientSecretBasic
        );
    }

    #[test]
    fn the_gateway_adds_its_audiences_and_the_wallet_scope() {
        let config = builder()
            .resources(["https://api.example.com", "https://llm.example.com"])
            .gateway_url("https://llm.example.com")
            .build()
            .unwrap();
        assert_eq!(
            config.scopes().last().map(String::as_str),
            Some(WALLET_SELF_SCOPE)
        );
        assert_eq!(
            config.resources(),
            [
                "https://api.example.com",
                "https://llm.example.com",
                "https://auth.example.com"
            ]
        );
    }

    #[test]
    fn resource_sharing_adds_its_scope_and_the_auth_service_audience() {
        let config = builder()
            .resources(["https://api.example.com"])
            .resource_sharing(true)
            .build()
            .unwrap();
        assert!(config.resource_sharing());
        assert!(config.scopes().contains(&RESOURCE_SELF_SCOPE.to_owned()));
        assert_eq!(
            config.resources(),
            ["https://api.example.com", "https://auth.example.com"]
        );

        let both = builder()
            .gateway_url("https://llm.example.com")
            .resource_sharing(true)
            .build()
            .unwrap();
        assert_eq!(
            both.resources(),
            ["https://llm.example.com", "https://auth.example.com"]
        );
        assert_eq!(
            both.scopes()
                .iter()
                .filter(|scope| *scope == WALLET_SELF_SCOPE || *scope == RESOURCE_SELF_SCOPE)
                .count(),
            2
        );
    }

    #[test]
    fn every_invalid_option_is_named_in_one_error() {
        let err =
            AuthClientConfig::builder("http://auth.example.com", "", "http://app.example.com/cb")
                .scopes(["profile"])
                .clock_tolerance_seconds(301)
                .timeout(Duration::ZERO)
                .build()
                .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Cfg001);
        for field in [
            "issuer",
            "client_id",
            "redirect_uri",
            "scopes",
            "clock_tolerance_seconds",
            "timeout",
        ] {
            assert!(
                err.message().contains(field),
                "{field} missing from {}",
                err.message()
            );
        }
    }

    #[test]
    fn issuer_rejects_credentials_query_and_fragment() {
        for issuer in [
            "https://user:pw@auth.example.com",
            "https://auth.example.com?x=1",
            "https://auth.example.com#frag",
            "auth.example.com",
            "http://auth.example.com",
        ] {
            let err = AuthClientConfig::builder(issuer, "app", "https://app.example.com/cb")
                .build()
                .unwrap_err();
            assert!(err.message().contains("issuer"), "{issuer} was accepted");
        }
    }

    #[test]
    fn http_is_accepted_for_loopback_redirects_only() {
        for uri in [
            "http://localhost:3000/cb",
            "http://127.0.0.1/cb",
            "http://[::1]:8000/cb",
        ] {
            assert!(
                AuthClientConfig::builder("https://a.example", "app", uri)
                    .build()
                    .is_ok(),
                "{uri}"
            );
        }
        assert!(
            AuthClientConfig::builder("https://a.example", "app", "http://app.example.com/cb")
                .build()
                .is_err()
        );
    }

    #[test]
    fn gateway_url_must_not_end_with_a_slash() {
        let err = builder()
            .gateway_url("https://llm.example.com/")
            .build()
            .unwrap_err();
        assert!(err.message().contains("gateway_url"));
        assert!(
            builder()
                .gateway_url("http://llm.example.com")
                .build()
                .is_err()
        );
    }

    #[test]
    fn an_empty_client_secret_is_refused() {
        let err = builder().client_secret("").build().unwrap_err();
        assert!(err.message().contains("client_secret"));
    }

    #[test]
    fn resources_must_be_absolute_urls() {
        assert!(builder().resources(["not a url"]).build().is_err());
    }

    #[test]
    fn debug_output_hides_the_client_secret() {
        let config = builder()
            .client_secret("super-secret-value")
            .build()
            .unwrap();
        assert!(!format!("{config:?}").contains("super-secret-value"));
    }
}
