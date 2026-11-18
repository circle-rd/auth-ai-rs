//! Wrapper for credentials, kept out of `Debug` output and wiped on drop.

use std::fmt;

use zeroize::Zeroizing;

/// A credential: a client secret, a token, a PKCE verifier.
///
/// It never prints itself and its memory is zeroed when it is dropped. Read it
/// with [`SecretString::expose_secret`] at the point of use only.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Wraps a credential.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// The credential itself.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_hides_the_value() {
        let secret = SecretString::new("hunter2-hunter2");
        assert!(!format!("{secret:?}").contains("hunter2"));
        assert_eq!(secret.expose_secret(), "hunter2-hunter2");
    }
}
