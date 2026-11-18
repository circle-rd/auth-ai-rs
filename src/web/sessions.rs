//! Where signed-in sessions live.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use async_trait::async_trait;

use crate::claims::IdTokenClaims;
use crate::error::Result;
use crate::secret::SecretString;
use crate::util::now_unix;

/// A signed-in browser session, as kept by the application's backend.
#[derive(Debug, Clone)]
pub struct Session {
    /// SHA-256 of the cookie value: a leaked store cannot be replayed as cookies.
    pub id: String,
    /// The provider's subject: also the key of the user's grant.
    pub user_id: String,
    /// The provider session, which a back-channel logout names.
    pub session_id: Option<String>,
    /// The verified claims.
    pub claims: IdTokenClaims,
    /// Hint for the provider's logout endpoint.
    pub id_token: SecretString,
    /// Creation time, in unix seconds.
    pub created_at: i64,
    /// Absolute end of the session, in unix seconds.
    pub expires_at: i64,
    /// When the claims are next renewed from the provider, in unix seconds.
    pub renew_at: i64,
}

/// Where sessions live.
///
/// Implement it on the database of the application; it must survive restarts
/// and be shared by every replica. Records are keyed by [`Session::id`], and
/// `session_id` and `user_id` must be indexed. A failing store reports `SRV_001`.
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Stores a new session.
    async fn create(&self, session: &Session) -> Result<()>;

    /// The session of that key; `None` for an unknown or expired one.
    async fn get(&self, session_key: &str) -> Result<Option<Session>>;

    /// Replaces a session that still exists.
    async fn update(&self, session: &Session) -> Result<()>;

    /// Removes a session.
    async fn delete(&self, session_key: &str) -> Result<()>;

    /// Removes every session of a provider session and returns what was removed.
    async fn delete_by_provider_session(&self, session_id: &str) -> Result<Vec<Session>>;

    /// The number of live sessions of a user.
    async fn count_by_user(&self, user_id: &str) -> Result<usize>;
}

/// Keeps sessions in the process: for tests and single-process prototypes.
#[derive(Debug, Default)]
pub struct MemorySessionStore {
    sessions: Mutex<HashMap<String, Session>>,
}

impl MemorySessionStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Session>> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[async_trait]
impl SessionStore for MemorySessionStore {
    async fn create(&self, session: &Session) -> Result<()> {
        self.lock().insert(session.id.clone(), session.clone());
        Ok(())
    }

    async fn get(&self, session_key: &str) -> Result<Option<Session>> {
        let mut sessions = self.lock();
        match sessions.get(session_key) {
            Some(session) if session.expires_at <= now_unix() => {
                sessions.remove(session_key);
                Ok(None)
            }
            found => Ok(found.cloned()),
        }
    }

    async fn update(&self, session: &Session) -> Result<()> {
        if let Some(stored) = self.lock().get_mut(&session.id) {
            *stored = session.clone();
        }
        Ok(())
    }

    async fn delete(&self, session_key: &str) -> Result<()> {
        self.lock().remove(session_key);
        Ok(())
    }

    async fn delete_by_provider_session(&self, session_id: &str) -> Result<Vec<Session>> {
        let mut sessions = self.lock();
        let ids: Vec<String> = sessions
            .values()
            .filter(|session| session.session_id.as_deref() == Some(session_id))
            .map(|session| session.id.clone())
            .collect();
        Ok(ids.iter().filter_map(|id| sessions.remove(id)).collect())
    }

    async fn count_by_user(&self, user_id: &str) -> Result<usize> {
        let now = now_unix();
        Ok(self
            .lock()
            .values()
            .filter(|session| session.user_id == user_id && session.expires_at > now)
            .count())
    }
}
