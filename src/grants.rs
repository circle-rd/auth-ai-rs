//! The refresh-token chain of each user, and the one place that refreshes it.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use tokio::sync::OwnedMutexGuard;

use crate::client::AuthClient;
use crate::error::{AuthAiError, ErrorCode, Result};
use crate::secret::SecretString;
use crate::types::{TokenSet, TokenTypeHint};
use crate::util::now_unix;

/// A cached access token is renewed this long before it expires.
pub const DEFAULT_EXPIRY_SKEW_SECONDS: i64 = 30;

/// Persists the single refresh-token chain of a user.
///
/// The provider rotates it on every use, so a store must hold exactly one value
/// per grant. Encrypt it at rest: it is a long-lived credential. A failing
/// store reports `SRV_001`.
#[async_trait]
pub trait GrantStore: Send + Sync {
    /// The refresh token of a grant, `None` when there is none.
    async fn get(&self, grant_id: &str) -> Result<Option<SecretString>>;

    /// Replaces the refresh token of a grant.
    async fn set(&self, grant_id: &str, refresh_token: &SecretString) -> Result<()>;

    /// Forgets a grant.
    async fn delete(&self, grant_id: &str) -> Result<()>;
}

/// Held while a grant is being refreshed; dropping it releases the lock.
pub struct LockGuard {
    _release: Box<dyn Send>,
}

impl LockGuard {
    /// Wraps whatever releases the lock when dropped.
    #[must_use]
    pub fn new(release_on_drop: impl Send + 'static) -> Self {
        Self {
            _release: Box::new(release_on_drop),
        }
    }
}

/// Serialises the refreshes of one grant.
///
/// The default lock only covers a single process: replicas need a distributed
/// lock (or a row lock in the store).
#[async_trait]
pub trait GrantLock: Send + Sync {
    /// Waits for the grant's turn.
    async fn hold(&self, grant_id: &str) -> Result<LockGuard>;
}

/// What the grant manager needs of the OIDC client.
#[async_trait]
pub trait GrantAuth: Send + Sync {
    /// Exchanges a refresh token for fresh tokens, narrowed to `resource`.
    async fn refresh(&self, refresh_token: &str, resource: Option<&str>) -> Result<TokenSet>;

    /// Revokes a token at the provider.
    async fn revoke(&self, token: &str, hint: Option<TokenTypeHint>) -> Result<()>;
}

#[async_trait]
impl GrantAuth for AuthClient {
    async fn refresh(&self, refresh_token: &str, resource: Option<&str>) -> Result<TokenSet> {
        Self::refresh(self, refresh_token, resource).await
    }

    async fn revoke(&self, token: &str, hint: Option<TokenTypeHint>) -> Result<()> {
        Self::revoke(self, token, hint).await
    }
}

#[async_trait]
impl<T: GrantStore + ?Sized> GrantStore for Arc<T> {
    async fn get(&self, grant_id: &str) -> Result<Option<SecretString>> {
        (**self).get(grant_id).await
    }

    async fn set(&self, grant_id: &str, refresh_token: &SecretString) -> Result<()> {
        (**self).set(grant_id, refresh_token).await
    }

    async fn delete(&self, grant_id: &str) -> Result<()> {
        (**self).delete(grant_id).await
    }
}

#[async_trait]
impl<T: GrantLock + ?Sized> GrantLock for Arc<T> {
    async fn hold(&self, grant_id: &str) -> Result<LockGuard> {
        (**self).hold(grant_id).await
    }
}

/// An access token minted for one audience.
#[derive(Debug, Clone)]
pub struct AccessToken {
    /// The token.
    pub access_token: SecretString,
    /// Expiry, in unix seconds.
    pub expires_at: i64,
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A poisoned lock only means another thread panicked mid-update of a cache or a map.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Keeps grants in the process: for tests and single-process prototypes.
#[derive(Debug, Default)]
pub struct MemoryGrantStore {
    grants: Mutex<HashMap<String, SecretString>>,
}

impl MemoryGrantStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl GrantStore for MemoryGrantStore {
    async fn get(&self, grant_id: &str) -> Result<Option<SecretString>> {
        Ok(locked(&self.grants).get(grant_id).cloned())
    }

    async fn set(&self, grant_id: &str, refresh_token: &SecretString) -> Result<()> {
        locked(&self.grants).insert(grant_id.to_owned(), refresh_token.clone());
        Ok(())
    }

    async fn delete(&self, grant_id: &str) -> Result<()> {
        locked(&self.grants).remove(grant_id);
        Ok(())
    }
}

type LockMap = Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>;

/// A lock covering the refreshes of one process.
#[derive(Debug, Default)]
pub struct InProcessGrantLock {
    entries: LockMap,
}

impl InProcessGrantLock {
    /// A lock with no holder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

struct InProcessGuard {
    guard: Option<OwnedMutexGuard<()>>,
    entries: LockMap,
    grant_id: String,
}

impl Drop for InProcessGuard {
    fn drop(&mut self) {
        let Some(guard) = self.guard.take() else {
            return;
        };
        let mutex = Arc::clone(OwnedMutexGuard::mutex(&guard));
        drop(guard);
        // An idle lock is dropped so the map does not grow: the map and `mutex` hold
        // the only references when nobody waits.
        let mut entries = locked(&self.entries);
        if Arc::strong_count(&mutex) == 2 {
            entries.remove(&self.grant_id);
        }
    }
}

#[async_trait]
impl GrantLock for InProcessGrantLock {
    async fn hold(&self, grant_id: &str) -> Result<LockGuard> {
        let mutex = Arc::clone(
            locked(&self.entries)
                .entry(grant_id.to_owned())
                .or_default(),
        );
        let guard = mutex.lock_owned().await;
        Ok(LockGuard::new(InProcessGuard {
            guard: Some(guard),
            entries: Arc::clone(&self.entries),
            grant_id: grant_id.to_owned(),
        }))
    }
}

fn cache_key(grant_id: &str, resource: Option<&str>) -> String {
    format!("{grant_id}\0{}", resource.unwrap_or_default())
}

struct GrantInner {
    auth: Arc<dyn GrantAuth>,
    store: Arc<dyn GrantStore>,
    lock: Arc<dyn GrantLock>,
    skew_seconds: i64,
    cache: Mutex<HashMap<String, AccessToken>>,
}

impl GrantInner {
    fn cached(&self, key: &str) -> Option<AccessToken> {
        let mut cache = locked(&self.cache);
        let token = cache.get(key)?;
        if token.expires_at - self.skew_seconds > now_unix() {
            return Some(token.clone());
        }
        cache.remove(key);
        None
    }

    fn forget(&self, grant_id: &str) {
        let prefix = format!("{grant_id}\0");
        locked(&self.cache).retain(|key, _| !key.starts_with(&prefix));
    }

    /// One refresh under the grant lock the caller already holds.
    async fn rotate(&self, grant_id: &str, resource: Option<&str>) -> Result<TokenSet> {
        let Some(refresh_token) = self.store.get(grant_id).await? else {
            return Err(AuthAiError::new(ErrorCode::Tok002));
        };
        match self
            .auth
            .refresh(refresh_token.expose_secret(), resource)
            .await
        {
            Ok(tokens) => {
                // Providers may omit the refresh token when they do not rotate it.
                self.store
                    .set(
                        grant_id,
                        tokens.refresh_token.as_ref().unwrap_or(&refresh_token),
                    )
                    .await?;
                Ok(tokens)
            }
            Err(err) if err.oauth_error() == Some("invalid_grant") => {
                self.store.delete(grant_id).await?;
                self.forget(grant_id);
                Err(AuthAiError::new(ErrorCode::Tok002).with_source(err))
            }
            Err(err) => Err(err),
        }
    }
}

// A caller that gives up must not abort a rotation half-way: the provider would hold a
// new refresh token this process never stored, and the next replay revokes the family.
async fn detached<T, F>(operation: F) -> Result<T>
where
    T: Send + 'static,
    F: Future<Output = Result<T>> + Send + 'static,
{
    tokio::spawn(operation).await.map_err(|err| {
        AuthAiError::new(ErrorCode::Srv001)
            .with_message("A grant operation was interrupted")
            .with_source(err)
    })?
}

/// The only place that refreshes tokens.
///
/// Access tokens are minted per resource (RFC 8707) from the stored refresh
/// token and cached in memory until shortly before they expire; they are never
/// persisted. Clones share the same cache.
#[derive(Clone)]
pub struct GrantManager {
    inner: Arc<GrantInner>,
}

impl std::fmt::Debug for GrantManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantManager").finish_non_exhaustive()
    }
}

/// Collects the options of a [`GrantManager`].
pub struct GrantManagerBuilder {
    auth: Arc<dyn GrantAuth>,
    store: Arc<dyn GrantStore>,
    lock: Option<Arc<dyn GrantLock>>,
    skew_seconds: i64,
}

impl GrantManagerBuilder {
    /// Replaces the default in-process lock, e.g. by a distributed one.
    #[must_use]
    pub fn lock(mut self, lock: impl GrantLock + 'static) -> Self {
        self.lock = Some(Arc::new(lock));
        self
    }

    /// Renews cached access tokens this many seconds before they expire.
    #[must_use]
    pub const fn expiry_skew_seconds(mut self, seconds: i64) -> Self {
        self.skew_seconds = seconds;
        self
    }

    /// Builds the manager.
    #[must_use]
    pub fn build(self) -> GrantManager {
        GrantManager {
            inner: Arc::new(GrantInner {
                auth: self.auth,
                store: self.store,
                lock: self
                    .lock
                    .unwrap_or_else(|| Arc::new(InProcessGrantLock::new())),
                skew_seconds: self.skew_seconds,
                cache: Mutex::new(HashMap::new()),
            }),
        }
    }
}

impl GrantManager {
    /// Starts a manager on an OIDC client (or any [`GrantAuth`]) and a store.
    #[must_use]
    pub fn builder(
        auth: impl GrantAuth + 'static,
        store: impl GrantStore + 'static,
    ) -> GrantManagerBuilder {
        GrantManagerBuilder {
            auth: Arc::new(auth),
            store: Arc::new(store),
            lock: None,
            skew_seconds: DEFAULT_EXPIRY_SKEW_SECONDS,
        }
    }

    /// A manager with the default lock and expiry skew.
    #[must_use]
    pub fn new(auth: impl GrantAuth + 'static, store: impl GrantStore + 'static) -> Self {
        Self::builder(auth, store).build()
    }

    /// Stores the refresh token obtained at sign-in, replacing any older chain.
    ///
    /// # Errors
    /// The store's or the lock's failure.
    pub async fn save(&self, grant_id: &str, refresh_token: &SecretString) -> Result<()> {
        let _held = self.inner.lock.hold(grant_id).await?;
        self.inner.store.set(grant_id, refresh_token).await?;
        self.inner.forget(grant_id);
        Ok(())
    }

    /// Whether the user has a grant.
    ///
    /// # Errors
    /// The store's failure.
    pub async fn has(&self, grant_id: &str) -> Result<bool> {
        Ok(self.inner.store.get(grant_id).await?.is_some())
    }

    /// An access token for one audience, narrowed to `resource` (RFC 8707).
    ///
    /// # Errors
    /// `TOK_002` when the user has no grant or the provider rejected it: the
    /// grant is then dropped and only a new sign-in restores it.
    pub async fn get_access_token(
        &self,
        grant_id: &str,
        resource: Option<&str>,
    ) -> Result<AccessToken> {
        let key = cache_key(grant_id, resource);
        if let Some(cached) = self.inner.cached(&key) {
            return Ok(cached);
        }
        let inner = Arc::clone(&self.inner);
        let grant_id = grant_id.to_owned();
        let resource = resource.map(str::to_owned);
        detached(async move {
            let _held = inner.lock.hold(&grant_id).await?;
            // Another caller may have refreshed while this one waited for the lock.
            if let Some(refreshed) = inner.cached(&key) {
                return Ok(refreshed);
            }
            let tokens = inner.rotate(&grant_id, resource.as_deref()).await?;
            let token = AccessToken {
                access_token: tokens.access_token,
                expires_at: tokens.expires_at,
            };
            locked(&inner.cache).insert(key, token.clone());
            Ok(token)
        })
        .await
    }

    /// Refreshes without narrowing to a resource and returns the whole token set.
    ///
    /// The ID token is included: this is the way to renew the claims of a
    /// session. The rotated refresh token is stored.
    ///
    /// # Errors
    /// Those of [`GrantManager::get_access_token`].
    pub async fn refresh_tokens(&self, grant_id: &str) -> Result<TokenSet> {
        let inner = Arc::clone(&self.inner);
        let grant_id = grant_id.to_owned();
        detached(async move {
            let _held = inner.lock.hold(&grant_id).await?;
            inner.rotate(&grant_id, None).await
        })
        .await
    }

    /// Drops a cached access token the API refused, so the next call mints a fresh one.
    pub fn invalidate(&self, grant_id: &str, resource: Option<&str>) {
        locked(&self.inner.cache).remove(&cache_key(grant_id, resource));
    }

    /// Revokes the refresh token at the provider, then forgets the grant.
    ///
    /// The grant is forgotten even when the provider is unreachable: that must
    /// not keep the user signed in locally.
    ///
    /// # Errors
    /// The provider's refusal, after the grant was forgotten.
    pub async fn revoke(&self, grant_id: &str) -> Result<()> {
        let inner = Arc::clone(&self.inner);
        let grant_id = grant_id.to_owned();
        detached(async move {
            let _held = inner.lock.hold(&grant_id).await?;
            let outcome = match inner.store.get(&grant_id).await? {
                Some(refresh_token) => {
                    inner
                        .auth
                        .revoke(
                            refresh_token.expose_secret(),
                            Some(TokenTypeHint::RefreshToken),
                        )
                        .await
                }
                None => Ok(()),
            };
            inner.store.delete(&grant_id).await?;
            inner.forget(&grant_id);
            outcome
        })
        .await
    }
}
