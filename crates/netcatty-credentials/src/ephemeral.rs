use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, oneshot};
use tokio::time::Instant;

use crate::{CredentialError, CredentialErrorCode, EphemeralCredentialReference, SecretValue};

pub const DEFAULT_EPHEMERAL_CREDENTIAL_TTL: Duration = Duration::from_secs(120);
pub const MAX_EPHEMERAL_CREDENTIAL_ENTRIES: usize = 256;
pub const MAX_EPHEMERAL_CREDENTIALS_PER_OWNER: usize = 32;
pub const MAX_EPHEMERAL_TOTAL_SECRET_BYTES: usize = 4 * 1_024 * 1_024;
const MAX_OWNER_BYTES: usize = 256;

struct EphemeralEntry {
    owner: String,
    expires_at: Instant,
    generation: u64,
    _expiry_cancel: oneshot::Sender<()>,
    secret: SecretValue,
}

struct EphemeralState {
    entries: HashMap<EphemeralCredentialReference, EphemeralEntry>,
    next_generation: u64,
}

impl EphemeralState {
    fn remove_expired_generation(
        &mut self,
        reference: &EphemeralCredentialReference,
        generation: u64,
        now: Instant,
    ) -> bool {
        let should_remove = self
            .entries
            .get(reference)
            .is_some_and(|entry| entry.generation == generation && entry.expires_at <= now);
        if should_remove {
            self.entries.remove(reference);
        }
        should_remove
    }
}

#[derive(Clone, Copy)]
struct EphemeralLimits {
    global_entries: usize,
    entries_per_owner: usize,
    total_secret_bytes: usize,
}

impl Default for EphemeralLimits {
    fn default() -> Self {
        Self {
            global_entries: MAX_EPHEMERAL_CREDENTIAL_ENTRIES,
            entries_per_owner: MAX_EPHEMERAL_CREDENTIALS_PER_OWNER,
            total_secret_bytes: MAX_EPHEMERAL_TOTAL_SECRET_BYTES,
        }
    }
}

#[derive(Clone)]
pub struct EphemeralCredentialStore {
    state: Arc<Mutex<EphemeralState>>,
    ttl: Duration,
    limits: EphemeralLimits,
}

impl EphemeralCredentialStore {
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            state: Arc::new(Mutex::new(EphemeralState {
                entries: HashMap::new(),
                next_generation: 0,
            })),
            ttl,
            limits: EphemeralLimits::default(),
        }
    }

    #[cfg(test)]
    fn with_limits(ttl: Duration, limits: EphemeralLimits) -> Self {
        Self {
            limits,
            ..Self::new(ttl)
        }
    }

    pub async fn insert(
        &self,
        owner: impl Into<String>,
        secret: SecretValue,
    ) -> Result<EphemeralCredentialReference, CredentialError> {
        let owner = owner.into();
        if owner.is_empty() || owner.len() > MAX_OWNER_BYTES {
            return Err(CredentialErrorCode::OwnerMismatch.into());
        }
        let now = Instant::now();
        let expires_at = now + self.ttl;
        let mut state = self.state.lock().await;
        state.entries.retain(|_, entry| entry.expires_at > now);

        let owner_entries = state
            .entries
            .values()
            .filter(|entry| entry.owner == owner)
            .count();
        let total_secret_bytes = state
            .entries
            .values()
            .map(|entry| entry.secret.len())
            .sum::<usize>();
        let exceeds_total_bytes = total_secret_bytes
            .checked_add(secret.len())
            .map_or(true, |total| total > self.limits.total_secret_bytes);
        if state.entries.len() >= self.limits.global_entries
            || owner_entries >= self.limits.entries_per_owner
            || exceeds_total_bytes
        {
            return Err(CredentialErrorCode::CapacityExceeded.into());
        }

        let reference = loop {
            let candidate = EphemeralCredentialReference::new();
            if !state.entries.contains_key(&candidate) {
                break candidate;
            }
        };
        state.next_generation = state.next_generation.wrapping_add(1);
        let generation = state.next_generation;
        let (expiry_cancel, expiry_cancelled) = oneshot::channel();
        state.entries.insert(
            reference,
            EphemeralEntry {
                owner,
                expires_at,
                generation,
                _expiry_cancel: expiry_cancel,
                secret,
            },
        );
        drop(state);

        self.schedule_expiry(reference, generation, expires_at, expiry_cancelled);
        Ok(reference)
    }

    fn schedule_expiry(
        &self,
        reference: EphemeralCredentialReference,
        generation: u64,
        expires_at: Instant,
        expiry_cancelled: oneshot::Receiver<()>,
    ) {
        let state = Arc::downgrade(&self.state);
        tokio::spawn(async move {
            if tokio::time::timeout_at(expires_at, expiry_cancelled)
                .await
                .is_ok()
            {
                return;
            }
            let Some(state) = state.upgrade() else {
                return;
            };
            let mut state = state.lock().await;
            state.remove_expired_generation(&reference, generation, Instant::now());
        });
    }

    pub async fn take(
        &self,
        owner: &str,
        reference: &EphemeralCredentialReference,
    ) -> Result<SecretValue, CredentialError> {
        let mut secrets = self
            .take_many(owner, std::slice::from_ref(reference))
            .await?;
        Ok(secrets
            .pop()
            .expect("one validated reference yields one secret"))
    }

    /// Atomically consumes an ordered group of owner-bound references.
    ///
    /// Every reference is validated while holding the same state lock. No
    /// valid entry is removed unless the complete group passes validation.
    pub async fn take_many(
        &self,
        owner: &str,
        references: &[EphemeralCredentialReference],
    ) -> Result<Vec<SecretValue>, CredentialError> {
        let now = Instant::now();
        let mut state = self.state.lock().await;
        let mut unique = HashSet::with_capacity(references.len());
        for reference in references {
            if !unique.insert(reference) {
                return Err(CredentialErrorCode::InvalidReference.into());
            }
            let Some(entry) = state.entries.get(reference) else {
                return Err(CredentialErrorCode::NotFound.into());
            };
            if now >= entry.expires_at {
                state.entries.remove(reference);
                return Err(CredentialErrorCode::Expired.into());
            }
            if entry.owner != owner {
                return Err(CredentialErrorCode::OwnerMismatch.into());
            }
        }
        Ok(references
            .iter()
            .map(|reference| {
                state
                    .entries
                    .remove(reference)
                    .expect("entry was validated while holding the same lock")
                    .secret
            })
            .collect())
    }

    pub async fn purge_owner(&self, owner: &str) -> usize {
        let mut state = self.state.lock().await;
        let before = state.entries.len();
        state.entries.retain(|_, entry| entry.owner != owner);
        before - state.entries.len()
    }

    pub async fn purge_expired(&self) -> usize {
        let now = Instant::now();
        let mut state = self.state.lock().await;
        let before = state.entries.len();
        state.entries.retain(|_, entry| entry.expires_at > now);
        before - state.entries.len()
    }

    pub async fn len(&self) -> usize {
        self.state.lock().await.entries.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.state.lock().await.entries.is_empty()
    }
}

impl Default for EphemeralCredentialStore {
    fn default() -> Self {
        Self::new(DEFAULT_EPHEMERAL_CREDENTIAL_TTL)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::sync::oneshot;
    use tokio::time::Instant;

    use super::{EphemeralCredentialStore, EphemeralEntry, EphemeralLimits};
    use crate::{CredentialErrorCode, SecretValue};

    fn secret(value: &str) -> SecretValue {
        SecretValue::from_utf8(value.to_owned()).expect("test secret")
    }

    #[tokio::test]
    async fn references_are_owner_bound_random_and_one_shot() {
        let store = EphemeralCredentialStore::default();
        let first = store.insert("main", secret("first")).await.expect("insert");
        let second = store
            .insert("main", secret("second"))
            .await
            .expect("insert");
        assert_ne!(first, second);
        assert!(first.to_string().starts_with("mem:v1:"));
        assert_eq!(
            store
                .take("other", &first)
                .await
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::OwnerMismatch)
        );
        let resolved = store.take("main", &first).await.expect("take");
        assert!(matches!(resolved.as_utf8(), Ok("first")));
        assert_eq!(
            store
                .take("main", &first)
                .await
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::NotFound)
        );
    }

    #[tokio::test]
    async fn take_many_is_atomic_when_any_reference_is_unavailable() {
        let store = EphemeralCredentialStore::default();
        let retained = store
            .insert("main", secret("retained"))
            .await
            .expect("insert retained entry");
        let missing = crate::EphemeralCredentialReference::new();

        let error = match store.take_many("main", &[retained, missing]).await {
            Ok(_) => panic!("missing peer must reject the batch"),
            Err(error) => error,
        };
        assert_eq!(error.code(), CredentialErrorCode::NotFound);
        assert_eq!(
            store
                .take("main", &retained)
                .await
                .expect("valid peer remains staged")
                .as_utf8(),
            Ok("retained")
        );
    }

    #[tokio::test]
    async fn owned_entries_are_purged() {
        let store = EphemeralCredentialStore::default();
        store.insert("main", secret("one")).await.expect("insert");
        store.insert("other", secret("two")).await.expect("insert");
        assert_eq!(store.purge_owner("main").await, 1);
        assert_eq!(store.len().await, 1);
        assert_eq!(store.purge_expired().await, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn expired_entries_are_removed_without_later_store_activity() {
        let store = EphemeralCredentialStore::new(Duration::from_millis(25));
        let reference = store.insert("main", secret("value")).await.expect("insert");
        assert_eq!(store.len().await, 1);

        tokio::time::advance(Duration::from_millis(24)).await;
        tokio::task::yield_now().await;
        assert_eq!(store.len().await, 1);

        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(store.is_empty().await);
        assert_eq!(
            store
                .take("main", &reference)
                .await
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::NotFound)
        );
    }

    #[tokio::test]
    async fn global_owner_and_byte_caps_return_a_stable_error() {
        let entry_limited = EphemeralCredentialStore::with_limits(
            Duration::from_secs(60),
            EphemeralLimits {
                global_entries: 2,
                entries_per_owner: 2,
                total_secret_bytes: 128,
            },
        );
        entry_limited
            .insert("first", secret("one"))
            .await
            .expect("first entry");
        entry_limited
            .insert("second", secret("two"))
            .await
            .expect("second entry");
        let error = entry_limited
            .insert("third", secret("three"))
            .await
            .expect_err("global entry cap");
        assert_eq!(error.code(), CredentialErrorCode::CapacityExceeded);
        assert_eq!(
            error.message(),
            "Staged credential storage capacity is exhausted"
        );
        assert_eq!(
            serde_json::to_value(&error).expect("serialize stable error"),
            serde_json::json!({
                "code": "capacityExceeded",
                "message": "Staged credential storage capacity is exhausted"
            })
        );

        let owner_limited = EphemeralCredentialStore::with_limits(
            Duration::from_secs(60),
            EphemeralLimits {
                global_entries: 3,
                entries_per_owner: 1,
                total_secret_bytes: 128,
            },
        );
        owner_limited
            .insert("main", secret("one"))
            .await
            .expect("owner entry");
        assert_eq!(
            owner_limited
                .insert("main", secret("two"))
                .await
                .expect_err("per-owner cap")
                .code(),
            CredentialErrorCode::CapacityExceeded
        );
        owner_limited
            .insert("other", secret("two"))
            .await
            .expect("different owner remains available");

        let byte_limited = EphemeralCredentialStore::with_limits(
            Duration::from_secs(60),
            EphemeralLimits {
                global_entries: 3,
                entries_per_owner: 3,
                total_secret_bytes: 5,
            },
        );
        byte_limited
            .insert("main", secret("123"))
            .await
            .expect("bytes below cap");
        assert_eq!(
            byte_limited
                .insert("other", secret("456"))
                .await
                .expect_err("total byte cap")
                .code(),
            CredentialErrorCode::CapacityExceeded
        );
    }

    #[tokio::test]
    async fn stale_expiry_generation_cannot_remove_a_replacement_reference() {
        let store = EphemeralCredentialStore::new(Duration::from_secs(60));
        let reference = store
            .insert("main", secret("original"))
            .await
            .expect("original entry");

        let mut state = store.state.lock().await;
        let original = state
            .entries
            .remove(&reference)
            .expect("original remains staged");
        let original_generation = original.generation;
        state.next_generation = state.next_generation.wrapping_add(1);
        let replacement_generation = state.next_generation;
        let replacement_expires_at = Instant::now() + Duration::from_secs(60);
        let (expiry_cancel, _expiry_cancelled) = oneshot::channel();
        state.entries.insert(
            reference,
            EphemeralEntry {
                owner: "main".to_owned(),
                expires_at: replacement_expires_at,
                generation: replacement_generation,
                _expiry_cancel: expiry_cancel,
                secret: secret("replacement"),
            },
        );

        assert!(!state.remove_expired_generation(
            &reference,
            original_generation,
            replacement_expires_at + Duration::from_secs(1)
        ));
        drop(state);
        drop(original);

        let replacement = store
            .take("main", &reference)
            .await
            .expect("replacement survives stale expiry");
        assert_eq!(replacement.as_utf8(), Ok("replacement"));
    }
}
