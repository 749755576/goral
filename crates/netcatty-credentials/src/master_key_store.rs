use std::sync::Arc;

use netcatty_secret_store::EnvelopeMasterKey;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use uuid::{Uuid, Version};
use zeroize::Zeroizing;

use crate::os_store::{
    BlockingCredentialBackend, KeyringBackend, SecretBlob, global_operation_lock,
    run_blocking_with_lock,
};
use crate::{CredentialError, CredentialErrorCode};

pub const SECRET_BLOB_MASTER_KEY_SERVICE: &str = "app.netcatty.secret-blobs.v1";
pub const MASTER_KEY_BYTES: usize = 32;

const ACCOUNT_PREFIX: &str = "master:";
const ENVELOPE_MAGIC: &[u8; 8] = b"NCATMKEY";
const ENVELOPE_VERSION: u8 = 1;
const STORE_ID_OFFSET: usize = ENVELOPE_MAGIC.len() + 1;
const EPOCH_OFFSET: usize = STORE_ID_OFFSET + 16;
const KEY_OFFSET: usize = EPOCH_OFFSET + 4;
const CHECKSUM_OFFSET: usize = KEY_OFFSET + MASTER_KEY_BYTES;
const CHECKSUM_BYTES: usize = 32;
const CHECKSUM_DOMAIN: &[u8] = b"netcatty-os-master-key-envelope-v1\0";
pub const MASTER_KEY_ENVELOPE_BYTES: usize = CHECKSUM_OFFSET + CHECKSUM_BYTES;

/// OS-keyring custody for the small root key used by the encrypted secret-blob
/// store. Large encrypted blobs deliberately do not pass through this type.
///
/// The store has no `Debug` implementation because its backend owns
/// secret-bearing envelopes and account identifiers.
#[derive(Clone)]
pub struct OsMasterKeyStore {
    backend: Arc<dyn BlockingCredentialBackend>,
    operation_lock: Arc<Mutex<()>>,
}

impl OsMasterKeyStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            backend: Arc::new(KeyringBackend),
            operation_lock: global_operation_lock(),
        }
    }

    /// Returns the existing key or creates exactly one securely random key
    /// after the backend has authoritatively reported that the account is
    /// absent. Corrupt, ambiguous, or otherwise unreadable records are never
    /// overwritten.
    ///
    /// The global operation lock makes this atomic among instances in the
    /// current process. Native keyring upsert APIs do not provide a portable
    /// cross-process create-new primitive, so the future secret-blob owner
    /// must hold its cross-process transaction/file lock around first use.
    pub async fn create_if_absent(
        &self,
        store_id: Uuid,
        epoch: u32,
    ) -> Result<EnvelopeMasterKey, CredentialError> {
        validate_locator(store_id, epoch)?;
        let account = account_for(store_id, epoch);
        let backend = self.backend.clone();
        run_blocking_with_lock(self.operation_lock.clone(), move || {
            match backend.resolve(SECRET_BLOB_MASTER_KEY_SERVICE, account.clone()) {
                Ok(envelope) => decode_envelope(envelope, store_id, epoch),
                Err(error) if error.code() == CredentialErrorCode::NotFound => {
                    create_missing_key(backend.as_ref(), account, store_id, epoch)
                }
                Err(error) => Err(error),
            }
        })
        .await
    }

    /// Blocking-worker-only counterpart to [`Self::create_if_absent`].
    ///
    /// The desktop secret-store coordinator uses this while retaining the
    /// non-`Send` file-store guard on the same blocking thread. The shared
    /// operation lock keeps it serialized with every async keyring call.
    pub fn create_if_absent_blocking(
        &self,
        store_id: Uuid,
        epoch: u32,
    ) -> Result<EnvelopeMasterKey, CredentialError> {
        validate_locator(store_id, epoch)?;
        let account = account_for(store_id, epoch);
        let backend = self.backend.clone();
        self.run_blocking_now(move || {
            match backend.resolve(SECRET_BLOB_MASTER_KEY_SERVICE, account.clone()) {
                Ok(envelope) => decode_envelope(envelope, store_id, epoch),
                Err(error) if error.code() == CredentialErrorCode::NotFound => {
                    create_missing_key(backend.as_ref(), account, store_id, epoch)
                }
                Err(error) => Err(error),
            }
        })
    }

    pub async fn load(
        &self,
        store_id: Uuid,
        epoch: u32,
    ) -> Result<EnvelopeMasterKey, CredentialError> {
        validate_locator(store_id, epoch)?;
        let account = account_for(store_id, epoch);
        let backend = self.backend.clone();
        run_blocking_with_lock(self.operation_lock.clone(), move || {
            let envelope = backend.resolve(SECRET_BLOB_MASTER_KEY_SERVICE, account)?;
            decode_envelope(envelope, store_id, epoch)
        })
        .await
    }

    /// Blocking-worker-only counterpart to [`Self::load`].
    pub fn load_blocking(
        &self,
        store_id: Uuid,
        epoch: u32,
    ) -> Result<EnvelopeMasterKey, CredentialError> {
        validate_locator(store_id, epoch)?;
        let account = account_for(store_id, epoch);
        let backend = self.backend.clone();
        self.run_blocking_now(move || {
            let envelope = backend.resolve(SECRET_BLOB_MASTER_KEY_SERVICE, account)?;
            decode_envelope(envelope, store_id, epoch)
        })
    }

    /// Deletes only a valid envelope for the requested store and epoch.
    /// Missing records are successful no-ops; malformed or mismatched records
    /// remain untouched for explicit repair.
    pub async fn delete(&self, store_id: Uuid, epoch: u32) -> Result<(), CredentialError> {
        validate_locator(store_id, epoch)?;
        let account = account_for(store_id, epoch);
        let backend = self.backend.clone();
        run_blocking_with_lock(self.operation_lock.clone(), move || {
            match backend.resolve(SECRET_BLOB_MASTER_KEY_SERVICE, account.clone()) {
                Ok(envelope) => {
                    let _validated = decode_envelope(envelope, store_id, epoch)?;
                    match backend.delete(SECRET_BLOB_MASTER_KEY_SERVICE, account) {
                        Err(error) if error.code() == CredentialErrorCode::NotFound => Ok(()),
                        result => result,
                    }
                }
                Err(error) if error.code() == CredentialErrorCode::NotFound => Ok(()),
                Err(error) => Err(error),
            }
        })
        .await
    }

    /// Blocking-worker-only counterpart to [`Self::delete`].
    pub fn delete_blocking(&self, store_id: Uuid, epoch: u32) -> Result<(), CredentialError> {
        validate_locator(store_id, epoch)?;
        let account = account_for(store_id, epoch);
        let backend = self.backend.clone();
        self.run_blocking_now(move || {
            match backend.resolve(SECRET_BLOB_MASTER_KEY_SERVICE, account.clone()) {
                Ok(envelope) => {
                    let _validated = decode_envelope(envelope, store_id, epoch)?;
                    match backend.delete(SECRET_BLOB_MASTER_KEY_SERVICE, account) {
                        Err(error) if error.code() == CredentialErrorCode::NotFound => Ok(()),
                        result => result,
                    }
                }
                Err(error) if error.code() == CredentialErrorCode::NotFound => Ok(()),
                Err(error) => Err(error),
            }
        })
    }

    fn run_blocking_now<T, F>(&self, operation: F) -> Result<T, CredentialError>
    where
        F: FnOnce() -> Result<T, CredentialError>,
    {
        let _guard = self.operation_lock.clone().blocking_lock_owned();
        operation()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn with_backend(backend: Arc<dyn BlockingCredentialBackend>) -> Self {
        Self {
            backend,
            operation_lock: global_operation_lock(),
        }
    }
}

impl Default for OsMasterKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

fn create_missing_key(
    backend: &dyn BlockingCredentialBackend,
    account: String,
    store_id: Uuid,
    epoch: u32,
) -> Result<EnvelopeMasterKey, CredentialError> {
    let generated = EnvelopeMasterKey::generate()
        .map_err(|_| CredentialError::new(CredentialErrorCode::BackendFailure))?;
    let envelope = encode_envelope(&generated, store_id, epoch);
    match backend.upsert(SECRET_BLOB_MASTER_KEY_SERVICE, account.clone(), envelope) {
        Ok(()) => verify_persisted_key(backend, account, store_id, epoch, &generated),
        Err(write_error) => match backend.resolve(SECRET_BLOB_MASTER_KEY_SERVICE, account) {
            Ok(persisted) => {
                let persisted = decode_envelope(persisted, store_id, epoch)?;
                if bool::from(persisted.as_bytes().ct_eq(generated.as_bytes())) {
                    Ok(persisted)
                } else {
                    Err(CredentialErrorCode::Conflict.into())
                }
            }
            Err(error) if error.code() == CredentialErrorCode::NotFound => Err(write_error),
            Err(error) => Err(error),
        },
    }
}

fn verify_persisted_key(
    backend: &dyn BlockingCredentialBackend,
    account: String,
    store_id: Uuid,
    epoch: u32,
    expected: &EnvelopeMasterKey,
) -> Result<EnvelopeMasterKey, CredentialError> {
    let persisted = backend
        .resolve(SECRET_BLOB_MASTER_KEY_SERVICE, account)
        .map_err(|error| {
            if error.code() == CredentialErrorCode::NotFound {
                CredentialError::new(CredentialErrorCode::BackendFailure)
            } else {
                error
            }
        })?;
    let persisted = decode_envelope(persisted, store_id, epoch)?;
    if bool::from(persisted.as_bytes().ct_eq(expected.as_bytes())) {
        Ok(persisted)
    } else {
        Err(CredentialErrorCode::Conflict.into())
    }
}

fn account_for(store_id: Uuid, epoch: u32) -> String {
    format!("{ACCOUNT_PREFIX}{}:{epoch:08x}", store_id.simple())
}

fn validate_locator(store_id: Uuid, epoch: u32) -> Result<(), CredentialError> {
    if store_id.get_version() == Some(Version::Random) && epoch != 0 {
        Ok(())
    } else {
        Err(CredentialErrorCode::InvalidReference.into())
    }
}

fn encode_envelope(key: &EnvelopeMasterKey, store_id: Uuid, epoch: u32) -> SecretBlob {
    let mut envelope = Zeroizing::new(Vec::with_capacity(MASTER_KEY_ENVELOPE_BYTES));
    envelope.extend_from_slice(ENVELOPE_MAGIC);
    envelope.push(ENVELOPE_VERSION);
    envelope.extend_from_slice(store_id.as_bytes());
    envelope.extend_from_slice(&epoch.to_be_bytes());
    envelope.extend_from_slice(key.as_bytes());
    let checksum = envelope_checksum(&envelope);
    envelope.extend_from_slice(&checksum);
    debug_assert_eq!(envelope.len(), MASTER_KEY_ENVELOPE_BYTES);
    envelope
}

fn decode_envelope(
    envelope: SecretBlob,
    expected_store_id: Uuid,
    expected_epoch: u32,
) -> Result<EnvelopeMasterKey, CredentialError> {
    if envelope.len() != MASTER_KEY_ENVELOPE_BYTES
        || envelope.get(..ENVELOPE_MAGIC.len()) != Some(ENVELOPE_MAGIC.as_slice())
        || envelope[ENVELOPE_MAGIC.len()] != ENVELOPE_VERSION
    {
        return Err(CredentialErrorCode::CorruptRecord.into());
    }

    let expected_checksum = envelope_checksum(&envelope[..CHECKSUM_OFFSET]);
    if !bool::from(envelope[CHECKSUM_OFFSET..].ct_eq(&expected_checksum))
        || envelope[STORE_ID_OFFSET..EPOCH_OFFSET] != expected_store_id.as_bytes()[..]
        || envelope[EPOCH_OFFSET..KEY_OFFSET] != expected_epoch.to_be_bytes()
    {
        return Err(CredentialErrorCode::CorruptRecord.into());
    }

    let mut key = Zeroizing::new([0_u8; MASTER_KEY_BYTES]);
    key.copy_from_slice(&envelope[KEY_OFFSET..CHECKSUM_OFFSET]);
    EnvelopeMasterKey::from_zeroizing(key)
        .map_err(|_| CredentialError::new(CredentialErrorCode::CorruptRecord))
}

fn envelope_checksum(bytes: &[u8]) -> [u8; CHECKSUM_BYTES] {
    let mut digest = Sha256::new();
    digest.update(CHECKSUM_DOMAIN);
    digest.update(bytes);
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{
        CHECKSUM_OFFSET, ENVELOPE_MAGIC, ENVELOPE_VERSION, KEY_OFFSET, MASTER_KEY_ENVELOPE_BYTES,
        OsMasterKeyStore, SECRET_BLOB_MASTER_KEY_SERVICE, account_for, decode_envelope,
        encode_envelope, envelope_checksum,
    };
    use crate::test_support::{CredentialOperation, FailureTiming, in_memory_master_key_store};
    use crate::{CredentialErrorCode, MasterKey};
    use subtle::ConstantTimeEq;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    fn key(marker: u8) -> MasterKey {
        MasterKey::from_bytes([marker; 32]).expect("test master key")
    }

    fn assert_same_key(left: &MasterKey, right: &MasterKey) {
        assert!(bool::from(left.as_bytes().ct_eq(right.as_bytes())));
    }

    fn exercise_blocking_master_key_lifecycle(store: OsMasterKeyStore, store_id: Uuid, epoch: u32) {
        let created = store
            .create_if_absent_blocking(store_id, epoch)
            .expect("create blocking master key");
        let repeated = store
            .create_if_absent_blocking(store_id, epoch)
            .expect("load existing blocking master key");
        let loaded = store
            .load_blocking(store_id, epoch)
            .expect("load blocking master key");
        assert_same_key(&created, &repeated);
        assert_same_key(&created, &loaded);
        store
            .delete_blocking(store_id, epoch)
            .expect("delete blocking master key");
        store
            .delete_blocking(store_id, epoch)
            .expect("idempotent blocking master-key delete");
        assert_eq!(
            store
                .load_blocking(store_id, epoch)
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::NotFound)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn create_load_repeat_and_idempotent_delete_use_one_strict_account() {
        let (store, controller) = in_memory_master_key_store();
        let store_id = Uuid::new_v4();
        let epoch = 0x01ab_cdef;
        let account = account_for(store_id, epoch);
        assert_eq!(account, format!("master:{}:01abcdef", store_id.simple()));
        assert_eq!(account.len(), "master:".len() + 32 + 1 + 8);
        assert!(
            account
                .bytes()
                .all(|byte| !byte.is_ascii_uppercase() && !byte.is_ascii_whitespace())
        );

        let created = store
            .create_if_absent(store_id, epoch)
            .await
            .expect("create master key");
        let repeated = store
            .create_if_absent(store_id, epoch)
            .await
            .expect("return existing master key");
        let loaded = store.load(store_id, epoch).await.expect("load master key");
        assert_same_key(&created, &repeated);
        assert_same_key(&created, &loaded);
        assert_eq!(controller.operation_count(CredentialOperation::Upsert), 1);

        let raw = controller
            .raw_value(SECRET_BLOB_MASTER_KEY_SERVICE, &account)
            .expect("stored master-key envelope");
        assert_eq!(raw.len(), MASTER_KEY_ENVELOPE_BYTES);
        assert!(raw.len() < 128);
        assert_eq!(&raw[..ENVELOPE_MAGIC.len()], ENVELOPE_MAGIC);
        assert_eq!(raw[ENVELOPE_MAGIC.len()], ENVELOPE_VERSION);
        assert!(
            controller
                .raw_value("app.netcatty.credentials.v1", &account)
                .is_none()
        );

        store
            .delete(store_id, epoch)
            .await
            .expect("delete master key");
        store
            .delete(store_id, epoch)
            .await
            .expect("idempotent missing delete");
        assert_eq!(controller.operation_count(CredentialOperation::Delete), 1);
        assert_eq!(
            store
                .load(store_id, epoch)
                .await
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::NotFound)
        );
    }

    #[tokio::test]
    async fn invalid_store_or_epoch_is_rejected_before_any_backend_operation() {
        let (store, controller) = in_memory_master_key_store();
        let valid_store_id = Uuid::new_v4();
        let invalid_store_id = Uuid::nil();

        for code in [
            store
                .create_if_absent(invalid_store_id, 1)
                .await
                .err()
                .map(|error| error.code()),
            store
                .load(invalid_store_id, 1)
                .await
                .err()
                .map(|error| error.code()),
            store
                .delete(invalid_store_id, 1)
                .await
                .err()
                .map(|error| error.code()),
            store
                .create_if_absent(valid_store_id, 0)
                .await
                .err()
                .map(|error| error.code()),
            store
                .load(valid_store_id, 0)
                .await
                .err()
                .map(|error| error.code()),
            store
                .delete(valid_store_id, 0)
                .await
                .err()
                .map(|error| error.code()),
        ] {
            assert_eq!(code, Some(CredentialErrorCode::InvalidReference));
        }
        assert!(controller.operation_log().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_create_in_one_process_publishes_only_one_key() {
        let (store, controller) = in_memory_master_key_store();
        let store_id = Uuid::new_v4();
        let epoch = 7;
        let mut tasks = Vec::new();
        for _ in 0..24 {
            let store = store.clone();
            tasks.push(tokio::spawn(async move {
                store.create_if_absent(store_id, epoch).await
            }));
        }

        let mut keys = Vec::new();
        for task in tasks {
            keys.push(task.await.expect("create task").expect("concurrent create"));
        }
        let first = keys.pop().expect("at least one key");
        for candidate in &keys {
            assert_same_key(&first, candidate);
        }
        assert_eq!(controller.operation_count(CredentialOperation::Upsert), 1);
        assert_eq!(controller.max_concurrent_operations(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn blocking_master_key_api_round_trips_from_spawn_blocking_and_ordinary_threads() {
        let (store, _) = in_memory_master_key_store();

        let blocking_worker_store = store.clone();
        tokio::task::spawn_blocking(move || {
            exercise_blocking_master_key_lifecycle(blocking_worker_store, Uuid::new_v4(), 1);
        })
        .await
        .expect("blocking master-key worker");

        let ordinary_thread_store = store.clone();
        std::thread::spawn(move || {
            exercise_blocking_master_key_lifecycle(ordinary_thread_store, Uuid::new_v4(), 2);
        })
        .join()
        .expect("ordinary master-key thread");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn blocking_and_async_master_key_calls_share_one_operation_lock() {
        let (store, controller) = in_memory_master_key_store();
        let async_load = (Uuid::new_v4(), 3);
        let blocking_load = (Uuid::new_v4(), 4);
        let async_delete = (Uuid::new_v4(), 5);
        let blocking_delete = (Uuid::new_v4(), 6);
        for (store_id, epoch) in [async_load, blocking_load, async_delete, blocking_delete] {
            store
                .create_if_absent(store_id, epoch)
                .await
                .expect("seed master key");
        }

        let start = Arc::new(tokio::sync::Barrier::new(7));
        let mut tasks = Vec::new();

        let async_store = store.clone();
        let async_start = start.clone();
        tasks.push(tokio::spawn(async move {
            async_start.wait().await;
            async_store
                .create_if_absent(Uuid::new_v4(), 7)
                .await
                .map(|_| ())
        }));

        let async_store = store.clone();
        let async_start = start.clone();
        tasks.push(tokio::spawn(async move {
            async_start.wait().await;
            async_store
                .load(async_load.0, async_load.1)
                .await
                .map(|_| ())
        }));

        let async_store = store.clone();
        let async_start = start.clone();
        tasks.push(tokio::spawn(async move {
            async_start.wait().await;
            async_store.delete(async_delete.0, async_delete.1).await
        }));

        let runtime = tokio::runtime::Handle::current();
        let blocking_store = store.clone();
        let blocking_start = start.clone();
        let blocking_runtime = runtime.clone();
        tasks.push(tokio::task::spawn_blocking(move || {
            blocking_runtime.block_on(blocking_start.wait());
            blocking_store
                .create_if_absent_blocking(Uuid::new_v4(), 8)
                .map(|_| ())
        }));

        let blocking_store = store.clone();
        let blocking_start = start.clone();
        let blocking_runtime = runtime.clone();
        tasks.push(tokio::task::spawn_blocking(move || {
            blocking_runtime.block_on(blocking_start.wait());
            blocking_store
                .load_blocking(blocking_load.0, blocking_load.1)
                .map(|_| ())
        }));

        let blocking_store = store.clone();
        let blocking_start = start.clone();
        tasks.push(tokio::task::spawn_blocking(move || {
            runtime.block_on(blocking_start.wait());
            blocking_store.delete_blocking(blocking_delete.0, blocking_delete.1)
        }));

        start.wait().await;
        for task in tasks {
            task.await
                .expect("master-key task")
                .expect("master-key call");
        }
        assert_eq!(controller.max_concurrent_operations(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn blocking_master_key_api_never_replaces_or_deletes_corrupt_records() {
        let store_id = Uuid::new_v4();
        let epoch = 9;
        let account = account_for(store_id, epoch);
        let (store, controller) = in_memory_master_key_store();
        let corrupt = vec![0xa5; MASTER_KEY_ENVELOPE_BYTES - 1];
        controller.replace_raw_value(
            SECRET_BLOB_MASTER_KEY_SERVICE,
            account.clone(),
            corrupt.clone(),
        );

        let blocking_store = store.clone();
        let codes = tokio::task::spawn_blocking(move || {
            [
                blocking_store
                    .create_if_absent_blocking(store_id, epoch)
                    .err()
                    .map(|error| error.code()),
                blocking_store
                    .load_blocking(store_id, epoch)
                    .err()
                    .map(|error| error.code()),
                blocking_store
                    .delete_blocking(store_id, epoch)
                    .err()
                    .map(|error| error.code()),
            ]
        })
        .await
        .expect("corrupt master-key task");
        assert_eq!(codes, [Some(CredentialErrorCode::CorruptRecord); 3]);
        assert_eq!(controller.operation_count(CredentialOperation::Upsert), 0);
        assert_eq!(controller.operation_count(CredentialOperation::Delete), 0);
        let retained = controller
            .raw_value(SECRET_BLOB_MASTER_KEY_SERVICE, &account)
            .expect("corrupt record retained");
        assert!(bool::from(retained.ct_eq(corrupt.as_slice())));
    }

    #[test]
    fn fixed_envelope_rejects_truncation_tampering_unknown_versions_and_wrong_context() {
        let store_id = Uuid::new_v4();
        let other_store_id = Uuid::new_v4();
        let epoch = 9;
        let original_key = key(0x5a);
        let valid = encode_envelope(&original_key, store_id, epoch);
        let decoded = decode_envelope(valid.clone(), store_id, epoch).expect("valid envelope");
        assert_same_key(&original_key, &decoded);

        for length in 0..MASTER_KEY_ENVELOPE_BYTES {
            assert_eq!(
                decode_envelope(Zeroizing::new(valid[..length].to_vec()), store_id, epoch,)
                    .err()
                    .map(|error| error.code()),
                Some(CredentialErrorCode::CorruptRecord)
            );
        }

        for offset in 0..MASTER_KEY_ENVELOPE_BYTES {
            let mut tampered = valid.clone();
            tampered[offset] ^= 0x80;
            assert_eq!(
                decode_envelope(tampered, store_id, epoch)
                    .err()
                    .map(|error| error.code()),
                Some(CredentialErrorCode::CorruptRecord)
            );
        }

        let mut unknown_version = valid.clone();
        unknown_version[ENVELOPE_MAGIC.len()] = ENVELOPE_VERSION + 1;
        let checksum = envelope_checksum(&unknown_version[..CHECKSUM_OFFSET]);
        unknown_version[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        assert_eq!(
            decode_envelope(unknown_version, store_id, epoch)
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::CorruptRecord)
        );
        assert_eq!(
            decode_envelope(valid.clone(), other_store_id, epoch)
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::CorruptRecord)
        );
        assert_eq!(
            decode_envelope(valid.clone(), store_id, epoch + 1)
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::CorruptRecord)
        );

        let mut zero_key = valid;
        zero_key[KEY_OFFSET..CHECKSUM_OFFSET].fill(0);
        let checksum = envelope_checksum(&zero_key[..CHECKSUM_OFFSET]);
        zero_key[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        assert_eq!(
            decode_envelope(zero_key, store_id, epoch)
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::CorruptRecord)
        );
    }

    #[tokio::test]
    async fn corrupt_conflicting_or_cross_context_records_are_never_overwritten_or_deleted() {
        let store_id = Uuid::new_v4();
        let epoch = 3;
        let account = account_for(store_id, epoch);
        let (store, controller) = in_memory_master_key_store();
        let corrupt = vec![0xa5; MASTER_KEY_ENVELOPE_BYTES - 1];
        controller.replace_raw_value(
            SECRET_BLOB_MASTER_KEY_SERVICE,
            account.clone(),
            corrupt.clone(),
        );

        for code in [
            store
                .create_if_absent(store_id, epoch)
                .await
                .err()
                .map(|error| error.code()),
            store
                .load(store_id, epoch)
                .await
                .err()
                .map(|error| error.code()),
            store
                .delete(store_id, epoch)
                .await
                .err()
                .map(|error| error.code()),
        ] {
            assert_eq!(code, Some(CredentialErrorCode::CorruptRecord));
        }
        assert_eq!(controller.operation_count(CredentialOperation::Upsert), 0);
        assert_eq!(controller.operation_count(CredentialOperation::Delete), 0);
        let retained = controller
            .raw_value(SECRET_BLOB_MASTER_KEY_SERVICE, &account)
            .expect("corrupt record retained");
        assert!(bool::from(retained.ct_eq(corrupt.as_slice())));

        let (conflict_store, conflict_controller) = in_memory_master_key_store();
        conflict_controller.set_failure(
            CredentialOperation::Resolve,
            1,
            FailureTiming::BeforeSideEffect,
            CredentialErrorCode::Conflict,
        );
        assert_eq!(
            conflict_store
                .create_if_absent(Uuid::new_v4(), 1)
                .await
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::Conflict)
        );
        assert_eq!(
            conflict_controller.operation_count(CredentialOperation::Upsert),
            0
        );

        for (stored_store_id, stored_epoch, requested_store_id, requested_epoch) in [
            (Uuid::new_v4(), 5, Uuid::new_v4(), 5),
            (Uuid::new_v4(), 5, Uuid::new_v4(), 6),
        ] {
            let stored_store_id = if stored_epoch == requested_epoch {
                stored_store_id
            } else {
                requested_store_id
            };
            let (store, controller) = in_memory_master_key_store();
            let account = account_for(requested_store_id, requested_epoch);
            let envelope = encode_envelope(&key(0x35), stored_store_id, stored_epoch);
            controller.replace_raw_value(
                SECRET_BLOB_MASTER_KEY_SERVICE,
                account,
                envelope.to_vec(),
            );
            assert_eq!(
                store
                    .create_if_absent(requested_store_id, requested_epoch)
                    .await
                    .err()
                    .map(|error| error.code()),
                Some(CredentialErrorCode::CorruptRecord)
            );
            assert_eq!(controller.operation_count(CredentialOperation::Upsert), 0);
        }
    }

    #[tokio::test]
    async fn create_and_delete_faults_have_deterministic_recovery_semantics() {
        let store_id = Uuid::new_v4();
        let epoch = 11;
        let account = account_for(store_id, epoch);

        let (store, controller) = in_memory_master_key_store();
        controller.set_failure(
            CredentialOperation::Upsert,
            1,
            FailureTiming::BeforeSideEffect,
            CredentialErrorCode::BackendFailure,
        );
        assert_eq!(
            store
                .create_if_absent(store_id, epoch)
                .await
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::BackendFailure)
        );
        assert!(
            controller
                .raw_value(SECRET_BLOB_MASTER_KEY_SERVICE, &account)
                .is_none()
        );

        let (store, controller) = in_memory_master_key_store();
        controller.set_failure(
            CredentialOperation::Upsert,
            1,
            FailureTiming::AfterSideEffect,
            CredentialErrorCode::BackendFailure,
        );
        let recovered = store
            .create_if_absent(store_id, epoch)
            .await
            .expect("recover an after-write failure by exact reread");
        let loaded = store
            .load(store_id, epoch)
            .await
            .expect("load recovered key");
        assert_same_key(&recovered, &loaded);
        assert_eq!(controller.operation_count(CredentialOperation::Upsert), 1);

        controller.set_failure(
            CredentialOperation::Resolve,
            1,
            FailureTiming::BeforeSideEffect,
            CredentialErrorCode::StorageUnavailable,
        );
        assert_eq!(
            store
                .delete(store_id, epoch)
                .await
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::StorageUnavailable)
        );
        controller.clear_failures();
        assert!(store.load(store_id, epoch).await.is_ok());

        controller.set_failure(
            CredentialOperation::Delete,
            1,
            FailureTiming::BeforeSideEffect,
            CredentialErrorCode::BackendFailure,
        );
        assert_eq!(
            store
                .delete(store_id, epoch)
                .await
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::BackendFailure)
        );
        controller.clear_failures();
        assert!(store.load(store_id, epoch).await.is_ok());

        controller.set_failure(
            CredentialOperation::Delete,
            1,
            FailureTiming::AfterSideEffect,
            CredentialErrorCode::BackendFailure,
        );
        assert_eq!(
            store
                .delete(store_id, epoch)
                .await
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::BackendFailure)
        );
        controller.clear_failures();
        store
            .delete(store_id, epoch)
            .await
            .expect("retry delete after side effect");
    }

    #[tokio::test]
    async fn diagnostics_are_fixed_and_never_expose_key_account_or_backend_values() {
        let (store, controller) = in_memory_master_key_store();
        let store_id = Uuid::new_v4();
        let epoch = 0x1234_abcd;
        let account = account_for(store_id, epoch);
        let known_key = key(0x7a);
        let key_marker = "7a".repeat(32);
        let debug_key = format!("{known_key:?}");
        assert!(!debug_key.contains(&key_marker));
        assert!(debug_key.contains("REDACTED"));

        let error = store
            .load(store_id, epoch)
            .await
            .err()
            .expect("missing key error");
        let store_id_marker = store_id.to_string();
        let rendered = format!(
            "{error:?} {error} {controller:?} {:?}",
            controller.operation_log()
        );
        for forbidden in [
            key_marker.as_str(),
            account.as_str(),
            store_id_marker.as_str(),
            "backend-secret-value-sentinel",
        ] {
            assert!(!rendered.contains(forbidden));
        }
        let json = serde_json::to_string(&error).expect("fixed error JSON");
        assert!(!json.contains(&account));
        assert!(!json.contains(&key_marker));
    }

    #[cfg(all(target_os = "windows", feature = "os-credential-tests"))]
    #[tokio::test(flavor = "multi_thread")]
    async fn windows_master_key_round_trip_uses_dedicated_service() {
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                if let Ok(entry) = keyring::Entry::new(SECRET_BLOB_MASTER_KEY_SERVICE, &self.0) {
                    let _ = entry.delete_credential();
                }
            }
        }

        let store = OsMasterKeyStore::new();
        let store_id = Uuid::new_v4();
        let epoch = 1;
        let account = account_for(store_id, epoch);
        let _cleanup = Cleanup(account.clone());
        let entry = keyring::Entry::new(SECRET_BLOB_MASTER_KEY_SERVICE, &account)
            .expect("Windows master-key entry");
        assert!(
            entry
                .get_credential()
                .downcast_ref::<keyring::windows::WinCredential>()
                .is_some()
        );
        store
            .delete(store_id, epoch)
            .await
            .expect("initial cleanup");
        let created = store
            .create_if_absent(store_id, epoch)
            .await
            .expect("Windows master-key create");
        let repeated = store
            .create_if_absent(store_id, epoch)
            .await
            .expect("Windows existing master key");
        let loaded = store
            .load(store_id, epoch)
            .await
            .expect("Windows master-key load");
        assert_same_key(&created, &repeated);
        assert_same_key(&created, &loaded);
        store.delete(store_id, epoch).await.expect("Windows delete");
        store
            .delete(store_id, epoch)
            .await
            .expect("idempotent Windows delete");
    }
}
