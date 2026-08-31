use std::sync::{Arc, OnceLock};

use tokio::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

use crate::{CredentialError, CredentialErrorCode, SecretValue, StoredCredentialReference};

pub(crate) const SERVICE_NAME: &str = "app.netcatty.credentials.v1";
const ACCOUNT_PREFIX: &str = "credential:";
const ENVELOPE_MAGIC: &[u8; 8] = b"NCATCRED";
const ENVELOPE_VERSION: u8 = 1;
const ENVELOPE_HEADER_BYTES: usize = 8 + 1 + 1 + 4;
const WINDOWS_CREDENTIAL_BLOB_LIMIT: usize = 2_560;
pub const MAX_PERSISTENT_SECRET_BYTES: usize = 2_048;

pub(crate) type SecretBlob = Zeroizing<Vec<u8>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    SshPassword,
    ProxyPassword,
    TelnetPassword,
    AiApiKey,
}

impl CredentialKind {
    const fn tag(self) -> u8 {
        match self {
            Self::SshPassword => 1,
            Self::ProxyPassword => 2,
            Self::TelnetPassword => 3,
            Self::AiApiKey => 4,
        }
    }
}

pub(crate) trait BlockingCredentialBackend: Send + Sync + 'static {
    fn upsert(
        &self,
        service: &'static str,
        account: String,
        secret: SecretBlob,
    ) -> Result<(), CredentialError>;
    fn resolve(
        &self,
        service: &'static str,
        account: String,
    ) -> Result<SecretBlob, CredentialError>;
    fn delete(&self, service: &'static str, account: String) -> Result<(), CredentialError>;
}

pub(crate) struct KeyringBackend;

impl KeyringBackend {
    fn entry(service: &str, account: &str) -> Result<keyring::Entry, CredentialError> {
        keyring::Entry::new(service, account).map_err(map_keyring_error)
    }
}

impl BlockingCredentialBackend for KeyringBackend {
    fn upsert(
        &self,
        service: &'static str,
        account: String,
        secret: SecretBlob,
    ) -> Result<(), CredentialError> {
        Self::entry(service, &account)?
            .set_secret(secret.as_slice())
            .map_err(map_keyring_error)
    }

    fn resolve(
        &self,
        service: &'static str,
        account: String,
    ) -> Result<SecretBlob, CredentialError> {
        Self::entry(service, &account)?
            .get_secret()
            .map(Zeroizing::new)
            .map_err(map_keyring_error)
    }

    fn delete(&self, service: &'static str, account: String) -> Result<(), CredentialError> {
        Self::entry(service, &account)?
            .delete_credential()
            .map_err(map_keyring_error)
    }
}

static GLOBAL_OS_CREDENTIAL_LOCK: OnceLock<Arc<Mutex<()>>> = OnceLock::new();

pub(crate) fn global_operation_lock() -> Arc<Mutex<()>> {
    GLOBAL_OS_CREDENTIAL_LOCK
        .get_or_init(|| Arc::new(Mutex::new(())))
        .clone()
}

#[derive(Clone)]
pub struct OsCredentialStore {
    backend: Arc<dyn BlockingCredentialBackend>,
    operation_lock: Arc<Mutex<()>>,
}

impl OsCredentialStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            backend: Arc::new(KeyringBackend),
            operation_lock: global_operation_lock(),
        }
    }

    pub async fn upsert(
        &self,
        reference: &StoredCredentialReference,
        kind: CredentialKind,
        secret: SecretValue,
    ) -> Result<(), CredentialError> {
        let account = account_for(reference);
        let blob = encode_envelope(kind, secret)?;
        let backend = self.backend.clone();
        self.run_blocking(move || backend.upsert(SERVICE_NAME, account, blob))
            .await
    }

    /// Synchronous counterpart used by a detached storage coordinator that
    /// already runs on a blocking worker and must retain another non-`Send`
    /// cross-process guard for the whole transaction.
    ///
    /// This method shares the same process-wide operation lock as the async
    /// API. It must not be called directly from an asynchronous runtime
    /// worker; use it only from `spawn_blocking` or an ordinary OS thread.
    pub fn upsert_blocking(
        &self,
        reference: &StoredCredentialReference,
        kind: CredentialKind,
        secret: SecretValue,
    ) -> Result<(), CredentialError> {
        let account = account_for(reference);
        let blob = encode_envelope(kind, secret)?;
        let backend = self.backend.clone();
        self.run_blocking_now(move || backend.upsert(SERVICE_NAME, account, blob))
    }

    pub async fn resolve(
        &self,
        reference: &StoredCredentialReference,
        expected_kind: CredentialKind,
    ) -> Result<SecretValue, CredentialError> {
        let account = account_for(reference);
        let backend = self.backend.clone();
        let blob = self
            .run_blocking(move || backend.resolve(SERVICE_NAME, account))
            .await?;
        decode_envelope(blob, expected_kind)
    }

    /// Blocking-worker-only counterpart to [`Self::resolve`].
    pub fn resolve_blocking(
        &self,
        reference: &StoredCredentialReference,
        expected_kind: CredentialKind,
    ) -> Result<SecretValue, CredentialError> {
        let account = account_for(reference);
        let backend = self.backend.clone();
        let blob = self.run_blocking_now(move || backend.resolve(SERVICE_NAME, account))?;
        decode_envelope(blob, expected_kind)
    }

    pub async fn delete(
        &self,
        reference: &StoredCredentialReference,
    ) -> Result<(), CredentialError> {
        let account = account_for(reference);
        let backend = self.backend.clone();
        match self
            .run_blocking(move || backend.delete(SERVICE_NAME, account))
            .await
        {
            Err(error) if error.code() == CredentialErrorCode::NotFound => Ok(()),
            result => result,
        }
    }

    /// Blocking-worker-only counterpart to [`Self::delete`].
    pub fn delete_blocking(
        &self,
        reference: &StoredCredentialReference,
    ) -> Result<(), CredentialError> {
        let account = account_for(reference);
        let backend = self.backend.clone();
        match self.run_blocking_now(move || backend.delete(SERVICE_NAME, account)) {
            Err(error) if error.code() == CredentialErrorCode::NotFound => Ok(()),
            result => result,
        }
    }

    async fn run_blocking<T, F>(&self, operation: F) -> Result<T, CredentialError>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, CredentialError> + Send + 'static,
    {
        run_blocking_with_lock(self.operation_lock.clone(), operation).await
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

pub(crate) async fn run_blocking_with_lock<T, F>(
    operation_lock: Arc<Mutex<()>>,
    operation: F,
) -> Result<T, CredentialError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, CredentialError> + Send + 'static,
{
    let guard = operation_lock.lock_owned().await;
    tokio::task::spawn_blocking(move || {
        let _guard = guard;
        operation()
    })
    .await
    .map_err(|_| CredentialError::new(CredentialErrorCode::BackendFailure))?
}

impl Default for OsCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

fn account_for(reference: &StoredCredentialReference) -> String {
    format!("{ACCOUNT_PREFIX}{}", reference.id().as_uuid().simple())
}

fn encode_envelope(
    kind: CredentialKind,
    secret: SecretValue,
) -> Result<SecretBlob, CredentialError> {
    if secret.len() > MAX_PERSISTENT_SECRET_BYTES {
        return Err(CredentialErrorCode::TooLarge.into());
    }
    let payload_len = u32::try_from(secret.len())
        .map_err(|_| CredentialError::new(CredentialErrorCode::TooLarge))?;
    let mut envelope = Zeroizing::new(Vec::with_capacity(ENVELOPE_HEADER_BYTES + secret.len()));
    envelope.extend_from_slice(ENVELOPE_MAGIC);
    envelope.push(ENVELOPE_VERSION);
    envelope.push(kind.tag());
    envelope.extend_from_slice(&payload_len.to_be_bytes());
    envelope.extend_from_slice(secret.as_bytes());
    if envelope.len() > WINDOWS_CREDENTIAL_BLOB_LIMIT {
        return Err(CredentialErrorCode::TooLarge.into());
    }
    Ok(envelope)
}

fn decode_envelope(
    envelope: SecretBlob,
    expected_kind: CredentialKind,
) -> Result<SecretValue, CredentialError> {
    if envelope.len() < ENVELOPE_HEADER_BYTES || envelope.len() > WINDOWS_CREDENTIAL_BLOB_LIMIT {
        return Err(CredentialErrorCode::CorruptRecord.into());
    }
    if envelope.get(..8) != Some(ENVELOPE_MAGIC.as_slice()) || envelope[8] != ENVELOPE_VERSION {
        return Err(CredentialErrorCode::CorruptRecord.into());
    }
    if envelope[9] != expected_kind.tag() {
        return Err(CredentialErrorCode::KindMismatch.into());
    }
    let payload_len =
        u32::from_be_bytes([envelope[10], envelope[11], envelope[12], envelope[13]]) as usize;
    if payload_len == 0 || ENVELOPE_HEADER_BYTES + payload_len != envelope.len() {
        return Err(CredentialErrorCode::CorruptRecord.into());
    }
    SecretValue::new(envelope[ENVELOPE_HEADER_BYTES..].to_vec())
        .map_err(|_| CredentialError::new(CredentialErrorCode::CorruptRecord))
}

fn map_keyring_error(error: keyring::Error) -> CredentialError {
    let code = match error {
        keyring::Error::NoEntry => CredentialErrorCode::NotFound,
        keyring::Error::NoStorageAccess(_) => CredentialErrorCode::StorageUnavailable,
        keyring::Error::TooLong(_, _) => CredentialErrorCode::TooLarge,
        keyring::Error::BadEncoding(mut secret) => {
            secret.zeroize();
            CredentialErrorCode::CorruptRecord
        }
        keyring::Error::Ambiguous(_) => CredentialErrorCode::Conflict,
        keyring::Error::Invalid(_, _) | keyring::Error::PlatformFailure(_) => {
            CredentialErrorCode::BackendFailure
        }
        _ => CredentialErrorCode::BackendFailure,
    };
    CredentialError::new(code)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    #[cfg(all(target_os = "windows", feature = "os-credential-tests"))]
    use super::OsCredentialStore;
    use super::{
        CredentialKind, MAX_PERSISTENT_SECRET_BYTES, SERVICE_NAME, account_for, map_keyring_error,
    };
    use crate::test_support::{CredentialOperation, FailureTiming, in_memory_credential_store};
    use crate::{CredentialError, CredentialErrorCode, SecretValue, StoredCredentialReference};
    #[cfg(all(target_os = "windows", feature = "os-credential-tests"))]
    use zeroize::Zeroizing;

    fn secret(value: &str) -> SecretValue {
        SecretValue::from_utf8(value.to_owned()).expect("test secret")
    }

    #[test]
    fn credential_kind_tags_are_stable_and_distinct() {
        assert_eq!(CredentialKind::SshPassword.tag(), 1);
        assert_eq!(CredentialKind::ProxyPassword.tag(), 2);
        assert_eq!(CredentialKind::TelnetPassword.tag(), 3);
        assert_eq!(CredentialKind::AiApiKey.tag(), 4);
    }

    #[tokio::test]
    async fn ai_api_key_round_trips_and_cannot_resolve_as_an_existing_kind() {
        let (store, controller) = in_memory_credential_store();
        let reference = StoredCredentialReference::for_ai_provider("openai-compatible")
            .expect("AI provider reference");
        let secret_marker = "ai-api-key-secret-marker";
        store
            .upsert(&reference, CredentialKind::AiApiKey, secret(secret_marker))
            .await
            .expect("store AI API key");

        for existing_kind in [
            CredentialKind::SshPassword,
            CredentialKind::ProxyPassword,
            CredentialKind::TelnetPassword,
        ] {
            let mismatch = match store.resolve(&reference, existing_kind).await {
                Ok(_) => panic!("AI API key envelope must remain kind-isolated"),
                Err(error) => error,
            };
            assert_eq!(mismatch.code(), CredentialErrorCode::KindMismatch);
        }

        let resolved = store
            .resolve(&reference, CredentialKind::AiApiKey)
            .await
            .expect("resolve AI API key");
        assert_eq!(resolved.as_utf8().expect("UTF-8 AI API key"), secret_marker);

        let rendered = format!("{controller:?} {:?}", controller.operation_log());
        assert!(!rendered.contains(secret_marker));
        assert!(!rendered.contains("openai-compatible"));
        assert!(!rendered.contains("credential:"));
    }

    #[tokio::test]
    async fn telnet_password_round_trips_and_kind_mismatches_fail_closed() {
        let (store, _) = in_memory_credential_store();
        let reference = StoredCredentialReference::for_saved_group_telnet("group-kind-test")
            .expect("group Telnet reference");
        store
            .upsert(
                &reference,
                CredentialKind::TelnetPassword,
                secret("telnet-kind-secret"),
            )
            .await
            .expect("store Telnet password");

        let ssh_mismatch = store
            .resolve(&reference, CredentialKind::SshPassword)
            .await
            .err()
            .expect("Telnet envelope must not resolve as SSH");
        assert_eq!(ssh_mismatch.code(), CredentialErrorCode::KindMismatch);
        let proxy_mismatch = store
            .resolve(&reference, CredentialKind::ProxyPassword)
            .await
            .err()
            .expect("Telnet envelope must not resolve as proxy");
        assert_eq!(proxy_mismatch.code(), CredentialErrorCode::KindMismatch);
        let resolved = store
            .resolve(&reference, CredentialKind::TelnetPassword)
            .await
            .expect("resolve Telnet password");
        assert_eq!(
            resolved.as_utf8().expect("UTF-8 Telnet password"),
            "telnet-kind-secret"
        );
    }

    #[tokio::test]
    async fn saved_host_ssh_and_telnet_accounts_round_trip_without_kind_or_owner_aliasing() {
        let (store, controller) = in_memory_credential_store();
        let shared_id = "same-host-id-kind-isolation-marker";
        let ssh_reference =
            StoredCredentialReference::for_saved_host(shared_id).expect("host SSH reference");
        let telnet_reference = StoredCredentialReference::for_saved_host_telnet(shared_id)
            .expect("host Telnet reference");
        assert_ne!(ssh_reference, telnet_reference);

        store
            .upsert(
                &ssh_reference,
                CredentialKind::SshPassword,
                secret("host-ssh-secret-marker"),
            )
            .await
            .expect("store host SSH password");
        store
            .upsert(
                &telnet_reference,
                CredentialKind::TelnetPassword,
                secret("host-telnet-secret-marker"),
            )
            .await
            .expect("store host Telnet password");

        let ssh = store
            .resolve(&ssh_reference, CredentialKind::SshPassword)
            .await
            .expect("resolve host SSH password");
        let telnet = store
            .resolve(&telnet_reference, CredentialKind::TelnetPassword)
            .await
            .expect("resolve host Telnet password");
        assert_eq!(
            ssh.as_utf8().expect("UTF-8 SSH password"),
            "host-ssh-secret-marker"
        );
        assert_eq!(
            telnet.as_utf8().expect("UTF-8 Telnet password"),
            "host-telnet-secret-marker"
        );

        let ssh_as_telnet = store
            .resolve(&ssh_reference, CredentialKind::TelnetPassword)
            .await
            .err()
            .expect("SSH envelope must not resolve as Telnet");
        let telnet_as_ssh = store
            .resolve(&telnet_reference, CredentialKind::SshPassword)
            .await
            .err()
            .expect("Telnet envelope must not resolve as SSH");
        assert_eq!(ssh_as_telnet.code(), CredentialErrorCode::KindMismatch);
        assert_eq!(telnet_as_ssh.code(), CredentialErrorCode::KindMismatch);

        let rendered = format!(
            "{ssh_as_telnet:?} {telnet_as_ssh:?} {controller:?} {:?}",
            controller.operation_log()
        );
        for forbidden in [
            shared_id,
            "host-ssh-secret-marker",
            "host-telnet-secret-marker",
            "credential:",
        ] {
            assert!(!rendered.contains(forbidden));
        }
    }

    #[tokio::test]
    async fn proxy_password_round_trips_and_kind_mismatches_fail_closed() {
        let (store, controller) = in_memory_credential_store();
        let reference = StoredCredentialReference::for_saved_proxy_profile("kind-test-profile")
            .expect("profile proxy reference");
        let secret_marker = "proxy-kind-secret-marker";
        store
            .upsert(
                &reference,
                CredentialKind::ProxyPassword,
                secret(secret_marker),
            )
            .await
            .expect("store proxy password");

        let mismatch = store
            .resolve(&reference, CredentialKind::SshPassword)
            .await
            .err()
            .expect("proxy envelope must not resolve as SSH password");
        assert_eq!(mismatch.code(), CredentialErrorCode::KindMismatch);
        let resolved = store
            .resolve(&reference, CredentialKind::ProxyPassword)
            .await
            .expect("resolve proxy password");
        assert_eq!(
            resolved.as_utf8().expect("UTF-8 proxy password"),
            secret_marker
        );
        drop(resolved);

        store
            .upsert(
                &reference,
                CredentialKind::SshPassword,
                secret("ssh-kind-secret-marker"),
            )
            .await
            .expect("replace with SSH password envelope");
        let reverse_mismatch = store
            .resolve(&reference, CredentialKind::ProxyPassword)
            .await
            .err()
            .expect("SSH envelope must not resolve as proxy password");
        assert_eq!(reverse_mismatch.code(), CredentialErrorCode::KindMismatch);

        let rendered = format!(
            "{mismatch:?} {reverse_mismatch:?} {controller:?} {:?}",
            controller.operation_log()
        );
        for forbidden in [
            secret_marker,
            "ssh-kind-secret-marker",
            "kind-test-profile",
            "credential:",
        ] {
            assert!(!rendered.contains(forbidden));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn memory_backend_round_trip_overwrite_delete_and_serialization() {
        let (store, controller) = in_memory_credential_store();
        let reference = StoredCredentialReference::new();
        store
            .upsert(&reference, CredentialKind::SshPassword, secret("first"))
            .await
            .expect("upsert");
        store
            .upsert(&reference, CredentialKind::SshPassword, secret("second"))
            .await
            .expect("overwrite");
        let resolved = store
            .resolve(&reference, CredentialKind::SshPassword)
            .await
            .expect("resolve");
        assert!(matches!(resolved.as_utf8(), Ok("second")));
        store.delete(&reference).await.expect("delete");
        store.delete(&reference).await.expect("idempotent delete");
        assert_eq!(
            store
                .resolve(&reference, CredentialKind::SshPassword)
                .await
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::NotFound)
        );
        assert_eq!(controller.operation_count(CredentialOperation::Upsert), 2);
        assert_eq!(controller.operation_count(CredentialOperation::Resolve), 2);
        assert_eq!(controller.operation_count(CredentialOperation::Delete), 2);

        let marker = "must-not-appear";
        let json = serde_json::to_string(&(
            reference,
            CredentialError::new(CredentialErrorCode::BackendFailure),
        ))
        .expect("safe JSON");
        assert!(!json.contains(marker));
    }

    #[tokio::test]
    async fn persistent_limit_is_smaller_than_the_ephemeral_quick_connect_limit() {
        let (store, _) = in_memory_credential_store();
        let reference = StoredCredentialReference::new();
        store
            .upsert(
                &reference,
                CredentialKind::SshPassword,
                SecretValue::new(vec![1; MAX_PERSISTENT_SECRET_BYTES])
                    .expect("persistent boundary"),
            )
            .await
            .expect("boundary upsert");
        assert_eq!(
            store
                .upsert(
                    &StoredCredentialReference::new(),
                    CredentialKind::SshPassword,
                    SecretValue::new(vec![1; MAX_PERSISTENT_SECRET_BYTES + 1])
                        .expect("valid ephemeral-sized secret"),
                )
                .await
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::TooLarge)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn all_os_backend_calls_are_globally_serialized() {
        let (store, controller) = in_memory_credential_store();
        let mut tasks = Vec::new();
        for index in 0..12 {
            let store = store.clone();
            tasks.push(tokio::spawn(async move {
                let reference = StoredCredentialReference::new();
                store
                    .upsert(
                        &reference,
                        CredentialKind::SshPassword,
                        secret(&format!("value-{index}")),
                    )
                    .await
            }));
        }
        for task in tasks {
            task.await.expect("task").expect("upsert");
        }
        assert_eq!(controller.max_concurrent_operations(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn blocking_api_round_trips_from_spawn_blocking_and_ordinary_threads() {
        let (store, _) = in_memory_credential_store();

        let blocking_worker_reference = StoredCredentialReference::new();
        let blocking_worker_store = store.clone();
        tokio::task::spawn_blocking(move || {
            blocking_worker_store
                .upsert_blocking(
                    &blocking_worker_reference,
                    CredentialKind::SshPassword,
                    secret("blocking-worker-secret"),
                )
                .expect("blocking-worker upsert");
            let resolved = blocking_worker_store
                .resolve_blocking(&blocking_worker_reference, CredentialKind::SshPassword)
                .expect("blocking-worker resolve");
            assert!(matches!(
                resolved.as_utf8(),
                Ok(value) if value == "blocking-worker-secret"
            ));
            blocking_worker_store
                .delete_blocking(&blocking_worker_reference)
                .expect("blocking-worker delete");
            blocking_worker_store
                .delete_blocking(&blocking_worker_reference)
                .expect("blocking-worker idempotent delete");
            assert_eq!(
                blocking_worker_store
                    .resolve_blocking(&blocking_worker_reference, CredentialKind::SshPassword,)
                    .err()
                    .map(|error| error.code()),
                Some(CredentialErrorCode::NotFound)
            );
        })
        .await
        .expect("blocking worker task");

        let ordinary_thread_reference = StoredCredentialReference::new();
        let ordinary_thread_store = store.clone();
        std::thread::spawn(move || {
            ordinary_thread_store
                .upsert_blocking(
                    &ordinary_thread_reference,
                    CredentialKind::SshPassword,
                    secret("ordinary-thread-secret"),
                )
                .expect("ordinary-thread upsert");
            let resolved = ordinary_thread_store
                .resolve_blocking(&ordinary_thread_reference, CredentialKind::SshPassword)
                .expect("ordinary-thread resolve");
            assert!(matches!(
                resolved.as_utf8(),
                Ok(value) if value == "ordinary-thread-secret"
            ));
            ordinary_thread_store
                .delete_blocking(&ordinary_thread_reference)
                .expect("ordinary-thread delete");
            ordinary_thread_store
                .delete_blocking(&ordinary_thread_reference)
                .expect("ordinary-thread idempotent delete");
            assert_eq!(
                ordinary_thread_store
                    .resolve_blocking(&ordinary_thread_reference, CredentialKind::SshPassword)
                    .err()
                    .map(|error| error.code()),
                Some(CredentialErrorCode::NotFound)
            );
        })
        .join()
        .expect("ordinary credential thread");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn blocking_and_async_credential_calls_share_one_operation_lock() {
        let (store, controller) = in_memory_credential_store();
        let async_resolve_reference = StoredCredentialReference::new();
        let blocking_resolve_reference = StoredCredentialReference::new();
        let async_delete_reference = StoredCredentialReference::new();
        let blocking_delete_reference = StoredCredentialReference::new();
        for reference in [
            async_resolve_reference,
            blocking_resolve_reference,
            async_delete_reference,
            blocking_delete_reference,
        ] {
            store
                .upsert(&reference, CredentialKind::SshPassword, secret("seed"))
                .await
                .expect("seed credential");
        }

        let start = Arc::new(tokio::sync::Barrier::new(7));
        let mut tasks = Vec::new();

        let async_store = store.clone();
        let async_start = start.clone();
        tasks.push(tokio::spawn(async move {
            async_start.wait().await;
            async_store
                .upsert(
                    &StoredCredentialReference::new(),
                    CredentialKind::SshPassword,
                    secret("async-upsert"),
                )
                .await
        }));

        let async_store = store.clone();
        let async_start = start.clone();
        tasks.push(tokio::spawn(async move {
            async_start.wait().await;
            async_store
                .resolve(&async_resolve_reference, CredentialKind::SshPassword)
                .await
                .map(|_| ())
        }));

        let async_store = store.clone();
        let async_start = start.clone();
        tasks.push(tokio::spawn(async move {
            async_start.wait().await;
            async_store.delete(&async_delete_reference).await
        }));

        let runtime = tokio::runtime::Handle::current();
        let blocking_store = store.clone();
        let blocking_start = start.clone();
        let blocking_runtime = runtime.clone();
        tasks.push(tokio::task::spawn_blocking(move || {
            blocking_runtime.block_on(blocking_start.wait());
            blocking_store.upsert_blocking(
                &StoredCredentialReference::new(),
                CredentialKind::SshPassword,
                secret("blocking-upsert"),
            )
        }));

        let blocking_store = store.clone();
        let blocking_start = start.clone();
        let blocking_runtime = runtime.clone();
        tasks.push(tokio::task::spawn_blocking(move || {
            blocking_runtime.block_on(blocking_start.wait());
            blocking_store
                .resolve_blocking(&blocking_resolve_reference, CredentialKind::SshPassword)
                .map(|_| ())
        }));

        let blocking_store = store.clone();
        let blocking_start = start.clone();
        tasks.push(tokio::task::spawn_blocking(move || {
            runtime.block_on(blocking_start.wait());
            blocking_store.delete_blocking(&blocking_delete_reference)
        }));

        start.wait().await;
        for task in tasks {
            task.await
                .expect("credential task")
                .expect("credential call");
        }
        assert_eq!(controller.max_concurrent_operations(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn blocking_resolve_preserves_missing_and_corrupt_record_errors() {
        let (store, controller) = in_memory_credential_store();
        let missing_reference = StoredCredentialReference::new();
        let missing_store = store.clone();
        assert_eq!(
            tokio::task::spawn_blocking(move || {
                missing_store
                    .resolve_blocking(&missing_reference, CredentialKind::SshPassword)
                    .err()
                    .map(|error| error.code())
            })
            .await
            .expect("missing resolve task"),
            Some(CredentialErrorCode::NotFound)
        );

        let corrupt_reference = StoredCredentialReference::new();
        let corrupt_account = account_for(&corrupt_reference);
        controller.replace_raw_value(SERVICE_NAME, corrupt_account.clone(), vec![0xa5; 7]);
        let corrupt_store = store.clone();
        assert_eq!(
            std::thread::spawn(move || {
                corrupt_store
                    .resolve_blocking(&corrupt_reference, CredentialKind::SshPassword)
                    .err()
                    .map(|error| error.code())
            })
            .join()
            .expect("corrupt resolve thread"),
            Some(CredentialErrorCode::CorruptRecord)
        );
        assert!(
            controller
                .raw_value(SERVICE_NAME, &corrupt_account)
                .is_some()
        );
    }

    #[tokio::test]
    async fn injected_upsert_failures_preserve_before_and_apply_after_side_effects() {
        let (store, controller) = in_memory_credential_store();
        let reference = StoredCredentialReference::new();
        store
            .upsert(&reference, CredentialKind::SshPassword, secret("original"))
            .await
            .expect("seed value");

        controller.set_failure(
            CredentialOperation::Upsert,
            1,
            FailureTiming::BeforeSideEffect,
            CredentialErrorCode::BackendFailure,
        );
        assert_eq!(
            store
                .upsert(
                    &reference,
                    CredentialKind::SshPassword,
                    secret("before-failure"),
                )
                .await
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::BackendFailure)
        );
        controller.clear_failures();
        let resolved = store
            .resolve(&reference, CredentialKind::SshPassword)
            .await
            .expect("value survives before-side-effect failure");
        assert!(matches!(resolved.as_utf8(), Ok("original")));

        controller.set_failure(
            CredentialOperation::Upsert,
            1,
            FailureTiming::AfterSideEffect,
            CredentialErrorCode::BackendFailure,
        );
        assert_eq!(
            store
                .upsert(
                    &reference,
                    CredentialKind::SshPassword,
                    secret("after-failure"),
                )
                .await
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::BackendFailure)
        );
        controller.clear_failures();
        let resolved = store
            .resolve(&reference, CredentialKind::SshPassword)
            .await
            .expect("value was changed before injected failure");
        assert!(matches!(resolved.as_utf8(), Ok("after-failure")));
    }

    #[tokio::test]
    async fn injected_delete_failures_preserve_before_and_remove_after_side_effects() {
        let (store, controller) = in_memory_credential_store();
        let reference = StoredCredentialReference::new();
        store
            .upsert(&reference, CredentialKind::SshPassword, secret("retained"))
            .await
            .expect("seed value");

        controller.set_failure(
            CredentialOperation::Delete,
            1,
            FailureTiming::BeforeSideEffect,
            CredentialErrorCode::BackendFailure,
        );
        assert_eq!(
            store
                .delete(&reference)
                .await
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::BackendFailure)
        );
        controller.clear_failures();
        assert!(
            store
                .resolve(&reference, CredentialKind::SshPassword)
                .await
                .is_ok()
        );

        controller.set_failure(
            CredentialOperation::Delete,
            1,
            FailureTiming::AfterSideEffect,
            CredentialErrorCode::BackendFailure,
        );
        assert_eq!(
            store
                .delete(&reference)
                .await
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::BackendFailure)
        );
        controller.clear_failures();
        assert_eq!(
            store
                .resolve(&reference, CredentialKind::SshPassword)
                .await
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::NotFound)
        );
    }

    #[tokio::test]
    async fn different_operation_failures_can_be_scheduled_together_for_compensation() {
        let (store, controller) = in_memory_credential_store();
        let reference = StoredCredentialReference::new();
        controller.set_failure(
            CredentialOperation::Upsert,
            1,
            FailureTiming::AfterSideEffect,
            CredentialErrorCode::BackendFailure,
        );
        controller.set_failure(
            CredentialOperation::Delete,
            1,
            FailureTiming::BeforeSideEffect,
            CredentialErrorCode::StorageUnavailable,
        );

        assert_eq!(
            store
                .upsert(
                    &reference,
                    CredentialKind::SshPassword,
                    secret("partially-written"),
                )
                .await
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::BackendFailure)
        );
        assert_eq!(
            store
                .delete(&reference)
                .await
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::StorageUnavailable)
        );
        controller.clear_failures_for(CredentialOperation::Delete);
        assert!(
            store
                .resolve(&reference, CredentialKind::SshPassword)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn resolve_faults_and_missing_or_repeated_deletes_are_deterministic() {
        let (store, controller) = in_memory_credential_store();
        let reference = StoredCredentialReference::new();
        assert_eq!(
            store
                .resolve(&reference, CredentialKind::SshPassword)
                .await
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::NotFound)
        );
        store.delete(&reference).await.expect("missing delete");
        store
            .delete(&reference)
            .await
            .expect("repeated missing delete");

        store
            .upsert(&reference, CredentialKind::SshPassword, secret("present"))
            .await
            .expect("seed value");
        controller.set_failure(
            CredentialOperation::Resolve,
            1,
            FailureTiming::BeforeSideEffect,
            CredentialErrorCode::StorageUnavailable,
        );
        controller.add_failure(
            CredentialOperation::Resolve,
            2,
            FailureTiming::AfterSideEffect,
            CredentialErrorCode::StorageUnavailable,
        );
        for _ in 0..2 {
            assert_eq!(
                store
                    .resolve(&reference, CredentialKind::SshPassword)
                    .await
                    .err()
                    .map(|error| error.code()),
                Some(CredentialErrorCode::StorageUnavailable)
            );
        }
        controller.clear_failures();
        assert!(
            store
                .resolve(&reference, CredentialKind::SshPassword)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn operation_log_excludes_accounts_references_and_secrets() {
        let (store, controller) = in_memory_credential_store();
        let reference = StoredCredentialReference::new();
        let reference_marker = reference.to_string();
        let secret_marker = "operation-log-secret-marker";
        store
            .upsert(
                &reference,
                CredentialKind::SshPassword,
                secret(secret_marker),
            )
            .await
            .expect("upsert");
        store
            .resolve(&reference, CredentialKind::SshPassword)
            .await
            .expect("resolve");

        let log = controller.operation_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log.count(CredentialOperation::Upsert), 1);
        assert_eq!(log.count(CredentialOperation::Resolve), 1);
        assert_eq!(log.entries()[0].operation(), CredentialOperation::Upsert);
        assert_eq!(log.entries()[0].operation_call(), 1);
        let rendered = format!("{controller:?} {log:?}");
        assert!(!rendered.contains(secret_marker));
        assert!(!rendered.contains(&reference_marker));
        assert!(!rendered.contains("credential:"));
        controller.clear_operation_log();
        assert!(controller.operation_log().is_empty());
        assert_eq!(controller.operation_count(CredentialOperation::Upsert), 1);
    }

    #[test]
    fn keyring_errors_are_mapped_without_secret_or_platform_payloads() {
        struct LeakyPlatformError;
        impl std::fmt::Debug for LeakyPlatformError {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("platform-secret-marker")
            }
        }
        impl std::fmt::Display for LeakyPlatformError {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("platform-secret-marker")
            }
        }
        impl std::error::Error for LeakyPlatformError {}

        let errors = [
            map_keyring_error(keyring::Error::NoEntry),
            map_keyring_error(keyring::Error::TooLong("secret".to_owned(), 2_560)),
            map_keyring_error(keyring::Error::Invalid(
                "target".to_owned(),
                "invalid".to_owned(),
            )),
            map_keyring_error(keyring::Error::BadEncoding(
                b"encoding-secret-marker".to_vec(),
            )),
            map_keyring_error(keyring::Error::PlatformFailure(Box::new(
                LeakyPlatformError,
            ))),
            map_keyring_error(keyring::Error::NoStorageAccess(Box::new(
                LeakyPlatformError,
            ))),
            map_keyring_error(keyring::Error::Ambiguous(Vec::new())),
        ];
        let rendered = format!("{errors:?}");
        assert!(!rendered.contains("secret-marker"));
        assert_eq!(errors[0].code(), CredentialErrorCode::NotFound);
        assert_eq!(errors[1].code(), CredentialErrorCode::TooLarge);
        assert_eq!(errors[2].code(), CredentialErrorCode::BackendFailure);
        assert_eq!(errors[3].code(), CredentialErrorCode::CorruptRecord);
        assert_eq!(errors[4].code(), CredentialErrorCode::BackendFailure);
        assert_eq!(errors[5].code(), CredentialErrorCode::StorageUnavailable);
        assert_eq!(errors[6].code(), CredentialErrorCode::Conflict);
    }

    #[cfg(all(target_os = "windows", feature = "os-credential-tests"))]
    #[tokio::test(flavor = "multi_thread")]
    async fn windows_credential_manager_round_trip() {
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                if let Ok(entry) = keyring::Entry::new(SERVICE_NAME, &self.0) {
                    let _ = entry.delete_credential();
                }
            }
        }

        let store = OsCredentialStore::new();
        let reference = StoredCredentialReference::new();
        let account = account_for(&reference);
        let _cleanup = Cleanup(account.clone());
        let entry = keyring::Entry::new(SERVICE_NAME, &account).expect("Windows entry");
        assert!(
            entry
                .get_credential()
                .downcast_ref::<keyring::windows::WinCredential>()
                .is_some()
        );
        store.delete(&reference).await.expect("initial cleanup");

        let first = Zeroizing::new(format!("proof-{}", uuid::Uuid::new_v4()));
        store
            .upsert(
                &reference,
                CredentialKind::SshPassword,
                SecretValue::from_utf8(first.as_str().to_owned()).expect("first secret"),
            )
            .await
            .expect("Windows write");
        let resolved = store
            .resolve(&reference, CredentialKind::SshPassword)
            .await
            .expect("Windows read");
        assert!(matches!(resolved.as_utf8(), Ok(value) if value == first.as_str()));

        let second = Zeroizing::new(format!("proof-{}", uuid::Uuid::new_v4()));
        store
            .upsert(
                &reference,
                CredentialKind::SshPassword,
                SecretValue::from_utf8(second.as_str().to_owned()).expect("second secret"),
            )
            .await
            .expect("Windows overwrite");
        let resolved = store
            .resolve(&reference, CredentialKind::SshPassword)
            .await
            .expect("Windows reread");
        assert!(matches!(resolved.as_utf8(), Ok(value) if value == second.as_str()));
        store.delete(&reference).await.expect("Windows delete");
        store
            .delete(&reference)
            .await
            .expect("idempotent Windows delete");
        assert_eq!(
            store
                .resolve(&reference, CredentialKind::SshPassword)
                .await
                .err()
                .map(|error| error.code()),
            Some(CredentialErrorCode::NotFound)
        );
    }

    #[cfg(all(target_os = "windows", feature = "os-credential-tests"))]
    #[tokio::test(flavor = "multi_thread")]
    async fn windows_endpoint_bound_ai_api_key_survives_store_reopen() {
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                if let Ok(entry) = keyring::Entry::new(SERVICE_NAME, &self.0) {
                    let _ = entry.delete_credential();
                }
            }
        }

        let provider_id = format!("restart-{}", uuid::Uuid::new_v4().simple());
        let reference = StoredCredentialReference::for_ai_provider_endpoint(
            &provider_id,
            "https://api.example.test/v1/chat/completions",
        )
        .expect("endpoint-bound AI provider reference");
        let account = account_for(&reference);
        let _cleanup = Cleanup(account);
        let secret = Zeroizing::new(format!("ai-proof-{}", uuid::Uuid::new_v4()));

        let first_process = OsCredentialStore::new();
        first_process
            .delete(&reference)
            .await
            .expect("initial AI key cleanup");
        first_process
            .upsert(
                &reference,
                CredentialKind::AiApiKey,
                SecretValue::from_utf8(secret.as_str().to_owned()).expect("AI key"),
            )
            .await
            .expect("persist AI key");
        drop(first_process);

        let reopened_process = OsCredentialStore::new();
        let resolved = reopened_process
            .resolve(&reference, CredentialKind::AiApiKey)
            .await
            .expect("resolve AI key after reopening the store");
        assert!(matches!(resolved.as_utf8(), Ok(value) if value == secret.as_str()));
        drop(resolved);
        reopened_process
            .delete(&reference)
            .await
            .expect("remove persisted AI key");
    }
}
