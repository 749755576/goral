mod ephemeral;
mod error;
mod master_key_store;
mod os_store;
mod reference;
mod secret;

#[cfg(feature = "test-support")]
pub mod test_support;
#[cfg(all(test, not(feature = "test-support")))]
mod test_support;

pub use ephemeral::{
    DEFAULT_EPHEMERAL_CREDENTIAL_TTL, EphemeralCredentialStore, MAX_EPHEMERAL_CREDENTIAL_ENTRIES,
    MAX_EPHEMERAL_CREDENTIALS_PER_OWNER, MAX_EPHEMERAL_TOTAL_SECRET_BYTES,
};
pub use error::{CredentialError, CredentialErrorCode};
pub use master_key_store::{
    MASTER_KEY_BYTES, MASTER_KEY_ENVELOPE_BYTES, OsMasterKeyStore, SECRET_BLOB_MASTER_KEY_SERVICE,
};
/// A zeroizing 256-bit key re-exported from the pure envelope layer.
///
/// It deliberately cannot be cloned, serialized, or displayed.
///
/// ```compile_fail
/// use netcatty_credentials::MasterKey;
/// let key = MasterKey::from_bytes([7; 32]).unwrap();
/// let _copy = key.clone();
/// ```
///
/// ```compile_fail
/// use netcatty_credentials::MasterKey;
/// fn requires_serialize<T: serde::Serialize>() {}
/// requires_serialize::<MasterKey>();
/// ```
///
/// ```compile_fail
/// use netcatty_credentials::MasterKey;
/// let key = MasterKey::from_bytes([7; 32]).unwrap();
/// let _rendered = format!("{key}");
/// ```
pub use netcatty_secret_store::EnvelopeMasterKey as MasterKey;
pub use os_store::{CredentialKind, MAX_PERSISTENT_SECRET_BYTES, OsCredentialStore};
pub use reference::{CredentialId, EphemeralCredentialReference, StoredCredentialReference};
pub use secret::{MAX_SECRET_VALUE_BYTES, SecretValue};
