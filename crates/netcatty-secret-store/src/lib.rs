//! Pure-Rust, bounded authenticated envelopes for SSH private keys,
//! certificates, public keys, and optional saved passphrases.
//!
//! This crate deliberately contains no operating-system keyring code.
//! Secret-bearing types do not implement Serde, `Clone`, or `Display`, and all
//! externally visible errors retain only fixed codes.

mod bundle;
mod envelope;
mod error;
mod file_error;
mod file_store;

pub use bundle::{
    MAX_BUNDLE_PLAINTEXT_BYTES, MAX_CERTIFICATE_BYTES, MAX_PASSPHRASE_BYTES, MAX_PRIVATE_KEY_BYTES,
    MAX_PUBLIC_KEY_BYTES, SshSecretBundle,
};
pub use envelope::{
    EncryptedSecretEnvelope, EnvelopeMasterKey, SecretEnvelopeContext, SecretEnvelopeSlot,
    decrypt_ssh_secret_bundle, encrypt_ssh_secret_bundle,
};
pub use error::{SecretEnvelopeError, SecretEnvelopeErrorCode};
pub use file_error::{SecretFileStoreError, SecretFileStoreErrorCode};
pub use file_store::{
    CompletedMasterKeyRotation, MasterKeyRotationRecovery, PreparedSecretObject,
    SecretBlobGarbageCollection, SecretFileMutation, SecretFileStore,
    SecretFileStoreExclusiveGuard, SecretFileStoreState, SecretObjectLocator,
    SecretObjectRetention, SecretPublicationDurability,
};
