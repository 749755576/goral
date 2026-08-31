use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::{Uuid, Version};

use crate::bundle::SshSecretBundle;
use crate::envelope::{
    EncryptedSecretEnvelope, EnvelopeMasterKey, SecretEntityDigest, SecretEnvelopeContext,
    SecretEnvelopeSlot, decrypt_ssh_secret_bundle, decrypt_ssh_secret_bundle_with_embedded_context,
    encrypt_ssh_secret_bundle,
};
use crate::{SecretFileStoreError, SecretFileStoreErrorCode};

const OWNER_MAGIC: &str = "netcatty-secret-blob-store";
const OWNER_FORMAT_VERSION: u32 = 1;
const KEYSET_MAGIC: &str = "netcatty-secret-blob-keyset";
const KEYSET_FORMAT_VERSION: u32 = 1;
const ROTATED_KEYSET_FORMAT_VERSION: u32 = 2;
const OWNER_CHECKSUM_DOMAIN: &[u8] = b"netcatty-secret-owner-checksum-v1\0";
const KEYSET_CHECKSUM_DOMAIN: &[u8] = b"netcatty-secret-keyset-checksum-v1\0";
const ROTATED_KEYSET_CHECKSUM_DOMAIN: &[u8] = b"netcatty-secret-keyset-checksum-v2\0";
const OBJECT_PATH_DOMAIN: &[u8] = b"netcatty-secret-object-path-v1\0";
const ROTATION_SOURCE_COMMITMENT_DOMAIN: &[u8] = b"netcatty-secret-rotation-source-commitment-v1\0";
const ROTATION_RETENTION_COMMITMENT_DOMAIN: &[u8] =
    b"netcatty-secret-rotation-retention-commitment-v1\0";
const ROTATION_KEYSET_COMMITMENT_DOMAIN: &[u8] = b"netcatty-secret-rotation-keyset-commitment-v1\0";
const ROTATION_MANIFEST_CHECKSUM_DOMAIN: &[u8] = b"netcatty-secret-rotation-manifest-checksum-v1\0";
const RETIRED_SOURCE_MARKER_CHECKSUM_DOMAIN: &[u8] =
    b"netcatty-secret-retired-source-marker-checksum-v1\0";
const RETIRED_SOURCE_MARKER_COMMITMENT_DOMAIN: &[u8] =
    b"netcatty-secret-retired-source-marker-commitment-v1\0";
const ROTATION_MANIFEST_COMMITMENT_DOMAIN: &[u8] =
    b"netcatty-secret-rotation-manifest-commitment-v1\0";
const ROTATION_MANIFEST_MAGIC: &str = "netcatty-secret-master-key-rotation";
const ROTATION_MANIFEST_FORMAT_VERSION: u32 = 1;
const RETIRED_SOURCE_MARKER_MAGIC: &str = "netcatty-secret-source-key-retired";
const RETIRED_SOURCE_MARKER_FORMAT_VERSION: u32 = 1;
const OWNER_FILE: &str = "owner.json";
const TRANSACTION_LOCK_FILE: &str = "transaction.lock";
const KEYSET_DIRECTORY: &str = "keyset";
const OBJECTS_DIRECTORY: &str = "objects";
const EPOCHS_DIRECTORY: &str = "epochs";
const EPOCH_DIRECTORY_OBJECT_STORAGE: &str = "epoch-directory-v1";
const LEGACY_FLAT_OBJECT_STORAGE: &str = "legacy-flat-v1";
const ROTATION_MANIFEST_FILE: &str = "rotation.json";
const RETIRED_SOURCE_MARKER_FILE: &str = "source-key-retired.json";
const SLOT_A_DIRECTORY: &str = "slot-a";
const SLOT_B_DIRECTORY: &str = "slot-b";
const MAX_OWNER_BYTES: u64 = 4 * 1_024;
const MAX_KEYSET_BYTES: u64 = 8 * 1_024;
const MAX_SLOT_ENTRIES: usize = 256;
const MAX_ROOT_ENTRIES: usize = 16;
const MAX_PREFIX_ENTRIES: usize = 16_384;
const MAX_ENVELOPE_BYTES: u64 = (crate::MAX_BUNDLE_PLAINTEXT_BYTES + 128 + 16) as u64;
const MAX_OBJECT_TEMP_ENTRIES: usize = 8;
const MAX_OBJECT_TEMP_AGGREGATE_BYTES: u64 = MAX_ENVELOPE_BYTES * 2;
const MAX_GARBAGE_COLLECTION_RETENTIONS: usize = 65_536;
const MAX_GARBAGE_COLLECTION_OBJECTS: usize = 65_536;
const MAX_GARBAGE_COLLECTION_ARTIFACTS: usize = 262_144;
const MAX_ROTATION_AGGREGATE_BYTES: u64 =
    MAX_ENVELOPE_BYTES * MAX_GARBAGE_COLLECTION_ARTIFACTS as u64;
const MAX_EPOCH_DIRECTORIES: usize = 256;
const BUNDLE_FINGERPRINT_DOMAIN: &[u8] = b"netcatty-secret-gc-bundle-fingerprint-v1\0";
const PUBLISH_ATTEMPTS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum FileSlot {
    A,
    B,
}

impl FileSlot {
    const fn for_generation(generation: u64) -> Self {
        if generation % 2 == 1 {
            Self::A
        } else {
            Self::B
        }
    }

    const fn directory(self) -> &'static str {
        match self {
            Self::A => SLOT_A_DIRECTORY,
            Self::B => SLOT_B_DIRECTORY,
        }
    }

    const fn envelope_slot(self) -> SecretEnvelopeSlot {
        match self {
            Self::A => SecretEnvelopeSlot::A,
            Self::B => SecretEnvelopeSlot::B,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnerEnvelope {
    magic: String,
    format_version: u32,
    store_id: String,
    checksum: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OwnerChecksumPayload<'a> {
    magic: &'a str,
    format_version: u32,
    store_id: &'a str,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KeysetEnvelope {
    magic: String,
    format_version: u32,
    store_id: String,
    slot: FileSlot,
    generation: u64,
    active_master_key_epoch: u32,
    checksum: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RotatedKeysetEnvelope {
    magic: String,
    format_version: u32,
    store_id: String,
    slot: FileSlot,
    generation: u64,
    active_master_key_epoch: u32,
    object_storage: String,
    checksum: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AnyKeysetEnvelope {
    Legacy(KeysetEnvelope),
    Rotated(RotatedKeysetEnvelope),
}

impl AnyKeysetEnvelope {
    const fn generation(&self) -> u64 {
        match self {
            Self::Legacy(envelope) => envelope.generation,
            Self::Rotated(envelope) => envelope.generation,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeysetChecksumPayload<'a> {
    magic: &'a str,
    format_version: u32,
    store_id: &'a str,
    slot: FileSlot,
    generation: u64,
    active_master_key_epoch: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RotatedKeysetChecksumPayload<'a> {
    magic: &'a str,
    format_version: u32,
    store_id: &'a str,
    slot: FileSlot,
    generation: u64,
    active_master_key_epoch: u32,
    object_storage: &'a str,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RotationManifestEnvelope {
    magic: String,
    format_version: u32,
    store_id: String,
    source_master_key_epoch: u32,
    source_keyset_generation: u64,
    source_object_storage: String,
    target_master_key_epoch: u32,
    source_keyset_commitment: String,
    source_tree_commitment: String,
    retention_commitment: String,
    retained_objects: u64,
    checksum: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RotationManifestChecksumPayload<'a> {
    magic: &'a str,
    format_version: u32,
    store_id: &'a str,
    source_master_key_epoch: u32,
    source_keyset_generation: u64,
    source_object_storage: &'a str,
    target_master_key_epoch: u32,
    source_keyset_commitment: &'a str,
    source_tree_commitment: &'a str,
    retention_commitment: &'a str,
    retained_objects: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RetiredSourceMarkerEnvelope {
    magic: String,
    format_version: u32,
    store_id: String,
    source_master_key_epoch: u32,
    target_master_key_epoch: u32,
    rotation_manifest_commitment: String,
    checksum: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RetiredSourceMarkerChecksumPayload<'a> {
    magic: &'a str,
    format_version: u32,
    store_id: &'a str,
    source_master_key_epoch: u32,
    target_master_key_epoch: u32,
    rotation_manifest_commitment: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObjectStorageLayout {
    LegacyFlat,
    EpochDirectory,
}

type ProcessGate = Arc<Mutex<()>>;
static PROCESS_GATES: OnceLock<Mutex<HashMap<PathBuf, Weak<Mutex<()>>>>> = OnceLock::new();

#[derive(Clone, Copy, PartialEq, Eq)]
struct ConfirmedRetiredSourceMarker {
    store_id: Uuid,
    source_epoch: u32,
    target_epoch: u32,
    rotation_manifest_commitment: [u8; 32],
    marker_commitment: [u8; 32],
}

type RetiredSourceConfirmationCache = Arc<Mutex<Option<ConfirmedRetiredSourceMarker>>>;

/// The disposition of an operation after its immutable hard-link publication
/// point. Only `Durable` authorizes a caller to advance a cross-store journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretPublicationDurability {
    Durable,
    PublishedDurabilityUncertain,
    PublicationIndeterminate,
}

/// A mutation whose final value is available only after confirmed durability.
pub enum SecretFileMutation<T> {
    Durable(T),
    PublishedDurabilityUncertain,
    PublicationIndeterminate,
}

impl<T> SecretFileMutation<T> {
    #[must_use]
    pub const fn durability(&self) -> SecretPublicationDurability {
        match self {
            Self::Durable(_) => SecretPublicationDurability::Durable,
            Self::PublishedDurabilityUncertain => {
                SecretPublicationDurability::PublishedDurabilityUncertain
            }
            Self::PublicationIndeterminate => SecretPublicationDurability::PublicationIndeterminate,
        }
    }

    pub fn into_durable(self) -> Option<T> {
        match self {
            Self::Durable(value) => Some(value),
            Self::PublishedDurabilityUncertain | Self::PublicationIndeterminate => None,
        }
    }
}

impl<T> fmt::Debug for SecretFileMutation<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Durable(_) => "SecretFileMutation::Durable([REDACTED])",
            Self::PublishedDurabilityUncertain => {
                "SecretFileMutation::PublishedDurabilityUncertain"
            }
            Self::PublicationIndeterminate => "SecretFileMutation::PublicationIndeterminate",
        })
    }
}

/// A validated owner/keyset view. Debug deliberately omits its UUID and epoch.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecretFileStoreState {
    store_id: Uuid,
    active_master_key_epoch: u32,
    keyset_generation: u64,
    object_storage_layout: ObjectStorageLayout,
}

impl SecretFileStoreState {
    #[must_use]
    pub const fn store_id(&self) -> Uuid {
        self.store_id
    }

    #[must_use]
    pub const fn active_master_key_epoch(&self) -> u32 {
        self.active_master_key_epoch
    }

    #[must_use]
    pub const fn keyset_generation(&self) -> u64 {
        self.keyset_generation
    }
}

impl fmt::Debug for SecretFileStoreState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretFileStoreState([REDACTED])")
    }
}

/// An opaque backend locator derived from a store UUID and an entity ID.
/// It has no `Display` or Serde implementation and never retains the real ID.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecretObjectLocator {
    store_id: Uuid,
    entity_digest: SecretEntityDigest,
    object_digest: [u8; 32],
}

impl fmt::Debug for SecretObjectLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretObjectLocator([REDACTED])")
    }
}

impl SecretObjectLocator {
    /// Returns the canonical backend-only value persisted by the Vault.
    /// Callers must never send this value to renderer IPC or diagnostics.
    #[must_use]
    pub fn backend_locator_hex(&self) -> String {
        hex_encode(&self.object_digest)
    }
}

/// One Vault-authorized managed-secret revision that garbage collection must
/// retain. The real entity ID and backend locator are both required so the
/// file store can independently prove their store-bound relationship.
///
/// This backend-only value intentionally has no Serde or `Display`
/// implementation. Its `Debug` form discloses no identifiers or locator.
///
/// ```compile_fail
/// use netcatty_secret_store::SecretObjectRetention;
/// fn requires_serialize<T: serde::Serialize>() {}
/// requires_serialize::<SecretObjectRetention>();
/// ```
///
/// ```compile_fail
/// use netcatty_secret_store::SecretObjectRetention;
/// let retained = SecretObjectRetention::new("entity", "01".repeat(32), 1).unwrap();
/// let _rendered = format!("{retained}");
/// ```
pub struct SecretObjectRetention {
    entity_id: String,
    backend_locator_hex: String,
    custody_revision: u64,
}

impl SecretObjectRetention {
    pub fn new(
        entity_id: impl Into<String>,
        backend_locator_hex: impl Into<String>,
        custody_revision: u64,
    ) -> Result<Self, SecretFileStoreError> {
        let entity_id = entity_id.into();
        let backend_locator_hex = backend_locator_hex.into();
        SecretEntityDigest::derive(&entity_id)
            .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidInput))?;
        if decode_hex_32(&backend_locator_hex).is_none() || custody_revision == 0 {
            return Err(SecretFileStoreErrorCode::InvalidInput.into());
        }
        Ok(Self {
            entity_id,
            backend_locator_hex,
            custody_revision,
        })
    }
}

impl fmt::Debug for SecretObjectRetention {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretObjectRetention([REDACTED])")
    }
}

/// Counts from one completed ordinary filesystem cleanup.
///
/// Deleting encrypted files is not physical secure erasure, especially on
/// copy-on-write filesystems and SSDs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecretBlobGarbageCollection {
    removed_blob_revisions: usize,
    removed_objects: usize,
}

/// Proof returned only after a master-key rotation has a stable v2 keyset and
/// an exact, durably re-read target object graph.
///
/// The caller must retain both OS-held keys for every non-durable mutation
/// outcome. Only this value authorizes deletion of the source epoch key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CompletedMasterKeyRotation {
    state: SecretFileStoreState,
    source_epoch: u32,
    target_epoch: u32,
    retained_objects: usize,
}

impl CompletedMasterKeyRotation {
    #[must_use]
    pub const fn state(&self) -> SecretFileStoreState {
        self.state
    }

    #[must_use]
    pub const fn source_epoch(&self) -> u32 {
        self.source_epoch
    }

    #[must_use]
    pub const fn target_epoch(&self) -> u32 {
        self.target_epoch
    }

    #[must_use]
    pub const fn retained_objects(&self) -> usize {
        self.retained_objects
    }

    /// This is true only because construction is gated by the complete
    /// durability and exact-graph confirmation described on the type.
    #[must_use]
    pub const fn old_master_key_deletion_authorized(&self) -> bool {
        true
    }
}

impl fmt::Debug for CompletedMasterKeyRotation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompletedMasterKeyRotation([REDACTED])")
    }
}

/// Secret-free recovery coordinates read from the one authoritative rotation
/// manifest. It has no Serde or `Display` implementation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MasterKeyRotationRecovery {
    source_state: SecretFileStoreState,
    target_epoch: u32,
    retained_objects: usize,
    completed: bool,
}

impl MasterKeyRotationRecovery {
    #[must_use]
    pub const fn source_state(&self) -> SecretFileStoreState {
        self.source_state
    }

    #[must_use]
    pub const fn source_epoch(&self) -> u32 {
        self.source_state.active_master_key_epoch
    }

    #[must_use]
    pub const fn target_epoch(&self) -> u32 {
        self.target_epoch
    }

    #[must_use]
    pub const fn retained_objects(&self) -> usize {
        self.retained_objects
    }

    /// A completed historical marker needs no source key to keep the active
    /// store usable. `false` means both source and target keys are required to
    /// resume safely.
    #[must_use]
    pub const fn completed(&self) -> bool {
        self.completed
    }
}

impl fmt::Debug for MasterKeyRotationRecovery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MasterKeyRotationRecovery([REDACTED])")
    }
}

impl SecretBlobGarbageCollection {
    #[must_use]
    pub const fn removed_blob_revisions(&self) -> usize {
        self.removed_blob_revisions
    }

    #[must_use]
    pub const fn removed_objects(&self) -> usize {
        self.removed_objects
    }
}

impl fmt::Debug for SecretBlobGarbageCollection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBlobGarbageCollection")
            .field("removed_blob_revisions", &self.removed_blob_revisions)
            .field("removed_objects", &self.removed_objects)
            .finish()
    }
}

/// Two independently encrypted immutable copies prepared for publication.
pub struct PreparedSecretObject {
    locator: SecretObjectLocator,
    revision: u64,
    epoch: u32,
    object_storage_layout: ObjectStorageLayout,
    a_context: SecretEnvelopeContext,
    b_context: SecretEnvelopeContext,
    a_envelope: EncryptedSecretEnvelope,
    b_envelope: EncryptedSecretEnvelope,
}

impl PreparedSecretObject {
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

impl fmt::Debug for PreparedSecretObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedSecretObject([REDACTED])")
    }
}

/// A validated, caller-selected local custody root. Opening creates only the
/// permanent `transaction.lock`; owner/keyset initialization remains an
/// explicit operation under [`SecretFileStoreExclusiveGuard`].
#[derive(Clone)]
pub struct SecretFileStore {
    root: Arc<PathBuf>,
    gate: ProcessGate,
    retired_source_confirmation: RetiredSourceConfirmationCache,
}

impl fmt::Debug for SecretFileStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretFileStore([REDACTED])")
    }
}

/// Exclusive process and file lock for every owner/keyset/blob operation.
///
/// The future desktop coordinator must keep this guard held while it performs
/// first-time `OsMasterKeyStore::create_if_absent` and then calls
/// [`Self::initialize`]. The keyring's process-local mutex is not a substitute
/// for this cross-process lock. This crate intentionally does not depend on
/// `netcatty-credentials`, avoiding a dependency cycle.
pub struct SecretFileStoreExclusiveGuard<'a> {
    store: &'a SecretFileStore,
    _process_guard: MutexGuard<'a, ()>,
    lock_file: File,
}

impl fmt::Debug for SecretFileStoreExclusiveGuard<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretFileStoreExclusiveGuard([REDACTED])")
    }
}

impl Drop for SecretFileStoreExclusiveGuard<'_> {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.lock_file);
    }
}

impl SecretFileStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, SecretFileStoreError> {
        let supplied = root.as_ref();
        if !supplied.is_absolute() {
            return Err(SecretFileStoreErrorCode::InvalidRoot.into());
        }
        ensure_root_directory(supplied)?;
        reject_reparse_directory(supplied, SecretFileStoreErrorCode::InvalidRoot)?;
        let root = fs::canonicalize(supplied)
            .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidRoot))?;
        reject_reparse_directory(&root, SecretFileStoreErrorCode::InvalidRoot)?;
        validate_root_entry_names(&root, true)?;
        ensure_transaction_lock(&root)?;
        let gate = process_gate(&root)?;
        let store = Self {
            root: Arc::new(root),
            gate,
            retired_source_confirmation: Arc::new(Mutex::new(None)),
        };
        {
            let guard = store.lock_exclusive()?;
            guard.validate_layout_for_open()?;
        }
        Ok(store)
    }

    pub fn lock_exclusive(
        &self,
    ) -> Result<SecretFileStoreExclusiveGuard<'_>, SecretFileStoreError> {
        let process_guard = self
            .gate
            .lock()
            .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::LockPoisoned))?;
        let lock_file = open_existing_regular(&self.root.join(TRANSACTION_LOCK_FILE), true)
            .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::LockUnavailable))?;
        lock_file
            .lock_exclusive()
            .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::LockUnavailable))?;
        reject_reparse_directory(&self.root, SecretFileStoreErrorCode::InvalidRoot)?;
        if lock_file
            .metadata()
            .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::LockUnavailable))?
            .len()
            != 0
        {
            let _ = FileExt::unlock(&lock_file);
            return Err(SecretFileStoreErrorCode::LockUnavailable.into());
        }
        if let Err(error) = validate_root_entry_names(&self.root, false) {
            let _ = FileExt::unlock(&lock_file);
            return Err(error);
        }
        Ok(SecretFileStoreExclusiveGuard {
            store: self,
            _process_guard: process_guard,
            lock_file,
        })
    }

    pub fn with_exclusive_lock<T, F>(&self, operation: F) -> Result<T, SecretFileStoreError>
    where
        F: FnOnce(&SecretFileStoreExclusiveGuard<'_>) -> Result<T, SecretFileStoreError>,
    {
        let guard = self.lock_exclusive()?;
        operation(&guard)
    }
}

impl SecretFileStoreExclusiveGuard<'_> {
    fn validate_layout_for_open(&self) -> Result<(), SecretFileStoreError> {
        reject_reparse_directory(&self.store.root, SecretFileStoreErrorCode::InvalidRoot)?;
        validate_lock_file(&self.store.root.join(TRANSACTION_LOCK_FILE))?;
        validate_root_entry_names(&self.store.root, false)?;
        let Some(store_id) = read_optional_owner(&self.store.root)? else {
            return Ok(());
        };

        let keyset = self.store.root.join(KEYSET_DIRECTORY);
        if path_exists(&keyset)? {
            reject_reparse_directory(&keyset, SecretFileStoreErrorCode::ArtifactConflict)?;
            for slot in [FileSlot::A, FileSlot::B] {
                let directory = keyset.join(slot.directory());
                if path_exists(&directory)? {
                    reject_reparse_directory(
                        &directory,
                        SecretFileStoreErrorCode::ArtifactConflict,
                    )?;
                }
            }
            if path_exists(&keyset.join(SLOT_A_DIRECTORY))?
                && path_exists(&keyset.join(SLOT_B_DIRECTORY))?
            {
                let _ = load_keyset(&self.store.root, store_id)?;
            }
        }
        let objects = self.store.root.join(OBJECTS_DIRECTORY);
        if path_exists(&objects)? {
            reject_reparse_directory(&objects, SecretFileStoreErrorCode::ArtifactConflict)?;
        }
        validate_epoch_storage_roots(&self.store.root, store_id)?;
        if path_exists(&keyset.join(SLOT_A_DIRECTORY))?
            && path_exists(&keyset.join(SLOT_B_DIRECTORY))?
            && let Some(state) = load_keyset(&self.store.root, store_id)?.state()
            && state.object_storage_layout == ObjectStorageLayout::EpochDirectory
        {
            validate_epoch_storage_root(
                &epoch_storage_root(&self.store.root, state.active_master_key_epoch),
                store_id,
                false,
            )?;
        }
        Ok(())
    }

    /// Returns the durable owner UUID, or `None` only when the root contains
    /// exactly the permanent transaction lock and is authoritatively empty.
    pub fn owner_id(&self) -> Result<Option<Uuid>, SecretFileStoreError> {
        self.validate_layout_for_open()?;
        read_optional_owner(&self.store.root)
    }

    /// Publishes the caller-selected UUID and initial active master-key epoch.
    ///
    /// The caller must create the corresponding OS-held key while this guard
    /// remains held, then call this method. A non-durable mutation result means
    /// that the key must be retained for recovery; it must not be compensated.
    pub fn initialize(
        &self,
        store_id: Uuid,
        active_master_key_epoch: u32,
    ) -> Result<SecretFileMutation<SecretFileStoreState>, SecretFileStoreError> {
        validate_store_id(store_id)?;
        if active_master_key_epoch == 0 {
            return Err(SecretFileStoreErrorCode::InvalidInput.into());
        }
        self.validate_layout_for_open()?;
        if let Some(owner) = read_optional_owner(&self.store.root)? {
            let keyset = self.store.root.join(KEYSET_DIRECTORY);
            if path_exists(&keyset.join(SLOT_A_DIRECTORY))?
                && path_exists(&keyset.join(SLOT_B_DIRECTORY))?
                && load_keyset(&self.store.root, owner)?.state().is_some()
            {
                ensure_no_pending_master_key_rotation(
                    &self.store.root,
                    &self.store.retired_source_confirmation,
                )?;
            }
        }
        let publication_visible;
        match read_optional_owner(&self.store.root)? {
            Some(existing) if existing != store_id => {
                return Err(SecretFileStoreErrorCode::InvalidOwner.into());
            }
            Some(_) => publication_visible = true,
            None => {
                ensure_authoritatively_empty(&self.store.root)?;
                let encoded = encode_owner(store_id)?;
                let durability = publish_named_no_overwrite(
                    &self.store.root,
                    OWNER_FILE,
                    ".owner",
                    &encoded,
                    MAX_ROOT_ENTRIES,
                )?;
                publication_visible = true;
                match durability {
                    SecretPublicationDurability::Durable => {}
                    SecretPublicationDurability::PublishedDurabilityUncertain => {
                        return Ok(SecretFileMutation::PublishedDurabilityUncertain);
                    }
                    SecretPublicationDurability::PublicationIndeterminate => {
                        return Ok(SecretFileMutation::PublicationIndeterminate);
                    }
                }
                if read_owner(&self.store.root.join(OWNER_FILE))? != store_id {
                    return Ok(SecretFileMutation::PublicationIndeterminate);
                }
            }
        }

        if let Err(error) = ensure_store_directories(&self.store.root) {
            return if publication_visible {
                Ok(SecretFileMutation::PublicationIndeterminate)
            } else {
                Err(error)
            };
        }
        let current = load_keyset(&self.store.root, store_id)?;
        if !current.can_initialize_epoch(active_master_key_epoch) {
            return Err(SecretFileStoreErrorCode::InvalidKeyset.into());
        }
        if current.state().is_none() {
            // An owner can survive a crash before the first keyset copy. It
            // must not authorize a new epoch over pre-existing ciphertext:
            // prove the objects authority empty before publishing generation 1.
            ensure_objects_authoritatively_empty(&self.store.root)?;
        }
        self.activate_epoch_internal(
            store_id,
            active_master_key_epoch,
            ObjectStorageLayout::LegacyFlat,
            false,
        )
    }

    /// Loads the selected keyset. One valid A/B copy may be used for reads,
    /// but mutation and durability confirmation require a healthy pair.
    pub fn load_state(&self) -> Result<SecretFileStoreState, SecretFileStoreError> {
        self.validate_layout_for_open()?;
        let store_id = read_optional_owner(&self.store.root)?
            .ok_or_else(|| SecretFileStoreError::new(SecretFileStoreErrorCode::NotInitialized))?;
        let loaded = load_keyset(&self.store.root, store_id)?;
        loaded
            .state()
            .ok_or_else(|| SecretFileStoreErrorCode::NotInitialized.into())
    }

    /// Changes (or repairs redundancy for) the active key epoch. The expected
    /// state prevents a stale coordinator from rotating a changed keyset.
    pub fn activate_master_key_epoch(
        &self,
        expected: &SecretFileStoreState,
        new_epoch: u32,
    ) -> Result<SecretFileMutation<SecretFileStoreState>, SecretFileStoreError> {
        ensure_no_pending_master_key_rotation(
            &self.store.root,
            &self.store.retired_source_confirmation,
        )?;
        if new_epoch == 0 {
            return Err(SecretFileStoreErrorCode::InvalidInput.into());
        }
        let owner = read_optional_owner(&self.store.root)?
            .ok_or_else(|| SecretFileStoreError::new(SecretFileStoreErrorCode::NotInitialized))?;
        if owner != expected.store_id {
            return Err(SecretFileStoreErrorCode::InvalidKeyset.into());
        }
        let loaded = load_keyset(&self.store.root, owner)?;
        if loaded.state() != Some(*expected) {
            return Err(SecretFileStoreErrorCode::InvalidKeyset.into());
        }
        let missing_slot_repair = match (&loaded.slot_a.keyset, &loaded.slot_b.keyset) {
            (Some(selected), None) => {
                loaded.slot_b.empty
                    && loaded.slot_b.max_seen.is_none()
                    && selected.active_master_key_epoch == new_epoch
            }
            (None, Some(selected)) => {
                loaded.slot_a.empty
                    && loaded.slot_a.max_seen.is_none()
                    && selected.active_master_key_epoch == new_epoch
            }
            _ => false,
        };
        if (loaded.slot_a.keyset.is_none() || loaded.slot_b.keyset.is_none())
            && !missing_slot_repair
        {
            return Err(SecretFileStoreErrorCode::InvalidKeyset.into());
        }
        if new_epoch != expected.active_master_key_epoch {
            if expected.object_storage_layout != ObjectStorageLayout::LegacyFlat {
                return Err(SecretFileStoreErrorCode::InvalidKeyset.into());
            }
            ensure_objects_authoritatively_empty(&self.store.root)?;
        }
        self.activate_epoch_internal(owner, new_epoch, expected.object_storage_layout, true)
    }

    /// Syncs both keyset slots and proves that the exact healthy pair is still
    /// selected. Fallback state is deliberately insufficient confirmation.
    pub fn confirm_keyset_durability(
        &self,
        expected: &SecretFileStoreState,
    ) -> Result<SecretFileStoreState, SecretFileStoreError> {
        let loaded = load_keyset(&self.store.root, expected.store_id)?;
        if loaded.state() != Some(*expected) || !loaded.is_stable() {
            return Err(SecretFileStoreErrorCode::DurabilityUnconfirmed.into());
        }
        confirm_loaded_keyset(&self.store.root, &loaded)?;
        Ok(*expected)
    }

    pub fn derive_object_locator(
        &self,
        entity_id: &str,
    ) -> Result<SecretObjectLocator, SecretFileStoreError> {
        let state = self.load_state()?;
        derive_locator(state.store_id, entity_id)
    }

    /// Reconstructs a locator from a backend-only Vault value and proves that
    /// it belongs to the supplied real entity ID and this store.
    pub fn restore_object_locator(
        &self,
        entity_id: &str,
        backend_locator_hex: &str,
    ) -> Result<SecretObjectLocator, SecretFileStoreError> {
        let locator = self.derive_object_locator(entity_id)?;
        let encoded = decode_hex_32(backend_locator_hex)
            .ok_or_else(|| SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidInput))?;
        if !bool::from(locator.object_digest.ct_eq(&encoded)) {
            return Err(SecretFileStoreErrorCode::InvalidInput.into());
        }
        Ok(locator)
    }

    pub fn prepare_object(
        &self,
        expected: &SecretFileStoreState,
        master_key: &EnvelopeMasterKey,
        locator: &SecretObjectLocator,
        revision: u64,
        bundle: SshSecretBundle,
    ) -> Result<PreparedSecretObject, SecretFileStoreError> {
        ensure_no_pending_master_key_rotation(
            &self.store.root,
            &self.store.retired_source_confirmation,
        )?;
        let loaded = load_keyset(&self.store.root, expected.store_id)?;
        if loaded.state() != Some(*expected)
            || !loaded.is_stable()
            || locator.store_id != expected.store_id
            || revision == 0
        {
            return Err(SecretFileStoreErrorCode::InvalidInput.into());
        }
        prepare_object_for_epoch(
            master_key,
            locator,
            revision,
            expected.active_master_key_epoch,
            expected.object_storage_layout,
            bundle,
        )
    }

    pub fn publish_object(
        &self,
        master_key: &EnvelopeMasterKey,
        prepared: &PreparedSecretObject,
    ) -> Result<SecretFileMutation<()>, SecretFileStoreError> {
        ensure_no_pending_master_key_rotation(
            &self.store.root,
            &self.store.retired_source_confirmation,
        )?;
        let loaded = load_keyset(&self.store.root, prepared.locator.store_id)?;
        let Some(state) = loaded.state() else {
            return Err(SecretFileStoreErrorCode::InvalidKeyset.into());
        };
        if !loaded.is_stable()
            || state.active_master_key_epoch != prepared.epoch
            || state.object_storage_layout != prepared.object_storage_layout
        {
            return Err(SecretFileStoreErrorCode::InvalidKeyset.into());
        }
        let storage_root = object_storage_root(&self.store.root, &state);
        publish_prepared_object_at_storage_root(&storage_root, master_key, prepared)
    }

    pub fn confirm_object_durability(
        &self,
        master_key: &EnvelopeMasterKey,
        locator: &SecretObjectLocator,
        revision: u64,
    ) -> Result<(), SecretFileStoreError> {
        ensure_no_pending_master_key_rotation(
            &self.store.root,
            &self.store.retired_source_confirmation,
        )?;
        let loaded = load_keyset(&self.store.root, locator.store_id)?;
        let state = loaded
            .state()
            .ok_or_else(|| SecretFileStoreError::new(SecretFileStoreErrorCode::NotInitialized))?;
        if !loaded.is_stable() {
            return Err(SecretFileStoreErrorCode::DurabilityUnconfirmed.into());
        }
        let storage_root = object_storage_root(&self.store.root, &state);
        validate_existing_object_directories(&storage_root, locator)?;
        let object_root = object_directory(&storage_root, locator);
        confirm_object_internal(
            &object_root,
            master_key,
            locator,
            revision,
            state.active_master_key_epoch,
            None,
        )?;
        cleanup_object_temps(
            &object_root,
            master_key,
            locator,
            revision,
            state.active_master_key_epoch,
        );
        Ok(())
    }

    pub fn resolve_object(
        &self,
        master_key: &EnvelopeMasterKey,
        locator: &SecretObjectLocator,
        revision: u64,
    ) -> Result<SshSecretBundle, SecretFileStoreError> {
        if revision == 0 {
            return Err(SecretFileStoreErrorCode::InvalidInput.into());
        }
        let loaded = load_keyset(&self.store.root, locator.store_id)?;
        let state = loaded
            .state()
            .ok_or_else(|| SecretFileStoreError::new(SecretFileStoreErrorCode::NotInitialized))?;
        let storage_root = object_storage_root(&self.store.root, &state);
        let object_root = object_directory(&storage_root, locator);
        validate_existing_object_directories(&storage_root, locator)?;
        let (a_context, b_context) =
            object_contexts(locator, revision, state.active_master_key_epoch)?;
        let a = read_object_copy(
            &object_root.join(SLOT_A_DIRECTORY),
            FileSlot::A,
            revision,
            &a_context,
            master_key,
        );
        let b = read_object_copy(
            &object_root.join(SLOT_B_DIRECTORY),
            FileSlot::B,
            revision,
            &b_context,
            master_key,
        );
        match (a, b) {
            (Ok(Some(a)), Ok(Some(b))) if a.bundle.contents_match(&b.bundle) => Ok(a.bundle),
            (Ok(Some(a)), Ok(None)) | (Ok(None), Ok(Some(a))) => Ok(a.bundle),
            (Ok(Some(a)), Err(error)) | (Err(error), Ok(Some(a)))
                if error.code() == SecretFileStoreErrorCode::ObjectUnavailable =>
            {
                Ok(a.bundle)
            }
            (Err(error), _) | (_, Err(error))
                if error.code() != SecretFileStoreErrorCode::ObjectUnavailable =>
            {
                Err(error)
            }
            _ => Err(SecretFileStoreErrorCode::ObjectUnavailable.into()),
        }
    }

    /// Discovers the one pending or just-completed durable rotation marker.
    /// A pending result supplies the exact source state needed to load both
    /// OS-held keys after restart. A completed result requires only the
    /// active target key and does not request the already-retired source key.
    pub fn inspect_master_key_rotation(
        &self,
    ) -> Result<Option<MasterKeyRotationRecovery>, SecretFileStoreError> {
        self.validate_layout_for_open()
            .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
        inspect_master_key_rotation_internal(
            &self.store.root,
            &self.store.retired_source_confirmation,
        )
    }

    /// Re-confirms an already stable target using only its active key. This is
    /// the restart path after the source key was already deleted following a
    /// previously returned durable completion.
    pub fn confirm_completed_master_key_rotation(
        &self,
        recovery: &MasterKeyRotationRecovery,
        new_master_key: &EnvelopeMasterKey,
        retained: &[SecretObjectRetention],
    ) -> Result<CompletedMasterKeyRotation, SecretFileStoreError> {
        if !recovery.completed {
            return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
        }
        self.validate_layout_for_open()
            .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
        let owner = read_optional_owner(&self.store.root)
            .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?
            .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
        if owner != recovery.source_state.store_id {
            return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
        }
        let retention = validate_garbage_collection_retention(owner, retained)
            .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
        confirm_completed_target_only(&self.store.root, recovery, new_master_key, &retention)
    }

    /// Persists the coordinator's assertion that the source epoch OS key is
    /// already absent. This never deletes ciphertext. Once durable, rotation
    /// discovery returns `None` for this completed lineage.
    pub fn acknowledge_source_key_retired(
        &self,
        completion: &CompletedMasterKeyRotation,
    ) -> Result<SecretFileMutation<()>, SecretFileStoreError> {
        self.validate_layout_for_open()
            .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
        let loaded = load_keyset(&self.store.root, completion.state.store_id)
            .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
        let current = loaded
            .state()
            .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
        if !loaded.is_stable()
            || current.active_master_key_epoch != completion.target_epoch
            || current.object_storage_layout != ObjectStorageLayout::EpochDirectory
        {
            return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
        }
        let epoch_root = epoch_storage_root(&self.store.root, completion.target_epoch);
        let manifest_path = epoch_root.join(ROTATION_MANIFEST_FILE);
        let manifest = read_rotation_manifest(&manifest_path)?;
        if manifest.store_id != completion.state.store_id
            || manifest.source_state.active_master_key_epoch != completion.source_epoch
            || manifest.target_epoch != completion.target_epoch
        {
            return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
        }
        let mutation = publish_retired_source_marker(&epoch_root, &manifest, &manifest_path)?;
        if matches!(mutation, SecretFileMutation::Durable(())) {
            let confirmation =
                retired_source_marker_confirmation(&epoch_root, &manifest, &manifest_path)?;
            *self
                .store
                .retired_source_confirmation
                .lock()
                .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)? =
                Some(confirmation);
        }
        Ok(mutation)
    }

    /// Re-encrypts the complete fallback-aware retention set into the next
    /// master-key epoch and activates it only after exact durable validation.
    ///
    /// This call is restart-safe from a stable source pair, a mixed v1/v2
    /// pair, or the exact stable target pair. The source ciphertext is never
    /// deleted. The caller must retain both OS-held keys unless the returned
    /// mutation is `Durable`; only its completion value authorizes deletion
    /// of the source epoch key.
    pub fn rotate_master_key_epoch(
        &self,
        expected_source: &SecretFileStoreState,
        old_master_key: &EnvelopeMasterKey,
        target_epoch: u32,
        new_master_key: &EnvelopeMasterKey,
        retained: &[SecretObjectRetention],
    ) -> Result<SecretFileMutation<CompletedMasterKeyRotation>, SecretFileStoreError> {
        self.validate_layout_for_open()
            .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
        let owner = read_optional_owner(&self.store.root)
            .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?
            .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
        if owner != expected_source.store_id
            || target_epoch
                != expected_source
                    .active_master_key_epoch
                    .checked_add(1)
                    .ok_or(SecretFileStoreErrorCode::GenerationOverflow)?
        {
            return Err(SecretFileStoreErrorCode::InvalidInput.into());
        }
        expected_source
            .keyset_generation
            .checked_add(2)
            .ok_or(SecretFileStoreErrorCode::GenerationOverflow)?;
        let retention = validate_garbage_collection_retention(owner, retained)
            .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
        let loaded = load_keyset(&self.store.root, owner)
            .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
        let phase = rotation_keyset_phase(&loaded, *expected_source, target_epoch)?;
        if phase == RotationKeysetPhase::StableTarget {
            let recovery = MasterKeyRotationRecovery {
                source_state: *expected_source,
                target_epoch,
                retained_objects: retention.keys.len(),
                completed: true,
            };
            return match confirm_completed_target_only(
                &self.store.root,
                &recovery,
                new_master_key,
                &retention,
            ) {
                Ok(completed) => Ok(SecretFileMutation::Durable(completed)),
                Err(_) => Ok(SecretFileMutation::PublicationIndeterminate),
            };
        }
        let plan = preflight_master_key_rotation_source(
            &self.store.root,
            *expected_source,
            old_master_key,
            &retention,
            target_epoch,
        )?;
        let target_root = epoch_storage_root(&self.store.root, target_epoch);

        if phase != RotationKeysetPhase::StableSource && !path_exists(&target_root)? {
            return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
        }
        if phase == RotationKeysetPhase::StableSource {
            match ensure_epoch_storage_root(&self.store.root, owner, target_epoch) {
                Ok(SecretPublicationDurability::Durable) => {}
                Ok(SecretPublicationDurability::PublishedDurabilityUncertain) => {
                    return Ok(SecretFileMutation::PublishedDurabilityUncertain);
                }
                Ok(SecretPublicationDurability::PublicationIndeterminate) | Err(_) => {
                    return Ok(SecretFileMutation::PublicationIndeterminate);
                }
            }
        }
        match publish_rotation_manifest(&target_root, &plan) {
            Ok(SecretPublicationDurability::Durable) => {}
            Ok(SecretPublicationDurability::PublishedDurabilityUncertain) => {
                return Ok(SecretFileMutation::PublishedDurabilityUncertain);
            }
            Ok(SecretPublicationDurability::PublicationIndeterminate) | Err(_) => {
                return Ok(SecretFileMutation::PublicationIndeterminate);
            }
        }
        cleanup_rotation_manifest_temps(&target_root, &plan);
        if preflight_master_key_rotation_target(&target_root, &plan, new_master_key, false).is_err()
        {
            return Ok(SecretFileMutation::PublicationIndeterminate);
        }

        if phase != RotationKeysetPhase::StableTarget {
            for entry in &plan.entries {
                let bundle =
                    match read_rotation_source_bundle(entry, plan.source_state, old_master_key) {
                        Ok(bundle) => bundle,
                        Err(_) => return Ok(SecretFileMutation::PublicationIndeterminate),
                    };
                let prepared = match prepare_object_for_epoch(
                    new_master_key,
                    &entry.locator,
                    entry.revision,
                    target_epoch,
                    ObjectStorageLayout::EpochDirectory,
                    bundle,
                ) {
                    Ok(prepared) => prepared,
                    Err(_) => return Ok(SecretFileMutation::PublicationIndeterminate),
                };
                match publish_prepared_object_at_storage_root(
                    &target_root,
                    new_master_key,
                    &prepared,
                ) {
                    Ok(SecretFileMutation::Durable(())) => {}
                    Ok(SecretFileMutation::PublishedDurabilityUncertain) => {
                        return Ok(SecretFileMutation::PublishedDurabilityUncertain);
                    }
                    Ok(SecretFileMutation::PublicationIndeterminate) | Err(_) => {
                        return Ok(SecretFileMutation::PublicationIndeterminate);
                    }
                }
            }
        }

        if confirm_master_key_rotation_graphs(
            &self.store.root,
            &target_root,
            &plan,
            old_master_key,
            new_master_key,
            &retention,
        )
        .is_err()
        {
            return Ok(SecretFileMutation::PublicationIndeterminate);
        }

        let activated = self.activate_epoch_internal(
            owner,
            target_epoch,
            ObjectStorageLayout::EpochDirectory,
            true,
        )?;
        let target_state = match activated {
            SecretFileMutation::Durable(state) => state,
            SecretFileMutation::PublishedDurabilityUncertain => {
                return Ok(SecretFileMutation::PublishedDurabilityUncertain);
            }
            SecretFileMutation::PublicationIndeterminate => {
                return Ok(SecretFileMutation::PublicationIndeterminate);
            }
        };
        let confirmed = match build_completed_master_key_rotation(
            &self.store.root,
            &target_root,
            &plan,
            old_master_key,
            new_master_key,
            &retention,
            target_state,
        ) {
            Ok(confirmed) => confirmed,
            Err(_) => return Ok(SecretFileMutation::PublicationIndeterminate),
        };
        Ok(SecretFileMutation::Durable(confirmed))
    }

    /// Deletes only authenticated blob revisions that are absent from the
    /// caller's fallback-aware Vault retention set.
    ///
    /// The complete owner, stable A/B keyset, retention input, object tree,
    /// filenames, envelope contexts, and AEAD contents are preflighted before
    /// the first unlink. Any uncertainty leaves every artifact untouched.
    /// Repeating a completed or durability-uncertain cleanup is supported.
    /// This is ordinary filesystem deletion, not physical secure erasure.
    pub fn garbage_collect_objects(
        &self,
        expected: &SecretFileStoreState,
        master_key: &EnvelopeMasterKey,
        retained: &[SecretObjectRetention],
    ) -> Result<SecretBlobGarbageCollection, SecretFileStoreError> {
        self.garbage_collect_objects_with_sync(expected, master_key, retained, sync_directory)
    }

    fn garbage_collect_objects_with_sync<F>(
        &self,
        expected: &SecretFileStoreState,
        master_key: &EnvelopeMasterKey,
        retained: &[SecretObjectRetention],
        sync: F,
    ) -> Result<SecretBlobGarbageCollection, SecretFileStoreError>
    where
        F: FnMut(&Path) -> io::Result<()>,
    {
        ensure_no_pending_master_key_rotation(
            &self.store.root,
            &self.store.retired_source_confirmation,
        )
        .map_err(|_| garbage_collection_uncertain())?;
        self.validate_layout_for_open()
            .map_err(|_| garbage_collection_uncertain())?;
        let owner = read_optional_owner(&self.store.root)
            .map_err(|_| garbage_collection_uncertain())?
            .ok_or_else(garbage_collection_uncertain)?;
        if owner != expected.store_id {
            return Err(garbage_collection_uncertain());
        }
        let loaded =
            load_keyset(&self.store.root, owner).map_err(|_| garbage_collection_uncertain())?;
        if loaded.state() != Some(*expected) || !loaded.is_stable() {
            return Err(garbage_collection_uncertain());
        }
        confirm_loaded_keyset(&self.store.root, &loaded)
            .map_err(|_| garbage_collection_uncertain())?;

        let retention = validate_garbage_collection_retention(owner, retained)?;
        let storage_root = object_storage_root(&self.store.root, expected);
        let plan = preflight_garbage_collection(&storage_root, *expected, master_key, &retention)?;

        let reloaded =
            load_keyset(&self.store.root, owner).map_err(|_| garbage_collection_uncertain())?;
        if !loaded.same_pair(&reloaded)
            || reloaded.state() != Some(*expected)
            || !reloaded.is_stable()
        {
            return Err(garbage_collection_uncertain());
        }
        execute_garbage_collection(&storage_root, plan, sync)
    }

    fn activate_epoch_internal(
        &self,
        store_id: Uuid,
        target_epoch: u32,
        target_layout: ObjectStorageLayout,
        allow_change: bool,
    ) -> Result<SecretFileMutation<SecretFileStoreState>, SecretFileStoreError> {
        let mut target_visible = false;
        for _ in 0..3 {
            let loaded = load_keyset(&self.store.root, store_id)?;
            if let Some(state) = loaded.state() {
                if loaded.has_higher_unreadable() {
                    return Err(SecretFileStoreErrorCode::InvalidKeyset.into());
                }
                if loaded.is_stable() {
                    if state.active_master_key_epoch == target_epoch
                        && state.object_storage_layout == target_layout
                    {
                        return match confirm_loaded_keyset(&self.store.root, &loaded) {
                            Ok(()) => {
                                if target_layout == ObjectStorageLayout::LegacyFlat {
                                    cleanup_keyset_artifacts(&self.store.root, &loaded);
                                }
                                cleanup_owner_temps(&self.store.root, store_id);
                                Ok(SecretFileMutation::Durable(state))
                            }
                            Err(_) if target_visible => {
                                if keyset_pair_is_still_visible(&self.store.root, &loaded) {
                                    Ok(SecretFileMutation::PublishedDurabilityUncertain)
                                } else {
                                    Ok(SecretFileMutation::PublicationIndeterminate)
                                }
                            }
                            Err(error) => Err(error),
                        };
                    }
                    if !allow_change {
                        return Err(SecretFileStoreErrorCode::InvalidKeyset.into());
                    }
                } else if state.active_master_key_epoch != target_epoch
                    || state.object_storage_layout != target_layout
                {
                    return Err(SecretFileStoreErrorCode::InvalidKeyset.into());
                } else {
                    target_visible = true;
                }
            }

            let generation = loaded.max_seen_generation().checked_add(1).ok_or_else(|| {
                SecretFileStoreError::new(SecretFileStoreErrorCode::GenerationOverflow)
            })?;
            let slot = FileSlot::for_generation(generation);
            let encoded = match target_layout {
                ObjectStorageLayout::LegacyFlat => {
                    encode_keyset(store_id, slot, generation, target_epoch)?
                }
                ObjectStorageLayout::EpochDirectory => {
                    encode_rotated_keyset(store_id, slot, generation, target_epoch)?
                }
            };
            let directory = self
                .store
                .root
                .join(KEYSET_DIRECTORY)
                .join(slot.directory());
            let final_name = keyset_final_name(generation);
            let durability = match publish_named_no_overwrite(
                &directory,
                &final_name,
                ".keyset",
                &encoded,
                MAX_SLOT_ENTRIES,
            ) {
                Ok(value) => value,
                Err(_error) if target_visible => {
                    return Ok(SecretFileMutation::PublicationIndeterminate);
                }
                Err(error) => return Err(error),
            };
            target_visible = true;
            match durability {
                SecretPublicationDurability::Durable => {
                    if read_keyset(&directory.join(&final_name), store_id, slot, generation)
                        .is_err()
                    {
                        return Ok(SecretFileMutation::PublicationIndeterminate);
                    }
                }
                SecretPublicationDurability::PublishedDurabilityUncertain => {
                    return Ok(SecretFileMutation::PublishedDurabilityUncertain);
                }
                SecretPublicationDurability::PublicationIndeterminate => {
                    return Ok(SecretFileMutation::PublicationIndeterminate);
                }
            }
        }
        Ok(SecretFileMutation::PublicationIndeterminate)
    }
}

fn prepare_object_for_epoch(
    master_key: &EnvelopeMasterKey,
    locator: &SecretObjectLocator,
    revision: u64,
    epoch: u32,
    object_storage_layout: ObjectStorageLayout,
    bundle: SshSecretBundle,
) -> Result<PreparedSecretObject, SecretFileStoreError> {
    let (a_context, b_context) = object_contexts(locator, revision, epoch)?;
    let a_envelope = encrypt_ssh_secret_bundle(master_key, &a_context, bundle)
        .map_err(|_| SecretFileStoreErrorCode::StorageUnavailable)?;
    let second_bundle = decrypt_ssh_secret_bundle(master_key, &a_context, a_envelope.as_bytes())
        .map_err(|_| SecretFileStoreErrorCode::StorageUnavailable)?;
    let b_envelope = encrypt_ssh_secret_bundle(master_key, &b_context, second_bundle)
        .map_err(|_| SecretFileStoreErrorCode::StorageUnavailable)?;
    Ok(PreparedSecretObject {
        locator: *locator,
        revision,
        epoch,
        object_storage_layout,
        a_context,
        b_context,
        a_envelope,
        b_envelope,
    })
}

fn publish_prepared_object_at_storage_root(
    storage_root: &Path,
    master_key: &EnvelopeMasterKey,
    prepared: &PreparedSecretObject,
) -> Result<SecretFileMutation<()>, SecretFileStoreError> {
    ensure_object_directories(storage_root, &prepared.locator)?;
    let object_root = object_directory(storage_root, &prepared.locator);
    let mut publication_visible = false;
    for (slot, context, envelope) in [
        (FileSlot::A, &prepared.a_context, &prepared.a_envelope),
        (FileSlot::B, &prepared.b_context, &prepared.b_envelope),
    ] {
        let directory = object_root.join(slot.directory());
        match find_object_revision(
            &directory,
            slot,
            prepared.revision,
            context,
            master_key,
            Some((context, envelope)),
        ) {
            Ok(Some(_)) => {
                publication_visible = true;
                continue;
            }
            Ok(None) => {}
            Err(error) => {
                return if publication_visible {
                    Ok(SecretFileMutation::PublicationIndeterminate)
                } else {
                    Err(error)
                };
            }
        }

        let final_name = blob_final_name(prepared.revision, context.generation());
        let temp_prefix = format!(
            ".blob-{:020}-{:020}",
            prepared.revision,
            context.generation()
        );
        let durability = match publish_named_no_overwrite(
            &directory,
            &final_name,
            &temp_prefix,
            envelope.as_bytes(),
            MAX_SLOT_ENTRIES,
        ) {
            Ok(value) => value,
            Err(error) => {
                return if publication_visible {
                    Ok(SecretFileMutation::PublicationIndeterminate)
                } else {
                    Err(error)
                };
            }
        };
        publication_visible = true;
        match durability {
            SecretPublicationDurability::Durable => {
                if find_object_revision(
                    &directory,
                    slot,
                    prepared.revision,
                    context,
                    master_key,
                    Some((context, envelope)),
                )
                .ok()
                .flatten()
                .is_none()
                {
                    return Ok(SecretFileMutation::PublicationIndeterminate);
                }
            }
            SecretPublicationDurability::PublishedDurabilityUncertain => {
                return Ok(SecretFileMutation::PublishedDurabilityUncertain);
            }
            SecretPublicationDurability::PublicationIndeterminate => {
                return Ok(SecretFileMutation::PublicationIndeterminate);
            }
        }
    }

    match confirm_object_internal(
        &object_root,
        master_key,
        &prepared.locator,
        prepared.revision,
        prepared.epoch,
        Some(prepared),
    ) {
        Ok(()) => {
            cleanup_object_temps(
                &object_root,
                master_key,
                &prepared.locator,
                prepared.revision,
                prepared.epoch,
            );
            Ok(SecretFileMutation::Durable(()))
        }
        Err(_) if publication_visible => {
            if object_pair_matches_prepared(&object_root, master_key, prepared) {
                Ok(SecretFileMutation::PublishedDurabilityUncertain)
            } else {
                Ok(SecretFileMutation::PublicationIndeterminate)
            }
        }
        Err(error) => Err(error),
    }
}

struct ValidatedKeyset {
    path: PathBuf,
    slot: FileSlot,
    generation: u64,
    active_master_key_epoch: u32,
    object_storage_layout: ObjectStorageLayout,
}

struct KeysetSlotProbe {
    empty: bool,
    max_seen: Option<u64>,
    keyset: Option<ValidatedKeyset>,
}

struct LoadedKeyset {
    store_id: Uuid,
    slot_a: KeysetSlotProbe,
    slot_b: KeysetSlotProbe,
}

impl LoadedKeyset {
    fn selected(&self) -> Option<&ValidatedKeyset> {
        match (&self.slot_a.keyset, &self.slot_b.keyset) {
            (Some(left), Some(right)) => {
                if left.generation > right.generation {
                    Some(left)
                } else {
                    Some(right)
                }
            }
            (Some(value), None) | (None, Some(value)) => Some(value),
            (None, None) => None,
        }
    }

    fn state(&self) -> Option<SecretFileStoreState> {
        self.selected().map(|selected| SecretFileStoreState {
            store_id: self.store_id,
            active_master_key_epoch: selected.active_master_key_epoch,
            keyset_generation: selected.generation,
            object_storage_layout: selected.object_storage_layout,
        })
    }

    fn max_seen_generation(&self) -> u64 {
        self.slot_a
            .max_seen
            .into_iter()
            .chain(self.slot_b.max_seen)
            .max()
            .unwrap_or(0)
    }

    fn has_higher_unreadable(&self) -> bool {
        self.selected()
            .is_some_and(|selected| self.max_seen_generation() > selected.generation)
    }

    fn is_stable(&self) -> bool {
        let (Some(left), Some(right)) = (&self.slot_a.keyset, &self.slot_b.keyset) else {
            return false;
        };
        left.generation.abs_diff(right.generation) == 1
            && left.active_master_key_epoch == right.active_master_key_epoch
            && left.object_storage_layout == right.object_storage_layout
            && self.max_seen_generation() == left.generation.max(right.generation)
    }

    fn same_pair(&self, other: &Self) -> bool {
        self.store_id == other.store_id
            && same_validated_keyset(self.slot_a.keyset.as_ref(), other.slot_a.keyset.as_ref())
            && same_validated_keyset(self.slot_b.keyset.as_ref(), other.slot_b.keyset.as_ref())
            && self.slot_a.max_seen == other.slot_a.max_seen
            && self.slot_b.max_seen == other.slot_b.max_seen
    }

    fn can_initialize_epoch(&self, epoch: u32) -> bool {
        match (&self.slot_a.keyset, &self.slot_b.keyset) {
            (None, None) => self.slot_a.empty && self.slot_b.empty,
            (Some(left), Some(right)) => {
                self.is_stable()
                    && left.active_master_key_epoch == epoch
                    && right.active_master_key_epoch == epoch
                    && left.object_storage_layout == ObjectStorageLayout::LegacyFlat
                    && right.object_storage_layout == ObjectStorageLayout::LegacyFlat
            }
            (Some(left), None) => {
                left.slot == FileSlot::A
                    && left.generation == 1
                    && left.active_master_key_epoch == epoch
                    && left.object_storage_layout == ObjectStorageLayout::LegacyFlat
                    && self.slot_b.empty
                    && self.slot_b.max_seen.is_none()
            }
            (None, Some(_)) => false,
        }
    }
}

fn same_validated_keyset(left: Option<&ValidatedKeyset>, right: Option<&ValidatedKeyset>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.path == right.path
                && left.slot == right.slot
                && left.generation == right.generation
                && left.active_master_key_epoch == right.active_master_key_epoch
                && left.object_storage_layout == right.object_storage_layout
        }
        _ => false,
    }
}

fn rotation_keyset_phase(
    loaded: &LoadedKeyset,
    source: SecretFileStoreState,
    target_epoch: u32,
) -> Result<RotationKeysetPhase, SecretFileStoreError> {
    if loaded.has_higher_unreadable()
        || target_epoch
            != source
                .active_master_key_epoch
                .checked_add(1)
                .ok_or(SecretFileStoreErrorCode::GenerationOverflow)?
    {
        return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
    }
    if loaded.is_stable() && loaded.state() == Some(source) {
        return Ok(RotationKeysetPhase::StableSource);
    }
    let state = loaded
        .state()
        .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    if state.store_id != source.store_id
        || state.active_master_key_epoch != target_epoch
        || state.object_storage_layout != ObjectStorageLayout::EpochDirectory
    {
        return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
    }
    let target_first = source
        .keyset_generation
        .checked_add(1)
        .ok_or(SecretFileStoreErrorCode::GenerationOverflow)?;
    if !loaded.is_stable() && state.keyset_generation == target_first {
        let (Some(a), Some(b)) = (&loaded.slot_a.keyset, &loaded.slot_b.keyset) else {
            return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
        };
        let mut saw_source = false;
        let mut saw_target = false;
        for keyset in [a, b] {
            if keyset.generation == source.keyset_generation
                && keyset.active_master_key_epoch == source.active_master_key_epoch
                && keyset.object_storage_layout == source.object_storage_layout
            {
                saw_source = true;
            } else if keyset.generation == target_first
                && keyset.active_master_key_epoch == target_epoch
                && keyset.object_storage_layout == ObjectStorageLayout::EpochDirectory
            {
                saw_target = true;
            } else {
                return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
            }
        }
        if saw_source && saw_target {
            return Ok(RotationKeysetPhase::Mixed);
        }
    }
    if loaded.is_stable() && state.keyset_generation > target_first {
        let (Some(a), Some(b)) = (&loaded.slot_a.keyset, &loaded.slot_b.keyset) else {
            return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
        };
        if [a, b].iter().all(|keyset| {
            keyset.active_master_key_epoch == target_epoch
                && keyset.object_storage_layout == ObjectStorageLayout::EpochDirectory
                && keyset.generation > source.keyset_generation
        }) {
            return Ok(RotationKeysetPhase::StableTarget);
        }
    }
    Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into())
}

struct ValidatedObjectCopy {
    path: PathBuf,
    bundle: SshSecretBundle,
}

#[derive(Default)]
struct ObjectTempBudget {
    entries: usize,
    aggregate_bytes: u64,
}

impl ObjectTempBudget {
    fn record_entry(&mut self) -> Result<(), SecretFileStoreError> {
        self.entries = self
            .entries
            .checked_add(1)
            .ok_or_else(|| SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict))?;
        if self.entries > MAX_OBJECT_TEMP_ENTRIES {
            return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
        }
        Ok(())
    }

    fn record_bytes(&mut self, encoded_bytes: usize) -> Result<(), SecretFileStoreError> {
        self.aggregate_bytes = self
            .aggregate_bytes
            .checked_add(u64::try_from(encoded_bytes).map_err(|_| {
                SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict)
            })?)
            .ok_or_else(|| SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict))?;
        if self.aggregate_bytes > MAX_OBJECT_TEMP_AGGREGATE_BYTES {
            return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct GarbageCollectionRetentionKey {
    object_digest: [u8; 32],
    entity_digest: [u8; 32],
    revision: u64,
}

struct ValidatedGarbageCollectionRetention {
    keys: BTreeSet<GarbageCollectionRetentionKey>,
}

struct GarbageCollectionArtifact {
    path: PathBuf,
    encoded_length: usize,
    encoded_digest: [u8; 32],
    temporary: bool,
    slot: FileSlot,
}

struct GarbageCollectionObject {
    prefix: PathBuf,
    object: PathBuf,
}

struct GarbageCollectionPlan {
    artifacts: Vec<GarbageCollectionArtifact>,
    removable_objects: Vec<GarbageCollectionObject>,
    prefixes: BTreeSet<PathBuf>,
    removed_blob_revisions: usize,
}

struct RotationSourceArtifact {
    path: PathBuf,
    encoded_length: usize,
    encoded_digest: [u8; 32],
}

struct RotationSourceEntry {
    key: GarbageCollectionRetentionKey,
    locator: SecretObjectLocator,
    revision: u64,
    bundle_fingerprint: [u8; 32],
    slot_a: RotationSourceArtifact,
    slot_b: RotationSourceArtifact,
}

struct MasterKeyRotationPlan {
    source_state: SecretFileStoreState,
    target_epoch: u32,
    source_keyset_commitment: [u8; 32],
    source_tree_commitment: [u8; 32],
    retention_commitment: [u8; 32],
    entries: Vec<RotationSourceEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RotationKeysetPhase {
    StableSource,
    Mixed,
    StableTarget,
}

#[derive(Default)]
struct GarbageCollectionRevision {
    entity_digest: Option<[u8; 32]>,
    bundle_fingerprint: Option<[u8; 32]>,
    final_slots: u8,
    artifacts: Vec<GarbageCollectionArtifact>,
}

fn garbage_collection_uncertain() -> SecretFileStoreError {
    SecretFileStoreErrorCode::GarbageCollectionUncertain.into()
}

fn validate_garbage_collection_retention(
    store_id: Uuid,
    retained: &[SecretObjectRetention],
) -> Result<ValidatedGarbageCollectionRetention, SecretFileStoreError> {
    if retained.len() > MAX_GARBAGE_COLLECTION_RETENTIONS {
        return Err(garbage_collection_uncertain());
    }
    let mut keys = BTreeSet::new();
    for retention in retained {
        let locator = derive_locator(store_id, &retention.entity_id)
            .map_err(|_| garbage_collection_uncertain())?;
        let supplied = decode_hex_32(&retention.backend_locator_hex)
            .ok_or_else(garbage_collection_uncertain)?;
        if retention.custody_revision == 0 || !bool::from(locator.object_digest.ct_eq(&supplied)) {
            return Err(garbage_collection_uncertain());
        }
        keys.insert(GarbageCollectionRetentionKey {
            object_digest: locator.object_digest,
            entity_digest: *locator.entity_digest.as_bytes(),
            revision: retention.custody_revision,
        });
    }
    Ok(ValidatedGarbageCollectionRetention { keys })
}

fn rotation_retention_commitment(retention: &ValidatedGarbageCollectionRetention) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(ROTATION_RETENTION_COMMITMENT_DOMAIN);
    digest.update((retention.keys.len() as u64).to_be_bytes());
    for key in &retention.keys {
        digest.update(key.object_digest);
        digest.update(key.entity_digest);
        digest.update(key.revision.to_be_bytes());
    }
    digest.finalize().into()
}

fn source_keyset_generations(max_generation: u64) -> Option<(u64, u64)> {
    if max_generation < 2 {
        return None;
    }
    if FileSlot::for_generation(max_generation) == FileSlot::A {
        Some((max_generation, max_generation.checked_sub(1)?))
    } else {
        Some((max_generation.checked_sub(1)?, max_generation))
    }
}

fn find_exact_keyset_generation(
    root: &Path,
    store_id: Uuid,
    slot: FileSlot,
    generation: u64,
) -> Result<ValidatedKeyset, SecretFileStoreError> {
    let directory = root.join(KEYSET_DIRECTORY).join(slot.directory());
    let mut exact = None;
    for entry in fs::read_dir(&directory)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?
    {
        let entry = entry.map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
        if parse_keyset_name(&name) == Some(generation) {
            if exact.replace(entry.path()).is_some() {
                return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
            }
        }
    }
    let path = exact.ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    read_keyset(&path, store_id, slot, generation)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain.into())
}

fn rotation_source_keyset_commitment(
    root: &Path,
    expected: SecretFileStoreState,
) -> Result<[u8; 32], SecretFileStoreError> {
    let (a_generation, b_generation) = source_keyset_generations(expected.keyset_generation)
        .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    let a = find_exact_keyset_generation(root, expected.store_id, FileSlot::A, a_generation)?;
    let b = find_exact_keyset_generation(root, expected.store_id, FileSlot::B, b_generation)?;
    for keyset in [&a, &b] {
        if keyset.active_master_key_epoch != expected.active_master_key_epoch
            || keyset.object_storage_layout != expected.object_storage_layout
        {
            return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
        }
    }
    let mut digest = Sha256::new();
    digest.update(ROTATION_KEYSET_COMMITMENT_DOMAIN);
    digest.update(expected.store_id.as_bytes());
    for keyset in [&a, &b] {
        let name = keyset
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
        let encoded = read_bounded(&keyset.path, MAX_KEYSET_BYTES)
            .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
        digest.update([match keyset.slot {
            FileSlot::A => 1,
            FileSlot::B => 2,
        }]);
        digest.update(keyset.generation.to_be_bytes());
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name.as_bytes());
        digest.update((encoded.len() as u64).to_be_bytes());
        digest.update(Sha256::digest(&encoded));
    }
    Ok(digest.finalize().into())
}

fn preflight_master_key_rotation_source(
    root: &Path,
    source_state: SecretFileStoreState,
    old_master_key: &EnvelopeMasterKey,
    retention: &ValidatedGarbageCollectionRetention,
    target_epoch: u32,
) -> Result<MasterKeyRotationPlan, SecretFileStoreError> {
    if target_epoch
        != source_state
            .active_master_key_epoch
            .checked_add(1)
            .ok_or(SecretFileStoreErrorCode::GenerationOverflow)?
    {
        return Err(SecretFileStoreErrorCode::InvalidInput.into());
    }
    let storage_root = object_storage_root(root, &source_state);
    if read_optional_owner(&storage_root)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?
        != Some(source_state.store_id)
    {
        return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
    }
    let objects = storage_root.join(OBJECTS_DIRECTORY);
    reject_reparse_directory(&objects, SecretFileStoreErrorCode::ArtifactConflict)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    validate_objects_root(&objects)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;

    let mut commitment = Sha256::new();
    commitment.update(ROTATION_SOURCE_COMMITMENT_DOMAIN);
    commitment.update(source_state.store_id.as_bytes());
    commitment.update(source_state.active_master_key_epoch.to_be_bytes());
    commitment.update(source_state.keyset_generation.to_be_bytes());
    commitment.update(object_storage_layout_name(source_state.object_storage_layout).as_bytes());
    let mut entries = Vec::with_capacity(retention.keys.len());
    let mut seen_retained = BTreeSet::new();
    let mut object_count = 0_usize;
    let mut artifact_count = 0_usize;
    let mut aggregate_bytes = 0_u64;

    for (prefix_name, prefix) in sorted_directory_entries(&objects)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?
    {
        validate_object_prefix(&prefix)
            .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
        commitment.update(b"prefix\0");
        commitment.update(prefix_name.as_bytes());
        for (object_name, object) in sorted_directory_entries(&prefix)
            .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?
        {
            object_count = object_count
                .checked_add(1)
                .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
            if object_count > MAX_GARBAGE_COLLECTION_OBJECTS {
                return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
            }
            let object_digest = decode_hex_32(&object_name)
                .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
            commitment.update(b"object\0");
            commitment.update(object_digest);
            let (revisions, _) = scan_garbage_collection_object(
                &object,
                object_digest,
                source_state,
                old_master_key,
                &mut artifact_count,
            )
            .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
            for (revision, scanned) in revisions {
                let entity_digest = scanned
                    .entity_digest
                    .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
                let fingerprint = scanned
                    .bundle_fingerprint
                    .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
                commitment.update(b"revision\0");
                commitment.update(revision.to_be_bytes());
                commitment.update(entity_digest);
                commitment.update(fingerprint);
                commitment.update([scanned.final_slots]);
                let key = GarbageCollectionRetentionKey {
                    object_digest,
                    entity_digest,
                    revision,
                };
                let mut slot_a = None;
                let mut slot_b = None;
                for artifact in scanned.artifacts {
                    aggregate_bytes = aggregate_bytes
                        .checked_add(artifact.encoded_length as u64)
                        .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
                    if aggregate_bytes > MAX_ROTATION_AGGREGATE_BYTES {
                        return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
                    }
                    let relative = artifact
                        .path
                        .strip_prefix(&storage_root)
                        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?
                        .to_str()
                        .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
                    commitment.update(b"artifact\0");
                    commitment.update((relative.len() as u64).to_be_bytes());
                    commitment.update(relative.as_bytes());
                    commitment.update((artifact.encoded_length as u64).to_be_bytes());
                    commitment.update(artifact.encoded_digest);
                    commitment.update([u8::from(artifact.temporary)]);
                    if !artifact.temporary && retention.keys.contains(&key) {
                        let source = RotationSourceArtifact {
                            path: artifact.path,
                            encoded_length: artifact.encoded_length,
                            encoded_digest: artifact.encoded_digest,
                        };
                        match artifact.slot {
                            FileSlot::A => slot_a = Some(source),
                            FileSlot::B => slot_b = Some(source),
                        }
                    }
                }
                if retention.keys.contains(&key) {
                    if scanned.final_slots != 3 {
                        return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
                    }
                    seen_retained.insert(key);
                    entries.push(RotationSourceEntry {
                        key,
                        locator: SecretObjectLocator {
                            store_id: source_state.store_id,
                            entity_digest: SecretEntityDigest::from_bytes(entity_digest),
                            object_digest,
                        },
                        revision,
                        bundle_fingerprint: fingerprint,
                        slot_a: slot_a
                            .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?,
                        slot_b: slot_b
                            .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?,
                    });
                }
            }
        }
    }
    if seen_retained != retention.keys {
        return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
    }
    entries.sort_by_key(|entry| entry.key);
    let source_keyset_commitment = rotation_source_keyset_commitment(root, source_state)?;
    Ok(MasterKeyRotationPlan {
        source_state,
        target_epoch,
        source_keyset_commitment,
        source_tree_commitment: commitment.finalize().into(),
        retention_commitment: rotation_retention_commitment(retention),
        entries,
    })
}

fn rotation_manifest_matches_plan(
    manifest: &ValidatedRotationManifest,
    plan: &MasterKeyRotationPlan,
) -> bool {
    manifest.source_state == plan.source_state
        && manifest.target_epoch == plan.target_epoch
        && manifest.retained_objects == plan.entries.len()
        && bool::from(
            manifest
                .source_keyset_commitment
                .ct_eq(&plan.source_keyset_commitment),
        )
        && bool::from(
            manifest
                .source_tree_commitment
                .ct_eq(&plan.source_tree_commitment),
        )
        && bool::from(
            manifest
                .retention_commitment
                .ct_eq(&plan.retention_commitment),
        )
}

fn validated_rotation_manifests_match(
    left: &ValidatedRotationManifest,
    right: &ValidatedRotationManifest,
) -> bool {
    left.store_id == right.store_id
        && left.source_state == right.source_state
        && left.target_epoch == right.target_epoch
        && left.retained_objects == right.retained_objects
        && bool::from(
            left.source_keyset_commitment
                .ct_eq(&right.source_keyset_commitment),
        )
        && bool::from(
            left.source_tree_commitment
                .ct_eq(&right.source_tree_commitment),
        )
        && bool::from(left.retention_commitment.ct_eq(&right.retention_commitment))
}

fn is_rotation_temp_name(name: &str) -> bool {
    name.strip_prefix(".rotation-")
        .and_then(|body| body.strip_suffix(".tmp"))
        .is_some_and(|artifact_id| is_lower_hex(artifact_id, 32))
}

fn is_retired_source_temp_name(name: &str) -> bool {
    name.strip_prefix(".source-key-retired-")
        .and_then(|body| body.strip_suffix(".tmp"))
        .is_some_and(|artifact_id| is_lower_hex(artifact_id, 32))
}

fn retired_source_marker_matches_manifest(
    marker: &ValidatedRetiredSourceMarker,
    manifest: &ValidatedRotationManifest,
    manifest_path: &Path,
) -> bool {
    marker.store_id == manifest.store_id
        && marker.source_epoch == manifest.source_state.active_master_key_epoch
        && marker.target_epoch == manifest.target_epoch
        && rotation_manifest_commitment(manifest_path).is_ok_and(|commitment| {
            bool::from(commitment.ct_eq(&marker.rotation_manifest_commitment))
        })
}

fn publish_rotation_manifest(
    epoch_root: &Path,
    plan: &MasterKeyRotationPlan,
) -> Result<SecretPublicationDurability, SecretFileStoreError> {
    let path = epoch_root.join(ROTATION_MANIFEST_FILE);
    for entry in fs::read_dir(epoch_root)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?
    {
        let entry = entry.map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
        if is_rotation_temp_name(&name) {
            let temporary = read_rotation_manifest(&entry.path())?;
            if !rotation_manifest_matches_plan(&temporary, plan) {
                return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
            }
        }
    }
    if path_exists(&path)? {
        let manifest = read_rotation_manifest(&path)?;
        if !rotation_manifest_matches_plan(&manifest, plan) {
            return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
        }
        sync_directory(epoch_root).map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?;
        return Ok(SecretPublicationDurability::Durable);
    }
    let encoded = encode_rotation_manifest(plan)?;
    publish_named_no_overwrite(
        epoch_root,
        ROTATION_MANIFEST_FILE,
        ".rotation",
        &encoded,
        MAX_ROOT_ENTRIES,
    )
}

fn cleanup_retired_source_temps(
    epoch_root: &Path,
    manifest: &ValidatedRotationManifest,
    manifest_path: &Path,
) {
    let Ok(entries) = fs::read_dir(epoch_root) else {
        return;
    };
    let mut removed = false;
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !is_retired_source_temp_name(&name) {
            continue;
        }
        let owned = read_retired_source_marker(&entry.path())
            .ok()
            .is_some_and(|marker| {
                retired_source_marker_matches_manifest(&marker, manifest, manifest_path)
            });
        if owned && fs::remove_file(entry.path()).is_ok() {
            removed = true;
        }
    }
    if removed {
        let _ = sync_directory(epoch_root);
    }
}

fn publish_retired_source_marker(
    epoch_root: &Path,
    manifest: &ValidatedRotationManifest,
    manifest_path: &Path,
) -> Result<SecretFileMutation<()>, SecretFileStoreError> {
    let root = epoch_root
        .parent()
        .and_then(Path::parent)
        .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    let mut sync = sync_directory;
    publish_retired_source_marker_with_sync(root, epoch_root, manifest, manifest_path, &mut sync)
}

fn publish_retired_source_marker_with_sync<F>(
    root: &Path,
    epoch_root: &Path,
    manifest: &ValidatedRotationManifest,
    manifest_path: &Path,
    sync: &mut F,
) -> Result<SecretFileMutation<()>, SecretFileStoreError>
where
    F: FnMut(&Path) -> io::Result<()>,
{
    let manifest_commitment = rotation_manifest_commitment(manifest_path)?;
    let encoded = encode_retired_source_marker(
        manifest.store_id,
        manifest.source_state.active_master_key_epoch,
        manifest.target_epoch,
        manifest_commitment,
    )?;
    for entry in fs::read_dir(epoch_root)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?
    {
        let entry = entry.map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
        if is_retired_source_temp_name(&name) {
            let marker = read_retired_source_marker(&entry.path())?;
            if !retired_source_marker_matches_manifest(&marker, manifest, manifest_path) {
                return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
            }
        }
    }
    let final_path = epoch_root.join(RETIRED_SOURCE_MARKER_FILE);
    if path_exists(&final_path)? {
        let marker = read_retired_source_marker(&final_path)?;
        if !retired_source_marker_matches_manifest(&marker, manifest, manifest_path) {
            return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
        }
        return match confirm_retired_source_marker_durability_with_sync(
            root,
            epoch_root,
            manifest,
            manifest_path,
            sync,
        ) {
            Ok(_) => {
                cleanup_retired_source_temps(epoch_root, manifest, manifest_path);
                Ok(SecretFileMutation::Durable(()))
            }
            Err(error) if error.code() == SecretFileStoreErrorCode::DurabilityUnconfirmed => {
                Ok(SecretFileMutation::PublishedDurabilityUncertain)
            }
            Err(_) => Ok(SecretFileMutation::PublicationIndeterminate),
        };
    }
    match publish_named_no_overwrite(
        epoch_root,
        RETIRED_SOURCE_MARKER_FILE,
        ".source-key-retired",
        &encoded,
        MAX_ROOT_ENTRIES,
    )? {
        SecretPublicationDurability::Durable => {
            match confirm_retired_source_marker_durability_with_sync(
                root,
                epoch_root,
                manifest,
                manifest_path,
                sync,
            ) {
                Ok(_) => {
                    cleanup_retired_source_temps(epoch_root, manifest, manifest_path);
                    Ok(SecretFileMutation::Durable(()))
                }
                Err(error) if error.code() == SecretFileStoreErrorCode::DurabilityUnconfirmed => {
                    Ok(SecretFileMutation::PublishedDurabilityUncertain)
                }
                Err(_) => Ok(SecretFileMutation::PublicationIndeterminate),
            }
        }
        SecretPublicationDurability::PublishedDurabilityUncertain => {
            Ok(SecretFileMutation::PublishedDurabilityUncertain)
        }
        SecretPublicationDurability::PublicationIndeterminate => {
            Ok(SecretFileMutation::PublicationIndeterminate)
        }
    }
}

fn confirm_retired_source_marker_durability_with_sync<F>(
    root: &Path,
    epoch_root: &Path,
    expected_manifest: &ValidatedRotationManifest,
    manifest_path: &Path,
    sync: &mut F,
) -> Result<ConfirmedRetiredSourceMarker, SecretFileStoreError>
where
    F: FnMut(&Path) -> io::Result<()>,
{
    let epochs = root.join(EPOCHS_DIRECTORY);
    if epoch_root != epoch_storage_root(root, expected_manifest.target_epoch)
        || manifest_path != epoch_root.join(ROTATION_MANIFEST_FILE)
    {
        return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
    }

    sync(epoch_root).map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?;
    sync(&epochs).map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?;
    sync(root).map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?;

    retired_source_marker_confirmation(epoch_root, expected_manifest, manifest_path)
}

fn retired_source_marker_confirmation(
    epoch_root: &Path,
    expected_manifest: &ValidatedRotationManifest,
    manifest_path: &Path,
) -> Result<ConfirmedRetiredSourceMarker, SecretFileStoreError> {
    let manifest = read_rotation_manifest(manifest_path)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    if !validated_rotation_manifests_match(&manifest, expected_manifest) {
        return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
    }
    let marker = read_retired_source_marker(&epoch_root.join(RETIRED_SOURCE_MARKER_FILE))
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    if !retired_source_marker_matches_manifest(&marker, &manifest, manifest_path) {
        return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
    }
    Ok(ConfirmedRetiredSourceMarker {
        store_id: manifest.store_id,
        source_epoch: manifest.source_state.active_master_key_epoch,
        target_epoch: manifest.target_epoch,
        rotation_manifest_commitment: rotation_manifest_commitment(manifest_path)?,
        marker_commitment: retired_source_marker_commitment(
            &epoch_root.join(RETIRED_SOURCE_MARKER_FILE),
        )?,
    })
}

fn revalidate_rotation_source_artifact(
    artifact: &RotationSourceArtifact,
) -> Result<Vec<u8>, SecretFileStoreError> {
    reject_reparse_regular(
        &artifact.path,
        SecretFileStoreErrorCode::MasterKeyRotationUncertain,
    )?;
    let encoded = read_bounded(&artifact.path, MAX_ENVELOPE_BYTES)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    if encoded.len() != artifact.encoded_length
        || !bool::from(Sha256::digest(&encoded).ct_eq(&artifact.encoded_digest))
    {
        return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
    }
    Ok(encoded)
}

fn read_rotation_source_bundle(
    entry: &RotationSourceEntry,
    source_state: SecretFileStoreState,
    old_master_key: &EnvelopeMasterKey,
) -> Result<SshSecretBundle, SecretFileStoreError> {
    let (a_context, b_context) = object_contexts(
        &entry.locator,
        entry.revision,
        source_state.active_master_key_epoch,
    )?;
    let a_encoded = revalidate_rotation_source_artifact(&entry.slot_a)?;
    let b_encoded = revalidate_rotation_source_artifact(&entry.slot_b)?;
    let a = decrypt_ssh_secret_bundle(old_master_key, &a_context, &a_encoded)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    let b = decrypt_ssh_secret_bundle(old_master_key, &b_context, &b_encoded)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    if !a.contents_match(&b)
        || !bool::from(bundle_fingerprint(&a)?.ct_eq(&entry.bundle_fingerprint))
    {
        return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
    }
    Ok(a)
}

fn preflight_master_key_rotation_target(
    target_root: &Path,
    plan: &MasterKeyRotationPlan,
    new_master_key: &EnvelopeMasterKey,
    require_complete: bool,
) -> Result<(), SecretFileStoreError> {
    validate_epoch_storage_root(target_root, plan.source_state.store_id, false)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    let manifest = read_rotation_manifest(&target_root.join(ROTATION_MANIFEST_FILE))?;
    if !rotation_manifest_matches_plan(&manifest, plan) {
        return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
    }
    let expected = plan
        .entries
        .iter()
        .map(|entry| (entry.key, entry.bundle_fingerprint))
        .collect::<BTreeMap<_, _>>();
    let expected_objects = expected
        .keys()
        .map(|key| key.object_digest)
        .collect::<BTreeSet<_>>();
    let target_state = SecretFileStoreState {
        store_id: plan.source_state.store_id,
        active_master_key_epoch: plan.target_epoch,
        keyset_generation: plan.source_state.keyset_generation,
        object_storage_layout: ObjectStorageLayout::EpochDirectory,
    };
    let objects = target_root.join(OBJECTS_DIRECTORY);
    validate_objects_root(&objects)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    let mut seen = BTreeSet::new();
    let mut artifact_count = 0_usize;
    let mut object_count = 0_usize;
    for (prefix_name, prefix) in sorted_directory_entries(&objects)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?
    {
        validate_object_prefix(&prefix)
            .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
        let mut prefix_objects = 0_usize;
        for (object_name, object) in sorted_directory_entries(&prefix)
            .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?
        {
            prefix_objects += 1;
            object_count = object_count
                .checked_add(1)
                .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
            if object_count > MAX_GARBAGE_COLLECTION_OBJECTS {
                return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
            }
            let object_digest = decode_hex_32(&object_name)
                .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
            if object_name.get(..2) != Some(prefix_name.as_str())
                || !expected_objects.contains(&object_digest)
            {
                return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
            }
            let (revisions, has_artifact) = scan_garbage_collection_object(
                &object,
                object_digest,
                target_state,
                new_master_key,
                &mut artifact_count,
            )
            .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
            if require_complete && !has_artifact {
                return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
            }
            for (revision, scanned) in revisions {
                let entity_digest = scanned
                    .entity_digest
                    .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
                let fingerprint = scanned
                    .bundle_fingerprint
                    .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
                let key = GarbageCollectionRetentionKey {
                    object_digest,
                    entity_digest,
                    revision,
                };
                let expected_fingerprint = expected
                    .get(&key)
                    .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
                if !bool::from(fingerprint.ct_eq(expected_fingerprint))
                    || require_complete && scanned.final_slots != 3
                {
                    return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
                }
                if scanned.final_slots == 3 {
                    seen.insert(key);
                }
            }
        }
        if require_complete && prefix_objects == 0 {
            return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
        }
    }
    if require_complete && seen != expected.keys().copied().collect() {
        return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
    }
    Ok(())
}

fn master_key_rotation_plans_match(
    left: &MasterKeyRotationPlan,
    right: &MasterKeyRotationPlan,
) -> bool {
    left.source_state == right.source_state
        && left.target_epoch == right.target_epoch
        && left.entries.len() == right.entries.len()
        && left
            .entries
            .iter()
            .zip(&right.entries)
            .all(|(left, right)| left.key == right.key)
        && bool::from(
            left.source_keyset_commitment
                .ct_eq(&right.source_keyset_commitment),
        )
        && bool::from(
            left.source_tree_commitment
                .ct_eq(&right.source_tree_commitment),
        )
        && bool::from(left.retention_commitment.ct_eq(&right.retention_commitment))
}

fn cleanup_rotation_manifest_temps(epoch_root: &Path, plan: &MasterKeyRotationPlan) {
    let Ok(entries) = fs::read_dir(epoch_root) else {
        return;
    };
    let mut removed = false;
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !is_rotation_temp_name(&name) {
            continue;
        }
        let owned = read_rotation_manifest(&entry.path())
            .ok()
            .is_some_and(|manifest| rotation_manifest_matches_plan(&manifest, plan));
        if owned && fs::remove_file(entry.path()).is_ok() {
            removed = true;
        }
    }
    if removed {
        let _ = sync_directory(epoch_root);
    }
}

fn confirm_master_key_rotation_graphs(
    root: &Path,
    target_root: &Path,
    plan: &MasterKeyRotationPlan,
    old_master_key: &EnvelopeMasterKey,
    new_master_key: &EnvelopeMasterKey,
    retention: &ValidatedGarbageCollectionRetention,
) -> Result<(), SecretFileStoreError> {
    let before = preflight_master_key_rotation_source(
        root,
        plan.source_state,
        old_master_key,
        retention,
        plan.target_epoch,
    )?;
    if !master_key_rotation_plans_match(plan, &before) {
        return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
    }
    preflight_master_key_rotation_target(target_root, plan, new_master_key, true)?;
    for entry in &plan.entries {
        let object = object_directory(target_root, &entry.locator);
        confirm_object_internal(
            &object,
            new_master_key,
            &entry.locator,
            entry.revision,
            plan.target_epoch,
            None,
        )
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    }
    sync_directory(&target_root.join(OBJECTS_DIRECTORY))
        .map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?;
    sync_directory(target_root).map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?;
    sync_directory(&root.join(EPOCHS_DIRECTORY))
        .map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?;
    sync_directory(root).map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?;
    preflight_master_key_rotation_target(target_root, plan, new_master_key, true)?;
    let after = preflight_master_key_rotation_source(
        root,
        plan.source_state,
        old_master_key,
        retention,
        plan.target_epoch,
    )?;
    if !master_key_rotation_plans_match(plan, &after) {
        return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
    }
    Ok(())
}

fn build_completed_master_key_rotation(
    root: &Path,
    target_root: &Path,
    plan: &MasterKeyRotationPlan,
    old_master_key: &EnvelopeMasterKey,
    new_master_key: &EnvelopeMasterKey,
    retention: &ValidatedGarbageCollectionRetention,
    target_state: SecretFileStoreState,
) -> Result<CompletedMasterKeyRotation, SecretFileStoreError> {
    let loaded = load_keyset(root, plan.source_state.store_id)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    if rotation_keyset_phase(&loaded, plan.source_state, plan.target_epoch)?
        != RotationKeysetPhase::StableTarget
        || loaded.state() != Some(target_state)
    {
        return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
    }
    confirm_loaded_keyset(root, &loaded)
        .map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?;
    confirm_master_key_rotation_graphs(
        root,
        target_root,
        plan,
        old_master_key,
        new_master_key,
        retention,
    )?;
    Ok(CompletedMasterKeyRotation {
        state: target_state,
        source_epoch: plan.source_state.active_master_key_epoch,
        target_epoch: plan.target_epoch,
        retained_objects: plan.entries.len(),
    })
}

fn preflight_completed_target_graph(
    target_root: &Path,
    store_id: Uuid,
    target_epoch: u32,
    new_master_key: &EnvelopeMasterKey,
    retention: &ValidatedGarbageCollectionRetention,
) -> Result<(), SecretFileStoreError> {
    let state = SecretFileStoreState {
        store_id,
        active_master_key_epoch: target_epoch,
        keyset_generation: 1,
        object_storage_layout: ObjectStorageLayout::EpochDirectory,
    };
    preflight_garbage_collection(target_root, state, new_master_key, retention)
        .map(|_| ())
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain.into())
}

fn confirm_completed_target_only(
    root: &Path,
    recovery: &MasterKeyRotationRecovery,
    new_master_key: &EnvelopeMasterKey,
    retention: &ValidatedGarbageCollectionRetention,
) -> Result<CompletedMasterKeyRotation, SecretFileStoreError> {
    let loaded = load_keyset(root, recovery.source_state.store_id)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    if rotation_keyset_phase(&loaded, recovery.source_state, recovery.target_epoch)?
        != RotationKeysetPhase::StableTarget
    {
        return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
    }
    let target_state = loaded
        .state()
        .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    let target_root = epoch_storage_root(root, recovery.target_epoch);
    validate_epoch_storage_root(&target_root, recovery.source_state.store_id, false)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    let manifest = read_rotation_manifest(&target_root.join(ROTATION_MANIFEST_FILE))?;
    if manifest.source_state != recovery.source_state
        || manifest.target_epoch != recovery.target_epoch
    {
        return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
    }
    preflight_completed_target_graph(
        &target_root,
        recovery.source_state.store_id,
        recovery.target_epoch,
        new_master_key,
        retention,
    )?;
    for retained in &retention.keys {
        let locator = SecretObjectLocator {
            store_id: recovery.source_state.store_id,
            entity_digest: SecretEntityDigest::from_bytes(retained.entity_digest),
            object_digest: retained.object_digest,
        };
        confirm_object_internal(
            &object_directory(&target_root, &locator),
            new_master_key,
            &locator,
            retained.revision,
            recovery.target_epoch,
            None,
        )
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    }
    sync_directory(&target_root.join(OBJECTS_DIRECTORY))
        .map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?;
    sync_directory(&target_root).map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?;
    sync_directory(&root.join(EPOCHS_DIRECTORY))
        .map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?;
    confirm_loaded_keyset(root, &loaded)
        .map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?;
    preflight_completed_target_graph(
        &target_root,
        recovery.source_state.store_id,
        recovery.target_epoch,
        new_master_key,
        retention,
    )?;
    Ok(CompletedMasterKeyRotation {
        state: target_state,
        source_epoch: recovery.source_epoch(),
        target_epoch: recovery.target_epoch,
        retained_objects: retention.keys.len(),
    })
}

fn inspect_master_key_rotation_internal(
    root: &Path,
    confirmation_cache: &RetiredSourceConfirmationCache,
) -> Result<Option<MasterKeyRotationRecovery>, SecretFileStoreError> {
    let mut sync = sync_directory;
    inspect_master_key_rotation_internal_with_sync(root, confirmation_cache, &mut sync)
}

fn inspect_master_key_rotation_internal_with_sync<F>(
    root: &Path,
    confirmation_cache: &RetiredSourceConfirmationCache,
    sync: &mut F,
) -> Result<Option<MasterKeyRotationRecovery>, SecretFileStoreError>
where
    F: FnMut(&Path) -> io::Result<()>,
{
    // Take the proof up front so every validation error invalidates the fast
    // path. Only a successful scan restores an exact parsed marker proof.
    let cached_confirmation = confirmation_cache
        .lock()
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?
        .take();
    let owner = read_optional_owner(root)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?
        .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    let loaded = load_keyset(root, owner)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    let current = loaded
        .state()
        .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    let epochs = root.join(EPOCHS_DIRECTORY);
    if !path_exists(&epochs)? {
        return Ok(None);
    }
    validate_epoch_storage_roots(root, owner)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    let mut pending = None;
    let mut completed = None;
    let mut confirmed_retired_source = None;
    for (name, epoch_root) in sorted_directory_entries(&epochs)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?
    {
        let epoch = parse_epoch_directory_name(&name)
            .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
        let manifest_path = epoch_root.join(ROTATION_MANIFEST_FILE);
        if !path_exists(&manifest_path)? {
            if epoch
                == current
                    .active_master_key_epoch
                    .checked_add(1)
                    .ok_or(SecretFileStoreErrorCode::GenerationOverflow)?
                && loaded.is_stable()
            {
                let recovery = MasterKeyRotationRecovery {
                    source_state: current,
                    target_epoch: epoch,
                    retained_objects: 0,
                    completed: false,
                };
                if pending.replace(recovery).is_some() {
                    return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
                }
            } else if epoch >= current.active_master_key_epoch {
                return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
            }
            continue;
        }
        let manifest = read_rotation_manifest(&manifest_path)?;
        if manifest.store_id != owner || manifest.target_epoch != epoch {
            return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
        }
        if current.active_master_key_epoch > manifest.target_epoch {
            continue;
        }
        let phase = rotation_keyset_phase(&loaded, manifest.source_state, manifest.target_epoch)?;
        let retired_path = epoch_root.join(RETIRED_SOURCE_MARKER_FILE);
        if path_exists(&retired_path)? {
            let marker = read_retired_source_marker(&retired_path)?;
            if phase != RotationKeysetPhase::StableTarget
                || !retired_source_marker_matches_manifest(&marker, &manifest, &manifest_path)
            {
                return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
            }
            let parsed_confirmation =
                retired_source_marker_confirmation(&epoch_root, &manifest, &manifest_path)?;
            let confirmation = if cached_confirmation == Some(parsed_confirmation) {
                parsed_confirmation
            } else {
                confirm_retired_source_marker_durability_with_sync(
                    root,
                    &epoch_root,
                    &manifest,
                    &manifest_path,
                    sync,
                )
                .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?
            };
            confirmed_retired_source = Some(confirmation);
            continue;
        }
        if phase != RotationKeysetPhase::StableTarget {
            let source_commitment = rotation_source_keyset_commitment(root, manifest.source_state)?;
            if !bool::from(source_commitment.ct_eq(&manifest.source_keyset_commitment)) {
                return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
            }
        }
        let recovery = MasterKeyRotationRecovery {
            source_state: manifest.source_state,
            target_epoch: manifest.target_epoch,
            retained_objects: manifest.retained_objects,
            completed: phase == RotationKeysetPhase::StableTarget,
        };
        match phase {
            RotationKeysetPhase::StableSource | RotationKeysetPhase::Mixed => {
                if pending.replace(recovery).is_some() {
                    return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
                }
            }
            RotationKeysetPhase::StableTarget => {
                if completed.replace(recovery).is_some() {
                    return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
                }
            }
        }
    }
    let result = pending.or(completed);
    *confirmation_cache
        .lock()
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)? =
        confirmed_retired_source;
    Ok(result)
}

fn ensure_no_pending_master_key_rotation(
    root: &Path,
    confirmation_cache: &RetiredSourceConfirmationCache,
) -> Result<(), SecretFileStoreError> {
    if inspect_master_key_rotation_internal(root, confirmation_cache)?
        .is_some_and(|recovery| !recovery.completed())
    {
        return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
    }
    Ok(())
}

fn preflight_garbage_collection(
    root: &Path,
    state: SecretFileStoreState,
    master_key: &EnvelopeMasterKey,
    retained: &ValidatedGarbageCollectionRetention,
) -> Result<GarbageCollectionPlan, SecretFileStoreError> {
    let objects = root.join(OBJECTS_DIRECTORY);
    reject_reparse_directory(&objects, SecretFileStoreErrorCode::ArtifactConflict)
        .map_err(|_| garbage_collection_uncertain())?;
    validate_objects_root(&objects).map_err(|_| garbage_collection_uncertain())?;

    let mut plan = GarbageCollectionPlan {
        artifacts: Vec::new(),
        removable_objects: Vec::new(),
        prefixes: BTreeSet::new(),
        removed_blob_revisions: 0,
    };
    let mut seen_retained = BTreeSet::new();
    let mut object_count = 0_usize;
    let mut artifact_count = 0_usize;

    for (_, prefix) in sorted_directory_entries(&objects)? {
        validate_object_prefix(&prefix).map_err(|_| garbage_collection_uncertain())?;
        plan.prefixes.insert(prefix.clone());
        for (object_name, object) in sorted_directory_entries(&prefix)? {
            object_count = object_count
                .checked_add(1)
                .ok_or_else(garbage_collection_uncertain)?;
            if object_count > MAX_GARBAGE_COLLECTION_OBJECTS {
                return Err(garbage_collection_uncertain());
            }
            let object_digest =
                decode_hex_32(&object_name).ok_or_else(garbage_collection_uncertain)?;
            let (mut revisions, has_any_artifact) = scan_garbage_collection_object(
                &object,
                object_digest,
                state,
                master_key,
                &mut artifact_count,
            )?;

            let mut object_has_retained_revision = false;
            for (revision, scanned) in &mut revisions {
                let entity_digest = scanned
                    .entity_digest
                    .ok_or_else(garbage_collection_uncertain)?;
                let key = GarbageCollectionRetentionKey {
                    object_digest,
                    entity_digest,
                    revision: *revision,
                };
                if retained.keys.contains(&key) {
                    if scanned.final_slots != 3 {
                        return Err(garbage_collection_uncertain());
                    }
                    object_has_retained_revision = true;
                    seen_retained.insert(key);
                    let artifacts = std::mem::take(&mut scanned.artifacts);
                    for artifact in artifacts {
                        if artifact.temporary {
                            plan.artifacts.push(artifact);
                        } else {
                            scanned.artifacts.push(artifact);
                        }
                    }
                } else {
                    plan.removed_blob_revisions = plan
                        .removed_blob_revisions
                        .checked_add(1)
                        .ok_or_else(garbage_collection_uncertain)?;
                    plan.artifacts.append(&mut scanned.artifacts);
                }
            }

            if !object_has_retained_revision {
                // An empty canonical object can be left by an interrupted
                // directory cleanup. It contains no data to unlink and is a
                // safe idempotent structural residue to remove.
                if has_any_artifact || revisions.is_empty() {
                    plan.removable_objects.push(GarbageCollectionObject {
                        prefix: prefix.clone(),
                        object,
                    });
                }
            }
        }
    }

    if seen_retained != retained.keys {
        return Err(garbage_collection_uncertain());
    }
    Ok(plan)
}

fn scan_garbage_collection_object(
    object: &Path,
    object_digest: [u8; 32],
    state: SecretFileStoreState,
    master_key: &EnvelopeMasterKey,
    artifact_count: &mut usize,
) -> Result<(BTreeMap<u64, GarbageCollectionRevision>, bool), SecretFileStoreError> {
    reject_reparse_directory(object, SecretFileStoreErrorCode::ArtifactConflict)
        .map_err(|_| garbage_collection_uncertain())?;
    let slots = garbage_collection_object_slots(object)?;
    let mut revisions = BTreeMap::<u64, GarbageCollectionRevision>::new();
    let mut object_entity_digest = None;
    let mut temp_budget = ObjectTempBudget::default();
    let mut has_any_artifact = false;

    for (slot, directory) in [(FileSlot::A, &slots[0]), (FileSlot::B, &slots[1])] {
        let Some(directory) = directory else {
            continue;
        };
        let entries = sorted_directory_entries(directory)?;
        if entries.len() > MAX_SLOT_ENTRIES {
            return Err(garbage_collection_uncertain());
        }
        for (name, path) in entries {
            has_any_artifact = true;
            *artifact_count = artifact_count
                .checked_add(1)
                .ok_or_else(garbage_collection_uncertain)?;
            if *artifact_count > MAX_GARBAGE_COLLECTION_ARTIFACTS {
                return Err(garbage_collection_uncertain());
            }
            reject_reparse_regular(&path, SecretFileStoreErrorCode::ArtifactConflict)
                .map_err(|_| garbage_collection_uncertain())?;
            let (revision, generation, temporary) =
                if let Some((revision, generation)) = parse_blob_name(&name) {
                    (revision, generation, false)
                } else if let Some((revision, generation)) = parse_blob_temp_name(&name) {
                    temp_budget
                        .record_entry()
                        .map_err(|_| garbage_collection_uncertain())?;
                    (revision, generation, true)
                } else {
                    return Err(garbage_collection_uncertain());
                };
            if expected_blob_generation(slot, revision) != Some(generation) {
                return Err(garbage_collection_uncertain());
            }

            let encoded = read_bounded(&path, MAX_ENVELOPE_BYTES)
                .map_err(|_| garbage_collection_uncertain())?;
            if temporary {
                temp_budget
                    .record_bytes(encoded.len())
                    .map_err(|_| garbage_collection_uncertain())?;
            }
            let (context, bundle) =
                decrypt_ssh_secret_bundle_with_embedded_context(master_key, &encoded)
                    .map_err(|_| garbage_collection_uncertain())?;
            let entity_digest = *context.entity_digest().as_bytes();
            if context.store_id() != state.store_id
                || context.master_key_epoch() != state.active_master_key_epoch
                || context.slot() != slot.envelope_slot()
                || context.revision() != revision
                || context.generation() != generation
                || !bool::from(
                    object_digest_for(state.store_id, context.entity_digest())
                        .ct_eq(&object_digest),
                )
            {
                return Err(garbage_collection_uncertain());
            }
            if object_entity_digest.is_some_and(|existing| existing != entity_digest) {
                return Err(garbage_collection_uncertain());
            }
            object_entity_digest = Some(entity_digest);
            let bundle_fingerprint = bundle_fingerprint(&bundle)?;
            let revision_scan = revisions.entry(revision).or_default();
            if revision_scan
                .entity_digest
                .is_some_and(|existing| existing != entity_digest)
                || revision_scan
                    .bundle_fingerprint
                    .is_some_and(|existing| !bool::from(existing.ct_eq(&bundle_fingerprint)))
            {
                return Err(garbage_collection_uncertain());
            }
            revision_scan.entity_digest = Some(entity_digest);
            revision_scan.bundle_fingerprint = Some(bundle_fingerprint);
            if !temporary {
                let slot_bit = match slot {
                    FileSlot::A => 1,
                    FileSlot::B => 2,
                };
                if revision_scan.final_slots & slot_bit != 0 {
                    return Err(garbage_collection_uncertain());
                }
                revision_scan.final_slots |= slot_bit;
            }
            revision_scan.artifacts.push(GarbageCollectionArtifact {
                path,
                encoded_length: encoded.len(),
                encoded_digest: Sha256::digest(&encoded).into(),
                temporary,
                slot,
            });
        }
    }
    Ok((revisions, has_any_artifact))
}

fn garbage_collection_object_slots(
    object: &Path,
) -> Result<[Option<PathBuf>; 2], SecretFileStoreError> {
    let mut slots = [None, None];
    let entries = sorted_directory_entries(object)?;
    if entries.len() > 2 {
        return Err(garbage_collection_uncertain());
    }
    for (name, path) in entries {
        let index = match name.as_str() {
            SLOT_A_DIRECTORY => 0,
            SLOT_B_DIRECTORY => 1,
            _ => return Err(garbage_collection_uncertain()),
        };
        reject_reparse_directory(&path, SecretFileStoreErrorCode::ArtifactConflict)
            .map_err(|_| garbage_collection_uncertain())?;
        slots[index] = Some(path);
    }
    Ok(slots)
}

fn sorted_directory_entries(
    directory: &Path,
) -> Result<Vec<(String, PathBuf)>, SecretFileStoreError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|_| garbage_collection_uncertain())?
        .map(|entry| {
            let entry = entry.map_err(|_| garbage_collection_uncertain())?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| garbage_collection_uncertain())?;
            Ok((name, entry.path()))
        })
        .collect::<Result<Vec<_>, SecretFileStoreError>>()?;
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(entries)
}

fn bundle_fingerprint(bundle: &SshSecretBundle) -> Result<[u8; 32], SecretFileStoreError> {
    let encoded = bundle
        .encode()
        .map_err(|_| garbage_collection_uncertain())?;
    let mut digest = Sha256::new();
    digest.update(BUNDLE_FINGERPRINT_DOMAIN);
    digest.update((encoded.len() as u64).to_be_bytes());
    digest.update(encoded.as_slice());
    Ok(digest.finalize().into())
}

fn execute_garbage_collection<F>(
    root: &Path,
    mut plan: GarbageCollectionPlan,
    mut sync: F,
) -> Result<SecretBlobGarbageCollection, SecretFileStoreError>
where
    F: FnMut(&Path) -> io::Result<()>,
{
    plan.artifacts
        .sort_by(|left, right| left.path.cmp(&right.path));
    for artifact in &plan.artifacts {
        revalidate_garbage_collection_artifact(artifact)?;
    }
    let mut touched_slots = BTreeSet::new();
    for artifact in &plan.artifacts {
        revalidate_garbage_collection_artifact(artifact)?;
        let parent = artifact
            .path
            .parent()
            .ok_or_else(|| {
                SecretFileStoreError::new(SecretFileStoreErrorCode::DurabilityUnconfirmed)
            })?
            .to_path_buf();
        fs::remove_file(&artifact.path)
            .map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?;
        touched_slots.insert(parent);
    }
    for directory in &touched_slots {
        sync(directory).map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?;
    }

    plan.removable_objects
        .sort_by(|left, right| left.object.cmp(&right.object));
    for removable in &plan.removable_objects {
        remove_empty_garbage_collection_object(removable, &mut sync)?;
    }

    let objects = root.join(OBJECTS_DIRECTORY);
    for prefix in &plan.prefixes {
        if !path_exists(prefix).map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)? {
            continue;
        }
        reject_reparse_directory(prefix, SecretFileStoreErrorCode::DurabilityUnconfirmed)?;
        if sorted_directory_entries(prefix)
            .map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?
            .is_empty()
        {
            sync(prefix).map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?;
            fs::remove_dir(prefix).map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?;
            sync(&objects).map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?;
        }
    }

    Ok(SecretBlobGarbageCollection {
        removed_blob_revisions: plan.removed_blob_revisions,
        removed_objects: plan.removable_objects.len(),
    })
}

fn revalidate_garbage_collection_artifact(
    artifact: &GarbageCollectionArtifact,
) -> Result<(), SecretFileStoreError> {
    let encoded = read_bounded(&artifact.path, MAX_ENVELOPE_BYTES)
        .map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?;
    if encoded.len() != artifact.encoded_length
        || !bool::from(<[u8; 32]>::from(Sha256::digest(&encoded)).ct_eq(&artifact.encoded_digest))
    {
        return Err(SecretFileStoreErrorCode::DurabilityUnconfirmed.into());
    }
    Ok(())
}

fn remove_empty_garbage_collection_object<F>(
    removable: &GarbageCollectionObject,
    sync: &mut F,
) -> Result<(), SecretFileStoreError>
where
    F: FnMut(&Path) -> io::Result<()>,
{
    if !path_exists(&removable.object)
        .map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?
    {
        return Ok(());
    }
    reject_reparse_directory(
        &removable.object,
        SecretFileStoreErrorCode::DurabilityUnconfirmed,
    )?;
    let slots = garbage_collection_object_slots(&removable.object)
        .map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?;
    for directory in slots.into_iter().flatten() {
        if !sorted_directory_entries(&directory)
            .map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?
            .is_empty()
        {
            return Err(SecretFileStoreErrorCode::DurabilityUnconfirmed.into());
        }
        sync(&directory).map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?;
        fs::remove_dir(&directory).map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?;
    }
    sync(&removable.object).map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?;
    if !sorted_directory_entries(&removable.object)
        .map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?
        .is_empty()
    {
        return Err(SecretFileStoreErrorCode::DurabilityUnconfirmed.into());
    }
    fs::remove_dir(&removable.object)
        .map_err(|_| SecretFileStoreErrorCode::DurabilityUnconfirmed)?;
    sync(&removable.prefix)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::DurabilityUnconfirmed))
}

fn validate_store_id(store_id: Uuid) -> Result<(), SecretFileStoreError> {
    if store_id.get_version() != Some(Version::Random) {
        return Err(SecretFileStoreErrorCode::InvalidInput.into());
    }
    Ok(())
}

fn parse_canonical_store_id(value: &str) -> Option<Uuid> {
    let parsed = Uuid::parse_str(value).ok()?;
    (parsed.get_version() == Some(Version::Random) && parsed.to_string() == value).then_some(parsed)
}

fn encode_owner(store_id: Uuid) -> Result<Vec<u8>, SecretFileStoreError> {
    validate_store_id(store_id)?;
    let store_id = store_id.to_string();
    let checksum = owner_checksum(&store_id)?;
    let envelope = OwnerEnvelope {
        magic: OWNER_MAGIC.to_owned(),
        format_version: OWNER_FORMAT_VERSION,
        store_id,
        checksum,
    };
    let encoded = serde_json::to_vec(&envelope)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::StorageUnavailable))?;
    if encoded.len() as u64 > MAX_OWNER_BYTES {
        return Err(SecretFileStoreErrorCode::StorageUnavailable.into());
    }
    Ok(encoded)
}

fn owner_checksum(store_id: &str) -> Result<String, SecretFileStoreError> {
    let payload = serde_json::to_vec(&OwnerChecksumPayload {
        magic: OWNER_MAGIC,
        format_version: OWNER_FORMAT_VERSION,
        store_id,
    })
    .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::StorageUnavailable))?;
    Ok(domain_checksum(OWNER_CHECKSUM_DOMAIN, &payload))
}

fn read_owner(path: &Path) -> Result<Uuid, SecretFileStoreError> {
    let encoded = read_bounded(path, MAX_OWNER_BYTES)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidOwner))?;
    let envelope: OwnerEnvelope = serde_json::from_slice(&encoded)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidOwner))?;
    if envelope.magic != OWNER_MAGIC || envelope.format_version != OWNER_FORMAT_VERSION {
        return Err(SecretFileStoreErrorCode::InvalidOwner.into());
    }
    let store_id = parse_canonical_store_id(&envelope.store_id)
        .ok_or_else(|| SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidOwner))?;
    let expected = owner_checksum(&envelope.store_id)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidOwner))?;
    if !canonical_checksum_matches(&envelope.checksum, &expected) {
        return Err(SecretFileStoreErrorCode::InvalidOwner.into());
    }
    Ok(store_id)
}

fn read_optional_owner(root: &Path) -> Result<Option<Uuid>, SecretFileStoreError> {
    let path = root.join(OWNER_FILE);
    match fs::symlink_metadata(&path) {
        Ok(_) => read_owner(&path).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(SecretFileStoreErrorCode::InvalidOwner.into()),
    }
}

struct ValidatedRotationManifest {
    store_id: Uuid,
    source_state: SecretFileStoreState,
    target_epoch: u32,
    source_keyset_commitment: [u8; 32],
    source_tree_commitment: [u8; 32],
    retention_commitment: [u8; 32],
    retained_objects: usize,
}

struct ValidatedRetiredSourceMarker {
    store_id: Uuid,
    source_epoch: u32,
    target_epoch: u32,
    rotation_manifest_commitment: [u8; 32],
}

fn object_storage_layout_name(layout: ObjectStorageLayout) -> &'static str {
    match layout {
        ObjectStorageLayout::LegacyFlat => LEGACY_FLAT_OBJECT_STORAGE,
        ObjectStorageLayout::EpochDirectory => EPOCH_DIRECTORY_OBJECT_STORAGE,
    }
}

fn parse_object_storage_layout(value: &str) -> Option<ObjectStorageLayout> {
    match value {
        LEGACY_FLAT_OBJECT_STORAGE => Some(ObjectStorageLayout::LegacyFlat),
        EPOCH_DIRECTORY_OBJECT_STORAGE => Some(ObjectStorageLayout::EpochDirectory),
        _ => None,
    }
}

fn rotation_manifest_checksum(
    envelope: &RotationManifestEnvelope,
) -> Result<String, SecretFileStoreError> {
    let payload = serde_json::to_vec(&RotationManifestChecksumPayload {
        magic: ROTATION_MANIFEST_MAGIC,
        format_version: ROTATION_MANIFEST_FORMAT_VERSION,
        store_id: &envelope.store_id,
        source_master_key_epoch: envelope.source_master_key_epoch,
        source_keyset_generation: envelope.source_keyset_generation,
        source_object_storage: &envelope.source_object_storage,
        target_master_key_epoch: envelope.target_master_key_epoch,
        source_keyset_commitment: &envelope.source_keyset_commitment,
        source_tree_commitment: &envelope.source_tree_commitment,
        retention_commitment: &envelope.retention_commitment,
        retained_objects: envelope.retained_objects,
    })
    .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::StorageUnavailable))?;
    Ok(domain_checksum(ROTATION_MANIFEST_CHECKSUM_DOMAIN, &payload))
}

fn encode_rotation_manifest(plan: &MasterKeyRotationPlan) -> Result<Vec<u8>, SecretFileStoreError> {
    let mut envelope = RotationManifestEnvelope {
        magic: ROTATION_MANIFEST_MAGIC.to_owned(),
        format_version: ROTATION_MANIFEST_FORMAT_VERSION,
        store_id: plan.source_state.store_id.to_string(),
        source_master_key_epoch: plan.source_state.active_master_key_epoch,
        source_keyset_generation: plan.source_state.keyset_generation,
        source_object_storage: object_storage_layout_name(plan.source_state.object_storage_layout)
            .to_owned(),
        target_master_key_epoch: plan.target_epoch,
        source_keyset_commitment: hex_encode(&plan.source_keyset_commitment),
        source_tree_commitment: hex_encode(&plan.source_tree_commitment),
        retention_commitment: hex_encode(&plan.retention_commitment),
        retained_objects: u64::try_from(plan.entries.len())
            .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?,
        checksum: String::new(),
    };
    envelope.checksum = rotation_manifest_checksum(&envelope)?;
    serde_json::to_vec(&envelope)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain.into())
}

fn read_rotation_manifest(path: &Path) -> Result<ValidatedRotationManifest, SecretFileStoreError> {
    let encoded = read_bounded(path, MAX_KEYSET_BYTES)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    let envelope: RotationManifestEnvelope = serde_json::from_slice(&encoded)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    let expected_checksum = rotation_manifest_checksum(&envelope)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    let store_id = parse_canonical_store_id(&envelope.store_id)
        .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    let layout = parse_object_storage_layout(&envelope.source_object_storage)
        .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    let source_keyset_commitment = decode_hex_32(&envelope.source_keyset_commitment)
        .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    let source_tree_commitment = decode_hex_32(&envelope.source_tree_commitment)
        .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    let retention_commitment = decode_hex_32(&envelope.retention_commitment)
        .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    let retained_objects = usize::try_from(envelope.retained_objects)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    if envelope.magic != ROTATION_MANIFEST_MAGIC
        || envelope.format_version != ROTATION_MANIFEST_FORMAT_VERSION
        || envelope.source_master_key_epoch == 0
        || envelope.source_keyset_generation < 2
        || envelope.target_master_key_epoch
            != envelope.source_master_key_epoch.checked_add(1).unwrap_or(0)
        || retained_objects > MAX_GARBAGE_COLLECTION_RETENTIONS
        || !canonical_checksum_matches(&envelope.checksum, &expected_checksum)
    {
        return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
    }
    Ok(ValidatedRotationManifest {
        store_id,
        source_state: SecretFileStoreState {
            store_id,
            active_master_key_epoch: envelope.source_master_key_epoch,
            keyset_generation: envelope.source_keyset_generation,
            object_storage_layout: layout,
        },
        target_epoch: envelope.target_master_key_epoch,
        source_keyset_commitment,
        source_tree_commitment,
        retention_commitment,
        retained_objects,
    })
}

fn rotation_manifest_commitment(path: &Path) -> Result<[u8; 32], SecretFileStoreError> {
    let encoded = read_bounded(path, MAX_KEYSET_BYTES)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    let _ = read_rotation_manifest(path)?;
    let mut digest = Sha256::new();
    digest.update(ROTATION_MANIFEST_COMMITMENT_DOMAIN);
    digest.update((encoded.len() as u64).to_be_bytes());
    digest.update(encoded);
    Ok(digest.finalize().into())
}

fn retired_source_marker_commitment(path: &Path) -> Result<[u8; 32], SecretFileStoreError> {
    let encoded = read_bounded(path, MAX_KEYSET_BYTES)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    let _ = read_retired_source_marker(path)?;
    let mut digest = Sha256::new();
    digest.update(RETIRED_SOURCE_MARKER_COMMITMENT_DOMAIN);
    digest.update((encoded.len() as u64).to_be_bytes());
    digest.update(encoded);
    Ok(digest.finalize().into())
}

fn retired_source_marker_checksum(
    envelope: &RetiredSourceMarkerEnvelope,
) -> Result<String, SecretFileStoreError> {
    let payload = serde_json::to_vec(&RetiredSourceMarkerChecksumPayload {
        magic: RETIRED_SOURCE_MARKER_MAGIC,
        format_version: RETIRED_SOURCE_MARKER_FORMAT_VERSION,
        store_id: &envelope.store_id,
        source_master_key_epoch: envelope.source_master_key_epoch,
        target_master_key_epoch: envelope.target_master_key_epoch,
        rotation_manifest_commitment: &envelope.rotation_manifest_commitment,
    })
    .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    Ok(domain_checksum(
        RETIRED_SOURCE_MARKER_CHECKSUM_DOMAIN,
        &payload,
    ))
}

fn encode_retired_source_marker(
    store_id: Uuid,
    source_epoch: u32,
    target_epoch: u32,
    manifest_commitment: [u8; 32],
) -> Result<Vec<u8>, SecretFileStoreError> {
    let mut envelope = RetiredSourceMarkerEnvelope {
        magic: RETIRED_SOURCE_MARKER_MAGIC.to_owned(),
        format_version: RETIRED_SOURCE_MARKER_FORMAT_VERSION,
        store_id: store_id.to_string(),
        source_master_key_epoch: source_epoch,
        target_master_key_epoch: target_epoch,
        rotation_manifest_commitment: hex_encode(&manifest_commitment),
        checksum: String::new(),
    };
    envelope.checksum = retired_source_marker_checksum(&envelope)?;
    serde_json::to_vec(&envelope)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain.into())
}

fn read_retired_source_marker(
    path: &Path,
) -> Result<ValidatedRetiredSourceMarker, SecretFileStoreError> {
    let encoded = read_bounded(path, MAX_KEYSET_BYTES)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    let envelope: RetiredSourceMarkerEnvelope = serde_json::from_slice(&encoded)
        .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    let expected_checksum = retired_source_marker_checksum(&envelope)?;
    let store_id = parse_canonical_store_id(&envelope.store_id)
        .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    let manifest_commitment = decode_hex_32(&envelope.rotation_manifest_commitment)
        .ok_or(SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    if envelope.magic != RETIRED_SOURCE_MARKER_MAGIC
        || envelope.format_version != RETIRED_SOURCE_MARKER_FORMAT_VERSION
        || envelope.source_master_key_epoch == 0
        || envelope.target_master_key_epoch
            != envelope.source_master_key_epoch.checked_add(1).unwrap_or(0)
        || !canonical_checksum_matches(&envelope.checksum, &expected_checksum)
    {
        return Err(SecretFileStoreErrorCode::MasterKeyRotationUncertain.into());
    }
    Ok(ValidatedRetiredSourceMarker {
        store_id,
        source_epoch: envelope.source_master_key_epoch,
        target_epoch: envelope.target_master_key_epoch,
        rotation_manifest_commitment: manifest_commitment,
    })
}

fn encode_keyset(
    store_id: Uuid,
    slot: FileSlot,
    generation: u64,
    active_master_key_epoch: u32,
) -> Result<Vec<u8>, SecretFileStoreError> {
    validate_store_id(store_id)?;
    if generation == 0
        || FileSlot::for_generation(generation) != slot
        || active_master_key_epoch == 0
    {
        return Err(SecretFileStoreErrorCode::InvalidInput.into());
    }
    let store_id = store_id.to_string();
    let checksum = keyset_checksum(&store_id, slot, generation, active_master_key_epoch)?;
    let envelope = KeysetEnvelope {
        magic: KEYSET_MAGIC.to_owned(),
        format_version: KEYSET_FORMAT_VERSION,
        store_id,
        slot,
        generation,
        active_master_key_epoch,
        checksum,
    };
    let encoded = serde_json::to_vec(&envelope)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::StorageUnavailable))?;
    if encoded.len() as u64 > MAX_KEYSET_BYTES {
        return Err(SecretFileStoreErrorCode::StorageUnavailable.into());
    }
    Ok(encoded)
}

fn encode_rotated_keyset(
    store_id: Uuid,
    slot: FileSlot,
    generation: u64,
    active_master_key_epoch: u32,
) -> Result<Vec<u8>, SecretFileStoreError> {
    validate_store_id(store_id)?;
    if generation == 0
        || FileSlot::for_generation(generation) != slot
        || active_master_key_epoch == 0
    {
        return Err(SecretFileStoreErrorCode::InvalidInput.into());
    }
    let store_id = store_id.to_string();
    let checksum = rotated_keyset_checksum(&store_id, slot, generation, active_master_key_epoch)?;
    let envelope = RotatedKeysetEnvelope {
        magic: KEYSET_MAGIC.to_owned(),
        format_version: ROTATED_KEYSET_FORMAT_VERSION,
        store_id,
        slot,
        generation,
        active_master_key_epoch,
        object_storage: EPOCH_DIRECTORY_OBJECT_STORAGE.to_owned(),
        checksum,
    };
    let encoded = serde_json::to_vec(&envelope)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::StorageUnavailable))?;
    if encoded.len() as u64 > MAX_KEYSET_BYTES {
        return Err(SecretFileStoreErrorCode::StorageUnavailable.into());
    }
    Ok(encoded)
}

fn keyset_checksum(
    store_id: &str,
    slot: FileSlot,
    generation: u64,
    active_master_key_epoch: u32,
) -> Result<String, SecretFileStoreError> {
    let payload = serde_json::to_vec(&KeysetChecksumPayload {
        magic: KEYSET_MAGIC,
        format_version: KEYSET_FORMAT_VERSION,
        store_id,
        slot,
        generation,
        active_master_key_epoch,
    })
    .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::StorageUnavailable))?;
    Ok(domain_checksum(KEYSET_CHECKSUM_DOMAIN, &payload))
}

fn rotated_keyset_checksum(
    store_id: &str,
    slot: FileSlot,
    generation: u64,
    active_master_key_epoch: u32,
) -> Result<String, SecretFileStoreError> {
    let payload = serde_json::to_vec(&RotatedKeysetChecksumPayload {
        magic: KEYSET_MAGIC,
        format_version: ROTATED_KEYSET_FORMAT_VERSION,
        store_id,
        slot,
        generation,
        active_master_key_epoch,
        object_storage: EPOCH_DIRECTORY_OBJECT_STORAGE,
    })
    .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::StorageUnavailable))?;
    Ok(domain_checksum(ROTATED_KEYSET_CHECKSUM_DOMAIN, &payload))
}

fn read_keyset(
    path: &Path,
    expected_store_id: Uuid,
    expected_slot: FileSlot,
    expected_generation: u64,
) -> Result<ValidatedKeyset, SecretFileStoreError> {
    let encoded = read_bounded(path, MAX_KEYSET_BYTES)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidKeyset))?;
    let envelope: AnyKeysetEnvelope = serde_json::from_slice(&encoded)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidKeyset))?;
    let (store_id, slot, generation, epoch, layout, actual_checksum, expected_checksum) =
        match envelope {
            AnyKeysetEnvelope::Legacy(envelope) => {
                let checksum = keyset_checksum(
                    &envelope.store_id,
                    envelope.slot,
                    envelope.generation,
                    envelope.active_master_key_epoch,
                )
                .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidKeyset))?;
                (
                    envelope.store_id,
                    envelope.slot,
                    envelope.generation,
                    envelope.active_master_key_epoch,
                    ObjectStorageLayout::LegacyFlat,
                    envelope.checksum,
                    checksum,
                )
            }
            AnyKeysetEnvelope::Rotated(envelope) => {
                if envelope.object_storage != EPOCH_DIRECTORY_OBJECT_STORAGE {
                    return Err(SecretFileStoreErrorCode::InvalidKeyset.into());
                }
                let checksum = rotated_keyset_checksum(
                    &envelope.store_id,
                    envelope.slot,
                    envelope.generation,
                    envelope.active_master_key_epoch,
                )
                .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidKeyset))?;
                (
                    envelope.store_id,
                    envelope.slot,
                    envelope.generation,
                    envelope.active_master_key_epoch,
                    ObjectStorageLayout::EpochDirectory,
                    envelope.checksum,
                    checksum,
                )
            }
        };
    let format_is_valid = match layout {
        ObjectStorageLayout::LegacyFlat => {
            // The untagged legacy shape has no v2-only field, so accepting it
            // cannot silently reinterpret an epoch-directory keyset.
            serde_json::from_slice::<KeysetEnvelope>(&encoded)
                .is_ok_and(|envelope| envelope.format_version == KEYSET_FORMAT_VERSION)
        }
        ObjectStorageLayout::EpochDirectory => {
            serde_json::from_slice::<RotatedKeysetEnvelope>(&encoded).is_ok_and(|envelope| {
                envelope.format_version == ROTATED_KEYSET_FORMAT_VERSION
                    && envelope.object_storage == EPOCH_DIRECTORY_OBJECT_STORAGE
            })
        }
    };
    if !format_is_valid
        || parse_canonical_store_id(&store_id) != Some(expected_store_id)
        || slot != expected_slot
        || generation != expected_generation
        || generation == 0
        || FileSlot::for_generation(generation) != slot
        || epoch == 0
        || !canonical_checksum_matches(&actual_checksum, &expected_checksum)
    {
        return Err(SecretFileStoreErrorCode::InvalidKeyset.into());
    }
    Ok(ValidatedKeyset {
        path: path.to_path_buf(),
        slot,
        generation,
        active_master_key_epoch: epoch,
        object_storage_layout: layout,
    })
}

fn load_keyset(root: &Path, store_id: Uuid) -> Result<LoadedKeyset, SecretFileStoreError> {
    let keyset_root = root.join(KEYSET_DIRECTORY);
    reject_reparse_directory(&keyset_root, SecretFileStoreErrorCode::NotInitialized)?;
    validate_keyset_root_entries(&keyset_root)?;
    let slot_a = probe_keyset_slot(&keyset_root.join(SLOT_A_DIRECTORY), FileSlot::A, store_id)?;
    let slot_b = probe_keyset_slot(&keyset_root.join(SLOT_B_DIRECTORY), FileSlot::B, store_id)?;
    let loaded = LoadedKeyset {
        store_id,
        slot_a,
        slot_b,
    };
    match (&loaded.slot_a.keyset, &loaded.slot_b.keyset) {
        (None, None) if loaded.slot_a.empty && loaded.slot_b.empty => Ok(loaded),
        (None, None) => Err(SecretFileStoreErrorCode::BothKeysetSlotsCorrupt.into()),
        (Some(left), Some(right)) if left.generation.abs_diff(right.generation) != 1 => {
            Err(SecretFileStoreErrorCode::InvalidKeyset.into())
        }
        _ => Ok(loaded),
    }
}

fn validate_keyset_root_entries(root: &Path) -> Result<(), SecretFileStoreError> {
    let mut seen = 0_usize;
    for entry in fs::read_dir(root)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidKeyset))?
    {
        let entry = entry
            .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidKeyset))?;
        seen += 1;
        if seen > 2 {
            return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict))?;
        if !matches!(name.as_str(), SLOT_A_DIRECTORY | SLOT_B_DIRECTORY) {
            return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
        }
        reject_reparse_directory(&entry.path(), SecretFileStoreErrorCode::ArtifactConflict)?;
    }
    for name in [SLOT_A_DIRECTORY, SLOT_B_DIRECTORY] {
        reject_reparse_directory(&root.join(name), SecretFileStoreErrorCode::NotInitialized)?;
    }
    Ok(())
}

fn probe_keyset_slot(
    directory: &Path,
    slot: FileSlot,
    store_id: Uuid,
) -> Result<KeysetSlotProbe, SecretFileStoreError> {
    reject_reparse_directory(directory, SecretFileStoreErrorCode::InvalidKeyset)?;
    let mut candidates = Vec::new();
    let mut entries = 0_usize;
    for entry in fs::read_dir(directory)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidKeyset))?
    {
        let entry = entry
            .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidKeyset))?;
        entries += 1;
        if entries > MAX_SLOT_ENTRIES {
            return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict))?;
        reject_reparse_regular(&entry.path(), SecretFileStoreErrorCode::ArtifactConflict)?;
        if let Some(generation) = parse_keyset_name(&name) {
            if FileSlot::for_generation(generation) != slot {
                return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
            }
            candidates.push((generation, entry.path()));
        } else if is_keyset_temp_name(&name) {
            // A recognizable temp is retained after a crash only when its
            // complete contents prove ownership by this store and slot.
            let encoded = read_bounded(&entry.path(), MAX_KEYSET_BYTES).map_err(|_| {
                SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict)
            })?;
            let envelope: AnyKeysetEnvelope = serde_json::from_slice(&encoded).map_err(|_| {
                SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict)
            })?;
            read_keyset(&entry.path(), store_id, slot, envelope.generation()).map_err(|_| {
                SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict)
            })?;
        } else {
            return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
        }
    }
    if candidates.is_empty() {
        return Ok(KeysetSlotProbe {
            empty: true,
            max_seen: None,
            keyset: None,
        });
    }
    candidates.sort_by_key(|(generation, _)| *generation);
    let max_seen = candidates.last().map(|value| value.0);
    let latest = candidates
        .iter()
        .rev()
        .take_while(|(generation, _)| Some(*generation) == max_seen)
        .collect::<Vec<_>>();
    let keyset = if latest.len() == 1 {
        let (generation, path) = latest[0];
        read_keyset(path, store_id, slot, *generation).ok()
    } else {
        None
    };
    Ok(KeysetSlotProbe {
        empty: false,
        max_seen,
        keyset,
    })
}

fn confirm_loaded_keyset(root: &Path, before: &LoadedKeyset) -> Result<(), SecretFileStoreError> {
    if !before.is_stable() || before.has_higher_unreadable() {
        return Err(SecretFileStoreErrorCode::DurabilityUnconfirmed.into());
    }
    let keyset = root.join(KEYSET_DIRECTORY);
    sync_directory(&keyset.join(SLOT_A_DIRECTORY))
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::DurabilityUnconfirmed))?;
    sync_directory(&keyset.join(SLOT_B_DIRECTORY))
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::DurabilityUnconfirmed))?;
    sync_directory(&keyset)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::DurabilityUnconfirmed))?;
    sync_directory(root)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::DurabilityUnconfirmed))?;
    if read_owner(&root.join(OWNER_FILE)).ok() != Some(before.store_id) {
        return Err(SecretFileStoreErrorCode::DurabilityUnconfirmed.into());
    }
    let after = load_keyset(root, before.store_id)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::DurabilityUnconfirmed))?;
    if !after.is_stable() || !before.same_pair(&after) {
        return Err(SecretFileStoreErrorCode::DurabilityUnconfirmed.into());
    }
    Ok(())
}

fn keyset_pair_is_still_visible(root: &Path, expected: &LoadedKeyset) -> bool {
    load_keyset(root, expected.store_id)
        .is_ok_and(|actual| actual.is_stable() && expected.same_pair(&actual))
        && read_owner(&root.join(OWNER_FILE)).ok() == Some(expected.store_id)
}

fn process_gate(root: &Path) -> Result<ProcessGate, SecretFileStoreError> {
    let registry = PROCESS_GATES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut registry = registry
        .lock()
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::LockPoisoned))?;
    registry.retain(|_, gate| gate.strong_count() > 0);
    if let Some(gate) = registry.get(root).and_then(Weak::upgrade) {
        return Ok(gate);
    }
    let gate = Arc::new(Mutex::new(()));
    registry.insert(root.to_path_buf(), Arc::downgrade(&gate));
    Ok(gate)
}

fn ensure_root_directory(path: &Path) -> Result<(), SecretFileStoreError> {
    use std::path::Component;

    if !path.is_absolute() || path.file_name().is_none() {
        return Err(SecretFileStoreErrorCode::InvalidRoot.into());
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                current.push(component.as_os_str());
            }
            Component::Normal(name) => {
                current.push(name);
                match fs::symlink_metadata(&current) {
                    Ok(metadata) => {
                        if !is_safe_directory(&metadata) {
                            return Err(SecretFileStoreErrorCode::InvalidRoot.into());
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        create_directory_secure(&current).map_err(|_| {
                            SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidRoot)
                        })?;
                        if let Some(parent) = current.parent() {
                            sync_directory(parent).map_err(|_| {
                                SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidRoot)
                            })?;
                        }
                    }
                    Err(_) => return Err(SecretFileStoreErrorCode::InvalidRoot.into()),
                }
            }
            Component::CurDir | Component::ParentDir => {
                return Err(SecretFileStoreErrorCode::InvalidRoot.into());
            }
        }
    }
    reject_reparse_directory(path, SecretFileStoreErrorCode::InvalidRoot)
}

fn ensure_transaction_lock(root: &Path) -> Result<(), SecretFileStoreError> {
    let path = root.join(TRANSACTION_LOCK_FILE);
    match fs::symlink_metadata(&path) {
        Ok(_) => return validate_lock_file(&path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(SecretFileStoreErrorCode::LockUnavailable.into()),
    }
    if fs::read_dir(root)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidRoot))?
        .next()
        .is_some()
    {
        return Err(SecretFileStoreErrorCode::LockUnavailable.into());
    }
    match create_new_regular(&path) {
        Ok(file) => {
            file.sync_all().map_err(|_| {
                SecretFileStoreError::new(SecretFileStoreErrorCode::StorageUnavailable)
            })?;
            sync_directory(root).map_err(|_| {
                SecretFileStoreError::new(SecretFileStoreErrorCode::StorageUnavailable)
            })?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            validate_lock_file(&path)?;
        }
        Err(_) => return Err(SecretFileStoreErrorCode::StorageUnavailable.into()),
    }
    validate_lock_file(&path)
}

fn validate_lock_file(path: &Path) -> Result<(), SecretFileStoreError> {
    let file = open_existing_regular(path, true)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::LockUnavailable))?;
    if file
        .metadata()
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::LockUnavailable))?
        .len()
        != 0
    {
        return Err(SecretFileStoreErrorCode::LockUnavailable.into());
    }
    Ok(())
}

fn validate_root_entry_names(
    root: &Path,
    lock_may_be_missing: bool,
) -> Result<(), SecretFileStoreError> {
    reject_reparse_directory(root, SecretFileStoreErrorCode::InvalidRoot)?;
    let mut seen = 0_usize;
    let mut has_lock = false;
    let mut has_owner = false;
    let mut has_keyset = false;
    let mut has_objects = false;
    let mut has_epochs = false;
    let mut owner_temps = Vec::new();
    for entry in fs::read_dir(root)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidRoot))?
    {
        let entry =
            entry.map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidRoot))?;
        seen += 1;
        if seen > MAX_ROOT_ENTRIES {
            return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict))?;
        match name.as_str() {
            TRANSACTION_LOCK_FILE => {
                has_lock = true;
                validate_lock_file(&entry.path())?;
            }
            OWNER_FILE => {
                has_owner = true;
                reject_reparse_regular(&entry.path(), SecretFileStoreErrorCode::InvalidOwner)?;
            }
            KEYSET_DIRECTORY => {
                has_keyset = true;
                reject_reparse_directory(
                    &entry.path(),
                    SecretFileStoreErrorCode::ArtifactConflict,
                )?;
            }
            OBJECTS_DIRECTORY => {
                has_objects = true;
                reject_reparse_directory(
                    &entry.path(),
                    SecretFileStoreErrorCode::ArtifactConflict,
                )?;
            }
            EPOCHS_DIRECTORY => {
                has_epochs = true;
                reject_reparse_directory(
                    &entry.path(),
                    SecretFileStoreErrorCode::ArtifactConflict,
                )?;
            }
            _ if is_owner_temp_name(&name) => {
                reject_reparse_regular(&entry.path(), SecretFileStoreErrorCode::ArtifactConflict)?;
                owner_temps.push(entry.path());
            }
            _ => return Err(SecretFileStoreErrorCode::ArtifactConflict.into()),
        }
    }
    if !lock_may_be_missing && !has_lock {
        return Err(SecretFileStoreErrorCode::LockUnavailable.into());
    }
    if !has_owner && (has_keyset || has_objects || has_epochs || !owner_temps.is_empty()) {
        return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
    }
    if has_owner {
        let owner = read_owner(&root.join(OWNER_FILE))?;
        for temporary in owner_temps {
            if read_owner(&temporary).ok() != Some(owner) {
                return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
            }
        }
    }
    Ok(())
}

fn is_owner_temp_name(name: &str) -> bool {
    name.strip_prefix(".owner-")
        .and_then(|body| body.strip_suffix(".tmp"))
        .is_some_and(|artifact_id| is_lower_hex(artifact_id, 32))
}

fn cleanup_owner_temps(root: &Path, store_id: Uuid) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    let mut removed = false;
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if is_owner_temp_name(&name)
            && read_owner(&entry.path()).ok() == Some(store_id)
            && fs::remove_file(entry.path()).is_ok()
        {
            removed = true;
        }
    }
    if removed {
        let _ = sync_directory(root);
    }
}

fn ensure_authoritatively_empty(root: &Path) -> Result<(), SecretFileStoreError> {
    validate_root_entry_names(root, false)?;
    let mut entries = fs::read_dir(root)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidRoot))?;
    let first = entries
        .next()
        .transpose()
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidRoot))?
        .ok_or_else(|| SecretFileStoreError::new(SecretFileStoreErrorCode::LockUnavailable))?;
    if first.file_name() != TRANSACTION_LOCK_FILE || entries.next().is_some() {
        return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
    }
    Ok(())
}

fn ensure_store_directories(root: &Path) -> Result<(), SecretFileStoreError> {
    let keyset = root.join(KEYSET_DIRECTORY);
    ensure_owned_directory(&keyset, root)?;
    ensure_owned_directory(&keyset.join(SLOT_A_DIRECTORY), &keyset)?;
    ensure_owned_directory(&keyset.join(SLOT_B_DIRECTORY), &keyset)?;
    let objects = root.join(OBJECTS_DIRECTORY);
    ensure_owned_directory(&objects, root)?;
    validate_root_entry_names(root, false)
}

fn epoch_storage_root(root: &Path, epoch: u32) -> PathBuf {
    root.join(EPOCHS_DIRECTORY).join(format!("{epoch:08x}"))
}

fn object_storage_root(root: &Path, state: &SecretFileStoreState) -> PathBuf {
    match state.object_storage_layout {
        ObjectStorageLayout::LegacyFlat => root.to_path_buf(),
        ObjectStorageLayout::EpochDirectory => {
            epoch_storage_root(root, state.active_master_key_epoch)
        }
    }
}

fn parse_epoch_directory_name(name: &str) -> Option<u32> {
    if !is_lower_hex(name, 8) {
        return None;
    }
    let epoch = u32::from_str_radix(name, 16).ok()?;
    (epoch > 0).then_some(epoch)
}

fn validate_epoch_storage_roots(root: &Path, store_id: Uuid) -> Result<(), SecretFileStoreError> {
    let epochs = root.join(EPOCHS_DIRECTORY);
    if !path_exists(&epochs)? {
        return Ok(());
    }
    reject_reparse_directory(&epochs, SecretFileStoreErrorCode::ArtifactConflict)?;
    let entries = sorted_directory_entries(&epochs)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict))?;
    if entries.len() > MAX_EPOCH_DIRECTORIES {
        return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
    }
    for (name, path) in entries {
        if parse_epoch_directory_name(&name).is_none() {
            return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
        }
        validate_epoch_storage_root(&path, store_id, true)?;
    }
    Ok(())
}

fn validate_epoch_storage_root(
    epoch_root: &Path,
    store_id: Uuid,
    allow_incomplete: bool,
) -> Result<(), SecretFileStoreError> {
    reject_reparse_directory(epoch_root, SecretFileStoreErrorCode::ArtifactConflict)?;
    let directory_epoch = epoch_root
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(parse_epoch_directory_name)
        .ok_or(SecretFileStoreErrorCode::ArtifactConflict)?;
    let entries = sorted_directory_entries(epoch_root)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict))?;
    if entries.len() > MAX_ROOT_ENTRIES {
        return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
    }
    let mut owner = false;
    let mut objects = false;
    let mut manifest = None;
    let mut retired_marker = None;
    let mut owner_temps = Vec::new();
    let mut rotation_temps = Vec::new();
    let mut retired_temps = Vec::new();
    for (name, path) in entries {
        match name.as_str() {
            OWNER_FILE => {
                reject_reparse_regular(&path, SecretFileStoreErrorCode::ArtifactConflict)?;
                if read_owner(&path)? != store_id {
                    return Err(SecretFileStoreErrorCode::InvalidOwner.into());
                }
                owner = true;
            }
            OBJECTS_DIRECTORY => {
                reject_reparse_directory(&path, SecretFileStoreErrorCode::ArtifactConflict)?;
                validate_objects_root(&path)?;
                objects = true;
            }
            ROTATION_MANIFEST_FILE => {
                reject_reparse_regular(&path, SecretFileStoreErrorCode::ArtifactConflict)?;
                let parsed = read_rotation_manifest(&path)?;
                if parsed.store_id != store_id || parsed.target_epoch != directory_epoch {
                    return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
                }
                manifest = Some(parsed);
            }
            RETIRED_SOURCE_MARKER_FILE => {
                reject_reparse_regular(&path, SecretFileStoreErrorCode::ArtifactConflict)?;
                let parsed = read_retired_source_marker(&path)?;
                if parsed.store_id != store_id || parsed.target_epoch != directory_epoch {
                    return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
                }
                retired_marker = Some(parsed);
            }
            _ if is_owner_temp_name(&name) => {
                reject_reparse_regular(&path, SecretFileStoreErrorCode::ArtifactConflict)?;
                owner_temps.push(path);
            }
            _ if is_rotation_temp_name(&name) => {
                reject_reparse_regular(&path, SecretFileStoreErrorCode::ArtifactConflict)?;
                rotation_temps.push(path);
            }
            _ if is_retired_source_temp_name(&name) => {
                reject_reparse_regular(&path, SecretFileStoreErrorCode::ArtifactConflict)?;
                retired_temps.push(path);
            }
            _ => return Err(SecretFileStoreErrorCode::ArtifactConflict.into()),
        }
    }
    if !owner
        && (objects
            || manifest.is_some()
            || retired_marker.is_some()
            || !rotation_temps.is_empty()
            || !retired_temps.is_empty())
        || !allow_incomplete && (!owner || !objects || manifest.is_none())
    {
        return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
    }
    if !owner && !owner_temps.is_empty() && !allow_incomplete {
        return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
    }
    for temporary in owner_temps {
        if read_owner(&temporary).ok() != Some(store_id) {
            return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
        }
    }
    if !rotation_temps.is_empty() {
        let mut parsed_temps = Vec::with_capacity(rotation_temps.len());
        for temporary in rotation_temps {
            let parsed = read_rotation_manifest(&temporary)?;
            if parsed.store_id != store_id
                || parsed.target_epoch != directory_epoch
                || manifest.as_ref().is_some_and(|reference| {
                    !validated_rotation_manifests_match(reference, &parsed)
                })
            {
                return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
            }
            parsed_temps.push(parsed);
        }
        if parsed_temps
            .windows(2)
            .any(|pair| !validated_rotation_manifests_match(&pair[0], &pair[1]))
        {
            return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
        }
    }
    if retired_marker.is_some() || !retired_temps.is_empty() {
        let manifest = manifest
            .as_ref()
            .ok_or(SecretFileStoreErrorCode::ArtifactConflict)?;
        let manifest_path = epoch_root.join(ROTATION_MANIFEST_FILE);
        if retired_marker.as_ref().is_some_and(|marker| {
            !retired_source_marker_matches_manifest(marker, manifest, &manifest_path)
        }) {
            return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
        }
        let mut reference = retired_marker;
        for temporary in retired_temps {
            let parsed = read_retired_source_marker(&temporary)?;
            if !retired_source_marker_matches_manifest(&parsed, manifest, &manifest_path)
                || reference.as_ref().is_some_and(|reference| {
                    reference.store_id != parsed.store_id
                        || reference.source_epoch != parsed.source_epoch
                        || reference.target_epoch != parsed.target_epoch
                        || !bool::from(
                            reference
                                .rotation_manifest_commitment
                                .ct_eq(&parsed.rotation_manifest_commitment),
                        )
                })
            {
                return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
            }
            if reference.is_none() {
                reference = Some(parsed);
            }
        }
    }
    Ok(())
}

fn ensure_epoch_storage_root(
    root: &Path,
    store_id: Uuid,
    epoch: u32,
) -> Result<SecretPublicationDurability, SecretFileStoreError> {
    if epoch == 0 {
        return Err(SecretFileStoreErrorCode::InvalidInput.into());
    }
    let epochs = root.join(EPOCHS_DIRECTORY);
    ensure_owned_directory(&epochs, root)?;
    validate_epoch_storage_roots(root, store_id)?;
    let epoch_root = epoch_storage_root(root, epoch);
    if !path_exists(&epoch_root)? {
        ensure_directory_entry_headroom(&epochs, MAX_EPOCH_DIRECTORIES, 1)
            .map_err(|_| SecretFileStoreErrorCode::MasterKeyRotationUncertain)?;
    }
    ensure_owned_directory(&epoch_root, &epochs)?;
    validate_epoch_storage_root(&epoch_root, store_id, true)?;
    let mut durability = SecretPublicationDurability::Durable;
    if read_optional_owner(&epoch_root)?.is_none() {
        let encoded = encode_owner(store_id)?;
        durability = publish_named_no_overwrite(
            &epoch_root,
            OWNER_FILE,
            ".owner",
            &encoded,
            MAX_ROOT_ENTRIES,
        )?;
        if durability != SecretPublicationDurability::Durable {
            return Ok(durability);
        }
    }
    if read_owner(&epoch_root.join(OWNER_FILE))? != store_id {
        return Err(SecretFileStoreErrorCode::InvalidOwner.into());
    }
    cleanup_owner_temps(&epoch_root, store_id);
    ensure_owned_directory(&epoch_root.join(OBJECTS_DIRECTORY), &epoch_root)?;
    validate_epoch_storage_root(&epoch_root, store_id, true)?;
    sync_directory(&epoch_root).map_err(|_| SecretFileStoreErrorCode::StorageUnavailable)?;
    sync_directory(&epochs).map_err(|_| SecretFileStoreErrorCode::StorageUnavailable)?;
    Ok(durability)
}

fn ensure_owned_directory(path: &Path, parent: &Path) -> Result<(), SecretFileStoreError> {
    match create_directory_secure(path) {
        Ok(()) => {
            sync_directory(parent).map_err(|_| SecretFileStoreErrorCode::StorageUnavailable.into())
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            reject_reparse_directory(path, SecretFileStoreErrorCode::ArtifactConflict)
        }
        Err(_) => Err(SecretFileStoreErrorCode::StorageUnavailable.into()),
    }
}

fn path_exists(path: &Path) -> Result<bool, SecretFileStoreError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(SecretFileStoreErrorCode::StorageUnavailable.into()),
    }
}

fn publish_named_no_overwrite(
    directory: &Path,
    final_name: &str,
    temp_prefix: &str,
    encoded: &[u8],
    maximum_entries: usize,
) -> Result<SecretPublicationDurability, SecretFileStoreError> {
    publish_named_no_overwrite_with_hooks(
        directory,
        final_name,
        temp_prefix,
        encoded,
        maximum_entries,
        sync_directory,
        published_bytes_match,
    )
}

fn publish_named_no_overwrite_with_hooks<F, R>(
    directory: &Path,
    final_name: &str,
    temp_prefix: &str,
    encoded: &[u8],
    maximum_entries: usize,
    mut sync: F,
    mut revalidate: R,
) -> Result<SecretPublicationDurability, SecretFileStoreError>
where
    F: FnMut(&Path) -> io::Result<()>,
    R: FnMut(&Path, &[u8]) -> io::Result<bool>,
{
    reject_reparse_directory(directory, SecretFileStoreErrorCode::ArtifactConflict)?;
    ensure_directory_entry_headroom(directory, maximum_entries, 2)?;
    let final_path = directory.join(final_name);
    for _ in 0..PUBLISH_ATTEMPTS {
        let temp_path = directory.join(format!("{temp_prefix}-{}.tmp", Uuid::new_v4().simple()));
        let mut temp = match create_new_regular(&temp_path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(SecretFileStoreErrorCode::StorageUnavailable.into()),
        };
        let write_result = temp.write_all(encoded).and_then(|()| temp.sync_all());
        drop(temp);
        if write_result.is_err() {
            remove_exact_temp(&temp_path, encoded);
            return Err(SecretFileStoreErrorCode::StorageUnavailable.into());
        }
        if let Err(error) = ensure_directory_entry_headroom(directory, maximum_entries, 1) {
            remove_exact_temp(&temp_path, encoded);
            return Err(error);
        }
        if let Err(error) = fs::hard_link(&temp_path, &final_path) {
            remove_exact_temp(&temp_path, encoded);
            if error.kind() == io::ErrorKind::AlreadyExists {
                return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
            }
            return Err(SecretFileStoreErrorCode::StorageUnavailable.into());
        }

        let sync_result = sync(directory);
        let revalidation = revalidate(&final_path, encoded);
        let outcome = match (sync_result, revalidation) {
            (Ok(()), Ok(true)) => SecretPublicationDurability::Durable,
            (Err(_), Ok(true)) => SecretPublicationDurability::PublishedDurabilityUncertain,
            _ => SecretPublicationDurability::PublicationIndeterminate,
        };
        if outcome != SecretPublicationDurability::PublicationIndeterminate {
            remove_exact_temp(&temp_path, encoded);
            let _ = sync(directory);
        }
        return Ok(outcome);
    }
    Err(SecretFileStoreErrorCode::ArtifactConflict.into())
}

fn ensure_directory_entry_headroom(
    directory: &Path,
    maximum_entries: usize,
    required_entries: usize,
) -> Result<(), SecretFileStoreError> {
    let maximum_existing = maximum_entries
        .checked_sub(required_entries)
        .ok_or_else(|| SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict))?;
    let mut entries = 0_usize;
    for entry in fs::read_dir(directory)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::StorageUnavailable))?
    {
        entry
            .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::StorageUnavailable))?;
        entries = entries
            .checked_add(1)
            .ok_or_else(|| SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict))?;
        if entries > maximum_existing {
            return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
        }
    }
    Ok(())
}

fn remove_exact_temp(path: &Path, expected: &[u8]) {
    if published_bytes_match(path, expected).unwrap_or(false) {
        let _ = fs::remove_file(path);
    }
}

fn published_bytes_match(path: &Path, expected: &[u8]) -> io::Result<bool> {
    let bytes = read_bounded(path, expected.len() as u64)?;
    Ok(bytes.len() == expected.len() && bool::from(bytes.as_slice().ct_eq(expected)))
}

fn invalid_artifact_io() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid custody artifact")
}

#[cfg(windows)]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse(_: &fs::Metadata) -> bool {
    false
}

fn is_safe_regular(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_file() && !metadata.file_type().is_symlink() && !is_reparse(metadata)
}

fn is_safe_directory(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_dir() && !metadata.file_type().is_symlink() && !is_reparse(metadata)
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(_: &fs::Metadata, _: &fs::Metadata) -> bool {
    true
}

fn reject_reparse_regular(
    path: &Path,
    code: SecretFileStoreErrorCode,
) -> Result<(), SecretFileStoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| SecretFileStoreError::new(code))?;
    if !is_safe_regular(&metadata) || !has_private_permissions(&metadata) {
        return Err(code.into());
    }
    Ok(())
}

fn reject_reparse_directory(
    path: &Path,
    code: SecretFileStoreErrorCode,
) -> Result<(), SecretFileStoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| SecretFileStoreError::new(code))?;
    if !is_safe_directory(&metadata) || !has_private_permissions(&metadata) {
        return Err(code.into());
    }
    let _ = open_existing_directory(path).map_err(|_| SecretFileStoreError::new(code))?;
    Ok(())
}

#[cfg(unix)]
fn has_private_permissions(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn has_private_permissions(_: &fs::Metadata) -> bool {
    true
}

fn open_existing_regular(path: &Path, writable: bool) -> io::Result<File> {
    let before = fs::symlink_metadata(path)?;
    if !is_safe_regular(&before) || !has_private_permissions(&before) {
        return Err(invalid_artifact_io());
    }
    let mut options = OpenOptions::new();
    options.read(true).write(writable);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_SHARE_READ: u32 = 1;
        const FILE_SHARE_WRITE: u32 = 2;
        options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
    let file = options.open(path)?;
    let opened = file.metadata()?;
    let after = fs::symlink_metadata(path)?;
    if !is_safe_regular(&opened)
        || !is_safe_regular(&after)
        || !has_private_permissions(&opened)
        || !has_private_permissions(&after)
        || !same_file(&before, &opened)
        || !same_file(&opened, &after)
    {
        return Err(invalid_artifact_io());
    }
    Ok(file)
}

fn open_existing_directory(path: &Path) -> io::Result<File> {
    let before = fs::symlink_metadata(path)?;
    if !is_safe_directory(&before) {
        return Err(invalid_artifact_io());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const FILE_SHARE_READ: u32 = 1;
        const FILE_SHARE_WRITE: u32 = 2;
        options
            .write(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
    let file = options.open(path)?;
    let opened = file.metadata()?;
    let after = fs::symlink_metadata(path)?;
    if !is_safe_directory(&opened)
        || !is_safe_directory(&after)
        || !same_file(&before, &opened)
        || !same_file(&opened, &after)
    {
        return Err(invalid_artifact_io());
    }
    Ok(file)
}

fn create_new_regular(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_SHARE_READ: u32 = 1;
        const FILE_SHARE_WRITE: u32 = 2;
        options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
    let file = options.open(path)?;
    let opened = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if !is_safe_regular(&opened) || !is_safe_regular(&named) || !same_file(&opened, &named) {
        return Err(invalid_artifact_io());
    }
    Ok(file)
}

#[cfg(unix)]
fn create_directory_secure(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path)
}

#[cfg(not(unix))]
fn create_directory_secure(path: &Path) -> io::Result<()> {
    fs::create_dir(path)
}

fn read_bounded(path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    let mut file = open_existing_regular(path, false)?;
    let length = file.metadata()?.len();
    if length > max_bytes {
        return Err(invalid_artifact_io());
    }
    let capacity = usize::try_from(length).map_err(|_| invalid_artifact_io())?;
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take(max_bytes.checked_add(1).ok_or_else(invalid_artifact_io)?)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(invalid_artifact_io());
    }
    Ok(bytes)
}

fn sync_directory(path: &Path) -> io::Result<()> {
    sync_directory_with(path, File::sync_all)
}

fn sync_directory_with<F>(path: &Path, sync: F) -> io::Result<()>
where
    F: FnOnce(&File) -> io::Result<()>,
{
    let directory = open_existing_directory(path)?;
    sync(&directory)
}

fn keyset_final_name(generation: u64) -> String {
    format!("keyset-{generation:020}-{}.json", Uuid::new_v4().simple())
}

fn parse_keyset_name(name: &str) -> Option<u64> {
    let body = name.strip_prefix("keyset-")?.strip_suffix(".json")?;
    let (generation, artifact_id) = body.split_once('-')?;
    if generation.len() != 20 || !is_lower_hex(artifact_id, 32) {
        return None;
    }
    let generation = generation.parse::<u64>().ok()?;
    (generation > 0).then_some(generation)
}

fn is_keyset_temp_name(name: &str) -> bool {
    name.strip_prefix(".keyset-")
        .and_then(|body| body.strip_suffix(".tmp"))
        .is_some_and(|artifact_id| is_lower_hex(artifact_id, 32))
}

fn cleanup_keyset_artifacts(root: &Path, loaded: &LoadedKeyset) {
    if !loaded.is_stable() {
        return;
    }
    for (slot, keep) in [
        (FileSlot::A, loaded.slot_a.keyset.as_ref()),
        (FileSlot::B, loaded.slot_b.keyset.as_ref()),
    ] {
        let (Some(keep), directory) = (keep, root.join(KEYSET_DIRECTORY).join(slot.directory()))
        else {
            continue;
        };
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        let mut removed = false;
        for entry in entries.flatten() {
            let path = entry.path();
            if path == keep.path {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let owned = if let Some(generation) = parse_keyset_name(&name) {
                generation < keep.generation
                    && read_keyset(&path, loaded.store_id, slot, generation).is_ok()
            } else if is_keyset_temp_name(&name) {
                let envelope = read_bounded(&path, MAX_KEYSET_BYTES)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<AnyKeysetEnvelope>(&bytes).ok());
                envelope.is_some_and(|envelope| {
                    envelope.generation() <= keep.generation
                        && read_keyset(&path, loaded.store_id, slot, envelope.generation()).is_ok()
                })
            } else {
                false
            };
            if owned && fs::remove_file(&path).is_ok() {
                removed = true;
            }
        }
        if removed {
            let _ = sync_directory(&directory);
        }
    }
}

fn domain_checksum(domain: &[u8], encoded: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update((encoded.len() as u64).to_be_bytes());
    digest.update(encoded);
    hex_encode(&digest.finalize())
}

fn canonical_checksum_matches(actual: &str, expected: &str) -> bool {
    actual.len() == 64
        && is_lower_hex(actual, 64)
        && expected.len() == actual.len()
        && bool::from(actual.as_bytes().ct_eq(expected.as_bytes()))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if !is_lower_hex(value, 64) {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    Some(decoded)
}

fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn derive_locator(
    store_id: Uuid,
    entity_id: &str,
) -> Result<SecretObjectLocator, SecretFileStoreError> {
    validate_store_id(store_id)?;
    let entity_digest = SecretEntityDigest::derive(entity_id)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidInput))?;
    let object_digest = object_digest_for(store_id, entity_digest);
    Ok(SecretObjectLocator {
        store_id,
        entity_digest,
        object_digest,
    })
}

fn object_digest_for(store_id: Uuid, entity_digest: SecretEntityDigest) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(OBJECT_PATH_DOMAIN);
    digest.update(store_id.as_bytes());
    digest.update(entity_digest.as_bytes());
    digest.finalize().into()
}

fn object_directory(root: &Path, locator: &SecretObjectLocator) -> PathBuf {
    let encoded = hex_encode(&locator.object_digest);
    root.join(OBJECTS_DIRECTORY)
        .join(&encoded[..2])
        .join(encoded)
}

fn ensure_object_directories(
    root: &Path,
    locator: &SecretObjectLocator,
) -> Result<(), SecretFileStoreError> {
    if read_optional_owner(root)? != Some(locator.store_id) {
        return Err(SecretFileStoreErrorCode::InvalidInput.into());
    }
    let objects = root.join(OBJECTS_DIRECTORY);
    reject_reparse_directory(&objects, SecretFileStoreErrorCode::ArtifactConflict)?;
    validate_objects_root(&objects)?;
    let encoded = hex_encode(&locator.object_digest);
    let prefix = objects.join(&encoded[..2]);
    if !path_exists(&prefix)? {
        ensure_directory_entry_headroom(&objects, 256, 1)?;
    }
    ensure_owned_directory(&prefix, &objects)?;
    validate_object_prefix(&prefix)?;
    let object = prefix.join(&encoded);
    if !path_exists(&object)? {
        ensure_directory_entry_headroom(&prefix, MAX_PREFIX_ENTRIES, 1)?;
    }
    ensure_owned_directory(&object, &prefix)?;
    validate_object_directory_entries(&object, true)?;
    ensure_owned_directory(&object.join(SLOT_A_DIRECTORY), &object)?;
    ensure_owned_directory(&object.join(SLOT_B_DIRECTORY), &object)?;
    validate_object_directory_entries(&object, false)
}

fn validate_existing_object_directories(
    root: &Path,
    locator: &SecretObjectLocator,
) -> Result<(), SecretFileStoreError> {
    if read_optional_owner(root)? != Some(locator.store_id) {
        return Err(SecretFileStoreErrorCode::InvalidInput.into());
    }
    let objects = root.join(OBJECTS_DIRECTORY);
    reject_reparse_directory(&objects, SecretFileStoreErrorCode::ObjectUnavailable)?;
    validate_objects_root(&objects)?;
    let encoded = hex_encode(&locator.object_digest);
    let prefix = objects.join(&encoded[..2]);
    reject_reparse_directory(&prefix, SecretFileStoreErrorCode::ObjectUnavailable)?;
    validate_object_prefix(&prefix)?;
    let object = prefix.join(encoded);
    reject_reparse_directory(&object, SecretFileStoreErrorCode::ObjectUnavailable)?;
    validate_object_directory_entries(&object, false)?;
    for slot in [SLOT_A_DIRECTORY, SLOT_B_DIRECTORY] {
        reject_reparse_directory(
            &object.join(slot),
            SecretFileStoreErrorCode::ObjectUnavailable,
        )?;
    }
    Ok(())
}

fn validate_objects_root(root: &Path) -> Result<(), SecretFileStoreError> {
    let mut count = 0_usize;
    for entry in fs::read_dir(root)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict))?
    {
        let entry = entry
            .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict))?;
        count += 1;
        if count > 256 {
            return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict))?;
        if !is_lower_hex(&name, 2) {
            return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
        }
        reject_reparse_directory(&entry.path(), SecretFileStoreErrorCode::ArtifactConflict)?;
    }
    Ok(())
}

fn ensure_objects_authoritatively_empty(root: &Path) -> Result<(), SecretFileStoreError> {
    let objects = root.join(OBJECTS_DIRECTORY);
    reject_reparse_directory(&objects, SecretFileStoreErrorCode::InvalidKeyset)?;
    validate_objects_root(&objects)?;
    if fs::read_dir(&objects)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidKeyset))?
        .next()
        .is_some()
    {
        return Err(SecretFileStoreErrorCode::InvalidKeyset.into());
    }
    Ok(())
}

fn validate_object_prefix(prefix: &Path) -> Result<(), SecretFileStoreError> {
    let expected_prefix = prefix
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict))?;
    let mut count = 0_usize;
    for entry in fs::read_dir(prefix)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict))?
    {
        let entry = entry
            .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict))?;
        count += 1;
        if count > MAX_PREFIX_ENTRIES {
            return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict))?;
        if !is_lower_hex(&name, 64) || &name[..2] != expected_prefix {
            return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
        }
        reject_reparse_directory(&entry.path(), SecretFileStoreErrorCode::ArtifactConflict)?;
    }
    Ok(())
}

fn validate_object_directory_entries(
    object: &Path,
    allow_missing: bool,
) -> Result<(), SecretFileStoreError> {
    let mut a = false;
    let mut b = false;
    let mut count = 0_usize;
    for entry in fs::read_dir(object)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict))?
    {
        let entry = entry
            .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict))?;
        count += 1;
        if count > 2 {
            return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict))?;
        match name.as_str() {
            SLOT_A_DIRECTORY => a = true,
            SLOT_B_DIRECTORY => b = true,
            _ => return Err(SecretFileStoreErrorCode::ArtifactConflict.into()),
        }
        reject_reparse_directory(&entry.path(), SecretFileStoreErrorCode::ArtifactConflict)?;
    }
    if !allow_missing && (!a || !b) {
        return Err(SecretFileStoreErrorCode::ObjectUnavailable.into());
    }
    Ok(())
}

fn object_contexts(
    locator: &SecretObjectLocator,
    revision: u64,
    epoch: u32,
) -> Result<(SecretEnvelopeContext, SecretEnvelopeContext), SecretFileStoreError> {
    if revision == 0 || epoch == 0 {
        return Err(SecretFileStoreErrorCode::InvalidInput.into());
    }
    let a_generation = revision
        .checked_mul(2)
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(|| SecretFileStoreError::new(SecretFileStoreErrorCode::GenerationOverflow))?;
    let b_generation = revision
        .checked_mul(2)
        .ok_or_else(|| SecretFileStoreError::new(SecretFileStoreErrorCode::GenerationOverflow))?;
    let a = SecretEnvelopeContext::from_digest(
        locator.store_id,
        locator.entity_digest,
        revision,
        SecretEnvelopeSlot::A,
        a_generation,
        epoch,
    )
    .map_err(|_| SecretFileStoreErrorCode::InvalidInput)?;
    let b = SecretEnvelopeContext::from_digest(
        locator.store_id,
        locator.entity_digest,
        revision,
        SecretEnvelopeSlot::B,
        b_generation,
        epoch,
    )
    .map_err(|_| SecretFileStoreErrorCode::InvalidInput)?;
    Ok((a, b))
}

fn blob_final_name(revision: u64, generation: u64) -> String {
    format!(
        "blob-{revision:020}-{generation:020}-{}.ncsb",
        Uuid::new_v4().simple()
    )
}

fn parse_blob_name(name: &str) -> Option<(u64, u64)> {
    let body = name.strip_prefix("blob-")?.strip_suffix(".ncsb")?;
    let mut parts = body.split('-');
    let revision_text = parts.next()?;
    let generation_text = parts.next()?;
    let artifact_id = parts.next()?;
    if parts.next().is_some()
        || revision_text.len() != 20
        || generation_text.len() != 20
        || !is_lower_hex(artifact_id, 32)
    {
        return None;
    }
    let revision = revision_text.parse::<u64>().ok()?;
    let generation = generation_text.parse::<u64>().ok()?;
    (revision > 0 && generation > 0).then_some((revision, generation))
}

fn parse_blob_temp_name(name: &str) -> Option<(u64, u64)> {
    let body = name.strip_prefix(".blob-")?.strip_suffix(".tmp")?;
    let mut parts = body.split('-');
    let revision_text = parts.next()?;
    let generation_text = parts.next()?;
    let artifact_id = parts.next()?;
    if parts.next().is_some()
        || revision_text.len() != 20
        || generation_text.len() != 20
        || !is_lower_hex(artifact_id, 32)
    {
        return None;
    }
    let revision = revision_text.parse::<u64>().ok()?;
    let generation = generation_text.parse::<u64>().ok()?;
    (revision > 0 && generation > 0).then_some((revision, generation))
}

fn expected_blob_generation(slot: FileSlot, revision: u64) -> Option<u64> {
    match slot {
        FileSlot::A => revision.checked_mul(2)?.checked_sub(1),
        FileSlot::B => revision.checked_mul(2),
    }
}

fn find_object_revision(
    directory: &Path,
    slot: FileSlot,
    revision: u64,
    expected_context: &SecretEnvelopeContext,
    master_key: &EnvelopeMasterKey,
    prepared: Option<(&SecretEnvelopeContext, &EncryptedSecretEnvelope)>,
) -> Result<Option<PathBuf>, SecretFileStoreError> {
    let copy = scan_object_copy(
        directory,
        slot,
        revision,
        expected_context,
        master_key,
        prepared,
        true,
    )?;
    Ok(copy.map(|copy| copy.path))
}

fn read_object_copy(
    directory: &Path,
    slot: FileSlot,
    revision: u64,
    expected_context: &SecretEnvelopeContext,
    master_key: &EnvelopeMasterKey,
) -> Result<Option<ValidatedObjectCopy>, SecretFileStoreError> {
    scan_object_copy(
        directory,
        slot,
        revision,
        expected_context,
        master_key,
        None,
        false,
    )
}

fn scan_object_copy(
    directory: &Path,
    slot: FileSlot,
    revision: u64,
    expected_context: &SecretEnvelopeContext,
    master_key: &EnvelopeMasterKey,
    prepared: Option<(&SecretEnvelopeContext, &EncryptedSecretEnvelope)>,
    reject_newer: bool,
) -> Result<Option<ValidatedObjectCopy>, SecretFileStoreError> {
    reject_reparse_directory(directory, SecretFileStoreErrorCode::ObjectUnavailable)?;
    let expected_generation = expected_blob_generation(slot, revision)
        .ok_or_else(|| SecretFileStoreError::new(SecretFileStoreErrorCode::GenerationOverflow))?;
    if expected_context.revision() != revision
        || expected_context.slot() != slot.envelope_slot()
        || expected_context.generation() != expected_generation
    {
        return Err(SecretFileStoreErrorCode::InvalidInput.into());
    }
    let prepared_bundle = if let Some((context, envelope)) = prepared {
        Some(
            decrypt_ssh_secret_bundle(master_key, context, envelope.as_bytes())
                .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::InvalidInput))?,
        )
    } else {
        None
    };
    let mut exact = None;
    let mut temp_reference = None;
    let mut temp_budget = ObjectTempBudget::default();
    let mut entries = 0_usize;
    for entry in fs::read_dir(directory)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::ObjectUnavailable))?
    {
        let entry = entry
            .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::ObjectUnavailable))?;
        entries += 1;
        if entries > MAX_SLOT_ENTRIES {
            return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict))?;
        reject_reparse_regular(&entry.path(), SecretFileStoreErrorCode::ArtifactConflict)?;
        if let Some((candidate_revision, generation)) = parse_blob_name(&name) {
            if expected_blob_generation(slot, candidate_revision) != Some(generation) {
                return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
            }
            if reject_newer && candidate_revision > revision {
                return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
            }
            if candidate_revision == revision {
                if exact.replace(entry.path()).is_some() {
                    return Err(SecretFileStoreErrorCode::ObjectUnavailable.into());
                }
            }
        } else if let Some((candidate_revision, generation)) = parse_blob_temp_name(&name) {
            if candidate_revision != revision || generation != expected_generation {
                return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
            }
            temp_budget.record_entry()?;
            let bytes = read_bounded(&entry.path(), MAX_ENVELOPE_BYTES).map_err(|_| {
                SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict)
            })?;
            temp_budget.record_bytes(bytes.len())?;
            let bundle =
                decrypt_ssh_secret_bundle(master_key, expected_context, &bytes).map_err(|_| {
                    SecretFileStoreError::new(SecretFileStoreErrorCode::ArtifactConflict)
                })?;
            if prepared_bundle
                .as_ref()
                .is_some_and(|prepared| !bundle.contents_match(prepared))
            {
                return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
            }
            if temp_reference
                .as_ref()
                .is_some_and(|first: &SshSecretBundle| !bundle.contents_match(first))
            {
                return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
            }
            if prepared_bundle.is_none() && temp_reference.is_none() {
                temp_reference = Some(bundle);
            } else {
                drop(bundle);
            }
        } else {
            return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
        }
    }
    let Some(path) = exact else {
        return Ok(None);
    };
    let bytes = read_bounded(&path, MAX_ENVELOPE_BYTES)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::ObjectUnavailable))?;
    let bundle = decrypt_ssh_secret_bundle(master_key, expected_context, &bytes)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::ObjectUnavailable))?;
    if temp_reference
        .as_ref()
        .is_some_and(|temporary| !bundle.contents_match(temporary))
    {
        return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
    }
    if prepared_bundle
        .as_ref()
        .is_some_and(|prepared| !bundle.contents_match(prepared))
    {
        return Err(SecretFileStoreErrorCode::ArtifactConflict.into());
    }
    Ok(Some(ValidatedObjectCopy { path, bundle }))
}

fn confirm_object_internal(
    object_root: &Path,
    master_key: &EnvelopeMasterKey,
    locator: &SecretObjectLocator,
    revision: u64,
    epoch: u32,
    prepared: Option<&PreparedSecretObject>,
) -> Result<(), SecretFileStoreError> {
    let (a_context, b_context) = object_contexts(locator, revision, epoch)?;
    let a_directory = object_root.join(SLOT_A_DIRECTORY);
    let b_directory = object_root.join(SLOT_B_DIRECTORY);
    let before_a = read_object_copy(&a_directory, FileSlot::A, revision, &a_context, master_key)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::DurabilityUnconfirmed))?
        .ok_or_else(|| {
            SecretFileStoreError::new(SecretFileStoreErrorCode::DurabilityUnconfirmed)
        })?;
    let before_b = read_object_copy(&b_directory, FileSlot::B, revision, &b_context, master_key)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::DurabilityUnconfirmed))?
        .ok_or_else(|| {
            SecretFileStoreError::new(SecretFileStoreErrorCode::DurabilityUnconfirmed)
        })?;
    if !before_a.bundle.contents_match(&before_b.bundle) {
        return Err(SecretFileStoreErrorCode::DurabilityUnconfirmed.into());
    }
    if let Some(prepared) = prepared {
        let prepared_bundle = decrypt_ssh_secret_bundle(
            master_key,
            &prepared.a_context,
            prepared.a_envelope.as_bytes(),
        )
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::DurabilityUnconfirmed))?;
        if !before_a.bundle.contents_match(&prepared_bundle) {
            return Err(SecretFileStoreErrorCode::DurabilityUnconfirmed.into());
        }
    }
    sync_directory(&a_directory)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::DurabilityUnconfirmed))?;
    sync_directory(&b_directory)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::DurabilityUnconfirmed))?;
    sync_directory(object_root)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::DurabilityUnconfirmed))?;
    let after_a = read_object_copy(&a_directory, FileSlot::A, revision, &a_context, master_key)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::DurabilityUnconfirmed))?
        .ok_or_else(|| {
            SecretFileStoreError::new(SecretFileStoreErrorCode::DurabilityUnconfirmed)
        })?;
    let after_b = read_object_copy(&b_directory, FileSlot::B, revision, &b_context, master_key)
        .map_err(|_| SecretFileStoreError::new(SecretFileStoreErrorCode::DurabilityUnconfirmed))?
        .ok_or_else(|| {
            SecretFileStoreError::new(SecretFileStoreErrorCode::DurabilityUnconfirmed)
        })?;
    if before_a.path != after_a.path
        || before_b.path != after_b.path
        || !before_a.bundle.contents_match(&after_a.bundle)
        || !before_b.bundle.contents_match(&after_b.bundle)
        || !after_a.bundle.contents_match(&after_b.bundle)
    {
        return Err(SecretFileStoreErrorCode::DurabilityUnconfirmed.into());
    }
    Ok(())
}

fn object_pair_matches_prepared(
    object_root: &Path,
    master_key: &EnvelopeMasterKey,
    prepared: &PreparedSecretObject,
) -> bool {
    let a = find_object_revision(
        &object_root.join(SLOT_A_DIRECTORY),
        FileSlot::A,
        prepared.revision,
        &prepared.a_context,
        master_key,
        Some((&prepared.a_context, &prepared.a_envelope)),
    );
    let b = find_object_revision(
        &object_root.join(SLOT_B_DIRECTORY),
        FileSlot::B,
        prepared.revision,
        &prepared.b_context,
        master_key,
        Some((&prepared.b_context, &prepared.b_envelope)),
    );
    matches!(a, Ok(Some(_))) && matches!(b, Ok(Some(_)))
}

fn cleanup_object_temps(
    object_root: &Path,
    master_key: &EnvelopeMasterKey,
    locator: &SecretObjectLocator,
    revision: u64,
    epoch: u32,
) {
    let Ok((a_context, b_context)) = object_contexts(locator, revision, epoch) else {
        return;
    };
    for (slot, context) in [(FileSlot::A, &a_context), (FileSlot::B, &b_context)] {
        let directory = object_root.join(slot.directory());
        let Ok(Some(published)) = read_object_copy(&directory, slot, revision, context, master_key)
        else {
            continue;
        };
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        let expected_generation = context.generation();
        let mut removed = false;
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if parse_blob_temp_name(&name) != Some((revision, expected_generation)) {
                continue;
            }
            let owned = read_bounded(&entry.path(), MAX_ENVELOPE_BYTES)
                .ok()
                .and_then(|bytes| decrypt_ssh_secret_bundle(master_key, context, &bytes).ok())
                .is_some_and(|bundle| bundle.contents_match(&published.bundle));
            if owned && fs::remove_file(entry.path()).is_ok() {
                removed = true;
            }
        }
        if removed {
            let _ = sync_directory(&directory);
        }
    }
}

#[cfg(test)]
#[path = "file_store_fault_tests.rs"]
mod fault_tests;
