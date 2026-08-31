//! Encrypted native custody for connection-log terminal replay data.
//!
//! Every replay is a distinct authenticated object. A second authenticated
//! object is the only index; neither terminal data nor log IDs are written to
//! an ordinary JSON/plaintext file. The OS keyring holds only the 256-bit
//! master key through [`OsMasterKeyStore`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use netcatty_credentials::{CredentialError, OsMasterKeyStore};
use netcatty_secret_store::{
    EnvelopeMasterKey, SecretBlobGarbageCollection, SecretFileMutation, SecretFileStore,
    SecretFileStoreError, SecretFileStoreErrorCode, SecretFileStoreExclusiveGuard,
    SecretFileStoreState, SecretObjectRetention, SshSecretBundle,
};
use netcatty_vault::{
    MAX_CONNECTION_LOG_RECORDS, MAX_CONNECTION_LOG_REPLAY_BYTES,
    MAX_PERSISTED_UNSAVED_CONNECTION_LOG_REPLAYS, SavedConnectionLog, SavedConnectionLogReplay,
    validate_saved_connection_logs,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

const INITIAL_MASTER_KEY_EPOCH: u32 = 1;
const INDEX_ENTITY_ID: &str = "netcatty-connection-log-replay-index-v1";
const LOG_ID_DIGEST_DOMAIN: &[u8] = b"netcatty-connection-log-replay-id-v1\0";
const REPLAY_ENTITY_PREFIX: &str = "netcatty-connection-log-replay-v1:";
const INDEX_MAGIC: &[u8; 8] = b"NCATIDX1";
const INDEX_FORMAT_VERSION: u16 = 1;
const INDEX_HEADER_BYTES: usize = 16;
const INDEX_ENTRY_BYTES: usize = 56;
const REPLAY_MAGIC: &[u8; 8] = b"NCATRPL1";
const REPLAY_FORMAT_VERSION: u16 = 1;
const REPLAY_HEADER_BYTES: usize = 48;
const MAX_SLOT_ENTRIES: usize = 256;
const WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// Fixed, renderer-safe replay-store failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectionLogReplayStoreErrorCode {
    InvalidInput,
    CredentialUnavailable,
    StorageUnavailable,
    CorruptStore,
    ReplayUnavailable,
    DurabilityUnconfirmed,
    GarbageCollectionFailed,
    RevisionOverflow,
}

impl ConnectionLogReplayStoreErrorCode {
    const fn message(self) -> &'static str {
        match self {
            Self::InvalidInput => "connection-log replay input is invalid",
            Self::CredentialUnavailable => "connection-log replay key is unavailable",
            Self::StorageUnavailable => "connection-log replay storage is unavailable",
            Self::CorruptStore => "connection-log replay storage is invalid",
            Self::ReplayUnavailable => "connection-log replay is unavailable or corrupt",
            Self::DurabilityUnconfirmed => {
                "connection-log replay durability could not be confirmed"
            }
            Self::GarbageCollectionFailed => {
                "connection-log replay cleanup could not be completed safely"
            }
            Self::RevisionOverflow => "connection-log replay revision limit is exhausted",
        }
    }
}

/// An error that retains no path, log ID, terminal contents, or backend text.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ConnectionLogReplayStoreError {
    code: ConnectionLogReplayStoreErrorCode,
}

impl ConnectionLogReplayStoreError {
    #[must_use]
    pub const fn new(code: ConnectionLogReplayStoreErrorCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(&self) -> ConnectionLogReplayStoreErrorCode {
        self.code
    }
}

impl From<ConnectionLogReplayStoreErrorCode> for ConnectionLogReplayStoreError {
    fn from(code: ConnectionLogReplayStoreErrorCode) -> Self {
        Self::new(code)
    }
}

impl fmt::Display for ConnectionLogReplayStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.message())
    }
}

impl fmt::Debug for ConnectionLogReplayStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionLogReplayStoreError")
            .field("code", &self.code)
            .finish()
    }
}

impl std::error::Error for ConnectionLogReplayStoreError {}

/// Counts from one authenticated cleanup. Filesystem deletion is ordinary
/// deletion, not guaranteed physical erasure on SSD/copy-on-write storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionLogReplayGarbageCollection {
    removed_blob_revisions: usize,
    removed_objects: usize,
}

impl ConnectionLogReplayGarbageCollection {
    #[must_use]
    pub const fn removed_blob_revisions(&self) -> usize {
        self.removed_blob_revisions
    }

    #[must_use]
    pub const fn removed_objects(&self) -> usize {
        self.removed_objects
    }
}

/// Synchronous native replay custody. Desktop callers should invoke its
/// methods on a blocking worker, just like the existing secret coordinator.
pub struct ConnectionLogReplayStore {
    root: PathBuf,
    files: SecretFileStore,
    master_keys: OsMasterKeyStore,
}

impl fmt::Debug for ConnectionLogReplayStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectionLogReplayStore([REDACTED])")
    }
}

impl ConnectionLogReplayStore {
    /// Opens a dedicated replay root and uses the platform keyring for its
    /// master key. No replay bytes pass through the keyring.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ConnectionLogReplayStoreError> {
        Self::open_with_master_key_store(root, OsMasterKeyStore::new())
    }

    /// Dependency-injected variant used by deterministic tests and native
    /// coordinators that already own an [`OsMasterKeyStore`].
    pub fn open_with_master_key_store(
        root: impl AsRef<Path>,
        master_keys: OsMasterKeyStore,
    ) -> Result<Self, ConnectionLogReplayStoreError> {
        let files = SecretFileStore::open(root.as_ref()).map_err(map_file_error)?;
        let root = fs::canonicalize(root.as_ref()).map_err(|_| {
            ConnectionLogReplayStoreError::new(
                ConnectionLogReplayStoreErrorCode::StorageUnavailable,
            )
        })?;
        let store = Self {
            root,
            files,
            master_keys,
        };
        let guard = store.files.lock_exclusive().map_err(map_file_error)?;
        store.ensure_initialized(&guard)?;
        drop(guard);
        Ok(store)
    }

    /// Replaces one replay. The replay ID must exactly match the metadata ID.
    /// The newest complete one-million-byte UTF-8 suffix is persisted.
    pub fn replace(
        &self,
        log: &SavedConnectionLog,
        replay: SavedConnectionLogReplay,
    ) -> Result<(), ConnectionLogReplayStoreError> {
        validate_log(log)?;
        if replay.log_id() != log.id {
            return Err(ConnectionLogReplayStoreErrorCode::InvalidInput.into());
        }
        let replay = SavedConnectionLogReplay::new(&log.id, replay.into_terminal_data())
            .map_err(|_| ConnectionLogReplayStoreErrorCode::InvalidInput)?;
        self.replace_terminal_data(log, replay.terminal_data())
    }

    /// Appends terminal output to one replay without exposing a replay catalog.
    /// Empty chunks still refresh bookmark/time retention metadata.
    pub fn append(
        &self,
        log: &SavedConnectionLog,
        chunk: &str,
    ) -> Result<(), ConnectionLogReplayStoreError> {
        validate_log(log)?;
        let guard = self.files.lock_exclusive().map_err(map_file_error)?;
        let (state, master_key) = self.load_state_and_key(&guard)?;
        let mut index = self.load_index(&guard, &master_key)?;
        let original_entries = index.entries.clone();
        let digest = digest_log_id(&log.id)?;
        let prior_revision = index.entries.get(&digest).map(|entry| entry.revision);
        index.entries.insert(
            digest,
            ReplayIndexEntry {
                revision: prior_revision.unwrap_or(1),
                start_time: log.start_time,
                saved: log.saved,
            },
        );
        apply_replay_retention(&mut index.entries);

        if !index.entries.contains_key(&digest) {
            self.publish_index_if_changed(
                &guard,
                &state,
                &master_key,
                &mut index,
                &original_entries,
            )?;
            self.collect_locked(&guard, &state, &master_key, &index)?;
            return Ok(());
        }

        let mut replay = match prior_revision {
            Some(revision) => {
                self.resolve_replay(&guard, &master_key, &log.id, digest, revision)?
            }
            None => SavedConnectionLogReplay::new(&log.id, String::new())
                .map_err(|_| ConnectionLogReplayStoreErrorCode::InvalidInput)?,
        };
        replay.append(chunk);
        let revision = self.next_entity_revision(&guard, &replay_entity_id(digest))?;
        self.publish_replay(
            &guard,
            &state,
            &master_key,
            digest,
            revision,
            replay.terminal_data(),
        )?;
        index.entries.insert(
            digest,
            ReplayIndexEntry {
                revision,
                start_time: log.start_time,
                saved: log.saved,
            },
        );
        self.publish_index(&guard, &state, &master_key, &mut index)?;
        self.collect_locked(&guard, &state, &master_key, &index)?;
        Ok(())
    }

    /// Reads only one requested replay. Missing index entries return `None`;
    /// corrupt or ambiguous ciphertext fails closed and never falls back to an
    /// older replay revision.
    pub fn read(
        &self,
        log_id: &str,
    ) -> Result<Option<SavedConnectionLogReplay>, ConnectionLogReplayStoreError> {
        validate_log_id(log_id)?;
        let guard = self.files.lock_exclusive().map_err(map_file_error)?;
        let (_, master_key) = self.load_state_and_key(&guard)?;
        let index = self.load_index(&guard, &master_key)?;
        let digest = digest_log_id(log_id)?;
        let Some(entry) = index.entries.get(&digest) else {
            return Ok(None);
        };
        self.resolve_replay(&guard, &master_key, log_id, digest, entry.revision)
            .map(Some)
    }

    /// Removes one replay from the encrypted index and then performs an exact
    /// authenticated cleanup. A cleanup fault is returned, never ignored.
    pub fn delete(&self, log_id: &str) -> Result<(), ConnectionLogReplayStoreError> {
        validate_log_id(log_id)?;
        let guard = self.files.lock_exclusive().map_err(map_file_error)?;
        let (state, master_key) = self.load_state_and_key(&guard)?;
        let mut index = self.load_index(&guard, &master_key)?;
        let original_entries = index.entries.clone();
        index.entries.remove(&digest_log_id(log_id)?);
        self.publish_index_if_changed(&guard, &state, &master_key, &mut index, &original_entries)?;
        self.collect_locked(&guard, &state, &master_key, &index)?;
        Ok(())
    }

    /// Reconciles replay custody with the complete Vault log catalog. Replays
    /// for deleted records disappear, bookmark changes are honored, and only
    /// the newest 50 unsaved replay entries remain alongside all saved ones.
    pub fn reconcile(
        &self,
        logs: &[SavedConnectionLog],
    ) -> Result<(), ConnectionLogReplayStoreError> {
        validate_saved_connection_logs(logs)
            .map_err(|_| ConnectionLogReplayStoreErrorCode::InvalidInput)?;
        let mut catalog = BTreeMap::new();
        for log in logs {
            let digest = digest_log_id(&log.id)?;
            if catalog
                .insert(digest, (log.saved, log.start_time))
                .is_some()
            {
                return Err(ConnectionLogReplayStoreErrorCode::InvalidInput.into());
            }
        }

        let guard = self.files.lock_exclusive().map_err(map_file_error)?;
        let (state, master_key) = self.load_state_and_key(&guard)?;
        let mut index = self.load_index(&guard, &master_key)?;
        let original_entries = index.entries.clone();
        index.entries.retain(|digest, entry| {
            let Some((saved, start_time)) = catalog.get(digest) else {
                return false;
            };
            entry.saved = *saved;
            entry.start_time = *start_time;
            true
        });
        apply_replay_retention(&mut index.entries);
        self.publish_index_if_changed(&guard, &state, &master_key, &mut index, &original_entries)?;
        self.collect_locked(&guard, &state, &master_key, &index)?;
        Ok(())
    }

    /// Retries exact cleanup after a prior mutation reported
    /// [`ConnectionLogReplayStoreErrorCode::GarbageCollectionFailed`].
    pub fn garbage_collect(
        &self,
    ) -> Result<ConnectionLogReplayGarbageCollection, ConnectionLogReplayStoreError> {
        self.garbage_collect_inner().map_err(|_| {
            ConnectionLogReplayStoreError::new(
                ConnectionLogReplayStoreErrorCode::GarbageCollectionFailed,
            )
        })
    }

    fn garbage_collect_inner(
        &self,
    ) -> Result<ConnectionLogReplayGarbageCollection, ConnectionLogReplayStoreError> {
        let guard = self.files.lock_exclusive().map_err(map_file_error)?;
        let (state, master_key) = self.load_state_and_key(&guard)?;
        let index = self.load_index(&guard, &master_key)?;
        self.collect_locked(&guard, &state, &master_key, &index)
    }

    fn replace_terminal_data(
        &self,
        log: &SavedConnectionLog,
        terminal_data: &str,
    ) -> Result<(), ConnectionLogReplayStoreError> {
        let guard = self.files.lock_exclusive().map_err(map_file_error)?;
        let (state, master_key) = self.load_state_and_key(&guard)?;
        let mut index = self.load_index(&guard, &master_key)?;
        let original_entries = index.entries.clone();
        let digest = digest_log_id(&log.id)?;
        let prior_revision = index.entries.get(&digest).map(|entry| entry.revision);
        index.entries.insert(
            digest,
            ReplayIndexEntry {
                revision: prior_revision.unwrap_or(1),
                start_time: log.start_time,
                saved: log.saved,
            },
        );
        apply_replay_retention(&mut index.entries);
        if !index.entries.contains_key(&digest) {
            self.publish_index_if_changed(
                &guard,
                &state,
                &master_key,
                &mut index,
                &original_entries,
            )?;
            self.collect_locked(&guard, &state, &master_key, &index)?;
            return Ok(());
        }

        let revision = self.next_entity_revision(&guard, &replay_entity_id(digest))?;
        self.publish_replay(&guard, &state, &master_key, digest, revision, terminal_data)?;
        index.entries.insert(
            digest,
            ReplayIndexEntry {
                revision,
                start_time: log.start_time,
                saved: log.saved,
            },
        );
        self.publish_index(&guard, &state, &master_key, &mut index)?;
        self.collect_locked(&guard, &state, &master_key, &index)?;
        Ok(())
    }

    fn ensure_initialized(
        &self,
        guard: &SecretFileStoreExclusiveGuard<'_>,
    ) -> Result<(), ConnectionLogReplayStoreError> {
        match guard.owner_id().map_err(map_file_error)? {
            None => self.initialize_owner(guard, Uuid::new_v4()),
            Some(owner) => match guard.load_state() {
                Ok(state) => {
                    self.master_keys
                        .load_blocking(owner, state.active_master_key_epoch())
                        .map_err(map_credential_error)?;
                    Ok(())
                }
                Err(error) if error.code() == SecretFileStoreErrorCode::NotInitialized => {
                    self.initialize_owner(guard, owner)
                }
                Err(error) => Err(map_file_error(error)),
            },
        }
    }

    fn initialize_owner(
        &self,
        guard: &SecretFileStoreExclusiveGuard<'_>,
        owner: Uuid,
    ) -> Result<(), ConnectionLogReplayStoreError> {
        let _key = self
            .master_keys
            .create_if_absent_blocking(owner, INITIAL_MASTER_KEY_EPOCH)
            .map_err(map_credential_error)?;
        let mutation = guard
            .initialize(owner, INITIAL_MASTER_KEY_EPOCH)
            .map_err(map_file_error)?;
        let state = match mutation {
            SecretFileMutation::Durable(state) => state,
            SecretFileMutation::PublishedDurabilityUncertain
            | SecretFileMutation::PublicationIndeterminate => guard.load_state().map_err(|_| {
                ConnectionLogReplayStoreError::new(
                    ConnectionLogReplayStoreErrorCode::DurabilityUnconfirmed,
                )
            })?,
        };
        if state.store_id() != owner || state.active_master_key_epoch() != INITIAL_MASTER_KEY_EPOCH
        {
            return Err(ConnectionLogReplayStoreErrorCode::CorruptStore.into());
        }
        guard
            .confirm_keyset_durability(&state)
            .map_err(|_| ConnectionLogReplayStoreErrorCode::DurabilityUnconfirmed)?;
        Ok(())
    }

    fn load_state_and_key(
        &self,
        guard: &SecretFileStoreExclusiveGuard<'_>,
    ) -> Result<(SecretFileStoreState, EnvelopeMasterKey), ConnectionLogReplayStoreError> {
        let state = guard.load_state().map_err(map_file_error)?;
        let master_key = self
            .master_keys
            .load_blocking(state.store_id(), state.active_master_key_epoch())
            .map_err(map_credential_error)?;
        Ok((state, master_key))
    }

    fn load_index(
        &self,
        guard: &SecretFileStoreExclusiveGuard<'_>,
        master_key: &EnvelopeMasterKey,
    ) -> Result<LoadedReplayIndex, ConnectionLogReplayStoreError> {
        let revision = self.discover_latest_revision(guard, INDEX_ENTITY_ID)?;
        let Some(revision) = revision else {
            return Ok(LoadedReplayIndex::default());
        };
        let locator = guard
            .derive_object_locator(INDEX_ENTITY_ID)
            .map_err(map_file_error)?;
        let bundle = guard
            .resolve_object(master_key, &locator, revision)
            .map_err(map_file_error)?;
        let entries = decode_index_bundle(&bundle)?;
        Ok(LoadedReplayIndex {
            revision: Some(revision),
            entries,
        })
    }

    fn publish_index_if_changed(
        &self,
        guard: &SecretFileStoreExclusiveGuard<'_>,
        state: &SecretFileStoreState,
        master_key: &EnvelopeMasterKey,
        index: &mut LoadedReplayIndex,
        original_entries: &BTreeMap<[u8; 32], ReplayIndexEntry>,
    ) -> Result<(), ConnectionLogReplayStoreError> {
        if &index.entries == original_entries {
            return Ok(());
        }
        self.publish_index(guard, state, master_key, index)
    }

    fn publish_index(
        &self,
        guard: &SecretFileStoreExclusiveGuard<'_>,
        state: &SecretFileStoreState,
        master_key: &EnvelopeMasterKey,
        index: &mut LoadedReplayIndex,
    ) -> Result<(), ConnectionLogReplayStoreError> {
        let revision = self.next_entity_revision(guard, INDEX_ENTITY_ID)?;
        let bundle = encode_index_bundle(&index.entries)?;
        self.publish_bundle(guard, state, master_key, INDEX_ENTITY_ID, revision, bundle)?;
        index.revision = Some(revision);
        Ok(())
    }

    fn publish_replay(
        &self,
        guard: &SecretFileStoreExclusiveGuard<'_>,
        state: &SecretFileStoreState,
        master_key: &EnvelopeMasterKey,
        digest: [u8; 32],
        revision: u64,
        terminal_data: &str,
    ) -> Result<(), ConnectionLogReplayStoreError> {
        let bundle = encode_replay_bundle(digest, terminal_data)?;
        self.publish_bundle(
            guard,
            state,
            master_key,
            &replay_entity_id(digest),
            revision,
            bundle,
        )
    }

    fn publish_bundle(
        &self,
        guard: &SecretFileStoreExclusiveGuard<'_>,
        state: &SecretFileStoreState,
        master_key: &EnvelopeMasterKey,
        entity_id: &str,
        revision: u64,
        bundle: SshSecretBundle,
    ) -> Result<(), ConnectionLogReplayStoreError> {
        let locator = guard
            .derive_object_locator(entity_id)
            .map_err(map_file_error)?;
        let prepared = guard
            .prepare_object(state, master_key, &locator, revision, bundle)
            .map_err(map_file_error)?;
        let _publication = guard
            .publish_object(master_key, &prepared)
            .map_err(map_file_error)?;
        guard
            .confirm_object_durability(master_key, &locator, revision)
            .map_err(|_| ConnectionLogReplayStoreErrorCode::DurabilityUnconfirmed)?;
        Ok(())
    }

    fn resolve_replay(
        &self,
        guard: &SecretFileStoreExclusiveGuard<'_>,
        master_key: &EnvelopeMasterKey,
        log_id: &str,
        digest: [u8; 32],
        revision: u64,
    ) -> Result<SavedConnectionLogReplay, ConnectionLogReplayStoreError> {
        let locator = guard
            .derive_object_locator(&replay_entity_id(digest))
            .map_err(map_file_error)?;
        let bundle = guard
            .resolve_object(master_key, &locator, revision)
            .map_err(map_file_error)?;
        let terminal_data = decode_replay_bundle(&bundle, digest)?;
        SavedConnectionLogReplay::new(log_id, terminal_data)
            .map_err(|_| ConnectionLogReplayStoreErrorCode::CorruptStore.into())
    }

    fn next_entity_revision(
        &self,
        guard: &SecretFileStoreExclusiveGuard<'_>,
        entity_id: &str,
    ) -> Result<u64, ConnectionLogReplayStoreError> {
        self.discover_latest_revision(guard, entity_id)?
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| ConnectionLogReplayStoreErrorCode::RevisionOverflow.into())
    }

    fn discover_latest_revision(
        &self,
        guard: &SecretFileStoreExclusiveGuard<'_>,
        entity_id: &str,
    ) -> Result<Option<u64>, ConnectionLogReplayStoreError> {
        let locator = guard
            .derive_object_locator(entity_id)
            .map_err(map_file_error)?;
        let encoded = locator.backend_locator_hex();
        let object = self.root.join("objects").join(&encoded[..2]).join(encoded);
        if !safe_directory_exists(&object)? {
            return Ok(None);
        }
        let a = scan_slot_revisions(&object.join("slot-a"), FileSlot::A)?;
        let b = scan_slot_revisions(&object.join("slot-b"), FileSlot::B)?;
        Ok(a.into_iter().chain(b).max())
    }

    fn collect_locked(
        &self,
        guard: &SecretFileStoreExclusiveGuard<'_>,
        state: &SecretFileStoreState,
        master_key: &EnvelopeMasterKey,
        index: &LoadedReplayIndex,
    ) -> Result<ConnectionLogReplayGarbageCollection, ConnectionLogReplayStoreError> {
        let mut retained = Vec::with_capacity(index.entries.len() + 1);
        if let Some(revision) = index.revision {
            retained.push(retention_for(guard, INDEX_ENTITY_ID, revision)?);
        } else if !index.entries.is_empty() {
            return Err(ConnectionLogReplayStoreErrorCode::CorruptStore.into());
        }
        for (digest, entry) in &index.entries {
            retained.push(retention_for(
                guard,
                &replay_entity_id(*digest),
                entry.revision,
            )?);
        }
        let result = guard
            .garbage_collect_objects(state, master_key, &retained)
            .map_err(|_| ConnectionLogReplayStoreErrorCode::GarbageCollectionFailed)?;
        Ok(map_gc(result))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FileSlot {
    A,
    B,
}

impl FileSlot {
    fn expected_generation(self, revision: u64) -> Option<u64> {
        match self {
            Self::A => revision.checked_mul(2)?.checked_sub(1),
            Self::B => revision.checked_mul(2),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ReplayIndexEntry {
    revision: u64,
    start_time: u64,
    saved: bool,
}

impl fmt::Debug for ReplayIndexEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayIndexEntry")
            .field("revision", &self.revision)
            .field("start_time", &self.start_time)
            .field("saved", &self.saved)
            .finish()
    }
}

#[derive(Default)]
struct LoadedReplayIndex {
    revision: Option<u64>,
    entries: BTreeMap<[u8; 32], ReplayIndexEntry>,
}

impl fmt::Debug for LoadedReplayIndex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedReplayIndex")
            .field("has_revision", &self.revision.is_some())
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

fn validate_log(log: &SavedConnectionLog) -> Result<(), ConnectionLogReplayStoreError> {
    log.validate()
        .map_err(|_| ConnectionLogReplayStoreErrorCode::InvalidInput.into())
}

fn validate_log_id(log_id: &str) -> Result<(), ConnectionLogReplayStoreError> {
    SavedConnectionLogReplay::new(log_id, String::new())
        .map(|_| ())
        .map_err(|_| ConnectionLogReplayStoreErrorCode::InvalidInput.into())
}

fn digest_log_id(log_id: &str) -> Result<[u8; 32], ConnectionLogReplayStoreError> {
    validate_log_id(log_id)?;
    let length =
        u32::try_from(log_id.len()).map_err(|_| ConnectionLogReplayStoreErrorCode::InvalidInput)?;
    let mut digest = Sha256::new();
    digest.update(LOG_ID_DIGEST_DOMAIN);
    digest.update(length.to_be_bytes());
    digest.update(log_id.as_bytes());
    Ok(digest.finalize().into())
}

fn replay_entity_id(digest: [u8; 32]) -> String {
    format!("{REPLAY_ENTITY_PREFIX}{}", hex_encode(&digest))
}

fn encode_replay_bundle(
    digest: [u8; 32],
    terminal_data: &str,
) -> Result<SshSecretBundle, ConnectionLogReplayStoreError> {
    let replay = SavedConnectionLogReplay::new("validated-placeholder", terminal_data)
        .map_err(|_| ConnectionLogReplayStoreErrorCode::InvalidInput)?;
    let terminal_data = replay.terminal_data().as_bytes();
    let length = u32::try_from(terminal_data.len())
        .map_err(|_| ConnectionLogReplayStoreErrorCode::InvalidInput)?;
    let mut encoded = Vec::with_capacity(REPLAY_HEADER_BYTES + terminal_data.len());
    encoded.extend_from_slice(REPLAY_MAGIC);
    encoded.extend_from_slice(&REPLAY_FORMAT_VERSION.to_be_bytes());
    encoded.extend_from_slice(&(REPLAY_HEADER_BYTES as u16).to_be_bytes());
    encoded.extend_from_slice(&digest);
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(terminal_data);
    SshSecretBundle::new(encoded, None, None, None)
        .map_err(|_| ConnectionLogReplayStoreErrorCode::InvalidInput.into())
}

fn decode_replay_bundle(
    bundle: &SshSecretBundle,
    expected_digest: [u8; 32],
) -> Result<String, ConnectionLogReplayStoreError> {
    if bundle.public_key().is_some()
        || bundle.certificate().is_some()
        || bundle.passphrase().is_some()
    {
        return Err(ConnectionLogReplayStoreErrorCode::CorruptStore.into());
    }
    let bytes = bundle.private_key();
    if bytes.len() < REPLAY_HEADER_BYTES
        || bytes.get(..8) != Some(REPLAY_MAGIC.as_slice())
        || read_u16(bytes, 8) != Some(REPLAY_FORMAT_VERSION)
        || read_u16(bytes, 10) != Some(REPLAY_HEADER_BYTES as u16)
        || !bool::from(bytes[12..44].ct_eq(&expected_digest))
    {
        return Err(ConnectionLogReplayStoreErrorCode::CorruptStore.into());
    }
    let length = read_u32(bytes, 44)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| {
            ConnectionLogReplayStoreError::new(ConnectionLogReplayStoreErrorCode::CorruptStore)
        })?;
    if length > MAX_CONNECTION_LOG_REPLAY_BYTES
        || REPLAY_HEADER_BYTES.checked_add(length) != Some(bytes.len())
    {
        return Err(ConnectionLogReplayStoreErrorCode::CorruptStore.into());
    }
    std::str::from_utf8(&bytes[REPLAY_HEADER_BYTES..])
        .map(str::to_owned)
        .map_err(|_| ConnectionLogReplayStoreErrorCode::CorruptStore.into())
}

fn encode_index_bundle(
    entries: &BTreeMap<[u8; 32], ReplayIndexEntry>,
) -> Result<SshSecretBundle, ConnectionLogReplayStoreError> {
    if entries.len() > MAX_CONNECTION_LOG_RECORDS {
        return Err(ConnectionLogReplayStoreErrorCode::InvalidInput.into());
    }
    let count = u32::try_from(entries.len())
        .map_err(|_| ConnectionLogReplayStoreErrorCode::InvalidInput)?;
    let capacity = INDEX_HEADER_BYTES
        .checked_add(
            entries
                .len()
                .checked_mul(INDEX_ENTRY_BYTES)
                .ok_or(ConnectionLogReplayStoreErrorCode::InvalidInput)?,
        )
        .ok_or(ConnectionLogReplayStoreErrorCode::InvalidInput)?;
    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(INDEX_MAGIC);
    encoded.extend_from_slice(&INDEX_FORMAT_VERSION.to_be_bytes());
    encoded.extend_from_slice(&(INDEX_HEADER_BYTES as u16).to_be_bytes());
    encoded.extend_from_slice(&count.to_be_bytes());
    for (digest, entry) in entries {
        if entry.revision == 0 || entry.start_time == 0 {
            return Err(ConnectionLogReplayStoreErrorCode::InvalidInput.into());
        }
        encoded.extend_from_slice(digest);
        encoded.extend_from_slice(&entry.revision.to_be_bytes());
        encoded.extend_from_slice(&entry.start_time.to_be_bytes());
        encoded.push(u8::from(entry.saved));
        encoded.extend_from_slice(&[0; 7]);
    }
    debug_assert_eq!(encoded.len(), capacity);
    SshSecretBundle::new(encoded, None, None, None)
        .map_err(|_| ConnectionLogReplayStoreErrorCode::InvalidInput.into())
}

fn decode_index_bundle(
    bundle: &SshSecretBundle,
) -> Result<BTreeMap<[u8; 32], ReplayIndexEntry>, ConnectionLogReplayStoreError> {
    if bundle.public_key().is_some()
        || bundle.certificate().is_some()
        || bundle.passphrase().is_some()
    {
        return Err(ConnectionLogReplayStoreErrorCode::CorruptStore.into());
    }
    let bytes = bundle.private_key();
    if bytes.len() < INDEX_HEADER_BYTES
        || bytes.get(..8) != Some(INDEX_MAGIC.as_slice())
        || read_u16(bytes, 8) != Some(INDEX_FORMAT_VERSION)
        || read_u16(bytes, 10) != Some(INDEX_HEADER_BYTES as u16)
    {
        return Err(ConnectionLogReplayStoreErrorCode::CorruptStore.into());
    }
    let count = read_u32(bytes, 12)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| {
            ConnectionLogReplayStoreError::new(ConnectionLogReplayStoreErrorCode::CorruptStore)
        })?;
    if count > MAX_CONNECTION_LOG_RECORDS
        || INDEX_HEADER_BYTES.checked_add(
            count
                .checked_mul(INDEX_ENTRY_BYTES)
                .ok_or(ConnectionLogReplayStoreErrorCode::CorruptStore)?,
        ) != Some(bytes.len())
    {
        return Err(ConnectionLogReplayStoreErrorCode::CorruptStore.into());
    }

    let mut entries = BTreeMap::new();
    let mut cursor = INDEX_HEADER_BYTES;
    for _ in 0..count {
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&bytes[cursor..cursor + 32]);
        let revision = read_u64(bytes, cursor + 32).ok_or_else(|| {
            ConnectionLogReplayStoreError::new(ConnectionLogReplayStoreErrorCode::CorruptStore)
        })?;
        let start_time = read_u64(bytes, cursor + 40).ok_or_else(|| {
            ConnectionLogReplayStoreError::new(ConnectionLogReplayStoreErrorCode::CorruptStore)
        })?;
        let saved = match bytes[cursor + 48] {
            0 => false,
            1 => true,
            _ => return Err(ConnectionLogReplayStoreErrorCode::CorruptStore.into()),
        };
        if revision == 0
            || start_time == 0
            || bytes[cursor + 49..cursor + INDEX_ENTRY_BYTES]
                .iter()
                .any(|byte| *byte != 0)
            || entries
                .insert(
                    digest,
                    ReplayIndexEntry {
                        revision,
                        start_time,
                        saved,
                    },
                )
                .is_some()
        {
            return Err(ConnectionLogReplayStoreErrorCode::CorruptStore.into());
        }
        cursor += INDEX_ENTRY_BYTES;
    }
    Ok(entries)
}

fn apply_replay_retention(entries: &mut BTreeMap<[u8; 32], ReplayIndexEntry>) {
    let mut unsaved = entries
        .iter()
        .filter(|(_, entry)| !entry.saved)
        .map(|(digest, entry)| (*digest, entry.start_time))
        .collect::<Vec<_>>();
    unsaved.sort_by(|(left_digest, left_time), (right_digest, right_time)| {
        right_time
            .cmp(left_time)
            .then_with(|| left_digest.cmp(right_digest))
    });
    let retained_unsaved = unsaved
        .into_iter()
        .take(MAX_PERSISTED_UNSAVED_CONNECTION_LOG_REPLAYS)
        .map(|(digest, _)| digest)
        .collect::<BTreeSet<_>>();
    entries.retain(|digest, entry| entry.saved || retained_unsaved.contains(digest));
}

fn retention_for(
    guard: &SecretFileStoreExclusiveGuard<'_>,
    entity_id: &str,
    revision: u64,
) -> Result<SecretObjectRetention, ConnectionLogReplayStoreError> {
    let locator = guard
        .derive_object_locator(entity_id)
        .map_err(map_file_error)?;
    SecretObjectRetention::new(entity_id, locator.backend_locator_hex(), revision)
        .map_err(map_file_error)
}

fn map_gc(result: SecretBlobGarbageCollection) -> ConnectionLogReplayGarbageCollection {
    ConnectionLogReplayGarbageCollection {
        removed_blob_revisions: result.removed_blob_revisions(),
        removed_objects: result.removed_objects(),
    }
}

fn map_credential_error(_: CredentialError) -> ConnectionLogReplayStoreError {
    ConnectionLogReplayStoreErrorCode::CredentialUnavailable.into()
}

fn map_file_error(error: SecretFileStoreError) -> ConnectionLogReplayStoreError {
    use ConnectionLogReplayStoreErrorCode as Replay;
    use SecretFileStoreErrorCode as Secret;
    let code = match error.code() {
        Secret::InvalidRoot | Secret::InvalidInput => Replay::InvalidInput,
        Secret::LockUnavailable | Secret::LockPoisoned | Secret::StorageUnavailable => {
            Replay::StorageUnavailable
        }
        Secret::ObjectUnavailable => Replay::ReplayUnavailable,
        Secret::DurabilityUnconfirmed => Replay::DurabilityUnconfirmed,
        Secret::GarbageCollectionUncertain => Replay::GarbageCollectionFailed,
        Secret::GenerationOverflow => Replay::RevisionOverflow,
        _ => Replay::CorruptStore,
    };
    code.into()
}

fn scan_slot_revisions(
    directory: &Path,
    slot: FileSlot,
) -> Result<Vec<u64>, ConnectionLogReplayStoreError> {
    if !safe_directory_exists(directory)? {
        return Err(ConnectionLogReplayStoreErrorCode::CorruptStore.into());
    }
    let mut revisions = BTreeSet::new();
    let mut count = 0_usize;
    for entry in fs::read_dir(directory)
        .map_err(|_| ConnectionLogReplayStoreErrorCode::StorageUnavailable)?
    {
        let entry = entry.map_err(|_| ConnectionLogReplayStoreErrorCode::StorageUnavailable)?;
        count += 1;
        if count > MAX_SLOT_ENTRIES || !safe_regular_file(&entry.path())? {
            return Err(ConnectionLogReplayStoreErrorCode::CorruptStore.into());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ConnectionLogReplayStoreErrorCode::CorruptStore)?;
        if let Some((revision, generation)) = parse_blob_name(&name, false) {
            if slot.expected_generation(revision) != Some(generation) || !revisions.insert(revision)
            {
                return Err(ConnectionLogReplayStoreErrorCode::CorruptStore.into());
            }
        } else if let Some((revision, generation)) = parse_blob_name(&name, true) {
            if slot.expected_generation(revision) != Some(generation) {
                return Err(ConnectionLogReplayStoreErrorCode::CorruptStore.into());
            }
        } else {
            return Err(ConnectionLogReplayStoreErrorCode::CorruptStore.into());
        }
    }
    Ok(revisions.into_iter().collect())
}

fn parse_blob_name(name: &str, temporary: bool) -> Option<(u64, u64)> {
    let body = if temporary {
        name.strip_prefix(".blob-")?.strip_suffix(".tmp")?
    } else {
        name.strip_prefix("blob-")?.strip_suffix(".ncsb")?
    };
    let mut parts = body.split('-');
    let revision_text = parts.next()?;
    let generation_text = parts.next()?;
    let artifact_id = parts.next()?;
    if parts.next().is_some()
        || revision_text.len() != 20
        || generation_text.len() != 20
        || artifact_id.len() != 32
        || !artifact_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let revision = revision_text.parse::<u64>().ok()?;
    let generation = generation_text.parse::<u64>().ok()?;
    (revision > 0 && generation > 0).then_some((revision, generation))
}

fn safe_directory_exists(path: &Path) -> Result<bool, ConnectionLogReplayStoreError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(ConnectionLogReplayStoreErrorCode::StorageUnavailable.into()),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse(&metadata) {
        return Err(ConnectionLogReplayStoreErrorCode::CorruptStore.into());
    }
    Ok(true)
}

fn safe_regular_file(path: &Path) -> Result<bool, ConnectionLogReplayStoreError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ConnectionLogReplayStoreErrorCode::StorageUnavailable)?;
    Ok(metadata.is_file() && !metadata.file_type().is_symlink() && !is_reparse(&metadata))
}

#[cfg(windows)]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse(_: &fs::Metadata) -> bool {
    let _ = WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT;
    false
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let raw = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let raw = bytes.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_be_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use netcatty_credentials::CredentialErrorCode;
    use netcatty_credentials::test_support::{
        CredentialOperation, FailureTiming, in_memory_master_key_store,
    };
    use netcatty_vault::{
        MAX_CONNECTION_LOG_REPLAY_BYTES, MAX_PERSISTED_UNSAVED_CONNECTION_LOG_REPLAYS,
        SavedConnectionLog, SavedConnectionLogHostOs, SavedConnectionLogProtocol,
        SavedConnectionLogReplay,
    };

    use super::{
        ConnectionLogReplayStore, ConnectionLogReplayStoreErrorCode, ReplayIndexEntry,
        apply_replay_retention, digest_log_id, replay_entity_id,
    };

    fn log(id: &str, start_time: u64, saved: bool) -> SavedConnectionLog {
        SavedConnectionLog {
            id: id.to_owned(),
            session_id: Some(format!("session-{id}")),
            host_id: "host-1".to_owned(),
            host_label: "Production".to_owned(),
            hostname: "server.example.test".to_owned(),
            username: "operator".to_owned(),
            protocol: SavedConnectionLogProtocol::Ssh,
            host_os: Some(SavedConnectionLogHostOs::Linux),
            host_distro: Some("ubuntu".to_owned()),
            host_icon_mode: None,
            host_icon_id: None,
            host_icon_color_mode: None,
            host_icon_color: None,
            host_icon_color_custom: None,
            start_time,
            end_time: Some(start_time + 1),
            local_username: "local-user".to_owned(),
            local_hostname: "workstation".to_owned(),
            saved,
            theme_id: Some("netcatty-dark".to_owned()),
            font_size: Some(14.0),
        }
    }

    fn blob_count(path: &Path) -> usize {
        let mut count = 0;
        let Ok(entries) = fs::read_dir(path) else {
            return 0;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                count += blob_count(&path);
            } else if path.extension().and_then(|value| value.to_str()) == Some("ncsb") {
                count += 1;
            }
        }
        count
    }

    fn files_contain(path: &Path, marker: &[u8]) -> bool {
        let Ok(entries) = fs::read_dir(path) else {
            return false;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if files_contain(&path, marker) {
                    return true;
                }
            } else if fs::read(path)
                .is_ok_and(|bytes| bytes.windows(marker.len()).any(|window| window == marker))
            {
                return true;
            }
        }
        false
    }

    #[test]
    fn replace_append_delete_round_trip_survives_restart_without_plaintext_files() {
        let directory = tempfile::tempdir().expect("temporary replay store");
        let (keys, _) = in_memory_master_key_store();
        let metadata = log("private-log-id", 100, true);
        let marker = "TOP-SECRET-terminal-password";

        let store =
            ConnectionLogReplayStore::open_with_master_key_store(directory.path(), keys.clone())
                .expect("open replay store");
        store
            .replace(
                &metadata,
                SavedConnectionLogReplay::new(&metadata.id, marker).expect("replay"),
            )
            .expect("replace replay");
        store.append(&metadata, "-tail").expect("append replay");
        assert_eq!(
            store
                .read(&metadata.id)
                .expect("read replay")
                .expect("present replay")
                .terminal_data(),
            format!("{marker}-tail")
        );
        assert!(!files_contain(directory.path(), marker.as_bytes()));
        assert!(!files_contain(directory.path(), metadata.id.as_bytes()));
        drop(store);

        let reopened = ConnectionLogReplayStore::open_with_master_key_store(directory.path(), keys)
            .expect("reopen replay store");
        assert_eq!(
            reopened
                .read(&metadata.id)
                .expect("read after restart")
                .expect("replay after restart")
                .terminal_data(),
            format!("{marker}-tail")
        );
        reopened.delete(&metadata.id).expect("delete replay");
        assert!(reopened.read(&metadata.id).expect("read deleted").is_none());
    }

    #[test]
    fn replay_is_bounded_to_newest_complete_one_million_byte_utf8_suffix() {
        let directory = tempfile::tempdir().expect("temporary replay store");
        let (keys, _) = in_memory_master_key_store();
        let store = ConnectionLogReplayStore::open_with_master_key_store(directory.path(), keys)
            .expect("open replay store");
        let metadata = log("bounded", 1, true);
        let input = format!("{}日日-tail", "x".repeat(MAX_CONNECTION_LOG_REPLAY_BYTES));
        store
            .replace(
                &metadata,
                SavedConnectionLogReplay::new(&metadata.id, input).expect("bounded replay"),
            )
            .expect("persist bounded replay");
        let replay = store
            .read(&metadata.id)
            .expect("read bounded")
            .expect("bounded replay exists");
        assert!(replay.terminal_data().len() <= MAX_CONNECTION_LOG_REPLAY_BYTES);
        assert!(replay.terminal_data().ends_with("日日-tail"));
        assert!(std::str::from_utf8(replay.terminal_data().as_bytes()).is_ok());
    }

    #[test]
    fn retention_keeps_every_saved_entry_and_only_newest_fifty_unsaved() {
        let mut entries = std::collections::BTreeMap::new();
        for index in 0..(MAX_PERSISTED_UNSAVED_CONNECTION_LOG_REPLAYS + 7) {
            entries.insert(
                digest_log_id(&format!("unsaved-{index}")).expect("digest"),
                ReplayIndexEntry {
                    revision: 1,
                    start_time: index as u64 + 1,
                    saved: false,
                },
            );
        }
        for index in 0..75 {
            entries.insert(
                digest_log_id(&format!("saved-{index}")).expect("digest"),
                ReplayIndexEntry {
                    revision: 1,
                    start_time: 1,
                    saved: true,
                },
            );
        }
        apply_replay_retention(&mut entries);
        assert_eq!(
            entries.values().filter(|entry| !entry.saved).count(),
            MAX_PERSISTED_UNSAVED_CONNECTION_LOG_REPLAYS
        );
        assert_eq!(entries.values().filter(|entry| entry.saved).count(), 75);
        for index in 0..7 {
            assert!(
                !entries.contains_key(&digest_log_id(&format!("unsaved-{index}")).expect("digest"))
            );
        }
    }

    #[test]
    fn keyring_fault_aborts_append_without_changing_the_visible_replay() {
        let directory = tempfile::tempdir().expect("temporary replay store");
        let (keys, controller) = in_memory_master_key_store();
        let store =
            ConnectionLogReplayStore::open_with_master_key_store(directory.path(), keys.clone())
                .expect("open replay store");
        let metadata = log("fault-private-id", 1, true);
        store
            .append(&metadata, "before-fault")
            .expect("seed replay");
        let before = blob_count(directory.path());
        controller.set_failure(
            CredentialOperation::Resolve,
            1,
            FailureTiming::BeforeSideEffect,
            CredentialErrorCode::StorageUnavailable,
        );
        let error = store
            .append(&metadata, "must-not-commit")
            .expect_err("key fault must fail closed");
        assert_eq!(
            error.code(),
            ConnectionLogReplayStoreErrorCode::CredentialUnavailable
        );
        assert_eq!(blob_count(directory.path()), before);
        controller.clear_failures();
        drop(store);

        let reopened = ConnectionLogReplayStore::open_with_master_key_store(directory.path(), keys)
            .expect("restart after fault");
        assert_eq!(
            reopened
                .read(&metadata.id)
                .expect("read after fault")
                .expect("seed remains")
                .terminal_data(),
            "before-fault"
        );
    }

    #[test]
    fn corrupt_newest_ciphertext_fails_closed_without_falling_back_or_leaking_markers() {
        let directory = tempfile::tempdir().expect("temporary replay store");
        let (keys, _) = in_memory_master_key_store();
        let store = ConnectionLogReplayStore::open_with_master_key_store(directory.path(), keys)
            .expect("open replay store");
        let metadata = log("do-not-leak-log-id", 1, true);
        store
            .append(&metadata, "older-secret")
            .expect("revision one");
        store
            .append(&metadata, "-newer-secret")
            .expect("revision two");

        let digest = digest_log_id(&metadata.id).expect("digest");
        let locator = {
            let guard = store.files.lock_exclusive().expect("exclusive lock");
            guard
                .derive_object_locator(&replay_entity_id(digest))
                .expect("locator")
                .backend_locator_hex()
        };
        let object = store.root.join("objects").join(&locator[..2]).join(locator);
        for slot in ["slot-a", "slot-b"] {
            let path = fs::read_dir(object.join(slot))
                .expect("slot")
                .filter_map(Result::ok)
                .find(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("blob-00000000000000000002-")
                })
                .expect("newest blob")
                .path();
            let mut bytes = fs::read(&path).expect("read ciphertext");
            let last = bytes.last_mut().expect("ciphertext byte");
            *last ^= 0x80;
            fs::write(path, bytes).expect("tamper ciphertext");
        }

        let error = store
            .read(&metadata.id)
            .expect_err("corrupt newest revision must not fall back");
        assert_eq!(
            error.code(),
            ConnectionLogReplayStoreErrorCode::ReplayUnavailable
        );
        let rendered = format!("{error:?} {error} {store:?}");
        for forbidden in ["do-not-leak-log-id", "older-secret", "newer-secret"] {
            assert!(!rendered.contains(forbidden));
        }
    }

    #[test]
    fn garbage_collection_fault_is_reported_and_removes_nothing() {
        let directory = tempfile::tempdir().expect("temporary replay store");
        let (keys, _) = in_memory_master_key_store();
        let store = ConnectionLogReplayStore::open_with_master_key_store(directory.path(), keys)
            .expect("open replay store");
        let metadata = log("gc-private-id", 1, true);
        store.append(&metadata, "gc-secret").expect("seed replay");
        let before = blob_count(directory.path());
        fs::create_dir(directory.path().join("objects").join("not-hex"))
            .expect("inject invalid artifact");
        let error = store
            .garbage_collect()
            .expect_err("unsafe graph must stop cleanup");
        assert_eq!(
            error.code(),
            ConnectionLogReplayStoreErrorCode::GarbageCollectionFailed
        );
        assert_eq!(blob_count(directory.path()), before);
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("gc-private-id"));
        assert!(!rendered.contains("gc-secret"));
    }
}
