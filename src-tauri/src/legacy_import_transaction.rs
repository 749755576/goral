use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use netcatty_vault::{SavedHostId, SavedVaultGraphCommitment};
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};
use uuid::{Uuid, Version};

const JOURNAL_MAGIC: &str = "netcatty-legacy-credential-import-transaction";
const LEGACY_JOURNAL_FORMAT_VERSION: u32 = 2;
const BLOB_JOURNAL_FORMAT_VERSION: u32 = 3;
const OWNER_JOURNAL_FORMAT_VERSION: u32 = 4;
const PROXY_JOURNAL_FORMAT_VERSION: u32 = 5;
const JOURNAL_FORMAT_VERSION: u32 = 6;
const SLOT_A_FILE: &str = "legacy-credential-import-transaction-a.json";
const SLOT_B_FILE: &str = "legacy-credential-import-transaction-b.json";
const MAX_ENTRIES: usize = 10_000;
// Every supported credential owner uses the Vault opaque-ID contract: at most
// 512 UTF-8 bytes and no control characters. `serde_json` can expand each
// accepted byte by at most two when escaping `"` and `\`. Keep this mirror
// covered by the boundary test below so an upstream ID-contract change cannot
// silently invalidate the journal proof.
const MAX_OWNER_ID_BYTES: usize = 512;
const MAX_JSON_ESCAPED_OWNER_ID_BYTES: usize = MAX_OWNER_ID_BYTES * 2;
// This is the exact fixed part of the longest current v6 entry encoding.
// `passwordIdentity` remains longer than the added `hostTelnet` owner kind.
const MAX_JOURNAL_ENTRY_FIXED_BYTES: usize =
    br#"{"ownerKind":"passwordIdentity","ownerId":"","previous":"backedUp"}"#.len();
// Exact v6 JSON punctuation and field names with empty scalar values. Add the
// longest canonical value for every scalar below. `false` is one byte longer
// than `true`, and `rollbackTargetsRestored` is the longest phase. The v2
// fixed envelope is smaller because it omits `requiresBlobPublication`.
const MAX_JOURNAL_ENVELOPE_FIXED_BYTES: usize = br#"{"magic":"","formatVersion":,"slot":"","generation":,"transactionId":"","beforeGraphCommitment":"","afterGraphCommitment":"","requiresBlobPublication":,"phase":"","entries":[],"checksum":""}"#.len()
    + JOURNAL_MAGIC.len()
    + 1 // format version
    + 1 // slot
    + 20 // u64 generation
    + 36 // hyphenated UUID
    + 64 // before graph commitment
    + 64 // after graph commitment
    + 5 // `false`
    + "rollbackTargetsRestored".len()
    + 64; // checksum
// Exact worst-case v6 bound: the fixed empty-array envelope, every accepted
// entry with a maximally JSON-escaped 512-byte ID and longest state, plus the
// commas between entries. This also covers every valid legacy-v2/v3/v4/v5
// envelope.
const MAX_JOURNAL_BYTES: u64 = (MAX_JOURNAL_ENVELOPE_FIXED_BYTES
    + MAX_ENTRIES * (MAX_JSON_ESCAPED_OWNER_ID_BYTES + MAX_JOURNAL_ENTRY_FIXED_BYTES)
    + (MAX_ENTRIES - 1)) as u64;

/// A fixed, secret-free description of what occupied a final saved-host
/// credential account before a legacy import attempted to change it.
///
/// `BackedUp` records only that a backup was made. The secret and its backup
/// account are deliberately outside this journal.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) enum LegacyPreviousCredentialState {
    Unknown,
    Absent,
    BackedUp,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) enum LegacyImportTransactionPhase {
    Preparing,
    BlobsDurable,
    Active,
    VaultDurable,
    RollbackTargetsRestored,
}

/// The namespace that owns one password credential touched by a transaction.
/// All eight owner kinds may use byte-for-byte equal IDs without sharing a
/// keyring account or a recovery coordinate.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) enum LegacyImportCredentialOwnerKind {
    Host,
    HostTelnet,
    PasswordIdentity,
    HostInlineProxy,
    ProxyProfile,
    GroupSsh,
    GroupTelnet,
    GroupProxy,
}

/// A validated, secret-free recovery coordinate. Debug deliberately omits the
/// opaque owner ID so incidental errors and logs cannot disclose identifiers.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct LegacyImportCredentialOwner {
    kind: LegacyImportCredentialOwnerKind,
    id: SavedHostId,
}

impl LegacyImportCredentialOwner {
    pub(crate) fn for_saved_host(id: &SavedHostId) -> Self {
        Self {
            kind: LegacyImportCredentialOwnerKind::Host,
            id: id.clone(),
        }
    }

    pub(crate) fn for_saved_host_telnet(id: &SavedHostId) -> Self {
        Self {
            kind: LegacyImportCredentialOwnerKind::HostTelnet,
            id: id.clone(),
        }
    }

    pub(crate) fn for_password_identity(
        id: impl Into<String>,
    ) -> Result<Self, LegacyImportTransactionError> {
        let id = SavedHostId::from_opaque(id.into())
            .map_err(|_| LegacyImportTransactionError::InvalidStateTransition)?;
        Ok(Self {
            kind: LegacyImportCredentialOwnerKind::PasswordIdentity,
            id,
        })
    }

    pub(crate) fn for_host_inline_proxy(id: &SavedHostId) -> Self {
        Self {
            kind: LegacyImportCredentialOwnerKind::HostInlineProxy,
            id: id.clone(),
        }
    }

    pub(crate) fn for_proxy_profile(
        id: impl Into<String>,
    ) -> Result<Self, LegacyImportTransactionError> {
        let id = SavedHostId::from_opaque(id.into())
            .map_err(|_| LegacyImportTransactionError::InvalidStateTransition)?;
        Ok(Self {
            kind: LegacyImportCredentialOwnerKind::ProxyProfile,
            id,
        })
    }

    pub(crate) fn for_group_ssh(
        id: impl Into<String>,
    ) -> Result<Self, LegacyImportTransactionError> {
        Self::for_opaque_owner(LegacyImportCredentialOwnerKind::GroupSsh, id)
    }

    pub(crate) fn for_group_telnet(
        id: impl Into<String>,
    ) -> Result<Self, LegacyImportTransactionError> {
        Self::for_opaque_owner(LegacyImportCredentialOwnerKind::GroupTelnet, id)
    }

    pub(crate) fn for_group_proxy(
        id: impl Into<String>,
    ) -> Result<Self, LegacyImportTransactionError> {
        Self::for_opaque_owner(LegacyImportCredentialOwnerKind::GroupProxy, id)
    }

    fn for_opaque_owner(
        kind: LegacyImportCredentialOwnerKind,
        id: impl Into<String>,
    ) -> Result<Self, LegacyImportTransactionError> {
        let id = SavedHostId::from_opaque(id.into())
            .map_err(|_| LegacyImportTransactionError::InvalidStateTransition)?;
        Ok(Self { kind, id })
    }

    pub(crate) const fn kind(&self) -> LegacyImportCredentialOwnerKind {
        self.kind
    }

    pub(crate) fn id(&self) -> &str {
        self.id.as_str()
    }
}

impl fmt::Debug for LegacyImportCredentialOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyImportCredentialOwner")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// One recovery target. Fields are private so callers cannot mutate a loaded
/// journal without publishing the next checked generation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LegacyImportTransactionEntry {
    owner_kind: LegacyImportCredentialOwnerKind,
    owner_id: SavedHostId,
    previous: LegacyPreviousCredentialState,
}

impl LegacyImportTransactionEntry {
    fn new(owner: LegacyImportCredentialOwner) -> Self {
        Self {
            owner_kind: owner.kind,
            owner_id: owner.id,
            previous: LegacyPreviousCredentialState::Unknown,
        }
    }

    pub(crate) const fn owner_kind(&self) -> LegacyImportCredentialOwnerKind {
        self.owner_kind
    }

    pub(crate) fn owner_id(&self) -> &str {
        self.owner_id.as_str()
    }

    pub(crate) fn owner(&self) -> LegacyImportCredentialOwner {
        LegacyImportCredentialOwner {
            kind: self.owner_kind,
            id: self.owner_id.clone(),
        }
    }

    // Transitional host-only accessor retained while the desktop import call
    // sites move to `owner()`. New identity-aware code must not use it.
    pub(crate) fn saved_host_id(&self) -> &SavedHostId {
        debug_assert_eq!(self.owner_kind, LegacyImportCredentialOwnerKind::Host);
        &self.owner_id
    }

    pub(crate) const fn previous(&self) -> LegacyPreviousCredentialState {
        self.previous
    }
}

// Saved-host IDs must never appear through incidental diagnostics.
impl fmt::Debug for LegacyImportTransactionEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyImportTransactionEntry")
            .field("owner_kind", &self.owner_kind)
            .field("previous", &self.previous)
            .finish_non_exhaustive()
    }
}

/// Exact v2/v3 on-disk entry shape. Old checksums bind `savedHostId`, so old
/// envelopes must not be normalized to v6 until a new generation is written.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyJournalEntryV2V3 {
    saved_host_id: SavedHostId,
    previous: LegacyPreviousCredentialState,
}

/// Exact v4 owner discriminator. Keeping this separate from later formats
/// prevents a forged old-format envelope from claiming a proxy account.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum LegacyImportCredentialOwnerKindV4 {
    Host,
    PasswordIdentity,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyJournalEntryV4 {
    owner_kind: LegacyImportCredentialOwnerKindV4,
    owner_id: SavedHostId,
    previous: LegacyPreviousCredentialState,
}

impl LegacyJournalEntryV4 {
    fn from_current(
        entry: &LegacyImportTransactionEntry,
    ) -> Result<Self, LegacyImportTransactionError> {
        let owner_kind = match entry.owner_kind {
            LegacyImportCredentialOwnerKind::Host => LegacyImportCredentialOwnerKindV4::Host,
            LegacyImportCredentialOwnerKind::PasswordIdentity => {
                LegacyImportCredentialOwnerKindV4::PasswordIdentity
            }
            LegacyImportCredentialOwnerKind::HostTelnet
            | LegacyImportCredentialOwnerKind::HostInlineProxy
            | LegacyImportCredentialOwnerKind::ProxyProfile
            | LegacyImportCredentialOwnerKind::GroupSsh
            | LegacyImportCredentialOwnerKind::GroupTelnet
            | LegacyImportCredentialOwnerKind::GroupProxy => {
                return Err(LegacyImportTransactionError::Serialization);
            }
        };
        Ok(Self {
            owner_kind,
            owner_id: entry.owner_id.clone(),
            previous: entry.previous,
        })
    }

    fn into_current(self) -> LegacyImportTransactionEntry {
        LegacyImportTransactionEntry {
            owner_kind: match self.owner_kind {
                LegacyImportCredentialOwnerKindV4::Host => LegacyImportCredentialOwnerKind::Host,
                LegacyImportCredentialOwnerKindV4::PasswordIdentity => {
                    LegacyImportCredentialOwnerKind::PasswordIdentity
                }
            },
            owner_id: self.owner_id,
            previous: self.previous,
        }
    }
}

/// Exact v5 owner discriminator. V5 introduced proxy owners, but must remain
/// unable to claim any of the group credential namespaces added by v6.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum LegacyImportCredentialOwnerKindV5 {
    Host,
    PasswordIdentity,
    HostInlineProxy,
    ProxyProfile,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyJournalEntryV5 {
    owner_kind: LegacyImportCredentialOwnerKindV5,
    owner_id: SavedHostId,
    previous: LegacyPreviousCredentialState,
}

impl LegacyJournalEntryV5 {
    fn from_current(
        entry: &LegacyImportTransactionEntry,
    ) -> Result<Self, LegacyImportTransactionError> {
        let owner_kind = match entry.owner_kind {
            LegacyImportCredentialOwnerKind::Host => LegacyImportCredentialOwnerKindV5::Host,
            LegacyImportCredentialOwnerKind::PasswordIdentity => {
                LegacyImportCredentialOwnerKindV5::PasswordIdentity
            }
            LegacyImportCredentialOwnerKind::HostInlineProxy => {
                LegacyImportCredentialOwnerKindV5::HostInlineProxy
            }
            LegacyImportCredentialOwnerKind::ProxyProfile => {
                LegacyImportCredentialOwnerKindV5::ProxyProfile
            }
            LegacyImportCredentialOwnerKind::HostTelnet
            | LegacyImportCredentialOwnerKind::GroupSsh
            | LegacyImportCredentialOwnerKind::GroupTelnet
            | LegacyImportCredentialOwnerKind::GroupProxy => {
                return Err(LegacyImportTransactionError::Serialization);
            }
        };
        Ok(Self {
            owner_kind,
            owner_id: entry.owner_id.clone(),
            previous: entry.previous,
        })
    }

    fn into_current(self) -> LegacyImportTransactionEntry {
        LegacyImportTransactionEntry {
            owner_kind: match self.owner_kind {
                LegacyImportCredentialOwnerKindV5::Host => LegacyImportCredentialOwnerKind::Host,
                LegacyImportCredentialOwnerKindV5::PasswordIdentity => {
                    LegacyImportCredentialOwnerKind::PasswordIdentity
                }
                LegacyImportCredentialOwnerKindV5::HostInlineProxy => {
                    LegacyImportCredentialOwnerKind::HostInlineProxy
                }
                LegacyImportCredentialOwnerKindV5::ProxyProfile => {
                    LegacyImportCredentialOwnerKind::ProxyProfile
                }
            },
            owner_id: self.owner_id,
            previous: self.previous,
        }
    }
}

impl LegacyJournalEntryV2V3 {
    fn from_current(
        entry: &LegacyImportTransactionEntry,
    ) -> Result<Self, LegacyImportTransactionError> {
        if entry.owner_kind != LegacyImportCredentialOwnerKind::Host {
            return Err(LegacyImportTransactionError::Serialization);
        }
        Ok(Self {
            saved_host_id: entry.owner_id.clone(),
            previous: entry.previous,
        })
    }

    fn into_current(self) -> LegacyImportTransactionEntry {
        LegacyImportTransactionEntry {
            owner_kind: LegacyImportCredentialOwnerKind::Host,
            owner_id: self.saved_host_id,
            previous: self.previous,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LegacyImportTransactionError {
    Storage,
    Serialization,
    InvalidLayout,
    RecoverySlotsUnavailable,
    ExistingTransaction,
    MissingTransaction,
    ConcurrentMutation,
    GenerationOverflow,
    TooManyEntries,
    JournalTooLarge,
    DuplicateCredentialOwner,
    UnknownCredentialOwner,
    IncompletePreviousStateMap,
    InvalidStateTransition,
    PublicationVerificationFailed,
}

impl fmt::Display for LegacyImportTransactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Storage => "legacy import transaction storage failed",
            Self::Serialization => "legacy import transaction serialization failed",
            Self::InvalidLayout => "legacy import transaction storage layout is invalid",
            Self::RecoverySlotsUnavailable => {
                "legacy import transaction recovery slots are unavailable or corrupt"
            }
            Self::ExistingTransaction => "a legacy import transaction is already active",
            Self::MissingTransaction => "the legacy import transaction is unavailable",
            Self::ConcurrentMutation => "the legacy import transaction changed concurrently",
            Self::GenerationOverflow => "legacy import transaction generation overflowed",
            Self::TooManyEntries => "legacy import transaction entry limit exceeded",
            Self::JournalTooLarge => "legacy import transaction byte limit exceeded",
            Self::DuplicateCredentialOwner => {
                "legacy import transaction contains a duplicate credential owner"
            }
            Self::UnknownCredentialOwner => {
                "legacy import transaction does not contain the credential owner"
            }
            Self::IncompletePreviousStateMap => {
                "legacy import transaction previous-state map is incomplete"
            }
            Self::InvalidStateTransition => "legacy import transaction state transition is invalid",
            Self::PublicationVerificationFailed => {
                "legacy import transaction publication could not be verified"
            }
        })
    }
}

// Keep Debug just as non-sensitive as Display. In particular, do not retain
// underlying io/Serde errors because their diagnostics can contain paths or
// source values.
impl fmt::Debug for LegacyImportTransactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for LegacyImportTransactionError {}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum Slot {
    A,
    B,
}

impl Slot {
    const fn for_generation(generation: u64) -> Self {
        if generation % 2 == 1 {
            Self::A
        } else {
            Self::B
        }
    }

    const fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }

    const fn file_name(self) -> &'static str {
        match self {
            Self::A => SLOT_A_FILE,
            Self::B => SLOT_B_FILE,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum LegacyJournalPhaseV2 {
    Preparing,
    Active,
    VaultDurable,
    RollbackTargetsRestored,
}

impl From<LegacyJournalPhaseV2> for LegacyImportTransactionPhase {
    fn from(phase: LegacyJournalPhaseV2) -> Self {
        match phase {
            LegacyJournalPhaseV2::Preparing => Self::Preparing,
            LegacyJournalPhaseV2::Active => Self::Active,
            LegacyJournalPhaseV2::VaultDurable => Self::VaultDurable,
            LegacyJournalPhaseV2::RollbackTargetsRestored => Self::RollbackTargetsRestored,
        }
    }
}

impl TryFrom<LegacyImportTransactionPhase> for LegacyJournalPhaseV2 {
    type Error = ();

    fn try_from(phase: LegacyImportTransactionPhase) -> Result<Self, Self::Error> {
        match phase {
            LegacyImportTransactionPhase::Preparing => Ok(Self::Preparing),
            LegacyImportTransactionPhase::Active => Ok(Self::Active),
            LegacyImportTransactionPhase::VaultDurable => Ok(Self::VaultDurable),
            LegacyImportTransactionPhase::RollbackTargetsRestored => {
                Ok(Self::RollbackTargetsRestored)
            }
            LegacyImportTransactionPhase::BlobsDurable => Err(()),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct JournalEnvelope {
    magic: String,
    format_version: u32,
    slot: Slot,
    generation: u64,
    transaction_id: Uuid,
    before_graph_commitment: SavedVaultGraphCommitment,
    after_graph_commitment: SavedVaultGraphCommitment,
    requires_blob_publication: bool,
    phase: LegacyImportTransactionPhase,
    entries: Vec<LegacyImportTransactionEntry>,
    checksum: String,
}

impl Serialize for JournalEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::{Error as _, SerializeStruct as _};

        match self.format_version {
            LEGACY_JOURNAL_FORMAT_VERSION => {
                let phase = LegacyJournalPhaseV2::try_from(self.phase)
                    .map_err(|_| S::Error::custom("invalid legacy journal phase"))?;
                if self.requires_blob_publication {
                    return Err(S::Error::custom("invalid legacy journal blob flag"));
                }
                let entries = legacy_entries(&self.entries)
                    .map_err(|_| S::Error::custom("invalid legacy journal owner"))?;
                let mut state = serializer.serialize_struct("JournalEnvelope", 10)?;
                state.serialize_field("magic", &self.magic)?;
                state.serialize_field("formatVersion", &self.format_version)?;
                state.serialize_field("slot", &self.slot)?;
                state.serialize_field("generation", &self.generation)?;
                state.serialize_field("transactionId", &self.transaction_id)?;
                state.serialize_field("beforeGraphCommitment", &self.before_graph_commitment)?;
                state.serialize_field("afterGraphCommitment", &self.after_graph_commitment)?;
                state.serialize_field("phase", &phase)?;
                state.serialize_field("entries", &entries)?;
                state.serialize_field("checksum", &self.checksum)?;
                state.end()
            }
            BLOB_JOURNAL_FORMAT_VERSION => {
                let entries = legacy_entries(&self.entries)
                    .map_err(|_| S::Error::custom("invalid v3 journal owner"))?;
                let mut state = serializer.serialize_struct("JournalEnvelope", 11)?;
                state.serialize_field("magic", &self.magic)?;
                state.serialize_field("formatVersion", &self.format_version)?;
                state.serialize_field("slot", &self.slot)?;
                state.serialize_field("generation", &self.generation)?;
                state.serialize_field("transactionId", &self.transaction_id)?;
                state.serialize_field("beforeGraphCommitment", &self.before_graph_commitment)?;
                state.serialize_field("afterGraphCommitment", &self.after_graph_commitment)?;
                state
                    .serialize_field("requiresBlobPublication", &self.requires_blob_publication)?;
                state.serialize_field("phase", &self.phase)?;
                state.serialize_field("entries", &entries)?;
                state.serialize_field("checksum", &self.checksum)?;
                state.end()
            }
            OWNER_JOURNAL_FORMAT_VERSION => {
                let entries = v4_entries(&self.entries)
                    .map_err(|_| S::Error::custom("invalid v4 journal owner"))?;
                let mut state = serializer.serialize_struct("JournalEnvelope", 11)?;
                state.serialize_field("magic", &self.magic)?;
                state.serialize_field("formatVersion", &self.format_version)?;
                state.serialize_field("slot", &self.slot)?;
                state.serialize_field("generation", &self.generation)?;
                state.serialize_field("transactionId", &self.transaction_id)?;
                state.serialize_field("beforeGraphCommitment", &self.before_graph_commitment)?;
                state.serialize_field("afterGraphCommitment", &self.after_graph_commitment)?;
                state
                    .serialize_field("requiresBlobPublication", &self.requires_blob_publication)?;
                state.serialize_field("phase", &self.phase)?;
                state.serialize_field("entries", &entries)?;
                state.serialize_field("checksum", &self.checksum)?;
                state.end()
            }
            PROXY_JOURNAL_FORMAT_VERSION => {
                let entries = v5_entries(&self.entries)
                    .map_err(|_| S::Error::custom("invalid v5 journal owner"))?;
                let mut state = serializer.serialize_struct("JournalEnvelope", 11)?;
                state.serialize_field("magic", &self.magic)?;
                state.serialize_field("formatVersion", &self.format_version)?;
                state.serialize_field("slot", &self.slot)?;
                state.serialize_field("generation", &self.generation)?;
                state.serialize_field("transactionId", &self.transaction_id)?;
                state.serialize_field("beforeGraphCommitment", &self.before_graph_commitment)?;
                state.serialize_field("afterGraphCommitment", &self.after_graph_commitment)?;
                state
                    .serialize_field("requiresBlobPublication", &self.requires_blob_publication)?;
                state.serialize_field("phase", &self.phase)?;
                state.serialize_field("entries", &entries)?;
                state.serialize_field("checksum", &self.checksum)?;
                state.end()
            }
            JOURNAL_FORMAT_VERSION => {
                let mut state = serializer.serialize_struct("JournalEnvelope", 11)?;
                state.serialize_field("magic", &self.magic)?;
                state.serialize_field("formatVersion", &self.format_version)?;
                state.serialize_field("slot", &self.slot)?;
                state.serialize_field("generation", &self.generation)?;
                state.serialize_field("transactionId", &self.transaction_id)?;
                state.serialize_field("beforeGraphCommitment", &self.before_graph_commitment)?;
                state.serialize_field("afterGraphCommitment", &self.after_graph_commitment)?;
                state
                    .serialize_field("requiresBlobPublication", &self.requires_blob_publication)?;
                state.serialize_field("phase", &self.phase)?;
                state.serialize_field("entries", &self.entries)?;
                state.serialize_field("checksum", &self.checksum)?;
                state.end()
            }
            _ => Err(S::Error::custom("unsupported journal format")),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JournalEnvelopeV2 {
    magic: String,
    format_version: u32,
    slot: Slot,
    generation: u64,
    transaction_id: Uuid,
    before_graph_commitment: SavedVaultGraphCommitment,
    after_graph_commitment: SavedVaultGraphCommitment,
    phase: LegacyJournalPhaseV2,
    entries: Vec<LegacyJournalEntryV2V3>,
    checksum: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JournalEnvelopeV3 {
    magic: String,
    format_version: u32,
    slot: Slot,
    generation: u64,
    transaction_id: Uuid,
    before_graph_commitment: SavedVaultGraphCommitment,
    after_graph_commitment: SavedVaultGraphCommitment,
    requires_blob_publication: bool,
    phase: LegacyImportTransactionPhase,
    entries: Vec<LegacyJournalEntryV2V3>,
    checksum: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JournalEnvelopeV4 {
    magic: String,
    format_version: u32,
    slot: Slot,
    generation: u64,
    transaction_id: Uuid,
    before_graph_commitment: SavedVaultGraphCommitment,
    after_graph_commitment: SavedVaultGraphCommitment,
    requires_blob_publication: bool,
    phase: LegacyImportTransactionPhase,
    entries: Vec<LegacyJournalEntryV4>,
    checksum: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JournalEnvelopeV5 {
    magic: String,
    format_version: u32,
    slot: Slot,
    generation: u64,
    transaction_id: Uuid,
    before_graph_commitment: SavedVaultGraphCommitment,
    after_graph_commitment: SavedVaultGraphCommitment,
    requires_blob_publication: bool,
    phase: LegacyImportTransactionPhase,
    entries: Vec<LegacyJournalEntryV5>,
    checksum: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JournalEnvelopeV6 {
    magic: String,
    format_version: u32,
    slot: Slot,
    generation: u64,
    transaction_id: Uuid,
    before_graph_commitment: SavedVaultGraphCommitment,
    after_graph_commitment: SavedVaultGraphCommitment,
    requires_blob_publication: bool,
    phase: LegacyImportTransactionPhase,
    entries: Vec<LegacyImportTransactionEntry>,
    checksum: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JournalFormatProbe {
    format_version: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChecksumPayloadV2<'a> {
    magic: &'a str,
    format_version: u32,
    slot: Slot,
    generation: u64,
    transaction_id: Uuid,
    before_graph_commitment: &'a SavedVaultGraphCommitment,
    after_graph_commitment: &'a SavedVaultGraphCommitment,
    phase: LegacyJournalPhaseV2,
    entries: &'a [LegacyJournalEntryV2V3],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChecksumPayloadV3<'a> {
    magic: &'a str,
    format_version: u32,
    slot: Slot,
    generation: u64,
    transaction_id: Uuid,
    before_graph_commitment: &'a SavedVaultGraphCommitment,
    after_graph_commitment: &'a SavedVaultGraphCommitment,
    requires_blob_publication: bool,
    phase: LegacyImportTransactionPhase,
    entries: &'a [LegacyJournalEntryV2V3],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChecksumPayloadV4<'a> {
    magic: &'a str,
    format_version: u32,
    slot: Slot,
    generation: u64,
    transaction_id: Uuid,
    before_graph_commitment: &'a SavedVaultGraphCommitment,
    after_graph_commitment: &'a SavedVaultGraphCommitment,
    requires_blob_publication: bool,
    phase: LegacyImportTransactionPhase,
    entries: &'a [LegacyJournalEntryV4],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChecksumPayloadV5<'a> {
    magic: &'a str,
    format_version: u32,
    slot: Slot,
    generation: u64,
    transaction_id: Uuid,
    before_graph_commitment: &'a SavedVaultGraphCommitment,
    after_graph_commitment: &'a SavedVaultGraphCommitment,
    requires_blob_publication: bool,
    phase: LegacyImportTransactionPhase,
    entries: &'a [LegacyJournalEntryV5],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChecksumPayloadV6<'a> {
    magic: &'a str,
    format_version: u32,
    slot: Slot,
    generation: u64,
    transaction_id: Uuid,
    before_graph_commitment: &'a SavedVaultGraphCommitment,
    after_graph_commitment: &'a SavedVaultGraphCommitment,
    requires_blob_publication: bool,
    phase: LegacyImportTransactionPhase,
    entries: &'a [LegacyImportTransactionEntry],
}

fn legacy_entries(
    entries: &[LegacyImportTransactionEntry],
) -> Result<Vec<LegacyJournalEntryV2V3>, LegacyImportTransactionError> {
    entries
        .iter()
        .map(LegacyJournalEntryV2V3::from_current)
        .collect()
}

fn v4_entries(
    entries: &[LegacyImportTransactionEntry],
) -> Result<Vec<LegacyJournalEntryV4>, LegacyImportTransactionError> {
    entries
        .iter()
        .map(LegacyJournalEntryV4::from_current)
        .collect()
}

fn v5_entries(
    entries: &[LegacyImportTransactionEntry],
) -> Result<Vec<LegacyJournalEntryV5>, LegacyImportTransactionError> {
    entries
        .iter()
        .map(LegacyJournalEntryV5::from_current)
        .collect()
}

impl JournalEnvelope {
    #[cfg(test)]
    fn new(
        slot: Slot,
        generation: u64,
        transaction_id: Uuid,
        before_graph_commitment: SavedVaultGraphCommitment,
        after_graph_commitment: SavedVaultGraphCommitment,
        phase: LegacyImportTransactionPhase,
        entries: Vec<LegacyImportTransactionEntry>,
    ) -> Result<Self, LegacyImportTransactionError> {
        Self::new_with_blob_publication(
            slot,
            generation,
            transaction_id,
            before_graph_commitment,
            after_graph_commitment,
            false,
            phase,
            entries,
        )
    }

    fn new_with_blob_publication(
        slot: Slot,
        generation: u64,
        transaction_id: Uuid,
        before_graph_commitment: SavedVaultGraphCommitment,
        after_graph_commitment: SavedVaultGraphCommitment,
        requires_blob_publication: bool,
        phase: LegacyImportTransactionPhase,
        entries: Vec<LegacyImportTransactionEntry>,
    ) -> Result<Self, LegacyImportTransactionError> {
        if generation == 0 || Slot::for_generation(generation) != slot {
            return Err(LegacyImportTransactionError::InvalidStateTransition);
        }
        validate_phase_for_format(JOURNAL_FORMAT_VERSION, requires_blob_publication, phase)?;
        validate_transaction_id(transaction_id)?;
        validate_graph_commitments(&before_graph_commitment, &after_graph_commitment)?;
        validate_entries(&entries)?;
        let checksum = journal_checksum(
            JOURNAL_MAGIC,
            JOURNAL_FORMAT_VERSION,
            slot,
            generation,
            transaction_id,
            &before_graph_commitment,
            &after_graph_commitment,
            requires_blob_publication,
            phase,
            &entries,
        )?;
        Ok(Self {
            magic: JOURNAL_MAGIC.to_owned(),
            format_version: JOURNAL_FORMAT_VERSION,
            slot,
            generation,
            transaction_id,
            before_graph_commitment,
            after_graph_commitment,
            requires_blob_publication,
            phase,
            entries,
            checksum,
        })
    }

    fn validate(self, expected_slot: Slot) -> Result<Self, LegacyImportTransactionError> {
        if self.magic != JOURNAL_MAGIC
            || !matches!(
                self.format_version,
                LEGACY_JOURNAL_FORMAT_VERSION
                    | BLOB_JOURNAL_FORMAT_VERSION
                    | OWNER_JOURNAL_FORMAT_VERSION
                    | PROXY_JOURNAL_FORMAT_VERSION
                    | JOURNAL_FORMAT_VERSION
            )
            || self.slot != expected_slot
            || self.generation == 0
            || Slot::for_generation(self.generation) != expected_slot
        {
            return Err(LegacyImportTransactionError::RecoverySlotsUnavailable);
        }
        validate_phase_for_format(
            self.format_version,
            self.requires_blob_publication,
            self.phase,
        )
        .map_err(|_| LegacyImportTransactionError::RecoverySlotsUnavailable)?;
        validate_transaction_id(self.transaction_id)
            .map_err(|_| LegacyImportTransactionError::RecoverySlotsUnavailable)?;
        validate_graph_commitments(&self.before_graph_commitment, &self.after_graph_commitment)
            .map_err(|_| LegacyImportTransactionError::RecoverySlotsUnavailable)?;
        validate_entries(&self.entries)
            .map_err(|_| LegacyImportTransactionError::RecoverySlotsUnavailable)?;
        let expected_checksum = journal_checksum(
            &self.magic,
            self.format_version,
            self.slot,
            self.generation,
            self.transaction_id,
            &self.before_graph_commitment,
            &self.after_graph_commitment,
            self.requires_blob_publication,
            self.phase,
            &self.entries,
        )
        .map_err(|_| LegacyImportTransactionError::RecoverySlotsUnavailable)?;
        if self.checksum != expected_checksum {
            return Err(LegacyImportTransactionError::RecoverySlotsUnavailable);
        }
        Ok(self)
    }
}

/// A loaded handle to the latest valid A/B generation. The path,
/// transaction UUID, and saved-host IDs are intentionally omitted from Debug.
pub(crate) struct LegacyImportTransaction {
    root: PathBuf,
    envelope: JournalEnvelope,
}

impl fmt::Debug for LegacyImportTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyImportTransaction")
            .field("phase", &self.envelope.phase)
            .field("entry_count", &self.envelope.entries.len())
            .finish_non_exhaustive()
    }
}

impl LegacyImportTransaction {
    /// Starts generation one in slot A. An existing or corrupt journal is never
    /// replaced implicitly.
    pub(crate) fn begin(
        root: impl AsRef<Path>,
        final_saved_host_ids: &[SavedHostId],
        before_graph_commitment: SavedVaultGraphCommitment,
        after_graph_commitment: SavedVaultGraphCommitment,
    ) -> Result<Self, LegacyImportTransactionError> {
        let owners = final_saved_host_ids
            .iter()
            .map(LegacyImportCredentialOwner::for_saved_host)
            .collect::<Vec<_>>();
        Self::begin_internal(
            root,
            &owners,
            before_graph_commitment,
            after_graph_commitment,
            false,
        )
    }

    /// Starts one checked transaction for any mixture of host and shared
    /// password-identity credential accounts.
    pub(crate) fn begin_for_owners(
        root: impl AsRef<Path>,
        owners: &[LegacyImportCredentialOwner],
        before_graph_commitment: SavedVaultGraphCommitment,
        after_graph_commitment: SavedVaultGraphCommitment,
    ) -> Result<Self, LegacyImportTransactionError> {
        Self::begin_internal(
            root,
            owners,
            before_graph_commitment,
            after_graph_commitment,
            false,
        )
    }

    /// Starts a transaction whose planned graph needs one or more managed
    /// secret blobs. The journal deliberately records only this boolean fact;
    /// blob locators, store identity, epochs, generations, and paths remain in
    /// their owning trusted stores. An empty credential-entry list is valid for
    /// a managed-only import.
    #[allow(dead_code)]
    pub(crate) fn begin_with_blob_publication(
        root: impl AsRef<Path>,
        final_saved_host_ids: &[SavedHostId],
        before_graph_commitment: SavedVaultGraphCommitment,
        after_graph_commitment: SavedVaultGraphCommitment,
    ) -> Result<Self, LegacyImportTransactionError> {
        let owners = final_saved_host_ids
            .iter()
            .map(LegacyImportCredentialOwner::for_saved_host)
            .collect::<Vec<_>>();
        Self::begin_internal(
            root,
            &owners,
            before_graph_commitment,
            after_graph_commitment,
            true,
        )
    }

    pub(crate) fn begin_for_owners_with_blob_publication(
        root: impl AsRef<Path>,
        owners: &[LegacyImportCredentialOwner],
        before_graph_commitment: SavedVaultGraphCommitment,
        after_graph_commitment: SavedVaultGraphCommitment,
    ) -> Result<Self, LegacyImportTransactionError> {
        Self::begin_internal(
            root,
            owners,
            before_graph_commitment,
            after_graph_commitment,
            true,
        )
    }

    fn begin_internal(
        root: impl AsRef<Path>,
        owners: &[LegacyImportCredentialOwner],
        before_graph_commitment: SavedVaultGraphCommitment,
        after_graph_commitment: SavedVaultGraphCommitment,
        requires_blob_publication: bool,
    ) -> Result<Self, LegacyImportTransactionError> {
        validate_graph_commitments(&before_graph_commitment, &after_graph_commitment)?;
        let entries = owners
            .iter()
            .cloned()
            .map(LegacyImportTransactionEntry::new)
            .collect::<Vec<_>>();
        validate_entries(&entries)?;

        let root = root.as_ref().to_path_buf();
        prepare_root(&root)?;
        match load_envelope(&root)? {
            Some(_) => return Err(LegacyImportTransactionError::ExistingTransaction),
            None => {}
        }

        let envelope = JournalEnvelope::new_with_blob_publication(
            Slot::A,
            1,
            Uuid::new_v4(),
            before_graph_commitment,
            after_graph_commitment,
            requires_blob_publication,
            LegacyImportTransactionPhase::Preparing,
            entries,
        )?;
        write_slot(&root, &envelope)?;
        Ok(Self { root, envelope })
    }

    /// Loads the highest valid generation. One damaged slot is ignored when
    /// the other validates; no valid slot plus any damaged slot fails closed.
    pub(crate) fn load(
        root: impl AsRef<Path>,
    ) -> Result<Option<Self>, LegacyImportTransactionError> {
        let root = root.as_ref().to_path_buf();
        if !root_exists_as_directory(&root)? {
            return Ok(None);
        }
        Ok(load_envelope(&root)?.map(|envelope| Self { root, envelope }))
    }

    pub(crate) fn transaction_id(&self) -> Uuid {
        self.envelope.transaction_id
    }

    pub(crate) fn before_graph_commitment(&self) -> &SavedVaultGraphCommitment {
        &self.envelope.before_graph_commitment
    }

    pub(crate) fn after_graph_commitment(&self) -> &SavedVaultGraphCommitment {
        &self.envelope.after_graph_commitment
    }

    pub(crate) const fn phase(&self) -> LegacyImportTransactionPhase {
        self.envelope.phase
    }

    #[allow(dead_code)]
    pub(crate) const fn requires_blob_publication(&self) -> bool {
        self.envelope.requires_blob_publication
    }

    pub(crate) fn entries(&self) -> &[LegacyImportTransactionEntry] {
        &self.envelope.entries
    }

    // Retained as a narrow read-only recovery/test lookup even though the
    // current integration iterates `entries()` in production.
    #[allow(dead_code)]
    pub(crate) fn entry(
        &self,
        saved_host_id: &SavedHostId,
    ) -> Option<&LegacyImportTransactionEntry> {
        let owner = LegacyImportCredentialOwner::for_saved_host(saved_host_id);
        self.entry_for_owner(&owner)
    }

    pub(crate) fn entry_for_owner(
        &self,
        owner: &LegacyImportCredentialOwner,
    ) -> Option<&LegacyImportTransactionEntry> {
        self.envelope
            .entries
            .iter()
            .find(|entry| entry_matches_owner(entry, owner))
    }

    /// Low-level preparation primitive retained for focused recovery tests.
    /// Production import uses [`Self::activate`] to avoid rewriting a large
    /// journal once per entry. Repeating the same durable fact is a no-op;
    /// changing a recorded fact or calling this after activation is rejected.
    #[allow(dead_code)]
    pub(crate) fn record_previous(
        &mut self,
        saved_host_id: &SavedHostId,
        previous: LegacyPreviousCredentialState,
    ) -> Result<(), LegacyImportTransactionError> {
        let owner = LegacyImportCredentialOwner::for_saved_host(saved_host_id);
        self.record_previous_for_owner(&owner, previous)
    }

    pub(crate) fn record_previous_for_owner(
        &mut self,
        owner: &LegacyImportCredentialOwner,
        previous: LegacyPreviousCredentialState,
    ) -> Result<(), LegacyImportTransactionError> {
        if self.envelope.phase != LegacyImportTransactionPhase::Preparing
            || previous == LegacyPreviousCredentialState::Unknown
        {
            return Err(LegacyImportTransactionError::InvalidStateTransition);
        }
        let Some(index) = self
            .envelope
            .entries
            .iter()
            .position(|entry| entry_matches_owner(entry, owner))
        else {
            return Err(LegacyImportTransactionError::UnknownCredentialOwner);
        };
        match self.envelope.entries[index].previous {
            LegacyPreviousCredentialState::Unknown => {}
            current if current == previous => return Ok(()),
            _ => return Err(LegacyImportTransactionError::InvalidStateTransition),
        }

        let mut entries = self.envelope.entries.clone();
        entries[index].previous = previous;
        self.publish_next(self.envelope.phase, entries)
    }

    /// Records that every managed secret blob needed by the planned after graph
    /// has been durably published and authenticated. Both slots must carry the
    /// fact before the caller may activate credential targets or commit Vault.
    /// Credential-only transactions cannot manufacture this phase.
    #[allow(dead_code)]
    pub(crate) fn mark_blobs_durable(&mut self) -> Result<(), LegacyImportTransactionError> {
        if !self.envelope.requires_blob_publication {
            return Err(LegacyImportTransactionError::InvalidStateTransition);
        }
        match self.envelope.phase {
            LegacyImportTransactionPhase::Preparing => {}
            LegacyImportTransactionPhase::BlobsDurable
                if both_slots_have_semantics(
                    &self.root,
                    self.envelope.transaction_id,
                    &self.envelope.before_graph_commitment,
                    &self.envelope.after_graph_commitment,
                    self.envelope.requires_blob_publication,
                    LegacyImportTransactionPhase::BlobsDurable,
                    &self.envelope.entries,
                ) =>
            {
                return Ok(());
            }
            LegacyImportTransactionPhase::BlobsDurable => {}
            LegacyImportTransactionPhase::Active
            | LegacyImportTransactionPhase::VaultDurable
            | LegacyImportTransactionPhase::RollbackTargetsRestored => {
                return Err(LegacyImportTransactionError::InvalidStateTransition);
            }
        }

        self.publish_next(
            LegacyImportTransactionPhase::BlobsDurable,
            self.envelope.entries.clone(),
        )?;
        if both_slots_have_semantics(
            &self.root,
            self.envelope.transaction_id,
            &self.envelope.before_graph_commitment,
            &self.envelope.after_graph_commitment,
            self.envelope.requires_blob_publication,
            LegacyImportTransactionPhase::BlobsDurable,
            &self.envelope.entries,
        ) {
            return Ok(());
        }
        self.publish_next(
            LegacyImportTransactionPhase::BlobsDurable,
            self.envelope.entries.clone(),
        )
    }

    /// Publishes the complete prior-state map twice before returning `Ok`.
    /// Both fixed slots therefore contain the same complete Active semantics;
    /// only after this succeeds may the caller write final credential accounts.
    /// Managed transactions cannot become Active until both blob-durable
    /// publications have completed.
    pub(crate) fn activate(
        &mut self,
        previous_states: &[(SavedHostId, LegacyPreviousCredentialState)],
    ) -> Result<(), LegacyImportTransactionError> {
        let previous_states = previous_states
            .iter()
            .map(|(saved_host_id, previous)| {
                (
                    LegacyImportCredentialOwner::for_saved_host(saved_host_id),
                    *previous,
                )
            })
            .collect::<Vec<_>>();
        self.activate_for_owners(&previous_states)
    }

    pub(crate) fn activate_for_owners(
        &mut self,
        previous_states: &[(LegacyImportCredentialOwner, LegacyPreviousCredentialState)],
    ) -> Result<(), LegacyImportTransactionError> {
        let activation_source = if self.envelope.requires_blob_publication {
            LegacyImportTransactionPhase::BlobsDurable
        } else {
            LegacyImportTransactionPhase::Preparing
        };
        if self.envelope.phase != activation_source {
            return Err(LegacyImportTransactionError::InvalidStateTransition);
        }
        if self.envelope.requires_blob_publication
            && !both_slots_have_semantics(
                &self.root,
                self.envelope.transaction_id,
                &self.envelope.before_graph_commitment,
                &self.envelope.after_graph_commitment,
                true,
                LegacyImportTransactionPhase::BlobsDurable,
                &self.envelope.entries,
            )
        {
            return Err(LegacyImportTransactionError::InvalidStateTransition);
        }

        let expected_owners = self
            .envelope
            .entries
            .iter()
            .map(entry_coordinate)
            .collect::<HashSet<_>>();
        let mut supplied = HashMap::with_capacity(previous_states.len());
        for (owner, previous) in previous_states {
            if *previous == LegacyPreviousCredentialState::Unknown {
                return Err(LegacyImportTransactionError::InvalidStateTransition);
            }
            let coordinate = owner_coordinate(owner);
            if !expected_owners.contains(&coordinate) {
                return Err(LegacyImportTransactionError::UnknownCredentialOwner);
            }
            if supplied.insert(coordinate, *previous).is_some() {
                return Err(LegacyImportTransactionError::DuplicateCredentialOwner);
            }
        }
        if supplied.len() != self.envelope.entries.len() {
            return Err(LegacyImportTransactionError::IncompletePreviousStateMap);
        }

        let mut entries = self.envelope.entries.clone();
        for entry in &mut entries {
            let coordinate = (entry.owner_kind, entry.owner_id.as_str());
            let previous = supplied
                .remove(&coordinate)
                .ok_or(LegacyImportTransactionError::IncompletePreviousStateMap)?;
            if entry.previous != LegacyPreviousCredentialState::Unknown
                && entry.previous != previous
            {
                return Err(LegacyImportTransactionError::InvalidStateTransition);
            }
            entry.previous = previous;
        }

        // A crash or error between these writes occurs before the caller is
        // authorized to mutate a target account. The first Active slot already
        // has the complete map; the older Preparing or BlobsDurable slot still
        // truthfully says that target mutation was never authorized.
        self.publish_next(LegacyImportTransactionPhase::Active, entries.clone())?;
        self.publish_next(LegacyImportTransactionPhase::Active, entries)
    }

    /// Marks that every credential rollback target represented by the journal
    /// has been restored. A repeated mark is idempotent.
    pub(crate) fn mark_rollback_targets_restored(
        &mut self,
    ) -> Result<(), LegacyImportTransactionError> {
        match self.envelope.phase {
            LegacyImportTransactionPhase::Active => {}
            LegacyImportTransactionPhase::RollbackTargetsRestored
                if both_slots_have_semantics(
                    &self.root,
                    self.envelope.transaction_id,
                    &self.envelope.before_graph_commitment,
                    &self.envelope.after_graph_commitment,
                    self.envelope.requires_blob_publication,
                    LegacyImportTransactionPhase::RollbackTargetsRestored,
                    &self.envelope.entries,
                ) =>
            {
                return Ok(());
            }
            LegacyImportTransactionPhase::RollbackTargetsRestored => {}
            LegacyImportTransactionPhase::Preparing
            | LegacyImportTransactionPhase::BlobsDurable
            | LegacyImportTransactionPhase::VaultDurable => {
                return Err(LegacyImportTransactionError::InvalidStateTransition);
            }
        }

        // Do not let callers delete backup accounts until both slots can prove
        // that all rollback targets were restored. A retry after the first
        // publication only needs to fill the remaining slot.
        self.publish_next(
            LegacyImportTransactionPhase::RollbackTargetsRestored,
            self.envelope.entries.clone(),
        )?;
        if both_slots_have_semantics(
            &self.root,
            self.envelope.transaction_id,
            &self.envelope.before_graph_commitment,
            &self.envelope.after_graph_commitment,
            self.envelope.requires_blob_publication,
            LegacyImportTransactionPhase::RollbackTargetsRestored,
            &self.envelope.entries,
        ) {
            return Ok(());
        }
        self.publish_next(
            LegacyImportTransactionPhase::RollbackTargetsRestored,
            self.envelope.entries.clone(),
        )
    }

    /// Records that the final vault has been synced and completely verified.
    /// Recovery from this phase must retain final targets and may only clean up
    /// backups and the journal. The fact is published to both slots before the
    /// first call returns, while a retry fills an interrupted first publish.
    pub(crate) fn mark_vault_durable(&mut self) -> Result<(), LegacyImportTransactionError> {
        match self.envelope.phase {
            LegacyImportTransactionPhase::Active => {}
            LegacyImportTransactionPhase::VaultDurable
                if both_slots_have_semantics(
                    &self.root,
                    self.envelope.transaction_id,
                    &self.envelope.before_graph_commitment,
                    &self.envelope.after_graph_commitment,
                    self.envelope.requires_blob_publication,
                    LegacyImportTransactionPhase::VaultDurable,
                    &self.envelope.entries,
                ) =>
            {
                return Ok(());
            }
            LegacyImportTransactionPhase::VaultDurable => {}
            LegacyImportTransactionPhase::Preparing
            | LegacyImportTransactionPhase::BlobsDurable
            | LegacyImportTransactionPhase::RollbackTargetsRestored => {
                return Err(LegacyImportTransactionError::InvalidStateTransition);
            }
        }

        self.publish_next(
            LegacyImportTransactionPhase::VaultDurable,
            self.envelope.entries.clone(),
        )?;
        if both_slots_have_semantics(
            &self.root,
            self.envelope.transaction_id,
            &self.envelope.before_graph_commitment,
            &self.envelope.after_graph_commitment,
            self.envelope.requires_blob_publication,
            LegacyImportTransactionPhase::VaultDurable,
            &self.envelope.entries,
        ) {
            return Ok(());
        }
        self.publish_next(
            LegacyImportTransactionPhase::VaultDurable,
            self.envelope.entries.clone(),
        )
    }

    /// Removes the fallback/older slot first and syncs that deletion before
    /// removing the latest slot. A crash between the two deletions therefore
    /// leaves the latest transaction visible instead of reviving stale state.
    pub(crate) fn finish(self) -> Result<(), LegacyImportTransactionError> {
        self.finish_with_after_old_deleted(|| Ok(()))
    }

    fn publish_next(
        &mut self,
        phase: LegacyImportTransactionPhase,
        entries: Vec<LegacyImportTransactionEntry>,
    ) -> Result<(), LegacyImportTransactionError> {
        let current = load_envelope_for_mutation(&self.root)?
            .ok_or(LegacyImportTransactionError::MissingTransaction)?;
        if current != self.envelope {
            return Err(LegacyImportTransactionError::ConcurrentMutation);
        }
        let generation = self
            .envelope
            .generation
            .checked_add(1)
            .ok_or(LegacyImportTransactionError::GenerationOverflow)?;
        let next = JournalEnvelope::new_with_blob_publication(
            self.envelope.slot.other(),
            generation,
            self.envelope.transaction_id,
            self.envelope.before_graph_commitment.clone(),
            self.envelope.after_graph_commitment.clone(),
            self.envelope.requires_blob_publication,
            phase,
            entries,
        )?;
        write_slot(&self.root, &next)?;
        self.envelope = next;
        Ok(())
    }

    fn finish_with_after_old_deleted<F>(
        self,
        after_old_deleted: F,
    ) -> Result<(), LegacyImportTransactionError>
    where
        F: FnOnce() -> Result<(), LegacyImportTransactionError>,
    {
        let current =
            load_envelope(&self.root)?.ok_or(LegacyImportTransactionError::MissingTransaction)?;
        if current != self.envelope {
            return Err(LegacyImportTransactionError::ConcurrentMutation);
        }

        remove_slot_if_present(&self.root, self.envelope.slot.other())?;
        sync_directory(&self.root).map_err(|_| LegacyImportTransactionError::Storage)?;
        after_old_deleted()?;
        remove_slot_if_present(&self.root, self.envelope.slot)?;
        sync_directory(&self.root).map_err(|_| LegacyImportTransactionError::Storage)
    }
}

enum SlotProbe {
    Missing,
    Valid(JournalEnvelope),
    Corrupt,
}

fn prepare_root(root: &Path) -> Result<(), LegacyImportTransactionError> {
    fs::create_dir_all(root).map_err(|_| LegacyImportTransactionError::Storage)?;
    if root_exists_as_directory(root)? {
        Ok(())
    } else {
        Err(LegacyImportTransactionError::InvalidLayout)
    }
}

fn root_exists_as_directory(root: &Path) -> Result<bool, LegacyImportTransactionError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            Ok(true)
        }
        Ok(_) => Err(LegacyImportTransactionError::InvalidLayout),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(LegacyImportTransactionError::Storage),
    }
}

fn load_envelope(root: &Path) -> Result<Option<JournalEnvelope>, LegacyImportTransactionError> {
    load_envelope_internal(root)
}

fn load_envelope_for_mutation(
    root: &Path,
) -> Result<Option<JournalEnvelope>, LegacyImportTransactionError> {
    load_envelope_internal(root)
}

fn load_envelope_internal(
    root: &Path,
) -> Result<Option<JournalEnvelope>, LegacyImportTransactionError> {
    let a = probe_slot(root, Slot::A);
    let b = probe_slot(root, Slot::B);
    match (a, b) {
        (SlotProbe::Missing, SlotProbe::Missing) => Ok(None),
        (SlotProbe::Valid(left), SlotProbe::Valid(right)) => {
            validate_slot_pair(&left, &right)?;
            if left.generation > right.generation {
                Ok(Some(left))
            } else {
                Ok(Some(right))
            }
        }
        (SlotProbe::Valid(envelope), SlotProbe::Missing | SlotProbe::Corrupt)
        | (SlotProbe::Missing | SlotProbe::Corrupt, SlotProbe::Valid(envelope)) => {
            Ok(Some(envelope))
        }
        (SlotProbe::Corrupt, SlotProbe::Corrupt)
        | (SlotProbe::Corrupt, SlotProbe::Missing)
        | (SlotProbe::Missing, SlotProbe::Corrupt) => {
            Err(LegacyImportTransactionError::RecoverySlotsUnavailable)
        }
    }
}

fn validate_slot_pair(
    left: &JournalEnvelope,
    right: &JournalEnvelope,
) -> Result<(), LegacyImportTransactionError> {
    if left.transaction_id != right.transaction_id
        || left.before_graph_commitment != right.before_graph_commitment
        || left.after_graph_commitment != right.after_graph_commitment
        || left.requires_blob_publication != right.requires_blob_publication
        || left.generation.abs_diff(right.generation) != 1
    {
        return Err(LegacyImportTransactionError::RecoverySlotsUnavailable);
    }

    if left.entries.len() != right.entries.len()
        || !left
            .entries
            .iter()
            .zip(&right.entries)
            .all(|(left, right)| entry_coordinate(left) == entry_coordinate(right))
    {
        return Err(LegacyImportTransactionError::RecoverySlotsUnavailable);
    }

    let (older, newer) = if left.generation < right.generation {
        (left, right)
    } else {
        (right, left)
    };
    // A recovered v2/v3/v4/v5 transaction may be advanced by current code,
    // which writes v6. The reverse direction is never legitimate.
    if older.format_version > newer.format_version {
        return Err(LegacyImportTransactionError::RecoverySlotsUnavailable);
    }
    let requires_blobs = newer.requires_blob_publication;
    let transition_is_valid = match (older.phase, newer.phase) {
        (LegacyImportTransactionPhase::Preparing, LegacyImportTransactionPhase::Preparing) => {
            preparing_entries_advance_once(&older.entries, &newer.entries)
        }
        (LegacyImportTransactionPhase::Preparing, LegacyImportTransactionPhase::Active) => {
            !requires_blobs && preparing_entries_activate(&older.entries, &newer.entries)
        }
        (LegacyImportTransactionPhase::Preparing, LegacyImportTransactionPhase::BlobsDurable) => {
            requires_blobs && older.entries == newer.entries
        }
        (
            LegacyImportTransactionPhase::BlobsDurable,
            LegacyImportTransactionPhase::BlobsDurable,
        ) => requires_blobs && older.entries == newer.entries,
        (LegacyImportTransactionPhase::BlobsDurable, LegacyImportTransactionPhase::Active) => {
            requires_blobs && preparing_entries_activate(&older.entries, &newer.entries)
        }
        (LegacyImportTransactionPhase::Active, LegacyImportTransactionPhase::Active)
        | (
            LegacyImportTransactionPhase::Active,
            LegacyImportTransactionPhase::RollbackTargetsRestored,
        )
        | (
            LegacyImportTransactionPhase::RollbackTargetsRestored,
            LegacyImportTransactionPhase::RollbackTargetsRestored,
        )
        | (LegacyImportTransactionPhase::Active, LegacyImportTransactionPhase::VaultDurable)
        | (
            LegacyImportTransactionPhase::VaultDurable,
            LegacyImportTransactionPhase::VaultDurable,
        ) => older.entries == newer.entries,
        _ => false,
    };
    if transition_is_valid {
        Ok(())
    } else {
        Err(LegacyImportTransactionError::RecoverySlotsUnavailable)
    }
}

fn preparing_entries_advance_once(
    older: &[LegacyImportTransactionEntry],
    newer: &[LegacyImportTransactionEntry],
) -> bool {
    let mut advances = 0;
    for (older, newer) in older.iter().zip(newer) {
        match (older.previous, newer.previous) {
            (left, right) if left == right => {}
            (LegacyPreviousCredentialState::Unknown, right)
                if right != LegacyPreviousCredentialState::Unknown =>
            {
                advances += 1;
            }
            _ => return false,
        }
    }
    advances == 1
}

fn preparing_entries_activate(
    older: &[LegacyImportTransactionEntry],
    newer: &[LegacyImportTransactionEntry],
) -> bool {
    older.iter().zip(newer).all(|(older, newer)| {
        newer.previous != LegacyPreviousCredentialState::Unknown
            && (older.previous == LegacyPreviousCredentialState::Unknown
                || older.previous == newer.previous)
    })
}

fn deserialize_envelope(encoded: &[u8]) -> Option<JournalEnvelope> {
    let format = serde_json::from_slice::<JournalFormatProbe>(encoded).ok()?;
    match format.format_version {
        LEGACY_JOURNAL_FORMAT_VERSION => {
            let envelope = serde_json::from_slice::<JournalEnvelopeV2>(encoded).ok()?;
            Some(JournalEnvelope {
                magic: envelope.magic,
                format_version: envelope.format_version,
                slot: envelope.slot,
                generation: envelope.generation,
                transaction_id: envelope.transaction_id,
                before_graph_commitment: envelope.before_graph_commitment,
                after_graph_commitment: envelope.after_graph_commitment,
                requires_blob_publication: false,
                phase: envelope.phase.into(),
                entries: envelope
                    .entries
                    .into_iter()
                    .map(LegacyJournalEntryV2V3::into_current)
                    .collect(),
                checksum: envelope.checksum,
            })
        }
        BLOB_JOURNAL_FORMAT_VERSION => {
            let envelope = serde_json::from_slice::<JournalEnvelopeV3>(encoded).ok()?;
            Some(JournalEnvelope {
                magic: envelope.magic,
                format_version: envelope.format_version,
                slot: envelope.slot,
                generation: envelope.generation,
                transaction_id: envelope.transaction_id,
                before_graph_commitment: envelope.before_graph_commitment,
                after_graph_commitment: envelope.after_graph_commitment,
                requires_blob_publication: envelope.requires_blob_publication,
                phase: envelope.phase,
                entries: envelope
                    .entries
                    .into_iter()
                    .map(LegacyJournalEntryV2V3::into_current)
                    .collect(),
                checksum: envelope.checksum,
            })
        }
        OWNER_JOURNAL_FORMAT_VERSION => {
            let envelope = serde_json::from_slice::<JournalEnvelopeV4>(encoded).ok()?;
            Some(JournalEnvelope {
                magic: envelope.magic,
                format_version: envelope.format_version,
                slot: envelope.slot,
                generation: envelope.generation,
                transaction_id: envelope.transaction_id,
                before_graph_commitment: envelope.before_graph_commitment,
                after_graph_commitment: envelope.after_graph_commitment,
                requires_blob_publication: envelope.requires_blob_publication,
                phase: envelope.phase,
                entries: envelope
                    .entries
                    .into_iter()
                    .map(LegacyJournalEntryV4::into_current)
                    .collect(),
                checksum: envelope.checksum,
            })
        }
        PROXY_JOURNAL_FORMAT_VERSION => {
            let envelope = serde_json::from_slice::<JournalEnvelopeV5>(encoded).ok()?;
            Some(JournalEnvelope {
                magic: envelope.magic,
                format_version: envelope.format_version,
                slot: envelope.slot,
                generation: envelope.generation,
                transaction_id: envelope.transaction_id,
                before_graph_commitment: envelope.before_graph_commitment,
                after_graph_commitment: envelope.after_graph_commitment,
                requires_blob_publication: envelope.requires_blob_publication,
                phase: envelope.phase,
                entries: envelope
                    .entries
                    .into_iter()
                    .map(LegacyJournalEntryV5::into_current)
                    .collect(),
                checksum: envelope.checksum,
            })
        }
        JOURNAL_FORMAT_VERSION => {
            let envelope = serde_json::from_slice::<JournalEnvelopeV6>(encoded).ok()?;
            Some(JournalEnvelope {
                magic: envelope.magic,
                format_version: envelope.format_version,
                slot: envelope.slot,
                generation: envelope.generation,
                transaction_id: envelope.transaction_id,
                before_graph_commitment: envelope.before_graph_commitment,
                after_graph_commitment: envelope.after_graph_commitment,
                requires_blob_publication: envelope.requires_blob_publication,
                phase: envelope.phase,
                entries: envelope.entries,
                checksum: envelope.checksum,
            })
        }
        _ => None,
    }
}

fn probe_slot(root: &Path, slot: Slot) -> SlotProbe {
    let path = root.join(slot.file_name());
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return SlotProbe::Missing,
        Err(_) => return SlotProbe::Corrupt,
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_JOURNAL_BYTES
    {
        return SlotProbe::Corrupt;
    }
    let encoded = match read_bounded(&path, MAX_JOURNAL_BYTES) {
        Ok(encoded) => encoded,
        Err(_) => return SlotProbe::Corrupt,
    };
    let envelope = match deserialize_envelope(&encoded) {
        Some(envelope) => envelope,
        None => return SlotProbe::Corrupt,
    };
    match envelope.validate(slot) {
        Ok(envelope) => SlotProbe::Valid(envelope),
        Err(_) => SlotProbe::Corrupt,
    }
}

fn both_slots_have_semantics(
    root: &Path,
    transaction_id: Uuid,
    before_graph_commitment: &SavedVaultGraphCommitment,
    after_graph_commitment: &SavedVaultGraphCommitment,
    requires_blob_publication: bool,
    phase: LegacyImportTransactionPhase,
    entries: &[LegacyImportTransactionEntry],
) -> bool {
    let (SlotProbe::Valid(left), SlotProbe::Valid(right)) =
        (probe_slot(root, Slot::A), probe_slot(root, Slot::B))
    else {
        return false;
    };
    validate_slot_pair(&left, &right).is_ok()
        && [left, right].into_iter().all(|envelope| {
            envelope.transaction_id == transaction_id
                && &envelope.before_graph_commitment == before_graph_commitment
                && &envelope.after_graph_commitment == after_graph_commitment
                && envelope.requires_blob_publication == requires_blob_publication
                && envelope.phase == phase
                && envelope.entries == entries
        })
}

fn validate_transaction_id(transaction_id: Uuid) -> Result<(), LegacyImportTransactionError> {
    if transaction_id.get_version() == Some(Version::Random) {
        Ok(())
    } else {
        Err(LegacyImportTransactionError::InvalidStateTransition)
    }
}

fn validate_graph_commitments(
    before: &SavedVaultGraphCommitment,
    after: &SavedVaultGraphCommitment,
) -> Result<(), LegacyImportTransactionError> {
    if before == after {
        Err(LegacyImportTransactionError::InvalidStateTransition)
    } else {
        Ok(())
    }
}

fn validate_phase_for_format(
    format_version: u32,
    requires_blob_publication: bool,
    phase: LegacyImportTransactionPhase,
) -> Result<(), LegacyImportTransactionError> {
    match format_version {
        LEGACY_JOURNAL_FORMAT_VERSION
            if !requires_blob_publication
                && phase != LegacyImportTransactionPhase::BlobsDurable =>
        {
            Ok(())
        }
        BLOB_JOURNAL_FORMAT_VERSION
        | OWNER_JOURNAL_FORMAT_VERSION
        | PROXY_JOURNAL_FORMAT_VERSION
        | JOURNAL_FORMAT_VERSION
            if requires_blob_publication || phase != LegacyImportTransactionPhase::BlobsDurable =>
        {
            Ok(())
        }
        _ => Err(LegacyImportTransactionError::InvalidStateTransition),
    }
}

fn validate_entries(
    entries: &[LegacyImportTransactionEntry],
) -> Result<(), LegacyImportTransactionError> {
    if entries.len() > MAX_ENTRIES {
        return Err(LegacyImportTransactionError::TooManyEntries);
    }
    let mut owners = HashSet::with_capacity(entries.len());
    for entry in entries {
        SavedHostId::from_opaque(entry.owner_id.as_str().to_owned())
            .map_err(|_| LegacyImportTransactionError::InvalidStateTransition)?;
        if !owners.insert(entry_coordinate(entry)) {
            return Err(LegacyImportTransactionError::DuplicateCredentialOwner);
        }
    }
    Ok(())
}

fn entry_coordinate(
    entry: &LegacyImportTransactionEntry,
) -> (LegacyImportCredentialOwnerKind, &str) {
    (entry.owner_kind, entry.owner_id.as_str())
}

fn owner_coordinate(
    owner: &LegacyImportCredentialOwner,
) -> (LegacyImportCredentialOwnerKind, &str) {
    (owner.kind, owner.id.as_str())
}

fn entry_matches_owner(
    entry: &LegacyImportTransactionEntry,
    owner: &LegacyImportCredentialOwner,
) -> bool {
    entry_coordinate(entry) == owner_coordinate(owner)
}

fn journal_checksum(
    magic: &str,
    format_version: u32,
    slot: Slot,
    generation: u64,
    transaction_id: Uuid,
    before_graph_commitment: &SavedVaultGraphCommitment,
    after_graph_commitment: &SavedVaultGraphCommitment,
    requires_blob_publication: bool,
    phase: LegacyImportTransactionPhase,
    entries: &[LegacyImportTransactionEntry],
) -> Result<String, LegacyImportTransactionError> {
    let encoded = match format_version {
        LEGACY_JOURNAL_FORMAT_VERSION => {
            if requires_blob_publication {
                return Err(LegacyImportTransactionError::Serialization);
            }
            let phase = LegacyJournalPhaseV2::try_from(phase)
                .map_err(|_| LegacyImportTransactionError::Serialization)?;
            let legacy_entries = legacy_entries(entries)?;
            serde_json::to_vec(&ChecksumPayloadV2 {
                magic,
                format_version,
                slot,
                generation,
                transaction_id,
                before_graph_commitment,
                after_graph_commitment,
                phase,
                entries: &legacy_entries,
            })
        }
        BLOB_JOURNAL_FORMAT_VERSION => {
            let legacy_entries = legacy_entries(entries)?;
            serde_json::to_vec(&ChecksumPayloadV3 {
                magic,
                format_version,
                slot,
                generation,
                transaction_id,
                before_graph_commitment,
                after_graph_commitment,
                requires_blob_publication,
                phase,
                entries: &legacy_entries,
            })
        }
        OWNER_JOURNAL_FORMAT_VERSION => {
            let entries = v4_entries(entries)?;
            serde_json::to_vec(&ChecksumPayloadV4 {
                magic,
                format_version,
                slot,
                generation,
                transaction_id,
                before_graph_commitment,
                after_graph_commitment,
                requires_blob_publication,
                phase,
                entries: &entries,
            })
        }
        PROXY_JOURNAL_FORMAT_VERSION => {
            let entries = v5_entries(entries)?;
            serde_json::to_vec(&ChecksumPayloadV5 {
                magic,
                format_version,
                slot,
                generation,
                transaction_id,
                before_graph_commitment,
                after_graph_commitment,
                requires_blob_publication,
                phase,
                entries: &entries,
            })
        }
        JOURNAL_FORMAT_VERSION => serde_json::to_vec(&ChecksumPayloadV6 {
            magic,
            format_version,
            slot,
            generation,
            transaction_id,
            before_graph_commitment,
            after_graph_commitment,
            requires_blob_publication,
            phase,
            entries,
        }),
        _ => return Err(LegacyImportTransactionError::Serialization),
    }
    .map_err(|_| LegacyImportTransactionError::Serialization)?;
    Ok(hex_digest(&encoded))
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn write_slot(root: &Path, envelope: &JournalEnvelope) -> Result<(), LegacyImportTransactionError> {
    write_slot_with_after_sync(root, envelope, |_| Ok(()))
}

fn write_slot_with_after_sync<F>(
    root: &Path,
    envelope: &JournalEnvelope,
    after_sync: F,
) -> Result<(), LegacyImportTransactionError>
where
    F: FnOnce(&Path) -> Result<(), LegacyImportTransactionError>,
{
    if !root_exists_as_directory(root)? {
        return Err(LegacyImportTransactionError::InvalidLayout);
    }
    let encoded =
        serde_json::to_vec(envelope).map_err(|_| LegacyImportTransactionError::Serialization)?;
    if encoded.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(LegacyImportTransactionError::JournalTooLarge);
    }

    let temp_path = root.join(format!(
        ".legacy-credential-import-transaction-{}.tmp",
        Uuid::new_v4().simple()
    ));
    let final_path = root.join(envelope.slot.file_name());
    let publication = (|| -> Result<(), LegacyImportTransactionError> {
        let mut temp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|_| LegacyImportTransactionError::Storage)?;
        temp.write_all(&encoded)
            .map_err(|_| LegacyImportTransactionError::Storage)?;
        temp.sync_all()
            .map_err(|_| LegacyImportTransactionError::Storage)?;
        drop(temp);

        remove_slot_if_present(root, envelope.slot)?;
        fs::rename(&temp_path, &final_path).map_err(|_| LegacyImportTransactionError::Storage)?;
        sync_directory(root).map_err(|_| LegacyImportTransactionError::Storage)?;
        after_sync(&final_path)?;
        Ok(())
    })();
    if publication.is_err() {
        let _ = fs::remove_file(&temp_path);
        return publication;
    }

    match probe_slot(root, envelope.slot) {
        SlotProbe::Valid(actual) if actual == *envelope => Ok(()),
        SlotProbe::Missing | SlotProbe::Corrupt | SlotProbe::Valid(_) => {
            Err(LegacyImportTransactionError::PublicationVerificationFailed)
        }
    }
}

fn remove_slot_if_present(root: &Path, slot: Slot) -> Result<(), LegacyImportTransactionError> {
    let path = root.join(slot.file_name());
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path).map_err(|_| LegacyImportTransactionError::Storage)
        }
        Ok(_) => Err(LegacyImportTransactionError::InvalidLayout),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(LegacyImportTransactionError::Storage),
    }
}

fn read_bounded(path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal is too large",
        ));
    }
    let mut encoded = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(max_bytes + 1)
        .read_to_end(&mut encoded)?;
    if encoded.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal is too large",
        ));
    }
    Ok(encoded)
}

#[cfg(windows)]
fn sync_directory(path: &Path) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    match directory.sync_all() {
        Ok(()) => Ok(()),
        Err(error) if matches!(error.raw_os_error(), Some(1 | 5 | 50 | 87)) => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(not(windows))]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::{
        BLOB_JOURNAL_FORMAT_VERSION, JOURNAL_FORMAT_VERSION, JournalEnvelope,
        LEGACY_JOURNAL_FORMAT_VERSION, LegacyImportCredentialOwner,
        LegacyImportCredentialOwnerKind, LegacyImportTransaction, LegacyImportTransactionEntry,
        LegacyImportTransactionError, LegacyImportTransactionPhase, LegacyPreviousCredentialState,
        MAX_ENTRIES, MAX_JOURNAL_BYTES, MAX_JSON_ESCAPED_OWNER_ID_BYTES, MAX_OWNER_ID_BYTES,
        OWNER_JOURNAL_FORMAT_VERSION, PROXY_JOURNAL_FORMAT_VERSION, SLOT_A_FILE, SLOT_B_FILE, Slot,
        SlotProbe, journal_checksum, probe_slot, write_slot, write_slot_with_after_sync,
    };
    use netcatty_vault::{SavedHostId, SavedVaultGraphCommitment};
    use serde_json::Value;
    use std::fs;

    fn saved_host_id(value: &str) -> SavedHostId {
        SavedHostId::from_opaque(value).expect("test saved-host ID")
    }

    fn maximally_json_escaped_saved_host_id(index: usize) -> SavedHostId {
        assert!(index < (1 << 14), "test index must fit the escape pattern");
        let mut value = String::with_capacity(MAX_OWNER_ID_BYTES);
        for bit in 0..MAX_OWNER_ID_BYTES {
            value.push(if bit < 14 && index & (1 << bit) != 0 {
                '\\'
            } else {
                '"'
            });
        }
        assert_eq!(value.len(), MAX_OWNER_ID_BYTES);
        saved_host_id(&value)
    }

    fn host_entry(
        id: SavedHostId,
        previous: LegacyPreviousCredentialState,
    ) -> LegacyImportTransactionEntry {
        LegacyImportTransactionEntry {
            owner_kind: LegacyImportCredentialOwnerKind::Host,
            owner_id: id,
            previous,
        }
    }

    fn graph_commitment(marker: u8) -> SavedVaultGraphCommitment {
        SavedVaultGraphCommitment::from_digest([marker; 32])
    }

    fn begin_transaction(
        root: impl AsRef<std::path::Path>,
        final_saved_host_ids: &[SavedHostId],
    ) -> Result<LegacyImportTransaction, LegacyImportTransactionError> {
        LegacyImportTransaction::begin(
            root,
            final_saved_host_ids,
            graph_commitment(0x11),
            graph_commitment(0x22),
        )
    }

    fn begin_blob_transaction(
        root: impl AsRef<std::path::Path>,
        final_saved_host_ids: &[SavedHostId],
    ) -> Result<LegacyImportTransaction, LegacyImportTransactionError> {
        LegacyImportTransaction::begin_with_blob_publication(
            root,
            final_saved_host_ids,
            graph_commitment(0x11),
            graph_commitment(0x22),
        )
    }

    fn entry_state(
        transaction: &LegacyImportTransaction,
        id: &SavedHostId,
    ) -> LegacyPreviousCredentialState {
        transaction.entry(id).expect("transaction entry").previous()
    }

    fn valid_envelope(root: &std::path::Path, slot: Slot) -> JournalEnvelope {
        match probe_slot(root, slot) {
            SlotProbe::Valid(envelope) => envelope,
            SlotProbe::Missing | SlotProbe::Corrupt => panic!("expected valid journal slot"),
        }
    }

    fn rewrite_checked_envelope(root: &std::path::Path, envelope: &mut JournalEnvelope) {
        envelope.checksum = journal_checksum(
            &envelope.magic,
            envelope.format_version,
            envelope.slot,
            envelope.generation,
            envelope.transaction_id,
            &envelope.before_graph_commitment,
            &envelope.after_graph_commitment,
            envelope.requires_blob_publication,
            envelope.phase,
            &envelope.entries,
        )
        .expect("recompute test checksum");
        fs::write(
            root.join(envelope.slot.file_name()),
            serde_json::to_vec(envelope).expect("encode test envelope"),
        )
        .expect("rewrite test envelope");
    }

    #[test]
    fn begin_and_load_publish_a_secret_free_checked_generation() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let root = temporary.path().join("journal-path-sentinel");
        let first = saved_host_id("final-host-id-sentinel-a");
        let second = saved_host_id("final-host-id-sentinel-b");
        let transaction =
            begin_transaction(&root, &[first.clone(), second.clone()]).expect("begin transaction");

        assert_eq!(transaction.phase(), LegacyImportTransactionPhase::Preparing);
        assert!(!transaction.requires_blob_publication());
        assert_eq!(transaction.entries().len(), 2);
        assert_eq!(
            transaction.before_graph_commitment(),
            &graph_commitment(0x11)
        );
        assert_eq!(
            transaction.after_graph_commitment(),
            &graph_commitment(0x22)
        );
        assert_eq!(
            entry_state(&transaction, &first),
            LegacyPreviousCredentialState::Unknown
        );
        assert_eq!(
            transaction.transaction_id().get_version(),
            Some(uuid::Version::Random)
        );
        assert!(root.join(SLOT_A_FILE).is_file());
        assert!(!root.join(SLOT_B_FILE).exists());

        let persisted = fs::read_to_string(root.join(SLOT_A_FILE)).expect("journal JSON");
        let value: Value = serde_json::from_str(&persisted).expect("journal object");
        assert_eq!(value["formatVersion"], JOURNAL_FORMAT_VERSION);
        assert_eq!(value["generation"], 1);
        assert_eq!(value["slot"], "a");
        assert_eq!(value["phase"], "preparing");
        assert_eq!(value["requiresBlobPublication"], false);
        assert_eq!(value["entries"][0]["ownerKind"], "host");
        assert_eq!(value["entries"][0]["ownerId"], first.as_str());
        assert!(value["entries"][0].get("savedHostId").is_none());
        assert_eq!(value["checksum"].as_str().expect("checksum").len(), 64);
        for (field, expected) in [
            ("beforeGraphCommitment", graph_commitment(0x11)),
            ("afterGraphCommitment", graph_commitment(0x22)),
        ] {
            let encoded = value[field].as_str().expect("graph commitment");
            assert_eq!(encoded, expected.as_str());
            assert_eq!(encoded.len(), 64);
            assert!(
                encoded
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            );
        }
        for forbidden in [
            "password",
            "secret",
            "credentialReference",
            "backupAccount",
            "backendLocator",
            "storeUuid",
            "masterKeyEpoch",
            "blobGeneration",
            "blobPath",
            "secret-value-sentinel",
            "graph-json-sentinel",
        ] {
            assert!(!persisted.contains(forbidden));
        }

        let debug = format!("{transaction:?}");
        let transaction_id = transaction.transaction_id().to_string();
        let root_display = root.display().to_string();
        let before_digest = graph_commitment(0x11).as_str().to_owned();
        let after_digest = graph_commitment(0x22).as_str().to_owned();
        for forbidden in [
            first.as_str(),
            second.as_str(),
            transaction_id.as_str(),
            root_display.as_str(),
            before_digest.as_str(),
            after_digest.as_str(),
            "graph-json-sentinel",
            "secret-value-sentinel",
        ] {
            assert!(!debug.contains(forbidden));
        }

        let loaded = LegacyImportTransaction::load(&root)
            .expect("load transaction")
            .expect("active transaction");
        assert_eq!(loaded.transaction_id(), transaction.transaction_id());
        assert_eq!(loaded.entries().len(), 2);
        assert_eq!(loaded.entries()[0].saved_host_id().as_str(), first.as_str());
    }

    #[test]
    fn begin_rejects_equal_graph_commitments_before_creating_the_journal() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let root = temporary.path().join("equal-commitment-journal");
        let id = saved_host_id("equal-commitment-host-id-sentinel");
        let commitment = graph_commitment(0x41);

        let error = LegacyImportTransaction::begin(
            &root,
            std::slice::from_ref(&id),
            commitment.clone(),
            commitment.clone(),
        )
        .expect_err("equal before/after commitments must fail");

        assert_eq!(error, LegacyImportTransactionError::InvalidStateTransition);
        assert!(!root.exists());
        assert!(!root_has_slot(&root));
        let diagnostics = format!("{error:?} {error}");
        assert!(!diagnostics.contains(commitment.as_str()));
        assert!(!diagnostics.contains(id.as_str()));
        assert!(!diagnostics.contains(&root.display().to_string()));
    }

    #[test]
    fn graph_commitments_are_checksum_bound_and_must_match_across_slots() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let root = temporary.path().join("commitment-integrity");
        let id = saved_host_id("commitment-integrity-host-id-sentinel");
        let mut transaction = begin_transaction(&root, std::slice::from_ref(&id))
            .expect("begin commitment-integrity transaction");
        transaction
            .record_previous(&id, LegacyPreviousCredentialState::Absent)
            .expect("publish second slot");

        let original_b = fs::read(root.join(SLOT_B_FILE)).expect("original slot B");
        let mut unchecked: Value = serde_json::from_slice(&original_b).expect("slot B JSON object");
        unchecked["afterGraphCommitment"] =
            Value::String(graph_commitment(0x44).as_str().to_owned());
        fs::write(
            root.join(SLOT_B_FILE),
            serde_json::to_vec(&unchecked).expect("tampered slot B JSON"),
        )
        .expect("tamper commitment without checksum");
        assert!(matches!(probe_slot(&root, Slot::B), SlotProbe::Corrupt));
        let fallback = LegacyImportTransaction::load(&root)
            .expect("fall back from checksum-bound commitment tampering")
            .expect("slot A survives");
        assert_eq!(fallback.envelope.generation, 1);
        assert_eq!(fallback.before_graph_commitment(), &graph_commitment(0x11));
        assert_eq!(fallback.after_graph_commitment(), &graph_commitment(0x22));

        fs::write(root.join(SLOT_B_FILE), &original_b).expect("restore slot B");
        let mut forged = valid_envelope(&root, Slot::B);
        forged.before_graph_commitment = graph_commitment(0x33);
        rewrite_checked_envelope(&root, &mut forged);
        assert!(matches!(
            LegacyImportTransaction::load(&root),
            Err(LegacyImportTransactionError::RecoverySlotsUnavailable)
        ));

        fs::write(root.join(SLOT_B_FILE), &original_b).expect("restore slot B again");
        let mut swapped = valid_envelope(&root, Slot::B);
        let original_before = swapped.before_graph_commitment.clone();
        swapped.before_graph_commitment = swapped.after_graph_commitment.clone();
        swapped.after_graph_commitment = original_before;
        rewrite_checked_envelope(&root, &mut swapped);
        assert!(matches!(
            LegacyImportTransaction::load(&root),
            Err(LegacyImportTransactionError::RecoverySlotsUnavailable)
        ));
    }

    #[test]
    fn version_one_or_missing_commitment_fields_fail_closed_without_sensitive_diagnostics() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let root = temporary.path().join("legacy-format-path-sentinel");
        let id = saved_host_id("legacy-format-host-id-sentinel");
        let transaction = begin_transaction(&root, std::slice::from_ref(&id))
            .expect("begin current-format transaction");
        let before_digest = transaction.before_graph_commitment().as_str().to_owned();
        let after_digest = transaction.after_graph_commitment().as_str().to_owned();
        let mut legacy: Value = serde_json::from_slice(
            &fs::read(root.join(SLOT_A_FILE)).expect("current-format journal bytes"),
        )
        .expect("current-format journal JSON");
        legacy["formatVersion"] = Value::from(1);
        let object = legacy.as_object_mut().expect("journal JSON object");
        object.remove("beforeGraphCommitment");
        object.remove("afterGraphCommitment");
        fs::write(
            root.join(SLOT_A_FILE),
            serde_json::to_vec(&legacy).expect("legacy journal JSON"),
        )
        .expect("write legacy journal");

        let error = LegacyImportTransaction::load(&root)
            .expect_err("version one without commitments must fail closed");
        assert_eq!(
            error,
            LegacyImportTransactionError::RecoverySlotsUnavailable
        );
        let diagnostics = format!("{transaction:?} {error:?} {error}");
        for forbidden in [
            id.as_str(),
            before_digest.as_str(),
            after_digest.as_str(),
            "graph-json-sentinel",
            "secret-value-sentinel",
        ] {
            assert!(!diagnostics.contains(forbidden));
        }
        assert!(!diagnostics.contains(&root.display().to_string()));
    }

    #[test]
    fn credential_only_v2_journals_load_in_every_legacy_phase_and_upgrade_on_write() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let id = saved_host_id("legacy-v2-compatible-host");

        for (index, phase) in [
            LegacyImportTransactionPhase::Preparing,
            LegacyImportTransactionPhase::Active,
            LegacyImportTransactionPhase::VaultDurable,
            LegacyImportTransactionPhase::RollbackTargetsRestored,
        ]
        .into_iter()
        .enumerate()
        {
            let root = temporary.path().join(format!("legacy-v2-phase-{index}"));
            fs::create_dir(&root).expect("create legacy-v2 journal root");
            let (slot, generation) = if phase == LegacyImportTransactionPhase::Preparing {
                (Slot::A, 1)
            } else {
                (Slot::B, 2)
            };
            let previous = if phase == LegacyImportTransactionPhase::Preparing {
                LegacyPreviousCredentialState::Unknown
            } else {
                LegacyPreviousCredentialState::BackedUp
            };
            let mut envelope = JournalEnvelope::new(
                slot,
                generation,
                uuid::Uuid::new_v4(),
                graph_commitment(0x61),
                graph_commitment(0x62),
                phase,
                vec![host_entry(id.clone(), previous)],
            )
            .expect("construct legacy-v2 compatibility envelope");
            envelope.format_version = LEGACY_JOURNAL_FORMAT_VERSION;
            rewrite_checked_envelope(&root, &mut envelope);

            let persisted = fs::read_to_string(root.join(slot.file_name()))
                .expect("read legacy-v2 compatibility envelope");
            let value: Value = serde_json::from_str(&persisted).expect("legacy-v2 JSON");
            assert_eq!(value["formatVersion"], LEGACY_JOURNAL_FORMAT_VERSION);
            assert!(value.get("requiresBlobPublication").is_none());

            let loaded = LegacyImportTransaction::load(&root)
                .expect("load legacy-v2 journal")
                .expect("legacy-v2 transaction");
            assert_eq!(loaded.phase(), phase);
            assert!(!loaded.requires_blob_publication());
        }

        let upgrade_root = temporary.path().join("legacy-v2-upgrade");
        fs::create_dir(&upgrade_root).expect("create legacy-v2 upgrade root");
        let mut legacy = JournalEnvelope::new(
            Slot::A,
            1,
            uuid::Uuid::new_v4(),
            graph_commitment(0x63),
            graph_commitment(0x64),
            LegacyImportTransactionPhase::Preparing,
            vec![host_entry(
                id.clone(),
                LegacyPreviousCredentialState::Unknown,
            )],
        )
        .expect("construct upgradable legacy-v2 envelope");
        legacy.format_version = LEGACY_JOURNAL_FORMAT_VERSION;
        rewrite_checked_envelope(&upgrade_root, &mut legacy);

        let mut upgraded = LegacyImportTransaction::load(&upgrade_root)
            .expect("load upgradable v2 journal")
            .expect("upgradable transaction");
        upgraded
            .record_previous(&id, LegacyPreviousCredentialState::Absent)
            .expect("advance recovered v2 journal");
        assert_eq!(upgraded.envelope.format_version, JOURNAL_FORMAT_VERSION);
        assert_eq!(upgraded.envelope.generation, 2);
        let old_value: Value = serde_json::from_slice(
            &fs::read(upgrade_root.join(SLOT_A_FILE)).expect("legacy-v2 slot"),
        )
        .expect("legacy-v2 slot JSON");
        let new_value: Value = serde_json::from_slice(
            &fs::read(upgrade_root.join(SLOT_B_FILE)).expect("upgraded-v6 slot"),
        )
        .expect("upgraded-v6 slot JSON");
        assert_eq!(old_value["formatVersion"], LEGACY_JOURNAL_FORMAT_VERSION);
        assert!(old_value.get("requiresBlobPublication").is_none());
        assert_eq!(new_value["formatVersion"], JOURNAL_FORMAT_VERSION);
        assert_eq!(new_value["requiresBlobPublication"], false);
        upgraded
            .activate(&[(id, LegacyPreviousCredentialState::Absent)])
            .expect("activate upgraded credential-only journal");
        assert_eq!(upgraded.phase(), LegacyImportTransactionPhase::Active);
        for slot in [Slot::A, Slot::B] {
            assert_eq!(
                valid_envelope(&upgrade_root, slot).format_version,
                JOURNAL_FORMAT_VERSION
            );
        }
    }

    #[test]
    fn v3_journals_keep_the_legacy_host_shape_and_upgrade_to_v6_on_write() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let root = temporary.path().join("v3-upgrade");
        fs::create_dir(&root).expect("create v3 journal root");
        let id = saved_host_id("v3-compatible-host");
        let mut legacy = JournalEnvelope::new_with_blob_publication(
            Slot::A,
            1,
            uuid::Uuid::new_v4(),
            graph_commitment(0x65),
            graph_commitment(0x66),
            false,
            LegacyImportTransactionPhase::Preparing,
            vec![host_entry(
                id.clone(),
                LegacyPreviousCredentialState::Unknown,
            )],
        )
        .expect("construct v3 envelope");
        legacy.format_version = BLOB_JOURNAL_FORMAT_VERSION;
        rewrite_checked_envelope(&root, &mut legacy);

        let old_value: Value =
            serde_json::from_slice(&fs::read(root.join(SLOT_A_FILE)).expect("read v3 slot"))
                .expect("v3 JSON");
        assert_eq!(old_value["formatVersion"], BLOB_JOURNAL_FORMAT_VERSION);
        assert_eq!(old_value["requiresBlobPublication"], false);
        assert_eq!(old_value["entries"][0]["savedHostId"], id.as_str());
        assert!(old_value["entries"][0].get("ownerKind").is_none());
        assert!(old_value["entries"][0].get("ownerId").is_none());

        let mut transaction = LegacyImportTransaction::load(&root)
            .expect("load v3 journal")
            .expect("v3 transaction");
        assert_eq!(
            transaction.entries()[0].owner_kind(),
            LegacyImportCredentialOwnerKind::Host
        );
        assert_eq!(transaction.entries()[0].owner_id(), id.as_str());
        transaction
            .record_previous(&id, LegacyPreviousCredentialState::Absent)
            .expect("upgrade v3 transaction");

        let new_value: Value = serde_json::from_slice(
            &fs::read(root.join(SLOT_B_FILE)).expect("read upgraded v6 slot"),
        )
        .expect("v6 JSON");
        assert_eq!(new_value["formatVersion"], JOURNAL_FORMAT_VERSION);
        assert_eq!(new_value["entries"][0]["ownerKind"], "host");
        assert_eq!(new_value["entries"][0]["ownerId"], id.as_str());
        assert!(new_value["entries"][0].get("savedHostId").is_none());

        let managed_root = temporary.path().join("v3-managed-upgrade");
        fs::create_dir(&managed_root).expect("create managed v3 journal root");
        let mut managed = JournalEnvelope::new_with_blob_publication(
            Slot::A,
            1,
            uuid::Uuid::new_v4(),
            graph_commitment(0x67),
            graph_commitment(0x68),
            true,
            LegacyImportTransactionPhase::BlobsDurable,
            vec![host_entry(
                id.clone(),
                LegacyPreviousCredentialState::Unknown,
            )],
        )
        .expect("construct managed v3 envelope");
        managed.format_version = BLOB_JOURNAL_FORMAT_VERSION;
        rewrite_checked_envelope(&managed_root, &mut managed);
        let mut managed = LegacyImportTransaction::load(&managed_root)
            .expect("load managed v3 journal")
            .expect("managed v3 transaction");
        managed
            .mark_blobs_durable()
            .expect("upgrade managed v3 semantics");
        assert_eq!(managed.envelope.format_version, JOURNAL_FORMAT_VERSION);
        assert_eq!(managed.phase(), LegacyImportTransactionPhase::BlobsDurable);
    }

    #[test]
    fn v4_owner_journals_keep_the_old_checksum_and_upgrade_to_v6_on_write() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let root = temporary.path().join("v4-owner-upgrade");
        fs::create_dir(&root).expect("create v4 journal root");
        let id = saved_host_id("v4-shared-compatible-owner");
        let host = LegacyImportCredentialOwner::for_saved_host(&id);
        let identity = LegacyImportCredentialOwner::for_password_identity(id.as_str())
            .expect("v4 identity owner");
        let mut legacy = JournalEnvelope::new(
            Slot::A,
            1,
            uuid::Uuid::parse_str("123e4567-e89b-42d3-a456-426614174000")
                .expect("fixed v4 transaction ID"),
            graph_commitment(0x71),
            graph_commitment(0x72),
            LegacyImportTransactionPhase::Preparing,
            vec![
                LegacyImportTransactionEntry::new(host.clone()),
                LegacyImportTransactionEntry::new(identity.clone()),
            ],
        )
        .expect("construct v4 compatibility envelope");
        legacy.format_version = OWNER_JOURNAL_FORMAT_VERSION;
        rewrite_checked_envelope(&root, &mut legacy);

        let old_bytes = fs::read(root.join(SLOT_A_FILE)).expect("read v4 owner slot");
        let old_value: Value = serde_json::from_slice(&old_bytes).expect("v4 owner JSON");
        assert_eq!(old_value["formatVersion"], OWNER_JOURNAL_FORMAT_VERSION);
        assert_eq!(
            old_value["checksum"],
            "a9c030805bb13a1e5ff7f8f1a20c9bd1c0adcd1d6c4af1bbbebf0fe2b0278dcf"
        );
        assert_eq!(old_value["entries"][0]["ownerKind"], "host");
        assert_eq!(old_value["entries"][1]["ownerKind"], "passwordIdentity");

        let mut transaction = LegacyImportTransaction::load(&root)
            .expect("load v4 owner journal")
            .expect("v4 owner transaction");
        assert!(transaction.entry_for_owner(&host).is_some());
        assert!(transaction.entry_for_owner(&identity).is_some());
        transaction
            .record_previous_for_owner(&host, LegacyPreviousCredentialState::Absent)
            .expect("advance v4 journal with v6 publication");

        assert_eq!(transaction.envelope.format_version, JOURNAL_FORMAT_VERSION);
        let new_value: Value = serde_json::from_slice(
            &fs::read(root.join(SLOT_B_FILE)).expect("read upgraded v6 slot"),
        )
        .expect("upgraded v6 JSON");
        assert_eq!(new_value["formatVersion"], JOURNAL_FORMAT_VERSION);
        assert_eq!(
            fs::read(root.join(SLOT_A_FILE)).expect("v4 slot remains unchanged"),
            old_bytes
        );
        LegacyImportTransaction::load(&root)
            .expect("load adjacent v4/v6 pair")
            .expect("upgraded transaction");
    }

    #[test]
    fn v5_four_owner_wire_is_frozen_and_upgrades_to_v6_on_write() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let root = temporary.path().join("v5-proxy-owner-upgrade");
        fs::create_dir(&root).expect("create v5 journal root");
        let id = saved_host_id("v5-shared-compatible-owner");
        let host = LegacyImportCredentialOwner::for_saved_host(&id);
        let identity = LegacyImportCredentialOwner::for_password_identity(id.as_str())
            .expect("v5 identity owner");
        let host_proxy = LegacyImportCredentialOwner::for_host_inline_proxy(&id);
        let profile_proxy =
            LegacyImportCredentialOwner::for_proxy_profile(id.as_str()).expect("v5 profile owner");
        let mut legacy = JournalEnvelope::new(
            Slot::A,
            1,
            uuid::Uuid::new_v4(),
            graph_commitment(0x73),
            graph_commitment(0x74),
            LegacyImportTransactionPhase::Preparing,
            vec![
                LegacyImportTransactionEntry::new(host.clone()),
                LegacyImportTransactionEntry::new(identity.clone()),
                LegacyImportTransactionEntry::new(host_proxy.clone()),
                LegacyImportTransactionEntry::new(profile_proxy.clone()),
            ],
        )
        .expect("construct v5 compatibility envelope");
        legacy.format_version = PROXY_JOURNAL_FORMAT_VERSION;
        rewrite_checked_envelope(&root, &mut legacy);

        let old_bytes = fs::read(root.join(SLOT_A_FILE)).expect("read v5 owner slot");
        let old_value: Value = serde_json::from_slice(&old_bytes).expect("v5 owner JSON");
        assert_eq!(old_value["formatVersion"], PROXY_JOURNAL_FORMAT_VERSION);
        assert_eq!(old_value["entries"][0]["ownerKind"], "host");
        assert_eq!(old_value["entries"][1]["ownerKind"], "passwordIdentity");
        assert_eq!(old_value["entries"][2]["ownerKind"], "hostInlineProxy");
        assert_eq!(old_value["entries"][3]["ownerKind"], "proxyProfile");

        let mut transaction = LegacyImportTransaction::load(&root)
            .expect("load v5 owner journal")
            .expect("v5 owner transaction");
        for owner in [&host, &identity, &host_proxy, &profile_proxy] {
            assert!(transaction.entry_for_owner(owner).is_some());
        }
        transaction
            .record_previous_for_owner(&host, LegacyPreviousCredentialState::Absent)
            .expect("advance v5 journal with v6 publication");
        assert_eq!(transaction.envelope.format_version, JOURNAL_FORMAT_VERSION);
        let new_value: Value = serde_json::from_slice(
            &fs::read(root.join(SLOT_B_FILE)).expect("read upgraded v6 slot"),
        )
        .expect("upgraded v6 JSON");
        assert_eq!(new_value["formatVersion"], JOURNAL_FORMAT_VERSION);
        assert_eq!(
            fs::read(root.join(SLOT_A_FILE)).expect("v5 slot remains unchanged"),
            old_bytes
        );
        LegacyImportTransaction::load(&root)
            .expect("load adjacent v5/v6 pair")
            .expect("upgraded transaction");

        let mut forged_group = old_value;
        forged_group["entries"][3]["ownerKind"] = Value::String("groupProxy".to_owned());
        assert!(
            super::deserialize_envelope(
                &serde_json::to_vec(&forged_group).expect("encode forged v5 group owner")
            )
            .is_none()
        );

        let group_entry = LegacyImportTransactionEntry::new(
            LegacyImportCredentialOwner::for_group_ssh(id.as_str()).expect("group SSH owner"),
        );
        assert_eq!(
            journal_checksum(
                super::JOURNAL_MAGIC,
                PROXY_JOURNAL_FORMAT_VERSION,
                Slot::A,
                1,
                legacy.transaction_id,
                &legacy.before_graph_commitment,
                &legacy.after_graph_commitment,
                false,
                LegacyImportTransactionPhase::Preparing,
                &[group_entry],
            ),
            Err(LegacyImportTransactionError::Serialization)
        );
    }

    #[test]
    fn v2_through_v5_cannot_serialize_or_claim_the_host_telnet_namespace() {
        let id = saved_host_id("legacy-format-host-telnet-sentinel");
        let entry = LegacyImportTransactionEntry::new(
            LegacyImportCredentialOwner::for_saved_host_telnet(&id),
        );
        let transaction_id = uuid::Uuid::new_v4();
        let before = graph_commitment(0x75);
        let after = graph_commitment(0x76);

        for format_version in [
            LEGACY_JOURNAL_FORMAT_VERSION,
            BLOB_JOURNAL_FORMAT_VERSION,
            OWNER_JOURNAL_FORMAT_VERSION,
            PROXY_JOURNAL_FORMAT_VERSION,
        ] {
            assert_eq!(
                journal_checksum(
                    super::JOURNAL_MAGIC,
                    format_version,
                    Slot::A,
                    1,
                    transaction_id,
                    &before,
                    &after,
                    false,
                    LegacyImportTransactionPhase::Preparing,
                    std::slice::from_ref(&entry),
                ),
                Err(LegacyImportTransactionError::Serialization),
                "legacy format {format_version} must reject Host Telnet",
            );
        }

        for format_version in [OWNER_JOURNAL_FORMAT_VERSION, PROXY_JOURNAL_FORMAT_VERSION] {
            let forged = serde_json::json!({
                "magic": super::JOURNAL_MAGIC,
                "formatVersion": format_version,
                "slot": "a",
                "generation": 1,
                "transactionId": transaction_id,
                "beforeGraphCommitment": before,
                "afterGraphCommitment": after,
                "requiresBlobPublication": false,
                "phase": "preparing",
                "entries": [{
                    "ownerKind": "hostTelnet",
                    "ownerId": id.as_str(),
                    "previous": "unknown"
                }],
                "checksum": "0".repeat(64)
            });
            assert!(
                super::deserialize_envelope(
                    &serde_json::to_vec(&forged).expect("encode forged old-format journal")
                )
                .is_none(),
                "legacy format {format_version} must not deserialize Host Telnet",
            );
        }
    }

    #[test]
    fn v6_constructors_and_coordinates_isolate_all_eight_owner_kinds_with_the_same_id() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let root = temporary.path().join("mixed-owner-transaction");
        let id = saved_host_id("same-owner-id-sentinel");
        let host = LegacyImportCredentialOwner::for_saved_host(&id);
        let host_telnet = LegacyImportCredentialOwner::for_saved_host_telnet(&id);
        let identity = LegacyImportCredentialOwner::for_password_identity(id.as_str())
            .expect("password-identity owner");
        let host_proxy = LegacyImportCredentialOwner::for_host_inline_proxy(&id);
        let profile_proxy = LegacyImportCredentialOwner::for_proxy_profile(id.as_str())
            .expect("proxy-profile owner");
        let group_ssh =
            LegacyImportCredentialOwner::for_group_ssh(id.as_str()).expect("group SSH owner");
        let group_telnet =
            LegacyImportCredentialOwner::for_group_telnet(id.as_str()).expect("group Telnet owner");
        let group_proxy =
            LegacyImportCredentialOwner::for_group_proxy(id.as_str()).expect("group proxy owner");
        let mut transaction = LegacyImportTransaction::begin_for_owners(
            &root,
            &[
                host.clone(),
                host_telnet.clone(),
                identity.clone(),
                host_proxy.clone(),
                profile_proxy.clone(),
                group_ssh.clone(),
                group_telnet.clone(),
                group_proxy.clone(),
            ],
            graph_commitment(0x69),
            graph_commitment(0x6a),
        )
        .expect("begin mixed-owner transaction");

        assert_eq!(transaction.entries().len(), 8);
        assert!(transaction.entry_for_owner(&host).is_some());
        assert!(transaction.entry_for_owner(&host_telnet).is_some());
        assert!(transaction.entry_for_owner(&identity).is_some());
        assert!(transaction.entry_for_owner(&host_proxy).is_some());
        assert!(transaction.entry_for_owner(&profile_proxy).is_some());
        assert!(transaction.entry_for_owner(&group_ssh).is_some());
        assert!(transaction.entry_for_owner(&group_telnet).is_some());
        assert!(transaction.entry_for_owner(&group_proxy).is_some());
        let original = fs::read(root.join(SLOT_A_FILE)).expect("read mixed-owner slot");
        let value: Value = serde_json::from_slice(&original).expect("mixed-owner JSON");
        assert_eq!(value["entries"][0]["ownerKind"], "host");
        assert_eq!(value["entries"][1]["ownerKind"], "hostTelnet");
        assert_eq!(value["entries"][2]["ownerKind"], "passwordIdentity");
        assert_eq!(value["entries"][3]["ownerKind"], "hostInlineProxy");
        assert_eq!(value["entries"][4]["ownerKind"], "proxyProfile");
        assert_eq!(value["entries"][5]["ownerKind"], "groupSsh");
        assert_eq!(value["entries"][6]["ownerKind"], "groupTelnet");
        assert_eq!(value["entries"][7]["ownerKind"], "groupProxy");
        for entry in value["entries"].as_array().expect("eight owner entries") {
            assert_eq!(entry["ownerId"], id.as_str());
        }

        let mut tampered = value.clone();
        tampered["entries"][0]["ownerKind"] = Value::String("passwordIdentity".to_owned());
        fs::write(
            root.join(SLOT_A_FILE),
            serde_json::to_vec(&tampered).expect("encode owner-kind tampering"),
        )
        .expect("tamper owner kind");
        assert!(matches!(probe_slot(&root, Slot::A), SlotProbe::Corrupt));
        fs::write(root.join(SLOT_A_FILE), original).expect("restore mixed-owner slot");

        transaction
            .activate_for_owners(&[
                (host.clone(), LegacyPreviousCredentialState::Absent),
                (host_telnet.clone(), LegacyPreviousCredentialState::BackedUp),
                (identity.clone(), LegacyPreviousCredentialState::BackedUp),
                (host_proxy.clone(), LegacyPreviousCredentialState::BackedUp),
                (profile_proxy.clone(), LegacyPreviousCredentialState::Absent),
                (group_ssh.clone(), LegacyPreviousCredentialState::Absent),
                (
                    group_telnet.clone(),
                    LegacyPreviousCredentialState::BackedUp,
                ),
                (group_proxy.clone(), LegacyPreviousCredentialState::Absent),
            ])
            .expect("activate mixed-owner transaction");
        assert_eq!(
            transaction
                .entry_for_owner(&host)
                .expect("host entry")
                .previous(),
            LegacyPreviousCredentialState::Absent
        );
        assert_eq!(
            transaction
                .entry_for_owner(&host_telnet)
                .expect("host Telnet entry")
                .previous(),
            LegacyPreviousCredentialState::BackedUp
        );
        assert_eq!(
            transaction
                .entry_for_owner(&group_ssh)
                .expect("group SSH entry")
                .previous(),
            LegacyPreviousCredentialState::Absent
        );
        assert_eq!(
            transaction
                .entry_for_owner(&group_telnet)
                .expect("group Telnet entry")
                .previous(),
            LegacyPreviousCredentialState::BackedUp
        );
        assert_eq!(
            transaction
                .entry_for_owner(&group_proxy)
                .expect("group proxy entry")
                .previous(),
            LegacyPreviousCredentialState::Absent
        );
        assert_eq!(
            transaction
                .entry_for_owner(&identity)
                .expect("identity entry")
                .previous(),
            LegacyPreviousCredentialState::BackedUp
        );
        assert_eq!(
            transaction
                .entry_for_owner(&host_proxy)
                .expect("host proxy entry")
                .previous(),
            LegacyPreviousCredentialState::BackedUp
        );
        assert_eq!(
            transaction
                .entry_for_owner(&profile_proxy)
                .expect("profile proxy entry")
                .previous(),
            LegacyPreviousCredentialState::Absent
        );

        let duplicate_root = temporary.path().join("duplicate-owner");
        let error = LegacyImportTransaction::begin_for_owners(
            &duplicate_root,
            &[identity.clone(), identity],
            graph_commitment(0x6b),
            graph_commitment(0x6c),
        )
        .expect_err("duplicate coordinate must fail");
        assert_eq!(
            error,
            LegacyImportTransactionError::DuplicateCredentialOwner
        );
        let diagnostics = format!("{transaction:?} {error:?} {error} {host:?}");
        assert!(!diagnostics.contains(id.as_str()));
        assert!(!diagnostics.contains(&root.display().to_string()));
    }

    #[test]
    fn versioned_blob_flag_shape_is_strict_and_checksum_pair_bound() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let root = temporary.path().join("strict-v6-shape");
        let transaction = begin_blob_transaction(&root, &[]).expect("begin managed-only journal");
        let original = fs::read(root.join(SLOT_A_FILE)).expect("original v6 slot");
        let original_value: Value = serde_json::from_slice(&original).expect("original v6 JSON");
        assert_eq!(original_value["requiresBlobPublication"], true);

        for mutation in ["missing", "null", "extra"] {
            let mut value = original_value.clone();
            let object = value.as_object_mut().expect("v6 journal object");
            match mutation {
                "missing" => {
                    object.remove("requiresBlobPublication");
                }
                "null" => {
                    object.insert("requiresBlobPublication".to_owned(), Value::Null);
                }
                "extra" => {
                    object.insert(
                        "backendLocator".to_owned(),
                        Value::String("sentinel".to_owned()),
                    );
                }
                _ => unreachable!(),
            }
            fs::write(
                root.join(SLOT_A_FILE),
                serde_json::to_vec(&value).expect("encode malformed v6 journal"),
            )
            .expect("write malformed v6 journal");
            assert!(matches!(
                LegacyImportTransaction::load(&root),
                Err(LegacyImportTransactionError::RecoverySlotsUnavailable)
            ));
        }

        fs::write(root.join(SLOT_A_FILE), &original).expect("restore original v6 slot");
        let mut legacy = transaction.envelope.clone();
        legacy.format_version = LEGACY_JOURNAL_FORMAT_VERSION;
        legacy.requires_blob_publication = false;
        rewrite_checked_envelope(&root, &mut legacy);
        let legacy_original = fs::read(root.join(SLOT_A_FILE)).expect("strict v2 slot");
        let mut legacy_value: Value =
            serde_json::from_slice(&legacy_original).expect("strict v2 JSON");
        assert!(legacy_value.get("requiresBlobPublication").is_none());

        legacy_value
            .as_object_mut()
            .expect("v2 object")
            .insert("requiresBlobPublication".to_owned(), Value::Bool(false));
        fs::write(
            root.join(SLOT_A_FILE),
            serde_json::to_vec(&legacy_value).expect("encode v2 with forged flag"),
        )
        .expect("write v2 with forged flag");
        assert!(matches!(
            LegacyImportTransaction::load(&root),
            Err(LegacyImportTransactionError::RecoverySlotsUnavailable)
        ));

        let mut forged_phase: Value =
            serde_json::from_slice(&legacy_original).expect("restore v2 JSON value");
        forged_phase["phase"] = Value::String("blobsDurable".to_owned());
        fs::write(
            root.join(SLOT_A_FILE),
            serde_json::to_vec(&forged_phase).expect("encode v2 with forged phase"),
        )
        .expect("write v2 with forged phase");
        assert!(matches!(
            LegacyImportTransaction::load(&root),
            Err(LegacyImportTransactionError::RecoverySlotsUnavailable)
        ));

        let pair_root = temporary.path().join("blob-flag-pair-binding");
        let id = saved_host_id("blob-flag-pair-host");
        let mut pair = begin_transaction(&pair_root, std::slice::from_ref(&id))
            .expect("begin flag-pair transaction");
        pair.record_previous(&id, LegacyPreviousCredentialState::Absent)
            .expect("publish second flag-pair slot");
        let original_b = fs::read(pair_root.join(SLOT_B_FILE)).expect("original pair slot B");
        let mut unchecked: Value = serde_json::from_slice(&original_b).expect("pair slot B JSON");
        unchecked["requiresBlobPublication"] = Value::Bool(true);
        fs::write(
            pair_root.join(SLOT_B_FILE),
            serde_json::to_vec(&unchecked).expect("encode unchecked flag tamper"),
        )
        .expect("tamper flag without checksum");
        assert!(matches!(
            probe_slot(&pair_root, Slot::B),
            SlotProbe::Corrupt
        ));
        assert_eq!(
            LegacyImportTransaction::load(&pair_root)
                .expect("fallback after checksum tamper")
                .expect("fallback transaction")
                .envelope
                .generation,
            1
        );

        fs::write(pair_root.join(SLOT_B_FILE), original_b).expect("restore pair slot B");
        let mut forged = valid_envelope(&pair_root, Slot::B);
        forged.requires_blob_publication = true;
        rewrite_checked_envelope(&pair_root, &mut forged);
        assert!(matches!(
            LegacyImportTransaction::load(&pair_root),
            Err(LegacyImportTransactionError::RecoverySlotsUnavailable)
        ));
    }

    #[test]
    fn managed_transactions_require_dual_blob_durability_before_activation() {
        let temporary = tempfile::tempdir().expect("temporary journal root");

        let credential_only_root = temporary.path().join("credential-only");
        let mut credential_only = begin_transaction(&credential_only_root, &[])
            .expect("begin empty credential-only transaction");
        assert_eq!(
            credential_only.mark_blobs_durable(),
            Err(LegacyImportTransactionError::InvalidStateTransition)
        );
        credential_only
            .activate(&[])
            .expect("legacy empty credential-only activation remains valid");

        let managed_only_root = temporary.path().join("managed-only");
        let mut managed_only = begin_blob_transaction(&managed_only_root, &[])
            .expect("begin managed-only transaction");
        assert!(managed_only.requires_blob_publication());
        assert!(managed_only.entries().is_empty());
        assert_eq!(
            managed_only.activate(&[]),
            Err(LegacyImportTransactionError::InvalidStateTransition)
        );
        assert_eq!(
            managed_only.mark_vault_durable(),
            Err(LegacyImportTransactionError::InvalidStateTransition)
        );
        assert_eq!(
            managed_only.mark_rollback_targets_restored(),
            Err(LegacyImportTransactionError::InvalidStateTransition)
        );
        managed_only
            .mark_blobs_durable()
            .expect("dual-publish managed-only blob durability");
        assert_eq!(managed_only.envelope.generation, 3);
        assert_eq!(
            managed_only.phase(),
            LegacyImportTransactionPhase::BlobsDurable
        );
        assert!(super::both_slots_have_semantics(
            &managed_only_root,
            managed_only.transaction_id(),
            managed_only.before_graph_commitment(),
            managed_only.after_graph_commitment(),
            true,
            LegacyImportTransactionPhase::BlobsDurable,
            managed_only.entries(),
        ));
        managed_only
            .mark_blobs_durable()
            .expect("blob durability mark is idempotent");
        assert_eq!(managed_only.envelope.generation, 3);
        managed_only
            .activate(&[])
            .expect("activate managed-only transaction after durable blobs");
        assert_eq!(managed_only.envelope.generation, 5);
        assert_eq!(managed_only.phase(), LegacyImportTransactionPhase::Active);
        assert_eq!(
            managed_only.mark_blobs_durable(),
            Err(LegacyImportTransactionError::InvalidStateTransition)
        );
        managed_only
            .mark_vault_durable()
            .expect("finish managed-only transaction decision");

        let interrupted_root = temporary.path().join("interrupted-blob-mark");
        let id = saved_host_id("managed-credential-host");
        let mut interrupted = begin_blob_transaction(&interrupted_root, std::slice::from_ref(&id))
            .expect("begin interrupted managed transaction");
        interrupted
            .publish_next(
                LegacyImportTransactionPhase::BlobsDurable,
                interrupted.envelope.entries.clone(),
            )
            .expect("publish only first blob-durable slot");
        let mut recovered = LegacyImportTransaction::load(&interrupted_root)
            .expect("load interrupted blob transition")
            .expect("interrupted blob transaction");
        assert_eq!(
            recovered.phase(),
            LegacyImportTransactionPhase::BlobsDurable
        );
        assert_eq!(
            recovered.activate(&[(id.clone(), LegacyPreviousCredentialState::BackedUp,)]),
            Err(LegacyImportTransactionError::InvalidStateTransition),
            "one blob-durable slot must not authorize credential mutation"
        );
        recovered
            .mark_blobs_durable()
            .expect("repair second blob-durable slot");
        recovered
            .activate(&[(id, LegacyPreviousCredentialState::BackedUp)])
            .expect("activate after dual blob-durable repair");
        assert_eq!(recovered.phase(), LegacyImportTransactionPhase::Active);
    }

    #[test]
    fn graph_commitments_remain_unchanged_through_every_transaction_phase() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let id = saved_host_id("phase-commitment-host-id");
        let before = graph_commitment(0x51);
        let after = graph_commitment(0x52);

        let durable_root = temporary.path().join("durable-phases");
        let mut durable = LegacyImportTransaction::begin(
            &durable_root,
            std::slice::from_ref(&id),
            before.clone(),
            after.clone(),
        )
        .expect("begin durable transaction");
        assert_eq!(durable.before_graph_commitment(), &before);
        assert_eq!(durable.after_graph_commitment(), &after);
        durable
            .activate(&[(id.clone(), LegacyPreviousCredentialState::Absent)])
            .expect("activate durable transaction");
        assert_eq!(durable.before_graph_commitment(), &before);
        assert_eq!(durable.after_graph_commitment(), &after);
        durable
            .mark_vault_durable()
            .expect("mark durable transaction complete");
        assert_eq!(durable.before_graph_commitment(), &before);
        assert_eq!(durable.after_graph_commitment(), &after);
        for slot in [Slot::A, Slot::B] {
            let envelope = valid_envelope(&durable_root, slot);
            assert_eq!(&envelope.before_graph_commitment, &before);
            assert_eq!(&envelope.after_graph_commitment, &after);
            assert_eq!(envelope.phase, LegacyImportTransactionPhase::VaultDurable);
        }

        let rollback_root = temporary.path().join("rollback-phases");
        let mut rollback = LegacyImportTransaction::begin(
            &rollback_root,
            std::slice::from_ref(&id),
            before.clone(),
            after.clone(),
        )
        .expect("begin rollback transaction");
        rollback
            .activate(&[(id, LegacyPreviousCredentialState::BackedUp)])
            .expect("activate rollback transaction");
        rollback
            .mark_rollback_targets_restored()
            .expect("mark rollback targets restored");
        assert_eq!(rollback.before_graph_commitment(), &before);
        assert_eq!(rollback.after_graph_commitment(), &after);
        for slot in [Slot::A, Slot::B] {
            let envelope = valid_envelope(&rollback_root, slot);
            assert_eq!(&envelope.before_graph_commitment, &before);
            assert_eq!(&envelope.after_graph_commitment, &after);
            assert_eq!(
                envelope.phase,
                LegacyImportTransactionPhase::RollbackTargetsRestored
            );
        }
    }

    #[test]
    fn duplicate_ids_and_entry_limit_are_rejected_before_publication() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let duplicate = saved_host_id("duplicate-id-sentinel");
        let error = begin_transaction(
            temporary.path().join("duplicate"),
            &[duplicate.clone(), duplicate.clone()],
        )
        .expect_err("duplicate IDs must fail");
        assert_eq!(
            error,
            LegacyImportTransactionError::DuplicateCredentialOwner
        );
        assert!(!format!("{error:?} {error}").contains(duplicate.as_str()));

        let ids = (0..=MAX_ENTRIES)
            .map(|index| saved_host_id(&format!("limit-host-{index}")))
            .collect::<Vec<_>>();
        let limit_root = temporary.path().join("limit-path-sentinel");
        let error = begin_transaction(&limit_root, &ids).expect_err("entry limit must fail");
        assert_eq!(error, LegacyImportTransactionError::TooManyEntries);
        assert!(!root_has_slot(&limit_root));
        let diagnostics = format!("{error:?} {error}");
        assert!(!diagnostics.contains(ids[0].as_str()));
        assert!(!diagnostics.contains(ids[MAX_ENTRIES].as_str()));
        assert!(!diagnostics.contains(&limit_root.display().to_string()));
    }

    #[test]
    fn byte_limit_covers_every_phase_and_slot_with_maximally_escaped_ids() {
        assert!(SavedHostId::from_opaque("x".repeat(MAX_OWNER_ID_BYTES)).is_ok());
        assert!(SavedHostId::from_opaque("x".repeat(MAX_OWNER_ID_BYTES + 1)).is_err());

        let ids = (0..MAX_ENTRIES)
            .map(maximally_json_escaped_saved_host_id)
            .collect::<Vec<_>>();
        assert_eq!(
            serde_json::to_vec(&ids[0])
                .expect("encode maximally escaped ID")
                .len(),
            MAX_JSON_ESCAPED_OWNER_ID_BYTES + 2
        );

        let temporary = tempfile::tempdir().expect("temporary journal root");
        let mut largest_encoded_len = 0;
        let mut cases = Vec::new();
        for format_version in [
            LEGACY_JOURNAL_FORMAT_VERSION,
            BLOB_JOURNAL_FORMAT_VERSION,
            OWNER_JOURNAL_FORMAT_VERSION,
            PROXY_JOURNAL_FORMAT_VERSION,
            JOURNAL_FORMAT_VERSION,
        ] {
            for requires_blobs in [false, true] {
                for phase in [
                    LegacyImportTransactionPhase::Preparing,
                    LegacyImportTransactionPhase::BlobsDurable,
                    LegacyImportTransactionPhase::Active,
                    LegacyImportTransactionPhase::VaultDurable,
                    LegacyImportTransactionPhase::RollbackTargetsRestored,
                ] {
                    if super::validate_phase_for_format(format_version, requires_blobs, phase)
                        .is_ok()
                    {
                        cases.push((format_version, requires_blobs, phase));
                    }
                }
            }
        }
        for (format_version, requires_blobs, phase) in cases {
            let newer_entries = ids
                .iter()
                .cloned()
                .map(|owner_id| LegacyImportTransactionEntry {
                    owner_kind: if format_version >= OWNER_JOURNAL_FORMAT_VERSION {
                        LegacyImportCredentialOwnerKind::PasswordIdentity
                    } else {
                        LegacyImportCredentialOwnerKind::Host
                    },
                    owner_id,
                    previous: LegacyPreviousCredentialState::BackedUp,
                })
                .collect::<Vec<_>>();
            let mut older_entries = newer_entries.clone();
            if phase == LegacyImportTransactionPhase::Preparing {
                older_entries[MAX_ENTRIES - 1].previous = LegacyPreviousCredentialState::Unknown;
            }
            let transaction_id = uuid::Uuid::new_v4();
            let before = graph_commitment(0x31);
            let after = graph_commitment(0x32);
            let mut older = JournalEnvelope::new_with_blob_publication(
                Slot::B,
                u64::MAX - 1,
                transaction_id,
                before.clone(),
                after.clone(),
                requires_blobs,
                phase,
                older_entries,
            )
            .expect("construct worst-shape older journal");
            let mut newer = JournalEnvelope::new_with_blob_publication(
                Slot::A,
                u64::MAX,
                transaction_id,
                before,
                after,
                requires_blobs,
                phase,
                newer_entries,
            )
            .expect("construct worst-shape newer journal");
            if format_version != JOURNAL_FORMAT_VERSION {
                for envelope in [&mut older, &mut newer] {
                    envelope.format_version = format_version;
                    envelope.checksum = journal_checksum(
                        &envelope.magic,
                        envelope.format_version,
                        envelope.slot,
                        envelope.generation,
                        envelope.transaction_id,
                        &envelope.before_graph_commitment,
                        &envelope.after_graph_commitment,
                        envelope.requires_blob_publication,
                        envelope.phase,
                        &envelope.entries,
                    )
                    .expect("checksum legacy worst-shape journal");
                }
            }

            let encoded_lengths = [&older, &newer].map(|envelope| {
                let encoded_len = serde_json::to_vec(envelope)
                    .expect("encode worst-shape journal")
                    .len() as u64;
                largest_encoded_len = largest_encoded_len.max(encoded_len);
                assert!(
                    encoded_len > 8 * 1024 * 1024,
                    "old byte cap was insufficient"
                );
                assert!(encoded_len <= MAX_JOURNAL_BYTES);
                encoded_len
            });

            // Exercise the actual bounded reader with both slots for the
            // largest phase shape. The preceding serialization assertions
            // cover both slots of every other phase without multiplying
            // durable test writes.
            if format_version == JOURNAL_FORMAT_VERSION
                && !requires_blobs
                && phase == LegacyImportTransactionPhase::RollbackTargetsRestored
            {
                let root = temporary.path().join("worst-shape-slot-pair");
                fs::create_dir(&root).expect("create journal root");
                for (envelope, encoded_len) in
                    [(&older, encoded_lengths[0]), (&newer, encoded_lengths[1])]
                {
                    write_slot(&root, envelope).expect("publish worst-shape journal");
                    assert_eq!(
                        fs::metadata(root.join(envelope.slot.file_name()))
                            .expect("worst-shape journal metadata")
                            .len(),
                        encoded_len
                    );
                }
                let loaded = LegacyImportTransaction::load(&root)
                    .expect("load worst-shape slot pair")
                    .expect("worst-shape transaction");
                assert_eq!(loaded.envelope.generation, u64::MAX);
                assert_eq!(loaded.phase(), phase);
                assert!(!loaded.requires_blob_publication());
            }
        }

        assert_eq!(
            largest_encoded_len, MAX_JOURNAL_BYTES,
            "derived cap must equal the actual v6 worst shape"
        );
    }

    #[test]
    fn oversized_serialization_and_file_fail_closed_without_leaking_context() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let seed_root = temporary.path().join("seed");
        let seed_id = saved_host_id("oversized-seed-host-id-sentinel");
        begin_transaction(&seed_root, std::slice::from_ref(&seed_id)).expect("seed valid envelope");
        let mut envelope = valid_envelope(&seed_root, Slot::A);

        let oversized_id_sentinel = "oversized-journal-id-sentinel";
        let oversized_id = serde_json::from_value::<SavedHostId>(Value::String(format!(
            "{oversized_id_sentinel}{}",
            "x".repeat(MAX_JOURNAL_BYTES as usize)
        )))
        .expect("deserialize deliberately invalid test ID");
        envelope.entries = vec![host_entry(
            oversized_id,
            LegacyPreviousCredentialState::BackedUp,
        )];

        let root = temporary.path().join("oversized-publication-path-sentinel");
        fs::create_dir(&root).expect("create oversized journal root");
        let error = write_slot(&root, &envelope).expect_err("oversized journal must fail");
        assert_eq!(error, LegacyImportTransactionError::JournalTooLarge);
        assert!(!root_has_slot(&root));
        assert_eq!(
            fs::read_dir(&root)
                .expect("inspect oversized journal root")
                .count(),
            0
        );

        let diagnostics = format!("{error:?} {error}");
        let transaction_id = envelope.transaction_id.to_string();
        let root_display = root.display().to_string();
        for forbidden in [
            oversized_id_sentinel,
            transaction_id.as_str(),
            envelope.before_graph_commitment.as_str(),
            envelope.after_graph_commitment.as_str(),
            root_display.as_str(),
        ] {
            assert!(!diagnostics.contains(forbidden));
        }

        let persisted_sentinel = b"oversized-on-disk-id-sentinel";
        let mut oversized_file = Vec::with_capacity(MAX_JOURNAL_BYTES as usize + 1);
        oversized_file.extend_from_slice(persisted_sentinel);
        oversized_file.resize(MAX_JOURNAL_BYTES as usize + 1, b'x');
        fs::write(root.join(SLOT_A_FILE), oversized_file)
            .expect("write deliberately oversized recovery slot");
        let error = LegacyImportTransaction::load(&root)
            .expect_err("oversized recovery slot must fail closed");
        assert_eq!(
            error,
            LegacyImportTransactionError::RecoverySlotsUnavailable
        );
        let diagnostics = format!("{error:?} {error}");
        assert!(!diagnostics.contains(std::str::from_utf8(persisted_sentinel).expect("ASCII")));
        assert!(!diagnostics.contains(&root_display));
    }

    #[test]
    fn previous_states_and_rollback_phase_advance_alternating_slots() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let root = temporary.path().join("journal");
        let first = saved_host_id("state-host-a");
        let second = saved_host_id("state-host-b");
        let unknown = saved_host_id("state-host-unknown-sentinel");
        let mut transaction =
            begin_transaction(&root, &[first.clone(), second.clone()]).expect("begin transaction");

        transaction
            .record_previous(&first, LegacyPreviousCredentialState::Absent)
            .expect("record absent");
        assert_eq!(transaction.envelope.generation, 2);
        assert_eq!(transaction.envelope.slot, Slot::B);
        assert_eq!(
            entry_state(&transaction, &first),
            LegacyPreviousCredentialState::Absent
        );
        let generation = transaction.envelope.generation;
        transaction
            .record_previous(&first, LegacyPreviousCredentialState::Absent)
            .expect("same fact is idempotent");
        assert_eq!(transaction.envelope.generation, generation);
        assert_eq!(
            transaction.record_previous(&first, LegacyPreviousCredentialState::BackedUp),
            Err(LegacyImportTransactionError::InvalidStateTransition)
        );
        assert_eq!(
            transaction.record_previous(&unknown, LegacyPreviousCredentialState::Absent),
            Err(LegacyImportTransactionError::UnknownCredentialOwner)
        );
        assert_eq!(
            transaction.record_previous(&second, LegacyPreviousCredentialState::Unknown),
            Err(LegacyImportTransactionError::InvalidStateTransition)
        );

        transaction
            .record_previous(&second, LegacyPreviousCredentialState::BackedUp)
            .expect("record backed-up state");
        assert_eq!(transaction.envelope.generation, 3);
        assert_eq!(transaction.envelope.slot, Slot::A);
        transaction
            .activate(&[
                (first.clone(), LegacyPreviousCredentialState::Absent),
                (second.clone(), LegacyPreviousCredentialState::BackedUp),
            ])
            .expect("publish complete Active state to both slots");
        assert_eq!(transaction.envelope.generation, 5);
        assert_eq!(transaction.envelope.slot, Slot::A);
        assert_eq!(transaction.phase(), LegacyImportTransactionPhase::Active);
        assert_eq!(
            transaction.record_previous(&second, LegacyPreviousCredentialState::BackedUp),
            Err(LegacyImportTransactionError::InvalidStateTransition)
        );
        transaction
            .mark_rollback_targets_restored()
            .expect("mark rollback restored");
        assert_eq!(transaction.envelope.generation, 7);
        assert_eq!(transaction.envelope.slot, Slot::A);
        assert_eq!(
            transaction.phase(),
            LegacyImportTransactionPhase::RollbackTargetsRestored
        );
        transaction
            .mark_rollback_targets_restored()
            .expect("phase mark is idempotent");
        assert_eq!(transaction.envelope.generation, 7);

        let loaded = LegacyImportTransaction::load(&root)
            .expect("load transaction")
            .expect("transaction remains active");
        assert_eq!(loaded.envelope.generation, 7);
        assert_eq!(
            entry_state(&loaded, &second),
            LegacyPreviousCredentialState::BackedUp
        );
    }

    #[test]
    fn activate_requires_a_complete_unique_known_map_and_dual_publishes_active_state() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let root = temporary.path().join("journal");
        let first = saved_host_id("activate-host-a");
        let second = saved_host_id("activate-host-b");
        let unknown = saved_host_id("activate-host-unknown");
        let mut transaction =
            begin_transaction(&root, &[first.clone(), second.clone()]).expect("begin transaction");

        assert_eq!(
            transaction.activate(&[(first.clone(), LegacyPreviousCredentialState::Absent,)]),
            Err(LegacyImportTransactionError::IncompletePreviousStateMap)
        );
        assert_eq!(
            transaction.activate(&[
                (first.clone(), LegacyPreviousCredentialState::Absent),
                (first.clone(), LegacyPreviousCredentialState::BackedUp),
            ]),
            Err(LegacyImportTransactionError::DuplicateCredentialOwner)
        );
        assert_eq!(
            transaction.activate(&[
                (first.clone(), LegacyPreviousCredentialState::Absent),
                (unknown, LegacyPreviousCredentialState::BackedUp),
            ]),
            Err(LegacyImportTransactionError::UnknownCredentialOwner)
        );
        assert_eq!(
            transaction.activate(&[
                (first.clone(), LegacyPreviousCredentialState::Absent),
                (second.clone(), LegacyPreviousCredentialState::Unknown),
            ]),
            Err(LegacyImportTransactionError::InvalidStateTransition)
        );
        assert_eq!(
            transaction.mark_rollback_targets_restored(),
            Err(LegacyImportTransactionError::InvalidStateTransition)
        );
        assert_eq!(transaction.envelope.generation, 1);
        assert_eq!(transaction.phase(), LegacyImportTransactionPhase::Preparing);

        transaction
            .activate(&[
                (second.clone(), LegacyPreviousCredentialState::BackedUp),
                (first.clone(), LegacyPreviousCredentialState::Absent),
            ])
            .expect("dual-publish complete Active state");
        assert_eq!(transaction.envelope.generation, 3);
        assert_eq!(transaction.envelope.slot, Slot::A);
        assert_eq!(transaction.phase(), LegacyImportTransactionPhase::Active);
        assert_eq!(
            entry_state(&transaction, &first),
            LegacyPreviousCredentialState::Absent
        );
        assert_eq!(
            entry_state(&transaction, &second),
            LegacyPreviousCredentialState::BackedUp
        );
        assert!(super::both_slots_have_semantics(
            &root,
            transaction.transaction_id(),
            transaction.before_graph_commitment(),
            transaction.after_graph_commitment(),
            transaction.requires_blob_publication(),
            LegacyImportTransactionPhase::Active,
            transaction.entries(),
        ));
        assert_eq!(
            transaction.activate(&[
                (first.clone(), LegacyPreviousCredentialState::Absent),
                (second.clone(), LegacyPreviousCredentialState::BackedUp,),
            ]),
            Err(LegacyImportTransactionError::InvalidStateTransition)
        );

        let active_a = fs::read(root.join(SLOT_A_FILE)).expect("Active slot A");
        let active_b = fs::read(root.join(SLOT_B_FILE)).expect("Active slot B");
        fs::write(root.join(SLOT_A_FILE), b"corrupt Active slot A").expect("corrupt Active A");
        let fallback_b = LegacyImportTransaction::load(&root)
            .expect("fallback to Active B")
            .expect("Active B");
        assert_eq!(fallback_b.phase(), LegacyImportTransactionPhase::Active);
        assert_eq!(
            entry_state(&fallback_b, &second),
            LegacyPreviousCredentialState::BackedUp
        );
        fs::write(root.join(SLOT_A_FILE), &active_a).expect("restore Active A");
        fs::write(root.join(SLOT_B_FILE), b"corrupt Active slot B").expect("corrupt Active B");
        let fallback_a = LegacyImportTransaction::load(&root)
            .expect("fallback to Active A")
            .expect("Active A");
        assert_eq!(fallback_a.phase(), LegacyImportTransactionPhase::Active);
        assert_eq!(
            entry_state(&fallback_a, &first),
            LegacyPreviousCredentialState::Absent
        );
        fs::write(root.join(SLOT_B_FILE), &active_b).expect("restore Active B");

        let mut transaction = LegacyImportTransaction::load(&root)
            .expect("reload both Active slots")
            .expect("Active transaction");
        transaction
            .mark_rollback_targets_restored()
            .expect("dual-publish restored phase");
        assert_eq!(transaction.envelope.generation, 5);
        assert_eq!(
            transaction.phase(),
            LegacyImportTransactionPhase::RollbackTargetsRestored
        );
        assert!(super::both_slots_have_semantics(
            &root,
            transaction.transaction_id(),
            transaction.before_graph_commitment(),
            transaction.after_graph_commitment(),
            transaction.requires_blob_publication(),
            LegacyImportTransactionPhase::RollbackTargetsRestored,
            transaction.entries(),
        ));
        let restored_a = fs::read(root.join(SLOT_A_FILE)).expect("restored slot A");
        let restored_b = fs::read(root.join(SLOT_B_FILE)).expect("restored slot B");
        fs::write(root.join(SLOT_A_FILE), b"corrupt restored slot A").expect("corrupt restored A");
        assert_eq!(
            LegacyImportTransaction::load(&root)
                .expect("recover surviving restored B")
                .expect("restored B")
                .phase(),
            LegacyImportTransactionPhase::RollbackTargetsRestored
        );
        assert_eq!(
            fs::read(root.join(SLOT_B_FILE)).expect("surviving restored B"),
            restored_b
        );
        fs::write(root.join(SLOT_A_FILE), &restored_a).expect("restore restored A");
        fs::write(root.join(SLOT_B_FILE), b"corrupt restored slot B").expect("corrupt restored B");
        assert_eq!(
            LegacyImportTransaction::load(&root)
                .expect("recover surviving restored A")
                .expect("restored A")
                .phase(),
            LegacyImportTransactionPhase::RollbackTargetsRestored
        );
        assert_eq!(
            fs::read(root.join(SLOT_A_FILE)).expect("surviving restored A"),
            restored_a
        );
        fs::write(root.join(SLOT_B_FILE), restored_b).expect("restore restored B");
    }

    #[test]
    fn crash_between_dual_publications_keeps_the_older_phase_conservative() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let root = temporary.path().join("activate-crash");
        let id = saved_host_id("activate-crash-host");
        let mut transaction =
            begin_transaction(&root, std::slice::from_ref(&id)).expect("begin transaction");
        let mut complete_entries = transaction.envelope.entries.clone();
        complete_entries[0].previous = LegacyPreviousCredentialState::BackedUp;

        // This is the state after activate's first publication but before it
        // can return success and authorize a target-account write.
        transaction
            .publish_next(
                LegacyImportTransactionPhase::Active,
                complete_entries.clone(),
            )
            .expect("first Active publication");
        assert_eq!(transaction.envelope.generation, 2);
        assert_eq!(
            LegacyImportTransaction::load(&root)
                .expect("load first Active publication")
                .expect("Active transaction")
                .phase(),
            LegacyImportTransactionPhase::Active
        );
        fs::write(root.join(SLOT_B_FILE), b"lose first Active publication")
            .expect("corrupt first Active publication");
        let preparing = LegacyImportTransaction::load(&root)
            .expect("fall back to Preparing")
            .expect("Preparing transaction");
        assert_eq!(preparing.phase(), LegacyImportTransactionPhase::Preparing);
        assert_eq!(
            entry_state(&preparing, &id),
            LegacyPreviousCredentialState::Unknown
        );

        let rollback_root = temporary.path().join("rollback-crash");
        let mut transaction = begin_transaction(&rollback_root, std::slice::from_ref(&id))
            .expect("begin rollback transaction");
        transaction
            .activate(&[(id.clone(), LegacyPreviousCredentialState::BackedUp)])
            .expect("activate both slots");
        transaction
            .publish_next(
                LegacyImportTransactionPhase::RollbackTargetsRestored,
                complete_entries,
            )
            .expect("first restored publication");
        assert_eq!(transaction.envelope.generation, 4);
        assert_eq!(
            LegacyImportTransaction::load(&rollback_root)
                .expect("load valid Active-to-restored transition")
                .expect("restored transaction")
                .phase(),
            LegacyImportTransactionPhase::RollbackTargetsRestored
        );
        let first_restored_publication =
            fs::read(rollback_root.join(SLOT_B_FILE)).expect("first restored publication bytes");
        fs::write(
            rollback_root.join(SLOT_B_FILE),
            b"lose first restored publication",
        )
        .expect("corrupt first restored publication");
        let active = LegacyImportTransaction::load(&rollback_root)
            .expect("fall back to dual-published Active")
            .expect("Active fallback");
        assert_eq!(active.phase(), LegacyImportTransactionPhase::Active);
        assert_eq!(
            entry_state(&active, &id),
            LegacyPreviousCredentialState::BackedUp
        );
        fs::write(rollback_root.join(SLOT_B_FILE), first_restored_publication)
            .expect("restore first restored publication");
        let mut restored = LegacyImportTransaction::load(&rollback_root)
            .expect("reload interrupted restored transition")
            .expect("restored transition");
        restored
            .mark_rollback_targets_restored()
            .expect("fill second restored slot");
        assert_eq!(restored.envelope.generation, 5);
        assert!(super::both_slots_have_semantics(
            &rollback_root,
            restored.transaction_id(),
            restored.before_graph_commitment(),
            restored.after_graph_commitment(),
            restored.requires_blob_publication(),
            LegacyImportTransactionPhase::RollbackTargetsRestored,
            restored.entries(),
        ));
    }

    #[test]
    fn valid_slots_from_different_transactions_fail_closed_without_rewriting_them() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let first_root = temporary.path().join("first-transaction-path-sentinel");
        let second_root = temporary.path().join("second-transaction-path-sentinel");
        let id = saved_host_id("cross-transaction-host-id-sentinel");

        let mut first = begin_transaction(&first_root, std::slice::from_ref(&id))
            .expect("begin first transaction");
        first
            .activate(&[(id.clone(), LegacyPreviousCredentialState::Absent)])
            .expect("activate first transaction");
        let mut second = begin_transaction(&second_root, std::slice::from_ref(&id))
            .expect("begin second transaction");
        second
            .activate(&[(id.clone(), LegacyPreviousCredentialState::Absent)])
            .expect("activate second transaction");

        let foreign_b = fs::read(second_root.join(SLOT_B_FILE)).expect("foreign slot B");
        fs::write(first_root.join(SLOT_B_FILE), &foreign_b).expect("mix transaction slots");
        let local_a = fs::read(first_root.join(SLOT_A_FILE)).expect("local slot A");
        let error = LegacyImportTransaction::load(&first_root)
            .expect_err("mixed transaction slots must fail closed");
        assert_eq!(
            error,
            LegacyImportTransactionError::RecoverySlotsUnavailable
        );
        assert_eq!(
            fs::read(first_root.join(SLOT_A_FILE)).expect("unchanged local A"),
            local_a
        );
        assert_eq!(
            fs::read(first_root.join(SLOT_B_FILE)).expect("unchanged foreign B"),
            foreign_b
        );

        let diagnostics = format!("{error:?} {error}");
        let first_transaction_id = first.transaction_id().to_string();
        let second_transaction_id = second.transaction_id().to_string();
        let first_root_display = first_root.display().to_string();
        let second_root_display = second_root.display().to_string();
        for forbidden in [
            id.as_str(),
            first_transaction_id.as_str(),
            second_transaction_id.as_str(),
            first_root_display.as_str(),
            second_root_display.as_str(),
        ] {
            assert!(!diagnostics.contains(forbidden));
        }
    }

    #[test]
    fn slot_pairs_reject_nonadjacent_generations_phase_regressions_and_restored_entry_mismatch() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let id = saved_host_id("invalid-pair-host-id-sentinel");

        let generation_root = temporary.path().join("nonadjacent");
        let mut transaction = begin_transaction(&generation_root, std::slice::from_ref(&id))
            .expect("begin nonadjacent transaction");
        transaction
            .activate(&[(id.clone(), LegacyPreviousCredentialState::Absent)])
            .expect("activate nonadjacent transaction");
        let mut forged = valid_envelope(&generation_root, Slot::A);
        forged.generation += 2;
        rewrite_checked_envelope(&generation_root, &mut forged);
        assert!(matches!(
            LegacyImportTransaction::load(&generation_root),
            Err(LegacyImportTransactionError::RecoverySlotsUnavailable)
        ));

        let regression_root = temporary.path().join("phase-regression");
        let mut transaction = begin_transaction(&regression_root, std::slice::from_ref(&id))
            .expect("begin regression transaction");
        transaction
            .activate(&[(id.clone(), LegacyPreviousCredentialState::Absent)])
            .expect("activate regression transaction");
        transaction
            .mark_rollback_targets_restored()
            .expect("mark regression transaction restored");
        let mut forged = valid_envelope(&regression_root, Slot::A);
        forged.phase = LegacyImportTransactionPhase::Active;
        rewrite_checked_envelope(&regression_root, &mut forged);
        assert!(matches!(
            LegacyImportTransaction::load(&regression_root),
            Err(LegacyImportTransactionError::RecoverySlotsUnavailable)
        ));

        let entries_root = temporary.path().join("restored-entry-mismatch");
        let mut transaction = begin_transaction(&entries_root, std::slice::from_ref(&id))
            .expect("begin entries transaction");
        transaction
            .activate(&[(id.clone(), LegacyPreviousCredentialState::Absent)])
            .expect("activate entries transaction");
        transaction
            .mark_rollback_targets_restored()
            .expect("mark entries transaction restored");
        let mut forged = valid_envelope(&entries_root, Slot::B);
        forged.entries[0].previous = LegacyPreviousCredentialState::BackedUp;
        rewrite_checked_envelope(&entries_root, &mut forged);
        assert!(matches!(
            LegacyImportTransaction::load(&entries_root),
            Err(LegacyImportTransactionError::RecoverySlotsUnavailable)
        ));

        let skipped_blob_root = temporary.path().join("skipped-blob-phase");
        let managed = begin_blob_transaction(&skipped_blob_root, std::slice::from_ref(&id))
            .expect("begin managed skip-phase transaction");
        let skipped = JournalEnvelope::new_with_blob_publication(
            Slot::B,
            2,
            managed.transaction_id(),
            managed.before_graph_commitment().clone(),
            managed.after_graph_commitment().clone(),
            true,
            LegacyImportTransactionPhase::Active,
            vec![host_entry(
                id.clone(),
                LegacyPreviousCredentialState::Absent,
            )],
        )
        .expect("construct individually valid skipped-phase slot");
        write_slot(&skipped_blob_root, &skipped).expect("write skipped-phase slot");
        assert!(matches!(
            LegacyImportTransaction::load(&skipped_blob_root),
            Err(LegacyImportTransactionError::RecoverySlotsUnavailable)
        ));

        let blob_regression_root = temporary.path().join("blob-phase-regression");
        let mut managed = begin_blob_transaction(&blob_regression_root, std::slice::from_ref(&id))
            .expect("begin managed regression transaction");
        managed
            .mark_blobs_durable()
            .expect("mark managed regression blobs durable");
        managed
            .activate(&[(id.clone(), LegacyPreviousCredentialState::Absent)])
            .expect("activate managed regression transaction");
        let mut forged = valid_envelope(&blob_regression_root, Slot::A);
        assert_eq!(forged.generation, 5);
        forged.phase = LegacyImportTransactionPhase::BlobsDurable;
        rewrite_checked_envelope(&blob_regression_root, &mut forged);
        assert!(matches!(
            LegacyImportTransaction::load(&blob_regression_root),
            Err(LegacyImportTransactionError::RecoverySlotsUnavailable)
        ));

        let format_regression_root = temporary.path().join("format-regression");
        let mut current = begin_transaction(&format_regression_root, std::slice::from_ref(&id))
            .expect("begin format regression transaction");
        current
            .record_previous(&id, LegacyPreviousCredentialState::Absent)
            .expect("publish current second slot");
        let mut forged = valid_envelope(&format_regression_root, Slot::B);
        forged.format_version = LEGACY_JOURNAL_FORMAT_VERSION;
        rewrite_checked_envelope(&format_regression_root, &mut forged);
        assert!(matches!(
            LegacyImportTransaction::load(&format_regression_root),
            Err(LegacyImportTransactionError::RecoverySlotsUnavailable)
        ));
    }

    #[test]
    fn vault_durable_dual_publication_is_idempotent_and_an_interrupted_mark_resumes() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let id = saved_host_id("vault-durable-host-id");
        let root = temporary.path().join("complete-vault-durable");
        let mut transaction = begin_transaction(&root, std::slice::from_ref(&id))
            .expect("begin vault-durable transaction");
        assert_eq!(
            transaction.mark_vault_durable(),
            Err(LegacyImportTransactionError::InvalidStateTransition)
        );
        transaction
            .activate(&[(id.clone(), LegacyPreviousCredentialState::BackedUp)])
            .expect("activate vault-durable transaction");
        transaction
            .mark_vault_durable()
            .expect("dual-publish vault-durable state");
        assert_eq!(transaction.envelope.generation, 5);
        assert_eq!(
            transaction.phase(),
            LegacyImportTransactionPhase::VaultDurable
        );
        assert!(super::both_slots_have_semantics(
            &root,
            transaction.transaction_id(),
            transaction.before_graph_commitment(),
            transaction.after_graph_commitment(),
            transaction.requires_blob_publication(),
            LegacyImportTransactionPhase::VaultDurable,
            transaction.entries(),
        ));
        transaction
            .mark_vault_durable()
            .expect("vault-durable mark is idempotent");
        assert_eq!(transaction.envelope.generation, 5);
        assert_eq!(
            transaction.mark_rollback_targets_restored(),
            Err(LegacyImportTransactionError::InvalidStateTransition)
        );

        let interrupted_root = temporary.path().join("interrupted-vault-durable");
        let mut interrupted = begin_transaction(&interrupted_root, std::slice::from_ref(&id))
            .expect("begin interrupted vault-durable transaction");
        interrupted
            .activate(&[(id.clone(), LegacyPreviousCredentialState::BackedUp)])
            .expect("activate interrupted vault-durable transaction");
        interrupted
            .publish_next(
                LegacyImportTransactionPhase::VaultDurable,
                interrupted.envelope.entries.clone(),
            )
            .expect("publish first vault-durable slot");
        assert_eq!(interrupted.envelope.generation, 4);

        let mut recovered = LegacyImportTransaction::load(&interrupted_root)
            .expect("load Active-to-vault-durable transition")
            .expect("vault-durable recovery transaction");
        assert_eq!(
            recovered.phase(),
            LegacyImportTransactionPhase::VaultDurable
        );
        recovered
            .mark_vault_durable()
            .expect("fill remaining vault-durable slot");
        assert_eq!(recovered.envelope.generation, 5);
        assert!(super::both_slots_have_semantics(
            &interrupted_root,
            recovered.transaction_id(),
            recovered.before_graph_commitment(),
            recovered.after_graph_commitment(),
            recovered.requires_blob_publication(),
            LegacyImportTransactionPhase::VaultDurable,
            recovered.entries(),
        ));
    }

    #[test]
    fn highest_valid_generation_wins_and_one_corrupt_slot_falls_back() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let root = temporary.path().join("journal");
        let first = saved_host_id("recovery-host-a");
        let second = saved_host_id("recovery-host-b");
        let mut transaction =
            begin_transaction(&root, &[first.clone(), second.clone()]).expect("begin transaction");
        transaction
            .record_previous(&first, LegacyPreviousCredentialState::Absent)
            .expect("generation two");
        transaction
            .record_previous(&second, LegacyPreviousCredentialState::BackedUp)
            .expect("generation three");

        let latest = LegacyImportTransaction::load(&root)
            .expect("load latest")
            .expect("transaction");
        assert_eq!(latest.envelope.generation, 3);
        assert_eq!(
            entry_state(&latest, &second),
            LegacyPreviousCredentialState::BackedUp
        );

        fs::write(root.join(SLOT_A_FILE), b"corrupt latest slot").expect("corrupt latest");
        let mut recovered = LegacyImportTransaction::load(&root)
            .expect("recover older slot")
            .expect("fallback transaction");
        assert_eq!(recovered.envelope.generation, 2);
        assert_eq!(
            entry_state(&recovered, &second),
            LegacyPreviousCredentialState::Unknown
        );
        recovered
            .record_previous(&second, LegacyPreviousCredentialState::BackedUp)
            .expect("repair inactive slot with next generation");
        assert_eq!(recovered.envelope.generation, 3);
        assert!(matches!(
            probe_slot(&root, Slot::A),
            super::SlotProbe::Valid(_)
        ));

        fs::write(root.join(SLOT_B_FILE), b"corrupt older slot").expect("corrupt older");
        assert!(
            LegacyImportTransaction::load(&root)
                .expect("single-slot fallback")
                .is_some()
        );
        fs::write(root.join(SLOT_A_FILE), b"corrupt remaining slot").expect("corrupt remaining");
        assert!(matches!(
            LegacyImportTransaction::load(&root),
            Err(LegacyImportTransactionError::RecoverySlotsUnavailable)
        ));
    }

    #[test]
    fn valid_checksum_cannot_hide_duplicate_ids_and_checksum_tampering_falls_back() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let root = temporary.path().join("journal");
        let id = saved_host_id("forged-duplicate-id-sentinel");
        let transaction =
            begin_transaction(&root, std::slice::from_ref(&id)).expect("begin transaction");
        let mut forged = transaction.envelope.clone();
        forged.entries.push(forged.entries[0].clone());
        forged.checksum = journal_checksum(
            &forged.magic,
            forged.format_version,
            forged.slot,
            forged.generation,
            forged.transaction_id,
            &forged.before_graph_commitment,
            &forged.after_graph_commitment,
            forged.requires_blob_publication,
            forged.phase,
            &forged.entries,
        )
        .expect("forged checksum");
        fs::write(
            root.join(SLOT_A_FILE),
            serde_json::to_vec(&forged).expect("forged JSON"),
        )
        .expect("write forged journal");
        assert!(matches!(
            LegacyImportTransaction::load(&root),
            Err(LegacyImportTransactionError::RecoverySlotsUnavailable)
        ));

        let second_root = temporary.path().join("checksum");
        let mut transaction = begin_transaction(&second_root, std::slice::from_ref(&id))
            .expect("begin checksum transaction");
        transaction
            .record_previous(&id, LegacyPreviousCredentialState::Absent)
            .expect("generation two");
        let mut latest: Value =
            serde_json::from_slice(&fs::read(second_root.join(SLOT_B_FILE)).expect("latest bytes"))
                .expect("latest JSON");
        latest["phase"] = Value::String("rollbackTargetsRestored".to_owned());
        fs::write(
            second_root.join(SLOT_B_FILE),
            serde_json::to_vec(&latest).expect("tampered JSON"),
        )
        .expect("tamper latest without checksum");
        let recovered = LegacyImportTransaction::load(&second_root)
            .expect("fall back after checksum mismatch")
            .expect("older transaction");
        assert_eq!(recovered.envelope.generation, 1);
        assert_eq!(
            entry_state(&recovered, &id),
            LegacyPreviousCredentialState::Unknown
        );
    }

    #[test]
    fn publication_is_re_read_and_a_bad_inactive_slot_never_hides_the_active_one() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let root = temporary.path().join("journal");
        let id = saved_host_id("verification-host-id");
        let transaction =
            begin_transaction(&root, std::slice::from_ref(&id)).expect("begin transaction");
        let mut entries = transaction.envelope.entries.clone();
        entries[0].previous = LegacyPreviousCredentialState::Absent;
        let next = super::JournalEnvelope::new(
            Slot::B,
            2,
            transaction.transaction_id(),
            transaction.before_graph_commitment().clone(),
            transaction.after_graph_commitment().clone(),
            LegacyImportTransactionPhase::Active,
            entries,
        )
        .expect("next envelope");
        let error = write_slot_with_after_sync(&root, &next, |published| {
            fs::write(published, b"corrupt after sync")
                .map_err(|_| LegacyImportTransactionError::Storage)
        })
        .expect_err("re-read must reject corrupt publication");
        assert_eq!(
            error,
            LegacyImportTransactionError::PublicationVerificationFailed
        );
        let recovered = LegacyImportTransaction::load(&root)
            .expect("load active fallback")
            .expect("generation one survives");
        assert_eq!(recovered.envelope.generation, 1);
        assert_eq!(
            entry_state(&recovered, &id),
            LegacyPreviousCredentialState::Unknown
        );
    }

    #[test]
    fn finish_deletes_old_then_latest_so_an_interrupted_finish_cannot_revive_old_state() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let root = temporary.path().join("journal");
        let id = saved_host_id("finish-host-id-sentinel");
        let mut transaction =
            begin_transaction(&root, std::slice::from_ref(&id)).expect("begin transaction");
        transaction
            .record_previous(&id, LegacyPreviousCredentialState::Absent)
            .expect("latest generation in B");
        assert!(root.join(SLOT_A_FILE).is_file());
        assert!(root.join(SLOT_B_FILE).is_file());

        let transaction_id = transaction.transaction_id();
        let error = transaction
            .finish_with_after_old_deleted(|| Err(LegacyImportTransactionError::Storage))
            .expect_err("simulate crash after old-slot deletion");
        assert_eq!(error, LegacyImportTransactionError::Storage);
        assert!(!root.join(SLOT_A_FILE).exists());
        assert!(root.join(SLOT_B_FILE).is_file());
        let surviving = LegacyImportTransaction::load(&root)
            .expect("load surviving latest slot")
            .expect("latest transaction survives");
        assert_eq!(surviving.transaction_id(), transaction_id);
        assert_eq!(surviving.envelope.generation, 2);
        assert_eq!(
            entry_state(&surviving, &id),
            LegacyPreviousCredentialState::Absent
        );

        surviving.finish().expect("finish remaining latest slot");
        assert!(!root.join(SLOT_A_FILE).exists());
        assert!(!root.join(SLOT_B_FILE).exists());
        assert!(
            LegacyImportTransaction::load(&root)
                .expect("load after finish")
                .is_none()
        );
    }

    #[test]
    fn a_single_terminal_slot_after_interrupted_finish_loads_and_rebuilds_redundancy() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let root = temporary.path().join("terminal-finish-interruption");
        let id = saved_host_id("terminal-finish-host-id");
        let mut transaction = begin_transaction(&root, std::slice::from_ref(&id))
            .expect("begin terminal transaction");
        transaction
            .activate(&[(id.clone(), LegacyPreviousCredentialState::BackedUp)])
            .expect("activate terminal transaction");
        transaction
            .mark_vault_durable()
            .expect("mark vault durable in both slots");
        let transaction_id = transaction.transaction_id();

        let error = transaction
            .finish_with_after_old_deleted(|| Err(LegacyImportTransactionError::Storage))
            .expect_err("interrupt finish after deleting the older terminal slot");
        assert_eq!(error, LegacyImportTransactionError::Storage);
        assert!(root.join(SLOT_A_FILE).is_file());
        assert!(!root.join(SLOT_B_FILE).exists());
        let surviving_bytes = fs::read(root.join(SLOT_A_FILE)).expect("surviving terminal slot");

        let mut recovered = LegacyImportTransaction::load(&root)
            .expect("load single valid terminal slot")
            .expect("terminal transaction survives");
        assert_eq!(recovered.transaction_id(), transaction_id);
        assert_eq!(
            recovered.phase(),
            LegacyImportTransactionPhase::VaultDurable
        );
        assert_eq!(
            fs::read(root.join(SLOT_A_FILE)).expect("unchanged terminal slot"),
            surviving_bytes
        );
        recovered
            .mark_vault_durable()
            .expect("rebuild the missing terminal slot");
        assert_eq!(recovered.envelope.generation, 6);
        assert!(super::both_slots_have_semantics(
            &root,
            transaction_id,
            recovered.before_graph_commitment(),
            recovered.after_graph_commitment(),
            recovered.requires_blob_publication(),
            LegacyImportTransactionPhase::VaultDurable,
            recovered.entries(),
        ));

        recovered.finish().expect("finish rebuilt terminal journal");
        assert!(!root.join(SLOT_A_FILE).exists());
        assert!(!root.join(SLOT_B_FILE).exists());
    }

    #[test]
    fn diagnostics_never_include_ids_transaction_ids_paths_or_source_values() {
        let temporary = tempfile::tempdir().expect("temporary journal root");
        let root = temporary.path().join("diagnostic-path-sentinel");
        let id = saved_host_id("diagnostic-host-id-sentinel");
        let unknown = saved_host_id("unknown-host-id-sentinel");
        let mut transaction =
            begin_transaction(&root, std::slice::from_ref(&id)).expect("begin transaction");
        let transaction_id = transaction.transaction_id().to_string();
        let error = transaction
            .record_previous(&unknown, LegacyPreviousCredentialState::Absent)
            .expect_err("unknown ID must fail");
        let diagnostics = format!("{transaction:?} {error:?} {error}");
        let root_display = root.display().to_string();
        for forbidden in [
            id.as_str(),
            unknown.as_str(),
            transaction_id.as_str(),
            root_display.as_str(),
            "plaintext-secret-sentinel",
        ] {
            assert!(!diagnostics.contains(forbidden));
        }

        let invalid_root = temporary.path().join("invalid-layout-path-sentinel");
        fs::write(&invalid_root, b"not a directory").expect("invalid root file");
        let error = begin_transaction(&invalid_root, std::slice::from_ref(&id))
            .expect_err("invalid root must fail safely");
        let diagnostics = format!("{error:?} {error}");
        assert!(!diagnostics.contains(id.as_str()));
        assert!(!diagnostics.contains(&invalid_root.display().to_string()));
    }

    fn root_has_slot(root: &std::path::Path) -> bool {
        root.join(SLOT_A_FILE).exists() || root.join(SLOT_B_FILE).exists()
    }
}
