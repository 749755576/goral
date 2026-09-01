use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::catalog_classification::{
    classify_custom_groups, classify_groups, classify_hosts, classify_identity_references,
    classify_managed_ssh_keys, classify_notes, classify_password_identities,
    classify_port_forward_rules, classify_proxy_profiles, classify_snippets,
    classify_ssh_key_references, group_business_fields_equal, identity_business_fields_equal,
    import_business_fields_equal, managed_key_business_fields_equal,
    password_identity_business_fields_equal, proxy_profile_business_fields_equal,
    ssh_key_business_fields_equal,
};
use crate::connection_log::{
    SavedConnectionLog, SavedConnectionLogCatalog, validate_saved_connection_logs,
};
use crate::group::SavedGroupCatalog;
use crate::group_config::{
    SavedGroupConfig, SavedGroupIdentityReference, SavedGroupOverride, SavedGroupProxyOverride,
};
use crate::known_host::{SavedKnownHost, validate_saved_known_hosts};
use crate::model::{
    SavedHost, SavedHostDraft, SavedHostId, SavedHostUpdate, SavedIdentityReference,
    SavedManagedSshKey, SavedPasswordIdentity, SavedProxyConfig, SavedProxyProfile,
    SavedSshKeyCategory, SavedSshKeyReference, ValidationError,
};
use crate::notes_snippets::{
    SavedHostReferenceKind, SavedNotesSnippetsCatalog, SavedNotesSnippetsError, SavedSnippetKind,
};
use crate::port_forward::{
    SavedPortForwardRule, SavedPortForwardRuleError, normalize_and_validate_port_forward_rules,
};

const OWNER_MAGIC: &str = "netcatty-saved-host-store";
const SNAPSHOT_MAGIC: &str = "netcatty-saved-host-snapshot";
const OWNER_FORMAT_VERSION: u32 = 1;
const SNAPSHOT_FORMAT_V1: u32 = 1;
const SNAPSHOT_FORMAT_V2: u32 = 2;
const SNAPSHOT_FORMAT_V3: u32 = 3;
const SNAPSHOT_FORMAT_V4: u32 = 4;
const SNAPSHOT_FORMAT_V5: u32 = 5;
const SNAPSHOT_FORMAT_V6: u32 = 6;
const SNAPSHOT_FORMAT_V7: u32 = 7;
const SNAPSHOT_FORMAT_V8: u32 = 8;
const SNAPSHOT_FORMAT_V9: u32 = 9;
const SNAPSHOT_FORMAT_V10: u32 = 10;
const SNAPSHOT_FORMAT_V11: u32 = 11;
const OWNER_FILE: &str = "owner.json";
const SLOT_A_DIRECTORY: &str = "slot-a";
const SLOT_B_DIRECTORY: &str = "slot-b";
const MAX_OWNER_BYTES: u64 = 4 * 1024;
const MAX_SNAPSHOT_BYTES: u64 = 32 * 1024 * 1024;
const PUBLISH_ATTEMPTS: usize = 8;

type ProcessGate = Arc<Mutex<()>>;

static PROCESS_GATES: OnceLock<Mutex<HashMap<PathBuf, Weak<Mutex<()>>>>> = OnceLock::new();
static INVENTORY_REVISION_KEY: OnceLock<[u8; 32]> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SavedVaultEntityKind {
    Host,
    SshKeyReference,
    ManagedSshKey,
    IdentityReference,
    PasswordIdentity,
    ProxyProfile,
    Group,
    Snippet,
    Note,
    PortForwardRule,
    KnownHost,
}

impl fmt::Display for SavedVaultEntityKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Host => "saved host",
            Self::SshKeyReference => "SSH key reference",
            Self::ManagedSshKey => "managed SSH key",
            Self::IdentityReference => "identity reference",
            Self::PasswordIdentity => "password identity",
            Self::ProxyProfile => "proxy profile",
            Self::Group => "saved group",
            Self::Snippet => "snippet",
            Self::Note => "note",
            Self::PortForwardRule => "port-forward rule",
            Self::KnownHost => "known host",
        })
    }
}

#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    Serialization,
    Validation(ValidationError),
    ArtifactConflict,
    InvalidOwner,
    BothSlotsCorrupt,
    ConflictingGeneration,
    GenerationOverflow,
    DuplicateId(SavedHostId),
    NotFound(SavedHostId),
    RevisionConflict {
        id: SavedHostId,
        expected: u64,
        actual: u64,
    },
    InventoryRevisionConflict {
        expected: SavedHostInventoryRevision,
        actual: SavedHostInventoryRevision,
    },
    ImportConflict(SavedHostId),
    DuplicateGraphEntityId(SavedVaultEntityKind),
    GraphImportConflict(SavedVaultEntityKind),
    MissingGraphReference {
        source: SavedVaultEntityKind,
        target: SavedVaultEntityKind,
    },
    IncompatibleGraphReference {
        source: SavedVaultEntityKind,
        target: SavedVaultEntityKind,
    },
    GraphImportPlanMismatch,
    GraphReplacementPlanMismatch,
    SnapshotDurabilityUnconfirmed,
    ManagedSecretRetentionUncertain,
    ClockUnavailable,
    LockPoisoned,
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => formatter.write_str("saved-host store I/O failed"),
            Self::Serialization => formatter.write_str("saved-host serialization failed"),
            Self::Validation(error) => write!(formatter, "saved-host validation failed: {error}"),
            Self::ArtifactConflict => {
                formatter.write_str("saved-host store path contains an unowned artifact")
            }
            Self::InvalidOwner => formatter.write_str("saved-host store owner marker is invalid"),
            Self::BothSlotsCorrupt => {
                formatter.write_str("both saved-host recovery slots are unavailable or corrupt")
            }
            Self::ConflictingGeneration => {
                formatter.write_str("saved-host slots contain a conflicting generation")
            }
            Self::GenerationOverflow => {
                formatter.write_str("saved-host snapshot generation overflowed")
            }
            Self::DuplicateId(id) => write!(formatter, "saved-host ID {id} is duplicated"),
            Self::NotFound(id) => write!(formatter, "saved host {id} was not found"),
            Self::RevisionConflict {
                id,
                expected,
                actual,
            } => write!(
                formatter,
                "saved host {id} revision conflict: expected {expected}, actual {actual}"
            ),
            Self::InventoryRevisionConflict { .. } => {
                formatter.write_str("saved-host inventory revision conflict")
            }
            Self::ImportConflict(id) => {
                write!(
                    formatter,
                    "saved-host import conflicts with existing ID {id}"
                )
            }
            Self::DuplicateGraphEntityId(entity) => {
                write!(formatter, "vault import contains a duplicated {entity}")
            }
            Self::GraphImportConflict(entity) => {
                write!(
                    formatter,
                    "vault import conflicts with an existing {entity}"
                )
            }
            Self::MissingGraphReference { source, target } => {
                write!(formatter, "vault {source} references a missing {target}")
            }
            Self::IncompatibleGraphReference { source, target } => {
                write!(
                    formatter,
                    "vault {source} references an incompatible {target}"
                )
            }
            Self::GraphImportPlanMismatch => {
                formatter.write_str("vault import no longer matches its sealed graph plan")
            }
            Self::GraphReplacementPlanMismatch => {
                formatter.write_str("vault replacement no longer matches its sealed graph plan")
            }
            Self::SnapshotDurabilityUnconfirmed => {
                formatter.write_str("current saved-host snapshot durability could not be confirmed")
            }
            Self::ManagedSecretRetentionUncertain => {
                formatter.write_str("managed-secret retention set could not be determined safely")
            }
            Self::ClockUnavailable => formatter.write_str("system clock is unavailable"),
            Self::LockPoisoned => formatter.write_str("saved-host store lock is poisoned"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Validation(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for StoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ValidationError> for StoreError {
    fn from(error: ValidationError) -> Self {
        Self::Validation(error)
    }
}

/// An opaque optimistic-concurrency token for the complete saved-host
/// inventory.
///
/// The token is tied to both the physical store identity and the recovery
/// state that was observed while loading it. Its fields are intentionally
/// private and carry a process-local HMAC seal: callers can round-trip a token
/// through Serde, but cannot assemble or alter one from generation numbers.
/// A token intentionally becomes stale after the desktop process restarts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SavedHostInventoryRevision {
    store_id: String,
    loaded_generation: u64,
    max_seen_generation: u64,
    seal: String,
}

impl SavedHostInventoryRevision {
    pub fn loaded_generation(&self) -> u64 {
        self.loaded_generation
    }

    pub fn max_seen_generation(&self) -> u64 {
        self.max_seen_generation
    }
}

/// Compatibility alias for the inventory token now covering every persisted
/// Vault catalog, not only hosts.
pub type SavedVaultInventoryRevision = SavedHostInventoryRevision;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedKnownHostCatalog {
    revision: SavedVaultInventoryRevision,
    known_hosts: Vec<SavedKnownHost>,
}

impl SavedKnownHostCatalog {
    pub fn revision(&self) -> &SavedVaultInventoryRevision {
        &self.revision
    }

    pub fn known_hosts(&self) -> &[SavedKnownHost] {
        &self.known_hosts
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedKnownHostCatalogCommit {
    revision: SavedVaultInventoryRevision,
    known_hosts: Vec<SavedKnownHost>,
    durability: SavedVaultCommitDurability,
}

/// Renderer-safe Connection Logs metadata plus the optimistic revision of the
/// complete Vault inventory observed in the same read.
///
/// Replay/terminal data is deliberately absent. It belongs to a separately
/// protected store and must never be added to this DTO or the Vault snapshot.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedConnectionLogCatalogState {
    revision: SavedVaultInventoryRevision,
    catalog: SavedConnectionLogCatalog,
}

impl SavedConnectionLogCatalogState {
    pub fn revision(&self) -> &SavedVaultInventoryRevision {
        &self.revision
    }

    pub fn catalog(&self) -> &SavedConnectionLogCatalog {
        &self.catalog
    }

    pub fn logs(&self) -> &[SavedConnectionLog] {
        &self.catalog.logs
    }
}

/// Result of one complete-inventory-CAS Connection Logs metadata replacement.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedConnectionLogCatalogCommit {
    revision: SavedVaultInventoryRevision,
    catalog: SavedConnectionLogCatalog,
    durability: SavedVaultCommitDurability,
}

impl SavedConnectionLogCatalogCommit {
    pub fn revision(&self) -> &SavedVaultInventoryRevision {
        &self.revision
    }

    pub fn catalog(&self) -> &SavedConnectionLogCatalog {
        &self.catalog
    }

    pub fn logs(&self) -> &[SavedConnectionLog] {
        &self.catalog.logs
    }

    pub const fn durability(&self) -> SavedVaultCommitDurability {
        self.durability
    }
}

impl SavedKnownHostCatalogCommit {
    pub fn revision(&self) -> &SavedVaultInventoryRevision {
        &self.revision
    }

    pub fn known_hosts(&self) -> &[SavedKnownHost] {
        &self.known_hosts
    }

    pub fn durability(&self) -> SavedVaultCommitDurability {
        self.durability
    }
}

/// One backend-only managed-secret revision that must remain available while
/// any valid Vault recovery snapshot still references it.
///
/// This value intentionally has no Serde or `Display` implementation. It may
/// cross trusted Rust backend boundaries, but must never become a renderer
/// DTO. Diagnostics redact the entity ID and opaque locator together.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SavedVaultManagedSecretRetention {
    entity_id: crate::model::SavedSshKeyReferenceId,
    backend_locator: crate::model::SavedSecretObjectLocator,
    custody_revision: u64,
}

impl SavedVaultManagedSecretRetention {
    pub fn entity_id(&self) -> &crate::model::SavedSshKeyReferenceId {
        &self.entity_id
    }

    pub fn backend_locator(&self) -> &crate::model::SavedSecretObjectLocator {
        &self.backend_locator
    }

    pub fn custody_revision(&self) -> u64 {
        self.custody_revision
    }
}

impl fmt::Debug for SavedVaultManagedSecretRetention {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SavedVaultManagedSecretRetention([redacted])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SavedHostImportDisposition {
    Importable,
    Duplicate,
    Conflict,
}

pub type SavedVaultImportDisposition = SavedHostImportDisposition;

/// A domain-separated SHA-256 commitment to one complete normalized Vault
/// graph. The digest is safe to persist in the local recovery journal, while
/// `Debug` and `Display` deliberately never reveal its value.
#[derive(Clone, PartialEq, Eq)]
pub struct SavedVaultGraphCommitment(String);

impl SavedVaultGraphCommitment {
    pub fn from_digest(digest: [u8; 32]) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(64);
        for byte in digest {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Self(encoded)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SavedVaultGraphCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SavedVaultGraphCommitment([redacted])")
    }
}

impl fmt::Display for SavedVaultGraphCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted Vault graph commitment]")
    }
}

impl Serialize for SavedVaultGraphCommitment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SavedVaultGraphCommitment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(serde::de::Error::custom(
                "Vault graph commitment must be canonical lowercase SHA-256 hex",
            ));
        }
        Ok(Self(value))
    }
}

/// Describes what is known about the filesystem publication backing a commit.
///
/// A snapshot hard link is the irreversible publication point. `Err` from a
/// mutating store method therefore means that this point was not reached.
/// Once the link succeeds, later sync or verification failures are represented
/// here so cross-store callers never mistake an already-published mutation for
/// a transaction that is safe to compensate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SavedVaultCommitDurability {
    /// No snapshot was needed, or the new directory entry was synced.
    #[default]
    Durable,
    /// The final snapshot was re-read exactly after directory syncing failed.
    PublishedDurabilityUncertain,
    /// The hard link succeeded, but the final snapshot could not be confirmed.
    PublicationIndeterminate,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SavedVaultGraph {
    #[serde(default)]
    hosts: Vec<SavedHost>,
    #[serde(default)]
    ssh_key_references: Vec<SavedSshKeyReference>,
    #[serde(default)]
    managed_ssh_keys: Vec<SavedManagedSshKey>,
    #[serde(default)]
    identity_references: Vec<SavedIdentityReference>,
    #[serde(default)]
    password_identities: Vec<SavedPasswordIdentity>,
    #[serde(default)]
    proxy_profiles: Vec<SavedProxyProfile>,
    #[serde(default)]
    groups: Vec<SavedGroupConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    custom_groups: Option<SavedGroupCatalog>,
    #[serde(default, skip_serializing_if = "SavedNotesSnippetsCatalog::is_absent")]
    notes_snippets: SavedNotesSnippetsCatalog,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    port_forward_rules: Vec<SavedPortForwardRule>,
}

impl SavedVaultGraph {
    pub fn new(
        hosts: Vec<SavedHost>,
        ssh_key_references: Vec<SavedSshKeyReference>,
        identity_references: Vec<SavedIdentityReference>,
    ) -> Self {
        Self {
            hosts,
            ssh_key_references,
            managed_ssh_keys: Vec::new(),
            identity_references,
            password_identities: Vec::new(),
            proxy_profiles: Vec::new(),
            groups: Vec::new(),
            custom_groups: None,
            notes_snippets: Default::default(),
            port_forward_rules: Vec::new(),
        }
    }

    pub fn new_with_managed_ssh_keys(
        hosts: Vec<SavedHost>,
        ssh_key_references: Vec<SavedSshKeyReference>,
        managed_ssh_keys: Vec<SavedManagedSshKey>,
        identity_references: Vec<SavedIdentityReference>,
    ) -> Self {
        Self {
            hosts,
            ssh_key_references,
            managed_ssh_keys,
            identity_references,
            password_identities: Vec::new(),
            proxy_profiles: Vec::new(),
            groups: Vec::new(),
            custom_groups: None,
            notes_snippets: SavedNotesSnippetsCatalog::default(),
            port_forward_rules: Vec::new(),
        }
    }

    /// Constructs a complete Vault v4 graph including the independent
    /// password-identity catalog.
    pub fn new_with_password_identities(
        hosts: Vec<SavedHost>,
        ssh_key_references: Vec<SavedSshKeyReference>,
        managed_ssh_keys: Vec<SavedManagedSshKey>,
        identity_references: Vec<SavedIdentityReference>,
        password_identities: Vec<SavedPasswordIdentity>,
    ) -> Self {
        Self {
            hosts,
            ssh_key_references,
            managed_ssh_keys,
            identity_references,
            password_identities,
            proxy_profiles: Vec::new(),
            groups: Vec::new(),
            custom_groups: None,
            notes_snippets: SavedNotesSnippetsCatalog::default(),
            port_forward_rules: Vec::new(),
        }
    }

    /// Constructs a complete Vault v6 graph including proxy profiles and
    /// saved group configuration.
    pub fn new_with_proxy_profiles(
        hosts: Vec<SavedHost>,
        ssh_key_references: Vec<SavedSshKeyReference>,
        managed_ssh_keys: Vec<SavedManagedSshKey>,
        identity_references: Vec<SavedIdentityReference>,
        password_identities: Vec<SavedPasswordIdentity>,
        proxy_profiles: Vec<SavedProxyProfile>,
        groups: Vec<SavedGroupConfig>,
    ) -> Self {
        Self {
            hosts,
            ssh_key_references,
            managed_ssh_keys,
            identity_references,
            password_identities,
            proxy_profiles,
            groups,
            custom_groups: None,
            notes_snippets: SavedNotesSnippetsCatalog::default(),
            port_forward_rules: Vec::new(),
        }
    }

    /// Constructs the complete latest Vault graph, including the optional
    /// Notes + Snippets import catalogs and their absent-versus-empty scope.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_notes_snippets(
        hosts: Vec<SavedHost>,
        ssh_key_references: Vec<SavedSshKeyReference>,
        managed_ssh_keys: Vec<SavedManagedSshKey>,
        identity_references: Vec<SavedIdentityReference>,
        password_identities: Vec<SavedPasswordIdentity>,
        proxy_profiles: Vec<SavedProxyProfile>,
        groups: Vec<SavedGroupConfig>,
        notes_snippets: SavedNotesSnippetsCatalog,
    ) -> Self {
        Self {
            hosts,
            ssh_key_references,
            managed_ssh_keys,
            identity_references,
            password_identities,
            proxy_profiles,
            groups,
            custom_groups: None,
            notes_snippets,
            port_forward_rules: Vec::new(),
        }
    }

    /// Constructs the complete latest Vault graph, including durable
    /// port-forward rules. Runtime forwarding phases remain process-owned and
    /// are never part of this graph.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_port_forward_rules(
        hosts: Vec<SavedHost>,
        ssh_key_references: Vec<SavedSshKeyReference>,
        managed_ssh_keys: Vec<SavedManagedSshKey>,
        identity_references: Vec<SavedIdentityReference>,
        password_identities: Vec<SavedPasswordIdentity>,
        proxy_profiles: Vec<SavedProxyProfile>,
        groups: Vec<SavedGroupConfig>,
        notes_snippets: SavedNotesSnippetsCatalog,
        port_forward_rules: Vec<SavedPortForwardRule>,
    ) -> Self {
        Self {
            hosts,
            ssh_key_references,
            managed_ssh_keys,
            identity_references,
            password_identities,
            proxy_profiles,
            groups,
            custom_groups: None,
            notes_snippets,
            port_forward_rules,
        }
    }

    pub fn hosts(&self) -> &[SavedHost] {
        &self.hosts
    }

    pub fn ssh_key_references(&self) -> &[SavedSshKeyReference] {
        &self.ssh_key_references
    }

    pub fn managed_ssh_keys(&self) -> &[SavedManagedSshKey] {
        &self.managed_ssh_keys
    }

    pub fn identity_references(&self) -> &[SavedIdentityReference] {
        &self.identity_references
    }

    pub fn password_identities(&self) -> &[SavedPasswordIdentity] {
        &self.password_identities
    }

    pub fn proxy_profiles(&self) -> &[SavedProxyProfile] {
        &self.proxy_profiles
    }

    pub fn groups(&self) -> &[SavedGroupConfig] {
        &self.groups
    }

    /// Explicit legacy `customGroups[]` paths, including groups with no host
    /// and no GroupConfig defaults. Implicit ancestors are projected by the
    /// catalog and are never persisted as explicit groups.
    pub fn group_catalog(&self) -> Option<&SavedGroupCatalog> {
        self.custom_groups.as_ref()
    }

    pub fn with_group_catalog(mut self, catalog: Option<SavedGroupCatalog>) -> Self {
        self.custom_groups = catalog;
        self
    }

    pub fn notes_snippets(&self) -> &SavedNotesSnippetsCatalog {
        &self.notes_snippets
    }

    pub fn port_forward_rules(&self) -> &[SavedPortForwardRule] {
        &self.port_forward_rules
    }

    pub fn with_port_forward_rules(mut self, rules: Vec<SavedPortForwardRule>) -> Self {
        self.port_forward_rules = rules;
        self
    }

    pub fn into_parts(
        self,
    ) -> (
        Vec<SavedHost>,
        Vec<SavedSshKeyReference>,
        Vec<SavedManagedSshKey>,
        Vec<SavedIdentityReference>,
    ) {
        assert!(
            self.password_identities.is_empty(),
            "password identities require SavedVaultGraph::into_all_parts"
        );
        assert!(
            self.proxy_profiles.is_empty(),
            "proxy profiles require SavedVaultGraph::into_complete_parts"
        );
        assert!(
            self.groups.is_empty(),
            "groups require SavedVaultGraph::into_complete_parts"
        );
        assert!(
            self.custom_groups.is_none(),
            "custom groups require SavedVaultGraph::into_current_parts"
        );
        assert!(
            self.notes_snippets.is_absent(),
            "notes/snippets require SavedVaultGraph::into_latest_parts"
        );
        assert!(
            self.port_forward_rules.is_empty(),
            "port-forward rules require SavedVaultGraph::into_current_parts"
        );
        (
            self.hosts,
            self.ssh_key_references,
            self.managed_ssh_keys,
            self.identity_references,
        )
    }

    /// Consumes every catalog, including password identities.
    pub fn into_all_parts(
        self,
    ) -> (
        Vec<SavedHost>,
        Vec<SavedSshKeyReference>,
        Vec<SavedManagedSshKey>,
        Vec<SavedIdentityReference>,
        Vec<SavedPasswordIdentity>,
    ) {
        assert!(
            self.proxy_profiles.is_empty(),
            "proxy profiles require SavedVaultGraph::into_complete_parts"
        );
        assert!(
            self.groups.is_empty(),
            "groups require SavedVaultGraph::into_complete_parts"
        );
        assert!(
            self.custom_groups.is_none(),
            "custom groups require SavedVaultGraph::into_current_parts"
        );
        assert!(
            self.notes_snippets.is_absent(),
            "notes/snippets require SavedVaultGraph::into_latest_parts"
        );
        assert!(
            self.custom_groups.is_none(),
            "custom groups require SavedVaultGraph::into_current_parts"
        );
        assert!(
            self.port_forward_rules.is_empty(),
            "port-forward rules require SavedVaultGraph::into_current_parts"
        );
        (
            self.hosts,
            self.ssh_key_references,
            self.managed_ssh_keys,
            self.identity_references,
            self.password_identities,
        )
    }

    /// Consumes every Vault v6 catalog.
    pub fn into_complete_parts(
        self,
    ) -> (
        Vec<SavedHost>,
        Vec<SavedSshKeyReference>,
        Vec<SavedManagedSshKey>,
        Vec<SavedIdentityReference>,
        Vec<SavedPasswordIdentity>,
        Vec<SavedProxyProfile>,
        Vec<SavedGroupConfig>,
    ) {
        assert!(
            self.notes_snippets.is_absent(),
            "notes/snippets require SavedVaultGraph::into_latest_parts"
        );
        assert!(
            self.custom_groups.is_none(),
            "custom groups require SavedVaultGraph::into_current_parts"
        );
        assert!(
            self.port_forward_rules.is_empty(),
            "port-forward rules require SavedVaultGraph::into_current_parts"
        );
        (
            self.hosts,
            self.ssh_key_references,
            self.managed_ssh_keys,
            self.identity_references,
            self.password_identities,
            self.proxy_profiles,
            self.groups,
        )
    }

    /// Consumes every catalog in the latest Vault graph.
    pub fn into_latest_parts(
        self,
    ) -> (
        Vec<SavedHost>,
        Vec<SavedSshKeyReference>,
        Vec<SavedManagedSshKey>,
        Vec<SavedIdentityReference>,
        Vec<SavedPasswordIdentity>,
        Vec<SavedProxyProfile>,
        Vec<SavedGroupConfig>,
        Option<SavedGroupCatalog>,
        SavedNotesSnippetsCatalog,
    ) {
        assert!(
            self.port_forward_rules.is_empty(),
            "port-forward rules require SavedVaultGraph::into_current_parts"
        );
        (
            self.hosts,
            self.ssh_key_references,
            self.managed_ssh_keys,
            self.identity_references,
            self.password_identities,
            self.proxy_profiles,
            self.groups,
            self.custom_groups,
            self.notes_snippets,
        )
    }

    /// Consumes every catalog in the current Vault graph.
    #[allow(clippy::type_complexity)]
    pub fn into_current_parts(
        self,
    ) -> (
        Vec<SavedHost>,
        Vec<SavedSshKeyReference>,
        Vec<SavedManagedSshKey>,
        Vec<SavedIdentityReference>,
        Vec<SavedPasswordIdentity>,
        Vec<SavedProxyProfile>,
        Vec<SavedGroupConfig>,
        Option<SavedGroupCatalog>,
        SavedNotesSnippetsCatalog,
        Vec<SavedPortForwardRule>,
    ) {
        (
            self.hosts,
            self.ssh_key_references,
            self.managed_ssh_keys,
            self.identity_references,
            self.password_identities,
            self.proxy_profiles,
            self.groups,
            self.custom_groups,
            self.notes_snippets,
            self.port_forward_rules,
        )
    }

    fn is_empty(&self) -> bool {
        self.hosts.is_empty()
            && self.ssh_key_references.is_empty()
            && self.managed_ssh_keys.is_empty()
            && self.identity_references.is_empty()
            && self.password_identities.is_empty()
            && self.proxy_profiles.is_empty()
            && self.groups.is_empty()
            && self.custom_groups.is_none()
            && self.notes_snippets.is_absent()
            && self.port_forward_rules.is_empty()
    }
}

/// A complete Vault graph whose selected immutable snapshot was confirmed
/// directory-durable without changing during confirmation.
///
/// This value is intentionally not serializable. It keeps the sealed
/// inventory revision and the graph together so callers can compare an
/// expected commit revision and inspect entity IDs without a second store
/// read and its accompanying time-of-check/time-of-use gap.
#[derive(Debug, Clone, PartialEq)]
pub struct SavedVaultDurableSnapshot {
    revision: SavedVaultInventoryRevision,
    commitment: SavedVaultGraphCommitment,
    graph: SavedVaultGraph,
    known_hosts: Vec<SavedKnownHost>,
    connection_logs: Vec<SavedConnectionLog>,
}

impl SavedVaultDurableSnapshot {
    pub fn revision(&self) -> &SavedVaultInventoryRevision {
        &self.revision
    }

    pub fn graph(&self) -> &SavedVaultGraph {
        &self.graph
    }

    pub fn commitment(&self) -> &SavedVaultGraphCommitment {
        &self.commitment
    }

    pub fn known_hosts(&self) -> &[SavedKnownHost] {
        &self.known_hosts
    }

    /// Safe Connection Logs metadata confirmed in the same immutable
    /// snapshot. Replay/terminal contents are never part of this value.
    pub fn connection_logs(&self) -> &[SavedConnectionLog] {
        &self.connection_logs
    }
}

/// A no-write projection of the exact normalized graph that
/// [`SavedHostStore::commit_graph_import`] would publish for one revision and
/// candidate set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedVaultGraphImportPlan {
    revision: SavedVaultInventoryRevision,
    before_graph_commitment: SavedVaultGraphCommitment,
    after_graph_commitment: SavedVaultGraphCommitment,
}

impl SavedVaultGraphImportPlan {
    pub fn revision(&self) -> &SavedVaultInventoryRevision {
        &self.revision
    }

    pub fn before_graph_commitment(&self) -> &SavedVaultGraphCommitment {
        &self.before_graph_commitment
    }

    pub fn after_graph_commitment(&self) -> &SavedVaultGraphCommitment {
        &self.after_graph_commitment
    }

    pub fn has_changes(&self) -> bool {
        self.before_graph_commitment != self.after_graph_commitment
    }
}

/// A no-write projection sealing the exact normalized graph before and after
/// one complete Vault graph replacement.
///
/// This backend-only value intentionally has no Serde or `Display`
/// implementation. Diagnostics redact the inventory token and both graph
/// commitments so a plan can never disclose store identifiers or entity
/// metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct SavedVaultGraphReplacementPlan {
    revision: SavedVaultInventoryRevision,
    before_graph_commitment: SavedVaultGraphCommitment,
    after_graph_commitment: SavedVaultGraphCommitment,
}

impl SavedVaultGraphReplacementPlan {
    pub fn revision(&self) -> &SavedVaultInventoryRevision {
        &self.revision
    }

    pub fn before_graph_commitment(&self) -> &SavedVaultGraphCommitment {
        &self.before_graph_commitment
    }

    pub fn after_graph_commitment(&self) -> &SavedVaultGraphCommitment {
        &self.after_graph_commitment
    }

    pub fn has_changes(&self) -> bool {
        self.before_graph_commitment != self.after_graph_commitment
    }
}

impl fmt::Debug for SavedVaultGraphReplacementPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SavedVaultGraphReplacementPlan")
            .field("has_changes", &self.has_changes())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SavedVaultGraphImportAssessment {
    revision: SavedVaultInventoryRevision,
    host_dispositions: Vec<SavedVaultImportDisposition>,
    ssh_key_reference_dispositions: Vec<SavedVaultImportDisposition>,
    managed_ssh_key_dispositions: Vec<SavedVaultImportDisposition>,
    identity_reference_dispositions: Vec<SavedVaultImportDisposition>,
    password_identity_dispositions: Vec<SavedVaultImportDisposition>,
    proxy_profile_dispositions: Vec<SavedVaultImportDisposition>,
    group_dispositions: Vec<SavedVaultImportDisposition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    custom_group_dispositions: Vec<SavedVaultImportDisposition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    snippet_dispositions: Vec<SavedVaultImportDisposition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    note_dispositions: Vec<SavedVaultImportDisposition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    port_forward_rule_dispositions: Vec<SavedVaultImportDisposition>,
}

impl SavedVaultGraphImportAssessment {
    pub fn revision(&self) -> &SavedVaultInventoryRevision {
        &self.revision
    }

    pub fn host_dispositions(&self) -> &[SavedVaultImportDisposition] {
        &self.host_dispositions
    }

    pub fn ssh_key_reference_dispositions(&self) -> &[SavedVaultImportDisposition] {
        &self.ssh_key_reference_dispositions
    }

    pub fn managed_ssh_key_dispositions(&self) -> &[SavedVaultImportDisposition] {
        &self.managed_ssh_key_dispositions
    }

    pub fn identity_reference_dispositions(&self) -> &[SavedVaultImportDisposition] {
        &self.identity_reference_dispositions
    }

    pub fn password_identity_dispositions(&self) -> &[SavedVaultImportDisposition] {
        &self.password_identity_dispositions
    }

    pub fn proxy_profile_dispositions(&self) -> &[SavedVaultImportDisposition] {
        &self.proxy_profile_dispositions
    }

    pub fn group_dispositions(&self) -> &[SavedVaultImportDisposition] {
        &self.group_dispositions
    }

    pub fn custom_group_dispositions(&self) -> &[SavedVaultImportDisposition] {
        &self.custom_group_dispositions
    }

    pub fn snippet_dispositions(&self) -> &[SavedVaultImportDisposition] {
        &self.snippet_dispositions
    }

    pub fn note_dispositions(&self) -> &[SavedVaultImportDisposition] {
        &self.note_dispositions
    }

    pub fn port_forward_rule_dispositions(&self) -> &[SavedVaultImportDisposition] {
        &self.port_forward_rule_dispositions
    }

    pub fn into_revision(self) -> SavedVaultInventoryRevision {
        self.revision
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SavedVaultGraphImportCommit {
    revision: SavedVaultInventoryRevision,
    imported: SavedVaultGraph,
    #[serde(default)]
    durability: SavedVaultCommitDurability,
}

impl SavedVaultGraphImportCommit {
    pub fn revision(&self) -> &SavedVaultInventoryRevision {
        &self.revision
    }

    pub fn imported(&self) -> &SavedVaultGraph {
        &self.imported
    }

    pub const fn durability(&self) -> SavedVaultCommitDurability {
        self.durability
    }

    pub fn into_imported(self) -> SavedVaultGraph {
        self.imported
    }
}

/// The complete normalized graph observed at a successful replacement commit
/// boundary, together with its new sealed inventory revision and publication
/// durability.
///
/// This backend-only value intentionally has no Serde or `Display`
/// implementation. Its custom `Debug` output never formats graph records,
/// opaque IDs, custody locators, or the inventory token.
#[derive(Clone, PartialEq)]
pub struct SavedVaultGraphReplacementCommit {
    revision: SavedVaultInventoryRevision,
    graph: SavedVaultGraph,
    changed: bool,
    durability: SavedVaultCommitDurability,
}

impl SavedVaultGraphReplacementCommit {
    pub fn revision(&self) -> &SavedVaultInventoryRevision {
        &self.revision
    }

    pub fn graph(&self) -> &SavedVaultGraph {
        &self.graph
    }

    pub const fn changed(&self) -> bool {
        self.changed
    }

    pub const fn durability(&self) -> SavedVaultCommitDurability {
        self.durability
    }

    pub fn into_graph(self) -> SavedVaultGraph {
        self.graph
    }
}

impl fmt::Debug for SavedVaultGraphReplacementCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SavedVaultGraphReplacementCommit")
            .field("changed", &self.changed)
            .field("durability", &self.durability)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SavedHostImportAssessment {
    revision: SavedHostInventoryRevision,
    dispositions: Vec<SavedHostImportDisposition>,
}

impl SavedHostImportAssessment {
    pub fn revision(&self) -> &SavedHostInventoryRevision {
        &self.revision
    }

    pub fn dispositions(&self) -> &[SavedHostImportDisposition] {
        &self.dispositions
    }

    pub fn into_revision(self) -> SavedHostInventoryRevision {
        self.revision
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SavedHostImportCommit {
    revision: SavedHostInventoryRevision,
    imported: Vec<SavedHost>,
    #[serde(default)]
    durability: SavedVaultCommitDurability,
}

impl SavedHostImportCommit {
    pub fn revision(&self) -> &SavedHostInventoryRevision {
        &self.revision
    }

    pub fn imported(&self) -> &[SavedHost] {
        &self.imported
    }

    pub const fn durability(&self) -> SavedVaultCommitDurability {
        self.durability
    }

    pub fn into_imported(self) -> Vec<SavedHost> {
        self.imported
    }
}

#[derive(Clone)]
pub struct SavedHostStore {
    root: Arc<PathBuf>,
    store_id: Arc<str>,
    gate: ProcessGate,
    #[cfg(test)]
    test_publish_fault: Arc<Mutex<Option<TestPublishFault>>>,
    #[cfg(test)]
    test_durability_confirmation_fault: Arc<Mutex<Option<TestDurabilityConfirmationFault>>>,
}

impl SavedHostStore {
    /// Opens or creates an owned two-slot store at `root`.
    ///
    /// Snapshots are immutable and alternate between the A/B directories. A
    /// synced temporary file is published with a no-clobber hard link rather
    /// than a replacing rename, so an unknown file can never be overwritten.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        fs::create_dir_all(root.as_ref())?;
        let root = fs::canonicalize(root.as_ref())?;
        require_directory(&root)?;
        let gate = process_gate(&root)?;
        let _guard = gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        let store_id = prepare_layout(&root)?;
        let store = Self {
            root: Arc::new(root),
            store_id: Arc::from(store_id),
            gate: gate.clone(),
            #[cfg(test)]
            test_publish_fault: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            test_durability_confirmation_fault: Arc::new(Mutex::new(None)),
        };
        store.load_locked()?;
        drop(_guard);
        Ok(store)
    }

    pub fn list(&self) -> Result<Vec<SavedHost>, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        Ok(self.load_locked()?.hosts)
    }

    pub fn list_ssh_key_references(&self) -> Result<Vec<SavedSshKeyReference>, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        Ok(self.load_locked()?.ssh_key_references)
    }

    pub fn list_managed_ssh_keys(&self) -> Result<Vec<SavedManagedSshKey>, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        Ok(self.load_locked()?.managed_ssh_keys)
    }

    /// Returns the de-duplicated union of managed-secret revisions referenced
    /// by every valid immutable snapshot still present in either recovery
    /// slot.
    ///
    /// This deliberately scans all owned snapshots rather than only the
    /// currently selected graph: the other slot can become authoritative
    /// after a crash. Unknown, mixed-owner, malformed, or corrupt slot
    /// artifacts make the retention set unknowable and fail closed. Callers
    /// coordinating cleanup across processes must additionally hold the
    /// saved-host transaction file lock for the entire scan and cleanup.
    pub fn managed_secret_retention_set(
        &self,
    ) -> Result<Vec<SavedVaultManagedSecretRetention>, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        self.managed_secret_retention_set_locked()
    }

    pub fn list_identity_references(&self) -> Result<Vec<SavedIdentityReference>, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        Ok(self.load_locked()?.identity_references)
    }

    pub fn list_password_identities(&self) -> Result<Vec<SavedPasswordIdentity>, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        Ok(self.load_locked()?.password_identities)
    }

    pub fn list_proxy_profiles(&self) -> Result<Vec<SavedProxyProfile>, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        Ok(self.load_locked()?.proxy_profiles)
    }

    pub fn list_groups(&self) -> Result<Vec<SavedGroupConfig>, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        Ok(self.load_locked()?.groups)
    }

    pub fn list_port_forward_rules(&self) -> Result<Vec<SavedPortForwardRule>, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        Ok(self.load_locked()?.port_forward_rules)
    }

    pub fn known_host_catalog(&self) -> Result<SavedKnownHostCatalog, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        let loaded = self.load_locked()?;
        Ok(SavedKnownHostCatalog {
            revision: loaded.inventory_revision(self.store_id.as_ref()),
            known_hosts: loaded.known_hosts,
        })
    }

    /// Reads the bounded, renderer-safe Connection Logs metadata catalog and
    /// the revision of the complete Vault inventory observed with it.
    pub fn connection_log_catalog(&self) -> Result<SavedConnectionLogCatalogState, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        let loaded = self.load_locked()?;
        let revision = loaded.inventory_revision(self.store_id.as_ref());
        let catalog = SavedConnectionLogCatalog::new(loaded.connection_logs)
            .map_err(|_| StoreError::Serialization)?;
        Ok(SavedConnectionLogCatalogState { revision, catalog })
    }

    /// Replaces Connection Logs metadata under the same complete-inventory
    /// CAS used by every other Vault catalog.
    ///
    /// The legacy retention rule is applied before publication: all saved
    /// records are retained and only the newest 500 unsaved records remain.
    /// Replay/terminal data cannot enter this API's serializable model.
    pub fn replace_connection_logs(
        &self,
        expected_revision: SavedVaultInventoryRevision,
        logs: Vec<SavedConnectionLog>,
    ) -> Result<SavedConnectionLogCatalogCommit, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        let mut loaded = self.load_locked()?;
        let actual_revision =
            verify_inventory_revision(&loaded, self.store_id.as_ref(), expected_revision)?;
        let mut catalog = SavedConnectionLogCatalog::with_legacy_retention(logs)
            .map_err(|_| StoreError::Serialization)?;
        normalize_connection_logs(&mut catalog.logs)?;
        if loaded.connection_logs == catalog.logs {
            return Ok(SavedConnectionLogCatalogCommit {
                revision: actual_revision,
                catalog,
                durability: SavedVaultCommitDurability::Durable,
            });
        }
        loaded.connection_logs = catalog.logs.clone();
        let publication = self.commit_locked(&loaded)?;
        loaded.generation = publication.generation;
        loaded.max_seen_generation = publication.generation;
        Ok(SavedConnectionLogCatalogCommit {
            revision: loaded.inventory_revision(self.store_id.as_ref()),
            catalog,
            durability: publication.durability,
        })
    }

    /// Removes all unbookmarked Connection Log metadata under the complete
    /// inventory CAS. The filtering is performed from the freshly loaded
    /// snapshot while holding the Vault gate, so a renderer cannot accidentally
    /// replace the catalog with a stale full-list projection.
    pub fn clear_unsaved_connection_logs(
        &self,
        expected_revision: SavedVaultInventoryRevision,
    ) -> Result<SavedConnectionLogCatalogCommit, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        let mut loaded = self.load_locked()?;
        let actual_revision =
            verify_inventory_revision(&loaded, self.store_id.as_ref(), expected_revision)?;
        let retained: Vec<SavedConnectionLog> = loaded
            .connection_logs
            .iter()
            .filter(|log| log.saved)
            .cloned()
            .collect();
        let catalog = SavedConnectionLogCatalog::with_legacy_retention(retained)
            .map_err(|_| StoreError::Serialization)?;
        if loaded.connection_logs == catalog.logs {
            return Ok(SavedConnectionLogCatalogCommit {
                revision: actual_revision,
                catalog,
                durability: SavedVaultCommitDurability::Durable,
            });
        }
        loaded.connection_logs = catalog.logs.clone();
        let publication = self.commit_locked(&loaded)?;
        loaded.generation = publication.generation;
        loaded.max_seen_generation = publication.generation;
        Ok(SavedConnectionLogCatalogCommit {
            revision: loaded.inventory_revision(self.store_id.as_ref()),
            catalog,
            durability: publication.durability,
        })
    }

    /// Replaces the device-local Known Hosts catalog under the same complete
    /// Vault inventory CAS used by every other catalog.
    pub fn replace_known_hosts(
        &self,
        expected_revision: SavedVaultInventoryRevision,
        known_hosts: Vec<SavedKnownHost>,
    ) -> Result<SavedKnownHostCatalogCommit, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        let mut loaded = self.load_locked()?;
        let actual_revision =
            verify_inventory_revision(&loaded, self.store_id.as_ref(), expected_revision)?;
        validate_saved_known_hosts(&known_hosts).map_err(|_| StoreError::Serialization)?;
        if loaded.known_hosts == known_hosts {
            return Ok(SavedKnownHostCatalogCommit {
                revision: actual_revision,
                known_hosts,
                durability: SavedVaultCommitDurability::Durable,
            });
        }
        loaded.known_hosts = known_hosts.clone();
        let publication = self.commit_locked(&loaded)?;
        loaded.generation = publication.generation;
        loaded.max_seen_generation = publication.generation;
        Ok(SavedKnownHostCatalogCommit {
            revision: loaded.inventory_revision(self.store_id.as_ref()),
            known_hosts,
            durability: publication.durability,
        })
    }

    pub fn graph(&self) -> Result<SavedVaultGraph, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        let loaded = self.load_locked()?;
        Ok(SavedVaultGraph::new_with_port_forward_rules(
            loaded.hosts,
            loaded.ssh_key_references,
            loaded.managed_ssh_keys,
            loaded.identity_references,
            loaded.password_identities,
            loaded.proxy_profiles,
            loaded.groups,
            loaded.notes_snippets,
            loaded.port_forward_rules,
        )
        .with_group_catalog(loaded.custom_groups))
    }

    /// Confirms that the complete currently selected Vault snapshot is
    /// directory-durable and returns the graph that was confirmed.
    ///
    /// The process-local store gate is held across the initial load, syncing
    /// the exact selected snapshot's slot directory, the competing slot
    /// directory whose state also determines selection, and a complete reload.
    /// The generation, maximum observed generation, selected immutable
    /// artifact, and every graph record must remain identical. An empty Vault
    /// instead syncs both slot directories and the store root before proving
    /// that it is still empty. Any inability to sync, reload, or establish an
    /// exact match fails closed.
    ///
    /// Cross-process callers must also hold the saved-host transaction file
    /// lock for the whole operation, just as they do for every mutation and
    /// recovery decision.
    pub fn confirm_current_snapshot_durability(
        &self,
    ) -> Result<SavedVaultDurableSnapshot, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;

        #[cfg(test)]
        if let Some(fault) = self.take_test_durability_confirmation_fault() {
            return match fault {
                TestDurabilityConfirmationFault::SyncFailure => self
                    .confirm_current_snapshot_durability_locked_with_hooks(
                        |_| Err(io::Error::other("injected directory sync failure")),
                        |_, _| Ok(()),
                    ),
                TestDurabilityConfirmationFault::CompetingSlotSyncFailure => {
                    let mut sync_count = 0_usize;
                    self.confirm_current_snapshot_durability_locked_with_hooks(
                        move |path| {
                            sync_count += 1;
                            if sync_count == 2 {
                                Err(io::Error::other("injected competing slot sync failure"))
                            } else {
                                sync_directory(path)
                            }
                        },
                        |_, _| Ok(()),
                    )
                }
                TestDurabilityConfirmationFault::ContentChange => self
                    .confirm_current_snapshot_durability_locked_with_hooks(
                        sync_directory,
                        inject_current_snapshot_content_change,
                    ),
                TestDurabilityConfirmationFault::GenerationChange => self
                    .confirm_current_snapshot_durability_locked_with_hooks(
                        sync_directory,
                        inject_next_snapshot_generation,
                    ),
            };
        }

        self.confirm_current_snapshot_durability_locked_with_hooks(sync_directory, |_, _| Ok(()))
    }

    pub fn get(&self, id: &SavedHostId) -> Result<Option<SavedHost>, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        Ok(self
            .load_locked()?
            .hosts
            .into_iter()
            .find(|host| &host.id == id))
    }

    pub fn create(&self, draft: SavedHostDraft) -> Result<SavedHost, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        let mut loaded = self.load_locked()?;
        let host = SavedHost::from_draft(draft, now_millis()?)?;
        if loaded.hosts.iter().any(|candidate| candidate.id == host.id) {
            return Err(StoreError::DuplicateId(host.id));
        }
        loaded.hosts.push(host.clone());
        normalize_hosts(&mut loaded.hosts)?;
        self.commit_locked(&loaded)?;
        Ok(host)
    }

    pub fn update(
        &self,
        id: &SavedHostId,
        expected_revision: u64,
        update: SavedHostUpdate,
    ) -> Result<SavedHost, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        let mut loaded = self.load_locked()?;
        let index = loaded
            .hosts
            .iter()
            .position(|host| &host.id == id)
            .ok_or_else(|| StoreError::NotFound(id.clone()))?;
        let current = &loaded.hosts[index];
        if current.revision != expected_revision {
            return Err(StoreError::RevisionConflict {
                id: id.clone(),
                expected: expected_revision,
                actual: current.revision,
            });
        }
        let updated = current.apply_update(update, now_millis()?)?;
        loaded.hosts[index] = updated.clone();
        normalize_hosts(&mut loaded.hosts)?;
        self.commit_locked(&loaded)?;
        Ok(updated)
    }

    pub fn delete(
        &self,
        id: &SavedHostId,
        expected_revision: u64,
    ) -> Result<SavedHost, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        let mut loaded = self.load_locked()?;
        let index = loaded
            .hosts
            .iter()
            .position(|host| &host.id == id)
            .ok_or_else(|| StoreError::NotFound(id.clone()))?;
        if loaded.hosts[index].revision != expected_revision {
            return Err(StoreError::RevisionConflict {
                id: id.clone(),
                expected: expected_revision,
                actual: loaded.hosts[index].revision,
            });
        }
        let deleted = loaded.hosts.remove(index);
        self.commit_locked(&loaded)?;
        Ok(deleted)
    }

    /// Classifies a complete import candidate set against one atomically
    /// loaded inventory without modifying the store.
    ///
    /// A duplicate has the same opaque ID and the same business and
    /// compatibility fields. Record format, record revision, and timestamps
    /// are deliberately ignored for this comparison. Reusing an ID for
    /// different content is a conflict; matching endpoints with different IDs
    /// remain independently importable.
    pub fn assess_import(
        &self,
        candidates: &[SavedHost],
    ) -> Result<SavedHostImportAssessment, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        validate_import_candidates(candidates)?;
        let loaded = self.load_locked()?;
        let existing = loaded
            .hosts
            .iter()
            .map(|host| (&host.id, host))
            .collect::<HashMap<_, _>>();
        let dispositions = candidates
            .iter()
            .map(|candidate| match existing.get(&candidate.id) {
                None => SavedHostImportDisposition::Importable,
                Some(current) if import_business_fields_equal(current, candidate) => {
                    SavedHostImportDisposition::Duplicate
                }
                Some(_) => SavedHostImportDisposition::Conflict,
            })
            .collect();
        Ok(SavedHostImportAssessment {
            revision: loaded.inventory_revision(self.store_id.as_ref()),
            dispositions,
        })
    }

    /// Appends an assessed candidate set in at most one immutable snapshot.
    ///
    /// The inventory is reloaded while holding the same process gate and the
    /// full store/recovery revision is compared before any candidate is
    /// examined. Exact duplicates are idempotent no-ops, conflicts fail the
    /// whole batch, and a batch with no additions does not publish a snapshot.
    pub fn commit_import(
        &self,
        expected_revision: SavedHostInventoryRevision,
        candidates: Vec<SavedHost>,
    ) -> Result<SavedHostImportCommit, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        let mut loaded = self.load_locked()?;
        let actual_revision = loaded.inventory_revision(self.store_id.as_ref());
        if expected_revision != actual_revision {
            return Err(StoreError::InventoryRevisionConflict {
                expected: expected_revision,
                actual: actual_revision,
            });
        }
        validate_import_candidates(&candidates)?;

        let mut imported = Vec::new();
        for candidate in candidates {
            match loaded.hosts.iter().find(|host| host.id == candidate.id) {
                Some(current) if import_business_fields_equal(current, &candidate) => continue,
                Some(_) => return Err(StoreError::ImportConflict(candidate.id)),
                None => {
                    loaded.hosts.push(candidate.clone());
                    imported.push(candidate);
                }
            }
        }
        if imported.is_empty() {
            return Ok(SavedHostImportCommit {
                revision: actual_revision,
                imported,
                durability: SavedVaultCommitDurability::Durable,
            });
        }

        normalize_hosts(&mut loaded.hosts)?;
        let publication = self.commit_locked(&loaded)?;
        loaded.generation = publication.generation;
        loaded.max_seen_generation = publication.generation;
        Ok(SavedHostImportCommit {
            revision: loaded.inventory_revision(self.store_id.as_ref()),
            imported,
            durability: publication.durability,
        })
    }

    /// Classifies a host/key/identity candidate graph against one atomically
    /// loaded inventory. The serialized assessment contains only entity-typed
    /// dispositions and the sealed inventory revision; it never contains
    /// labels, file paths, or opaque relationship IDs.
    pub fn assess_graph_import(
        &self,
        candidates: &SavedVaultGraph,
    ) -> Result<SavedVaultGraphImportAssessment, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        validate_graph_candidates(candidates)?;
        let loaded = self.load_locked()?;
        validate_candidate_graph_references(candidates, &loaded)?;

        Ok(SavedVaultGraphImportAssessment {
            revision: loaded.inventory_revision(self.store_id.as_ref()),
            host_dispositions: classify_hosts(&loaded.hosts, &candidates.hosts),
            ssh_key_reference_dispositions: classify_ssh_key_references(
                &loaded.ssh_key_references,
                &loaded.managed_ssh_keys,
                &candidates.ssh_key_references,
            ),
            managed_ssh_key_dispositions: classify_managed_ssh_keys(
                &loaded.managed_ssh_keys,
                &loaded.ssh_key_references,
                &candidates.managed_ssh_keys,
            ),
            identity_reference_dispositions: classify_identity_references(
                &loaded.identity_references,
                &loaded.password_identities,
                &candidates.identity_references,
            ),
            password_identity_dispositions: classify_password_identities(
                &loaded.password_identities,
                &loaded.identity_references,
                &candidates.password_identities,
            ),
            proxy_profile_dispositions: classify_proxy_profiles(
                &loaded.proxy_profiles,
                &candidates.proxy_profiles,
            ),
            group_dispositions: classify_groups(&loaded.groups, &candidates.groups),
            custom_group_dispositions: classify_custom_groups(
                loaded.custom_groups.as_ref(),
                candidates.custom_groups.as_ref(),
            ),
            snippet_dispositions: classify_snippets(
                loaded.notes_snippets.snippets().unwrap_or_default(),
                candidates.notes_snippets.snippets().unwrap_or_default(),
            ),
            note_dispositions: classify_notes(
                loaded.notes_snippets.notes().unwrap_or_default(),
                candidates.notes_snippets.notes().unwrap_or_default(),
            ),
            port_forward_rule_dispositions: classify_port_forward_rules(
                &loaded.port_forward_rules,
                &candidates.port_forward_rules,
            ),
        })
    }

    /// Projects the exact normalized graph that a matching
    /// [`Self::commit_graph_import`] call would publish, without writing a
    /// snapshot. Exact duplicates are no-ops; any conflict or stale inventory
    /// token rejects the whole projection.
    pub fn plan_graph_import(
        &self,
        expected_revision: SavedVaultInventoryRevision,
        candidates: &SavedVaultGraph,
    ) -> Result<SavedVaultGraphImportPlan, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        let mut projected = self.load_locked()?;
        let actual_revision =
            verify_inventory_revision(&projected, self.store_id.as_ref(), expected_revision)?;
        let before_graph_commitment = projected.graph_commitment(self.store_id.as_ref())?;
        let imported = apply_graph_import(&mut projected, candidates.clone())?;
        let after_graph_commitment = projected.graph_commitment(self.store_id.as_ref())?;
        debug_assert!(
            !imported.is_empty() || before_graph_commitment == after_graph_commitment,
            "a no-op graph import must retain the exact graph commitment"
        );
        Ok(SavedVaultGraphImportPlan {
            revision: actual_revision,
            before_graph_commitment,
            after_graph_commitment,
        })
    }

    /// Atomically appends a previously assessed host/key/identity graph.
    /// Every addition is published in one v6 snapshot. Exact duplicates are
    /// no-ops; any conflict or stale inventory token rejects the whole batch.
    pub fn commit_graph_import(
        &self,
        expected_revision: SavedVaultInventoryRevision,
        candidates: SavedVaultGraph,
    ) -> Result<SavedVaultGraphImportCommit, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        let mut loaded = self.load_locked()?;
        let actual_revision =
            verify_inventory_revision(&loaded, self.store_id.as_ref(), expected_revision)?;
        let imported = apply_graph_import(&mut loaded, candidates)?;

        if imported.is_empty() {
            return Ok(SavedVaultGraphImportCommit {
                revision: actual_revision,
                imported,
                durability: SavedVaultCommitDurability::Durable,
            });
        }

        let publication = self.commit_locked(&loaded)?;
        loaded.generation = publication.generation;
        loaded.max_seen_generation = publication.generation;
        Ok(SavedVaultGraphImportCommit {
            revision: loaded.inventory_revision(self.store_id.as_ref()),
            imported,
            durability: publication.durability,
        })
    }

    /// Commits only the exact candidate graph sealed by `plan`. In addition to
    /// the inventory CAS, both complete before/after graph commitments are
    /// recomputed while the store gate is held. This is the commit boundary
    /// used by cross-store managed-secret transactions.
    pub fn commit_planned_graph_import(
        &self,
        plan: SavedVaultGraphImportPlan,
        candidates: SavedVaultGraph,
    ) -> Result<SavedVaultGraphImportCommit, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        let mut loaded = self.load_locked()?;
        let actual_revision =
            verify_inventory_revision(&loaded, self.store_id.as_ref(), plan.revision)?;
        if loaded.graph_commitment(self.store_id.as_ref())? != plan.before_graph_commitment {
            return Err(StoreError::GraphImportPlanMismatch);
        }
        let imported = apply_graph_import(&mut loaded, candidates)?;
        if loaded.graph_commitment(self.store_id.as_ref())? != plan.after_graph_commitment {
            return Err(StoreError::GraphImportPlanMismatch);
        }
        if imported.is_empty() {
            return Ok(SavedVaultGraphImportCommit {
                revision: actual_revision,
                imported,
                durability: SavedVaultCommitDurability::Durable,
            });
        }

        let publication = self.commit_locked(&loaded)?;
        loaded.generation = publication.generation;
        loaded.max_seen_generation = publication.generation;
        Ok(SavedVaultGraphImportCommit {
            revision: loaded.inventory_revision(self.store_id.as_ref()),
            imported,
            durability: publication.durability,
        })
    }

    /// Projects a complete replacement of every Vault catalog without
    /// writing a snapshot.
    ///
    /// The target graph is validated as a closed graph: none of its host or
    /// identity relationships may resolve through an entity that exists only
    /// in the current graph. Stable normalization is applied before the exact
    /// before/after commitments are sealed into the returned plan.
    pub fn plan_graph_replacement(
        &self,
        expected_revision: SavedVaultInventoryRevision,
        replacement: &SavedVaultGraph,
    ) -> Result<SavedVaultGraphReplacementPlan, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        let loaded = self.load_locked()?;
        let actual_revision =
            verify_inventory_revision(&loaded, self.store_id.as_ref(), expected_revision)?;
        let before_graph_commitment = loaded.graph_commitment(self.store_id.as_ref())?;
        let projected = project_graph_replacement(&loaded, replacement.clone())?;
        let after_graph_commitment = projected.graph_commitment(self.store_id.as_ref())?;
        Ok(SavedVaultGraphReplacementPlan {
            revision: actual_revision,
            before_graph_commitment,
            after_graph_commitment,
        })
    }

    /// Publishes only the exact complete replacement sealed by `plan`.
    ///
    /// The inventory CAS and both graph commitments are revalidated while the
    /// process gate is held. A normalized no-op returns the current revision
    /// and graph without writing a snapshot; a change publishes exactly one
    /// v6 snapshot and reports its three-state durability result.
    pub fn commit_planned_graph_replacement(
        &self,
        plan: SavedVaultGraphReplacementPlan,
        replacement: SavedVaultGraph,
    ) -> Result<SavedVaultGraphReplacementCommit, StoreError> {
        let _guard = self.gate.lock().map_err(|_| StoreError::LockPoisoned)?;
        let loaded = self.load_locked()?;
        let SavedVaultGraphReplacementPlan {
            revision,
            before_graph_commitment,
            after_graph_commitment,
        } = plan;
        let actual_revision = verify_inventory_revision(&loaded, self.store_id.as_ref(), revision)?;
        if loaded.graph_commitment(self.store_id.as_ref())? != before_graph_commitment {
            return Err(StoreError::GraphReplacementPlanMismatch);
        }

        let mut projected = project_graph_replacement(&loaded, replacement)?;
        if projected.graph_commitment(self.store_id.as_ref())? != after_graph_commitment {
            return Err(StoreError::GraphReplacementPlanMismatch);
        }

        let changed = before_graph_commitment != after_graph_commitment;
        if !changed {
            return Ok(SavedVaultGraphReplacementCommit {
                revision: actual_revision,
                graph: projected.into_graph(),
                changed,
                durability: SavedVaultCommitDurability::Durable,
            });
        }

        let publication = self.commit_locked(&projected)?;
        projected.generation = publication.generation;
        projected.max_seen_generation = publication.generation;
        let revision = projected.inventory_revision(self.store_id.as_ref());
        Ok(SavedVaultGraphReplacementCommit {
            revision,
            graph: projected.into_graph(),
            changed,
            durability: publication.durability,
        })
    }

    #[cfg(test)]
    fn inject_next_publish_fault(&self, fault: TestPublishFault) {
        *self
            .test_publish_fault
            .lock()
            .expect("test publish fault lock") = Some(fault);
    }

    #[cfg(test)]
    fn take_test_publish_fault(&self) -> Option<TestPublishFault> {
        self.test_publish_fault
            .lock()
            .expect("test publish fault lock")
            .take()
    }

    #[cfg(test)]
    fn inject_next_durability_confirmation_fault(&self, fault: TestDurabilityConfirmationFault) {
        *self
            .test_durability_confirmation_fault
            .lock()
            .expect("test durability confirmation fault lock") = Some(fault);
    }

    #[cfg(test)]
    fn take_test_durability_confirmation_fault(&self) -> Option<TestDurabilityConfirmationFault> {
        self.test_durability_confirmation_fault
            .lock()
            .expect("test durability confirmation fault lock")
            .take()
    }

    fn confirm_current_snapshot_durability_locked_with_hooks<F, H>(
        &self,
        mut sync: F,
        after_sync: H,
    ) -> Result<SavedVaultDurableSnapshot, StoreError>
    where
        F: FnMut(&Path) -> io::Result<()>,
        H: FnOnce(&Self, &LoadedStore) -> Result<(), StoreError>,
    {
        let before = self.load_locked()?;
        // A lower valid snapshot can be selected when a higher-generation
        // artifact exists but is unreadable or corrupt. Directory syncing
        // cannot make that artifact's file contents durable, so a crash could
        // make the higher generation valid again. Such recovery state is not
        // sufficient evidence for a cross-store rollback/cleanup decision.
        if before.generation != before.max_seen_generation {
            return Err(StoreError::SnapshotDurabilityUnconfirmed);
        }
        if let Some(snapshot_path) = &before.snapshot_path {
            let selected_slot = Slot::for_generation(before.generation);
            let expected_directory = self.root.join(selected_slot.directory());
            if snapshot_path.parent() != Some(expected_directory.as_path()) {
                return Err(StoreError::SnapshotDurabilityUnconfirmed);
            }
            sync(&expected_directory)?;
            let competing_slot = match selected_slot {
                Slot::A => Slot::B,
                Slot::B => Slot::A,
            };
            sync(&self.root.join(competing_slot.directory()))?;
        } else {
            if before.generation != 0 || before.max_seen_generation != 0 {
                return Err(StoreError::SnapshotDurabilityUnconfirmed);
            }
            sync(&self.root.join(SLOT_A_DIRECTORY))?;
            sync(&self.root.join(SLOT_B_DIRECTORY))?;
            sync(self.root.as_ref())?;
        }

        after_sync(self, &before)?;
        let after = self.load_locked()?;
        if !before.same_snapshot_and_graph(&after) {
            return Err(StoreError::SnapshotDurabilityUnconfirmed);
        }
        let revision = after.inventory_revision(self.store_id.as_ref());
        let commitment = after.graph_commitment(self.store_id.as_ref())?;
        let known_hosts = after.known_hosts.clone();
        let connection_logs = after.connection_logs.clone();
        Ok(SavedVaultDurableSnapshot {
            revision,
            commitment,
            graph: after.into_graph(),
            known_hosts,
            connection_logs,
        })
    }

    fn load_locked(&self) -> Result<LoadedStore, StoreError> {
        let slot_a = probe_slot(&self.root.join(SLOT_A_DIRECTORY), Slot::A, &self.store_id)?;
        let slot_b = probe_slot(&self.root.join(SLOT_B_DIRECTORY), Slot::B, &self.store_id)?;
        let max_seen_generation = slot_a.max_seen.max(slot_b.max_seen).unwrap_or(0);
        match (slot_a.snapshot, slot_b.snapshot) {
            (None, None) if slot_a.empty && slot_b.empty => Ok(LoadedStore {
                generation: 0,
                max_seen_generation,
                snapshot_path: None,
                hosts: Vec::new(),
                ssh_key_references: Vec::new(),
                managed_ssh_keys: Vec::new(),
                identity_references: Vec::new(),
                password_identities: Vec::new(),
                proxy_profiles: Vec::new(),
                groups: Vec::new(),
                custom_groups: None,
                notes_snippets: SavedNotesSnippetsCatalog::default(),
                port_forward_rules: Vec::new(),
                known_hosts: Vec::new(),
                connection_logs: Vec::new(),
            }),
            (None, None) => Err(StoreError::BothSlotsCorrupt),
            (Some(snapshot), None) | (None, Some(snapshot)) => Ok(LoadedStore {
                generation: snapshot.generation,
                max_seen_generation,
                snapshot_path: Some(snapshot.path),
                hosts: snapshot.hosts,
                ssh_key_references: snapshot.ssh_key_references,
                managed_ssh_keys: snapshot.managed_ssh_keys,
                identity_references: snapshot.identity_references,
                password_identities: snapshot.password_identities,
                proxy_profiles: snapshot.proxy_profiles,
                groups: snapshot.groups,
                custom_groups: snapshot.custom_groups,
                notes_snippets: snapshot.notes_snippets,
                port_forward_rules: snapshot.port_forward_rules,
                known_hosts: snapshot.known_hosts,
                connection_logs: snapshot.connection_logs,
            }),
            (Some(left), Some(right)) if left.generation == right.generation => {
                Err(StoreError::ConflictingGeneration)
            }
            (Some(left), Some(right)) => {
                let snapshot = if left.generation > right.generation {
                    left
                } else {
                    right
                };
                Ok(LoadedStore {
                    generation: snapshot.generation,
                    max_seen_generation,
                    snapshot_path: Some(snapshot.path),
                    hosts: snapshot.hosts,
                    ssh_key_references: snapshot.ssh_key_references,
                    managed_ssh_keys: snapshot.managed_ssh_keys,
                    identity_references: snapshot.identity_references,
                    password_identities: snapshot.password_identities,
                    proxy_profiles: snapshot.proxy_profiles,
                    groups: snapshot.groups,
                    custom_groups: snapshot.custom_groups,
                    notes_snippets: snapshot.notes_snippets,
                    port_forward_rules: snapshot.port_forward_rules,
                    known_hosts: snapshot.known_hosts,
                    connection_logs: snapshot.connection_logs,
                })
            }
        }
    }

    fn managed_secret_retention_set_locked(
        &self,
    ) -> Result<Vec<SavedVaultManagedSecretRetention>, StoreError> {
        validate_root_entries(self.root.as_ref())
            .map_err(|_| StoreError::ManagedSecretRetentionUncertain)?;
        let owner_id = read_owner(&self.root.join(OWNER_FILE))
            .map_err(|_| StoreError::ManagedSecretRetentionUncertain)?;
        if owner_id != self.store_id.as_ref() {
            return Err(StoreError::ManagedSecretRetentionUncertain);
        }

        let mut retained = BTreeSet::new();
        scan_slot_managed_secret_retention(
            &self.root.join(SLOT_A_DIRECTORY),
            Slot::A,
            self.store_id.as_ref(),
            &mut retained,
        )?;
        scan_slot_managed_secret_retention(
            &self.root.join(SLOT_B_DIRECTORY),
            Slot::B,
            self.store_id.as_ref(),
            &mut retained,
        )?;
        Ok(retained.into_iter().collect())
    }

    fn commit_locked(&self, loaded: &LoadedStore) -> Result<CommitPublication, StoreError> {
        let graph = SavedVaultGraph::new_with_port_forward_rules(
            loaded.hosts.clone(),
            loaded.ssh_key_references.clone(),
            loaded.managed_ssh_keys.clone(),
            loaded.identity_references.clone(),
            loaded.password_identities.clone(),
            loaded.proxy_profiles.clone(),
            loaded.groups.clone(),
            loaded.notes_snippets.clone(),
            loaded.port_forward_rules.clone(),
        )
        .with_group_catalog(loaded.custom_groups.clone());
        validate_graph_candidates(&graph)?;
        validate_saved_known_hosts(&loaded.known_hosts).map_err(|_| StoreError::Serialization)?;
        validate_saved_connection_logs(&loaded.connection_logs)
            .map_err(|_| StoreError::Serialization)?;
        let empty = LoadedStore {
            generation: loaded.generation,
            max_seen_generation: loaded.max_seen_generation,
            snapshot_path: loaded.snapshot_path.clone(),
            hosts: Vec::new(),
            ssh_key_references: Vec::new(),
            managed_ssh_keys: Vec::new(),
            identity_references: Vec::new(),
            password_identities: Vec::new(),
            proxy_profiles: Vec::new(),
            groups: Vec::new(),
            custom_groups: None,
            notes_snippets: Default::default(),
            port_forward_rules: Vec::new(),
            known_hosts: Vec::new(),
            connection_logs: Vec::new(),
        };
        validate_candidate_graph_references(&graph, &empty)?;
        let (
            hosts,
            ssh_key_references,
            managed_ssh_keys,
            identity_references,
            password_identities,
            proxy_profiles,
            groups,
            custom_groups,
            notes_snippets,
            port_forward_rules,
        ) = graph.into_current_parts();
        let known_hosts = loaded.known_hosts.clone();
        let connection_logs = loaded.connection_logs.clone();
        let generation = loaded
            .max_seen_generation
            .max(loaded.generation)
            .checked_add(1)
            .ok_or(StoreError::GenerationOverflow)?;
        let slot = Slot::for_generation(generation);
        let directory = self.root.join(slot.directory());
        require_directory(&directory)?;
        let envelope = SnapshotEnvelope::new_latest(
            self.store_id.to_string(),
            slot,
            generation,
            hosts,
            ssh_key_references,
            managed_ssh_keys,
            identity_references,
            password_identities,
            proxy_profiles,
            groups,
            custom_groups,
            notes_snippets,
            port_forward_rules,
            known_hosts,
            connection_logs,
        )?;
        let encoded = serde_json::to_vec(&envelope).map_err(|_| StoreError::Serialization)?;
        if encoded.len() as u64 > MAX_SNAPSHOT_BYTES {
            return Err(StoreError::Serialization);
        }
        #[cfg(test)]
        let durability = match self.take_test_publish_fault() {
            Some(fault) => publish_snapshot_no_overwrite_with_test_fault(
                &directory,
                self.store_id.as_ref(),
                slot,
                generation,
                &encoded,
                fault,
            )?,
            None => publish_snapshot_no_overwrite(
                &directory,
                self.store_id.as_ref(),
                slot,
                generation,
                &encoded,
            )?,
        };
        #[cfg(not(test))]
        let durability = publish_snapshot_no_overwrite(
            &directory,
            self.store_id.as_ref(),
            slot,
            generation,
            &encoded,
        )?;
        if durability == SavedVaultCommitDurability::Durable {
            cleanup_owned_slot_artifacts(&directory, self.store_id.as_ref(), slot, generation);
        }
        Ok(CommitPublication {
            generation,
            durability,
        })
    }
}

struct CommitPublication {
    generation: u64,
    durability: SavedVaultCommitDurability,
}

struct LoadedStore {
    generation: u64,
    max_seen_generation: u64,
    snapshot_path: Option<PathBuf>,
    hosts: Vec<SavedHost>,
    ssh_key_references: Vec<SavedSshKeyReference>,
    managed_ssh_keys: Vec<SavedManagedSshKey>,
    identity_references: Vec<SavedIdentityReference>,
    password_identities: Vec<SavedPasswordIdentity>,
    proxy_profiles: Vec<SavedProxyProfile>,
    groups: Vec<SavedGroupConfig>,
    custom_groups: Option<SavedGroupCatalog>,
    notes_snippets: SavedNotesSnippetsCatalog,
    port_forward_rules: Vec<SavedPortForwardRule>,
    known_hosts: Vec<SavedKnownHost>,
    connection_logs: Vec<SavedConnectionLog>,
}

impl LoadedStore {
    fn inventory_revision(&self, store_id: &str) -> SavedHostInventoryRevision {
        SavedHostInventoryRevision {
            store_id: store_id.to_owned(),
            loaded_generation: self.generation,
            max_seen_generation: self.max_seen_generation,
            seal: inventory_revision_seal(store_id, self.generation, self.max_seen_generation),
        }
    }

    fn same_snapshot_and_graph(&self, other: &Self) -> bool {
        self.generation == other.generation
            && self.max_seen_generation == other.max_seen_generation
            && self.snapshot_path == other.snapshot_path
            && self.hosts == other.hosts
            && self.ssh_key_references == other.ssh_key_references
            && self.managed_ssh_keys == other.managed_ssh_keys
            && self.identity_references == other.identity_references
            && self.password_identities == other.password_identities
            && self.proxy_profiles == other.proxy_profiles
            && self.groups == other.groups
            && self.custom_groups == other.custom_groups
            && self.notes_snippets == other.notes_snippets
            && self.port_forward_rules == other.port_forward_rules
            && self.known_hosts == other.known_hosts
            && self.connection_logs == other.connection_logs
    }

    fn graph_commitment(&self, store_id: &str) -> Result<SavedVaultGraphCommitment, StoreError> {
        let (domain, encoded) = if self.custom_groups.is_some() {
            (
                b"netcatty-saved-vault-graph-commitment-v10\0".as_slice(),
                serde_json::to_vec(&GraphCommitmentPayloadV10 {
                    format_version: 10,
                    store_id,
                    hosts: &self.hosts,
                    ssh_key_references: &self.ssh_key_references,
                    managed_ssh_keys: &self.managed_ssh_keys,
                    identity_references: &self.identity_references,
                    password_identities: &self.password_identities,
                    proxy_profiles: &self.proxy_profiles,
                    groups: &self.groups,
                    custom_groups: self.custom_groups.as_ref().expect("presence checked"),
                    notes_snippets: &self.notes_snippets,
                    port_forward_rules: &self.port_forward_rules,
                    known_hosts: &self.known_hosts,
                    connection_logs: &self.connection_logs,
                })
                .map_err(|_| StoreError::Serialization)?,
            )
        } else if !self.connection_logs.is_empty() {
            (
                b"netcatty-saved-vault-graph-commitment-v9\0".as_slice(),
                serde_json::to_vec(&GraphCommitmentPayloadV9 {
                    format_version: 9,
                    store_id,
                    hosts: &self.hosts,
                    ssh_key_references: &self.ssh_key_references,
                    managed_ssh_keys: &self.managed_ssh_keys,
                    identity_references: &self.identity_references,
                    password_identities: &self.password_identities,
                    proxy_profiles: &self.proxy_profiles,
                    groups: &self.groups,
                    notes_snippets: &self.notes_snippets,
                    port_forward_rules: &self.port_forward_rules,
                    known_hosts: &self.known_hosts,
                    connection_logs: &self.connection_logs,
                })
                .map_err(|_| StoreError::Serialization)?,
            )
        } else if !self.known_hosts.is_empty() {
            (
                b"netcatty-saved-vault-graph-commitment-v8\0".as_slice(),
                serde_json::to_vec(&GraphCommitmentPayloadV8 {
                    format_version: 8,
                    store_id,
                    hosts: &self.hosts,
                    ssh_key_references: &self.ssh_key_references,
                    managed_ssh_keys: &self.managed_ssh_keys,
                    identity_references: &self.identity_references,
                    password_identities: &self.password_identities,
                    proxy_profiles: &self.proxy_profiles,
                    groups: &self.groups,
                    notes_snippets: &self.notes_snippets,
                    port_forward_rules: &self.port_forward_rules,
                    known_hosts: &self.known_hosts,
                })
                .map_err(|_| StoreError::Serialization)?,
            )
        } else if !self.port_forward_rules.is_empty() {
            (
                b"netcatty-saved-vault-graph-commitment-v7\0".as_slice(),
                serde_json::to_vec(&GraphCommitmentPayloadV7 {
                    format_version: 7,
                    store_id,
                    hosts: &self.hosts,
                    ssh_key_references: &self.ssh_key_references,
                    managed_ssh_keys: &self.managed_ssh_keys,
                    identity_references: &self.identity_references,
                    password_identities: &self.password_identities,
                    proxy_profiles: &self.proxy_profiles,
                    groups: &self.groups,
                    notes_snippets: &self.notes_snippets,
                    port_forward_rules: &self.port_forward_rules,
                })
                .map_err(|_| StoreError::Serialization)?,
            )
        } else if !self.notes_snippets.is_absent() {
            (
                b"netcatty-saved-vault-graph-commitment-v6\0".as_slice(),
                serde_json::to_vec(&GraphCommitmentPayloadV6 {
                    format_version: 6,
                    store_id,
                    hosts: &self.hosts,
                    ssh_key_references: &self.ssh_key_references,
                    managed_ssh_keys: &self.managed_ssh_keys,
                    identity_references: &self.identity_references,
                    password_identities: &self.password_identities,
                    proxy_profiles: &self.proxy_profiles,
                    groups: &self.groups,
                    notes_snippets: &self.notes_snippets,
                })
                .map_err(|_| StoreError::Serialization)?,
            )
        } else if !self.groups.is_empty() {
            (
                b"netcatty-saved-vault-graph-commitment-v5\0".as_slice(),
                serde_json::to_vec(&GraphCommitmentPayloadV5 {
                    format_version: 5,
                    store_id,
                    hosts: &self.hosts,
                    ssh_key_references: &self.ssh_key_references,
                    managed_ssh_keys: &self.managed_ssh_keys,
                    identity_references: &self.identity_references,
                    password_identities: &self.password_identities,
                    proxy_profiles: &self.proxy_profiles,
                    groups: &self.groups,
                })
                .map_err(|_| StoreError::Serialization)?,
            )
        } else if !self.proxy_profiles.is_empty() {
            (
                b"netcatty-saved-vault-graph-commitment-v4\0".as_slice(),
                serde_json::to_vec(&GraphCommitmentPayloadV4 {
                    format_version: 4,
                    store_id,
                    hosts: &self.hosts,
                    ssh_key_references: &self.ssh_key_references,
                    managed_ssh_keys: &self.managed_ssh_keys,
                    identity_references: &self.identity_references,
                    password_identities: &self.password_identities,
                    proxy_profiles: &self.proxy_profiles,
                })
                .map_err(|_| StoreError::Serialization)?,
            )
        } else if !self.password_identities.is_empty() {
            (
                b"netcatty-saved-vault-graph-commitment-v3\0".as_slice(),
                serde_json::to_vec(&GraphCommitmentPayloadV3 {
                    format_version: 3,
                    store_id,
                    hosts: &self.hosts,
                    ssh_key_references: &self.ssh_key_references,
                    managed_ssh_keys: &self.managed_ssh_keys,
                    identity_references: &self.identity_references,
                    password_identities: &self.password_identities,
                })
                .map_err(|_| StoreError::Serialization)?,
            )
        } else if self.managed_ssh_keys.is_empty() {
            let legacy_identity_references = legacy_identity_references(&self.identity_references);
            (
                b"netcatty-saved-vault-graph-commitment-v1\0".as_slice(),
                serde_json::to_vec(&GraphCommitmentPayloadV1 {
                    format_version: 1,
                    store_id,
                    hosts: &self.hosts,
                    ssh_key_references: &self.ssh_key_references,
                    identity_references: &legacy_identity_references,
                })
                .map_err(|_| StoreError::Serialization)?,
            )
        } else {
            (
                b"netcatty-saved-vault-graph-commitment-v2\0".as_slice(),
                serde_json::to_vec(&GraphCommitmentPayloadV2 {
                    format_version: 2,
                    store_id,
                    hosts: &self.hosts,
                    ssh_key_references: &self.ssh_key_references,
                    managed_ssh_keys: &self.managed_ssh_keys,
                    identity_references: &self.identity_references,
                })
                .map_err(|_| StoreError::Serialization)?,
            )
        };
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update((encoded.len() as u64).to_be_bytes());
        hasher.update(&encoded);
        Ok(SavedVaultGraphCommitment::from_digest(
            hasher.finalize().into(),
        ))
    }

    fn into_graph(self) -> SavedVaultGraph {
        SavedVaultGraph::new_with_port_forward_rules(
            self.hosts,
            self.ssh_key_references,
            self.managed_ssh_keys,
            self.identity_references,
            self.password_identities,
            self.proxy_profiles,
            self.groups,
            self.notes_snippets,
            self.port_forward_rules,
        )
        .with_group_catalog(self.custom_groups)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnerMarker {
    magic: String,
    format_version: u32,
    store_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Slot {
    A,
    B,
}

impl Slot {
    fn for_generation(generation: u64) -> Self {
        if generation % 2 == 1 {
            Self::A
        } else {
            Self::B
        }
    }

    fn directory(self) -> &'static str {
        match self {
            Self::A => SLOT_A_DIRECTORY,
            Self::B => SLOT_B_DIRECTORY,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SnapshotEnvelope {
    magic: String,
    format_version: u32,
    store_id: String,
    slot: Slot,
    generation: u64,
    hosts: Vec<SavedHost>,
    #[serde(default, deserialize_with = "deserialize_present_vec")]
    ssh_key_references: Option<Option<Vec<SavedSshKeyReference>>>,
    #[serde(default, deserialize_with = "deserialize_present_vec")]
    managed_ssh_keys: Option<Option<Vec<SavedManagedSshKey>>>,
    #[serde(default, deserialize_with = "deserialize_present_vec")]
    identity_references: Option<Option<Vec<SavedIdentityReference>>>,
    #[serde(default, deserialize_with = "deserialize_present_vec")]
    password_identities: Option<Option<Vec<SavedPasswordIdentity>>>,
    #[serde(default, deserialize_with = "deserialize_present_vec")]
    proxy_profiles: Option<Option<Vec<SavedProxyProfile>>>,
    #[serde(default, deserialize_with = "deserialize_present_vec")]
    groups: Option<Option<Vec<SavedGroupConfig>>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_value"
    )]
    custom_groups: Option<Option<SavedGroupCatalog>>,
    #[serde(default, deserialize_with = "deserialize_present_value")]
    notes_snippets: Option<Option<SavedNotesSnippetsCatalog>>,
    #[serde(default, deserialize_with = "deserialize_present_vec")]
    port_forward_rules: Option<Option<Vec<SavedPortForwardRule>>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_vec"
    )]
    known_hosts: Option<Option<Vec<SavedKnownHost>>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_connection_logs"
    )]
    connection_logs: Option<Option<Vec<SavedConnectionLog>>>,
    checksum: String,
}

fn deserialize_present_vec<'de, D, T>(deserializer: D) -> Result<Option<Option<Vec<T>>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<Vec<T>>::deserialize(deserializer).map(Some)
}

fn deserialize_present_value<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

/// Vault v10 accepts only metadata-only Connection Log records. The public
/// model can consume a legacy `terminalData` field for migration, but a native
/// Vault snapshot containing that field must fail closed instead of silently
/// authenticating uncommitted replay contents.
fn deserialize_present_connection_logs<'de, D>(
    deserializer: D,
) -> Result<Option<Option<Vec<SavedConnectionLog>>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let values = Option::<Vec<Value>>::deserialize(deserializer)?;
    let Some(values) = values else {
        return Ok(Some(None));
    };
    let mut logs = Vec::with_capacity(values.len());
    for value in values {
        if value
            .as_object()
            .is_some_and(|record| record.contains_key("terminalData"))
        {
            return Err(serde::de::Error::custom(
                "terminal replay data is forbidden in Vault metadata",
            ));
        }
        logs.push(serde_json::from_value(value).map_err(serde::de::Error::custom)?);
    }
    Ok(Some(Some(logs)))
}

fn optional_catalog<T>(catalog: &Option<Option<Vec<T>>>) -> Result<&[T], StoreError> {
    match catalog {
        None => Ok(&[]),
        Some(Some(values)) => Ok(values),
        Some(None) => Err(StoreError::BothSlotsCorrupt),
    }
}

fn required_catalog<T>(catalog: &Option<Option<Vec<T>>>) -> Result<&[T], StoreError> {
    catalog
        .as_ref()
        .and_then(Option::as_deref)
        .ok_or(StoreError::BothSlotsCorrupt)
}

fn required_value<T>(value: &Option<Option<T>>) -> Result<&T, StoreError> {
    value
        .as_ref()
        .and_then(Option::as_ref)
        .ok_or(StoreError::BothSlotsCorrupt)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChecksumPayloadV1<'a> {
    format_version: u32,
    store_id: &'a str,
    slot: Slot,
    generation: u64,
    hosts: &'a [SavedHost],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChecksumPayloadV2<'a> {
    format_version: u32,
    store_id: &'a str,
    slot: Slot,
    generation: u64,
    hosts: &'a [SavedHost],
    ssh_key_references: &'a [SavedSshKeyReference],
    identity_references: &'a [LegacyIdentityReferenceV2<'a>],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChecksumPayloadV3<'a> {
    magic: &'a str,
    format_version: u32,
    store_id: &'a str,
    slot: Slot,
    generation: u64,
    hosts: &'a [SavedHost],
    ssh_key_references: &'a [SavedSshKeyReference],
    managed_ssh_keys: &'a [SavedManagedSshKey],
    identity_references: &'a [SavedIdentityReference],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChecksumPayloadV4<'a> {
    magic: &'a str,
    format_version: u32,
    store_id: &'a str,
    slot: Slot,
    generation: u64,
    hosts: &'a [SavedHost],
    ssh_key_references: &'a [SavedSshKeyReference],
    managed_ssh_keys: &'a [SavedManagedSshKey],
    identity_references: &'a [SavedIdentityReference],
    password_identities: &'a [SavedPasswordIdentity],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChecksumPayloadV5<'a> {
    magic: &'a str,
    format_version: u32,
    store_id: &'a str,
    slot: Slot,
    generation: u64,
    hosts: &'a [SavedHost],
    ssh_key_references: &'a [SavedSshKeyReference],
    managed_ssh_keys: &'a [SavedManagedSshKey],
    identity_references: &'a [SavedIdentityReference],
    password_identities: &'a [SavedPasswordIdentity],
    proxy_profiles: &'a [SavedProxyProfile],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChecksumPayloadV6<'a> {
    magic: &'a str,
    format_version: u32,
    store_id: &'a str,
    slot: Slot,
    generation: u64,
    hosts: &'a [SavedHost],
    ssh_key_references: &'a [SavedSshKeyReference],
    managed_ssh_keys: &'a [SavedManagedSshKey],
    identity_references: &'a [SavedIdentityReference],
    password_identities: &'a [SavedPasswordIdentity],
    proxy_profiles: &'a [SavedProxyProfile],
    groups: &'a [SavedGroupConfig],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChecksumPayloadV7<'a> {
    magic: &'a str,
    format_version: u32,
    store_id: &'a str,
    slot: Slot,
    generation: u64,
    hosts: &'a [SavedHost],
    ssh_key_references: &'a [SavedSshKeyReference],
    managed_ssh_keys: &'a [SavedManagedSshKey],
    identity_references: &'a [SavedIdentityReference],
    password_identities: &'a [SavedPasswordIdentity],
    proxy_profiles: &'a [SavedProxyProfile],
    groups: &'a [SavedGroupConfig],
    notes_snippets: &'a SavedNotesSnippetsCatalog,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChecksumPayloadV8<'a> {
    magic: &'a str,
    format_version: u32,
    store_id: &'a str,
    slot: Slot,
    generation: u64,
    hosts: &'a [SavedHost],
    ssh_key_references: &'a [SavedSshKeyReference],
    managed_ssh_keys: &'a [SavedManagedSshKey],
    identity_references: &'a [SavedIdentityReference],
    password_identities: &'a [SavedPasswordIdentity],
    proxy_profiles: &'a [SavedProxyProfile],
    groups: &'a [SavedGroupConfig],
    notes_snippets: &'a SavedNotesSnippetsCatalog,
    port_forward_rules: &'a [SavedPortForwardRule],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChecksumPayloadV9<'a> {
    magic: &'a str,
    format_version: u32,
    store_id: &'a str,
    slot: Slot,
    generation: u64,
    hosts: &'a [SavedHost],
    ssh_key_references: &'a [SavedSshKeyReference],
    managed_ssh_keys: &'a [SavedManagedSshKey],
    identity_references: &'a [SavedIdentityReference],
    password_identities: &'a [SavedPasswordIdentity],
    proxy_profiles: &'a [SavedProxyProfile],
    groups: &'a [SavedGroupConfig],
    notes_snippets: &'a SavedNotesSnippetsCatalog,
    port_forward_rules: &'a [SavedPortForwardRule],
    known_hosts: &'a [SavedKnownHost],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChecksumPayloadV10<'a> {
    magic: &'a str,
    format_version: u32,
    store_id: &'a str,
    slot: Slot,
    generation: u64,
    hosts: &'a [SavedHost],
    ssh_key_references: &'a [SavedSshKeyReference],
    managed_ssh_keys: &'a [SavedManagedSshKey],
    identity_references: &'a [SavedIdentityReference],
    password_identities: &'a [SavedPasswordIdentity],
    proxy_profiles: &'a [SavedProxyProfile],
    groups: &'a [SavedGroupConfig],
    notes_snippets: &'a SavedNotesSnippetsCatalog,
    port_forward_rules: &'a [SavedPortForwardRule],
    known_hosts: &'a [SavedKnownHost],
    connection_logs: &'a [SavedConnectionLog],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChecksumPayloadV11<'a> {
    magic: &'a str,
    format_version: u32,
    store_id: &'a str,
    slot: Slot,
    generation: u64,
    hosts: &'a [SavedHost],
    ssh_key_references: &'a [SavedSshKeyReference],
    managed_ssh_keys: &'a [SavedManagedSshKey],
    identity_references: &'a [SavedIdentityReference],
    password_identities: &'a [SavedPasswordIdentity],
    proxy_profiles: &'a [SavedProxyProfile],
    groups: &'a [SavedGroupConfig],
    custom_groups: &'a SavedGroupCatalog,
    notes_snippets: &'a SavedNotesSnippetsCatalog,
    port_forward_rules: &'a [SavedPortForwardRule],
    known_hosts: &'a [SavedKnownHost],
    connection_logs: &'a [SavedConnectionLog],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphCommitmentPayloadV1<'a> {
    format_version: u32,
    store_id: &'a str,
    hosts: &'a [SavedHost],
    ssh_key_references: &'a [SavedSshKeyReference],
    identity_references: &'a [LegacyIdentityReferenceV2<'a>],
}

/// Exact serialized identity shape used by snapshot v2 and graph commitment
/// v1. `authMethod` did not exist in that format and adding it to either
/// checksum payload would make already-published snapshots and recovery
/// journals unreadable after an upgrade.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LegacyIdentityReferenceV2<'a> {
    id: &'a crate::model::SavedIdentityReferenceId,
    label: &'a str,
    username: &'a str,
    key_id: &'a crate::model::SavedSshKeyReferenceId,
    created_at: u64,
    updated_at: u64,
    #[serde(flatten)]
    compatibility_fields: &'a BTreeMap<String, Value>,
}

fn legacy_identity_references(
    references: &[SavedIdentityReference],
) -> Vec<LegacyIdentityReferenceV2<'_>> {
    references
        .iter()
        .map(|reference| LegacyIdentityReferenceV2 {
            id: &reference.id,
            label: &reference.label,
            username: &reference.username,
            key_id: &reference.key_id,
            created_at: reference.created_at,
            updated_at: reference.updated_at,
            compatibility_fields: reference.compatibility_fields(),
        })
        .collect()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphCommitmentPayloadV2<'a> {
    format_version: u32,
    store_id: &'a str,
    hosts: &'a [SavedHost],
    ssh_key_references: &'a [SavedSshKeyReference],
    managed_ssh_keys: &'a [SavedManagedSshKey],
    identity_references: &'a [SavedIdentityReference],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphCommitmentPayloadV3<'a> {
    format_version: u32,
    store_id: &'a str,
    hosts: &'a [SavedHost],
    ssh_key_references: &'a [SavedSshKeyReference],
    managed_ssh_keys: &'a [SavedManagedSshKey],
    identity_references: &'a [SavedIdentityReference],
    password_identities: &'a [SavedPasswordIdentity],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphCommitmentPayloadV4<'a> {
    format_version: u32,
    store_id: &'a str,
    hosts: &'a [SavedHost],
    ssh_key_references: &'a [SavedSshKeyReference],
    managed_ssh_keys: &'a [SavedManagedSshKey],
    identity_references: &'a [SavedIdentityReference],
    password_identities: &'a [SavedPasswordIdentity],
    proxy_profiles: &'a [SavedProxyProfile],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphCommitmentPayloadV5<'a> {
    format_version: u32,
    store_id: &'a str,
    hosts: &'a [SavedHost],
    ssh_key_references: &'a [SavedSshKeyReference],
    managed_ssh_keys: &'a [SavedManagedSshKey],
    identity_references: &'a [SavedIdentityReference],
    password_identities: &'a [SavedPasswordIdentity],
    proxy_profiles: &'a [SavedProxyProfile],
    groups: &'a [SavedGroupConfig],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphCommitmentPayloadV6<'a> {
    format_version: u32,
    store_id: &'a str,
    hosts: &'a [SavedHost],
    ssh_key_references: &'a [SavedSshKeyReference],
    managed_ssh_keys: &'a [SavedManagedSshKey],
    identity_references: &'a [SavedIdentityReference],
    password_identities: &'a [SavedPasswordIdentity],
    proxy_profiles: &'a [SavedProxyProfile],
    groups: &'a [SavedGroupConfig],
    notes_snippets: &'a SavedNotesSnippetsCatalog,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphCommitmentPayloadV7<'a> {
    format_version: u32,
    store_id: &'a str,
    hosts: &'a [SavedHost],
    ssh_key_references: &'a [SavedSshKeyReference],
    managed_ssh_keys: &'a [SavedManagedSshKey],
    identity_references: &'a [SavedIdentityReference],
    password_identities: &'a [SavedPasswordIdentity],
    proxy_profiles: &'a [SavedProxyProfile],
    groups: &'a [SavedGroupConfig],
    notes_snippets: &'a SavedNotesSnippetsCatalog,
    port_forward_rules: &'a [SavedPortForwardRule],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphCommitmentPayloadV8<'a> {
    format_version: u32,
    store_id: &'a str,
    hosts: &'a [SavedHost],
    ssh_key_references: &'a [SavedSshKeyReference],
    managed_ssh_keys: &'a [SavedManagedSshKey],
    identity_references: &'a [SavedIdentityReference],
    password_identities: &'a [SavedPasswordIdentity],
    proxy_profiles: &'a [SavedProxyProfile],
    groups: &'a [SavedGroupConfig],
    notes_snippets: &'a SavedNotesSnippetsCatalog,
    port_forward_rules: &'a [SavedPortForwardRule],
    known_hosts: &'a [SavedKnownHost],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphCommitmentPayloadV9<'a> {
    format_version: u32,
    store_id: &'a str,
    hosts: &'a [SavedHost],
    ssh_key_references: &'a [SavedSshKeyReference],
    managed_ssh_keys: &'a [SavedManagedSshKey],
    identity_references: &'a [SavedIdentityReference],
    password_identities: &'a [SavedPasswordIdentity],
    proxy_profiles: &'a [SavedProxyProfile],
    groups: &'a [SavedGroupConfig],
    notes_snippets: &'a SavedNotesSnippetsCatalog,
    port_forward_rules: &'a [SavedPortForwardRule],
    known_hosts: &'a [SavedKnownHost],
    connection_logs: &'a [SavedConnectionLog],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphCommitmentPayloadV10<'a> {
    format_version: u32,
    store_id: &'a str,
    hosts: &'a [SavedHost],
    ssh_key_references: &'a [SavedSshKeyReference],
    managed_ssh_keys: &'a [SavedManagedSshKey],
    identity_references: &'a [SavedIdentityReference],
    password_identities: &'a [SavedPasswordIdentity],
    proxy_profiles: &'a [SavedProxyProfile],
    groups: &'a [SavedGroupConfig],
    custom_groups: &'a SavedGroupCatalog,
    notes_snippets: &'a SavedNotesSnippetsCatalog,
    port_forward_rules: &'a [SavedPortForwardRule],
    known_hosts: &'a [SavedKnownHost],
    connection_logs: &'a [SavedConnectionLog],
}

impl SnapshotEnvelope {
    #[cfg(test)]
    fn new(
        store_id: String,
        slot: Slot,
        generation: u64,
        hosts: Vec<SavedHost>,
        ssh_key_references: Vec<SavedSshKeyReference>,
        managed_ssh_keys: Vec<SavedManagedSshKey>,
        identity_references: Vec<SavedIdentityReference>,
        password_identities: Vec<SavedPasswordIdentity>,
    ) -> Result<Self, StoreError> {
        Self::new_with_proxy_profiles(
            store_id,
            slot,
            generation,
            hosts,
            ssh_key_references,
            managed_ssh_keys,
            identity_references,
            password_identities,
            Vec::new(),
            Vec::new(),
            SavedNotesSnippetsCatalog::default(),
            Vec::new(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_proxy_profiles(
        store_id: String,
        slot: Slot,
        generation: u64,
        hosts: Vec<SavedHost>,
        ssh_key_references: Vec<SavedSshKeyReference>,
        managed_ssh_keys: Vec<SavedManagedSshKey>,
        identity_references: Vec<SavedIdentityReference>,
        password_identities: Vec<SavedPasswordIdentity>,
        proxy_profiles: Vec<SavedProxyProfile>,
        groups: Vec<SavedGroupConfig>,
        notes_snippets: SavedNotesSnippetsCatalog,
        port_forward_rules: Vec<SavedPortForwardRule>,
    ) -> Result<Self, StoreError> {
        let checksum = snapshot_checksum_v8(
            &store_id,
            slot,
            generation,
            &hosts,
            &ssh_key_references,
            &managed_ssh_keys,
            &identity_references,
            &password_identities,
            &proxy_profiles,
            &groups,
            &notes_snippets,
            &port_forward_rules,
        )?;
        Ok(Self {
            magic: SNAPSHOT_MAGIC.to_owned(),
            format_version: SNAPSHOT_FORMAT_V8,
            store_id,
            slot,
            generation,
            hosts,
            ssh_key_references: Some(Some(ssh_key_references)),
            managed_ssh_keys: Some(Some(managed_ssh_keys)),
            identity_references: Some(Some(identity_references)),
            password_identities: Some(Some(password_identities)),
            proxy_profiles: Some(Some(proxy_profiles)),
            groups: Some(Some(groups)),
            custom_groups: None,
            notes_snippets: Some(Some(notes_snippets)),
            port_forward_rules: Some(Some(port_forward_rules)),
            known_hosts: None,
            connection_logs: None,
            checksum,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_known_hosts(
        store_id: String,
        slot: Slot,
        generation: u64,
        hosts: Vec<SavedHost>,
        ssh_key_references: Vec<SavedSshKeyReference>,
        managed_ssh_keys: Vec<SavedManagedSshKey>,
        identity_references: Vec<SavedIdentityReference>,
        password_identities: Vec<SavedPasswordIdentity>,
        proxy_profiles: Vec<SavedProxyProfile>,
        groups: Vec<SavedGroupConfig>,
        notes_snippets: SavedNotesSnippetsCatalog,
        port_forward_rules: Vec<SavedPortForwardRule>,
        known_hosts: Vec<SavedKnownHost>,
    ) -> Result<Self, StoreError> {
        let checksum = snapshot_checksum_v9(
            &store_id,
            slot,
            generation,
            &hosts,
            &ssh_key_references,
            &managed_ssh_keys,
            &identity_references,
            &password_identities,
            &proxy_profiles,
            &groups,
            &notes_snippets,
            &port_forward_rules,
            &known_hosts,
        )?;
        Ok(Self {
            magic: SNAPSHOT_MAGIC.to_owned(),
            format_version: SNAPSHOT_FORMAT_V9,
            store_id,
            slot,
            generation,
            hosts,
            ssh_key_references: Some(Some(ssh_key_references)),
            managed_ssh_keys: Some(Some(managed_ssh_keys)),
            identity_references: Some(Some(identity_references)),
            password_identities: Some(Some(password_identities)),
            proxy_profiles: Some(Some(proxy_profiles)),
            groups: Some(Some(groups)),
            custom_groups: None,
            notes_snippets: Some(Some(notes_snippets)),
            port_forward_rules: Some(Some(port_forward_rules)),
            known_hosts: Some(Some(known_hosts)),
            connection_logs: None,
            checksum,
        })
    }

    /// Constructs the complete Vault v10 metadata snapshot. Terminal replay
    /// contents are structurally impossible here because `SavedConnectionLog`
    /// serializes metadata only.
    #[allow(clippy::too_many_arguments)]
    fn new_with_connection_logs(
        store_id: String,
        slot: Slot,
        generation: u64,
        hosts: Vec<SavedHost>,
        ssh_key_references: Vec<SavedSshKeyReference>,
        managed_ssh_keys: Vec<SavedManagedSshKey>,
        identity_references: Vec<SavedIdentityReference>,
        password_identities: Vec<SavedPasswordIdentity>,
        proxy_profiles: Vec<SavedProxyProfile>,
        groups: Vec<SavedGroupConfig>,
        notes_snippets: SavedNotesSnippetsCatalog,
        port_forward_rules: Vec<SavedPortForwardRule>,
        known_hosts: Vec<SavedKnownHost>,
        connection_logs: Vec<SavedConnectionLog>,
    ) -> Result<Self, StoreError> {
        let checksum = snapshot_checksum_v10(
            &store_id,
            slot,
            generation,
            &hosts,
            &ssh_key_references,
            &managed_ssh_keys,
            &identity_references,
            &password_identities,
            &proxy_profiles,
            &groups,
            &notes_snippets,
            &port_forward_rules,
            &known_hosts,
            &connection_logs,
        )?;
        Ok(Self {
            magic: SNAPSHOT_MAGIC.to_owned(),
            format_version: SNAPSHOT_FORMAT_V10,
            store_id,
            slot,
            generation,
            hosts,
            ssh_key_references: Some(Some(ssh_key_references)),
            managed_ssh_keys: Some(Some(managed_ssh_keys)),
            identity_references: Some(Some(identity_references)),
            password_identities: Some(Some(password_identities)),
            proxy_profiles: Some(Some(proxy_profiles)),
            groups: Some(Some(groups)),
            custom_groups: None,
            notes_snippets: Some(Some(notes_snippets)),
            port_forward_rules: Some(Some(port_forward_rules)),
            known_hosts: Some(Some(known_hosts)),
            connection_logs: Some(Some(connection_logs)),
            checksum,
        })
    }

    /// Constructs the complete Vault v11 snapshot. Presence of
    /// `customGroups` is authenticated even when the explicit catalog is
    /// empty, preserving legacy absent-versus-explicit-empty semantics.
    #[allow(clippy::too_many_arguments)]
    fn new_with_custom_groups(
        store_id: String,
        slot: Slot,
        generation: u64,
        hosts: Vec<SavedHost>,
        ssh_key_references: Vec<SavedSshKeyReference>,
        managed_ssh_keys: Vec<SavedManagedSshKey>,
        identity_references: Vec<SavedIdentityReference>,
        password_identities: Vec<SavedPasswordIdentity>,
        proxy_profiles: Vec<SavedProxyProfile>,
        groups: Vec<SavedGroupConfig>,
        custom_groups: SavedGroupCatalog,
        notes_snippets: SavedNotesSnippetsCatalog,
        port_forward_rules: Vec<SavedPortForwardRule>,
        known_hosts: Vec<SavedKnownHost>,
        connection_logs: Vec<SavedConnectionLog>,
    ) -> Result<Self, StoreError> {
        let checksum = snapshot_checksum_v11(
            &store_id,
            slot,
            generation,
            &hosts,
            &ssh_key_references,
            &managed_ssh_keys,
            &identity_references,
            &password_identities,
            &proxy_profiles,
            &groups,
            &custom_groups,
            &notes_snippets,
            &port_forward_rules,
            &known_hosts,
            &connection_logs,
        )?;
        Ok(Self {
            magic: SNAPSHOT_MAGIC.to_owned(),
            format_version: SNAPSHOT_FORMAT_V11,
            store_id,
            slot,
            generation,
            hosts,
            ssh_key_references: Some(Some(ssh_key_references)),
            managed_ssh_keys: Some(Some(managed_ssh_keys)),
            identity_references: Some(Some(identity_references)),
            password_identities: Some(Some(password_identities)),
            proxy_profiles: Some(Some(proxy_profiles)),
            groups: Some(Some(groups)),
            custom_groups: Some(Some(custom_groups)),
            notes_snippets: Some(Some(notes_snippets)),
            port_forward_rules: Some(Some(port_forward_rules)),
            known_hosts: Some(Some(known_hosts)),
            connection_logs: Some(Some(connection_logs)),
            checksum,
        })
    }

    /// Uses the newest format required by the populated catalogs while
    /// retaining the established empty-catalog compatibility behavior.
    #[allow(clippy::too_many_arguments)]
    fn new_latest(
        store_id: String,
        slot: Slot,
        generation: u64,
        hosts: Vec<SavedHost>,
        ssh_key_references: Vec<SavedSshKeyReference>,
        managed_ssh_keys: Vec<SavedManagedSshKey>,
        identity_references: Vec<SavedIdentityReference>,
        password_identities: Vec<SavedPasswordIdentity>,
        proxy_profiles: Vec<SavedProxyProfile>,
        groups: Vec<SavedGroupConfig>,
        custom_groups: Option<SavedGroupCatalog>,
        notes_snippets: SavedNotesSnippetsCatalog,
        port_forward_rules: Vec<SavedPortForwardRule>,
        known_hosts: Vec<SavedKnownHost>,
        connection_logs: Vec<SavedConnectionLog>,
    ) -> Result<Self, StoreError> {
        if let Some(custom_groups) = custom_groups {
            return Self::new_with_custom_groups(
                store_id,
                slot,
                generation,
                hosts,
                ssh_key_references,
                managed_ssh_keys,
                identity_references,
                password_identities,
                proxy_profiles,
                groups,
                custom_groups,
                notes_snippets,
                port_forward_rules,
                known_hosts,
                connection_logs,
            );
        }
        if !connection_logs.is_empty() {
            return Self::new_with_connection_logs(
                store_id,
                slot,
                generation,
                hosts,
                ssh_key_references,
                managed_ssh_keys,
                identity_references,
                password_identities,
                proxy_profiles,
                groups,
                notes_snippets,
                port_forward_rules,
                known_hosts,
                connection_logs,
            );
        }
        if !known_hosts.is_empty() {
            return Self::new_with_known_hosts(
                store_id,
                slot,
                generation,
                hosts,
                ssh_key_references,
                managed_ssh_keys,
                identity_references,
                password_identities,
                proxy_profiles,
                groups,
                notes_snippets,
                port_forward_rules,
                known_hosts,
            );
        }
        Self::new_with_proxy_profiles(
            store_id,
            slot,
            generation,
            hosts,
            ssh_key_references,
            managed_ssh_keys,
            identity_references,
            password_identities,
            proxy_profiles,
            groups,
            notes_snippets,
            port_forward_rules,
        )
    }

    fn validate(
        mut self,
        expected_store_id: &str,
        expected_slot: Slot,
        expected_generation: u64,
        path: PathBuf,
    ) -> Result<ValidatedSnapshot, StoreError> {
        if self.magic != SNAPSHOT_MAGIC
            || self.store_id != expected_store_id
            || self.slot != expected_slot
            || self.generation != expected_generation
        {
            return Err(StoreError::BothSlotsCorrupt);
        }
        let ssh_key_references = optional_catalog(&self.ssh_key_references)?;
        let identity_references = optional_catalog(&self.identity_references)?;
        let expected_checksum = match self.format_version {
            SNAPSHOT_FORMAT_V1
                if ssh_key_references.is_empty()
                    && self.managed_ssh_keys.is_none()
                    && identity_references.is_empty()
                    && self.password_identities.is_none()
                    && self.proxy_profiles.is_none()
                    && self.groups.is_none()
                    && self.custom_groups.is_none()
                    && self.notes_snippets.is_none()
                    && self.port_forward_rules.is_none()
                    && self.known_hosts.is_none()
                    && self.connection_logs.is_none() =>
            {
                snapshot_checksum_v1(&self.store_id, self.slot, self.generation, &self.hosts)?
            }
            SNAPSHOT_FORMAT_V2
                if self.managed_ssh_keys.is_none()
                    && self.password_identities.is_none()
                    && self.proxy_profiles.is_none()
                    && self.groups.is_none()
                    && self.custom_groups.is_none()
                    && self.notes_snippets.is_none()
                    && self.port_forward_rules.is_none()
                    && self.known_hosts.is_none()
                    && self.connection_logs.is_none() =>
            {
                snapshot_checksum_v2(
                    &self.store_id,
                    self.slot,
                    self.generation,
                    &self.hosts,
                    ssh_key_references,
                    identity_references,
                )?
            }
            SNAPSHOT_FORMAT_V3
                if self.password_identities.is_none()
                    && self.proxy_profiles.is_none()
                    && self.groups.is_none()
                    && self.custom_groups.is_none()
                    && self.notes_snippets.is_none()
                    && self.port_forward_rules.is_none()
                    && self.known_hosts.is_none()
                    && self.connection_logs.is_none() =>
            {
                snapshot_checksum_v3(
                    &self.store_id,
                    self.slot,
                    self.generation,
                    &self.hosts,
                    ssh_key_references,
                    required_catalog(&self.managed_ssh_keys)?,
                    identity_references,
                )?
            }
            SNAPSHOT_FORMAT_V4
                if self.proxy_profiles.is_none()
                    && self.groups.is_none()
                    && self.custom_groups.is_none()
                    && self.notes_snippets.is_none()
                    && self.port_forward_rules.is_none()
                    && self.known_hosts.is_none()
                    && self.connection_logs.is_none() =>
            {
                snapshot_checksum_v4(
                    &self.store_id,
                    self.slot,
                    self.generation,
                    &self.hosts,
                    required_catalog(&self.ssh_key_references)?,
                    required_catalog(&self.managed_ssh_keys)?,
                    required_catalog(&self.identity_references)?,
                    required_catalog(&self.password_identities)?,
                )?
            }
            SNAPSHOT_FORMAT_V5
                if self.groups.is_none()
                    && self.custom_groups.is_none()
                    && self.notes_snippets.is_none()
                    && self.port_forward_rules.is_none()
                    && self.known_hosts.is_none()
                    && self.connection_logs.is_none() =>
            {
                snapshot_checksum_v5(
                    &self.store_id,
                    self.slot,
                    self.generation,
                    &self.hosts,
                    required_catalog(&self.ssh_key_references)?,
                    required_catalog(&self.managed_ssh_keys)?,
                    required_catalog(&self.identity_references)?,
                    required_catalog(&self.password_identities)?,
                    required_catalog(&self.proxy_profiles)?,
                )?
            }
            SNAPSHOT_FORMAT_V6
                if self.custom_groups.is_none()
                    && self.notes_snippets.is_none()
                    && self.port_forward_rules.is_none()
                    && self.known_hosts.is_none()
                    && self.connection_logs.is_none() =>
            {
                snapshot_checksum_v6(
                    &self.store_id,
                    self.slot,
                    self.generation,
                    &self.hosts,
                    required_catalog(&self.ssh_key_references)?,
                    required_catalog(&self.managed_ssh_keys)?,
                    required_catalog(&self.identity_references)?,
                    required_catalog(&self.password_identities)?,
                    required_catalog(&self.proxy_profiles)?,
                    required_catalog(&self.groups)?,
                )?
            }
            SNAPSHOT_FORMAT_V7
                if self.custom_groups.is_none()
                    && self.port_forward_rules.is_none()
                    && self.known_hosts.is_none()
                    && self.connection_logs.is_none() =>
            {
                snapshot_checksum_v7(
                    &self.store_id,
                    self.slot,
                    self.generation,
                    &self.hosts,
                    required_catalog(&self.ssh_key_references)?,
                    required_catalog(&self.managed_ssh_keys)?,
                    required_catalog(&self.identity_references)?,
                    required_catalog(&self.password_identities)?,
                    required_catalog(&self.proxy_profiles)?,
                    required_catalog(&self.groups)?,
                    required_value(&self.notes_snippets)?,
                )?
            }
            SNAPSHOT_FORMAT_V8
                if self.custom_groups.is_none()
                    && self.known_hosts.is_none()
                    && self.connection_logs.is_none() =>
            {
                snapshot_checksum_v8(
                    &self.store_id,
                    self.slot,
                    self.generation,
                    &self.hosts,
                    required_catalog(&self.ssh_key_references)?,
                    required_catalog(&self.managed_ssh_keys)?,
                    required_catalog(&self.identity_references)?,
                    required_catalog(&self.password_identities)?,
                    required_catalog(&self.proxy_profiles)?,
                    required_catalog(&self.groups)?,
                    required_value(&self.notes_snippets)?,
                    required_catalog(&self.port_forward_rules)?,
                )?
            }
            SNAPSHOT_FORMAT_V9
                if self.custom_groups.is_none() && self.connection_logs.is_none() =>
            {
                snapshot_checksum_v9(
                    &self.store_id,
                    self.slot,
                    self.generation,
                    &self.hosts,
                    required_catalog(&self.ssh_key_references)?,
                    required_catalog(&self.managed_ssh_keys)?,
                    required_catalog(&self.identity_references)?,
                    required_catalog(&self.password_identities)?,
                    required_catalog(&self.proxy_profiles)?,
                    required_catalog(&self.groups)?,
                    required_value(&self.notes_snippets)?,
                    required_catalog(&self.port_forward_rules)?,
                    required_catalog(&self.known_hosts)?,
                )?
            }
            SNAPSHOT_FORMAT_V10 if self.custom_groups.is_none() => snapshot_checksum_v10(
                &self.store_id,
                self.slot,
                self.generation,
                &self.hosts,
                required_catalog(&self.ssh_key_references)?,
                required_catalog(&self.managed_ssh_keys)?,
                required_catalog(&self.identity_references)?,
                required_catalog(&self.password_identities)?,
                required_catalog(&self.proxy_profiles)?,
                required_catalog(&self.groups)?,
                required_value(&self.notes_snippets)?,
                required_catalog(&self.port_forward_rules)?,
                required_catalog(&self.known_hosts)?,
                required_catalog(&self.connection_logs)?,
            )?,
            SNAPSHOT_FORMAT_V11 => snapshot_checksum_v11(
                &self.store_id,
                self.slot,
                self.generation,
                &self.hosts,
                required_catalog(&self.ssh_key_references)?,
                required_catalog(&self.managed_ssh_keys)?,
                required_catalog(&self.identity_references)?,
                required_catalog(&self.password_identities)?,
                required_catalog(&self.proxy_profiles)?,
                required_catalog(&self.groups)?,
                required_value(&self.custom_groups)?,
                required_value(&self.notes_snippets)?,
                required_catalog(&self.port_forward_rules)?,
                required_catalog(&self.known_hosts)?,
                required_catalog(&self.connection_logs)?,
            )?,
            _ => return Err(StoreError::BothSlotsCorrupt),
        };
        if self.checksum != expected_checksum {
            return Err(StoreError::BothSlotsCorrupt);
        }
        let mut ssh_key_references = self.ssh_key_references.flatten().unwrap_or_default();
        let mut managed_ssh_keys = self.managed_ssh_keys.flatten().unwrap_or_default();
        let mut identity_references = self.identity_references.flatten().unwrap_or_default();
        let mut password_identities = self.password_identities.flatten().unwrap_or_default();
        let mut proxy_profiles = self.proxy_profiles.flatten().unwrap_or_default();
        let mut groups = self.groups.flatten().unwrap_or_default();
        let custom_groups = self.custom_groups.flatten();
        let notes_snippets = self.notes_snippets.flatten().unwrap_or_default();
        let mut port_forward_rules = self.port_forward_rules.flatten().unwrap_or_default();
        let known_hosts = self.known_hosts.flatten().unwrap_or_default();
        let mut connection_logs = self.connection_logs.flatten().unwrap_or_default();
        normalize_hosts(&mut self.hosts)?;
        normalize_ssh_key_references(&mut ssh_key_references)?;
        normalize_managed_ssh_keys(&mut managed_ssh_keys, &ssh_key_references)?;
        normalize_identity_references(
            &mut identity_references,
            &ssh_key_references,
            &managed_ssh_keys,
        )?;
        normalize_password_identities(&mut password_identities, &identity_references)?;
        normalize_proxy_profiles(&mut proxy_profiles)?;
        normalize_groups(&mut groups)?;
        if matches!(
            self.format_version,
            SNAPSHOT_FORMAT_V3
                | SNAPSHOT_FORMAT_V4
                | SNAPSHOT_FORMAT_V5
                | SNAPSHOT_FORMAT_V6
                | SNAPSHOT_FORMAT_V7
                | SNAPSHOT_FORMAT_V8
                | SNAPSHOT_FORMAT_V9
                | SNAPSHOT_FORMAT_V10
                | SNAPSHOT_FORMAT_V11
        ) {
            validate_host_graph_references(
                &self.hosts,
                &ssh_key_references,
                &managed_ssh_keys,
                &identity_references,
                &password_identities,
            )?;
            if matches!(
                self.format_version,
                SNAPSHOT_FORMAT_V5
                    | SNAPSHOT_FORMAT_V6
                    | SNAPSHOT_FORMAT_V7
                    | SNAPSHOT_FORMAT_V8
                    | SNAPSHOT_FORMAT_V9
                    | SNAPSHOT_FORMAT_V10
                    | SNAPSHOT_FORMAT_V11
            ) {
                validate_proxy_graph_references(
                    &self.hosts,
                    &proxy_profiles,
                    &identity_references,
                    &password_identities,
                )?;
            }
            if matches!(
                self.format_version,
                SNAPSHOT_FORMAT_V6
                    | SNAPSHOT_FORMAT_V7
                    | SNAPSHOT_FORMAT_V8
                    | SNAPSHOT_FORMAT_V9
                    | SNAPSHOT_FORMAT_V10
                    | SNAPSHOT_FORMAT_V11
            ) {
                validate_group_graph_references(
                    &groups,
                    &self.hosts,
                    &ssh_key_references,
                    &managed_ssh_keys,
                    &identity_references,
                    &password_identities,
                    &proxy_profiles,
                )?;
            }
            if matches!(
                self.format_version,
                SNAPSHOT_FORMAT_V7
                    | SNAPSHOT_FORMAT_V8
                    | SNAPSHOT_FORMAT_V9
                    | SNAPSHOT_FORMAT_V10
                    | SNAPSHOT_FORMAT_V11
            ) {
                validate_notes_snippets_graph_references(&self.hosts, &groups, &notes_snippets)?;
            }
            if matches!(
                self.format_version,
                SNAPSHOT_FORMAT_V8 | SNAPSHOT_FORMAT_V9 | SNAPSHOT_FORMAT_V10 | SNAPSHOT_FORMAT_V11
            ) {
                normalize_port_forward_rules(&mut port_forward_rules, &self.hosts)?;
            }
            if matches!(
                self.format_version,
                SNAPSHOT_FORMAT_V9 | SNAPSHOT_FORMAT_V10 | SNAPSHOT_FORMAT_V11
            ) {
                validate_saved_known_hosts(&known_hosts).map_err(|_| StoreError::Serialization)?;
            }
            if matches!(
                self.format_version,
                SNAPSHOT_FORMAT_V10 | SNAPSHOT_FORMAT_V11
            ) {
                normalize_connection_logs(&mut connection_logs)?;
            }
        }
        Ok(ValidatedSnapshot {
            path,
            generation: self.generation,
            hosts: self.hosts,
            ssh_key_references,
            managed_ssh_keys,
            identity_references,
            password_identities,
            proxy_profiles,
            groups,
            custom_groups,
            notes_snippets,
            port_forward_rules,
            known_hosts,
            connection_logs,
        })
    }
}

struct ValidatedSnapshot {
    path: PathBuf,
    generation: u64,
    hosts: Vec<SavedHost>,
    ssh_key_references: Vec<SavedSshKeyReference>,
    managed_ssh_keys: Vec<SavedManagedSshKey>,
    identity_references: Vec<SavedIdentityReference>,
    password_identities: Vec<SavedPasswordIdentity>,
    proxy_profiles: Vec<SavedProxyProfile>,
    groups: Vec<SavedGroupConfig>,
    custom_groups: Option<SavedGroupCatalog>,
    notes_snippets: SavedNotesSnippetsCatalog,
    port_forward_rules: Vec<SavedPortForwardRule>,
    known_hosts: Vec<SavedKnownHost>,
    connection_logs: Vec<SavedConnectionLog>,
}

struct SlotProbe {
    empty: bool,
    max_seen: Option<u64>,
    snapshot: Option<ValidatedSnapshot>,
}

fn process_gate(root: &Path) -> Result<ProcessGate, StoreError> {
    let registry = PROCESS_GATES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut registry = registry.lock().map_err(|_| StoreError::LockPoisoned)?;
    registry.retain(|_, gate| gate.strong_count() > 0);
    if let Some(gate) = registry.get(root).and_then(Weak::upgrade) {
        return Ok(gate);
    }
    let gate = Arc::new(Mutex::new(()));
    registry.insert(root.to_path_buf(), Arc::downgrade(&gate));
    Ok(gate)
}

fn prepare_layout(root: &Path) -> Result<String, StoreError> {
    let owner_path = root.join(OWNER_FILE);
    let store_id = if owner_path.try_exists()? {
        read_owner(&owner_path)?
    } else {
        if fs::read_dir(root)?.next().transpose()?.is_some() {
            return Err(StoreError::ArtifactConflict);
        }
        let owner = OwnerMarker {
            magic: OWNER_MAGIC.to_owned(),
            format_version: OWNER_FORMAT_VERSION,
            store_id: Uuid::new_v4().to_string(),
        };
        let encoded = serde_json::to_vec(&owner).map_err(|_| StoreError::Serialization)?;
        publish_named_no_overwrite(root, OWNER_FILE, ".owner", &encoded)?;
        owner.store_id
    };

    for directory in [SLOT_A_DIRECTORY, SLOT_B_DIRECTORY] {
        let path = root.join(directory);
        match fs::create_dir(&path) {
            Ok(()) => sync_directory(root)?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                require_directory(&path)?;
            }
            Err(error) => return Err(StoreError::Io(error)),
        }
    }
    validate_root_entries(root)?;
    Ok(store_id)
}

fn read_owner(path: &Path) -> Result<String, StoreError> {
    require_regular_file(path).map_err(|_| StoreError::InvalidOwner)?;
    let bytes = read_bounded(path, MAX_OWNER_BYTES).map_err(|_| StoreError::InvalidOwner)?;
    let owner: OwnerMarker =
        serde_json::from_slice(&bytes).map_err(|_| StoreError::InvalidOwner)?;
    if owner.magic != OWNER_MAGIC
        || owner.format_version != OWNER_FORMAT_VERSION
        || Uuid::parse_str(&owner.store_id).is_err()
    {
        return Err(StoreError::InvalidOwner);
    }
    Ok(owner.store_id)
}

fn validate_root_entries(root: &Path) -> Result<(), StoreError> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(StoreError::ArtifactConflict)?;
        if matches!(name, OWNER_FILE | SLOT_A_DIRECTORY | SLOT_B_DIRECTORY)
            || (name.starts_with(".owner-") && name.ends_with(".tmp"))
        {
            continue;
        }
        return Err(StoreError::ArtifactConflict);
    }
    Ok(())
}

fn probe_slot(directory: &Path, slot: Slot, store_id: &str) -> Result<SlotProbe, StoreError> {
    require_directory(directory)?;
    let mut candidates: Vec<(u64, PathBuf)> = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Some(generation) = parse_snapshot_name(name) {
            candidates.push((generation, entry.path()));
        }
    }
    if candidates.is_empty() {
        return Ok(SlotProbe {
            empty: true,
            max_seen: None,
            snapshot: None,
        });
    }
    candidates.sort_by_key(|(generation, _)| *generation);
    let max_seen = candidates.last().map(|(generation, _)| *generation);
    let latest = candidates
        .iter()
        .rev()
        .take_while(|(generation, _)| Some(*generation) == max_seen)
        .collect::<Vec<_>>();
    if latest.len() != 1 {
        return Ok(SlotProbe {
            empty: false,
            max_seen,
            snapshot: None,
        });
    }
    let (generation, path) = latest[0];
    let snapshot = read_snapshot(path, store_id, slot, *generation).ok();
    Ok(SlotProbe {
        empty: false,
        max_seen,
        snapshot,
    })
}

fn scan_slot_managed_secret_retention(
    directory: &Path,
    slot: Slot,
    store_id: &str,
    retained: &mut BTreeSet<SavedVaultManagedSecretRetention>,
) -> Result<(), StoreError> {
    require_directory(directory).map_err(|_| StoreError::ManagedSecretRetentionUncertain)?;
    let entries =
        fs::read_dir(directory).map_err(|_| StoreError::ManagedSecretRetentionUncertain)?;
    let mut final_generations = HashSet::new();

    for entry in entries {
        let entry = entry.map_err(|_| StoreError::ManagedSecretRetentionUncertain)?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or(StoreError::ManagedSecretRetentionUncertain)?;
        let path = entry.path();
        let snapshot = if let Some(generation) = parse_snapshot_name(name) {
            if !final_generations.insert(generation) {
                return Err(StoreError::ManagedSecretRetentionUncertain);
            }
            read_snapshot(&path, store_id, slot, generation)
                .map_err(|_| StoreError::ManagedSecretRetentionUncertain)?
        } else if is_snapshot_temp_name(name) {
            read_retention_temp_snapshot(&path, store_id, slot)?
        } else {
            return Err(StoreError::ManagedSecretRetentionUncertain);
        };

        for managed_key in snapshot.managed_ssh_keys {
            retained.insert(SavedVaultManagedSecretRetention {
                entity_id: managed_key.id.clone(),
                backend_locator: managed_key.custody().backend_locator().clone(),
                custody_revision: managed_key.custody().custody_revision(),
            });
        }
    }
    Ok(())
}

fn read_retention_temp_snapshot(
    path: &Path,
    store_id: &str,
    slot: Slot,
) -> Result<ValidatedSnapshot, StoreError> {
    require_regular_file(path).map_err(|_| StoreError::ManagedSecretRetentionUncertain)?;
    let encoded = read_bounded(path, MAX_SNAPSHOT_BYTES)
        .map_err(|_| StoreError::ManagedSecretRetentionUncertain)?;
    let envelope: SnapshotEnvelope = serde_json::from_slice(&encoded)
        .map_err(|_| StoreError::ManagedSecretRetentionUncertain)?;
    let generation = envelope.generation;
    if generation == 0 || Slot::for_generation(generation) != slot {
        return Err(StoreError::ManagedSecretRetentionUncertain);
    }
    envelope
        .validate(store_id, slot, generation, path.to_path_buf())
        .map_err(|_| StoreError::ManagedSecretRetentionUncertain)
}

fn read_snapshot(
    path: &Path,
    store_id: &str,
    slot: Slot,
    generation: u64,
) -> Result<ValidatedSnapshot, StoreError> {
    if Slot::for_generation(generation) != slot {
        return Err(StoreError::BothSlotsCorrupt);
    }
    require_regular_file(path).map_err(|_| StoreError::BothSlotsCorrupt)?;
    let encoded =
        read_bounded(path, MAX_SNAPSHOT_BYTES).map_err(|_| StoreError::BothSlotsCorrupt)?;
    let envelope: SnapshotEnvelope =
        serde_json::from_slice(&encoded).map_err(|_| StoreError::BothSlotsCorrupt)?;
    envelope.validate(store_id, slot, generation, path.to_path_buf())
}

fn parse_snapshot_name(name: &str) -> Option<u64> {
    let body = name.strip_prefix("snapshot-")?.strip_suffix(".json")?;
    let (generation, artifact_id) = body.split_once('-')?;
    if generation.len() != 20
        || artifact_id.len() != 32
        || !artifact_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let generation = generation.parse().ok()?;
    (generation > 0).then_some(generation)
}

fn snapshot_checksum_v1(
    store_id: &str,
    slot: Slot,
    generation: u64,
    hosts: &[SavedHost],
) -> Result<String, StoreError> {
    let encoded = serde_json::to_vec(&ChecksumPayloadV1 {
        format_version: SNAPSHOT_FORMAT_V1,
        store_id,
        slot,
        generation,
        hosts,
    })
    .map_err(|_| StoreError::Serialization)?;
    Ok(hex_digest(&encoded))
}

fn snapshot_checksum_v2(
    store_id: &str,
    slot: Slot,
    generation: u64,
    hosts: &[SavedHost],
    ssh_key_references: &[SavedSshKeyReference],
    identity_references: &[SavedIdentityReference],
) -> Result<String, StoreError> {
    let legacy_identity_references = legacy_identity_references(identity_references);
    let encoded = serde_json::to_vec(&ChecksumPayloadV2 {
        format_version: SNAPSHOT_FORMAT_V2,
        store_id,
        slot,
        generation,
        hosts,
        ssh_key_references,
        identity_references: &legacy_identity_references,
    })
    .map_err(|_| StoreError::Serialization)?;
    Ok(hex_digest(&encoded))
}

fn snapshot_checksum_v3(
    store_id: &str,
    slot: Slot,
    generation: u64,
    hosts: &[SavedHost],
    ssh_key_references: &[SavedSshKeyReference],
    managed_ssh_keys: &[SavedManagedSshKey],
    identity_references: &[SavedIdentityReference],
) -> Result<String, StoreError> {
    let encoded = serde_json::to_vec(&ChecksumPayloadV3 {
        magic: SNAPSHOT_MAGIC,
        format_version: SNAPSHOT_FORMAT_V3,
        store_id,
        slot,
        generation,
        hosts,
        ssh_key_references,
        managed_ssh_keys,
        identity_references,
    })
    .map_err(|_| StoreError::Serialization)?;
    let mut digest = Sha256::new();
    digest.update(b"netcatty-saved-host-snapshot-checksum-v3\0");
    digest.update((encoded.len() as u64).to_be_bytes());
    digest.update(&encoded);
    Ok(hex_encode(&digest.finalize()))
}

fn snapshot_checksum_v4(
    store_id: &str,
    slot: Slot,
    generation: u64,
    hosts: &[SavedHost],
    ssh_key_references: &[SavedSshKeyReference],
    managed_ssh_keys: &[SavedManagedSshKey],
    identity_references: &[SavedIdentityReference],
    password_identities: &[SavedPasswordIdentity],
) -> Result<String, StoreError> {
    let encoded = serde_json::to_vec(&ChecksumPayloadV4 {
        magic: SNAPSHOT_MAGIC,
        format_version: SNAPSHOT_FORMAT_V4,
        store_id,
        slot,
        generation,
        hosts,
        ssh_key_references,
        managed_ssh_keys,
        identity_references,
        password_identities,
    })
    .map_err(|_| StoreError::Serialization)?;
    let mut digest = Sha256::new();
    digest.update(b"netcatty-saved-host-snapshot-checksum-v4\0");
    digest.update((encoded.len() as u64).to_be_bytes());
    digest.update(&encoded);
    Ok(hex_encode(&digest.finalize()))
}

fn snapshot_checksum_v5(
    store_id: &str,
    slot: Slot,
    generation: u64,
    hosts: &[SavedHost],
    ssh_key_references: &[SavedSshKeyReference],
    managed_ssh_keys: &[SavedManagedSshKey],
    identity_references: &[SavedIdentityReference],
    password_identities: &[SavedPasswordIdentity],
    proxy_profiles: &[SavedProxyProfile],
) -> Result<String, StoreError> {
    let encoded = serde_json::to_vec(&ChecksumPayloadV5 {
        magic: SNAPSHOT_MAGIC,
        format_version: SNAPSHOT_FORMAT_V5,
        store_id,
        slot,
        generation,
        hosts,
        ssh_key_references,
        managed_ssh_keys,
        identity_references,
        password_identities,
        proxy_profiles,
    })
    .map_err(|_| StoreError::Serialization)?;
    let mut digest = Sha256::new();
    digest.update(b"netcatty-saved-host-snapshot-checksum-v5\0");
    digest.update((encoded.len() as u64).to_be_bytes());
    digest.update(&encoded);
    Ok(hex_encode(&digest.finalize()))
}

#[allow(clippy::too_many_arguments)]
fn snapshot_checksum_v6(
    store_id: &str,
    slot: Slot,
    generation: u64,
    hosts: &[SavedHost],
    ssh_key_references: &[SavedSshKeyReference],
    managed_ssh_keys: &[SavedManagedSshKey],
    identity_references: &[SavedIdentityReference],
    password_identities: &[SavedPasswordIdentity],
    proxy_profiles: &[SavedProxyProfile],
    groups: &[SavedGroupConfig],
) -> Result<String, StoreError> {
    let encoded = serde_json::to_vec(&ChecksumPayloadV6 {
        magic: SNAPSHOT_MAGIC,
        format_version: SNAPSHOT_FORMAT_V6,
        store_id,
        slot,
        generation,
        hosts,
        ssh_key_references,
        managed_ssh_keys,
        identity_references,
        password_identities,
        proxy_profiles,
        groups,
    })
    .map_err(|_| StoreError::Serialization)?;
    let mut digest = Sha256::new();
    digest.update(b"netcatty-saved-host-snapshot-checksum-v6\0");
    digest.update((encoded.len() as u64).to_be_bytes());
    digest.update(&encoded);
    Ok(hex_encode(&digest.finalize()))
}

#[allow(clippy::too_many_arguments)]
fn snapshot_checksum_v7(
    store_id: &str,
    slot: Slot,
    generation: u64,
    hosts: &[SavedHost],
    ssh_key_references: &[SavedSshKeyReference],
    managed_ssh_keys: &[SavedManagedSshKey],
    identity_references: &[SavedIdentityReference],
    password_identities: &[SavedPasswordIdentity],
    proxy_profiles: &[SavedProxyProfile],
    groups: &[SavedGroupConfig],
    notes_snippets: &SavedNotesSnippetsCatalog,
) -> Result<String, StoreError> {
    let encoded = serde_json::to_vec(&ChecksumPayloadV7 {
        magic: SNAPSHOT_MAGIC,
        format_version: SNAPSHOT_FORMAT_V7,
        store_id,
        slot,
        generation,
        hosts,
        ssh_key_references,
        managed_ssh_keys,
        identity_references,
        password_identities,
        proxy_profiles,
        groups,
        notes_snippets,
    })
    .map_err(|_| StoreError::Serialization)?;
    let mut digest = Sha256::new();
    digest.update(b"netcatty-saved-host-snapshot-checksum-v7\0");
    digest.update((encoded.len() as u64).to_be_bytes());
    digest.update(&encoded);
    Ok(hex_encode(&digest.finalize()))
}

#[allow(clippy::too_many_arguments)]
fn snapshot_checksum_v8(
    store_id: &str,
    slot: Slot,
    generation: u64,
    hosts: &[SavedHost],
    ssh_key_references: &[SavedSshKeyReference],
    managed_ssh_keys: &[SavedManagedSshKey],
    identity_references: &[SavedIdentityReference],
    password_identities: &[SavedPasswordIdentity],
    proxy_profiles: &[SavedProxyProfile],
    groups: &[SavedGroupConfig],
    notes_snippets: &SavedNotesSnippetsCatalog,
    port_forward_rules: &[SavedPortForwardRule],
) -> Result<String, StoreError> {
    let encoded = serde_json::to_vec(&ChecksumPayloadV8 {
        magic: SNAPSHOT_MAGIC,
        format_version: SNAPSHOT_FORMAT_V8,
        store_id,
        slot,
        generation,
        hosts,
        ssh_key_references,
        managed_ssh_keys,
        identity_references,
        password_identities,
        proxy_profiles,
        groups,
        notes_snippets,
        port_forward_rules,
    })
    .map_err(|_| StoreError::Serialization)?;
    let mut digest = Sha256::new();
    digest.update(b"netcatty-saved-host-snapshot-checksum-v8\0");
    digest.update((encoded.len() as u64).to_be_bytes());
    digest.update(&encoded);
    Ok(hex_encode(&digest.finalize()))
}

#[allow(clippy::too_many_arguments)]
fn snapshot_checksum_v9(
    store_id: &str,
    slot: Slot,
    generation: u64,
    hosts: &[SavedHost],
    ssh_key_references: &[SavedSshKeyReference],
    managed_ssh_keys: &[SavedManagedSshKey],
    identity_references: &[SavedIdentityReference],
    password_identities: &[SavedPasswordIdentity],
    proxy_profiles: &[SavedProxyProfile],
    groups: &[SavedGroupConfig],
    notes_snippets: &SavedNotesSnippetsCatalog,
    port_forward_rules: &[SavedPortForwardRule],
    known_hosts: &[SavedKnownHost],
) -> Result<String, StoreError> {
    let encoded = serde_json::to_vec(&ChecksumPayloadV9 {
        magic: SNAPSHOT_MAGIC,
        format_version: SNAPSHOT_FORMAT_V9,
        store_id,
        slot,
        generation,
        hosts,
        ssh_key_references,
        managed_ssh_keys,
        identity_references,
        password_identities,
        proxy_profiles,
        groups,
        notes_snippets,
        port_forward_rules,
        known_hosts,
    })
    .map_err(|_| StoreError::Serialization)?;
    let mut digest = Sha256::new();
    digest.update(b"netcatty-saved-host-snapshot-checksum-v9\0");
    digest.update((encoded.len() as u64).to_be_bytes());
    digest.update(&encoded);
    Ok(hex_encode(&digest.finalize()))
}

#[allow(clippy::too_many_arguments)]
fn snapshot_checksum_v10(
    store_id: &str,
    slot: Slot,
    generation: u64,
    hosts: &[SavedHost],
    ssh_key_references: &[SavedSshKeyReference],
    managed_ssh_keys: &[SavedManagedSshKey],
    identity_references: &[SavedIdentityReference],
    password_identities: &[SavedPasswordIdentity],
    proxy_profiles: &[SavedProxyProfile],
    groups: &[SavedGroupConfig],
    notes_snippets: &SavedNotesSnippetsCatalog,
    port_forward_rules: &[SavedPortForwardRule],
    known_hosts: &[SavedKnownHost],
    connection_logs: &[SavedConnectionLog],
) -> Result<String, StoreError> {
    let encoded = serde_json::to_vec(&ChecksumPayloadV10 {
        magic: SNAPSHOT_MAGIC,
        format_version: SNAPSHOT_FORMAT_V10,
        store_id,
        slot,
        generation,
        hosts,
        ssh_key_references,
        managed_ssh_keys,
        identity_references,
        password_identities,
        proxy_profiles,
        groups,
        notes_snippets,
        port_forward_rules,
        known_hosts,
        connection_logs,
    })
    .map_err(|_| StoreError::Serialization)?;
    let mut digest = Sha256::new();
    digest.update(b"netcatty-saved-host-snapshot-checksum-v10\0");
    digest.update((encoded.len() as u64).to_be_bytes());
    digest.update(&encoded);
    Ok(hex_encode(&digest.finalize()))
}

#[allow(clippy::too_many_arguments)]
fn snapshot_checksum_v11(
    store_id: &str,
    slot: Slot,
    generation: u64,
    hosts: &[SavedHost],
    ssh_key_references: &[SavedSshKeyReference],
    managed_ssh_keys: &[SavedManagedSshKey],
    identity_references: &[SavedIdentityReference],
    password_identities: &[SavedPasswordIdentity],
    proxy_profiles: &[SavedProxyProfile],
    groups: &[SavedGroupConfig],
    custom_groups: &SavedGroupCatalog,
    notes_snippets: &SavedNotesSnippetsCatalog,
    port_forward_rules: &[SavedPortForwardRule],
    known_hosts: &[SavedKnownHost],
    connection_logs: &[SavedConnectionLog],
) -> Result<String, StoreError> {
    let encoded = serde_json::to_vec(&ChecksumPayloadV11 {
        magic: SNAPSHOT_MAGIC,
        format_version: SNAPSHOT_FORMAT_V11,
        store_id,
        slot,
        generation,
        hosts,
        ssh_key_references,
        managed_ssh_keys,
        identity_references,
        password_identities,
        proxy_profiles,
        groups,
        custom_groups,
        notes_snippets,
        port_forward_rules,
        known_hosts,
        connection_logs,
    })
    .map_err(|_| StoreError::Serialization)?;
    let mut digest = Sha256::new();
    digest.update(b"netcatty-saved-host-snapshot-checksum-v11\0");
    digest.update((encoded.len() as u64).to_be_bytes());
    digest.update(&encoded);
    Ok(hex_encode(&digest.finalize()))
}

fn normalize_hosts(hosts: &mut [SavedHost]) -> Result<(), StoreError> {
    let mut ids = HashSet::with_capacity(hosts.len());
    for host in hosts.iter() {
        host.validate()?;
        if !ids.insert(host.id.clone()) {
            return Err(StoreError::DuplicateId(host.id.clone()));
        }
    }
    hosts.sort_by(SavedHost::stable_cmp);
    Ok(())
}

fn normalize_ssh_key_references(references: &mut [SavedSshKeyReference]) -> Result<(), StoreError> {
    let mut ids = HashSet::with_capacity(references.len());
    for reference in references.iter() {
        reference.validate()?;
        if !ids.insert(reference.id.clone()) {
            return Err(StoreError::DuplicateGraphEntityId(
                SavedVaultEntityKind::SshKeyReference,
            ));
        }
    }
    references.sort_by(SavedSshKeyReference::stable_cmp);
    Ok(())
}

fn normalize_managed_ssh_keys(
    managed_keys: &mut [SavedManagedSshKey],
    ssh_key_references: &[SavedSshKeyReference],
) -> Result<(), StoreError> {
    let reference_ids = ssh_key_references
        .iter()
        .map(|reference| &reference.id)
        .collect::<HashSet<_>>();
    let mut ids = HashSet::with_capacity(managed_keys.len());
    for managed_key in managed_keys.iter() {
        managed_key.validate()?;
        if reference_ids.contains(&managed_key.id) || !ids.insert(managed_key.id.clone()) {
            return Err(StoreError::DuplicateGraphEntityId(
                SavedVaultEntityKind::ManagedSshKey,
            ));
        }
    }
    managed_keys.sort_by(SavedManagedSshKey::stable_cmp);
    Ok(())
}

fn normalize_identity_references(
    references: &mut [SavedIdentityReference],
    ssh_key_references: &[SavedSshKeyReference],
    managed_ssh_keys: &[SavedManagedSshKey],
) -> Result<(), StoreError> {
    let reference_keys = ssh_key_references
        .iter()
        .map(|reference| (reference.id.as_str(), &reference.category))
        .collect::<HashMap<_, _>>();
    let managed_keys = managed_ssh_keys
        .iter()
        .map(|key| (key.id.as_str(), &key.category))
        .collect::<HashMap<_, _>>();
    let mut ids = HashSet::with_capacity(references.len());
    for reference in references.iter() {
        reference.validate()?;
        if !ids.insert(reference.id.clone()) {
            return Err(StoreError::DuplicateGraphEntityId(
                SavedVaultEntityKind::IdentityReference,
            ));
        }
        validate_identity_key_reference(reference, &reference_keys, &managed_keys)?;
    }
    references.sort_by(SavedIdentityReference::stable_cmp);
    Ok(())
}

fn normalize_password_identities(
    identities: &mut [SavedPasswordIdentity],
    identity_references: &[SavedIdentityReference],
) -> Result<(), StoreError> {
    let reference_ids = identity_references
        .iter()
        .map(|identity| identity.id.as_str())
        .collect::<HashSet<_>>();
    let mut ids = HashSet::with_capacity(identities.len());
    for identity in identities.iter() {
        identity.validate()?;
        if reference_ids.contains(identity.id.as_str()) || !ids.insert(identity.id.clone()) {
            return Err(StoreError::DuplicateGraphEntityId(
                SavedVaultEntityKind::PasswordIdentity,
            ));
        }
    }
    identities.sort_by(SavedPasswordIdentity::stable_cmp);
    Ok(())
}

fn normalize_proxy_profiles(profiles: &mut [SavedProxyProfile]) -> Result<(), StoreError> {
    let mut ids = HashSet::with_capacity(profiles.len());
    for profile in profiles.iter() {
        profile.validate()?;
        if !ids.insert(profile.id.clone()) {
            return Err(StoreError::DuplicateGraphEntityId(
                SavedVaultEntityKind::ProxyProfile,
            ));
        }
    }
    profiles.sort_by(SavedProxyProfile::stable_cmp);
    Ok(())
}

fn normalize_groups(groups: &mut [SavedGroupConfig]) -> Result<(), StoreError> {
    let mut ids = HashSet::with_capacity(groups.len());
    let mut paths = HashSet::with_capacity(groups.len());
    for group in groups.iter() {
        group.validate().map_err(|_| StoreError::Serialization)?;
        if !ids.insert(group.id.clone()) || !paths.insert(group.path.clone()) {
            return Err(StoreError::DuplicateGraphEntityId(
                SavedVaultEntityKind::Group,
            ));
        }
    }
    groups.sort_by(SavedGroupConfig::stable_cmp);
    Ok(())
}

fn normalize_port_forward_rules(
    rules: &mut [SavedPortForwardRule],
    hosts: &[SavedHost],
) -> Result<(), StoreError> {
    normalize_and_validate_port_forward_rules(rules, hosts).map_err(map_port_forward_rule_error)?;
    rules.sort_by(|left, right| {
        left.order
            .cmp(&right.order)
            .then_with(|| left.created_at.cmp(&right.created_at))
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(())
}

fn map_port_forward_rule_error(error: SavedPortForwardRuleError) -> StoreError {
    match error {
        SavedPortForwardRuleError::DuplicateRule => {
            StoreError::DuplicateGraphEntityId(SavedVaultEntityKind::PortForwardRule)
        }
        SavedPortForwardRuleError::HostUnavailable => StoreError::MissingGraphReference {
            source: SavedVaultEntityKind::PortForwardRule,
            target: SavedVaultEntityKind::Host,
        },
        SavedPortForwardRuleError::HostUnsupported => StoreError::IncompatibleGraphReference {
            source: SavedVaultEntityKind::PortForwardRule,
            target: SavedVaultEntityKind::Host,
        },
        SavedPortForwardRuleError::InvalidRule | SavedPortForwardRuleError::CatalogTooLarge => {
            StoreError::Serialization
        }
    }
}

fn normalize_loaded_store(loaded: &mut LoadedStore) -> Result<(), StoreError> {
    normalize_hosts(&mut loaded.hosts)?;
    normalize_ssh_key_references(&mut loaded.ssh_key_references)?;
    normalize_managed_ssh_keys(&mut loaded.managed_ssh_keys, &loaded.ssh_key_references)?;
    normalize_identity_references(
        &mut loaded.identity_references,
        &loaded.ssh_key_references,
        &loaded.managed_ssh_keys,
    )?;
    normalize_password_identities(&mut loaded.password_identities, &loaded.identity_references)?;
    normalize_proxy_profiles(&mut loaded.proxy_profiles)?;
    normalize_groups(&mut loaded.groups)?;
    normalize_port_forward_rules(&mut loaded.port_forward_rules, &loaded.hosts)?;
    validate_saved_known_hosts(&loaded.known_hosts).map_err(|_| StoreError::Serialization)?;
    normalize_connection_logs(&mut loaded.connection_logs)?;
    validate_host_graph_references(
        &loaded.hosts,
        &loaded.ssh_key_references,
        &loaded.managed_ssh_keys,
        &loaded.identity_references,
        &loaded.password_identities,
    )?;
    validate_proxy_graph_references(
        &loaded.hosts,
        &loaded.proxy_profiles,
        &loaded.identity_references,
        &loaded.password_identities,
    )?;
    validate_group_graph_references(
        &loaded.groups,
        &loaded.hosts,
        &loaded.ssh_key_references,
        &loaded.managed_ssh_keys,
        &loaded.identity_references,
        &loaded.password_identities,
        &loaded.proxy_profiles,
    )?;
    validate_notes_snippets_graph_references(&loaded.hosts, &loaded.groups, &loaded.notes_snippets)
}

fn normalize_connection_logs(logs: &mut [SavedConnectionLog]) -> Result<(), StoreError> {
    validate_saved_connection_logs(logs).map_err(|_| StoreError::Serialization)?;
    logs.sort_by(|left, right| {
        right
            .start_time
            .cmp(&left.start_time)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(())
}

/// Builds and normalizes a complete target graph without allowing any edge
/// to resolve through an entity that exists only in the current graph.
fn project_graph_replacement(
    current: &LoadedStore,
    replacement: SavedVaultGraph,
) -> Result<LoadedStore, StoreError> {
    validate_graph_candidates(&replacement)?;
    let empty = LoadedStore {
        generation: current.generation,
        max_seen_generation: current.max_seen_generation,
        snapshot_path: current.snapshot_path.clone(),
        hosts: Vec::new(),
        ssh_key_references: Vec::new(),
        managed_ssh_keys: Vec::new(),
        identity_references: Vec::new(),
        password_identities: Vec::new(),
        proxy_profiles: Vec::new(),
        groups: Vec::new(),
        custom_groups: None,
        notes_snippets: SavedNotesSnippetsCatalog::default(),
        port_forward_rules: Vec::new(),
        known_hosts: Vec::new(),
        connection_logs: Vec::new(),
    };
    validate_candidate_graph_references(&replacement, &empty)?;
    let (
        hosts,
        ssh_key_references,
        managed_ssh_keys,
        identity_references,
        password_identities,
        proxy_profiles,
        groups,
        custom_groups,
        notes_snippets,
        port_forward_rules,
    ) = replacement.into_current_parts();
    let mut projected = LoadedStore {
        generation: current.generation,
        max_seen_generation: current.max_seen_generation,
        snapshot_path: current.snapshot_path.clone(),
        hosts,
        ssh_key_references,
        managed_ssh_keys,
        identity_references,
        password_identities,
        proxy_profiles,
        groups,
        custom_groups,
        notes_snippets,
        port_forward_rules,
        known_hosts: current.known_hosts.clone(),
        connection_logs: current.connection_logs.clone(),
    };
    normalize_loaded_store(&mut projected)?;
    Ok(projected)
}

fn verify_inventory_revision(
    loaded: &LoadedStore,
    store_id: &str,
    expected_revision: SavedVaultInventoryRevision,
) -> Result<SavedVaultInventoryRevision, StoreError> {
    let actual_revision = loaded.inventory_revision(store_id);
    if expected_revision != actual_revision {
        return Err(StoreError::InventoryRevisionConflict {
            expected: expected_revision,
            actual: actual_revision,
        });
    }
    Ok(actual_revision)
}

/// Applies the exact validation, merge, conflict, duplicate, and
/// normalization semantics shared by graph planning and publication.
fn apply_graph_import(
    loaded: &mut LoadedStore,
    candidates: SavedVaultGraph,
) -> Result<SavedVaultGraph, StoreError> {
    validate_graph_candidates(&candidates)?;
    validate_candidate_graph_references(&candidates, loaded)?;

    let mut imported = SavedVaultGraph::default();
    for candidate in candidates.ssh_key_references {
        if loaded
            .managed_ssh_keys
            .iter()
            .any(|managed| managed.id == candidate.id)
        {
            return Err(StoreError::GraphImportConflict(
                SavedVaultEntityKind::SshKeyReference,
            ));
        }
        match loaded
            .ssh_key_references
            .iter()
            .find(|reference| reference.id == candidate.id)
        {
            Some(current) if ssh_key_business_fields_equal(current, &candidate) => continue,
            Some(_) => {
                return Err(StoreError::GraphImportConflict(
                    SavedVaultEntityKind::SshKeyReference,
                ));
            }
            None => {
                loaded.ssh_key_references.push(candidate.clone());
                imported.ssh_key_references.push(candidate);
            }
        }
    }
    for candidate in candidates.managed_ssh_keys {
        if loaded
            .ssh_key_references
            .iter()
            .any(|reference| reference.id == candidate.id)
        {
            return Err(StoreError::GraphImportConflict(
                SavedVaultEntityKind::ManagedSshKey,
            ));
        }
        match loaded
            .managed_ssh_keys
            .iter()
            .find(|managed| managed.id == candidate.id)
        {
            Some(current) if managed_key_business_fields_equal(current, &candidate) => continue,
            Some(_) => {
                return Err(StoreError::GraphImportConflict(
                    SavedVaultEntityKind::ManagedSshKey,
                ));
            }
            None => {
                loaded.managed_ssh_keys.push(candidate.clone());
                imported.managed_ssh_keys.push(candidate);
            }
        }
    }
    for candidate in candidates.identity_references {
        if loaded
            .password_identities
            .iter()
            .any(|identity| identity.id.as_str() == candidate.id.as_str())
        {
            return Err(StoreError::GraphImportConflict(
                SavedVaultEntityKind::IdentityReference,
            ));
        }
        match loaded
            .identity_references
            .iter()
            .find(|reference| reference.id == candidate.id)
        {
            Some(current) if identity_business_fields_equal(current, &candidate) => continue,
            Some(_) => {
                return Err(StoreError::GraphImportConflict(
                    SavedVaultEntityKind::IdentityReference,
                ));
            }
            None => {
                loaded.identity_references.push(candidate.clone());
                imported.identity_references.push(candidate);
            }
        }
    }
    for candidate in candidates.password_identities {
        if loaded
            .identity_references
            .iter()
            .any(|identity| identity.id.as_str() == candidate.id.as_str())
        {
            return Err(StoreError::GraphImportConflict(
                SavedVaultEntityKind::PasswordIdentity,
            ));
        }
        match loaded
            .password_identities
            .iter()
            .find(|identity| identity.id == candidate.id)
        {
            Some(current) if password_identity_business_fields_equal(current, &candidate) => {
                continue;
            }
            Some(_) => {
                return Err(StoreError::GraphImportConflict(
                    SavedVaultEntityKind::PasswordIdentity,
                ));
            }
            None => {
                loaded.password_identities.push(candidate.clone());
                imported.password_identities.push(candidate);
            }
        }
    }
    for candidate in candidates.proxy_profiles {
        match loaded
            .proxy_profiles
            .iter()
            .find(|profile| profile.id == candidate.id)
        {
            Some(current) if proxy_profile_business_fields_equal(current, &candidate) => continue,
            Some(_) => {
                return Err(StoreError::GraphImportConflict(
                    SavedVaultEntityKind::ProxyProfile,
                ));
            }
            None => {
                loaded.proxy_profiles.push(candidate.clone());
                imported.proxy_profiles.push(candidate);
            }
        }
    }
    for candidate in candidates.groups {
        if loaded
            .groups
            .iter()
            .any(|group| group.path == candidate.path && group.id != candidate.id)
        {
            return Err(StoreError::GraphImportConflict(SavedVaultEntityKind::Group));
        }
        match loaded.groups.iter().find(|group| group.id == candidate.id) {
            Some(current) if group_business_fields_equal(current, &candidate) => continue,
            Some(_) => {
                return Err(StoreError::GraphImportConflict(SavedVaultEntityKind::Group));
            }
            None => {
                loaded.groups.push(candidate.clone());
                imported.groups.push(candidate);
            }
        }
    }
    for candidate in candidates.hosts {
        match loaded.hosts.iter().find(|host| host.id == candidate.id) {
            Some(current) if import_business_fields_equal(current, &candidate) => continue,
            Some(_) => return Err(StoreError::GraphImportConflict(SavedVaultEntityKind::Host)),
            None => {
                loaded.hosts.push(candidate.clone());
                imported.hosts.push(candidate);
            }
        }
    }

    for candidate in candidates.port_forward_rules {
        match loaded
            .port_forward_rules
            .iter()
            .find(|rule| rule.id == candidate.id)
        {
            Some(current) if current == &candidate => continue,
            Some(_) => {
                return Err(StoreError::GraphImportConflict(
                    SavedVaultEntityKind::PortForwardRule,
                ));
            }
            None => {
                loaded.port_forward_rules.push(candidate.clone());
                imported.port_forward_rules.push(candidate);
            }
        }
    }

    imported.custom_groups =
        merge_custom_group_import(&mut loaded.custom_groups, candidates.custom_groups)?;
    imported.notes_snippets =
        merge_notes_snippets_import(&mut loaded.notes_snippets, candidates.notes_snippets)?;

    if !imported.is_empty() {
        normalize_loaded_store(loaded)?;
    }
    Ok(imported)
}

fn merge_custom_group_import(
    current: &mut Option<SavedGroupCatalog>,
    candidates: Option<SavedGroupCatalog>,
) -> Result<Option<SavedGroupCatalog>, StoreError> {
    let Some(candidates) = candidates else {
        return Ok(None);
    };
    match current {
        None => {
            *current = Some(candidates.clone());
            Ok(Some(candidates))
        }
        Some(existing) => {
            let mut imported = SavedGroupCatalog::new();
            for path in candidates.explicit_paths() {
                if existing
                    .insert_path(path.clone())
                    .map_err(|_| StoreError::Serialization)?
                {
                    imported
                        .insert_path(path.clone())
                        .map_err(|_| StoreError::Serialization)?;
                }
            }
            Ok((!imported.is_empty()).then_some(imported))
        }
    }
}

fn merge_notes_snippets_import(
    current: &mut SavedNotesSnippetsCatalog,
    candidates: SavedNotesSnippetsCatalog,
) -> Result<SavedNotesSnippetsCatalog, StoreError> {
    let (mut snippets, mut snippet_packages, mut notes, mut note_groups) =
        std::mem::take(current).into_parts();
    let (candidate_snippets, candidate_snippet_packages, candidate_notes, candidate_note_groups) =
        candidates.into_parts();

    let mut imported_snippets = None;
    if let Some(candidates) = candidate_snippets {
        match &mut snippets {
            None => {
                imported_snippets = Some(candidates.clone());
                snippets = Some(candidates);
            }
            Some(existing) => {
                let mut additions = Vec::new();
                for candidate in candidates {
                    match existing
                        .iter()
                        .find(|snippet| snippet.id() == candidate.id())
                    {
                        Some(current) if current == &candidate => {}
                        Some(_) => {
                            return Err(StoreError::GraphImportConflict(
                                SavedVaultEntityKind::Snippet,
                            ));
                        }
                        None => {
                            existing.push(candidate.clone());
                            additions.push(candidate);
                        }
                    }
                }
                if !additions.is_empty() {
                    imported_snippets = Some(additions);
                }
            }
        }
    }

    let mut imported_notes = None;
    if let Some(candidates) = candidate_notes {
        match &mut notes {
            None => {
                imported_notes = Some(candidates.clone());
                notes = Some(candidates);
            }
            Some(existing) => {
                let mut additions = Vec::new();
                for candidate in candidates {
                    match existing.iter().find(|note| note.id() == candidate.id()) {
                        Some(current) if current == &candidate => {}
                        Some(_) => {
                            return Err(StoreError::GraphImportConflict(
                                SavedVaultEntityKind::Note,
                            ));
                        }
                        None => {
                            existing.push(candidate.clone());
                            additions.push(candidate);
                        }
                    }
                }
                if !additions.is_empty() {
                    imported_notes = Some(additions);
                }
            }
        }
    }

    let imported_snippet_packages =
        merge_plain_catalog_import(&mut snippet_packages, candidate_snippet_packages);
    let imported_note_groups = merge_plain_catalog_import(&mut note_groups, candidate_note_groups);

    *current = SavedNotesSnippetsCatalog::from_normalized_parts(
        snippets,
        snippet_packages,
        notes,
        note_groups,
    )
    .map_err(|_| StoreError::Serialization)?;
    SavedNotesSnippetsCatalog::from_normalized_parts(
        imported_snippets,
        imported_snippet_packages,
        imported_notes,
        imported_note_groups,
    )
    .map_err(|_| StoreError::Serialization)
}

fn merge_plain_catalog_import<T: Clone + Ord>(
    current: &mut Option<Vec<T>>,
    candidates: Option<Vec<T>>,
) -> Option<Vec<T>> {
    let candidates = candidates?;
    match current {
        None => {
            *current = Some(candidates.clone());
            Some(candidates)
        }
        Some(existing) => {
            let mut seen = existing.iter().cloned().collect::<BTreeSet<_>>();
            let additions = candidates
                .into_iter()
                .filter(|candidate| seen.insert(candidate.clone()))
                .collect::<Vec<_>>();
            if additions.is_empty() {
                None
            } else {
                existing.extend(additions.iter().cloned());
                Some(additions)
            }
        }
    }
}

fn validate_import_candidates(candidates: &[SavedHost]) -> Result<(), StoreError> {
    let mut ids = HashSet::with_capacity(candidates.len());
    for candidate in candidates {
        candidate.validate()?;
        if !ids.insert(candidate.id.clone()) {
            return Err(StoreError::DuplicateId(candidate.id.clone()));
        }
    }
    Ok(())
}

fn validate_graph_candidates(candidates: &SavedVaultGraph) -> Result<(), StoreError> {
    let mut host_ids = HashSet::with_capacity(candidates.hosts.len());
    for host in &candidates.hosts {
        host.validate()?;
        if !host_ids.insert(host.id.clone()) {
            return Err(StoreError::DuplicateGraphEntityId(
                SavedVaultEntityKind::Host,
            ));
        }
    }

    let mut key_ids = HashSet::with_capacity(
        candidates.ssh_key_references.len() + candidates.managed_ssh_keys.len(),
    );
    for reference in &candidates.ssh_key_references {
        reference.validate()?;
        if !key_ids.insert(reference.id.clone()) {
            return Err(StoreError::DuplicateGraphEntityId(
                SavedVaultEntityKind::SshKeyReference,
            ));
        }
    }

    for managed_key in &candidates.managed_ssh_keys {
        managed_key.validate()?;
        if !key_ids.insert(managed_key.id.clone()) {
            return Err(StoreError::DuplicateGraphEntityId(
                SavedVaultEntityKind::ManagedSshKey,
            ));
        }
    }

    let mut identity_ids = HashSet::with_capacity(
        candidates.identity_references.len() + candidates.password_identities.len(),
    );
    for reference in &candidates.identity_references {
        reference.validate()?;
        if !identity_ids.insert(reference.id.as_str()) {
            return Err(StoreError::DuplicateGraphEntityId(
                SavedVaultEntityKind::IdentityReference,
            ));
        }
    }
    for identity in &candidates.password_identities {
        identity.validate()?;
        if !identity_ids.insert(identity.id.as_str()) {
            return Err(StoreError::DuplicateGraphEntityId(
                SavedVaultEntityKind::PasswordIdentity,
            ));
        }
    }
    let mut proxy_profile_ids = HashSet::with_capacity(candidates.proxy_profiles.len());
    for profile in &candidates.proxy_profiles {
        profile.validate()?;
        if !proxy_profile_ids.insert(profile.id.as_str()) {
            return Err(StoreError::DuplicateGraphEntityId(
                SavedVaultEntityKind::ProxyProfile,
            ));
        }
    }
    let mut group_ids = HashSet::with_capacity(candidates.groups.len());
    let mut group_paths = HashSet::with_capacity(candidates.groups.len());
    for group in &candidates.groups {
        group.validate().map_err(|_| StoreError::Serialization)?;
        if !group_ids.insert(group.id.clone()) || !group_paths.insert(group.path.clone()) {
            return Err(StoreError::DuplicateGraphEntityId(
                SavedVaultEntityKind::Group,
            ));
        }
    }
    Ok(())
}

fn validate_candidate_graph_references(
    candidates: &SavedVaultGraph,
    loaded: &LoadedStore,
) -> Result<(), StoreError> {
    let mut reference_categories = HashMap::new();
    for reference in &loaded.ssh_key_references {
        reference_categories.insert(reference.id.as_str(), &reference.category);
    }
    for reference in &candidates.ssh_key_references {
        reference_categories.insert(reference.id.as_str(), &reference.category);
    }
    let mut managed_categories = HashMap::new();
    for managed_key in &loaded.managed_ssh_keys {
        managed_categories.insert(managed_key.id.as_str(), &managed_key.category);
    }
    for managed_key in &candidates.managed_ssh_keys {
        managed_categories.insert(managed_key.id.as_str(), &managed_key.category);
    }
    let mut identities = HashMap::new();
    for identity in &loaded.identity_references {
        identities.insert(identity.id.as_str(), identity);
    }
    for identity in &candidates.identity_references {
        identities.insert(identity.id.as_str(), identity);
    }
    let mut password_identities = HashMap::new();
    for identity in &loaded.password_identities {
        password_identities.insert(identity.id.as_str(), identity);
    }
    for identity in &candidates.password_identities {
        password_identities.insert(identity.id.as_str(), identity);
    }
    let mut proxy_profiles = HashMap::new();
    for profile in &loaded.proxy_profiles {
        proxy_profiles.insert(profile.id.as_str(), profile);
    }
    for profile in &candidates.proxy_profiles {
        proxy_profiles.insert(profile.id.as_str(), profile);
    }

    for reference in &candidates.identity_references {
        validate_identity_key_reference(reference, &reference_categories, &managed_categories)?;
    }
    for profile in &candidates.proxy_profiles {
        validate_proxy_config_reference(
            &profile.config,
            SavedVaultEntityKind::ProxyProfile,
            &identities,
            &password_identities,
        )?;
    }
    for host in &candidates.hosts {
        validate_host_graph_reference(
            host,
            &reference_categories,
            &managed_categories,
            &identities,
            &password_identities,
        )?;
        validate_host_proxy_reference(host, &proxy_profiles, &identities, &password_identities)?;
    }
    for group in &candidates.groups {
        validate_group_graph_reference(
            group,
            &candidates
                .hosts
                .iter()
                .chain(&loaded.hosts)
                .map(|host| host.id.as_str())
                .collect(),
            &reference_categories,
            &managed_categories,
            &identities,
            &password_identities,
            &proxy_profiles,
        )?;
    }
    let final_hosts = loaded
        .hosts
        .iter()
        .chain(&candidates.hosts)
        .cloned()
        .collect::<Vec<_>>();
    let mut port_forward_rules = candidates.port_forward_rules.clone();
    normalize_port_forward_rules(&mut port_forward_rules, &final_hosts)?;
    validate_candidate_notes_snippets_references(candidates, loaded)?;
    Ok(())
}

fn validate_candidate_notes_snippets_references(
    candidates: &SavedVaultGraph,
    loaded: &LoadedStore,
) -> Result<(), StoreError> {
    let final_host_ids = loaded
        .hosts
        .iter()
        .chain(&candidates.hosts)
        .map(|host| host.id.clone())
        .collect::<BTreeSet<_>>();
    candidates
        .notes_snippets
        .validate_host_references(&final_host_ids)
        .map_err(map_notes_snippets_reference_error)?;

    let loaded_snippets = loaded.notes_snippets.snippets();
    let candidate_snippets = candidates.notes_snippets.snippets();
    if loaded_snippets.is_none() && candidate_snippets.is_none() {
        return Ok(());
    }

    let mut scripts = HashMap::new();
    for snippet in loaded_snippets.unwrap_or_default() {
        scripts.insert(snippet.id().as_str(), snippet.kind());
    }
    for snippet in candidate_snippets.unwrap_or_default() {
        scripts
            .entry(snippet.id().as_str())
            .or_insert(snippet.kind());
    }

    if candidate_snippets.is_some() {
        for host in loaded.hosts.iter().chain(&candidates.hosts) {
            validate_host_script_references(host, &scripts)?;
        }
        for group in loaded.groups.iter().chain(&candidates.groups) {
            validate_group_script_reference(group, &scripts)?;
        }
    } else {
        for host in &candidates.hosts {
            validate_host_script_references(host, &scripts)?;
        }
        for group in &candidates.groups {
            validate_group_script_reference(group, &scripts)?;
        }
    }
    Ok(())
}

fn validate_notes_snippets_graph_references(
    hosts: &[SavedHost],
    groups: &[SavedGroupConfig],
    catalog: &SavedNotesSnippetsCatalog,
) -> Result<(), StoreError> {
    let host_ids = hosts
        .iter()
        .map(|host| host.id.clone())
        .collect::<BTreeSet<_>>();
    catalog
        .validate_host_references(&host_ids)
        .map_err(map_notes_snippets_reference_error)?;

    let Some(snippets) = catalog.snippets() else {
        return Ok(());
    };
    let scripts = snippets
        .iter()
        .map(|snippet| (snippet.id().as_str(), snippet.kind()))
        .collect::<HashMap<_, _>>();
    for host in hosts {
        validate_host_script_references(host, &scripts)?;
    }
    for group in groups {
        validate_group_script_reference(group, &scripts)?;
    }
    Ok(())
}

fn map_notes_snippets_reference_error(error: SavedNotesSnippetsError) -> StoreError {
    match error {
        SavedNotesSnippetsError::MissingHostReference { kind, .. } => {
            StoreError::MissingGraphReference {
                source: match kind {
                    SavedHostReferenceKind::SnippetTarget => SavedVaultEntityKind::Snippet,
                    SavedHostReferenceKind::NoteLinkedHost => SavedVaultEntityKind::Note,
                },
                target: SavedVaultEntityKind::Host,
            }
        }
        _ => StoreError::Serialization,
    }
}

fn validate_host_script_references(
    host: &SavedHost,
    scripts: &HashMap<&str, Option<SavedSnippetKind>>,
) -> Result<(), StoreError> {
    let fields = host.compatibility_fields();
    if let Some(value) = fields.get("loginScriptId") {
        match value {
            Value::Null => {}
            Value::String(id) if id.is_empty() => {}
            Value::String(id) => validate_script_reference(id, scripts)?,
            _ => return Err(missing_host_snippet_reference()),
        }
    }
    if let Some(value) = fields.get("connectScriptIds") {
        match value {
            Value::Null => {}
            Value::Array(values) => {
                for value in values {
                    let Value::String(id) = value else {
                        return Err(missing_host_snippet_reference());
                    };
                    if id.is_empty() {
                        return Err(missing_host_snippet_reference());
                    }
                    validate_script_reference(id, scripts)?;
                }
            }
            _ => return Err(missing_host_snippet_reference()),
        }
    }
    if let Some(value) = fields.get("outputTriggers") {
        match value {
            Value::Null => {}
            Value::Array(values) => {
                for value in values {
                    let Value::Object(trigger) = value else {
                        return Err(missing_host_snippet_reference());
                    };
                    let Some(Value::String(id)) = trigger.get("scriptId") else {
                        return Err(missing_host_snippet_reference());
                    };
                    if id.is_empty() {
                        return Err(missing_host_snippet_reference());
                    }
                    validate_script_reference(id, scripts)?;
                }
            }
            _ => return Err(missing_host_snippet_reference()),
        }
    }
    Ok(())
}

fn validate_group_script_reference(
    group: &SavedGroupConfig,
    scripts: &HashMap<&str, Option<SavedSnippetKind>>,
) -> Result<(), StoreError> {
    if let SavedGroupOverride::Set(id) = &group.defaults.login_script_id {
        match scripts.get(id.as_str()) {
            None => return Err(missing_group_snippet_reference()),
            Some(Some(SavedSnippetKind::Script)) => {}
            Some(_) => {
                return Err(StoreError::IncompatibleGraphReference {
                    source: SavedVaultEntityKind::Group,
                    target: SavedVaultEntityKind::Snippet,
                });
            }
        }
    }
    Ok(())
}

fn validate_script_reference(
    id: &str,
    scripts: &HashMap<&str, Option<SavedSnippetKind>>,
) -> Result<(), StoreError> {
    match scripts.get(id) {
        None => Err(missing_host_snippet_reference()),
        Some(Some(SavedSnippetKind::Script)) => Ok(()),
        Some(_) => Err(StoreError::IncompatibleGraphReference {
            source: SavedVaultEntityKind::Host,
            target: SavedVaultEntityKind::Snippet,
        }),
    }
}

fn missing_host_snippet_reference() -> StoreError {
    StoreError::MissingGraphReference {
        source: SavedVaultEntityKind::Host,
        target: SavedVaultEntityKind::Snippet,
    }
}

fn missing_group_snippet_reference() -> StoreError {
    StoreError::MissingGraphReference {
        source: SavedVaultEntityKind::Group,
        target: SavedVaultEntityKind::Snippet,
    }
}

fn validate_identity_key_reference(
    identity: &SavedIdentityReference,
    reference_categories: &HashMap<&str, &SavedSshKeyCategory>,
    managed_categories: &HashMap<&str, &SavedSshKeyCategory>,
) -> Result<(), StoreError> {
    let key_id = identity.key_id.as_str();
    if identity.auth_method.is_certificate() {
        if let Some(category) = managed_categories.get(key_id) {
            return if category.is_certificate() {
                Ok(())
            } else {
                Err(StoreError::IncompatibleGraphReference {
                    source: SavedVaultEntityKind::IdentityReference,
                    target: SavedVaultEntityKind::ManagedSshKey,
                })
            };
        }
        if reference_categories.contains_key(key_id) {
            return Err(StoreError::IncompatibleGraphReference {
                source: SavedVaultEntityKind::IdentityReference,
                target: SavedVaultEntityKind::SshKeyReference,
            });
        }
        return Err(StoreError::MissingGraphReference {
            source: SavedVaultEntityKind::IdentityReference,
            target: SavedVaultEntityKind::ManagedSshKey,
        });
    }

    if let Some(category) = reference_categories.get(key_id) {
        return if category.is_certificate() {
            Err(StoreError::IncompatibleGraphReference {
                source: SavedVaultEntityKind::IdentityReference,
                target: SavedVaultEntityKind::SshKeyReference,
            })
        } else {
            // Version-2 reference records allowed extension categories. They
            // still require a fresh file selection and remain key-capable,
            // except for the explicit certificate category.
            Ok(())
        };
    }
    if let Some(category) = managed_categories.get(key_id) {
        return if category.is_private_key_material() {
            Ok(())
        } else {
            Err(StoreError::IncompatibleGraphReference {
                source: SavedVaultEntityKind::IdentityReference,
                target: SavedVaultEntityKind::ManagedSshKey,
            })
        };
    }
    Err(StoreError::MissingGraphReference {
        source: SavedVaultEntityKind::IdentityReference,
        target: SavedVaultEntityKind::SshKeyReference,
    })
}

fn validate_host_graph_references(
    hosts: &[SavedHost],
    ssh_key_references: &[SavedSshKeyReference],
    managed_ssh_keys: &[SavedManagedSshKey],
    identity_references: &[SavedIdentityReference],
    password_identities: &[SavedPasswordIdentity],
) -> Result<(), StoreError> {
    let reference_categories = ssh_key_references
        .iter()
        .map(|reference| (reference.id.as_str(), &reference.category))
        .collect::<HashMap<_, _>>();
    let managed_categories = managed_ssh_keys
        .iter()
        .map(|key| (key.id.as_str(), &key.category))
        .collect::<HashMap<_, _>>();
    let identities = identity_references
        .iter()
        .map(|identity| (identity.id.as_str(), identity))
        .collect::<HashMap<_, _>>();
    let password_identities = password_identities
        .iter()
        .map(|identity| (identity.id.as_str(), identity))
        .collect::<HashMap<_, _>>();
    for host in hosts {
        validate_host_graph_reference(
            host,
            &reference_categories,
            &managed_categories,
            &identities,
            &password_identities,
        )?;
    }
    Ok(())
}

fn validate_host_graph_reference(
    host: &SavedHost,
    reference_categories: &HashMap<&str, &SavedSshKeyCategory>,
    managed_categories: &HashMap<&str, &SavedSshKeyCategory>,
    identities: &HashMap<&str, &SavedIdentityReference>,
    password_identities: &HashMap<&str, &SavedPasswordIdentity>,
) -> Result<(), StoreError> {
    // Serial keeps the legacy flattened host record for round-trip
    // compatibility, but none of the SSH or Telnet identity/key edges are
    // active while Serial is the primary protocol.
    if host.protocol.is_serial() {
        return Ok(());
    }
    // Telnet shares the flattened legacy host record. Its own reusable
    // password identity is a live graph edge, while dormant SSH identity and
    // key fields remain round-trippable until the record switches back.
    if host.protocol.is_telnet() {
        if let Some(identity_id) = host_catalog_reference(host, "telnetIdentityId")? {
            if password_identities.contains_key(identity_id) {
                return Ok(());
            }
            return Err(if identities.contains_key(identity_id) {
                StoreError::IncompatibleGraphReference {
                    source: SavedVaultEntityKind::Host,
                    target: SavedVaultEntityKind::PasswordIdentity,
                }
            } else {
                StoreError::MissingGraphReference {
                    source: SavedVaultEntityKind::Host,
                    target: SavedVaultEntityKind::PasswordIdentity,
                }
            });
        }
        return Ok(());
    }

    let auth_method = host.auth_method.as_str();
    let is_password = auth_method.eq_ignore_ascii_case("password");
    let is_key = auth_method.eq_ignore_ascii_case("key");
    let is_certificate = auth_method.eq_ignore_ascii_case("certificate");
    let direct_key_id = host_catalog_reference(host, "identityFileId")?;
    let identity_id = host_catalog_reference(host, "identityId")?;

    if let Some(key_id) = direct_key_id {
        if is_password {
            return Err(StoreError::IncompatibleGraphReference {
                source: SavedVaultEntityKind::Host,
                target: SavedVaultEntityKind::SshKeyReference,
            });
        }
        if is_key {
            if let Some(category) = reference_categories.get(key_id) {
                if category.is_certificate() {
                    return Err(StoreError::IncompatibleGraphReference {
                        source: SavedVaultEntityKind::Host,
                        target: SavedVaultEntityKind::SshKeyReference,
                    });
                }
            } else if let Some(category) = managed_categories.get(key_id) {
                if !category.is_private_key_material() {
                    return Err(StoreError::IncompatibleGraphReference {
                        source: SavedVaultEntityKind::Host,
                        target: SavedVaultEntityKind::ManagedSshKey,
                    });
                }
            } else {
                return Err(StoreError::MissingGraphReference {
                    source: SavedVaultEntityKind::Host,
                    target: SavedVaultEntityKind::SshKeyReference,
                });
            }
        } else if is_certificate {
            if let Some(category) = managed_categories.get(key_id) {
                if !category.is_certificate() {
                    return Err(StoreError::IncompatibleGraphReference {
                        source: SavedVaultEntityKind::Host,
                        target: SavedVaultEntityKind::ManagedSshKey,
                    });
                }
            } else if reference_categories.contains_key(key_id) {
                return Err(StoreError::IncompatibleGraphReference {
                    source: SavedVaultEntityKind::Host,
                    target: SavedVaultEntityKind::SshKeyReference,
                });
            } else {
                return Err(StoreError::MissingGraphReference {
                    source: SavedVaultEntityKind::Host,
                    target: SavedVaultEntityKind::ManagedSshKey,
                });
            }
        } else if !reference_categories.contains_key(key_id)
            && !managed_categories.contains_key(key_id)
        {
            return Err(StoreError::MissingGraphReference {
                source: SavedVaultEntityKind::Host,
                target: SavedVaultEntityKind::SshKeyReference,
            });
        }
    }

    if let Some(identity_id) = identity_id {
        if is_password {
            if password_identities.contains_key(identity_id) {
                // The catalog itself fixes the authentication kind; there is
                // no key edge to validate for a password identity.
            } else if identities.contains_key(identity_id) {
                return Err(StoreError::IncompatibleGraphReference {
                    source: SavedVaultEntityKind::Host,
                    target: SavedVaultEntityKind::IdentityReference,
                });
            } else {
                return Err(StoreError::MissingGraphReference {
                    source: SavedVaultEntityKind::Host,
                    target: SavedVaultEntityKind::PasswordIdentity,
                });
            }
        } else {
            let identity = if let Some(identity) = identities.get(identity_id) {
                identity
            } else if password_identities.contains_key(identity_id) {
                return Err(StoreError::IncompatibleGraphReference {
                    source: SavedVaultEntityKind::Host,
                    target: SavedVaultEntityKind::PasswordIdentity,
                });
            } else {
                return Err(StoreError::MissingGraphReference {
                    source: SavedVaultEntityKind::Host,
                    target: SavedVaultEntityKind::IdentityReference,
                });
            };
            if direct_key_id.is_some_and(|key_id| key_id != identity.key_id.as_str()) {
                return Err(StoreError::IncompatibleGraphReference {
                    source: SavedVaultEntityKind::Host,
                    target: SavedVaultEntityKind::IdentityReference,
                });
            }
            if (!is_key && !is_certificate)
                || (is_key && !identity.auth_method.is_key())
                || (is_certificate && !identity.auth_method.is_certificate())
            {
                return Err(StoreError::IncompatibleGraphReference {
                    source: SavedVaultEntityKind::Host,
                    target: SavedVaultEntityKind::IdentityReference,
                });
            }
        }
    }
    Ok(())
}

fn validate_proxy_graph_references(
    hosts: &[SavedHost],
    proxy_profiles: &[SavedProxyProfile],
    identity_references: &[SavedIdentityReference],
    password_identities: &[SavedPasswordIdentity],
) -> Result<(), StoreError> {
    let profiles = proxy_profiles
        .iter()
        .map(|profile| (profile.id.as_str(), profile))
        .collect::<HashMap<_, _>>();
    let key_identities = identity_references
        .iter()
        .map(|identity| (identity.id.as_str(), identity))
        .collect::<HashMap<_, _>>();
    let password_identities = password_identities
        .iter()
        .map(|identity| (identity.id.as_str(), identity))
        .collect::<HashMap<_, _>>();
    for profile in proxy_profiles {
        validate_proxy_config_reference(
            &profile.config,
            SavedVaultEntityKind::ProxyProfile,
            &key_identities,
            &password_identities,
        )?;
    }
    for host in hosts {
        validate_host_proxy_reference(host, &profiles, &key_identities, &password_identities)?;
    }
    Ok(())
}

fn validate_host_proxy_reference(
    host: &SavedHost,
    profiles: &HashMap<&str, &SavedProxyProfile>,
    key_identities: &HashMap<&str, &SavedIdentityReference>,
    password_identities: &HashMap<&str, &SavedPasswordIdentity>,
) -> Result<(), StoreError> {
    // A primary Telnet record does not use the SSH proxy relationship. Keep
    // legacy flattened fields intact, but do not require their targets while
    // the host remains Telnet.
    if host.protocol.is_telnet() || host.protocol.is_serial() {
        return Ok(());
    }

    // A non-null inline value has absolute precedence. It is parsed before
    // looking at the shadowed profile field, so invalid inline data fails
    // closed and a missing shadowed profile remains harmless and preserved.
    if host
        .compatibility_fields()
        .get("proxyConfig")
        .is_some_and(|value| !value.is_null())
    {
        let config = host
            .proxy_config()?
            .ok_or(ValidationError::InvalidProxyConfig)?;
        return validate_proxy_config_reference(
            &config,
            SavedVaultEntityKind::Host,
            key_identities,
            password_identities,
        );
    }

    let Some(profile_id) = host.proxy_profile_id()? else {
        return Ok(());
    };
    if profiles.contains_key(profile_id.as_str()) {
        Ok(())
    } else {
        Err(StoreError::MissingGraphReference {
            source: SavedVaultEntityKind::Host,
            target: SavedVaultEntityKind::ProxyProfile,
        })
    }
}

fn validate_proxy_config_reference(
    config: &SavedProxyConfig,
    source: SavedVaultEntityKind,
    key_identities: &HashMap<&str, &SavedIdentityReference>,
    password_identities: &HashMap<&str, &SavedPasswordIdentity>,
) -> Result<(), StoreError> {
    config.validate()?;
    let Some(identity_id) = config.identity_id() else {
        return Ok(());
    };
    if password_identities.contains_key(identity_id.as_str()) {
        Ok(())
    } else if key_identities.contains_key(identity_id.as_str()) {
        Err(StoreError::IncompatibleGraphReference {
            source,
            target: SavedVaultEntityKind::IdentityReference,
        })
    } else {
        Err(StoreError::MissingGraphReference {
            source,
            target: SavedVaultEntityKind::PasswordIdentity,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_group_graph_references(
    groups: &[SavedGroupConfig],
    hosts: &[SavedHost],
    ssh_key_references: &[SavedSshKeyReference],
    managed_ssh_keys: &[SavedManagedSshKey],
    identity_references: &[SavedIdentityReference],
    password_identities: &[SavedPasswordIdentity],
    proxy_profiles: &[SavedProxyProfile],
) -> Result<(), StoreError> {
    let host_ids = hosts
        .iter()
        .map(|host| host.id.as_str())
        .collect::<HashSet<_>>();
    let reference_categories = ssh_key_references
        .iter()
        .map(|reference| (reference.id.as_str(), &reference.category))
        .collect::<HashMap<_, _>>();
    let managed_categories = managed_ssh_keys
        .iter()
        .map(|key| (key.id.as_str(), &key.category))
        .collect::<HashMap<_, _>>();
    let identities = identity_references
        .iter()
        .map(|identity| (identity.id.as_str(), identity))
        .collect::<HashMap<_, _>>();
    let password_identities = password_identities
        .iter()
        .map(|identity| (identity.id.as_str(), identity))
        .collect::<HashMap<_, _>>();
    let proxy_profiles = proxy_profiles
        .iter()
        .map(|profile| (profile.id.as_str(), profile))
        .collect::<HashMap<_, _>>();
    for group in groups {
        validate_group_graph_reference(
            group,
            &host_ids,
            &reference_categories,
            &managed_categories,
            &identities,
            &password_identities,
            &proxy_profiles,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_group_graph_reference(
    group: &SavedGroupConfig,
    host_ids: &HashSet<&str>,
    reference_categories: &HashMap<&str, &SavedSshKeyCategory>,
    managed_categories: &HashMap<&str, &SavedSshKeyCategory>,
    identities: &HashMap<&str, &SavedIdentityReference>,
    password_identities: &HashMap<&str, &SavedPasswordIdentity>,
    proxy_profiles: &HashMap<&str, &SavedProxyProfile>,
) -> Result<(), StoreError> {
    let defaults = &group.defaults;
    if let SavedGroupOverride::Set(chain) = &defaults.host_chain {
        if chain
            .host_ids()
            .iter()
            .any(|host_id| !host_ids.contains(host_id.as_str()))
        {
            return Err(StoreError::MissingGraphReference {
                source: SavedVaultEntityKind::Group,
                target: SavedVaultEntityKind::Host,
            });
        }
    }
    if let SavedGroupOverride::Set(key_id) = &defaults.identity_file_id {
        if !reference_categories.contains_key(key_id.as_str())
            && !managed_categories.contains_key(key_id.as_str())
        {
            return Err(StoreError::MissingGraphReference {
                source: SavedVaultEntityKind::Group,
                target: SavedVaultEntityKind::SshKeyReference,
            });
        }
    }
    if let SavedGroupOverride::Set(identity) = &defaults.identity_id {
        match identity {
            SavedGroupIdentityReference::Key(id) if identities.contains_key(id.as_str()) => {}
            SavedGroupIdentityReference::Key(id)
                if password_identities.contains_key(id.as_str()) =>
            {
                return Err(StoreError::IncompatibleGraphReference {
                    source: SavedVaultEntityKind::Group,
                    target: SavedVaultEntityKind::PasswordIdentity,
                });
            }
            SavedGroupIdentityReference::Key(_) => {
                return Err(StoreError::MissingGraphReference {
                    source: SavedVaultEntityKind::Group,
                    target: SavedVaultEntityKind::IdentityReference,
                });
            }
            SavedGroupIdentityReference::Password(id)
                if password_identities.contains_key(id.as_str()) => {}
            SavedGroupIdentityReference::Password(id) if identities.contains_key(id.as_str()) => {
                return Err(StoreError::IncompatibleGraphReference {
                    source: SavedVaultEntityKind::Group,
                    target: SavedVaultEntityKind::IdentityReference,
                });
            }
            SavedGroupIdentityReference::Password(_) => {
                return Err(StoreError::MissingGraphReference {
                    source: SavedVaultEntityKind::Group,
                    target: SavedVaultEntityKind::PasswordIdentity,
                });
            }
        }
    }
    if let SavedGroupOverride::Set(id) = &defaults.telnet_identity_id {
        if password_identities.contains_key(id.as_str()) {
        } else if identities.contains_key(id.as_str()) {
            return Err(StoreError::IncompatibleGraphReference {
                source: SavedVaultEntityKind::Group,
                target: SavedVaultEntityKind::IdentityReference,
            });
        } else {
            return Err(StoreError::MissingGraphReference {
                source: SavedVaultEntityKind::Group,
                target: SavedVaultEntityKind::PasswordIdentity,
            });
        }
    }
    match &defaults.proxy {
        SavedGroupProxyOverride::Profile(id) if !proxy_profiles.contains_key(id.as_str()) => {
            Err(StoreError::MissingGraphReference {
                source: SavedVaultEntityKind::Group,
                target: SavedVaultEntityKind::ProxyProfile,
            })
        }
        SavedGroupProxyOverride::Inline(config) => validate_proxy_config_reference(
            config,
            SavedVaultEntityKind::Group,
            identities,
            password_identities,
        ),
        SavedGroupProxyOverride::Inherit
        | SavedGroupProxyOverride::Clear
        | SavedGroupProxyOverride::Profile(_) => Ok(()),
    }
}

fn host_catalog_reference<'a>(
    host: &'a SavedHost,
    field: &str,
) -> Result<Option<&'a str>, StoreError> {
    match host.compatibility_fields().get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) if value.is_empty() => Ok(None),
        Some(serde_json::Value::String(value)) => Ok(Some(value)),
        _ => Err(StoreError::MissingGraphReference {
            source: SavedVaultEntityKind::Host,
            target: match field {
                "identityId" => SavedVaultEntityKind::IdentityReference,
                "telnetIdentityId" => SavedVaultEntityKind::PasswordIdentity,
                _ => SavedVaultEntityKind::SshKeyReference,
            },
        }),
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestPublishFault {
    SyncFailure,
    SyncFailureAndRevalidationReadFailure,
    SyncFailureAndTargetDeletion,
    SyncFailureAndTargetCorruption,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestDurabilityConfirmationFault {
    SyncFailure,
    CompetingSlotSyncFailure,
    ContentChange,
    GenerationChange,
}

#[cfg(test)]
fn inject_current_snapshot_content_change(
    _store: &SavedHostStore,
    loaded: &LoadedStore,
) -> Result<(), StoreError> {
    let path = loaded
        .snapshot_path
        .as_ref()
        .ok_or(StoreError::SnapshotDurabilityUnconfirmed)?;
    let mut hosts = loaded.hosts.clone();
    let mut ssh_key_references = loaded.ssh_key_references.clone();
    let mut managed_ssh_keys = loaded.managed_ssh_keys.clone();
    let mut identity_references = loaded.identity_references.clone();
    let mut password_identities = loaded.password_identities.clone();
    let mut proxy_profiles = loaded.proxy_profiles.clone();
    let mut groups = loaded.groups.clone();
    let mut custom_groups = loaded.custom_groups.clone();
    let mut notes_snippets = loaded.notes_snippets.clone();
    let mut port_forward_rules = loaded.port_forward_rules.clone();
    let mut known_hosts = loaded.known_hosts.clone();
    let mut connection_logs = loaded.connection_logs.clone();
    if let Some(host) = hosts.first_mut() {
        host.label.push_str(" changed");
    } else if let Some(reference) = ssh_key_references.first_mut() {
        reference.label.push_str(" changed");
    } else if let Some(managed) = managed_ssh_keys.first_mut() {
        managed.label.push_str(" changed");
    } else if let Some(reference) = identity_references.first_mut() {
        reference.label.push_str(" changed");
    } else if let Some(identity) = password_identities.first_mut() {
        identity.label.push_str(" changed");
    } else if let Some(profile) = proxy_profiles.first_mut() {
        profile.label.push_str(" changed");
    } else if let Some(group) = groups.first_mut() {
        group.updated_at = group.updated_at.saturating_add(1);
    } else if custom_groups.is_some() {
        custom_groups = Some(
            SavedGroupCatalog::from_paths(["confirmation-content-changed"])
                .map_err(|_| StoreError::Serialization)?,
        );
    } else if !notes_snippets.is_absent() {
        notes_snippets = SavedNotesSnippetsCatalog::default();
    } else if let Some(rule) = port_forward_rules.first_mut() {
        rule.label.push_str(" changed");
    } else if let Some(known_host) = known_hosts.first_mut() {
        known_host.last_seen = Some(
            known_host
                .last_seen
                .unwrap_or(known_host.discovered_at)
                .saturating_add(1),
        );
    } else if let Some(log) = connection_logs.first_mut() {
        log.host_label.push_str(" changed");
    } else {
        return Err(StoreError::SnapshotDurabilityUnconfirmed);
    }
    let envelope = SnapshotEnvelope::new_latest(
        _store.store_id.to_string(),
        Slot::for_generation(loaded.generation),
        loaded.generation,
        hosts,
        ssh_key_references,
        managed_ssh_keys,
        identity_references,
        password_identities,
        proxy_profiles,
        groups,
        custom_groups,
        notes_snippets,
        port_forward_rules,
        known_hosts,
        connection_logs,
    )?;
    let encoded = serde_json::to_vec(&envelope).map_err(|_| StoreError::Serialization)?;
    let original_path = path.with_file_name(format!(
        ".confirmation-original-{}.tmp",
        Uuid::new_v4().simple()
    ));
    fs::rename(path, original_path)?;
    let mut replacement = OpenOptions::new().write(true).create_new(true).open(path)?;
    replacement.write_all(&encoded)?;
    replacement.sync_all()?;
    Ok(())
}

#[cfg(test)]
fn inject_next_snapshot_generation(
    store: &SavedHostStore,
    loaded: &LoadedStore,
) -> Result<(), StoreError> {
    let generation = loaded
        .max_seen_generation
        .max(loaded.generation)
        .checked_add(1)
        .ok_or(StoreError::GenerationOverflow)?;
    let slot = Slot::for_generation(generation);
    let envelope = SnapshotEnvelope::new_latest(
        store.store_id.to_string(),
        slot,
        generation,
        loaded.hosts.clone(),
        loaded.ssh_key_references.clone(),
        loaded.managed_ssh_keys.clone(),
        loaded.identity_references.clone(),
        loaded.password_identities.clone(),
        loaded.proxy_profiles.clone(),
        loaded.groups.clone(),
        loaded.custom_groups.clone(),
        loaded.notes_snippets.clone(),
        loaded.port_forward_rules.clone(),
        loaded.known_hosts.clone(),
        loaded.connection_logs.clone(),
    )?;
    let encoded = serde_json::to_vec(&envelope).map_err(|_| StoreError::Serialization)?;
    let durability = publish_snapshot_no_overwrite(
        &store.root.join(slot.directory()),
        store.store_id.as_ref(),
        slot,
        generation,
        &encoded,
    )?;
    if durability != SavedVaultCommitDurability::Durable {
        return Err(StoreError::SnapshotDurabilityUnconfirmed);
    }
    Ok(())
}

#[cfg(test)]
fn publish_snapshot_no_overwrite_with_test_fault(
    directory: &Path,
    _store_id: &str,
    _slot: Slot,
    generation: u64,
    encoded: &[u8],
    fault: TestPublishFault,
) -> Result<SavedVaultCommitDurability, StoreError> {
    publish_snapshot_no_overwrite_with_hooks(
        directory,
        generation,
        encoded,
        |_| Err(io::Error::other("injected directory sync failure")),
        move |path, expected| match fault {
            TestPublishFault::SyncFailure => published_bytes_match(path, expected),
            TestPublishFault::SyncFailureAndRevalidationReadFailure => {
                Err(io::Error::other("injected publication read failure"))
            }
            TestPublishFault::SyncFailureAndTargetDeletion => {
                fs::remove_file(path)?;
                published_bytes_match(path, expected)
            }
            TestPublishFault::SyncFailureAndTargetCorruption => {
                fs::write(path, b"injected corrupt publication")?;
                published_bytes_match(path, expected)
            }
        },
    )
}

fn publish_snapshot_no_overwrite(
    directory: &Path,
    store_id: &str,
    slot: Slot,
    generation: u64,
    encoded: &[u8],
) -> Result<SavedVaultCommitDurability, StoreError> {
    publish_snapshot_no_overwrite_with_sync(
        directory,
        store_id,
        slot,
        generation,
        encoded,
        sync_directory,
    )
}

fn publish_snapshot_no_overwrite_with_sync<F>(
    directory: &Path,
    _store_id: &str,
    _slot: Slot,
    generation: u64,
    encoded: &[u8],
    sync: F,
) -> Result<SavedVaultCommitDurability, StoreError>
where
    F: FnMut(&Path) -> io::Result<()>,
{
    publish_snapshot_no_overwrite_with_hooks(
        directory,
        generation,
        encoded,
        sync,
        published_bytes_match,
    )
}

fn publish_snapshot_no_overwrite_with_hooks<F, R>(
    directory: &Path,
    generation: u64,
    encoded: &[u8],
    mut sync: F,
    mut revalidate: R,
) -> Result<SavedVaultCommitDurability, StoreError>
where
    F: FnMut(&Path) -> io::Result<()>,
    R: FnMut(&Path, &[u8]) -> io::Result<bool>,
{
    for _ in 0..PUBLISH_ATTEMPTS {
        let artifact_id = Uuid::new_v4().simple().to_string();
        let final_name = format!("snapshot-{generation:020}-{artifact_id}.json");
        match publish_named_no_overwrite_with_hooks(
            directory,
            &final_name,
            ".snapshot",
            encoded,
            &mut sync,
            &mut revalidate,
        ) {
            Err(StoreError::ArtifactConflict) => continue,
            result => return result,
        }
    }
    Err(StoreError::ArtifactConflict)
}

/// Best-effort compaction after a new snapshot has already been published and
/// synced. Only artifacts whose name, owner, slot, generation, checksum, and
/// host records all validate are eligible for deletion. An error here must not
/// turn a completed commit into an apparent failure.
fn cleanup_owned_slot_artifacts(
    directory: &Path,
    store_id: &str,
    slot: Slot,
    published_generation: u64,
) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    let mut removed_any = false;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let path = entry.path();
        let remove = if let Some(generation) = parse_snapshot_name(name) {
            generation < published_generation
                && read_snapshot(&path, store_id, slot, generation).is_ok()
        } else if is_snapshot_temp_name(name) {
            owned_temp_generation(&path, store_id, slot)
                .is_some_and(|generation| generation <= published_generation)
        } else {
            false
        };
        if remove && fs::remove_file(path).is_ok() {
            removed_any = true;
        }
    }
    if removed_any {
        let _ = sync_directory(directory);
    }
}

fn is_snapshot_temp_name(name: &str) -> bool {
    let Some(artifact_id) = name
        .strip_prefix(".snapshot-")
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    artifact_id.len() == 32
        && artifact_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn owned_temp_generation(path: &Path, store_id: &str, slot: Slot) -> Option<u64> {
    require_regular_file(path).ok()?;
    let encoded = read_bounded(path, MAX_SNAPSHOT_BYTES).ok()?;
    let envelope: SnapshotEnvelope = serde_json::from_slice(&encoded).ok()?;
    let generation = envelope.generation;
    if generation == 0 || Slot::for_generation(generation) != slot {
        return None;
    }
    envelope
        .validate(store_id, slot, generation, path.to_path_buf())
        .ok()?;
    Some(generation)
}

fn publish_named_no_overwrite(
    directory: &Path,
    final_name: &str,
    temp_prefix: &str,
    encoded: &[u8],
) -> Result<SavedVaultCommitDurability, StoreError> {
    publish_named_no_overwrite_with_sync(
        directory,
        final_name,
        temp_prefix,
        encoded,
        sync_directory,
    )
}

fn publish_named_no_overwrite_with_sync<F>(
    directory: &Path,
    final_name: &str,
    temp_prefix: &str,
    encoded: &[u8],
    sync: F,
) -> Result<SavedVaultCommitDurability, StoreError>
where
    F: FnMut(&Path) -> io::Result<()>,
{
    publish_named_no_overwrite_with_hooks(
        directory,
        final_name,
        temp_prefix,
        encoded,
        sync,
        published_bytes_match,
    )
}

fn publish_named_no_overwrite_with_hooks<F, R>(
    directory: &Path,
    final_name: &str,
    temp_prefix: &str,
    encoded: &[u8],
    mut sync: F,
    mut revalidate: R,
) -> Result<SavedVaultCommitDurability, StoreError>
where
    F: FnMut(&Path) -> io::Result<()>,
    R: FnMut(&Path, &[u8]) -> io::Result<bool>,
{
    require_directory(directory)?;
    let temp_path = directory.join(format!("{temp_prefix}-{}.tmp", Uuid::new_v4().simple()));
    let final_path = directory.join(final_name);
    let mut temp = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                StoreError::ArtifactConflict
            } else {
                StoreError::Io(error)
            }
        })?;
    let pre_publication = (|| -> Result<(), StoreError> {
        temp.write_all(encoded)?;
        temp.sync_all()?;
        drop(temp);
        fs::hard_link(&temp_path, &final_path).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                StoreError::ArtifactConflict
            } else {
                StoreError::Io(error)
            }
        })?;
        Ok(())
    })();
    if let Err(error) = pre_publication {
        if !final_path.try_exists().unwrap_or(true) {
            let _ = fs::remove_file(&temp_path);
        }
        return Err(error);
    }

    // The hard link above is the publication point. After it succeeds, an
    // ordinary I/O error must not be reported as an uncommitted mutation: a
    // caller could otherwise compensate an OS-keyring write while metadata is
    // already visible. If directory syncing fails, an exact byte-for-byte
    // re-read narrows the result to a visible publication whose crash
    // durability is uncertain. A missing, changed, or unreadable target is
    // still a post-publication result, but its visibility is indeterminate.
    let outcome = match sync(directory) {
        Ok(()) => SavedVaultCommitDurability::Durable,
        Err(_) => match revalidate(&final_path, encoded) {
            Ok(true) => SavedVaultCommitDurability::PublishedDurabilityUncertain,
            Ok(false) | Err(_) => SavedVaultCommitDurability::PublicationIndeterminate,
        },
    };
    if outcome != SavedVaultCommitDurability::PublicationIndeterminate {
        let _ = fs::remove_file(&temp_path);
        let _ = sync(directory);
    }
    Ok(outcome)
}

fn published_bytes_match(path: &Path, encoded: &[u8]) -> io::Result<bool> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() != encoded.len() as u64
    {
        return Ok(false);
    }
    let actual = read_bounded(path, encoded.len() as u64)?;
    Ok(actual == encoded)
}

fn read_bounded(path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file is too large",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file is too large",
        ));
    }
    Ok(bytes)
}

fn require_directory(path: &Path) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(StoreError::ArtifactConflict);
    }
    Ok(())
}

fn require_regular_file(path: &Path) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(StoreError::ArtifactConflict);
    }
    Ok(())
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
        // Windows can open a directory handle with backup semantics, but
        // FlushFileBuffers is not supported for directory handles on every
        // filesystem/version. The file itself was flushed before publication;
        // tolerate only the documented family of unsupported-operation errors.
        Err(error) if matches!(error.raw_os_error(), Some(1 | 5 | 50 | 87)) => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(not(windows))]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn now_millis() -> Result<u64, StoreError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StoreError::ClockUnavailable)?
        .as_millis();
    u64::try_from(millis).map_err(|_| StoreError::ClockUnavailable)
}

fn inventory_revision_seal(
    store_id: &str,
    loaded_generation: u64,
    max_seen_generation: u64,
) -> String {
    let mut payload = Vec::with_capacity(64 + store_id.len());
    payload.extend_from_slice(b"netcatty-saved-host-inventory-revision-v1\0");
    payload.extend_from_slice(&(store_id.len() as u64).to_be_bytes());
    payload.extend_from_slice(store_id.as_bytes());
    payload.extend_from_slice(&loaded_generation.to_be_bytes());
    payload.extend_from_slice(&max_seen_generation.to_be_bytes());
    hmac_sha256_hex(inventory_revision_key(), &payload)
}

fn inventory_revision_key() -> &'static [u8; 32] {
    INVENTORY_REVISION_KEY.get_or_init(|| {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let mut key = [0_u8; 32];
        key[..16].copy_from_slice(first.as_bytes());
        key[16..].copy_from_slice(second.as_bytes());
        key
    })
}

fn hmac_sha256_hex(key: &[u8; 32], value: &[u8]) -> String {
    const BLOCK_BYTES: usize = 64;
    let mut inner_pad = [0x36_u8; BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; BLOCK_BYTES];
    for (index, byte) in key.iter().copied().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(value);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    let digest = outer.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn hex_digest(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    hex_encode(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
include!("store_tests.rs");
