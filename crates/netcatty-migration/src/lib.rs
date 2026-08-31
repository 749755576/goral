//! Read-only parsing of legacy Netcatty Vault exports.
//!
//! This crate deliberately separates secret-bearing migration candidates from
//! the safe, serializable preview returned to a renderer. A parsed document and
//! its candidates implement neither `Debug`, `Clone`, nor Serde serialization.

mod group_config;
mod notes_snippets;

pub use group_config::{
    LegacyGroupCatalogCandidates, LegacyGroupConfigCandidate, LegacyGroupConfigParseError,
    LegacyGroupConfigParseErrorCode, LegacyGroupConfigReferences, parse_legacy_group_catalogs,
};
pub use notes_snippets::{
    LegacyNotesSnippetsAssessment, LegacyNotesSnippetsCandidates, LegacyNotesSnippetsDisposition,
    LegacyNotesSnippetsError, LegacyNotesSnippetsErrorCode, LegacyNotesSnippetsImportPlan,
    LegacyNotesSnippetsRecordKind, parse_legacy_notes_snippets_catalogs,
    plan_legacy_notes_snippets_import,
};

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use netcatty_credentials::{MAX_PERSISTENT_SECRET_BYTES, SecretValue};
use netcatty_secret_store::{
    MAX_CERTIFICATE_BYTES, MAX_PASSPHRASE_BYTES, MAX_PRIVATE_KEY_BYTES, MAX_PUBLIC_KEY_BYTES,
    SshSecretBundle,
};
use netcatty_vault::{
    DEFAULT_SERIAL_BAUD_RATE, SavedHost, SavedIdentityReference, SavedIdentityReferenceId,
    SavedManagedSshKey, SavedPasswordIdentity, SavedPasswordIdentityId, SavedProxyConfig,
    SavedProxyProfile, SavedProxyProfileId, SavedSecretObjectLocator, SavedSshKeyCategory,
    SavedSshKeyCustodyReference, SavedSshKeyReference, SavedSshKeyReferenceId, SavedSshKeySource,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// Maximum size accepted for a plain legacy Vault document or decoded plain
/// payload. The outer envelope has a separate, larger bound.
pub const MAX_LEGACY_PLAINTEXT_BYTES: usize = 25 * 1_024 * 1_024;

/// Maximum size accepted for an outer backup envelope.
pub const MAX_LEGACY_BACKUP_BYTES: usize = 50 * 1_024 * 1_024;

/// Upper bound on host records considered in one dry run.
pub const MAX_LEGACY_HOSTS: usize = 10_000;

/// Upper bound applied independently to legacy SSH-key, identity, and proxy
/// profile catalogs.
pub const MAX_LEGACY_CATALOG_ENTITIES: usize = 10_000;

/// Maximum number of individual safe issues returned to the renderer. Exact
/// aggregate counts remain available even when this presentation list is
/// truncated, preventing a hostile source from creating an enormous DOM.
pub const MAX_LEGACY_PREVIEW_ISSUES: usize = 500;

const FORMAT_VERSION_V1: u64 = 1;
const PLAIN_JSON_V1: &str = "plain-json-v1";
const SAFE_STORAGE_V1: &str = "safeStorage-v1";
const ENCRYPTED_CREDENTIAL_PREFIX: &str = "enc:v1:";
const MAX_LEGACY_IDENTITY_FILE_PATHS: usize = 8;
const MAX_LEGACY_IDENTITY_FILE_PATH_BYTES: usize = 32 * 1_024;
const MAX_LEGACY_IDENTITY_FILE_PATH_TOTAL_BYTES: usize = 64 * 1_024;

/// Stable, renderer-safe parser error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LegacyVaultErrorCode {
    InputTooLarge,
    PlaintextPayloadTooLarge,
    InvalidUtf8,
    InvalidJson,
    InvalidRoot,
    InvalidEnvelope,
    UnsupportedFormatVersion,
    UnsupportedPayloadEncoding,
    InvalidPayloadData,
    HostLimitExceeded,
    CatalogLimitExceeded,
    InvalidNotesSnippetsCatalog,
}

impl LegacyVaultErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InputTooLarge => "INPUT_TOO_LARGE",
            Self::PlaintextPayloadTooLarge => "PLAINTEXT_PAYLOAD_TOO_LARGE",
            Self::InvalidUtf8 => "INVALID_UTF8",
            Self::InvalidJson => "INVALID_JSON",
            Self::InvalidRoot => "INVALID_ROOT",
            Self::InvalidEnvelope => "INVALID_ENVELOPE",
            Self::UnsupportedFormatVersion => "UNSUPPORTED_FORMAT_VERSION",
            Self::UnsupportedPayloadEncoding => "UNSUPPORTED_PAYLOAD_ENCODING",
            Self::InvalidPayloadData => "INVALID_PAYLOAD_DATA",
            Self::HostLimitExceeded => "HOST_LIMIT_EXCEEDED",
            Self::CatalogLimitExceeded => "CATALOG_LIMIT_EXCEEDED",
            Self::InvalidNotesSnippetsCatalog => "INVALID_NOTES_SNIPPETS_CATALOG",
        }
    }
}

/// An error that never retains source text, JSON values, ciphertext, or secret
/// material. Its `Debug`, `Display`, and serialized forms are therefore safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyVaultError {
    pub code: LegacyVaultErrorCode,
}

impl LegacyVaultError {
    const fn new(code: LegacyVaultErrorCode) -> Self {
        Self { code }
    }
}

impl fmt::Display for LegacyVaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.code {
            LegacyVaultErrorCode::InputTooLarge => "legacy backup exceeds the input limit",
            LegacyVaultErrorCode::PlaintextPayloadTooLarge => {
                "legacy plaintext payload exceeds the input limit"
            }
            LegacyVaultErrorCode::InvalidUtf8 => "legacy backup is not UTF-8",
            LegacyVaultErrorCode::InvalidJson => "legacy backup is not valid JSON",
            LegacyVaultErrorCode::InvalidRoot => {
                "legacy backup must contain a host array or Vault object"
            }
            LegacyVaultErrorCode::InvalidEnvelope => "legacy backup envelope is incomplete",
            LegacyVaultErrorCode::UnsupportedFormatVersion => {
                "legacy backup format version is unsupported"
            }
            LegacyVaultErrorCode::UnsupportedPayloadEncoding => {
                "legacy backup payload encoding is unsupported"
            }
            LegacyVaultErrorCode::InvalidPayloadData => "legacy backup payload data is invalid",
            LegacyVaultErrorCode::HostLimitExceeded => {
                "legacy backup contains too many host records"
            }
            LegacyVaultErrorCode::CatalogLimitExceeded => {
                "legacy backup contains too many catalog records"
            }
            LegacyVaultErrorCode::InvalidNotesSnippetsCatalog => {
                "legacy notes/scripts catalog is invalid"
            }
        })
    }
}

impl std::error::Error for LegacyVaultError {}

/// Which supported legacy shape was recognized. These values are safe to send
/// to the frontend and intentionally contain no payload details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LegacyVaultSourceKind {
    #[serde(rename = "bareHostArray")]
    BareHostArray,
    #[serde(rename = "unversionedVaultExport")]
    UnversionedVault,
    #[serde(rename = "backupPlainJsonV1")]
    VersionedPlainJsonV1,
    #[serde(rename = "backupSafeStorageV1RequiresRecovery")]
    SafeStorageV1,
}

/// Entity catalog associated with an issue index. This discriminator is fixed
/// and safe; it prevents equal numeric indices in different arrays from being
/// confused without exposing an entity ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LegacyVaultRecordKind {
    Source,
    Host,
    SshKey,
    Identity,
    ProxyProfile,
    GroupConfig,
    Snippet,
    Note,
}

/// Stable issue codes emitted by a dry-run preview.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LegacyVaultIssueCode {
    #[serde(rename = "LEGACY_SOURCE_RECOVERY_REQUIRED")]
    SourceRecoveryRequired,
    #[serde(rename = "LEGACY_HOST_REJECTED")]
    HostRejected,
    #[serde(rename = "LEGACY_HOST_UNSUPPORTED")]
    HostUnsupported,
    #[serde(rename = "LEGACY_DUPLICATE_HOST_ID")]
    DuplicateHostId,
    #[serde(rename = "LEGACY_SECRET_MATERIAL_STRIPPED")]
    SecretMaterialStripped,
    #[serde(rename = "LEGACY_ENCRYPTED_CREDENTIAL_REENTRY_REQUIRED")]
    EncryptedCredentialReentryRequired,
    #[serde(rename = "LEGACY_OVERSIZED_CREDENTIAL_REENTRY_REQUIRED")]
    OversizedCredentialReentryRequired,
    #[serde(rename = "LEGACY_INVALID_CREDENTIAL_REENTRY_REQUIRED")]
    InvalidCredentialReentryRequired,
    #[serde(rename = "LEGACY_MISSING_CREDENTIAL_REENTRY_REQUIRED")]
    MissingCredentialReentryRequired,
    #[serde(rename = "LEGACY_ADDITIONAL_CREDENTIAL_REENTRY_REQUIRED")]
    AdditionalCredentialReentryRequired,
    #[serde(rename = "LEGACY_PASSWORD_NOT_SAVED_BY_POLICY")]
    PasswordNotSavedByPolicy,
    #[serde(rename = "LEGACY_NON_SSH_PASSWORD_REENTRY_REQUIRED")]
    NonSshPasswordReentryRequired,
    #[serde(rename = "LEGACY_SSH_KEY_REJECTED")]
    SshKeyRejected,
    #[serde(rename = "LEGACY_SSH_KEY_UNSUPPORTED")]
    SshKeyUnsupported,
    #[serde(rename = "LEGACY_DUPLICATE_SSH_KEY_ID")]
    DuplicateSshKeyId,
    #[serde(rename = "LEGACY_SSH_KEY_CREDENTIAL_RECOVERY_REQUIRED")]
    SshKeyCredentialRecoveryRequired,
    #[serde(rename = "LEGACY_SSH_KEY_PASSPHRASE_NOT_SAVED_BY_POLICY")]
    SshKeyPassphraseNotSavedByPolicy,
    #[serde(rename = "LEGACY_SSH_CERTIFICATE_UNSUPPORTED")]
    SshCertificateUnsupported,
    #[serde(rename = "LEGACY_IDENTITY_REJECTED")]
    IdentityRejected,
    #[serde(rename = "LEGACY_IDENTITY_UNSUPPORTED")]
    IdentityUnsupported,
    #[serde(rename = "LEGACY_DUPLICATE_IDENTITY_ID")]
    DuplicateIdentityId,
    #[serde(rename = "LEGACY_IDENTITY_CREDENTIAL_REENTRY_REQUIRED")]
    IdentityCredentialReentryRequired,
    #[serde(rename = "LEGACY_PASSWORD_IDENTITY_RESIDUAL_KEY_REFERENCE_IGNORED")]
    PasswordIdentityResidualKeyReferenceIgnored,
    #[serde(rename = "LEGACY_MISSING_SSH_KEY_REFERENCE")]
    MissingSshKeyReference,
    #[serde(rename = "LEGACY_MISSING_IDENTITY_REFERENCE")]
    MissingIdentityReference,
    #[serde(rename = "LEGACY_INVALID_IDENTITY_FILE_PATHS")]
    InvalidIdentityFilePaths,
    #[serde(rename = "LEGACY_PROXY_PROFILE_REJECTED")]
    ProxyProfileRejected,
    #[serde(rename = "LEGACY_PROXY_PROFILE_UNSUPPORTED")]
    ProxyProfileUnsupported,
    #[serde(rename = "LEGACY_DUPLICATE_PROXY_PROFILE_ID")]
    DuplicateProxyProfileId,
    #[serde(rename = "LEGACY_INVALID_PROXY_CONFIG")]
    InvalidProxyConfig,
    #[serde(rename = "LEGACY_PROXY_AUTHENTICATION_CONFLICT")]
    ProxyAuthenticationConflict,
    #[serde(rename = "LEGACY_MISSING_PROXY_PROFILE_REFERENCE")]
    MissingProxyProfileReference,
    #[serde(rename = "LEGACY_MISSING_PROXY_IDENTITY_REFERENCE")]
    MissingProxyIdentityReference,
    #[serde(rename = "LEGACY_PROXY_CREDENTIAL_REENTRY_REQUIRED")]
    ProxyCredentialReentryRequired,
    #[serde(rename = "LEGACY_GROUP_CONFIG_SSH_CREDENTIAL_REENTRY_REQUIRED")]
    GroupConfigSshCredentialReentryRequired,
    #[serde(rename = "LEGACY_GROUP_CONFIG_TELNET_CREDENTIAL_REENTRY_REQUIRED")]
    GroupConfigTelnetCredentialReentryRequired,
    #[serde(rename = "LEGACY_GROUP_CONFIG_PROXY_CREDENTIAL_REENTRY_REQUIRED")]
    GroupConfigProxyCredentialReentryRequired,
}

impl LegacyVaultIssueCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceRecoveryRequired => "LEGACY_SOURCE_RECOVERY_REQUIRED",
            Self::HostRejected => "LEGACY_HOST_REJECTED",
            Self::HostUnsupported => "LEGACY_HOST_UNSUPPORTED",
            Self::DuplicateHostId => "LEGACY_DUPLICATE_HOST_ID",
            Self::SecretMaterialStripped => "LEGACY_SECRET_MATERIAL_STRIPPED",
            Self::EncryptedCredentialReentryRequired => {
                "LEGACY_ENCRYPTED_CREDENTIAL_REENTRY_REQUIRED"
            }
            Self::OversizedCredentialReentryRequired => {
                "LEGACY_OVERSIZED_CREDENTIAL_REENTRY_REQUIRED"
            }
            Self::InvalidCredentialReentryRequired => "LEGACY_INVALID_CREDENTIAL_REENTRY_REQUIRED",
            Self::MissingCredentialReentryRequired => "LEGACY_MISSING_CREDENTIAL_REENTRY_REQUIRED",
            Self::AdditionalCredentialReentryRequired => {
                "LEGACY_ADDITIONAL_CREDENTIAL_REENTRY_REQUIRED"
            }
            Self::PasswordNotSavedByPolicy => "LEGACY_PASSWORD_NOT_SAVED_BY_POLICY",
            Self::NonSshPasswordReentryRequired => "LEGACY_NON_SSH_PASSWORD_REENTRY_REQUIRED",
            Self::SshKeyRejected => "LEGACY_SSH_KEY_REJECTED",
            Self::SshKeyUnsupported => "LEGACY_SSH_KEY_UNSUPPORTED",
            Self::DuplicateSshKeyId => "LEGACY_DUPLICATE_SSH_KEY_ID",
            Self::SshKeyCredentialRecoveryRequired => "LEGACY_SSH_KEY_CREDENTIAL_RECOVERY_REQUIRED",
            Self::SshKeyPassphraseNotSavedByPolicy => {
                "LEGACY_SSH_KEY_PASSPHRASE_NOT_SAVED_BY_POLICY"
            }
            Self::SshCertificateUnsupported => "LEGACY_SSH_CERTIFICATE_UNSUPPORTED",
            Self::IdentityRejected => "LEGACY_IDENTITY_REJECTED",
            Self::IdentityUnsupported => "LEGACY_IDENTITY_UNSUPPORTED",
            Self::DuplicateIdentityId => "LEGACY_DUPLICATE_IDENTITY_ID",
            Self::IdentityCredentialReentryRequired => {
                "LEGACY_IDENTITY_CREDENTIAL_REENTRY_REQUIRED"
            }
            Self::PasswordIdentityResidualKeyReferenceIgnored => {
                "LEGACY_PASSWORD_IDENTITY_RESIDUAL_KEY_REFERENCE_IGNORED"
            }
            Self::MissingSshKeyReference => "LEGACY_MISSING_SSH_KEY_REFERENCE",
            Self::MissingIdentityReference => "LEGACY_MISSING_IDENTITY_REFERENCE",
            Self::InvalidIdentityFilePaths => "LEGACY_INVALID_IDENTITY_FILE_PATHS",
            Self::ProxyProfileRejected => "LEGACY_PROXY_PROFILE_REJECTED",
            Self::ProxyProfileUnsupported => "LEGACY_PROXY_PROFILE_UNSUPPORTED",
            Self::DuplicateProxyProfileId => "LEGACY_DUPLICATE_PROXY_PROFILE_ID",
            Self::InvalidProxyConfig => "LEGACY_INVALID_PROXY_CONFIG",
            Self::ProxyAuthenticationConflict => "LEGACY_PROXY_AUTHENTICATION_CONFLICT",
            Self::MissingProxyProfileReference => "LEGACY_MISSING_PROXY_PROFILE_REFERENCE",
            Self::MissingProxyIdentityReference => "LEGACY_MISSING_PROXY_IDENTITY_REFERENCE",
            Self::ProxyCredentialReentryRequired => "LEGACY_PROXY_CREDENTIAL_REENTRY_REQUIRED",
            Self::GroupConfigSshCredentialReentryRequired => {
                "LEGACY_GROUP_CONFIG_SSH_CREDENTIAL_REENTRY_REQUIRED"
            }
            Self::GroupConfigTelnetCredentialReentryRequired => {
                "LEGACY_GROUP_CONFIG_TELNET_CREDENTIAL_REENTRY_REQUIRED"
            }
            Self::GroupConfigProxyCredentialReentryRequired => {
                "LEGACY_GROUP_CONFIG_PROXY_CREDENTIAL_REENTRY_REQUIRED"
            }
        }
    }

    /// Static, secret-free user-facing text paired with the fixed code.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::SourceRecoveryRequired => {
                "该备份由旧版系统安全存储加密，需要在原设备恢复后重新导出。"
            }
            Self::HostRejected => "该主机记录无效，已跳过。",
            Self::HostUnsupported => "该主机的协议或认证方式当前尚不支持，已跳过。",
            Self::DuplicateHostId => "导入文件内存在重复的主机 ID，重复项已跳过。",
            Self::SecretMaterialStripped => "旧记录中的秘密字段已从主机资料中移除。",
            Self::EncryptedCredentialReentryRequired => {
                "旧密码是设备绑定的密文，导入后需要重新输入。"
            }
            Self::OversizedCredentialReentryRequired => {
                "旧密码超过安全存储限制，导入后需要重新输入。"
            }
            Self::InvalidCredentialReentryRequired => "旧密码格式无效，导入后需要重新输入。",
            Self::MissingCredentialReentryRequired => {
                "该 SSH 密码记录没有可迁移的密码，连接时需要重新输入。"
            }
            Self::AdditionalCredentialReentryRequired => {
                "记录包含当前不能直接迁移的其他凭据，之后需要重新输入。"
            }
            Self::PasswordNotSavedByPolicy => "该记录明确禁止保存密码，连接时仍需输入密码。",
            Self::SshKeyRejected => "A legacy SSH-key record is invalid and was skipped.",
            Self::SshKeyUnsupported => {
                "Only local reference-file SSH keys are supported by this import step."
            }
            Self::DuplicateSshKeyId => {
                "The source contains a duplicate SSH-key ID; the repeated record was skipped."
            }
            Self::SshKeyCredentialRecoveryRequired => {
                "The SSH-key record contains key or passphrase material that needs recovery or re-entry."
            }
            Self::SshKeyPassphraseNotSavedByPolicy => {
                "The SSH-key passphrase was discarded because the source record did not permit saving it."
            }
            Self::SshCertificateUnsupported => {
                "Certificate-backed SSH keys are not supported by this import step."
            }
            Self::IdentityRejected => "A legacy identity record is invalid and was skipped.",
            Self::IdentityUnsupported => {
                "Only key identities backed by a supported reference-file key are supported."
            }
            Self::DuplicateIdentityId => {
                "The source contains a duplicate identity ID; the repeated record was skipped."
            }
            Self::IdentityCredentialReentryRequired => {
                "The identity contains credential material that needs recovery or re-entry."
            }
            Self::PasswordIdentityResidualKeyReferenceIgnored => {
                "A password identity contained a stale key reference; the reference was ignored."
            }
            Self::MissingSshKeyReference => {
                "A required SSH-key reference is missing or unavailable in this import."
            }
            Self::MissingIdentityReference => {
                "A required identity reference is missing or unavailable in this import."
            }
            Self::InvalidIdentityFilePaths => {
                "An identity-file path relationship is invalid and requires review."
            }
            Self::ProxyProfileRejected => {
                "A legacy proxy-profile record is invalid and was skipped."
            }
            Self::ProxyProfileUnsupported => {
                "A legacy proxy-profile record has an unavailable dependency and was skipped."
            }
            Self::DuplicateProxyProfileId => {
                "The source contains a duplicate proxy-profile ID; the repeated record was skipped."
            }
            Self::InvalidProxyConfig => {
                "A legacy proxy configuration is invalid and requires review."
            }
            Self::ProxyAuthenticationConflict => {
                "A legacy proxy configuration mixes mutually exclusive authentication modes."
            }
            Self::MissingProxyProfileReference => {
                "A required proxy-profile reference is missing or unavailable in this import."
            }
            Self::MissingProxyIdentityReference => {
                "A required proxy password-identity reference is missing or incompatible."
            }
            Self::ProxyCredentialReentryRequired => {
                "A proxy password is unavailable and must be entered again."
            }
            Self::GroupConfigSshCredentialReentryRequired => {
                "A saved-group SSH password is unavailable and must be entered again."
            }
            Self::GroupConfigTelnetCredentialReentryRequired => {
                "A saved-group Telnet password is unavailable and must be entered again."
            }
            Self::GroupConfigProxyCredentialReentryRequired => {
                "A saved-group inline-proxy password is unavailable and must be entered again."
            }
            Self::NonSshPasswordReentryRequired => {
                "非 SSH 密码不会写入 SSH 凭据存储，之后需要重新输入。"
            }
        }
    }
}

/// A single safe preview issue. The fixed code identifies the entity catalog;
/// indices identify records without echoing attacker-controlled IDs, labels,
/// field values, or JSON paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyVaultIssue {
    pub code: LegacyVaultIssueCode,
    pub message: String,
    pub record_kind: LegacyVaultRecordKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_index: Option<u32>,
}

/// Safe aggregate counts for a dry run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyVaultCounts {
    pub source_hosts: u32,
    pub candidate_hosts: u32,
    pub candidate_managed_key_hosts: u32,
    pub rejected_hosts: u32,
    pub unsupported_hosts: u32,
    pub duplicate_hosts: u32,
    pub source_ssh_keys: u32,
    pub candidate_ssh_key_references: u32,
    pub candidate_managed_ssh_keys: u32,
    pub managed_ssh_key_recovery_required: u32,
    pub managed_passphrases_discarded_by_policy: u32,
    pub rejected_ssh_keys: u32,
    pub unsupported_ssh_keys: u32,
    pub duplicate_ssh_keys: u32,
    pub source_identities: u32,
    pub candidate_identity_references: u32,
    pub candidate_managed_identity_references: u32,
    pub candidate_password_identities: u32,
    pub candidate_password_identity_hosts: u32,
    pub password_identity_password_candidates: u32,
    pub password_identity_credential_reentry_required: u32,
    pub password_identity_residual_key_references: u32,
    pub rejected_identities: u32,
    pub unsupported_identities: u32,
    pub duplicate_identities: u32,
    pub missing_key_references: u32,
    pub missing_identity_references: u32,
    pub invalid_identity_file_path_hosts: u32,
    pub ssh_password_candidates: u32,
    pub telnet_password_candidates: u32,
    pub telnet_credential_reentry_required: u32,
    pub credential_reentry_required_hosts: u32,
    pub secret_fields_stripped: u32,
    pub source_proxy_profiles: u32,
    pub candidate_proxy_profiles: u32,
    pub rejected_proxy_profiles: u32,
    pub unsupported_proxy_profiles: u32,
    pub duplicate_proxy_profiles: u32,
    pub candidate_inline_proxy_hosts: u32,
    pub proxy_profile_password_candidates: u32,
    pub inline_proxy_password_candidates: u32,
    pub proxy_profile_credential_reentry_required: u32,
    pub inline_proxy_credential_reentry_required: u32,
    pub missing_proxy_profile_references: u32,
    pub missing_proxy_identity_references: u32,
    pub source_custom_groups: u32,
    pub candidate_custom_groups: u32,
    pub source_group_configs: u32,
    pub candidate_group_configs: u32,
    pub group_config_ssh_password_candidates: u32,
    pub group_config_telnet_password_candidates: u32,
    pub group_config_inline_proxy_password_candidates: u32,
    pub group_config_ssh_credential_reentry_required: u32,
    pub group_config_telnet_credential_reentry_required: u32,
    pub group_config_inline_proxy_credential_reentry_required: u32,
    pub missing_group_config_proxy_identity_references: u32,
    pub source_snippets: u32,
    pub candidate_snippets: u32,
    pub source_snippet_packages: u32,
    pub candidate_snippet_packages: u32,
    pub source_notes: u32,
    pub candidate_notes: u32,
    pub source_note_groups: u32,
    pub candidate_note_groups: u32,
}

/// Renderer-safe dry-run information. It is the only serializable view of a
/// parsed legacy source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyVaultPreview {
    pub source_kind: LegacyVaultSourceKind,
    pub source_count: u32,
    pub importable_count: u32,
    pub duplicate_count: u32,
    pub conflict_count: u32,
    pub recoverable_credential_count: u32,
    pub requires_credential_reentry_count: u32,
    pub unsupported_count: u32,
    pub issues: Vec<LegacyVaultIssue>,
    #[serde(default)]
    pub omitted_issue_count: u32,
    #[serde(skip)]
    counts: LegacyVaultCounts,
}

impl LegacyVaultPreview {
    /// Detailed parser-only counts. The public fields above form the safe
    /// parser-owned part of the desktop inspection contract; the trusted
    /// adapter adds its sealed source token and can replace the
    /// importable/duplicate/conflict values after assessing the live Vault.
    #[must_use]
    pub const fn counts(&self) -> &LegacyVaultCounts {
        &self.counts
    }

    #[must_use]
    pub const fn source_recovery_required(&self) -> bool {
        matches!(self.source_kind, LegacyVaultSourceKind::SafeStorageV1)
    }
}

/// Secret-free status describing what happened to a legacy SSH password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LegacyCredentialDisposition {
    None,
    PlaintextCandidate,
    ReentryRequiredEncrypted,
    ReentryRequiredOversized,
    ReentryRequiredInvalid,
    ReentryRequiredMissing,
    ReentryRequiredAdditionalSecret,
    ReentryRequiredNonSsh,
    NotSavedByPolicy,
}

/// A validated saved host plus an optional zeroizing credential candidate.
///
/// This type intentionally implements neither `Debug`, `Clone`, nor Serde
/// serialization. Consume it with [`LegacyHostCandidate::into_parts`] at the
/// trusted migration boundary.
///
/// ```compile_fail
/// use netcatty_migration::parse_legacy_vault;
/// let document = parse_legacy_vault(
///     br#"[{"id":"legacy","hostname":"host","username":"user"}]"#,
///     1,
/// ).unwrap();
/// let candidate = document.into_candidates().pop().unwrap();
/// let _ = serde_json::to_string(&candidate);
/// ```
pub struct LegacyHostCandidate {
    host: SavedHost,
    ssh_password: Option<SecretValue>,
    credential_disposition: LegacyCredentialDisposition,
    telnet_password: Option<SecretValue>,
    telnet_credential_disposition: LegacyCredentialDisposition,
    inline_proxy_password: Option<SecretValue>,
    inline_proxy_credential_disposition: LegacyProxyCredentialDisposition,
    requires_additional_credential_reentry: bool,
    currently_importable: bool,
}

impl LegacyHostCandidate {
    #[must_use]
    pub fn host(&self) -> &SavedHost {
        &self.host
    }

    #[must_use]
    pub const fn credential_disposition(&self) -> LegacyCredentialDisposition {
        self.credential_disposition
    }

    #[must_use]
    pub const fn has_ssh_password_candidate(&self) -> bool {
        self.ssh_password.is_some()
    }

    #[must_use]
    pub const fn telnet_credential_disposition(&self) -> LegacyCredentialDisposition {
        self.telnet_credential_disposition
    }

    #[must_use]
    pub const fn has_telnet_password_candidate(&self) -> bool {
        self.telnet_password.is_some()
    }

    #[must_use]
    pub const fn has_inline_proxy_password_candidate(&self) -> bool {
        self.inline_proxy_password.is_some()
    }

    #[must_use]
    pub const fn inline_proxy_credential_disposition(&self) -> LegacyProxyCredentialDisposition {
        self.inline_proxy_credential_disposition
    }

    #[must_use]
    pub const fn requires_additional_credential_reentry(&self) -> bool {
        self.requires_additional_credential_reentry
    }

    #[must_use]
    pub fn requires_credential_reentry(&self) -> bool {
        self.requires_additional_credential_reentry
            || disposition_requires_reentry(self.credential_disposition)
            || disposition_requires_reentry(self.telnet_credential_disposition)
    }

    /// Whether the current Rust saved-host connection path can consume this
    /// record. Unsupported records remain available for review without ever
    /// being passed to Vault assessment/commit by accident.
    #[must_use]
    pub fn is_currently_importable(&self) -> bool {
        self.currently_importable
    }

    #[must_use]
    pub fn into_parts(self) -> (SavedHost, Option<SecretValue>, LegacyCredentialDisposition) {
        (self.host, self.ssh_password, self.credential_disposition)
    }

    /// Consumes every credential owned by the host. Older callers deliberately
    /// keep using [`Self::into_parts`] and therefore cannot accidentally gain
    /// access to the newer inline-proxy secret.
    #[must_use]
    pub fn into_proxy_parts(
        self,
    ) -> (
        SavedHost,
        Option<SecretValue>,
        LegacyCredentialDisposition,
        Option<SecretValue>,
        LegacyProxyCredentialDisposition,
    ) {
        (
            self.host,
            self.ssh_password,
            self.credential_disposition,
            self.inline_proxy_password,
            self.inline_proxy_credential_disposition,
        )
    }

    /// Consumes every direct credential candidate owned by the host. Telnet
    /// and SSH passwords remain separate even when the legacy Telnet record
    /// fell back from `telnetPassword` to the old `password` field.
    #[must_use]
    pub fn into_all_credential_parts(
        self,
    ) -> (
        SavedHost,
        Option<SecretValue>,
        LegacyCredentialDisposition,
        Option<SecretValue>,
        LegacyCredentialDisposition,
        Option<SecretValue>,
        LegacyProxyCredentialDisposition,
    ) {
        (
            self.host,
            self.ssh_password,
            self.credential_disposition,
            self.telnet_password,
            self.telnet_credential_disposition,
            self.inline_proxy_password,
            self.inline_proxy_credential_disposition,
        )
    }
}

/// A validated reference-file SSH-key record retained only at the trusted
/// migration boundary. Labels, paths, and opaque IDs never enter the preview.
/// This wrapper intentionally implements neither `Debug`, `Clone`, nor Serde.
///
/// ```compile_fail
/// use netcatty_migration::parse_legacy_vault;
/// let document = parse_legacy_vault(
///     br#"{"hosts":[],"keys":[{"id":"key","label":"Key","source":"reference","category":"key","created":1,"filePath":"key-file"}],"identities":[]}"#,
///     1,
/// ).unwrap();
/// println!("{:?}", document.ssh_key_reference_candidates()[0]);
/// ```
pub struct LegacySshKeyReferenceCandidate {
    reference: SavedSshKeyReference,
}

impl LegacySshKeyReferenceCandidate {
    #[must_use]
    pub fn reference(&self) -> &SavedSshKeyReference {
        &self.reference
    }

    #[must_use]
    pub fn into_reference(self) -> SavedSshKeyReference {
        self.reference
    }
}

/// Secret-free status for the optional passphrase attached to a managed SSH
/// key candidate. It never carries the passphrase itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LegacyManagedPassphraseDisposition {
    Absent,
    Saved,
    DiscardedByPolicy,
}

/// Trusted, secret-free metadata parsed for an embedded legacy SSH key.
///
/// This value deliberately has no Serde or `Debug` implementation because its
/// labels and opaque source IDs are not part of the renderer preview contract.
pub struct LegacyManagedSshKeyMetadata {
    id: SavedSshKeyReferenceId,
    label: String,
    category: SavedSshKeyCategory,
    source: SavedSshKeySource,
    passphrase_disposition: LegacyManagedPassphraseDisposition,
    created_at: u64,
    updated_at: u64,
    compatibility_fields: BTreeMap<String, Value>,
}

impl LegacyManagedSshKeyMetadata {
    #[must_use]
    pub fn id(&self) -> &SavedSshKeyReferenceId {
        &self.id
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    #[must_use]
    pub fn category(&self) -> &SavedSshKeyCategory {
        &self.category
    }

    #[must_use]
    pub fn source(&self) -> &SavedSshKeySource {
        &self.source
    }

    #[must_use]
    pub const fn passphrase_disposition(&self) -> LegacyManagedPassphraseDisposition {
        self.passphrase_disposition
    }

    #[must_use]
    pub const fn has_saved_passphrase(&self) -> bool {
        matches!(
            self.passphrase_disposition,
            LegacyManagedPassphraseDisposition::Saved
        )
    }

    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }

    #[must_use]
    pub const fn updated_at(&self) -> u64 {
        self.updated_at
    }

    #[must_use]
    pub fn compatibility_fields(&self) -> &BTreeMap<String, Value> {
        &self.compatibility_fields
    }

    /// Consumes the metadata into the arguments needed to construct the final
    /// Vault record after an encrypted blob locator and revision exist.
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        SavedSshKeyReferenceId,
        String,
        SavedSshKeyCategory,
        SavedSshKeySource,
        bool,
        u64,
        u64,
        BTreeMap<String, Value>,
    ) {
        let has_saved_passphrase = self.has_saved_passphrase();
        (
            self.id,
            self.label,
            self.category,
            self.source,
            has_saved_passphrase,
            self.created_at,
            self.updated_at,
            self.compatibility_fields,
        )
    }
}

/// A validated generated/imported SSH-key record and its zeroizing secret
/// bundle, retained only at the trusted Rust migration boundary.
///
/// The wrapper intentionally implements neither `Debug`, `Clone`, nor Serde.
/// Consume it only after the encrypted blob transaction is ready.
///
/// ```compile_fail
/// use netcatty_migration::parse_legacy_vault;
/// let document = parse_legacy_vault(
///     br#"{"hosts":[],"keys":[{"id":"key","label":"Key","source":"imported","category":"key","created":1,"privateKey":"PRIVATE"}],"identities":[]}"#,
///     1,
/// ).unwrap();
/// println!("{:?}", document.managed_ssh_key_candidates()[0]);
/// ```
///
/// ```compile_fail
/// use netcatty_migration::parse_legacy_vault;
/// let document = parse_legacy_vault(
///     br#"{"hosts":[],"keys":[{"id":"key","label":"Key","source":"imported","category":"key","created":1,"privateKey":"PRIVATE"}],"identities":[]}"#,
///     1,
/// ).unwrap();
/// let _ = serde_json::to_string(&document.managed_ssh_key_candidates()[0]);
/// ```
///
/// ```compile_fail
/// use netcatty_migration::parse_legacy_vault;
/// let document = parse_legacy_vault(
///     br#"{"hosts":[],"keys":[{"id":"key","label":"Key","source":"imported","category":"key","created":1,"privateKey":"PRIVATE"}],"identities":[]}"#,
///     1,
/// ).unwrap();
/// let _ = document.managed_ssh_key_candidates()[0].clone();
/// ```
pub struct LegacyManagedSshKeyCandidate {
    metadata: LegacyManagedSshKeyMetadata,
    secret_bundle: SshSecretBundle,
}

impl LegacyManagedSshKeyCandidate {
    #[must_use]
    pub fn metadata(&self) -> &LegacyManagedSshKeyMetadata {
        &self.metadata
    }

    #[must_use]
    pub fn secret_bundle(&self) -> &SshSecretBundle {
        &self.secret_bundle
    }

    #[must_use]
    pub fn into_parts(self) -> (LegacyManagedSshKeyMetadata, SshSecretBundle) {
        (self.metadata, self.secret_bundle)
    }
}

/// A validated key identity retained only at the trusted migration boundary.
/// This wrapper intentionally implements neither `Debug`, `Clone`, nor Serde.
///
/// ```compile_fail
/// use netcatty_migration::parse_legacy_vault;
/// let document = parse_legacy_vault(
///     br#"{"hosts":[],"keys":[{"id":"key","label":"Key","source":"reference","category":"key","created":1,"filePath":"key-file"}],"identities":[{"id":"identity","label":"Identity","username":"user","authMethod":"key","keyId":"key","created":1}]}"#,
///     1,
/// ).unwrap();
/// let _ = serde_json::to_string(&document.identity_reference_candidates()[0]);
/// ```
pub struct LegacyIdentityReferenceCandidate {
    reference: SavedIdentityReference,
}

impl LegacyIdentityReferenceCandidate {
    #[must_use]
    pub fn reference(&self) -> &SavedIdentityReference {
        &self.reference
    }

    #[must_use]
    pub fn into_reference(self) -> SavedIdentityReference {
        self.reference
    }
}

/// Secret-free classification for the password owned by a legacy password
/// identity. The plaintext itself is never stored in this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LegacyPasswordIdentityCredentialDisposition {
    PlaintextCandidate,
    ReentryRequiredEncrypted,
    ReentryRequiredMissing,
    ReentryRequiredInvalid,
    ReentryRequiredOversized,
}

impl LegacyPasswordIdentityCredentialDisposition {
    #[must_use]
    pub const fn requires_reentry(self) -> bool {
        !matches!(self, Self::PlaintextCandidate)
    }
}

/// A validated password identity plus an optional zeroizing password. The
/// identity contains metadata only and starts with `has_saved_credential =
/// false`; the trusted desktop transaction may set that bit only after OS
/// credential-store publication succeeds.
///
/// This wrapper intentionally implements neither `Debug`, `Clone`, nor Serde.
/// The only way to take ownership of plaintext is [`Self::into_parts`], which
/// returns it as [`SecretValue`].
///
/// ```compile_fail
/// use netcatty_migration::parse_legacy_vault;
/// let document = parse_legacy_vault(
///     br#"{"hosts":[],"identities":[{"id":"identity","label":"Identity","username":"user","authMethod":"password","password":"secret","created":1}]}"#,
///     1,
/// ).unwrap();
/// let _ = serde_json::to_string(&document.password_identity_candidates()[0]);
/// ```
///
/// ```compile_fail
/// use netcatty_migration::parse_legacy_vault;
/// let document = parse_legacy_vault(
///     br#"{"hosts":[],"identities":[{"id":"identity","label":"Identity","username":"user","authMethod":"password","password":"secret","created":1}]}"#,
///     1,
/// ).unwrap();
/// println!("{:?}", document.password_identity_candidates()[0]);
/// ```
///
/// ```compile_fail
/// use netcatty_migration::parse_legacy_vault;
/// let document = parse_legacy_vault(
///     br#"{"hosts":[],"identities":[{"id":"identity","label":"Identity","username":"user","authMethod":"password","password":"secret","created":1}]}"#,
///     1,
/// ).unwrap();
/// let _ = document.password_identity_candidates()[0].clone();
/// ```
pub struct LegacyPasswordIdentityCandidate {
    identity: SavedPasswordIdentity,
    password: Option<SecretValue>,
    credential_disposition: LegacyPasswordIdentityCredentialDisposition,
    ignored_residual_key_reference: bool,
}

impl LegacyPasswordIdentityCandidate {
    #[must_use]
    pub fn identity(&self) -> &SavedPasswordIdentity {
        &self.identity
    }

    #[must_use]
    pub fn id(&self) -> &SavedPasswordIdentityId {
        &self.identity.id
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.identity.label
    }

    #[must_use]
    pub fn username(&self) -> &str {
        &self.identity.username
    }

    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.identity.created_at
    }

    /// The legacy optional ordering value is retained exactly as compatibility
    /// metadata; this convenience view is intended only for legacy sorting.
    #[must_use]
    pub fn order(&self) -> Option<f64> {
        self.identity
            .compatibility_fields()
            .get("order")
            .and_then(Value::as_f64)
    }

    #[must_use]
    pub const fn credential_disposition(&self) -> LegacyPasswordIdentityCredentialDisposition {
        self.credential_disposition
    }

    #[must_use]
    pub const fn has_password_candidate(&self) -> bool {
        self.password.is_some()
    }

    #[must_use]
    pub const fn ignored_residual_key_reference(&self) -> bool {
        self.ignored_residual_key_reference
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        SavedPasswordIdentity,
        Option<SecretValue>,
        LegacyPasswordIdentityCredentialDisposition,
    ) {
        (self.identity, self.password, self.credential_disposition)
    }
}

/// Secret-free classification for a manually configured proxy password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LegacyProxyCredentialDisposition {
    None,
    PlaintextCandidate,
    ReentryRequiredEncrypted,
    ReentryRequiredMissing,
    ReentryRequiredInvalid,
    ReentryRequiredOversized,
}

impl LegacyProxyCredentialDisposition {
    #[must_use]
    pub const fn requires_reentry(self) -> bool {
        matches!(
            self,
            Self::ReentryRequiredEncrypted
                | Self::ReentryRequiredMissing
                | Self::ReentryRequiredInvalid
                | Self::ReentryRequiredOversized
        )
    }
}

/// A validated proxy profile plus an optional zeroizing manual password.
/// This wrapper intentionally implements neither `Debug`, `Clone`, nor Serde.
///
/// ```compile_fail
/// use netcatty_migration::parse_legacy_vault;
/// let document = parse_legacy_vault(
///     br#"{"hosts":[],"proxyProfiles":[{"id":"proxy","config":{"type":"http","host":"proxy.example","port":8080}}]}"#,
///     1,
/// ).unwrap();
/// println!("{:?}", document.proxy_profile_candidates()[0]);
/// ```
///
/// ```compile_fail
/// use netcatty_migration::parse_legacy_vault;
/// let document = parse_legacy_vault(
///     br#"{"hosts":[],"proxyProfiles":[{"id":"proxy","config":{"type":"http","host":"proxy.example","port":8080}}]}"#,
///     1,
/// ).unwrap();
/// let _ = serde_json::to_string(&document.proxy_profile_candidates()[0]);
/// ```
///
/// ```compile_fail
/// use netcatty_migration::parse_legacy_vault;
/// let document = parse_legacy_vault(
///     br#"{"hosts":[],"proxyProfiles":[{"id":"proxy","config":{"type":"http","host":"proxy.example","port":8080}}]}"#,
///     1,
/// ).unwrap();
/// fn assert_clone<T: Clone>(_: &T) {}
/// assert_clone(&document.proxy_profile_candidates()[0]);
/// ```
pub struct LegacyProxyProfileCandidate {
    profile: SavedProxyProfile,
    password: Option<SecretValue>,
    credential_disposition: LegacyProxyCredentialDisposition,
}

impl LegacyProxyProfileCandidate {
    #[must_use]
    pub fn profile(&self) -> &SavedProxyProfile {
        &self.profile
    }

    #[must_use]
    pub const fn has_password_candidate(&self) -> bool {
        self.password.is_some()
    }

    #[must_use]
    pub const fn credential_disposition(&self) -> LegacyProxyCredentialDisposition {
        self.credential_disposition
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        SavedProxyProfile,
        Option<SecretValue>,
        LegacyProxyCredentialDisposition,
    ) {
        (self.profile, self.password, self.credential_disposition)
    }
}

/// Parsed source document. It retains only validated candidates and a safe
/// preview; it never retains an outer safeStorage ciphertext.
///
/// This type intentionally implements neither `Debug`, `Clone`, nor Serde
/// serialization.
///
/// ```compile_fail
/// use netcatty_migration::parse_legacy_vault;
/// let document = parse_legacy_vault(b"[]", 1).unwrap();
/// println!("{document:?}");
/// ```
///
/// ```compile_fail
/// use netcatty_migration::parse_legacy_vault;
/// let document = parse_legacy_vault(b"[]", 1).unwrap();
/// let _ = serde_json::to_string(&document);
/// ```
///
/// ```compile_fail
/// use netcatty_migration::parse_legacy_vault;
/// let document = parse_legacy_vault(b"[]", 1).unwrap();
/// let _ = document.clone();
/// ```
pub struct LegacyVaultDocument {
    source_sha256: [u8; 32],
    preview: LegacyVaultPreview,
    candidates: Vec<LegacyHostCandidate>,
    managed_key_host_candidates: Vec<LegacyHostCandidate>,
    unsupported_candidates: Vec<LegacyHostCandidate>,
    ssh_key_reference_candidates: Vec<LegacySshKeyReferenceCandidate>,
    managed_ssh_key_candidates: Vec<LegacyManagedSshKeyCandidate>,
    identity_reference_candidates: Vec<LegacyIdentityReferenceCandidate>,
    managed_identity_reference_candidates: Vec<LegacyIdentityReferenceCandidate>,
    password_identity_candidates: Vec<LegacyPasswordIdentityCandidate>,
    password_identity_host_candidates: Vec<LegacyHostCandidate>,
    proxy_profile_candidates: Vec<LegacyProxyProfileCandidate>,
    group_catalogs: LegacyGroupCatalogCandidates,
    notes_snippets: LegacyNotesSnippetsCandidates,
}

impl LegacyVaultDocument {
    /// Borrows the SHA-256 digest of the exact outer source bytes. The digest
    /// is deliberately retained only by this non-serializable document so a
    /// trusted adapter can bind an inspection to a later re-read without
    /// putting the raw digest in a renderer-safe preview.
    #[must_use]
    pub const fn source_sha256(&self) -> &[u8; 32] {
        &self.source_sha256
    }

    #[must_use]
    pub fn preview(&self) -> &LegacyVaultPreview {
        &self.preview
    }

    #[must_use]
    pub fn candidates(&self) -> &[LegacyHostCandidate] {
        &self.candidates
    }

    /// Hosts whose authentication graph depends on an embedded managed key.
    /// They are deliberately absent from [`Self::candidates`] so the older
    /// reference-only desktop adapter cannot publish half of the graph.
    #[must_use]
    pub fn managed_key_host_candidates(&self) -> &[LegacyHostCandidate] {
        &self.managed_key_host_candidates
    }

    /// Valid, uniquely-ID'd records whose protocol/authentication mode is
    /// faithfully preserved but not yet supported by the current connector.
    #[must_use]
    pub fn unsupported_candidates(&self) -> &[LegacyHostCandidate] {
        &self.unsupported_candidates
    }

    /// Sensitive catalog metadata for the trusted Tauri adapter. Inspection
    /// code must never serialize these values into a renderer response.
    #[must_use]
    pub fn ssh_key_reference_candidates(&self) -> &[LegacySshKeyReferenceCandidate] {
        &self.ssh_key_reference_candidates
    }

    /// Secret-bearing embedded-key candidates for the trusted Rust import
    /// transaction. These values must never cross the renderer boundary.
    #[must_use]
    pub fn managed_ssh_key_candidates(&self) -> &[LegacyManagedSshKeyCandidate] {
        &self.managed_ssh_key_candidates
    }

    /// Sensitive catalog metadata for the trusted Tauri adapter. Inspection
    /// code must never serialize these values into a renderer response.
    #[must_use]
    pub fn identity_reference_candidates(&self) -> &[LegacyIdentityReferenceCandidate] {
        &self.identity_reference_candidates
    }

    /// Identity records backed by managed key candidates. The established
    /// reference-only accessor excludes these fail-closed.
    #[must_use]
    pub fn managed_identity_reference_candidates(&self) -> &[LegacyIdentityReferenceCandidate] {
        &self.managed_identity_reference_candidates
    }

    /// Password identities are kept separate from key/certificate identities
    /// and are available only to the trusted Rust migration coordinator.
    #[must_use]
    pub fn password_identity_candidates(&self) -> &[LegacyPasswordIdentityCandidate] {
        &self.password_identity_candidates
    }

    /// Hosts depending on the password-identity catalog are excluded from all
    /// older graph-consuming APIs so an older coordinator cannot publish a
    /// dangling identity edge.
    #[must_use]
    pub fn password_identity_host_candidates(&self) -> &[LegacyHostCandidate] {
        &self.password_identity_host_candidates
    }

    /// Proxy profiles and their manual passwords remain available only to the
    /// trusted Rust migration coordinator.
    #[must_use]
    pub fn proxy_profile_candidates(&self) -> &[LegacyProxyProfileCandidate] {
        &self.proxy_profile_candidates
    }

    /// `None` means the source omitted `customGroups`; `Some(&[])` means it
    /// explicitly supplied an empty replacement catalog.
    #[must_use]
    pub fn custom_groups(&self) -> Option<&[netcatty_vault::SavedGroupPath]> {
        self.group_catalogs.custom_groups()
    }

    /// Group defaults and their isolated credential candidates remain inside
    /// the trusted, non-serializable document boundary.
    #[must_use]
    pub fn group_config_candidates(&self) -> Option<&[LegacyGroupConfigCandidate]> {
        self.group_catalogs.group_configs()
    }

    /// Parsed Notes/Scripts catalogs remain inside the trusted document. The
    /// contained commands and note bodies are never part of the renderer-safe
    /// preview.
    #[must_use]
    pub fn notes_snippets_candidates(&self) -> &LegacyNotesSnippetsCandidates {
        &self.notes_snippets
    }

    /// Consumes only the group slice while preserving all established graph
    /// tuple APIs for older coordinators.
    #[must_use]
    pub fn into_group_catalog_parts(self) -> (LegacyVaultPreview, LegacyGroupCatalogCandidates) {
        (self.preview, self.group_catalogs)
    }

    /// Consumes only the legacy Notes/Scripts slice. Existing graph tuple APIs
    /// intentionally keep their established shapes.
    #[must_use]
    pub fn into_notes_snippets_parts(self) -> (LegacyVaultPreview, LegacyNotesSnippetsCandidates) {
        (self.preview, self.notes_snippets)
    }

    #[must_use]
    pub fn into_candidates(self) -> Vec<LegacyHostCandidate> {
        self.candidates
    }

    #[must_use]
    pub fn into_parts(self) -> (LegacyVaultPreview, Vec<LegacyHostCandidate>) {
        (self.preview, self.candidates)
    }

    #[must_use]
    pub fn into_all_parts(
        self,
    ) -> (
        LegacyVaultPreview,
        Vec<LegacyHostCandidate>,
        Vec<LegacyHostCandidate>,
    ) {
        (self.preview, self.candidates, self.unsupported_candidates)
    }

    /// Consumes the complete supported relationship graph while keeping the
    /// established host-only accessors intact for the previous import slice.
    #[must_use]
    pub fn into_graph_parts(
        self,
    ) -> (
        LegacyVaultPreview,
        Vec<LegacyHostCandidate>,
        Vec<LegacySshKeyReferenceCandidate>,
        Vec<LegacyIdentityReferenceCandidate>,
    ) {
        (
            self.preview,
            self.candidates,
            self.ssh_key_reference_candidates,
            self.identity_reference_candidates,
        )
    }

    /// Consumes reference and managed key candidates together. The older
    /// [`Self::into_graph_parts`] shape remains unchanged for callers that
    /// implement only the established reference-file slice.
    #[must_use]
    pub fn into_complete_graph_parts(
        mut self,
    ) -> (
        LegacyVaultPreview,
        Vec<LegacyHostCandidate>,
        Vec<LegacySshKeyReferenceCandidate>,
        Vec<LegacyManagedSshKeyCandidate>,
        Vec<LegacyIdentityReferenceCandidate>,
    ) {
        self.candidates
            .append(&mut self.managed_key_host_candidates);
        self.identity_reference_candidates
            .append(&mut self.managed_identity_reference_candidates);
        (
            self.preview,
            self.candidates,
            self.ssh_key_reference_candidates,
            self.managed_ssh_key_candidates,
            self.identity_reference_candidates,
        )
    }

    /// Consumes the complete graph including the new password-identity slice.
    /// Existing graph APIs intentionally retain their earlier tuple shapes and
    /// continue to exclude password-identity dependencies fail-closed.
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn into_password_identity_graph_parts(
        mut self,
    ) -> (
        LegacyVaultPreview,
        Vec<LegacyHostCandidate>,
        Vec<LegacySshKeyReferenceCandidate>,
        Vec<LegacyManagedSshKeyCandidate>,
        Vec<LegacyIdentityReferenceCandidate>,
        Vec<LegacyPasswordIdentityCandidate>,
    ) {
        self.candidates
            .append(&mut self.managed_key_host_candidates);
        self.candidates
            .append(&mut self.password_identity_host_candidates);
        self.identity_reference_candidates
            .append(&mut self.managed_identity_reference_candidates);
        (
            self.preview,
            self.candidates,
            self.ssh_key_reference_candidates,
            self.managed_ssh_key_candidates,
            self.identity_reference_candidates,
            self.password_identity_candidates,
        )
    }

    /// Consumes every currently supported legacy graph catalog, including
    /// proxy profiles and host inline-proxy candidates. Earlier tuple APIs
    /// intentionally retain their established shapes.
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn into_proxy_graph_parts(
        mut self,
    ) -> (
        LegacyVaultPreview,
        Vec<LegacyHostCandidate>,
        Vec<LegacySshKeyReferenceCandidate>,
        Vec<LegacyManagedSshKeyCandidate>,
        Vec<LegacyIdentityReferenceCandidate>,
        Vec<LegacyPasswordIdentityCandidate>,
        Vec<LegacyProxyProfileCandidate>,
    ) {
        self.candidates
            .append(&mut self.managed_key_host_candidates);
        self.candidates
            .append(&mut self.password_identity_host_candidates);
        self.identity_reference_candidates
            .append(&mut self.managed_identity_reference_candidates);
        (
            self.preview,
            self.candidates,
            self.ssh_key_reference_candidates,
            self.managed_ssh_key_candidates,
            self.identity_reference_candidates,
            self.password_identity_candidates,
            self.proxy_profile_candidates,
        )
    }

    /// Consumes every currently parsed legacy Vault graph slice in one call.
    /// This is the trusted desktop-orchestration boundary for an atomic import:
    /// commands, note bodies, group credential candidates, and secret-bearing
    /// entity candidates remain inside Rust and are never renderer DTOs.
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn into_current_graph_parts(
        mut self,
    ) -> (
        LegacyVaultPreview,
        Vec<LegacyHostCandidate>,
        Vec<LegacySshKeyReferenceCandidate>,
        Vec<LegacyManagedSshKeyCandidate>,
        Vec<LegacyIdentityReferenceCandidate>,
        Vec<LegacyPasswordIdentityCandidate>,
        Vec<LegacyProxyProfileCandidate>,
        LegacyGroupCatalogCandidates,
        LegacyNotesSnippetsCandidates,
    ) {
        self.candidates
            .append(&mut self.managed_key_host_candidates);
        self.candidates
            .append(&mut self.password_identity_host_candidates);
        self.identity_reference_candidates
            .append(&mut self.managed_identity_reference_candidates);
        (
            self.preview,
            self.candidates,
            self.ssh_key_reference_candidates,
            self.managed_ssh_key_candidates,
            self.identity_reference_candidates,
            self.password_identity_candidates,
            self.proxy_profile_candidates,
            self.group_catalogs,
            self.notes_snippets,
        )
    }
}

/// Parse one supported legacy Vault source without writing either Vault or an
/// OS credential store. `now_ms` is used only to fill missing timestamps.
///
/// The caller retains ownership of `input`; when it came from a plaintext
/// file, the owning adapter must zeroize its mutable read buffer after this
/// function returns. Parsed secret fields owned by this crate are zeroized or
/// moved into [`SecretValue`].
pub fn parse_legacy_vault(
    input: &[u8],
    now_ms: u64,
) -> Result<LegacyVaultDocument, LegacyVaultError> {
    if input.len() > MAX_LEGACY_BACKUP_BYTES {
        return Err(LegacyVaultError::new(LegacyVaultErrorCode::InputTooLarge));
    }

    let source_sha256 = sha256_digest(input);
    let text = std::str::from_utf8(input)
        .map_err(|_| LegacyVaultError::new(LegacyVaultErrorCode::InvalidUtf8))?;
    let root: Value = serde_json::from_str(text)
        .map_err(|_| LegacyVaultError::new(LegacyVaultErrorCode::InvalidJson))?;

    match root {
        Value::Array(hosts) => {
            if let Err(error) = enforce_plaintext_limit(input.len()) {
                let mut value = Value::Array(hosts);
                zeroize_value(&mut value);
                return Err(error);
            }
            parse_catalog_values(
                LegacyCatalogValues::hosts_only(hosts),
                LegacyVaultSourceKind::BareHostArray,
                source_sha256,
                now_ms,
            )
        }
        Value::Object(object) => {
            if object.contains_key("formatVersion") {
                parse_versioned_envelope(object, source_sha256, now_ms)
            } else {
                if let Err(error) = enforce_plaintext_limit(input.len()) {
                    let mut value = Value::Object(object);
                    zeroize_value(&mut value);
                    return Err(error);
                }
                let catalogs = take_unversioned_catalogs(object)?;
                parse_catalog_values(
                    catalogs,
                    LegacyVaultSourceKind::UnversionedVault,
                    source_sha256,
                    now_ms,
                )
            }
        }
        mut unsupported => {
            zeroize_value(&mut unsupported);
            Err(LegacyVaultError::new(LegacyVaultErrorCode::InvalidRoot))
        }
    }
}

/// Convenience wrapper for already-decoded UTF-8 input.
pub fn parse_legacy_vault_str(
    input: &str,
    now_ms: u64,
) -> Result<LegacyVaultDocument, LegacyVaultError> {
    parse_legacy_vault(input.as_bytes(), now_ms)
}

fn parse_versioned_envelope(
    mut object: Map<String, Value>,
    source_sha256: [u8; 32],
    now_ms: u64,
) -> Result<LegacyVaultDocument, LegacyVaultError> {
    let mut version_value = object.remove("formatVersion").unwrap_or(Value::Null);
    let version = version_value.as_u64();
    zeroize_value(&mut version_value);
    if version != Some(FORMAT_VERSION_V1) {
        let mut remaining = Value::Object(object);
        zeroize_value(&mut remaining);
        return Err(LegacyVaultError::new(
            LegacyVaultErrorCode::UnsupportedFormatVersion,
        ));
    }

    let mut encoding = match object.remove("payloadEncoding") {
        Some(Value::String(encoding)) => encoding,
        Some(mut invalid) => {
            zeroize_value(&mut invalid);
            let mut remaining = Value::Object(object);
            zeroize_value(&mut remaining);
            return Err(LegacyVaultError::new(LegacyVaultErrorCode::InvalidEnvelope));
        }
        None => {
            let mut remaining = Value::Object(object);
            zeroize_value(&mut remaining);
            return Err(LegacyVaultError::new(LegacyVaultErrorCode::InvalidEnvelope));
        }
    };
    let encoding_kind = match encoding.as_str() {
        PLAIN_JSON_V1 => 1_u8,
        SAFE_STORAGE_V1 => 2_u8,
        _ => 0_u8,
    };
    encoding.zeroize();

    match encoding_kind {
        1 => {
            let payload_value = object.remove("payloadData");
            let mut remaining = Value::Object(object);
            zeroize_value(&mut remaining);
            let mut payload = match payload_value {
                Some(Value::String(payload)) => payload,
                Some(mut value) => {
                    zeroize_value(&mut value);
                    return Err(LegacyVaultError::new(
                        LegacyVaultErrorCode::InvalidPayloadData,
                    ));
                }
                None => {
                    return Err(LegacyVaultError::new(
                        LegacyVaultErrorCode::InvalidPayloadData,
                    ));
                }
            };
            if payload.len() > MAX_LEGACY_PLAINTEXT_BYTES {
                payload.zeroize();
                return Err(LegacyVaultError::new(
                    LegacyVaultErrorCode::PlaintextPayloadTooLarge,
                ));
            }
            let parsed_payload = serde_json::from_str(&payload);
            payload.zeroize();
            let payload_root: Value = parsed_payload
                .map_err(|_| LegacyVaultError::new(LegacyVaultErrorCode::InvalidPayloadData))?;
            let catalogs = match payload_root {
                Value::Array(hosts) => LegacyCatalogValues::hosts_only(hosts),
                Value::Object(payload_object) if !payload_object.contains_key("formatVersion") => {
                    take_unversioned_catalogs(payload_object)?
                }
                mut unsupported => {
                    zeroize_value(&mut unsupported);
                    return Err(LegacyVaultError::new(
                        LegacyVaultErrorCode::InvalidPayloadData,
                    ));
                }
            };
            parse_catalog_values(
                catalogs,
                LegacyVaultSourceKind::VersionedPlainJsonV1,
                source_sha256,
                now_ms,
            )
        }
        2 => {
            // Validate only that an opaque payload exists. Never base64-decode,
            // JSON-parse, retain, decrypt, or otherwise guess at its contents.
            let mut ciphertext = match object.remove("payloadData") {
                Some(Value::String(ciphertext)) => ciphertext,
                Some(mut invalid) => {
                    zeroize_value(&mut invalid);
                    let mut remaining = Value::Object(object);
                    zeroize_value(&mut remaining);
                    return Err(LegacyVaultError::new(
                        LegacyVaultErrorCode::InvalidPayloadData,
                    ));
                }
                None => {
                    let mut remaining = Value::Object(object);
                    zeroize_value(&mut remaining);
                    return Err(LegacyVaultError::new(
                        LegacyVaultErrorCode::InvalidPayloadData,
                    ));
                }
            };
            ciphertext.zeroize();
            let mut remaining = Value::Object(object);
            zeroize_value(&mut remaining);
            Ok(LegacyVaultDocument {
                source_sha256,
                preview: LegacyVaultPreview {
                    source_kind: LegacyVaultSourceKind::SafeStorageV1,
                    source_count: 0,
                    importable_count: 0,
                    duplicate_count: 0,
                    conflict_count: 0,
                    recoverable_credential_count: 0,
                    requires_credential_reentry_count: 0,
                    unsupported_count: 0,
                    issues: vec![LegacyVaultIssue {
                        code: LegacyVaultIssueCode::SourceRecoveryRequired,
                        message: LegacyVaultIssueCode::SourceRecoveryRequired
                            .message()
                            .to_owned(),
                        record_kind: LegacyVaultRecordKind::Source,
                        record_index: None,
                    }],
                    omitted_issue_count: 0,
                    counts: LegacyVaultCounts::default(),
                },
                candidates: Vec::new(),
                managed_key_host_candidates: Vec::new(),
                unsupported_candidates: Vec::new(),
                ssh_key_reference_candidates: Vec::new(),
                managed_ssh_key_candidates: Vec::new(),
                identity_reference_candidates: Vec::new(),
                managed_identity_reference_candidates: Vec::new(),
                password_identity_candidates: Vec::new(),
                password_identity_host_candidates: Vec::new(),
                proxy_profile_candidates: Vec::new(),
                group_catalogs: LegacyGroupCatalogCandidates::absent(),
                notes_snippets: LegacyNotesSnippetsCandidates::absent(),
            })
        }
        _ => {
            let mut remaining = Value::Object(object);
            zeroize_value(&mut remaining);
            Err(LegacyVaultError::new(
                LegacyVaultErrorCode::UnsupportedPayloadEncoding,
            ))
        }
    }
}

struct LegacyCatalogValues {
    hosts: Vec<Value>,
    ssh_keys: Vec<Value>,
    identities: Vec<Value>,
    proxy_profiles: Vec<Value>,
    custom_groups: Option<Value>,
    group_configs: Option<Value>,
    snippets: Option<Value>,
    snippet_packages: Option<Value>,
    notes: Option<Value>,
    note_groups: Option<Value>,
}

impl LegacyCatalogValues {
    fn hosts_only(hosts: Vec<Value>) -> Self {
        Self {
            hosts,
            ssh_keys: Vec::new(),
            identities: Vec::new(),
            proxy_profiles: Vec::new(),
            custom_groups: None,
            group_configs: None,
            snippets: None,
            snippet_packages: None,
            notes: None,
            note_groups: None,
        }
    }
}

fn zeroize_catalog_values(catalogs: &mut LegacyCatalogValues) {
    for value in catalogs
        .hosts
        .iter_mut()
        .chain(catalogs.ssh_keys.iter_mut())
        .chain(catalogs.identities.iter_mut())
        .chain(catalogs.proxy_profiles.iter_mut())
    {
        zeroize_value(value);
    }
    catalogs.hosts.clear();
    catalogs.ssh_keys.clear();
    catalogs.identities.clear();
    catalogs.proxy_profiles.clear();
    zeroize_optional_value(catalogs.custom_groups.take());
    zeroize_optional_value(catalogs.group_configs.take());
    zeroize_optional_value(catalogs.snippets.take());
    zeroize_optional_value(catalogs.snippet_packages.take());
    zeroize_optional_value(catalogs.notes.take());
    zeroize_optional_value(catalogs.note_groups.take());
}

fn take_unversioned_catalogs(
    mut object: Map<String, Value>,
) -> Result<LegacyCatalogValues, LegacyVaultError> {
    let mut hosts = match take_required_array(&mut object, "hosts") {
        Ok(hosts) => hosts,
        Err(error) => {
            let mut remaining = Value::Object(object);
            zeroize_value(&mut remaining);
            return Err(error);
        }
    };
    let mut ssh_keys = match take_optional_array(&mut object, "keys") {
        Ok(ssh_keys) => ssh_keys,
        Err(error) => {
            zeroize_values(&mut hosts);
            let mut remaining = Value::Object(object);
            zeroize_value(&mut remaining);
            return Err(error);
        }
    };
    let mut identities = match take_optional_array(&mut object, "identities") {
        Ok(identities) => identities,
        Err(error) => {
            zeroize_values(&mut hosts);
            zeroize_values(&mut ssh_keys);
            let mut remaining = Value::Object(object);
            zeroize_value(&mut remaining);
            return Err(error);
        }
    };
    let proxy_profiles = match take_optional_array(&mut object, "proxyProfiles") {
        Ok(proxy_profiles) => proxy_profiles,
        Err(error) => {
            zeroize_values(&mut hosts);
            zeroize_values(&mut ssh_keys);
            zeroize_values(&mut identities);
            let mut remaining = Value::Object(object);
            zeroize_value(&mut remaining);
            return Err(error);
        }
    };
    let custom_groups = object.remove("customGroups");
    let group_configs = object.remove("groupConfigs");
    let snippets = object.remove("snippets");
    let snippet_packages = object.remove("snippetPackages");
    let notes = object.remove("notes");
    let note_groups = object.remove("noteGroups");
    let mut remaining = Value::Object(object);
    zeroize_value(&mut remaining);
    Ok(LegacyCatalogValues {
        hosts,
        ssh_keys,
        identities,
        proxy_profiles,
        custom_groups,
        group_configs,
        snippets,
        snippet_packages,
        notes,
        note_groups,
    })
}

fn zeroize_values(values: &mut Vec<Value>) {
    for value in values.iter_mut() {
        zeroize_value(value);
    }
    values.clear();
}

fn take_required_array(
    object: &mut Map<String, Value>,
    key: &str,
) -> Result<Vec<Value>, LegacyVaultError> {
    match object.remove(key) {
        Some(Value::Array(values)) => Ok(values),
        Some(mut value) => {
            zeroize_value(&mut value);
            Err(LegacyVaultError::new(LegacyVaultErrorCode::InvalidRoot))
        }
        None => Err(LegacyVaultError::new(LegacyVaultErrorCode::InvalidRoot)),
    }
}

fn take_optional_array(
    object: &mut Map<String, Value>,
    key: &str,
) -> Result<Vec<Value>, LegacyVaultError> {
    match object.remove(key) {
        Some(Value::Array(values)) => Ok(values),
        Some(Value::Null) | None => Ok(Vec::new()),
        Some(mut value) => {
            zeroize_value(&mut value);
            Err(LegacyVaultError::new(LegacyVaultErrorCode::InvalidRoot))
        }
    }
}

fn enforce_plaintext_limit(size: usize) -> Result<(), LegacyVaultError> {
    if size > MAX_LEGACY_PLAINTEXT_BYTES {
        Err(LegacyVaultError::new(
            LegacyVaultErrorCode::PlaintextPayloadTooLarge,
        ))
    } else {
        Ok(())
    }
}

fn parse_catalog_values(
    mut catalogs: LegacyCatalogValues,
    source: LegacyVaultSourceKind,
    source_sha256: [u8; 32],
    now_ms: u64,
) -> Result<LegacyVaultDocument, LegacyVaultError> {
    if catalogs.hosts.len() > MAX_LEGACY_HOSTS {
        zeroize_catalog_values(&mut catalogs);
        return Err(LegacyVaultError::new(
            LegacyVaultErrorCode::HostLimitExceeded,
        ));
    }
    if catalogs.ssh_keys.len() > MAX_LEGACY_CATALOG_ENTITIES
        || catalogs.identities.len() > MAX_LEGACY_CATALOG_ENTITIES
        || catalogs.proxy_profiles.len() > MAX_LEGACY_CATALOG_ENTITIES
    {
        zeroize_catalog_values(&mut catalogs);
        return Err(LegacyVaultError::new(
            LegacyVaultErrorCode::CatalogLimitExceeded,
        ));
    }

    let notes_snippets = match parse_legacy_notes_snippets_catalogs(
        catalogs.snippets.take(),
        catalogs.snippet_packages.take(),
        catalogs.notes.take(),
        catalogs.note_groups.take(),
        now_ms,
    ) {
        Ok(candidates) => candidates,
        Err(error) => {
            zeroize_catalog_values(&mut catalogs);
            return Err(LegacyVaultError::new(match error.code {
                LegacyNotesSnippetsErrorCode::CatalogLimitExceeded => {
                    LegacyVaultErrorCode::CatalogLimitExceeded
                }
                _ => LegacyVaultErrorCode::InvalidNotesSnippetsCatalog,
            }));
        }
    };

    let source_custom_groups = catalogs
        .custom_groups
        .as_ref()
        .and_then(Value::as_array)
        .map_or(0, |values| values.len().min(u32::MAX as usize) as u32);
    let source_group_configs = catalogs
        .group_configs
        .as_ref()
        .and_then(Value::as_array)
        .map_or(0, |values| values.len().min(u32::MAX as usize) as u32);
    let custom_groups_value = catalogs.custom_groups.take();
    let group_configs_value = catalogs.group_configs.take();

    let mut counts = LegacyVaultCounts {
        source_hosts: catalogs.hosts.len() as u32,
        source_ssh_keys: catalogs.ssh_keys.len() as u32,
        source_identities: catalogs.identities.len() as u32,
        source_proxy_profiles: catalogs.proxy_profiles.len() as u32,
        source_custom_groups,
        source_group_configs,
        source_snippets: notes_snippets.source_snippet_count(),
        candidate_snippets: notes_snippets
            .catalog()
            .snippets()
            .map_or(0, |values| values.len().min(u32::MAX as usize) as u32),
        source_snippet_packages: notes_snippets.source_snippet_package_count(),
        candidate_snippet_packages: notes_snippets
            .catalog()
            .snippet_packages()
            .map_or(0, |values| values.len().min(u32::MAX as usize) as u32),
        source_notes: notes_snippets.source_note_count(),
        candidate_notes: notes_snippets
            .catalog()
            .notes()
            .map_or(0, |values| values.len().min(u32::MAX as usize) as u32),
        source_note_groups: notes_snippets.source_note_group_count(),
        candidate_note_groups: notes_snippets
            .catalog()
            .note_groups()
            .map_or(0, |values| values.len().min(u32::MAX as usize) as u32),
        ..LegacyVaultCounts::default()
    };
    let mut issues = Vec::new();
    let mut ssh_key_reference_candidates = Vec::with_capacity(catalogs.ssh_keys.len());
    let mut managed_ssh_key_candidates = Vec::with_capacity(catalogs.ssh_keys.len());
    let mut seen_key_ids = HashSet::new();
    for (index, value) in std::mem::take(&mut catalogs.ssh_keys)
        .into_iter()
        .enumerate()
    {
        let record_index = index as u32;
        let outcome = parse_ssh_key(value, now_ms);
        counts.secret_fields_stripped = counts
            .secret_fields_stripped
            .saturating_add(outcome.secret_fields_stripped);
        if outcome.secret_fields_stripped > 0 {
            push_typed_issue(
                &mut issues,
                LegacyVaultRecordKind::SshKey,
                LegacyVaultIssueCode::SecretMaterialStripped,
                record_index,
            );
        }
        let recovery_required = outcome
            .issues
            .contains(&LegacyVaultIssueCode::SshKeyCredentialRecoveryRequired);
        for code in outcome.issues {
            push_typed_issue(
                &mut issues,
                LegacyVaultRecordKind::SshKey,
                code,
                record_index,
            );
        }
        if recovery_required {
            counts.managed_ssh_key_recovery_required =
                counts.managed_ssh_key_recovery_required.saturating_add(1);
        }
        if let Some(id) = outcome.id {
            if !seen_key_ids.insert(id) {
                counts.duplicate_ssh_keys = counts.duplicate_ssh_keys.saturating_add(1);
                push_typed_issue(
                    &mut issues,
                    LegacyVaultRecordKind::SshKey,
                    LegacyVaultIssueCode::DuplicateSshKeyId,
                    record_index,
                );
                continue;
            }
        }
        match outcome.record {
            ParsedCatalogRecord::Candidate(ParsedSshKeyCandidate::Reference(candidate)) => {
                counts.candidate_ssh_key_references =
                    counts.candidate_ssh_key_references.saturating_add(1);
                ssh_key_reference_candidates.push(candidate);
            }
            ParsedCatalogRecord::Candidate(ParsedSshKeyCandidate::Managed(candidate)) => {
                counts.candidate_managed_ssh_keys =
                    counts.candidate_managed_ssh_keys.saturating_add(1);
                if candidate.metadata.passphrase_disposition
                    == LegacyManagedPassphraseDisposition::DiscardedByPolicy
                {
                    counts.managed_passphrases_discarded_by_policy = counts
                        .managed_passphrases_discarded_by_policy
                        .saturating_add(1);
                }
                managed_ssh_key_candidates.push(candidate);
            }
            ParsedCatalogRecord::Unsupported => {
                counts.unsupported_ssh_keys = counts.unsupported_ssh_keys.saturating_add(1);
                push_typed_issue(
                    &mut issues,
                    LegacyVaultRecordKind::SshKey,
                    LegacyVaultIssueCode::SshKeyUnsupported,
                    record_index,
                );
            }
            ParsedCatalogRecord::Rejected => {
                counts.rejected_ssh_keys = counts.rejected_ssh_keys.saturating_add(1);
                push_typed_issue(
                    &mut issues,
                    LegacyVaultRecordKind::SshKey,
                    LegacyVaultIssueCode::SshKeyRejected,
                    record_index,
                );
            }
        }
    }

    let mut available_keys = ssh_key_reference_candidates
        .iter()
        .map(|candidate| {
            (
                candidate.reference.id.as_str().to_owned(),
                AvailableSshKeyKind::Key,
            )
        })
        .collect::<HashMap<_, _>>();
    available_keys.extend(managed_ssh_key_candidates.iter().map(|candidate| {
        let kind = if candidate.metadata.category.is_certificate() {
            AvailableSshKeyKind::Certificate
        } else {
            AvailableSshKeyKind::Key
        };
        (candidate.metadata.id.as_str().to_owned(), kind)
    }));
    let managed_key_ids = managed_ssh_key_candidates
        .iter()
        .map(|candidate| candidate.metadata.id.as_str().to_owned())
        .collect::<HashSet<_>>();
    let available_key_ids = available_keys.keys().cloned().collect::<HashSet<_>>();
    let mut identity_reference_candidates = Vec::with_capacity(catalogs.identities.len());
    let mut managed_identity_reference_candidates = Vec::with_capacity(catalogs.identities.len());
    let mut password_identity_candidates = Vec::with_capacity(catalogs.identities.len());
    let mut seen_identity_ids = HashSet::new();
    for (index, value) in std::mem::take(&mut catalogs.identities)
        .into_iter()
        .enumerate()
    {
        let record_index = index as u32;
        let outcome = parse_identity(value, now_ms, &available_keys);
        counts.secret_fields_stripped = counts
            .secret_fields_stripped
            .saturating_add(outcome.secret_fields_stripped);
        if outcome.secret_fields_stripped > 0 {
            push_typed_issue(
                &mut issues,
                LegacyVaultRecordKind::Identity,
                LegacyVaultIssueCode::SecretMaterialStripped,
                record_index,
            );
        }
        for code in outcome.issues {
            if code == LegacyVaultIssueCode::MissingSshKeyReference {
                counts.missing_key_references = counts.missing_key_references.saturating_add(1);
            }
            push_typed_issue(
                &mut issues,
                LegacyVaultRecordKind::Identity,
                code,
                record_index,
            );
        }
        if let Some(id) = outcome.id {
            if !seen_identity_ids.insert(id) {
                counts.duplicate_identities = counts.duplicate_identities.saturating_add(1);
                push_typed_issue(
                    &mut issues,
                    LegacyVaultRecordKind::Identity,
                    LegacyVaultIssueCode::DuplicateIdentityId,
                    record_index,
                );
                continue;
            }
        }
        match outcome.record {
            ParsedCatalogRecord::Candidate(ParsedIdentityCandidate::Reference(candidate)) => {
                if managed_key_ids.contains(candidate.reference.key_id.as_str()) {
                    counts.candidate_managed_identity_references = counts
                        .candidate_managed_identity_references
                        .saturating_add(1);
                    counts.unsupported_identities = counts.unsupported_identities.saturating_add(1);
                    push_typed_issue(
                        &mut issues,
                        LegacyVaultRecordKind::Identity,
                        LegacyVaultIssueCode::IdentityUnsupported,
                        record_index,
                    );
                    managed_identity_reference_candidates.push(candidate);
                } else {
                    counts.candidate_identity_references =
                        counts.candidate_identity_references.saturating_add(1);
                    identity_reference_candidates.push(candidate);
                }
            }
            ParsedCatalogRecord::Candidate(ParsedIdentityCandidate::Password(candidate)) => {
                counts.candidate_password_identities =
                    counts.candidate_password_identities.saturating_add(1);
                if candidate.has_password_candidate() {
                    counts.password_identity_password_candidates = counts
                        .password_identity_password_candidates
                        .saturating_add(1);
                }
                if candidate.credential_disposition().requires_reentry() {
                    counts.password_identity_credential_reentry_required = counts
                        .password_identity_credential_reentry_required
                        .saturating_add(1);
                }
                if candidate.ignored_residual_key_reference() {
                    counts.password_identity_residual_key_references = counts
                        .password_identity_residual_key_references
                        .saturating_add(1);
                }
                password_identity_candidates.push(candidate);
            }
            ParsedCatalogRecord::Unsupported => {
                counts.unsupported_identities = counts.unsupported_identities.saturating_add(1);
                push_typed_issue(
                    &mut issues,
                    LegacyVaultRecordKind::Identity,
                    LegacyVaultIssueCode::IdentityUnsupported,
                    record_index,
                );
            }
            ParsedCatalogRecord::Rejected => {
                counts.rejected_identities = counts.rejected_identities.saturating_add(1);
                push_typed_issue(
                    &mut issues,
                    LegacyVaultRecordKind::Identity,
                    LegacyVaultIssueCode::IdentityRejected,
                    record_index,
                );
            }
        }
    }

    let mut available_identity_ids = identity_reference_candidates
        .iter()
        .chain(managed_identity_reference_candidates.iter())
        .map(|candidate| candidate.reference.id.as_str().to_owned())
        .collect::<HashSet<_>>();
    available_identity_ids.extend(
        password_identity_candidates
            .iter()
            .map(|candidate| candidate.identity.id.as_str().to_owned()),
    );
    let managed_identity_ids = managed_identity_reference_candidates
        .iter()
        .map(|candidate| candidate.reference.id.as_str().to_owned())
        .collect::<HashSet<_>>();
    let mut available_identity_usernames = identity_reference_candidates
        .iter()
        .chain(managed_identity_reference_candidates.iter())
        .map(|candidate| {
            (
                candidate.reference.id.as_str().to_owned(),
                candidate.reference.username.clone(),
            )
        })
        .collect::<HashMap<_, _>>();
    available_identity_usernames.extend(password_identity_candidates.iter().map(|candidate| {
        (
            candidate.identity.id.as_str().to_owned(),
            candidate.identity.username.clone(),
        )
    }));
    let mut available_identity_auth_methods = identity_reference_candidates
        .iter()
        .chain(managed_identity_reference_candidates.iter())
        .map(|candidate| {
            (
                candidate.reference.id.as_str().to_owned(),
                candidate.reference.auth_method.as_str().to_owned(),
            )
        })
        .collect::<HashMap<_, _>>();
    available_identity_auth_methods.extend(password_identity_candidates.iter().map(|candidate| {
        (
            candidate.identity.id.as_str().to_owned(),
            "password".to_owned(),
        )
    }));
    let password_identity_ids = password_identity_candidates
        .iter()
        .map(|candidate| candidate.identity.id.as_str().to_owned())
        .collect::<HashSet<_>>();
    let mut proxy_profile_candidates = Vec::with_capacity(catalogs.proxy_profiles.len());
    let mut seen_proxy_profile_ids = HashSet::new();
    for (index, value) in std::mem::take(&mut catalogs.proxy_profiles)
        .into_iter()
        .enumerate()
    {
        let record_index = index as u32;
        let outcome = parse_proxy_profile(
            value,
            now_ms,
            &available_identity_ids,
            &password_identity_ids,
        );
        counts.secret_fields_stripped = counts
            .secret_fields_stripped
            .saturating_add(outcome.secret_fields_stripped);
        if outcome.secret_fields_stripped > 0 {
            push_typed_issue(
                &mut issues,
                LegacyVaultRecordKind::ProxyProfile,
                LegacyVaultIssueCode::SecretMaterialStripped,
                record_index,
            );
        }
        for code in outcome.issues {
            if code == LegacyVaultIssueCode::MissingProxyIdentityReference {
                counts.missing_proxy_identity_references =
                    counts.missing_proxy_identity_references.saturating_add(1);
            }
            push_typed_issue(
                &mut issues,
                LegacyVaultRecordKind::ProxyProfile,
                code,
                record_index,
            );
        }
        if let Some(id) = outcome.id {
            if !seen_proxy_profile_ids.insert(id) {
                counts.duplicate_proxy_profiles = counts.duplicate_proxy_profiles.saturating_add(1);
                push_typed_issue(
                    &mut issues,
                    LegacyVaultRecordKind::ProxyProfile,
                    LegacyVaultIssueCode::DuplicateProxyProfileId,
                    record_index,
                );
                continue;
            }
        }
        match outcome.record {
            ParsedCatalogRecord::Candidate(candidate) => {
                counts.candidate_proxy_profiles = counts.candidate_proxy_profiles.saturating_add(1);
                if candidate.has_password_candidate() {
                    counts.proxy_profile_password_candidates =
                        counts.proxy_profile_password_candidates.saturating_add(1);
                }
                if candidate.credential_disposition().requires_reentry() {
                    counts.proxy_profile_credential_reentry_required = counts
                        .proxy_profile_credential_reentry_required
                        .saturating_add(1);
                }
                proxy_profile_candidates.push(candidate);
            }
            ParsedCatalogRecord::Unsupported => {
                counts.unsupported_proxy_profiles =
                    counts.unsupported_proxy_profiles.saturating_add(1);
                push_typed_issue(
                    &mut issues,
                    LegacyVaultRecordKind::ProxyProfile,
                    LegacyVaultIssueCode::ProxyProfileUnsupported,
                    record_index,
                );
            }
            ParsedCatalogRecord::Rejected => {
                counts.rejected_proxy_profiles = counts.rejected_proxy_profiles.saturating_add(1);
                push_typed_issue(
                    &mut issues,
                    LegacyVaultRecordKind::ProxyProfile,
                    LegacyVaultIssueCode::ProxyProfileRejected,
                    record_index,
                );
            }
        }
    }
    let available_proxy_profile_ids = proxy_profile_candidates
        .iter()
        .map(|candidate| candidate.profile.id.as_str().to_owned())
        .collect::<HashSet<_>>();
    let group_catalogs = match parse_legacy_group_catalogs(
        custom_groups_value,
        group_configs_value,
        &source_sha256,
        now_ms,
        LegacyGroupConfigReferences::new(&available_identity_ids, &password_identity_ids),
    ) {
        Ok(group_catalogs) => group_catalogs,
        Err(error) => {
            // The group parser owns and scrubs both group catalog values on
            // failure. Explicitly scrub every raw catalog value still owned
            // here (notably hosts) before returning the renderer-safe error.
            zeroize_catalog_values(&mut catalogs);
            return Err(LegacyVaultError::new(match error.code {
                LegacyGroupConfigParseErrorCode::CatalogLimitExceeded => {
                    LegacyVaultErrorCode::CatalogLimitExceeded
                }
                _ => LegacyVaultErrorCode::InvalidRoot,
            }));
        }
    };
    counts.candidate_custom_groups = group_catalogs
        .custom_groups()
        .map_or(0, |paths| paths.len().min(u32::MAX as usize) as u32);
    if let Some(group_configs) = group_catalogs.group_configs() {
        counts.candidate_group_configs = group_configs.len().min(u32::MAX as usize) as u32;
        for (index, candidate) in group_configs.iter().enumerate() {
            let record_index = index.min(u32::MAX as usize) as u32;
            counts.secret_fields_stripped = counts
                .secret_fields_stripped
                .saturating_add(candidate.secret_fields_stripped());
            if candidate.secret_fields_stripped() > 0 {
                push_typed_issue(
                    &mut issues,
                    LegacyVaultRecordKind::GroupConfig,
                    LegacyVaultIssueCode::SecretMaterialStripped,
                    record_index,
                );
            }
            if candidate.has_ssh_password_candidate() {
                counts.group_config_ssh_password_candidates = counts
                    .group_config_ssh_password_candidates
                    .saturating_add(1);
            }
            if disposition_requires_reentry(candidate.ssh_credential_disposition()) {
                counts.group_config_ssh_credential_reentry_required = counts
                    .group_config_ssh_credential_reentry_required
                    .saturating_add(1);
                push_typed_issue(
                    &mut issues,
                    LegacyVaultRecordKind::GroupConfig,
                    LegacyVaultIssueCode::GroupConfigSshCredentialReentryRequired,
                    record_index,
                );
            }
            if candidate.has_telnet_password_candidate() {
                counts.group_config_telnet_password_candidates = counts
                    .group_config_telnet_password_candidates
                    .saturating_add(1);
            }
            if disposition_requires_reentry(candidate.telnet_credential_disposition()) {
                counts.group_config_telnet_credential_reentry_required = counts
                    .group_config_telnet_credential_reentry_required
                    .saturating_add(1);
                push_typed_issue(
                    &mut issues,
                    LegacyVaultRecordKind::GroupConfig,
                    LegacyVaultIssueCode::GroupConfigTelnetCredentialReentryRequired,
                    record_index,
                );
            }
            if candidate.has_inline_proxy_password_candidate() {
                counts.group_config_inline_proxy_password_candidates = counts
                    .group_config_inline_proxy_password_candidates
                    .saturating_add(1);
            }
            if candidate
                .inline_proxy_credential_disposition()
                .requires_reentry()
            {
                counts.group_config_inline_proxy_credential_reentry_required = counts
                    .group_config_inline_proxy_credential_reentry_required
                    .saturating_add(1);
                push_typed_issue(
                    &mut issues,
                    LegacyVaultRecordKind::GroupConfig,
                    LegacyVaultIssueCode::GroupConfigProxyCredentialReentryRequired,
                    record_index,
                );
            }
            if candidate.has_unresolved_inline_proxy_identity() {
                counts.missing_group_config_proxy_identity_references = counts
                    .missing_group_config_proxy_identity_references
                    .saturating_add(1);
                push_typed_issue(
                    &mut issues,
                    LegacyVaultRecordKind::GroupConfig,
                    LegacyVaultIssueCode::MissingProxyIdentityReference,
                    record_index,
                );
            }
        }
    }
    let relationships = AvailableLegacyRelationships {
        ssh_key_ids: &available_key_ids,
        ssh_key_kinds: &available_keys,
        identity_ids: &available_identity_ids,
        identity_usernames: &available_identity_usernames,
        identity_auth_methods: &available_identity_auth_methods,
        managed_key_ids: &managed_key_ids,
        managed_identity_ids: &managed_identity_ids,
        password_identity_ids: &password_identity_ids,
        proxy_profile_ids: &available_proxy_profile_ids,
    };
    let mut candidates = Vec::with_capacity(catalogs.hosts.len());
    let mut managed_key_host_candidates = Vec::new();
    let mut password_identity_host_candidates = Vec::new();
    let mut unsupported_candidates = Vec::new();
    let mut seen_ids = HashSet::new();

    for (index, value) in catalogs.hosts.into_iter().enumerate() {
        let host_index = index as u32;
        let outcome = parse_host(value, now_ms, &relationships);
        counts.secret_fields_stripped = counts
            .secret_fields_stripped
            .saturating_add(outcome.secret_fields_stripped);

        if outcome.secret_fields_stripped > 0 {
            push_issue(
                &mut issues,
                LegacyVaultIssueCode::SecretMaterialStripped,
                host_index,
            );
        }
        for code in outcome.issues {
            match code {
                LegacyVaultIssueCode::MissingSshKeyReference => {
                    counts.missing_key_references = counts.missing_key_references.saturating_add(1);
                }
                LegacyVaultIssueCode::MissingIdentityReference => {
                    counts.missing_identity_references =
                        counts.missing_identity_references.saturating_add(1);
                }
                LegacyVaultIssueCode::InvalidIdentityFilePaths => {
                    counts.invalid_identity_file_path_hosts =
                        counts.invalid_identity_file_path_hosts.saturating_add(1);
                }
                LegacyVaultIssueCode::MissingProxyProfileReference => {
                    counts.missing_proxy_profile_references =
                        counts.missing_proxy_profile_references.saturating_add(1);
                }
                LegacyVaultIssueCode::MissingProxyIdentityReference => {
                    counts.missing_proxy_identity_references =
                        counts.missing_proxy_identity_references.saturating_add(1);
                }
                _ => {}
            }
            push_issue(&mut issues, code, host_index);
        }

        let Some(candidate) = outcome.candidate else {
            counts.rejected_hosts = counts.rejected_hosts.saturating_add(1);
            push_issue(&mut issues, LegacyVaultIssueCode::HostRejected, host_index);
            continue;
        };

        let duplicate = !seen_ids.insert(candidate.host.id.as_str().to_owned());
        if duplicate {
            counts.duplicate_hosts = counts.duplicate_hosts.saturating_add(1);
            push_issue(
                &mut issues,
                LegacyVaultIssueCode::DuplicateHostId,
                host_index,
            );
            continue;
        }

        if candidate.requires_credential_reentry() {
            counts.credential_reentry_required_hosts =
                counts.credential_reentry_required_hosts.saturating_add(1);
        }
        if disposition_requires_reentry(candidate.telnet_credential_disposition()) {
            counts.telnet_credential_reentry_required =
                counts.telnet_credential_reentry_required.saturating_add(1);
        }
        if candidate.has_inline_proxy_password_candidate() {
            counts.inline_proxy_password_candidates =
                counts.inline_proxy_password_candidates.saturating_add(1);
        }
        if candidate
            .inline_proxy_credential_disposition()
            .requires_reentry()
        {
            counts.inline_proxy_credential_reentry_required = counts
                .inline_proxy_credential_reentry_required
                .saturating_add(1);
        }
        if candidate
            .host
            .proxy_config()
            .is_ok_and(|config| config.is_some())
        {
            counts.candidate_inline_proxy_hosts =
                counts.candidate_inline_proxy_hosts.saturating_add(1);
        }
        counts.candidate_hosts = counts.candidate_hosts.saturating_add(1);
        if host_depends_on_password_identity_graph(&candidate.host, &relationships) {
            counts.candidate_password_identity_hosts =
                counts.candidate_password_identity_hosts.saturating_add(1);
            counts.unsupported_hosts = counts.unsupported_hosts.saturating_add(1);
            push_issue(
                &mut issues,
                LegacyVaultIssueCode::HostUnsupported,
                host_index,
            );
            password_identity_host_candidates.push(candidate);
            continue;
        }
        if candidate.is_currently_importable() {
            if host_depends_on_managed_key_graph(&candidate.host, &relationships) {
                counts.candidate_managed_key_hosts =
                    counts.candidate_managed_key_hosts.saturating_add(1);
                counts.unsupported_hosts = counts.unsupported_hosts.saturating_add(1);
                push_issue(
                    &mut issues,
                    LegacyVaultIssueCode::HostUnsupported,
                    host_index,
                );
                managed_key_host_candidates.push(candidate);
                continue;
            }
            if candidate.has_ssh_password_candidate() {
                counts.ssh_password_candidates = counts.ssh_password_candidates.saturating_add(1);
            }
            if candidate.has_telnet_password_candidate() {
                counts.telnet_password_candidates =
                    counts.telnet_password_candidates.saturating_add(1);
            }
            candidates.push(candidate);
        } else {
            counts.unsupported_hosts = counts.unsupported_hosts.saturating_add(1);
            push_issue(
                &mut issues,
                LegacyVaultIssueCode::HostUnsupported,
                host_index,
            );
            unsupported_candidates.push(candidate);
        }
    }

    let unsupported_count = counts
        .rejected_hosts
        .saturating_add(counts.unsupported_hosts);
    let importable_count = counts
        .source_hosts
        .saturating_sub(unsupported_count)
        .saturating_sub(counts.duplicate_hosts);
    let omitted_issue_count = issues
        .len()
        .saturating_sub(MAX_LEGACY_PREVIEW_ISSUES)
        .min(u32::MAX as usize) as u32;
    issues.truncate(MAX_LEGACY_PREVIEW_ISSUES);
    let group_recoverable_credential_count = counts
        .group_config_ssh_password_candidates
        .saturating_add(counts.group_config_telnet_password_candidates)
        .saturating_add(counts.group_config_inline_proxy_password_candidates);
    let group_credential_reentry_count = counts
        .group_config_ssh_credential_reentry_required
        .saturating_add(counts.group_config_telnet_credential_reentry_required)
        .saturating_add(counts.group_config_inline_proxy_credential_reentry_required);

    Ok(LegacyVaultDocument {
        source_sha256,
        preview: LegacyVaultPreview {
            source_kind: source,
            source_count: counts.source_hosts,
            importable_count,
            duplicate_count: counts.duplicate_hosts,
            conflict_count: 0,
            recoverable_credential_count: counts
                .ssh_password_candidates
                .saturating_add(counts.telnet_password_candidates)
                .saturating_add(group_recoverable_credential_count),
            requires_credential_reentry_count: counts
                .credential_reentry_required_hosts
                .saturating_add(group_credential_reentry_count),
            unsupported_count,
            issues,
            omitted_issue_count,
            counts,
        },
        candidates,
        managed_key_host_candidates,
        unsupported_candidates,
        ssh_key_reference_candidates,
        managed_ssh_key_candidates,
        identity_reference_candidates,
        managed_identity_reference_candidates,
        password_identity_candidates,
        password_identity_host_candidates,
        proxy_profile_candidates,
        group_catalogs,
        notes_snippets,
    })
}

fn host_depends_on_managed_key_graph(
    host: &SavedHost,
    relationships: &AvailableLegacyRelationships<'_>,
) -> bool {
    if host.protocol.is_telnet() || host.protocol.is_serial() {
        return false;
    }
    host.compatibility_fields()
        .get("identityFileId")
        .and_then(Value::as_str)
        .is_some_and(|id| relationships.managed_key_ids.contains(id))
        || host
            .compatibility_fields()
            .get("identityId")
            .and_then(Value::as_str)
            .is_some_and(|id| relationships.managed_identity_ids.contains(id))
}

fn host_depends_on_password_identity_graph(
    host: &SavedHost,
    relationships: &AvailableLegacyRelationships<'_>,
) -> bool {
    if host.protocol.is_telnet() || host.protocol.is_serial() {
        return false;
    }
    host.compatibility_fields()
        .get("identityId")
        .and_then(Value::as_str)
        .is_some_and(|id| relationships.password_identity_ids.contains(id))
}

fn disposition_requires_reentry(disposition: LegacyCredentialDisposition) -> bool {
    matches!(
        disposition,
        LegacyCredentialDisposition::ReentryRequiredEncrypted
            | LegacyCredentialDisposition::ReentryRequiredOversized
            | LegacyCredentialDisposition::ReentryRequiredInvalid
            | LegacyCredentialDisposition::ReentryRequiredMissing
            | LegacyCredentialDisposition::ReentryRequiredAdditionalSecret
            | LegacyCredentialDisposition::ReentryRequiredNonSsh
            | LegacyCredentialDisposition::NotSavedByPolicy
    )
}

fn push_issue(issues: &mut Vec<LegacyVaultIssue>, code: LegacyVaultIssueCode, host_index: u32) {
    push_typed_issue(issues, LegacyVaultRecordKind::Host, code, host_index);
}

fn push_typed_issue(
    issues: &mut Vec<LegacyVaultIssue>,
    record_kind: LegacyVaultRecordKind,
    code: LegacyVaultIssueCode,
    record_index: u32,
) {
    if issues.iter().any(|issue| {
        issue.record_kind == record_kind
            && issue.record_index == Some(record_index)
            && issue.code == code
    }) {
        return;
    }
    issues.push(LegacyVaultIssue {
        code,
        message: code.message().to_owned(),
        record_kind,
        record_index: Some(record_index),
    });
}

enum ParsedCatalogRecord<T> {
    Candidate(T),
    Unsupported,
    Rejected,
}

struct CatalogParseOutcome<T> {
    id: Option<String>,
    record: ParsedCatalogRecord<T>,
    secret_fields_stripped: u32,
    issues: Vec<LegacyVaultIssueCode>,
}

enum ParsedSshKeyCandidate {
    Reference(LegacySshKeyReferenceCandidate),
    Managed(LegacyManagedSshKeyCandidate),
}

enum ParsedIdentityCandidate {
    Reference(LegacyIdentityReferenceCandidate),
    Password(LegacyPasswordIdentityCandidate),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AvailableSshKeyKind {
    Key,
    Certificate,
}

fn parse_ssh_key(value: Value, now_ms: u64) -> CatalogParseOutcome<ParsedSshKeyCandidate> {
    let managed_source = value.as_object().and_then(|object| {
        match object.get("source") {
            Some(Value::String(source)) if source.eq_ignore_ascii_case("generated") => {
                Some(SavedSshKeySource::generated())
            }
            Some(Value::String(source)) if source.eq_ignore_ascii_case("imported") => {
                Some(SavedSshKeySource::imported())
            }
            None | Some(Value::Null) => {
                // This is the legacy migrateKey compatibility rule: old
                // records without `source` were imported when they retained
                // private-key text and otherwise classified as generated.
                if object
                    .get("privateKey")
                    .is_some_and(value_has_secret_material)
                {
                    Some(SavedSshKeySource::imported())
                } else {
                    Some(SavedSshKeySource::generated())
                }
            }
            Some(_) => None,
        }
    });

    if let Some(source) = managed_source {
        parse_managed_ssh_key(value, now_ms, source)
    } else {
        let outcome = parse_reference_ssh_key(value, now_ms);
        CatalogParseOutcome {
            id: outcome.id,
            record: match outcome.record {
                ParsedCatalogRecord::Candidate(candidate) => {
                    ParsedCatalogRecord::Candidate(ParsedSshKeyCandidate::Reference(candidate))
                }
                ParsedCatalogRecord::Unsupported => ParsedCatalogRecord::Unsupported,
                ParsedCatalogRecord::Rejected => ParsedCatalogRecord::Rejected,
            },
            secret_fields_stripped: outcome.secret_fields_stripped,
            issues: outcome.issues,
        }
    }
}

fn parse_reference_ssh_key(
    mut value: Value,
    now_ms: u64,
) -> CatalogParseOutcome<LegacySshKeyReferenceCandidate> {
    let Value::Object(mut object) = value else {
        zeroize_value(&mut value);
        return CatalogParseOutcome {
            id: None,
            record: ParsedCatalogRecord::Rejected,
            secret_fields_stripped: 0,
            issues: Vec::new(),
        };
    };

    let private_key = object.remove("privateKey");
    let passphrase = object.remove("passphrase");
    let certificate = object.remove("certificate");
    let private_key_material = private_key.as_ref().is_some_and(value_has_secret_material);
    let passphrase_material = passphrase.as_ref().is_some_and(value_has_secret_material);
    let certificate_material = certificate.as_ref().is_some_and(value_has_secret_material);
    let mut secret_fields_stripped =
        u32::from(private_key.is_some()).saturating_add(u32::from(passphrase.is_some()));
    zeroize_optional_value(private_key);
    zeroize_optional_value(passphrase);
    zeroize_optional_value(certificate);

    let id_text = remove_optional_string(&mut object, "id").ok().flatten();
    let source = remove_optional_string(&mut object, "source").ok().flatten();
    let file_path = remove_optional_string(&mut object, "filePath")
        .ok()
        .flatten();
    let label = remove_optional_string(&mut object, "label").ok().flatten();
    let category = remove_optional_string(&mut object, "category")
        .ok()
        .flatten()
        .unwrap_or_else(|| "key".to_owned());
    let created_at = timestamp(&object, "created")
        .or_else(|| timestamp(&object, "createdAt"))
        .or_else(|| timestamp(&object, "updatedAt"))
        .unwrap_or(now_ms);
    let updated_at = timestamp(&object, "updatedAt")
        .unwrap_or(created_at)
        .max(created_at);
    remove_and_zeroize(&mut object, "created");
    remove_and_zeroize(&mut object, "createdAt");
    remove_and_zeroize(&mut object, "updatedAt");
    remove_and_zeroize(&mut object, "recordVersion");
    remove_and_zeroize(&mut object, "revision");

    let mut scrub = ScrubStats::default();
    scrub_object(&mut object, &mut scrub);
    secret_fields_stripped = secret_fields_stripped.saturating_add(scrub.removed);

    let mut issues = Vec::new();
    let credential_material = private_key_material || passphrase_material || scrub.reentry_required;
    if credential_material {
        issues.push(LegacyVaultIssueCode::SshKeyCredentialRecoveryRequired);
    }
    let certificate_unsupported =
        certificate_material || category.eq_ignore_ascii_case("certificate");
    if certificate_unsupported {
        issues.push(LegacyVaultIssueCode::SshCertificateUnsupported);
    }

    let Some(id_text) = id_text else {
        let mut remaining = Value::Object(object);
        zeroize_value(&mut remaining);
        return CatalogParseOutcome {
            id: None,
            record: ParsedCatalogRecord::Rejected,
            secret_fields_stripped,
            issues,
        };
    };
    let id = match SavedSshKeyReferenceId::from_opaque(id_text.clone()) {
        Ok(id) => id,
        Err(_) => {
            let mut remaining = Value::Object(object);
            zeroize_value(&mut remaining);
            return CatalogParseOutcome {
                id: None,
                record: ParsedCatalogRecord::Rejected,
                secret_fields_stripped,
                issues,
            };
        }
    };

    let supported_shape = source
        .as_deref()
        .is_some_and(|source| source.eq_ignore_ascii_case("reference"))
        && file_path
            .as_deref()
            .is_some_and(|path| !path.trim().is_empty())
        && !credential_material
        && !certificate_unsupported;
    if !supported_shape {
        let mut remaining = Value::Object(object);
        zeroize_value(&mut remaining);
        return CatalogParseOutcome {
            id: Some(id_text),
            record: ParsedCatalogRecord::Unsupported,
            secret_fields_stripped,
            issues,
        };
    }

    let label = label.unwrap_or_else(|| {
        let prefix = id_text.chars().take(8).collect::<String>();
        format!("Key {prefix}")
    });
    let reference = SavedSshKeyReference::from_parts(
        id,
        label,
        file_path.expect("supported shape has a path"),
        SavedSshKeyCategory::compatible(category),
        created_at,
        updated_at,
        object.into_iter().collect::<BTreeMap<_, _>>(),
    );
    match reference {
        Ok(reference) => CatalogParseOutcome {
            id: Some(id_text),
            record: ParsedCatalogRecord::Candidate(LegacySshKeyReferenceCandidate { reference }),
            secret_fields_stripped,
            issues,
        },
        Err(_) => CatalogParseOutcome {
            id: Some(id_text),
            record: ParsedCatalogRecord::Rejected,
            secret_fields_stripped,
            issues,
        },
    }
}

fn parse_managed_ssh_key(
    mut value: Value,
    now_ms: u64,
    source: SavedSshKeySource,
) -> CatalogParseOutcome<ParsedSshKeyCandidate> {
    let Value::Object(mut object) = value else {
        zeroize_value(&mut value);
        return CatalogParseOutcome {
            id: None,
            record: ParsedCatalogRecord::Rejected,
            secret_fields_stripped: 0,
            issues: Vec::new(),
        };
    };

    let private_key = object.remove("privateKey");
    let public_key = object.remove("publicKey");
    let certificate = object.remove("certificate");
    let passphrase = object.remove("passphrase");
    let mut secret_fields_stripped = [
        private_key.is_some(),
        public_key.is_some(),
        certificate.is_some(),
        passphrase.is_some(),
    ]
    .into_iter()
    .map(u32::from)
    .sum::<u32>();

    let certificate_was_nonempty = certificate.as_ref().is_some_and(value_has_secret_material);
    let id_text_result = remove_optional_string(&mut object, "id");
    let label_result = remove_optional_string(&mut object, "label");
    let category_result = remove_optional_string(&mut object, "category");
    remove_and_zeroize(&mut object, "source");
    // A managed key is intentionally detached from every old filesystem path.
    remove_and_zeroize(&mut object, "filePath");

    let save_passphrase_result = match object.remove("savePassphrase") {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(value)) => Ok(value),
        Some(mut value) => {
            zeroize_value(&mut value);
            Err(())
        }
    };
    let created_at = timestamp(&object, "created")
        .or_else(|| timestamp(&object, "createdAt"))
        .or_else(|| timestamp(&object, "updatedAt"))
        .unwrap_or(now_ms);
    let updated_at = timestamp(&object, "updatedAt")
        .unwrap_or(created_at)
        .max(created_at);
    remove_and_zeroize(&mut object, "created");
    remove_and_zeroize(&mut object, "createdAt");
    remove_and_zeroize(&mut object, "updatedAt");

    let mut scrub = ScrubStats::default();
    scrub_object(&mut object, &mut scrub);
    secret_fields_stripped = secret_fields_stripped.saturating_add(scrub.removed);

    let mut issues = Vec::new();
    let private_key = parse_required_managed_secret(private_key, MAX_PRIVATE_KEY_BYTES);
    let public_key = parse_optional_managed_secret(public_key, MAX_PUBLIC_KEY_BYTES);
    let certificate = parse_optional_managed_secret(certificate, MAX_CERTIFICATE_BYTES);
    let passphrase = parse_optional_managed_secret(passphrase, MAX_PASSPHRASE_BYTES);
    let secret_shape_valid = private_key.is_ok()
        && public_key.is_ok()
        && certificate.is_ok()
        && passphrase.is_ok()
        && save_passphrase_result.is_ok()
        && !scrub.reentry_required;

    let id_text = id_text_result.ok().flatten();
    let Some(id_text) = id_text else {
        let mut remaining = Value::Object(object);
        zeroize_value(&mut remaining);
        if !secret_shape_valid {
            issues.push(LegacyVaultIssueCode::SshKeyCredentialRecoveryRequired);
        }
        return CatalogParseOutcome {
            id: None,
            record: ParsedCatalogRecord::Rejected,
            secret_fields_stripped,
            issues,
        };
    };
    let id = match SavedSshKeyReferenceId::from_opaque(id_text.clone()) {
        Ok(id) => id,
        Err(_) => {
            let mut remaining = Value::Object(object);
            zeroize_value(&mut remaining);
            if !secret_shape_valid {
                issues.push(LegacyVaultIssueCode::SshKeyCredentialRecoveryRequired);
            }
            return CatalogParseOutcome {
                id: None,
                record: ParsedCatalogRecord::Rejected,
                secret_fields_stripped,
                issues,
            };
        }
    };

    let label = match label_result {
        Ok(label) => label.unwrap_or_else(|| {
            let prefix = id_text.chars().take(8).collect::<String>();
            format!("Key {prefix}")
        }),
        Err(()) => {
            return managed_key_unavailable(id_text, object, secret_fields_stripped, issues);
        }
    };
    let category = match category_result {
        Ok(Some(category)) if category.eq_ignore_ascii_case("key") => SavedSshKeyCategory::key(),
        Ok(Some(category)) if category.eq_ignore_ascii_case("identity") => {
            SavedSshKeyCategory::identity()
        }
        Ok(Some(category)) if category.eq_ignore_ascii_case("certificate") => {
            SavedSshKeyCategory::certificate()
        }
        Ok(None) if certificate_was_nonempty => SavedSshKeyCategory::certificate(),
        Ok(None) => SavedSshKeyCategory::key(),
        Ok(Some(_)) | Err(()) => {
            return managed_key_unavailable(id_text, object, secret_fields_stripped, issues);
        }
    };

    if !secret_shape_valid
        || (category.is_certificate()
            && certificate.as_ref().ok().and_then(Option::as_ref).is_none())
    {
        issues.push(LegacyVaultIssueCode::SshKeyCredentialRecoveryRequired);
        return managed_key_unavailable(id_text, object, secret_fields_stripped, issues);
    }

    let save_passphrase = save_passphrase_result.expect("validated savePassphrase shape");
    let mut private_key = private_key.expect("validated private key");
    let mut public_key = public_key.expect("validated public key");
    let mut certificate = certificate.expect("validated certificate");
    let mut passphrase = passphrase.expect("validated passphrase");
    let passphrase_disposition = if passphrase.is_some() && save_passphrase {
        LegacyManagedPassphraseDisposition::Saved
    } else if passphrase.is_some() {
        issues.push(LegacyVaultIssueCode::SshKeyPassphraseNotSavedByPolicy);
        passphrase = None;
        LegacyManagedPassphraseDisposition::DiscardedByPolicy
    } else {
        LegacyManagedPassphraseDisposition::Absent
    };
    let secret_bundle = match SshSecretBundle::new(
        std::mem::take(private_key.as_mut()),
        take_zeroizing_bytes(&mut public_key),
        take_zeroizing_bytes(&mut certificate),
        take_zeroizing_bytes(&mut passphrase),
    ) {
        Ok(bundle) => bundle,
        Err(_) => {
            issues.push(LegacyVaultIssueCode::SshKeyCredentialRecoveryRequired);
            return managed_key_unavailable(id_text, object, secret_fields_stripped, issues);
        }
    };

    let compatibility_fields = object.into_iter().collect::<BTreeMap<_, _>>();
    let metadata = LegacyManagedSshKeyMetadata {
        id,
        label,
        category,
        source,
        passphrase_disposition,
        created_at,
        updated_at,
        compatibility_fields,
    };
    if !managed_metadata_is_valid(&metadata) {
        return CatalogParseOutcome {
            id: Some(id_text),
            record: ParsedCatalogRecord::Rejected,
            secret_fields_stripped,
            issues,
        };
    }

    CatalogParseOutcome {
        id: Some(id_text),
        record: ParsedCatalogRecord::Candidate(ParsedSshKeyCandidate::Managed(
            LegacyManagedSshKeyCandidate {
                metadata,
                secret_bundle,
            },
        )),
        secret_fields_stripped,
        issues,
    }
}

fn managed_key_unavailable(
    id: String,
    object: Map<String, Value>,
    secret_fields_stripped: u32,
    mut issues: Vec<LegacyVaultIssueCode>,
) -> CatalogParseOutcome<ParsedSshKeyCandidate> {
    let mut remaining = Value::Object(object);
    zeroize_value(&mut remaining);
    push_issue_code(
        &mut issues,
        LegacyVaultIssueCode::SshKeyCredentialRecoveryRequired,
    );
    CatalogParseOutcome {
        id: Some(id),
        record: ParsedCatalogRecord::Unsupported,
        secret_fields_stripped,
        issues,
    }
}

fn parse_required_managed_secret(
    value: Option<Value>,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, ()> {
    let Some(value) = parse_optional_managed_secret(value, maximum)? else {
        return Err(());
    };
    if value.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Err(());
    }
    Ok(value)
}

fn parse_optional_managed_secret(
    value: Option<Value>,
    maximum: usize,
) -> Result<Option<Zeroizing<Vec<u8>>>, ()> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(mut value)) => {
            if value.is_empty() {
                value.zeroize();
                return Ok(None);
            }
            if value.starts_with(ENCRYPTED_CREDENTIAL_PREFIX) || value.len() > maximum {
                value.zeroize();
                return Err(());
            }
            Ok(Some(Zeroizing::new(value.into_bytes())))
        }
        Some(mut value) => {
            zeroize_value(&mut value);
            Err(())
        }
    }
}

fn take_zeroizing_bytes(value: &mut Option<Zeroizing<Vec<u8>>>) -> Option<Vec<u8>> {
    value.as_mut().map(|value| std::mem::take(value.as_mut()))
}

fn managed_metadata_is_valid(metadata: &LegacyManagedSshKeyMetadata) -> bool {
    let Ok(locator) = SavedSecretObjectLocator::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000000",
    ) else {
        return false;
    };
    let Ok(custody) = SavedSshKeyCustodyReference::new(locator, 1) else {
        return false;
    };
    SavedManagedSshKey::from_parts(
        metadata.id.clone(),
        metadata.label.clone(),
        metadata.category.clone(),
        metadata.source.clone(),
        metadata.has_saved_passphrase(),
        metadata.created_at,
        metadata.updated_at,
        custody,
        metadata.compatibility_fields.clone(),
    )
    .is_ok()
}

fn parse_identity(
    value: Value,
    now_ms: u64,
    available_keys: &HashMap<String, AvailableSshKeyKind>,
) -> CatalogParseOutcome<ParsedIdentityCandidate> {
    let password_identity = value
        .as_object()
        .and_then(|object| object.get("authMethod"))
        .and_then(Value::as_str)
        .is_some_and(|method| method.eq_ignore_ascii_case("password"));
    if password_identity {
        return parse_password_identity(value, now_ms);
    }

    let outcome = parse_identity_reference(value, now_ms, available_keys);
    CatalogParseOutcome {
        id: outcome.id,
        record: match outcome.record {
            ParsedCatalogRecord::Candidate(candidate) => {
                ParsedCatalogRecord::Candidate(ParsedIdentityCandidate::Reference(candidate))
            }
            ParsedCatalogRecord::Unsupported => ParsedCatalogRecord::Unsupported,
            ParsedCatalogRecord::Rejected => ParsedCatalogRecord::Rejected,
        },
        secret_fields_stripped: outcome.secret_fields_stripped,
        issues: outcome.issues,
    }
}

fn parse_password_identity(
    mut value: Value,
    now_ms: u64,
) -> CatalogParseOutcome<ParsedIdentityCandidate> {
    let Value::Object(mut object) = value else {
        zeroize_value(&mut value);
        return CatalogParseOutcome {
            id: None,
            record: ParsedCatalogRecord::Rejected,
            secret_fields_stripped: 0,
            issues: Vec::new(),
        };
    };

    let password_value = object.remove("password");
    let mut secret_fields_stripped = u32::from(password_value.is_some());
    let (mut password, mut credential_disposition) =
        classify_password_identity_password(password_value);

    let id_result = remove_optional_string(&mut object, "id");
    let label_result = remove_optional_string(&mut object, "label");
    let username_result = remove_optional_string(&mut object, "username");
    let auth_method_result = remove_optional_string(&mut object, "authMethod");
    let residual_key_id = object.remove("keyId");
    let ignored_residual_key_reference = residual_key_id
        .as_ref()
        .is_some_and(value_has_secret_material);
    zeroize_optional_value(residual_key_id);

    let created_at = timestamp(&object, "created")
        .or_else(|| timestamp(&object, "createdAt"))
        .or_else(|| timestamp(&object, "updatedAt"))
        .unwrap_or(now_ms);
    let updated_at = timestamp(&object, "updatedAt")
        .unwrap_or(created_at)
        .max(created_at);
    remove_and_zeroize(&mut object, "created");
    remove_and_zeroize(&mut object, "createdAt");
    remove_and_zeroize(&mut object, "updatedAt");
    if object.get("order").is_some_and(Value::is_null) {
        object.remove("order");
    }
    let order_is_valid = object.get("order").is_none_or(Value::is_number);

    let mut scrub = ScrubStats::default();
    scrub_object(&mut object, &mut scrub);
    secret_fields_stripped = secret_fields_stripped.saturating_add(scrub.removed);
    if scrub.reentry_required {
        password = None;
        credential_disposition =
            LegacyPasswordIdentityCredentialDisposition::ReentryRequiredInvalid;
    }

    let mut issues = Vec::new();
    if credential_disposition.requires_reentry() {
        issues.push(LegacyVaultIssueCode::IdentityCredentialReentryRequired);
    }
    if ignored_residual_key_reference {
        issues.push(LegacyVaultIssueCode::PasswordIdentityResidualKeyReferenceIgnored);
    }

    let metadata_shape_valid = id_result.is_ok()
        && label_result.is_ok()
        && username_result.is_ok()
        && auth_method_result
            .as_ref()
            .ok()
            .and_then(|method| method.as_deref())
            .is_some_and(|method| method.eq_ignore_ascii_case("password"))
        && order_is_valid;
    let Some(id_text) = id_result.ok().flatten() else {
        let mut remaining = Value::Object(object);
        zeroize_value(&mut remaining);
        return CatalogParseOutcome {
            id: None,
            record: ParsedCatalogRecord::Rejected,
            secret_fields_stripped,
            issues,
        };
    };
    let id = match SavedPasswordIdentityId::from_opaque(id_text.clone()) {
        Ok(id) => id,
        Err(_) => {
            let mut remaining = Value::Object(object);
            zeroize_value(&mut remaining);
            return CatalogParseOutcome {
                id: None,
                record: ParsedCatalogRecord::Rejected,
                secret_fields_stripped,
                issues,
            };
        }
    };
    if !metadata_shape_valid {
        let mut remaining = Value::Object(object);
        zeroize_value(&mut remaining);
        return CatalogParseOutcome {
            id: Some(id_text),
            record: ParsedCatalogRecord::Rejected,
            secret_fields_stripped,
            issues,
        };
    }

    let label = label_result
        .expect("validated label shape")
        .unwrap_or_else(|| {
            let prefix = id_text.chars().take(8).collect::<String>();
            format!("Identity {prefix}")
        });
    let username = username_result
        .expect("validated username shape")
        .unwrap_or_default();
    let identity = match SavedPasswordIdentity::from_parts(
        id,
        1,
        label,
        username,
        false,
        created_at,
        updated_at,
        object.into_iter().collect::<BTreeMap<_, _>>(),
    ) {
        Ok(identity) => identity,
        Err(_) => {
            return CatalogParseOutcome {
                id: Some(id_text),
                record: ParsedCatalogRecord::Rejected,
                secret_fields_stripped,
                issues,
            };
        }
    };

    CatalogParseOutcome {
        id: Some(id_text),
        record: ParsedCatalogRecord::Candidate(ParsedIdentityCandidate::Password(
            LegacyPasswordIdentityCandidate {
                identity,
                password,
                credential_disposition,
                ignored_residual_key_reference,
            },
        )),
        secret_fields_stripped,
        issues,
    }
}

fn classify_password_identity_password(
    password: Option<Value>,
) -> (
    Option<SecretValue>,
    LegacyPasswordIdentityCredentialDisposition,
) {
    let Some(mut password) = password else {
        return (
            None,
            LegacyPasswordIdentityCredentialDisposition::ReentryRequiredMissing,
        );
    };
    if password.is_null() {
        return (
            None,
            LegacyPasswordIdentityCredentialDisposition::ReentryRequiredMissing,
        );
    }
    let Value::String(mut password_text) = password else {
        zeroize_value(&mut password);
        return (
            None,
            LegacyPasswordIdentityCredentialDisposition::ReentryRequiredInvalid,
        );
    };
    if password_text.is_empty() {
        password_text.zeroize();
        return (
            None,
            LegacyPasswordIdentityCredentialDisposition::ReentryRequiredMissing,
        );
    }
    if password_text.starts_with(ENCRYPTED_CREDENTIAL_PREFIX) {
        password_text.zeroize();
        return (
            None,
            LegacyPasswordIdentityCredentialDisposition::ReentryRequiredEncrypted,
        );
    }
    if password_text.len() > MAX_PERSISTENT_SECRET_BYTES {
        password_text.zeroize();
        return (
            None,
            LegacyPasswordIdentityCredentialDisposition::ReentryRequiredOversized,
        );
    }
    match SecretValue::from_utf8(password_text) {
        Ok(password) => (
            Some(password),
            LegacyPasswordIdentityCredentialDisposition::PlaintextCandidate,
        ),
        Err(_) => (
            None,
            LegacyPasswordIdentityCredentialDisposition::ReentryRequiredInvalid,
        ),
    }
}

fn parse_identity_reference(
    mut value: Value,
    now_ms: u64,
    available_keys: &HashMap<String, AvailableSshKeyKind>,
) -> CatalogParseOutcome<LegacyIdentityReferenceCandidate> {
    let Value::Object(mut object) = value else {
        zeroize_value(&mut value);
        return CatalogParseOutcome {
            id: None,
            record: ParsedCatalogRecord::Rejected,
            secret_fields_stripped: 0,
            issues: Vec::new(),
        };
    };

    let password = object.remove("password");
    let password_material = password.as_ref().is_some_and(value_has_secret_material);
    let mut secret_fields_stripped = u32::from(password.is_some());
    zeroize_optional_value(password);

    let id_text = remove_optional_string(&mut object, "id").ok().flatten();
    let label = remove_optional_string(&mut object, "label").ok().flatten();
    let username = remove_optional_string(&mut object, "username")
        .ok()
        .flatten()
        .unwrap_or_default();
    let auth_method = remove_optional_string(&mut object, "authMethod")
        .ok()
        .flatten();
    let key_id_text = remove_optional_string(&mut object, "keyId").ok().flatten();
    let created_at = timestamp(&object, "created")
        .or_else(|| timestamp(&object, "createdAt"))
        .or_else(|| timestamp(&object, "updatedAt"))
        .unwrap_or(now_ms);
    let updated_at = timestamp(&object, "updatedAt")
        .unwrap_or(created_at)
        .max(created_at);
    remove_and_zeroize(&mut object, "created");
    remove_and_zeroize(&mut object, "createdAt");
    remove_and_zeroize(&mut object, "updatedAt");

    let mut scrub = ScrubStats::default();
    scrub_object(&mut object, &mut scrub);
    secret_fields_stripped = secret_fields_stripped.saturating_add(scrub.removed);
    let credential_material = password_material || scrub.reentry_required;
    let mut issues = Vec::new();
    let password_identity = auth_method
        .as_deref()
        .is_some_and(|method| method.eq_ignore_ascii_case("password"));
    if credential_material || password_identity {
        issues.push(LegacyVaultIssueCode::IdentityCredentialReentryRequired);
    }
    let Some(id_text) = id_text else {
        let mut remaining = Value::Object(object);
        zeroize_value(&mut remaining);
        return CatalogParseOutcome {
            id: None,
            record: ParsedCatalogRecord::Rejected,
            secret_fields_stripped,
            issues,
        };
    };
    let id = match SavedIdentityReferenceId::from_opaque(id_text.clone()) {
        Ok(id) => id,
        Err(_) => {
            let mut remaining = Value::Object(object);
            zeroize_value(&mut remaining);
            return CatalogParseOutcome {
                id: None,
                record: ParsedCatalogRecord::Rejected,
                secret_fields_stripped,
                issues,
            };
        }
    };

    let requested_key_kind = auth_method.as_deref().and_then(|method| {
        if method.eq_ignore_ascii_case("key") {
            Some(AvailableSshKeyKind::Key)
        } else if method.eq_ignore_ascii_case("certificate") {
            Some(AvailableSshKeyKind::Certificate)
        } else {
            None
        }
    });
    let key_available = key_id_text.as_deref().is_some_and(|key_id| {
        requested_key_kind.is_some_and(|requested| {
            available_keys
                .get(key_id)
                .is_some_and(|available| *available == requested)
        })
    });
    let key_authentication = requested_key_kind.is_some();
    if key_authentication && !key_available {
        issues.push(LegacyVaultIssueCode::MissingSshKeyReference);
    }
    let supported_shape = key_authentication && key_available && !credential_material;
    if !supported_shape {
        let mut remaining = Value::Object(object);
        zeroize_value(&mut remaining);
        return CatalogParseOutcome {
            id: Some(id_text),
            record: ParsedCatalogRecord::Unsupported,
            secret_fields_stripped,
            issues,
        };
    }

    let key_id = match SavedSshKeyReferenceId::from_opaque(
        key_id_text.expect("supported shape has a key ID"),
    ) {
        Ok(key_id) => key_id,
        Err(_) => {
            let mut remaining = Value::Object(object);
            zeroize_value(&mut remaining);
            return CatalogParseOutcome {
                id: Some(id_text),
                record: ParsedCatalogRecord::Rejected,
                secret_fields_stripped,
                issues,
            };
        }
    };
    let label = label.unwrap_or_else(|| {
        let prefix = id_text.chars().take(8).collect::<String>();
        format!("Identity {prefix}")
    });
    let compatibility_fields = object.into_iter().collect::<BTreeMap<_, _>>();
    let reference = if requested_key_kind == Some(AvailableSshKeyKind::Certificate) {
        SavedIdentityReference::from_certificate_parts(
            id,
            label,
            username,
            key_id,
            created_at,
            updated_at,
            compatibility_fields,
        )
    } else {
        SavedIdentityReference::from_parts(
            id,
            label,
            username,
            key_id,
            created_at,
            updated_at,
            compatibility_fields,
        )
    };
    match reference {
        Ok(reference) => CatalogParseOutcome {
            id: Some(id_text),
            record: ParsedCatalogRecord::Candidate(LegacyIdentityReferenceCandidate { reference }),
            secret_fields_stripped,
            issues,
        },
        Err(_) => CatalogParseOutcome {
            id: Some(id_text),
            record: ParsedCatalogRecord::Rejected,
            secret_fields_stripped,
            issues,
        },
    }
}

fn remove_optional_string(
    object: &mut Map<String, Value>,
    key: &str,
) -> Result<Option<String>, ()> {
    match object.remove(key) {
        Some(Value::String(value)) => Ok(Some(value)),
        Some(Value::Null) | None => Ok(None),
        Some(mut value) => {
            zeroize_value(&mut value);
            Err(())
        }
    }
}

fn remove_and_zeroize(object: &mut Map<String, Value>, key: &str) {
    zeroize_optional_value(object.remove(key));
}

fn zeroize_optional_value(value: Option<Value>) {
    if let Some(mut value) = value {
        zeroize_value(&mut value);
    }
}

struct ProxyConfigParseOutcome {
    config: Option<SavedProxyConfig>,
    password: Option<SecretValue>,
    credential_disposition: LegacyProxyCredentialDisposition,
    secret_fields_stripped: u32,
    unsupported: bool,
    issues: Vec<LegacyVaultIssueCode>,
}

fn parse_proxy_profile(
    mut value: Value,
    now_ms: u64,
    available_identity_ids: &HashSet<String>,
    password_identity_ids: &HashSet<String>,
) -> CatalogParseOutcome<LegacyProxyProfileCandidate> {
    let Value::Object(mut object) = value else {
        zeroize_value(&mut value);
        return CatalogParseOutcome {
            id: None,
            record: ParsedCatalogRecord::Rejected,
            secret_fields_stripped: 0,
            issues: Vec::new(),
        };
    };

    let id_result = remove_optional_string(&mut object, "id");
    let label_result = remove_optional_string(&mut object, "label");
    let config_value = object.remove("config");
    let mut config_outcome =
        parse_proxy_config_candidate(config_value, available_identity_ids, password_identity_ids);
    let created_at = timestamp(&object, "createdAt")
        .or_else(|| timestamp(&object, "created"))
        .or_else(|| timestamp(&object, "updatedAt"))
        .unwrap_or(now_ms);
    let updated_at = timestamp(&object, "updatedAt")
        .unwrap_or(created_at)
        .max(created_at);
    remove_and_zeroize(&mut object, "created");
    remove_and_zeroize(&mut object, "createdAt");
    remove_and_zeroize(&mut object, "updatedAt");
    if object.get("order").is_some_and(Value::is_null) {
        object.remove("order");
    }
    let order_is_valid = object.get("order").is_none_or(Value::is_number);
    let mut scrub = ScrubStats::default();
    scrub_object(&mut object, &mut scrub);
    config_outcome.secret_fields_stripped = config_outcome
        .secret_fields_stripped
        .saturating_add(scrub.removed);
    if scrub.reentry_required {
        config_outcome.password = None;
        config_outcome.config = None;
        push_issue_code(
            &mut config_outcome.issues,
            LegacyVaultIssueCode::InvalidProxyConfig,
        );
    }

    let Some(id_text) = id_result.ok().flatten() else {
        let mut remaining = Value::Object(object);
        zeroize_value(&mut remaining);
        return CatalogParseOutcome {
            id: None,
            record: ParsedCatalogRecord::Rejected,
            secret_fields_stripped: config_outcome.secret_fields_stripped,
            issues: config_outcome.issues,
        };
    };
    let id = match SavedProxyProfileId::from_opaque(id_text.clone()) {
        Ok(id) => id,
        Err(_) => {
            let mut remaining = Value::Object(object);
            zeroize_value(&mut remaining);
            return CatalogParseOutcome {
                id: None,
                record: ParsedCatalogRecord::Rejected,
                secret_fields_stripped: config_outcome.secret_fields_stripped,
                issues: config_outcome.issues,
            };
        }
    };
    let shape_valid = label_result.is_ok() && order_is_valid;
    let Some(config) = config_outcome.config else {
        let mut remaining = Value::Object(object);
        zeroize_value(&mut remaining);
        return CatalogParseOutcome {
            id: Some(id_text),
            record: ParsedCatalogRecord::Rejected,
            secret_fields_stripped: config_outcome.secret_fields_stripped,
            issues: config_outcome.issues,
        };
    };
    if !shape_valid {
        let mut remaining = Value::Object(object);
        zeroize_value(&mut remaining);
        return CatalogParseOutcome {
            id: Some(id_text),
            record: ParsedCatalogRecord::Rejected,
            secret_fields_stripped: config_outcome.secret_fields_stripped,
            issues: config_outcome.issues,
        };
    }
    let label = label_result
        .expect("validated label shape")
        .unwrap_or_else(|| {
            let prefix = id_text.chars().take(8).collect::<String>();
            format!("Proxy {prefix}")
        });
    let profile = match SavedProxyProfile::from_parts(
        id,
        1,
        label,
        config,
        created_at,
        updated_at,
        object.into_iter().collect::<BTreeMap<_, _>>(),
    ) {
        Ok(profile) => profile,
        Err(_) => {
            return CatalogParseOutcome {
                id: Some(id_text),
                record: ParsedCatalogRecord::Rejected,
                secret_fields_stripped: config_outcome.secret_fields_stripped,
                issues: config_outcome.issues,
            };
        }
    };
    if config_outcome.unsupported {
        return CatalogParseOutcome {
            id: Some(id_text),
            record: ParsedCatalogRecord::Unsupported,
            secret_fields_stripped: config_outcome.secret_fields_stripped,
            issues: config_outcome.issues,
        };
    }
    CatalogParseOutcome {
        id: Some(id_text),
        record: ParsedCatalogRecord::Candidate(LegacyProxyProfileCandidate {
            profile,
            password: config_outcome.password,
            credential_disposition: config_outcome.credential_disposition,
        }),
        secret_fields_stripped: config_outcome.secret_fields_stripped,
        issues: config_outcome.issues,
    }
}

fn parse_proxy_config_candidate(
    value: Option<Value>,
    available_identity_ids: &HashSet<String>,
    password_identity_ids: &HashSet<String>,
) -> ProxyConfigParseOutcome {
    let Some(mut value) = value else {
        return invalid_proxy_config_outcome(0, Vec::new());
    };
    let Value::Object(mut object) = value else {
        zeroize_value(&mut value);
        return invalid_proxy_config_outcome(0, Vec::new());
    };
    let proxy_type = object
        .get("type")
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase);
    let password_value = object.remove("password");
    let mut secret_fields_stripped = u32::from(password_value.is_some());
    let credential_hint = remove_proxy_credential_status_fields(&mut object);

    if proxy_type.as_deref() == Some("command") {
        zeroize_optional_value(password_value);
        for field in ["host", "hostname", "port", "identityId", "username"] {
            remove_and_zeroize(&mut object, field);
        }
        let mut scrub = ScrubStats::default();
        scrub_object(&mut object, &mut scrub);
        secret_fields_stripped = secret_fields_stripped.saturating_add(scrub.removed);
        return match serde_json::from_value::<SavedProxyConfig>(Value::Object(object)) {
            Ok(config) => ProxyConfigParseOutcome {
                config: Some(config),
                password: None,
                credential_disposition: LegacyProxyCredentialDisposition::None,
                secret_fields_stripped,
                unsupported: false,
                issues: Vec::new(),
            },
            Err(_) => invalid_proxy_config_outcome(secret_fields_stripped, Vec::new()),
        };
    }

    if !matches!(proxy_type.as_deref(), Some("http" | "socks5")) {
        zeroize_optional_value(password_value);
        let mut remaining = Value::Object(object);
        zeroize_value(&mut remaining);
        return invalid_proxy_config_outcome(secret_fields_stripped, Vec::new());
    }

    let identity_id = object
        .get("identityId")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let username_present = object
        .get("username")
        .and_then(Value::as_str)
        .is_some_and(|username| !username.is_empty());
    let password_present = password_value
        .as_ref()
        .is_some_and(value_has_secret_material);
    if identity_id.is_some() && (username_present || password_present || credential_hint) {
        zeroize_optional_value(password_value);
        let mut remaining = Value::Object(object);
        zeroize_value(&mut remaining);
        return invalid_proxy_config_outcome(
            secret_fields_stripped,
            vec![LegacyVaultIssueCode::ProxyAuthenticationConflict],
        );
    }

    let (password, credential_disposition) = if identity_id.is_some() {
        zeroize_optional_value(password_value);
        object.insert("username".to_owned(), Value::String(String::new()));
        (None, LegacyProxyCredentialDisposition::None)
    } else {
        if object
            .get("identityId")
            .is_some_and(|value| value.is_null() || value.as_str() == Some(""))
        {
            object.remove("identityId");
        }
        classify_proxy_password(password_value, username_present || credential_hint)
    };
    object.insert("hasSavedCredential".to_owned(), Value::Bool(false));
    let mut scrub = ScrubStats::default();
    scrub_object(&mut object, &mut scrub);
    secret_fields_stripped = secret_fields_stripped.saturating_add(scrub.removed);
    if scrub.reentry_required {
        let mut remaining = Value::Object(object);
        zeroize_value(&mut remaining);
        return invalid_proxy_config_outcome(secret_fields_stripped, Vec::new());
    }
    let config = serde_json::from_value::<SavedProxyConfig>(Value::Object(object)).ok();
    let Some(config) = config else {
        return invalid_proxy_config_outcome(secret_fields_stripped, Vec::new());
    };
    let mut issues = Vec::new();
    if credential_disposition.requires_reentry() {
        issues.push(LegacyVaultIssueCode::ProxyCredentialReentryRequired);
    }
    let unsupported = identity_id.as_ref().is_some_and(|identity_id| {
        if password_identity_ids.contains(identity_id) {
            false
        } else {
            let _incompatible = available_identity_ids.contains(identity_id);
            push_issue_code(
                &mut issues,
                LegacyVaultIssueCode::MissingProxyIdentityReference,
            );
            true
        }
    });
    ProxyConfigParseOutcome {
        config: Some(config),
        password,
        credential_disposition,
        secret_fields_stripped,
        unsupported,
        issues,
    }
}

fn invalid_proxy_config_outcome(
    secret_fields_stripped: u32,
    mut issues: Vec<LegacyVaultIssueCode>,
) -> ProxyConfigParseOutcome {
    push_issue_code(&mut issues, LegacyVaultIssueCode::InvalidProxyConfig);
    ProxyConfigParseOutcome {
        config: None,
        password: None,
        credential_disposition: LegacyProxyCredentialDisposition::ReentryRequiredInvalid,
        secret_fields_stripped,
        unsupported: false,
        issues,
    }
}

fn remove_proxy_credential_status_fields(object: &mut Map<String, Value>) -> bool {
    let mut credential_hint = false;
    for key in [
        "hasSavedCredential",
        "hasCredential",
        "hasPassword",
        "savePassword",
    ] {
        if let Some(mut value) = object.remove(key) {
            credential_hint |= value.as_bool() == Some(true);
            zeroize_value(&mut value);
        }
    }
    credential_hint
}

fn classify_proxy_password(
    password: Option<Value>,
    credential_required: bool,
) -> (Option<SecretValue>, LegacyProxyCredentialDisposition) {
    let Some(mut password) = password else {
        return (
            None,
            if credential_required {
                LegacyProxyCredentialDisposition::ReentryRequiredMissing
            } else {
                LegacyProxyCredentialDisposition::None
            },
        );
    };
    if password.is_null() {
        return (
            None,
            if credential_required {
                LegacyProxyCredentialDisposition::ReentryRequiredMissing
            } else {
                LegacyProxyCredentialDisposition::None
            },
        );
    }
    let Value::String(mut password_text) = password else {
        zeroize_value(&mut password);
        return (
            None,
            LegacyProxyCredentialDisposition::ReentryRequiredInvalid,
        );
    };
    if password_text.is_empty() {
        password_text.zeroize();
        return (
            None,
            if credential_required {
                LegacyProxyCredentialDisposition::ReentryRequiredMissing
            } else {
                LegacyProxyCredentialDisposition::None
            },
        );
    }
    if password_text.starts_with(ENCRYPTED_CREDENTIAL_PREFIX) {
        password_text.zeroize();
        return (
            None,
            LegacyProxyCredentialDisposition::ReentryRequiredEncrypted,
        );
    }
    if password_text.len() > MAX_PERSISTENT_SECRET_BYTES {
        password_text.zeroize();
        return (
            None,
            LegacyProxyCredentialDisposition::ReentryRequiredOversized,
        );
    }
    match SecretValue::from_utf8(password_text) {
        Ok(password) => (
            Some(password),
            LegacyProxyCredentialDisposition::PlaintextCandidate,
        ),
        Err(_) => (
            None,
            LegacyProxyCredentialDisposition::ReentryRequiredInvalid,
        ),
    }
}

struct AvailableLegacyRelationships<'a> {
    ssh_key_ids: &'a HashSet<String>,
    ssh_key_kinds: &'a HashMap<String, AvailableSshKeyKind>,
    identity_ids: &'a HashSet<String>,
    identity_usernames: &'a HashMap<String, String>,
    identity_auth_methods: &'a HashMap<String, String>,
    managed_key_ids: &'a HashSet<String>,
    managed_identity_ids: &'a HashSet<String>,
    password_identity_ids: &'a HashSet<String>,
    proxy_profile_ids: &'a HashSet<String>,
}

struct HostParseOutcome {
    candidate: Option<LegacyHostCandidate>,
    secret_fields_stripped: u32,
    issues: Vec<LegacyVaultIssueCode>,
}

/// JavaScript nullish coalescing for owned legacy JSON values. An explicit
/// empty string remains authoritative; only a missing/null preferred field
/// falls back. Every discarded branch is scrubbed before release.
fn coalesce_legacy_value(preferred: Option<Value>, fallback: Option<Value>) -> Option<Value> {
    match preferred {
        None => fallback,
        Some(Value::Null) => fallback,
        Some(value) => {
            if let Some(mut fallback) = fallback {
                zeroize_value(&mut fallback);
            }
            Some(value)
        }
    }
}

fn parse_host(
    mut value: Value,
    now_ms: u64,
    relationships: &AvailableLegacyRelationships<'_>,
) -> HostParseOutcome {
    let Value::Object(mut object) = value else {
        zeroize_value(&mut value);
        return HostParseOutcome {
            candidate: None,
            secret_fields_stripped: 0,
            issues: Vec::new(),
        };
    };

    let source_protocol = object
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or("ssh")
        .to_owned();
    let is_primary_telnet = source_protocol.eq_ignore_ascii_case("telnet");
    let is_primary_serial = source_protocol.eq_ignore_ascii_case("serial");

    let inline_proxy_value = object.remove("proxyConfig");
    let inline_proxy_present = inline_proxy_value
        .as_ref()
        .is_some_and(|value| !value.is_null());
    let mut inline_proxy_password = None;
    let mut inline_proxy_credential_disposition = LegacyProxyCredentialDisposition::None;
    let mut inline_proxy_secret_fields_stripped = 0;
    let mut inline_proxy_unsupported = false;
    let mut inline_proxy_issues = Vec::new();
    if inline_proxy_present {
        let ProxyConfigParseOutcome {
            config,
            password,
            credential_disposition,
            secret_fields_stripped,
            unsupported,
            issues,
        } = parse_proxy_config_candidate(
            inline_proxy_value,
            relationships.identity_ids,
            relationships.password_identity_ids,
        );
        inline_proxy_password = password;
        inline_proxy_credential_disposition = credential_disposition;
        inline_proxy_secret_fields_stripped = secret_fields_stripped;
        inline_proxy_unsupported = unsupported || config.is_none();
        inline_proxy_issues = issues;
        if let Some(config) = config {
            object.insert(
                "proxyConfig".to_owned(),
                serde_json::to_value(config).expect("saved proxy config serializes"),
            );
        } else {
            // Retain a safe non-null fail-closed marker. Non-null inline proxy
            // data has absolute precedence over a shadowed profile reference,
            // even when the legacy inline shape is invalid.
            object.insert("proxyConfig".to_owned(), json_invalid_proxy_config());
        }
    } else if matches!(inline_proxy_value, Some(Value::Null)) {
        object.insert("proxyConfig".to_owned(), Value::Null);
    }

    // SSH proxy metadata is dormant on primary Telnet and Serial records.
    // Preserve its safe shape, but never let an ignored proxy edge or
    // credential prevent a directly connectable non-SSH host from importing.
    if is_primary_telnet || is_primary_serial {
        drop(inline_proxy_password.take());
        inline_proxy_credential_disposition = LegacyProxyCredentialDisposition::None;
        inline_proxy_unsupported = false;
        inline_proxy_issues.clear();
    }

    let save_password = !matches!(object.get("savePassword"), Some(Value::Bool(false)));
    let primary_password_value = object.remove("password");
    let telnet_password_value = is_primary_telnet
        .then(|| object.remove("telnetPassword"))
        .flatten();
    let primary_password_was_present = primary_password_value.is_some();
    let telnet_password_was_present = telnet_password_value.is_some();
    let password_value = if is_primary_telnet {
        coalesce_legacy_value(telnet_password_value, primary_password_value)
    } else if is_primary_serial {
        if let Some(mut ignored) = primary_password_value {
            zeroize_value(&mut ignored);
        }
        None
    } else {
        primary_password_value
    };

    let mut telnet_fields_valid = true;
    if is_primary_telnet {
        match object.remove("telnetUsername") {
            None | Some(Value::Null) => {}
            Some(Value::String(username)) => {
                object.insert("username".to_owned(), Value::String(username));
            }
            Some(mut invalid) => {
                zeroize_value(&mut invalid);
                telnet_fields_valid = false;
            }
        }
        match object.remove("telnetPort") {
            None | Some(Value::Null) => {}
            Some(Value::Number(port))
                if port
                    .as_u64()
                    .is_some_and(|port| (1..=u64::from(u16::MAX)).contains(&port)) =>
            {
                object.insert("port".to_owned(), Value::Number(port));
            }
            Some(mut invalid) => {
                zeroize_value(&mut invalid);
                telnet_fields_valid = false;
            }
        }
        // Mirrors normalizePrimaryTelnetState in the legacy domain layer.
        object.insert("telnetEnabled".to_owned(), Value::Bool(true));
    }
    let available_identity_username = object
        .get("identityId")
        .and_then(Value::as_str)
        .and_then(|identity_id| relationships.identity_usernames.get(identity_id));
    let available_identity_auth_method = object
        .get("identityId")
        .and_then(Value::as_str)
        .and_then(|identity_id| relationships.identity_auth_methods.get(identity_id));
    let uses_password_identity = object
        .get("identityId")
        .and_then(Value::as_str)
        .is_some_and(|identity_id| relationships.password_identity_ids.contains(identity_id));
    let mut effective_auth_method = if is_primary_telnet || is_primary_serial {
        "password".to_owned()
    } else if let Some(method) = available_identity_auth_method {
        method.as_str().to_owned()
    } else {
        infer_legacy_auth_method(&object, password_value.as_ref())
    };
    let mut relationship_assessment = if is_primary_telnet || is_primary_serial {
        HostRelationshipAssessment {
            has_supported_key_source: false,
            unsupported: false,
            requires_reentry: false,
            issues: Vec::new(),
        }
    } else {
        assess_host_relationships(
            &object,
            &effective_auth_method,
            inline_proxy_present,
            relationships,
        )
    };
    relationship_assessment.unsupported |= inline_proxy_unsupported;
    for code in inline_proxy_issues {
        push_issue_code(&mut relationship_assessment.issues, code);
    }
    if effective_auth_method.eq_ignore_ascii_case("auto")
        && relationship_assessment.has_supported_key_source
    {
        effective_auth_method = "key".to_owned();
    } else if effective_auth_method.eq_ignore_ascii_case("key") {
        effective_auth_method = "key".to_owned();
    }
    if !is_primary_telnet
        && let Some(username) = available_identity_username.filter(|username| !username.is_empty())
    {
        object.insert("username".to_owned(), Value::String(username.clone()));
    }
    let mut secret_fields_stripped = u32::from(primary_password_was_present)
        .saturating_add(u32::from(telnet_password_was_present))
        .saturating_add(inline_proxy_secret_fields_stripped);
    let mut issues = relationship_assessment.issues;

    let (ssh_password, mut credential_disposition, telnet_password, telnet_credential_disposition) =
        if is_primary_telnet {
            let (password, disposition) =
                classify_password(password_value, save_password, true, &mut issues);
            (
                None,
                LegacyCredentialDisposition::None,
                password,
                disposition,
            )
        } else if is_primary_serial {
            (
                None,
                LegacyCredentialDisposition::None,
                None,
                LegacyCredentialDisposition::None,
            )
        } else {
            let (password, disposition) = classify_password(
                password_value,
                save_password,
                source_protocol.eq_ignore_ascii_case("ssh"),
                &mut issues,
            );
            (
                password,
                disposition,
                None,
                LegacyCredentialDisposition::None,
            )
        };

    let mut scrub = ScrubStats::default();
    scrub_object(&mut object, &mut scrub);
    secret_fields_stripped = secret_fields_stripped.saturating_add(scrub.removed);
    let requires_additional_credential_reentry =
        scrub.reentry_required || relationship_assessment.requires_reentry;
    if requires_additional_credential_reentry {
        issues.push(LegacyVaultIssueCode::AdditionalCredentialReentryRequired);
        if matches!(credential_disposition, LegacyCredentialDisposition::None) {
            credential_disposition = LegacyCredentialDisposition::ReentryRequiredAdditionalSecret;
        }
    }

    // Resolve the old authentication decision once, including identity
    // overrides, and persist the explicit current-policy method.
    object.insert(
        "authMethod".to_owned(),
        Value::String(effective_auth_method),
    );
    object.insert("protocol".to_owned(), Value::String(source_protocol));

    // Legacy Serial records use `serialConfig` as the authoritative endpoint
    // while mirroring its path/baud into the generic Host fields. Repair a
    // stale or missing mirror during import so current list/search/log views
    // and the runtime all describe the same local device.
    if is_primary_serial {
        let serial_endpoint = object
            .get("serialConfig")
            .and_then(Value::as_object)
            .and_then(|config| {
                let path = config.get("path")?.as_str()?.to_owned();
                let baud_rate = config.get("baudRate")?.as_u64()?;
                (baud_rate <= u64::from(u32::MAX)).then_some((path, baud_rate))
            });
        if let Some((path, baud_rate)) = serial_endpoint {
            object.insert("hostname".to_owned(), Value::String(path));
            object.insert("port".to_owned(), Value::from(baud_rate));
        }
        if object.get("port").is_none_or(Value::is_null) {
            object.insert("port".to_owned(), Value::from(DEFAULT_SERIAL_BAUD_RATE));
        }
    }
    for nullable_default in ["label", "port", "username"] {
        if object.get(nullable_default).is_some_and(Value::is_null) {
            object.remove(nullable_default);
        }
    }

    // A persisted credential-presence bit is not proof that a corresponding
    // OS credential exists. Every parsed candidate starts fail-closed.
    object.insert("hasSavedCredential".to_owned(), Value::Bool(false));

    let Some(hostname) = object
        .get("hostname")
        .and_then(Value::as_str)
        .and_then(|value| {
            if is_primary_serial {
                normalize_legacy_serial_path(value)
            } else {
                normalize_legacy_hostname(value)
            }
        })
    else {
        return HostParseOutcome {
            candidate: None,
            secret_fields_stripped,
            issues,
        };
    };
    object.insert("hostname".to_owned(), Value::String(hostname));

    let created_at = timestamp(&object, "createdAt")
        .or_else(|| timestamp(&object, "updatedAt"))
        .unwrap_or(now_ms);
    let updated_at = timestamp(&object, "updatedAt")
        .unwrap_or(created_at)
        .max(created_at);

    // These fields describe the new Vault record, not the legacy container.
    object.insert("recordVersion".to_owned(), Value::from(1_u64));
    object.insert("revision".to_owned(), Value::from(1_u64));
    object.insert("createdAt".to_owned(), Value::from(created_at));
    object.insert("updatedAt".to_owned(), Value::from(updated_at));
    object.insert("authPolicyVersion".to_owned(), Value::from(1_u64));

    let host = match serde_json::from_value::<SavedHost>(Value::Object(object)) {
        Ok(host) => host,
        Err(_) => {
            return HostParseOutcome {
                candidate: None,
                secret_fields_stripped,
                issues,
            };
        }
    };

    if host.protocol.is_ssh()
        && host.auth_method.is_password()
        && ssh_password.is_none()
        && !uses_password_identity
        && matches!(credential_disposition, LegacyCredentialDisposition::None)
    {
        issues.push(LegacyVaultIssueCode::MissingCredentialReentryRequired);
        credential_disposition = LegacyCredentialDisposition::ReentryRequiredMissing;
    }

    let supported_auth = host.auth_method.is_password()
        || ((host.auth_method.as_str().eq_ignore_ascii_case("key")
            || host
                .auth_method
                .as_str()
                .eq_ignore_ascii_case("certificate"))
            && relationship_assessment.has_supported_key_source);
    let currently_importable = if host.protocol.is_telnet() {
        telnet_fields_valid && !requires_additional_credential_reentry
    } else if host.protocol.is_serial() {
        host.effective_serial_config().is_ok() && !requires_additional_credential_reentry
    } else {
        host.protocol.is_ssh()
            && supported_auth
            && !relationship_assessment.unsupported
            && !requires_additional_credential_reentry
    };

    HostParseOutcome {
        candidate: Some(LegacyHostCandidate {
            host,
            ssh_password,
            credential_disposition,
            telnet_password,
            telnet_credential_disposition,
            inline_proxy_password,
            inline_proxy_credential_disposition,
            requires_additional_credential_reentry,
            currently_importable,
        }),
        secret_fields_stripped,
        issues,
    }
}

fn json_invalid_proxy_config() -> Value {
    Value::Object(Map::from_iter([(
        "type".to_owned(),
        Value::String("invalid".to_owned()),
    )]))
}

fn infer_legacy_auth_method(object: &Map<String, Value>, password: Option<&Value>) -> String {
    let source_method = object
        .get("authMethod")
        .and_then(Value::as_str)
        .filter(|method| !method.is_empty());
    let versioned = object.get("authPolicyVersion").and_then(Value::as_u64) == Some(1);
    if versioned {
        return source_method.unwrap_or("auto").to_owned();
    }

    let uses_agent = matches!(object.get("useSshAgent"), Some(Value::Bool(true)));
    let has_identity_file_id = nonempty_string_field(object, "identityFileId");
    let has_identity_paths = nonempty_array_field(object, "identityFilePaths");
    let password_nonempty = matches!(password, Some(Value::String(value)) if !value.is_empty());
    let save_password = !matches!(object.get("savePassword"), Some(Value::Bool(false)));

    // This is the one-time legacy-password-default migration from sanitizeHost:
    // old records wrote `password` even when agent/key fallback was intended.
    if source_method == Some("password")
        && (uses_agent
            || has_identity_file_id
            || has_identity_paths
            || (save_password && !password_nonempty))
    {
        return "auto".to_owned();
    }
    if let Some(source_method) = source_method {
        return source_method.to_owned();
    }
    if !uses_agent {
        if has_identity_paths {
            return "key".to_owned();
        }
        if !has_identity_file_id && password_nonempty {
            return "password".to_owned();
        }
    }
    "auto".to_owned()
}

struct HostRelationshipAssessment {
    has_supported_key_source: bool,
    unsupported: bool,
    requires_reentry: bool,
    issues: Vec<LegacyVaultIssueCode>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RelationshipState {
    Absent,
    Available,
    Missing,
}

fn assess_host_relationships(
    object: &Map<String, Value>,
    auth_method: &str,
    inline_proxy_present: bool,
    available: &AvailableLegacyRelationships<'_>,
) -> HostRelationshipAssessment {
    let identity = catalog_reference_state(object.get("identityId"), available.identity_ids);
    let key = catalog_reference_state(object.get("identityFileId"), available.ssh_key_ids);
    let paths = identity_file_paths_state(object.get("identityFilePaths"));
    let requested_key_kind = if auth_method.eq_ignore_ascii_case("certificate") {
        Some(AvailableSshKeyKind::Certificate)
    } else if auth_method.eq_ignore_ascii_case("key") {
        Some(AvailableSshKeyKind::Key)
    } else {
        None
    };
    let direct_key_kind_matches = object
        .get("identityFileId")
        .and_then(Value::as_str)
        .and_then(|id| available.ssh_key_kinds.get(id))
        .is_some_and(|kind| requested_key_kind.is_none_or(|requested| *kind == requested));
    let mut issues = Vec::new();
    let mut unsupported = false;
    let mut requires_reentry = false;

    if identity == RelationshipState::Missing {
        push_issue_code(&mut issues, LegacyVaultIssueCode::MissingIdentityReference);
        unsupported = true;
        requires_reentry = true;
    }
    if key == RelationshipState::Missing
        || (key == RelationshipState::Available && !direct_key_kind_matches)
    {
        push_issue_code(&mut issues, LegacyVaultIssueCode::MissingSshKeyReference);
        unsupported = true;
        requires_reentry = true;
    }
    if paths == RelationshipState::Missing {
        push_issue_code(&mut issues, LegacyVaultIssueCode::InvalidIdentityFilePaths);
        unsupported = true;
        requires_reentry = true;
    }
    let has_supported_key_source = identity == RelationshipState::Available
        || (key == RelationshipState::Available && direct_key_kind_matches)
        || (paths == RelationshipState::Available
            && !auth_method.eq_ignore_ascii_case("certificate"));
    if (auth_method.eq_ignore_ascii_case("key") || auth_method.eq_ignore_ascii_case("certificate"))
        && !has_supported_key_source
        && !matches!(object.get("useSshAgent"), Some(Value::Bool(true)))
    {
        push_issue_code(&mut issues, LegacyVaultIssueCode::MissingSshKeyReference);
        unsupported = true;
        requires_reentry = true;
    }
    if auth_method.eq_ignore_ascii_case("certificate") && !has_supported_key_source {
        push_issue_code(&mut issues, LegacyVaultIssueCode::SshCertificateUnsupported);
    }

    // Inline proxy data has absolute priority. Its shape and identity edge
    // were assessed by `parse_proxy_config_candidate`; only an absent or null
    // inline value allows the profile relationship to take effect.
    if !inline_proxy_present {
        let profile = match object.get("proxyProfileId") {
            None | Some(Value::Null) => RelationshipState::Absent,
            Some(Value::String(value)) if available.proxy_profile_ids.contains(value) => {
                RelationshipState::Available
            }
            Some(_) => RelationshipState::Missing,
        };
        if profile == RelationshipState::Missing {
            push_issue_code(
                &mut issues,
                LegacyVaultIssueCode::MissingProxyProfileReference,
            );
            unsupported = true;
        }
    }

    HostRelationshipAssessment {
        has_supported_key_source,
        unsupported,
        requires_reentry,
        issues,
    }
}

fn push_issue_code(issues: &mut Vec<LegacyVaultIssueCode>, code: LegacyVaultIssueCode) {
    if !issues.contains(&code) {
        issues.push(code);
    }
}

fn catalog_reference_state(
    value: Option<&Value>,
    available_ids: &HashSet<String>,
) -> RelationshipState {
    match value {
        None | Some(Value::Null) => RelationshipState::Absent,
        Some(Value::String(value)) if value.is_empty() => RelationshipState::Absent,
        Some(Value::String(value)) if available_ids.contains(value) => RelationshipState::Available,
        Some(Value::String(_)) | Some(_) => RelationshipState::Missing,
    }
}

fn identity_file_paths_state(value: Option<&Value>) -> RelationshipState {
    let paths = match value {
        None | Some(Value::Null) => return RelationshipState::Absent,
        Some(Value::Array(paths)) if paths.is_empty() => return RelationshipState::Absent,
        Some(Value::Array(paths)) => paths,
        Some(_) => return RelationshipState::Missing,
    };
    if paths.len() > MAX_LEGACY_IDENTITY_FILE_PATHS {
        return RelationshipState::Missing;
    }

    let mut seen = HashSet::with_capacity(paths.len());
    let mut total_bytes = 0_usize;
    for path in paths {
        let Some(path) = path.as_str() else {
            return RelationshipState::Missing;
        };
        total_bytes = match total_bytes.checked_add(path.len()) {
            Some(total) => total,
            None => return RelationshipState::Missing,
        };
        if path.trim().is_empty()
            || path.len() > MAX_LEGACY_IDENTITY_FILE_PATH_BYTES
            || total_bytes > MAX_LEGACY_IDENTITY_FILE_PATH_TOTAL_BYTES
            || path.chars().any(char::is_control)
            || !seen.insert(path)
        {
            return RelationshipState::Missing;
        }
    }
    RelationshipState::Available
}

fn nonempty_string_field(object: &Map<String, Value>, key: &str) -> bool {
    object
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
}

fn nonempty_array_field(object: &Map<String, Value>, key: &str) -> bool {
    object
        .get(key)
        .and_then(Value::as_array)
        .is_some_and(|values| !values.is_empty())
}

fn classify_password(
    password: Option<Value>,
    save_password: bool,
    is_ssh: bool,
    issues: &mut Vec<LegacyVaultIssueCode>,
) -> (Option<SecretValue>, LegacyCredentialDisposition) {
    let Some(mut password) = password else {
        return (None, LegacyCredentialDisposition::None);
    };
    let Value::String(mut password_text) = password else {
        if password.is_null() {
            return (None, LegacyCredentialDisposition::None);
        }
        zeroize_value(&mut password);
        issues.push(LegacyVaultIssueCode::InvalidCredentialReentryRequired);
        return (None, LegacyCredentialDisposition::ReentryRequiredInvalid);
    };
    if password_text.is_empty() {
        return (None, LegacyCredentialDisposition::None);
    }
    if password_text.starts_with(ENCRYPTED_CREDENTIAL_PREFIX) {
        password_text.zeroize();
        issues.push(LegacyVaultIssueCode::EncryptedCredentialReentryRequired);
        return (None, LegacyCredentialDisposition::ReentryRequiredEncrypted);
    }
    if !save_password {
        password_text.zeroize();
        issues.push(LegacyVaultIssueCode::PasswordNotSavedByPolicy);
        return (None, LegacyCredentialDisposition::NotSavedByPolicy);
    }
    if !is_ssh {
        password_text.zeroize();
        issues.push(LegacyVaultIssueCode::NonSshPasswordReentryRequired);
        return (None, LegacyCredentialDisposition::ReentryRequiredNonSsh);
    }
    if password_text.len() > MAX_PERSISTENT_SECRET_BYTES {
        password_text.zeroize();
        issues.push(LegacyVaultIssueCode::OversizedCredentialReentryRequired);
        return (None, LegacyCredentialDisposition::ReentryRequiredOversized);
    }

    match SecretValue::from_utf8(password_text) {
        Ok(secret) => (
            Some(secret),
            LegacyCredentialDisposition::PlaintextCandidate,
        ),
        Err(_) => {
            issues.push(LegacyVaultIssueCode::InvalidCredentialReentryRequired);
            (None, LegacyCredentialDisposition::ReentryRequiredInvalid)
        }
    }
}

fn timestamp(object: &Map<String, Value>, key: &str) -> Option<u64> {
    object.get(key).and_then(Value::as_u64)
}

fn normalize_legacy_hostname(value: &str) -> Option<String> {
    value
        .trim()
        .split_whitespace()
        .next()
        .filter(|hostname| !hostname.is_empty())
        .map(str::to_owned)
}

fn normalize_legacy_serial_path(value: &str) -> Option<String> {
    if value.chars().any(char::is_control) {
        return None;
    }
    let path = value.trim();
    (!path.is_empty()).then(|| path.to_owned())
}

#[derive(Default)]
struct ScrubStats {
    removed: u32,
    reentry_required: bool,
}

fn scrub_object(object: &mut Map<String, Value>, stats: &mut ScrubStats) {
    let keys = object.keys().cloned().collect::<Vec<_>>();
    for key in keys {
        if is_secret_status_key(&key) {
            let valid = matches!(object.get(&key), Some(Value::Bool(_) | Value::Null));
            if !valid {
                if let Some(mut value) = object.remove(&key) {
                    zeroize_value(&mut value);
                }
                stats.removed = stats.removed.saturating_add(1);
            }
            continue;
        }

        if is_secret_key(&key) {
            if let Some(mut value) = object.remove(&key) {
                stats.removed = stats.removed.saturating_add(1);
                stats.reentry_required |= value_has_secret_material(&value);
                zeroize_value(&mut value);
            }
            continue;
        }

        if let Some(value) = object.get_mut(&key) {
            scrub_value(value, stats);
        }
    }
}

fn scrub_value(value: &mut Value, stats: &mut ScrubStats) {
    match value {
        // An unknown non-secret field is compatibility data even when its text
        // happens to begin with the legacy ciphertext marker. Only a known
        // credential/secret key gives that marker secret semantics.
        Value::String(_) => {}
        Value::Array(values) => {
            for value in values {
                scrub_value(value, stats);
            }
        }
        Value::Object(object) => {
            scrub_object(object, stats);
        }
        _ => {}
    }
}

fn zeroize_value(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => {
            for value in values.iter_mut() {
                zeroize_value(value);
            }
            values.clear();
        }
        Value::Object(object) => {
            let entries = std::mem::take(object);
            for (mut key, mut value) in entries {
                key.zeroize();
                zeroize_value(&mut value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn value_has_secret_material(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(value) => !value.is_empty(),
        Value::Array(values) => !values.is_empty(),
        Value::Object(values) => !values.is_empty(),
        Value::Bool(_) | Value::Number(_) => true,
    }
}

fn is_secret_key(key: &str) -> bool {
    let normalized = normalize_key(key);
    normalized.contains("password")
        || normalized.contains("passphrase")
        || normalized.contains("privatekey")
        || normalized.contains("credentialref")
        || normalized.contains("credentialid")
        || normalized.contains("credentialkey")
        || normalized == "credential"
        || normalized == "credentials"
        || normalized == "secret"
        || normalized.ends_with("secret")
}

fn is_secret_status_key(key: &str) -> bool {
    matches!(
        normalize_key(key).as_str(),
        "savepassword"
            | "haspassword"
            | "savepassphrase"
            | "haspassphrase"
            | "hasprivatekey"
            | "hascredential"
    )
}

fn normalize_key(key: &str) -> String {
    key.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn sha256_digest(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: u64 = 1_700_000_000_000;
    const PLAINTEXT_SECRET: &str = "migration-only-password-9f61";
    const CIPHERTEXT: &str = "enc:v1:not-even-valid-base64%%%";

    fn host_json(extra: Value) -> Value {
        let mut host = json!({
            "id": "opaque:legacy/id?1",
            "label": "Legacy server",
            "hostname": "  example.com  accidental-argument ",
            "port": 2222,
            "username": "alice",
            "authMethod": "password",
            "authPolicyVersion": 1,
            "tags": [],
            "os": "linux"
        });
        host.as_object_mut()
            .expect("host object")
            .extend(extra.as_object().expect("extra object").clone());
        host
    }

    fn proxy_config(extra: Value) -> Value {
        let mut config = json!({
            "type": "http",
            "host": "proxy.example",
            "port": 8080
        });
        config
            .as_object_mut()
            .expect("proxy config")
            .extend(extra.as_object().expect("extra proxy config").clone());
        config
    }

    fn proxy_profile(id: &str, config: Value) -> Value {
        json!({
            "id": id,
            "label": format!("Proxy {id}"),
            "config": config,
            "created": 1
        })
    }

    fn parse_value(value: Value) -> LegacyVaultDocument {
        parse_legacy_vault_str(&serde_json::to_string(&value).expect("JSON"), NOW)
            .expect("legacy document")
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write as _;
            write!(encoded, "{byte:02x}").expect("write to String");
        }
        encoded
    }

    fn assert_preview_excludes_source_digest(document: &LegacyVaultDocument) {
        let preview_json = serde_json::to_string(document.preview()).expect("preview JSON");
        let preview_debug = format!("{:?}", document.preview());
        let counts_json = serde_json::to_string(document.preview().counts()).expect("counts JSON");
        let counts_debug = format!("{:?}", document.preview().counts());
        let raw_hex = hex_encode(document.source_sha256());
        let raw_json = serde_json::to_string(document.source_sha256()).expect("digest JSON");
        let raw_debug = format!("{:?}", document.source_sha256());

        for field_name in [
            "sourceFingerprint",
            "source_fingerprint",
            "sourceSha256",
            "source_sha256",
        ] {
            assert!(!preview_json.contains(field_name));
            assert!(!preview_debug.contains(field_name));
            assert!(!counts_json.contains(field_name));
            assert!(!counts_debug.contains(field_name));
        }
        for raw_representation in [&raw_hex, &raw_json, &raw_debug] {
            assert!(!preview_json.contains(raw_representation));
            assert!(!preview_debug.contains(raw_representation));
            assert!(!counts_json.contains(raw_representation));
            assert!(!counts_debug.contains(raw_representation));
        }
    }

    fn assert_safe_report_excludes(document: &LegacyVaultDocument, forbidden: &[&str]) {
        let preview_json = serde_json::to_string(document.preview()).expect("preview JSON");
        let preview_debug = format!("{:?}", document.preview());
        let counts_json = serde_json::to_string(document.preview().counts()).expect("counts JSON");
        let counts_debug = format!("{:?}", document.preview().counts());
        for value in forbidden {
            assert!(
                !preview_json.contains(value),
                "preview JSON leaked source data"
            );
            assert!(
                !preview_debug.contains(value),
                "preview Debug leaked source data"
            );
            assert!(
                !counts_json.contains(value),
                "counts JSON leaked source data"
            );
            assert!(
                !counts_debug.contains(value),
                "counts Debug leaked source data"
            );
        }
        assert_preview_excludes_source_digest(document);
    }

    #[test]
    fn parses_bare_host_array_and_normalizes_hostname_and_timestamps() {
        let document = parse_value(json!([host_json(json!({
            "createdAt": 123,
            "pluginFlag": false,
            "pluginEmpty": "",
            "pluginNull": null
        }))]));
        assert_eq!(
            document.preview().source_kind,
            LegacyVaultSourceKind::BareHostArray
        );
        assert_eq!(document.preview().counts().candidate_hosts, 1);
        let host = document.candidates()[0].host();
        assert_eq!(host.id.as_str(), "opaque:legacy/id?1");
        assert_eq!(host.hostname, "example.com");
        assert_eq!(host.created_at, 123);
        assert_eq!(host.updated_at, 123);
        assert_eq!(host.compatibility_fields()["pluginFlag"], false);
        assert_eq!(host.compatibility_fields()["pluginEmpty"], "");
        assert!(host.compatibility_fields()["pluginNull"].is_null());
        assert_eq!(
            host.compatibility_fields()["hasSavedCredential"],
            Value::Bool(false)
        );
    }

    #[test]
    fn parses_unversioned_vault_and_inventories_related_catalogs() {
        let document = parse_value(json!({
            "hosts": [host_json(json!({}))],
            "keys": [{"privateKey": PLAINTEXT_SECRET}],
            "identities": [{"password": PLAINTEXT_SECRET}]
        }));
        assert_eq!(
            document.preview().source_kind,
            LegacyVaultSourceKind::UnversionedVault
        );
        assert_eq!(document.candidates().len(), 1);
        assert_eq!(document.preview().counts().source_ssh_keys, 1);
        assert_eq!(document.preview().counts().source_identities, 1);
        assert_eq!(document.preview().counts().rejected_ssh_keys, 1);
        assert_eq!(document.preview().counts().rejected_identities, 1);
        assert_eq!(document.preview().counts().secret_fields_stripped, 2);
        let preview = serde_json::to_string(document.preview()).expect("preview JSON");
        assert!(!preview.contains(PLAINTEXT_SECRET));
    }

    #[test]
    fn parses_plain_json_v1_payload_data_as_json() {
        let inner = serde_json::to_string(&json!({
            "hosts": [host_json(json!({"protocol": "ssh"}))],
            "keys": []
        }))
        .expect("inner JSON");
        let document = parse_value(json!({
            "formatVersion": 1,
            "payloadEncoding": "plain-json-v1",
            "payloadData": inner
        }));
        assert_eq!(
            document.preview().source_kind,
            LegacyVaultSourceKind::VersionedPlainJsonV1
        );
        assert_eq!(document.candidates().len(), 1);
    }

    #[test]
    fn group_catalog_fields_preserve_absent_and_present_empty_in_unversioned_vaults() {
        let absent = parse_value(json!({ "hosts": [] }));
        assert!(absent.custom_groups().is_none());
        assert!(absent.group_config_candidates().is_none());

        let empty = parse_value(json!({
            "hosts": [],
            "customGroups": [],
            "groupConfigs": []
        }));
        assert_eq!(empty.custom_groups().map(|values| values.len()), Some(0));
        assert_eq!(
            empty.group_config_candidates().map(|values| values.len()),
            Some(0)
        );
        assert_eq!(empty.preview().counts().source_custom_groups, 0);
        assert_eq!(empty.preview().counts().candidate_custom_groups, 0);
        assert_eq!(empty.preview().counts().source_group_configs, 0);
        assert_eq!(empty.preview().counts().candidate_group_configs, 0);

        let absent_payload =
            serde_json::to_string(&json!({ "hosts": [] })).expect("absent backup payload");
        let absent_backup = parse_value(json!({
            "formatVersion": 1,
            "payloadEncoding": "plain-json-v1",
            "payloadData": absent_payload
        }));
        assert!(absent_backup.custom_groups().is_none());
        assert!(absent_backup.group_config_candidates().is_none());

        let empty_payload = serde_json::to_string(&json!({
            "hosts": [],
            "customGroups": [],
            "groupConfigs": []
        }))
        .expect("empty backup payload");
        let empty_backup = parse_value(json!({
            "formatVersion": 1,
            "payloadEncoding": "plain-json-v1",
            "payloadData": empty_payload
        }));
        assert_eq!(
            empty_backup.custom_groups().map(|values| values.len()),
            Some(0)
        );
        assert_eq!(
            empty_backup
                .group_config_candidates()
                .map(|values| values.len()),
            Some(0)
        );
    }

    #[test]
    fn plain_backup_group_catalogs_feed_complete_secret_free_preview_and_candidates() {
        let ssh_plaintext = "group-ssh-plaintext-sentinel";
        let telnet_plaintext = "group-telnet-plaintext-sentinel";
        let proxy_plaintext = "group-proxy-plaintext-sentinel";
        let encrypted = "enc:v1:group-device-bound-sentinel";
        let payload = serde_json::to_string(&json!({
            "hosts": [],
            "identities": [],
            "customGroups": [r"/ Team //Ops\DB/./"],
            "groupConfigs": [
                {
                    "path": r"Ops\DB// Team /./..",
                    "password": ssh_plaintext,
                    "telnetPassword": telnet_plaintext,
                    "proxyConfig": {
                        "type": "http",
                        "host": "proxy.example.test",
                        "port": 8080,
                        "username": "alice",
                        "password": proxy_plaintext
                    }
                },
                {
                    "path": "Needs/Reentry",
                    "password": encrypted,
                    "telnetPassword": encrypted,
                    "proxyConfig": {
                        "type": "socks5",
                        "host": "proxy.example.test",
                        "port": 1080,
                        "username": "alice",
                        "password": encrypted
                    }
                }
            ]
        }))
        .expect("backup payload");
        let document = parse_value(json!({
            "formatVersion": 1,
            "payloadEncoding": "plain-json-v1",
            "payloadData": payload
        }));

        assert_eq!(
            document.preview().source_kind,
            LegacyVaultSourceKind::VersionedPlainJsonV1
        );
        assert_eq!(
            document.custom_groups().expect("custom groups")[0].as_str(),
            r" Team /Ops\DB/."
        );
        let configs = document
            .group_config_candidates()
            .expect("group config candidates");
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].config().path.as_str(), r"Ops\DB/ Team /./..");

        let counts = document.preview().counts();
        assert_eq!(counts.source_custom_groups, 1);
        assert_eq!(counts.candidate_custom_groups, 1);
        assert_eq!(counts.source_group_configs, 2);
        assert_eq!(counts.candidate_group_configs, 2);
        assert_eq!(counts.group_config_ssh_password_candidates, 1);
        assert_eq!(counts.group_config_telnet_password_candidates, 1);
        assert_eq!(counts.group_config_inline_proxy_password_candidates, 1);
        assert_eq!(counts.group_config_ssh_credential_reentry_required, 1);
        assert_eq!(counts.group_config_telnet_credential_reentry_required, 1);
        assert_eq!(
            counts.group_config_inline_proxy_credential_reentry_required,
            1
        );
        assert_eq!(counts.secret_fields_stripped, 6);
        assert_eq!(document.preview().recoverable_credential_count, 3);
        assert_eq!(document.preview().requires_credential_reentry_count, 3);

        for code in [
            LegacyVaultIssueCode::GroupConfigSshCredentialReentryRequired,
            LegacyVaultIssueCode::GroupConfigTelnetCredentialReentryRequired,
            LegacyVaultIssueCode::GroupConfigProxyCredentialReentryRequired,
        ] {
            assert!(document.preview().issues.iter().any(|issue| {
                issue.code == code
                    && issue.record_kind == LegacyVaultRecordKind::GroupConfig
                    && issue.record_index == Some(1)
            }));
        }
        assert_eq!(
            document
                .preview()
                .issues
                .iter()
                .filter(|issue| issue.record_kind == LegacyVaultRecordKind::GroupConfig)
                .count(),
            5
        );
        assert_safe_report_excludes(
            &document,
            &[ssh_plaintext, telnet_plaintext, proxy_plaintext, encrypted],
        );

        let (_, group_catalogs) = document.into_group_catalog_parts();
        let mut candidates = group_catalogs.into_parts().1.expect("group configs");
        let (_, ssh, _, telnet, _, proxy, _) = candidates.remove(0).into_parts();
        assert_eq!(
            ssh.as_ref().and_then(|secret| secret.as_utf8().ok()),
            Some(ssh_plaintext)
        );
        assert_eq!(
            telnet.as_ref().and_then(|secret| secret.as_utf8().ok()),
            Some(telnet_plaintext)
        );
        assert_eq!(
            proxy.as_ref().and_then(|secret| secret.as_utf8().ok()),
            Some(proxy_plaintext)
        );
    }

    #[test]
    fn parses_reference_key_identity_and_host_relationships_without_reading_paths() {
        let key_id = "opaque-key-success-sentinel";
        let identity_id = "opaque-identity-success-sentinel";
        let key_label = "sensitive-key-label-sentinel";
        let identity_label = "sensitive-identity-label-sentinel";
        let file_path = r"\\never-open-this-host.invalid\share\key-path-sentinel";
        let direct_path = r"Z:\definitely-missing\direct-key-path-sentinel";
        let document = parse_value(json!({
            "hosts": [host_json(json!({
                "id": "relationship-host",
                "authMethod": "key",
                "authPolicyVersion": 1,
                "identityId": identity_id,
                "identityFileId": key_id,
                "identityFilePaths": [direct_path]
            }))],
            "keys": [{
                "id": key_id,
                "label": key_label,
                "type": "ED25519",
                "privateKey": "",
                "source": "reference",
                "category": "key",
                "created": 11,
                "filePath": file_path,
                "legacyNull": null,
                "legacyFalse": false
            }],
            "identities": [{
                "id": identity_id,
                "label": identity_label,
                "username": "identity-user",
                "authMethod": "key",
                "keyId": key_id,
                "created": 12,
                "legacyEmpty": ""
            }]
        }));

        let counts = document.preview().counts();
        assert_eq!(counts.source_ssh_keys, 1);
        assert_eq!(counts.candidate_ssh_key_references, 1);
        assert_eq!(counts.source_identities, 1);
        assert_eq!(counts.candidate_identity_references, 1);
        assert_eq!(counts.candidate_hosts, 1);
        assert_eq!(document.candidates().len(), 1);
        assert_eq!(document.ssh_key_reference_candidates().len(), 1);
        assert_eq!(document.identity_reference_candidates().len(), 1);
        assert_eq!(
            document.candidates()[0].host().compatibility_fields()["identityId"],
            identity_id
        );
        assert_eq!(
            document.candidates()[0].host().compatibility_fields()["identityFileId"],
            key_id
        );
        assert_eq!(
            document.candidates()[0].host().compatibility_fields()["identityFilePaths"],
            json!([direct_path])
        );
        assert_safe_report_excludes(
            &document,
            &[
                key_id,
                identity_id,
                key_label,
                identity_label,
                file_path,
                direct_path,
            ],
        );

        let (_preview, hosts, keys, identities) = document.into_graph_parts();
        assert_eq!(hosts.len(), 1);
        let key = keys.into_iter().next().expect("key").into_reference();
        assert_eq!(key.id.as_str(), key_id);
        assert_eq!(key.label, key_label);
        assert_eq!(key.file_path, file_path);
        assert_eq!(key.compatibility_fields()["legacyNull"], Value::Null);
        assert_eq!(key.compatibility_fields()["legacyFalse"], false);
        let identity = identities
            .into_iter()
            .next()
            .expect("identity")
            .into_reference();
        assert_eq!(identity.id.as_str(), identity_id);
        assert_eq!(identity.key_id.as_str(), key_id);
        assert_eq!(identity.label, identity_label);
        assert_eq!(identity.compatibility_fields()["legacyEmpty"], "");
    }

    #[test]
    fn plaintext_embedded_key_becomes_only_a_managed_zeroizing_candidate() {
        let key_id = "managed-key-id-private-sentinel";
        let label = "managed-key-label-private-sentinel";
        let private_key = [
            "-----BEGIN PRIVATE",
            " KEY-----\nprivate-managed-sentinel\n-----END PRIVATE",
            " KEY-----",
        ]
        .concat();
        let public_key = "ssh-ed25519 public-managed-sentinel";
        let certificate = "ssh-ed25519-cert-v01@openssh.com certificate-managed-sentinel";
        let passphrase = "passphrase-managed-sentinel";
        let legacy_path = "C:\\keys\\managed-path-sentinel";
        let document = parse_value(json!({
            "hosts": [],
            "keys": [{
                "id": key_id,
                "label": label,
                "source": "IMPORTED",
                "category": "identity",
                "privateKey": private_key,
                "publicKey": public_key,
                "certificate": certificate,
                "passphrase": passphrase,
                "savePassphrase": true,
                "filePath": legacy_path,
                "type": "ed25519",
                "created": 12,
                "updatedAt": 18
            }],
            "identities": []
        }));

        let counts = document.preview().counts();
        assert_eq!(counts.candidate_managed_ssh_keys, 1);
        assert_eq!(counts.candidate_ssh_key_references, 0);
        assert_eq!(counts.managed_ssh_key_recovery_required, 0);
        assert_eq!(document.managed_ssh_key_candidates().len(), 1);
        let candidate = &document.managed_ssh_key_candidates()[0];
        assert_eq!(candidate.metadata().id().as_str(), key_id);
        assert_eq!(candidate.metadata().label(), label);
        assert_eq!(candidate.metadata().source().as_str(), "imported");
        assert_eq!(candidate.metadata().category().as_str(), "identity");
        assert!(candidate.metadata().has_saved_passphrase());
        assert_eq!(candidate.metadata().created_at(), 12);
        assert_eq!(candidate.metadata().updated_at(), 18);
        assert_eq!(
            candidate.metadata().compatibility_fields()["type"],
            "ed25519"
        );
        assert!(
            !candidate
                .metadata()
                .compatibility_fields()
                .contains_key("filePath")
        );
        assert_eq!(
            candidate.secret_bundle().private_key(),
            private_key.as_bytes()
        );
        assert_eq!(
            candidate.secret_bundle().public_key(),
            Some(public_key.as_bytes())
        );
        assert_eq!(
            candidate.secret_bundle().certificate(),
            Some(certificate.as_bytes())
        );
        assert_eq!(
            candidate.secret_bundle().passphrase(),
            Some(passphrase.as_bytes())
        );
        assert_safe_report_excludes(
            &document,
            &[
                key_id,
                label,
                private_key.as_str(),
                public_key,
                certificate,
                passphrase,
                legacy_path,
            ],
        );
    }

    #[test]
    fn certificate_key_identity_and_host_form_one_supported_relationship_graph() {
        let key_id = "managed-certificate-key-sentinel";
        let identity_id = "managed-certificate-identity-sentinel";
        let private_key = "certificate-private-key-sentinel";
        let certificate = "certificate-public-material-sentinel";
        let document = parse_value(json!({
            "hosts": [host_json(json!({
                "id": "managed-certificate-host-sentinel",
                "authMethod": "certificate",
                "identityId": identity_id
            }))],
            "keys": [{
                "id": key_id,
                "label": "Managed certificate",
                "source": "generated",
                "category": "certificate",
                "privateKey": private_key,
                "certificate": certificate,
                "created": 4
            }],
            "identities": [{
                "id": identity_id,
                "label": "Certificate identity",
                "username": "certificate-user",
                "authMethod": "certificate",
                "keyId": key_id,
                "created": 5
            }]
        }));

        assert_eq!(document.managed_ssh_key_candidates().len(), 1);
        assert!(document.identity_reference_candidates().is_empty());
        assert_eq!(document.managed_identity_reference_candidates().len(), 1);
        assert!(document.candidates().is_empty());
        assert_eq!(document.managed_key_host_candidates().len(), 1);
        assert_eq!(
            document.managed_identity_reference_candidates()[0]
                .reference()
                .auth_method
                .as_str(),
            "certificate"
        );
        assert_eq!(
            document.managed_key_host_candidates()[0]
                .host()
                .auth_method
                .as_str(),
            "certificate"
        );
        assert!(document.managed_key_host_candidates()[0].is_currently_importable());
        assert_eq!(document.preview().counts().candidate_managed_key_hosts, 1);
        assert_eq!(
            document
                .preview()
                .counts()
                .candidate_managed_identity_references,
            1
        );
        assert_eq!(document.preview().counts().missing_key_references, 0);
        assert_eq!(document.preview().counts().missing_identity_references, 0);
        assert_safe_report_excludes(
            &document,
            &[
                key_id,
                identity_id,
                private_key,
                certificate,
                "certificate-user",
            ],
        );
    }

    #[test]
    fn managed_passphrase_is_explicitly_discarded_when_policy_is_false() {
        let passphrase = "discarded-managed-passphrase-sentinel";
        let document = parse_value(json!({
            "hosts": [],
            "keys": [{
                "id": "managed-policy-key-sentinel",
                "label": "Managed policy key",
                "source": "imported",
                "category": "key",
                "privateKey": "managed-policy-private-sentinel",
                "passphrase": passphrase,
                "savePassphrase": false,
                "created": 1
            }]
        }));

        let candidate = &document.managed_ssh_key_candidates()[0];
        assert_eq!(candidate.secret_bundle().passphrase(), None);
        assert_eq!(
            candidate.metadata().passphrase_disposition(),
            LegacyManagedPassphraseDisposition::DiscardedByPolicy
        );
        assert!(!candidate.metadata().has_saved_passphrase());
        assert_eq!(
            document
                .preview()
                .counts()
                .managed_passphrases_discarded_by_policy,
            1
        );
        assert!(document.preview().issues.iter().any(|issue| {
            issue.record_kind == LegacyVaultRecordKind::SshKey
                && issue.code == LegacyVaultIssueCode::SshKeyPassphraseNotSavedByPolicy
        }));
        assert_safe_report_excludes(&document, &[passphrase]);
    }

    #[test]
    fn missing_legacy_source_and_category_follow_the_frozen_migration_defaults() {
        let document = parse_value(json!({
            "hosts": [],
            "keys": [
                {
                    "id": "inferred-imported-key",
                    "label": "Inferred imported",
                    "privateKey": "inferred-imported-private"
                },
                {
                    "id": "inferred-certificate-key",
                    "label": "Inferred certificate",
                    "privateKey": "inferred-certificate-private",
                    "certificate": "inferred-certificate-material"
                }
            ]
        }));

        assert_eq!(document.managed_ssh_key_candidates().len(), 2);
        let imported = &document.managed_ssh_key_candidates()[0];
        assert_eq!(imported.metadata().source().as_str(), "imported");
        assert_eq!(imported.metadata().category().as_str(), "key");
        let certificate = &document.managed_ssh_key_candidates()[1];
        assert_eq!(certificate.metadata().source().as_str(), "imported");
        assert_eq!(certificate.metadata().category().as_str(), "certificate");
        assert_safe_report_excludes(
            &document,
            &[
                "inferred-imported-private",
                "inferred-certificate-private",
                "inferred-certificate-material",
            ],
        );
    }

    #[test]
    fn reference_only_graph_api_cannot_observe_managed_dependencies() {
        let source = json!({
            "hosts": [host_json(json!({
                "id": "managed-isolation-host",
                "authMethod": "key",
                "identityId": "managed-isolation-identity"
            }))],
            "keys": [{
                "id": "managed-isolation-key",
                "source": "imported",
                "category": "key",
                "privateKey": "managed-isolation-private"
            }],
            "identities": [{
                "id": "managed-isolation-identity",
                "label": "Managed isolation identity",
                "username": "managed-user",
                "authMethod": "key",
                "keyId": "managed-isolation-key",
                "created": 1
            }]
        });

        let old_document = parse_value(source.clone());
        let (_preview, hosts, reference_keys, identities) = old_document.into_graph_parts();
        assert!(hosts.is_empty());
        assert!(reference_keys.is_empty());
        assert!(identities.is_empty());

        let complete_document = parse_value(source);
        let (_preview, hosts, reference_keys, managed_keys, identities) =
            complete_document.into_complete_graph_parts();
        assert_eq!(hosts.len(), 1);
        assert!(reference_keys.is_empty());
        assert_eq!(managed_keys.len(), 1);
        assert_eq!(identities.len(), 1);
    }

    #[test]
    fn encrypted_missing_empty_and_invalid_managed_secrets_fail_closed() {
        let invalid_records = vec![
            json!({
                "id": "encrypted-private",
                "source": "imported",
                "privateKey": CIPHERTEXT
            }),
            json!({
                "id": "encrypted-passphrase",
                "source": "generated",
                "privateKey": "plain-private-a",
                "passphrase": CIPHERTEXT,
                "savePassphrase": false
            }),
            json!({
                "id": "missing-private",
                "source": "generated"
            }),
            json!({
                "id": "null-private",
                "source": "imported",
                "privateKey": null
            }),
            json!({
                "id": "empty-private",
                "source": "imported",
                "privateKey": "   \r\n"
            }),
            json!({
                "id": "typed-private",
                "source": "imported",
                "privateKey": ["not", "text"]
            }),
            json!({
                "id": "typed-public",
                "source": "generated",
                "privateKey": "plain-private-b",
                "publicKey": 7
            }),
            json!({
                "id": "typed-certificate",
                "source": "generated",
                "privateKey": "plain-private-c",
                "certificate": {"invalid": true}
            }),
            json!({
                "id": "typed-passphrase",
                "source": "generated",
                "privateKey": "plain-private-d",
                "passphrase": true,
                "savePassphrase": true
            }),
            json!({
                "id": "typed-policy",
                "source": "generated",
                "privateKey": "plain-private-e",
                "savePassphrase": "true"
            }),
            json!({
                "id": "certificate-without-certificate",
                "source": "generated",
                "category": "certificate",
                "privateKey": "plain-private-f"
            }),
        ];
        let document = parse_value(json!({"hosts": [], "keys": invalid_records}));

        assert!(document.managed_ssh_key_candidates().is_empty());
        assert_eq!(document.preview().counts().unsupported_ssh_keys, 11);
        assert_eq!(
            document
                .preview()
                .counts()
                .managed_ssh_key_recovery_required,
            11
        );
        for index in 0..11 {
            assert!(document.preview().issues.iter().any(|issue| {
                issue.record_kind == LegacyVaultRecordKind::SshKey
                    && issue.record_index == Some(index)
                    && issue.code == LegacyVaultIssueCode::SshKeyCredentialRecoveryRequired
            }));
        }
        assert_safe_report_excludes(
            &document,
            &[CIPHERTEXT, "plain-private-a", "plain-private-f"],
        );
    }

    #[test]
    fn every_managed_secret_field_enforces_the_secret_store_size_limit() {
        let cases = [
            (
                "oversized-private",
                json!({
                    "privateKey": "p".repeat(MAX_PRIVATE_KEY_BYTES + 1)
                }),
            ),
            (
                "oversized-public",
                json!({
                    "privateKey": "private",
                    "publicKey": "u".repeat(MAX_PUBLIC_KEY_BYTES + 1)
                }),
            ),
            (
                "oversized-certificate",
                json!({
                    "privateKey": "private",
                    "certificate": "c".repeat(MAX_CERTIFICATE_BYTES + 1)
                }),
            ),
            (
                "oversized-passphrase",
                json!({
                    "privateKey": "private",
                    "passphrase": "s".repeat(MAX_PASSPHRASE_BYTES + 1),
                    "savePassphrase": true
                }),
            ),
        ];

        for (id, fields) in cases {
            let mut record = json!({
                "id": id,
                "source": "imported",
                "category": "key"
            });
            record
                .as_object_mut()
                .expect("record")
                .extend(fields.as_object().expect("fields").clone());
            let document = parse_value(json!({"hosts": [], "keys": [record]}));
            assert!(document.managed_ssh_key_candidates().is_empty());
            assert_eq!(document.preview().counts().unsupported_ssh_keys, 1);
            assert_eq!(
                document
                    .preview()
                    .counts()
                    .managed_ssh_key_recovery_required,
                1
            );
        }
    }

    #[test]
    fn duplicate_ids_share_one_namespace_across_reference_and_managed_keys() {
        let duplicate_id = "cross-catalog-duplicate-key-sentinel";
        let managed_first = parse_value(json!({
            "hosts": [],
            "keys": [
                {
                    "id": duplicate_id,
                    "source": "imported",
                    "category": "key",
                    "privateKey": "first-managed-private-sentinel"
                },
                {
                    "id": duplicate_id,
                    "source": "reference",
                    "category": "key",
                    "filePath": "second-reference-path-sentinel"
                }
            ]
        }));
        assert_eq!(managed_first.managed_ssh_key_candidates().len(), 1);
        assert!(managed_first.ssh_key_reference_candidates().is_empty());
        assert_eq!(managed_first.preview().counts().duplicate_ssh_keys, 1);

        let reference_first = parse_value(json!({
            "hosts": [],
            "keys": [
                {
                    "id": duplicate_id,
                    "source": "reference",
                    "category": "key",
                    "filePath": "first-reference-path-sentinel"
                },
                {
                    "id": duplicate_id,
                    "source": "generated",
                    "category": "key",
                    "privateKey": "second-managed-private-sentinel"
                }
            ]
        }));
        assert_eq!(reference_first.ssh_key_reference_candidates().len(), 1);
        assert!(reference_first.managed_ssh_key_candidates().is_empty());
        assert_eq!(reference_first.preview().counts().duplicate_ssh_keys, 1);
        assert_safe_report_excludes(
            &managed_first,
            &[duplicate_id, "first-managed-private-sentinel"],
        );
        assert_safe_report_excludes(
            &reference_first,
            &[duplicate_id, "second-managed-private-sentinel"],
        );
    }

    #[test]
    fn identity_authentication_kind_must_match_the_managed_key_category() {
        let key_id = "managed-kind-mismatch-key-sentinel";
        let identity_id = "managed-kind-mismatch-identity-sentinel";
        let document = parse_value(json!({
            "hosts": [],
            "keys": [{
                "id": key_id,
                "source": "generated",
                "category": "key",
                "privateKey": "managed-kind-mismatch-private-sentinel"
            }],
            "identities": [{
                "id": identity_id,
                "label": "Mismatched certificate identity",
                "authMethod": "certificate",
                "keyId": key_id,
                "created": 1
            }]
        }));

        assert_eq!(document.managed_ssh_key_candidates().len(), 1);
        assert!(document.identity_reference_candidates().is_empty());
        assert_eq!(document.preview().counts().unsupported_identities, 1);
        assert_eq!(document.preview().counts().missing_key_references, 1);
        assert_safe_report_excludes(&document, &[key_id, identity_id]);
    }

    #[test]
    fn available_key_identity_overrides_host_username_and_auth_method() {
        let key_id = "identity-override-key-id-sentinel";
        let identity_id = "identity-override-id-sentinel";
        let identity_username = "identity-override-user-sentinel";
        let host_username = "host-user-must-be-overridden-sentinel";
        let key_path = r"\\never-open.invalid\identity-override-key-path-sentinel";
        let document = parse_value(json!({
            "hosts": [host_json(json!({
                "id": "identity-override-host",
                "username": host_username,
                "authMethod": "password",
                "authPolicyVersion": 1,
                "identityId": identity_id
            }))],
            "keys": [{
                "id": key_id,
                "label": "Identity override key",
                "source": "reference",
                "category": "key",
                "created": 1,
                "filePath": key_path
            }],
            "identities": [{
                "id": identity_id,
                "label": "Identity override",
                "username": identity_username,
                "authMethod": "key",
                "keyId": key_id,
                "created": 1
            }]
        }));

        assert_eq!(document.candidates().len(), 1);
        assert!(document.unsupported_candidates().is_empty());
        let host = document.candidates()[0].host();
        assert_eq!(host.username, identity_username);
        assert_eq!(host.auth_method.as_str(), "key");
        assert_eq!(host.compatibility_fields()["identityId"], identity_id);
        assert_safe_report_excludes(
            &document,
            &[
                key_id,
                identity_id,
                identity_username,
                host_username,
                key_path,
            ],
        );
    }

    #[test]
    fn empty_key_identity_username_falls_back_to_the_host_username() {
        let key_id = "empty-identity-username-key-id-sentinel";
        let identity_id = "empty-identity-username-id-sentinel";
        let host_username = "fallback-host-user-sentinel";
        let document = parse_value(json!({
            "hosts": [host_json(json!({
                "id": "empty-identity-username-host",
                "username": host_username,
                "authMethod": "auto",
                "authPolicyVersion": 1,
                "identityId": identity_id
            }))],
            "keys": [{
                "id": key_id,
                "label": "Empty username key",
                "source": "reference",
                "category": "key",
                "created": 1,
                "filePath": "empty-identity-username-key-path-sentinel"
            }],
            "identities": [{
                "id": identity_id,
                "label": "Empty username identity",
                "username": "   ",
                "authMethod": "key",
                "keyId": key_id,
                "created": 1
            }]
        }));

        assert_eq!(document.candidates().len(), 1);
        let host = document.candidates()[0].host();
        assert_eq!(host.username, host_username);
        assert_eq!(host.auth_method.as_str(), "key");
        assert_safe_report_excludes(&document, &[key_id, identity_id, host_username]);
    }

    #[test]
    fn auto_auth_normalizes_to_key_only_with_an_available_key_source() {
        let key_id = "auto-reference-key-id-sentinel";
        let identity_id = "auto-identity-id-sentinel";
        let direct_path = r"Z:\never-open\auto-direct-key-path-sentinel";
        let reference_path = r"Z:\never-open\auto-reference-key-path-sentinel";
        let document = parse_value(json!({
            "hosts": [
                host_json(json!({
                    "id": "auto-reference-host",
                    "authMethod": "auto",
                    "authPolicyVersion": 1,
                    "identityFileId": key_id
                })),
                host_json(json!({
                    "id": "auto-identity-host",
                    "authMethod": "AUTO",
                    "authPolicyVersion": 1,
                    "identityId": identity_id
                })),
                host_json(json!({
                    "id": "auto-direct-path-host",
                    "authMethod": "auto",
                    "authPolicyVersion": 1,
                    "identityFilePaths": [direct_path]
                })),
                host_json(json!({
                    "id": "auto-without-key-source-host",
                    "authMethod": "auto",
                    "authPolicyVersion": 1
                }))
            ],
            "keys": [{
                "id": key_id,
                "label": "Auto reference key",
                "source": "reference",
                "category": "key",
                "created": 1,
                "filePath": reference_path
            }],
            "identities": [{
                "id": identity_id,
                "label": "Auto identity",
                "username": "auto-identity-user-sentinel",
                "authMethod": "key",
                "keyId": key_id,
                "created": 1
            }]
        }));

        assert_eq!(document.candidates().len(), 3);
        assert!(
            document
                .candidates()
                .iter()
                .all(|candidate| candidate.host().auth_method.as_str() == "key")
        );
        assert_eq!(document.unsupported_candidates().len(), 1);
        assert_eq!(
            document.unsupported_candidates()[0]
                .host()
                .auth_method
                .as_str(),
            "auto"
        );
        assert_eq!(document.preview().importable_count, 3);
        assert_eq!(document.preview().unsupported_count, 1);
        assert_safe_report_excludes(
            &document,
            &[key_id, identity_id, direct_path, reference_path],
        );
    }

    #[test]
    fn identity_file_paths_enforce_count_size_content_and_uniqueness_bounds() {
        let eight_paths = (0..MAX_LEGACY_IDENTITY_FILE_PATHS)
            .map(|index| Value::String(format!("path-{index}")))
            .collect::<Vec<_>>();
        assert!(matches!(
            identity_file_paths_state(Some(&Value::Array(eight_paths))),
            RelationshipState::Available
        ));

        let nine_paths = (0..=MAX_LEGACY_IDENTITY_FILE_PATHS)
            .map(|index| Value::String(format!("path-{index}")))
            .collect::<Vec<_>>();
        assert!(matches!(
            identity_file_paths_state(Some(&Value::Array(nine_paths))),
            RelationshipState::Missing
        ));

        let maximum_path = "x".repeat(MAX_LEGACY_IDENTITY_FILE_PATH_BYTES);
        assert!(matches!(
            identity_file_paths_state(Some(&json!([maximum_path]))),
            RelationshipState::Available
        ));
        let oversized_path = "x".repeat(MAX_LEGACY_IDENTITY_FILE_PATH_BYTES + 1);
        assert!(matches!(
            identity_file_paths_state(Some(&json!([oversized_path]))),
            RelationshipState::Missing
        ));

        let total_half_a = "a".repeat(MAX_LEGACY_IDENTITY_FILE_PATH_BYTES);
        let total_half_b = "b".repeat(MAX_LEGACY_IDENTITY_FILE_PATH_BYTES);
        assert!(matches!(
            identity_file_paths_state(Some(&json!([total_half_a, total_half_b]))),
            RelationshipState::Available
        ));
        let total_half_a = "a".repeat(MAX_LEGACY_IDENTITY_FILE_PATH_BYTES);
        let total_half_b = "b".repeat(MAX_LEGACY_IDENTITY_FILE_PATH_BYTES);
        assert!(matches!(
            identity_file_paths_state(Some(&json!([total_half_a, total_half_b, "overflow"]))),
            RelationshipState::Missing
        ));

        for invalid_paths in [
            json!([""]),
            json!(["   "]),
            json!(["bad\npath"]),
            json!(["bad\tpath"]),
            json!(["bad\0path"]),
            json!(["same-path", "same-path"]),
            json!(["valid", 7]),
        ] {
            assert!(matches!(
                identity_file_paths_state(Some(&invalid_paths)),
                RelationshipState::Missing
            ));
        }
    }

    #[test]
    fn invalid_identity_file_paths_report_only_the_fixed_preview_issue() {
        let duplicate_path = r"Z:\preview-must-not-leak\duplicate-path-sentinel";
        let control_path = "control-path-sentinel\n";
        let oversized_path = format!(
            "oversized-path-sentinel{}",
            "x".repeat(MAX_LEGACY_IDENTITY_FILE_PATH_BYTES)
        );
        let too_many_paths = (0..=MAX_LEGACY_IDENTITY_FILE_PATHS)
            .map(|index| Value::String(format!("too-many-path-sentinel-{index}")))
            .collect::<Vec<_>>();
        let aggregate_prefix_a = "aggregate-a-path-sentinel";
        let aggregate_prefix_b = "aggregate-b-path-sentinel";
        let aggregate_a = format!(
            "{aggregate_prefix_a}{}",
            "a".repeat(MAX_LEGACY_IDENTITY_FILE_PATH_BYTES - aggregate_prefix_a.len())
        );
        let aggregate_b = format!(
            "{aggregate_prefix_b}{}",
            "b".repeat(MAX_LEGACY_IDENTITY_FILE_PATH_BYTES - aggregate_prefix_b.len())
        );
        let aggregate_overflow = "aggregate-overflow-path-sentinel";
        let document = parse_value(json!({
            "hosts": [
                host_json(json!({
                    "id": "invalid-path-host-sentinel-count",
                    "authMethod": "auto",
                    "authPolicyVersion": 1,
                    "identityFilePaths": too_many_paths
                })),
                host_json(json!({
                    "id": "invalid-path-host-sentinel-size",
                    "authMethod": "auto",
                    "authPolicyVersion": 1,
                    "identityFilePaths": [oversized_path]
                })),
                host_json(json!({
                    "id": "invalid-path-host-sentinel-control",
                    "authMethod": "auto",
                    "authPolicyVersion": 1,
                    "identityFilePaths": [control_path]
                })),
                host_json(json!({
                    "id": "invalid-path-host-sentinel-duplicate",
                    "authMethod": "auto",
                    "authPolicyVersion": 1,
                    "identityFilePaths": [duplicate_path, duplicate_path]
                })),
                host_json(json!({
                    "id": "invalid-path-host-sentinel-aggregate",
                    "authMethod": "auto",
                    "authPolicyVersion": 1,
                    "identityFilePaths": [aggregate_a, aggregate_b, aggregate_overflow]
                })),
                host_json(json!({
                    "id": "invalid-path-host-sentinel-blank",
                    "authMethod": "auto",
                    "authPolicyVersion": 1,
                    "identityFilePaths": ["   "]
                }))
            ],
            "keys": [],
            "identities": []
        }));

        assert!(document.candidates().is_empty());
        assert_eq!(document.preview().unsupported_count, 6);
        assert_eq!(
            document.preview().counts().invalid_identity_file_path_hosts,
            6
        );
        for record_index in 0..6 {
            assert!(document.preview().issues.iter().any(|issue| {
                issue.record_kind == LegacyVaultRecordKind::Host
                    && issue.record_index == Some(record_index)
                    && issue.code == LegacyVaultIssueCode::InvalidIdentityFilePaths
            }));
        }
        let preview = serde_json::to_string(document.preview()).expect("preview JSON");
        assert!(preview.contains("LEGACY_INVALID_IDENTITY_FILE_PATHS"));
        assert_safe_report_excludes(
            &document,
            &[
                duplicate_path,
                "control-path-sentinel",
                "oversized-path-sentinel",
                "too-many-path-sentinel",
                aggregate_prefix_a,
                aggregate_prefix_b,
                aggregate_overflow,
                "invalid-path-host-sentinel",
            ],
        );
    }

    #[test]
    fn plain_backup_and_non_catalog_sources_keep_graph_inventory_semantics() {
        let payload = json!({
            "hosts": [],
            "keys": [{
                "id": "plain-backup-key",
                "label": "Plain backup key",
                "type": "ED25519",
                "privateKey": "",
                "source": "reference",
                "category": "key",
                "created": 1,
                "filePath": "C:\\keys\\plain-backup"
            }],
            "identities": [{
                "id": "plain-backup-identity",
                "label": "Plain backup identity",
                "username": "user",
                "authMethod": "key",
                "keyId": "plain-backup-key",
                "created": 1
            }]
        });
        let envelope = json!({
            "formatVersion": 1,
            "payloadEncoding": "plain-json-v1",
            "payloadData": serde_json::to_string(&payload).expect("payload JSON")
        });
        let plain = parse_value(envelope);
        assert_eq!(plain.preview().counts().candidate_ssh_key_references, 1);
        assert_eq!(plain.preview().counts().candidate_identity_references, 1);

        let bare = parse_value(json!([]));
        assert_eq!(bare.preview().counts().source_ssh_keys, 0);
        assert_eq!(bare.preview().counts().source_identities, 0);

        let safe_storage = parse_value(json!({
            "formatVersion": 1,
            "payloadEncoding": "safeStorage-v1",
            "payloadData": "opaque-device-bound-payload"
        }));
        assert_eq!(safe_storage.preview().counts().source_ssh_keys, 0);
        assert_eq!(safe_storage.preview().counts().source_identities, 0);
        assert!(safe_storage.ssh_key_reference_candidates().is_empty());
        assert!(safe_storage.identity_reference_candidates().is_empty());
        assert_preview_excludes_source_digest(&safe_storage);
    }

    #[test]
    fn missing_graph_targets_and_invalid_direct_paths_are_classified_safely() {
        let missing_key_id = "missing-key-id-sentinel";
        let missing_identity_id = "missing-identity-id-sentinel";
        let invalid_path = "invalid-path-sentinel";
        let document = parse_value(json!({
            "hosts": [host_json(json!({
                "id": "missing-relationship-host",
                "authMethod": "key",
                "authPolicyVersion": 1,
                "identityId": missing_identity_id,
                "identityFileId": missing_key_id,
                "identityFilePaths": [""]
            }))],
            "keys": [],
            "identities": [{
                "id": missing_identity_id,
                "label": "Missing target identity",
                "username": "user",
                "authMethod": "key",
                "keyId": missing_key_id,
                "created": 1,
                "opaquePathHint": invalid_path
            }]
        }));

        let counts = document.preview().counts();
        assert_eq!(counts.candidate_identity_references, 0);
        assert_eq!(counts.unsupported_identities, 1);
        assert_eq!(counts.missing_key_references, 2);
        assert_eq!(counts.missing_identity_references, 1);
        assert_eq!(counts.invalid_identity_file_path_hosts, 1);
        assert!(document.candidates().is_empty());
        assert_eq!(document.unsupported_candidates().len(), 1);
        assert!(document.preview().issues.iter().any(|issue| {
            issue.record_kind == LegacyVaultRecordKind::Identity
                && issue.code == LegacyVaultIssueCode::MissingSshKeyReference
        }));
        assert!(document.preview().issues.iter().any(|issue| {
            issue.record_kind == LegacyVaultRecordKind::Host
                && issue.code == LegacyVaultIssueCode::MissingIdentityReference
        }));
        assert!(document.preview().issues.iter().any(|issue| {
            issue.record_kind == LegacyVaultRecordKind::Host
                && issue.code == LegacyVaultIssueCode::InvalidIdentityFilePaths
        }));
        assert_safe_report_excludes(
            &document,
            &[missing_key_id, missing_identity_id, invalid_path],
        );
    }

    #[test]
    fn duplicate_key_and_identity_ids_never_reach_owned_graph_candidates() {
        let duplicate_key_id = "duplicate-key-id-sentinel";
        let duplicate_identity_id = "duplicate-identity-id-sentinel";
        let document = parse_value(json!({
            "hosts": [],
            "keys": [
                {
                    "id": duplicate_key_id,
                    "label": "First key label sentinel",
                    "source": "reference",
                    "category": "key",
                    "created": 1,
                    "filePath": "C:\\keys\\first-path-sentinel"
                },
                {
                    "id": duplicate_key_id,
                    "label": "Second key label sentinel",
                    "source": "reference",
                    "category": "key",
                    "created": 2,
                    "filePath": "C:\\keys\\second-path-sentinel"
                }
            ],
            "identities": [
                {
                    "id": duplicate_identity_id,
                    "label": "First identity label sentinel",
                    "username": "first",
                    "authMethod": "key",
                    "keyId": duplicate_key_id,
                    "created": 1
                },
                {
                    "id": duplicate_identity_id,
                    "label": "Second identity label sentinel",
                    "username": "second",
                    "authMethod": "key",
                    "keyId": duplicate_key_id,
                    "created": 2
                }
            ]
        }));

        assert_eq!(document.preview().counts().duplicate_ssh_keys, 1);
        assert_eq!(document.preview().counts().duplicate_identities, 1);
        assert_eq!(document.ssh_key_reference_candidates().len(), 1);
        assert_eq!(document.identity_reference_candidates().len(), 1);
        assert!(document.preview().issues.iter().any(|issue| {
            issue.record_kind == LegacyVaultRecordKind::SshKey
                && issue.code == LegacyVaultIssueCode::DuplicateSshKeyId
                && issue.record_index == Some(1)
        }));
        assert!(document.preview().issues.iter().any(|issue| {
            issue.record_kind == LegacyVaultRecordKind::Identity
                && issue.code == LegacyVaultIssueCode::DuplicateIdentityId
                && issue.record_index == Some(1)
        }));
        assert_safe_report_excludes(
            &document,
            &[
                duplicate_key_id,
                duplicate_identity_id,
                "first-path-sentinel",
                "second-path-sentinel",
                "First key label sentinel",
                "Second identity label sentinel",
            ],
        );
    }

    #[test]
    fn unsupported_key_material_and_key_identities_do_not_regress_as_password_identities_land() {
        let private_key = "private-key-material-sentinel";
        let encrypted_passphrase = "enc:v1:passphrase-ciphertext-sentinel";
        let certificate = "certificate-material-sentinel";
        let identity_password = "identity-password-sentinel";
        let nested_reference = "opaque-credential-reference-sentinel";
        let sensitive_path = "C:\\sensitive-path-sentinel\\id";
        let document = parse_value(json!({
            "hosts": [host_json(json!({
                "id": "certificate-host-id-sentinel",
                "authMethod": "certificate",
                "authPolicyVersion": 1,
                "identityFileId": "supported-reference-key"
            }))],
            "keys": [
                {
                    "id": "supported-reference-key",
                    "label": "Supported reference",
                    "source": "reference",
                    "category": "key",
                    "created": 1,
                    "filePath": "C:\\keys\\supported"
                },
                {
                    "id": "private-key-record",
                    "label": "Private key record",
                    "source": "reference",
                    "category": "key",
                    "created": 1,
                    "filePath": sensitive_path,
                    "privateKey": private_key
                },
                {
                    "id": "passphrase-record",
                    "label": "Passphrase record",
                    "source": "reference",
                    "category": "key",
                    "created": 1,
                    "filePath": sensitive_path,
                    "passphrase": encrypted_passphrase
                },
                {
                    "id": "certificate-record",
                    "label": "Certificate record",
                    "source": "reference",
                    "category": "certificate",
                    "created": 1,
                    "filePath": sensitive_path,
                    "certificate": certificate
                }
            ],
            "identities": [
                {
                    "id": "password-identity",
                    "label": "Password identity",
                    "username": "user",
                    "authMethod": "password",
                    "password": identity_password,
                    "created": 1
                },
                {
                    "id": "certificate-identity",
                    "label": "Certificate identity",
                    "username": "user",
                    "authMethod": "certificate",
                    "keyId": "supported-reference-key",
                    "created": 1
                },
                {
                    "id": "nested-secret-identity",
                    "label": "Nested secret identity",
                    "username": "user",
                    "authMethod": "key",
                    "keyId": "supported-reference-key",
                    "created": 1,
                    "pluginConfig": {"credentialRef": nested_reference}
                },
                {
                    "id": "password-identity-missing-secret",
                    "label": "Password identity without stored password",
                    "username": "user",
                    "authMethod": "password",
                    "created": 1
                }
            ]
        }));

        let counts = document.preview().counts();
        assert_eq!(counts.candidate_ssh_key_references, 1);
        assert_eq!(counts.unsupported_ssh_keys, 3);
        assert_eq!(counts.candidate_identity_references, 0);
        assert_eq!(counts.candidate_password_identities, 2);
        assert_eq!(counts.password_identity_password_candidates, 1);
        assert_eq!(counts.password_identity_credential_reentry_required, 1);
        assert_eq!(counts.unsupported_identities, 2);
        assert_eq!(document.password_identity_candidates().len(), 2);
        assert!(document.candidates().is_empty());
        assert_eq!(document.unsupported_candidates().len(), 1);
        assert!(
            document.preview().issues.iter().any(|issue| {
                issue.code == LegacyVaultIssueCode::SshKeyCredentialRecoveryRequired
            })
        );
        assert!(document.preview().issues.iter().any(|issue| {
            issue.code == LegacyVaultIssueCode::IdentityCredentialReentryRequired
        }));
        assert!(document.preview().issues.iter().any(|issue| {
            issue.record_kind == LegacyVaultRecordKind::Identity
                && issue.record_index == Some(3)
                && issue.code == LegacyVaultIssueCode::IdentityCredentialReentryRequired
        }));
        assert!(
            document
                .preview()
                .issues
                .iter()
                .any(|issue| { issue.code == LegacyVaultIssueCode::SshCertificateUnsupported })
        );
        assert_safe_report_excludes(
            &document,
            &[
                private_key,
                encrypted_passphrase,
                certificate,
                identity_password,
                nested_reference,
                sensitive_path,
                "private-key-record",
                "password-identity",
                "password-identity-missing-secret",
                "certificate-host-id-sentinel",
            ],
        );
    }

    #[test]
    fn plaintext_password_identity_preserves_metadata_once_for_shared_hosts() {
        let identity_id = "shared-password-identity-id-sentinel";
        let label = "shared-password-identity-label-sentinel";
        let username = "shared-password-identity-user-sentinel";
        let password = "shared-password-identity-secret-sentinel";
        let residual_key_id = "stale-password-identity-key-sentinel";
        let document = parse_value(json!({
            "hosts": [
                host_json(json!({
                    "id": "password-identity-host-a",
                    "identityId": identity_id
                })),
                host_json(json!({
                    "id": "password-identity-host-b",
                    "identityId": identity_id
                }))
            ],
            "keys": [],
            "identities": [{
                "id": identity_id,
                "label": label,
                "username": username,
                "authMethod": "PASSWORD",
                "password": password,
                "keyId": residual_key_id,
                "created": 17,
                "order": 2000,
                "legacyFlag": false
            }]
        }));

        let counts = document.preview().counts();
        assert_eq!(counts.candidate_password_identities, 1);
        assert_eq!(counts.candidate_password_identity_hosts, 2);
        assert_eq!(counts.password_identity_password_candidates, 1);
        assert_eq!(counts.password_identity_credential_reentry_required, 0);
        assert_eq!(counts.password_identity_residual_key_references, 1);
        assert_eq!(document.password_identity_candidates().len(), 1);
        assert_eq!(document.password_identity_host_candidates().len(), 2);
        assert!(document.candidates().is_empty());
        assert!(document.preview().issues.iter().any(|issue| {
            issue.record_kind == LegacyVaultRecordKind::Identity
                && issue.record_index == Some(0)
                && issue.code == LegacyVaultIssueCode::PasswordIdentityResidualKeyReferenceIgnored
        }));

        let candidate = &document.password_identity_candidates()[0];
        assert_eq!(candidate.identity().id.as_str(), identity_id);
        assert_eq!(candidate.identity().label, label);
        assert_eq!(candidate.identity().username, username);
        assert_eq!(candidate.identity().created_at, 17);
        assert_eq!(candidate.order(), Some(2000.0));
        assert!(!candidate.identity().has_saved_credential);
        assert!(candidate.has_password_candidate());
        assert_eq!(
            candidate.credential_disposition(),
            LegacyPasswordIdentityCredentialDisposition::PlaintextCandidate
        );
        assert!(candidate.ignored_residual_key_reference());
        assert_eq!(
            candidate.identity().compatibility_fields()["legacyFlag"],
            false
        );
        for removed in ["authMethod", "password", "keyId"] {
            assert!(
                !candidate
                    .identity()
                    .compatibility_fields()
                    .contains_key(removed)
            );
        }
        assert_safe_report_excludes(
            &document,
            &[identity_id, label, username, password, residual_key_id],
        );

        let (_preview, hosts, keys, managed_keys, key_identities, password_identities) =
            document.into_password_identity_graph_parts();
        assert_eq!(hosts.len(), 2);
        assert!(keys.is_empty());
        assert!(managed_keys.is_empty());
        assert!(key_identities.is_empty());
        let (identity, password_candidate, disposition) = password_identities
            .into_iter()
            .next()
            .expect("password identity")
            .into_parts();
        assert_eq!(identity.id.as_str(), identity_id);
        assert_eq!(
            password_candidate
                .as_ref()
                .expect("zeroizing password candidate")
                .as_utf8()
                .expect("UTF-8"),
            password
        );
        assert_eq!(
            disposition,
            LegacyPasswordIdentityCredentialDisposition::PlaintextCandidate
        );
    }

    #[test]
    fn password_identity_unrecoverable_passwords_are_precisely_classified() {
        let oversized = "x".repeat(MAX_PERSISTENT_SECRET_BYTES + 1);
        let document = parse_value(json!({
            "hosts": [],
            "identities": [
                {"id":"encrypted", "authMethod":"password", "password":CIPHERTEXT, "created":1},
                {"id":"missing", "authMethod":"password", "created":1},
                {"id":"empty", "authMethod":"password", "password":"", "created":1},
                {"id":"null", "authMethod":"password", "password":null, "created":1},
                {"id":"invalid", "authMethod":"password", "password":[255], "created":1},
                {"id":"oversized", "authMethod":"password", "password":oversized, "created":1}
            ]
        }));

        let dispositions = document
            .password_identity_candidates()
            .iter()
            .map(LegacyPasswordIdentityCandidate::credential_disposition)
            .collect::<Vec<_>>();
        assert_eq!(
            dispositions,
            vec![
                LegacyPasswordIdentityCredentialDisposition::ReentryRequiredEncrypted,
                LegacyPasswordIdentityCredentialDisposition::ReentryRequiredMissing,
                LegacyPasswordIdentityCredentialDisposition::ReentryRequiredMissing,
                LegacyPasswordIdentityCredentialDisposition::ReentryRequiredMissing,
                LegacyPasswordIdentityCredentialDisposition::ReentryRequiredInvalid,
                LegacyPasswordIdentityCredentialDisposition::ReentryRequiredOversized,
            ]
        );
        assert!(
            document
                .password_identity_candidates()
                .iter()
                .all(|candidate| !candidate.has_password_candidate())
        );
        assert_eq!(
            document
                .preview()
                .counts()
                .password_identity_credential_reentry_required,
            6
        );
        assert_eq!(
            document
                .preview()
                .issues
                .iter()
                .filter(|issue| {
                    issue.record_kind == LegacyVaultRecordKind::Identity
                        && issue.code == LegacyVaultIssueCode::IdentityCredentialReentryRequired
                })
                .count(),
            6
        );
        assert_safe_report_excludes(&document, &[CIPHERTEXT, &oversized]);
    }

    #[test]
    fn password_identity_enforces_the_persistent_password_limit() {
        let maximum = "m".repeat(MAX_PERSISTENT_SECRET_BYTES);
        let oversized = "o".repeat(MAX_PERSISTENT_SECRET_BYTES + 1);
        let document = parse_value(json!({
            "hosts": [],
            "identities": [
                {"id":"maximum", "authMethod":"password", "password":maximum, "created":1},
                {"id":"too-large", "authMethod":"password", "password":oversized, "created":1}
            ]
        }));
        assert!(document.password_identity_candidates()[0].has_password_candidate());
        assert_eq!(
            document.password_identity_candidates()[0]
                .identity()
                .has_saved_credential,
            false
        );
        assert_eq!(
            document.password_identity_candidates()[1].credential_disposition(),
            LegacyPasswordIdentityCredentialDisposition::ReentryRequiredOversized
        );
        assert_safe_report_excludes(&document, &[&maximum, &oversized]);
    }

    #[test]
    fn plain_backup_shape_produces_the_same_password_identity_candidate() {
        let password = "plain-backup-password-identity-secret-sentinel";
        let payload = serde_json::to_string(&json!({
            "hosts": [],
            "identities": [{
                "id": "plain-backup-password-identity",
                "label": "Plain backup password identity",
                "username": "backup-user",
                "authMethod": "password",
                "password": password,
                "created": 91,
                "order": 1000
            }]
        }))
        .expect("payload");
        let document = parse_value(json!({
            "formatVersion": 1,
            "payloadEncoding": "plain-json-v1",
            "payloadData": payload
        }));
        assert_eq!(
            document.preview().source_kind,
            LegacyVaultSourceKind::VersionedPlainJsonV1
        );
        assert_eq!(document.password_identity_candidates().len(), 1);
        assert!(document.password_identity_candidates()[0].has_password_candidate());
        assert_safe_report_excludes(&document, &[password, "backup-user"]);
    }

    #[test]
    fn invalid_utf8_source_fails_before_any_secret_candidate_or_echo() {
        let source =
            b"{\"hosts\":[],\"identities\":[{\"authMethod\":\"password\",\"password\":\"\xff\"}]}";
        let error = parse_legacy_vault(source, NOW)
            .err()
            .expect("invalid UTF-8 source");
        assert_eq!(error.code, LegacyVaultErrorCode::InvalidUtf8);
        assert_eq!(error.to_string(), "legacy backup is not UTF-8");
        assert_eq!(
            serde_json::to_string(&error).expect("safe error"),
            r#"{"code":"INVALID_UTF8"}"#
        );
    }

    #[test]
    fn catalog_shape_errors_never_echo_paths_labels_ids_or_secrets() {
        let path = "error-path-sentinel";
        let label = "error-label-sentinel";
        let id = "error-id-sentinel";
        let secret = "error-secret-sentinel";
        let input = serde_json::to_vec(&json!({
            "hosts": [],
            "keys": {"id": id, "label": label, "filePath": path, "privateKey": secret},
            "identities": []
        }))
        .expect("invalid catalog JSON");
        let error = parse_legacy_vault(&input, NOW)
            .err()
            .expect("invalid catalog shape");
        let serialized = serde_json::to_string(&error).expect("error JSON");
        let debug = format!("{error:?}");
        let displayed = error.to_string();
        for forbidden in [path, label, id, secret] {
            assert!(!serialized.contains(forbidden));
            assert!(!debug.contains(forbidden));
            assert!(!displayed.contains(forbidden));
        }
        assert_eq!(error.code, LegacyVaultErrorCode::InvalidRoot);
    }

    #[test]
    fn invalid_group_catalog_scrubs_pending_host_values_before_error_return() {
        let pending_host_secret = "pending-host-secret-sentinel";
        let group_ssh_secret = "invalid-group-ssh-secret-sentinel";
        let group_telnet_secret = "invalid-group-telnet-secret-sentinel";
        let group_proxy_secret = "invalid-group-proxy-secret-sentinel";
        let input = serde_json::to_vec(&json!({
            "hosts": [host_json(json!({ "password": pending_host_secret }))],
            "groupConfigs": [{
                "path": null,
                "password": group_ssh_secret,
                "telnetPassword": group_telnet_secret,
                "proxyConfig": {
                    "type": "http",
                    "host": "proxy.example.test",
                    "port": 8080,
                    "username": "alice",
                    "password": group_proxy_secret
                }
            }]
        }))
        .expect("invalid group catalog JSON");

        let error = parse_legacy_vault(&input, NOW)
            .err()
            .expect("invalid group catalog");
        assert_eq!(error.code, LegacyVaultErrorCode::InvalidRoot);
        let safe_error = format!(
            "{:?}\n{}\n{}",
            error,
            error,
            serde_json::to_string(&error).expect("safe error JSON")
        );
        for secret in [
            pending_host_secret,
            group_ssh_secret,
            group_telnet_secret,
            group_proxy_secret,
        ] {
            assert!(!safe_error.contains(secret));
        }
    }

    #[test]
    fn safe_storage_is_never_decoded_or_retained() {
        let disguised_json = "eyJob3N0cyI6W3sicGFzc3dvcmQiOiJkb250LXBhcnNlLW1lIn1dfQ==";
        let document = parse_value(json!({
            "formatVersion": 1,
            "payloadEncoding": "safeStorage-v1",
            "payloadData": disguised_json
        }));
        assert_eq!(
            document.preview().source_kind,
            LegacyVaultSourceKind::SafeStorageV1
        );
        assert!(document.preview().source_recovery_required());
        assert!(document.candidates().is_empty());
        let preview_json = serde_json::to_string(document.preview()).expect("preview JSON");
        assert!(!preview_json.contains(disguised_json));
        assert!(!format!("{:?}", document.preview()).contains(disguised_json));
        assert_preview_excludes_source_digest(&document);
    }

    #[test]
    fn plaintext_ssh_password_becomes_only_a_zeroizing_candidate() {
        let document = parse_value(json!([host_json(json!({
            "password": PLAINTEXT_SECRET,
            "savePassword": true
        }))]));
        assert_eq!(document.preview().recoverable_credential_count, 1);
        let preview = serde_json::to_string(document.preview()).expect("preview JSON");
        assert!(!preview.contains(PLAINTEXT_SECRET));

        let candidate = document.into_candidates().pop().expect("candidate");
        assert_eq!(
            candidate.credential_disposition(),
            LegacyCredentialDisposition::PlaintextCandidate
        );
        let (host, secret, _) = candidate.into_parts();
        assert!(
            !serde_json::to_string(&host)
                .expect("host JSON")
                .contains(PLAINTEXT_SECRET)
        );
        assert_eq!(
            secret
                .expect("password candidate")
                .as_utf8()
                .expect("UTF-8"),
            PLAINTEXT_SECRET
        );
    }

    #[test]
    fn primary_telnet_uses_exact_legacy_nullish_fallbacks_and_is_importable() {
        let primary_secret = "primary-ssh-slot-secret-sentinel";
        let telnet_secret = "primary-telnet-slot-secret-sentinel";
        let explicit = parse_value(json!([host_json(json!({
            "protocol": "telnet",
            "port": 2023,
            "telnetPort": 2323,
            "username": "ssh-user",
            "telnetUsername": "  telnet-user  ",
            "password": primary_secret,
            "telnetPassword": telnet_secret
        }))]));
        assert_eq!(explicit.candidates().len(), 1);
        assert!(explicit.unsupported_candidates().is_empty());
        assert_eq!(explicit.preview().importable_count, 1);
        assert_eq!(explicit.preview().recoverable_credential_count, 1);
        let candidate = &explicit.candidates()[0];
        assert!(candidate.host().protocol.is_telnet());
        assert_eq!(candidate.host().port, 2323);
        assert_eq!(candidate.host().username, "telnet-user");
        assert_eq!(
            candidate.host().compatibility_fields()["telnetEnabled"],
            true
        );
        assert!(!candidate.has_ssh_password_candidate());
        assert!(candidate.has_telnet_password_candidate());
        assert_eq!(
            candidate.telnet_credential_disposition(),
            LegacyCredentialDisposition::PlaintextCandidate
        );
        let safe_host = serde_json::to_string(candidate.host()).expect("safe Telnet host");
        for secret in [primary_secret, telnet_secret] {
            assert!(!safe_host.contains(secret));
            assert!(
                !serde_json::to_string(explicit.preview())
                    .expect("safe preview")
                    .contains(secret)
            );
        }
        let counts = explicit.preview().counts();
        assert_eq!(counts.telnet_password_candidates, 1);
        assert_eq!(counts.ssh_password_candidates, 0);
        assert_eq!(counts.telnet_credential_reentry_required, 0);
        assert_eq!(counts.unsupported_hosts, 0);

        let candidate = explicit.into_candidates().pop().expect("Telnet candidate");
        let (host, ssh, ssh_disposition, telnet, telnet_disposition, proxy, proxy_disposition) =
            candidate.into_all_credential_parts();
        assert!(host.protocol.is_telnet());
        assert!(ssh.is_none());
        assert_eq!(ssh_disposition, LegacyCredentialDisposition::None);
        assert_eq!(
            telnet.expect("Telnet password").as_utf8().expect("UTF-8"),
            telnet_secret
        );
        assert_eq!(
            telnet_disposition,
            LegacyCredentialDisposition::PlaintextCandidate
        );
        assert!(proxy.is_none());
        assert_eq!(proxy_disposition, LegacyProxyCredentialDisposition::None);

        let fallback = parse_value(json!([host_json(json!({
            "id": "telnet-fallback",
            "protocol": "telnet",
            "port": 2024,
            "username": "fallback-user",
            "password": "fallback-telnet-secret"
        }))]));
        let fallback_candidate = &fallback.candidates()[0];
        assert_eq!(fallback_candidate.host().port, 2024);
        assert_eq!(fallback_candidate.host().username, "fallback-user");
        assert!(fallback_candidate.has_telnet_password_candidate());

        let nullish = parse_value(json!([host_json(json!({
            "id": "telnet-nullish",
            "protocol": "telnet",
            "port": null,
            "telnetPort": null,
            "username": "null-fallback-user",
            "telnetUsername": null,
            "password": "null-fallback-secret",
            "telnetPassword": null
        }))]));
        let nullish_candidate = &nullish.candidates()[0];
        assert_eq!(nullish_candidate.host().port, 23);
        assert_eq!(nullish_candidate.host().username, "null-fallback-user");
        assert!(nullish_candidate.has_telnet_password_candidate());
    }

    #[test]
    fn primary_serial_preserves_full_config_high_baud_and_path_spaces() {
        let document = parse_value(json!([host_json(json!({
            "id": "legacy-serial-full",
            "protocol": "serial",
            "hostname": "stale-device-mirror",
            "port": 22,
            "username": "",
            "password": "ignored-serial-password-sentinel",
            "serialConfig": {
                "path": "/tmp/serial link",
                "baudRate": 921600,
                "dataBits": 7,
                "stopBits": 1.5,
                "parity": "mark",
                "flowControl": "rts/cts",
                "localEcho": true,
                "lineMode": true,
                "backspaceBehavior": "ctrl-h"
            },
            "proxyConfig": {
                "type": "http",
                "host": "ignored-proxy.example.test",
                "port": 8080,
                "password": "ignored-proxy-password-sentinel"
            }
        }))]));
        assert_eq!(document.candidates().len(), 1);
        assert!(document.unsupported_candidates().is_empty());
        assert_eq!(document.preview().importable_count, 1);
        assert_eq!(document.preview().recoverable_credential_count, 0);
        let candidate = &document.candidates()[0];
        assert!(candidate.host().protocol.is_serial());
        assert_eq!(candidate.host().hostname, "/tmp/serial link");
        assert_eq!(candidate.host().port, 921_600);
        assert!(!candidate.has_ssh_password_candidate());
        assert!(!candidate.has_telnet_password_candidate());
        assert!(!candidate.has_inline_proxy_password_candidate());
        assert!(!candidate.requires_credential_reentry());
        let config = candidate
            .host()
            .effective_serial_config()
            .expect("effective serial config");
        assert_eq!(config.path, "/tmp/serial link");
        assert_eq!(config.baud_rate, 921_600);
        assert_eq!(config.data_bits.get(), 7);
        assert_eq!(config.stop_bits.as_f64(), 1.5);
        let safe = serde_json::to_string(candidate.host()).expect("safe Serial host");
        assert!(!safe.contains("ignored-serial-password-sentinel"));
        assert!(!safe.contains("ignored-proxy-password-sentinel"));
    }

    #[test]
    fn legacy_serial_without_serial_config_uses_generic_endpoint_defaults() {
        let explicit = parse_value(json!([host_json(json!({
            "id": "legacy-serial-fallback",
            "protocol": "serial",
            "hostname": " C:\\Virtual Ports\\COM Link ",
            "port": 115200,
            "username": ""
        }))]));
        let host = explicit.candidates()[0].host();
        assert_eq!(host.hostname, "C:\\Virtual Ports\\COM Link");
        let config = host
            .effective_serial_config()
            .expect("fallback serial config");
        assert_eq!(config.path, "C:\\Virtual Ports\\COM Link");
        assert_eq!(config.baud_rate, 115_200);

        let default_baud = parse_value(json!([host_json(json!({
            "id": "legacy-serial-default-baud",
            "protocol": "serial",
            "hostname": "COM7",
            "port": null,
            "username": ""
        }))]));
        let config = default_baud.candidates()[0]
            .host()
            .effective_serial_config()
            .expect("default serial config");
        assert_eq!(config.baud_rate, DEFAULT_SERIAL_BAUD_RATE);
    }

    #[test]
    fn explicit_empty_telnet_fields_override_fallback_without_leaking_it() {
        let fallback_secret = "must-be-discarded-telnet-fallback-sentinel";
        let document = parse_value(json!([host_json(json!({
            "protocol": "telnet",
            "username": "fallback-user",
            "telnetUsername": "",
            "password": fallback_secret,
            "telnetPassword": ""
        }))]));
        let candidate = &document.candidates()[0];
        assert_eq!(candidate.host().username, "");
        assert!(!candidate.has_telnet_password_candidate());
        assert_eq!(
            candidate.telnet_credential_disposition(),
            LegacyCredentialDisposition::None
        );
        assert_eq!(document.preview().recoverable_credential_count, 0);
        assert!(
            !serde_json::to_string(candidate.host())
                .expect("safe host")
                .contains(fallback_secret)
        );
        assert_safe_report_excludes(&document, &[fallback_secret]);
    }

    #[test]
    fn primary_telnet_credential_failures_are_classified_without_becoming_ssh() {
        let oversized = "t".repeat(MAX_PERSISTENT_SECRET_BYTES + 1);
        let cases = [
            (
                "encrypted",
                Value::String(CIPHERTEXT.to_owned()),
                true,
                LegacyCredentialDisposition::ReentryRequiredEncrypted,
            ),
            (
                "oversized",
                Value::String(oversized),
                true,
                LegacyCredentialDisposition::ReentryRequiredOversized,
            ),
            (
                "invalid",
                json!(["not", "text"]),
                true,
                LegacyCredentialDisposition::ReentryRequiredInvalid,
            ),
            (
                "not-saved",
                Value::String("discarded-by-policy".to_owned()),
                false,
                LegacyCredentialDisposition::NotSavedByPolicy,
            ),
        ];
        for (id, password, save_password, expected) in cases {
            let document = parse_value(json!([host_json(json!({
                "id": format!("telnet-{id}"),
                "protocol": "telnet",
                "telnetPassword": password,
                "savePassword": save_password
            }))]));
            let candidate = &document.candidates()[0];
            assert!(candidate.host().protocol.is_telnet());
            assert!(!candidate.has_ssh_password_candidate());
            assert!(!candidate.has_telnet_password_candidate());
            assert_eq!(candidate.telnet_credential_disposition(), expected);
            assert_eq!(document.preview().requires_credential_reentry_count, 1);
            assert_eq!(
                document
                    .preview()
                    .counts()
                    .telnet_credential_reentry_required,
                1
            );
        }

        let manual = parse_value(json!([host_json(json!({
            "id": "telnet-manual-login",
            "protocol": "telnet",
            "username": "",
            "password": null
        }))]));
        assert_eq!(manual.candidates().len(), 1);
        assert!(!manual.candidates()[0].requires_credential_reentry());
    }

    #[test]
    fn save_password_false_blocks_plaintext_candidate() {
        let document = parse_value(json!([host_json(json!({
            "password": PLAINTEXT_SECRET,
            "savePassword": false
        }))]));
        let candidate = &document.candidates()[0];
        assert!(!candidate.has_ssh_password_candidate());
        assert_eq!(
            candidate.credential_disposition(),
            LegacyCredentialDisposition::NotSavedByPolicy
        );
        assert!(
            document
                .preview()
                .issues
                .iter()
                .any(|issue| { issue.code == LegacyVaultIssueCode::PasswordNotSavedByPolicy })
        );
    }

    #[test]
    fn malformed_and_plausible_enc_v1_values_both_require_reentry() {
        for encrypted in [CIPHERTEXT, "enc:v1:AQAAANCMnd8AAAAA"] {
            let document = parse_value(json!([host_json(json!({
                "password": encrypted,
                "authMethod": "password"
            }))]));
            let candidate = &document.candidates()[0];
            assert!(!candidate.has_ssh_password_candidate());
            assert_eq!(
                candidate.credential_disposition(),
                LegacyCredentialDisposition::ReentryRequiredEncrypted
            );
            assert_eq!(document.preview().requires_credential_reentry_count, 1);
            let preview_json = serde_json::to_string(document.preview()).expect("preview JSON");
            assert!(!preview_json.contains(encrypted));
        }
    }

    #[test]
    fn oversized_password_is_not_moved_into_secret_value() {
        let oversized = "x".repeat(MAX_PERSISTENT_SECRET_BYTES + 1);
        let document = parse_value(json!([host_json(json!({
            "password": oversized
        }))]));
        let candidate = &document.candidates()[0];
        assert!(!candidate.has_ssh_password_candidate());
        assert_eq!(
            candidate.credential_disposition(),
            LegacyCredentialDisposition::ReentryRequiredOversized
        );
    }

    #[test]
    fn recursively_strips_secret_fields_and_ciphertext_but_preserves_semantics() {
        let document = parse_value(json!([host_json(json!({
            "authMethod": "future-auth",
            "protocol": "vendor:future",
            "telnetPassword": PLAINTEXT_SECRET,
            "proxyConfig": {
                "type": "http",
                "host": "nested-proxy.example",
                "port": 8080,
                "password": PLAINTEXT_SECRET,
                "enabled": false,
                "nullable": null,
                "empty": ""
            },
            "pluginConfig": {
                "privateKey": PLAINTEXT_SECRET,
                "credentialRef": "opaque-ref",
                "ciphertextInUnexpectedField": CIPHERTEXT,
                "falseValue": false,
                "nullValue": null,
                "emptyValue": ""
            },
            "identityId": "identity-1",
            "identityFilePaths": []
        }))]));
        let host = document.unsupported_candidates()[0].host();
        assert_eq!(host.protocol.as_str(), "vendor:future");
        assert_eq!(host.auth_method.as_str(), "future-auth");
        assert_eq!(host.compatibility_fields()["identityId"], "identity-1");
        assert_eq!(host.compatibility_fields()["identityFilePaths"], json!([]));
        assert!(document.unsupported_candidates()[0].has_inline_proxy_password_candidate());
        let encoded = serde_json::to_string(host).expect("host JSON");
        for forbidden in [PLAINTEXT_SECRET, "opaque-ref", "privateKey"] {
            assert!(!encoded.contains(forbidden), "leaked {forbidden}");
        }
        assert!(encoded.contains(CIPHERTEXT));
        assert!(encoded.contains("\"enabled\":false"));
        assert!(encoded.contains("\"nullable\":null"));
        assert!(encoded.contains("\"empty\":\"\""));
        assert!(encoded.contains("\"falseValue\":false"));
        assert_eq!(document.preview().counts().unsupported_hosts, 1);
        assert!(document.preview().counts().secret_fields_stripped >= 4);
    }

    #[test]
    fn normalizes_untrusted_has_saved_credential_to_false() {
        let document = parse_value(json!([host_json(json!({
            "hasSavedCredential": true,
            "hasPassword": true
        }))]));
        let host = document.candidates()[0].host();
        assert_eq!(
            host.compatibility_fields()["hasSavedCredential"],
            Value::Bool(false)
        );
        assert_eq!(host.compatibility_fields()["hasPassword"], true);
    }

    #[test]
    fn rejects_bad_hosts_individually_without_echoing_values() {
        let source_secret = "host-secret-that-must-not-be-an-error";
        let document = parse_value(json!([
            host_json(json!({})),
            {"id": source_secret, "hostname": "", "password": source_secret},
            source_secret
        ]));
        assert_eq!(document.preview().source_count, 3);
        assert_eq!(document.preview().counts().candidate_hosts, 1);
        assert_eq!(document.preview().unsupported_count, 2);
        let debug = format!("{:?}", document.preview());
        let serialized = serde_json::to_string(document.preview()).expect("preview JSON");
        assert!(!debug.contains(source_secret));
        assert!(!serialized.contains(source_secret));
    }

    #[test]
    fn reports_duplicate_ids_without_serializing_the_id() {
        let secret_like_id = "id-that-could-be-sensitive";
        let first = host_json(json!({
            "id": secret_like_id,
            "password": "first-password"
        }));
        let second = host_json(json!({
            "id": secret_like_id,
            "hostname": "other",
            "password": "second-password"
        }));
        let document = parse_value(json!([first, second]));
        assert_eq!(document.preview().source_count, 2);
        assert_eq!(document.preview().importable_count, 1);
        assert_eq!(document.preview().duplicate_count, 1);
        assert_eq!(document.preview().recoverable_credential_count, 1);
        assert_eq!(document.candidates().len(), 1);
        assert!(document.preview().issues.iter().any(|issue| {
            issue.code == LegacyVaultIssueCode::DuplicateHostId && issue.record_index == Some(1)
        }));
        assert!(
            !serde_json::to_string(document.preview())
                .expect("preview JSON")
                .contains(secret_like_id)
        );
    }

    #[test]
    fn known_null_fields_default_and_legacy_auth_is_inferred_once() {
        let document = parse_value(json!([host_json(json!({
            "label": null,
            "port": null,
            "username": null,
            "protocol": null,
            "authMethod": null,
            "authPolicyVersion": null,
            "password": PLAINTEXT_SECRET,
            "pluginNull": null,
            "pluginEmpty": "",
            "pluginFalse": false
        }))]));
        assert_eq!(document.candidates().len(), 1);
        let candidate = &document.candidates()[0];
        let host = candidate.host();
        assert_eq!(host.label, "example.com");
        assert_eq!(host.port, 22);
        assert_eq!(host.username, "");
        assert!(host.protocol.is_ssh());
        assert!(host.auth_method.is_password());
        assert_eq!(host.auth_policy_version, 1);
        assert_eq!(host.compatibility_fields()["pluginNull"], Value::Null);
        assert_eq!(host.compatibility_fields()["pluginEmpty"], "");
        assert_eq!(host.compatibility_fields()["pluginFalse"], false);
        assert!(candidate.has_ssh_password_candidate());
    }

    #[test]
    fn legacy_password_default_and_key_fields_infer_auto_or_key() {
        let legacy_password_default = host_json(json!({
            "authMethod": "password",
            "authPolicyVersion": null,
            "password": null,
            "useSshAgent": true
        }));
        let legacy_key = host_json(json!({
            "id": "legacy-key",
            "authMethod": null,
            "authPolicyVersion": null,
            "identityFilePaths": ["/safe/reference/path"]
        }));
        let document = parse_value(json!([legacy_password_default, legacy_key]));
        assert_eq!(document.candidates().len(), 1);
        assert_eq!(document.unsupported_candidates().len(), 1);
        assert_eq!(
            document.unsupported_candidates()[0]
                .host()
                .auth_method
                .as_str(),
            "auto"
        );
        assert_eq!(document.candidates()[0].host().auth_method.as_str(), "key");
        assert_eq!(document.preview().unsupported_count, 1);
        assert_eq!(document.preview().requires_credential_reentry_count, 0);
    }

    #[test]
    fn explicit_password_without_credential_requires_reentry() {
        for password in [None, Some(Value::Null), Some(Value::String(String::new()))] {
            let mut extra = json!({
                "authMethod": "password",
                "authPolicyVersion": 1
            });
            if let Some(password) = password {
                extra
                    .as_object_mut()
                    .expect("extra")
                    .insert("password".to_owned(), password);
            }
            let document = parse_value(json!([host_json(extra)]));
            let candidate = &document.candidates()[0];
            assert_eq!(
                candidate.credential_disposition(),
                LegacyCredentialDisposition::ReentryRequiredMissing
            );
            assert_eq!(document.preview().requires_credential_reentry_count, 1);
            assert_eq!(document.preview().recoverable_credential_count, 0);
        }
    }

    #[test]
    fn external_identity_dependency_is_unsupported_and_not_recoverable() {
        let document = parse_value(json!([host_json(json!({
            "password": PLAINTEXT_SECRET,
            "identityId": "legacy-identity"
        }))]));
        assert!(document.candidates().is_empty());
        assert_eq!(document.unsupported_candidates().len(), 1);
        let candidate = &document.unsupported_candidates()[0];
        assert!(candidate.has_ssh_password_candidate());
        assert!(candidate.requires_additional_credential_reentry());
        assert!(!candidate.is_currently_importable());
        assert_eq!(document.preview().importable_count, 0);
        assert_eq!(document.preview().unsupported_count, 1);
        assert_eq!(document.preview().recoverable_credential_count, 0);
        assert_eq!(document.preview().requires_credential_reentry_count, 1);
        let preview = serde_json::to_string(document.preview()).expect("preview");
        assert!(!preview.contains(PLAINTEXT_SECRET));
    }

    #[test]
    fn serialized_preview_matches_the_frontend_field_contract() {
        let document = parse_value(json!([host_json(json!({
            "password": PLAINTEXT_SECRET
        }))]));
        let preview = serde_json::to_value(document.preview()).expect("preview JSON");
        assert_eq!(preview["sourceKind"], "bareHostArray");
        for key in [
            "sourceCount",
            "importableCount",
            "duplicateCount",
            "conflictCount",
            "recoverableCredentialCount",
            "requiresCredentialReentryCount",
            "unsupportedCount",
            "issues",
        ] {
            assert!(preview.get(key).is_some(), "missing {key}");
        }
        assert!(preview.get("sourceFingerprint").is_none());
        assert!(preview.get("counts").is_none());
        assert!(preview.get("sourceRecoveryRequired").is_none());
        assert_eq!(preview["sourceCount"], 1);
        assert_eq!(preview["importableCount"], 1);
        assert_eq!(preview["recoverableCredentialCount"], 1);
    }

    #[test]
    fn source_digest_is_private_and_hashes_the_original_outer_source() {
        let input = b"[]";
        let document = parse_legacy_vault(input, NOW).expect("document");
        assert_eq!(
            hex_encode(document.source_sha256()),
            "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
        );
        assert_preview_excludes_source_digest(&document);
    }

    #[test]
    fn rejects_future_versions_unknown_encodings_and_nested_envelopes() {
        for value in [
            json!({
                "formatVersion": 2,
                "payloadEncoding": "plain-json-v1",
                "payloadData": "[]"
            }),
            json!({
                "formatVersion": 1,
                "payloadEncoding": "future-v2",
                "payloadData": "[]"
            }),
        ] {
            assert!(
                parse_legacy_vault_str(&serde_json::to_string(&value).expect("JSON"), NOW).is_err()
            );
        }

        let nested = json!({
            "formatVersion": 1,
            "payloadEncoding": "plain-json-v1",
            "payloadData": serde_json::to_string(&json!({
                "formatVersion": 1,
                "payloadEncoding": "safeStorage-v1",
                "payloadData": "opaque"
            })).expect("inner")
        });
        assert_eq!(
            parse_legacy_vault_str(&serde_json::to_string(&nested).expect("JSON"), NOW)
                .err()
                .map(|error| error.code),
            Some(LegacyVaultErrorCode::InvalidPayloadData)
        );
    }

    #[test]
    fn size_host_count_and_invalid_input_errors_are_fixed_and_secret_safe() {
        let oversized = vec![b' '; MAX_LEGACY_BACKUP_BYTES + 1];
        let error = parse_legacy_vault(&oversized, NOW)
            .err()
            .expect("too large");
        assert_eq!(error.code, LegacyVaultErrorCode::InputTooLarge);

        let too_many = vec![Value::Null; MAX_LEGACY_HOSTS + 1];
        let error = parse_legacy_vault_str(&serde_json::to_string(&too_many).expect("JSON"), NOW)
            .err()
            .expect("host limit");
        assert_eq!(error.code, LegacyVaultErrorCode::HostLimitExceeded);

        let invalid_secret = "invalid-json-secret-5cf2";
        let error = parse_legacy_vault_str(&format!("{{{invalid_secret}"), NOW)
            .err()
            .expect("invalid JSON");
        for safe_form in [
            format!("{error}"),
            format!("{error:?}"),
            serde_json::to_string(&error).expect("error JSON"),
        ] {
            assert!(!safe_form.contains(invalid_secret));
        }
    }

    #[test]
    fn renderer_issue_list_is_bounded_while_exact_counts_are_preserved() {
        let source_count = MAX_LEGACY_PREVIEW_ISSUES + 25;
        let source = vec![Value::Null; source_count];
        let document = parse_value(Value::Array(source));
        let preview = document.preview();

        assert_eq!(preview.source_count, source_count as u32);
        assert_eq!(preview.counts().rejected_hosts, source_count as u32);
        assert_eq!(preview.issues.len(), MAX_LEGACY_PREVIEW_ISSUES);
        assert_eq!(preview.omitted_issue_count, 25);
        let encoded = serde_json::to_value(preview).expect("preview JSON");
        assert_eq!(
            encoded["issues"].as_array().expect("issues").len(),
            MAX_LEGACY_PREVIEW_ISSUES
        );
        assert_eq!(encoded["omittedIssueCount"], 25);
    }

    #[test]
    fn missing_timestamps_are_filled_and_inverted_timestamps_are_repaired() {
        let missing = parse_value(json!([host_json(json!({}))]));
        let missing_host = missing.candidates()[0].host();
        assert_eq!(missing_host.created_at, NOW);
        assert_eq!(missing_host.updated_at, NOW);

        let inverted = parse_value(json!([host_json(json!({
            "createdAt": 200,
            "updatedAt": 100
        }))]));
        let inverted_host = inverted.candidates()[0].host();
        assert_eq!(inverted_host.created_at, 200);
        assert_eq!(inverted_host.updated_at, 200);
    }

    #[test]
    fn plaintext_proxy_passwords_exist_only_as_zeroizing_candidates() {
        let profile_secret = "profile-proxy-password-sentinel";
        let inline_secret = "inline-proxy-password-sentinel";
        let document = parse_value(json!({
            "hosts": [host_json(json!({
                "password": "ssh-password-sentinel",
                "proxyConfig": proxy_config(json!({
                    "username": "inline-user",
                    "password": inline_secret
                }))
            }))],
            "proxyProfiles": [proxy_profile(
                "plaintext-profile",
                proxy_config(json!({"username":"profile-user", "password":profile_secret}))
            )]
        }));

        let profile = &document.proxy_profile_candidates()[0];
        assert!(profile.has_password_candidate());
        assert_eq!(
            profile.credential_disposition(),
            LegacyProxyCredentialDisposition::PlaintextCandidate
        );
        let host = &document.candidates()[0];
        assert!(host.has_inline_proxy_password_candidate());
        assert_eq!(
            host.inline_proxy_credential_disposition(),
            LegacyProxyCredentialDisposition::PlaintextCandidate
        );
        let host_json = serde_json::to_string(host.host()).expect("host JSON");
        let profile_json = serde_json::to_string(profile.profile()).expect("proxy-profile JSON");
        for secret in [profile_secret, inline_secret] {
            assert!(!host_json.contains(secret));
            assert!(!profile_json.contains(secret));
        }

        let (_preview, hosts, _keys, _managed, _identities, _password_identities, profiles) =
            document.into_proxy_graph_parts();
        let (_profile, profile_password, profile_disposition) = profiles
            .into_iter()
            .next()
            .expect("proxy profile")
            .into_parts();
        assert_eq!(
            profile_password
                .expect("profile password")
                .as_utf8()
                .expect("UTF-8"),
            profile_secret
        );
        assert_eq!(
            profile_disposition,
            LegacyProxyCredentialDisposition::PlaintextCandidate
        );
        let (_host, _ssh, _ssh_disposition, inline_password, inline_disposition) =
            hosts.into_iter().next().expect("host").into_proxy_parts();
        assert_eq!(
            inline_password
                .expect("inline password")
                .as_utf8()
                .expect("UTF-8"),
            inline_secret
        );
        assert_eq!(
            inline_disposition,
            LegacyProxyCredentialDisposition::PlaintextCandidate
        );
    }

    #[test]
    fn proxy_unrecoverable_passwords_are_precisely_classified() {
        let oversized = "p".repeat(MAX_PERSISTENT_SECRET_BYTES + 1);
        let cases = [
            (
                "encrypted",
                Some(Value::String(CIPHERTEXT.to_owned())),
                LegacyProxyCredentialDisposition::ReentryRequiredEncrypted,
            ),
            (
                "missing",
                None,
                LegacyProxyCredentialDisposition::ReentryRequiredMissing,
            ),
            (
                "invalid",
                Some(json!(["not", "text"])),
                LegacyProxyCredentialDisposition::ReentryRequiredInvalid,
            ),
            (
                "oversized",
                Some(Value::String(oversized.clone())),
                LegacyProxyCredentialDisposition::ReentryRequiredOversized,
            ),
        ];
        let mut profiles = Vec::new();
        let mut hosts = Vec::new();
        for (index, (id, password, _)) in cases.iter().enumerate() {
            let mut config = proxy_config(json!({"username":"manual-user"}));
            if let Some(password) = password {
                config
                    .as_object_mut()
                    .expect("config")
                    .insert("password".to_owned(), password.clone());
            }
            profiles.push(proxy_profile(id, config.clone()));
            hosts.push(host_json(json!({
                "id": format!("inline-{index}"),
                "password": "ssh-password",
                "proxyConfig": config
            })));
        }
        let document = parse_value(json!({
            "hosts": hosts,
            "proxyProfiles": profiles
        }));

        let expected = cases.iter().map(|case| case.2).collect::<Vec<_>>();
        assert_eq!(
            document
                .proxy_profile_candidates()
                .iter()
                .map(LegacyProxyProfileCandidate::credential_disposition)
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            document
                .candidates()
                .iter()
                .map(LegacyHostCandidate::inline_proxy_credential_disposition)
                .collect::<Vec<_>>(),
            expected
        );
        assert!(
            document
                .proxy_profile_candidates()
                .iter()
                .all(|candidate| !candidate.has_password_candidate())
        );
        assert!(
            document
                .candidates()
                .iter()
                .all(|candidate| !candidate.has_inline_proxy_password_candidate())
        );
        assert_eq!(
            document
                .preview()
                .counts()
                .proxy_profile_credential_reentry_required,
            4
        );
        assert_eq!(
            document
                .preview()
                .counts()
                .inline_proxy_credential_reentry_required,
            4
        );
        assert_safe_report_excludes(&document, &[CIPHERTEXT, &oversized, "manual-user"]);
    }

    #[test]
    fn anonymous_network_proxies_do_not_require_a_missing_password() {
        let document = parse_value(json!({
            "hosts": [host_json(json!({
                "password": "ssh-password",
                "proxyConfig": proxy_config(json!({"type":"socks5"}))
            }))],
            "proxyProfiles": [proxy_profile(
                "anonymous-http",
                proxy_config(json!({}))
            )]
        }));
        assert_eq!(
            document.proxy_profile_candidates()[0].credential_disposition(),
            LegacyProxyCredentialDisposition::None
        );
        assert_eq!(
            document.candidates()[0].inline_proxy_credential_disposition(),
            LegacyProxyCredentialDisposition::None
        );
    }

    #[test]
    fn proxy_identity_auth_is_exclusive_and_requires_a_password_identity() {
        let password_identity = "proxy-password-identity";
        let key_identity = "proxy-key-identity";
        let document = parse_value(json!({
            "hosts": [
                host_json(json!({
                    "id":"valid-inline-identity",
                    "password":"ssh-password",
                    "proxyConfig":proxy_config(json!({"identityId":password_identity}))
                })),
                host_json(json!({
                    "id":"conflicting-inline-identity",
                    "password":"ssh-password",
                    "proxyConfig":proxy_config(json!({
                        "identityId":password_identity,
                        "username":"manual-user",
                        "password":"manual-password"
                    }))
                }))
            ],
            "keys": [{
                "id":"proxy-key", "source":"reference", "category":"key",
                "filePath":"proxy-key-path", "created":1
            }],
            "identities": [
                {"id":password_identity, "authMethod":"password", "password":"identity-password", "created":1},
                {"id":key_identity, "authMethod":"key", "keyId":"proxy-key", "created":1}
            ],
            "proxyProfiles": [
                proxy_profile("valid-identity", proxy_config(json!({"identityId":password_identity}))),
                proxy_profile("key-identity", proxy_config(json!({"identityId":key_identity}))),
                proxy_profile("missing-identity", proxy_config(json!({"identityId":"missing"}))),
                proxy_profile("conflict", proxy_config(json!({
                    "identityId":password_identity,
                    "username":"manual-user",
                    "password":"manual-password"
                })))
            ]
        }));

        assert_eq!(document.proxy_profile_candidates().len(), 1);
        let valid_profile = &document.proxy_profile_candidates()[0];
        assert!(!valid_profile.has_password_candidate());
        assert_eq!(
            valid_profile
                .profile()
                .config
                .identity_id()
                .map(|id| id.as_str()),
            Some(password_identity)
        );
        assert_eq!(document.preview().counts().unsupported_proxy_profiles, 2);
        assert_eq!(document.preview().counts().rejected_proxy_profiles, 1);
        assert_eq!(document.candidates().len(), 1);
        assert_eq!(document.unsupported_candidates().len(), 1);
        assert!(document.preview().issues.iter().any(|issue| {
            issue.code == LegacyVaultIssueCode::ProxyAuthenticationConflict
                && issue.record_kind == LegacyVaultRecordKind::ProxyProfile
        }));
        assert!(document.preview().issues.iter().any(|issue| {
            issue.code == LegacyVaultIssueCode::ProxyAuthenticationConflict
                && issue.record_kind == LegacyVaultRecordKind::Host
        }));
        assert_safe_report_excludes(
            &document,
            &[
                password_identity,
                key_identity,
                "manual-user",
                "manual-password",
            ],
        );
    }

    #[test]
    fn command_proxy_discards_network_and_credential_fields() {
        let command = "proxy-command --stdio";
        let config = json!({
            "type":"command",
            "command":command,
            "host":"ignored.example",
            "hostname":"ignored-too.example",
            "port":9999,
            "identityId":"ignored-identity",
            "username":"ignored-user",
            "password":"ignored-password",
            "nested":{"privateKey":"ignored-private", "flag":false}
        });
        let document = parse_value(json!({
            "hosts":[host_json(json!({
                "password":"ssh-password",
                "proxyConfig":config.clone()
            }))],
            "proxyProfiles":[proxy_profile("command-profile", config)]
        }));

        assert!(!document.proxy_profile_candidates()[0].has_password_candidate());
        assert!(!document.candidates()[0].has_inline_proxy_password_candidate());
        let profile_config =
            serde_json::to_value(&document.proxy_profile_candidates()[0].profile().config)
                .expect("profile config JSON");
        let inline_config = serde_json::to_value(
            document.candidates()[0]
                .host()
                .proxy_config()
                .expect("inline shape")
                .expect("inline config"),
        )
        .expect("inline config JSON");
        for saved in [&profile_config, &inline_config] {
            assert_eq!(saved["type"], "command");
            assert_eq!(saved["command"], command);
            for removed in [
                "host",
                "hostname",
                "port",
                "identityId",
                "username",
                "password",
            ] {
                assert!(saved.get(removed).is_none(), "retained {removed}");
            }
            assert_eq!(saved["nested"]["flag"], false);
            assert!(saved["nested"].get("privateKey").is_none());
        }
        assert_safe_report_excludes(
            &document,
            &[
                command,
                "ignored-user",
                "ignored-password",
                "ignored-private",
            ],
        );
    }

    #[test]
    fn inline_proxy_priority_is_fail_closed_and_profile_only_applies_when_absent_or_null() {
        let profile_id = "available-profile";
        let document = parse_value(json!({
            "hosts":[
                host_json(json!({
                    "id":"valid-inline-shadow",
                    "password":"ssh-password",
                    "proxyProfileId":"missing-shadowed-profile",
                    "proxyConfig":proxy_config(json!({}))
                })),
                host_json(json!({
                    "id":"invalid-inline-no-fallback",
                    "password":"ssh-password",
                    "proxyProfileId":profile_id,
                    "proxyConfig":{"type":"http", "password":"discarded-secret"}
                })),
                host_json(json!({
                    "id":"absent-inline-profile",
                    "password":"ssh-password",
                    "proxyProfileId":profile_id
                })),
                host_json(json!({
                    "id":"null-inline-profile",
                    "password":"ssh-password",
                    "proxyProfileId":profile_id,
                    "proxyConfig":null
                }))
            ],
            "proxyProfiles":[proxy_profile(profile_id, proxy_config(json!({})))]
        }));

        assert_eq!(document.candidates().len(), 3);
        assert_eq!(document.unsupported_candidates().len(), 1);
        assert_eq!(
            document.unsupported_candidates()[0].host().id.as_str(),
            "invalid-inline-no-fallback"
        );
        assert!(
            document.unsupported_candidates()[0]
                .host()
                .compatibility_fields()["proxyConfig"]
                .is_object()
        );
        assert!(document.preview().issues.iter().any(|issue| {
            issue.code == LegacyVaultIssueCode::InvalidProxyConfig && issue.record_index == Some(1)
        }));
        assert!(!document.preview().issues.iter().any(|issue| {
            issue.code == LegacyVaultIssueCode::MissingProxyProfileReference
                && issue.record_index == Some(0)
        }));
        assert_eq!(
            document.preview().counts().missing_proxy_profile_references,
            0
        );
        assert_safe_report_excludes(&document, &["missing-shadowed-profile", "discarded-secret"]);
    }

    #[test]
    fn duplicate_proxy_profile_id_keeps_the_first_valid_record() {
        let profile_id = "opaque-profile-id-sentinel";
        let document = parse_value(json!({
            "hosts":[],
            "proxyProfiles":[
                proxy_profile(profile_id, proxy_config(json!({"host":"first.example"}))),
                proxy_profile(profile_id, proxy_config(json!({"host":"second.example"})))
            ]
        }));
        assert_eq!(document.proxy_profile_candidates().len(), 1);
        assert_eq!(document.preview().counts().duplicate_proxy_profiles, 1);
        let serialized = serde_json::to_value(document.proxy_profile_candidates()[0].profile())
            .expect("profile JSON");
        assert_eq!(serialized["config"]["host"], "first.example");
        assert_safe_report_excludes(&document, &[profile_id, "first.example", "second.example"]);
    }

    #[test]
    fn bare_host_array_supports_owned_inline_modes_but_not_catalog_dependencies() {
        let document = parse_value(json!([
            host_json(json!({
                "id":"manual-inline",
                "password":"ssh-password",
                "proxyConfig":proxy_config(json!({"username":"user", "password":"proxy-password"}))
            })),
            host_json(json!({
                "id":"command-inline",
                "password":"ssh-password",
                "proxyConfig":{"type":"command", "command":"proxy-command"}
            })),
            host_json(json!({
                "id":"identity-inline",
                "password":"ssh-password",
                "proxyConfig":proxy_config(json!({"identityId":"unavailable-identity"}))
            })),
            host_json(json!({
                "id":"profile-reference",
                "password":"ssh-password",
                "proxyProfileId":"unavailable-profile"
            }))
        ]));
        assert_eq!(
            document.preview().source_kind,
            LegacyVaultSourceKind::BareHostArray
        );
        assert_eq!(document.candidates().len(), 2);
        assert_eq!(document.unsupported_candidates().len(), 2);
        assert_eq!(
            document
                .preview()
                .counts()
                .missing_proxy_identity_references,
            1
        );
        assert_eq!(
            document.preview().counts().missing_proxy_profile_references,
            1
        );
        assert_safe_report_excludes(
            &document,
            &[
                "proxy-password",
                "proxy-command",
                "unavailable-identity",
                "unavailable-profile",
            ],
        );
    }

    #[test]
    fn proxy_preview_and_old_consumption_apis_do_not_expose_proxy_secrets_or_profiles() {
        let profile_secret = "preview-profile-secret-sentinel";
        let inline_secret = "preview-inline-secret-sentinel";
        let command = "preview-command-sentinel --stdio";
        let source = json!({
            "hosts":[host_json(json!({
                "id":"preview-host-id-sentinel",
                "hostname":"preview-hostname-sentinel.example",
                "username":"preview-host-user-sentinel",
                "password":"preview-ssh-secret-sentinel",
                "proxyConfig":proxy_config(json!({
                    "host":"preview-proxy-host-sentinel.example",
                    "username":"preview-proxy-user-sentinel",
                    "password":inline_secret
                }))
            }))],
            "proxyProfiles":[
                proxy_profile("preview-profile-id-sentinel", proxy_config(json!({
                    "username":"preview-profile-user-sentinel",
                    "password":profile_secret
                }))),
                proxy_profile("preview-command-profile", json!({"type":"command", "command":command}))
            ]
        });

        let old_document = parse_value(source.clone());
        let old_preview_json = serde_json::to_string(old_document.preview()).expect("preview JSON");
        for forbidden in [
            profile_secret,
            inline_secret,
            command,
            "preview-profile-id-sentinel",
            "preview-host-id-sentinel",
            "preview-hostname-sentinel.example",
            "preview-host-user-sentinel",
            "preview-proxy-host-sentinel.example",
            "preview-proxy-user-sentinel",
            CIPHERTEXT,
        ] {
            assert!(
                !old_preview_json.contains(forbidden),
                "preview leaked {forbidden}"
            );
        }
        let (_preview, old_hosts, _keys, _managed, _identities, _password_identities) =
            old_document.into_password_identity_graph_parts();
        let (_host, _ssh_password, _ssh_disposition) =
            old_hosts.into_iter().next().expect("old host").into_parts();

        let complete_document = parse_value(source);
        let (_preview, hosts, _keys, _managed, _identities, _password_identities, profiles) =
            complete_document.into_proxy_graph_parts();
        assert_eq!(profiles.len(), 2);
        let (_host, _ssh, _ssh_disposition, inline_password, _) = hosts
            .into_iter()
            .next()
            .expect("complete host")
            .into_proxy_parts();
        assert_eq!(
            inline_password
                .expect("inline secret")
                .as_utf8()
                .expect("UTF-8"),
            inline_secret
        );
        let (_profile, profile_password, _) = profiles
            .into_iter()
            .next()
            .expect("manual profile")
            .into_parts();
        assert_eq!(
            profile_password
                .expect("profile secret")
                .as_utf8()
                .expect("UTF-8"),
            profile_secret
        );
    }

    #[test]
    fn issue_code_serialization_is_stable() {
        let codes = [
            (
                LegacyVaultIssueCode::SourceRecoveryRequired,
                "\"LEGACY_SOURCE_RECOVERY_REQUIRED\"",
            ),
            (
                LegacyVaultIssueCode::EncryptedCredentialReentryRequired,
                "\"LEGACY_ENCRYPTED_CREDENTIAL_REENTRY_REQUIRED\"",
            ),
            (
                LegacyVaultIssueCode::SecretMaterialStripped,
                "\"LEGACY_SECRET_MATERIAL_STRIPPED\"",
            ),
            (
                LegacyVaultIssueCode::PasswordIdentityResidualKeyReferenceIgnored,
                "\"LEGACY_PASSWORD_IDENTITY_RESIDUAL_KEY_REFERENCE_IGNORED\"",
            ),
            (
                LegacyVaultIssueCode::ProxyCredentialReentryRequired,
                "\"LEGACY_PROXY_CREDENTIAL_REENTRY_REQUIRED\"",
            ),
            (
                LegacyVaultIssueCode::GroupConfigSshCredentialReentryRequired,
                "\"LEGACY_GROUP_CONFIG_SSH_CREDENTIAL_REENTRY_REQUIRED\"",
            ),
            (
                LegacyVaultIssueCode::GroupConfigTelnetCredentialReentryRequired,
                "\"LEGACY_GROUP_CONFIG_TELNET_CREDENTIAL_REENTRY_REQUIRED\"",
            ),
            (
                LegacyVaultIssueCode::GroupConfigProxyCredentialReentryRequired,
                "\"LEGACY_GROUP_CONFIG_PROXY_CREDENTIAL_REENTRY_REQUIRED\"",
            ),
        ];
        for (code, expected) in codes {
            assert_eq!(serde_json::to_string(&code).expect("code JSON"), expected);
            assert_eq!(code.as_str(), expected.trim_matches('"'));
        }
    }
}
