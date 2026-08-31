use std::collections::HashSet;
use std::fmt;

use netcatty_credentials::CredentialErrorCode;
use netcatty_vault::{
    SavedGroupId, SavedHost, SavedHostConnectionCredentialOwner, SavedIdentityReference,
    SavedPasswordIdentity, SavedPasswordIdentityId, SavedSshKeyReferenceId, SavedVaultGraph,
};
use serde_json::Value;

pub(crate) const SAVED_HOST_AUTH_RELATIONSHIP_INVALID: &str =
    "SAVED_HOST_AUTH_RELATIONSHIP_INVALID";
pub(crate) const SAVED_HOST_REFERENCE_CERTIFICATE_UNSUPPORTED: &str =
    "SAVED_HOST_REFERENCE_CERTIFICATE_UNSUPPORTED";
pub(crate) const SAVED_HOST_AUTH_METHOD_UNSUPPORTED: &str = "SAVED_HOST_AUTH_METHOD_UNSUPPORTED";

const MAX_REFERENCE_FILE_PATHS: usize = 8;
const MAX_REFERENCE_FILE_PATH_BYTES: usize = 32 * 1_024;
const MAX_REFERENCE_FILE_PATHS_BYTES: usize = 64 * 1_024;

/// A fail-closed, secret-free authentication decision for one saved host.
///
/// The managed variants intentionally retain only the public Vault entity ID
/// and the renderer-safe passphrase-presence bit. In particular, this type
/// cannot expose a managed object's backend locator.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SavedHostAuthResolution<'graph> {
    Password,
    ManagedPrivateKey {
        key_id: &'graph SavedSshKeyReferenceId,
        has_saved_passphrase: bool,
    },
    ManagedCertificate {
        key_id: &'graph SavedSshKeyReferenceId,
        has_saved_passphrase: bool,
    },
    /// `key_id` is absent for the compatible legacy shape that stores only
    /// `identityFilePaths`. Those persisted paths are provenance only; the
    /// connection must still obtain a fresh native-picker selection.
    ReferencePrivateKey {
        key_id: Option<&'graph SavedSshKeyReferenceId>,
    },
}

/// Secret-free password authentication metadata for one saved host.
///
/// This value deliberately exposes neither a keyring reference nor a keyring
/// account. Its custom `Debug` implementation also omits the password identity
/// ID and username.
#[derive(Clone, PartialEq)]
pub(crate) struct SavedPasswordAuthResolution<'graph> {
    identity: Option<&'graph SavedPasswordIdentity>,
    manual_credential_owner: Option<SavedPasswordManualCredentialOwner>,
}

#[derive(Clone, PartialEq, Eq)]
enum SavedPasswordManualCredentialOwner {
    Host,
    Group(SavedGroupId),
}

impl SavedPasswordAuthResolution<'_> {
    /// Uses a non-empty identity username and otherwise preserves the host
    /// username, matching the legacy reusable-login behavior.
    pub(crate) fn effective_username<'value>(&'value self, host: &'value SavedHost) -> &'value str {
        self.identity
            .map(|identity| identity.username.as_str())
            .filter(|username| !username.is_empty())
            .unwrap_or(host.username.as_str())
    }

    /// Whether this password host is bound to reusable password-identity
    /// metadata. This is safe for renderer DTO construction and reveals no ID.
    pub(crate) fn has_password_identity(&self) -> bool {
        self.identity.is_some()
    }

    pub(crate) fn password_identity_id(&self) -> Option<&SavedPasswordIdentityId> {
        self.identity.map(|identity| &identity.id)
    }

    pub(crate) fn password_identity_label(&self) -> Option<&str> {
        self.identity.map(|identity| identity.label.as_str())
    }

    pub(crate) fn password_identity_username(&self) -> Option<&str> {
        self.identity.map(|identity| identity.username.as_str())
    }

    pub(crate) fn password_identity_revision(&self) -> Option<u64> {
        self.identity.map(|identity| identity.revision)
    }

    /// The identity-owned custody hint, kept separate so host editors never
    /// mistake a shared identity password for a host-owned password.
    pub(crate) fn identity_has_saved_credential(&self) -> bool {
        self.identity
            .is_some_and(|identity| identity.has_saved_credential)
    }

    /// The host-owned custody hint, independently useful for edit/remove
    /// decisions even when an identity credential currently takes priority.
    pub(crate) fn host_has_saved_credential(&self) -> bool {
        matches!(
            self.manual_credential_owner.as_ref(),
            Some(SavedPasswordManualCredentialOwner::Host)
        )
    }

    /// Whether the effective manual password belongs to a GroupConfig. The
    /// owner ID stays backend-only and is exposed only through credential
    /// actions that need to derive the exact isolated keyring account.
    pub(crate) fn group_has_saved_credential(&self) -> bool {
        matches!(
            self.manual_credential_owner.as_ref(),
            Some(SavedPasswordManualCredentialOwner::Group(_))
        )
    }

    /// Renderer-safe effective persisted-credential availability. One-shot
    /// credentials are intentionally excluded because they are not metadata.
    pub(crate) fn effective_has_saved_credential(&self) -> bool {
        self.identity_has_saved_credential() || self.manual_credential_owner.is_some()
    }

    pub(crate) fn first_credential_action(
        &self,
        has_one_shot_credential: bool,
    ) -> SavedPasswordCredentialAction<'_> {
        if has_one_shot_credential {
            return SavedPasswordCredentialAction::UseOneShot;
        }
        if let Some(identity) = self
            .identity
            .filter(|identity| identity.has_saved_credential)
        {
            return SavedPasswordCredentialAction::ResolveIdentity {
                identity_id: &identity.id,
            };
        }
        match &self.manual_credential_owner {
            Some(SavedPasswordManualCredentialOwner::Host) => {
                SavedPasswordCredentialAction::ResolveHost
            }
            Some(SavedPasswordManualCredentialOwner::Group(group_id)) => {
                SavedPasswordCredentialAction::ResolveGroup { group_id }
            }
            None => SavedPasswordCredentialAction::RequireOneShot,
        }
    }

    /// Converts a keyring lookup error into the only permitted next action.
    ///
    /// Only an authoritative `NotFound` may fall through. Corrupt records,
    /// unavailable storage, conflicts, backend failures, and every other error
    /// fail closed without consulting a lower-priority credential.
    pub(crate) fn after_lookup_error(
        &self,
        lookup: SavedPasswordCredentialLookup,
        error: CredentialErrorCode,
    ) -> SavedPasswordCredentialAction<'_> {
        if error != CredentialErrorCode::NotFound {
            return SavedPasswordCredentialAction::FailClosed;
        }
        match lookup {
            SavedPasswordCredentialLookup::Identity => {
                let Some(identity) = self
                    .identity
                    .filter(|identity| identity.has_saved_credential)
                else {
                    return SavedPasswordCredentialAction::FailClosed;
                };
                match &self.manual_credential_owner {
                    Some(SavedPasswordManualCredentialOwner::Host) => {
                        SavedPasswordCredentialAction::ClearIdentityHintThenResolveHost {
                            identity_id: &identity.id,
                        }
                    }
                    Some(SavedPasswordManualCredentialOwner::Group(group_id)) => {
                        SavedPasswordCredentialAction::ClearIdentityHintThenResolveGroup {
                            identity_id: &identity.id,
                            group_id,
                        }
                    }
                    None => SavedPasswordCredentialAction::ClearIdentityHintThenRequireOneShot {
                        identity_id: &identity.id,
                    },
                }
            }
            SavedPasswordCredentialLookup::Host
                if matches!(
                    self.manual_credential_owner.as_ref(),
                    Some(SavedPasswordManualCredentialOwner::Host)
                ) =>
            {
                SavedPasswordCredentialAction::ClearHostHintThenRequireOneShot
            }
            SavedPasswordCredentialLookup::Group => {
                let Some(SavedPasswordManualCredentialOwner::Group(group_id)) =
                    &self.manual_credential_owner
                else {
                    return SavedPasswordCredentialAction::FailClosed;
                };
                SavedPasswordCredentialAction::ClearGroupHintThenRequireOneShot { group_id }
            }
            SavedPasswordCredentialLookup::Host => SavedPasswordCredentialAction::FailClosed,
        }
    }
}

impl fmt::Debug for SavedPasswordAuthResolution<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SavedPasswordAuthResolution")
            .field("has_identity", &self.identity.is_some())
            .field(
                "identity_has_saved_credential",
                &self.identity_has_saved_credential(),
            )
            .field(
                "manual_credential_owner",
                &match self.manual_credential_owner.as_ref() {
                    Some(SavedPasswordManualCredentialOwner::Host) => "host",
                    Some(SavedPasswordManualCredentialOwner::Group(_)) => "group",
                    None => "none",
                },
            )
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SavedPasswordCredentialLookup {
    Identity,
    Host,
    Group,
}

/// A secret-free instruction for the detached saved-host coordinator.
///
/// Identity IDs are available only as typed values needed to derive the
/// isolated OS-keyring reference and to clear a stale Vault hint. They are
/// intentionally omitted from `Debug`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SavedPasswordCredentialAction<'graph> {
    UseOneShot,
    ResolveIdentity {
        identity_id: &'graph SavedPasswordIdentityId,
    },
    ResolveHost,
    ResolveGroup {
        group_id: &'graph SavedGroupId,
    },
    RequireOneShot,
    ClearIdentityHintThenResolveHost {
        identity_id: &'graph SavedPasswordIdentityId,
    },
    ClearIdentityHintThenResolveGroup {
        identity_id: &'graph SavedPasswordIdentityId,
        group_id: &'graph SavedGroupId,
    },
    ClearIdentityHintThenRequireOneShot {
        identity_id: &'graph SavedPasswordIdentityId,
    },
    ClearHostHintThenRequireOneShot,
    ClearGroupHintThenRequireOneShot {
        group_id: &'graph SavedGroupId,
    },
    FailClosed,
}

impl fmt::Debug for SavedPasswordCredentialAction<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UseOneShot => "UseOneShot",
            Self::ResolveIdentity { .. } => "ResolveIdentity",
            Self::ResolveHost => "ResolveHost",
            Self::ResolveGroup { .. } => "ResolveGroup",
            Self::RequireOneShot => "RequireOneShot",
            Self::ClearIdentityHintThenResolveHost { .. } => "ClearIdentityHintThenResolveHost",
            Self::ClearIdentityHintThenResolveGroup { .. } => "ClearIdentityHintThenResolveGroup",
            Self::ClearIdentityHintThenRequireOneShot { .. } => {
                "ClearIdentityHintThenRequireOneShot"
            }
            Self::ClearHostHintThenRequireOneShot => "ClearHostHintThenRequireOneShot",
            Self::ClearGroupHintThenRequireOneShot { .. } => "ClearGroupHintThenRequireOneShot",
            Self::FailClosed => "FailClosed",
        })
    }
}

impl SavedHostAuthResolution<'_> {
    #[cfg(test)]
    pub(crate) fn key_id(&self) -> Option<&SavedSshKeyReferenceId> {
        match self {
            Self::Password => None,
            Self::ManagedPrivateKey { key_id, .. } | Self::ManagedCertificate { key_id, .. } => {
                Some(key_id)
            }
            Self::ReferencePrivateKey { key_id } => *key_id,
        }
    }

    #[cfg(test)]
    pub(crate) fn has_saved_key_passphrase(&self) -> bool {
        match self {
            Self::ManagedPrivateKey {
                has_saved_passphrase,
                ..
            }
            | Self::ManagedCertificate {
                has_saved_passphrase,
                ..
            } => *has_saved_passphrase,
            Self::Password | Self::ReferencePrivateKey { .. } => false,
        }
    }
}

impl fmt::Debug for SavedHostAuthResolution<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password => formatter.write_str("Password"),
            Self::ManagedPrivateKey {
                has_saved_passphrase,
                ..
            } => formatter
                .debug_struct("ManagedPrivateKey")
                .field("has_saved_passphrase", has_saved_passphrase)
                .finish_non_exhaustive(),
            Self::ManagedCertificate {
                has_saved_passphrase,
                ..
            } => formatter
                .debug_struct("ManagedCertificate")
                .field("has_saved_passphrase", has_saved_passphrase)
                .finish_non_exhaustive(),
            Self::ReferencePrivateKey { key_id } => formatter
                .debug_struct("ReferencePrivateKey")
                .field("catalog_reference", &key_id.is_some())
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SavedHostAuthGuardError {
    UnsupportedHostAuthMethod,
    InvalidIdentityReference,
    MissingIdentityReference,
    AmbiguousIdentityReference,
    IdentityAuthMethodMismatch,
    InvalidKeyReference,
    MissingKeyReference,
    AmbiguousKeyReference,
    ConflictingKeyReferences,
    KeyCategoryMismatch,
    InvalidReferenceFilePaths,
    ReferenceCertificateUnsupported,
    InvalidCredentialOwner,
}

impl SavedHostAuthGuardError {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::UnsupportedHostAuthMethod => SAVED_HOST_AUTH_METHOD_UNSUPPORTED,
            Self::ReferenceCertificateUnsupported => SAVED_HOST_REFERENCE_CERTIFICATE_UNSUPPORTED,
            Self::InvalidIdentityReference
            | Self::MissingIdentityReference
            | Self::AmbiguousIdentityReference
            | Self::IdentityAuthMethodMismatch
            | Self::InvalidKeyReference
            | Self::MissingKeyReference
            | Self::AmbiguousKeyReference
            | Self::ConflictingKeyReferences
            | Self::KeyCategoryMismatch
            | Self::InvalidReferenceFilePaths
            | Self::InvalidCredentialOwner => SAVED_HOST_AUTH_RELATIONSHIP_INVALID,
        }
    }
}

impl fmt::Display for SavedHostAuthGuardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedHostAuthMethod => {
                "This saved host authentication method is not available"
            }
            Self::ReferenceCertificateUnsupported => {
                "Reference-file certificates require separate certificate and private-key selection"
            }
            Self::InvalidIdentityReference
            | Self::MissingIdentityReference
            | Self::AmbiguousIdentityReference
            | Self::IdentityAuthMethodMismatch
            | Self::InvalidKeyReference
            | Self::MissingKeyReference
            | Self::AmbiguousKeyReference
            | Self::ConflictingKeyReferences
            | Self::KeyCategoryMismatch
            | Self::InvalidReferenceFilePaths
            | Self::InvalidCredentialOwner => {
                "The saved host key relationship is invalid; repair the Vault before connecting"
            }
        };
        write!(formatter, "{}: {message}", self.code())
    }
}

impl std::error::Error for SavedHostAuthGuardError {}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RequiredKeyKind {
    PrivateKey,
    Certificate,
}

enum ResolvedCatalogKey<'graph> {
    Managed {
        id: &'graph SavedSshKeyReferenceId,
        category: &'graph netcatty_vault::SavedSshKeyCategory,
        has_saved_passphrase: bool,
    },
    Reference {
        id: &'graph SavedSshKeyReferenceId,
        category: &'graph netcatty_vault::SavedSshKeyCategory,
    },
}

/// Resolves the complete saved-host identity/key relationship before any
/// credential, secret blob, legacy path, or native-picker result is used.
///
/// A relationship ID that is present but malformed or missing never falls
/// back to another source. If both `identityId` and `identityFileId` exist,
/// they must resolve to the same key. The same key ID may not exist in both
/// the managed and reference catalogs.
pub(crate) fn resolve_saved_host_authentication<'graph>(
    host: &SavedHost,
    graph: &'graph SavedVaultGraph,
) -> Result<SavedHostAuthResolution<'graph>, SavedHostAuthGuardError> {
    let required_kind = if host.auth_method.is_password() {
        // Password identities are an independent catalog. Validate their
        // relationship even though this compatibility return type remains a
        // unit variant for existing callers.
        resolve_saved_password_authentication(host, graph)?;
        return Ok(SavedHostAuthResolution::Password);
    } else if host.auth_method.as_str().eq_ignore_ascii_case("key") {
        RequiredKeyKind::PrivateKey
    } else if host
        .auth_method
        .as_str()
        .eq_ignore_ascii_case("certificate")
    {
        RequiredKeyKind::Certificate
    } else {
        return Err(SavedHostAuthGuardError::UnsupportedHostAuthMethod);
    };

    let identity_id = optional_relationship_id(host, "identityId")
        .map_err(|_| SavedHostAuthGuardError::InvalidIdentityReference)?;
    let direct_key_id = optional_relationship_id(host, "identityFileId")
        .map_err(|_| SavedHostAuthGuardError::InvalidKeyReference)?;
    let has_reference_paths = validated_reference_file_paths(host)?;

    let identity = identity_id
        .map(|id| resolve_identity(graph, id))
        .transpose()?;
    if let Some(identity) = identity {
        let identity_matches = match required_kind {
            RequiredKeyKind::PrivateKey => identity.auth_method.is_key(),
            RequiredKeyKind::Certificate => identity.auth_method.is_certificate(),
        };
        if !identity_matches {
            return Err(SavedHostAuthGuardError::IdentityAuthMethodMismatch);
        }
        if direct_key_id.is_some_and(|id| id != identity.key_id.as_str()) {
            return Err(SavedHostAuthGuardError::ConflictingKeyReferences);
        }
    }

    let resolved_id = identity
        .map(|identity| identity.key_id.as_str())
        .or(direct_key_id);
    let Some(resolved_id) = resolved_id else {
        if has_reference_paths {
            return match required_kind {
                RequiredKeyKind::PrivateKey => {
                    Ok(SavedHostAuthResolution::ReferencePrivateKey { key_id: None })
                }
                RequiredKeyKind::Certificate => {
                    Err(SavedHostAuthGuardError::ReferenceCertificateUnsupported)
                }
            };
        }
        return Err(SavedHostAuthGuardError::MissingKeyReference);
    };

    let key = resolve_catalog_key(graph, resolved_id)?;
    let category_matches = match (&key, required_kind) {
        (ResolvedCatalogKey::Managed { category, .. }, RequiredKeyKind::PrivateKey)
        | (ResolvedCatalogKey::Reference { category, .. }, RequiredKeyKind::PrivateKey) => {
            category.is_private_key_material()
        }
        (ResolvedCatalogKey::Managed { category, .. }, RequiredKeyKind::Certificate)
        | (ResolvedCatalogKey::Reference { category, .. }, RequiredKeyKind::Certificate) => {
            category.is_certificate()
        }
    };
    if !category_matches {
        return Err(SavedHostAuthGuardError::KeyCategoryMismatch);
    }

    match (key, required_kind) {
        (
            ResolvedCatalogKey::Managed {
                id,
                has_saved_passphrase,
                ..
            },
            RequiredKeyKind::PrivateKey,
        ) => Ok(SavedHostAuthResolution::ManagedPrivateKey {
            key_id: id,
            has_saved_passphrase,
        }),
        (
            ResolvedCatalogKey::Managed {
                id,
                has_saved_passphrase,
                ..
            },
            RequiredKeyKind::Certificate,
        ) => Ok(SavedHostAuthResolution::ManagedCertificate {
            key_id: id,
            has_saved_passphrase,
        }),
        (ResolvedCatalogKey::Reference { id, .. }, RequiredKeyKind::PrivateKey) => {
            Ok(SavedHostAuthResolution::ReferencePrivateKey { key_id: Some(id) })
        }
        (ResolvedCatalogKey::Reference { .. }, RequiredKeyKind::Certificate) => {
            Err(SavedHostAuthGuardError::ReferenceCertificateUnsupported)
        }
    }
}

/// Resolves reusable password-identity metadata without touching the OS
/// keyring or accepting any secret-bearing value.
///
/// A present `identityId` must resolve exactly once in the password-identity
/// catalog and must not also be claimed by the key/certificate identity
/// catalog. Missing, malformed, cross-typed, and ambiguous relationships fail
/// before one-shot or persisted credentials are selected.
pub(crate) fn resolve_saved_password_authentication<'graph>(
    host: &SavedHost,
    graph: &'graph SavedVaultGraph,
) -> Result<SavedPasswordAuthResolution<'graph>, SavedHostAuthGuardError> {
    let inferred_owner = host
        .compatibility_fields()
        .get("hasSavedCredential")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        .then(|| SavedHostConnectionCredentialOwner::Host(host.id.clone()));
    resolve_projected_saved_password_authentication(host, graph, inferred_owner.as_ref())
}

/// Resolves password authentication for an effective GroupConfig projection.
///
/// The projected `hasSavedCredential` bit is deliberately insufficient to
/// choose a keyring namespace. Its exact host/group provenance must accompany
/// the host view, otherwise the relationship fails closed.
pub(crate) fn resolve_projected_saved_password_authentication<'graph>(
    host: &SavedHost,
    graph: &'graph SavedVaultGraph,
    credential_owner: Option<&SavedHostConnectionCredentialOwner>,
) -> Result<SavedPasswordAuthResolution<'graph>, SavedHostAuthGuardError> {
    if !host.auth_method.is_password() {
        return Err(SavedHostAuthGuardError::UnsupportedHostAuthMethod);
    }
    let identity_id = optional_relationship_id(host, "identityId")
        .map_err(|_| SavedHostAuthGuardError::InvalidIdentityReference)?;
    let identity = identity_id
        .map(|id| resolve_password_identity(graph, id))
        .transpose()?;
    let has_saved_credential = host
        .compatibility_fields()
        .get("hasSavedCredential")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let manual_credential_owner = match (has_saved_credential, credential_owner) {
        (false, None) => None,
        (true, Some(SavedHostConnectionCredentialOwner::Host(owner_id)))
            if owner_id == &host.id =>
        {
            Some(SavedPasswordManualCredentialOwner::Host)
        }
        (true, Some(SavedHostConnectionCredentialOwner::Group(group_id))) => {
            Some(SavedPasswordManualCredentialOwner::Group(group_id.clone()))
        }
        _ => return Err(SavedHostAuthGuardError::InvalidCredentialOwner),
    };
    Ok(SavedPasswordAuthResolution {
        identity,
        manual_credential_owner,
    })
}

pub(crate) fn validate_saved_password_identity_selection<'graph>(
    identity_id: &str,
    graph: &'graph SavedVaultGraph,
) -> Result<&'graph SavedPasswordIdentity, SavedHostAuthGuardError> {
    if identity_id.trim().is_empty() || identity_id.chars().any(char::is_control) {
        return Err(SavedHostAuthGuardError::InvalidIdentityReference);
    }
    resolve_password_identity(graph, identity_id)
}

fn optional_relationship_id<'host>(
    host: &'host SavedHost,
    field: &str,
) -> Result<Option<&'host str>, ()> {
    match host.compatibility_fields().get(field) {
        None => Ok(None),
        Some(Value::String(id)) if !id.trim().is_empty() && !id.chars().any(char::is_control) => {
            Ok(Some(id))
        }
        Some(_) => Err(()),
    }
}

fn resolve_identity<'graph>(
    graph: &'graph SavedVaultGraph,
    id: &str,
) -> Result<&'graph SavedIdentityReference, SavedHostAuthGuardError> {
    let mut matches = graph
        .identity_references()
        .iter()
        .filter(|identity| identity.id.as_str() == id);
    let Some(identity) = matches.next() else {
        return Err(SavedHostAuthGuardError::MissingIdentityReference);
    };
    if matches.next().is_some() {
        return Err(SavedHostAuthGuardError::AmbiguousIdentityReference);
    }
    Ok(identity)
}

fn resolve_password_identity<'graph>(
    graph: &'graph SavedVaultGraph,
    id: &str,
) -> Result<&'graph SavedPasswordIdentity, SavedHostAuthGuardError> {
    let mut password_matches = graph
        .password_identities()
        .iter()
        .filter(|identity| identity.id.as_str() == id);
    let password_identity = password_matches.next();
    let password_is_ambiguous = password_matches.next().is_some();

    let mut key_matches = graph
        .identity_references()
        .iter()
        .filter(|identity| identity.id.as_str() == id);
    let key_identity = key_matches.next();
    let key_is_ambiguous = key_matches.next().is_some();

    if password_is_ambiguous
        || key_is_ambiguous
        || (password_identity.is_some() && key_identity.is_some())
    {
        return Err(SavedHostAuthGuardError::AmbiguousIdentityReference);
    }
    if let Some(identity) = password_identity {
        return Ok(identity);
    }
    if key_identity.is_some() {
        return Err(SavedHostAuthGuardError::IdentityAuthMethodMismatch);
    }
    Err(SavedHostAuthGuardError::MissingIdentityReference)
}

fn resolve_catalog_key<'graph>(
    graph: &'graph SavedVaultGraph,
    id: &str,
) -> Result<ResolvedCatalogKey<'graph>, SavedHostAuthGuardError> {
    let mut managed = graph
        .managed_ssh_keys()
        .iter()
        .filter(|key| key.id.as_str() == id);
    let managed_key = managed.next();
    let managed_is_ambiguous = managed.next().is_some();

    let mut references = graph
        .ssh_key_references()
        .iter()
        .filter(|key| key.id.as_str() == id);
    let reference_key = references.next();
    let reference_is_ambiguous = references.next().is_some();

    if managed_is_ambiguous
        || reference_is_ambiguous
        || (managed_key.is_some() && reference_key.is_some())
    {
        return Err(SavedHostAuthGuardError::AmbiguousKeyReference);
    }
    if let Some(key) = managed_key {
        return Ok(ResolvedCatalogKey::Managed {
            id: &key.id,
            category: &key.category,
            has_saved_passphrase: key.has_saved_passphrase,
        });
    }
    if let Some(key) = reference_key {
        return Ok(ResolvedCatalogKey::Reference {
            id: &key.id,
            category: &key.category,
        });
    }
    Err(SavedHostAuthGuardError::MissingKeyReference)
}

fn validated_reference_file_paths(host: &SavedHost) -> Result<bool, SavedHostAuthGuardError> {
    let Some(value) = host.compatibility_fields().get("identityFilePaths") else {
        return Ok(false);
    };
    let Value::Array(paths) = value else {
        return Err(SavedHostAuthGuardError::InvalidReferenceFilePaths);
    };
    if paths.is_empty() || paths.len() > MAX_REFERENCE_FILE_PATHS {
        return Err(SavedHostAuthGuardError::InvalidReferenceFilePaths);
    }

    let mut total_bytes = 0_usize;
    let mut seen = HashSet::with_capacity(paths.len());
    for value in paths {
        let Some(path) = value.as_str() else {
            return Err(SavedHostAuthGuardError::InvalidReferenceFilePaths);
        };
        total_bytes = total_bytes
            .checked_add(path.len())
            .ok_or(SavedHostAuthGuardError::InvalidReferenceFilePaths)?;
        if path.trim().is_empty()
            || path.len() > MAX_REFERENCE_FILE_PATH_BYTES
            || total_bytes > MAX_REFERENCE_FILE_PATHS_BYTES
            || path.chars().any(char::is_control)
            || !seen.insert(path)
        {
            return Err(SavedHostAuthGuardError::InvalidReferenceFilePaths);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use netcatty_credentials::CredentialErrorCode;
    use netcatty_vault::{
        SavedGroupId, SavedHost, SavedHostConnectionCredentialOwner, SavedHostId,
        SavedIdentityReference, SavedIdentityReferenceId, SavedManagedSshKey,
        SavedPasswordIdentity, SavedPasswordIdentityId, SavedSecretObjectLocator,
        SavedSshKeyCategory, SavedSshKeyCustodyReference, SavedSshKeyReference,
        SavedSshKeyReferenceId, SavedSshKeySource, SavedVaultGraph,
    };
    use serde_json::{Map, Value, json};

    use super::{
        SAVED_HOST_AUTH_RELATIONSHIP_INVALID, SAVED_HOST_REFERENCE_CERTIFICATE_UNSUPPORTED,
        SavedHostAuthGuardError, SavedHostAuthResolution, SavedPasswordCredentialAction,
        SavedPasswordCredentialLookup, resolve_projected_saved_password_authentication,
        resolve_saved_host_authentication, resolve_saved_password_authentication,
    };

    fn host(auth_method: &str, compatibility_fields: Value) -> SavedHost {
        let mut object = Map::from_iter([
            ("recordVersion".to_owned(), json!(1)),
            ("id".to_owned(), json!("guard-host")),
            ("revision".to_owned(), json!(1)),
            ("label".to_owned(), json!("Guard host")),
            ("hostname".to_owned(), json!("guard.example.test")),
            ("port".to_owned(), json!(22)),
            ("username".to_owned(), json!("alice")),
            ("protocol".to_owned(), json!("ssh")),
            ("authMethod".to_owned(), json!(auth_method)),
            ("authPolicyVersion".to_owned(), json!(1)),
            ("createdAt".to_owned(), json!(1)),
            ("updatedAt".to_owned(), json!(1)),
        ]);
        if let Value::Object(fields) = compatibility_fields {
            object.extend(fields);
        }
        serde_json::from_value(Value::Object(object)).expect("saved host")
    }

    fn reference_key(id: &str, category: SavedSshKeyCategory) -> SavedSshKeyReference {
        SavedSshKeyReference::from_parts(
            SavedSshKeyReferenceId::from_opaque(id).expect("key ID"),
            "Reference key",
            r"Z:\never-open\reference-key",
            category,
            1,
            1,
            BTreeMap::new(),
        )
        .expect("reference key")
    }

    fn managed_key(
        id: &str,
        category: SavedSshKeyCategory,
        locator_byte: u8,
    ) -> SavedManagedSshKey {
        let locator = SavedSecretObjectLocator::from_hex(format!("{locator_byte:02x}").repeat(32))
            .expect("locator");
        SavedManagedSshKey::from_parts(
            SavedSshKeyReferenceId::from_opaque(id).expect("key ID"),
            "Managed key",
            category,
            SavedSshKeySource::imported(),
            true,
            1,
            1,
            SavedSshKeyCustodyReference::new(locator, 1).expect("custody"),
            BTreeMap::new(),
        )
        .expect("managed key")
    }

    fn identity(id: &str, key_id: &str, certificate: bool) -> SavedIdentityReference {
        let id = SavedIdentityReferenceId::from_opaque(id).expect("identity ID");
        let key_id = SavedSshKeyReferenceId::from_opaque(key_id).expect("key ID");
        if certificate {
            SavedIdentityReference::from_certificate_parts(
                id,
                "Certificate identity",
                "alice",
                key_id,
                1,
                1,
                BTreeMap::new(),
            )
            .expect("certificate identity")
        } else {
            SavedIdentityReference::from_parts(
                id,
                "Key identity",
                "alice",
                key_id,
                1,
                1,
                BTreeMap::new(),
            )
            .expect("key identity")
        }
    }

    fn graph(
        references: Vec<SavedSshKeyReference>,
        managed: Vec<SavedManagedSshKey>,
        identities: Vec<SavedIdentityReference>,
    ) -> SavedVaultGraph {
        SavedVaultGraph::new_with_managed_ssh_keys(Vec::new(), references, managed, identities)
    }

    fn password_identity(
        id: &str,
        username: &str,
        has_saved_credential: bool,
    ) -> SavedPasswordIdentity {
        SavedPasswordIdentity::from_parts(
            SavedPasswordIdentityId::from_opaque(id).expect("password identity ID"),
            1,
            "Password identity",
            username,
            has_saved_credential,
            1,
            1,
            BTreeMap::new(),
        )
        .expect("password identity")
    }

    fn password_graph(
        password_identities: Vec<SavedPasswordIdentity>,
        key_identities: Vec<SavedIdentityReference>,
    ) -> SavedVaultGraph {
        SavedVaultGraph::new_with_password_identities(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            key_identities,
            password_identities,
        )
    }

    #[test]
    fn managed_key_and_certificate_resolve_without_exposing_custody() {
        let locator_sentinel = "ab".repeat(32);
        let private_graph = graph(
            Vec::new(),
            vec![managed_key(
                "managed-private",
                SavedSshKeyCategory::identity(),
                0xab,
            )],
            vec![identity("private-identity", "managed-private", false)],
        );
        let private_host = host("key", json!({"identityId": "private-identity"}));
        let private = resolve_saved_host_authentication(&private_host, &private_graph)
            .expect("managed private key");
        assert!(matches!(
            private,
            SavedHostAuthResolution::ManagedPrivateKey {
                key_id,
                has_saved_passphrase: true
            } if key_id.as_str() == "managed-private"
        ));
        assert!(private.has_saved_key_passphrase());
        assert_eq!(
            private.key_id().expect("key ID").as_str(),
            "managed-private"
        );
        let debug = format!("{private:?}");
        assert!(!debug.contains("managed-private"));
        assert!(!debug.contains(&locator_sentinel));

        let certificate_graph = graph(
            Vec::new(),
            vec![managed_key(
                "managed-certificate",
                SavedSshKeyCategory::certificate(),
                0xcd,
            )],
            vec![identity(
                "certificate-identity",
                "managed-certificate",
                true,
            )],
        );
        let certificate_host = host("certificate", json!({"identityId": "certificate-identity"}));
        assert!(matches!(
            resolve_saved_host_authentication(&certificate_host, &certificate_graph),
            Ok(SavedHostAuthResolution::ManagedCertificate { key_id, .. })
                if key_id.as_str() == "managed-certificate"
        ));
    }

    #[test]
    fn direct_reference_private_key_and_legacy_path_only_shape_are_explicit() {
        let catalog_graph = graph(
            vec![reference_key(
                "reference-private",
                SavedSshKeyCategory::key(),
            )],
            Vec::new(),
            Vec::new(),
        );
        let catalog_host = host("key", json!({"identityFileId": "reference-private"}));
        assert!(matches!(
            resolve_saved_host_authentication(&catalog_host, &catalog_graph),
            Ok(SavedHostAuthResolution::ReferencePrivateKey { key_id: Some(id) })
                if id.as_str() == "reference-private"
        ));

        let path_only = host(
            "key",
            json!({"identityFilePaths": [r"Z:\never-open\legacy-key"]}),
        );
        assert_eq!(
            resolve_saved_host_authentication(&path_only, &SavedVaultGraph::default()),
            Ok(SavedHostAuthResolution::ReferencePrivateKey { key_id: None })
        );
    }

    #[test]
    fn identity_and_direct_key_references_must_agree() {
        let graph = graph(
            vec![
                reference_key("identity-key", SavedSshKeyCategory::key()),
                reference_key("direct-key", SavedSshKeyCategory::key()),
            ],
            Vec::new(),
            vec![identity("identity", "identity-key", false)],
        );
        let conflict = host(
            "key",
            json!({"identityId": "identity", "identityFileId": "direct-key"}),
        );
        assert_eq!(
            resolve_saved_host_authentication(&conflict, &graph),
            Err(SavedHostAuthGuardError::ConflictingKeyReferences)
        );

        let same = host(
            "key",
            json!({"identityId": "identity", "identityFileId": "identity-key"}),
        );
        assert!(matches!(
            resolve_saved_host_authentication(&same, &graph),
            Ok(SavedHostAuthResolution::ReferencePrivateKey { .. })
        ));
    }

    #[test]
    fn identity_auth_method_and_key_category_mismatches_fail_closed() {
        let key_identity_graph = graph(
            Vec::new(),
            vec![managed_key(
                "managed-certificate",
                SavedSshKeyCategory::certificate(),
                0xef,
            )],
            vec![identity("key-identity", "managed-certificate", false)],
        );
        let certificate_host = host("certificate", json!({"identityId": "key-identity"}));
        assert_eq!(
            resolve_saved_host_authentication(&certificate_host, &key_identity_graph),
            Err(SavedHostAuthGuardError::IdentityAuthMethodMismatch)
        );

        let direct_mismatch = host("key", json!({"identityFileId": "managed-certificate"}));
        assert_eq!(
            resolve_saved_host_authentication(&direct_mismatch, &key_identity_graph),
            Err(SavedHostAuthGuardError::KeyCategoryMismatch)
        );
    }

    #[test]
    fn managed_and_reference_catalogs_cannot_claim_the_same_key_id() {
        let ambiguous = graph(
            vec![reference_key("shared-key", SavedSshKeyCategory::key())],
            vec![managed_key("shared-key", SavedSshKeyCategory::key(), 0x12)],
            Vec::new(),
        );
        let host = host("key", json!({"identityFileId": "shared-key"}));
        assert_eq!(
            resolve_saved_host_authentication(&host, &ambiguous),
            Err(SavedHostAuthGuardError::AmbiguousKeyReference)
        );
    }

    #[test]
    fn present_but_missing_or_malformed_references_never_fall_back() {
        let path = r"Z:\must-not-be-used\fallback-key-sentinel";
        for (host, expected) in [
            (
                host(
                    "key",
                    json!({"identityId": "missing", "identityFilePaths": [path]}),
                ),
                SavedHostAuthGuardError::MissingIdentityReference,
            ),
            (
                host(
                    "key",
                    json!({"identityFileId": "missing", "identityFilePaths": [path]}),
                ),
                SavedHostAuthGuardError::MissingKeyReference,
            ),
            (
                host("key", json!({"identityId": 7, "identityFilePaths": [path]})),
                SavedHostAuthGuardError::InvalidIdentityReference,
            ),
            (
                host(
                    "key",
                    json!({"identityFileId": "", "identityFilePaths": [path]}),
                ),
                SavedHostAuthGuardError::InvalidKeyReference,
            ),
        ] {
            let error = resolve_saved_host_authentication(&host, &SavedVaultGraph::default())
                .expect_err("relationship must fail closed");
            assert_eq!(error, expected);
            let rendered = error.to_string();
            assert!(rendered.starts_with(SAVED_HOST_AUTH_RELATIONSHIP_INVALID));
            assert!(!rendered.contains("missing"));
            assert!(!rendered.contains(path));
        }
    }

    #[test]
    fn malformed_persisted_reference_paths_fail_before_picker_use() {
        for fields in [
            json!({"identityFilePaths": []}),
            json!({"identityFilePaths": [""]}),
            json!({"identityFilePaths": ["duplicate", "duplicate"]}),
            json!({"identityFilePaths": ["control\npath"]}),
            json!({"identityFilePaths": [7]}),
            json!({"identityFilePaths": "not-an-array"}),
        ] {
            assert_eq!(
                resolve_saved_host_authentication(
                    &host("key", fields),
                    &SavedVaultGraph::default()
                ),
                Err(SavedHostAuthGuardError::InvalidReferenceFilePaths)
            );
        }
    }

    #[test]
    fn reference_certificates_are_rejected_with_one_fixed_safe_error() {
        let locator_sentinel = r"Z:\must-not-leak\certificate-reference";
        let reference = SavedSshKeyReference::from_parts(
            SavedSshKeyReferenceId::from_opaque("reference-certificate").expect("ID"),
            "Reference certificate",
            locator_sentinel,
            SavedSshKeyCategory::certificate(),
            1,
            1,
            BTreeMap::new(),
        )
        .expect("reference certificate");
        let graph = graph(vec![reference], Vec::new(), Vec::new());
        let direct = host(
            "certificate",
            json!({"identityFileId": "reference-certificate"}),
        );
        let path_only = host(
            "certificate",
            json!({"identityFilePaths": [locator_sentinel]}),
        );

        for host in [&direct, &path_only] {
            let error = resolve_saved_host_authentication(host, &graph)
                .expect_err("reference certificate must be rejected");
            assert_eq!(
                error,
                SavedHostAuthGuardError::ReferenceCertificateUnsupported
            );
            let rendered = error.to_string();
            assert!(rendered.starts_with(SAVED_HOST_REFERENCE_CERTIFICATE_UNSUPPORTED));
            assert!(!rendered.contains("reference-certificate"));
            assert!(!rendered.contains(locator_sentinel));
        }
    }

    #[test]
    fn password_is_the_only_authentication_mode_without_a_key_relationship() {
        assert_eq!(
            resolve_saved_host_authentication(
                &host("password", json!({})),
                &SavedVaultGraph::default()
            ),
            Ok(SavedHostAuthResolution::Password)
        );
        assert_eq!(
            resolve_saved_host_authentication(
                &host("future-auth", json!({})),
                &SavedVaultGraph::default()
            ),
            Err(SavedHostAuthGuardError::UnsupportedHostAuthMethod)
        );
    }

    #[test]
    fn password_identity_username_and_credential_precedence_are_explicit() {
        let identity_id = "shared-password-identity-sentinel";
        let graph = password_graph(
            vec![password_identity(identity_id, "identity-user", true)],
            Vec::new(),
        );
        let host = host(
            "password",
            json!({"identityId": identity_id, "hasSavedCredential": true}),
        );
        let resolution =
            resolve_saved_password_authentication(&host, &graph).expect("password resolution");

        assert_eq!(resolution.effective_username(&host), "identity-user");
        assert!(resolution.has_password_identity());
        assert!(resolution.identity_has_saved_credential());
        assert!(resolution.host_has_saved_credential());
        assert!(resolution.effective_has_saved_credential());
        assert_eq!(
            resolution.first_credential_action(true),
            SavedPasswordCredentialAction::UseOneShot,
            "one-shot credentials must always outrank persisted credentials"
        );
        assert!(matches!(
            resolution.first_credential_action(false),
            SavedPasswordCredentialAction::ResolveIdentity { identity_id: id }
                if id.as_str() == identity_id
        ));

        let rendered = format!(
            "{resolution:?} {:?}",
            resolution.first_credential_action(false)
        );
        assert!(!rendered.contains(identity_id));
        assert!(!rendered.contains("identity-user"));
    }

    #[test]
    fn projected_group_password_uses_only_the_group_credential_namespace() {
        let group_id = SavedGroupId::from_opaque("group-ssh-owner-sentinel").expect("group ID");
        let owner = SavedHostConnectionCredentialOwner::Group(group_id.clone());
        let host = host("password", json!({"hasSavedCredential": true}));
        let graph = SavedVaultGraph::default();
        let resolution =
            resolve_projected_saved_password_authentication(&host, &graph, Some(&owner))
                .expect("projected password resolution");

        assert!(resolution.group_has_saved_credential());
        assert!(!resolution.host_has_saved_credential());
        assert!(matches!(
            resolution.first_credential_action(false),
            SavedPasswordCredentialAction::ResolveGroup { group_id: selected }
                if selected == &group_id
        ));
        assert_eq!(
            resolution.after_lookup_error(
                SavedPasswordCredentialLookup::Host,
                CredentialErrorCode::NotFound,
            ),
            SavedPasswordCredentialAction::FailClosed,
            "a group hint must never authorize a host-account repair"
        );
        assert!(matches!(
            resolution.after_lookup_error(
                SavedPasswordCredentialLookup::Group,
                CredentialErrorCode::NotFound,
            ),
            SavedPasswordCredentialAction::ClearGroupHintThenRequireOneShot {
                group_id: selected
            } if selected == &group_id
        ));

        let rendered = format!(
            "{resolution:?} {:?}",
            resolution.first_credential_action(false)
        );
        assert!(!rendered.contains(group_id.as_str()));
    }

    #[test]
    fn missing_identity_falls_back_to_the_projected_group_not_the_host() {
        let identity_id = "group-fallback-identity-sentinel";
        let group_id =
            SavedGroupId::from_opaque("group-fallback-owner-sentinel").expect("group ID");
        let graph = password_graph(
            vec![password_identity(identity_id, "identity-user", true)],
            Vec::new(),
        );
        let host = host(
            "password",
            json!({"identityId": identity_id, "hasSavedCredential": true}),
        );
        let owner = SavedHostConnectionCredentialOwner::Group(group_id.clone());
        let resolution =
            resolve_projected_saved_password_authentication(&host, &graph, Some(&owner))
                .expect("projected identity resolution");

        assert!(matches!(
            resolution.after_lookup_error(
                SavedPasswordCredentialLookup::Identity,
                CredentialErrorCode::NotFound,
            ),
            SavedPasswordCredentialAction::ClearIdentityHintThenResolveGroup {
                identity_id: selected_identity,
                group_id: selected_group,
            } if selected_identity.as_str() == identity_id && selected_group == &group_id
        ));
    }

    #[test]
    fn projected_password_rejects_missing_or_wrong_host_provenance() {
        let host = host("password", json!({"hasSavedCredential": true}));
        let graph = SavedVaultGraph::default();
        assert_eq!(
            resolve_projected_saved_password_authentication(&host, &graph, None),
            Err(SavedHostAuthGuardError::InvalidCredentialOwner)
        );

        let wrong = SavedHostConnectionCredentialOwner::Host(
            SavedHostId::from_opaque("different-host-owner").expect("host ID"),
        );
        assert_eq!(
            resolve_projected_saved_password_authentication(&host, &graph, Some(&wrong)),
            Err(SavedHostAuthGuardError::InvalidCredentialOwner)
        );
    }

    #[test]
    fn empty_or_absent_identity_username_preserves_host_username() {
        let graph = password_graph(
            vec![password_identity("empty-user-identity", "", false)],
            Vec::new(),
        );
        let with_identity = host(
            "password",
            json!({"identityId": "empty-user-identity", "hasSavedCredential": true}),
        );
        let resolution = resolve_saved_password_authentication(&with_identity, &graph)
            .expect("empty username is valid");
        assert_eq!(resolution.effective_username(&with_identity), "alice");
        assert!(resolution.has_password_identity());
        assert!(!resolution.identity_has_saved_credential());
        assert!(resolution.host_has_saved_credential());
        assert!(resolution.effective_has_saved_credential());
        assert_eq!(
            resolution.first_credential_action(false),
            SavedPasswordCredentialAction::ResolveHost
        );

        let without_identity = host("password", json!({"hasSavedCredential": false}));
        let empty_graph = SavedVaultGraph::default();
        let resolution = resolve_saved_password_authentication(&without_identity, &empty_graph)
            .expect("host-only password resolution");
        assert_eq!(resolution.effective_username(&without_identity), "alice");
        assert!(!resolution.has_password_identity());
        assert!(!resolution.identity_has_saved_credential());
        assert!(!resolution.host_has_saved_credential());
        assert!(!resolution.effective_has_saved_credential());
        assert_eq!(
            resolution.first_credential_action(false),
            SavedPasswordCredentialAction::RequireOneShot
        );
    }

    #[test]
    fn missing_identity_credential_clears_only_its_hint_then_falls_back_to_host() {
        let identity_id = "missing-identity-credential-sentinel";
        let graph = password_graph(
            vec![password_identity(identity_id, "identity-user", true)],
            Vec::new(),
        );
        let saved_host = host(
            "password",
            json!({"identityId": identity_id, "hasSavedCredential": true}),
        );
        let resolution = resolve_saved_password_authentication(&saved_host, &graph)
            .expect("password resolution");
        let action = resolution.after_lookup_error(
            SavedPasswordCredentialLookup::Identity,
            CredentialErrorCode::NotFound,
        );
        assert!(matches!(
            action,
            SavedPasswordCredentialAction::ClearIdentityHintThenResolveHost { identity_id: id }
                if id.as_str() == identity_id
        ));
        assert!(!format!("{action:?}").contains(identity_id));

        let no_host_hint = host("password", json!({"identityId": identity_id}));
        let resolution = resolve_saved_password_authentication(&no_host_hint, &graph)
            .expect("password resolution without host credential");
        assert!(matches!(
            resolution.after_lookup_error(
                SavedPasswordCredentialLookup::Identity,
                CredentialErrorCode::NotFound,
            ),
            SavedPasswordCredentialAction::ClearIdentityHintThenRequireOneShot {
                identity_id: id
            } if id.as_str() == identity_id
        ));
    }

    #[test]
    fn corrupt_or_unavailable_identity_credential_never_falls_back() {
        let identity_id = "fail-closed-identity-sentinel";
        let graph = password_graph(
            vec![password_identity(identity_id, "identity-user", true)],
            Vec::new(),
        );
        let host = host(
            "password",
            json!({"identityId": identity_id, "hasSavedCredential": true}),
        );
        let resolution =
            resolve_saved_password_authentication(&host, &graph).expect("password resolution");

        let non_missing_errors = [
            CredentialErrorCode::InvalidReference,
            CredentialErrorCode::Expired,
            CredentialErrorCode::OwnerMismatch,
            CredentialErrorCode::InvalidSecret,
            CredentialErrorCode::TooLarge,
            CredentialErrorCode::CapacityExceeded,
            CredentialErrorCode::InvalidUtf8,
            CredentialErrorCode::KindMismatch,
            CredentialErrorCode::CorruptRecord,
            CredentialErrorCode::StorageUnavailable,
            CredentialErrorCode::Conflict,
            CredentialErrorCode::BackendFailure,
        ];
        for error in non_missing_errors {
            assert_eq!(
                resolution.after_lookup_error(SavedPasswordCredentialLookup::Identity, error),
                SavedPasswordCredentialAction::FailClosed,
                "only NotFound may authorize host fallback"
            );
            assert_eq!(
                resolution.after_lookup_error(SavedPasswordCredentialLookup::Host, error),
                SavedPasswordCredentialAction::FailClosed,
                "host keyring failures must also fail closed"
            );
        }
    }

    #[test]
    fn impossible_lookup_transitions_fail_closed_even_for_not_found() {
        let graph = password_graph(
            vec![password_identity("identity-without-hint", "", false)],
            Vec::new(),
        );
        let identity_host = host("password", json!({"identityId": "identity-without-hint"}));
        let identity_resolution =
            resolve_saved_password_authentication(&identity_host, &graph).expect("resolution");
        assert_eq!(
            identity_resolution.after_lookup_error(
                SavedPasswordCredentialLookup::Identity,
                CredentialErrorCode::NotFound,
            ),
            SavedPasswordCredentialAction::FailClosed,
            "a coordinator must not look up an identity whose hint is false"
        );

        let empty_graph = SavedVaultGraph::default();
        let host_without_hint = host("password", json!({}));
        let host_resolution =
            resolve_saved_password_authentication(&host_without_hint, &empty_graph)
                .expect("resolution");
        assert_eq!(
            host_resolution.after_lookup_error(
                SavedPasswordCredentialLookup::Host,
                CredentialErrorCode::NotFound,
            ),
            SavedPasswordCredentialAction::FailClosed,
            "a coordinator must not look up a host whose hint is false"
        );
    }

    #[test]
    fn missing_host_credential_has_an_explicit_hint_cleanup_result() {
        let host = host("password", json!({"hasSavedCredential": true}));
        let empty_graph = SavedVaultGraph::default();
        let resolution = resolve_saved_password_authentication(&host, &empty_graph)
            .expect("host-only resolution");
        assert_eq!(
            resolution.after_lookup_error(
                SavedPasswordCredentialLookup::Host,
                CredentialErrorCode::NotFound,
            ),
            SavedPasswordCredentialAction::ClearHostHintThenRequireOneShot
        );
        assert_eq!(
            resolution.after_lookup_error(
                SavedPasswordCredentialLookup::Host,
                CredentialErrorCode::StorageUnavailable,
            ),
            SavedPasswordCredentialAction::FailClosed
        );
    }

    #[test]
    fn password_identity_relationships_are_strict_and_secret_free() {
        let missing_id = "missing-password-identity-sentinel";
        let key_id = "wrong-type-identity-sentinel";
        let key_graph = password_graph(Vec::new(), vec![identity(key_id, "unused-key", false)]);
        for (host, graph, expected) in [
            (
                host("password", json!({"identityId": missing_id})),
                SavedVaultGraph::default(),
                SavedHostAuthGuardError::MissingIdentityReference,
            ),
            (
                host("password", json!({"identityId": key_id})),
                key_graph,
                SavedHostAuthGuardError::IdentityAuthMethodMismatch,
            ),
            (
                host("password", json!({"identityId": 7})),
                SavedVaultGraph::default(),
                SavedHostAuthGuardError::InvalidIdentityReference,
            ),
        ] {
            let error = resolve_saved_host_authentication(&host, &graph)
                .expect_err("invalid password identity relationship");
            assert_eq!(error, expected);
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains(missing_id));
            assert!(!rendered.contains(key_id));
            assert!(rendered.contains(SAVED_HOST_AUTH_RELATIONSHIP_INVALID));
        }
    }

    #[test]
    fn duplicate_and_cross_catalog_password_identity_ids_fail_closed() {
        let duplicate_id = "duplicate-password-identity-sentinel";
        let duplicate_graph = password_graph(
            vec![
                password_identity(duplicate_id, "first", true),
                password_identity(duplicate_id, "second", false),
            ],
            Vec::new(),
        );
        let cross_id = "cross-catalog-identity-sentinel";
        let cross_graph = password_graph(
            vec![password_identity(cross_id, "password", true)],
            vec![identity(cross_id, "unused-key", false)],
        );

        for (identity_id, graph) in [(duplicate_id, duplicate_graph), (cross_id, cross_graph)] {
            let error = resolve_saved_password_authentication(
                &host("password", json!({"identityId": identity_id})),
                &graph,
            )
            .expect_err("ambiguous identity catalog relationship");
            assert_eq!(error, SavedHostAuthGuardError::AmbiguousIdentityReference);
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains(identity_id));
            assert!(rendered.contains(SAVED_HOST_AUTH_RELATIONSHIP_INVALID));
        }
    }
}
