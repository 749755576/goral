use netcatty_credentials::{EphemeralCredentialReference, StoredCredentialReference};
use netcatty_vault::{
    SavedPasswordIdentityId, SavedProxyConfig, SavedProxyProfile, SavedProxyProfileId,
    SavedProxyProfileUpdate, SavedVaultGraph, SavedVaultInventoryRevision,
};
use serde::{Deserialize, Serialize};

pub(crate) const PROXY_PROFILE_INVALID: &str = "PROXY_PROFILE_INVALID";
pub(crate) const PROXY_PROFILE_NOT_FOUND: &str = "PROXY_PROFILE_NOT_FOUND";
pub(crate) const PROXY_PROFILE_CHANGED: &str = "PROXY_PROFILE_CHANGED";
pub(crate) const PROXY_PROFILE_INVENTORY_CHANGED: &str = "PROXY_PROFILE_INVENTORY_CHANGED";
pub(crate) const PROXY_PROFILE_PUBLICATION_FAILED: &str = "PROXY_PROFILE_PUBLICATION_FAILED";
pub(crate) const PROXY_PROFILE_REPAIR_REQUIRED: &str = "PROXY_PROFILE_REPAIR_REQUIRED";

#[derive(Deserialize)]
#[serde(
    tag = "action",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum ProxyProfileCredentialMutationRequest {
    Keep,
    Remove,
    Replace {
        staged_credential_reference: EphemeralCredentialReference,
    },
}

#[derive(Deserialize)]
#[serde(
    tag = "mode",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum ProxyNetworkAuthRequest {
    Manual {
        #[serde(default)]
        username: String,
        credential_mutation: ProxyProfileCredentialMutationRequest,
    },
    Identity {
        identity_id: String,
    },
}

#[derive(Deserialize)]
#[serde(
    tag = "action",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum ProxyCommandMutationRequest {
    Keep,
    Replace { command: String },
}

#[derive(Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum ProxyProfileConfigRequest {
    Http {
        host: String,
        port: u32,
        auth: ProxyNetworkAuthRequest,
    },
    Socks5 {
        host: String,
        port: u32,
        auth: ProxyNetworkAuthRequest,
    },
    Command {
        command_mutation: ProxyCommandMutationRequest,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProxyProfileMetadataRequest {
    pub(crate) label: String,
    pub(crate) config: ProxyProfileConfigRequest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreateProxyProfileRequest {
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
    pub(crate) metadata: ProxyProfileMetadataRequest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UpdateProxyProfileRequest {
    pub(crate) id: String,
    pub(crate) expected_revision: u64,
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
    pub(crate) metadata: ProxyProfileMetadataRequest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DeleteProxyProfileRequest {
    pub(crate) id: String,
    pub(crate) expected_revision: u64,
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(
    tag = "mode",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum ProxyNetworkAuthView {
    Manual {
        username: String,
        has_saved_credential: bool,
    },
    Identity {
        identity_id: String,
    },
}

/// Renderer-safe effective proxy metadata. The command variant deliberately
/// carries no command body, and no variant can carry an account locator,
/// staged reference, or password.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum ProxyProfileConfigView {
    Http {
        host: String,
        port: u16,
        auth: ProxyNetworkAuthView,
    },
    Socks5 {
        host: String,
        port: u16,
        auth: ProxyNetworkAuthView,
    },
    Command,
}

impl From<&SavedProxyConfig> for ProxyProfileConfigView {
    fn from(config: &SavedProxyConfig) -> Self {
        match config {
            SavedProxyConfig::Http {
                host,
                port,
                identity_id,
                username,
                has_saved_credential,
                ..
            } => Self::Http {
                host: host.clone(),
                port: *port,
                auth: network_auth_view(identity_id.as_ref(), username, *has_saved_credential),
            },
            SavedProxyConfig::Socks5 {
                host,
                port,
                identity_id,
                username,
                has_saved_credential,
                ..
            } => Self::Socks5 {
                host: host.clone(),
                port: *port,
                auth: network_auth_view(identity_id.as_ref(), username, *has_saved_credential),
            },
            SavedProxyConfig::Command { .. } => Self::Command,
        }
    }
}

fn network_auth_view(
    identity_id: Option<&SavedPasswordIdentityId>,
    username: &str,
    has_saved_credential: bool,
) -> ProxyNetworkAuthView {
    match identity_id {
        Some(identity_id) => ProxyNetworkAuthView::Identity {
            identity_id: identity_id.as_str().to_owned(),
        },
        None => ProxyNetworkAuthView::Manual {
            username: username.to_owned(),
            has_saved_credential,
        },
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProxyProfileView {
    id: String,
    revision: u64,
    label: String,
    config: ProxyProfileConfigView,
    created_at: u64,
    updated_at: u64,
}

impl From<&SavedProxyProfile> for ProxyProfileView {
    fn from(profile: &SavedProxyProfile) -> Self {
        Self {
            id: profile.id.as_str().to_owned(),
            revision: profile.revision,
            label: profile.label.clone(),
            config: ProxyProfileConfigView::from(&profile.config),
            created_at: profile.created_at,
            updated_at: profile.updated_at,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProxyProfileCatalog {
    inventory_revision: SavedVaultInventoryRevision,
    profiles: Vec<ProxyProfileView>,
}

impl ProxyProfileCatalog {
    pub(crate) fn from_graph(
        inventory_revision: SavedVaultInventoryRevision,
        graph: &SavedVaultGraph,
    ) -> Self {
        Self {
            inventory_revision,
            profiles: graph
                .proxy_profiles()
                .iter()
                .map(ProxyProfileView::from)
                .collect(),
        }
    }
}

/// Backend-only keyring work for the transaction coordinator. This type has
/// no Serde or value-revealing Debug implementation.
pub(crate) enum PreparedProxyCredentialMutation {
    Keep {
        target: StoredCredentialReference,
    },
    Remove {
        target: StoredCredentialReference,
    },
    Replace {
        target: StoredCredentialReference,
        staged_credential_reference: EphemeralCredentialReference,
    },
}

impl PreparedProxyCredentialMutation {
    pub(crate) fn target(&self) -> &StoredCredentialReference {
        match self {
            Self::Keep { target } | Self::Remove { target } | Self::Replace { target, .. } => {
                target
            }
        }
    }

    pub(crate) fn staged_credential_reference(&self) -> Option<&EphemeralCredentialReference> {
        match self {
            Self::Replace {
                staged_credential_reference,
                ..
            } => Some(staged_credential_reference),
            Self::Keep { .. } | Self::Remove { .. } => None,
        }
    }

    pub(crate) const fn keeps_existing(&self) -> bool {
        matches!(self, Self::Keep { .. })
    }

    pub(crate) const fn removes_existing(&self) -> bool {
        matches!(self, Self::Remove { .. })
    }

    pub(crate) const fn replaces_existing(&self) -> bool {
        matches!(self, Self::Replace { .. })
    }
}

pub(crate) struct PreparedProxyProfileMutation {
    expected_inventory_revision: SavedVaultInventoryRevision,
    target_graph: SavedVaultGraph,
    profile: SavedProxyProfile,
    credential: PreparedProxyCredentialMutation,
}

impl PreparedProxyProfileMutation {
    pub(crate) fn expected_inventory_revision(&self) -> &SavedVaultInventoryRevision {
        &self.expected_inventory_revision
    }

    pub(crate) fn target_graph(&self) -> &SavedVaultGraph {
        &self.target_graph
    }

    pub(crate) fn profile(&self) -> &SavedProxyProfile {
        &self.profile
    }

    pub(crate) fn credential(&self) -> &PreparedProxyCredentialMutation {
        &self.credential
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        SavedVaultInventoryRevision,
        SavedVaultGraph,
        SavedProxyProfile,
        PreparedProxyCredentialMutation,
    ) {
        (
            self.expected_inventory_revision,
            self.target_graph,
            self.profile,
            self.credential,
        )
    }
}

pub(crate) struct PreparedProxyProfileDeletion {
    expected_inventory_revision: SavedVaultInventoryRevision,
    target_graph: SavedVaultGraph,
    profile_id: SavedProxyProfileId,
    credential: PreparedProxyCredentialMutation,
}

impl PreparedProxyProfileDeletion {
    pub(crate) fn expected_inventory_revision(&self) -> &SavedVaultInventoryRevision {
        &self.expected_inventory_revision
    }

    pub(crate) fn target_graph(&self) -> &SavedVaultGraph {
        &self.target_graph
    }

    pub(crate) fn profile_id(&self) -> &SavedProxyProfileId {
        &self.profile_id
    }

    pub(crate) fn credential(&self) -> &PreparedProxyCredentialMutation {
        &self.credential
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        SavedVaultInventoryRevision,
        SavedVaultGraph,
        SavedProxyProfileId,
        PreparedProxyCredentialMutation,
    ) {
        (
            self.expected_inventory_revision,
            self.target_graph,
            self.profile_id,
            self.credential,
        )
    }
}

pub(crate) fn prepare_proxy_profile_creation(
    graph: SavedVaultGraph,
    request: CreateProxyProfileRequest,
    id: SavedProxyProfileId,
    now: u64,
) -> Result<PreparedProxyProfileMutation, String> {
    ensure_profile_id_available(&graph, &id)?;
    let CreateProxyProfileRequest {
        expected_inventory_revision,
        metadata,
    } = request;
    let target = proxy_credential_reference(&id)?;
    let (config, credential) = prepare_config(&graph, metadata.config, None, target)?;
    let profile =
        SavedProxyProfile::from_parts(id, 1, metadata.label, config, now, now, Default::default())
            .map_err(|_| proxy_profile_invalid())?;
    let target_graph = graph_with_profile(graph, profile.clone(), false)?;
    Ok(PreparedProxyProfileMutation {
        expected_inventory_revision,
        target_graph,
        profile,
        credential,
    })
}

pub(crate) fn prepare_proxy_profile_update(
    graph: SavedVaultGraph,
    request: UpdateProxyProfileRequest,
    now: u64,
) -> Result<PreparedProxyProfileMutation, String> {
    let UpdateProxyProfileRequest {
        id,
        expected_revision,
        expected_inventory_revision,
        metadata,
    } = request;
    let id = parse_profile_id(id)?;
    let current = graph
        .proxy_profiles()
        .iter()
        .find(|profile| profile.id == id)
        .cloned()
        .ok_or_else(proxy_profile_not_found)?;
    ensure_expected_revision(&current, expected_revision)?;
    let target = proxy_credential_reference(&id)?;
    let (config, credential) =
        prepare_config(&graph, metadata.config, Some(&current.config), target)?;
    let config = preserve_config_compatibility(config, &current.config)?;
    let mut update = SavedProxyProfileUpdate::default();
    update.label = Some(metadata.label);
    update.config = Some(config);
    let profile = current
        .apply_update(update, now)
        .map_err(|_| proxy_profile_invalid())?;
    let target_graph = graph_with_profile(graph, profile.clone(), true)?;
    Ok(PreparedProxyProfileMutation {
        expected_inventory_revision,
        target_graph,
        profile,
        credential,
    })
}

pub(crate) fn prepare_proxy_profile_deletion(
    graph: SavedVaultGraph,
    request: DeleteProxyProfileRequest,
    now: u64,
) -> Result<PreparedProxyProfileDeletion, String> {
    let DeleteProxyProfileRequest {
        id,
        expected_revision,
        expected_inventory_revision,
    } = request;
    let id = parse_profile_id(id)?;
    let current = graph
        .proxy_profiles()
        .iter()
        .find(|profile| profile.id == id)
        .ok_or_else(proxy_profile_not_found)?;
    ensure_expected_revision(current, expected_revision)?;
    let target = proxy_credential_reference(&id)?;

    let (
        mut hosts,
        references,
        managed_keys,
        identities,
        password_identities,
        mut proxy_profiles,
        groups,
        custom_groups,
        notes_snippets,
        port_forward_rules,
    ) = graph.into_current_parts();
    for host in &mut hosts {
        let referenced = host
            .proxy_profile_id()
            .map_err(|_| proxy_profile_repair_required())?;
        if referenced.as_ref() == Some(&id) {
            *host = host
                .apply_update(
                    netcatty_vault::SavedHostUpdate::default().clear_proxy_profile_id(),
                    now,
                )
                .map_err(|_| proxy_profile_repair_required())?;
        }
    }
    proxy_profiles.retain(|profile| profile.id != id);
    let target_graph = SavedVaultGraph::new_with_port_forward_rules(
        hosts,
        references,
        managed_keys,
        identities,
        password_identities,
        proxy_profiles,
        groups,
        notes_snippets,
        port_forward_rules,
    )
    .with_group_catalog(custom_groups);
    Ok(PreparedProxyProfileDeletion {
        expected_inventory_revision,
        target_graph,
        profile_id: id,
        // Deletion always removes the deterministic account. A false hint is
        // not evidence that a stale keyring record is absent.
        credential: PreparedProxyCredentialMutation::Remove { target },
    })
}

fn prepare_config(
    graph: &SavedVaultGraph,
    request: ProxyProfileConfigRequest,
    current: Option<&SavedProxyConfig>,
    target: StoredCredentialReference,
) -> Result<(SavedProxyConfig, PreparedProxyCredentialMutation), String> {
    match request {
        ProxyProfileConfigRequest::Http { host, port, auth } => {
            prepare_network_config(graph, true, host, port, auth, current, target)
        }
        ProxyProfileConfigRequest::Socks5 { host, port, auth } => {
            prepare_network_config(graph, false, host, port, auth, current, target)
        }
        ProxyProfileConfigRequest::Command { command_mutation } => {
            let command = match command_mutation {
                ProxyCommandMutationRequest::Keep => match current {
                    Some(SavedProxyConfig::Command { command, .. }) => command.clone(),
                    Some(SavedProxyConfig::Http { .. })
                    | Some(SavedProxyConfig::Socks5 { .. })
                    | None => return Err(proxy_profile_invalid()),
                },
                ProxyCommandMutationRequest::Replace { command } => command,
            };
            let config = SavedProxyConfig::command(command).map_err(|_| proxy_profile_invalid())?;
            let credential = automatic_non_manual_mutation(current, target);
            Ok((config, credential))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare_network_config(
    graph: &SavedVaultGraph,
    http: bool,
    host: String,
    port: u32,
    auth: ProxyNetworkAuthRequest,
    current: Option<&SavedProxyConfig>,
    target: StoredCredentialReference,
) -> Result<(SavedProxyConfig, PreparedProxyCredentialMutation), String> {
    match auth {
        ProxyNetworkAuthRequest::Manual {
            username,
            credential_mutation,
        } => {
            let (has_saved_credential, credential) = match credential_mutation {
                ProxyProfileCredentialMutationRequest::Keep => (
                    current.and_then(manual_credential_hint).unwrap_or(false),
                    PreparedProxyCredentialMutation::Keep { target },
                ),
                ProxyProfileCredentialMutationRequest::Remove => {
                    (false, PreparedProxyCredentialMutation::Remove { target })
                }
                ProxyProfileCredentialMutationRequest::Replace {
                    staged_credential_reference,
                } => (
                    true,
                    PreparedProxyCredentialMutation::Replace {
                        target,
                        staged_credential_reference,
                    },
                ),
            };
            let config = if http {
                SavedProxyConfig::http(host, port, None, username, false)
            } else {
                SavedProxyConfig::socks5(host, port, None, username, false)
            }
            .and_then(|config| config.with_saved_credential_hint(has_saved_credential))
            .map_err(|_| proxy_profile_invalid())?;
            Ok((config, credential))
        }
        ProxyNetworkAuthRequest::Identity { identity_id } => {
            let identity_id = SavedPasswordIdentityId::from_opaque(identity_id)
                .map_err(|_| proxy_profile_invalid())?;
            ensure_password_identity_available(graph, &identity_id)?;
            let config = if http {
                SavedProxyConfig::http(host, port, Some(identity_id), "", false)
            } else {
                SavedProxyConfig::socks5(host, port, Some(identity_id), "", false)
            }
            .map_err(|_| proxy_profile_invalid())?;
            let credential = automatic_non_manual_mutation(current, target);
            Ok((config, credential))
        }
    }
}

fn automatic_non_manual_mutation(
    current: Option<&SavedProxyConfig>,
    target: StoredCredentialReference,
) -> PreparedProxyCredentialMutation {
    if current.is_none() || current.is_some_and(is_manual_network_config) {
        PreparedProxyCredentialMutation::Remove { target }
    } else {
        PreparedProxyCredentialMutation::Keep { target }
    }
}

fn is_manual_network_config(config: &SavedProxyConfig) -> bool {
    matches!(
        config,
        SavedProxyConfig::Http {
            identity_id: None,
            ..
        } | SavedProxyConfig::Socks5 {
            identity_id: None,
            ..
        }
    )
}

fn manual_credential_hint(config: &SavedProxyConfig) -> Option<bool> {
    match config {
        SavedProxyConfig::Http {
            identity_id: None,
            has_saved_credential,
            ..
        }
        | SavedProxyConfig::Socks5 {
            identity_id: None,
            has_saved_credential,
            ..
        } => Some(*has_saved_credential),
        SavedProxyConfig::Http { .. }
        | SavedProxyConfig::Socks5 { .. }
        | SavedProxyConfig::Command { .. } => None,
    }
}

fn preserve_config_compatibility(
    mut next: SavedProxyConfig,
    current: &SavedProxyConfig,
) -> Result<SavedProxyConfig, String> {
    for (key, value) in current.compatibility_fields() {
        next = next
            .with_compatibility_field(key.clone(), value.clone())
            .map_err(|_| proxy_profile_repair_required())?;
    }
    Ok(next)
}

fn ensure_password_identity_available(
    graph: &SavedVaultGraph,
    id: &SavedPasswordIdentityId,
) -> Result<(), String> {
    if graph
        .password_identities()
        .iter()
        .any(|identity| &identity.id == id)
        && !graph
            .identity_references()
            .iter()
            .any(|identity| identity.id.as_str() == id.as_str())
    {
        Ok(())
    } else {
        Err(proxy_profile_invalid())
    }
}

fn ensure_profile_id_available(
    graph: &SavedVaultGraph,
    id: &SavedProxyProfileId,
) -> Result<(), String> {
    if graph
        .proxy_profiles()
        .iter()
        .any(|profile| &profile.id == id)
    {
        Err(proxy_profile_invalid())
    } else {
        Ok(())
    }
}

fn ensure_expected_revision(
    profile: &SavedProxyProfile,
    expected_revision: u64,
) -> Result<(), String> {
    if expected_revision == 0 || profile.revision != expected_revision {
        Err(proxy_profile_changed())
    } else {
        Ok(())
    }
}

fn graph_with_profile(
    graph: SavedVaultGraph,
    profile: SavedProxyProfile,
    replace: bool,
) -> Result<SavedVaultGraph, String> {
    let (
        hosts,
        references,
        managed_keys,
        identities,
        password_identities,
        mut proxy_profiles,
        groups,
        custom_groups,
        notes_snippets,
        port_forward_rules,
    ) = graph.into_current_parts();
    if replace {
        let Some(index) = proxy_profiles
            .iter()
            .position(|current| current.id == profile.id)
        else {
            return Err(proxy_profile_not_found());
        };
        proxy_profiles[index] = profile;
    } else {
        proxy_profiles.push(profile);
    }
    Ok(SavedVaultGraph::new_with_port_forward_rules(
        hosts,
        references,
        managed_keys,
        identities,
        password_identities,
        proxy_profiles,
        groups,
        notes_snippets,
        port_forward_rules,
    )
    .with_group_catalog(custom_groups))
}

fn parse_profile_id(id: String) -> Result<SavedProxyProfileId, String> {
    SavedProxyProfileId::from_opaque(id).map_err(|_| proxy_profile_invalid())
}

fn proxy_credential_reference(
    id: &SavedProxyProfileId,
) -> Result<StoredCredentialReference, String> {
    StoredCredentialReference::for_saved_proxy_profile(id.as_str())
        .map_err(|_| proxy_profile_repair_required())
}

pub(crate) fn proxy_profile_error(code: &str, message: &str) -> String {
    format!("{code}: {message}")
}

pub(crate) fn proxy_profile_invalid() -> String {
    proxy_profile_error(
        PROXY_PROFILE_INVALID,
        "The proxy profile request is invalid",
    )
}

pub(crate) fn proxy_profile_not_found() -> String {
    proxy_profile_error(PROXY_PROFILE_NOT_FOUND, "The proxy profile was not found")
}

pub(crate) fn proxy_profile_changed() -> String {
    proxy_profile_error(
        PROXY_PROFILE_CHANGED,
        "The proxy profile changed; refresh and retry",
    )
}

pub(crate) fn proxy_profile_inventory_changed() -> String {
    proxy_profile_error(
        PROXY_PROFILE_INVENTORY_CHANGED,
        "The proxy profile catalog changed; refresh and retry",
    )
}

pub(crate) fn proxy_profile_publication_failed() -> String {
    proxy_profile_error(
        PROXY_PROFILE_PUBLICATION_FAILED,
        "The proxy profile update could not be published",
    )
}

pub(crate) fn proxy_profile_repair_required() -> String {
    proxy_profile_error(
        PROXY_PROFILE_REPAIR_REQUIRED,
        "Proxy profile storage requires repair",
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use netcatty_credentials::{EphemeralCredentialReference, StoredCredentialReference};
    use netcatty_vault::{
        SavedHost, SavedHostDraft, SavedIdentityReference, SavedIdentityReferenceId,
        SavedManagedSshKey, SavedNotesSnippetsCatalog, SavedPasswordIdentity,
        SavedPasswordIdentityId, SavedPortForwardKind, SavedPortForwardRule, SavedProxyConfig,
        SavedProxyProfile, SavedProxyProfileId, SavedSecretObjectLocator, SavedSshKeyCategory,
        SavedSshKeyCustodyReference, SavedSshKeyReference, SavedSshKeyReferenceId,
        SavedSshKeySource, SavedVaultGraph, SavedVaultInventoryRevision,
    };
    use serde_json::json;

    use super::{
        CreateProxyProfileRequest, DeleteProxyProfileRequest, PROXY_PROFILE_CHANGED,
        PROXY_PROFILE_INVALID, PROXY_PROFILE_NOT_FOUND, ProxyCommandMutationRequest,
        ProxyNetworkAuthRequest, ProxyProfileCatalog, ProxyProfileConfigRequest,
        ProxyProfileCredentialMutationRequest, ProxyProfileMetadataRequest, ProxyProfileView,
        UpdateProxyProfileRequest, prepare_proxy_profile_creation, prepare_proxy_profile_deletion,
        prepare_proxy_profile_update,
    };

    fn inventory_revision() -> SavedVaultInventoryRevision {
        serde_json::from_value(json!({
            "storeId": "proxy-profile-test-store",
            "loadedGeneration": 9,
            "maxSeenGeneration": 9,
            "seal": "00"
        }))
        .expect("inventory revision")
    }

    fn manual_http(action: ProxyProfileCredentialMutationRequest) -> ProxyProfileMetadataRequest {
        ProxyProfileMetadataRequest {
            label: "  Office proxy  ".to_owned(),
            config: ProxyProfileConfigRequest::Http {
                host: " proxy.example.com ".to_owned(),
                port: 3128,
                auth: ProxyNetworkAuthRequest::Manual {
                    username: " proxy-user ".to_owned(),
                    credential_mutation: action,
                },
            },
        }
    }

    fn create_request(metadata: ProxyProfileMetadataRequest) -> CreateProxyProfileRequest {
        CreateProxyProfileRequest {
            expected_inventory_revision: inventory_revision(),
            metadata,
        }
    }

    fn profile(id: &str, config: SavedProxyConfig) -> SavedProxyProfile {
        SavedProxyProfile::from_parts(
            SavedProxyProfileId::from_opaque(id).expect("profile ID"),
            3,
            "Existing proxy",
            config,
            10,
            20,
            BTreeMap::from([("order".to_owned(), json!(4))]),
        )
        .expect("profile")
    }

    fn password_identity(id: &str) -> SavedPasswordIdentity {
        SavedPasswordIdentity::from_parts(
            SavedPasswordIdentityId::from_opaque(id).expect("identity ID"),
            1,
            "Proxy identity",
            "identity-user",
            true,
            1,
            1,
            BTreeMap::new(),
        )
        .expect("password identity")
    }

    fn preserved_catalogs() -> (
        SavedSshKeyReference,
        SavedManagedSshKey,
        SavedIdentityReference,
        SavedPasswordIdentity,
    ) {
        let key = SavedSshKeyReference::from_parts(
            SavedSshKeyReferenceId::from_opaque("preserved-reference").expect("key ID"),
            "Reference",
            "D:\\keys\\reference",
            SavedSshKeyCategory::key(),
            1,
            1,
            BTreeMap::new(),
        )
        .expect("key");
        let managed = SavedManagedSshKey::from_parts(
            SavedSshKeyReferenceId::from_opaque("preserved-managed").expect("managed ID"),
            "Managed",
            SavedSshKeyCategory::key(),
            SavedSshKeySource::generated(),
            false,
            1,
            1,
            SavedSshKeyCustodyReference::new(
                SavedSecretObjectLocator::from_hex("ab".repeat(32)).expect("locator"),
                1,
            )
            .expect("custody"),
            BTreeMap::new(),
        )
        .expect("managed");
        let identity = SavedIdentityReference::from_parts(
            SavedIdentityReferenceId::from_opaque("preserved-key-identity").expect("identity ID"),
            "Key identity",
            "key-user",
            key.id.clone(),
            1,
            1,
            BTreeMap::new(),
        )
        .expect("key identity");
        let password = password_identity("preserved-password-identity");
        (key, managed, identity, password)
    }

    fn graph_with_profile(profile: SavedProxyProfile) -> SavedVaultGraph {
        let host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("proxy-catalog-forward.example.com", "alice"),
            1,
        )
        .expect("port-forward host");
        let notes_snippets = SavedNotesSnippetsCatalog::from_parts(
            Some(Vec::new()),
            Some(vec!["preserved-package".to_owned()]),
            Some(Vec::new()),
            Some(vec!["Preserved/Notes".to_owned()]),
        )
        .expect("notes/snippets catalog");
        let port_forward = SavedPortForwardRule::new(
            "preserved-proxy-forward",
            "Preserved proxy forward",
            SavedPortForwardKind::Dynamic,
            1080,
            "127.0.0.1",
            None,
            None,
            host.id.as_str(),
            false,
            1,
            None,
            Some(0),
        )
        .expect("port-forward rule");
        SavedVaultGraph::new_with_port_forward_rules(
            vec![host],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![profile],
            Vec::new(),
            notes_snippets,
            vec![port_forward],
        )
    }

    #[test]
    fn manual_creation_derives_hint_target_and_preserves_complete_inventory() {
        let staged = EphemeralCredentialReference::new();
        let id = SavedProxyProfileId::from_opaque("new-proxy-profile").expect("ID");
        let (key, managed, key_identity, password_identity) = preserved_catalogs();
        let host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("creation-forward.example.com", "alice"),
            1,
        )
        .expect("port-forward host");
        let notes_snippets = SavedNotesSnippetsCatalog::from_parts(
            Some(Vec::new()),
            Some(vec!["creation-package".to_owned()]),
            Some(Vec::new()),
            Some(vec!["Creation/Notes".to_owned()]),
        )
        .expect("notes/snippets catalog");
        let port_forward = SavedPortForwardRule::new(
            "creation-proxy-forward",
            "Creation proxy forward",
            SavedPortForwardKind::Dynamic,
            1081,
            "127.0.0.1",
            None,
            None,
            host.id.as_str(),
            false,
            1,
            None,
            Some(0),
        )
        .expect("port-forward rule");
        let graph = SavedVaultGraph::new_with_port_forward_rules(
            vec![host],
            vec![key.clone()],
            vec![managed.clone()],
            vec![key_identity.clone()],
            vec![password_identity.clone()],
            Vec::new(),
            Vec::new(),
            notes_snippets.clone(),
            vec![port_forward.clone()],
        );
        let prepared = prepare_proxy_profile_creation(
            graph,
            create_request(manual_http(
                ProxyProfileCredentialMutationRequest::Replace {
                    staged_credential_reference: staged,
                },
            )),
            id.clone(),
            30,
        )
        .expect("creation plan");

        assert_eq!(prepared.profile().id, id);
        assert_eq!(prepared.profile().revision, 1);
        assert_eq!(prepared.profile().label, "Office proxy");
        assert!(prepared.credential().replaces_existing());
        assert_eq!(
            prepared.credential().staged_credential_reference(),
            Some(&staged)
        );
        assert_eq!(
            prepared.credential().target(),
            &StoredCredentialReference::for_saved_proxy_profile(id.as_str()).expect("target")
        );
        assert_eq!(
            prepared.target_graph().ssh_key_references(),
            std::slice::from_ref(&key)
        );
        assert_eq!(
            prepared.target_graph().managed_ssh_keys(),
            std::slice::from_ref(&managed)
        );
        assert_eq!(
            prepared.target_graph().identity_references(),
            std::slice::from_ref(&key_identity)
        );
        assert_eq!(
            prepared.target_graph().password_identities(),
            std::slice::from_ref(&password_identity)
        );
        assert_eq!(prepared.target_graph().notes_snippets(), &notes_snippets);
        assert_eq!(
            prepared.target_graph().port_forward_rules(),
            std::slice::from_ref(&port_forward)
        );
        assert_eq!(
            prepared.expected_inventory_revision(),
            &inventory_revision()
        );
        match &prepared.profile().config {
            SavedProxyConfig::Http {
                host,
                username,
                has_saved_credential,
                ..
            } => {
                assert_eq!(host, "proxy.example.com");
                assert_eq!(username, "proxy-user");
                assert!(*has_saved_credential);
            }
            _ => panic!("expected HTTP config"),
        }
    }

    #[test]
    fn update_actions_and_identity_auth_are_mutually_exclusive() {
        let current = profile(
            "updated-proxy",
            SavedProxyConfig::http("old.proxy", 8080, None, "old-user", false)
                .and_then(|config| config.with_saved_credential_hint(true))
                .expect("manual proxy")
                .with_compatibility_field("futureMode", json!({"enabled": true}))
                .expect("compatibility"),
        );
        let keep = prepare_proxy_profile_update(
            graph_with_profile(current.clone()),
            UpdateProxyProfileRequest {
                id: current.id.as_str().to_owned(),
                expected_revision: current.revision,
                expected_inventory_revision: inventory_revision(),
                metadata: manual_http(ProxyProfileCredentialMutationRequest::Keep),
            },
            30,
        )
        .expect("keep update");
        assert!(keep.credential().keeps_existing());
        assert_eq!(keep.profile().revision, 4);
        assert_eq!(
            keep.target_graph().notes_snippets().snippet_packages(),
            Some(&["preserved-package".to_owned()][..])
        );
        assert_eq!(keep.target_graph().port_forward_rules().len(), 1);
        assert_eq!(
            keep.profile().config.compatibility_fields()["futureMode"],
            json!({"enabled": true})
        );
        assert!(matches!(
            &keep.profile().config,
            SavedProxyConfig::Http {
                has_saved_credential: true,
                ..
            }
        ));

        let login = password_identity("selected-proxy-identity");
        let graph = SavedVaultGraph::new_with_proxy_profiles(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![login.clone()],
            vec![current.clone()],
            Vec::new(),
        );
        let identity_update = prepare_proxy_profile_update(
            graph,
            UpdateProxyProfileRequest {
                id: current.id.as_str().to_owned(),
                expected_revision: current.revision,
                expected_inventory_revision: inventory_revision(),
                metadata: ProxyProfileMetadataRequest {
                    label: "Identity proxy".to_owned(),
                    config: ProxyProfileConfigRequest::Socks5 {
                        host: "identity.proxy".to_owned(),
                        port: 1080,
                        auth: ProxyNetworkAuthRequest::Identity {
                            identity_id: login.id.as_str().to_owned(),
                        },
                    },
                },
            },
            31,
        )
        .expect("identity update");
        assert!(identity_update.credential().removes_existing());
        assert_eq!(
            identity_update.profile().config.identity_id(),
            Some(&login.id)
        );

        let staged = EphemeralCredentialReference::new();
        let invalid_identity_auth = json!({
            "type": "http",
            "host": "proxy",
            "port": 80,
            "auth": {
                "mode": "identity",
                "identityId": "selected-proxy-identity",
                "credentialMutation": {
                    "action": "replace",
                    "stagedCredentialReference": staged
                }
            }
        });
        assert!(
            serde_json::from_value::<ProxyProfileConfigRequest>(invalid_identity_auth).is_err()
        );
    }

    #[test]
    fn command_views_never_return_command_or_backend_references() {
        let command_marker = "command-body-marker --connect %h:%p";
        let profile = profile(
            "command-profile",
            SavedProxyConfig::command(command_marker).expect("command"),
        );
        let catalog = ProxyProfileCatalog::from_graph(
            inventory_revision(),
            &graph_with_profile(profile.clone()),
        );
        let encoded = serde_json::to_string(&catalog).expect("catalog JSON");
        assert!(encoded.contains("inventoryRevision"));
        assert!(encoded.contains("revision"));
        assert!(encoded.contains("\"type\":\"command\""));
        assert!(!encoded.contains(command_marker));
        assert!(!encoded.contains("command-body-marker"));
        assert!(!encoded.contains("credentialReference"));
        assert!(!encoded.contains("account"));

        let view = serde_json::to_value(ProxyProfileView::from(&profile)).expect("view JSON");
        assert_eq!(view["config"], json!({"type": "command"}));
    }

    #[test]
    fn command_keep_preserves_hidden_body_only_for_an_existing_command() {
        let current = profile(
            "kept-command-profile",
            SavedProxyConfig::command("hidden-command-marker --connect %h:%p").expect("command"),
        );
        let kept = prepare_proxy_profile_update(
            graph_with_profile(current.clone()),
            UpdateProxyProfileRequest {
                id: current.id.as_str().to_owned(),
                expected_revision: current.revision,
                expected_inventory_revision: inventory_revision(),
                metadata: ProxyProfileMetadataRequest {
                    label: "Kept command".to_owned(),
                    config: ProxyProfileConfigRequest::Command {
                        command_mutation: ProxyCommandMutationRequest::Keep,
                    },
                },
            },
            31,
        )
        .expect("keep hidden command");
        assert_eq!(kept.profile().config, current.config);

        let create_with_keep = prepare_proxy_profile_creation(
            SavedVaultGraph::default(),
            create_request(ProxyProfileMetadataRequest {
                label: "Invalid keep".to_owned(),
                config: ProxyProfileConfigRequest::Command {
                    command_mutation: ProxyCommandMutationRequest::Keep,
                },
            }),
            SavedProxyProfileId::from_opaque("invalid-command-keep").expect("ID"),
            1,
        )
        .err()
        .expect("create keep must fail");
        assert!(create_with_keep.starts_with(PROXY_PROFILE_INVALID));
        assert!(!create_with_keep.contains("hidden-command-marker"));
    }

    #[test]
    fn deletion_clears_every_host_profile_reference_and_preserves_inline_and_catalogs() {
        let removed = profile(
            "removed-profile",
            SavedProxyConfig::http("removed.proxy", 8080, None, "user", false)
                .expect("removed config"),
        );
        let preserved = profile(
            "preserved-profile",
            SavedProxyConfig::command("preserved command body").expect("preserved config"),
        );
        let referenced = SavedHost::from_draft(
            SavedHostDraft::ssh_password("referenced.example.com", "host-user")
                .with_proxy_profile_id(removed.id.clone())
                .expect("profile binding"),
            1,
        )
        .expect("referenced host");
        let inline = SavedProxyConfig::socks5("inline.proxy", 1080, None, "inline-user", false)
            .expect("inline config");
        let shadowed = SavedHost::from_draft(
            SavedHostDraft::ssh_password("shadowed.example.com", "host-user")
                .with_proxy_profile_id(removed.id.clone())
                .expect("profile binding")
                .with_proxy_config(inline.clone())
                .expect("inline proxy"),
            1,
        )
        .expect("shadowed host");
        let unrelated = SavedHost::from_draft(
            SavedHostDraft::ssh_password("unrelated.example.com", "host-user")
                .with_proxy_profile_id(preserved.id.clone())
                .expect("profile binding"),
            1,
        )
        .expect("unrelated host");
        let (key, managed, key_identity, password_identity) = preserved_catalogs();
        let notes_snippets = SavedNotesSnippetsCatalog::from_parts(
            Some(Vec::new()),
            Some(vec!["deletion-package".to_owned()]),
            Some(Vec::new()),
            Some(vec!["Deletion/Notes".to_owned()]),
        )
        .expect("notes/snippets catalog");
        let port_forward = SavedPortForwardRule::new(
            "deletion-proxy-forward",
            "Deletion proxy forward",
            SavedPortForwardKind::Local,
            15432,
            "127.0.0.1",
            Some("database.internal".to_owned()),
            Some(5432),
            unrelated.id.as_str(),
            false,
            1,
            None,
            Some(0),
        )
        .expect("port-forward rule");
        let graph = SavedVaultGraph::new_with_port_forward_rules(
            vec![referenced.clone(), shadowed.clone(), unrelated.clone()],
            vec![key.clone()],
            vec![managed.clone()],
            vec![key_identity.clone()],
            vec![password_identity.clone()],
            vec![removed.clone(), preserved.clone()],
            Vec::new(),
            notes_snippets.clone(),
            vec![port_forward.clone()],
        );
        let prepared = prepare_proxy_profile_deletion(
            graph,
            DeleteProxyProfileRequest {
                id: removed.id.as_str().to_owned(),
                expected_revision: removed.revision,
                expected_inventory_revision: inventory_revision(),
            },
            40,
        )
        .expect("delete plan");

        assert_eq!(prepared.profile_id(), &removed.id);
        assert!(prepared.credential().removes_existing());
        assert_eq!(
            prepared.credential().target(),
            &StoredCredentialReference::for_saved_proxy_profile(removed.id.as_str())
                .expect("target")
        );
        assert_eq!(
            prepared.target_graph().proxy_profiles(),
            std::slice::from_ref(&preserved)
        );
        let hosts = prepared.target_graph().hosts();
        let cleared = hosts
            .iter()
            .find(|host| host.id == referenced.id)
            .expect("cleared host");
        assert_eq!(cleared.proxy_profile_id().expect("profile ID"), None);
        assert_eq!(cleared.revision, referenced.revision + 1);
        let inline_preserved = hosts
            .iter()
            .find(|host| host.id == shadowed.id)
            .expect("inline host");
        assert_eq!(
            inline_preserved.proxy_config().expect("inline config"),
            Some(inline)
        );
        assert_eq!(
            inline_preserved.proxy_profile_id().expect("profile ID"),
            None
        );
        let unrelated_preserved = hosts
            .iter()
            .find(|host| host.id == unrelated.id)
            .expect("unrelated host");
        assert_eq!(unrelated_preserved, &unrelated);
        assert_eq!(
            prepared.target_graph().ssh_key_references(),
            std::slice::from_ref(&key)
        );
        assert_eq!(
            prepared.target_graph().managed_ssh_keys(),
            std::slice::from_ref(&managed)
        );
        assert_eq!(
            prepared.target_graph().identity_references(),
            std::slice::from_ref(&key_identity)
        );
        assert_eq!(
            prepared.target_graph().password_identities(),
            std::slice::from_ref(&password_identity)
        );
        assert_eq!(prepared.target_graph().notes_snippets(), &notes_snippets);
        assert_eq!(
            prepared.target_graph().port_forward_rules(),
            std::slice::from_ref(&port_forward)
        );
        assert_eq!(
            prepared.expected_inventory_revision(),
            &inventory_revision()
        );
    }

    #[test]
    fn fixed_errors_never_echo_ids_commands_staged_references_or_accounts() {
        let current = profile(
            "sensitive-profile-id",
            SavedProxyConfig::command("sensitive-command-marker").expect("command"),
        );
        let stale = prepare_proxy_profile_update(
            graph_with_profile(current.clone()),
            UpdateProxyProfileRequest {
                id: current.id.as_str().to_owned(),
                expected_revision: current.revision - 1,
                expected_inventory_revision: inventory_revision(),
                metadata: ProxyProfileMetadataRequest {
                    label: "Updated".to_owned(),
                    config: ProxyProfileConfigRequest::Command {
                        command_mutation: ProxyCommandMutationRequest::Replace {
                            command: "new-sensitive-command-marker".to_owned(),
                        },
                    },
                },
            },
            30,
        )
        .err()
        .expect("stale update");
        assert!(stale.starts_with(PROXY_PROFILE_CHANGED));

        let invalid_id = "invalid-profile-id\nmarker";
        let invalid = prepare_proxy_profile_update(
            SavedVaultGraph::default(),
            UpdateProxyProfileRequest {
                id: invalid_id.to_owned(),
                expected_revision: 1,
                expected_inventory_revision: inventory_revision(),
                metadata: manual_http(ProxyProfileCredentialMutationRequest::Keep),
            },
            1,
        )
        .err()
        .expect("invalid ID");
        assert!(invalid.starts_with(PROXY_PROFILE_INVALID));

        let missing_id = "missing-profile-marker";
        let missing = prepare_proxy_profile_update(
            SavedVaultGraph::default(),
            UpdateProxyProfileRequest {
                id: missing_id.to_owned(),
                expected_revision: 1,
                expected_inventory_revision: inventory_revision(),
                metadata: manual_http(ProxyProfileCredentialMutationRequest::Keep),
            },
            1,
        )
        .err()
        .expect("missing ID");
        assert!(missing.starts_with(PROXY_PROFILE_NOT_FOUND));

        for error in [stale, invalid, missing] {
            for forbidden in [
                current.id.as_str(),
                invalid_id,
                missing_id,
                "sensitive-command-marker",
                "new-sensitive-command-marker",
            ] {
                assert!(!error.contains(forbidden));
            }
        }
    }
}
