use netcatty_credentials::{EphemeralCredentialReference, StoredCredentialReference};
use netcatty_vault::{
    SavedGroupConfig, SavedGroupConfigUpdate, SavedGroupCredentialOverride, SavedGroupDefaults,
    SavedGroupId, SavedGroupIdentityReference, SavedGroupOverride, SavedGroupPath,
    SavedGroupProxyOverride, SavedProxyConfig, SavedVaultGraph, SavedVaultInventoryRevision,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub(crate) const GROUP_CONFIG_INVALID: &str = "GROUP_CONFIG_INVALID";
pub(crate) const GROUP_CONFIG_NOT_FOUND: &str = "GROUP_CONFIG_NOT_FOUND";
pub(crate) const GROUP_CONFIG_CHANGED: &str = "GROUP_CONFIG_CHANGED";
pub(crate) const GROUP_CONFIG_INVENTORY_CHANGED: &str = "GROUP_CONFIG_INVENTORY_CHANGED";
pub(crate) const GROUP_CONFIG_PUBLICATION_FAILED: &str = "GROUP_CONFIG_PUBLICATION_FAILED";
pub(crate) const GROUP_CONFIG_REPAIR_REQUIRED: &str = "GROUP_CONFIG_REPAIR_REQUIRED";
const HIDDEN_PROXY_COMMAND_PLACEHOLDER: &str = "netcatty-hidden-proxy-command";

/// Group defaults accepted from ordinary renderer JSON.
///
/// The underlying Vault model can deserialize backend-derived credential
/// hints for snapshot compatibility. This request boundary deliberately
/// rejects those hints: only the planner can copy one from the current record
/// after an explicit `Keep` action.
#[derive(Clone)]
pub(crate) struct GroupDefaultsRequest {
    defaults: SavedGroupDefaults,
    has_hidden_proxy_command: bool,
}

impl<'de> Deserialize<'de> for GroupDefaultsRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut value = serde_json::Value::deserialize(deserializer)?;
        ensure_renderer_credential_wire_is_metadata_only(&value)
            .map_err(serde::de::Error::custom)?;
        let has_hidden_proxy_command =
            prepare_renderer_proxy_wire(&mut value).map_err(serde::de::Error::custom)?;
        let defaults: SavedGroupDefaults = serde_json::from_value(value)
            .map_err(|_| serde::de::Error::custom("invalid group defaults"))?;
        ensure_renderer_defaults_are_hint_free(&defaults).map_err(serde::de::Error::custom)?;
        Ok(Self {
            defaults,
            has_hidden_proxy_command,
        })
    }
}

#[derive(Clone, Deserialize)]
#[serde(
    tag = "action",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum GroupProxyCommandMutationRequest {
    Keep,
    Replace { command: String },
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum GroupCredentialHintActionRequest {
    #[default]
    UseMetadata,
    Keep,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GroupCredentialHintActionsRequest {
    ssh_password: GroupCredentialHintActionRequest,
    telnet_password: GroupCredentialHintActionRequest,
    proxy_password: GroupCredentialHintActionRequest,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(
    tag = "action",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum GroupCredentialMutationRequest {
    Keep,
    Remove,
    Replace {
        staged_credential_reference: EphemeralCredentialReference,
    },
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GroupCredentialMutationsRequest {
    ssh_password: Option<GroupCredentialMutationRequest>,
    telnet_password: Option<GroupCredentialMutationRequest>,
    proxy_password: Option<GroupCredentialMutationRequest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GroupConfigMetadataRequest {
    pub(crate) path: SavedGroupPath,
    pub(crate) defaults: GroupDefaultsRequest,
    #[serde(default)]
    pub(crate) proxy_command_mutation: Option<GroupProxyCommandMutationRequest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreateGroupConfigRequest {
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
    pub(crate) metadata: GroupConfigMetadataRequest,
    #[serde(default)]
    pub(crate) credential_mutations: GroupCredentialMutationsRequest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UpdateGroupConfigRequest {
    pub(crate) id: String,
    pub(crate) expected_revision: u64,
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
    pub(crate) metadata: GroupConfigMetadataRequest,
    #[serde(default)]
    pub(crate) credential_hints: GroupCredentialHintActionsRequest,
    #[serde(default)]
    pub(crate) credential_mutations: GroupCredentialMutationsRequest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DeleteGroupConfigRequest {
    pub(crate) id: String,
    pub(crate) expected_revision: u64,
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
}

/// Renderer-safe GroupConfig metadata. `SavedGroupDefaults` cannot represent a
/// password body, ciphertext, credential locator, or staged capability. Its
/// credential fields contain only backend-derived presence hints.
#[derive(Clone, PartialEq)]
struct GroupDefaultsView(SavedGroupDefaults);

impl std::fmt::Debug for GroupDefaultsView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GroupDefaultsView([redacted bounded configuration])")
    }
}

impl Serialize for GroupDefaultsView {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Never ask Serde to materialize the backend proxy representation:
        // command bodies and compatibility fields are removed before the
        // ordinary defaults object is created.
        let mut safe_defaults = self.0.clone();
        safe_defaults.proxy = SavedGroupProxyOverride::Inherit;
        let mut value = serde_json::to_value(safe_defaults).map_err(serde::ser::Error::custom)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| serde::ser::Error::custom("invalid group defaults"))?;
        object.insert("proxy".to_owned(), renderer_safe_proxy_value(&self.0.proxy));
        value.serialize(serializer)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GroupConfigView {
    id: String,
    revision: u64,
    path: String,
    defaults: GroupDefaultsView,
    created_at: u64,
    updated_at: u64,
}

impl From<&SavedGroupConfig> for GroupConfigView {
    fn from(group: &SavedGroupConfig) -> Self {
        Self {
            id: group.id.as_str().to_owned(),
            revision: group.revision,
            path: group.path.as_str().to_owned(),
            defaults: GroupDefaultsView(group.defaults.clone()),
            created_at: group.created_at,
            updated_at: group.updated_at,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GroupConfigCatalog {
    inventory_revision: SavedVaultInventoryRevision,
    custom_groups: Vec<String>,
    groups: Vec<GroupConfigView>,
}

impl GroupConfigCatalog {
    pub(crate) fn from_graph(
        inventory_revision: SavedVaultInventoryRevision,
        graph: &SavedVaultGraph,
    ) -> Self {
        Self {
            inventory_revision,
            custom_groups: graph
                .group_catalog()
                .map(|catalog| {
                    catalog
                        .explicit_paths()
                        .iter()
                        .map(|path| path.as_str().to_owned())
                        .collect()
                })
                .unwrap_or_default(),
            groups: graph.groups().iter().map(GroupConfigView::from).collect(),
        }
    }
}

/// One secret-free custody instruction for a deterministic group account.
/// Only an opaque, owner-bound one-shot reference may cross ordinary JSON;
/// the transaction coordinator resolves the password after complete-graph
/// CAS succeeds. This type has no Serde or value-revealing Debug output.
pub(crate) enum PreparedGroupCredentialMutation {
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

impl PreparedGroupCredentialMutation {
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
}

pub(crate) struct PreparedGroupCredentialMutations {
    ssh: PreparedGroupCredentialMutation,
    telnet: PreparedGroupCredentialMutation,
    proxy: PreparedGroupCredentialMutation,
}

impl PreparedGroupCredentialMutations {
    pub(crate) fn into_parts(
        self,
    ) -> (
        PreparedGroupCredentialMutation,
        PreparedGroupCredentialMutation,
        PreparedGroupCredentialMutation,
    ) {
        (self.ssh, self.telnet, self.proxy)
    }
}

/// A complete-graph metadata/custody proposal. The outer coordinator must
/// pass the inventory revision and this exact graph to the Vault replacement
/// planner before consuming any staged credential.
pub(crate) struct PreparedGroupConfigMutation {
    expected_inventory_revision: SavedVaultInventoryRevision,
    target_graph: SavedVaultGraph,
    group: SavedGroupConfig,
    credential_mutations: PreparedGroupCredentialMutations,
}

impl PreparedGroupConfigMutation {
    pub(crate) fn expected_inventory_revision(&self) -> &SavedVaultInventoryRevision {
        &self.expected_inventory_revision
    }

    pub(crate) fn target_graph(&self) -> &SavedVaultGraph {
        &self.target_graph
    }

    pub(crate) fn group(&self) -> &SavedGroupConfig {
        &self.group
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        SavedVaultInventoryRevision,
        SavedVaultGraph,
        SavedGroupConfig,
        PreparedGroupCredentialMutations,
    ) {
        (
            self.expected_inventory_revision,
            self.target_graph,
            self.group,
            self.credential_mutations,
        )
    }
}

/// One deterministic credential owner that a later journal coordinator must
/// remove when deleting a group. The target stays backend-only.
pub(crate) struct PreparedGroupCredentialOwnerDeletion {
    target: StoredCredentialReference,
    had_stored_hint: bool,
}

impl PreparedGroupCredentialOwnerDeletion {
    pub(crate) fn target(&self) -> &StoredCredentialReference {
        &self.target
    }

    pub(crate) const fn had_stored_hint(&self) -> bool {
        self.had_stored_hint
    }
}

/// The three isolated credential owners associated with one group. Returning
/// this plan does not inspect or mutate the OS keyring.
pub(crate) struct PreparedGroupCredentialDeletions {
    ssh: PreparedGroupCredentialOwnerDeletion,
    telnet: PreparedGroupCredentialOwnerDeletion,
    proxy: PreparedGroupCredentialOwnerDeletion,
}

impl PreparedGroupCredentialDeletions {
    pub(crate) fn ssh(&self) -> &PreparedGroupCredentialOwnerDeletion {
        &self.ssh
    }

    pub(crate) fn telnet(&self) -> &PreparedGroupCredentialOwnerDeletion {
        &self.telnet
    }

    pub(crate) fn proxy(&self) -> &PreparedGroupCredentialOwnerDeletion {
        &self.proxy
    }
}

pub(crate) struct PreparedGroupConfigDeletion {
    expected_inventory_revision: SavedVaultInventoryRevision,
    target_graph: SavedVaultGraph,
    group_id: SavedGroupId,
    credential_deletions: PreparedGroupCredentialDeletions,
}

impl PreparedGroupConfigDeletion {
    pub(crate) fn expected_inventory_revision(&self) -> &SavedVaultInventoryRevision {
        &self.expected_inventory_revision
    }

    pub(crate) fn target_graph(&self) -> &SavedVaultGraph {
        &self.target_graph
    }

    pub(crate) fn group_id(&self) -> &SavedGroupId {
        &self.group_id
    }

    pub(crate) fn credential_deletions(&self) -> &PreparedGroupCredentialDeletions {
        &self.credential_deletions
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        SavedVaultInventoryRevision,
        SavedVaultGraph,
        SavedGroupId,
        PreparedGroupCredentialDeletions,
    ) {
        (
            self.expected_inventory_revision,
            self.target_graph,
            self.group_id,
            self.credential_deletions,
        )
    }
}

pub(crate) fn prepare_group_config_creation(
    graph: SavedVaultGraph,
    request: CreateGroupConfigRequest,
    id: SavedGroupId,
    now: u64,
) -> Result<PreparedGroupConfigMutation, String> {
    let CreateGroupConfigRequest {
        expected_inventory_revision,
        metadata,
        credential_mutations,
    } = request;
    let GroupConfigMetadataRequest {
        path,
        defaults,
        proxy_command_mutation,
    } = metadata;
    let mut defaults = resolve_renderer_proxy_command(defaults, proxy_command_mutation, None)?;
    ensure_renderer_defaults_are_hint_free(&defaults).map_err(|_| group_config_invalid())?;
    ensure_group_identity_and_path_available(&graph, &id, &path, None)?;
    let credential_mutations = prepare_group_credential_mutations(
        &id,
        &mut defaults,
        None,
        credential_mutations,
        GroupCredentialHintActionsRequest::default(),
    )?;
    let group = SavedGroupConfig::from_parts(id, 1, path, defaults, now, now)
        .map_err(|_| group_config_invalid())?;
    ensure_group_references(&graph, &group)?;
    let target_graph = graph_with_group(graph, group.clone(), false)?;
    Ok(PreparedGroupConfigMutation {
        expected_inventory_revision,
        target_graph,
        group,
        credential_mutations,
    })
}

pub(crate) fn prepare_group_config_update(
    graph: SavedVaultGraph,
    request: UpdateGroupConfigRequest,
    now: u64,
) -> Result<PreparedGroupConfigMutation, String> {
    let UpdateGroupConfigRequest {
        id,
        expected_revision,
        expected_inventory_revision,
        metadata,
        credential_hints,
        credential_mutations,
    } = request;
    let id = parse_group_id(id)?;
    let current = graph
        .groups()
        .iter()
        .find(|group| group.id == id)
        .cloned()
        .ok_or_else(group_config_not_found)?;
    ensure_expected_revision(&current, expected_revision)?;
    let GroupConfigMetadataRequest {
        path,
        defaults,
        proxy_command_mutation,
    } = metadata;
    let mut defaults = resolve_renderer_proxy_command(
        defaults,
        proxy_command_mutation,
        Some(&current.defaults.proxy),
    )?;
    ensure_renderer_defaults_are_hint_free(&defaults).map_err(|_| group_config_invalid())?;
    ensure_group_identity_and_path_available(&graph, &id, &path, Some(&id))?;
    let credential_mutations = prepare_group_credential_mutations(
        &id,
        &mut defaults,
        Some(&current.defaults),
        credential_mutations,
        credential_hints,
    )?;
    let group = current
        .apply_update(
            SavedGroupConfigUpdate {
                path: Some(path),
                defaults: Some(defaults),
            },
            now,
        )
        .map_err(|_| group_config_invalid())?;
    ensure_group_references(&graph, &group)?;
    let target_graph = graph_with_group(graph, group.clone(), true)?;
    Ok(PreparedGroupConfigMutation {
        expected_inventory_revision,
        target_graph,
        group,
        credential_mutations,
    })
}

pub(crate) fn prepare_group_config_deletion(
    graph: SavedVaultGraph,
    request: DeleteGroupConfigRequest,
) -> Result<PreparedGroupConfigDeletion, String> {
    let DeleteGroupConfigRequest {
        id,
        expected_revision,
        expected_inventory_revision,
    } = request;
    let id = parse_group_id(id)?;
    let current = graph
        .groups()
        .iter()
        .find(|group| group.id == id)
        .cloned()
        .ok_or_else(group_config_not_found)?;
    ensure_expected_revision(&current, expected_revision)?;
    ensure_group_references(&graph, &current)?;

    let credential_deletions = PreparedGroupCredentialDeletions {
        ssh: PreparedGroupCredentialOwnerDeletion {
            target: StoredCredentialReference::for_saved_group_ssh(id.as_str())
                .map_err(|_| group_config_repair_required())?,
            had_stored_hint: current.defaults.password == SavedGroupCredentialOverride::StoredHint,
        },
        telnet: PreparedGroupCredentialOwnerDeletion {
            target: StoredCredentialReference::for_saved_group_telnet(id.as_str())
                .map_err(|_| group_config_repair_required())?,
            had_stored_hint: current.defaults.telnet_password
                == SavedGroupCredentialOverride::StoredHint,
        },
        proxy: PreparedGroupCredentialOwnerDeletion {
            target: StoredCredentialReference::for_saved_group_proxy(id.as_str())
                .map_err(|_| group_config_repair_required())?,
            had_stored_hint: proxy_has_saved_credential(&current.defaults.proxy),
        },
    };

    let (
        hosts,
        references,
        managed_keys,
        identities,
        password_identities,
        proxy_profiles,
        mut groups,
        custom_groups,
        notes_snippets,
        port_forward_rules,
    ) = graph.into_current_parts();
    groups.retain(|group| group.id != id);
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
    Ok(PreparedGroupConfigDeletion {
        expected_inventory_revision,
        target_graph,
        group_id: id,
        credential_deletions,
    })
}

#[derive(Clone, Copy)]
enum PlannedGroupCredentialAction {
    UseMetadata,
    Keep,
    Remove,
    Replace(EphemeralCredentialReference),
}

fn prepare_group_credential_mutations(
    group_id: &SavedGroupId,
    candidate: &mut SavedGroupDefaults,
    current: Option<&SavedGroupDefaults>,
    requests: GroupCredentialMutationsRequest,
    legacy_hints: GroupCredentialHintActionsRequest,
) -> Result<PreparedGroupCredentialMutations, String> {
    let ssh_target = StoredCredentialReference::for_saved_group_ssh(group_id.as_str())
        .map_err(|_| group_config_repair_required())?;
    let telnet_target = StoredCredentialReference::for_saved_group_telnet(group_id.as_str())
        .map_err(|_| group_config_repair_required())?;
    let proxy_target = StoredCredentialReference::for_saved_group_proxy(group_id.as_str())
        .map_err(|_| group_config_repair_required())?;
    let current = current.cloned().unwrap_or_default();

    let ssh = prepare_scalar_credential_mutation(
        &mut candidate.password,
        current.password,
        matches!(candidate.identity_id, SavedGroupOverride::Set(_)),
        combine_group_credential_action(requests.ssh_password, legacy_hints.ssh_password)?,
        ssh_target,
    )?;
    let telnet = prepare_scalar_credential_mutation(
        &mut candidate.telnet_password,
        current.telnet_password,
        matches!(candidate.telnet_identity_id, SavedGroupOverride::Set(_)),
        combine_group_credential_action(requests.telnet_password, legacy_hints.telnet_password)?,
        telnet_target,
    )?;
    let proxy = prepare_proxy_credential_mutation(
        &mut candidate.proxy,
        &current.proxy,
        combine_group_credential_action(requests.proxy_password, legacy_hints.proxy_password)?,
        proxy_target,
    )?;
    Ok(PreparedGroupCredentialMutations { ssh, telnet, proxy })
}

fn combine_group_credential_action(
    request: Option<GroupCredentialMutationRequest>,
    legacy_hint: GroupCredentialHintActionRequest,
) -> Result<PlannedGroupCredentialAction, String> {
    if request.is_some() && legacy_hint != GroupCredentialHintActionRequest::UseMetadata {
        return Err(group_config_invalid());
    }
    Ok(match request {
        Some(GroupCredentialMutationRequest::Keep) => PlannedGroupCredentialAction::Keep,
        Some(GroupCredentialMutationRequest::Remove) => PlannedGroupCredentialAction::Remove,
        Some(GroupCredentialMutationRequest::Replace {
            staged_credential_reference,
        }) => PlannedGroupCredentialAction::Replace(staged_credential_reference),
        None => match legacy_hint {
            GroupCredentialHintActionRequest::UseMetadata => {
                PlannedGroupCredentialAction::UseMetadata
            }
            GroupCredentialHintActionRequest::Keep => PlannedGroupCredentialAction::Keep,
        },
    })
}

fn prepare_scalar_credential_mutation(
    candidate: &mut SavedGroupCredentialOverride,
    current: SavedGroupCredentialOverride,
    identity_selected: bool,
    action: PlannedGroupCredentialAction,
    target: StoredCredentialReference,
) -> Result<PreparedGroupCredentialMutation, String> {
    match action {
        PlannedGroupCredentialAction::UseMetadata => {
            if current == SavedGroupCredentialOverride::StoredHint {
                return Err(group_config_invalid());
            }
            Ok(PreparedGroupCredentialMutation::Keep { target })
        }
        PlannedGroupCredentialAction::Keep => {
            if current == SavedGroupCredentialOverride::StoredHint {
                if identity_selected {
                    return Err(group_config_invalid());
                }
                *candidate = SavedGroupCredentialOverride::StoredHint;
            }
            Ok(PreparedGroupCredentialMutation::Keep { target })
        }
        PlannedGroupCredentialAction::Remove => {
            Ok(PreparedGroupCredentialMutation::Remove { target })
        }
        PlannedGroupCredentialAction::Replace(staged_credential_reference) => {
            if identity_selected {
                return Err(group_config_invalid());
            }
            *candidate = SavedGroupCredentialOverride::StoredHint;
            Ok(PreparedGroupCredentialMutation::Replace {
                target,
                staged_credential_reference,
            })
        }
    }
}

fn prepare_proxy_credential_mutation(
    candidate: &mut SavedGroupProxyOverride,
    current: &SavedGroupProxyOverride,
    action: PlannedGroupCredentialAction,
    target: StoredCredentialReference,
) -> Result<PreparedGroupCredentialMutation, String> {
    match action {
        PlannedGroupCredentialAction::UseMetadata => {
            if proxy_has_saved_credential(current) {
                return Err(group_config_invalid());
            }
            Ok(PreparedGroupCredentialMutation::Keep { target })
        }
        PlannedGroupCredentialAction::Keep => {
            if proxy_has_saved_credential(current) {
                set_candidate_proxy_saved_hint(candidate)?;
            }
            Ok(PreparedGroupCredentialMutation::Keep { target })
        }
        PlannedGroupCredentialAction::Remove => {
            Ok(PreparedGroupCredentialMutation::Remove { target })
        }
        PlannedGroupCredentialAction::Replace(staged_credential_reference) => {
            set_candidate_proxy_saved_hint(candidate)?;
            Ok(PreparedGroupCredentialMutation::Replace {
                target,
                staged_credential_reference,
            })
        }
    }
}

fn set_candidate_proxy_saved_hint(candidate: &mut SavedGroupProxyOverride) -> Result<(), String> {
    let SavedGroupProxyOverride::Inline(config) = candidate else {
        return Err(group_config_invalid());
    };
    *config = config
        .clone()
        .with_saved_credential_hint(true)
        .map_err(|_| group_config_invalid())?;
    if !proxy_has_saved_credential(candidate) {
        return Err(group_config_invalid());
    }
    Ok(())
}

fn ensure_renderer_defaults_are_hint_free(
    defaults: &SavedGroupDefaults,
) -> Result<(), &'static str> {
    if defaults.password == SavedGroupCredentialOverride::StoredHint
        || defaults.telnet_password == SavedGroupCredentialOverride::StoredHint
        || proxy_has_saved_credential(&defaults.proxy)
    {
        Err("stored credential hints are backend-owned")
    } else if matches!(&defaults.mosh_enabled, SavedGroupOverride::Set(true))
        && matches!(&defaults.et_enabled, SavedGroupOverride::Set(true))
    {
        Err("Mosh and Eternal Terminal cannot both be enabled")
    } else {
        Ok(())
    }
}

fn ensure_renderer_credential_wire_is_metadata_only(
    value: &serde_json::Value,
) -> Result<(), &'static str> {
    let object = value
        .as_object()
        .ok_or("group defaults must be an object")?;
    for field in ["password", "telnetPassword"] {
        match object.get(field) {
            None => {}
            Some(serde_json::Value::String(state)) if state == "inherit" || state == "clear" => {}
            Some(_) => return Err("group credential fields accept metadata states only"),
        }
    }
    Ok(())
}

fn prepare_renderer_proxy_wire(defaults: &mut serde_json::Value) -> Result<bool, &'static str> {
    let object = defaults
        .as_object_mut()
        .ok_or("group defaults must be an object")?;
    let Some(proxy) = object.get_mut("proxy") else {
        return Ok(false);
    };
    let proxy_object = proxy
        .as_object_mut()
        .ok_or("group proxy must be an object")?;
    let state = proxy_object
        .get("state")
        .and_then(serde_json::Value::as_str)
        .ok_or("group proxy state is invalid")?;
    match state {
        "inherit" | "clear" => {
            ensure_only_keys(proxy_object, &["state"])?;
            Ok(false)
        }
        "profile" => {
            ensure_only_keys(proxy_object, &["state", "value"])?;
            if !proxy_object
                .get("value")
                .is_some_and(serde_json::Value::is_string)
            {
                return Err("group proxy profile is invalid");
            }
            Ok(false)
        }
        "inline" => {
            ensure_only_keys(proxy_object, &["state", "value"])?;
            let config = proxy_object
                .get_mut("value")
                .and_then(serde_json::Value::as_object_mut)
                .ok_or("group inline proxy is invalid")?;
            let proxy_type = config
                .get("type")
                .and_then(serde_json::Value::as_str)
                .ok_or("group inline proxy type is invalid")?
                .to_owned();
            match proxy_type.as_str() {
                "http" | "socks5" => {
                    ensure_only_keys(
                        config,
                        &[
                            "type",
                            "host",
                            "port",
                            "identityId",
                            "username",
                            "hasSavedCredential",
                        ],
                    )?;
                    if config
                        .get("hasSavedCredential")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false)
                    {
                        return Err("group proxy credential hints are backend-owned");
                    }
                    Ok(false)
                }
                "command" => {
                    // The renderer receives only `{ type: "command" }` and
                    // must express keep/replace through the sibling mutation
                    // field. A temporary fixed body exists only long enough
                    // for the strict Vault model to parse the remaining
                    // defaults and is always replaced before planning.
                    ensure_only_keys(config, &["type"])?;
                    config.insert(
                        "command".to_owned(),
                        serde_json::Value::String(HIDDEN_PROXY_COMMAND_PLACEHOLDER.to_owned()),
                    );
                    Ok(true)
                }
                _ => Err("group inline proxy type is invalid"),
            }
        }
        _ => Err("group proxy state is invalid"),
    }
}

fn ensure_only_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    allowed: &[&str],
) -> Result<(), &'static str> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        Err("group proxy contains unsupported fields")
    } else {
        Ok(())
    }
}

fn resolve_renderer_proxy_command(
    request: GroupDefaultsRequest,
    mutation: Option<GroupProxyCommandMutationRequest>,
    current: Option<&SavedGroupProxyOverride>,
) -> Result<SavedGroupDefaults, String> {
    let GroupDefaultsRequest {
        mut defaults,
        has_hidden_proxy_command,
    } = request;
    if !has_hidden_proxy_command {
        return if mutation.is_none() {
            Ok(defaults)
        } else {
            Err(group_config_invalid())
        };
    }

    let config = match mutation.ok_or_else(group_config_invalid)? {
        GroupProxyCommandMutationRequest::Keep => {
            let Some(SavedGroupProxyOverride::Inline(config @ SavedProxyConfig::Command { .. })) =
                current
            else {
                return Err(group_config_invalid());
            };
            (*config).clone()
        }
        GroupProxyCommandMutationRequest::Replace { command } => {
            SavedProxyConfig::command(command).map_err(|_| group_config_invalid())?
        }
    };
    defaults.proxy = SavedGroupProxyOverride::Inline(config);
    Ok(defaults)
}

fn renderer_safe_proxy_value(proxy: &SavedGroupProxyOverride) -> serde_json::Value {
    match proxy {
        SavedGroupProxyOverride::Inherit => serde_json::json!({"state": "inherit"}),
        SavedGroupProxyOverride::Clear => serde_json::json!({"state": "clear"}),
        SavedGroupProxyOverride::Profile(id) => {
            serde_json::json!({"state": "profile", "value": id.as_str()})
        }
        SavedGroupProxyOverride::Inline(config) => {
            let value = match config {
                SavedProxyConfig::Http {
                    host,
                    port,
                    identity_id,
                    username,
                    has_saved_credential,
                    ..
                } => renderer_safe_network_proxy_value(
                    "http",
                    host,
                    *port,
                    identity_id.as_ref(),
                    username,
                    *has_saved_credential,
                ),
                SavedProxyConfig::Socks5 {
                    host,
                    port,
                    identity_id,
                    username,
                    has_saved_credential,
                    ..
                } => renderer_safe_network_proxy_value(
                    "socks5",
                    host,
                    *port,
                    identity_id.as_ref(),
                    username,
                    *has_saved_credential,
                ),
                SavedProxyConfig::Command { .. } => serde_json::json!({"type": "command"}),
            };
            serde_json::json!({"state": "inline", "value": value})
        }
    }
}

fn renderer_safe_network_proxy_value(
    proxy_type: &str,
    host: &str,
    port: u16,
    identity_id: Option<&netcatty_vault::SavedPasswordIdentityId>,
    username: &str,
    has_saved_credential: bool,
) -> serde_json::Value {
    let mut value = serde_json::Map::new();
    value.insert("type".to_owned(), serde_json::json!(proxy_type));
    value.insert("host".to_owned(), serde_json::json!(host));
    value.insert("port".to_owned(), serde_json::json!(port));
    if let Some(identity_id) = identity_id {
        value.insert(
            "identityId".to_owned(),
            serde_json::json!(identity_id.as_str()),
        );
    }
    value.insert("username".to_owned(), serde_json::json!(username));
    value.insert(
        "hasSavedCredential".to_owned(),
        serde_json::json!(has_saved_credential),
    );
    serde_json::Value::Object(value)
}

fn proxy_has_saved_credential(proxy: &SavedGroupProxyOverride) -> bool {
    matches!(
        proxy,
        SavedGroupProxyOverride::Inline(
            SavedProxyConfig::Http {
                identity_id: None,
                has_saved_credential: true,
                ..
            } | SavedProxyConfig::Socks5 {
                identity_id: None,
                has_saved_credential: true,
                ..
            }
        )
    )
}

fn ensure_group_identity_and_path_available(
    graph: &SavedVaultGraph,
    id: &SavedGroupId,
    path: &SavedGroupPath,
    excluded_id: Option<&SavedGroupId>,
) -> Result<(), String> {
    if graph
        .groups()
        .iter()
        .any(|group| group.id == *id && excluded_id != Some(&group.id))
        || graph
            .groups()
            .iter()
            .any(|group| group.path == *path && excluded_id != Some(&group.id))
    {
        Err(group_config_invalid())
    } else {
        Ok(())
    }
}

fn ensure_expected_revision(
    group: &SavedGroupConfig,
    expected_revision: u64,
) -> Result<(), String> {
    if expected_revision == 0 || group.revision != expected_revision {
        Err(group_config_changed())
    } else {
        Ok(())
    }
}

fn ensure_group_references(
    graph: &SavedVaultGraph,
    group: &SavedGroupConfig,
) -> Result<(), String> {
    let defaults = &group.defaults;
    if let SavedGroupOverride::Set(chain) = &defaults.host_chain {
        if chain
            .host_ids()
            .iter()
            .any(|id| !graph.hosts().iter().any(|candidate| candidate.id == *id))
        {
            return Err(group_config_invalid());
        }
    }
    if let SavedGroupOverride::Set(id) = &defaults.identity_file_id {
        if !graph
            .ssh_key_references()
            .iter()
            .any(|candidate| candidate.id == *id)
            && !graph
                .managed_ssh_keys()
                .iter()
                .any(|candidate| candidate.id == *id)
        {
            return Err(group_config_invalid());
        }
    }
    if let SavedGroupOverride::Set(identity) = &defaults.identity_id {
        match identity {
            SavedGroupIdentityReference::Key(id) => {
                if !graph
                    .identity_references()
                    .iter()
                    .any(|candidate| candidate.id == *id)
                    || graph
                        .password_identities()
                        .iter()
                        .any(|candidate| candidate.id.as_str() == id.as_str())
                {
                    return Err(group_config_invalid());
                }
            }
            SavedGroupIdentityReference::Password(id) => {
                if !graph
                    .password_identities()
                    .iter()
                    .any(|candidate| candidate.id == *id)
                    || graph
                        .identity_references()
                        .iter()
                        .any(|candidate| candidate.id.as_str() == id.as_str())
                {
                    return Err(group_config_invalid());
                }
            }
        }
    }
    if let SavedGroupOverride::Set(id) = &defaults.telnet_identity_id {
        if !graph
            .password_identities()
            .iter()
            .any(|candidate| candidate.id == *id)
            || graph
                .identity_references()
                .iter()
                .any(|candidate| candidate.id.as_str() == id.as_str())
        {
            return Err(group_config_invalid());
        }
    }
    match &defaults.proxy {
        SavedGroupProxyOverride::Profile(id) => {
            if !graph
                .proxy_profiles()
                .iter()
                .any(|candidate| candidate.id == *id)
            {
                return Err(group_config_invalid());
            }
        }
        SavedGroupProxyOverride::Inline(config) => {
            if let Some(id) = config.identity_id() {
                if !graph
                    .password_identities()
                    .iter()
                    .any(|candidate| candidate.id == *id)
                    || graph
                        .identity_references()
                        .iter()
                        .any(|candidate| candidate.id.as_str() == id.as_str())
                {
                    return Err(group_config_invalid());
                }
            }
        }
        SavedGroupProxyOverride::Inherit | SavedGroupProxyOverride::Clear => {}
    }
    Ok(())
}

fn graph_with_group(
    graph: SavedVaultGraph,
    group: SavedGroupConfig,
    replace: bool,
) -> Result<SavedVaultGraph, String> {
    let (
        hosts,
        references,
        managed_keys,
        identities,
        password_identities,
        proxy_profiles,
        mut groups,
        custom_groups,
        notes_snippets,
        port_forward_rules,
    ) = graph.into_current_parts();
    if replace {
        let Some(index) = groups.iter().position(|current| current.id == group.id) else {
            return Err(group_config_not_found());
        };
        groups[index] = group;
    } else {
        groups.push(group);
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

fn parse_group_id(id: String) -> Result<SavedGroupId, String> {
    SavedGroupId::from_opaque(id).map_err(|_| group_config_invalid())
}

pub(crate) fn group_config_error(code: &str, message: &str) -> String {
    format!("{code}: {message}")
}

pub(crate) fn group_config_invalid() -> String {
    group_config_error(
        GROUP_CONFIG_INVALID,
        "The group configuration request is invalid",
    )
}

pub(crate) fn group_config_not_found() -> String {
    group_config_error(
        GROUP_CONFIG_NOT_FOUND,
        "The group configuration was not found",
    )
}

pub(crate) fn group_config_changed() -> String {
    group_config_error(
        GROUP_CONFIG_CHANGED,
        "The group configuration changed; refresh and retry",
    )
}

pub(crate) fn group_config_inventory_changed() -> String {
    group_config_error(
        GROUP_CONFIG_INVENTORY_CHANGED,
        "The group configuration catalog changed; refresh and retry",
    )
}

pub(crate) fn group_config_publication_failed() -> String {
    group_config_error(
        GROUP_CONFIG_PUBLICATION_FAILED,
        "The group configuration update could not be published",
    )
}

pub(crate) fn group_config_repair_required() -> String {
    group_config_error(
        GROUP_CONFIG_REPAIR_REQUIRED,
        "Group configuration storage requires repair",
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use netcatty_credentials::StoredCredentialReference;
    use netcatty_vault::{
        SavedGroupCatalog, SavedGroupConfig, SavedGroupCredentialOverride, SavedGroupDefaults,
        SavedGroupHostChain, SavedGroupId, SavedGroupIdentityReference, SavedGroupOverride,
        SavedGroupPath, SavedGroupProxyOverride, SavedHost, SavedHostDraft, SavedIdentityReference,
        SavedIdentityReferenceId, SavedManagedSshKey, SavedNotesSnippetsCatalog,
        SavedPasswordIdentity, SavedPasswordIdentityId, SavedPortForwardKind, SavedPortForwardRule,
        SavedProxyConfig, SavedProxyProfile, SavedProxyProfileId, SavedSecretObjectLocator,
        SavedSshKeyCategory, SavedSshKeyCustodyReference, SavedSshKeyReference,
        SavedSshKeyReferenceId, SavedSshKeySource, SavedVaultGraph, SavedVaultInventoryRevision,
    };
    use serde_json::json;

    use super::{
        CreateGroupConfigRequest, DeleteGroupConfigRequest, GROUP_CONFIG_CHANGED,
        GROUP_CONFIG_INVALID, GROUP_CONFIG_NOT_FOUND, GroupConfigCatalog,
        GroupConfigMetadataRequest, GroupCredentialHintActionRequest,
        GroupCredentialHintActionsRequest, GroupCredentialMutationsRequest, GroupDefaultsRequest,
        UpdateGroupConfigRequest, prepare_group_config_creation, prepare_group_config_deletion,
        prepare_group_config_update,
    };

    fn inventory_revision() -> SavedVaultInventoryRevision {
        serde_json::from_value(json!({
            "storeId": "group-config-test-store",
            "loadedGeneration": 9,
            "maxSeenGeneration": 9,
            "seal": "00"
        }))
        .expect("inventory revision")
    }

    fn metadata(path: &str, defaults: SavedGroupDefaults) -> GroupConfigMetadataRequest {
        GroupConfigMetadataRequest {
            path: SavedGroupPath::new(path).expect("group path"),
            defaults: GroupDefaultsRequest {
                defaults,
                has_hidden_proxy_command: false,
            },
            proxy_command_mutation: None,
        }
    }

    fn group(
        id: &str,
        revision: u64,
        path: &str,
        defaults: SavedGroupDefaults,
    ) -> SavedGroupConfig {
        SavedGroupConfig::from_parts(
            SavedGroupId::from_opaque(id).expect("group ID"),
            revision,
            SavedGroupPath::new(path).expect("group path"),
            defaults,
            10,
            10,
        )
        .expect("group")
    }

    #[test]
    fn catalog_projects_host_independent_custom_groups_for_the_renderer() {
        let graph = SavedVaultGraph::default().with_group_catalog(Some(
            SavedGroupCatalog::from_paths(["Empty/Leaf", "Standalone"]).expect("custom groups"),
        ));
        let catalog = GroupConfigCatalog::from_graph(inventory_revision(), &graph);
        let value = serde_json::to_value(catalog).expect("catalog JSON");

        assert_eq!(value["customGroups"], json!(["Empty/Leaf", "Standalone"]));
        assert_eq!(value["groups"], json!([]));

        let absent =
            GroupConfigCatalog::from_graph(inventory_revision(), &SavedVaultGraph::default());
        assert_eq!(
            serde_json::to_value(absent).expect("absent catalog JSON")["customGroups"],
            json!([])
        );
    }

    struct CatalogIds {
        host: netcatty_vault::SavedHostId,
        reference_key: SavedSshKeyReferenceId,
        key_identity: SavedIdentityReferenceId,
        password_identity: SavedPasswordIdentityId,
        proxy_profile: SavedProxyProfileId,
        notes_snippets: SavedNotesSnippetsCatalog,
        port_forward: SavedPortForwardRule,
    }

    fn complete_graph(groups: Vec<SavedGroupConfig>) -> (SavedVaultGraph, CatalogIds) {
        let host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("group-target.example.com", "alice"),
            1,
        )
        .expect("host");
        let reference_key_id =
            SavedSshKeyReferenceId::from_opaque("preserved-reference-key").expect("key ID");
        let reference_key = SavedSshKeyReference::from_parts(
            reference_key_id.clone(),
            "Reference key",
            "D:\\keys\\reference",
            SavedSshKeyCategory::key(),
            1,
            1,
            BTreeMap::new(),
        )
        .expect("reference key");
        let managed_key = SavedManagedSshKey::from_parts(
            SavedSshKeyReferenceId::from_opaque("preserved-managed-key").expect("managed ID"),
            "Managed key",
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
        .expect("managed key");
        let key_identity_id =
            SavedIdentityReferenceId::from_opaque("preserved-key-identity").expect("identity ID");
        let key_identity = SavedIdentityReference::from_parts(
            key_identity_id.clone(),
            "Key identity",
            "alice",
            reference_key_id.clone(),
            1,
            1,
            BTreeMap::new(),
        )
        .expect("identity");
        let password_identity_id =
            SavedPasswordIdentityId::from_opaque("preserved-password-identity")
                .expect("password identity ID");
        let password_identity = SavedPasswordIdentity::from_parts(
            password_identity_id.clone(),
            1,
            "Password identity",
            "alice",
            true,
            1,
            1,
            BTreeMap::new(),
        )
        .expect("password identity");
        let proxy_profile_id =
            SavedProxyProfileId::from_opaque("preserved-proxy-profile").expect("profile ID");
        let proxy_profile = SavedProxyProfile::from_parts(
            proxy_profile_id.clone(),
            1,
            "Proxy profile",
            SavedProxyConfig::command("connect %h %p").expect("proxy config"),
            1,
            1,
            BTreeMap::new(),
        )
        .expect("proxy profile");
        let notes_snippets = SavedNotesSnippetsCatalog::from_parts(
            Some(Vec::new()),
            Some(vec!["preserved-package".to_owned()]),
            Some(Vec::new()),
            Some(vec!["Preserved/Notes".to_owned()]),
        )
        .expect("notes/snippets catalog");
        let port_forward = SavedPortForwardRule::new(
            "preserved-group-forward",
            "Preserved group forward",
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
        let ids = CatalogIds {
            host: host.id.clone(),
            reference_key: reference_key_id,
            key_identity: key_identity_id,
            password_identity: password_identity_id,
            proxy_profile: proxy_profile_id,
            notes_snippets: notes_snippets.clone(),
            port_forward: port_forward.clone(),
        };
        (
            SavedVaultGraph::new_with_port_forward_rules(
                vec![host],
                vec![reference_key],
                vec![managed_key],
                vec![key_identity],
                vec![password_identity],
                vec![proxy_profile],
                groups,
                notes_snippets,
                vec![port_forward],
            ),
            ids,
        )
    }

    fn hinted_defaults() -> SavedGroupDefaults {
        SavedGroupDefaults {
            password: SavedGroupCredentialOverride::StoredHint,
            telnet_password: SavedGroupCredentialOverride::StoredHint,
            proxy: SavedGroupProxyOverride::Inline(
                SavedProxyConfig::http("proxy.example.com", 8080, None, "proxy-user", true)
                    .expect("inline proxy"),
            ),
            ..SavedGroupDefaults::default()
        }
    }

    #[test]
    fn catalog_is_renderer_safe_and_json_cannot_forge_credential_hints_or_bodies() {
        let saved = group("safe-group", 2, "Operations", hinted_defaults());
        let graph = SavedVaultGraph::new_with_proxy_profiles(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![saved],
        );
        let catalog = GroupConfigCatalog::from_graph(inventory_revision(), &graph);
        let value = serde_json::to_value(&catalog).expect("catalog JSON");
        assert_eq!(value["groups"][0]["defaults"]["password"], "storedHint");
        assert_eq!(
            value["groups"][0]["defaults"]["telnetPassword"],
            "storedHint"
        );
        assert_eq!(
            value["groups"][0]["defaults"]["proxy"]["value"]["hasSavedCredential"],
            true
        );
        let encoded = serde_json::to_string(&catalog).expect("catalog text");
        for forbidden in [
            "password-body-marker",
            "credentialReference",
            "credentialLocator",
            "keyringAccount",
            "ciphertext",
        ] {
            assert!(!encoded.contains(forbidden));
        }

        let request = |defaults| {
            json!({
                "expectedInventoryRevision": inventory_revision(),
                "metadata": {"path": "Operations", "defaults": defaults}
            })
        };
        assert!(
            serde_json::from_value::<CreateGroupConfigRequest>(request(json!({
                "password": "storedHint"
            })))
            .is_err()
        );
        assert!(
            serde_json::from_value::<CreateGroupConfigRequest>(request(json!({
                "telnetPassword": "storedHint"
            })))
            .is_err()
        );
        let plaintext_error = serde_json::from_value::<CreateGroupConfigRequest>(request(json!({
            "password": "password-body-marker"
        })))
        .err()
        .expect("plaintext password must fail")
        .to_string();
        assert!(!plaintext_error.contains("password-body-marker"));
        assert!(
            serde_json::from_value::<CreateGroupConfigRequest>(request(json!({
                "passwordBody": "password-body-marker"
            })))
            .is_err()
        );
        let proxy = serde_json::to_value(hinted_defaults().proxy).expect("proxy JSON");
        assert!(
            serde_json::from_value::<CreateGroupConfigRequest>(request(json!({
                "proxy": proxy
            })))
            .is_err()
        );
        assert!(
            serde_json::from_value::<CreateGroupConfigRequest>(request(json!({
                "password": "clear",
                "telnetPassword": "inherit"
            })))
            .is_ok()
        );
        assert!(
            serde_json::from_value::<CreateGroupConfigRequest>(request(json!({
                "moshEnabled": {"state": "set", "value": true},
                "etEnabled": {"state": "set", "value": true}
            })))
            .is_err()
        );
    }

    #[test]
    fn command_proxy_body_is_redacted_and_changes_require_explicit_keep_or_replace() {
        let command_marker = "hidden-group-command-marker --connect %h:%p";
        let current = group(
            "command-group",
            2,
            "Command",
            SavedGroupDefaults {
                proxy: SavedGroupProxyOverride::Inline(
                    SavedProxyConfig::command(command_marker).expect("command proxy"),
                ),
                ..SavedGroupDefaults::default()
            },
        );
        let graph = SavedVaultGraph::new_with_proxy_profiles(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![current.clone()],
        );
        let catalog = GroupConfigCatalog::from_graph(inventory_revision(), &graph);
        let value = serde_json::to_value(&catalog).expect("renderer catalog");
        assert_eq!(
            value["groups"][0]["defaults"]["proxy"],
            json!({"state": "inline", "value": {"type": "command"}})
        );
        let encoded = serde_json::to_string(&catalog).expect("catalog JSON");
        assert!(!encoded.contains(command_marker));
        assert!(!encoded.contains("hidden-group-command-marker"));
        assert!(!format!("{catalog:?}").contains(command_marker));

        let update_request = |action| {
            serde_json::from_value::<UpdateGroupConfigRequest>(json!({
                "id": current.id.as_str(),
                "expectedRevision": current.revision,
                "expectedInventoryRevision": inventory_revision(),
                "metadata": {
                    "path": current.path.as_str(),
                    "defaults": {
                        "proxy": {"state": "inline", "value": {"type": "command"}}
                    },
                    "proxyCommandMutation": action
                }
            }))
            .expect("command update request")
        };
        let kept = prepare_group_config_update(
            graph.clone(),
            update_request(json!({"action": "keep"})),
            20,
        )
        .expect("keep hidden command");
        assert!(matches!(
            &kept.group().defaults.proxy,
            SavedGroupProxyOverride::Inline(SavedProxyConfig::Command { command, .. })
                if command == command_marker
        ));
        let replacement = "replacement-group-command --connect %h:%p";
        let replaced = prepare_group_config_update(
            graph,
            update_request(json!({"action": "replace", "command": replacement})),
            21,
        )
        .expect("replace hidden command");
        assert!(matches!(
            &replaced.group().defaults.proxy,
            SavedGroupProxyOverride::Inline(SavedProxyConfig::Command { command, .. })
                if command == replacement
        ));

        let leaked_body = serde_json::from_value::<CreateGroupConfigRequest>(json!({
            "expectedInventoryRevision": inventory_revision(),
            "metadata": {
                "path": "Leaked",
                "defaults": {
                    "proxy": {
                        "state": "inline",
                        "value": {"type": "command", "command": command_marker}
                    }
                },
                "proxyCommandMutation": {"action": "keep"}
            }
        }))
        .err()
        .expect("inline command body must be rejected")
        .to_string();
        assert!(!leaked_body.contains(command_marker));

        let compatibility_password = "proxy-compat-password-marker";
        let leaked_compatibility = serde_json::from_value::<CreateGroupConfigRequest>(json!({
            "expectedInventoryRevision": inventory_revision(),
            "metadata": {
                "path": "Compatibility",
                "defaults": {
                    "proxy": {
                        "state": "inline",
                        "value": {
                            "type": "http",
                            "host": "proxy.example.test",
                            "port": 8080,
                            "username": "proxy-user",
                            "password": compatibility_password
                        }
                    }
                }
            }
        }))
        .err()
        .expect("proxy compatibility secret field must be rejected")
        .to_string();
        assert!(!leaked_compatibility.contains(compatibility_password));
    }

    #[test]
    fn creation_validates_references_and_preserves_all_other_v6_catalogs() {
        let (graph, ids) = complete_graph(Vec::new());
        let defaults = SavedGroupDefaults {
            host_chain: SavedGroupOverride::Set(
                SavedGroupHostChain::new(vec![ids.host.clone()]).expect("host chain"),
            ),
            identity_id: SavedGroupOverride::Set(SavedGroupIdentityReference::Password(
                ids.password_identity.clone(),
            )),
            identity_file_id: SavedGroupOverride::Set(ids.reference_key.clone()),
            telnet_identity_id: SavedGroupOverride::Set(ids.password_identity.clone()),
            proxy: SavedGroupProxyOverride::Profile(ids.proxy_profile.clone()),
            ..SavedGroupDefaults::default()
        };
        let id = SavedGroupId::from_opaque("created-group").expect("group ID");
        let prepared = prepare_group_config_creation(
            graph,
            CreateGroupConfigRequest {
                expected_inventory_revision: inventory_revision(),
                metadata: metadata("/Operations//Primary/", defaults),
                credential_mutations: GroupCredentialMutationsRequest::default(),
            },
            id.clone(),
            30,
        )
        .expect("creation plan");
        assert_eq!(prepared.group().id, id);
        assert_eq!(prepared.group().revision, 1);
        assert_eq!(prepared.group().path.as_str(), "Operations/Primary");
        assert_eq!(
            prepared.expected_inventory_revision(),
            &inventory_revision()
        );
        let target = prepared.target_graph();
        assert_eq!(target.hosts().len(), 1);
        assert_eq!(target.ssh_key_references().len(), 1);
        assert_eq!(target.managed_ssh_keys().len(), 1);
        assert_eq!(target.identity_references().len(), 1);
        assert_eq!(target.password_identities().len(), 1);
        assert_eq!(target.proxy_profiles().len(), 1);
        assert_eq!(target.groups(), std::slice::from_ref(prepared.group()));
        assert_eq!(target.notes_snippets(), &ids.notes_snippets);
        assert_eq!(
            target.port_forward_rules(),
            std::slice::from_ref(&ids.port_forward)
        );

        let missing_host = SavedGroupDefaults {
            host_chain: SavedGroupOverride::Set(
                SavedGroupHostChain::new(vec![
                    netcatty_vault::SavedHostId::from_opaque("missing-host").expect("host ID"),
                ])
                .expect("host chain"),
            ),
            ..SavedGroupDefaults::default()
        };
        let error = prepare_group_config_creation(
            SavedVaultGraph::default(),
            CreateGroupConfigRequest {
                expected_inventory_revision: inventory_revision(),
                metadata: metadata("Missing", missing_host),
                credential_mutations: GroupCredentialMutationsRequest::default(),
            },
            SavedGroupId::from_opaque("missing-reference-group").expect("group ID"),
            1,
        )
        .err()
        .expect("missing reference");
        assert!(error.starts_with(GROUP_CONFIG_INVALID));
        assert!(!error.contains("missing-host"));
    }

    #[test]
    fn update_requires_record_revision_and_explicit_keep_for_every_existing_hint() {
        let current = group("hinted-group", 3, "Old", hinted_defaults());
        let graph = SavedVaultGraph::new_with_proxy_profiles(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![current.clone()],
        );
        let candidate = SavedGroupDefaults {
            password: SavedGroupCredentialOverride::Clear,
            telnet_password: SavedGroupCredentialOverride::Inherit,
            proxy: SavedGroupProxyOverride::Inline(
                SavedProxyConfig::socks5("new.proxy", 1080, None, "new-user", false)
                    .expect("candidate proxy"),
            ),
            ..SavedGroupDefaults::default()
        };
        let keep = GroupCredentialHintActionsRequest {
            ssh_password: GroupCredentialHintActionRequest::Keep,
            telnet_password: GroupCredentialHintActionRequest::Keep,
            proxy_password: GroupCredentialHintActionRequest::Keep,
        };
        let prepared = prepare_group_config_update(
            graph.clone(),
            UpdateGroupConfigRequest {
                id: current.id.as_str().to_owned(),
                expected_revision: current.revision,
                expected_inventory_revision: inventory_revision(),
                metadata: metadata("New/Path", candidate.clone()),
                credential_hints: keep,
                credential_mutations: GroupCredentialMutationsRequest::default(),
            },
            30,
        )
        .expect("update plan");
        assert_eq!(prepared.group().revision, 4);
        assert_eq!(prepared.group().path.as_str(), "New/Path");
        assert_eq!(
            prepared.group().defaults.password,
            SavedGroupCredentialOverride::StoredHint
        );
        assert_eq!(
            prepared.group().defaults.telnet_password,
            SavedGroupCredentialOverride::StoredHint
        );
        assert!(matches!(
            &prepared.group().defaults.proxy,
            SavedGroupProxyOverride::Inline(SavedProxyConfig::Socks5 {
                has_saved_credential: true,
                ..
            })
        ));
        assert_eq!(prepared.target_graph().groups().len(), 1);

        let without_keep = prepare_group_config_update(
            graph.clone(),
            UpdateGroupConfigRequest {
                id: current.id.as_str().to_owned(),
                expected_revision: current.revision,
                expected_inventory_revision: inventory_revision(),
                metadata: metadata("New/Path", candidate.clone()),
                credential_hints: GroupCredentialHintActionsRequest::default(),
                credential_mutations: GroupCredentialMutationsRequest::default(),
            },
            30,
        )
        .err()
        .expect("hint deletion must fail");
        assert!(without_keep.starts_with(GROUP_CONFIG_INVALID));
        assert!(!without_keep.contains(current.id.as_str()));

        let stale = prepare_group_config_update(
            graph,
            UpdateGroupConfigRequest {
                id: current.id.as_str().to_owned(),
                expected_revision: current.revision - 1,
                expected_inventory_revision: inventory_revision(),
                metadata: metadata("New/Path", candidate),
                credential_hints: keep,
                credential_mutations: GroupCredentialMutationsRequest::default(),
            },
            30,
        )
        .err()
        .expect("stale record");
        assert!(stale.starts_with(GROUP_CONFIG_CHANGED));
    }

    #[test]
    fn update_rejects_duplicate_paths_and_wrong_catalog_reference_types() {
        let first = group("first-group", 1, "First", SavedGroupDefaults::default());
        let second = group("second-group", 1, "Second", SavedGroupDefaults::default());
        let graph = SavedVaultGraph::new_with_proxy_profiles(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![first.clone(), second],
        );
        let duplicate = prepare_group_config_update(
            graph,
            UpdateGroupConfigRequest {
                id: first.id.as_str().to_owned(),
                expected_revision: first.revision,
                expected_inventory_revision: inventory_revision(),
                metadata: metadata("Second", SavedGroupDefaults::default()),
                credential_hints: GroupCredentialHintActionsRequest::default(),
                credential_mutations: GroupCredentialMutationsRequest::default(),
            },
            2,
        )
        .err()
        .expect("duplicate path");
        assert!(duplicate.starts_with(GROUP_CONFIG_INVALID));

        let (graph, ids) = complete_graph(Vec::new());
        let wrong_type = SavedGroupDefaults {
            identity_id: SavedGroupOverride::Set(SavedGroupIdentityReference::Password(
                SavedPasswordIdentityId::from_opaque(ids.key_identity.as_str())
                    .expect("cross-catalog ID"),
            )),
            ..SavedGroupDefaults::default()
        };
        let error = prepare_group_config_creation(
            graph,
            CreateGroupConfigRequest {
                expected_inventory_revision: inventory_revision(),
                metadata: metadata("Wrong type", wrong_type),
                credential_mutations: GroupCredentialMutationsRequest::default(),
            },
            SavedGroupId::from_opaque("wrong-type-group").expect("group ID"),
            2,
        )
        .err()
        .expect("wrong reference type");
        assert!(error.starts_with(GROUP_CONFIG_INVALID));
        assert!(!error.contains(ids.key_identity.as_str()));
    }

    #[test]
    fn deletion_preserves_six_catalogs_and_returns_three_backend_only_owner_plans() {
        let removed = group("removed-group", 4, "Removed", hinted_defaults());
        let preserved = group(
            "preserved-group",
            1,
            "Preserved",
            SavedGroupDefaults::default(),
        );
        let (graph, ids) = complete_graph(vec![removed.clone(), preserved.clone()]);
        let prepared = prepare_group_config_deletion(
            graph,
            DeleteGroupConfigRequest {
                id: removed.id.as_str().to_owned(),
                expected_revision: removed.revision,
                expected_inventory_revision: inventory_revision(),
            },
        )
        .expect("deletion plan");
        assert_eq!(prepared.group_id(), &removed.id);
        assert_eq!(
            prepared.expected_inventory_revision(),
            &inventory_revision()
        );
        let target = prepared.target_graph();
        assert_eq!(target.hosts().len(), 1);
        assert_eq!(target.ssh_key_references().len(), 1);
        assert_eq!(target.managed_ssh_keys().len(), 1);
        assert_eq!(target.identity_references().len(), 1);
        assert_eq!(target.password_identities().len(), 1);
        assert_eq!(target.proxy_profiles().len(), 1);
        assert_eq!(target.groups(), std::slice::from_ref(&preserved));
        assert_eq!(target.notes_snippets(), &ids.notes_snippets);
        assert_eq!(
            target.port_forward_rules(),
            std::slice::from_ref(&ids.port_forward)
        );

        let owners = prepared.credential_deletions();
        assert_eq!(
            owners.ssh().target(),
            &StoredCredentialReference::for_saved_group_ssh(removed.id.as_str())
                .expect("SSH owner")
        );
        assert_eq!(
            owners.telnet().target(),
            &StoredCredentialReference::for_saved_group_telnet(removed.id.as_str())
                .expect("Telnet owner")
        );
        assert_eq!(
            owners.proxy().target(),
            &StoredCredentialReference::for_saved_group_proxy(removed.id.as_str())
                .expect("proxy owner")
        );
        assert!(owners.ssh().had_stored_hint());
        assert!(owners.telnet().had_stored_hint());
        assert!(owners.proxy().had_stored_hint());
    }

    #[test]
    fn missing_invalid_and_stale_delete_errors_are_fixed_and_secret_free() {
        let missing_id = "missing-group-marker";
        let missing = prepare_group_config_deletion(
            SavedVaultGraph::default(),
            DeleteGroupConfigRequest {
                id: missing_id.to_owned(),
                expected_revision: 1,
                expected_inventory_revision: inventory_revision(),
            },
        )
        .err()
        .expect("missing group");
        assert!(missing.starts_with(GROUP_CONFIG_NOT_FOUND));

        let invalid_id = "invalid-group\npassword-body-marker";
        let invalid = prepare_group_config_deletion(
            SavedVaultGraph::default(),
            DeleteGroupConfigRequest {
                id: invalid_id.to_owned(),
                expected_revision: 1,
                expected_inventory_revision: inventory_revision(),
            },
        )
        .err()
        .expect("invalid group ID");
        assert!(invalid.starts_with(GROUP_CONFIG_INVALID));

        let current = group(
            "stale-group-marker",
            2,
            "Stale",
            SavedGroupDefaults::default(),
        );
        let stale = prepare_group_config_deletion(
            SavedVaultGraph::new_with_proxy_profiles(
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                vec![current.clone()],
            ),
            DeleteGroupConfigRequest {
                id: current.id.as_str().to_owned(),
                expected_revision: 1,
                expected_inventory_revision: inventory_revision(),
            },
        )
        .err()
        .expect("stale delete");
        assert!(stale.starts_with(GROUP_CONFIG_CHANGED));

        for error in [missing, invalid, stale] {
            for forbidden in [
                missing_id,
                invalid_id,
                current.id.as_str(),
                "password-body-marker",
            ] {
                assert!(!error.contains(forbidden));
            }
        }
    }
}
