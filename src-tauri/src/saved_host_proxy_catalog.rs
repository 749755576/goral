use netcatty_credentials::{EphemeralCredentialReference, StoredCredentialReference};
use netcatty_vault::{
    SavedHost, SavedHostDraft, SavedHostId, SavedHostUpdate, SavedPasswordIdentityId,
    SavedProxyConfig, SavedProxyProfileId, SavedVaultGraph,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const SAVED_HOST_PROXY_INVALID: &str = "SAVED_HOST_PROXY_INVALID";
pub(crate) const SAVED_HOST_PROXY_REPAIR_REQUIRED: &str = "SAVED_HOST_PROXY_REPAIR_REQUIRED";

#[derive(Deserialize)]
#[serde(
    tag = "action",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum HostInlineProxyCredentialMutationRequest {
    Keep,
    Remove,
    Replace {
        staged_credential_reference: EphemeralCredentialReference,
    },
}

#[derive(Deserialize)]
#[serde(
    tag = "action",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum HostInlineProxyCommandMutationRequest {
    Keep,
    Replace { command: String },
}

#[derive(Deserialize)]
#[serde(
    tag = "mode",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum HostInlineProxyNetworkAuthRequest {
    Manual {
        #[serde(default)]
        username: String,
        credential_mutation: HostInlineProxyCredentialMutationRequest,
    },
    Identity {
        identity_id: String,
    },
}

#[derive(Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum HostInlineProxyConfigRequest {
    Http {
        host: String,
        port: u32,
        auth: HostInlineProxyNetworkAuthRequest,
    },
    Socks5 {
        host: String,
        port: u32,
        auth: HostInlineProxyNetworkAuthRequest,
    },
    Command {
        command_mutation: HostInlineProxyCommandMutationRequest,
    },
}

#[derive(Deserialize)]
#[serde(
    tag = "action",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum HostInlineProxyMutationRequest {
    Keep,
    Remove,
    Replace {
        config: HostInlineProxyConfigRequest,
    },
}

#[derive(Deserialize)]
#[serde(
    tag = "action",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum HostProxyProfileMutationRequest {
    Keep,
    Remove,
    Replace { profile_id: String },
}

/// A host create/update planner can embed this value without accepting a
/// password, stored account locator, or raw command outside the explicitly
/// typed command mutation.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SavedHostProxyMutationRequest {
    pub(crate) inline_proxy: HostInlineProxyMutationRequest,
    pub(crate) profile: HostProxyProfileMutationRequest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(
    tag = "mode",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum HostInlineProxyNetworkAuthView {
    Manual {
        username: String,
        has_saved_credential: bool,
    },
    Identity {
        identity_id: String,
    },
}

/// Renderer-safe inline configuration. The command body is deliberately not
/// representable; clients use `commandMutation: { action: "keep" }` when an
/// existing command must survive an update.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum HostInlineProxyConfigView {
    Http {
        host: String,
        port: u16,
        auth: HostInlineProxyNetworkAuthView,
    },
    Socks5 {
        host: String,
        port: u16,
        auth: HostInlineProxyNetworkAuthView,
    },
    Command,
}

impl From<&SavedProxyConfig> for HostInlineProxyConfigView {
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
) -> HostInlineProxyNetworkAuthView {
    match identity_id {
        Some(identity_id) => HostInlineProxyNetworkAuthView::Identity {
            identity_id: identity_id.as_str().to_owned(),
        },
        None => HostInlineProxyNetworkAuthView::Manual {
            username: username.to_owned(),
            has_saved_credential,
        },
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SavedHostProxyView {
    pub(crate) proxy_profile_id: Option<String>,
    pub(crate) inline_proxy: Option<HostInlineProxyConfigView>,
}

/// Reads inline configuration before consulting a profile binding. A malformed
/// non-null inline value therefore cannot fall back to an otherwise valid
/// profile. A valid inline value keeps a profile ID only as shadowed metadata.
pub(crate) fn saved_host_proxy_view(
    host: &SavedHost,
    graph: &SavedVaultGraph,
) -> Result<SavedHostProxyView, String> {
    let raw_inline = host.compatibility_fields().get("proxyConfig");
    if raw_inline.is_some_and(|value| !value.is_null()) {
        let inline = host
            .proxy_config()
            .map_err(|_| saved_host_proxy_repair_required())?
            .ok_or_else(saved_host_proxy_repair_required)?;
        let shadowed_profile_id = host
            .compatibility_fields()
            .get("proxyProfileId")
            .and_then(Value::as_str)
            .map(str::to_owned);
        return Ok(SavedHostProxyView {
            proxy_profile_id: shadowed_profile_id,
            inline_proxy: Some(HostInlineProxyConfigView::from(&inline)),
        });
    }

    let profile_id = host
        .proxy_profile_id()
        .map_err(|_| saved_host_proxy_repair_required())?;
    if let Some(profile_id) = &profile_id {
        ensure_profile_available(graph, profile_id)?;
    }
    Ok(SavedHostProxyView {
        proxy_profile_id: profile_id.map(|id| id.as_str().to_owned()),
        inline_proxy: None,
    })
}

/// Backend-only deterministic keyring work. It intentionally has no Serde,
/// `Debug`, or `Clone` implementation because `Replace` owns an ephemeral
/// credential capability.
pub(crate) enum PreparedHostInlineProxyCredentialMutation {
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

impl PreparedHostInlineProxyCredentialMutation {
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

enum PreparedInlineField {
    Keep,
    Clear,
    Set(SavedProxyConfig),
}

enum PreparedProfileField {
    Keep,
    Clear,
    Set(SavedProxyProfileId),
}

enum PreparedCredentialAction {
    Keep,
    Remove,
    Replace {
        staged_credential_reference: EphemeralCredentialReference,
    },
}

pub(crate) struct PreparedSavedHostProxyMutation {
    inline: PreparedInlineField,
    profile: PreparedProfileField,
    credential: PreparedCredentialAction,
}

impl PreparedSavedHostProxyMutation {
    pub(crate) const fn removes_existing_credential(&self) -> bool {
        matches!(self.credential, PreparedCredentialAction::Remove)
    }

    pub(crate) const fn replaces_existing_credential(&self) -> bool {
        matches!(self.credential, PreparedCredentialAction::Replace { .. })
    }

    /// Applies only proxy-owned compatibility fields, leaving every existing
    /// caller-owned draft field and compatibility extension untouched.
    pub(crate) fn apply_to_draft(
        &self,
        mut draft: SavedHostDraft,
    ) -> Result<SavedHostDraft, String> {
        draft = match &self.inline {
            PreparedInlineField::Keep => draft,
            PreparedInlineField::Clear => draft
                .with_compatibility_field("proxyConfig", Value::Null)
                .map_err(|_| saved_host_proxy_repair_required())?,
            PreparedInlineField::Set(config) => draft
                .with_proxy_config(config.clone())
                .map_err(|_| saved_host_proxy_repair_required())?,
        };
        match &self.profile {
            PreparedProfileField::Keep => Ok(draft),
            PreparedProfileField::Clear => draft
                .with_compatibility_field("proxyProfileId", Value::Null)
                .map_err(|_| saved_host_proxy_repair_required()),
            PreparedProfileField::Set(profile_id) => draft
                .with_proxy_profile_id(profile_id.clone())
                .map_err(|_| saved_host_proxy_repair_required()),
        }
    }

    /// Produces a composable partial host update. Applying it merges only the
    /// two proxy keys and therefore preserves all unrelated host compatibility
    /// fields.
    pub(crate) fn apply_to_update(
        &self,
        mut update: SavedHostUpdate,
    ) -> Result<SavedHostUpdate, String> {
        update = match &self.inline {
            PreparedInlineField::Keep => update,
            PreparedInlineField::Clear => update.clear_proxy_config(),
            PreparedInlineField::Set(config) => update
                .with_proxy_config(config.clone())
                .map_err(|_| saved_host_proxy_repair_required())?,
        };
        match &self.profile {
            PreparedProfileField::Keep => Ok(update),
            PreparedProfileField::Clear => Ok(update.clear_proxy_profile_id()),
            PreparedProfileField::Set(profile_id) => update
                .with_proxy_profile_id(profile_id.clone())
                .map_err(|_| saved_host_proxy_repair_required()),
        }
    }

    /// Binds the already-planned action after creation has generated its host
    /// ID (or immediately for update). The account is derived from the final
    /// host ID and is never accepted from the renderer.
    pub(crate) fn into_credential(
        self,
        host_id: &SavedHostId,
    ) -> Result<PreparedHostInlineProxyCredentialMutation, String> {
        let target = StoredCredentialReference::for_saved_host_proxy(host_id.as_str())
            .map_err(|_| saved_host_proxy_repair_required())?;
        Ok(match self.credential {
            PreparedCredentialAction::Keep => {
                PreparedHostInlineProxyCredentialMutation::Keep { target }
            }
            PreparedCredentialAction::Remove => {
                PreparedHostInlineProxyCredentialMutation::Remove { target }
            }
            PreparedCredentialAction::Replace {
                staged_credential_reference,
            } => PreparedHostInlineProxyCredentialMutation::Replace {
                target,
                staged_credential_reference,
            },
        })
    }
}

enum CurrentInline {
    Absent,
    Valid(SavedProxyConfig),
    Invalid,
}

impl CurrentInline {
    fn valid(&self) -> Option<&SavedProxyConfig> {
        match self {
            Self::Valid(config) => Some(config),
            Self::Absent | Self::Invalid => None,
        }
    }
}

/// Pure preflight shared by saved-host creation and update planners. It never
/// reads or writes a credential store and returns exactly one deterministic
/// host-inline credential action for the caller's unified journal.
pub(crate) fn prepare_saved_host_proxy_mutation(
    graph: &SavedVaultGraph,
    current: Option<&SavedHost>,
    request: SavedHostProxyMutationRequest,
) -> Result<PreparedSavedHostProxyMutation, String> {
    let current_inline = inspect_current_inline(current);
    let (inline, credential, final_inline_present) = match request.inline_proxy {
        HostInlineProxyMutationRequest::Keep => match current_inline {
            CurrentInline::Invalid => return Err(saved_host_proxy_repair_required()),
            CurrentInline::Valid(config) => {
                let credential = if manual_credential_hint(&config).is_some() {
                    PreparedCredentialAction::Keep
                } else {
                    // Identity and command proxies do not use the host-inline
                    // password account. Probe/remove any deterministic orphan
                    // even when the proxy metadata itself is unchanged.
                    PreparedCredentialAction::Remove
                };
                (PreparedInlineField::Keep, credential, true)
            }
            CurrentInline::Absent => (
                PreparedInlineField::Keep,
                // Preserve pure metadata-only host updates when no inline
                // proxy exists. Host deletion still probes the deterministic
                // account regardless of metadata, so an orphan cannot survive
                // deletion.
                PreparedCredentialAction::Keep,
                false,
            ),
        },
        HostInlineProxyMutationRequest::Remove => (
            PreparedInlineField::Clear,
            PreparedCredentialAction::Remove,
            false,
        ),
        HostInlineProxyMutationRequest::Replace { config } => {
            let (config, credential) =
                prepare_inline_config(graph, config, current_inline.valid())?;
            (PreparedInlineField::Set(config), credential, true)
        }
    };

    let profile = match request.profile {
        HostProxyProfileMutationRequest::Keep => {
            // A kept profile becomes effective only when no inline value will
            // remain. Shadowed metadata is deliberately preserved as-is.
            if !final_inline_present {
                if let Some(current) = current {
                    let profile_id = current
                        .proxy_profile_id()
                        .map_err(|_| saved_host_proxy_repair_required())?;
                    if let Some(profile_id) = profile_id {
                        ensure_profile_available(graph, &profile_id)?;
                    }
                }
            }
            PreparedProfileField::Keep
        }
        HostProxyProfileMutationRequest::Remove => PreparedProfileField::Clear,
        HostProxyProfileMutationRequest::Replace { profile_id } => {
            let profile_id = SavedProxyProfileId::from_opaque(profile_id)
                .map_err(|_| saved_host_proxy_invalid())?;
            ensure_profile_available(graph, &profile_id)?;
            PreparedProfileField::Set(profile_id)
        }
    };

    Ok(PreparedSavedHostProxyMutation {
        inline,
        profile,
        credential,
    })
}

pub(crate) fn prepare_saved_host_proxy_creation(
    graph: &SavedVaultGraph,
    request: SavedHostProxyMutationRequest,
) -> Result<PreparedSavedHostProxyMutation, String> {
    prepare_saved_host_proxy_mutation(graph, None, request)
}

pub(crate) fn prepare_saved_host_proxy_update(
    graph: &SavedVaultGraph,
    current: &SavedHost,
    request: SavedHostProxyMutationRequest,
) -> Result<PreparedSavedHostProxyMutation, String> {
    prepare_saved_host_proxy_mutation(graph, Some(current), request)
}

fn inspect_current_inline(current: Option<&SavedHost>) -> CurrentInline {
    let Some(current) = current else {
        return CurrentInline::Absent;
    };
    if !current
        .compatibility_fields()
        .get("proxyConfig")
        .is_some_and(|value| !value.is_null())
    {
        return CurrentInline::Absent;
    }
    match current.proxy_config() {
        Ok(Some(config)) => CurrentInline::Valid(config),
        Ok(None) => CurrentInline::Absent,
        Err(_) => CurrentInline::Invalid,
    }
}

fn prepare_inline_config(
    graph: &SavedVaultGraph,
    request: HostInlineProxyConfigRequest,
    current: Option<&SavedProxyConfig>,
) -> Result<(SavedProxyConfig, PreparedCredentialAction), String> {
    let (config, credential) = match request {
        HostInlineProxyConfigRequest::Http { host, port, auth } => {
            prepare_network_config(graph, true, host, port, auth, current)?
        }
        HostInlineProxyConfigRequest::Socks5 { host, port, auth } => {
            prepare_network_config(graph, false, host, port, auth, current)?
        }
        HostInlineProxyConfigRequest::Command { command_mutation } => {
            let command = match command_mutation {
                HostInlineProxyCommandMutationRequest::Keep => match current {
                    Some(SavedProxyConfig::Command { command, .. }) => command.clone(),
                    Some(SavedProxyConfig::Http { .. } | SavedProxyConfig::Socks5 { .. })
                    | None => return Err(saved_host_proxy_invalid()),
                },
                HostInlineProxyCommandMutationRequest::Replace { command } => command,
            };
            let config =
                SavedProxyConfig::command(command).map_err(|_| saved_host_proxy_invalid())?;
            // Command proxies can never consume the deterministic inline
            // password account. Probe/remove it even when the previous shape
            // was also non-manual so stale legacy or false-hint secrets cannot
            // survive a successful update.
            (config, PreparedCredentialAction::Remove)
        }
    };
    let config = preserve_config_compatibility(config, current)?;
    Ok((config, credential))
}

#[allow(clippy::too_many_arguments)]
fn prepare_network_config(
    graph: &SavedVaultGraph,
    http: bool,
    host: String,
    port: u32,
    auth: HostInlineProxyNetworkAuthRequest,
    current: Option<&SavedProxyConfig>,
) -> Result<(SavedProxyConfig, PreparedCredentialAction), String> {
    match auth {
        HostInlineProxyNetworkAuthRequest::Manual {
            username,
            credential_mutation,
        } => {
            let (has_saved_credential, credential) = match credential_mutation {
                HostInlineProxyCredentialMutationRequest::Keep => {
                    match current.and_then(manual_credential_hint) {
                        Some(has_saved_credential) => {
                            (has_saved_credential, PreparedCredentialAction::Keep)
                        }
                        // There is no valid manual credential to keep. Remove
                        // the deterministic account in case older code left an
                        // orphan whose metadata hint is absent or unusable.
                        None => (false, PreparedCredentialAction::Remove),
                    }
                }
                HostInlineProxyCredentialMutationRequest::Remove => {
                    (false, PreparedCredentialAction::Remove)
                }
                HostInlineProxyCredentialMutationRequest::Replace {
                    staged_credential_reference,
                } => (
                    true,
                    PreparedCredentialAction::Replace {
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
            .map_err(|_| saved_host_proxy_invalid())?;
            Ok((config, credential))
        }
        HostInlineProxyNetworkAuthRequest::Identity { identity_id } => {
            let identity_id = SavedPasswordIdentityId::from_opaque(identity_id)
                .map_err(|_| saved_host_proxy_invalid())?;
            ensure_password_identity_available(graph, &identity_id)?;
            let config = if http {
                SavedProxyConfig::http(host, port, Some(identity_id), "", false)
            } else {
                SavedProxyConfig::socks5(host, port, Some(identity_id), "", false)
            }
            .map_err(|_| saved_host_proxy_invalid())?;
            // Identity authentication is isolated in the identity account and
            // must never retain a host-inline manual password account.
            Ok((config, PreparedCredentialAction::Remove))
        }
    }
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
    current: Option<&SavedProxyConfig>,
) -> Result<SavedProxyConfig, String> {
    let Some(current) = current else {
        return Ok(next);
    };
    for (key, value) in current.compatibility_fields() {
        next = next
            .with_compatibility_field(key.clone(), value.clone())
            .map_err(|_| saved_host_proxy_repair_required())?;
    }
    Ok(next)
}

fn ensure_password_identity_available(
    graph: &SavedVaultGraph,
    id: &SavedPasswordIdentityId,
) -> Result<(), String> {
    let password_matches = graph
        .password_identities()
        .iter()
        .filter(|identity| &identity.id == id)
        .count();
    let incompatible = graph
        .identity_references()
        .iter()
        .any(|identity| identity.id.as_str() == id.as_str());
    if password_matches == 1 && !incompatible {
        Ok(())
    } else {
        Err(saved_host_proxy_invalid())
    }
}

fn ensure_profile_available(
    graph: &SavedVaultGraph,
    id: &SavedProxyProfileId,
) -> Result<(), String> {
    if graph
        .proxy_profiles()
        .iter()
        .filter(|profile| &profile.id == id)
        .count()
        == 1
    {
        Ok(())
    } else {
        Err(saved_host_proxy_invalid())
    }
}

pub(crate) fn saved_host_proxy_error(code: &str, message: &str) -> String {
    format!("{code}: {message}")
}

pub(crate) fn saved_host_proxy_invalid() -> String {
    saved_host_proxy_error(
        SAVED_HOST_PROXY_INVALID,
        "The saved host proxy request is invalid",
    )
}

pub(crate) fn saved_host_proxy_repair_required() -> String {
    saved_host_proxy_error(
        SAVED_HOST_PROXY_REPAIR_REQUIRED,
        "Saved host proxy storage requires repair",
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use netcatty_credentials::{EphemeralCredentialReference, StoredCredentialReference};
    use netcatty_vault::{
        SavedHost, SavedHostDraft, SavedPasswordIdentity, SavedPasswordIdentityId,
        SavedProxyConfig, SavedProxyProfile, SavedProxyProfileId, SavedVaultGraph,
    };
    use serde_json::json;

    use super::{
        HostInlineProxyCommandMutationRequest, HostInlineProxyConfigRequest,
        HostInlineProxyMutationRequest, HostProxyProfileMutationRequest, SAVED_HOST_PROXY_INVALID,
        SAVED_HOST_PROXY_REPAIR_REQUIRED, SavedHostProxyMutationRequest,
        prepare_saved_host_proxy_mutation, saved_host_proxy_view,
    };

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

    fn profile(id: &str) -> SavedProxyProfile {
        SavedProxyProfile::from_parts(
            SavedProxyProfileId::from_opaque(id).expect("profile ID"),
            1,
            "Proxy profile",
            SavedProxyConfig::command("profile-command-secret").expect("profile config"),
            1,
            1,
            BTreeMap::new(),
        )
        .expect("profile")
    }

    fn graph(
        identity: Option<SavedPasswordIdentity>,
        profile: Option<SavedProxyProfile>,
    ) -> SavedVaultGraph {
        SavedVaultGraph::new_with_proxy_profiles(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            identity.into_iter().collect(),
            profile.into_iter().collect(),
            Vec::new(),
        )
    }

    fn host_with_fields(fields: BTreeMap<String, serde_json::Value>) -> SavedHost {
        let mut value = json!({
            "recordVersion":1,
            "id":"host-id",
            "revision":1,
            "label":"Host",
            "hostname":"host.example",
            "port":22,
            "username":"user",
            "protocol":"ssh",
            "authMethod":"password",
            "authPolicyVersion":1,
            "createdAt":1,
            "updatedAt":1,
            "legacyMarker":"preserve-me"
        });
        value.as_object_mut().expect("host").extend(fields);
        serde_json::from_value(value).expect("saved host")
    }

    fn replace_command(
        action: HostInlineProxyCommandMutationRequest,
    ) -> SavedHostProxyMutationRequest {
        SavedHostProxyMutationRequest {
            inline_proxy: HostInlineProxyMutationRequest::Replace {
                config: HostInlineProxyConfigRequest::Command {
                    command_mutation: action,
                },
            },
            profile: HostProxyProfileMutationRequest::Keep,
        }
    }

    #[test]
    fn command_view_hides_body_and_command_keep_preserves_it_and_compatibility() {
        let command = "command-body-must-not-render --stdio";
        let config = SavedProxyConfig::command(command)
            .expect("command")
            .with_compatibility_field("pluginFlag", json!(false))
            .expect("compatibility");
        let host = host_with_fields(BTreeMap::from([(
            "proxyConfig".to_owned(),
            serde_json::to_value(config).expect("config JSON"),
        )]));
        let empty_graph = SavedVaultGraph::default();
        let view = saved_host_proxy_view(&host, &empty_graph).expect("safe view");
        let encoded = serde_json::to_string(&view).expect("view JSON");
        assert!(!encoded.contains(command));
        assert_eq!(
            encoded,
            r#"{"proxyProfileId":null,"inlineProxy":{"type":"command"}}"#
        );

        let plan = prepare_saved_host_proxy_mutation(
            &empty_graph,
            Some(&host),
            replace_command(HostInlineProxyCommandMutationRequest::Keep),
        )
        .expect("command keep plan");
        assert!(plan.removes_existing_credential());
        let update = plan
            .apply_to_update(Default::default())
            .expect("proxy update");
        let updated = host.apply_update(update, 2).expect("updated host");
        let updated_config = updated.proxy_config().expect("shape").expect("inline");
        assert!(matches!(
            updated_config,
            SavedProxyConfig::Command { ref command, .. } if command == "command-body-must-not-render --stdio"
        ));
        assert_eq!(updated_config.compatibility_fields()["pluginFlag"], false);
        assert_eq!(
            updated.compatibility_fields()["legacyMarker"],
            "preserve-me"
        );
    }

    #[test]
    fn valid_inline_shadows_profile_while_explicit_profile_binding_is_validated() {
        let available_profile = profile("available-profile");
        let available_graph = graph(None, Some(available_profile));
        let host = host_with_fields(BTreeMap::from([
            (
                "proxyConfig".to_owned(),
                json!({"type":"command", "command":"inline-command-secret"}),
            ),
            (
                "proxyProfileId".to_owned(),
                json!("missing-shadowed-profile"),
            ),
        ]));
        let view = saved_host_proxy_view(&host, &available_graph).expect("inline wins");
        assert_eq!(
            view.proxy_profile_id.as_deref(),
            Some("missing-shadowed-profile")
        );
        assert!(view.inline_proxy.is_some());

        let invalid_binding = SavedHostProxyMutationRequest {
            inline_proxy: HostInlineProxyMutationRequest::Keep,
            profile: HostProxyProfileMutationRequest::Replace {
                profile_id: "missing-profile".to_owned(),
            },
        };
        let error =
            prepare_saved_host_proxy_mutation(&available_graph, Some(&host), invalid_binding)
                .err()
                .expect("missing explicit profile rejected");
        assert!(error.starts_with(SAVED_HOST_PROXY_INVALID));

        let valid_binding = SavedHostProxyMutationRequest {
            inline_proxy: HostInlineProxyMutationRequest::Keep,
            profile: HostProxyProfileMutationRequest::Replace {
                profile_id: "available-profile".to_owned(),
            },
        };
        let plan = prepare_saved_host_proxy_mutation(&available_graph, Some(&host), valid_binding)
            .expect("valid shadowed binding");
        let updated = host
            .apply_update(plan.apply_to_update(Default::default()).expect("update"), 2)
            .expect("host update");
        assert!(updated.proxy_config().expect("inline").is_some());
        assert_eq!(
            updated
                .proxy_profile_id()
                .expect("profile")
                .expect("profile ID")
                .as_str(),
            "available-profile"
        );
    }

    #[test]
    fn identity_reference_is_typed_and_manual_identity_shapes_are_mutually_exclusive() {
        let identity = password_identity("password-identity");
        let available_graph = graph(Some(identity), None);
        let request_json = json!({
            "inlineProxy": {
                "action":"replace",
                "config": {
                    "type":"http",
                    "host":"proxy.example",
                    "port":8080,
                    "auth":{"mode":"identity", "identityId":"password-identity"}
                }
            },
            "profile":{"action":"remove"}
        });
        let request = serde_json::from_value(request_json).expect("typed request");
        let plan = prepare_saved_host_proxy_mutation(&available_graph, None, request)
            .expect("identity plan");
        assert!(plan.removes_existing_credential());
        let draft = plan
            .apply_to_draft(SavedHostDraft::ssh_password("host.example", "user"))
            .expect("draft");
        let host = SavedHost::from_draft(draft, 1).expect("host");
        assert_eq!(
            host.proxy_config()
                .expect("shape")
                .expect("inline")
                .identity_id()
                .map(SavedPasswordIdentityId::as_str),
            Some("password-identity")
        );

        let conflicting = json!({
            "inlineProxy": {
                "action":"replace",
                "config": {
                    "type":"http",
                    "host":"proxy.example",
                    "port":8080,
                    "auth":{
                        "mode":"identity",
                        "identityId":"password-identity",
                        "username":"manual-user",
                        "credentialMutation":{"action":"remove"}
                    }
                }
            },
            "profile":{"action":"remove"}
        });
        assert!(serde_json::from_value::<SavedHostProxyMutationRequest>(conflicting).is_err());
    }

    #[test]
    fn malformed_inline_never_falls_back_and_renderer_json_is_secret_safe() {
        let available_profile = profile("available-profile");
        let available_graph = graph(None, Some(available_profile));
        let host = host_with_fields(BTreeMap::from([
            (
                "proxyConfig".to_owned(),
                json!({
                    "type":"http",
                    "port":8080,
                    "sensitiveMarker":"inline-value-sentinel"
                }),
            ),
            ("proxyProfileId".to_owned(), json!("available-profile")),
        ]));
        let error = saved_host_proxy_view(&host, &available_graph)
            .err()
            .expect("invalid inline blocks fallback");
        assert!(error.starts_with(SAVED_HOST_PROXY_REPAIR_REQUIRED));
        assert!(!error.contains("inline-value-sentinel"));
        let keep_error = prepare_saved_host_proxy_mutation(
            &available_graph,
            Some(&host),
            SavedHostProxyMutationRequest {
                inline_proxy: HostInlineProxyMutationRequest::Keep,
                profile: HostProxyProfileMutationRequest::Keep,
            },
        )
        .err()
        .expect("invalid inline cannot be kept");
        assert!(keep_error.starts_with(SAVED_HOST_PROXY_REPAIR_REQUIRED));
        assert!(!keep_error.contains("inline-value-sentinel"));

        let staged = EphemeralCredentialReference::new();
        let request = json!({
            "inlineProxy": {
                "action":"replace",
                "config": {
                    "type":"http",
                    "host":"proxy-safe.example",
                    "port":8080,
                    "auth":{
                        "mode":"manual",
                        "username":"proxy-user",
                        "credentialMutation":{
                            "action":"replace",
                            "stagedCredentialReference":staged
                        }
                    }
                }
            },
            "profile":{"action":"remove"}
        });
        let parsed: SavedHostProxyMutationRequest =
            serde_json::from_value(request).expect("request");
        let repaired = prepare_saved_host_proxy_mutation(&available_graph, Some(&host), parsed)
            .expect("invalid inline can be explicitly replaced");
        assert!(repaired.replaces_existing_credential());
        let repaired = repaired
            .into_credential(&host.id)
            .expect("deterministic credential plan");
        assert_eq!(repaired.staged_credential_reference(), Some(&staged));
        let target = StoredCredentialReference::for_saved_host_proxy(host.id.as_str())
            .expect("deterministic target");
        assert_eq!(repaired.target(), &target);
    }
}
