//! Connection-time SavedHost projection for GroupConfig inheritance.
//!
//! This module intentionally works on a non-persistent clone. It covers the
//! secret-free optional SSH/session metadata, proxy selection, and credential
//! presence/provenance. The normalized `SavedHost` core currently cannot tell
//! whether legacy `port`, `protocol`, or `authMethod` was omitted or explicitly
//! saved as its default. Those three core fields are therefore left untouched
//! here; `resolved_group_defaults()` exposes their merged values for a later
//! connection-config type that can carry explicitness provenance.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::group_config::{
    ResolvedSavedGroupDefaults, SavedGroupConfig, SavedGroupCredentialOverride, SavedGroupDefaults,
    SavedGroupHostChain, SavedGroupId, SavedGroupIdentityReference, SavedGroupOverride,
    SavedGroupProxyOverride, resolve_group_defaults_with_provenance,
};
use crate::model::{SavedHost, SavedHostId, SavedProxyConfig};

/// Backend-only owner of a manual credential selected for an effective saved
/// host connection.
///
/// The field holding this value determines the credential namespace (SSH,
/// Telnet, or inline proxy). It deliberately has no Serde implementation, and
/// its `Debug` output omits the opaque owner ID.
#[derive(Clone, PartialEq, Eq)]
pub enum SavedHostConnectionCredentialOwner {
    Host(SavedHostId),
    Group(SavedGroupId),
}

impl SavedHostConnectionCredentialOwner {
    pub fn host_id(&self) -> Option<&SavedHostId> {
        match self {
            Self::Host(id) => Some(id),
            Self::Group(_) => None,
        }
    }

    pub fn group_id(&self) -> Option<&SavedGroupId> {
        match self {
            Self::Host(_) => None,
            Self::Group(id) => Some(id),
        }
    }
}

impl fmt::Debug for SavedHostConnectionCredentialOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Host(_) => "Host",
            Self::Group(_) => "Group",
        })
    }
}

/// A non-persistent, secret-free host view after applying its root-to-leaf
/// group defaults.
///
/// `effective_host` is a clone. Its ID, revision, and timestamps remain those
/// of the durable host, but its optional compatibility metadata may contain
/// inherited values. It must never be written back as a host edit. Manual
/// credential owners stay separate because a group-owned credential must not
/// be looked up under a host-owned keyring account merely because the
/// effective metadata contains a `hasSavedCredential` hint.
#[derive(Clone, PartialEq)]
pub struct SavedHostConnectionProjection {
    effective_host: SavedHost,
    resolved_group_defaults: SavedGroupDefaults,
    host_chain_ids: Vec<SavedHostId>,
    ssh_credential_owner: Option<SavedHostConnectionCredentialOwner>,
    telnet_credential_owner: Option<SavedHostConnectionCredentialOwner>,
    inline_proxy_credential_owner: Option<SavedHostConnectionCredentialOwner>,
}

impl SavedHostConnectionProjection {
    pub fn effective_host(&self) -> &SavedHost {
        &self.effective_host
    }

    pub fn into_effective_host(self) -> SavedHost {
        self.effective_host
    }

    /// The merged group value before host precedence is applied. Consumers
    /// should normally use `effective_host`; this accessor exists for fields
    /// whose legacy absence cannot yet be represented by the normalized
    /// `SavedHost` core record (notably port, protocol, and auth method).
    pub fn resolved_group_defaults(&self) -> &SavedGroupDefaults {
        &self.resolved_group_defaults
    }

    /// Ordered effective jump-host IDs, with the first host closest to the
    /// client. Both the legacy `{ hostIds: [...] }` host shape and the
    /// normalized GroupConfig projection are accepted, but malformed or
    /// oversized values make the complete connection projection fail closed.
    pub fn host_chain_ids(&self) -> &[SavedHostId] {
        &self.host_chain_ids
    }

    pub fn ssh_credential_owner(&self) -> Option<&SavedHostConnectionCredentialOwner> {
        self.ssh_credential_owner.as_ref()
    }

    pub fn telnet_credential_owner(&self) -> Option<&SavedHostConnectionCredentialOwner> {
        self.telnet_credential_owner.as_ref()
    }

    pub fn inline_proxy_credential_owner(&self) -> Option<&SavedHostConnectionCredentialOwner> {
        self.inline_proxy_credential_owner.as_ref()
    }
}

impl fmt::Debug for SavedHostConnectionProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SavedHostConnectionProjection")
            .field("ssh_credential_owner", &self.ssh_credential_owner)
            .field("telnet_credential_owner", &self.telnet_credential_owner)
            .field(
                "inline_proxy_credential_owner",
                &self.inline_proxy_credential_owner,
            )
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SavedHostConnectionProjectionError {
    InvalidHostMetadata,
    InvalidProjectedMetadata,
    MissingCredentialProvenance,
}

impl fmt::Display for SavedHostConnectionProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidHostMetadata => "saved host connection metadata is invalid",
            Self::InvalidProjectedMetadata => "effective saved host connection metadata is invalid",
            Self::MissingCredentialProvenance => {
                "effective saved host credential provenance is invalid"
            }
        })
    }
}

impl std::error::Error for SavedHostConnectionProjectionError {}

/// Applies one host's root-to-leaf GroupConfig chain without reading any
/// credential body or mutating the durable host record.
///
/// Normalized `SavedHost` core fields are concrete rather than optional, so
/// hostname, port, protocol, and auth method are treated as explicit host
/// values. An empty host username retains the legacy "inherit" behavior.
/// Optional connection metadata continues to distinguish missing/null/empty,
/// including the legacy explicit-empty identity markers.
pub fn project_saved_host_connection(
    host: &SavedHost,
    group_configs: &[SavedGroupConfig],
) -> Result<SavedHostConnectionProjection, SavedHostConnectionProjectionError> {
    let is_primary_telnet = host.protocol.is_telnet();
    let is_primary_serial = host.protocol.is_serial();
    let has_inactive_ssh_relationships = is_primary_telnet || is_primary_serial;
    let resolved = match host
        .group_path()
        .map_err(|_| SavedHostConnectionProjectionError::InvalidHostMetadata)?
    {
        Some(path) => resolve_group_defaults_with_provenance(&path, group_configs),
        None => ResolvedSavedGroupDefaults::default(),
    };

    // Validate relationship-shaped fields before deciding whether a group
    // proxy may be inherited. A malformed host inline/profile marker must
    // remain a fail-closed host error; it may never turn into a silent group
    // fallback.
    let parsed_host_inline_proxy = host
        .proxy_config()
        .map_err(|_| SavedHostConnectionProjectionError::InvalidHostMetadata)?;
    host.proxy_profile_id()
        .map_err(|_| SavedHostConnectionProjectionError::InvalidHostMetadata)?;

    let mut fields = host.compatibility_fields().clone();
    let mut effective_username = host.username.clone();

    let host_has_saved_ssh_credential = boolean_field(&fields, "hasSavedCredential");
    let mut ssh_credential_owner = (!has_inactive_ssh_relationships
        && host_has_saved_ssh_credential)
        .then(|| SavedHostConnectionCredentialOwner::Host(host.id.clone()));

    let mut telnet_credential_owner =
        if host.protocol.as_str().eq_ignore_ascii_case("telnet") && host_has_saved_ssh_credential {
            Some(SavedHostConnectionCredentialOwner::Host(host.id.clone()))
        } else {
            None
        };

    let mut inline_proxy_credential_owner = parsed_host_inline_proxy
        .filter(|_| !has_inactive_ssh_relationships)
        .filter(inline_proxy_has_saved_manual_credential)
        .map(|_| SavedHostConnectionCredentialOwner::Host(host.id.clone()));

    if !has_inactive_ssh_relationships {
        apply_ssh_defaults(
            host,
            &resolved,
            &mut fields,
            &mut effective_username,
            &mut ssh_credential_owner,
        )?;
    }
    if !is_primary_serial {
        apply_telnet_defaults(host, &resolved, &mut fields, &mut telnet_credential_owner)?;
    }
    if !has_inactive_ssh_relationships {
        apply_proxy_defaults(&resolved, &mut fields, &mut inline_proxy_credential_owner)?;
    }
    apply_non_credential_defaults(
        &resolved.defaults,
        &mut fields,
        !has_inactive_ssh_relationships,
    )?;

    let mut effective_host = host
        .with_projected_compatibility_fields(fields)
        .map_err(|_| SavedHostConnectionProjectionError::InvalidProjectedMetadata)?;
    effective_host.username = effective_username;
    effective_host
        .validate()
        .map_err(|_| SavedHostConnectionProjectionError::InvalidProjectedMetadata)?;
    let host_chain_ids = if has_inactive_ssh_relationships {
        Vec::new()
    } else {
        parse_effective_host_chain(effective_host.compatibility_fields().get("hostChain"))?
    };

    Ok(SavedHostConnectionProjection {
        effective_host,
        resolved_group_defaults: resolved.defaults,
        host_chain_ids,
        ssh_credential_owner,
        telnet_credential_owner,
        inline_proxy_credential_owner,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacySavedHostChainWire {
    host_ids: SavedGroupHostChain,
}

fn parse_effective_host_chain(
    value: Option<&Value>,
) -> Result<Vec<SavedHostId>, SavedHostConnectionProjectionError> {
    let chain_result = match value {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(value @ Value::Object(_)) => {
            serde_json::from_value::<LegacySavedHostChainWire>(value.clone())
                .map(|wire| wire.host_ids)
        }
        // GroupConfig keeps a typed transparent list internally. Projection
        // accepts that normalized representation as well as legacy host JSON.
        Some(value @ Value::Array(_)) => {
            serde_json::from_value::<SavedGroupHostChain>(value.clone())
        }
        Some(_) => return Err(SavedHostConnectionProjectionError::InvalidHostMetadata),
    };
    let chain =
        chain_result.map_err(|_| SavedHostConnectionProjectionError::InvalidHostMetadata)?;
    Ok(chain.host_ids().to_vec())
}

fn apply_ssh_defaults(
    host: &SavedHost,
    resolved: &ResolvedSavedGroupDefaults,
    fields: &mut BTreeMap<String, Value>,
    effective_username: &mut String,
    credential_owner: &mut Option<SavedHostConnectionCredentialOwner>,
) -> Result<(), SavedHostConnectionProjectionError> {
    let defaults = &resolved.defaults;
    let host_identity_selected = fields.get("identityId").is_some_and(js_truthy);
    let host_identity_explicitly_empty = matches!(
        fields.get("identityId"),
        Some(Value::String(value)) if value.is_empty()
    );
    let host_username = host.username.trim();
    let host_has_manual_ssh_credentials = !host_identity_selected
        && ((!host_username.is_empty() && host_username != "root")
            // Current-policy hosts carry an explicit authentication choice.
            // Legacy unversioned hosts may still inherit a group identity,
            // matching the old `authPolicyVersion === 1` guard exactly.
            || host.auth_policy_version == 1
            || boolean_field(fields, "hasSavedCredential")
            || matches!(fields.get("savePassword"), Some(Value::Bool(false)))
            || fields.get("identityFileId").is_some_and(js_truthy)
            || fields
                .get("identityFilePaths")
                .is_some_and(has_non_empty_length));
    let group_selects_identity = matches!(defaults.identity_id, SavedGroupOverride::Set(_));
    let skip_group_ssh_bundle = host_identity_selected
        || (group_selects_identity
            && (host_identity_explicitly_empty || host_has_manual_ssh_credentials));

    if skip_group_ssh_bundle {
        return Ok(());
    }

    if effective_username.is_empty() {
        if let SavedGroupOverride::Set(username) = &defaults.username {
            *effective_username = username.as_str().to_owned();
        }
    }

    let host_blocks_group_password = boolean_field(fields, "hasSavedCredential")
        || matches!(fields.get("savePassword"), Some(Value::Bool(false)));
    if !host_blocks_group_password && !matches!(defaults.identity_id, SavedGroupOverride::Set(_)) {
        match defaults.password {
            SavedGroupCredentialOverride::Inherit | SavedGroupCredentialOverride::Clear => {}
            SavedGroupCredentialOverride::StoredHint => {
                let owner = resolved
                    .ssh_credential_owner
                    .as_ref()
                    .ok_or(SavedHostConnectionProjectionError::MissingCredentialProvenance)?;
                fields.insert("hasSavedCredential".to_owned(), Value::Bool(true));
                *credential_owner = Some(SavedHostConnectionCredentialOwner::Group(owner.clone()));
            }
        }
    }

    apply_serialized_override(fields, "savePassword", &defaults.save_password, false)?;
    apply_identity_override(fields, &defaults.identity_id)?;
    apply_serialized_override(fields, "identityFileId", &defaults.identity_file_id, false)?;
    apply_serialized_override(
        fields,
        "identityFilePaths",
        &defaults.identity_file_paths,
        false,
    )?;
    Ok(())
}

fn apply_identity_override(
    fields: &mut BTreeMap<String, Value>,
    value: &SavedGroupOverride<SavedGroupIdentityReference>,
) -> Result<(), SavedHostConnectionProjectionError> {
    if !field_inherits(fields.get("identityId"), true) {
        return Ok(());
    }
    match value {
        SavedGroupOverride::Inherit => {}
        SavedGroupOverride::Clear => {
            fields.remove("identityId");
        }
        SavedGroupOverride::Set(SavedGroupIdentityReference::Key(id)) => {
            fields.insert(
                "identityId".to_owned(),
                Value::String(id.as_str().to_owned()),
            );
        }
        SavedGroupOverride::Set(SavedGroupIdentityReference::Password(id)) => {
            fields.insert(
                "identityId".to_owned(),
                Value::String(id.as_str().to_owned()),
            );
        }
    }
    Ok(())
}

fn apply_telnet_defaults(
    host: &SavedHost,
    resolved: &ResolvedSavedGroupDefaults,
    fields: &mut BTreeMap<String, Value>,
    credential_owner: &mut Option<SavedHostConnectionCredentialOwner>,
) -> Result<(), SavedHostConnectionProjectionError> {
    let defaults = &resolved.defaults;
    let host_telnet_identity = fields.get("telnetIdentityId").is_some_and(js_truthy);
    let host_username = host.username.trim();
    let primary_telnet_manual = host.protocol.as_str().eq_ignore_ascii_case("telnet")
        && ((!host_username.is_empty() && host_username != "root")
            || boolean_field(fields, "hasSavedCredential")
            || matches!(fields.get("savePassword"), Some(Value::Bool(false))));
    let host_telnet_manual = !host_telnet_identity
        && (fields.contains_key("telnetUsername")
            || fields.contains_key("telnetPassword")
            || primary_telnet_manual);

    if !host_telnet_manual {
        apply_serialized_override(
            fields,
            "telnetIdentityId",
            &defaults.telnet_identity_id,
            true,
        )?;
    }
    apply_serialized_override(fields, "telnetUsername", &defaults.telnet_username, true)?;

    if credential_owner.is_none()
        && !host_telnet_manual
        && !matches!(defaults.telnet_identity_id, SavedGroupOverride::Set(_))
        && matches!(
            defaults.telnet_password,
            SavedGroupCredentialOverride::StoredHint
        )
    {
        let owner = resolved
            .telnet_credential_owner
            .as_ref()
            .ok_or(SavedHostConnectionProjectionError::MissingCredentialProvenance)?;
        *credential_owner = Some(SavedHostConnectionCredentialOwner::Group(owner.clone()));
    }
    Ok(())
}

fn apply_proxy_defaults(
    resolved: &ResolvedSavedGroupDefaults,
    fields: &mut BTreeMap<String, Value>,
    credential_owner: &mut Option<SavedHostConnectionCredentialOwner>,
) -> Result<(), SavedHostConnectionProjectionError> {
    let host_inline_property_present = fields.contains_key("proxyConfig");
    let host_profile_property_present = fields.contains_key("proxyProfileId");
    let inline_inherits = field_inherits(fields.get("proxyConfig"), false);
    let profile_inherits = field_inherits(fields.get("proxyProfileId"), false);

    match &resolved.defaults.proxy {
        SavedGroupProxyOverride::Inherit => {}
        SavedGroupProxyOverride::Clear => {
            // `Clear` means that this group contributes no proxy value. The
            // host's own null/empty marker is still an explicit legacy field
            // and must not be erased merely because no group value remains.
            *credential_owner = None;
        }
        SavedGroupProxyOverride::Profile(profile_id) => {
            if !host_inline_property_present && profile_inherits {
                fields.remove("proxyConfig");
                fields.insert(
                    "proxyProfileId".to_owned(),
                    Value::String(profile_id.as_str().to_owned()),
                );
                *credential_owner = None;
            }
        }
        SavedGroupProxyOverride::Inline(config) => {
            if !host_profile_property_present && inline_inherits {
                fields.remove("proxyProfileId");
                fields.insert(
                    "proxyConfig".to_owned(),
                    serde_json::to_value(config).map_err(|_| {
                        SavedHostConnectionProjectionError::InvalidProjectedMetadata
                    })?,
                );
                *credential_owner = if inline_proxy_has_saved_manual_credential(config) {
                    let owner = resolved
                        .inline_proxy_credential_owner
                        .as_ref()
                        .ok_or(SavedHostConnectionProjectionError::MissingCredentialProvenance)?;
                    Some(SavedHostConnectionCredentialOwner::Group(owner.clone()))
                } else {
                    None
                };
            }
        }
    }
    Ok(())
}

fn apply_non_credential_defaults(
    defaults: &SavedGroupDefaults,
    fields: &mut BTreeMap<String, Value>,
    include_host_chain: bool,
) -> Result<(), SavedHostConnectionProjectionError> {
    macro_rules! apply {
        ($key:literal, $field:ident) => {
            apply_serialized_override(fields, $key, &defaults.$field, false)?
        };
        ($key:literal, $field:ident, empty_is_explicit) => {
            apply_serialized_override(fields, $key, &defaults.$field, true)?
        };
    }

    apply!("deviceType", device_type);
    apply!("agentForwarding", agent_forwarding);
    if include_host_chain {
        apply!("hostChain", host_chain);
    }
    apply!("startupCommand", startup_command);
    apply!("startupCommandRunMode", startup_command_run_mode);
    apply!("loginScriptId", login_script_id);
    apply!("legacyAlgorithms", legacy_algorithms);
    apply!("skipEcdsaHostKey", skip_ecdsa_host_key);
    apply!("algorithms", algorithms);
    apply!("environmentVariables", environment_variables);
    apply!("charset", charset);
    apply!("moshEnabled", mosh_enabled);
    apply!("moshServerPath", mosh_server_path);
    apply!("etEnabled", et_enabled);
    apply!("etPort", et_port);
    apply!("telnetEnabled", telnet_enabled);
    apply!("telnetPort", telnet_port);
    apply!("theme", theme);
    apply!("themeOverride", theme_override);
    apply!("fontFamily", font_family);
    apply!("fontFamilyOverride", font_family_override);
    apply!("fontSize", font_size);
    apply!("fontSizeOverride", font_size_override);
    apply!("fontWeight", font_weight);
    apply!("fontWeightOverride", font_weight_override);
    apply!("backspaceBehavior", backspace_behavior);
    Ok(())
}

fn apply_serialized_override<T: Serialize>(
    fields: &mut BTreeMap<String, Value>,
    key: &'static str,
    value: &SavedGroupOverride<T>,
    empty_is_explicit: bool,
) -> Result<(), SavedHostConnectionProjectionError> {
    if !field_inherits(fields.get(key), empty_is_explicit) {
        return Ok(());
    }
    match value {
        SavedGroupOverride::Inherit => {}
        SavedGroupOverride::Clear => {
            fields.remove(key);
        }
        SavedGroupOverride::Set(value) => {
            fields.insert(
                key.to_owned(),
                serde_json::to_value(value)
                    .map_err(|_| SavedHostConnectionProjectionError::InvalidProjectedMetadata)?,
            );
        }
    }
    Ok(())
}

fn field_inherits(value: Option<&Value>, empty_is_explicit: bool) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::String(value)) if value.is_empty() && !empty_is_explicit => true,
        Some(_) => false,
    }
}

fn boolean_field(fields: &BTreeMap<String, Value>, key: &str) -> bool {
    fields.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn has_non_empty_length(value: &Value) -> bool {
    match value {
        Value::Array(values) => !values.is_empty(),
        Value::String(value) => !value.is_empty(),
        _ => false,
    }
}

fn js_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

fn inline_proxy_has_saved_manual_credential(config: &SavedProxyConfig) -> bool {
    matches!(
        config,
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
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::group::SavedGroupPath;
    use crate::group_config::{
        SavedGroupAuthMethod, SavedGroupBackspaceBehavior, SavedGroupPort, SavedGroupProtocol,
        SavedGroupSingleLineText, SavedGroupText,
    };
    use crate::model::{
        SavedHostDraft, SavedIdentityReferenceId, SavedProxyProfileId, SavedSshKeyReferenceId,
    };
    use crate::serial::{SavedSerialBackspaceBehavior, SavedSerialConfig};

    fn path(value: &str) -> SavedGroupPath {
        SavedGroupPath::new(value).expect("group path")
    }

    fn text(value: &str) -> SavedGroupSingleLineText {
        SavedGroupSingleLineText::new(value).expect("single-line text")
    }

    fn group(id: &str, path_value: &str, defaults: SavedGroupDefaults) -> SavedGroupConfig {
        SavedGroupConfig::from_parts(
            SavedGroupId::from_opaque(id).expect("group ID"),
            1,
            path(path_value),
            defaults,
            1,
            1,
        )
        .expect("group config")
    }

    fn host(username: &str, group_path: &str) -> SavedHost {
        SavedHost::from_draft(
            SavedHostDraft::ssh_password("host.example.test", username)
                .with_group_path(path(group_path)),
            10,
        )
        .expect("saved host")
    }

    #[test]
    fn primary_telnet_projection_keeps_but_does_not_activate_ssh_relationship_fields() {
        let host = SavedHost::from_draft(
            SavedHostDraft::telnet("console.example.test", "")
                .with_compatibility_field("hasSavedCredential", json!(true))
                .expect("Telnet credential hint")
                .with_compatibility_field("identityId", json!({"legacy": "shape"}))
                .expect("legacy identity field")
                .with_compatibility_field("proxyConfig", json!("legacy-invalid-proxy"))
                .expect("legacy proxy field")
                .with_compatibility_field("hostChain", json!({"legacy": "shape"}))
                .expect("legacy jump field"),
            10,
        )
        .expect("Telnet host");

        let projection = project_saved_host_connection(&host, &[]).expect("Telnet projection");
        assert!(projection.effective_host().protocol.is_telnet());
        assert!(projection.effective_host().username.is_empty());
        assert!(projection.host_chain_ids().is_empty());
        assert!(projection.ssh_credential_owner().is_none());
        assert!(projection.inline_proxy_credential_owner().is_none());
        assert!(projection.telnet_credential_owner().is_some());
        assert_eq!(
            projection
                .effective_host()
                .compatibility_fields()
                .get("proxyConfig"),
            Some(&json!("legacy-invalid-proxy"))
        );
        assert!(
            projection
                .effective_host()
                .proxy_config()
                .expect("inactive proxy")
                .is_none()
        );
    }

    #[test]
    fn primary_serial_projection_inherits_charset_and_backspace_but_no_network_credentials() {
        let serial = SavedHost::from_draft(
            SavedHostDraft::serial(
                SavedSerialConfig::new("/tmp/serial link", 921_600).expect("Serial config"),
            )
            .expect("Serial draft")
            .with_group_path(path("Lab/Console"))
            .with_compatibility_field("identityId", json!({"legacy": "shape"}))
            .expect("dormant SSH identity")
            .with_compatibility_field("proxyConfig", json!("legacy-invalid-proxy"))
            .expect("dormant SSH proxy")
            .with_compatibility_field("hostChain", json!({"legacy": "shape"}))
            .expect("dormant jump chain"),
            10,
        )
        .expect("Serial host");
        let configs = vec![group(
            "serial-group",
            "Lab/Console",
            SavedGroupDefaults {
                username: SavedGroupOverride::Set(text("must-not-become-serial-username")),
                password: SavedGroupCredentialOverride::StoredHint,
                telnet_username: SavedGroupOverride::Set(text("must-not-become-telnet-user")),
                telnet_password: SavedGroupCredentialOverride::StoredHint,
                charset: SavedGroupOverride::Set(text("GBK")),
                backspace_behavior: SavedGroupOverride::Set(SavedGroupBackspaceBehavior::CtrlH),
                ..SavedGroupDefaults::default()
            },
        )];

        let projection =
            project_saved_host_connection(&serial, &configs).expect("Serial projection");
        let effective = projection.effective_host();
        assert!(effective.protocol.is_serial());
        assert!(effective.username.is_empty());
        assert!(projection.host_chain_ids().is_empty());
        assert!(projection.ssh_credential_owner().is_none());
        assert!(projection.telnet_credential_owner().is_none());
        assert!(projection.inline_proxy_credential_owner().is_none());
        assert!(
            !effective
                .compatibility_fields()
                .contains_key("hasSavedCredential")
        );
        assert!(
            !effective
                .compatibility_fields()
                .contains_key("telnetUsername")
        );
        assert_eq!(
            effective.compatibility_fields().get("charset"),
            Some(&json!("GBK"))
        );
        assert_eq!(
            effective
                .effective_serial_config()
                .expect("effective Serial config")
                .backspace_behavior,
            Some(SavedSerialBackspaceBehavior::CtrlH)
        );
    }

    #[test]
    fn parses_legacy_effective_host_chain_in_connection_order() {
        let host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("host.example.test", "alice")
                .with_compatibility_field(
                    "hostChain",
                    json!({ "hostIds": ["nearest-jump", "furthest-jump"] }),
                )
                .expect("host chain"),
            10,
        )
        .expect("saved host");

        let projection = project_saved_host_connection(&host, &[]).expect("connection projection");
        assert_eq!(
            projection
                .host_chain_ids()
                .iter()
                .map(SavedHostId::as_str)
                .collect::<Vec<_>>(),
            vec!["nearest-jump", "furthest-jump"]
        );
    }

    #[test]
    fn parses_inherited_group_host_chain_in_connection_order() {
        let defaults = SavedGroupDefaults {
            host_chain: SavedGroupOverride::Set(
                SavedGroupHostChain::new(vec![
                    SavedHostId::from_opaque("group-nearest").expect("host ID"),
                    SavedHostId::from_opaque("group-furthest").expect("host ID"),
                ])
                .expect("host chain"),
            ),
            ..SavedGroupDefaults::default()
        };
        let projection = project_saved_host_connection(
            &host("alice", "A/B"),
            &[group("chain-owner", "A", defaults)],
        )
        .expect("connection projection");

        assert_eq!(
            projection
                .host_chain_ids()
                .iter()
                .map(SavedHostId::as_str)
                .collect::<Vec<_>>(),
            vec!["group-nearest", "group-furthest"]
        );
    }

    #[test]
    fn malformed_effective_host_chain_fails_the_complete_projection() {
        for host_chain in [
            json!("jump-host"),
            json!({ "hostIds": ["jump-host"], "unexpected": true }),
            json!({ "hostIds": [""] }),
        ] {
            let host = SavedHost::from_draft(
                SavedHostDraft::ssh_password("host.example.test", "alice")
                    .with_compatibility_field("hostChain", host_chain)
                    .expect("compatibility field"),
                10,
            )
            .expect("saved host");
            assert_eq!(
                project_saved_host_connection(&host, &[]),
                Err(SavedHostConnectionProjectionError::InvalidHostMetadata)
            );
        }
    }

    #[test]
    fn projects_root_to_leaf_defaults_and_keeps_ancestor_ssh_owner() {
        let parent_id = "parent-credential-owner";
        let configs = vec![
            group(
                parent_id,
                "A",
                SavedGroupDefaults {
                    username: SavedGroupOverride::Set(text("parent-user")),
                    password: SavedGroupCredentialOverride::StoredHint,
                    agent_forwarding: SavedGroupOverride::Set(true),
                    ..SavedGroupDefaults::default()
                },
            ),
            group(
                "child-record",
                "A/B",
                SavedGroupDefaults {
                    username: SavedGroupOverride::Set(text("child-user")),
                    charset: SavedGroupOverride::Set(text("utf-8")),
                    ..SavedGroupDefaults::default()
                },
            ),
        ];
        let original = host("", "A/B/C");

        let projection =
            project_saved_host_connection(&original, &configs).expect("connection projection");
        let effective = projection.effective_host();

        assert_eq!(effective.username, "child-user");
        assert_eq!(
            effective.compatibility_fields().get("agentForwarding"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            effective.compatibility_fields().get("charset"),
            Some(&Value::String("utf-8".to_owned()))
        );
        assert_eq!(
            effective.compatibility_fields().get("hasSavedCredential"),
            Some(&Value::Bool(true))
        );
        assert_eq!(original.username, "");
        assert!(
            !original
                .compatibility_fields()
                .contains_key("hasSavedCredential")
        );
        assert_eq!(
            projection
                .ssh_credential_owner()
                .and_then(SavedHostConnectionCredentialOwner::group_id)
                .map(SavedGroupId::as_str),
            Some(parent_id)
        );
    }

    #[test]
    fn explicit_host_metadata_and_host_credential_win_over_group_values() {
        let host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("host.example.test", "host-user")
                .with_group_path(path("A"))
                .with_compatibility_field("hasSavedCredential", json!(true))
                .expect("host credential hint")
                .with_compatibility_field("identityFileId", json!("host-key"))
                .expect("host key relationship"),
            10,
        )
        .expect("saved host");
        let configs = vec![group(
            "group-owner",
            "A",
            SavedGroupDefaults {
                username: SavedGroupOverride::Set(text("group-user")),
                password: SavedGroupCredentialOverride::StoredHint,
                identity_file_id: SavedGroupOverride::Set(
                    SavedSshKeyReferenceId::from_opaque("group-key").expect("key ID"),
                ),
                agent_forwarding: SavedGroupOverride::Set(true),
                ..SavedGroupDefaults::default()
            },
        )];

        let projection =
            project_saved_host_connection(&host, &configs).expect("connection projection");
        let effective = projection.effective_host();
        assert_eq!(effective.username, "host-user");
        assert_eq!(
            effective.compatibility_fields().get("identityFileId"),
            Some(&json!("host-key"))
        );
        assert_eq!(
            projection
                .ssh_credential_owner()
                .and_then(SavedHostConnectionCredentialOwner::host_id),
            Some(&host.id)
        );
        assert_eq!(
            effective.compatibility_fields().get("agentForwarding"),
            Some(&json!(true))
        );
    }

    #[test]
    fn selected_host_identity_skips_the_complete_group_ssh_bundle() {
        let host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("host.example.test", "")
                .with_group_path(path("A"))
                .with_compatibility_field("identityId", json!("host-identity"))
                .expect("host identity"),
            10,
        )
        .expect("saved host");
        let configs = vec![group(
            "group-owner",
            "A",
            SavedGroupDefaults {
                username: SavedGroupOverride::Set(text("group-user")),
                password: SavedGroupCredentialOverride::StoredHint,
                save_password: SavedGroupOverride::Set(true),
                identity_file_id: SavedGroupOverride::Set(
                    SavedSshKeyReferenceId::from_opaque("group-key").expect("key ID"),
                ),
                ..SavedGroupDefaults::default()
            },
        )];

        let projection =
            project_saved_host_connection(&host, &configs).expect("connection projection");
        let effective = projection.effective_host();
        assert_eq!(effective.username, "");
        assert_eq!(
            effective.compatibility_fields().get("identityId"),
            Some(&json!("host-identity"))
        );
        assert!(
            !effective
                .compatibility_fields()
                .contains_key("hasSavedCredential")
        );
        assert!(
            !effective
                .compatibility_fields()
                .contains_key("identityFileId")
        );
        assert_eq!(projection.ssh_credential_owner(), None);
    }

    #[test]
    fn an_unversioned_default_password_host_inherits_group_identity() {
        let mut host_value = serde_json::to_value(host("root", "A")).expect("host JSON");
        host_value["authPolicyVersion"] = json!(0);
        let host: SavedHost = serde_json::from_value(host_value).expect("legacy host");
        let config = group(
            "identity-owner",
            "A",
            SavedGroupDefaults {
                identity_id: SavedGroupOverride::Set(SavedGroupIdentityReference::Password(
                    crate::model::SavedPasswordIdentityId::from_opaque("shared-password")
                        .expect("password identity"),
                )),
                username: SavedGroupOverride::Set(text("identity-user")),
                ..SavedGroupDefaults::default()
            },
        );

        let projection =
            project_saved_host_connection(&host, &[config]).expect("identity projection");
        assert_eq!(
            projection
                .effective_host()
                .compatibility_fields()
                .get("identityId"),
            Some(&json!("shared-password"))
        );
        // Legacy applyGroupDefaults treats the default root username as a
        // non-manual credential signal for identity selection, but the later
        // field-by-field pass still preserves the concrete host username.
        assert_eq!(projection.effective_host().username, "root");
    }

    #[test]
    fn a_current_policy_password_choice_blocks_group_identity() {
        let host = host("root", "A");
        let config = group(
            "identity-owner",
            "A",
            SavedGroupDefaults {
                identity_id: SavedGroupOverride::Set(SavedGroupIdentityReference::Password(
                    crate::model::SavedPasswordIdentityId::from_opaque("shared-password")
                        .expect("password identity"),
                )),
                ..SavedGroupDefaults::default()
            },
        );

        let projection =
            project_saved_host_connection(&host, &[config]).expect("identity projection");
        assert!(
            !projection
                .effective_host()
                .compatibility_fields()
                .contains_key("identityId")
        );
    }

    #[test]
    fn explicit_empty_identity_inherits_manual_group_credentials_but_not_group_identity() {
        let host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("host.example.test", "")
                .with_group_path(path("A"))
                .with_compatibility_field("identityId", json!(""))
                .expect("explicit identity clear"),
            10,
        )
        .expect("saved host");
        let manual = group(
            "manual-owner",
            "A",
            SavedGroupDefaults {
                username: SavedGroupOverride::Set(text("group-user")),
                password: SavedGroupCredentialOverride::StoredHint,
                ..SavedGroupDefaults::default()
            },
        );
        let projected = project_saved_host_connection(&host, &[manual]).expect("manual defaults");
        assert_eq!(projected.effective_host().username, "group-user");
        assert_eq!(
            projected
                .effective_host()
                .compatibility_fields()
                .get("identityId"),
            Some(&json!(""))
        );
        assert!(projected.ssh_credential_owner().is_some());

        let group_identity = group(
            "identity-record",
            "A",
            SavedGroupDefaults {
                identity_id: SavedGroupOverride::Set(SavedGroupIdentityReference::Key(
                    SavedIdentityReferenceId::from_opaque("group-identity").expect("identity ID"),
                )),
                ..SavedGroupDefaults::default()
            },
        );
        let projected =
            project_saved_host_connection(&host, &[group_identity]).expect("identity defaults");
        assert_eq!(
            projected
                .effective_host()
                .compatibility_fields()
                .get("identityId"),
            Some(&json!(""))
        );
    }

    #[test]
    fn child_clear_removes_ancestor_credential_and_metadata_defaults() {
        let original = host("", "A/B");
        let configs = vec![
            group(
                "parent-owner",
                "A",
                SavedGroupDefaults {
                    password: SavedGroupCredentialOverride::StoredHint,
                    startup_command: SavedGroupOverride::Set(
                        SavedGroupText::new("parent command").expect("command"),
                    ),
                    ..SavedGroupDefaults::default()
                },
            ),
            group(
                "child-record",
                "A/B",
                SavedGroupDefaults {
                    password: SavedGroupCredentialOverride::Clear,
                    startup_command: SavedGroupOverride::Clear,
                    ..SavedGroupDefaults::default()
                },
            ),
        ];

        let projection =
            project_saved_host_connection(&original, &configs).expect("connection projection");
        assert_eq!(projection.ssh_credential_owner(), None);
        assert!(
            !projection
                .effective_host()
                .compatibility_fields()
                .contains_key("hasSavedCredential")
        );
        assert!(
            !projection
                .effective_host()
                .compatibility_fields()
                .contains_key("startupCommand")
        );
    }

    #[test]
    fn inherited_inline_proxy_uses_group_owner_while_host_inline_proxy_wins() {
        let group_proxy =
            SavedProxyConfig::http("group-proxy.example.test", 8080, None, "group-user", true)
                .expect("group proxy");
        let configs = vec![group(
            "proxy-group-owner",
            "A",
            SavedGroupDefaults {
                proxy: SavedGroupProxyOverride::Inline(group_proxy),
                ..SavedGroupDefaults::default()
            },
        )];

        let inherited = project_saved_host_connection(&host("host-user", "A"), &configs)
            .expect("group proxy projection");
        assert!(matches!(
            inherited.effective_host().proxy_config(),
            Ok(Some(SavedProxyConfig::Http { ref host, .. }))
                if host == "group-proxy.example.test"
        ));
        assert_eq!(
            inherited
                .inline_proxy_credential_owner()
                .and_then(SavedHostConnectionCredentialOwner::group_id)
                .map(SavedGroupId::as_str),
            Some("proxy-group-owner")
        );

        let host_proxy =
            SavedProxyConfig::socks5("host-proxy.example.test", 1080, None, "host-user", true)
                .expect("host proxy");
        let explicit_host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("host.example.test", "host-user")
                .with_group_path(path("A"))
                .with_proxy_config(host_proxy)
                .expect("inline host proxy"),
            10,
        )
        .expect("saved host");
        let explicit =
            project_saved_host_connection(&explicit_host, &configs).expect("host proxy projection");
        assert!(matches!(
            explicit.effective_host().proxy_config(),
            Ok(Some(SavedProxyConfig::Socks5 { ref host, .. }))
                if host == "host-proxy.example.test"
        ));
        assert_eq!(
            explicit
                .inline_proxy_credential_owner()
                .and_then(SavedHostConnectionCredentialOwner::host_id),
            Some(&explicit_host.id)
        );
    }

    #[test]
    fn explicit_host_profile_blocks_inherited_inline_proxy() {
        let profile_id = SavedProxyProfileId::from_opaque("host-profile").expect("profile ID");
        let host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("host.example.test", "host-user")
                .with_group_path(path("A"))
                .with_proxy_profile_id(profile_id.clone())
                .expect("host profile"),
            10,
        )
        .expect("saved host");
        let group_proxy =
            SavedProxyConfig::http("group-proxy.example.test", 8080, None, "group-user", true)
                .expect("group proxy");
        let config = group(
            "group-owner",
            "A",
            SavedGroupDefaults {
                proxy: SavedGroupProxyOverride::Inline(group_proxy),
                ..SavedGroupDefaults::default()
            },
        );

        let projection =
            project_saved_host_connection(&host, &[config]).expect("connection projection");
        assert_eq!(
            projection.effective_host().proxy_profile_id(),
            Ok(Some(profile_id))
        );
        assert_eq!(projection.effective_host().proxy_config(), Ok(None));
        assert_eq!(projection.inline_proxy_credential_owner(), None);
    }

    #[test]
    fn normalized_core_fields_are_explicit_and_merged_values_remain_inspectable() {
        let host = host("root", "A");
        let config = group(
            "core-defaults",
            "A",
            SavedGroupDefaults {
                port: SavedGroupOverride::Set(SavedGroupPort::new(2222).expect("port")),
                protocol: SavedGroupOverride::Set(SavedGroupProtocol::Telnet),
                auth_method: SavedGroupOverride::Set(SavedGroupAuthMethod::Key),
                ..SavedGroupDefaults::default()
            },
        );

        let projection =
            project_saved_host_connection(&host, &[config]).expect("connection projection");
        assert_eq!(projection.effective_host().port, 22);
        assert_eq!(projection.effective_host().protocol.as_str(), "ssh");
        assert_eq!(projection.effective_host().auth_method.as_str(), "password");
        assert_eq!(
            projection.resolved_group_defaults().port,
            SavedGroupOverride::Set(SavedGroupPort::new(2222).expect("port"))
        );
        assert_eq!(
            projection.resolved_group_defaults().protocol,
            SavedGroupOverride::Set(SavedGroupProtocol::Telnet)
        );
    }

    #[test]
    fn debug_output_never_reveals_owner_ids_or_effective_metadata() {
        let owner_id = "owner-id-must-not-appear";
        let config = group(
            owner_id,
            "A",
            SavedGroupDefaults {
                password: SavedGroupCredentialOverride::StoredHint,
                startup_command: SavedGroupOverride::Set(
                    SavedGroupText::new("metadata-must-not-appear").expect("command"),
                ),
                ..SavedGroupDefaults::default()
            },
        );
        let projection = project_saved_host_connection(&host("", "A"), &[config])
            .expect("connection projection");
        let debug = format!("{projection:?}");
        assert!(!debug.contains(owner_id));
        assert!(!debug.contains("metadata-must-not-appear"));
        assert!(debug.contains("Group"));
    }
}
