use std::collections::HashSet;
use std::fmt;

use netcatty_credentials::SecretValue;
use netcatty_vault::{
    SavedGroupAuthMethod, SavedGroupConfig, SavedGroupCredentialOverride, SavedGroupDefaults,
    SavedGroupId, SavedGroupIdentityReference, SavedGroupOpaqueId, SavedGroupOverride,
    SavedGroupPath, SavedGroupProxyOverride, SavedIdentityReferenceId, SavedPasswordIdentityId,
    SavedProxyProfileId, SavedSshKeyReferenceId,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{
    LegacyCredentialDisposition, LegacyProxyCredentialDisposition, MAX_LEGACY_CATALOG_ENTITIES,
};

const LEGACY_GROUP_ID_DOMAIN: &[u8] = b"netcatty-legacy-group-config-id-v1\0";

/// Stable, payload-free failure categories for strict legacy group parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LegacyGroupConfigParseErrorCode {
    InvalidCustomGroups,
    InvalidGroupConfigs,
    CatalogLimitExceeded,
    InvalidGroupPath,
    InvalidGroupConfig,
    UnknownGroupConfigField,
    ConflictingProxyOverrides,
}

/// A renderer-safe parse error. It never retains a path, field value, or secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyGroupConfigParseError {
    pub code: LegacyGroupConfigParseErrorCode,
    pub record_index: Option<u32>,
}

impl LegacyGroupConfigParseError {
    const fn catalog(code: LegacyGroupConfigParseErrorCode) -> Self {
        Self {
            code,
            record_index: None,
        }
    }

    fn record(code: LegacyGroupConfigParseErrorCode, index: usize) -> Self {
        Self {
            code,
            record_index: u32::try_from(index).ok(),
        }
    }
}

impl fmt::Display for LegacyGroupConfigParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.code {
            LegacyGroupConfigParseErrorCode::InvalidCustomGroups => {
                "legacy customGroups must be an array"
            }
            LegacyGroupConfigParseErrorCode::InvalidGroupConfigs => {
                "legacy groupConfigs must be an array"
            }
            LegacyGroupConfigParseErrorCode::CatalogLimitExceeded => {
                "legacy group catalog exceeds the record limit"
            }
            LegacyGroupConfigParseErrorCode::InvalidGroupPath => "legacy group path is invalid",
            LegacyGroupConfigParseErrorCode::InvalidGroupConfig => {
                "legacy group configuration is invalid"
            }
            LegacyGroupConfigParseErrorCode::UnknownGroupConfigField => {
                "legacy group configuration contains an unknown field"
            }
            LegacyGroupConfigParseErrorCode::ConflictingProxyOverrides => {
                "legacy group configuration contains conflicting proxy overrides"
            }
        })
    }
}

impl std::error::Error for LegacyGroupConfigParseError {}

/// Catalog knowledge needed to type legacy identity references without doing
/// graph assessment in this parser module. A non-password identity ID is kept
/// as a key/certificate identity reference; missing references are assessed by
/// the later graph slice.
pub struct LegacyGroupConfigReferences<'a> {
    available_identity_ids: &'a HashSet<String>,
    password_identity_ids: &'a HashSet<String>,
}

impl<'a> LegacyGroupConfigReferences<'a> {
    #[must_use]
    pub const fn new(
        available_identity_ids: &'a HashSet<String>,
        password_identity_ids: &'a HashSet<String>,
    ) -> Self {
        Self {
            available_identity_ids,
            password_identity_ids,
        }
    }
}

/// A validated group record plus three separately owned zeroizing credential
/// candidates. This type deliberately implements neither `Debug`, `Clone`,
/// nor Serde serialization.
///
/// ```compile_fail
/// use std::collections::HashSet;
/// use netcatty_migration::{LegacyGroupConfigReferences, parse_legacy_group_catalogs};
/// let ids = HashSet::new();
/// let parsed = parse_legacy_group_catalogs(
///     None,
///     Some(serde_json::json!([{"path":"A","password":"secret"}])),
///     &[0; 32],
///     1,
///     LegacyGroupConfigReferences::new(&ids, &ids),
/// ).unwrap();
/// println!("{:?}", parsed.group_configs().unwrap()[0]);
/// ```
///
/// ```compile_fail
/// use std::collections::HashSet;
/// use netcatty_migration::{LegacyGroupConfigReferences, parse_legacy_group_catalogs};
/// let ids = HashSet::new();
/// let parsed = parse_legacy_group_catalogs(
///     None,
///     Some(serde_json::json!([{"path":"A","password":"secret"}])),
///     &[0; 32],
///     1,
///     LegacyGroupConfigReferences::new(&ids, &ids),
/// ).unwrap();
/// let _ = serde_json::to_string(&parsed.group_configs().unwrap()[0]);
/// ```
pub struct LegacyGroupConfigCandidate {
    config: SavedGroupConfig,
    ssh_password: Option<SecretValue>,
    ssh_credential_disposition: LegacyCredentialDisposition,
    telnet_password: Option<SecretValue>,
    telnet_credential_disposition: LegacyCredentialDisposition,
    inline_proxy_password: Option<SecretValue>,
    inline_proxy_credential_disposition: LegacyProxyCredentialDisposition,
    unresolved_inline_proxy_identity: bool,
    secret_fields_stripped: u32,
}

impl LegacyGroupConfigCandidate {
    #[must_use]
    pub fn config(&self) -> &SavedGroupConfig {
        &self.config
    }

    #[must_use]
    pub const fn has_ssh_password_candidate(&self) -> bool {
        self.ssh_password.is_some()
    }

    #[must_use]
    pub const fn ssh_credential_disposition(&self) -> LegacyCredentialDisposition {
        self.ssh_credential_disposition
    }

    #[must_use]
    pub const fn has_telnet_password_candidate(&self) -> bool {
        self.telnet_password.is_some()
    }

    #[must_use]
    pub const fn telnet_credential_disposition(&self) -> LegacyCredentialDisposition {
        self.telnet_credential_disposition
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
    pub const fn has_unresolved_inline_proxy_identity(&self) -> bool {
        self.unresolved_inline_proxy_identity
    }

    #[must_use]
    pub const fn secret_fields_stripped(&self) -> u32 {
        self.secret_fields_stripped
    }

    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        SavedGroupConfig,
        Option<SecretValue>,
        LegacyCredentialDisposition,
        Option<SecretValue>,
        LegacyCredentialDisposition,
        Option<SecretValue>,
        LegacyProxyCredentialDisposition,
    ) {
        (
            self.config,
            self.ssh_password,
            self.ssh_credential_disposition,
            self.telnet_password,
            self.telnet_credential_disposition,
            self.inline_proxy_password,
            self.inline_proxy_credential_disposition,
        )
    }
}

/// Preserves catalog-level absence separately from a present empty array.
/// Like the contained candidates, this aggregate is intentionally not Debug,
/// Clone, or serializable.
pub struct LegacyGroupCatalogCandidates {
    custom_groups: Option<Vec<SavedGroupPath>>,
    group_configs: Option<Vec<LegacyGroupConfigCandidate>>,
}

impl LegacyGroupCatalogCandidates {
    pub(crate) const fn absent() -> Self {
        Self {
            custom_groups: None,
            group_configs: None,
        }
    }

    #[must_use]
    pub fn custom_groups(&self) -> Option<&[SavedGroupPath]> {
        self.custom_groups.as_deref()
    }

    #[must_use]
    pub fn group_configs(&self) -> Option<&[LegacyGroupConfigCandidate]> {
        self.group_configs.as_deref()
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Option<Vec<SavedGroupPath>>,
        Option<Vec<LegacyGroupConfigCandidate>>,
    ) {
        (self.custom_groups, self.group_configs)
    }
}

/// Strictly parses the two optional legacy Vault group catalog fields.
///
/// The caller removes these fields from the larger source object and transfers
/// ownership here. `None` means the catalog was absent; `Some([])` remains a
/// present, explicitly empty replacement catalog.
pub fn parse_legacy_group_catalogs(
    custom_groups: Option<Value>,
    group_configs: Option<Value>,
    source_sha256: &[u8; 32],
    now_ms: u64,
    references: LegacyGroupConfigReferences<'_>,
) -> Result<LegacyGroupCatalogCandidates, LegacyGroupConfigParseError> {
    let custom_groups = match parse_custom_groups(custom_groups) {
        Ok(custom_groups) => custom_groups,
        Err(error) => {
            super::zeroize_optional_value(group_configs);
            return Err(error);
        }
    };
    let group_configs = parse_group_configs(group_configs, source_sha256, now_ms, references)?;
    Ok(LegacyGroupCatalogCandidates {
        custom_groups,
        group_configs,
    })
}

fn parse_custom_groups(
    value: Option<Value>,
) -> Result<Option<Vec<SavedGroupPath>>, LegacyGroupConfigParseError> {
    let Some(mut value) = value else {
        return Ok(None);
    };
    let Value::Array(values) = value else {
        super::zeroize_value(&mut value);
        return Err(LegacyGroupConfigParseError::catalog(
            LegacyGroupConfigParseErrorCode::InvalidCustomGroups,
        ));
    };
    if values.len() > MAX_LEGACY_CATALOG_ENTITIES {
        let mut remaining = Value::Array(values);
        super::zeroize_value(&mut remaining);
        return Err(LegacyGroupConfigParseError::catalog(
            LegacyGroupConfigParseErrorCode::CatalogLimitExceeded,
        ));
    }

    let value_count = values.len();
    let mut paths = Vec::with_capacity(value_count);
    let mut values = values.into_iter();
    for index in 0..value_count {
        let Some(mut value) = values.next() else {
            break;
        };
        let Value::String(path) = value else {
            super::zeroize_value(&mut value);
            zeroize_remaining_values(values);
            return Err(LegacyGroupConfigParseError::record(
                LegacyGroupConfigParseErrorCode::InvalidGroupPath,
                index,
            ));
        };
        match SavedGroupPath::new(&path) {
            Ok(path) => paths.push(path),
            Err(_) => {
                let mut path = Value::String(path);
                super::zeroize_value(&mut path);
                zeroize_remaining_values(values);
                return Err(LegacyGroupConfigParseError::record(
                    LegacyGroupConfigParseErrorCode::InvalidGroupPath,
                    index,
                ));
            }
        }
    }
    Ok(Some(paths))
}

fn parse_group_configs(
    value: Option<Value>,
    source_sha256: &[u8; 32],
    now_ms: u64,
    references: LegacyGroupConfigReferences<'_>,
) -> Result<Option<Vec<LegacyGroupConfigCandidate>>, LegacyGroupConfigParseError> {
    let Some(mut value) = value else {
        return Ok(None);
    };
    let Value::Array(values) = value else {
        super::zeroize_value(&mut value);
        return Err(LegacyGroupConfigParseError::catalog(
            LegacyGroupConfigParseErrorCode::InvalidGroupConfigs,
        ));
    };
    if values.len() > MAX_LEGACY_CATALOG_ENTITIES {
        let mut remaining = Value::Array(values);
        super::zeroize_value(&mut remaining);
        return Err(LegacyGroupConfigParseError::catalog(
            LegacyGroupConfigParseErrorCode::CatalogLimitExceeded,
        ));
    }

    let value_count = values.len();
    let mut candidates = Vec::with_capacity(value_count);
    let mut values = values.into_iter();
    for index in 0..value_count {
        let Some(value) = values.next() else {
            break;
        };
        match parse_group_config(value, source_sha256, index, now_ms, &references) {
            Ok(candidate) => candidates.push(candidate),
            Err(code) => {
                zeroize_remaining_values(values);
                return Err(LegacyGroupConfigParseError::record(code, index));
            }
        }
    }
    Ok(Some(candidates))
}

fn zeroize_remaining_values(values: impl Iterator<Item = Value>) {
    for mut value in values {
        super::zeroize_value(&mut value);
    }
}

fn parse_group_config(
    mut value: Value,
    source_sha256: &[u8; 32],
    record_index: usize,
    now_ms: u64,
    references: &LegacyGroupConfigReferences<'_>,
) -> Result<LegacyGroupConfigCandidate, LegacyGroupConfigParseErrorCode> {
    let Value::Object(mut object) = value else {
        super::zeroize_value(&mut value);
        return Err(LegacyGroupConfigParseErrorCode::InvalidGroupConfig);
    };

    let result =
        parse_group_config_object(&mut object, source_sha256, record_index, now_ms, references);
    if result.is_err() {
        let mut remaining = Value::Object(object);
        super::zeroize_value(&mut remaining);
    }
    result
}

fn parse_group_config_object(
    object: &mut Map<String, Value>,
    source_sha256: &[u8; 32],
    record_index: usize,
    now_ms: u64,
    references: &LegacyGroupConfigReferences<'_>,
) -> Result<LegacyGroupConfigCandidate, LegacyGroupConfigParseErrorCode> {
    // Remove all credential-bearing values before ordinary field parsing.
    // Keep a zeroizing guard around them until each value is handed to a
    // consuming parser. This covers malformed non-secret fields and every
    // early-return path without dropping a legacy password-bearing JSON value.
    let mut protected = GroupSecretValueGuard {
        ssh_password: object.remove("password"),
        telnet_password: object.remove("telnetPassword"),
        inline_proxy: object.remove("proxyConfig"),
        proxy_profile: object.remove("proxyProfileId"),
    };

    let path = take_required_path(object)?;
    let save_password = object
        .get("savePassword")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let ssh_password_nonempty = protected
        .ssh_password
        .as_ref()
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty());
    let mut secret_fields_stripped = u32::from(protected.ssh_password.is_some())
        .saturating_add(u32::from(protected.telnet_password.is_some()));
    let (password, ssh_password, ssh_credential_disposition) =
        parse_credential_override(protected.ssh_password.take(), save_password);
    let (telnet_password, telnet_secret, telnet_credential_disposition) =
        parse_credential_override(protected.telnet_password.take(), true);

    let identity_id = take_identity_override(object, "identityId", references)?;
    let identity_file_id = take_id_override(object, "identityFileId", |value| {
        SavedSshKeyReferenceId::from_opaque(value).map_err(|_| ())
    })?;
    let identity_file_paths = take_override(object, "identityFilePaths")?;

    let (
        proxy,
        inline_proxy_password,
        inline_proxy_credential_disposition,
        unresolved_inline_proxy_identity,
        inline_proxy_secret_fields_stripped,
    ) = parse_proxy_override(
        protected.proxy_profile.take(),
        protected.inline_proxy.take(),
        references,
    )?;
    secret_fields_stripped =
        secret_fields_stripped.saturating_add(inline_proxy_secret_fields_stripped);

    let mut defaults = SavedGroupDefaults {
        order: take_override(object, "order")?,
        username: take_override(object, "username")?,
        password,
        save_password: take_override(object, "savePassword")?,
        auth_method: take_override(object, "authMethod")?,
        identity_id,
        identity_file_id,
        identity_file_paths,
        port: take_override(object, "port")?,
        protocol: take_override(object, "protocol")?,
        device_type: take_override(object, "deviceType")?,
        agent_forwarding: take_override(object, "agentForwarding")?,
        proxy,
        host_chain: take_host_chain_override(object)?,
        startup_command: take_override(object, "startupCommand")?,
        startup_command_run_mode: take_override(object, "startupCommandRunMode")?,
        login_script_id: take_id_override(object, "loginScriptId", |value| {
            SavedGroupOpaqueId::from_opaque(value).map_err(|_| ())
        })?,
        legacy_algorithms: take_override(object, "legacyAlgorithms")?,
        skip_ecdsa_host_key: take_override(object, "skipEcdsaHostKey")?,
        algorithms: take_override(object, "algorithms")?,
        environment_variables: take_override(object, "environmentVariables")?,
        charset: take_override(object, "charset")?,
        mosh_enabled: take_override(object, "moshEnabled")?,
        mosh_server_path: take_override(object, "moshServerPath")?,
        et_enabled: take_override(object, "etEnabled")?,
        et_port: take_override(object, "etPort")?,
        telnet_enabled: take_override(object, "telnetEnabled")?,
        telnet_port: take_override(object, "telnetPort")?,
        telnet_identity_id: take_id_override(object, "telnetIdentityId", |value| {
            SavedPasswordIdentityId::from_opaque(value).map_err(|_| ())
        })?,
        telnet_username: take_override(object, "telnetUsername")?,
        telnet_password,
        theme: take_override(object, "theme")?,
        theme_override: take_override(object, "themeOverride")?,
        font_family: take_override(object, "fontFamily")?,
        font_family_override: take_override(object, "fontFamilyOverride")?,
        font_size: take_override(object, "fontSize")?,
        font_size_override: take_override(object, "fontSizeOverride")?,
        font_weight: take_override(object, "fontWeight")?,
        font_weight_override: take_override(object, "fontWeightOverride")?,
        backspace_behavior: take_override(object, "backspaceBehavior")?,
    };

    migrate_deprecated_font_override(&mut defaults);
    infer_password_only_auth_method(&mut defaults, ssh_password_nonempty);

    if !object.is_empty() {
        return Err(LegacyGroupConfigParseErrorCode::UnknownGroupConfigField);
    }
    let id = derive_legacy_group_id(source_sha256, record_index, &path)?;
    let config = SavedGroupConfig::from_parts(id, 1, path, defaults, now_ms, now_ms)
        .map_err(|_| LegacyGroupConfigParseErrorCode::InvalidGroupConfig)?;
    Ok(LegacyGroupConfigCandidate {
        config,
        ssh_password,
        ssh_credential_disposition,
        telnet_password: telnet_secret,
        telnet_credential_disposition,
        inline_proxy_password,
        inline_proxy_credential_disposition,
        unresolved_inline_proxy_identity,
        secret_fields_stripped,
    })
}

fn derive_legacy_group_id(
    source_sha256: &[u8; 32],
    record_index: usize,
    path: &SavedGroupPath,
) -> Result<SavedGroupId, LegacyGroupConfigParseErrorCode> {
    let path = path.as_str().as_bytes();
    let record_index = u64::try_from(record_index)
        .map_err(|_| LegacyGroupConfigParseErrorCode::InvalidGroupConfig)?;
    let path_len = u64::try_from(path.len())
        .map_err(|_| LegacyGroupConfigParseErrorCode::InvalidGroupConfig)?;
    let mut digest = Sha256::new();
    digest.update(LEGACY_GROUP_ID_DOMAIN);
    digest.update(source_sha256);
    digest.update(record_index.to_be_bytes());
    digest.update(path_len.to_be_bytes());
    digest.update(path);
    SavedGroupId::from_opaque(format!("{:x}", digest.finalize()))
        .map_err(|_| LegacyGroupConfigParseErrorCode::InvalidGroupConfig)
}

/// Owns credential-bearing legacy JSON values while a group record is being
/// validated. Values transferred to a credential parser are taken out; any
/// value left on an error path is recursively zeroized in `Drop`.
struct GroupSecretValueGuard {
    ssh_password: Option<Value>,
    telnet_password: Option<Value>,
    inline_proxy: Option<Value>,
    proxy_profile: Option<Value>,
}

impl Drop for GroupSecretValueGuard {
    fn drop(&mut self) {
        super::zeroize_optional_value(self.ssh_password.take());
        super::zeroize_optional_value(self.telnet_password.take());
        super::zeroize_optional_value(self.inline_proxy.take());
        super::zeroize_optional_value(self.proxy_profile.take());
    }
}

fn take_required_path(
    object: &mut Map<String, Value>,
) -> Result<SavedGroupPath, LegacyGroupConfigParseErrorCode> {
    let Some(mut value) = object.remove("path") else {
        return Err(LegacyGroupConfigParseErrorCode::InvalidGroupPath);
    };
    let Value::String(path) = value else {
        super::zeroize_value(&mut value);
        return Err(LegacyGroupConfigParseErrorCode::InvalidGroupPath);
    };
    SavedGroupPath::new(path).map_err(|_| LegacyGroupConfigParseErrorCode::InvalidGroupPath)
}

fn take_override<T: DeserializeOwned>(
    object: &mut Map<String, Value>,
    key: &str,
) -> Result<SavedGroupOverride<T>, LegacyGroupConfigParseErrorCode> {
    match object.remove(key) {
        None => Ok(SavedGroupOverride::Inherit),
        Some(Value::Null) => Ok(SavedGroupOverride::Clear),
        Some(value) => serde_json::from_value(value)
            .map(SavedGroupOverride::Set)
            .map_err(|_| LegacyGroupConfigParseErrorCode::InvalidGroupConfig),
    }
}

fn take_id_override<T, F>(
    object: &mut Map<String, Value>,
    key: &str,
    parse: F,
) -> Result<SavedGroupOverride<T>, LegacyGroupConfigParseErrorCode>
where
    F: FnOnce(String) -> Result<T, ()>,
{
    match object.remove(key) {
        None => Ok(SavedGroupOverride::Inherit),
        Some(Value::Null) => Ok(SavedGroupOverride::Clear),
        Some(Value::String(value)) if value.is_empty() => Ok(SavedGroupOverride::Clear),
        Some(Value::String(value)) => parse(value)
            .map(SavedGroupOverride::Set)
            .map_err(|_| LegacyGroupConfigParseErrorCode::InvalidGroupConfig),
        Some(mut value) => {
            super::zeroize_value(&mut value);
            Err(LegacyGroupConfigParseErrorCode::InvalidGroupConfig)
        }
    }
}

fn take_identity_override(
    object: &mut Map<String, Value>,
    key: &str,
    references: &LegacyGroupConfigReferences<'_>,
) -> Result<SavedGroupOverride<SavedGroupIdentityReference>, LegacyGroupConfigParseErrorCode> {
    take_id_override(object, key, |value| {
        if references.password_identity_ids.contains(&value) {
            SavedPasswordIdentityId::from_opaque(value)
                .map(SavedGroupIdentityReference::Password)
                .map_err(|_| ())
        } else {
            SavedIdentityReferenceId::from_opaque(value)
                .map(SavedGroupIdentityReference::Key)
                .map_err(|_| ())
        }
    })
}

fn take_host_chain_override(
    object: &mut Map<String, Value>,
) -> Result<
    netcatty_vault::SavedGroupOverride<netcatty_vault::SavedGroupHostChain>,
    LegacyGroupConfigParseErrorCode,
> {
    match object.remove("hostChain") {
        None => Ok(SavedGroupOverride::Inherit),
        Some(Value::Null) => Ok(SavedGroupOverride::Clear),
        Some(Value::Object(mut chain)) => {
            let Some(host_ids) = chain.remove("hostIds") else {
                return Err(LegacyGroupConfigParseErrorCode::InvalidGroupConfig);
            };
            if !chain.is_empty() {
                let mut remaining = Value::Object(chain);
                super::zeroize_value(&mut remaining);
                return Err(LegacyGroupConfigParseErrorCode::InvalidGroupConfig);
            }
            serde_json::from_value(host_ids)
                .map(SavedGroupOverride::Set)
                .map_err(|_| LegacyGroupConfigParseErrorCode::InvalidGroupConfig)
        }
        Some(mut value) => {
            super::zeroize_value(&mut value);
            Err(LegacyGroupConfigParseErrorCode::InvalidGroupConfig)
        }
    }
}

fn parse_credential_override(
    value: Option<Value>,
    save_password: bool,
) -> (
    SavedGroupCredentialOverride,
    Option<SecretValue>,
    LegacyCredentialDisposition,
) {
    let was_defined = value.is_some();
    let mut issues = Vec::new();
    let (secret, disposition) = super::classify_password(value, save_password, true, &mut issues);
    let state = if !was_defined {
        SavedGroupCredentialOverride::Inherit
    } else if secret.is_some() {
        SavedGroupCredentialOverride::StoredHint
    } else {
        // An unavailable explicit child password must still block an ancestor
        // credential from being inherited while re-entry is pending.
        SavedGroupCredentialOverride::Clear
    };
    (state, secret, disposition)
}

fn parse_proxy_override(
    profile_value: Option<Value>,
    inline_value: Option<Value>,
    references: &LegacyGroupConfigReferences<'_>,
) -> Result<
    (
        SavedGroupProxyOverride,
        Option<SecretValue>,
        LegacyProxyCredentialDisposition,
        bool,
        u32,
    ),
    LegacyGroupConfigParseErrorCode,
> {
    if profile_value.is_some() && inline_value.is_some() {
        let mut profile = profile_value;
        let mut inline = inline_value;
        super::zeroize_optional_value(profile.take());
        super::zeroize_optional_value(inline.take());
        return Err(LegacyGroupConfigParseErrorCode::ConflictingProxyOverrides);
    }

    if let Some(value) = profile_value {
        let profile = match value {
            Value::Null => SavedGroupProxyOverride::Clear,
            Value::String(value) if value.is_empty() => SavedGroupProxyOverride::Clear,
            Value::String(value) => SavedProxyProfileId::from_opaque(value)
                .map(SavedGroupProxyOverride::Profile)
                .map_err(|_| LegacyGroupConfigParseErrorCode::InvalidGroupConfig)?,
            mut value => {
                super::zeroize_value(&mut value);
                return Err(LegacyGroupConfigParseErrorCode::InvalidGroupConfig);
            }
        };
        return Ok((
            profile,
            None,
            LegacyProxyCredentialDisposition::None,
            false,
            0,
        ));
    }

    let Some(value) = inline_value else {
        return Ok((
            SavedGroupProxyOverride::Inherit,
            None,
            LegacyProxyCredentialDisposition::None,
            false,
            0,
        ));
    };
    if value.is_null() {
        return Ok((
            SavedGroupProxyOverride::Clear,
            None,
            LegacyProxyCredentialDisposition::None,
            false,
            0,
        ));
    }

    let super::ProxyConfigParseOutcome {
        config,
        password,
        credential_disposition,
        secret_fields_stripped,
        unsupported,
        ..
    } = super::parse_proxy_config_candidate(
        Some(value),
        references.available_identity_ids,
        references.password_identity_ids,
    );
    let config = config.ok_or(LegacyGroupConfigParseErrorCode::InvalidGroupConfig)?;
    Ok((
        SavedGroupProxyOverride::Inline(config),
        password,
        credential_disposition,
        unsupported,
        secret_fields_stripped,
    ))
}

fn infer_password_only_auth_method(defaults: &mut SavedGroupDefaults, password_nonempty: bool) {
    if !password_nonempty || !defaults.auth_method.is_inherit() {
        return;
    }
    let has_identity = matches!(defaults.identity_id, SavedGroupOverride::Set(_));
    let has_identity_file = matches!(defaults.identity_file_id, SavedGroupOverride::Set(_));
    let has_identity_paths = matches!(
        &defaults.identity_file_paths,
        SavedGroupOverride::Set(paths) if !paths.as_slice().is_empty()
    );
    if !has_identity && !has_identity_file && !has_identity_paths {
        defaults.auth_method = SavedGroupOverride::Set(SavedGroupAuthMethod::Password);
    }
}

fn migrate_deprecated_font_override(defaults: &mut SavedGroupDefaults) {
    let deprecated = matches!(
        &defaults.font_family,
        SavedGroupOverride::Set(value)
            if matches!(
                value.as_str(),
                "pingfang-sc" | "microsoft-yahei" | "comic-sans-ms"
            )
    );
    if !deprecated {
        return;
    }
    defaults.font_family = SavedGroupOverride::Inherit;
    if matches!(defaults.font_family_override, SavedGroupOverride::Set(true)) {
        defaults.font_family_override = SavedGroupOverride::Set(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SOURCE_SHA256: [u8; 32] = [0x41; 32];

    fn references<'a>(
        available: &'a HashSet<String>,
        passwords: &'a HashSet<String>,
    ) -> LegacyGroupConfigReferences<'a> {
        LegacyGroupConfigReferences::new(available, passwords)
    }

    #[test]
    fn absent_and_present_empty_catalogs_remain_distinct() {
        let identities = HashSet::new();
        let absent = parse_legacy_group_catalogs(
            None,
            None,
            &SOURCE_SHA256,
            10,
            references(&identities, &identities),
        )
        .expect("absent catalogs");
        assert!(absent.custom_groups().is_none());
        assert!(absent.group_configs().is_none());

        let empty = parse_legacy_group_catalogs(
            Some(json!([])),
            Some(json!([])),
            &SOURCE_SHA256,
            10,
            references(&identities, &identities),
        )
        .expect("empty catalogs");
        assert_eq!(empty.custom_groups().map(|values| values.len()), Some(0));
        assert_eq!(empty.group_configs().map(|values| values.len()), Some(0));
    }

    #[test]
    fn group_ids_are_stable_for_one_source_and_separated_by_source_path_and_position() {
        let identities = HashSet::new();
        let parse_ids = |source_sha256: &[u8; 32], paths: &[&str], now_ms| {
            let records = paths
                .iter()
                .map(|path| json!({ "path": path }))
                .collect::<Vec<_>>();
            parse_legacy_group_catalogs(
                None,
                Some(Value::Array(records)),
                source_sha256,
                now_ms,
                references(&identities, &identities),
            )
            .expect("group catalog")
            .group_configs()
            .expect("group configs")
            .iter()
            .map(|candidate| candidate.config().id.as_str().to_owned())
            .collect::<Vec<_>>()
        };

        let first = parse_ids(&SOURCE_SHA256, &["Team/A", "Team/B"], 10);
        let repeated = parse_ids(&SOURCE_SHA256, &["Team/A", "Team/B"], 999);
        assert_eq!(first, repeated, "wall-clock time must not affect IDs");
        assert!(first.iter().all(|id| {
            id.len() == 64
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }));

        let other_source = parse_ids(&[0x42; 32], &["Team/A", "Team/B"], 10);
        assert_ne!(
            first, other_source,
            "source identity must domain-separate IDs"
        );

        let other_path = parse_ids(&SOURCE_SHA256, &["Team/C", "Team/B"], 10);
        assert_ne!(first[0], other_path[0], "group path must affect its ID");
        assert_eq!(first[1], other_path[1], "unrelated records remain stable");

        let repeated_path = parse_ids(&SOURCE_SHA256, &["Team/A", "Team/A"], 10);
        assert_ne!(
            repeated_path[0], repeated_path[1],
            "record position must keep malformed duplicate paths collision-free"
        );
    }

    #[test]
    fn parses_complete_group_config_with_exact_path_and_tri_state_semantics() {
        let password_identity = "password-identity".to_owned();
        let available = HashSet::from([password_identity.clone()]);
        let passwords = HashSet::from([password_identity.clone()]);
        let parsed = parse_legacy_group_catalogs(
            Some(json!([r"/ Team //Ops\DB/./"])),
            Some(json!([{
                "path": r"Ops\DB// Team /./..",
                "order": 3,
                "password": "ssh-secret-sentinel",
                "savePassword": true,
                "authMethod": "auto",
                "identityId": password_identity,
                "identityFileId": "key-file",
                "identityFilePaths": [],
                "port": 22,
                "protocol": "ssh",
                "deviceType": "network",
                "agentForwarding": false,
                "proxyConfig": {
                    "type": "http",
                    "host": "proxy.example.test",
                    "port": 8080,
                    "username": "proxy-user",
                    "password": "proxy-secret-sentinel"
                },
                "hostChain": { "hostIds": [] },
                "startupCommand": "first\nsecond",
                "startupCommandRunMode": "lineDelay",
                "loginScriptId": "script-id",
                "legacyAlgorithms": false,
                "skipEcdsaHostKey": true,
                "algorithms": {
                    "kex": ["curve25519-sha256"],
                    "cipher": [],
                    "hmac": [],
                    "serverHostKey": [],
                    "compress": []
                },
                "environmentVariables": [{ "name": "TERM", "value": "xterm-256color" }],
                "charset": "utf-8",
                "moshEnabled": false,
                "moshServerPath": "",
                "etEnabled": false,
                "etPort": 2022,
                "telnetEnabled": true,
                "telnetPort": 23,
                "telnetIdentityId": "",
                "telnetUsername": "",
                "telnetPassword": "telnet-secret-sentinel",
                "theme": "dark",
                "themeOverride": false,
                "fontFamily": "jetbrains-mono",
                "fontFamilyOverride": true,
                "fontSize": 14,
                "fontSizeOverride": false,
                "fontWeight": 500,
                "fontWeightOverride": true,
                "backspaceBehavior": "ctrl-h"
            }])),
            &SOURCE_SHA256,
            10,
            references(&available, &passwords),
        )
        .expect("complete group catalogs");

        assert_eq!(
            parsed.custom_groups().expect("custom groups")[0].as_str(),
            r" Team /Ops\DB/."
        );
        let candidate = &parsed.group_configs().expect("group configs")[0];
        assert_eq!(candidate.config().path.as_str(), r"Ops\DB/ Team /./..");
        assert!(candidate.has_ssh_password_candidate());
        assert!(candidate.has_telnet_password_candidate());
        assert!(candidate.has_inline_proxy_password_candidate());
        assert_eq!(
            candidate.ssh_credential_disposition(),
            LegacyCredentialDisposition::PlaintextCandidate
        );
        assert_eq!(
            candidate.telnet_credential_disposition(),
            LegacyCredentialDisposition::PlaintextCandidate
        );
        assert_eq!(
            candidate.inline_proxy_credential_disposition(),
            LegacyProxyCredentialDisposition::PlaintextCandidate
        );
        assert_eq!(
            candidate.config().defaults.agent_forwarding,
            SavedGroupOverride::Set(false)
        );
        assert!(matches!(
            &candidate.config().defaults.identity_file_paths,
            SavedGroupOverride::Set(paths) if paths.as_slice().is_empty()
        ));
        assert_eq!(
            candidate.config().defaults.telnet_identity_id,
            SavedGroupOverride::Clear
        );
        assert!(matches!(
            &candidate.config().defaults.telnet_username,
            SavedGroupOverride::Set(value) if value.as_str().is_empty()
        ));
    }

    #[test]
    fn secret_bodies_never_enter_saved_config_debug_or_serde() {
        let available = HashSet::new();
        let parsed = parse_legacy_group_catalogs(
            None,
            Some(json!([{
                "path": "Team",
                "password": "ssh-secret-leak-sentinel",
                "telnetPassword": "telnet-secret-leak-sentinel",
                "proxyConfig": {
                    "type": "socks5",
                    "host": "proxy.example.test",
                    "port": 1080,
                    "username": "alice",
                    "password": "proxy-secret-leak-sentinel"
                }
            }])),
            &SOURCE_SHA256,
            10,
            references(&available, &available),
        )
        .expect("secret-bearing group config");
        let candidate = &parsed.group_configs().expect("group configs")[0];
        let safe_forms = [
            format!("{:?}", candidate.config()),
            serde_json::to_string(candidate.config()).expect("safe group JSON"),
            format!("{:?}", candidate.ssh_credential_disposition()),
            format!("{:?}", candidate.telnet_credential_disposition()),
            format!("{:?}", candidate.inline_proxy_credential_disposition()),
        ]
        .join("\n");
        for secret in [
            "ssh-secret-leak-sentinel",
            "telnet-secret-leak-sentinel",
            "proxy-secret-leak-sentinel",
        ] {
            assert!(!safe_forms.contains(secret));
        }

        let mut configs = parsed.into_parts().1.expect("group configs");
        let (_, ssh, _, telnet, _, proxy, _) = configs.pop().expect("group config").into_parts();
        assert_eq!(
            ssh.as_ref().and_then(|value| value.as_utf8().ok()),
            Some("ssh-secret-leak-sentinel")
        );
        assert_eq!(
            telnet.as_ref().and_then(|value| value.as_utf8().ok()),
            Some("telnet-secret-leak-sentinel")
        );
        assert_eq!(
            proxy.as_ref().and_then(|value| value.as_utf8().ok()),
            Some("proxy-secret-leak-sentinel")
        );
    }

    #[test]
    fn unavailable_and_empty_passwords_clear_without_inheriting() {
        let identities = HashSet::new();
        let parsed = parse_legacy_group_catalogs(
            None,
            Some(json!([
                { "path": "empty", "password": "" },
                { "path": "encrypted", "password": "enc:v1:not-portable" },
                { "path": "no-save", "password": "discarded", "savePassword": false }
            ])),
            &SOURCE_SHA256,
            10,
            references(&identities, &identities),
        )
        .expect("credential states");
        let configs = parsed.group_configs().expect("group configs");
        for candidate in configs {
            assert_eq!(
                candidate.config().defaults.password,
                SavedGroupCredentialOverride::Clear
            );
            assert!(!candidate.has_ssh_password_candidate());
        }
        assert_eq!(
            configs[1].ssh_credential_disposition(),
            LegacyCredentialDisposition::ReentryRequiredEncrypted
        );
        assert_eq!(
            configs[2].ssh_credential_disposition(),
            LegacyCredentialDisposition::NotSavedByPolicy
        );
    }

    #[test]
    fn password_only_auth_and_deprecated_fonts_follow_legacy_sanitizer() {
        let identities = HashSet::new();
        let parsed = parse_legacy_group_catalogs(
            None,
            Some(json!([{
                "path": "Team",
                "identityId": "",
                "password": "secret",
                "fontFamily": "pingfang-sc",
                "fontFamilyOverride": true
            }])),
            &SOURCE_SHA256,
            10,
            references(&identities, &identities),
        )
        .expect("sanitized group config");
        let defaults = &parsed.group_configs().expect("group configs")[0]
            .config()
            .defaults;
        assert_eq!(
            defaults.auth_method,
            SavedGroupOverride::Set(SavedGroupAuthMethod::Password)
        );
        assert_eq!(defaults.font_family, SavedGroupOverride::Inherit);
        assert_eq!(
            defaults.font_family_override,
            SavedGroupOverride::Set(false)
        );
    }

    #[test]
    fn strict_shapes_reject_unknown_fields_and_proxy_conflicts_without_echoing_values() {
        let identities = HashSet::new();
        let secret = "unknown-secret-sentinel";
        let unknown = parse_legacy_group_catalogs(
            None,
            Some(json!([{ "path": "Team", "futureField": secret }])),
            &SOURCE_SHA256,
            10,
            references(&identities, &identities),
        )
        .err()
        .expect("unknown field error");
        assert_eq!(
            unknown.code,
            LegacyGroupConfigParseErrorCode::UnknownGroupConfigField
        );
        let safe_error = format!(
            "{:?}\n{}\n{}",
            unknown,
            unknown,
            serde_json::to_string(&unknown).expect("safe error JSON")
        );
        assert!(!safe_error.contains(secret));

        let conflict = parse_legacy_group_catalogs(
            None,
            Some(json!([{
                "path": "Team",
                "proxyProfileId": "profile",
                "proxyConfig": null
            }])),
            &SOURCE_SHA256,
            10,
            references(&identities, &identities),
        )
        .err()
        .expect("proxy conflict");
        assert_eq!(
            conflict.code,
            LegacyGroupConfigParseErrorCode::ConflictingProxyOverrides
        );
    }

    #[test]
    fn early_failures_never_expose_unconsumed_group_credentials() {
        let identities = HashSet::new();
        let ssh_secret = "early-ssh-secret-sentinel";
        let telnet_secret = "early-telnet-secret-sentinel";
        let proxy_secret = "early-proxy-secret-sentinel";
        let protected_record = || {
            json!({
                "path": "Team",
                "password": ssh_secret,
                "telnetPassword": telnet_secret,
                "proxyConfig": {
                    "type": "http",
                    "host": "proxy.example.test",
                    "port": 8080,
                    "username": "alice",
                    "password": proxy_secret
                }
            })
        };

        let mut invalid_path = protected_record();
        invalid_path["path"] = Value::Null;
        let mut invalid_identity = protected_record();
        invalid_identity["identityId"] = json!({ "invalid": true });
        let mut invalid_field = protected_record();
        invalid_field["order"] = json!({ "invalid": true });
        let mut unknown_field = protected_record();
        unknown_field["futureField"] = json!("non-secret-field-sentinel");

        for (record, expected_code) in [
            (
                invalid_path,
                LegacyGroupConfigParseErrorCode::InvalidGroupPath,
            ),
            (
                invalid_identity,
                LegacyGroupConfigParseErrorCode::InvalidGroupConfig,
            ),
            (
                invalid_field,
                LegacyGroupConfigParseErrorCode::InvalidGroupConfig,
            ),
            (
                unknown_field,
                LegacyGroupConfigParseErrorCode::UnknownGroupConfigField,
            ),
        ] {
            let error = parse_legacy_group_catalogs(
                None,
                Some(Value::Array(vec![record])),
                &SOURCE_SHA256,
                10,
                references(&identities, &identities),
            )
            .err()
            .expect("malformed group config");
            assert_eq!(error.code, expected_code);
            let safe_error = format!(
                "{:?}\n{}\n{}",
                error,
                error,
                serde_json::to_string(&error).expect("safe error JSON")
            );
            for secret in [ssh_secret, telnet_secret, proxy_secret] {
                assert!(!safe_error.contains(secret));
            }
        }
    }
}
