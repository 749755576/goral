use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::{
    SavedGroupPath, SavedHostId, SavedIdentityReferenceId, SavedPasswordIdentityId,
    SavedProxyConfig, SavedProxyProfileId, SavedSshKeyReferenceId,
};

const MAX_ID_BYTES: usize = 512;
const MAX_TEXT_BYTES: usize = 32 * 1024;
const MAX_SINGLE_LINE_BYTES: usize = 32 * 1024;
const MAX_COLLECTION_ITEMS: usize = 256;
const MAX_ALGORITHM_TOKEN_BYTES: usize = 256;
const MAX_HOST_CHAIN_ITEMS: usize = 128;
const GROUP_CONFIG_RECORD_VERSION: u32 = 1;

/// Stable identity for a saved group-configuration record.
///
/// It is deliberately distinct from [`SavedGroupPath`]: renaming a group does
/// not have to change the record identity. This core type is not wired into the
/// Vault snapshot format by this slice.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct SavedGroupId(String);

impl SavedGroupId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn from_opaque(value: impl Into<String>) -> Result<Self, SavedGroupConfigError> {
        let value = value.into();
        validate_non_empty_single_line("saved group ID", &value, MAX_ID_BYTES)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SavedGroupId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SavedGroupId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SavedGroupId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_opaque(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SavedGroupConfigError {
    Empty(&'static str),
    TooLong {
        field: &'static str,
        max_bytes: usize,
    },
    UnsafeCharacters(&'static str),
    InvalidPort,
    NonFiniteNumber(&'static str),
    TooManyItems {
        field: &'static str,
        max_items: usize,
    },
    InvalidRevision,
    InvalidTimestamps,
    NonCanonicalRecordVersion,
    EmptyUpdate,
}

impl fmt::Display for SavedGroupConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty(field) => write!(formatter, "{field} is empty"),
            Self::TooLong { field, max_bytes } => {
                write!(formatter, "{field} exceeds {max_bytes} UTF-8 bytes")
            }
            Self::UnsafeCharacters(field) => {
                write!(formatter, "{field} contains unsafe control characters")
            }
            Self::InvalidPort => formatter.write_str("port must be between 1 and 65535"),
            Self::NonFiniteNumber(field) => write!(formatter, "{field} must be finite"),
            Self::TooManyItems { field, max_items } => {
                write!(formatter, "{field} contains more than {max_items} items")
            }
            Self::InvalidRevision => formatter.write_str("group revision must be positive"),
            Self::InvalidTimestamps => formatter.write_str("group timestamps are invalid"),
            Self::NonCanonicalRecordVersion => {
                formatter.write_str("group record version is not canonical")
            }
            Self::EmptyUpdate => formatter.write_str("group update contains no fields"),
        }
    }
}

impl std::error::Error for SavedGroupConfigError {}

/// An override with a distinct absent state and explicit-clear state.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(
    tag = "state",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum SavedGroupOverride<T> {
    #[default]
    Inherit,
    Clear,
    Set(T),
}

impl<T> SavedGroupOverride<T> {
    pub fn is_inherit(&self) -> bool {
        matches!(self, Self::Inherit)
    }

    pub fn is_defined(&self) -> bool {
        !self.is_inherit()
    }

    pub fn as_ref(&self) -> SavedGroupOverride<&T> {
        match self {
            Self::Inherit => SavedGroupOverride::Inherit,
            Self::Clear => SavedGroupOverride::Clear,
            Self::Set(value) => SavedGroupOverride::Set(value),
        }
    }
}

impl<T: Clone> SavedGroupOverride<T> {
    fn merge_from(&mut self, child: &Self) {
        if child.is_defined() {
            *self = child.clone();
        }
    }
}

/// Password-body-free state for either the SSH or Telnet manual password slot.
///
/// `StoredHint` says that the credential layer has a value. The value itself
/// cannot be represented, logged, or serialized through this model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SavedGroupCredentialOverride {
    #[default]
    Inherit,
    Clear,
    StoredHint,
}

impl SavedGroupCredentialOverride {
    pub fn is_defined(self) -> bool {
        !matches!(self, Self::Inherit)
    }

    fn merge_from(&mut self, child: Self) {
        if child.is_defined() {
            *self = child;
        }
    }
}

/// Bounded application text. Newlines and tabs are allowed; NUL and other
/// non-whitespace control characters are rejected. Debug output is redacted.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SavedGroupText(String);

impl SavedGroupText {
    pub fn new(value: impl Into<String>) -> Result<Self, SavedGroupConfigError> {
        let value = value.into();
        validate_text("group text", &value, MAX_TEXT_BYTES, true)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SavedGroupText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SavedGroupText([redacted])")
    }
}

impl Serialize for SavedGroupText {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SavedGroupText {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Bounded single-line text used for usernames, paths, theme/font IDs and
/// other legacy scalar strings. Empty strings remain representable because
/// they are meaningful explicit legacy values in several fields.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SavedGroupSingleLineText(String);

impl SavedGroupSingleLineText {
    pub fn new(value: impl Into<String>) -> Result<Self, SavedGroupConfigError> {
        let value = value.into();
        validate_text(
            "group single-line text",
            &value,
            MAX_SINGLE_LINE_BYTES,
            false,
        )?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SavedGroupSingleLineText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SavedGroupSingleLineText([redacted])")
    }
}

impl Serialize for SavedGroupSingleLineText {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SavedGroupSingleLineText {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Strict local reference type for legacy IDs that do not yet have a domain
/// model (currently `loginScriptId`).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SavedGroupOpaqueId(String);

impl SavedGroupOpaqueId {
    pub fn from_opaque(value: impl Into<String>) -> Result<Self, SavedGroupConfigError> {
        let value = value.into();
        validate_non_empty_single_line("group opaque ID", &value, MAX_ID_BYTES)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SavedGroupOpaqueId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SavedGroupOpaqueId([redacted])")
    }
}

impl Serialize for SavedGroupOpaqueId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SavedGroupOpaqueId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_opaque(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct SavedGroupPort(u16);

impl SavedGroupPort {
    pub fn new(value: u32) -> Result<Self, SavedGroupConfigError> {
        u16::try_from(value)
            .ok()
            .filter(|port| *port != 0)
            .map(Self)
            .ok_or(SavedGroupConfigError::InvalidPort)
    }

    pub fn get(self) -> u16 {
        self.0
    }
}

impl<'de> Deserialize<'de> for SavedGroupPort {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(u32::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SavedGroupFiniteNumber(f64);

impl SavedGroupFiniteNumber {
    pub fn new(field: &'static str, value: f64) -> Result<Self, SavedGroupConfigError> {
        value
            .is_finite()
            .then_some(Self(value))
            .ok_or(SavedGroupConfigError::NonFiniteNumber(field))
    }

    pub fn get(self) -> f64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for SavedGroupFiniteNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new("group finite number", f64::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SavedGroupAuthMethod {
    Auto,
    Password,
    Key,
    Certificate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SavedGroupProtocol {
    Ssh,
    Telnet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SavedGroupDeviceType {
    General,
    Network,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SavedGroupStartupCommandRunMode {
    LineDelay,
    Paste,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SavedGroupBackspaceBehavior {
    #[serde(rename = "ctrl-h")]
    CtrlH,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "type",
    content = "id",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum SavedGroupIdentityReference {
    Key(SavedIdentityReferenceId),
    Password(SavedPasswordIdentityId),
}

#[derive(Deserialize)]
#[serde(
    tag = "type",
    content = "id",
    rename_all = "camelCase",
    deny_unknown_fields
)]
enum SavedGroupIdentityReferenceWire {
    Key(SavedIdentityReferenceId),
    Password(SavedPasswordIdentityId),
}

impl<'de> Deserialize<'de> for SavedGroupIdentityReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match SavedGroupIdentityReferenceWire::deserialize(deserializer)? {
            SavedGroupIdentityReferenceWire::Key(id) => {
                SavedIdentityReferenceId::from_opaque(id.as_str().to_owned())
                    .map_err(serde::de::Error::custom)?;
                Ok(Self::Key(id))
            }
            SavedGroupIdentityReferenceWire::Password(id) => {
                SavedPasswordIdentityId::from_opaque(id.as_str().to_owned())
                    .map_err(serde::de::Error::custom)?;
                Ok(Self::Password(id))
            }
        }
    }
}

#[derive(Clone, PartialEq, Serialize)]
#[serde(
    tag = "state",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum SavedGroupProxyOverride {
    Inherit,
    Clear,
    Profile(SavedProxyProfileId),
    Inline(SavedProxyConfig),
}

#[derive(Deserialize)]
#[serde(
    tag = "state",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
enum SavedGroupProxyOverrideWire {
    Inherit,
    Clear,
    Profile(SavedProxyProfileId),
    Inline(SavedProxyConfig),
}

impl<'de> Deserialize<'de> for SavedGroupProxyOverride {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match SavedGroupProxyOverrideWire::deserialize(deserializer)? {
            SavedGroupProxyOverrideWire::Inherit => Ok(Self::Inherit),
            SavedGroupProxyOverrideWire::Clear => Ok(Self::Clear),
            SavedGroupProxyOverrideWire::Profile(id) => {
                SavedProxyProfileId::from_opaque(id.as_str().to_owned())
                    .map_err(serde::de::Error::custom)?;
                Ok(Self::Profile(id))
            }
            SavedGroupProxyOverrideWire::Inline(config) => Ok(Self::Inline(config)),
        }
    }
}

impl fmt::Debug for SavedGroupProxyOverride {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inherit => formatter.write_str("Inherit"),
            Self::Clear => formatter.write_str("Clear"),
            Self::Profile(id) => formatter.debug_tuple("Profile").field(id).finish(),
            Self::Inline(_) => formatter.write_str("Inline([redacted])"),
        }
    }
}

impl Default for SavedGroupProxyOverride {
    fn default() -> Self {
        Self::Inherit
    }
}

impl SavedGroupProxyOverride {
    pub fn is_inherit(&self) -> bool {
        matches!(self, Self::Inherit)
    }

    fn merge_from(&mut self, child: &Self) {
        if !child.is_inherit() {
            *self = child.clone();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SavedGroupHostChain(Vec<SavedHostId>);

impl SavedGroupHostChain {
    pub fn new(host_ids: Vec<SavedHostId>) -> Result<Self, SavedGroupConfigError> {
        validate_item_count("host chain", host_ids.len(), MAX_HOST_CHAIN_ITEMS)?;
        Ok(Self(host_ids))
    }

    pub fn host_ids(&self) -> &[SavedHostId] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SavedGroupHostChain {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let host_ids = Vec::<SavedHostId>::deserialize(deserializer)?;
        for id in &host_ids {
            SavedHostId::from_opaque(id.as_str().to_owned()).map_err(serde::de::Error::custom)?;
        }
        Self::new(host_ids).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SavedGroupFilePaths(Vec<SavedGroupSingleLineText>);

impl SavedGroupFilePaths {
    pub fn new(paths: Vec<SavedGroupSingleLineText>) -> Result<Self, SavedGroupConfigError> {
        validate_item_count("identity file paths", paths.len(), MAX_COLLECTION_ITEMS)?;
        Ok(Self(paths))
    }

    pub fn as_slice(&self) -> &[SavedGroupSingleLineText] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SavedGroupFilePaths {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(Vec::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SavedGroupAlgorithmToken(String);

impl SavedGroupAlgorithmToken {
    pub fn new(value: impl Into<String>) -> Result<Self, SavedGroupConfigError> {
        let value = value.into();
        validate_non_empty_single_line("algorithm token", &value, MAX_ALGORITHM_TOKEN_BYTES)?;
        if value.chars().any(char::is_whitespace) {
            return Err(SavedGroupConfigError::UnsafeCharacters("algorithm token"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SavedGroupAlgorithmToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedGroupAlgorithmOverrides {
    pub kex: Option<Vec<SavedGroupAlgorithmToken>>,
    pub cipher: Option<Vec<SavedGroupAlgorithmToken>>,
    pub hmac: Option<Vec<SavedGroupAlgorithmToken>>,
    pub server_host_key: Option<Vec<SavedGroupAlgorithmToken>>,
    pub compress: Option<Vec<SavedGroupAlgorithmToken>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SavedGroupAlgorithmOverridesWire {
    #[serde(default)]
    kex: Option<Vec<SavedGroupAlgorithmToken>>,
    #[serde(default)]
    cipher: Option<Vec<SavedGroupAlgorithmToken>>,
    #[serde(default)]
    hmac: Option<Vec<SavedGroupAlgorithmToken>>,
    #[serde(default)]
    server_host_key: Option<Vec<SavedGroupAlgorithmToken>>,
    #[serde(default)]
    compress: Option<Vec<SavedGroupAlgorithmToken>>,
}

impl<'de> Deserialize<'de> for SavedGroupAlgorithmOverrides {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SavedGroupAlgorithmOverridesWire::deserialize(deserializer)?;
        Self {
            kex: wire.kex,
            cipher: wire.cipher,
            hmac: wire.hmac,
            server_host_key: wire.server_host_key,
            compress: wire.compress,
        }
        .validate()
        .map_err(serde::de::Error::custom)
    }
}

impl SavedGroupAlgorithmOverrides {
    pub fn validate(self) -> Result<Self, SavedGroupConfigError> {
        for (field, values) in [
            ("kex algorithms", self.kex.as_ref()),
            ("cipher algorithms", self.cipher.as_ref()),
            ("hmac algorithms", self.hmac.as_ref()),
            ("server host-key algorithms", self.server_host_key.as_ref()),
            ("compression algorithms", self.compress.as_ref()),
        ] {
            if let Some(values) = values {
                validate_item_count(field, values.len(), MAX_COLLECTION_ITEMS)?;
            }
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SavedGroupEnvironmentVariable {
    pub name: SavedGroupSingleLineText,
    pub value: SavedGroupText,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SavedGroupEnvironmentVariableWire {
    name: String,
    value: String,
}

impl<'de> Deserialize<'de> for SavedGroupEnvironmentVariable {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SavedGroupEnvironmentVariableWire::deserialize(deserializer)?;
        Self::new(wire.name, wire.value).map_err(serde::de::Error::custom)
    }
}

impl SavedGroupEnvironmentVariable {
    pub fn new(
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, SavedGroupConfigError> {
        let name = name.into();
        if name.is_empty() {
            return Err(SavedGroupConfigError::Empty("environment variable name"));
        }
        Ok(Self {
            name: SavedGroupSingleLineText::new(name)?,
            value: SavedGroupText::new(value)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SavedGroupEnvironment(Vec<SavedGroupEnvironmentVariable>);

impl SavedGroupEnvironment {
    pub fn new(values: Vec<SavedGroupEnvironmentVariable>) -> Result<Self, SavedGroupConfigError> {
        validate_item_count("environment variables", values.len(), MAX_COLLECTION_ITEMS)?;
        Ok(Self(values))
    }

    pub fn as_slice(&self) -> &[SavedGroupEnvironmentVariable] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SavedGroupEnvironment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(Vec::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// All legacy GroupConfig fields other than `path`.
///
/// Its strict camelCase Serde form rejects unknown fields and treats omitted
/// fields as `Inherit`. In particular, the legacy `password` and
/// `telnetPassword` slots serialize only [`SavedGroupCredentialOverride`]
/// state. Inline proxy passwords are likewise reduced to the secret-free hints
/// supported by [`SavedProxyConfig`].
#[derive(Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct SavedGroupDefaults {
    pub order: SavedGroupOverride<SavedGroupFiniteNumber>,
    pub username: SavedGroupOverride<SavedGroupSingleLineText>,
    pub password: SavedGroupCredentialOverride,
    pub save_password: SavedGroupOverride<bool>,
    pub auth_method: SavedGroupOverride<SavedGroupAuthMethod>,
    pub identity_id: SavedGroupOverride<SavedGroupIdentityReference>,
    pub identity_file_id: SavedGroupOverride<SavedSshKeyReferenceId>,
    pub identity_file_paths: SavedGroupOverride<SavedGroupFilePaths>,
    pub port: SavedGroupOverride<SavedGroupPort>,
    pub protocol: SavedGroupOverride<SavedGroupProtocol>,
    pub device_type: SavedGroupOverride<SavedGroupDeviceType>,
    pub agent_forwarding: SavedGroupOverride<bool>,
    pub proxy: SavedGroupProxyOverride,
    pub host_chain: SavedGroupOverride<SavedGroupHostChain>,
    pub startup_command: SavedGroupOverride<SavedGroupText>,
    pub startup_command_run_mode: SavedGroupOverride<SavedGroupStartupCommandRunMode>,
    pub login_script_id: SavedGroupOverride<SavedGroupOpaqueId>,
    pub legacy_algorithms: SavedGroupOverride<bool>,
    pub skip_ecdsa_host_key: SavedGroupOverride<bool>,
    pub algorithms: SavedGroupOverride<SavedGroupAlgorithmOverrides>,
    pub environment_variables: SavedGroupOverride<SavedGroupEnvironment>,
    pub charset: SavedGroupOverride<SavedGroupSingleLineText>,
    pub mosh_enabled: SavedGroupOverride<bool>,
    pub mosh_server_path: SavedGroupOverride<SavedGroupSingleLineText>,
    pub et_enabled: SavedGroupOverride<bool>,
    pub et_port: SavedGroupOverride<SavedGroupPort>,
    pub telnet_enabled: SavedGroupOverride<bool>,
    pub telnet_port: SavedGroupOverride<SavedGroupPort>,
    pub telnet_identity_id: SavedGroupOverride<SavedPasswordIdentityId>,
    pub telnet_username: SavedGroupOverride<SavedGroupSingleLineText>,
    pub telnet_password: SavedGroupCredentialOverride,
    pub theme: SavedGroupOverride<SavedGroupSingleLineText>,
    pub theme_override: SavedGroupOverride<bool>,
    pub font_family: SavedGroupOverride<SavedGroupSingleLineText>,
    pub font_family_override: SavedGroupOverride<bool>,
    pub font_size: SavedGroupOverride<SavedGroupFiniteNumber>,
    pub font_size_override: SavedGroupOverride<bool>,
    pub font_weight: SavedGroupOverride<SavedGroupFiniteNumber>,
    pub font_weight_override: SavedGroupOverride<bool>,
    pub backspace_behavior: SavedGroupOverride<SavedGroupBackspaceBehavior>,
}

impl fmt::Debug for SavedGroupDefaults {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SavedGroupDefaults([redacted bounded configuration])")
    }
}

impl SavedGroupDefaults {
    pub fn validate(&self) -> Result<(), SavedGroupConfigError> {
        if let SavedGroupOverride::Set(reference) = &self.identity_id {
            match reference {
                SavedGroupIdentityReference::Key(id) => {
                    SavedIdentityReferenceId::from_opaque(id.as_str().to_owned())
                        .map_err(|_| SavedGroupConfigError::UnsafeCharacters("identityId"))?;
                }
                SavedGroupIdentityReference::Password(id) => {
                    SavedPasswordIdentityId::from_opaque(id.as_str().to_owned())
                        .map_err(|_| SavedGroupConfigError::UnsafeCharacters("identityId"))?;
                }
            }
        }
        if let SavedGroupOverride::Set(id) = &self.identity_file_id {
            SavedSshKeyReferenceId::from_opaque(id.as_str().to_owned())
                .map_err(|_| SavedGroupConfigError::UnsafeCharacters("identityFileId"))?;
        }
        if let SavedGroupProxyOverride::Profile(id) = &self.proxy {
            SavedProxyProfileId::from_opaque(id.as_str().to_owned())
                .map_err(|_| SavedGroupConfigError::UnsafeCharacters("proxyProfileId"))?;
        }
        if let SavedGroupOverride::Set(id) = &self.telnet_identity_id {
            SavedPasswordIdentityId::from_opaque(id.as_str().to_owned())
                .map_err(|_| SavedGroupConfigError::UnsafeCharacters("telnetIdentityId"))?;
        }
        if let SavedGroupOverride::Set(algorithms) = &self.algorithms {
            algorithms.clone().validate()?;
        }
        Ok(())
    }

    pub fn merge_from(&mut self, child: &Self) {
        let child_has_ssh_identity = child.identity_id.is_defined();
        let child_has_manual_ssh = child.username.is_defined()
            || child.password.is_defined()
            || child.save_password.is_defined()
            || child.auth_method.is_defined()
            || child.identity_file_id.is_defined()
            || child.identity_file_paths.is_defined();

        if child_has_ssh_identity {
            self.clear_manual_ssh_bundle();
        } else if child_has_manual_ssh {
            let replaces_selected_identity = matches!(self.identity_id, SavedGroupOverride::Set(_));
            self.identity_id = SavedGroupOverride::Inherit;
            if replaces_selected_identity {
                self.clear_manual_ssh_bundle();
            }
        }

        let child_has_telnet_identity = child.telnet_identity_id.is_defined();
        let child_has_manual_telnet =
            child.telnet_username.is_defined() || child.telnet_password.is_defined();
        if child_has_telnet_identity {
            self.clear_manual_telnet_bundle();
        } else if child_has_manual_telnet {
            let replaces_selected_identity =
                matches!(self.telnet_identity_id, SavedGroupOverride::Set(_));
            self.telnet_identity_id = SavedGroupOverride::Inherit;
            if replaces_selected_identity {
                self.clear_manual_telnet_bundle();
            }
        }

        self.order.merge_from(&child.order);
        self.username.merge_from(&child.username);
        self.password.merge_from(child.password);
        self.save_password.merge_from(&child.save_password);
        self.auth_method.merge_from(&child.auth_method);
        self.identity_id.merge_from(&child.identity_id);
        self.identity_file_id.merge_from(&child.identity_file_id);
        self.identity_file_paths
            .merge_from(&child.identity_file_paths);
        self.port.merge_from(&child.port);
        self.protocol.merge_from(&child.protocol);
        self.device_type.merge_from(&child.device_type);
        self.agent_forwarding.merge_from(&child.agent_forwarding);
        self.proxy.merge_from(&child.proxy);
        self.host_chain.merge_from(&child.host_chain);
        self.startup_command.merge_from(&child.startup_command);
        self.startup_command_run_mode
            .merge_from(&child.startup_command_run_mode);
        self.login_script_id.merge_from(&child.login_script_id);
        self.legacy_algorithms.merge_from(&child.legacy_algorithms);
        self.skip_ecdsa_host_key
            .merge_from(&child.skip_ecdsa_host_key);
        self.algorithms.merge_from(&child.algorithms);
        self.environment_variables
            .merge_from(&child.environment_variables);
        self.charset.merge_from(&child.charset);
        self.mosh_enabled.merge_from(&child.mosh_enabled);
        self.mosh_server_path.merge_from(&child.mosh_server_path);
        self.et_enabled.merge_from(&child.et_enabled);
        self.et_port.merge_from(&child.et_port);
        self.telnet_enabled.merge_from(&child.telnet_enabled);
        self.telnet_port.merge_from(&child.telnet_port);
        self.telnet_identity_id
            .merge_from(&child.telnet_identity_id);
        self.telnet_username.merge_from(&child.telnet_username);
        self.telnet_password.merge_from(child.telnet_password);

        merge_style_pair(
            &mut self.theme,
            &mut self.theme_override,
            &child.theme,
            &child.theme_override,
        );
        merge_style_pair(
            &mut self.font_family,
            &mut self.font_family_override,
            &child.font_family,
            &child.font_family_override,
        );
        merge_style_pair(
            &mut self.font_size,
            &mut self.font_size_override,
            &child.font_size,
            &child.font_size_override,
        );
        merge_style_pair(
            &mut self.font_weight,
            &mut self.font_weight_override,
            &child.font_weight,
            &child.font_weight_override,
        );
        self.backspace_behavior
            .merge_from(&child.backspace_behavior);
    }

    fn clear_manual_ssh_bundle(&mut self) {
        self.username = SavedGroupOverride::Inherit;
        self.password = SavedGroupCredentialOverride::Inherit;
        self.save_password = SavedGroupOverride::Inherit;
        self.auth_method = SavedGroupOverride::Inherit;
        self.identity_file_id = SavedGroupOverride::Inherit;
        self.identity_file_paths = SavedGroupOverride::Inherit;
    }

    fn clear_manual_telnet_bundle(&mut self) {
        self.telnet_username = SavedGroupOverride::Inherit;
        self.telnet_password = SavedGroupCredentialOverride::Inherit;
    }
}

fn merge_style_pair<T: Clone>(
    target_value: &mut SavedGroupOverride<T>,
    target_flag: &mut SavedGroupOverride<bool>,
    child_value: &SavedGroupOverride<T>,
    child_flag: &SavedGroupOverride<bool>,
) {
    if matches!(child_flag, SavedGroupOverride::Set(false)) {
        // Legacy behavior: false ignores the same-level value, removes the
        // inherited marker, and leaves any inherited value untouched.
        *target_flag = SavedGroupOverride::Inherit;
        return;
    }
    target_value.merge_from(child_value);
    target_flag.merge_from(child_flag);
}

/// A stable, versioned, strictly validated saved GroupConfig record suitable
/// for direct inclusion in the next Vault snapshot schema.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedGroupConfig {
    pub record_version: u32,
    pub id: SavedGroupId,
    pub revision: u64,
    pub path: SavedGroupPath,
    pub defaults: SavedGroupDefaults,
    pub created_at: u64,
    pub updated_at: u64,
}

impl SavedGroupConfig {
    pub fn new(
        path: SavedGroupPath,
        defaults: SavedGroupDefaults,
        now: u64,
    ) -> Result<Self, SavedGroupConfigError> {
        let saved = Self {
            record_version: GROUP_CONFIG_RECORD_VERSION,
            id: SavedGroupId::new(),
            revision: 1,
            path,
            defaults,
            created_at: now,
            updated_at: now,
        };
        saved.validate()?;
        Ok(saved)
    }

    pub fn from_parts(
        id: SavedGroupId,
        revision: u64,
        path: SavedGroupPath,
        defaults: SavedGroupDefaults,
        created_at: u64,
        updated_at: u64,
    ) -> Result<Self, SavedGroupConfigError> {
        let saved = Self {
            record_version: GROUP_CONFIG_RECORD_VERSION,
            id,
            revision,
            path,
            defaults,
            created_at,
            updated_at,
        };
        saved.validate()?;
        Ok(saved)
    }

    pub fn validate(&self) -> Result<(), SavedGroupConfigError> {
        if self.record_version != GROUP_CONFIG_RECORD_VERSION {
            return Err(SavedGroupConfigError::NonCanonicalRecordVersion);
        }
        SavedGroupId::from_opaque(self.id.as_str().to_owned())?;
        if self.revision == 0 {
            return Err(SavedGroupConfigError::InvalidRevision);
        }
        if self.updated_at < self.created_at {
            return Err(SavedGroupConfigError::InvalidTimestamps);
        }
        self.defaults.validate()
    }

    pub fn apply_update(
        &self,
        update: SavedGroupConfigUpdate,
        now: u64,
    ) -> Result<Self, SavedGroupConfigError> {
        if update.path.is_none() && update.defaults.is_none() {
            return Err(SavedGroupConfigError::EmptyUpdate);
        }
        let mut next = self.clone();
        if let Some(path) = update.path {
            next.path = path;
        }
        if let Some(defaults) = update.defaults {
            next.defaults = defaults;
        }
        next.record_version = GROUP_CONFIG_RECORD_VERSION;
        next.revision = self
            .revision
            .checked_add(1)
            .ok_or(SavedGroupConfigError::InvalidRevision)?;
        next.updated_at = now.max(self.updated_at.saturating_add(1));
        next.validate()?;
        Ok(next)
    }

    pub fn stable_cmp(left: &Self, right: &Self) -> Ordering {
        left.path
            .as_str()
            .to_lowercase()
            .cmp(&right.path.as_str().to_lowercase())
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.id.cmp(&right.id))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct SavedGroupConfigUpdate {
    pub path: Option<SavedGroupPath>,
    pub defaults: Option<SavedGroupDefaults>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SavedGroupConfigWire {
    record_version: u32,
    id: SavedGroupId,
    revision: u64,
    path: SavedGroupPath,
    defaults: SavedGroupDefaults,
    created_at: u64,
    updated_at: u64,
}

impl<'de> Deserialize<'de> for SavedGroupConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SavedGroupConfigWire::deserialize(deserializer)?;
        let saved = Self {
            record_version: wire.record_version,
            id: wire.id,
            revision: wire.revision,
            path: wire.path,
            defaults: wire.defaults,
            created_at: wire.created_at,
            updated_at: wire.updated_at,
        };
        saved.validate().map_err(serde::de::Error::custom)?;
        Ok(saved)
    }
}

/// Resolved defaults plus ownership of credential objects kept outside this
/// Serde model. Owners always identify the record that actually defined the
/// inherited credential, never merely the requested leaf group.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedSavedGroupDefaults {
    pub defaults: SavedGroupDefaults,
    pub ssh_credential_owner: Option<SavedGroupId>,
    pub telnet_credential_owner: Option<SavedGroupId>,
    pub inline_proxy_credential_owner: Option<SavedGroupId>,
}

impl Default for ResolvedSavedGroupDefaults {
    fn default() -> Self {
        Self {
            defaults: SavedGroupDefaults::default(),
            ssh_credential_owner: None,
            telnet_credential_owner: None,
            inline_proxy_credential_owner: None,
        }
    }
}

impl ResolvedSavedGroupDefaults {
    fn merge_record(&mut self, config: &SavedGroupConfig) {
        let child = &config.defaults;

        let child_has_ssh_identity = child.identity_id.is_defined();
        let child_has_manual_ssh = child.username.is_defined()
            || child.password.is_defined()
            || child.save_password.is_defined()
            || child.auth_method.is_defined()
            || child.identity_file_id.is_defined()
            || child.identity_file_paths.is_defined();
        if child_has_ssh_identity
            || (child_has_manual_ssh
                && matches!(self.defaults.identity_id, SavedGroupOverride::Set(_)))
        {
            self.ssh_credential_owner = None;
        }
        if !child_has_ssh_identity {
            match child.password {
                SavedGroupCredentialOverride::StoredHint => {
                    self.ssh_credential_owner = Some(config.id.clone());
                }
                SavedGroupCredentialOverride::Clear => self.ssh_credential_owner = None,
                SavedGroupCredentialOverride::Inherit => {}
            }
        }

        let child_has_telnet_identity = child.telnet_identity_id.is_defined();
        let child_has_manual_telnet =
            child.telnet_username.is_defined() || child.telnet_password.is_defined();
        if child_has_telnet_identity
            || (child_has_manual_telnet
                && matches!(self.defaults.telnet_identity_id, SavedGroupOverride::Set(_)))
        {
            self.telnet_credential_owner = None;
        }
        if !child_has_telnet_identity {
            match child.telnet_password {
                SavedGroupCredentialOverride::StoredHint => {
                    self.telnet_credential_owner = Some(config.id.clone());
                }
                SavedGroupCredentialOverride::Clear => self.telnet_credential_owner = None,
                SavedGroupCredentialOverride::Inherit => {}
            }
        }

        match &child.proxy {
            SavedGroupProxyOverride::Inherit => {}
            SavedGroupProxyOverride::Inline(config_value)
                if inline_proxy_has_saved_manual_credential(config_value) =>
            {
                self.inline_proxy_credential_owner = Some(config.id.clone());
            }
            SavedGroupProxyOverride::Clear
            | SavedGroupProxyOverride::Profile(_)
            | SavedGroupProxyOverride::Inline(_) => {
                self.inline_proxy_credential_owner = None;
            }
        }

        self.defaults.merge_from(child);
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

/// Resolves `A`, then `A/B`, then `A/B/C`. Duplicate records at the same path
/// use the last record in `configs`, matching the legacy `Map` construction.
pub fn resolve_group_defaults(
    group_path: &SavedGroupPath,
    configs: &[SavedGroupConfig],
) -> SavedGroupDefaults {
    resolve_group_defaults_with_provenance(group_path, configs).defaults
}

pub fn resolve_group_defaults_with_provenance(
    group_path: &SavedGroupPath,
    configs: &[SavedGroupConfig],
) -> ResolvedSavedGroupDefaults {
    let mut by_path = BTreeMap::new();
    for config in configs {
        by_path.insert(config.path.as_str(), config);
    }

    let mut resolved = ResolvedSavedGroupDefaults::default();
    for ancestor in group_path.ancestors() {
        if let Some(config) = by_path.get(ancestor.as_str()) {
            resolved.merge_record(config);
        }
    }
    resolved
}

fn validate_text(
    field: &'static str,
    value: &str,
    max_bytes: usize,
    allow_line_breaks: bool,
) -> Result<(), SavedGroupConfigError> {
    if value.len() > max_bytes {
        return Err(SavedGroupConfigError::TooLong { field, max_bytes });
    }
    let unsafe_control = value.chars().any(|character| {
        character.is_control() && !(allow_line_breaks && matches!(character, '\n' | '\r' | '\t'))
    });
    if unsafe_control {
        return Err(SavedGroupConfigError::UnsafeCharacters(field));
    }
    Ok(())
}

fn validate_non_empty_single_line(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), SavedGroupConfigError> {
    if value.is_empty() {
        return Err(SavedGroupConfigError::Empty(field));
    }
    validate_text(field, value, max_bytes, false)
}

fn validate_item_count(
    field: &'static str,
    actual: usize,
    max_items: usize,
) -> Result<(), SavedGroupConfigError> {
    if actual > max_items {
        return Err(SavedGroupConfigError::TooManyItems { field, max_items });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(value: &str) -> SavedGroupPath {
        SavedGroupPath::new(value).expect("group path")
    }

    fn text(value: &str) -> SavedGroupSingleLineText {
        SavedGroupSingleLineText::new(value).expect("single-line text")
    }

    fn record(path_value: &str, defaults: SavedGroupDefaults) -> SavedGroupConfig {
        SavedGroupConfig::new(path(path_value), defaults, 1).expect("saved group")
    }

    fn identity(value: &str) -> SavedGroupIdentityReference {
        SavedGroupIdentityReference::Key(
            SavedIdentityReferenceId::from_opaque(value).expect("identity ID"),
        )
    }

    #[test]
    fn complete_record_represents_every_legacy_field_without_password_bodies() {
        let defaults = SavedGroupDefaults {
            order: SavedGroupOverride::Set(
                SavedGroupFiniteNumber::new("order", 3.0).expect("order"),
            ),
            username: SavedGroupOverride::Set(text("alice")),
            password: SavedGroupCredentialOverride::StoredHint,
            save_password: SavedGroupOverride::Set(true),
            auth_method: SavedGroupOverride::Set(SavedGroupAuthMethod::Certificate),
            identity_id: SavedGroupOverride::Set(identity("identity")),
            identity_file_id: SavedGroupOverride::Set(
                SavedSshKeyReferenceId::from_opaque("key-file").expect("key ID"),
            ),
            identity_file_paths: SavedGroupOverride::Set(
                SavedGroupFilePaths::new(vec![text("C:\\keys\\id_ed25519")]).expect("paths"),
            ),
            port: SavedGroupOverride::Set(SavedGroupPort::new(22).expect("port")),
            protocol: SavedGroupOverride::Set(SavedGroupProtocol::Ssh),
            device_type: SavedGroupOverride::Set(SavedGroupDeviceType::Network),
            agent_forwarding: SavedGroupOverride::Set(true),
            proxy: SavedGroupProxyOverride::Inline(
                SavedProxyConfig::http("proxy.example.com", 8080, None, "proxy-user", true)
                    .expect("proxy"),
            ),
            host_chain: SavedGroupOverride::Set(
                SavedGroupHostChain::new(vec![
                    SavedHostId::from_opaque("jump-host").expect("host ID"),
                ])
                .expect("host chain"),
            ),
            startup_command: SavedGroupOverride::Set(
                SavedGroupText::new("first\nsecond").expect("command"),
            ),
            startup_command_run_mode: SavedGroupOverride::Set(
                SavedGroupStartupCommandRunMode::LineDelay,
            ),
            login_script_id: SavedGroupOverride::Set(
                SavedGroupOpaqueId::from_opaque("login-script").expect("script ID"),
            ),
            legacy_algorithms: SavedGroupOverride::Set(true),
            skip_ecdsa_host_key: SavedGroupOverride::Set(true),
            algorithms: SavedGroupOverride::Set(
                SavedGroupAlgorithmOverrides {
                    kex: Some(vec![
                        SavedGroupAlgorithmToken::new("curve25519-sha256").expect("algorithm"),
                    ]),
                    cipher: Some(vec![]),
                    hmac: None,
                    server_host_key: None,
                    compress: None,
                }
                .validate()
                .expect("algorithms"),
            ),
            environment_variables: SavedGroupOverride::Set(
                SavedGroupEnvironment::new(vec![
                    SavedGroupEnvironmentVariable::new("TERM", "xterm-256color")
                        .expect("environment"),
                ])
                .expect("environment"),
            ),
            charset: SavedGroupOverride::Set(text("utf-8")),
            mosh_enabled: SavedGroupOverride::Set(true),
            mosh_server_path: SavedGroupOverride::Set(text("/usr/bin/mosh-server")),
            et_enabled: SavedGroupOverride::Set(true),
            et_port: SavedGroupOverride::Set(SavedGroupPort::new(2022).expect("ET port")),
            telnet_enabled: SavedGroupOverride::Set(true),
            telnet_port: SavedGroupOverride::Set(SavedGroupPort::new(23).expect("Telnet port")),
            telnet_identity_id: SavedGroupOverride::Set(
                SavedPasswordIdentityId::from_opaque("telnet-identity").expect("identity"),
            ),
            telnet_username: SavedGroupOverride::Set(text("operator")),
            telnet_password: SavedGroupCredentialOverride::StoredHint,
            theme: SavedGroupOverride::Set(text("dark")),
            theme_override: SavedGroupOverride::Set(true),
            font_family: SavedGroupOverride::Set(text("jetbrains-mono")),
            font_family_override: SavedGroupOverride::Set(true),
            font_size: SavedGroupOverride::Set(
                SavedGroupFiniteNumber::new("font size", 14.0).expect("font size"),
            ),
            font_size_override: SavedGroupOverride::Set(true),
            font_weight: SavedGroupOverride::Set(
                SavedGroupFiniteNumber::new("font weight", 500.0).expect("font weight"),
            ),
            font_weight_override: SavedGroupOverride::Set(true),
            backspace_behavior: SavedGroupOverride::Set(SavedGroupBackspaceBehavior::CtrlH),
        };

        let saved = SavedGroupConfig::from_parts(
            SavedGroupId::from_opaque("group-record").expect("group ID"),
            7,
            path("Team/Production"),
            defaults.clone(),
            10,
            20,
        )
        .expect("complete record");
        assert_eq!(saved.defaults, defaults);
        assert_eq!(saved.revision, 7);
        assert_eq!(saved.path.as_str(), "Team/Production");
    }

    #[test]
    fn resolves_root_to_leaf_and_child_values_override_parent() {
        let configs = vec![
            record(
                "A",
                SavedGroupDefaults {
                    username: SavedGroupOverride::Set(text("root")),
                    port: SavedGroupOverride::Set(SavedGroupPort::new(22).expect("port")),
                    ..SavedGroupDefaults::default()
                },
            ),
            record(
                "A/B",
                SavedGroupDefaults {
                    username: SavedGroupOverride::Set(text("middle")),
                    ..SavedGroupDefaults::default()
                },
            ),
            record(
                "A/B/C",
                SavedGroupDefaults {
                    protocol: SavedGroupOverride::Set(SavedGroupProtocol::Telnet),
                    ..SavedGroupDefaults::default()
                },
            ),
        ];
        let resolved = resolve_group_defaults(&path("A/B/C"), &configs);
        assert_eq!(resolved.username, SavedGroupOverride::Set(text("middle")));
        assert_eq!(
            resolved.port,
            SavedGroupOverride::Set(SavedGroupPort::new(22).expect("port"))
        );
        assert_eq!(
            resolved.protocol,
            SavedGroupOverride::Set(SavedGroupProtocol::Telnet)
        );
    }

    #[test]
    fn duplicate_same_path_uses_last_record() {
        let configs = vec![
            record(
                "A/B",
                SavedGroupDefaults {
                    username: SavedGroupOverride::Set(text("first")),
                    ..SavedGroupDefaults::default()
                },
            ),
            record(
                "A/B",
                SavedGroupDefaults {
                    username: SavedGroupOverride::Set(text("last")),
                    ..SavedGroupDefaults::default()
                },
            ),
        ];
        assert_eq!(
            resolve_group_defaults(&path("A/B"), &configs).username,
            SavedGroupOverride::Set(text("last"))
        );
    }

    #[test]
    fn child_manual_ssh_bundle_replaces_parent_identity() {
        let resolved = resolve_group_defaults(
            &path("prod/manual"),
            &[
                record(
                    "prod",
                    SavedGroupDefaults {
                        identity_id: SavedGroupOverride::Set(identity("parent-identity")),
                        username: SavedGroupOverride::Set(text("stale-user")),
                        ..SavedGroupDefaults::default()
                    },
                ),
                record(
                    "prod/manual",
                    SavedGroupDefaults {
                        username: SavedGroupOverride::Set(text("child-user")),
                        password: SavedGroupCredentialOverride::StoredHint,
                        ..SavedGroupDefaults::default()
                    },
                ),
            ],
        );
        assert_eq!(resolved.identity_id, SavedGroupOverride::Inherit);
        assert_eq!(
            resolved.username,
            SavedGroupOverride::Set(text("child-user"))
        );
        assert_eq!(resolved.password, SavedGroupCredentialOverride::StoredHint);
    }

    #[test]
    fn child_identity_or_identity_clear_removes_inherited_manual_ssh_bundle() {
        for identity_override in [
            SavedGroupOverride::Set(identity("child-identity")),
            SavedGroupOverride::Clear,
        ] {
            let resolved = resolve_group_defaults(
                &path("prod/identity"),
                &[
                    record(
                        "prod",
                        SavedGroupDefaults {
                            username: SavedGroupOverride::Set(text("parent-user")),
                            password: SavedGroupCredentialOverride::StoredHint,
                            identity_file_paths: SavedGroupOverride::Set(
                                SavedGroupFilePaths::new(vec![text("parent-key")]).expect("paths"),
                            ),
                            ..SavedGroupDefaults::default()
                        },
                    ),
                    record(
                        "prod/identity",
                        SavedGroupDefaults {
                            identity_id: identity_override.clone(),
                            ..SavedGroupDefaults::default()
                        },
                    ),
                ],
            );
            assert_eq!(resolved.identity_id, identity_override);
            assert_eq!(resolved.username, SavedGroupOverride::Inherit);
            assert_eq!(resolved.password, SavedGroupCredentialOverride::Inherit);
            assert_eq!(resolved.identity_file_paths, SavedGroupOverride::Inherit);
        }
    }

    #[test]
    fn telnet_identity_and_manual_credentials_are_mutually_exclusive() {
        let manual = resolve_group_defaults(
            &path("A/B"),
            &[
                record(
                    "A",
                    SavedGroupDefaults {
                        telnet_identity_id: SavedGroupOverride::Set(
                            SavedPasswordIdentityId::from_opaque("parent").expect("identity"),
                        ),
                        ..SavedGroupDefaults::default()
                    },
                ),
                record(
                    "A/B",
                    SavedGroupDefaults {
                        telnet_username: SavedGroupOverride::Set(text("operator")),
                        telnet_password: SavedGroupCredentialOverride::StoredHint,
                        ..SavedGroupDefaults::default()
                    },
                ),
            ],
        );
        assert_eq!(manual.telnet_identity_id, SavedGroupOverride::Inherit);
        assert_eq!(
            manual.telnet_username,
            SavedGroupOverride::Set(text("operator"))
        );

        let cleared = resolve_group_defaults(
            &path("A/B"),
            &[
                record(
                    "A",
                    SavedGroupDefaults {
                        telnet_username: SavedGroupOverride::Set(text("parent")),
                        telnet_password: SavedGroupCredentialOverride::StoredHint,
                        ..SavedGroupDefaults::default()
                    },
                ),
                record(
                    "A/B",
                    SavedGroupDefaults {
                        telnet_identity_id: SavedGroupOverride::Clear,
                        ..SavedGroupDefaults::default()
                    },
                ),
            ],
        );
        assert_eq!(cleared.telnet_identity_id, SavedGroupOverride::Clear);
        assert_eq!(cleared.telnet_username, SavedGroupOverride::Inherit);
        assert_eq!(
            cleared.telnet_password,
            SavedGroupCredentialOverride::Inherit
        );
    }

    #[test]
    fn proxy_profile_inline_and_clear_share_one_slot() {
        let missing = SavedProxyProfileId::from_opaque("missing-profile").expect("profile ID");
        let resolved = resolve_group_defaults(
            &path("A/B"),
            &[
                record(
                    "A",
                    SavedGroupDefaults {
                        proxy: SavedGroupProxyOverride::Inline(
                            SavedProxyConfig::command("connect %h %p").expect("proxy"),
                        ),
                        ..SavedGroupDefaults::default()
                    },
                ),
                record(
                    "A/B",
                    SavedGroupDefaults {
                        proxy: SavedGroupProxyOverride::Profile(missing.clone()),
                        ..SavedGroupDefaults::default()
                    },
                ),
            ],
        );
        assert_eq!(resolved.proxy, SavedGroupProxyOverride::Profile(missing));

        let mut cleared = resolved;
        cleared.merge_from(&SavedGroupDefaults {
            proxy: SavedGroupProxyOverride::Clear,
            ..SavedGroupDefaults::default()
        });
        assert_eq!(cleared.proxy, SavedGroupProxyOverride::Clear);
    }

    #[test]
    fn false_style_override_ignores_same_level_value_and_keeps_parent_value() {
        let resolved = resolve_group_defaults(
            &path("A/B"),
            &[
                record(
                    "A",
                    SavedGroupDefaults {
                        theme: SavedGroupOverride::Set(text("parent-theme")),
                        theme_override: SavedGroupOverride::Set(true),
                        ..SavedGroupDefaults::default()
                    },
                ),
                record(
                    "A/B",
                    SavedGroupDefaults {
                        theme: SavedGroupOverride::Set(text("ignored-child-theme")),
                        theme_override: SavedGroupOverride::Set(false),
                        ..SavedGroupDefaults::default()
                    },
                ),
            ],
        );
        assert_eq!(
            resolved.theme,
            SavedGroupOverride::Set(text("parent-theme"))
        );
        assert_eq!(resolved.theme_override, SavedGroupOverride::Inherit);
    }

    #[test]
    fn clear_is_distinct_from_inherit_and_set() {
        let inherited: SavedGroupOverride<bool> = SavedGroupOverride::Inherit;
        let cleared = SavedGroupOverride::Clear;
        let set = SavedGroupOverride::Set(false);
        assert_ne!(inherited, cleared);
        assert_ne!(cleared, set);
        assert_ne!(inherited, set);
    }

    #[test]
    fn credential_slots_contain_only_state_not_password_text() {
        let states = [
            SavedGroupCredentialOverride::Inherit,
            SavedGroupCredentialOverride::Clear,
            SavedGroupCredentialOverride::StoredHint,
        ];
        assert_eq!(states.iter().filter(|state| state.is_defined()).count(), 2);
        assert_eq!(format!("{:?}", states), "[Inherit, Clear, StoredHint]");
    }

    #[test]
    fn strict_serde_round_trips_record_and_defaults_missing_to_inherit() {
        let saved = SavedGroupConfig::from_parts(
            SavedGroupId::from_opaque("serde-group").expect("group ID"),
            2,
            path("A/B"),
            SavedGroupDefaults {
                password: SavedGroupCredentialOverride::StoredHint,
                theme: SavedGroupOverride::Clear,
                backspace_behavior: SavedGroupOverride::Set(SavedGroupBackspaceBehavior::CtrlH),
                ..SavedGroupDefaults::default()
            },
            10,
            20,
        )
        .expect("saved group");
        let encoded = serde_json::to_value(&saved).expect("encode group");
        assert_eq!(encoded["recordVersion"], 1);
        assert_eq!(encoded["defaults"]["password"], "storedHint");
        assert_eq!(encoded["defaults"]["theme"]["state"], "clear");
        assert_eq!(encoded["defaults"]["backspaceBehavior"]["value"], "ctrl-h");
        assert!(encoded["defaults"]["password"].as_str().is_some());
        assert_eq!(
            serde_json::from_value::<SavedGroupConfig>(encoded).expect("decode group"),
            saved
        );

        let sparse: SavedGroupDefaults = serde_json::from_value(serde_json::json!({
            "protocol": { "state": "set", "value": "telnet" }
        }))
        .expect("sparse defaults");
        assert_eq!(sparse.username, SavedGroupOverride::Inherit);
        assert_eq!(sparse.password, SavedGroupCredentialOverride::Inherit);
        assert_eq!(
            sparse.protocol,
            SavedGroupOverride::Set(SavedGroupProtocol::Telnet)
        );
    }

    #[test]
    fn strict_serde_rejects_unknown_fields_and_credential_payloads() {
        assert!(
            serde_json::from_value::<SavedGroupDefaults>(serde_json::json!({
                "futureField": true
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<SavedGroupDefaults>(serde_json::json!({
                "password": { "state": "storedHint", "value": "secret" }
            }))
            .is_err()
        );

        let saved = record("A", SavedGroupDefaults::default());
        let mut encoded = serde_json::to_value(saved).expect("record JSON");
        encoded["unknownRecordField"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SavedGroupConfig>(encoded).is_err());
    }

    #[test]
    fn record_update_preserves_identity_and_advances_revision_and_time() {
        let saved = SavedGroupConfig::from_parts(
            SavedGroupId::from_opaque("stable-group").expect("group ID"),
            4,
            path("A"),
            SavedGroupDefaults::default(),
            10,
            20,
        )
        .expect("saved group");
        let updated = saved
            .apply_update(
                SavedGroupConfigUpdate {
                    path: Some(path("A/Renamed")),
                    defaults: Some(SavedGroupDefaults {
                        port: SavedGroupOverride::Set(SavedGroupPort::new(2222).expect("port")),
                        ..SavedGroupDefaults::default()
                    }),
                },
                20,
            )
            .expect("updated group");
        assert_eq!(updated.id, saved.id);
        assert_eq!(updated.created_at, 10);
        assert_eq!(updated.updated_at, 21);
        assert_eq!(updated.revision, 5);
        assert_eq!(updated.path.as_str(), "A/Renamed");
        assert_eq!(
            saved.apply_update(SavedGroupConfigUpdate::default(), 30),
            Err(SavedGroupConfigError::EmptyUpdate)
        );
    }

    #[test]
    fn inherited_credentials_keep_the_actual_ancestor_record_as_owner() {
        let parent_id = SavedGroupId::from_opaque("parent-owner").expect("group ID");
        let parent = SavedGroupConfig::from_parts(
            parent_id.clone(),
            1,
            path("A"),
            SavedGroupDefaults {
                password: SavedGroupCredentialOverride::StoredHint,
                telnet_password: SavedGroupCredentialOverride::StoredHint,
                proxy: SavedGroupProxyOverride::Inline(
                    SavedProxyConfig::http("proxy.example.com", 8080, None, "alice", true)
                        .expect("proxy"),
                ),
                ..SavedGroupDefaults::default()
            },
            1,
            1,
        )
        .expect("parent");
        let configs = vec![
            parent,
            record(
                "A/B",
                SavedGroupDefaults {
                    theme: SavedGroupOverride::Set(text("middle")),
                    ..SavedGroupDefaults::default()
                },
            ),
            record(
                "A/B/C",
                SavedGroupDefaults {
                    port: SavedGroupOverride::Set(SavedGroupPort::new(22).expect("port")),
                    ..SavedGroupDefaults::default()
                },
            ),
        ];

        let resolved = resolve_group_defaults_with_provenance(&path("A/B/C"), &configs);
        assert_eq!(resolved.ssh_credential_owner, Some(parent_id.clone()));
        assert_eq!(resolved.telnet_credential_owner, Some(parent_id.clone()));
        assert_eq!(resolved.inline_proxy_credential_owner, Some(parent_id));
        assert_eq!(
            resolved.defaults.password,
            SavedGroupCredentialOverride::StoredHint
        );
    }

    #[test]
    fn identity_profile_and_command_overrides_clear_credential_provenance() {
        let parent = SavedGroupConfig::from_parts(
            SavedGroupId::from_opaque("parent-owner").expect("group ID"),
            1,
            path("A"),
            SavedGroupDefaults {
                password: SavedGroupCredentialOverride::StoredHint,
                telnet_password: SavedGroupCredentialOverride::StoredHint,
                proxy: SavedGroupProxyOverride::Inline(
                    SavedProxyConfig::http("proxy.example.com", 8080, None, "alice", true)
                        .expect("proxy"),
                ),
                ..SavedGroupDefaults::default()
            },
            1,
            1,
        )
        .expect("parent");
        let child = record(
            "A/B",
            SavedGroupDefaults {
                identity_id: SavedGroupOverride::Set(identity("ssh-identity")),
                telnet_identity_id: SavedGroupOverride::Set(
                    SavedPasswordIdentityId::from_opaque("telnet-identity").expect("identity"),
                ),
                proxy: SavedGroupProxyOverride::Inline(
                    SavedProxyConfig::command("connect %h %p").expect("command proxy"),
                ),
                ..SavedGroupDefaults::default()
            },
        );
        let resolved = resolve_group_defaults_with_provenance(&path("A/B"), &[parent, child]);
        assert_eq!(resolved.ssh_credential_owner, None);
        assert_eq!(resolved.telnet_credential_owner, None);
        assert_eq!(resolved.inline_proxy_credential_owner, None);
    }
}
