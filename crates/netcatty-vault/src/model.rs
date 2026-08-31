use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use uuid::Uuid;

use crate::group::SavedGroupPath;
use crate::serial::{
    DEFAULT_SERIAL_BAUD_RATE, SavedSerialBackspaceBehavior, SavedSerialConfig,
    SavedSerialConfigError, normalize_serial_path,
};

pub(crate) const RECORD_VERSION: u32 = 1;
pub(crate) const AUTH_POLICY_VERSION: u8 = 1;
const DEFAULT_SSH_PORT: u32 = 22;
const DEFAULT_TELNET_PORT: u32 = 23;
const MAX_ID_BYTES: usize = 512;
const MAX_LABEL_BYTES: usize = 256;
const MAX_HOSTNAME_BYTES: usize = 253;
const MAX_USERNAME_BYTES: usize = 128;
const MAX_PROXY_USERNAME_BYTES: usize = 255;
const MAX_PROXY_COMMAND_BYTES: usize = 32 * 1024;
const MAX_FILE_PATH_BYTES: usize = 32 * 1024;
const MAX_COMPATIBILITY_KEY_BYTES: usize = 256;
const MAX_COMPATIBILITY_DEPTH: usize = 32;
const SECRET_OBJECT_LOCATOR_HEX_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    MissingField(&'static str),
    TooLong {
        field: &'static str,
        max_bytes: usize,
    },
    UnsafeCharacters(&'static str),
    InternalWhitespace(&'static str),
    InvalidPort,
    InvalidSerialConfig(SavedSerialConfigError),
    InvalidProxyConfig,
    InvalidGroupPath,
    InvalidAuthenticationConfiguration(&'static str),
    UnsupportedProtocol,
    UnsupportedAuthMethod,
    InvalidId,
    InvalidOpaqueId(&'static str),
    InvalidRevision,
    InvalidTimestamps,
    UnsupportedReferenceSource,
    UnsupportedManagedKeySource,
    UnsupportedReferenceAuthMethod,
    InvalidSecretObjectLocator,
    InvalidCustodyRevision,
    NonCanonicalField(&'static str),
    ForbiddenCompatibilityField(String),
    CompatibilityNestingTooDeep,
    EmptyUpdate,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(field) => write!(formatter, "{field} is required"),
            Self::TooLong { field, max_bytes } => {
                write!(formatter, "{field} exceeds {max_bytes} UTF-8 bytes")
            }
            Self::UnsafeCharacters(field) => {
                write!(formatter, "{field} contains unsafe control characters")
            }
            Self::InternalWhitespace(field) => {
                write!(formatter, "{field} must not contain whitespace")
            }
            Self::InvalidPort => formatter
                .write_str("port must be positive and SSH/Telnet ports must not exceed 65535"),
            Self::InvalidSerialConfig(error) => error.fmt(formatter),
            Self::InvalidProxyConfig => formatter.write_str("proxy configuration is invalid"),
            Self::InvalidGroupPath => formatter.write_str("saved group path is invalid"),
            Self::InvalidAuthenticationConfiguration(reason) => {
                write!(formatter, "saved-host authentication is invalid: {reason}")
            }
            Self::UnsupportedProtocol => {
                formatter.write_str("new saved hosts support SSH, Telnet, or Serial")
            }
            Self::UnsupportedAuthMethod => formatter.write_str(
                "new SSH saved hosts support password, key, or certificate authentication",
            ),
            Self::InvalidId => formatter.write_str("saved-host ID is invalid"),
            Self::InvalidOpaqueId(field) => write!(formatter, "{field} is invalid"),
            Self::InvalidRevision => formatter.write_str("saved-host revision is invalid"),
            Self::InvalidTimestamps => formatter.write_str("saved-host timestamps are invalid"),
            Self::UnsupportedReferenceSource => {
                formatter.write_str("saved SSH key metadata must reference a local file")
            }
            Self::UnsupportedManagedKeySource => {
                formatter.write_str("managed SSH key metadata must use an embedded key source")
            }
            Self::UnsupportedReferenceAuthMethod => formatter
                .write_str("saved identity metadata must use key or certificate authentication"),
            Self::InvalidSecretObjectLocator => {
                formatter.write_str("managed SSH key custody locator is invalid")
            }
            Self::InvalidCustodyRevision => {
                formatter.write_str("managed SSH key custody revision is invalid")
            }
            Self::NonCanonicalField(field) => {
                write!(formatter, "{field} is not in canonical form")
            }
            Self::ForbiddenCompatibilityField(field) => {
                write!(
                    formatter,
                    "compatibility field {field:?} may contain secret material"
                )
            }
            Self::CompatibilityNestingTooDeep => {
                formatter.write_str("compatibility fields are nested too deeply")
            }
            Self::EmptyUpdate => formatter.write_str("saved-host update contains no fields"),
        }
    }
}

impl std::error::Error for ValidationError {}

impl From<SavedSerialConfigError> for ValidationError {
    fn from(error: SavedSerialConfigError) -> Self {
        Self::InvalidSerialConfig(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SavedHostId(String);

impl SavedHostId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn from_opaque(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        validate_id(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SavedHostId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SavedHostId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SavedSshKeyReferenceId(String);

impl SavedSshKeyReferenceId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn from_opaque(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        validate_opaque_id("saved SSH key reference ID", &value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SavedSshKeyReferenceId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SavedSshKeyReferenceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SavedIdentityReferenceId(String);

impl SavedIdentityReferenceId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn from_opaque(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        validate_opaque_id("saved identity reference ID", &value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SavedIdentityReferenceId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SavedIdentityReferenceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Opaque identifier for a password identity.
///
/// Password identities intentionally use a distinct Rust type from
/// key/certificate identity references. The Vault graph still enforces one
/// shared string namespace across both identity catalogs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SavedPasswordIdentityId(String);

impl SavedPasswordIdentityId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn from_opaque(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        validate_opaque_id("saved password identity ID", &value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SavedPasswordIdentityId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SavedPasswordIdentityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Opaque identifier for a reusable proxy profile.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SavedProxyProfileId(String);

impl SavedProxyProfileId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn from_opaque(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        validate_opaque_id("saved proxy profile ID", &value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SavedProxyProfileId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SavedProxyProfileId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// An opaque, backend-only locator for one managed SSH secret object.
///
/// The canonical value is persisted in Vault snapshots, but diagnostics never
/// reveal it. Desktop adapters must not serialize this type to the renderer.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SavedSecretObjectLocator(String);

impl SavedSecretObjectLocator {
    pub fn from_hex(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        validate_secret_object_locator(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SavedSecretObjectLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SavedSecretObjectLocator([redacted])")
    }
}

impl fmt::Display for SavedSecretObjectLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted secret object locator]")
    }
}

impl Serialize for SavedSecretObjectLocator {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SavedSecretObjectLocator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SavedSshKeySource(String);

impl SavedSshKeySource {
    pub fn reference() -> Self {
        Self("reference".to_owned())
    }

    pub fn generated() -> Self {
        Self("generated".to_owned())
    }

    pub fn imported() -> Self {
        Self("imported".to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_reference(&self) -> bool {
        self.0.eq_ignore_ascii_case("reference")
    }

    pub fn is_managed(&self) -> bool {
        self.0.eq_ignore_ascii_case("generated") || self.0.eq_ignore_ascii_case("imported")
    }

    fn canonical_managed(&self) -> Option<Self> {
        if self.0.eq_ignore_ascii_case("generated") {
            Some(Self::generated())
        } else if self.0.eq_ignore_ascii_case("imported") {
            Some(Self::imported())
        } else {
            None
        }
    }
}

impl Default for SavedSshKeySource {
    fn default() -> Self {
        Self::reference()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SavedSshKeyCategory(String);

impl SavedSshKeyCategory {
    pub fn key() -> Self {
        Self("key".to_owned())
    }

    pub fn certificate() -> Self {
        Self("certificate".to_owned())
    }

    pub fn identity() -> Self {
        Self("identity".to_owned())
    }

    pub fn compatible(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_certificate(&self) -> bool {
        self.0.eq_ignore_ascii_case("certificate")
    }

    pub fn is_private_key_material(&self) -> bool {
        self.0.eq_ignore_ascii_case("key") || self.0.eq_ignore_ascii_case("identity")
    }

    fn canonical_managed(&self) -> Option<Self> {
        if self.0.eq_ignore_ascii_case("key") {
            Some(Self::key())
        } else if self.0.eq_ignore_ascii_case("identity") {
            Some(Self::identity())
        } else if self.0.eq_ignore_ascii_case("certificate") {
            Some(Self::certificate())
        } else {
            None
        }
    }
}

impl Default for SavedSshKeyCategory {
    fn default() -> Self {
        Self::key()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SavedIdentityAuthMethod(String);

impl SavedIdentityAuthMethod {
    pub fn key() -> Self {
        Self("key".to_owned())
    }

    pub fn certificate() -> Self {
        Self("certificate".to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_key(&self) -> bool {
        self.0.eq_ignore_ascii_case("key")
    }

    pub fn is_certificate(&self) -> bool {
        self.0.eq_ignore_ascii_case("certificate")
    }

    fn canonical_key_or_certificate(&self) -> Option<Self> {
        if self.is_key() {
            Some(Self::key())
        } else if self.is_certificate() {
            Some(Self::certificate())
        } else {
            None
        }
    }
}

impl Default for SavedIdentityAuthMethod {
    fn default() -> Self {
        Self::key()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SavedHostProtocol(String);

impl SavedHostProtocol {
    pub fn ssh() -> Self {
        Self("ssh".to_owned())
    }

    pub fn telnet() -> Self {
        Self("telnet".to_owned())
    }

    pub fn serial() -> Self {
        Self("serial".to_owned())
    }

    pub fn compatible(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_ssh(&self) -> bool {
        self.0.eq_ignore_ascii_case("ssh")
    }

    pub fn is_telnet(&self) -> bool {
        self.0.eq_ignore_ascii_case("telnet")
    }

    pub fn is_serial(&self) -> bool {
        self.0.eq_ignore_ascii_case("serial")
    }

    fn canonical_supported(&self) -> Option<Self> {
        if self.is_ssh() {
            Some(Self::ssh())
        } else if self.is_telnet() {
            Some(Self::telnet())
        } else if self.is_serial() {
            Some(Self::serial())
        } else {
            None
        }
    }

    fn default_port(&self) -> u32 {
        if self.is_telnet() {
            DEFAULT_TELNET_PORT
        } else if self.is_serial() {
            DEFAULT_SERIAL_BAUD_RATE
        } else {
            DEFAULT_SSH_PORT
        }
    }
}

impl Default for SavedHostProtocol {
    fn default() -> Self {
        Self::ssh()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SavedHostAuthMethod(String);

impl SavedHostAuthMethod {
    pub fn password() -> Self {
        Self("password".to_owned())
    }

    pub fn key() -> Self {
        Self("key".to_owned())
    }

    pub fn certificate() -> Self {
        Self("certificate".to_owned())
    }

    pub fn compatible(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_password(&self) -> bool {
        self.0.eq_ignore_ascii_case("password")
    }

    pub fn is_key(&self) -> bool {
        self.0.eq_ignore_ascii_case("key")
    }

    pub fn is_certificate(&self) -> bool {
        self.0.eq_ignore_ascii_case("certificate")
    }

    fn canonical_ssh(&self) -> Option<Self> {
        if self.is_password() {
            Some(Self::password())
        } else if self.is_key() {
            Some(Self::key())
        } else if self.is_certificate() {
            Some(Self::certificate())
        } else {
            None
        }
    }
}

impl Default for SavedHostAuthMethod {
    fn default() -> Self {
        Self::password()
    }
}

/// A typed, secret-free SSH authentication selection for a saved host.
///
/// The durable JSON remains compatible with Netcatty's original flattened
/// host shape (`authMethod`, `identityId`, `identityFileId`, and
/// `hasSavedCredential`). A password identity can retain the host-owned
/// credential hint because connection resolution deliberately falls back to
/// that password only when the identity credential is authoritatively absent.
/// Secret material is never carried by this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SavedHostAuthentication {
    DirectPassword {
        has_saved_credential: bool,
    },
    PasswordIdentity {
        identity_id: SavedPasswordIdentityId,
        has_saved_host_credential: bool,
    },
    ManagedPrivateKey {
        key_id: SavedSshKeyReferenceId,
    },
    ManagedCertificate {
        key_id: SavedSshKeyReferenceId,
    },
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SavedHost {
    pub record_version: u32,
    pub id: SavedHostId,
    pub revision: u64,
    pub label: String,
    pub hostname: String,
    pub port: u32,
    pub username: String,
    pub protocol: SavedHostProtocol,
    pub auth_method: SavedHostAuthMethod,
    pub auth_policy_version: u8,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(flatten)]
    compatibility_fields: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SavedHostWire {
    #[serde(default = "default_record_version")]
    record_version: u32,
    id: SavedHostId,
    #[serde(default = "default_revision")]
    revision: u64,
    #[serde(default)]
    label: String,
    hostname: String,
    #[serde(default)]
    port: Option<u32>,
    #[serde(default)]
    username: String,
    #[serde(default)]
    protocol: SavedHostProtocol,
    #[serde(default)]
    auth_method: SavedHostAuthMethod,
    #[serde(default = "default_auth_policy_version")]
    auth_policy_version: u8,
    created_at: u64,
    updated_at: u64,
    #[serde(flatten)]
    compatibility_fields: BTreeMap<String, Value>,
}

impl<'de> Deserialize<'de> for SavedHost {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SavedHostWire::deserialize(deserializer)?;
        let protocol = wire.protocol;
        let serial_config = if protocol.is_serial() {
            parse_serial_config(wire.compatibility_fields.get("serialConfig"))
                .map_err(serde::de::Error::custom)?
        } else {
            None
        };
        let endpoint = serial_config
            .as_ref()
            .map_or(wire.hostname.as_str(), |config| config.path.as_str());
        let hostname =
            normalize_host_endpoint(&protocol, endpoint).map_err(serde::de::Error::custom)?;
        let label = if wire.label.trim().is_empty() {
            hostname.clone()
        } else {
            normalize_label(&wire.label).map_err(serde::de::Error::custom)?
        };
        let username = normalize_username(&wire.username).map_err(serde::de::Error::custom)?;
        let port = serial_config.as_ref().map_or_else(
            || wire.port.unwrap_or_else(|| protocol.default_port()),
            |config| config.baud_rate,
        );
        let host = Self {
            record_version: wire.record_version,
            id: wire.id,
            revision: wire.revision,
            label,
            hostname,
            port,
            username,
            protocol,
            auth_method: wire.auth_method,
            auth_policy_version: wire.auth_policy_version,
            created_at: wire.created_at,
            updated_at: wire.updated_at,
            compatibility_fields: wire.compatibility_fields,
        };
        host.validate().map_err(serde::de::Error::custom)?;
        Ok(host)
    }
}

impl SavedHost {
    pub fn compatibility_fields(&self) -> &BTreeMap<String, Value> {
        &self.compatibility_fields
    }

    /// Parses the active legacy `serialConfig` object without mutating the
    /// durable flattened host JSON. A dormant Serial config on another
    /// protocol remains compatibility metadata and has no runtime authority.
    pub fn serial_config(&self) -> Result<Option<SavedSerialConfig>, ValidationError> {
        if !self.protocol.is_serial() {
            return Ok(None);
        }
        parse_serial_config(self.compatibility_fields.get("serialConfig"))
    }

    /// Returns the complete launch-time Serial configuration. Old Serial
    /// hosts that predate `serialConfig` fall back to `hostname`, `port`, and
    /// the legacy 8-N-1/no-flow/no-echo defaults.
    pub fn effective_serial_config(&self) -> Result<SavedSerialConfig, ValidationError> {
        if !self.protocol.is_serial() {
            return Err(ValidationError::UnsupportedProtocol);
        }
        let mut config = match self.serial_config()? {
            Some(config) => config,
            None => SavedSerialConfig::new(self.hostname.clone(), self.port)?,
        };
        if config.backspace_behavior.is_none() {
            config.backspace_behavior = Some(parse_serial_backspace_behavior(
                self.compatibility_fields.get("backspaceBehavior"),
            )?);
        }
        Ok(config)
    }

    /// Narrows an active SSH/Telnet endpoint at the protocol boundary. The
    /// durable `port` remains `u32` so Serial baud rates such as 921600 can
    /// retain the original host JSON shape.
    pub fn network_port(&self) -> Result<u16, ValidationError> {
        if !self.protocol.is_ssh() && !self.protocol.is_telnet() {
            return Err(ValidationError::UnsupportedProtocol);
        }
        u16::try_from(self.port)
            .ok()
            .filter(|port| *port > 0)
            .ok_or(ValidationError::InvalidPort)
    }

    /// Parses the flattened inline proxy compatibility field without moving
    /// it into the normal saved-host record shape. Primary Telnet records keep
    /// the legacy field serialized but do not expose it as an active proxy.
    pub fn proxy_config(&self) -> Result<Option<SavedProxyConfig>, ValidationError> {
        if self.protocol.is_telnet() || self.protocol.is_serial() {
            return Ok(None);
        }
        parse_proxy_config(self.compatibility_fields.get("proxyConfig"))
    }

    /// Parses the flattened proxy-profile relationship field. Primary Telnet
    /// records retain the field only for compatibility.
    pub fn proxy_profile_id(&self) -> Result<Option<SavedProxyProfileId>, ValidationError> {
        if self.protocol.is_telnet() || self.protocol.is_serial() {
            return Ok(None);
        }
        parse_proxy_profile_id(self.compatibility_fields.get("proxyProfileId"))
    }

    /// Returns the legacy-compatible logical group path. Empty values mean
    /// the host is at the Vault root; only `/` has hierarchy semantics.
    pub fn group_path(&self) -> Result<Option<SavedGroupPath>, ValidationError> {
        parse_group_path(self.compatibility_fields.get("group"))
    }

    /// Returns the native SSH authentication selection represented by the
    /// original Netcatty-compatible flattened host fields.
    ///
    /// Legacy key/certificate identities that only carry `identityId` remain
    /// readable and round-trippable, but are not reported as a managed-key
    /// selection until their resolved `identityFileId` is present.
    pub fn authentication(&self) -> Result<SavedHostAuthentication, ValidationError> {
        if !self.protocol.is_ssh() {
            return Err(ValidationError::UnsupportedProtocol);
        }
        validate_new_host_authentication(&self.auth_method, &self.compatibility_fields, true)?;
        if self.auth_method.is_password() {
            if let Some(identity_id) = host_password_identity_id(&self.compatibility_fields)? {
                return Ok(SavedHostAuthentication::PasswordIdentity {
                    identity_id,
                    has_saved_host_credential: host_saved_credential_hint(
                        &self.compatibility_fields,
                    )?,
                });
            }
            return Ok(SavedHostAuthentication::DirectPassword {
                has_saved_credential: host_saved_credential_hint(&self.compatibility_fields)?,
            });
        }
        let key_id = host_key_reference_id(&self.compatibility_fields)?.ok_or(
            ValidationError::InvalidAuthenticationConfiguration(
                "managed key or certificate authentication requires identityFileId",
            ),
        )?;
        if self.auth_method.is_key() {
            Ok(SavedHostAuthentication::ManagedPrivateKey { key_id })
        } else if self.auth_method.is_certificate() {
            Ok(SavedHostAuthentication::ManagedCertificate { key_id })
        } else {
            Err(ValidationError::UnsupportedAuthMethod)
        }
    }

    /// Replaces only the flattened, secret-free compatibility metadata on a
    /// connection-time clone.
    ///
    /// Group defaults are projected through this crate-private boundary so
    /// callers cannot mutate a durable [`SavedHost`] record in place. The
    /// returned value keeps the original identity, revision, and timestamps
    /// and is validated with the same rules as a persisted host.
    pub(crate) fn with_projected_compatibility_fields(
        &self,
        compatibility_fields: BTreeMap<String, Value>,
    ) -> Result<Self, ValidationError> {
        validate_compatibility_fields(&compatibility_fields)?;
        let mut projected = self.clone();
        projected.compatibility_fields = compatibility_fields;
        projected.validate()?;
        Ok(projected)
    }

    /// Builds and validates a new saved-host record without publishing it.
    ///
    /// Cross-store coordinators use this pure constructor to seal a complete
    /// before/after Vault graph before any credential side effect occurs.
    pub fn from_draft(mut draft: SavedHostDraft, now: u64) -> Result<Self, ValidationError> {
        validate_compatibility_fields(&draft.compatibility_fields)?;
        let protocol = draft
            .protocol
            .take()
            .unwrap_or_default()
            .canonical_supported()
            .ok_or(ValidationError::UnsupportedProtocol)?;
        if protocol.is_serial() {
            if let Some(config) =
                parse_serial_config(draft.compatibility_fields.get("serialConfig"))?
            {
                draft.hostname = config.path;
                draft.port = Some(config.baud_rate);
            }
        }
        let hostname = normalize_host_endpoint(&protocol, &draft.hostname)?;
        let label = match draft.label {
            Some(label) if !label.trim().is_empty() => normalize_label(&label)?,
            _ => hostname.clone(),
        };
        let username = normalize_username(&draft.username)?;
        let port = normalize_host_port(
            &protocol,
            draft.port.unwrap_or_else(|| protocol.default_port()),
        )?;
        let auth_method = draft.auth_method.unwrap_or_default();
        let auth_method = if protocol.is_ssh() {
            auth_method
                .canonical_ssh()
                .ok_or(ValidationError::UnsupportedAuthMethod)?
        } else {
            auth_method
        };
        if protocol.is_ssh() {
            validate_new_host_authentication(&auth_method, &draft.compatibility_fields, false)?;
        }
        let host = Self {
            record_version: RECORD_VERSION,
            id: SavedHostId::new(),
            revision: 1,
            label,
            hostname,
            port,
            username,
            protocol,
            auth_method,
            auth_policy_version: AUTH_POLICY_VERSION,
            created_at: now,
            updated_at: now,
            compatibility_fields: draft.compatibility_fields,
        };
        host.validate()?;
        Ok(host)
    }

    /// Applies and validates an update without publishing it.
    ///
    /// The returned record preserves the ID and creation time while advancing
    /// the optimistic revision, allowing callers to plan one complete-graph
    /// transaction before touching an external secret store.
    pub fn apply_update(&self, update: SavedHostUpdate, now: u64) -> Result<Self, ValidationError> {
        if self.protocol.canonical_supported().is_none() {
            return Err(ValidationError::UnsupportedProtocol);
        }
        if update.is_empty() {
            return Err(ValidationError::EmptyUpdate);
        }
        validate_compatibility_fields(&update.compatibility_fields)?;
        let hostname_updated = update.hostname.is_some();
        let port_updated = update.port.is_some();
        let protocol_updated = update.protocol.is_some();
        let serial_config_update = update.compatibility_fields.get("serialConfig").cloned();
        let mut next = self.clone();
        if let Some(label) = update.label {
            next.label = normalize_label(&label)?;
        }
        if let Some(protocol) = update.protocol {
            next.protocol = protocol
                .canonical_supported()
                .ok_or(ValidationError::UnsupportedProtocol)?;
        }
        if let Some(hostname) = update.hostname {
            next.hostname = normalize_host_endpoint(&next.protocol, &hostname)?;
        } else if protocol_updated {
            next.hostname = normalize_host_endpoint(&next.protocol, &next.hostname)?;
        }
        if let Some(port) = update.port {
            next.port = normalize_host_port(&next.protocol, port)?;
        } else if protocol_updated {
            next.port = normalize_host_port(&next.protocol, next.port)?;
        }
        if let Some(username) = update.username {
            next.username = normalize_username(&username)?;
        }
        if let Some(auth_method) = update.auth_method {
            let auth_method = if next.protocol.is_ssh() {
                auth_method
                    .canonical_ssh()
                    .ok_or(ValidationError::UnsupportedAuthMethod)?
            } else {
                auth_method
            };
            if !next
                .auth_method
                .as_str()
                .eq_ignore_ascii_case(auth_method.as_str())
            {
                clear_host_authentication_fields(&mut next.compatibility_fields, false);
            }
            next.auth_method = auth_method;
        }
        for (key, value) in update.compatibility_fields {
            if value.is_null() {
                next.compatibility_fields.remove(&key);
            } else {
                next.compatibility_fields.insert(key, value);
            }
        }
        if next.protocol.is_serial() {
            match serial_config_update {
                Some(Value::Null) => {}
                Some(value) => {
                    let config = parse_serial_config(Some(&value))?.ok_or(
                        ValidationError::InvalidSerialConfig(SavedSerialConfigError::MissingPath),
                    )?;
                    next.hostname = config.path;
                    next.port = config.baud_rate;
                }
                None if hostname_updated || port_updated => {
                    if let Some(mut config) = next.serial_config()? {
                        config.path = next.hostname.clone();
                        config.baud_rate = next.port;
                        config.validate()?;
                        next.compatibility_fields.insert(
                            "serialConfig".to_owned(),
                            serde_json::to_value(config).map_err(|_| {
                                ValidationError::InvalidSerialConfig(
                                    SavedSerialConfigError::MalformedConfig,
                                )
                            })?,
                        );
                    }
                }
                None if protocol_updated => {
                    if let Some(config) = next.serial_config()? {
                        next.hostname = config.path;
                        next.port = config.baud_rate;
                    }
                }
                None => {}
            }
        }
        if next.protocol.is_ssh() {
            validate_new_host_authentication(&next.auth_method, &next.compatibility_fields, false)?;
        }
        next.record_version = RECORD_VERSION;
        next.auth_policy_version = AUTH_POLICY_VERSION;
        next.revision = self
            .revision
            .checked_add(1)
            .ok_or(ValidationError::InvalidRevision)?;
        next.updated_at = now.max(self.updated_at.saturating_add(1));
        next.validate()?;
        Ok(next)
    }

    pub(crate) fn validate(&self) -> Result<(), ValidationError> {
        validate_id(self.id.as_str())?;
        if self.revision == 0 {
            return Err(ValidationError::InvalidRevision);
        }
        validate_canonical("label", &self.label, normalize_label(&self.label)?)?;
        validate_canonical(
            "hostname",
            &self.hostname,
            normalize_host_endpoint(&self.protocol, &self.hostname)?,
        )?;
        validate_canonical(
            "username",
            &self.username,
            normalize_username(&self.username)?,
        )?;
        normalize_host_port(&self.protocol, self.port)?;
        validate_token("protocol", self.protocol.as_str())?;
        validate_token("authMethod", self.auth_method.as_str())?;
        if self.created_at > self.updated_at {
            return Err(ValidationError::InvalidTimestamps);
        }
        validate_compatibility_fields(&self.compatibility_fields)?;
        if self.protocol.is_serial() {
            let config = self.serial_config()?;
            if config
                .as_ref()
                .is_some_and(|config| config.path != self.hostname || config.baud_rate != self.port)
            {
                return Err(ValidationError::InvalidSerialConfig(
                    SavedSerialConfigError::EndpointMismatch,
                ));
            }
            if config
                .as_ref()
                .is_none_or(|config| config.backspace_behavior.is_none())
            {
                parse_serial_backspace_behavior(
                    self.compatibility_fields.get("backspaceBehavior"),
                )?;
            }
        }
        Ok(())
    }

    pub(crate) fn stable_cmp(left: &Self, right: &Self) -> Ordering {
        left.label
            .to_lowercase()
            .cmp(&right.label.to_lowercase())
            .then_with(|| left.label.cmp(&right.label))
            .then_with(|| {
                left.hostname
                    .to_lowercase()
                    .cmp(&right.hostname.to_lowercase())
            })
            .then_with(|| left.port.cmp(&right.port))
            .then_with(|| {
                left.username
                    .to_lowercase()
                    .cmp(&right.username.to_lowercase())
            })
            .then_with(|| left.id.cmp(&right.id))
    }
}

/// Secret-free metadata for an SSH key that remains in a user-selected local
/// file. The referenced file is never opened by this model or the Vault
/// store.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SavedSshKeyReference {
    pub id: SavedSshKeyReferenceId,
    pub label: String,
    pub file_path: String,
    pub category: SavedSshKeyCategory,
    pub source: SavedSshKeySource,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(flatten)]
    compatibility_fields: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SavedSshKeyReferenceWire {
    id: SavedSshKeyReferenceId,
    label: String,
    file_path: String,
    #[serde(default)]
    category: SavedSshKeyCategory,
    #[serde(default)]
    source: SavedSshKeySource,
    created_at: u64,
    updated_at: u64,
    #[serde(flatten)]
    compatibility_fields: BTreeMap<String, Value>,
}

impl<'de> Deserialize<'de> for SavedSshKeyReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SavedSshKeyReferenceWire::deserialize(deserializer)?;
        let source = if wire.source.is_reference() {
            SavedSshKeySource::reference()
        } else {
            return Err(serde::de::Error::custom(
                ValidationError::UnsupportedReferenceSource,
            ));
        };
        let reference = Self {
            id: wire.id,
            label: normalize_label(&wire.label).map_err(serde::de::Error::custom)?,
            file_path: normalize_file_path(&wire.file_path).map_err(serde::de::Error::custom)?,
            category: wire.category,
            source,
            created_at: wire.created_at,
            updated_at: wire.updated_at,
            compatibility_fields: wire.compatibility_fields,
        };
        reference.validate().map_err(serde::de::Error::custom)?;
        Ok(reference)
    }
}

impl SavedSshKeyReference {
    pub fn from_parts(
        id: SavedSshKeyReferenceId,
        label: impl Into<String>,
        file_path: impl Into<String>,
        category: SavedSshKeyCategory,
        created_at: u64,
        updated_at: u64,
        compatibility_fields: BTreeMap<String, Value>,
    ) -> Result<Self, ValidationError> {
        let reference = Self {
            id,
            label: normalize_label(&label.into())?,
            file_path: normalize_file_path(&file_path.into())?,
            category,
            source: SavedSshKeySource::reference(),
            created_at,
            updated_at,
            compatibility_fields,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn compatibility_fields(&self) -> &BTreeMap<String, Value> {
        &self.compatibility_fields
    }

    pub fn with_compatibility_field(
        mut self,
        key: impl Into<String>,
        value: Value,
    ) -> Result<Self, ValidationError> {
        let key = key.into();
        let candidate = BTreeMap::from([(key.clone(), value.clone())]);
        validate_key_compatibility_fields(&candidate)?;
        self.compatibility_fields.insert(key, value);
        self.validate()?;
        Ok(self)
    }

    pub(crate) fn validate(&self) -> Result<(), ValidationError> {
        validate_opaque_id("saved SSH key reference ID", self.id.as_str())?;
        validate_canonical("label", &self.label, normalize_label(&self.label)?)?;
        validate_canonical(
            "filePath",
            &self.file_path,
            normalize_file_path(&self.file_path)?,
        )?;
        validate_token("category", self.category.as_str())?;
        validate_token("source", self.source.as_str())?;
        if !self.source.is_reference() {
            return Err(ValidationError::UnsupportedReferenceSource);
        }
        if self.created_at > self.updated_at {
            return Err(ValidationError::InvalidTimestamps);
        }
        validate_key_compatibility_fields(&self.compatibility_fields)
    }

    pub(crate) fn stable_cmp(left: &Self, right: &Self) -> Ordering {
        left.label
            .to_lowercase()
            .cmp(&right.label.to_lowercase())
            .then_with(|| left.label.cmp(&right.label))
            .then_with(|| left.id.cmp(&right.id))
    }
}

/// Secret-free pointer from a managed key record to an encrypted secret-blob
/// revision. The locator is backend-only and is always redacted from
/// diagnostics.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SavedSshKeyCustodyReference {
    backend_locator: SavedSecretObjectLocator,
    custody_revision: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SavedSshKeyCustodyReferenceWire {
    backend_locator: SavedSecretObjectLocator,
    custody_revision: u64,
}

impl<'de> Deserialize<'de> for SavedSshKeyCustodyReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SavedSshKeyCustodyReferenceWire::deserialize(deserializer)?;
        Self::new(wire.backend_locator, wire.custody_revision).map_err(serde::de::Error::custom)
    }
}

impl SavedSshKeyCustodyReference {
    pub fn new(
        backend_locator: SavedSecretObjectLocator,
        custody_revision: u64,
    ) -> Result<Self, ValidationError> {
        let reference = Self {
            backend_locator,
            custody_revision,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn backend_locator(&self) -> &SavedSecretObjectLocator {
        &self.backend_locator
    }

    pub fn custody_revision(&self) -> u64 {
        self.custody_revision
    }

    fn validate(&self) -> Result<(), ValidationError> {
        validate_secret_object_locator(self.backend_locator.as_str())?;
        if self.custody_revision == 0 {
            return Err(ValidationError::InvalidCustodyRevision);
        }
        Ok(())
    }
}

impl fmt::Debug for SavedSshKeyCustodyReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SavedSshKeyCustodyReference([redacted])")
    }
}

/// Secret-free metadata for a private key/certificate whose bytes are held by
/// the managed encrypted secret store. This type is persisted by Vault but
/// must never be used directly as a renderer DTO.
#[derive(Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SavedManagedSshKey {
    pub id: SavedSshKeyReferenceId,
    pub label: String,
    pub category: SavedSshKeyCategory,
    pub source: SavedSshKeySource,
    pub has_saved_passphrase: bool,
    pub created_at: u64,
    pub updated_at: u64,
    custody: SavedSshKeyCustodyReference,
    #[serde(flatten)]
    compatibility_fields: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SavedManagedSshKeyWire {
    id: SavedSshKeyReferenceId,
    label: String,
    category: SavedSshKeyCategory,
    source: SavedSshKeySource,
    #[serde(default)]
    has_saved_passphrase: bool,
    created_at: u64,
    updated_at: u64,
    custody: SavedSshKeyCustodyReference,
    #[serde(flatten)]
    compatibility_fields: BTreeMap<String, Value>,
}

impl<'de> Deserialize<'de> for SavedManagedSshKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SavedManagedSshKeyWire::deserialize(deserializer)?;
        Self::from_parts(
            wire.id,
            wire.label,
            wire.category,
            wire.source,
            wire.has_saved_passphrase,
            wire.created_at,
            wire.updated_at,
            wire.custody,
            wire.compatibility_fields,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl SavedManagedSshKey {
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        id: SavedSshKeyReferenceId,
        label: impl Into<String>,
        category: SavedSshKeyCategory,
        source: SavedSshKeySource,
        has_saved_passphrase: bool,
        created_at: u64,
        updated_at: u64,
        custody: SavedSshKeyCustodyReference,
        compatibility_fields: BTreeMap<String, Value>,
    ) -> Result<Self, ValidationError> {
        let source = source
            .canonical_managed()
            .ok_or(ValidationError::UnsupportedManagedKeySource)?;
        let category = category
            .canonical_managed()
            .ok_or(ValidationError::NonCanonicalField("category"))?;
        let key = Self {
            id,
            label: normalize_label(&label.into())?,
            category,
            source,
            has_saved_passphrase,
            created_at,
            updated_at,
            custody,
            compatibility_fields,
        };
        key.validate()?;
        Ok(key)
    }

    pub fn custody(&self) -> &SavedSshKeyCustodyReference {
        &self.custody
    }

    pub fn compatibility_fields(&self) -> &BTreeMap<String, Value> {
        &self.compatibility_fields
    }

    pub fn with_compatibility_field(
        mut self,
        key: impl Into<String>,
        value: Value,
    ) -> Result<Self, ValidationError> {
        let key = key.into();
        let candidate = BTreeMap::from([(key.clone(), value.clone())]);
        validate_managed_key_compatibility_fields(&candidate)?;
        self.compatibility_fields.insert(key, value);
        self.validate()?;
        Ok(self)
    }

    pub(crate) fn validate(&self) -> Result<(), ValidationError> {
        validate_opaque_id("saved managed SSH key ID", self.id.as_str())?;
        validate_canonical("label", &self.label, normalize_label(&self.label)?)?;
        validate_token("category", self.category.as_str())?;
        if self.category.canonical_managed().as_ref() != Some(&self.category) {
            return Err(ValidationError::NonCanonicalField("category"));
        }
        validate_token("source", self.source.as_str())?;
        if !self.source.is_managed()
            || self.source.canonical_managed().as_ref() != Some(&self.source)
        {
            return Err(ValidationError::UnsupportedManagedKeySource);
        }
        if self.created_at > self.updated_at {
            return Err(ValidationError::InvalidTimestamps);
        }
        self.custody.validate()?;
        validate_managed_key_compatibility_fields(&self.compatibility_fields)
    }

    pub(crate) fn stable_cmp(left: &Self, right: &Self) -> Ordering {
        left.label
            .to_lowercase()
            .cmp(&right.label.to_lowercase())
            .then_with(|| left.label.cmp(&right.label))
            .then_with(|| left.id.cmp(&right.id))
    }
}

impl fmt::Debug for SavedManagedSshKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SavedManagedSshKey")
            .field("category", &self.category)
            .field("source", &self.source)
            .field("has_saved_passphrase", &self.has_saved_passphrase)
            .field("custody", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// Secret-free identity metadata whose authentication key resolves to either
/// a reference-file key or a managed encrypted key. Password identities
/// deliberately cannot be represented by this type.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SavedIdentityReference {
    pub id: SavedIdentityReferenceId,
    pub label: String,
    pub username: String,
    pub auth_method: SavedIdentityAuthMethod,
    pub key_id: SavedSshKeyReferenceId,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(flatten)]
    compatibility_fields: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SavedIdentityReferenceWire {
    id: SavedIdentityReferenceId,
    label: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    auth_method: SavedIdentityAuthMethod,
    key_id: SavedSshKeyReferenceId,
    created_at: u64,
    updated_at: u64,
    #[serde(flatten)]
    compatibility_fields: BTreeMap<String, Value>,
}

impl<'de> Deserialize<'de> for SavedIdentityReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SavedIdentityReferenceWire::deserialize(deserializer)?;
        let auth_method = wire
            .auth_method
            .canonical_key_or_certificate()
            .ok_or(ValidationError::UnsupportedReferenceAuthMethod)
            .map_err(serde::de::Error::custom)?;
        let reference = Self {
            id: wire.id,
            label: normalize_label(&wire.label).map_err(serde::de::Error::custom)?,
            username: normalize_username(&wire.username).map_err(serde::de::Error::custom)?,
            auth_method,
            key_id: wire.key_id,
            created_at: wire.created_at,
            updated_at: wire.updated_at,
            compatibility_fields: wire.compatibility_fields,
        };
        reference.validate().map_err(serde::de::Error::custom)?;
        Ok(reference)
    }
}

impl SavedIdentityReference {
    pub fn from_parts(
        id: SavedIdentityReferenceId,
        label: impl Into<String>,
        username: impl Into<String>,
        key_id: SavedSshKeyReferenceId,
        created_at: u64,
        updated_at: u64,
        compatibility_fields: BTreeMap<String, Value>,
    ) -> Result<Self, ValidationError> {
        let reference = Self {
            id,
            label: normalize_label(&label.into())?,
            username: normalize_username(&username.into())?,
            auth_method: SavedIdentityAuthMethod::key(),
            key_id,
            created_at,
            updated_at,
            compatibility_fields,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn from_certificate_parts(
        id: SavedIdentityReferenceId,
        label: impl Into<String>,
        username: impl Into<String>,
        key_id: SavedSshKeyReferenceId,
        created_at: u64,
        updated_at: u64,
        compatibility_fields: BTreeMap<String, Value>,
    ) -> Result<Self, ValidationError> {
        let reference = Self {
            id,
            label: normalize_label(&label.into())?,
            username: normalize_username(&username.into())?,
            auth_method: SavedIdentityAuthMethod::certificate(),
            key_id,
            created_at,
            updated_at,
            compatibility_fields,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn compatibility_fields(&self) -> &BTreeMap<String, Value> {
        &self.compatibility_fields
    }

    pub fn with_compatibility_field(
        mut self,
        key: impl Into<String>,
        value: Value,
    ) -> Result<Self, ValidationError> {
        let key = key.into();
        let candidate = BTreeMap::from([(key.clone(), value.clone())]);
        validate_identity_compatibility_fields(&candidate)?;
        self.compatibility_fields.insert(key, value);
        self.validate()?;
        Ok(self)
    }

    pub(crate) fn validate(&self) -> Result<(), ValidationError> {
        validate_opaque_id("saved identity reference ID", self.id.as_str())?;
        validate_opaque_id("saved SSH key reference ID", self.key_id.as_str())?;
        validate_canonical("label", &self.label, normalize_label(&self.label)?)?;
        validate_canonical(
            "username",
            &self.username,
            normalize_username(&self.username)?,
        )?;
        validate_token("authMethod", self.auth_method.as_str())?;
        if !self.auth_method.is_key() && !self.auth_method.is_certificate() {
            return Err(ValidationError::UnsupportedReferenceAuthMethod);
        }
        if self.created_at > self.updated_at {
            return Err(ValidationError::InvalidTimestamps);
        }
        validate_identity_compatibility_fields(&self.compatibility_fields)
    }

    pub(crate) fn stable_cmp(left: &Self, right: &Self) -> Ordering {
        left.label
            .to_lowercase()
            .cmp(&right.label.to_lowercase())
            .then_with(|| left.label.cmp(&right.label))
            .then_with(|| left.id.cmp(&right.id))
    }
}

/// Secret-free proxy configuration shared by profiles and inline host
/// overrides. Password material has no representable field.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(
    tag = "type",
    rename_all = "lowercase",
    rename_all_fields = "camelCase"
)]
pub enum SavedProxyConfig {
    Http {
        host: String,
        port: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        identity_id: Option<SavedPasswordIdentityId>,
        #[serde(default)]
        username: String,
        #[serde(default)]
        has_saved_credential: bool,
        #[serde(flatten)]
        compatibility_fields: BTreeMap<String, Value>,
    },
    Socks5 {
        host: String,
        port: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        identity_id: Option<SavedPasswordIdentityId>,
        #[serde(default)]
        username: String,
        #[serde(default)]
        has_saved_credential: bool,
        #[serde(flatten)]
        compatibility_fields: BTreeMap<String, Value>,
    },
    Command {
        command: String,
        #[serde(flatten)]
        compatibility_fields: BTreeMap<String, Value>,
    },
}

#[derive(Deserialize)]
#[serde(
    tag = "type",
    rename_all = "lowercase",
    rename_all_fields = "camelCase"
)]
enum SavedProxyConfigWire {
    Http {
        host: String,
        port: u32,
        #[serde(default)]
        identity_id: Option<SavedPasswordIdentityId>,
        #[serde(default)]
        username: String,
        #[serde(default)]
        has_saved_credential: bool,
        #[serde(flatten)]
        compatibility_fields: BTreeMap<String, Value>,
    },
    Socks5 {
        host: String,
        port: u32,
        #[serde(default)]
        identity_id: Option<SavedPasswordIdentityId>,
        #[serde(default)]
        username: String,
        #[serde(default)]
        has_saved_credential: bool,
        #[serde(flatten)]
        compatibility_fields: BTreeMap<String, Value>,
    },
    Command {
        command: String,
        #[serde(flatten)]
        compatibility_fields: BTreeMap<String, Value>,
    },
}

impl<'de> Deserialize<'de> for SavedProxyConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SavedProxyConfigWire::deserialize(deserializer)?;
        let config = match wire {
            SavedProxyConfigWire::Http {
                host,
                port,
                identity_id,
                username,
                has_saved_credential,
                compatibility_fields,
            } => Self::network(
                true,
                host,
                port,
                identity_id,
                username,
                has_saved_credential,
                compatibility_fields,
            ),
            SavedProxyConfigWire::Socks5 {
                host,
                port,
                identity_id,
                username,
                has_saved_credential,
                compatibility_fields,
            } => Self::network(
                false,
                host,
                port,
                identity_id,
                username,
                has_saved_credential,
                compatibility_fields,
            ),
            SavedProxyConfigWire::Command {
                command,
                compatibility_fields,
            } => Self::command_with_compatibility(command, compatibility_fields),
        };
        config.map_err(serde::de::Error::custom)
    }
}

impl SavedProxyConfig {
    pub fn http(
        host: impl Into<String>,
        port: u32,
        identity_id: Option<SavedPasswordIdentityId>,
        username: impl Into<String>,
        has_saved_credential: bool,
    ) -> Result<Self, ValidationError> {
        Self::network(
            true,
            host.into(),
            port,
            identity_id,
            username.into(),
            has_saved_credential,
            BTreeMap::new(),
        )
    }

    pub fn socks5(
        host: impl Into<String>,
        port: u32,
        identity_id: Option<SavedPasswordIdentityId>,
        username: impl Into<String>,
        has_saved_credential: bool,
    ) -> Result<Self, ValidationError> {
        Self::network(
            false,
            host.into(),
            port,
            identity_id,
            username.into(),
            has_saved_credential,
            BTreeMap::new(),
        )
    }

    pub fn command(command: impl Into<String>) -> Result<Self, ValidationError> {
        Self::command_with_compatibility(command.into(), BTreeMap::new())
    }

    #[allow(clippy::too_many_arguments)]
    fn network(
        http: bool,
        host: String,
        port: u32,
        identity_id: Option<SavedPasswordIdentityId>,
        username: String,
        has_saved_credential: bool,
        compatibility_fields: BTreeMap<String, Value>,
    ) -> Result<Self, ValidationError> {
        validate_proxy_compatibility_fields(&compatibility_fields)?;
        let host = normalize_proxy_hostname(&host)?;
        let port = normalize_port(port)?;
        if let Some(identity_id) = &identity_id {
            validate_opaque_id("saved password identity ID", identity_id.as_str())?;
        }
        let (username, has_saved_credential) = if identity_id.is_some() {
            (String::new(), false)
        } else {
            (normalize_proxy_username(&username)?, has_saved_credential)
        };
        Ok(if http {
            Self::Http {
                host,
                port,
                identity_id,
                username,
                has_saved_credential,
                compatibility_fields,
            }
        } else {
            Self::Socks5 {
                host,
                port,
                identity_id,
                username,
                has_saved_credential,
                compatibility_fields,
            }
        })
    }

    fn command_with_compatibility(
        command: String,
        compatibility_fields: BTreeMap<String, Value>,
    ) -> Result<Self, ValidationError> {
        validate_proxy_compatibility_fields(&compatibility_fields)?;
        Ok(Self::Command {
            command: normalize_proxy_command(&command)?,
            compatibility_fields,
        })
    }

    pub fn identity_id(&self) -> Option<&SavedPasswordIdentityId> {
        match self {
            Self::Http { identity_id, .. } | Self::Socks5 { identity_id, .. } => {
                identity_id.as_ref()
            }
            Self::Command { .. } => None,
        }
    }

    /// Returns a copy carrying the backend-derived manual credential hint.
    /// Identity-owned network credentials and command proxies do not have a
    /// manual proxy credential slot, so callers cannot set even a false hint
    /// on those variants through this API.
    pub fn with_saved_credential_hint(
        mut self,
        has_saved_credential: bool,
    ) -> Result<Self, ValidationError> {
        match &mut self {
            Self::Http {
                identity_id: None,
                has_saved_credential: current,
                ..
            }
            | Self::Socks5 {
                identity_id: None,
                has_saved_credential: current,
                ..
            } => {
                *current = has_saved_credential;
                Ok(self)
            }
            Self::Http { .. } | Self::Socks5 { .. } | Self::Command { .. } => {
                Err(ValidationError::InvalidProxyConfig)
            }
        }
    }

    pub fn compatibility_fields(&self) -> &BTreeMap<String, Value> {
        match self {
            Self::Http {
                compatibility_fields,
                ..
            }
            | Self::Socks5 {
                compatibility_fields,
                ..
            }
            | Self::Command {
                compatibility_fields,
                ..
            } => compatibility_fields,
        }
    }

    pub fn with_compatibility_field(
        mut self,
        key: impl Into<String>,
        value: Value,
    ) -> Result<Self, ValidationError> {
        let key = key.into();
        let candidate = BTreeMap::from([(key.clone(), value.clone())]);
        validate_proxy_compatibility_fields(&candidate)?;
        match &mut self {
            Self::Http {
                compatibility_fields,
                ..
            }
            | Self::Socks5 {
                compatibility_fields,
                ..
            }
            | Self::Command {
                compatibility_fields,
                ..
            } => {
                compatibility_fields.insert(key, value);
            }
        }
        self.validate()?;
        Ok(self)
    }

    pub(crate) fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::Http {
                host,
                port,
                identity_id,
                username,
                has_saved_credential,
                compatibility_fields,
            }
            | Self::Socks5 {
                host,
                port,
                identity_id,
                username,
                has_saved_credential,
                compatibility_fields,
            } => {
                validate_canonical("host", host, normalize_proxy_hostname(host)?)?;
                if *port == 0 {
                    return Err(ValidationError::InvalidPort);
                }
                if let Some(id) = identity_id {
                    validate_opaque_id("saved password identity ID", id.as_str())?;
                    if !username.is_empty() || *has_saved_credential {
                        return Err(ValidationError::NonCanonicalField("proxyConfig"));
                    }
                } else {
                    validate_canonical("username", username, normalize_proxy_username(username)?)?;
                }
                validate_proxy_compatibility_fields(compatibility_fields)
            }
            Self::Command {
                command,
                compatibility_fields,
            } => {
                validate_canonical("command", command, normalize_proxy_command(command)?)?;
                validate_proxy_compatibility_fields(compatibility_fields)
            }
        }
    }
}

/// Secret-free metadata for a reusable proxy profile.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SavedProxyProfile {
    pub record_version: u32,
    pub id: SavedProxyProfileId,
    pub revision: u64,
    pub label: String,
    pub config: SavedProxyConfig,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(flatten)]
    compatibility_fields: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SavedProxyProfileWire {
    record_version: u32,
    id: SavedProxyProfileId,
    revision: u64,
    label: String,
    config: SavedProxyConfig,
    created_at: u64,
    updated_at: u64,
    #[serde(flatten)]
    compatibility_fields: BTreeMap<String, Value>,
}

impl<'de> Deserialize<'de> for SavedProxyProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SavedProxyProfileWire::deserialize(deserializer)?;
        let profile = Self {
            record_version: wire.record_version,
            id: wire.id,
            revision: wire.revision,
            label: normalize_label(&wire.label).map_err(serde::de::Error::custom)?,
            config: wire.config,
            created_at: wire.created_at,
            updated_at: wire.updated_at,
            compatibility_fields: wire.compatibility_fields,
        };
        profile.validate().map_err(serde::de::Error::custom)?;
        Ok(profile)
    }
}

impl SavedProxyProfile {
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        id: SavedProxyProfileId,
        revision: u64,
        label: impl Into<String>,
        config: SavedProxyConfig,
        created_at: u64,
        updated_at: u64,
        compatibility_fields: BTreeMap<String, Value>,
    ) -> Result<Self, ValidationError> {
        let profile = Self {
            record_version: RECORD_VERSION,
            id,
            revision,
            label: normalize_label(&label.into())?,
            config,
            created_at,
            updated_at,
            compatibility_fields,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn from_draft(draft: SavedProxyProfileDraft, now: u64) -> Result<Self, ValidationError> {
        Self::from_parts(
            SavedProxyProfileId::new(),
            1,
            draft.label,
            draft.config,
            now,
            now,
            draft.compatibility_fields,
        )
    }

    pub fn apply_update(
        &self,
        update: SavedProxyProfileUpdate,
        now: u64,
    ) -> Result<Self, ValidationError> {
        if update.is_empty() {
            return Err(ValidationError::EmptyUpdate);
        }
        validate_proxy_profile_compatibility_fields(&update.compatibility_fields)?;
        let mut next = self.clone();
        if let Some(label) = update.label {
            next.label = normalize_label(&label)?;
        }
        if let Some(config) = update.config {
            config.validate()?;
            next.config = config;
        }
        for (key, value) in update.compatibility_fields {
            if value.is_null() {
                next.compatibility_fields.remove(&key);
            } else {
                next.compatibility_fields.insert(key, value);
            }
        }
        next.record_version = RECORD_VERSION;
        next.revision = self
            .revision
            .checked_add(1)
            .ok_or(ValidationError::InvalidRevision)?;
        next.updated_at = now.max(self.updated_at.saturating_add(1));
        next.validate()?;
        Ok(next)
    }

    pub fn compatibility_fields(&self) -> &BTreeMap<String, Value> {
        &self.compatibility_fields
    }

    pub(crate) fn validate(&self) -> Result<(), ValidationError> {
        validate_opaque_id("saved proxy profile ID", self.id.as_str())?;
        if self.record_version != RECORD_VERSION {
            return Err(ValidationError::NonCanonicalField("recordVersion"));
        }
        if self.revision == 0 {
            return Err(ValidationError::InvalidRevision);
        }
        validate_canonical("label", &self.label, normalize_label(&self.label)?)?;
        self.config.validate()?;
        if self.created_at > self.updated_at {
            return Err(ValidationError::InvalidTimestamps);
        }
        validate_proxy_profile_compatibility_fields(&self.compatibility_fields)
    }

    pub(crate) fn stable_cmp(left: &Self, right: &Self) -> Ordering {
        left.label
            .to_lowercase()
            .cmp(&right.label.to_lowercase())
            .then_with(|| left.label.cmp(&right.label))
            .then_with(|| left.id.cmp(&right.id))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SavedProxyProfileDraft {
    pub label: String,
    pub config: SavedProxyConfig,
    #[serde(flatten)]
    compatibility_fields: BTreeMap<String, Value>,
}

impl SavedProxyProfileDraft {
    pub fn new(label: impl Into<String>, config: SavedProxyConfig) -> Self {
        Self {
            label: label.into(),
            config,
            compatibility_fields: BTreeMap::new(),
        }
    }

    pub fn with_compatibility_field(
        mut self,
        key: impl Into<String>,
        value: Value,
    ) -> Result<Self, ValidationError> {
        let key = key.into();
        let candidate = BTreeMap::from([(key.clone(), value.clone())]);
        validate_proxy_profile_compatibility_fields(&candidate)?;
        self.compatibility_fields.insert(key, value);
        Ok(self)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SavedProxyProfileUpdate {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub config: Option<SavedProxyConfig>,
    #[serde(flatten)]
    compatibility_fields: BTreeMap<String, Value>,
}

impl SavedProxyProfileUpdate {
    pub fn with_compatibility_field(
        mut self,
        key: impl Into<String>,
        value: Value,
    ) -> Result<Self, ValidationError> {
        let key = key.into();
        let candidate = BTreeMap::from([(key.clone(), value.clone())]);
        validate_proxy_profile_compatibility_fields(&candidate)?;
        self.compatibility_fields.insert(key, value);
        Ok(self)
    }

    fn is_empty(&self) -> bool {
        self.label.is_none() && self.config.is_none() && self.compatibility_fields.is_empty()
    }
}

/// Secret-free metadata for a reusable password identity.
///
/// The password itself is held independently by the OS credential store.
/// This record contains only a boolean custody hint and deliberately cannot
/// represent a credential locator, account name, ciphertext, or plaintext.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SavedPasswordIdentity {
    pub record_version: u32,
    pub id: SavedPasswordIdentityId,
    pub revision: u64,
    pub label: String,
    pub username: String,
    pub has_saved_credential: bool,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(flatten)]
    compatibility_fields: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SavedPasswordIdentityWire {
    record_version: u32,
    id: SavedPasswordIdentityId,
    revision: u64,
    label: String,
    username: String,
    has_saved_credential: bool,
    created_at: u64,
    updated_at: u64,
    #[serde(flatten)]
    compatibility_fields: BTreeMap<String, Value>,
}

impl<'de> Deserialize<'de> for SavedPasswordIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SavedPasswordIdentityWire::deserialize(deserializer)?;
        Self::from_parts(
            wire.id,
            wire.revision,
            wire.label,
            wire.username,
            wire.has_saved_credential,
            wire.created_at,
            wire.updated_at,
            wire.compatibility_fields,
        )
        .map(|mut identity| {
            identity.record_version = wire.record_version;
            identity
        })
        .and_then(|identity| {
            identity.validate()?;
            Ok(identity)
        })
        .map_err(serde::de::Error::custom)
    }
}

impl SavedPasswordIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        id: SavedPasswordIdentityId,
        revision: u64,
        label: impl Into<String>,
        username: impl Into<String>,
        has_saved_credential: bool,
        created_at: u64,
        updated_at: u64,
        compatibility_fields: BTreeMap<String, Value>,
    ) -> Result<Self, ValidationError> {
        let identity = Self {
            record_version: RECORD_VERSION,
            id,
            revision,
            label: normalize_label(&label.into())?,
            username: normalize_username(&username.into())?,
            has_saved_credential,
            created_at,
            updated_at,
            compatibility_fields,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn from_draft(
        draft: SavedPasswordIdentityDraft,
        now: u64,
    ) -> Result<Self, ValidationError> {
        Self::from_parts(
            SavedPasswordIdentityId::new(),
            1,
            draft.label,
            draft.username,
            draft.has_saved_credential,
            now,
            now,
            draft.compatibility_fields,
        )
    }

    pub fn apply_update(
        &self,
        update: SavedPasswordIdentityUpdate,
        now: u64,
    ) -> Result<Self, ValidationError> {
        if update.is_empty() {
            return Err(ValidationError::EmptyUpdate);
        }
        validate_password_identity_compatibility_fields(&update.compatibility_fields)?;
        let mut next = self.clone();
        if let Some(label) = update.label {
            next.label = normalize_label(&label)?;
        }
        if let Some(username) = update.username {
            next.username = normalize_username(&username)?;
        }
        if let Some(has_saved_credential) = update.has_saved_credential {
            next.has_saved_credential = has_saved_credential;
        }
        for (key, value) in update.compatibility_fields {
            if value.is_null() {
                next.compatibility_fields.remove(&key);
            } else {
                next.compatibility_fields.insert(key, value);
            }
        }
        next.record_version = RECORD_VERSION;
        next.revision = self
            .revision
            .checked_add(1)
            .ok_or(ValidationError::InvalidRevision)?;
        next.updated_at = now.max(self.updated_at.saturating_add(1));
        next.validate()?;
        Ok(next)
    }

    pub fn compatibility_fields(&self) -> &BTreeMap<String, Value> {
        &self.compatibility_fields
    }

    pub fn with_compatibility_field(
        mut self,
        key: impl Into<String>,
        value: Value,
    ) -> Result<Self, ValidationError> {
        let key = key.into();
        let candidate = BTreeMap::from([(key.clone(), value.clone())]);
        validate_password_identity_compatibility_fields(&candidate)?;
        self.compatibility_fields.insert(key, value);
        self.validate()?;
        Ok(self)
    }

    pub(crate) fn validate(&self) -> Result<(), ValidationError> {
        validate_opaque_id("saved password identity ID", self.id.as_str())?;
        if self.record_version != RECORD_VERSION {
            return Err(ValidationError::NonCanonicalField("recordVersion"));
        }
        if self.revision == 0 {
            return Err(ValidationError::InvalidRevision);
        }
        validate_canonical("label", &self.label, normalize_label(&self.label)?)?;
        validate_canonical(
            "username",
            &self.username,
            normalize_username(&self.username)?,
        )?;
        if self.created_at > self.updated_at {
            return Err(ValidationError::InvalidTimestamps);
        }
        validate_password_identity_compatibility_fields(&self.compatibility_fields)
    }

    pub(crate) fn stable_cmp(left: &Self, right: &Self) -> Ordering {
        left.label
            .to_lowercase()
            .cmp(&right.label.to_lowercase())
            .then_with(|| left.label.cmp(&right.label))
            .then_with(|| left.id.cmp(&right.id))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SavedPasswordIdentityDraft {
    pub label: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub has_saved_credential: bool,
    #[serde(flatten)]
    compatibility_fields: BTreeMap<String, Value>,
}

impl SavedPasswordIdentityDraft {
    pub fn new(
        label: impl Into<String>,
        username: impl Into<String>,
        has_saved_credential: bool,
    ) -> Self {
        Self {
            label: label.into(),
            username: username.into(),
            has_saved_credential,
            compatibility_fields: BTreeMap::new(),
        }
    }

    pub fn with_compatibility_field(
        mut self,
        key: impl Into<String>,
        value: Value,
    ) -> Result<Self, ValidationError> {
        let key = key.into();
        let candidate = BTreeMap::from([(key.clone(), value.clone())]);
        validate_password_identity_compatibility_fields(&candidate)?;
        self.compatibility_fields.insert(key, value);
        Ok(self)
    }

    pub fn compatibility_fields(&self) -> &BTreeMap<String, Value> {
        &self.compatibility_fields
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SavedPasswordIdentityUpdate {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub has_saved_credential: Option<bool>,
    #[serde(flatten)]
    compatibility_fields: BTreeMap<String, Value>,
}

impl SavedPasswordIdentityUpdate {
    pub fn with_compatibility_field(
        mut self,
        key: impl Into<String>,
        value: Value,
    ) -> Result<Self, ValidationError> {
        let key = key.into();
        let candidate = BTreeMap::from([(key.clone(), value.clone())]);
        validate_password_identity_compatibility_fields(&candidate)?;
        self.compatibility_fields.insert(key, value);
        Ok(self)
    }

    pub fn compatibility_fields(&self) -> &BTreeMap<String, Value> {
        &self.compatibility_fields
    }

    fn is_empty(&self) -> bool {
        self.label.is_none()
            && self.username.is_none()
            && self.has_saved_credential.is_none()
            && self.compatibility_fields.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SavedHostDraft {
    #[serde(default)]
    pub label: Option<String>,
    pub hostname: String,
    #[serde(default)]
    pub port: Option<u32>,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub protocol: Option<SavedHostProtocol>,
    #[serde(default)]
    pub auth_method: Option<SavedHostAuthMethod>,
    #[serde(flatten)]
    compatibility_fields: BTreeMap<String, Value>,
}

impl SavedHostDraft {
    pub fn ssh_password(hostname: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            label: None,
            hostname: hostname.into(),
            port: None,
            username: username.into(),
            protocol: Some(SavedHostProtocol::ssh()),
            auth_method: Some(SavedHostAuthMethod::password()),
            compatibility_fields: BTreeMap::new(),
        }
    }

    /// Builds a primary Telnet host while retaining the flattened legacy host
    /// fields used by shared Vault snapshots. SSH authentication, key, proxy,
    /// and jump metadata may remain present for round-trip compatibility, but
    /// it is not active while the host protocol is Telnet.
    pub fn telnet(hostname: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            label: None,
            hostname: hostname.into(),
            port: None,
            username: username.into(),
            protocol: Some(SavedHostProtocol::telnet()),
            auth_method: Some(SavedHostAuthMethod::password()),
            compatibility_fields: BTreeMap::new(),
        }
    }

    /// Builds a primary Serial host using the original flattened host shape:
    /// `hostname` mirrors the device path and `port` mirrors the baud rate,
    /// while `serialConfig` retains the complete typed configuration.
    pub fn serial(config: SavedSerialConfig) -> Result<Self, ValidationError> {
        config.validate()?;
        let hostname = config.path.clone();
        let port = config.baud_rate;
        let serial_config = serde_json::to_value(config).map_err(|_| {
            ValidationError::InvalidSerialConfig(SavedSerialConfigError::MalformedConfig)
        })?;
        Ok(Self {
            label: None,
            hostname,
            port: Some(port),
            username: String::new(),
            protocol: Some(SavedHostProtocol::serial()),
            auth_method: Some(SavedHostAuthMethod::password()),
            compatibility_fields: BTreeMap::from([("serialConfig".to_owned(), serial_config)]),
        })
    }

    pub fn ssh_password_identity(
        hostname: impl Into<String>,
        username: impl Into<String>,
        identity_id: SavedPasswordIdentityId,
        has_saved_host_credential: bool,
    ) -> Self {
        Self::ssh_password(hostname, username).with_authentication(
            SavedHostAuthentication::PasswordIdentity {
                identity_id,
                has_saved_host_credential,
            },
        )
    }

    pub fn ssh_managed_private_key(
        hostname: impl Into<String>,
        username: impl Into<String>,
        key_id: SavedSshKeyReferenceId,
    ) -> Self {
        Self::ssh_password(hostname, username)
            .with_authentication(SavedHostAuthentication::ManagedPrivateKey { key_id })
    }

    pub fn ssh_managed_certificate(
        hostname: impl Into<String>,
        username: impl Into<String>,
        key_id: SavedSshKeyReferenceId,
    ) -> Self {
        Self::ssh_password(hostname, username)
            .with_authentication(SavedHostAuthentication::ManagedCertificate { key_id })
    }

    /// Selects one native SSH authentication mode and removes stale fields
    /// owned by every other mode before the draft can be persisted.
    pub fn with_authentication(mut self, authentication: SavedHostAuthentication) -> Self {
        self.protocol = Some(SavedHostProtocol::ssh());
        self.auth_method = Some(saved_host_auth_method(&authentication));
        replace_host_authentication_fields(&mut self.compatibility_fields, &authentication, false);
        self
    }

    pub fn with_compatibility_field(
        mut self,
        key: impl Into<String>,
        value: Value,
    ) -> Result<Self, ValidationError> {
        let key = key.into();
        if key == "serialConfig" && !value.is_null() {
            parse_serial_config(Some(&value))?;
        }
        let candidate = BTreeMap::from([(key.clone(), value.clone())]);
        validate_compatibility_fields(&candidate)?;
        self.compatibility_fields.insert(key, value);
        Ok(self)
    }

    pub fn with_serial_config(
        mut self,
        config: SavedSerialConfig,
    ) -> Result<Self, ValidationError> {
        config.validate()?;
        self.hostname = config.path.clone();
        self.port = Some(config.baud_rate);
        self.protocol = Some(SavedHostProtocol::serial());
        self.auth_method = Some(SavedHostAuthMethod::password());
        self.compatibility_fields.insert(
            "serialConfig".to_owned(),
            serde_json::to_value(config).map_err(|_| {
                ValidationError::InvalidSerialConfig(SavedSerialConfigError::MalformedConfig)
            })?,
        );
        Ok(self)
    }

    pub fn compatibility_fields(&self) -> &BTreeMap<String, Value> {
        &self.compatibility_fields
    }

    pub fn with_proxy_config(mut self, config: SavedProxyConfig) -> Result<Self, ValidationError> {
        config.validate()?;
        self.compatibility_fields.insert(
            "proxyConfig".to_owned(),
            serde_json::to_value(config).map_err(|_| ValidationError::InvalidProxyConfig)?,
        );
        Ok(self)
    }

    pub fn with_proxy_profile_id(
        mut self,
        id: SavedProxyProfileId,
    ) -> Result<Self, ValidationError> {
        validate_opaque_id("saved proxy profile ID", id.as_str())?;
        self.compatibility_fields
            .insert("proxyProfileId".to_owned(), Value::String(id.0));
        Ok(self)
    }

    pub fn with_group_path(mut self, path: SavedGroupPath) -> Self {
        self.compatibility_fields
            .insert("group".to_owned(), Value::String(path.to_string()));
        self
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SavedHostUpdate {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub port: Option<u32>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub protocol: Option<SavedHostProtocol>,
    #[serde(default)]
    pub auth_method: Option<SavedHostAuthMethod>,
    #[serde(flatten)]
    compatibility_fields: BTreeMap<String, Value>,
}

impl SavedHostUpdate {
    /// Atomically switches authentication and writes removal tombstones for
    /// stale password hints, identity references, and key references.
    pub fn with_authentication(mut self, authentication: SavedHostAuthentication) -> Self {
        self.auth_method = Some(saved_host_auth_method(&authentication));
        replace_host_authentication_fields(&mut self.compatibility_fields, &authentication, true);
        self
    }

    pub fn with_compatibility_field(
        mut self,
        key: impl Into<String>,
        value: Value,
    ) -> Result<Self, ValidationError> {
        let key = key.into();
        if key == "serialConfig" && !value.is_null() {
            parse_serial_config(Some(&value))?;
        }
        let candidate = BTreeMap::from([(key.clone(), value.clone())]);
        validate_compatibility_fields(&candidate)?;
        self.compatibility_fields.insert(key, value);
        Ok(self)
    }

    pub fn with_serial_config(
        mut self,
        config: SavedSerialConfig,
    ) -> Result<Self, ValidationError> {
        config.validate()?;
        self.hostname = Some(config.path.clone());
        self.port = Some(config.baud_rate);
        self.protocol = Some(SavedHostProtocol::serial());
        self.compatibility_fields.insert(
            "serialConfig".to_owned(),
            serde_json::to_value(config).map_err(|_| {
                ValidationError::InvalidSerialConfig(SavedSerialConfigError::MalformedConfig)
            })?,
        );
        Ok(self)
    }

    /// Removes the complete Serial object while retaining the legacy
    /// `hostname`/`port` fallback fields.
    pub fn clear_serial_config(mut self) -> Self {
        self.compatibility_fields
            .insert("serialConfig".to_owned(), Value::Null);
        self
    }

    pub fn with_proxy_config(mut self, config: SavedProxyConfig) -> Result<Self, ValidationError> {
        config.validate()?;
        self.compatibility_fields.insert(
            "proxyConfig".to_owned(),
            serde_json::to_value(config).map_err(|_| ValidationError::InvalidProxyConfig)?,
        );
        Ok(self)
    }

    pub fn clear_proxy_config(mut self) -> Self {
        self.compatibility_fields
            .insert("proxyConfig".to_owned(), Value::Null);
        self
    }

    pub fn with_proxy_profile_id(
        mut self,
        id: SavedProxyProfileId,
    ) -> Result<Self, ValidationError> {
        validate_opaque_id("saved proxy profile ID", id.as_str())?;
        self.compatibility_fields
            .insert("proxyProfileId".to_owned(), Value::String(id.0));
        Ok(self)
    }

    pub fn clear_proxy_profile_id(mut self) -> Self {
        self.compatibility_fields
            .insert("proxyProfileId".to_owned(), Value::Null);
        self
    }

    pub fn with_group_path(mut self, path: SavedGroupPath) -> Self {
        self.compatibility_fields
            .insert("group".to_owned(), Value::String(path.to_string()));
        self
    }

    pub fn clear_group_path(mut self) -> Self {
        self.compatibility_fields
            .insert("group".to_owned(), Value::Null);
        self
    }

    fn is_empty(&self) -> bool {
        self.label.is_none()
            && self.hostname.is_none()
            && self.port.is_none()
            && self.username.is_none()
            && self.protocol.is_none()
            && self.auth_method.is_none()
            && self.compatibility_fields.is_empty()
    }
}

const HOST_AUTH_COMPATIBILITY_FIELDS: [&str; 8] = [
    "identityId",
    "identityFileId",
    "identityFilePaths",
    "hasSavedCredential",
    "savePassword",
    "hasPassword",
    "hasPrivateKey",
    "hasPassphrase",
];

fn saved_host_auth_method(authentication: &SavedHostAuthentication) -> SavedHostAuthMethod {
    match authentication {
        SavedHostAuthentication::DirectPassword { .. }
        | SavedHostAuthentication::PasswordIdentity { .. } => SavedHostAuthMethod::password(),
        SavedHostAuthentication::ManagedPrivateKey { .. } => SavedHostAuthMethod::key(),
        SavedHostAuthentication::ManagedCertificate { .. } => SavedHostAuthMethod::certificate(),
    }
}

fn replace_host_authentication_fields(
    fields: &mut BTreeMap<String, Value>,
    authentication: &SavedHostAuthentication,
    tombstone_removed_fields: bool,
) {
    clear_host_authentication_fields(fields, tombstone_removed_fields);
    match authentication {
        SavedHostAuthentication::DirectPassword {
            has_saved_credential: true,
        } => {
            fields.insert("hasSavedCredential".to_owned(), Value::Bool(true));
        }
        SavedHostAuthentication::DirectPassword {
            has_saved_credential: false,
        } => {}
        SavedHostAuthentication::PasswordIdentity {
            identity_id,
            has_saved_host_credential,
        } => {
            fields.insert(
                "identityId".to_owned(),
                Value::String(identity_id.as_str().to_owned()),
            );
            if *has_saved_host_credential {
                fields.insert("hasSavedCredential".to_owned(), Value::Bool(true));
            }
        }
        SavedHostAuthentication::ManagedPrivateKey { key_id }
        | SavedHostAuthentication::ManagedCertificate { key_id } => {
            fields.insert(
                "identityFileId".to_owned(),
                Value::String(key_id.as_str().to_owned()),
            );
        }
    }
}

fn clear_host_authentication_fields(
    fields: &mut BTreeMap<String, Value>,
    tombstone_removed_fields: bool,
) {
    for key in HOST_AUTH_COMPATIBILITY_FIELDS {
        if tombstone_removed_fields {
            fields.insert(key.to_owned(), Value::Null);
        } else {
            fields.remove(key);
        }
    }
}

fn parse_proxy_config(value: Option<&Value>) -> Result<Option<SavedProxyConfig>, ValidationError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => serde_json::from_value(value.clone())
            .map(Some)
            .map_err(|_| ValidationError::InvalidProxyConfig),
    }
}

fn parse_proxy_profile_id(
    value: Option<&Value>,
) -> Result<Option<SavedProxyProfileId>, ValidationError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        Some(Value::String(value)) => SavedProxyProfileId::from_opaque(value.clone()).map(Some),
        _ => Err(ValidationError::InvalidOpaqueId("saved proxy profile ID")),
    }
}

fn host_opaque_reference(
    fields: &BTreeMap<String, Value>,
    key: &'static str,
    field: &'static str,
) -> Result<Option<String>, ValidationError> {
    match fields.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        Some(Value::String(value)) => {
            validate_opaque_id(field, value)?;
            Ok(Some(value.clone()))
        }
        Some(_) => Err(ValidationError::InvalidAuthenticationConfiguration(
            "identity references must be strings, null, or absent",
        )),
    }
}

fn host_password_identity_id(
    fields: &BTreeMap<String, Value>,
) -> Result<Option<SavedPasswordIdentityId>, ValidationError> {
    host_opaque_reference(fields, "identityId", "saved password identity ID")?
        .map(SavedPasswordIdentityId::from_opaque)
        .transpose()
}

fn host_key_reference_id(
    fields: &BTreeMap<String, Value>,
) -> Result<Option<SavedSshKeyReferenceId>, ValidationError> {
    host_opaque_reference(fields, "identityFileId", "saved SSH key reference ID")?
        .map(SavedSshKeyReferenceId::from_opaque)
        .transpose()
}

fn host_saved_credential_hint(fields: &BTreeMap<String, Value>) -> Result<bool, ValidationError> {
    match fields.get("hasSavedCredential") {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(ValidationError::InvalidAuthenticationConfiguration(
            "hasSavedCredential must be boolean, null, or absent",
        )),
    }
}

fn host_password_hint_is_true(fields: &BTreeMap<String, Value>) -> bool {
    ["hasSavedCredential", "savePassword", "hasPassword"]
        .into_iter()
        .any(|key| matches!(fields.get(key), Some(Value::Bool(true))))
}

fn host_has_identity_file_paths(fields: &BTreeMap<String, Value>) -> Result<bool, ValidationError> {
    let Some(value) = fields.get("identityFilePaths") else {
        return Ok(false);
    };
    match value {
        Value::Null => Ok(false),
        Value::Array(paths) => {
            for path in paths {
                let Value::String(path) = path else {
                    return Err(ValidationError::InvalidAuthenticationConfiguration(
                        "identityFilePaths must contain only strings",
                    ));
                };
                normalize_file_path(path)?;
            }
            Ok(!paths.is_empty())
        }
        _ => Err(ValidationError::InvalidAuthenticationConfiguration(
            "identityFilePaths must be an array, null, or absent",
        )),
    }
}

fn validate_new_host_authentication(
    auth_method: &SavedHostAuthMethod,
    fields: &BTreeMap<String, Value>,
    enforce_exclusive_fields: bool,
) -> Result<(), ValidationError> {
    let identity_id = host_opaque_reference(fields, "identityId", "saved identity ID")?;
    let key_id = host_key_reference_id(fields)?;
    let has_identity_file_paths = host_has_identity_file_paths(fields)?;
    let has_password_hint = host_password_hint_is_true(fields);

    if auth_method.is_password() {
        if enforce_exclusive_fields && (key_id.is_some() || has_identity_file_paths) {
            return Err(ValidationError::InvalidAuthenticationConfiguration(
                "password authentication cannot reference an SSH key",
            ));
        }
        return Ok(());
    }
    if auth_method.is_key() || auth_method.is_certificate() {
        if enforce_exclusive_fields && has_password_hint {
            return Err(ValidationError::InvalidAuthenticationConfiguration(
                "key authentication cannot retain a password credential hint",
            ));
        }
        if identity_id.is_none() && key_id.is_none() && !has_identity_file_paths {
            return Err(ValidationError::InvalidAuthenticationConfiguration(
                "key or certificate authentication requires an identity or key reference",
            ));
        }
        return Ok(());
    }
    Err(ValidationError::UnsupportedAuthMethod)
}

fn default_record_version() -> u32 {
    RECORD_VERSION
}

fn default_revision() -> u64 {
    1
}

fn default_auth_policy_version() -> u8 {
    AUTH_POLICY_VERSION
}

fn validate_id(value: &str) -> Result<(), ValidationError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || value.chars().any(|character| character.is_control())
    {
        return Err(ValidationError::InvalidId);
    }
    Ok(())
}

fn validate_opaque_id(field: &'static str, value: &str) -> Result<(), ValidationError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || value.chars().any(|character| character.is_control())
    {
        return Err(ValidationError::InvalidOpaqueId(field));
    }
    Ok(())
}

fn validate_secret_object_locator(value: &str) -> Result<(), ValidationError> {
    if value.len() != SECRET_OBJECT_LOCATOR_HEX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ValidationError::InvalidSecretObjectLocator);
    }
    Ok(())
}

fn normalize_label(value: &str) -> Result<String, ValidationError> {
    normalize_text(value, "label", MAX_LABEL_BYTES, false, true)
}

fn normalize_hostname(value: &str) -> Result<String, ValidationError> {
    normalize_text(value, "hostname", MAX_HOSTNAME_BYTES, true, true)
}

fn normalize_host_endpoint(
    protocol: &SavedHostProtocol,
    value: &str,
) -> Result<String, ValidationError> {
    if protocol.is_serial() {
        normalize_serial_path(value).map_err(ValidationError::from)
    } else {
        normalize_hostname(value)
    }
}

fn normalize_host_port(protocol: &SavedHostProtocol, value: u32) -> Result<u32, ValidationError> {
    if value == 0 || ((protocol.is_ssh() || protocol.is_telnet()) && u16::try_from(value).is_err())
    {
        return Err(ValidationError::InvalidPort);
    }
    Ok(value)
}

fn normalize_proxy_hostname(value: &str) -> Result<String, ValidationError> {
    normalize_text(value, "host", MAX_HOSTNAME_BYTES, true, true)
}

fn normalize_username(value: &str) -> Result<String, ValidationError> {
    normalize_text(value, "username", MAX_USERNAME_BYTES, true, false)
}

fn normalize_proxy_username(value: &str) -> Result<String, ValidationError> {
    normalize_text(value, "username", MAX_PROXY_USERNAME_BYTES, false, false)
}

fn normalize_proxy_command(value: &str) -> Result<String, ValidationError> {
    if value.contains('\0') {
        return Err(ValidationError::UnsafeCharacters("command"));
    }
    let value = value.trim();
    if value.is_empty() {
        return Err(ValidationError::MissingField("command"));
    }
    if value.len() > MAX_PROXY_COMMAND_BYTES {
        return Err(ValidationError::TooLong {
            field: "command",
            max_bytes: MAX_PROXY_COMMAND_BYTES,
        });
    }
    Ok(value.to_owned())
}

fn normalize_file_path(value: &str) -> Result<String, ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::MissingField("filePath"));
    }
    if value.len() > MAX_FILE_PATH_BYTES {
        return Err(ValidationError::TooLong {
            field: "filePath",
            max_bytes: MAX_FILE_PATH_BYTES,
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ValidationError::UnsafeCharacters("filePath"));
    }
    Ok(value.to_owned())
}

fn normalize_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
    reject_whitespace: bool,
    required: bool,
) -> Result<String, ValidationError> {
    if value.chars().any(|character| character.is_control()) {
        return Err(ValidationError::UnsafeCharacters(field));
    }
    let value = value.trim();
    if required && value.is_empty() {
        return Err(ValidationError::MissingField(field));
    }
    if value.len() > max_bytes {
        return Err(ValidationError::TooLong { field, max_bytes });
    }
    if reject_whitespace && value.chars().any(char::is_whitespace) {
        return Err(ValidationError::InternalWhitespace(field));
    }
    Ok(value.to_owned())
}

fn normalize_port(value: u32) -> Result<u16, ValidationError> {
    u16::try_from(value)
        .ok()
        .filter(|port| *port > 0)
        .ok_or(ValidationError::InvalidPort)
}

fn parse_serial_config(
    value: Option<&Value>,
) -> Result<Option<SavedSerialConfig>, ValidationError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => serde_json::from_value(value.clone())
            .map(Some)
            .map_err(|_| {
                ValidationError::InvalidSerialConfig(SavedSerialConfigError::MalformedConfig)
            }),
    }
}

fn parse_serial_backspace_behavior(
    value: Option<&Value>,
) -> Result<SavedSerialBackspaceBehavior, ValidationError> {
    match value {
        None | Some(Value::Null) => Ok(SavedSerialBackspaceBehavior::Default),
        Some(Value::String(value)) if value == "default" => {
            Ok(SavedSerialBackspaceBehavior::Default)
        }
        Some(Value::String(value)) if value == "ctrl-h" => Ok(SavedSerialBackspaceBehavior::CtrlH),
        Some(_) => Err(ValidationError::InvalidSerialConfig(
            SavedSerialConfigError::InvalidBackspaceBehavior,
        )),
    }
}

fn validate_canonical(
    field: &'static str,
    value: &str,
    canonical: String,
) -> Result<(), ValidationError> {
    if value == canonical {
        Ok(())
    } else {
        Err(ValidationError::NonCanonicalField(field))
    }
}

fn validate_token(field: &'static str, value: &str) -> Result<(), ValidationError> {
    if value.is_empty() || value.len() > 64 {
        return Err(ValidationError::TooLong {
            field,
            max_bytes: 64,
        });
    }
    if value
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(ValidationError::UnsafeCharacters(field));
    }
    Ok(())
}

fn validate_compatibility_fields(fields: &BTreeMap<String, Value>) -> Result<(), ValidationError> {
    for (key, value) in fields {
        if key == "proxyConfig" {
            if value.is_null() {
                continue;
            }
            validate_compatibility_value(value, 1, never_reserved_compatibility_key)?;
        } else if key == "group" {
            parse_group_path(Some(value))?;
        } else {
            validate_compatibility_entry(
                key,
                value,
                0,
                is_reserved_compatibility_key,
                never_reserved_compatibility_key,
            )?;
        }
    }
    Ok(())
}

fn parse_group_path(value: Option<&Value>) -> Result<Option<SavedGroupPath>, ValidationError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(path)) if path.split('/').all(str::is_empty) => Ok(None),
        Some(Value::String(path)) => SavedGroupPath::new(path)
            .map(Some)
            .map_err(|_| ValidationError::InvalidGroupPath),
        Some(_) => Err(ValidationError::InvalidGroupPath),
    }
}

fn never_reserved_compatibility_key(_key: &str) -> bool {
    false
}

fn validate_key_compatibility_fields(
    fields: &BTreeMap<String, Value>,
) -> Result<(), ValidationError> {
    validate_compatibility_fields_with(fields, is_reserved_key_reference_field)
}

fn validate_managed_key_compatibility_fields(
    fields: &BTreeMap<String, Value>,
) -> Result<(), ValidationError> {
    validate_compatibility_fields_with(fields, is_reserved_managed_key_field)
}

fn validate_identity_compatibility_fields(
    fields: &BTreeMap<String, Value>,
) -> Result<(), ValidationError> {
    validate_compatibility_fields_with(fields, is_reserved_identity_reference_field)
}

fn validate_password_identity_compatibility_fields(
    fields: &BTreeMap<String, Value>,
) -> Result<(), ValidationError> {
    validate_compatibility_fields_with(fields, is_reserved_password_identity_field)
}

fn validate_proxy_compatibility_fields(
    fields: &BTreeMap<String, Value>,
) -> Result<(), ValidationError> {
    validate_compatibility_fields_with(fields, is_reserved_proxy_config_field)
}

fn validate_proxy_profile_compatibility_fields(
    fields: &BTreeMap<String, Value>,
) -> Result<(), ValidationError> {
    validate_compatibility_fields_with(fields, is_reserved_proxy_profile_field)
}

fn validate_compatibility_fields_with(
    fields: &BTreeMap<String, Value>,
    is_reserved: fn(&str) -> bool,
) -> Result<(), ValidationError> {
    for (key, value) in fields {
        validate_compatibility_entry(key, value, 0, is_reserved, is_reserved)?;
    }
    Ok(())
}

fn validate_compatibility_entry(
    key: &str,
    value: &Value,
    depth: usize,
    is_reserved: fn(&str) -> bool,
    nested_is_reserved: fn(&str) -> bool,
) -> Result<(), ValidationError> {
    if depth > MAX_COMPATIBILITY_DEPTH {
        return Err(ValidationError::CompatibilityNestingTooDeep);
    }
    if key.is_empty()
        || key.len() > MAX_COMPATIBILITY_KEY_BYTES
        || key.chars().any(|character| character.is_control())
        || is_reserved(key)
        || is_forbidden_compatibility_key(key)
    {
        return Err(ValidationError::ForbiddenCompatibilityField(key.to_owned()));
    }
    if is_secret_status_key(key) && !matches!(value, Value::Bool(_) | Value::Null) {
        return Err(ValidationError::ForbiddenCompatibilityField(key.to_owned()));
    }
    match value {
        Value::Array(values) => {
            for value in values {
                validate_compatibility_value(value, depth + 1, nested_is_reserved)?;
            }
        }
        Value::Object(values) => {
            for (child_key, child_value) in values {
                validate_compatibility_entry(
                    child_key,
                    child_value,
                    depth + 1,
                    nested_is_reserved,
                    nested_is_reserved,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_compatibility_value(
    value: &Value,
    depth: usize,
    is_reserved: fn(&str) -> bool,
) -> Result<(), ValidationError> {
    if depth > MAX_COMPATIBILITY_DEPTH {
        return Err(ValidationError::CompatibilityNestingTooDeep);
    }
    match value {
        Value::Array(values) => {
            for value in values {
                validate_compatibility_value(value, depth + 1, is_reserved)?;
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                validate_compatibility_entry(key, value, depth + 1, is_reserved, is_reserved)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn is_forbidden_compatibility_key(key: &str) -> bool {
    let normalized = normalize_compatibility_key(key);
    if is_secret_status_key_normalized(&normalized) {
        return false;
    }
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
    is_secret_status_key_normalized(&normalize_compatibility_key(key))
}

fn is_secret_status_key_normalized(normalized: &str) -> bool {
    matches!(
        normalized,
        "savepassword"
            | "haspassword"
            | "hassavedcredential"
            | "savepassphrase"
            | "haspassphrase"
            | "hasprivatekey"
            | "hascredential"
    )
}

fn normalize_compatibility_key(key: &str) -> String {
    key.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_reserved_compatibility_key(key: &str) -> bool {
    matches!(
        key,
        "recordVersion"
            | "id"
            | "revision"
            | "label"
            | "hostname"
            | "port"
            | "username"
            | "protocol"
            | "authMethod"
            | "authPolicyVersion"
            | "createdAt"
            | "updatedAt"
    )
}

fn is_reserved_key_reference_field(key: &str) -> bool {
    matches!(
        key,
        "id" | "label" | "filePath" | "category" | "source" | "createdAt" | "updatedAt"
    )
}

fn is_reserved_managed_key_field(key: &str) -> bool {
    let normalized = normalize_compatibility_key(key);
    matches!(
        normalized.as_str(),
        "id" | "label"
            | "filepath"
            | "category"
            | "source"
            | "privatekey"
            | "publickey"
            | "certificate"
            | "passphrase"
            | "savepassphrase"
            | "hassavedpassphrase"
            | "custody"
            | "backendlocator"
            | "custodyrevision"
            | "createdat"
            | "updatedat"
            | "secretstoreuuid"
            | "storeuuid"
            | "masterkeyaccount"
            | "masterkeyepoch"
            | "masteraccount"
            | "keyringaccount"
            | "objectdigest"
            | "entitydigest"
            | "blobgeneration"
            | "blobslot"
            | "ciphertext"
            | "nonce"
    ) || normalized.ends_with("filepath")
        || normalized.contains("masterkey")
        || normalized.contains("secretstore")
        || normalized.contains("objectdigest")
        || normalized.contains("blobgeneration")
}

fn is_reserved_identity_reference_field(key: &str) -> bool {
    matches!(
        key,
        "id" | "label" | "username" | "authMethod" | "keyId" | "createdAt" | "updatedAt"
    )
}

fn is_reserved_password_identity_field(key: &str) -> bool {
    let normalized = normalize_compatibility_key(key);
    matches!(
        normalized.as_str(),
        "recordversion"
            | "id"
            | "revision"
            | "label"
            | "username"
            | "authmethod"
            | "keyid"
            | "hassavedcredential"
            | "createdat"
            | "updatedat"
            | "credentialaccount"
            | "credentiallocator"
            | "hascredential"
            | "haspassword"
            | "savepassword"
            | "savepassphrase"
            | "haspassphrase"
            | "hasprivatekey"
            | "keyringaccount"
            | "ciphertext"
            | "nonce"
    ) || normalized.contains("credential")
        || normalized.contains("keyring")
        || normalized.contains("secretstore")
        || normalized.ends_with("locator")
        || normalized.ends_with("account")
}

fn is_reserved_proxy_config_field(key: &str) -> bool {
    let normalized = normalize_compatibility_key(key);
    matches!(
        normalized.as_str(),
        "type"
            | "host"
            | "hostname"
            | "port"
            | "command"
            | "identityid"
            | "username"
            | "hassavedcredential"
            | "hascredential"
            | "haspassword"
            | "savepassword"
            | "credential"
            | "credentials"
            | "password"
    )
}

fn is_reserved_proxy_profile_field(key: &str) -> bool {
    matches!(
        normalize_compatibility_key(key).as_str(),
        "recordversion" | "id" | "revision" | "label" | "config" | "createdat" | "updatedat"
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::group::SavedGroupPath;

    use super::{
        AUTH_POLICY_VERSION, SavedHost, SavedHostAuthMethod, SavedHostAuthentication,
        SavedHostDraft, SavedHostProtocol, SavedHostUpdate, SavedIdentityReference,
        SavedManagedSshKey, SavedPasswordIdentity, SavedPasswordIdentityDraft,
        SavedPasswordIdentityId, SavedPasswordIdentityUpdate, SavedProxyConfig, SavedProxyProfile,
        SavedProxyProfileDraft, SavedProxyProfileId, SavedProxyProfileUpdate,
        SavedSecretObjectLocator, SavedSshKeyCategory, SavedSshKeyCustodyReference,
        SavedSshKeyReference, SavedSshKeyReferenceId, SavedSshKeySource, ValidationError,
    };

    #[test]
    fn draft_defaults_name_ssh_password_and_policy() {
        let host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("server.example.com", "alice@example.com"),
            100,
        )
        .expect("saved host");
        assert_eq!(host.label, "server.example.com");
        assert_eq!(host.port, 22);
        assert!(host.protocol.is_ssh());
        assert!(host.auth_method.is_password());
        assert_eq!(host.auth_policy_version, AUTH_POLICY_VERSION);
        assert_eq!(
            uuid::Uuid::parse_str(host.id.as_str())
                .expect("UUID")
                .get_version_num(),
            4
        );
    }

    #[test]
    fn native_saved_host_authentication_modes_keep_the_legacy_wire_shape() {
        let direct = SavedHost::from_draft(
            SavedHostDraft::ssh_password("password.example.com", "alice").with_authentication(
                SavedHostAuthentication::DirectPassword {
                    has_saved_credential: true,
                },
            ),
            1,
        )
        .expect("direct password host");
        assert_eq!(
            direct.authentication(),
            Ok(SavedHostAuthentication::DirectPassword {
                has_saved_credential: true,
            })
        );
        let direct_json = serde_json::to_value(&direct).expect("direct JSON");
        assert_eq!(direct_json["authMethod"], "password");
        assert_eq!(direct_json["hasSavedCredential"], true);
        assert!(direct_json.get("identityId").is_none());
        assert!(direct_json.get("identityFileId").is_none());

        let password_identity_id =
            SavedPasswordIdentityId::from_opaque("shared-password").expect("password identity");
        let password_identity = SavedHost::from_draft(
            SavedHostDraft::ssh_password_identity(
                "identity.example.com",
                "ignored-at-resolution",
                password_identity_id.clone(),
                false,
            ),
            2,
        )
        .expect("password identity host");
        assert_eq!(
            password_identity.authentication(),
            Ok(SavedHostAuthentication::PasswordIdentity {
                identity_id: password_identity_id,
                has_saved_host_credential: false,
            })
        );
        let identity_json = serde_json::to_value(password_identity).expect("identity JSON");
        assert_eq!(identity_json["authMethod"], "password");
        assert_eq!(identity_json["identityId"], "shared-password");
        assert!(identity_json.get("hasSavedCredential").is_none());
        assert!(identity_json.get("identityFileId").is_none());

        let key_id = SavedSshKeyReferenceId::from_opaque("managed-private").expect("key ID");
        let private_key = SavedHost::from_draft(
            SavedHostDraft::ssh_managed_private_key("key.example.com", "alice", key_id.clone()),
            3,
        )
        .expect("managed private-key host");
        assert_eq!(
            private_key.authentication(),
            Ok(SavedHostAuthentication::ManagedPrivateKey {
                key_id: key_id.clone(),
            })
        );
        let key_json = serde_json::to_value(private_key).expect("key JSON");
        assert_eq!(key_json["authMethod"], "key");
        assert_eq!(key_json["identityFileId"], "managed-private");

        let certificate = SavedHost::from_draft(
            SavedHostDraft::ssh_managed_certificate(
                "certificate.example.com",
                "alice",
                key_id.clone(),
            ),
            4,
        )
        .expect("managed certificate host");
        assert_eq!(
            certificate.authentication(),
            Ok(SavedHostAuthentication::ManagedCertificate { key_id })
        );
        let certificate_json = serde_json::to_value(certificate).expect("certificate JSON");
        assert_eq!(certificate_json["authMethod"], "certificate");
        assert_eq!(certificate_json["identityFileId"], "managed-private");
    }

    #[test]
    fn authentication_updates_remove_every_stale_reference_and_credential_hint() {
        let host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("switch.example.com", "alice")
                .with_compatibility_field("pluginSetting", serde_json::json!({"keep": true}))
                .expect("plugin metadata")
                .with_authentication(SavedHostAuthentication::DirectPassword {
                    has_saved_credential: true,
                }),
            10,
        )
        .expect("password host");
        let mut legacy_json = serde_json::to_value(host).expect("legacy host JSON");
        legacy_json["identityId"] = serde_json::json!("stale-identity");
        legacy_json["identityFileId"] = serde_json::json!("stale-key");
        legacy_json["identityFilePaths"] = serde_json::json!(["/stale/key/path"]);
        legacy_json["savePassword"] = serde_json::json!(false);
        legacy_json["hasPrivateKey"] = serde_json::json!(true);
        legacy_json["hasPassphrase"] = serde_json::json!(true);
        let host: SavedHost =
            serde_json::from_value(legacy_json).expect("read legacy mixed authentication fields");
        let key_id = SavedSshKeyReferenceId::from_opaque("managed-key").expect("key ID");
        let key_update = SavedHostUpdate {
            auth_method: Some(SavedHostAuthMethod::key()),
            ..SavedHostUpdate::default()
        }
        .with_compatibility_field("identityFileId", serde_json::json!(key_id.as_str()))
        .expect("managed key relationship");
        let key_host = host.apply_update(key_update, 11).expect("switch to key");
        assert_eq!(
            key_host.authentication(),
            Ok(SavedHostAuthentication::ManagedPrivateKey {
                key_id: key_id.clone(),
            })
        );
        for stale in [
            "identityId",
            "identityFilePaths",
            "hasSavedCredential",
            "savePassword",
            "hasPassword",
            "hasPrivateKey",
            "hasPassphrase",
        ] {
            assert!(!key_host.compatibility_fields().contains_key(stale));
        }
        assert_eq!(
            key_host.compatibility_fields()["pluginSetting"],
            serde_json::json!({"keep": true})
        );

        let identity_id =
            SavedPasswordIdentityId::from_opaque("password-identity").expect("identity ID");
        let identity_host = key_host
            .apply_update(
                SavedHostUpdate::default().with_authentication(
                    SavedHostAuthentication::PasswordIdentity {
                        identity_id: identity_id.clone(),
                        has_saved_host_credential: true,
                    },
                ),
                12,
            )
            .expect("switch to password identity");
        assert_eq!(
            identity_host.authentication(),
            Ok(SavedHostAuthentication::PasswordIdentity {
                identity_id,
                has_saved_host_credential: true,
            })
        );
        assert!(
            !identity_host
                .compatibility_fields()
                .contains_key("identityFileId")
        );
        assert_eq!(
            identity_host
                .compatibility_fields()
                .get("hasSavedCredential"),
            Some(&serde_json::json!(true))
        );

        let certificate_host = identity_host
            .apply_update(
                SavedHostUpdate::default().with_authentication(
                    SavedHostAuthentication::ManagedCertificate {
                        key_id: key_id.clone(),
                    },
                ),
                13,
            )
            .expect("switch identity with fallback to certificate");
        assert_eq!(
            certificate_host.authentication(),
            Ok(SavedHostAuthentication::ManagedCertificate { key_id })
        );
        assert!(
            !certificate_host
                .compatibility_fields()
                .contains_key("identityId")
        );
        assert!(
            !certificate_host
                .compatibility_fields()
                .contains_key("hasSavedCredential")
        );

        let direct = certificate_host
            .apply_update(
                SavedHostUpdate::default().with_authentication(
                    SavedHostAuthentication::DirectPassword {
                        has_saved_credential: false,
                    },
                ),
                14,
            )
            .expect("switch to direct password");
        assert_eq!(
            direct.authentication(),
            Ok(SavedHostAuthentication::DirectPassword {
                has_saved_credential: false,
            })
        );
        assert!(!direct.compatibility_fields().contains_key("identityId"));
        assert!(!direct.compatibility_fields().contains_key("identityFileId"));
    }

    #[test]
    fn new_authentication_input_rejects_missing_conflicting_and_malformed_relationships() {
        let missing_key = SavedHostDraft {
            auth_method: Some(SavedHostAuthMethod::key()),
            ..SavedHostDraft::ssh_password("missing.example.com", "alice")
        };
        assert!(matches!(
            SavedHost::from_draft(missing_key, 1),
            Err(ValidationError::InvalidAuthenticationConfiguration(_))
        ));

        let password_with_key = SavedHostDraft::ssh_password("conflict.example.com", "alice")
            .with_compatibility_field("identityFileId", serde_json::json!("managed-key"))
            .expect("safe-shaped relationship");
        let password_with_key = SavedHost::from_draft(password_with_key, 1)
            .expect("legacy mixed authentication remains readable");
        assert!(matches!(
            password_with_key.authentication(),
            Err(ValidationError::InvalidAuthenticationConfiguration(_))
        ));

        let identity_with_host_password = SavedHostDraft::ssh_password_identity(
            "identity.example.com",
            "alice",
            SavedPasswordIdentityId::from_opaque("shared-login").expect("identity ID"),
            true,
        );
        let identity_with_host_password = SavedHost::from_draft(identity_with_host_password, 1)
            .expect("password identity with host fallback");
        assert_eq!(
            identity_with_host_password.authentication(),
            Ok(SavedHostAuthentication::PasswordIdentity {
                identity_id: SavedPasswordIdentityId::from_opaque("shared-login")
                    .expect("identity ID"),
                has_saved_host_credential: true,
            })
        );

        let host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("malformed.example.com", "alice"),
            1,
        )
        .expect("base host");
        for (field, value) in [
            ("identityId", serde_json::json!(["not", "an", "id"])),
            ("identityFileId", serde_json::json!(7)),
            ("identityFilePaths", serde_json::json!("not-an-array")),
        ] {
            let mut encoded = serde_json::to_value(&host).expect("host JSON");
            encoded[field] = value;
            let compatible: SavedHost =
                serde_json::from_value(encoded).expect("legacy metadata remains readable");
            assert!(matches!(
                compatible.authentication(),
                Err(ValidationError::InvalidAuthenticationConfiguration(_))
            ));
        }
    }

    #[test]
    fn saved_host_group_path_is_typed_canonical_and_clearable() {
        let group = SavedGroupPath::new(r"/ Team //Ops\DB/./").expect("group path");
        let host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("server.example.com", "alice")
                .with_group_path(group.clone()),
            100,
        )
        .expect("grouped saved host");
        assert_eq!(host.group_path(), Ok(Some(group)));
        assert_eq!(
            serde_json::to_value(&host).expect("host JSON")["group"],
            serde_json::json!(r" Team /Ops\DB/.")
        );

        let cleared = host
            .apply_update(SavedHostUpdate::default().clear_group_path(), 101)
            .expect("clear group");
        assert_eq!(cleared.group_path(), Ok(None));
        assert!(
            serde_json::to_value(cleared)
                .expect("cleared host JSON")
                .get("group")
                .is_none()
        );
    }

    #[test]
    fn saved_host_group_compatibility_rejects_wrong_shapes_but_accepts_legacy_root_markers() {
        for invalid in [
            serde_json::json!([]),
            serde_json::json!({}),
            serde_json::json!(7),
        ] {
            assert_eq!(
                SavedHostDraft::ssh_password("host", "user")
                    .with_compatibility_field("group", invalid),
                Err(ValidationError::InvalidGroupPath)
            );
        }
        for root in ["", "/", "////"] {
            let host = SavedHost::from_draft(
                SavedHostDraft::ssh_password("host", "user")
                    .with_compatibility_field("group", serde_json::json!(root))
                    .expect("legacy root marker"),
                1,
            )
            .expect("host");
            assert_eq!(host.group_path(), Ok(None));
        }
    }

    #[test]
    fn compatibility_values_round_trip_but_secret_fields_are_rejected() {
        let draft = SavedHostDraft::ssh_password("host", "user")
            .with_compatibility_field("pluginSetting", serde_json::json!({ "mode": "safe" }))
            .expect("compatible field");
        let host = SavedHost::from_draft(draft, 1).expect("host");
        let encoded = serde_json::to_string(&host).expect("encode");
        let decoded: SavedHost = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded.compatibility_fields(), host.compatibility_fields());

        let unsafe_json = encoded.replace(
            "\"pluginSetting\":{\"mode\":\"safe\"}",
            "\"proxyConfig\":{\"password\":\"must-not-survive\"}",
        );
        assert!(serde_json::from_str::<SavedHost>(&unsafe_json).is_err());
        assert_eq!(
            SavedHostDraft::ssh_password("host", "user")
                .with_compatibility_field("credentialReference", serde_json::json!("opaque")),
            Err(ValidationError::ForbiddenCompatibilityField(
                "credentialReference".to_owned()
            ))
        );
    }

    #[test]
    fn credential_status_flags_must_be_boolean_and_core_keys_cannot_be_flattened() {
        let draft = SavedHostDraft::ssh_password("host", "user")
            .with_compatibility_field("savePassword", serde_json::json!(true))
            .expect("boolean status")
            .with_compatibility_field("hasPrivateKey", serde_json::json!(false))
            .expect("boolean private-key status");
        let host = SavedHost::from_draft(draft, 1).expect("host");
        let encoded = serde_json::to_value(host).expect("encode");
        assert_eq!(encoded["savePassword"], true);
        assert_eq!(encoded["hasPrivateKey"], false);

        for (key, value) in [
            ("savePassword", serde_json::json!("plaintext")),
            ("hasPassword", serde_json::json!("yes")),
            ("hasPrivateKey", serde_json::json!("key material")),
            ("id", serde_json::json!("shadow-id")),
            ("label", serde_json::json!("shadow label")),
            ("hostname", serde_json::json!("shadow.example.com")),
        ] {
            assert!(matches!(
                SavedHostDraft::ssh_password("host", "user").with_compatibility_field(key, value),
                Err(ValidationError::ForbiddenCompatibilityField(_))
            ));
        }
    }

    #[test]
    fn nested_secret_material_is_rejected_but_legacy_identity_metadata_survives() {
        let safe = SavedHostDraft::ssh_password("host", "user")
            .with_compatibility_field("identityId", serde_json::json!(""))
            .expect("empty legacy identity ID")
            .with_compatibility_field("identityFilePaths", serde_json::json!([]))
            .expect("empty identity path list");
        let host = SavedHost::from_draft(safe, 1).expect("safe legacy metadata");
        assert_eq!(host.compatibility_fields()["identityId"], "");
        assert_eq!(
            host.compatibility_fields()["identityFilePaths"],
            serde_json::json!([])
        );

        for unsafe_value in [
            serde_json::json!({ "proxy": { "password": "plaintext" } }),
            serde_json::json!({ "auth": { "passphrase": "plaintext" } }),
            serde_json::json!({ "auth": { "privateKey": "PEM" } }),
            serde_json::json!({ "plugin": { "credentialId": "opaque-reference" } }),
        ] {
            assert!(matches!(
                SavedHostDraft::ssh_password("host", "user")
                    .with_compatibility_field("pluginConfig", unsafe_value),
                Err(ValidationError::ForbiddenCompatibilityField(_))
            ));
        }
    }

    #[test]
    fn nested_reserved_names_round_trip_without_weakening_top_level_or_secret_checks() {
        let output_triggers = serde_json::json!([{
            "id": "trigger-id",
            "pattern": "ready",
            "scriptId": "script-id",
            "enabled": false,
            "metadata": {
                "label": "nested label",
                "hostname": "nested.example.test"
            }
        }]);
        let draft = SavedHostDraft::ssh_password("host", "user")
            .with_compatibility_field("outputTriggers", output_triggers.clone())
            .expect("nested legacy IDs are compatibility metadata");
        let host = SavedHost::from_draft(draft, 1).expect("host");
        assert_eq!(
            host.compatibility_fields()["outputTriggers"],
            output_triggers
        );
        let encoded = serde_json::to_value(&host).expect("encode host");
        let decoded: SavedHost = serde_json::from_value(encoded).expect("decode host");
        assert_eq!(decoded, host);

        for top_level in ["id", "label", "hostname", "recordVersion", "revision"] {
            assert!(matches!(
                SavedHostDraft::ssh_password("host", "user")
                    .with_compatibility_field(top_level, serde_json::json!("shadow")),
                Err(ValidationError::ForbiddenCompatibilityField(_))
            ));
        }
        assert!(matches!(
            SavedHostDraft::ssh_password("host", "user").with_compatibility_field(
                "outputTriggers",
                serde_json::json!([{
                    "id": "trigger-id",
                    "scriptId": "script-id",
                    "details": { "password": "must-not-survive" }
                }]),
            ),
            Err(ValidationError::ForbiddenCompatibilityField(_))
        ));
    }

    #[test]
    fn deserialization_canonicalizes_text_and_defaults_a_blank_label() {
        let encoded = serde_json::json!({
            "id": "legacy-id",
            "label": "  ",
            "hostname": "  legacy.example.com  ",
            "port": 22,
            "username": "  user@example.com  ",
            "createdAt": 1,
            "updatedAt": 1
        });
        let host: SavedHost = serde_json::from_value(encoded).expect("legacy host");
        assert_eq!(host.label, "legacy.example.com");
        assert_eq!(host.hostname, "legacy.example.com");
        assert_eq!(host.username, "user@example.com");

        let mut non_canonical = host;
        non_canonical.label = " padded ".to_owned();
        assert_eq!(
            non_canonical.validate(),
            Err(ValidationError::NonCanonicalField("label"))
        );
    }

    #[test]
    fn updates_preserve_id_created_at_and_unknown_fields() {
        let host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("host", "user")
                .with_compatibility_field("pluginValue", serde_json::json!(7))
                .expect("compatibility"),
            10,
        )
        .expect("host");
        let updated = host
            .apply_update(
                SavedHostUpdate {
                    label: Some("New label".to_owned()),
                    ..SavedHostUpdate::default()
                },
                11,
            )
            .expect("update");
        assert_eq!(updated.id, host.id);
        assert_eq!(updated.created_at, host.created_at);
        assert_eq!(updated.revision, 2);
        assert_eq!(
            updated.compatibility_fields().get("pluginValue"),
            Some(&serde_json::json!(7))
        );
    }

    #[test]
    fn unknown_legacy_protocol_and_auth_values_deserialize_and_round_trip() {
        let encoded = serde_json::json!({
            "recordVersion": 1,
            "id": "legacy-id",
            "revision": 1,
            "label": "Legacy",
            "hostname": "legacy.example.com",
            "port": 22,
            "username": "user@example.com",
            "protocol": "plugin-protocol",
            "authMethod": "plugin-auth",
            "authPolicyVersion": 1,
            "createdAt": 1,
            "updatedAt": 1,
            "pluginFlag": true
        });
        let host: SavedHost = serde_json::from_value(encoded).expect("legacy host");
        assert_eq!(
            host.protocol,
            SavedHostProtocol::compatible("plugin-protocol")
        );
        assert_eq!(
            host.auth_method,
            SavedHostAuthMethod::compatible("plugin-auth")
        );
        assert!(serde_json::to_value(host).expect("encode")["pluginFlag"] == true);
    }

    #[test]
    fn reference_key_and_identity_relationships_round_trip_opaque_compatibility_values() {
        let key_json = serde_json::json!({
            "id": "legacy-key-id",
            "label": "Work key",
            "filePath": "D:\\keys\\work key",
            "category": "identity",
            "source": "REFERENCE",
            "createdAt": 10,
            "updatedAt": 11,
            "legacyNull": null,
            "legacyEmpty": "",
            "legacyFalse": false
        });
        let key: SavedSshKeyReference =
            serde_json::from_value(key_json).expect("reference key metadata");
        assert_eq!(key.source.as_str(), "reference");
        assert_eq!(
            key.compatibility_fields()["legacyNull"],
            serde_json::Value::Null
        );
        assert_eq!(key.compatibility_fields()["legacyEmpty"], "");
        assert_eq!(key.compatibility_fields()["legacyFalse"], false);

        let identity_json = serde_json::json!({
            "id": "legacy-identity-id",
            "label": "Work identity",
            "username": "alice@example.com",
            "authMethod": "KEY",
            "keyId": "legacy-key-id",
            "createdAt": 12,
            "updatedAt": 13,
            "order": 0,
            "enabled": false
        });
        let identity: SavedIdentityReference =
            serde_json::from_value(identity_json).expect("identity metadata");
        assert_eq!(identity.auth_method.as_str(), "key");
        assert_eq!(identity.key_id, key.id);

        let encoded_key = serde_json::to_value(&key).expect("encode key");
        let encoded_identity = serde_json::to_value(&identity).expect("encode identity");
        assert_eq!(
            serde_json::from_value::<SavedSshKeyReference>(encoded_key).expect("decode key"),
            key
        );
        assert_eq!(
            serde_json::from_value::<SavedIdentityReference>(encoded_identity)
                .expect("decode identity"),
            identity
        );
    }

    #[test]
    fn reference_models_reject_secrets_credentials_and_non_reference_auth() {
        let base_key = serde_json::json!({
            "id": "key-id",
            "label": "Key",
            "filePath": "D:\\keys\\id_ed25519",
            "category": "key",
            "source": "reference",
            "createdAt": 1,
            "updatedAt": 1
        });
        for forbidden in [
            "privateKey",
            "passphrase",
            "password",
            "credentialReference",
        ] {
            let mut value = base_key.clone();
            value[forbidden] = serde_json::json!("must-not-survive");
            assert!(serde_json::from_value::<SavedSshKeyReference>(value).is_err());
        }
        let mut generated = base_key;
        generated["source"] = serde_json::json!("generated");
        assert!(serde_json::from_value::<SavedSshKeyReference>(generated).is_err());

        let base_identity = serde_json::json!({
            "id": "identity-id",
            "label": "Identity",
            "username": "alice",
            "authMethod": "key",
            "keyId": "key-id",
            "createdAt": 1,
            "updatedAt": 1
        });
        for forbidden in ["password", "passphrase", "privateKey", "credentialRef"] {
            let mut value = base_identity.clone();
            value[forbidden] = serde_json::json!("must-not-survive");
            assert!(serde_json::from_value::<SavedIdentityReference>(value).is_err());
        }
        let mut password_identity = base_identity;
        password_identity["authMethod"] = serde_json::json!("password");
        assert!(serde_json::from_value::<SavedIdentityReference>(password_identity).is_err());
    }

    #[test]
    fn managed_key_metadata_is_canonical_bounded_and_redacted() {
        let locator_text = "ab".repeat(32);
        let key: SavedManagedSshKey = serde_json::from_value(serde_json::json!({
            "id": "managed-key-id",
            "label": "Managed key label",
            "category": "IDENTITY",
            "source": "IMPORTED",
            "hasSavedPassphrase": true,
            "createdAt": 10,
            "updatedAt": 11,
            "custody": {
                "backendLocator": locator_text,
                "custodyRevision": 7
            },
            "safeDisplayHint": "ed25519"
        }))
        .expect("managed key metadata");
        assert_eq!(key.category, SavedSshKeyCategory::identity());
        assert_eq!(key.source, SavedSshKeySource::imported());
        assert_eq!(key.custody().custody_revision(), 7);
        assert_eq!(key.compatibility_fields()["safeDisplayHint"], "ed25519");

        let debug = format!(
            "{key:?} {:?} {}",
            key.custody(),
            key.custody().backend_locator()
        );
        for hidden in ["managed-key-id", "Managed key label", locator_text.as_str()] {
            assert!(!debug.contains(hidden));
        }

        for invalid in ["ab", &"AB".repeat(32), &"gg".repeat(32)] {
            assert_eq!(
                SavedSecretObjectLocator::from_hex(invalid.to_owned()),
                Err(ValidationError::InvalidSecretObjectLocator)
            );
        }
        assert_eq!(
            SavedSshKeyCustodyReference::new(
                SavedSecretObjectLocator::from_hex("cd".repeat(32)).expect("locator"),
                0,
            ),
            Err(ValidationError::InvalidCustodyRevision)
        );
    }

    #[test]
    fn managed_key_compatibility_cannot_smuggle_secret_store_coordinates() {
        let custody = || {
            SavedSshKeyCustodyReference::new(
                SavedSecretObjectLocator::from_hex("01".repeat(32)).expect("locator"),
                1,
            )
            .expect("custody")
        };
        let managed = || {
            SavedManagedSshKey::from_parts(
                SavedSshKeyReferenceId::from_opaque("managed-key").expect("key ID"),
                "Managed key",
                SavedSshKeyCategory::key(),
                SavedSshKeySource::generated(),
                false,
                1,
                1,
                custody(),
                BTreeMap::new(),
            )
            .expect("managed key")
        };

        for field in [
            "legacy_file_path",
            "public_key",
            "secret_store_uuid",
            "masterKeyEpoch",
            "master_key_account",
            "objectDigest",
            "blobGeneration",
            "ciphertext",
            "nonce",
        ] {
            assert!(matches!(
                managed().with_compatibility_field(field, serde_json::json!("must-not-survive")),
                Err(ValidationError::ForbiddenCompatibilityField(_))
            ));
        }
        assert!(matches!(
            managed().with_compatibility_field(
                "pluginState",
                serde_json::json!({ "storage": { "secret-store": "must-not-survive" } }),
            ),
            Err(ValidationError::ForbiddenCompatibilityField(_))
        ));
    }

    #[test]
    fn password_identity_round_trips_and_updates_only_secret_free_metadata() {
        let identity = SavedPasswordIdentity::from_parts(
            SavedPasswordIdentityId::from_opaque("password-identity").expect("identity ID"),
            7,
            "  Shared login  ",
            "  alice@example.com  ",
            true,
            10,
            11,
            BTreeMap::from([("order".to_owned(), serde_json::json!(2))]),
        )
        .expect("password identity");
        assert_eq!(identity.label, "Shared login");
        assert_eq!(identity.username, "alice@example.com");
        assert!(identity.has_saved_credential);

        let encoded = serde_json::to_value(&identity).expect("encode identity");
        assert_eq!(encoded["hasSavedCredential"], true);
        assert!(encoded.get("password").is_none());
        assert!(encoded.get("credentialReference").is_none());
        assert_eq!(
            serde_json::from_value::<SavedPasswordIdentity>(encoded).expect("decode identity"),
            identity
        );

        let updated = identity
            .apply_update(
                SavedPasswordIdentityUpdate {
                    username: Some("bob".to_owned()),
                    has_saved_credential: Some(false),
                    ..SavedPasswordIdentityUpdate::default()
                },
                11,
            )
            .expect("update identity");
        assert_eq!(updated.revision, 8);
        assert_eq!(updated.created_at, 10);
        assert_eq!(updated.updated_at, 12);
        assert_eq!(updated.username, "bob");
        assert!(!updated.has_saved_credential);
    }

    #[test]
    fn password_identity_rejects_secret_and_catalog_type_fields() {
        let draft = SavedPasswordIdentityDraft::new("Login", "alice", false);
        let identity = SavedPasswordIdentity::from_draft(draft, 1).expect("identity");
        assert_eq!(identity.revision, 1);

        let encoded = serde_json::to_value(&identity).expect("identity JSON");
        for required in [
            "recordVersion",
            "id",
            "revision",
            "label",
            "username",
            "hasSavedCredential",
            "createdAt",
            "updatedAt",
        ] {
            let mut missing = encoded.clone();
            missing.as_object_mut().expect("object").remove(required);
            assert!(serde_json::from_value::<SavedPasswordIdentity>(missing).is_err());
        }
        let mut wrong_version = encoded;
        wrong_version["recordVersion"] = serde_json::json!(2);
        assert!(serde_json::from_value::<SavedPasswordIdentity>(wrong_version).is_err());

        for field in [
            "password",
            "credentialReference",
            "credentialLocator",
            "keyringAccount",
            "ciphertext",
            "authMethod",
            "keyId",
            "hasSavedCredential",
        ] {
            assert!(matches!(
                SavedPasswordIdentityDraft::new("Login", "alice", false)
                    .with_compatibility_field(field, serde_json::json!("must-not-survive")),
                Err(ValidationError::ForbiddenCompatibilityField(_))
            ));
        }
        assert_eq!(
            identity.apply_update(SavedPasswordIdentityUpdate::default(), 2),
            Err(ValidationError::EmptyUpdate)
        );
    }

    #[test]
    fn proxy_configs_are_canonical_bounded_and_secret_free() {
        let identity_id = SavedPasswordIdentityId::from_opaque("proxy-login").expect("ID");
        let config: SavedProxyConfig = serde_json::from_value(serde_json::json!({
            "type": "http",
            "host": " proxy.example.com ",
            "port": 8080,
            "identityId": identity_id,
            "username": "must-be-cleared",
            "hasSavedCredential": true,
            "futureMode": { "enabled": true }
        }))
        .expect("proxy config");
        let encoded = serde_json::to_value(&config).expect("proxy JSON");
        assert_eq!(encoded["host"], "proxy.example.com");
        assert_eq!(encoded["username"], "");
        assert_eq!(encoded["hasSavedCredential"], false);
        assert_eq!(encoded["futureMode"]["enabled"], true);
        assert!(encoded.get("password").is_none());

        assert!(SavedProxyConfig::http("bad host", 80, None, "", false).is_err());
        assert!(SavedProxyConfig::socks5("proxy", 0, None, "", false).is_err());
        assert!(SavedProxyConfig::http("proxy", 80, None, "x".repeat(256), false).is_err());
        assert_eq!(
            SavedProxyConfig::command("  ssh -W %h:%p gateway  ").expect("command"),
            SavedProxyConfig::command("ssh -W %h:%p gateway").expect("trimmed command")
        );
        assert!(SavedProxyConfig::command("bad\0command").is_err());
        assert!(
            SavedProxyConfig::http("proxy", 80, None, "alice", false)
                .expect("manual proxy")
                .with_saved_credential_hint(true)
                .is_ok()
        );
        assert!(
            SavedProxyConfig::http(
                "proxy",
                80,
                Some(SavedPasswordIdentityId::from_opaque("identity").expect("ID")),
                "",
                false,
            )
            .expect("identity proxy")
            .with_saved_credential_hint(false)
            .is_err()
        );
        assert!(
            SavedProxyConfig::command("connect %h %p")
                .expect("command proxy")
                .with_saved_credential_hint(true)
                .is_err()
        );
        assert!(
            serde_json::from_value::<SavedProxyConfig>(serde_json::json!({
                "type": "socks5",
                "host": "proxy",
                "port": 1080,
                "password": "must-not-survive"
            }))
            .is_err()
        );
    }

    #[test]
    fn proxy_profile_planning_and_flattened_host_helpers_preserve_compatibility() {
        let profile = SavedProxyProfile::from_draft(
            SavedProxyProfileDraft::new(
                "  Office proxy  ",
                SavedProxyConfig::command("  connect --stdio  ").expect("config"),
            )
            .with_compatibility_field("order", serde_json::json!(3))
            .expect("compatibility"),
            10,
        )
        .expect("profile");
        assert_eq!(profile.label, "Office proxy");
        assert_eq!(profile.revision, 1);
        let updated = profile
            .apply_update(
                SavedProxyProfileUpdate {
                    label: Some("Office proxy 2".to_owned()),
                    ..SavedProxyProfileUpdate::default()
                },
                10,
            )
            .expect("update");
        assert_eq!(updated.revision, 2);
        assert_eq!(updated.created_at, 10);
        assert_eq!(updated.updated_at, 11);

        let missing_profile = SavedProxyProfileId::from_opaque("missing-profile").expect("ID");
        let host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("host.example.com", "alice")
                .with_proxy_profile_id(missing_profile.clone())
                .expect("profile field")
                .with_proxy_config(
                    SavedProxyConfig::http("inline.proxy", 3128, None, "bob", true)
                        .expect("inline config"),
                )
                .expect("inline field"),
            20,
        )
        .expect("host");
        assert_eq!(
            host.proxy_profile_id().expect("typed profile"),
            Some(missing_profile)
        );
        assert!(host.proxy_config().expect("typed inline").is_some());
        let host_json = serde_json::to_value(host).expect("host JSON");
        assert!(host_json.get("proxyConfig").is_some());
        assert!(host_json.get("proxyProfileId").is_some());
        assert!(host_json.get("password").is_none());
    }
}
