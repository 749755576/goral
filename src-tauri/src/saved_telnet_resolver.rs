//! Secret-safe SavedHost Telnet connection preparation.
//!
//! This module is deliberately independent from Tauri commands.  It binds a
//! connection-time [`SavedHostConnectionProjection`] back to the durable
//! [`SavedVaultGraph`], validates the Telnet-only metadata, plans the exact
//! credential namespaces, and performs the small asynchronous credential
//! lookup.  Missing credential hints are returned as typed repair work; this
//! module never mutates the Vault.

use std::fmt;

use netcatty_credentials::{
    CredentialErrorCode, CredentialKind, OsCredentialStore, SecretValue, StoredCredentialReference,
};
use netcatty_telnet::{
    DEFAULT_TERMINAL_TYPE, MAX_INPUT_BYTES, TelnetCharset, TelnetConfig, TelnetRuntimeConfig,
    WindowSize, auto_login::LOGIN_VALUE_LIMIT,
};
use netcatty_vault::{
    SavedGroupHostChain, SavedGroupId, SavedGroupOverride, SavedGroupProxyOverride, SavedHost,
    SavedHostConnectionCredentialOwner, SavedHostConnectionProjection, SavedHostId,
    SavedPasswordIdentityId, SavedVaultGraph, project_saved_host_connection,
};
use serde::Deserialize;
use serde_json::Value;

const MAX_CHARSET_NAME_BYTES: usize = 32;
const MAX_STARTUP_COMMAND_BYTES: usize = MAX_INPUT_BYTES - 1;

/// Terminal facts supplied by the renderer for a SavedHost session.
///
/// Construction validates NAWS dimensions and the RFC 1091 terminal name
/// before any one-shot or persistent credential is examined.
pub(crate) struct SavedTelnetTerminalOptions {
    terminal_type: String,
    columns: u32,
    rows: u32,
}

impl SavedTelnetTerminalOptions {
    pub(crate) fn new(columns: u32, rows: u32) -> Result<Self, SavedTelnetResolverError> {
        WindowSize::new(columns, rows)
            .map_err(|_| SavedTelnetResolverError::InvalidTerminalSize)?;
        Ok(Self {
            terminal_type: DEFAULT_TERMINAL_TYPE.to_owned(),
            columns,
            rows,
        })
    }

    pub(crate) fn with_terminal_type(
        mut self,
        terminal_type: impl Into<String>,
    ) -> Result<Self, SavedTelnetResolverError> {
        let terminal_type = terminal_type.into();
        TelnetConfig::default()
            .with_terminal_type(&terminal_type)
            .map_err(|_| SavedTelnetResolverError::InvalidTerminalType)?;
        self.terminal_type = terminal_type;
        Ok(self)
    }
}

impl Default for SavedTelnetTerminalOptions {
    fn default() -> Self {
        Self {
            terminal_type: DEFAULT_TERMINAL_TYPE.to_owned(),
            columns: 80,
            rows: 24,
        }
    }
}

impl fmt::Debug for SavedTelnetTerminalOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SavedTelnetTerminalOptions([validated])")
    }
}

/// Secret-free runtime metadata.  Text accessors are available to the trusted
/// adapter for connection-log metadata, while diagnostics remain redacted.
pub(crate) struct SavedTelnetRuntimeMetadata {
    hostname: String,
    port: u16,
    username: String,
    charset: TelnetCharset,
    startup_command: Option<String>,
    terminal: SavedTelnetTerminalOptions,
}

impl SavedTelnetRuntimeMetadata {
    pub(crate) fn hostname(&self) -> &str {
        &self.hostname
    }

    pub(crate) const fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn username(&self) -> &str {
        &self.username
    }

    fn build_runtime_config(&self) -> Result<TelnetRuntimeConfig, SavedTelnetResolverError> {
        let mut config = TelnetRuntimeConfig::new(
            self.hostname.clone(),
            self.port,
            self.terminal.columns,
            self.terminal.rows,
        )
        .map_err(|_| SavedTelnetResolverError::InvalidRuntimeConfiguration)?
        .with_terminal_type(&self.terminal.terminal_type)
        .map_err(|_| SavedTelnetResolverError::InvalidRuntimeConfiguration)?
        .with_charset(self.charset);

        if !self.username.is_empty() {
            config = config
                .with_username(self.username.clone())
                .map_err(|_| SavedTelnetResolverError::InvalidRuntimeConfiguration)?;
        }
        if let Some(startup_command) = self.startup_command.as_ref() {
            config = config
                .with_startup_command(startup_command.clone())
                .map_err(|_| SavedTelnetResolverError::InvalidRuntimeConfiguration)?;
        }
        Ok(config)
    }
}

impl fmt::Debug for SavedTelnetRuntimeMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SavedTelnetRuntimeMetadata([redacted validated metadata])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SavedTelnetCredentialSource {
    None,
    OneShot,
    PasswordIdentity,
    Host,
    Group,
}

/// A stale durable presence hint discovered through an authoritative
/// `NotFound`.  The caller may apply these under its normal Vault CAS and
/// recovery boundary.  IDs are intentionally omitted from `Debug`.
pub(crate) enum SavedTelnetHintRepair {
    PasswordIdentity {
        identity_id: SavedPasswordIdentityId,
        expected_revision: u64,
    },
    Host {
        host_id: SavedHostId,
        expected_revision: u64,
    },
    Group {
        group_id: SavedGroupId,
        expected_revision: u64,
    },
}

impl fmt::Debug for SavedTelnetHintRepair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PasswordIdentity { .. } => "PasswordIdentityHintRepair([redacted])",
            Self::Host { .. } => "HostTelnetHintRepair([redacted])",
            Self::Group { .. } => "GroupTelnetHintRepair([redacted])",
        })
    }
}

struct PersistentCredentialLookup {
    reference: StoredCredentialReference,
    kind: CredentialKind,
    source: SavedTelnetCredentialSource,
    missing_hint_repair: SavedTelnetHintRepair,
}

impl fmt::Debug for PersistentCredentialLookup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistentCredentialLookup")
            .field("source", &self.source)
            .field("reference", &"[redacted]")
            .field("missing_hint_repair", &self.missing_hint_repair)
            .finish()
    }
}

enum SavedTelnetCredentialPlan {
    OneShot(SecretValue),
    Persistent {
        identity: Option<PersistentCredentialLookup>,
        manual: Option<PersistentCredentialLookup>,
    },
}

impl fmt::Debug for SavedTelnetCredentialPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OneShot(_) => formatter.write_str("OneShot([redacted])"),
            Self::Persistent { identity, manual } => formatter
                .debug_struct("Persistent")
                .field("has_identity_lookup", &identity.is_some())
                .field("has_manual_lookup", &manual.is_some())
                .finish(),
        }
    }
}

/// Fully validated pure plan.  It may own a one-shot password but cannot be
/// serialized, cloned, or displayed.
pub(crate) struct SavedTelnetSessionPlan {
    metadata: SavedTelnetRuntimeMetadata,
    credential: SavedTelnetCredentialPlan,
}

impl SavedTelnetSessionPlan {
    pub(crate) fn metadata(&self) -> &SavedTelnetRuntimeMetadata {
        &self.metadata
    }
}

impl fmt::Debug for SavedTelnetSessionPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SavedTelnetSessionPlan")
            .field("metadata", &self.metadata)
            .field("credential", &self.credential)
            .finish()
    }
}

/// Secret-owning resolution result.  `Debug` exposes only the selected source
/// class and repair count, never connection text, owner IDs, or password data.
pub(crate) struct ResolvedSavedTelnetSession {
    metadata: SavedTelnetRuntimeMetadata,
    password: Option<SecretValue>,
    credential_source: SavedTelnetCredentialSource,
    repairs: Vec<SavedTelnetHintRepair>,
}

impl ResolvedSavedTelnetSession {
    pub(crate) fn metadata(&self) -> &SavedTelnetRuntimeMetadata {
        &self.metadata
    }

    pub(crate) const fn credential_source(&self) -> SavedTelnetCredentialSource {
        self.credential_source
    }

    pub(crate) fn repair_actions(&self) -> &[SavedTelnetHintRepair] {
        &self.repairs
    }

    /// Consumes all secret-bearing state into the Telnet runtime's own
    /// zeroizing auto-login values and returns any independent Vault repairs.
    pub(crate) fn into_runtime_config(
        self,
    ) -> Result<(TelnetRuntimeConfig, Vec<SavedTelnetHintRepair>), SavedTelnetResolverError> {
        let mut config = self.metadata.build_runtime_config()?;
        if let Some(password) = self.password {
            let password = password
                .as_utf8()
                .map_err(|_| SavedTelnetResolverError::InvalidCredential)?
                .to_owned();
            config = config
                .with_password(password)
                .map_err(|_| SavedTelnetResolverError::InvalidCredential)?;
        }
        Ok((config, self.repairs))
    }
}

impl fmt::Debug for ResolvedSavedTelnetSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedSavedTelnetSession")
            .field("metadata", &self.metadata)
            .field("credential_source", &self.credential_source)
            .field("has_password", &self.password.is_some())
            .field("repair_count", &self.repairs.len())
            .finish()
    }
}

/// Fixed, renderer-safe failures.  The enum deliberately stores no attacker
/// controlled text, raw owner ID, reference, username, hostname, or secret.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SavedTelnetResolverError {
    InvalidProjection,
    UnsupportedProtocol,
    InvalidMetadata,
    InvalidPort,
    InvalidUsername,
    InvalidCharset,
    InvalidStartupCommand,
    InvalidTerminalSize,
    InvalidTerminalType,
    UnsupportedProxy,
    UnsupportedJumpChain,
    MissingPasswordIdentity,
    AmbiguousPasswordIdentity,
    InvalidCredentialOwner,
    InvalidCredential,
    CredentialLookup(CredentialErrorCode),
    InvalidRuntimeConfiguration,
}

impl fmt::Display for SavedTelnetResolverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidProjection => "Saved Telnet projection is not bound to the durable Vault",
            Self::UnsupportedProtocol => "Saved connection is not a primary Telnet host",
            Self::InvalidMetadata => "Saved Telnet metadata is invalid",
            Self::InvalidPort => "Saved Telnet port is invalid",
            Self::InvalidUsername => "Saved Telnet username is invalid",
            Self::InvalidCharset => "Saved Telnet charset is invalid",
            Self::InvalidStartupCommand => "Saved Telnet startup command is invalid",
            Self::InvalidTerminalSize => "Telnet terminal size is invalid",
            Self::InvalidTerminalType => "Telnet terminal type is invalid",
            Self::UnsupportedProxy => "Telnet does not support the effective saved proxy",
            Self::UnsupportedJumpChain => "Telnet does not support the effective jump-host chain",
            Self::MissingPasswordIdentity => "Saved Telnet password identity is missing",
            Self::AmbiguousPasswordIdentity => "Saved Telnet password identity is ambiguous",
            Self::InvalidCredentialOwner => "Saved Telnet credential ownership is invalid",
            Self::InvalidCredential => "Saved Telnet credential is invalid",
            Self::CredentialLookup(code) => code.message(),
            Self::InvalidRuntimeConfiguration => "Saved Telnet runtime configuration is invalid",
        })
    }
}

impl fmt::Debug for SavedTelnetResolverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for SavedTelnetResolverError {}

/// Purely validates and plans a SavedHost Telnet start.
///
/// `projection` must be the exact result of projecting the unique durable host
/// in `graph`.  Recomputing and comparing it here prevents a stale projection,
/// another graph's projection, or forged credential provenance from selecting
/// an unrelated keyring owner.
pub(crate) fn plan_saved_telnet_session(
    graph: &SavedVaultGraph,
    projection: &SavedHostConnectionProjection,
    one_shot_password: Option<SecretValue>,
    terminal: SavedTelnetTerminalOptions,
) -> Result<SavedTelnetSessionPlan, SavedTelnetResolverError> {
    let durable_host = bind_durable_projection(graph, projection)?;
    if !durable_host.protocol.is_telnet() || !projection.effective_host().protocol.is_telnet() {
        return Err(SavedTelnetResolverError::UnsupportedProtocol);
    }

    reject_unsupported_relationships(projection)?;

    let effective_host = projection.effective_host();
    let identity_id = parse_telnet_identity_id(effective_host)?;
    let selected_identity = match identity_id.as_ref() {
        Some(identity_id) => Some(unique_password_identity(graph, identity_id)?),
        None => None,
    };

    let mut username = parse_telnet_username(effective_host)?;
    if let Some(identity) = selected_identity {
        let identity_username = identity.username.trim();
        if !identity_username.is_empty() {
            username.clear();
            username.push_str(identity_username);
        }
    }
    validate_username(&username)?;

    let metadata = SavedTelnetRuntimeMetadata {
        hostname: effective_host.hostname.clone(),
        port: parse_telnet_port(effective_host)?,
        username,
        charset: parse_charset(effective_host)?,
        startup_command: parse_startup_command(effective_host)?,
        terminal,
    };
    // Complete non-secret validation happens before inspecting a one-shot or
    // reading a persistent credential.
    metadata.build_runtime_config()?;

    let identity_lookup = selected_identity
        .filter(|identity| identity.has_saved_credential)
        .map(|identity| {
            let reference = StoredCredentialReference::for_saved_identity(identity.id.as_str())
                .map_err(|_| SavedTelnetResolverError::InvalidCredentialOwner)?;
            Ok(PersistentCredentialLookup {
                reference,
                // PasswordIdentity is an existing shared SSH-password owner;
                // Telnet must use its established envelope kind.
                kind: CredentialKind::SshPassword,
                source: SavedTelnetCredentialSource::PasswordIdentity,
                missing_hint_repair: SavedTelnetHintRepair::PasswordIdentity {
                    identity_id: identity.id.clone(),
                    expected_revision: identity.revision,
                },
            })
        })
        .transpose()?;
    let manual_lookup = plan_manual_credential_lookup(graph, durable_host, projection)?;

    let credential = match one_shot_password {
        Some(secret) => {
            validate_password(&secret)?;
            SavedTelnetCredentialPlan::OneShot(secret)
        }
        None => SavedTelnetCredentialPlan::Persistent {
            identity: identity_lookup,
            manual: manual_lookup,
        },
    };

    Ok(SavedTelnetSessionPlan {
        metadata,
        credential,
    })
}

/// Resolves the pure plan against the OS credential abstraction.
///
/// Password lookup order is fixed: one-shot, password identity using the
/// identity's existing `SshPassword` kind, then the exact Host/Group Telnet
/// owner using `TelnetPassword`.  Authoritative missing entries become repair
/// actions and resolution continues; no password is a valid manual-login
/// result.  Every other custody error fails closed.
pub(crate) async fn resolve_saved_telnet_plan(
    credentials: &OsCredentialStore,
    plan: SavedTelnetSessionPlan,
) -> Result<ResolvedSavedTelnetSession, SavedTelnetResolverError> {
    let SavedTelnetSessionPlan {
        metadata,
        credential,
    } = plan;
    match credential {
        SavedTelnetCredentialPlan::OneShot(password) => Ok(ResolvedSavedTelnetSession {
            metadata,
            password: Some(password),
            credential_source: SavedTelnetCredentialSource::OneShot,
            repairs: Vec::new(),
        }),
        SavedTelnetCredentialPlan::Persistent { identity, manual } => {
            let mut repairs = Vec::with_capacity(2);
            for lookup in identity.into_iter().chain(manual) {
                match credentials.resolve(&lookup.reference, lookup.kind).await {
                    Ok(password) => {
                        validate_password(&password)?;
                        return Ok(ResolvedSavedTelnetSession {
                            metadata,
                            password: Some(password),
                            credential_source: lookup.source,
                            repairs,
                        });
                    }
                    Err(error) if error.code() == CredentialErrorCode::NotFound => {
                        repairs.push(lookup.missing_hint_repair);
                    }
                    Err(error) => {
                        return Err(SavedTelnetResolverError::CredentialLookup(error.code()));
                    }
                }
            }
            Ok(ResolvedSavedTelnetSession {
                metadata,
                password: None,
                credential_source: SavedTelnetCredentialSource::None,
                repairs,
            })
        }
    }
}

/// Convenience wrapper for the normal adapter path.
pub(crate) async fn resolve_saved_telnet_session(
    credentials: &OsCredentialStore,
    graph: &SavedVaultGraph,
    projection: &SavedHostConnectionProjection,
    one_shot_password: Option<SecretValue>,
    terminal: SavedTelnetTerminalOptions,
) -> Result<ResolvedSavedTelnetSession, SavedTelnetResolverError> {
    let plan = plan_saved_telnet_session(graph, projection, one_shot_password, terminal)?;
    resolve_saved_telnet_plan(credentials, plan).await
}

fn bind_durable_projection<'a>(
    graph: &'a SavedVaultGraph,
    projection: &SavedHostConnectionProjection,
) -> Result<&'a SavedHost, SavedTelnetResolverError> {
    let projected_id = &projection.effective_host().id;
    let mut matches = graph.hosts().iter().filter(|host| host.id == *projected_id);
    let durable = matches
        .next()
        .ok_or(SavedTelnetResolverError::InvalidProjection)?;
    if matches.next().is_some() {
        return Err(SavedTelnetResolverError::InvalidProjection);
    }
    let expected = project_saved_host_connection(durable, graph.groups())
        .map_err(|_| SavedTelnetResolverError::InvalidProjection)?;
    if &expected != projection {
        return Err(SavedTelnetResolverError::InvalidProjection);
    }
    Ok(durable)
}

fn parse_telnet_port(host: &SavedHost) -> Result<u16, SavedTelnetResolverError> {
    match host.compatibility_fields().get("telnetPort") {
        None | Some(Value::Null) => host
            .network_port()
            .map_err(|_| SavedTelnetResolverError::InvalidPort),
        Some(Value::Number(value)) => value
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .filter(|value| *value != 0)
            .ok_or(SavedTelnetResolverError::InvalidPort),
        Some(_) => Err(SavedTelnetResolverError::InvalidPort),
    }
}

fn parse_telnet_username(host: &SavedHost) -> Result<String, SavedTelnetResolverError> {
    let username = match host.compatibility_fields().get("telnetUsername") {
        None | Some(Value::Null) => host.username.trim(),
        Some(Value::String(value)) => value.trim(),
        Some(_) => return Err(SavedTelnetResolverError::InvalidUsername),
    };
    Ok(username.to_owned())
}

fn validate_username(username: &str) -> Result<(), SavedTelnetResolverError> {
    if username.len() > LOGIN_VALUE_LIMIT || username.chars().any(char::is_control) {
        Err(SavedTelnetResolverError::InvalidUsername)
    } else {
        Ok(())
    }
}

fn parse_telnet_identity_id(
    host: &SavedHost,
) -> Result<Option<SavedPasswordIdentityId>, SavedTelnetResolverError> {
    match host.compatibility_fields().get("telnetIdentityId") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        Some(Value::String(value)) => SavedPasswordIdentityId::from_opaque(value.clone())
            .map(Some)
            .map_err(|_| SavedTelnetResolverError::InvalidMetadata),
        Some(_) => Err(SavedTelnetResolverError::InvalidMetadata),
    }
}

fn unique_password_identity<'a>(
    graph: &'a SavedVaultGraph,
    identity_id: &SavedPasswordIdentityId,
) -> Result<&'a netcatty_vault::SavedPasswordIdentity, SavedTelnetResolverError> {
    let mut matches = graph
        .password_identities()
        .iter()
        .filter(|identity| identity.id == *identity_id);
    let identity = matches
        .next()
        .ok_or(SavedTelnetResolverError::MissingPasswordIdentity)?;
    if matches.next().is_some()
        || graph
            .identity_references()
            .iter()
            .any(|candidate| candidate.id.as_str() == identity_id.as_str())
    {
        return Err(SavedTelnetResolverError::AmbiguousPasswordIdentity);
    }
    Ok(identity)
}

fn parse_charset(host: &SavedHost) -> Result<TelnetCharset, SavedTelnetResolverError> {
    let Some(value) = host.compatibility_fields().get("charset") else {
        return Ok(TelnetCharset::Utf8);
    };
    let Value::String(value) = value else {
        return if value.is_null() {
            Ok(TelnetCharset::Utf8)
        } else {
            Err(SavedTelnetResolverError::InvalidCharset)
        };
    };
    if value.len() > MAX_CHARSET_NAME_BYTES || value.chars().any(char::is_control) {
        return Err(SavedTelnetResolverError::InvalidCharset);
    }
    // The runtime owns the allow-listed, ASCII-compatible encoding parser and
    // its legacy-compatible UTF-8 fallback for empty/unknown labels.
    Ok(TelnetCharset::parse_label(value))
}

fn parse_startup_command(host: &SavedHost) -> Result<Option<String>, SavedTelnetResolverError> {
    match host.compatibility_fields().get("startupCommand") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value))
            if value.len() <= MAX_STARTUP_COMMAND_BYTES
                && !value.chars().any(|character| {
                    character.is_control() && !matches!(character, '\n' | '\r' | '\t')
                }) =>
        {
            Ok(Some(value.clone()))
        }
        Some(_) => Err(SavedTelnetResolverError::InvalidStartupCommand),
    }
}

fn validate_password(password: &SecretValue) -> Result<(), SavedTelnetResolverError> {
    let password = password
        .as_utf8()
        .map_err(|_| SavedTelnetResolverError::InvalidCredential)?;
    if password.len() > LOGIN_VALUE_LIMIT {
        Err(SavedTelnetResolverError::InvalidCredential)
    } else {
        Ok(())
    }
}

fn plan_manual_credential_lookup(
    graph: &SavedVaultGraph,
    durable_host: &SavedHost,
    projection: &SavedHostConnectionProjection,
) -> Result<Option<PersistentCredentialLookup>, SavedTelnetResolverError> {
    let Some(owner) = projection.telnet_credential_owner() else {
        return Ok(None);
    };
    match owner {
        SavedHostConnectionCredentialOwner::Host(host_id) => {
            if host_id != &durable_host.id {
                return Err(SavedTelnetResolverError::InvalidCredentialOwner);
            }
            let reference = StoredCredentialReference::for_saved_host_telnet(host_id.as_str())
                .map_err(|_| SavedTelnetResolverError::InvalidCredentialOwner)?;
            Ok(Some(PersistentCredentialLookup {
                reference,
                kind: CredentialKind::TelnetPassword,
                source: SavedTelnetCredentialSource::Host,
                missing_hint_repair: SavedTelnetHintRepair::Host {
                    host_id: host_id.clone(),
                    expected_revision: durable_host.revision,
                },
            }))
        }
        SavedHostConnectionCredentialOwner::Group(group_id) => {
            let mut matches = graph.groups().iter().filter(|group| group.id == *group_id);
            let group = matches
                .next()
                .ok_or(SavedTelnetResolverError::InvalidCredentialOwner)?;
            if matches.next().is_some() {
                return Err(SavedTelnetResolverError::InvalidCredentialOwner);
            }
            let reference = StoredCredentialReference::for_saved_group_telnet(group_id.as_str())
                .map_err(|_| SavedTelnetResolverError::InvalidCredentialOwner)?;
            Ok(Some(PersistentCredentialLookup {
                reference,
                kind: CredentialKind::TelnetPassword,
                source: SavedTelnetCredentialSource::Group,
                missing_hint_repair: SavedTelnetHintRepair::Group {
                    group_id: group_id.clone(),
                    expected_revision: group.revision,
                },
            }))
        }
    }
}

fn reject_unsupported_relationships(
    projection: &SavedHostConnectionProjection,
) -> Result<(), SavedTelnetResolverError> {
    let host = projection.effective_host();
    if active_proxy_config(host.compatibility_fields().get("proxyConfig"))?
        || active_profile(host.compatibility_fields().get("proxyProfileId"))?
        || matches!(
            projection.resolved_group_defaults().proxy,
            SavedGroupProxyOverride::Profile(_) | SavedGroupProxyOverride::Inline(_)
        )
    {
        return Err(SavedTelnetResolverError::UnsupportedProxy);
    }

    if !projection.host_chain_ids().is_empty()
        || active_host_chain(host.compatibility_fields().get("hostChain"))?
        || matches!(
            &projection.resolved_group_defaults().host_chain,
            SavedGroupOverride::Set(chain) if !chain.host_ids().is_empty()
        )
    {
        return Err(SavedTelnetResolverError::UnsupportedJumpChain);
    }
    Ok(())
}

fn active_proxy_config(value: Option<&Value>) -> Result<bool, SavedTelnetResolverError> {
    match value {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Object(object)) if !object.is_empty() => Ok(true),
        Some(_) => Err(SavedTelnetResolverError::InvalidMetadata),
    }
}

fn active_profile(value: Option<&Value>) -> Result<bool, SavedTelnetResolverError> {
    match value {
        None | Some(Value::Null) => Ok(false),
        Some(Value::String(value)) if value.is_empty() => Ok(false),
        Some(Value::String(_)) => Ok(true),
        Some(_) => Err(SavedTelnetResolverError::InvalidMetadata),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SavedHostChainWire {
    host_ids: SavedGroupHostChain,
}

fn active_host_chain(value: Option<&Value>) -> Result<bool, SavedTelnetResolverError> {
    let chain = match value {
        None | Some(Value::Null) => return Ok(false),
        Some(value @ Value::Object(_)) => {
            serde_json::from_value::<SavedHostChainWire>(value.clone()).map(|wire| wire.host_ids)
        }
        Some(value @ Value::Array(_)) => {
            serde_json::from_value::<SavedGroupHostChain>(value.clone())
        }
        Some(_) => return Err(SavedTelnetResolverError::InvalidMetadata),
    }
    .map_err(|_| SavedTelnetResolverError::InvalidMetadata)?;
    Ok(!chain.host_ids().is_empty())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use netcatty_credentials::{
        CredentialKind, SecretValue, StoredCredentialReference,
        test_support::{CredentialOperation, in_memory_credential_store},
    };
    use netcatty_telnet::{MAX_INPUT_BYTES, MAX_WINDOW_DIMENSION};
    use netcatty_vault::{
        SavedGroupConfig, SavedGroupCredentialOverride, SavedGroupDefaults, SavedGroupHostChain,
        SavedGroupId, SavedGroupOverride, SavedGroupPath, SavedGroupProxyOverride,
        SavedGroupSingleLineText, SavedHost, SavedHostDraft, SavedHostId, SavedPasswordIdentity,
        SavedPasswordIdentityId, SavedProxyProfileId, SavedVaultGraph,
        project_saved_host_connection,
    };
    use serde_json::{Value, json};

    use super::{
        SavedTelnetCredentialSource, SavedTelnetHintRepair, SavedTelnetResolverError,
        SavedTelnetTerminalOptions, plan_saved_telnet_session, resolve_saved_telnet_plan,
        resolve_saved_telnet_session,
    };

    fn secret(value: &str) -> SecretValue {
        SecretValue::from_utf8(value.to_owned()).expect("test secret")
    }

    fn text(value: &str) -> SavedGroupSingleLineText {
        SavedGroupSingleLineText::new(value).expect("single-line group value")
    }

    fn telnet_host(
        hostname: &str,
        username: &str,
        port: u32,
        fields: impl IntoIterator<Item = (&'static str, Value)>,
    ) -> SavedHost {
        let mut draft = SavedHostDraft::telnet(hostname, username);
        draft.port = Some(port);
        for (key, value) in fields {
            draft = draft
                .with_compatibility_field(key, value)
                .expect("host compatibility field");
        }
        SavedHost::from_draft(draft, 10).expect("saved Telnet host")
    }

    fn password_identity(
        id: &str,
        username: &str,
        has_saved_credential: bool,
    ) -> SavedPasswordIdentity {
        SavedPasswordIdentity::from_parts(
            SavedPasswordIdentityId::from_opaque(id).expect("identity ID"),
            7,
            "Telnet identity",
            username,
            has_saved_credential,
            1,
            2,
            BTreeMap::new(),
        )
        .expect("password identity")
    }

    fn group(id: &str, path: &str, defaults: SavedGroupDefaults) -> SavedGroupConfig {
        SavedGroupConfig::from_parts(
            SavedGroupId::from_opaque(id).expect("group ID"),
            11,
            SavedGroupPath::new(path).expect("group path"),
            defaults,
            1,
            2,
        )
        .expect("group config")
    }

    fn graph(
        host: SavedHost,
        identities: Vec<SavedPasswordIdentity>,
        groups: Vec<SavedGroupConfig>,
    ) -> SavedVaultGraph {
        SavedVaultGraph::new_with_proxy_profiles(
            vec![host],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            identities,
            Vec::new(),
            groups,
        )
    }

    fn projection(graph: &SavedVaultGraph) -> netcatty_vault::SavedHostConnectionProjection {
        project_saved_host_connection(&graph.hosts()[0], graph.groups())
            .expect("saved-host projection")
    }

    fn terminal() -> SavedTelnetTerminalOptions {
        SavedTelnetTerminalOptions::new(120, 40)
            .expect("terminal size")
            .with_terminal_type("xterm-256color")
            .expect("terminal type")
    }

    #[tokio::test]
    async fn metadata_uses_telnet_specific_port_and_username_before_host_values() {
        let host = telnet_host(
            "console.private.example",
            "host-user-private",
            2323,
            [
                ("telnetPort", json!(2424)),
                ("telnetUsername", json!("  telnet-user-private  ")),
                ("charset", json!("GBK")),
                ("startupCommand", json!("show private-status\nshow clock")),
            ],
        );
        let graph = graph(host, Vec::new(), Vec::new());
        let projection = projection(&graph);
        let plan =
            plan_saved_telnet_session(&graph, &projection, None, terminal()).expect("valid plan");
        assert_eq!(plan.metadata().hostname(), "console.private.example");
        assert_eq!(plan.metadata().port(), 2424);
        assert_eq!(plan.metadata().username(), "telnet-user-private");

        let (store, _) = in_memory_credential_store();
        let resolved = resolve_saved_telnet_plan(&store, plan)
            .await
            .expect("manual-login result");
        assert_eq!(
            resolved.credential_source(),
            SavedTelnetCredentialSource::None
        );
        let (runtime, repairs) = resolved
            .into_runtime_config()
            .expect("runtime configuration");
        assert_eq!(runtime.port(), 2424);
        assert_eq!(runtime.window_size().columns(), 120);
        assert_eq!(runtime.window_size().rows(), 40);
        assert_eq!(runtime.charset().normalized_label(), "gb18030");
        assert!(repairs.is_empty());
    }

    #[tokio::test]
    async fn one_shot_password_has_absolute_priority_and_performs_no_keyring_read() {
        let identity_id = "one-shot-priority-identity-private";
        let host = telnet_host(
            "one-shot.example",
            "host-user",
            23,
            [("telnetIdentityId", json!(identity_id))],
        );
        let identity = password_identity(identity_id, "identity-user", true);
        let graph = graph(host, vec![identity], Vec::new());
        let projection = projection(&graph);
        let (store, controller) = in_memory_credential_store();
        let identity_reference =
            StoredCredentialReference::for_saved_identity(identity_id).expect("identity reference");
        store
            .upsert(
                &identity_reference,
                CredentialKind::SshPassword,
                secret("identity-password-private"),
            )
            .await
            .expect("store identity password");
        controller.clear_operation_log();

        let resolved = resolve_saved_telnet_session(
            &store,
            &graph,
            &projection,
            Some(secret("one-shot-password-private")),
            terminal(),
        )
        .await
        .expect("one-shot resolution");
        assert_eq!(
            resolved.credential_source(),
            SavedTelnetCredentialSource::OneShot
        );
        assert_eq!(
            resolved
                .password
                .as_ref()
                .expect("one-shot password")
                .as_utf8()
                .expect("UTF-8 password"),
            "one-shot-password-private"
        );
        assert_eq!(
            controller
                .operation_log()
                .count(CredentialOperation::Resolve),
            0
        );
    }

    #[tokio::test]
    async fn password_identity_uses_existing_identity_owner_kind_and_overrides_username() {
        let identity_id = "identity-owner-private";
        let host = telnet_host(
            "identity.example",
            "host-user-private",
            23,
            [
                ("telnetUsername", json!("telnet-user-private")),
                ("telnetIdentityId", json!(identity_id)),
                ("hasSavedCredential", json!(true)),
            ],
        );
        let identity = password_identity(identity_id, "identity-user-private", true);
        let host_id = host.id.clone();
        let graph = graph(host, vec![identity], Vec::new());
        let projection = projection(&graph);
        let (store, controller) = in_memory_credential_store();
        store
            .upsert(
                &StoredCredentialReference::for_saved_identity(identity_id)
                    .expect("identity owner"),
                CredentialKind::SshPassword,
                secret("identity-secret-private"),
            )
            .await
            .expect("store identity password");
        store
            .upsert(
                &StoredCredentialReference::for_saved_host_telnet(host_id.as_str())
                    .expect("host Telnet owner"),
                CredentialKind::TelnetPassword,
                secret("host-secret-must-not-win"),
            )
            .await
            .expect("store host Telnet password");
        controller.clear_operation_log();

        let resolved = resolve_saved_telnet_session(&store, &graph, &projection, None, terminal())
            .await
            .expect("identity resolution");
        assert_eq!(resolved.metadata().username(), "identity-user-private");
        assert_eq!(
            resolved.credential_source(),
            SavedTelnetCredentialSource::PasswordIdentity
        );
        assert_eq!(
            resolved
                .password
                .as_ref()
                .expect("identity password")
                .as_utf8()
                .expect("UTF-8 password"),
            "identity-secret-private"
        );
        assert_eq!(
            controller
                .operation_log()
                .count(CredentialOperation::Resolve),
            1
        );
    }

    #[tokio::test]
    async fn missing_identity_password_repairs_hint_then_falls_back_to_host_telnet_password() {
        let identity_id = "missing-fallback-identity-private";
        let host = telnet_host(
            "identity-fallback.example",
            "host-user-private",
            23,
            [
                ("telnetIdentityId", json!(identity_id)),
                ("hasSavedCredential", json!(true)),
            ],
        );
        let host_id = host.id.clone();
        let identity = password_identity(identity_id, "identity-user-private", true);
        let expected_identity_id = identity.id.clone();
        let expected_identity_revision = identity.revision;
        let graph = graph(host, vec![identity], Vec::new());
        let projection = projection(&graph);
        let (store, controller) = in_memory_credential_store();
        store
            .upsert(
                &StoredCredentialReference::for_saved_host_telnet(host_id.as_str())
                    .expect("host Telnet owner"),
                CredentialKind::TelnetPassword,
                secret("host-fallback-secret-private"),
            )
            .await
            .expect("store host fallback password");
        controller.clear_operation_log();

        let resolved = resolve_saved_telnet_session(&store, &graph, &projection, None, terminal())
            .await
            .expect("missing identity falls back to the isolated host account");
        assert_eq!(
            resolved.credential_source(),
            SavedTelnetCredentialSource::Host
        );
        assert_eq!(
            resolved
                .password
                .as_ref()
                .expect("fallback password")
                .as_utf8()
                .expect("UTF-8 fallback password"),
            "host-fallback-secret-private"
        );
        assert!(matches!(
            resolved.repair_actions(),
            [SavedTelnetHintRepair::PasswordIdentity { identity_id, expected_revision }]
                if identity_id == &expected_identity_id
                    && *expected_revision == expected_identity_revision
        ));
        assert_eq!(
            controller
                .operation_log()
                .count(CredentialOperation::Resolve),
            2
        );
    }

    #[tokio::test]
    async fn host_manual_password_uses_isolated_telnet_owner_and_kind() {
        let host = telnet_host(
            "host-owner.example",
            "host-user",
            23,
            [("hasSavedCredential", json!(true))],
        );
        let host_id = host.id.clone();
        let graph = graph(host, Vec::new(), Vec::new());
        let projection = projection(&graph);
        let (store, _) = in_memory_credential_store();
        store
            .upsert(
                &StoredCredentialReference::for_saved_host(host_id.as_str())
                    .expect("SSH host owner"),
                CredentialKind::SshPassword,
                secret("ssh-secret-must-not-win"),
            )
            .await
            .expect("store SSH password");
        store
            .upsert(
                &StoredCredentialReference::for_saved_host_telnet(host_id.as_str())
                    .expect("Telnet host owner"),
                CredentialKind::TelnetPassword,
                secret("telnet-host-secret-private"),
            )
            .await
            .expect("store Telnet password");

        let resolved = resolve_saved_telnet_session(&store, &graph, &projection, None, terminal())
            .await
            .expect("host Telnet resolution");
        assert_eq!(
            resolved.credential_source(),
            SavedTelnetCredentialSource::Host
        );
        assert_eq!(
            resolved
                .password
                .as_ref()
                .expect("host password")
                .as_utf8()
                .expect("UTF-8 password"),
            "telnet-host-secret-private"
        );
    }

    #[tokio::test]
    async fn group_manual_password_uses_exact_provenance_owner() {
        let group_id = "group-telnet-owner-private";
        let config = group(
            group_id,
            "Network/Console",
            SavedGroupDefaults {
                telnet_username: SavedGroupOverride::Set(text("group-user-private")),
                telnet_password: SavedGroupCredentialOverride::StoredHint,
                ..SavedGroupDefaults::default()
            },
        );
        let mut draft = SavedHostDraft::telnet("group-owner.example", "");
        draft = draft
            .with_group_path(SavedGroupPath::new("Network/Console/Leaf").expect("host group path"));
        let host = SavedHost::from_draft(draft, 10).expect("grouped Telnet host");
        let graph = graph(host, Vec::new(), vec![config]);
        let projection = projection(&graph);
        let (store, _) = in_memory_credential_store();
        store
            .upsert(
                &StoredCredentialReference::for_saved_group_telnet(group_id)
                    .expect("group Telnet owner"),
                CredentialKind::TelnetPassword,
                secret("group-telnet-secret-private"),
            )
            .await
            .expect("store group Telnet password");

        let resolved = resolve_saved_telnet_session(&store, &graph, &projection, None, terminal())
            .await
            .expect("group Telnet resolution");
        assert_eq!(resolved.metadata().username(), "group-user-private");
        assert_eq!(
            resolved.credential_source(),
            SavedTelnetCredentialSource::Group
        );
        assert_eq!(
            resolved
                .password
                .as_ref()
                .expect("group password")
                .as_utf8()
                .expect("UTF-8 password"),
            "group-telnet-secret-private"
        );
    }

    #[tokio::test]
    async fn missing_host_identity_and_group_hints_allow_manual_login_with_typed_repairs() {
        let host = telnet_host(
            "missing-host.example",
            "host-user",
            23,
            [("hasSavedCredential", json!(true))],
        );
        let expected_host_id = host.id.clone();
        let expected_host_revision = host.revision;
        let host_graph = graph(host, Vec::new(), Vec::new());
        let host_projection = projection(&host_graph);
        let (store, _) = in_memory_credential_store();
        let missing_host =
            resolve_saved_telnet_session(&store, &host_graph, &host_projection, None, terminal())
                .await
                .expect("missing host password permits manual login");
        assert_eq!(
            missing_host.credential_source(),
            SavedTelnetCredentialSource::None
        );
        assert!(missing_host.password.is_none());
        assert!(matches!(
            missing_host.repair_actions(),
            [SavedTelnetHintRepair::Host { host_id, expected_revision }]
                if host_id == &expected_host_id && *expected_revision == expected_host_revision
        ));

        let identity_id = "missing-identity-private";
        let identity_host = telnet_host(
            "missing-identity.example",
            "host-user",
            23,
            [("telnetIdentityId", json!(identity_id))],
        );
        let identity = password_identity(identity_id, "identity-user", true);
        let expected_identity_id = identity.id.clone();
        let expected_identity_revision = identity.revision;
        let identity_graph = graph(identity_host, vec![identity], Vec::new());
        let identity_projection = projection(&identity_graph);
        let missing_identity = resolve_saved_telnet_session(
            &store,
            &identity_graph,
            &identity_projection,
            None,
            terminal(),
        )
        .await
        .expect("missing identity password permits manual login");
        assert!(matches!(
            missing_identity.repair_actions(),
            [SavedTelnetHintRepair::PasswordIdentity { identity_id, expected_revision }]
                if identity_id == &expected_identity_id
                    && *expected_revision == expected_identity_revision
        ));

        let group_id = "missing-group-private";
        let group_config = group(
            group_id,
            "Missing/Group",
            SavedGroupDefaults {
                telnet_password: SavedGroupCredentialOverride::StoredHint,
                ..SavedGroupDefaults::default()
            },
        );
        let expected_group_id = group_config.id.clone();
        let expected_group_revision = group_config.revision;
        let group_host = SavedHost::from_draft(
            SavedHostDraft::telnet("missing-group.example", "")
                .with_group_path(SavedGroupPath::new("Missing/Group/Leaf").expect("group path")),
            10,
        )
        .expect("group host");
        let group_graph = graph(group_host, Vec::new(), vec![group_config]);
        let group_projection = projection(&group_graph);
        let missing_group =
            resolve_saved_telnet_session(&store, &group_graph, &group_projection, None, terminal())
                .await
                .expect("missing group password permits manual login");
        assert!(matches!(
            missing_group.repair_actions(),
            [SavedTelnetHintRepair::Group { group_id, expected_revision }]
                if group_id == &expected_group_id && *expected_revision == expected_group_revision
        ));
    }

    #[test]
    fn protocol_projection_identity_and_runtime_metadata_fail_closed() {
        let ssh_host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("ssh.private.example", "ssh-user-private"),
            10,
        )
        .expect("SSH host");
        let ssh_graph = graph(ssh_host, Vec::new(), Vec::new());
        let ssh_projection = projection(&ssh_graph);
        assert_eq!(
            plan_saved_telnet_session(&ssh_graph, &ssh_projection, None, terminal())
                .expect_err("SSH must be rejected"),
            SavedTelnetResolverError::UnsupportedProtocol
        );

        let missing_id = "missing-password-identity-private";
        let missing_host = telnet_host(
            "missing-id.example",
            "user",
            23,
            [("telnetIdentityId", json!(missing_id))],
        );
        let missing_graph = graph(missing_host, Vec::new(), Vec::new());
        let missing_projection = projection(&missing_graph);
        assert_eq!(
            plan_saved_telnet_session(&missing_graph, &missing_projection, None, terminal())
                .expect_err("missing identity"),
            SavedTelnetResolverError::MissingPasswordIdentity
        );

        let duplicate_host = telnet_host(
            "duplicate-id.example",
            "user",
            23,
            [("telnetIdentityId", json!(missing_id))],
        );
        let identity = password_identity(missing_id, "identity-user", true);
        let duplicate_graph = graph(duplicate_host, vec![identity.clone(), identity], Vec::new());
        let duplicate_projection = projection(&duplicate_graph);
        assert_eq!(
            plan_saved_telnet_session(&duplicate_graph, &duplicate_projection, None, terminal())
                .expect_err("ambiguous identity"),
            SavedTelnetResolverError::AmbiguousPasswordIdentity
        );

        assert_eq!(
            SavedTelnetTerminalOptions::new(0, 24).expect_err("zero columns"),
            SavedTelnetResolverError::InvalidTerminalSize
        );
        assert_eq!(
            SavedTelnetTerminalOptions::new(MAX_WINDOW_DIMENSION + 1, 24)
                .expect_err("oversized columns"),
            SavedTelnetResolverError::InvalidTerminalSize
        );
        assert_eq!(
            SavedTelnetTerminalOptions::new(80, 24)
                .expect("size")
                .with_terminal_type("private\nterminal")
                .expect_err("unsafe terminal"),
            SavedTelnetResolverError::InvalidTerminalType
        );

        for (field, value, expected) in [
            (
                "telnetPort",
                json!(0),
                SavedTelnetResolverError::InvalidPort,
            ),
            (
                "telnetUsername",
                json!("private\nuser"),
                SavedTelnetResolverError::InvalidUsername,
            ),
            (
                "charset",
                json!("private\ncharset"),
                SavedTelnetResolverError::InvalidCharset,
            ),
            (
                "startupCommand",
                json!("private\0command"),
                SavedTelnetResolverError::InvalidStartupCommand,
            ),
        ] {
            let host = telnet_host("metadata.example", "user", 23, [(field, value)]);
            let graph = graph(host, Vec::new(), Vec::new());
            let projection = projection(&graph);
            assert_eq!(
                plan_saved_telnet_session(&graph, &projection, None, terminal())
                    .expect_err("invalid runtime metadata"),
                expected
            );
        }

        let oversized = "x".repeat(MAX_INPUT_BYTES);
        let host = telnet_host(
            "oversized-startup.example",
            "user",
            23,
            [("startupCommand", json!(oversized))],
        );
        let graph = graph(host, Vec::new(), Vec::new());
        let projection = projection(&graph);
        assert_eq!(
            plan_saved_telnet_session(&graph, &projection, None, terminal())
                .expect_err("oversized startup command"),
            SavedTelnetResolverError::InvalidStartupCommand
        );
    }

    #[test]
    fn active_host_and_group_proxy_or_jump_relationships_are_never_ignored() {
        for (field, value, expected) in [
            (
                "proxyConfig",
                json!({ "type": "http", "host": "proxy.private", "port": 8080 }),
                SavedTelnetResolverError::UnsupportedProxy,
            ),
            (
                "proxyProfileId",
                json!("profile-private"),
                SavedTelnetResolverError::UnsupportedProxy,
            ),
            (
                "hostChain",
                json!({ "hostIds": ["jump-private"] }),
                SavedTelnetResolverError::UnsupportedJumpChain,
            ),
        ] {
            let host = telnet_host("relationship.example", "user", 23, [(field, value)]);
            let graph = graph(host, Vec::new(), Vec::new());
            let projection = projection(&graph);
            assert_eq!(
                plan_saved_telnet_session(&graph, &projection, None, terminal())
                    .expect_err("unsupported relationship"),
                expected
            );
        }

        let proxy_group = group(
            "proxy-group-private",
            "Proxy/Group",
            SavedGroupDefaults {
                proxy: SavedGroupProxyOverride::Profile(
                    SavedProxyProfileId::from_opaque("profile-private").expect("profile ID"),
                ),
                ..SavedGroupDefaults::default()
            },
        );
        let proxy_host = SavedHost::from_draft(
            SavedHostDraft::telnet("group-proxy.example", "")
                .with_group_path(SavedGroupPath::new("Proxy/Group/Leaf").expect("group path")),
            10,
        )
        .expect("group proxy host");
        let proxy_graph = graph(proxy_host, Vec::new(), vec![proxy_group]);
        let proxy_projection = projection(&proxy_graph);
        assert_eq!(
            plan_saved_telnet_session(&proxy_graph, &proxy_projection, None, terminal())
                .expect_err("group proxy"),
            SavedTelnetResolverError::UnsupportedProxy
        );

        let jump_group = group(
            "jump-group-private",
            "Jump/Group",
            SavedGroupDefaults {
                host_chain: SavedGroupOverride::Set(
                    SavedGroupHostChain::new(vec![
                        SavedHostId::from_opaque("jump-private").expect("jump ID"),
                    ])
                    .expect("host chain"),
                ),
                ..SavedGroupDefaults::default()
            },
        );
        let jump_host = SavedHost::from_draft(
            SavedHostDraft::telnet("group-jump.example", "")
                .with_group_path(SavedGroupPath::new("Jump/Group/Leaf").expect("group path")),
            10,
        )
        .expect("group jump host");
        let jump_graph = graph(jump_host, Vec::new(), vec![jump_group]);
        let jump_projection = projection(&jump_graph);
        assert_eq!(
            plan_saved_telnet_session(&jump_graph, &jump_projection, None, terminal())
                .expect_err("group jump chain"),
            SavedTelnetResolverError::UnsupportedJumpChain
        );
    }

    #[tokio::test]
    async fn non_not_found_custody_errors_fail_closed_without_fallback() {
        let identity_id = "kind-mismatch-identity-private";
        let host = telnet_host(
            "kind-mismatch.example",
            "user",
            23,
            [
                ("telnetIdentityId", json!(identity_id)),
                ("hasSavedCredential", json!(true)),
            ],
        );
        let host_id = host.id.clone();
        let graph = graph(
            host,
            vec![password_identity(identity_id, "identity-user", true)],
            Vec::new(),
        );
        let projection = projection(&graph);
        let (store, _) = in_memory_credential_store();
        store
            .upsert(
                &StoredCredentialReference::for_saved_identity(identity_id)
                    .expect("identity reference"),
                CredentialKind::TelnetPassword,
                secret("wrong-kind-secret-private"),
            )
            .await
            .expect("store wrong-kind envelope");
        store
            .upsert(
                &StoredCredentialReference::for_saved_host_telnet(host_id.as_str())
                    .expect("host fallback reference"),
                CredentialKind::TelnetPassword,
                secret("host-fallback-must-not-run"),
            )
            .await
            .expect("store host fallback password");
        assert_eq!(
            resolve_saved_telnet_session(&store, &graph, &projection, None, terminal(),)
                .await
                .expect_err("kind mismatch must fail closed"),
            SavedTelnetResolverError::CredentialLookup(
                netcatty_credentials::CredentialErrorCode::KindMismatch
            )
        );
    }

    #[tokio::test]
    async fn every_debug_and_error_surface_redacts_connection_and_secret_markers() {
        let identity_id = "debug-identity-id-private-marker";
        let markers = [
            "debug-host-private-marker.example",
            "debug-user-private-marker",
            identity_id,
            "debug-startup-private-marker",
            "debug-secret-private-marker",
        ];
        let host = telnet_host(
            markers[0],
            markers[1],
            23,
            [
                ("telnetIdentityId", json!(identity_id)),
                ("startupCommand", json!(markers[3])),
            ],
        );
        let marker_graph = graph(
            host,
            vec![password_identity(identity_id, markers[1], true)],
            Vec::new(),
        );
        let marker_projection = projection(&marker_graph);
        let plan = plan_saved_telnet_session(
            &marker_graph,
            &marker_projection,
            Some(secret(markers[4])),
            terminal(),
        )
        .expect("redacted plan");
        let plan_debug = format!("{plan:?} {:?}", plan.metadata());
        for marker in markers {
            assert!(!plan_debug.contains(marker));
        }

        let (store, _) = in_memory_credential_store();
        let resolved = resolve_saved_telnet_plan(&store, plan)
            .await
            .expect("redacted resolution");
        let resolved_debug = format!("{resolved:?} {:?}", resolved.repair_actions());
        for marker in markers {
            assert!(!resolved_debug.contains(marker));
        }

        let attacker_marker = "attacker-controlled-private-error-marker";
        let error = SavedTelnetResolverError::InvalidMetadata;
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(attacker_marker));

        let oversized_secret = format!("{attacker_marker}{}", "x".repeat(super::LOGIN_VALUE_LIMIT));
        let simple_host = telnet_host("safe.example", "safe-user", 23, []);
        let simple_graph = graph(simple_host, Vec::new(), Vec::new());
        let simple_projection = projection(&simple_graph);
        let invalid_secret_error = plan_saved_telnet_session(
            &simple_graph,
            &simple_projection,
            Some(secret(&oversized_secret)),
            terminal(),
        )
        .expect_err("oversized one-shot password");
        let rendered = format!("{invalid_secret_error:?} {invalid_secret_error}");
        assert!(!rendered.contains(attacker_marker));
    }

    #[test]
    fn saved_telnet_start_request_is_strict_camel_case_and_redacted() {
        let marker = "saved-telnet-request-private-marker";
        let request = serde_json::from_value::<crate::StartSavedTelnetSessionRequest>(json!({
            "hostId": marker,
            "expectedRevision": 7,
            "terminal": marker,
            "size": {
                "columns": 120,
                "rows": 40,
                "pixelWidth": 1440,
                "pixelHeight": 900
            }
        }))
        .expect("strict SavedHost Telnet request");
        assert_eq!(request.expected_revision, 7);
        assert!(!format!("{request:?}").contains(marker));

        let default_terminal =
            serde_json::from_value::<crate::StartSavedTelnetSessionRequest>(json!({
                "hostId": "saved-telnet-default-terminal",
                "expectedRevision": 8,
                "size": { "columns": 80, "rows": 24 }
            }))
            .expect("default terminal request");
        assert_eq!(default_terminal.terminal, "xterm-256color");

        for invalid in [
            json!({
                "host_id": "snake-case-host",
                "expectedRevision": 1,
                "size": { "columns": 80, "rows": 24 }
            }),
            json!({
                "hostId": "plaintext-password-host",
                "expectedRevision": 1,
                "password": "must-never-enter-json",
                "size": { "columns": 80, "rows": 24 }
            }),
            json!({
                "hostId": "unknown-field-host",
                "expectedRevision": 1,
                "size": { "columns": 80, "rows": 24, "privateField": true }
            }),
        ] {
            assert!(
                serde_json::from_value::<crate::StartSavedTelnetSessionRequest>(invalid).is_err()
            );
        }
    }

    #[test]
    fn adapter_applies_host_identity_and_group_hint_repairs_in_one_graph() {
        let identity = password_identity("repair-identity", "identity-user", true);
        let identity_id = identity.id.clone();
        let identity_revision = identity.revision;
        let group_config = group(
            "repair-group",
            "Repair/Console",
            SavedGroupDefaults {
                telnet_password: SavedGroupCredentialOverride::StoredHint,
                ..SavedGroupDefaults::default()
            },
        );
        let group_id = group_config.id.clone();
        let group_revision = group_config.revision;
        let mut draft = SavedHostDraft::telnet("repair.example", "host-user")
            .with_group_path(SavedGroupPath::new("Repair/Console/Leaf").expect("group path"));
        draft = draft
            .with_compatibility_field("telnetIdentityId", json!(identity_id.as_str()))
            .expect("identity field")
            .with_compatibility_field("hasSavedCredential", json!(true))
            .expect("credential hint");
        let host = SavedHost::from_draft(draft, 10).expect("repair host");
        let host_id = host.id.clone();
        let host_revision = host.revision;
        let graph = graph(host, vec![identity], vec![group_config]);

        let repaired = crate::apply_saved_telnet_hint_repairs_to_graph(
            graph,
            vec![
                SavedTelnetHintRepair::Host {
                    host_id: host_id.clone(),
                    expected_revision: host_revision,
                },
                SavedTelnetHintRepair::PasswordIdentity {
                    identity_id: identity_id.clone(),
                    expected_revision: identity_revision,
                },
                SavedTelnetHintRepair::Group {
                    group_id: group_id.clone(),
                    expected_revision: group_revision,
                },
            ],
            100,
        )
        .expect("atomic hint repair graph");

        let repaired_host = repaired
            .hosts()
            .iter()
            .find(|candidate| candidate.id == host_id)
            .expect("repaired host");
        assert_eq!(
            repaired_host
                .compatibility_fields()
                .get("hasSavedCredential"),
            Some(&json!(false))
        );
        assert!(
            !repaired
                .password_identities()
                .iter()
                .find(|candidate| candidate.id == identity_id)
                .expect("repaired identity")
                .has_saved_credential
        );
        assert_eq!(
            repaired
                .groups()
                .iter()
                .find(|candidate| candidate.id == group_id)
                .expect("repaired group")
                .defaults
                .telnet_password,
            SavedGroupCredentialOverride::Inherit
        );
    }
}
