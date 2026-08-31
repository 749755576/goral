use std::fmt;

use netcatty_credentials::CredentialErrorCode;
use netcatty_vault::{
    SavedGroupId, SavedHost, SavedHostConnectionCredentialOwner, SavedPasswordIdentity,
    SavedPasswordIdentityId, SavedProxyConfig, SavedProxyProfileId, SavedVaultGraph,
    ValidationError,
};

pub(crate) const SAVED_PROXY_CONFIGURATION_INVALID: &str = "SAVED_PROXY_CONFIGURATION_INVALID";
pub(crate) const SAVED_PROXY_RELATIONSHIP_INVALID: &str = "SAVED_PROXY_RELATIONSHIP_INVALID";
pub(crate) const SAVED_PROXY_CREDENTIAL_UNSUPPORTED: &str = "SAVED_PROXY_CREDENTIAL_UNSUPPORTED";

/// Secret-free connection metadata for a selected saved proxy.
///
/// This type deliberately has no serialization implementation. Its custom
/// `Debug` implementation exposes neither proxy endpoints nor commands.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum SavedProxyTransportPlan {
    Http { host: String, port: u16 },
    Socks5 { host: String, port: u16 },
    Command { command: String },
}

impl fmt::Debug for SavedProxyTransportPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http { port, .. } => formatter
                .debug_struct("Http")
                .field("port", port)
                .finish_non_exhaustive(),
            Self::Socks5 { port, .. } => formatter
                .debug_struct("Socks5")
                .field("port", port)
                .finish_non_exhaustive(),
            Self::Command { .. } => formatter.write_str("Command"),
        }
    }
}

impl SavedProxyTransportPlan {
    pub(crate) fn host(&self) -> Option<&str> {
        match self {
            Self::Http { host, .. } | Self::Socks5 { host, .. } => Some(host),
            Self::Command { .. } => None,
        }
    }

    pub(crate) fn command(&self) -> Option<&str> {
        match self {
            Self::Command { command } => Some(command),
            Self::Http { .. } | Self::Socks5 { .. } => None,
        }
    }
}

/// The only credential operations a saved-proxy coordinator may perform.
///
/// `ProxyPassword` and `SshPassword` deliberately remain distinct custody
/// domains. Typed IDs are retained only where the coordinator needs them to
/// derive a keyring reference or clear an authoritative stale hint. They are
/// omitted from `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum SavedProxyCredentialAction {
    UseOneShotProxyPassword,
    ResolveHostInlineProxyPassword,
    ResolveGroupProxyPassword {
        group_id: SavedGroupId,
    },
    ResolveProfileProxyPassword {
        profile_id: SavedProxyProfileId,
    },
    ResolveIdentitySshPassword {
        identity_id: SavedPasswordIdentityId,
    },
    RequireOneShotProxyPassword,
    NoCredential,
    ClearHostInlineProxyPasswordHintThenRequireOneShot,
    ClearGroupProxyPasswordHintThenRequireOneShot {
        group_id: SavedGroupId,
    },
    ClearProfileProxyPasswordHintThenRequireOneShot {
        profile_id: SavedProxyProfileId,
    },
    ClearIdentitySshPasswordHintThenRequireOneShot {
        identity_id: SavedPasswordIdentityId,
    },
    FailClosed,
}

impl fmt::Debug for SavedProxyCredentialAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UseOneShotProxyPassword => "UseOneShotProxyPassword",
            Self::ResolveHostInlineProxyPassword => "ResolveHostInlineProxyPassword",
            Self::ResolveGroupProxyPassword { .. } => "ResolveGroupProxyPassword",
            Self::ResolveProfileProxyPassword { .. } => "ResolveProfileProxyPassword",
            Self::ResolveIdentitySshPassword { .. } => "ResolveIdentitySshPassword",
            Self::RequireOneShotProxyPassword => "RequireOneShotProxyPassword",
            Self::NoCredential => "NoCredential",
            Self::ClearHostInlineProxyPasswordHintThenRequireOneShot => {
                "ClearHostInlineProxyPasswordHintThenRequireOneShot"
            }
            Self::ClearGroupProxyPasswordHintThenRequireOneShot { .. } => {
                "ClearGroupProxyPasswordHintThenRequireOneShot"
            }
            Self::ClearProfileProxyPasswordHintThenRequireOneShot { .. } => {
                "ClearProfileProxyPasswordHintThenRequireOneShot"
            }
            Self::ClearIdentitySshPasswordHintThenRequireOneShot { .. } => {
                "ClearIdentitySshPasswordHintThenRequireOneShot"
            }
            Self::FailClosed => "FailClosed",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SavedProxyCredentialLookup {
    HostInlineProxyPassword,
    GroupProxyPassword,
    ProfileProxyPassword,
    IdentitySshPassword,
}

impl SavedProxyCredentialAction {
    /// Converts a lookup result into the only permitted next action.
    ///
    /// An authoritative `NotFound` clears precisely the hint that authorized
    /// the attempted lookup. Corruption, storage failures, conflicts, and all
    /// other errors fail closed without trying another credential namespace.
    pub(crate) fn after_lookup_error(
        &self,
        lookup: SavedProxyCredentialLookup,
        error: CredentialErrorCode,
    ) -> Self {
        if error != CredentialErrorCode::NotFound {
            return Self::FailClosed;
        }
        match (self, lookup) {
            (
                Self::ResolveHostInlineProxyPassword,
                SavedProxyCredentialLookup::HostInlineProxyPassword,
            ) => Self::ClearHostInlineProxyPasswordHintThenRequireOneShot,
            (
                Self::ResolveGroupProxyPassword { group_id },
                SavedProxyCredentialLookup::GroupProxyPassword,
            ) => Self::ClearGroupProxyPasswordHintThenRequireOneShot {
                group_id: group_id.clone(),
            },
            (
                Self::ResolveProfileProxyPassword { profile_id },
                SavedProxyCredentialLookup::ProfileProxyPassword,
            ) => Self::ClearProfileProxyPasswordHintThenRequireOneShot {
                profile_id: profile_id.clone(),
            },
            (
                Self::ResolveIdentitySshPassword { identity_id },
                SavedProxyCredentialLookup::IdentitySshPassword,
            ) => Self::ClearIdentitySshPasswordHintThenRequireOneShot {
                identity_id: identity_id.clone(),
            },
            _ => Self::FailClosed,
        }
    }
}

/// A complete, secret-free proxy decision ready for a detached coordinator.
///
/// `username` is connection metadata, not credential material. It is kept out
/// of `Debug` alongside the transport endpoint and typed relationship IDs.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SavedProxyConnectionPlan {
    transport: SavedProxyTransportPlan,
    username: Option<String>,
    credential_action: SavedProxyCredentialAction,
}

impl fmt::Debug for SavedProxyConnectionPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SavedProxyConnectionPlan")
            .field("transport", &self.transport)
            .field("has_username", &self.username.is_some())
            .field("credential_action", &self.credential_action)
            .finish()
    }
}

impl SavedProxyConnectionPlan {
    pub(crate) fn transport(&self) -> &SavedProxyTransportPlan {
        &self.transport
    }

    pub(crate) fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    pub(crate) fn credential_action(&self) -> &SavedProxyCredentialAction {
        &self.credential_action
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        SavedProxyTransportPlan,
        Option<String>,
        SavedProxyCredentialAction,
    ) {
        (self.transport, self.username, self.credential_action)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SavedProxyAuthGuardError {
    InvalidInlineProxy,
    InvalidProfileReference,
    MissingProfileReference,
    AmbiguousProfileReference,
    InvalidCredentialMode,
    MissingPasswordIdentity,
    AmbiguousPasswordIdentity,
    CommandCredentialUnsupported,
    CredentialWithoutProxy,
}

impl SavedProxyAuthGuardError {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::InvalidInlineProxy | Self::InvalidCredentialMode => {
                SAVED_PROXY_CONFIGURATION_INVALID
            }
            Self::InvalidProfileReference
            | Self::MissingProfileReference
            | Self::AmbiguousProfileReference
            | Self::MissingPasswordIdentity
            | Self::AmbiguousPasswordIdentity => SAVED_PROXY_RELATIONSHIP_INVALID,
            Self::CommandCredentialUnsupported | Self::CredentialWithoutProxy => {
                SAVED_PROXY_CREDENTIAL_UNSUPPORTED
            }
        }
    }
}

impl fmt::Display for SavedProxyAuthGuardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidInlineProxy | Self::InvalidCredentialMode => {
                "The saved proxy configuration is invalid; repair the Vault before connecting"
            }
            Self::InvalidProfileReference
            | Self::MissingProfileReference
            | Self::AmbiguousProfileReference
            | Self::MissingPasswordIdentity
            | Self::AmbiguousPasswordIdentity => {
                "The saved proxy relationship is invalid; repair the Vault before connecting"
            }
            Self::CommandCredentialUnsupported => "Command proxies cannot use password credentials",
            Self::CredentialWithoutProxy => {
                "A proxy credential cannot be used without a configured proxy"
            }
        };
        write!(formatter, "{}: {message}", self.code())
    }
}

impl std::error::Error for SavedProxyAuthGuardError {}

#[derive(Clone, Copy)]
enum ManualCredentialOwner<'graph> {
    HostInline,
    GroupInline(&'graph SavedGroupId),
    Profile(&'graph SavedProxyProfileId),
    Missing,
}

/// Resolves one saved host's proxy selection and authentication policy without
/// reading a credential store or accepting any secret-bearing value.
///
/// Inline `proxyConfig` has absolute priority. Its typed parse result is
/// examined before `proxyProfileId` is parsed, so both valid and malformed
/// inline values prevent profile fallback.
pub(crate) fn resolve_saved_proxy_authentication(
    host: &SavedHost,
    graph: &SavedVaultGraph,
    has_one_shot_credential: bool,
) -> Result<Option<SavedProxyConnectionPlan>, SavedProxyAuthGuardError> {
    resolve_proxy_selection(
        host.proxy_config(),
        || host.proxy_profile_id(),
        graph,
        has_one_shot_credential,
    )
}

/// Resolves a proxy from an effective GroupConfig projection while preserving
/// the exact manual inline credential namespace. A projected presence hint
/// without its host/group provenance fails closed.
pub(crate) fn resolve_projected_saved_proxy_authentication(
    host: &SavedHost,
    graph: &SavedVaultGraph,
    has_one_shot_credential: bool,
    credential_owner: Option<&SavedHostConnectionCredentialOwner>,
) -> Result<Option<SavedProxyConnectionPlan>, SavedProxyAuthGuardError> {
    let inline_owner = match credential_owner {
        Some(SavedHostConnectionCredentialOwner::Host(owner_id)) if owner_id == &host.id => {
            ManualCredentialOwner::HostInline
        }
        Some(SavedHostConnectionCredentialOwner::Group(group_id)) => {
            ManualCredentialOwner::GroupInline(group_id)
        }
        Some(SavedHostConnectionCredentialOwner::Host(_)) | None => ManualCredentialOwner::Missing,
    };
    resolve_proxy_selection_with_inline_owner(
        host.proxy_config(),
        || host.proxy_profile_id(),
        graph,
        has_one_shot_credential,
        inline_owner,
    )
}

fn resolve_proxy_selection<F>(
    inline: Result<Option<SavedProxyConfig>, ValidationError>,
    profile_id: F,
    graph: &SavedVaultGraph,
    has_one_shot_credential: bool,
) -> Result<Option<SavedProxyConnectionPlan>, SavedProxyAuthGuardError>
where
    F: FnOnce() -> Result<Option<SavedProxyProfileId>, ValidationError>,
{
    resolve_proxy_selection_with_inline_owner(
        inline,
        profile_id,
        graph,
        has_one_shot_credential,
        ManualCredentialOwner::HostInline,
    )
}

fn resolve_proxy_selection_with_inline_owner<F>(
    inline: Result<Option<SavedProxyConfig>, ValidationError>,
    profile_id: F,
    graph: &SavedVaultGraph,
    has_one_shot_credential: bool,
    inline_owner: ManualCredentialOwner<'_>,
) -> Result<Option<SavedProxyConnectionPlan>, SavedProxyAuthGuardError>
where
    F: FnOnce() -> Result<Option<SavedProxyProfileId>, ValidationError>,
{
    match inline {
        Err(_) => Err(SavedProxyAuthGuardError::InvalidInlineProxy),
        Ok(Some(config)) => {
            plan_from_config(&config, inline_owner, graph, has_one_shot_credential).map(Some)
        }
        Ok(None) => {
            let profile_id =
                profile_id().map_err(|_| SavedProxyAuthGuardError::InvalidProfileReference)?;
            let Some(profile_id) = profile_id else {
                return if has_one_shot_credential {
                    Err(SavedProxyAuthGuardError::CredentialWithoutProxy)
                } else {
                    Ok(None)
                };
            };
            let profile = resolve_profile(graph, &profile_id)?;
            plan_from_config(
                &profile.config,
                ManualCredentialOwner::Profile(&profile.id),
                graph,
                has_one_shot_credential,
            )
            .map(Some)
        }
    }
}

fn resolve_profile<'graph>(
    graph: &'graph SavedVaultGraph,
    profile_id: &SavedProxyProfileId,
) -> Result<&'graph netcatty_vault::SavedProxyProfile, SavedProxyAuthGuardError> {
    let mut matches = graph
        .proxy_profiles()
        .iter()
        .filter(|profile| &profile.id == profile_id);
    let Some(profile) = matches.next() else {
        return Err(SavedProxyAuthGuardError::MissingProfileReference);
    };
    if matches.next().is_some() {
        return Err(SavedProxyAuthGuardError::AmbiguousProfileReference);
    }
    Ok(profile)
}

fn resolve_password_identity<'graph>(
    graph: &'graph SavedVaultGraph,
    identity_id: &SavedPasswordIdentityId,
) -> Result<&'graph SavedPasswordIdentity, SavedProxyAuthGuardError> {
    let mut matches = graph
        .password_identities()
        .iter()
        .filter(|identity| &identity.id == identity_id);
    let Some(identity) = matches.next() else {
        return Err(SavedProxyAuthGuardError::MissingPasswordIdentity);
    };
    if matches.next().is_some() {
        return Err(SavedProxyAuthGuardError::AmbiguousPasswordIdentity);
    }
    Ok(identity)
}

fn plan_from_config(
    config: &SavedProxyConfig,
    manual_owner: ManualCredentialOwner<'_>,
    graph: &SavedVaultGraph,
    has_one_shot_credential: bool,
) -> Result<SavedProxyConnectionPlan, SavedProxyAuthGuardError> {
    match config {
        SavedProxyConfig::Http {
            host,
            port,
            identity_id,
            username,
            has_saved_credential,
            ..
        } => network_plan(
            SavedProxyTransportPlan::Http {
                host: host.clone(),
                port: *port,
            },
            identity_id.as_ref(),
            username,
            *has_saved_credential,
            manual_owner,
            graph,
            has_one_shot_credential,
        ),
        SavedProxyConfig::Socks5 {
            host,
            port,
            identity_id,
            username,
            has_saved_credential,
            ..
        } => network_plan(
            SavedProxyTransportPlan::Socks5 {
                host: host.clone(),
                port: *port,
            },
            identity_id.as_ref(),
            username,
            *has_saved_credential,
            manual_owner,
            graph,
            has_one_shot_credential,
        ),
        SavedProxyConfig::Command { command, .. } => {
            if has_one_shot_credential {
                return Err(SavedProxyAuthGuardError::CommandCredentialUnsupported);
            }
            Ok(SavedProxyConnectionPlan {
                transport: SavedProxyTransportPlan::Command {
                    command: command.clone(),
                },
                username: None,
                credential_action: SavedProxyCredentialAction::NoCredential,
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn network_plan(
    transport: SavedProxyTransportPlan,
    identity_id: Option<&SavedPasswordIdentityId>,
    manual_username: &str,
    manual_has_saved_credential: bool,
    manual_owner: ManualCredentialOwner<'_>,
    graph: &SavedVaultGraph,
    has_one_shot_credential: bool,
) -> Result<SavedProxyConnectionPlan, SavedProxyAuthGuardError> {
    if let Some(identity_id) = identity_id {
        // Keep this explicit even though canonical Vault constructors already
        // normalize these mutually exclusive modes.
        if !manual_username.is_empty() || manual_has_saved_credential {
            return Err(SavedProxyAuthGuardError::InvalidCredentialMode);
        }
        let identity = resolve_password_identity(graph, identity_id)?;
        let credential_action = if has_one_shot_credential {
            SavedProxyCredentialAction::UseOneShotProxyPassword
        } else if identity.has_saved_credential {
            SavedProxyCredentialAction::ResolveIdentitySshPassword {
                identity_id: identity.id.clone(),
            }
        } else {
            SavedProxyCredentialAction::RequireOneShotProxyPassword
        };
        return Ok(SavedProxyConnectionPlan {
            transport,
            username: Some(identity.username.clone()),
            credential_action,
        });
    }

    let username = (!manual_username.is_empty()).then(|| manual_username.to_owned());
    let credential_action = if has_one_shot_credential {
        SavedProxyCredentialAction::UseOneShotProxyPassword
    } else if manual_has_saved_credential {
        match manual_owner {
            ManualCredentialOwner::HostInline => {
                SavedProxyCredentialAction::ResolveHostInlineProxyPassword
            }
            ManualCredentialOwner::GroupInline(group_id) => {
                SavedProxyCredentialAction::ResolveGroupProxyPassword {
                    group_id: group_id.clone(),
                }
            }
            ManualCredentialOwner::Profile(profile_id) => {
                SavedProxyCredentialAction::ResolveProfileProxyPassword {
                    profile_id: profile_id.clone(),
                }
            }
            ManualCredentialOwner::Missing => {
                return Err(SavedProxyAuthGuardError::InvalidCredentialMode);
            }
        }
    } else if username.is_some() {
        SavedProxyCredentialAction::RequireOneShotProxyPassword
    } else {
        SavedProxyCredentialAction::NoCredential
    };
    Ok(SavedProxyConnectionPlan {
        transport,
        username,
        credential_action,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use netcatty_credentials::CredentialErrorCode;
    use netcatty_vault::{
        SavedGroupId, SavedHost, SavedHostConnectionCredentialOwner, SavedHostDraft,
        SavedPasswordIdentity, SavedPasswordIdentityId, SavedProxyConfig, SavedProxyProfile,
        SavedProxyProfileId, SavedVaultGraph, ValidationError,
    };
    use serde_json::json;

    use super::{
        SAVED_PROXY_CONFIGURATION_INVALID, SAVED_PROXY_RELATIONSHIP_INVALID,
        SavedProxyAuthGuardError, SavedProxyCredentialAction, SavedProxyCredentialLookup,
        SavedProxyTransportPlan, resolve_projected_saved_proxy_authentication,
        resolve_proxy_selection, resolve_saved_proxy_authentication,
    };

    fn profile_id(value: &str) -> SavedProxyProfileId {
        SavedProxyProfileId::from_opaque(value).expect("profile ID")
    }

    fn identity_id(value: &str) -> SavedPasswordIdentityId {
        SavedPasswordIdentityId::from_opaque(value).expect("identity ID")
    }

    fn profile(id: &str, config: SavedProxyConfig) -> SavedProxyProfile {
        SavedProxyProfile::from_parts(profile_id(id), 1, "profile", config, 1, 1, BTreeMap::new())
            .expect("profile")
    }

    fn identity(id: &str, username: &str, has_saved_credential: bool) -> SavedPasswordIdentity {
        SavedPasswordIdentity::from_parts(
            identity_id(id),
            1,
            "identity",
            username,
            has_saved_credential,
            1,
            1,
            BTreeMap::new(),
        )
        .expect("identity")
    }

    fn graph(
        identities: Vec<SavedPasswordIdentity>,
        profiles: Vec<SavedProxyProfile>,
    ) -> SavedVaultGraph {
        SavedVaultGraph::new_with_proxy_profiles(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            identities,
            profiles,
            Vec::new(),
        )
    }

    fn host_with_fields(
        fields: impl IntoIterator<Item = (&'static str, serde_json::Value)>,
    ) -> SavedHost {
        let mut draft = SavedHostDraft::ssh_password("target.example", "target-user");
        for (key, value) in fields {
            draft = draft
                .with_compatibility_field(key, value)
                .expect("compatibility field");
        }
        SavedHost::from_draft(draft, 1).expect("saved host")
    }

    #[test]
    fn inline_proxy_has_absolute_priority_and_profile_parsing_is_lazy() {
        let inline = SavedProxyConfig::http("inline-secret.example", 8080, None, "alice", true)
            .expect("inline proxy");
        let plan = resolve_proxy_selection(
            Ok(Some(inline)),
            || -> Result<Option<SavedProxyProfileId>, ValidationError> {
                panic!("shadowed profile relationship must not be parsed")
            },
            &SavedVaultGraph::default(),
            false,
        )
        .expect("inline resolution")
        .expect("proxy plan");
        assert_eq!(plan.transport().host(), Some("inline-secret.example"));
        assert_eq!(plan.username(), Some("alice"));
        assert_eq!(
            plan.credential_action(),
            &SavedProxyCredentialAction::ResolveHostInlineProxyPassword
        );

        for shadowed_profile in [json!("missing-shadowed-profile"), json!(7)] {
            let host = host_with_fields([
                (
                    "proxyConfig",
                    json!({
                        "type": "socks5",
                        "host": "inline.example",
                        "port": 1080
                    }),
                ),
                ("proxyProfileId", shadowed_profile),
            ]);
            assert!(
                resolve_saved_proxy_authentication(&host, &SavedVaultGraph::default(), false)
                    .expect("missing or malformed shadowed profile is irrelevant")
                    .is_some()
            );
        }
    }

    #[test]
    fn projected_group_inline_proxy_uses_only_the_group_proxy_namespace() {
        let group_id = SavedGroupId::from_opaque("group-proxy-owner-sentinel").expect("group ID");
        let owner = SavedHostConnectionCredentialOwner::Group(group_id.clone());
        let host = host_with_fields([(
            "proxyConfig",
            json!({
                "type": "http",
                "host": "group-proxy.example",
                "port": 8080,
                "username": "group-user",
                "hasSavedCredential": true
            }),
        )]);
        let plan = resolve_projected_saved_proxy_authentication(
            &host,
            &SavedVaultGraph::default(),
            false,
            Some(&owner),
        )
        .expect("projected group proxy")
        .expect("proxy plan");
        assert_eq!(
            plan.credential_action(),
            &SavedProxyCredentialAction::ResolveGroupProxyPassword {
                group_id: group_id.clone(),
            }
        );
        assert_eq!(
            plan.credential_action().after_lookup_error(
                SavedProxyCredentialLookup::HostInlineProxyPassword,
                CredentialErrorCode::NotFound,
            ),
            SavedProxyCredentialAction::FailClosed,
            "a group proxy hint must never clear a host inline hint"
        );
        assert_eq!(
            plan.credential_action().after_lookup_error(
                SavedProxyCredentialLookup::GroupProxyPassword,
                CredentialErrorCode::NotFound,
            ),
            SavedProxyCredentialAction::ClearGroupProxyPasswordHintThenRequireOneShot {
                group_id: group_id.clone(),
            }
        );
        assert!(!format!("{plan:?}").contains(group_id.as_str()));
    }

    #[test]
    fn projected_saved_proxy_hint_without_provenance_fails_closed() {
        let host = host_with_fields([(
            "proxyConfig",
            json!({
                "type": "socks5",
                "host": "missing-owner.example",
                "port": 1080,
                "username": "group-user",
                "hasSavedCredential": true
            }),
        )]);
        assert_eq!(
            resolve_projected_saved_proxy_authentication(
                &host,
                &SavedVaultGraph::default(),
                false,
                None,
            ),
            Err(SavedProxyAuthGuardError::InvalidCredentialMode)
        );
    }

    #[test]
    fn malformed_inline_fails_closed_without_profile_fallback() {
        let error = resolve_proxy_selection(
            Err(ValidationError::InvalidProxyConfig),
            || -> Result<Option<SavedProxyProfileId>, ValidationError> {
                panic!("malformed inline proxy must not fall back")
            },
            &SavedVaultGraph::default(),
            false,
        )
        .expect_err("malformed inline proxy");
        assert_eq!(error, SavedProxyAuthGuardError::InvalidInlineProxy);
        assert_eq!(error.code(), SAVED_PROXY_CONFIGURATION_INVALID);

        let host = host_with_fields([
            ("proxyConfig", json!({"type": "http", "port": 8080})),
            ("proxyProfileId", json!("otherwise-valid-profile")),
        ]);
        let profiles = vec![profile(
            "otherwise-valid-profile",
            SavedProxyConfig::http("fallback.example", 3128, None, "", false)
                .expect("profile config"),
        )];
        assert_eq!(
            resolve_saved_proxy_authentication(&host, &graph(Vec::new(), profiles), false),
            Err(SavedProxyAuthGuardError::InvalidInlineProxy)
        );
    }

    #[test]
    fn identity_mode_uses_identity_username_and_ssh_password_namespace() {
        let id = identity_id("proxy-login");
        let config = SavedProxyConfig::socks5("proxy.example", 1080, Some(id), "", false)
            .expect("identity proxy");
        let host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("target.example", "target-user")
                .with_proxy_config(config)
                .expect("inline proxy"),
            1,
        )
        .expect("host");
        let graph = graph(
            vec![identity("proxy-login", "identity-user", true)],
            Vec::new(),
        );
        let plan = resolve_saved_proxy_authentication(&host, &graph, false)
            .expect("resolution")
            .expect("plan");
        assert_eq!(plan.username(), Some("identity-user"));
        assert_eq!(
            plan.credential_action(),
            &SavedProxyCredentialAction::ResolveIdentitySshPassword {
                identity_id: identity_id("proxy-login")
            }
        );
    }

    #[test]
    fn profile_and_identity_ids_with_same_opaque_value_stay_in_separate_namespaces() {
        let opaque = "shared-opaque-id";
        let profile = profile(
            opaque,
            SavedProxyConfig::http("proxy.example", 8080, Some(identity_id(opaque)), "", false)
                .expect("profile config"),
        );
        let host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("target.example", "target-user")
                .with_proxy_profile_id(profile_id(opaque))
                .expect("profile relationship"),
            1,
        )
        .expect("host");
        let graph = graph(vec![identity(opaque, "identity-user", true)], vec![profile]);
        let plan = resolve_saved_proxy_authentication(&host, &graph, false)
            .expect("typed namespaces resolve independently")
            .expect("plan");
        assert_eq!(plan.username(), Some("identity-user"));
        assert!(matches!(
            plan.credential_action(),
            SavedProxyCredentialAction::ResolveIdentitySshPassword { identity_id }
                if identity_id.as_str() == opaque
        ));
    }

    #[test]
    fn command_proxy_rejects_one_shot_credentials_and_otherwise_needs_none() {
        let command = "secret-command --proxy sentinel";
        let host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("target.example", "target-user")
                .with_proxy_config(SavedProxyConfig::command(command).expect("command proxy"))
                .expect("inline proxy"),
            1,
        )
        .expect("host");
        let plan = resolve_saved_proxy_authentication(&host, &SavedVaultGraph::default(), false)
            .expect("command plan")
            .expect("plan");
        assert_eq!(
            plan.credential_action(),
            &SavedProxyCredentialAction::NoCredential
        );
        assert_eq!(plan.transport().command(), Some(command));
        assert_eq!(
            resolve_saved_proxy_authentication(&host, &SavedVaultGraph::default(), true),
            Err(SavedProxyAuthGuardError::CommandCredentialUnsupported)
        );
    }

    #[test]
    fn anonymous_manual_proxy_needs_no_credential_and_one_shot_has_priority() {
        let anonymous = SavedProxyConfig::http("anonymous.example", 8080, None, "", false)
            .expect("anonymous proxy");
        let no_secret = resolve_proxy_selection(
            Ok(Some(anonymous.clone())),
            || Ok(None),
            &SavedVaultGraph::default(),
            false,
        )
        .expect("anonymous resolution")
        .expect("plan");
        assert_eq!(no_secret.username(), None);
        assert_eq!(
            no_secret.credential_action(),
            &SavedProxyCredentialAction::NoCredential
        );

        let one_shot = resolve_proxy_selection(
            Ok(Some(anonymous)),
            || Ok(None),
            &SavedVaultGraph::default(),
            true,
        )
        .expect("one-shot resolution")
        .expect("plan");
        assert_eq!(
            one_shot.credential_action(),
            &SavedProxyCredentialAction::UseOneShotProxyPassword
        );
    }

    #[test]
    fn manual_username_and_password_policy_preserves_inline_and_profile_custody() {
        let inline = SavedProxyConfig::http("inline.example", 8080, None, "inline-user", false)
            .expect("inline proxy");
        let inline_plan = resolve_proxy_selection(
            Ok(Some(inline)),
            || Ok(None),
            &SavedVaultGraph::default(),
            false,
        )
        .expect("inline resolution")
        .expect("plan");
        assert_eq!(inline_plan.username(), Some("inline-user"));
        assert_eq!(
            inline_plan.credential_action(),
            &SavedProxyCredentialAction::RequireOneShotProxyPassword
        );

        let id = profile_id("manual-profile");
        let profile = profile(
            id.as_str(),
            SavedProxyConfig::socks5("profile.example", 1080, None, "profile-user", true)
                .expect("profile proxy"),
        );
        let profile_plan = resolve_proxy_selection(
            Ok(None),
            || Ok(Some(id.clone())),
            &graph(Vec::new(), vec![profile]),
            false,
        )
        .expect("profile resolution")
        .expect("plan");
        assert_eq!(profile_plan.username(), Some("profile-user"));
        assert_eq!(
            profile_plan.credential_action(),
            &SavedProxyCredentialAction::ResolveProfileProxyPassword { profile_id: id }
        );
    }

    #[test]
    fn not_found_clears_only_the_exact_lookup_hint() {
        let cases = [
            (
                SavedProxyCredentialAction::ResolveHostInlineProxyPassword,
                SavedProxyCredentialLookup::HostInlineProxyPassword,
                SavedProxyCredentialAction::ClearHostInlineProxyPasswordHintThenRequireOneShot,
            ),
            (
                SavedProxyCredentialAction::ResolveProfileProxyPassword {
                    profile_id: profile_id("profile-hint"),
                },
                SavedProxyCredentialLookup::ProfileProxyPassword,
                SavedProxyCredentialAction::ClearProfileProxyPasswordHintThenRequireOneShot {
                    profile_id: profile_id("profile-hint"),
                },
            ),
            (
                SavedProxyCredentialAction::ResolveIdentitySshPassword {
                    identity_id: identity_id("identity-hint"),
                },
                SavedProxyCredentialLookup::IdentitySshPassword,
                SavedProxyCredentialAction::ClearIdentitySshPasswordHintThenRequireOneShot {
                    identity_id: identity_id("identity-hint"),
                },
            ),
        ];
        for (action, lookup, expected) in cases {
            assert_eq!(
                action.after_lookup_error(lookup, CredentialErrorCode::NotFound),
                expected
            );
        }

        assert_eq!(
            SavedProxyCredentialAction::ResolveProfileProxyPassword {
                profile_id: profile_id("profile-hint")
            }
            .after_lookup_error(
                SavedProxyCredentialLookup::IdentitySshPassword,
                CredentialErrorCode::NotFound,
            ),
            SavedProxyCredentialAction::FailClosed,
            "a mismatched lookup must not clear any hint"
        );
    }

    #[test]
    fn every_non_not_found_lookup_error_fails_closed() {
        let action = SavedProxyCredentialAction::ResolveIdentitySshPassword {
            identity_id: identity_id("identity-hint"),
        };
        let errors = [
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
        for error in errors {
            assert_eq!(
                action.after_lookup_error(SavedProxyCredentialLookup::IdentitySshPassword, error),
                SavedProxyCredentialAction::FailClosed
            );
        }
    }

    #[test]
    fn missing_and_ambiguous_relationships_fail_closed_without_exposing_ids() {
        let missing_id = "missing-profile-secret-sentinel";
        let host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("target.example", "target-user")
                .with_proxy_profile_id(profile_id(missing_id))
                .expect("profile relationship"),
            1,
        )
        .expect("host");
        let error = resolve_saved_proxy_authentication(&host, &SavedVaultGraph::default(), false)
            .expect_err("missing profile");
        assert_eq!(error, SavedProxyAuthGuardError::MissingProfileReference);
        assert_eq!(error.code(), SAVED_PROXY_RELATIONSHIP_INVALID);
        assert!(!format!("{error:?} {error}").contains(missing_id));

        let duplicate_id = "duplicate-profile-secret-sentinel";
        let config =
            SavedProxyConfig::http("proxy.example", 8080, None, "", false).expect("proxy config");
        let duplicate_graph = graph(
            Vec::new(),
            vec![
                profile(duplicate_id, config.clone()),
                profile(duplicate_id, config),
            ],
        );
        let duplicate_host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("target.example", "target-user")
                .with_proxy_profile_id(profile_id(duplicate_id))
                .expect("profile relationship"),
            1,
        )
        .expect("host");
        assert_eq!(
            resolve_saved_proxy_authentication(&duplicate_host, &duplicate_graph, false),
            Err(SavedProxyAuthGuardError::AmbiguousProfileReference)
        );
    }

    #[test]
    fn debug_output_omits_hosts_usernames_commands_and_ids() {
        let host_sentinel = "debug-host-secret-sentinel";
        let user_sentinel = "debug-user-secret-sentinel";
        let id_sentinel = "debug-id-secret-sentinel";
        let plan = resolve_proxy_selection(
            Ok(Some(
                SavedProxyConfig::http(
                    host_sentinel,
                    8080,
                    Some(identity_id(id_sentinel)),
                    "",
                    false,
                )
                .expect("proxy config"),
            )),
            || Ok(None),
            &graph(vec![identity(id_sentinel, user_sentinel, true)], Vec::new()),
            false,
        )
        .expect("resolution")
        .expect("plan");
        let rendered = format!("{plan:?} {:?}", plan.credential_action());
        for secret_metadata in [host_sentinel, user_sentinel, id_sentinel] {
            assert!(!rendered.contains(secret_metadata));
        }

        let command_sentinel = "debug-command-secret-sentinel";
        let command_plan = resolve_proxy_selection(
            Ok(Some(
                SavedProxyConfig::command(command_sentinel).expect("command config"),
            )),
            || Ok(None),
            &SavedVaultGraph::default(),
            false,
        )
        .expect("resolution")
        .expect("plan");
        assert!(!format!("{command_plan:?}").contains(command_sentinel));
        assert!(matches!(
            command_plan.transport(),
            SavedProxyTransportPlan::Command { .. }
        ));
    }
}
