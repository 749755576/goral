use netcatty_credentials::{EphemeralCredentialReference, StoredCredentialReference};
use netcatty_vault::{
    SavedPasswordIdentity, SavedPasswordIdentityId, SavedPasswordIdentityUpdate, SavedVaultGraph,
    SavedVaultInventoryRevision,
};
use serde::{Deserialize, Serialize};

pub(crate) const PASSWORD_IDENTITY_INVALID: &str = "PASSWORD_IDENTITY_INVALID";
pub(crate) const PASSWORD_IDENTITY_NOT_FOUND: &str = "PASSWORD_IDENTITY_NOT_FOUND";
pub(crate) const PASSWORD_IDENTITY_CHANGED: &str = "PASSWORD_IDENTITY_CHANGED";
pub(crate) const PASSWORD_IDENTITY_IN_USE: &str = "PASSWORD_IDENTITY_IN_USE";
pub(crate) const PASSWORD_IDENTITY_INVENTORY_CHANGED: &str = "PASSWORD_IDENTITY_INVENTORY_CHANGED";
pub(crate) const PASSWORD_IDENTITY_PUBLICATION_FAILED: &str =
    "PASSWORD_IDENTITY_PUBLICATION_FAILED";
pub(crate) const PASSWORD_IDENTITY_REPAIR_REQUIRED: &str = "PASSWORD_IDENTITY_REPAIR_REQUIRED";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PasswordIdentityMetadataRequest {
    pub(crate) label: String,
    #[serde(default)]
    pub(crate) username: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreatePasswordIdentityRequest {
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
    pub(crate) metadata: PasswordIdentityMetadataRequest,
    #[serde(default)]
    pub(crate) staged_credential_reference: Option<EphemeralCredentialReference>,
}

#[derive(Debug, Deserialize)]
#[serde(
    tag = "action",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum PasswordIdentityCredentialMutationRequest {
    Keep,
    Remove,
    Replace {
        staged_credential_reference: EphemeralCredentialReference,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UpdatePasswordIdentityRequest {
    pub(crate) id: String,
    pub(crate) expected_revision: u64,
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
    pub(crate) metadata: PasswordIdentityMetadataRequest,
    pub(crate) credential_mutation: PasswordIdentityCredentialMutationRequest,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DeletePasswordIdentityRequest {
    pub(crate) id: String,
    pub(crate) expected_revision: u64,
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
}

/// Renderer-safe password-identity metadata. The password and its deterministic
/// OS-keyring reference are deliberately absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PasswordIdentityView {
    id: String,
    revision: u64,
    label: String,
    username: String,
    has_saved_credential: bool,
    created_at: u64,
    updated_at: u64,
}

impl From<&SavedPasswordIdentity> for PasswordIdentityView {
    fn from(identity: &SavedPasswordIdentity) -> Self {
        Self {
            id: identity.id.as_str().to_owned(),
            revision: identity.revision,
            label: identity.label.clone(),
            username: identity.username.clone(),
            has_saved_credential: identity.has_saved_credential,
            created_at: identity.created_at,
            updated_at: identity.updated_at,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PasswordIdentityCatalog {
    inventory_revision: SavedVaultInventoryRevision,
    identities: Vec<PasswordIdentityView>,
}

impl PasswordIdentityCatalog {
    pub(crate) fn from_graph(
        inventory_revision: SavedVaultInventoryRevision,
        graph: &SavedVaultGraph,
    ) -> Self {
        Self {
            inventory_revision,
            identities: graph
                .password_identities()
                .iter()
                .map(PasswordIdentityView::from)
                .collect(),
        }
    }
}

/// A secret-free instruction for the outer journal coordinator. This type
/// never resolves or consumes the staged secret and never mutates the OS
/// keyring. `target` is backend-only and is intentionally not serializable.
/// `Keep` is the only variant that must not inspect or mutate the keyring.
/// `Remove` and `Replace` must inspect the deterministic target even when the
/// current Vault hint is false, record `absent` or `backedUp` in the journal,
/// and only then perform the requested mutation after the journal is active.
pub(crate) enum PreparedPasswordCredentialMutation {
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

impl PreparedPasswordCredentialMutation {
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

/// A complete-graph mutation proposal. The outer coordinator must use
/// `expected_inventory_revision` with `SavedHostStore::plan_graph_replacement`
/// before any keyring side effect, then bind this exact target graph and the
/// credential owner into the unified recovery journal. It must not publish the
/// target graph independently of that journal.
pub(crate) struct PreparedPasswordIdentityMutation {
    expected_inventory_revision: SavedVaultInventoryRevision,
    target_graph: SavedVaultGraph,
    identity: SavedPasswordIdentity,
    credential: PreparedPasswordCredentialMutation,
}

impl PreparedPasswordIdentityMutation {
    pub(crate) fn expected_inventory_revision(&self) -> &SavedVaultInventoryRevision {
        &self.expected_inventory_revision
    }

    pub(crate) fn target_graph(&self) -> &SavedVaultGraph {
        &self.target_graph
    }

    pub(crate) fn identity(&self) -> &SavedPasswordIdentity {
        &self.identity
    }

    pub(crate) fn credential(&self) -> &PreparedPasswordCredentialMutation {
        &self.credential
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        SavedVaultInventoryRevision,
        SavedVaultGraph,
        SavedPasswordIdentity,
        PreparedPasswordCredentialMutation,
    ) {
        (
            self.expected_inventory_revision,
            self.target_graph,
            self.identity,
            self.credential,
        )
    }
}

pub(crate) struct PreparedPasswordIdentityDeletion {
    expected_inventory_revision: SavedVaultInventoryRevision,
    target_graph: SavedVaultGraph,
    identity_id: SavedPasswordIdentityId,
    credential: PreparedPasswordCredentialMutation,
}

impl PreparedPasswordIdentityDeletion {
    pub(crate) fn expected_inventory_revision(&self) -> &SavedVaultInventoryRevision {
        &self.expected_inventory_revision
    }

    pub(crate) fn target_graph(&self) -> &SavedVaultGraph {
        &self.target_graph
    }

    pub(crate) fn identity_id(&self) -> &SavedPasswordIdentityId {
        &self.identity_id
    }

    pub(crate) fn credential(&self) -> &PreparedPasswordCredentialMutation {
        &self.credential
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        SavedVaultInventoryRevision,
        SavedVaultGraph,
        SavedPasswordIdentityId,
        PreparedPasswordCredentialMutation,
    ) {
        (
            self.expected_inventory_revision,
            self.target_graph,
            self.identity_id,
            self.credential,
        )
    }
}

pub(crate) fn prepare_password_identity_creation(
    graph: SavedVaultGraph,
    request: CreatePasswordIdentityRequest,
    id: SavedPasswordIdentityId,
    now: u64,
) -> Result<PreparedPasswordIdentityMutation, String> {
    ensure_identity_id_available(&graph, &id)?;
    let CreatePasswordIdentityRequest {
        expected_inventory_revision,
        metadata,
        staged_credential_reference,
    } = request;
    let has_saved_credential = staged_credential_reference.is_some();
    let identity = SavedPasswordIdentity::from_parts(
        id,
        1,
        metadata.label,
        metadata.username,
        has_saved_credential,
        now,
        now,
        Default::default(),
    )
    .map_err(|_| password_identity_invalid())?;
    let target = identity_credential_reference(&identity.id)?;
    let credential = match staged_credential_reference {
        Some(staged_credential_reference) => PreparedPasswordCredentialMutation::Replace {
            target,
            staged_credential_reference,
        },
        None => PreparedPasswordCredentialMutation::Keep { target },
    };
    let target_graph = graph_with_identity(graph, identity.clone(), false)?;
    Ok(PreparedPasswordIdentityMutation {
        expected_inventory_revision,
        target_graph,
        identity,
        credential,
    })
}

pub(crate) fn prepare_password_identity_update(
    graph: SavedVaultGraph,
    request: UpdatePasswordIdentityRequest,
    now: u64,
) -> Result<PreparedPasswordIdentityMutation, String> {
    let UpdatePasswordIdentityRequest {
        id,
        expected_revision,
        expected_inventory_revision,
        metadata,
        credential_mutation,
    } = request;
    let id = parse_identity_id(id)?;
    let current = graph
        .password_identities()
        .iter()
        .find(|identity| identity.id == id)
        .cloned()
        .ok_or_else(password_identity_not_found)?;
    ensure_expected_revision(&current, expected_revision)?;

    let target = identity_credential_reference(&id)?;
    let (has_saved_credential, credential) = match credential_mutation {
        PasswordIdentityCredentialMutationRequest::Keep => (
            current.has_saved_credential,
            PreparedPasswordCredentialMutation::Keep { target },
        ),
        PasswordIdentityCredentialMutationRequest::Remove => {
            (false, PreparedPasswordCredentialMutation::Remove { target })
        }
        PasswordIdentityCredentialMutationRequest::Replace {
            staged_credential_reference,
        } => (
            true,
            PreparedPasswordCredentialMutation::Replace {
                target,
                staged_credential_reference,
            },
        ),
    };

    let mut update = SavedPasswordIdentityUpdate::default();
    update.label = Some(metadata.label);
    update.username = Some(metadata.username);
    update.has_saved_credential = Some(has_saved_credential);
    let identity = current
        .apply_update(update, now)
        .map_err(|_| password_identity_invalid())?;
    let target_graph = graph_with_identity(graph, identity.clone(), true)?;
    Ok(PreparedPasswordIdentityMutation {
        expected_inventory_revision,
        target_graph,
        identity,
        credential,
    })
}

pub(crate) fn prepare_password_identity_deletion(
    graph: SavedVaultGraph,
    request: DeletePasswordIdentityRequest,
) -> Result<PreparedPasswordIdentityDeletion, String> {
    let DeletePasswordIdentityRequest {
        id,
        expected_revision,
        expected_inventory_revision,
    } = request;
    let id = parse_identity_id(id)?;
    let current = graph
        .password_identities()
        .iter()
        .find(|identity| identity.id == id)
        .ok_or_else(password_identity_not_found)?;
    ensure_expected_revision(current, expected_revision)?;
    ensure_identity_not_referenced(&graph, &id)?;
    let target = identity_credential_reference(&id)?;

    let (
        hosts,
        references,
        managed_keys,
        identities,
        mut password_identities,
        proxy_profiles,
        groups,
        custom_groups,
        notes_snippets,
        port_forward_rules,
    ) = graph.into_current_parts();
    password_identities.retain(|identity| identity.id != id);
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
    Ok(PreparedPasswordIdentityDeletion {
        expected_inventory_revision,
        target_graph,
        identity_id: id,
        // Delete the deterministic account even if the hint was already
        // false. This cleans an unreachable residue without trusting a hint
        // as proof that the keyring entry is absent.
        credential: PreparedPasswordCredentialMutation::Remove { target },
    })
}

fn ensure_identity_id_available(
    graph: &SavedVaultGraph,
    id: &SavedPasswordIdentityId,
) -> Result<(), String> {
    if graph
        .password_identities()
        .iter()
        .any(|identity| &identity.id == id)
        || graph
            .identity_references()
            .iter()
            .any(|identity| identity.id.as_str() == id.as_str())
    {
        return Err(password_identity_error(
            PASSWORD_IDENTITY_INVALID,
            "The password identity identifier is unavailable",
        ));
    }
    Ok(())
}

fn ensure_expected_revision(
    identity: &SavedPasswordIdentity,
    expected_revision: u64,
) -> Result<(), String> {
    if expected_revision == 0 || identity.revision != expected_revision {
        return Err(password_identity_error(
            PASSWORD_IDENTITY_CHANGED,
            "The password identity changed; refresh and retry",
        ));
    }
    Ok(())
}

fn ensure_identity_not_referenced(
    graph: &SavedVaultGraph,
    id: &SavedPasswordIdentityId,
) -> Result<(), String> {
    for host in graph.hosts() {
        // SSH and Telnet identity relationships live in separate flattened
        // fields. Both remain durable graph edges even while the other
        // protocol is active, so deleting either referenced identity would
        // leave a broken host after a later protocol switch.
        for field in ["identityId", "telnetIdentityId"] {
            let referenced_id = match host.compatibility_fields().get(field) {
                None | Some(serde_json::Value::Null) => continue,
                Some(serde_json::Value::String(value)) if value.is_empty() => continue,
                Some(serde_json::Value::String(value)) => value.as_str(),
                Some(_) => return Err(password_identity_repair_required()),
            };
            if referenced_id == id.as_str() {
                return Err(password_identity_error(
                    PASSWORD_IDENTITY_IN_USE,
                    "The password identity is still used by a saved host",
                ));
            }
        }
    }
    for profile in graph.proxy_profiles() {
        if profile.config.identity_id() == Some(id) {
            return Err(password_identity_error(
                PASSWORD_IDENTITY_IN_USE,
                "The password identity is still used by a proxy profile",
            ));
        }
    }
    for host in graph.hosts() {
        let proxy_config = host
            .proxy_config()
            .map_err(|_| password_identity_repair_required())?;
        if proxy_config
            .as_ref()
            .is_some_and(|config| config.identity_id() == Some(id))
        {
            return Err(password_identity_error(
                PASSWORD_IDENTITY_IN_USE,
                "The password identity is still used by a saved-host proxy",
            ));
        }
    }
    Ok(())
}

fn graph_with_identity(
    graph: SavedVaultGraph,
    identity: SavedPasswordIdentity,
    replace: bool,
) -> Result<SavedVaultGraph, String> {
    let (
        hosts,
        references,
        managed_keys,
        identities,
        mut password_identities,
        proxy_profiles,
        groups,
        custom_groups,
        notes_snippets,
        port_forward_rules,
    ) = graph.into_current_parts();
    if replace {
        let Some(index) = password_identities
            .iter()
            .position(|current| current.id == identity.id)
        else {
            return Err(password_identity_not_found());
        };
        password_identities[index] = identity;
    } else {
        password_identities.push(identity);
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

fn parse_identity_id(id: String) -> Result<SavedPasswordIdentityId, String> {
    SavedPasswordIdentityId::from_opaque(id).map_err(|_| password_identity_invalid())
}

fn identity_credential_reference(
    id: &SavedPasswordIdentityId,
) -> Result<StoredCredentialReference, String> {
    StoredCredentialReference::for_saved_identity(id.as_str())
        .map_err(|_| password_identity_repair_required())
}

pub(crate) fn password_identity_error(code: &str, message: &str) -> String {
    format!("{code}: {message}")
}

pub(crate) fn password_identity_invalid() -> String {
    password_identity_error(
        PASSWORD_IDENTITY_INVALID,
        "The password identity request is invalid",
    )
}

pub(crate) fn password_identity_not_found() -> String {
    password_identity_error(
        PASSWORD_IDENTITY_NOT_FOUND,
        "The password identity was not found",
    )
}

pub(crate) fn password_identity_inventory_changed() -> String {
    password_identity_error(
        PASSWORD_IDENTITY_INVENTORY_CHANGED,
        "The password identity catalog changed; refresh and retry",
    )
}

pub(crate) fn password_identity_publication_failed() -> String {
    password_identity_error(
        PASSWORD_IDENTITY_PUBLICATION_FAILED,
        "The password identity update could not be published",
    )
}

pub(crate) fn password_identity_repair_required() -> String {
    password_identity_error(
        PASSWORD_IDENTITY_REPAIR_REQUIRED,
        "Password identity storage requires repair",
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use netcatty_credentials::{EphemeralCredentialReference, StoredCredentialReference};
    use netcatty_vault::{
        SavedHost, SavedIdentityReference, SavedIdentityReferenceId, SavedNotesSnippetsCatalog,
        SavedPasswordIdentity, SavedPasswordIdentityId, SavedPortForwardKind, SavedPortForwardRule,
        SavedProxyConfig, SavedProxyProfile, SavedProxyProfileId, SavedSshKeyCategory,
        SavedSshKeyReference, SavedSshKeyReferenceId, SavedVaultGraph, SavedVaultInventoryRevision,
    };
    use serde_json::json;

    use super::{
        CreatePasswordIdentityRequest, DeletePasswordIdentityRequest, PASSWORD_IDENTITY_CHANGED,
        PASSWORD_IDENTITY_IN_USE, PASSWORD_IDENTITY_INVALID, PASSWORD_IDENTITY_NOT_FOUND,
        PasswordIdentityCatalog, PasswordIdentityCredentialMutationRequest,
        PasswordIdentityMetadataRequest, PasswordIdentityView, UpdatePasswordIdentityRequest,
        prepare_password_identity_creation, prepare_password_identity_deletion,
        prepare_password_identity_update,
    };

    fn inventory_revision() -> SavedVaultInventoryRevision {
        serde_json::from_value(json!({
            "storeId": "password-identity-test-store",
            "loadedGeneration": 7,
            "maxSeenGeneration": 7,
            "seal": "00"
        }))
        .expect("syntactically valid inventory revision")
    }

    fn metadata(label: &str, username: &str) -> PasswordIdentityMetadataRequest {
        PasswordIdentityMetadataRequest {
            label: label.to_owned(),
            username: username.to_owned(),
        }
    }

    fn password_identity(
        id: &str,
        revision: u64,
        has_saved_credential: bool,
    ) -> SavedPasswordIdentity {
        SavedPasswordIdentity::from_parts(
            SavedPasswordIdentityId::from_opaque(id).expect("identity ID"),
            revision,
            "Shared password",
            "identity-user",
            has_saved_credential,
            10,
            20,
            BTreeMap::from([("legacyHint".to_owned(), json!("preserved"))]),
        )
        .expect("password identity")
    }

    fn create_request(
        staged_credential_reference: Option<EphemeralCredentialReference>,
    ) -> CreatePasswordIdentityRequest {
        CreatePasswordIdentityRequest {
            expected_inventory_revision: inventory_revision(),
            metadata: metadata("  Shared login  ", "  alice@example.com  "),
            staged_credential_reference,
        }
    }

    fn update_request(
        id: &str,
        expected_revision: u64,
        credential_mutation: PasswordIdentityCredentialMutationRequest,
    ) -> UpdatePasswordIdentityRequest {
        UpdatePasswordIdentityRequest {
            id: id.to_owned(),
            expected_revision,
            expected_inventory_revision: inventory_revision(),
            metadata: metadata("Renamed login", "renamed-user"),
            credential_mutation,
        }
    }

    fn host_with_identity(host_id: &str, identity_id: &str) -> SavedHost {
        serde_json::from_value(json!({
            "recordVersion": 1,
            "id": host_id,
            "revision": 1,
            "label": "Password host",
            "hostname": "host.example.com",
            "port": 22,
            "username": "host-user",
            "protocol": "ssh",
            "authMethod": "password",
            "authPolicyVersion": 1,
            "createdAt": 1,
            "updatedAt": 1,
            "identityId": identity_id
        }))
        .expect("host")
    }

    fn telnet_host_with_identity(host_id: &str, identity_id: &str) -> SavedHost {
        serde_json::from_value(json!({
            "recordVersion": 1,
            "id": host_id,
            "revision": 1,
            "label": "Telnet password host",
            "hostname": "console.example.com",
            "port": 23,
            "username": "console-user",
            "protocol": "telnet",
            "authMethod": "password",
            "authPolicyVersion": 1,
            "createdAt": 1,
            "updatedAt": 1,
            "telnetIdentityId": identity_id
        }))
        .expect("Telnet host")
    }

    fn graph_with(identity: SavedPasswordIdentity) -> SavedVaultGraph {
        SavedVaultGraph::new_with_password_identities(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![identity],
        )
    }

    #[test]
    fn create_derives_hint_from_staging_and_returns_secret_free_complete_graph_plan() {
        let staged = EphemeralCredentialReference::new();
        let id = SavedPasswordIdentityId::from_opaque("new-password-identity").expect("ID");
        let prepared = prepare_password_identity_creation(
            SavedVaultGraph::default(),
            create_request(Some(staged)),
            id.clone(),
            30,
        )
        .expect("creation plan");

        assert_eq!(prepared.identity().id, id);
        assert_eq!(prepared.identity().revision, 1);
        assert_eq!(prepared.identity().label, "Shared login");
        assert_eq!(prepared.identity().username, "alice@example.com");
        assert!(prepared.identity().has_saved_credential);
        assert_eq!(
            prepared.target_graph().password_identities(),
            std::slice::from_ref(prepared.identity())
        );
        assert!(prepared.credential().replaces_existing());
        assert_eq!(
            prepared.credential().staged_credential_reference(),
            Some(&staged)
        );
        assert_eq!(
            prepared.credential().target(),
            &StoredCredentialReference::for_saved_identity(id.as_str()).expect("target")
        );
        assert_ne!(
            prepared.credential().target(),
            &StoredCredentialReference::for_saved_host(id.as_str()).expect("host target"),
            "equal host and identity IDs must still use isolated accounts"
        );
        assert_eq!(
            prepared.expected_inventory_revision(),
            &inventory_revision()
        );

        let view = serde_json::to_value(PasswordIdentityView::from(prepared.identity()))
            .expect("renderer-safe view");
        let encoded = view.to_string();
        assert!(!encoded.contains(&staged.to_string()));
        assert!(!encoded.contains(&prepared.credential().target().to_string()));
        for forbidden in ["password", "credentialReference", "credentialLocator"] {
            assert!(view.get(forbidden).is_none());
        }
    }

    #[test]
    fn create_without_staged_secret_keeps_keyring_untouched_and_hint_false() {
        let prepared = prepare_password_identity_creation(
            SavedVaultGraph::default(),
            create_request(None),
            SavedPasswordIdentityId::from_opaque("metadata-only-identity").expect("ID"),
            40,
        )
        .expect("metadata-only creation");
        assert!(!prepared.identity().has_saved_credential);
        assert!(prepared.credential().keeps_existing());
        assert!(
            prepared
                .credential()
                .staged_credential_reference()
                .is_none()
        );
    }

    #[test]
    fn create_rejects_both_password_and_key_identity_id_collisions_without_echoing_ids() {
        let duplicate = password_identity("duplicate-password-identity", 1, false);
        let password_error = prepare_password_identity_creation(
            graph_with(duplicate.clone()),
            create_request(None),
            duplicate.id.clone(),
            30,
        )
        .err()
        .expect("password collision");

        let key_id = SavedSshKeyReferenceId::from_opaque("identity-key").expect("key ID");
        let key = SavedSshKeyReference::from_parts(
            key_id.clone(),
            "Reference key",
            "D:\\keys\\identity-key",
            SavedSshKeyCategory::key(),
            1,
            1,
            BTreeMap::new(),
        )
        .expect("key");
        let identity = SavedIdentityReference::from_parts(
            SavedIdentityReferenceId::from_opaque("duplicate-key-identity").expect("identity ID"),
            "Key identity",
            "key-user",
            key_id,
            1,
            1,
            BTreeMap::new(),
        )
        .expect("identity");
        let graph = SavedVaultGraph::new_with_password_identities(
            Vec::new(),
            vec![key],
            Vec::new(),
            vec![identity],
            Vec::new(),
        );
        let key_error = prepare_password_identity_creation(
            graph,
            create_request(None),
            SavedPasswordIdentityId::from_opaque("duplicate-key-identity").expect("ID"),
            30,
        )
        .err()
        .expect("cross-catalog collision");

        for (error, forbidden) in [
            (password_error, "duplicate-password-identity"),
            (key_error, "duplicate-key-identity"),
        ] {
            assert!(error.starts_with(PASSWORD_IDENTITY_INVALID));
            assert!(!error.contains(forbidden));
        }
    }

    #[test]
    fn update_keep_preserves_hint_compatibility_and_credential_target() {
        let current = password_identity("updated-password-identity", 7, true);
        let current_fields = current.compatibility_fields().clone();
        let prepared = prepare_password_identity_update(
            graph_with(current.clone()),
            update_request(
                current.id.as_str(),
                7,
                PasswordIdentityCredentialMutationRequest::Keep,
            ),
            30,
        )
        .expect("keep update");
        assert_eq!(prepared.identity().revision, 8);
        assert_eq!(prepared.identity().created_at, current.created_at);
        assert_eq!(prepared.identity().updated_at, 30);
        assert_eq!(prepared.identity().compatibility_fields(), &current_fields);
        assert!(prepared.identity().has_saved_credential);
        assert!(prepared.credential().keeps_existing());
        assert_eq!(
            prepared.credential().target(),
            &StoredCredentialReference::for_saved_identity(current.id.as_str()).expect("target")
        );
    }

    #[test]
    fn update_remove_and_replace_derive_hint_only_from_the_typed_action() {
        // A false hint is not proof that the deterministic account is absent:
        // both actions must still return a target for journal inspection.
        let current = password_identity("credential-mutation-identity", 2, false);
        let remove = prepare_password_identity_update(
            graph_with(current.clone()),
            update_request(
                current.id.as_str(),
                2,
                PasswordIdentityCredentialMutationRequest::Remove,
            ),
            30,
        )
        .expect("remove plan");
        assert!(!remove.identity().has_saved_credential);
        assert!(remove.credential().removes_existing());

        let staged = EphemeralCredentialReference::new();
        let replace = prepare_password_identity_update(
            graph_with(current.clone()),
            update_request(
                current.id.as_str(),
                2,
                PasswordIdentityCredentialMutationRequest::Replace {
                    staged_credential_reference: staged,
                },
            ),
            30,
        )
        .expect("replace plan");
        assert!(replace.identity().has_saved_credential);
        assert!(replace.credential().replaces_existing());
        assert_eq!(
            replace.credential().staged_credential_reference(),
            Some(&staged)
        );
    }

    #[test]
    fn update_and_delete_require_exact_record_revisions_with_fixed_errors() {
        let current = password_identity("revision-sentinel-identity", 4, false);
        let update_error = prepare_password_identity_update(
            graph_with(current.clone()),
            update_request(
                current.id.as_str(),
                3,
                PasswordIdentityCredentialMutationRequest::Keep,
            ),
            30,
        )
        .err()
        .expect("stale update");
        let delete_error = prepare_password_identity_deletion(
            graph_with(current.clone()),
            DeletePasswordIdentityRequest {
                id: current.id.as_str().to_owned(),
                expected_revision: 0,
                expected_inventory_revision: inventory_revision(),
            },
        )
        .err()
        .expect("invalid delete revision");
        for error in [update_error, delete_error] {
            assert!(error.starts_with(PASSWORD_IDENTITY_CHANGED));
            assert!(!error.contains(current.id.as_str()));
            assert!(!error.contains('4'));
        }
    }

    #[test]
    fn invalid_or_missing_ids_and_metadata_use_fixed_redacted_errors() {
        let invalid_id = "invalid-identity-id\nmarker";
        let invalid_error = prepare_password_identity_update(
            SavedVaultGraph::default(),
            update_request(
                invalid_id,
                1,
                PasswordIdentityCredentialMutationRequest::Keep,
            ),
            1,
        )
        .err()
        .expect("invalid ID");
        assert!(invalid_error.starts_with(PASSWORD_IDENTITY_INVALID));
        assert!(!invalid_error.contains(invalid_id));

        let missing_id = "missing-password-identity";
        let missing_error = prepare_password_identity_update(
            SavedVaultGraph::default(),
            update_request(
                missing_id,
                1,
                PasswordIdentityCredentialMutationRequest::Keep,
            ),
            1,
        )
        .err()
        .expect("missing ID");
        assert!(missing_error.starts_with(PASSWORD_IDENTITY_NOT_FOUND));
        assert!(!missing_error.contains(missing_id));

        let label_marker = "invalid-label-marker\n";
        let mut request = create_request(None);
        request.metadata.label = label_marker.to_owned();
        let metadata_error = prepare_password_identity_creation(
            SavedVaultGraph::default(),
            request,
            SavedPasswordIdentityId::from_opaque("valid-id").expect("ID"),
            1,
        )
        .err()
        .expect("invalid metadata");
        assert!(metadata_error.starts_with(PASSWORD_IDENTITY_INVALID));
        assert!(!metadata_error.contains(label_marker));
    }

    #[test]
    fn deletion_fails_closed_while_any_host_references_the_identity() {
        let current = password_identity("identity-in-use-marker", 5, true);
        let host = host_with_identity("host-using-password-identity", current.id.as_str());
        let graph = SavedVaultGraph::new_with_password_identities(
            vec![host],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![current.clone()],
        );
        let error = prepare_password_identity_deletion(
            graph,
            DeletePasswordIdentityRequest {
                id: current.id.as_str().to_owned(),
                expected_revision: current.revision,
                expected_inventory_revision: inventory_revision(),
            },
        )
        .err()
        .expect("identity is in use");
        assert!(error.starts_with(PASSWORD_IDENTITY_IN_USE));
        assert!(!error.contains(current.id.as_str()));
        assert!(!error.contains("host-using-password-identity"));
    }

    #[test]
    fn deletion_fails_closed_while_a_telnet_host_references_the_identity() {
        let current = password_identity("telnet-identity-in-use-marker", 5, true);
        let host =
            telnet_host_with_identity("host-using-telnet-password-identity", current.id.as_str());
        let graph = SavedVaultGraph::new_with_password_identities(
            vec![host],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![current.clone()],
        );
        let error = prepare_password_identity_deletion(
            graph,
            DeletePasswordIdentityRequest {
                id: current.id.as_str().to_owned(),
                expected_revision: current.revision,
                expected_inventory_revision: inventory_revision(),
            },
        )
        .err()
        .expect("Telnet identity is in use");
        assert!(error.starts_with(PASSWORD_IDENTITY_IN_USE));
        assert!(!error.contains(current.id.as_str()));
        assert!(!error.contains("host-using-telnet-password-identity"));
    }

    #[test]
    fn deletion_fails_closed_for_proxy_profile_and_inline_proxy_identity_references() {
        let current = password_identity("proxy-password-identity", 5, true);
        let profile = SavedProxyProfile::from_parts(
            SavedProxyProfileId::from_opaque("identity-proxy-profile").expect("profile ID"),
            1,
            "Identity proxy",
            SavedProxyConfig::http(
                "profile.proxy.test",
                8080,
                Some(current.id.clone()),
                "",
                false,
            )
            .expect("profile config"),
            1,
            1,
            BTreeMap::new(),
        )
        .expect("proxy profile");
        let profile_graph = SavedVaultGraph::new_with_proxy_profiles(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![current.clone()],
            vec![profile],
            Vec::new(),
        );
        let profile_error = prepare_password_identity_deletion(
            profile_graph,
            DeletePasswordIdentityRequest {
                id: current.id.as_str().to_owned(),
                expected_revision: current.revision,
                expected_inventory_revision: inventory_revision(),
            },
        )
        .err()
        .expect("profile identity is in use");

        let inline_host = SavedHost::from_draft(
            netcatty_vault::SavedHostDraft::ssh_password("inline.target.test", "host-user")
                .with_proxy_config(
                    SavedProxyConfig::socks5(
                        "inline.proxy.test",
                        1080,
                        Some(current.id.clone()),
                        "",
                        false,
                    )
                    .expect("inline config"),
                )
                .expect("inline proxy draft"),
            1,
        )
        .expect("inline proxy host");
        let inline_graph = SavedVaultGraph::new_with_proxy_profiles(
            vec![inline_host],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![current.clone()],
            Vec::new(),
            Vec::new(),
        );
        let inline_error = prepare_password_identity_deletion(
            inline_graph,
            DeletePasswordIdentityRequest {
                id: current.id.as_str().to_owned(),
                expected_revision: current.revision,
                expected_inventory_revision: inventory_revision(),
            },
        )
        .err()
        .expect("inline proxy identity is in use");

        for error in [profile_error, inline_error] {
            assert!(error.starts_with(PASSWORD_IDENTITY_IN_USE));
            assert!(!error.contains(current.id.as_str()));
            assert!(!error.contains("proxy.test"));
        }
    }

    #[test]
    fn deletion_removes_only_the_identity_and_always_cleans_its_account() {
        let removed = password_identity("removed-password-identity", 3, false);
        let preserved = password_identity("preserved-password-identity", 9, true);
        let graph = SavedVaultGraph::new_with_password_identities(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![removed.clone(), preserved.clone()],
        );
        let prepared = prepare_password_identity_deletion(
            graph,
            DeletePasswordIdentityRequest {
                id: removed.id.as_str().to_owned(),
                expected_revision: removed.revision,
                expected_inventory_revision: inventory_revision(),
            },
        )
        .expect("delete plan");
        assert_eq!(prepared.identity_id(), &removed.id);
        assert_eq!(
            prepared.target_graph().password_identities(),
            std::slice::from_ref(&preserved)
        );
        assert!(prepared.credential().removes_existing());
        assert_eq!(
            prepared.credential().target(),
            &StoredCredentialReference::for_saved_identity(removed.id.as_str()).expect("target")
        );
        assert_eq!(
            prepared.expected_inventory_revision(),
            &inventory_revision()
        );
    }

    #[test]
    fn mutations_preserve_every_unrelated_full_graph_catalog() {
        let current = password_identity("full-graph-password-identity", 1, false);
        let key_id = SavedSshKeyReferenceId::from_opaque("preserved-key").expect("key ID");
        let key = SavedSshKeyReference::from_parts(
            key_id.clone(),
            "Preserved key",
            "D:\\keys\\preserved-key",
            SavedSshKeyCategory::key(),
            1,
            1,
            BTreeMap::new(),
        )
        .expect("key");
        let key_identity = SavedIdentityReference::from_parts(
            SavedIdentityReferenceId::from_opaque("preserved-key-identity").expect("identity ID"),
            "Preserved identity",
            "identity-user",
            key_id,
            1,
            1,
            BTreeMap::new(),
        )
        .expect("key identity");
        let host = host_with_identity("preserved-host", current.id.as_str());
        let proxy_profile = SavedProxyProfile::from_parts(
            SavedProxyProfileId::from_opaque("preserved-proxy-profile").expect("profile ID"),
            1,
            "Preserved proxy",
            SavedProxyConfig::command("proxy-helper --stdio").expect("proxy command"),
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
            "preserved-forward",
            "Preserved forward",
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
        let graph = SavedVaultGraph::new_with_port_forward_rules(
            vec![host.clone()],
            vec![key.clone()],
            Vec::new(),
            vec![key_identity.clone()],
            vec![current.clone()],
            vec![proxy_profile.clone()],
            Vec::new(),
            notes_snippets.clone(),
            vec![port_forward.clone()],
        );
        let prepared = prepare_password_identity_update(
            graph,
            update_request(
                current.id.as_str(),
                current.revision,
                PasswordIdentityCredentialMutationRequest::Keep,
            ),
            30,
        )
        .expect("full graph update");
        assert_eq!(prepared.target_graph().hosts(), std::slice::from_ref(&host));
        assert_eq!(
            prepared.target_graph().ssh_key_references(),
            std::slice::from_ref(&key)
        );
        assert!(prepared.target_graph().managed_ssh_keys().is_empty());
        assert_eq!(
            prepared.target_graph().identity_references(),
            std::slice::from_ref(&key_identity)
        );
        assert_eq!(
            prepared.target_graph().proxy_profiles(),
            std::slice::from_ref(&proxy_profile)
        );
        assert_eq!(prepared.target_graph().notes_snippets(), &notes_snippets);
        assert_eq!(
            prepared.target_graph().port_forward_rules(),
            std::slice::from_ref(&port_forward)
        );
    }

    #[test]
    fn request_json_is_strict_and_cannot_smuggle_plaintext_credentials() {
        let revision = serde_json::to_value(inventory_revision()).expect("revision JSON");
        let staged = EphemeralCredentialReference::new();
        let valid = json!({
            "id": "identity",
            "expectedRevision": 1,
            "expectedInventoryRevision": revision,
            "metadata": {"label": "Identity", "username": "user"},
            "credentialMutation": {
                "action": "replace",
                "stagedCredentialReference": staged
            }
        });
        assert!(serde_json::from_value::<UpdatePasswordIdentityRequest>(valid.clone()).is_ok());

        for (path, value) in [
            ("password", json!("plaintext-password-sentinel")),
            ("credential", json!("plaintext-password-sentinel")),
            ("hasSavedCredential", json!(true)),
        ] {
            let mut smuggled = valid.clone();
            smuggled["metadata"][path] = value;
            assert!(serde_json::from_value::<UpdatePasswordIdentityRequest>(smuggled).is_err());
        }
        let mut mutation_secret = valid.clone();
        mutation_secret["credentialMutation"]["password"] = json!("plaintext-password-sentinel");
        assert!(serde_json::from_value::<UpdatePasswordIdentityRequest>(mutation_secret).is_err());

        let mut unknown_top_level = valid;
        unknown_top_level["unexpected"] = json!(true);
        assert!(
            serde_json::from_value::<UpdatePasswordIdentityRequest>(unknown_top_level).is_err()
        );
    }

    #[test]
    fn catalog_json_is_safe_and_contains_only_display_metadata_and_inventory_cas() {
        let identity = password_identity("catalog-identity", 6, true);
        let graph = graph_with(identity);
        let catalog = PasswordIdentityCatalog::from_graph(inventory_revision(), &graph);
        let value = serde_json::to_value(&catalog).expect("catalog JSON");
        assert_eq!(value["identities"][0]["id"], "catalog-identity");
        assert_eq!(value["identities"][0]["hasSavedCredential"], true);
        assert!(value["identities"][0].get("password").is_none());
        assert!(value["identities"][0].get("credentialReference").is_none());
        assert!(value["identities"][0].get("compatibilityFields").is_none());
        let encoded = value.to_string();
        assert!(!encoded.contains("os:v1:"));
        assert!(!encoded.contains("mem:v1:"));
        assert!(!encoded.contains("preserved"));
    }

    #[test]
    fn missing_deletion_is_fixed_and_does_not_echo_the_requested_id() {
        let missing = "missing-deletion-identity";
        let error = prepare_password_identity_deletion(
            SavedVaultGraph::default(),
            DeletePasswordIdentityRequest {
                id: missing.to_owned(),
                expected_revision: 1,
                expected_inventory_revision: inventory_revision(),
            },
        )
        .err()
        .expect("missing deletion");
        assert!(error.starts_with(PASSWORD_IDENTITY_NOT_FOUND));
        assert!(!error.contains(missing));
    }
}
