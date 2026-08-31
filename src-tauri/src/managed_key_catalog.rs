use std::collections::BTreeMap;

use netcatty_secret_store::SshSecretBundle;
use netcatty_vault::{
    SavedManagedSshKey, SavedSecretObjectLocator, SavedSshKeyCategory, SavedSshKeyCustodyReference,
    SavedSshKeyReferenceId, SavedSshKeySource, SavedVaultGraph, SavedVaultInventoryRevision,
};
use serde::{Deserialize, Serialize};

use crate::managed_key_staging::ManagedKeyStagingReference;

pub(crate) const MANAGED_KEY_INVALID: &str = "MANAGED_SSH_KEY_INVALID";
pub(crate) const MANAGED_KEY_NOT_FOUND: &str = "MANAGED_SSH_KEY_NOT_FOUND";
pub(crate) const MANAGED_KEY_IN_USE: &str = "MANAGED_SSH_KEY_IN_USE";
pub(crate) const MANAGED_KEY_INVENTORY_CHANGED: &str = "MANAGED_SSH_KEY_INVENTORY_CHANGED";
pub(crate) const MANAGED_KEY_PUBLICATION_FAILED: &str = "MANAGED_SSH_KEY_PUBLICATION_FAILED";
pub(crate) const MANAGED_KEY_REPAIR_REQUIRED: &str = "MANAGED_SSH_KEY_REPAIR_REQUIRED";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ManagedSshKeyCategoryRequest {
    Key,
    Certificate,
}

impl ManagedSshKeyCategoryRequest {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Certificate => "certificate",
        }
    }

    fn into_vault(self) -> SavedSshKeyCategory {
        match self {
            Self::Key => SavedSshKeyCategory::key(),
            Self::Certificate => SavedSshKeyCategory::certificate(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ManagedSshKeyMetadataRequest {
    pub(crate) label: String,
    pub(crate) category: ManagedSshKeyCategoryRequest,
    pub(crate) save_passphrase: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreateManagedSshKeyRequest {
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
    pub(crate) metadata: ManagedSshKeyMetadataRequest,
    pub(crate) staged_bundle_reference: ManagedKeyStagingReference,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UpdateManagedSshKeyRequest {
    pub(crate) id: String,
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
    pub(crate) metadata: ManagedSshKeyMetadataRequest,
    #[serde(default)]
    pub(crate) staged_bundle_reference: Option<ManagedKeyStagingReference>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DeleteManagedSshKeyRequest {
    pub(crate) id: String,
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ManagedSshKeyView {
    id: String,
    label: String,
    category: String,
    source: String,
    has_saved_passphrase: bool,
    created_at: u64,
    updated_at: u64,
}

impl From<&SavedManagedSshKey> for ManagedSshKeyView {
    fn from(key: &SavedManagedSshKey) -> Self {
        Self {
            id: key.id.as_str().to_owned(),
            label: key.label.clone(),
            category: key.category.as_str().to_owned(),
            source: key.source.as_str().to_owned(),
            has_saved_passphrase: key.has_saved_passphrase,
            created_at: key.created_at,
            updated_at: key.updated_at,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ManagedSshKeyCatalog {
    inventory_revision: SavedVaultInventoryRevision,
    keys: Vec<ManagedSshKeyView>,
}

impl ManagedSshKeyCatalog {
    pub(crate) fn from_graph(
        inventory_revision: SavedVaultInventoryRevision,
        graph: &SavedVaultGraph,
    ) -> Self {
        Self {
            inventory_revision,
            keys: graph
                .managed_ssh_keys()
                .iter()
                .map(ManagedSshKeyView::from)
                .collect(),
        }
    }
}

pub(crate) struct PreparedManagedKeyMutation {
    target_graph: SavedVaultGraph,
    key: SavedManagedSshKey,
    bundle: Option<SshSecretBundle>,
}

impl PreparedManagedKeyMutation {
    pub(crate) fn target_graph(&self) -> &SavedVaultGraph {
        &self.target_graph
    }

    pub(crate) fn publication(&self) -> Option<(&SavedManagedSshKey, &SshSecretBundle)> {
        self.bundle.as_ref().map(|bundle| (&self.key, bundle))
    }

    pub(crate) fn into_parts(
        self,
    ) -> (SavedVaultGraph, SavedManagedSshKey, Option<SshSecretBundle>) {
        (self.target_graph, self.key, self.bundle)
    }
}

pub(crate) fn prepare_managed_key_creation(
    graph: SavedVaultGraph,
    metadata: ManagedSshKeyMetadataRequest,
    mut bundle: SshSecretBundle,
    id: SavedSshKeyReferenceId,
    backend_locator: SavedSecretObjectLocator,
    now: u64,
) -> Result<PreparedManagedKeyMutation, String> {
    ensure_managed_key_id_available(&graph, &id)?;
    apply_bundle_policy(&metadata, &mut bundle)?;
    let custody =
        SavedSshKeyCustodyReference::new(backend_locator, 1).map_err(|_| managed_key_invalid())?;
    let key = SavedManagedSshKey::from_parts(
        id,
        metadata.label,
        metadata.category.into_vault(),
        SavedSshKeySource::imported(),
        metadata.save_passphrase && bundle.passphrase().is_some(),
        now,
        now,
        custody,
        BTreeMap::new(),
    )
    .map_err(|_| managed_key_invalid())?;
    let target_graph = graph_with_key(graph, key.clone(), false)?;
    Ok(PreparedManagedKeyMutation {
        target_graph,
        key,
        bundle: Some(bundle),
    })
}

/// Validates every renderer-controlled creation field before the desktop may
/// initialize the secret store, create a keyring account, run GC, or derive a
/// real backend locator. The fixed dummy locator never leaves this function.
pub(crate) fn preflight_managed_key_creation(
    graph: &SavedVaultGraph,
    metadata: &ManagedSshKeyMetadataRequest,
    bundle: &mut SshSecretBundle,
    id: &SavedSshKeyReferenceId,
    now: u64,
) -> Result<(), String> {
    ensure_managed_key_id_available(graph, id)?;
    apply_bundle_policy(metadata, bundle)?;
    let dummy_locator =
        SavedSecretObjectLocator::from_hex("ab".repeat(32)).map_err(|_| managed_key_invalid())?;
    let dummy_custody =
        SavedSshKeyCustodyReference::new(dummy_locator, 1).map_err(|_| managed_key_invalid())?;
    SavedManagedSshKey::from_parts(
        id.clone(),
        metadata.label.clone(),
        metadata.category.into_vault(),
        SavedSshKeySource::imported(),
        metadata.save_passphrase && bundle.passphrase().is_some(),
        now,
        now,
        dummy_custody,
        BTreeMap::new(),
    )
    .map(|_| ())
    .map_err(|_| managed_key_invalid())
}

fn ensure_managed_key_id_available(
    graph: &SavedVaultGraph,
    id: &SavedSshKeyReferenceId,
) -> Result<(), String> {
    if graph
        .managed_ssh_keys()
        .iter()
        .any(|current| &current.id == id)
        || graph
            .ssh_key_references()
            .iter()
            .any(|current| &current.id == id)
    {
        return Err(managed_key_error(
            MANAGED_KEY_INVALID,
            "The managed SSH key identifier is unavailable",
        ));
    }
    Ok(())
}

pub(crate) fn prepare_managed_key_update(
    graph: SavedVaultGraph,
    id: &SavedSshKeyReferenceId,
    metadata: ManagedSshKeyMetadataRequest,
    staged_bundle: Option<SshSecretBundle>,
    now: u64,
) -> Result<PreparedManagedKeyMutation, String> {
    let current = graph
        .managed_ssh_keys()
        .iter()
        .find(|key| &key.id == id)
        .cloned()
        .ok_or_else(managed_key_not_found)?;

    let (custody, has_saved_passphrase, bundle) = match staged_bundle {
        Some(mut bundle) => {
            apply_bundle_policy(&metadata, &mut bundle)?;
            let revision = current
                .custody()
                .custody_revision()
                .checked_add(1)
                .ok_or_else(managed_key_invalid)?;
            let custody = SavedSshKeyCustodyReference::new(
                current.custody().backend_locator().clone(),
                revision,
            )
            .map_err(|_| managed_key_invalid())?;
            let has_saved_passphrase = metadata.save_passphrase && bundle.passphrase().is_some();
            (custody, has_saved_passphrase, Some(bundle))
        }
        None => {
            if metadata.category.as_str() != current.category.as_str()
                || metadata.save_passphrase != current.has_saved_passphrase
            {
                return Err(managed_key_error(
                    MANAGED_KEY_INVALID,
                    "Replacing key material is required for this change",
                ));
            }
            (
                current.custody().clone(),
                current.has_saved_passphrase,
                None,
            )
        }
    };

    let key = SavedManagedSshKey::from_parts(
        current.id.clone(),
        metadata.label,
        metadata.category.into_vault(),
        current.source.clone(),
        has_saved_passphrase,
        current.created_at,
        now.max(current.created_at),
        custody,
        current.compatibility_fields().clone(),
    )
    .map_err(|_| managed_key_invalid())?;
    let target_graph = graph_with_key(graph, key.clone(), true)?;
    Ok(PreparedManagedKeyMutation {
        target_graph,
        key,
        bundle,
    })
}

pub(crate) fn prepare_managed_key_deletion(
    graph: SavedVaultGraph,
    id: &SavedSshKeyReferenceId,
) -> Result<SavedVaultGraph, String> {
    if !graph.managed_ssh_keys().iter().any(|key| &key.id == id) {
        return Err(managed_key_not_found());
    }
    let (
        hosts,
        references,
        mut managed_keys,
        identities,
        password_identities,
        proxy_profiles,
        groups,
        custom_groups,
        notes_snippets,
        port_forward_rules,
    ) = graph.into_current_parts();
    managed_keys.retain(|key| &key.id != id);
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

fn graph_with_key(
    graph: SavedVaultGraph,
    key: SavedManagedSshKey,
    replace: bool,
) -> Result<SavedVaultGraph, String> {
    let (
        hosts,
        references,
        mut managed_keys,
        identities,
        password_identities,
        proxy_profiles,
        groups,
        custom_groups,
        notes_snippets,
        port_forward_rules,
    ) = graph.into_current_parts();
    if replace {
        let Some(index) = managed_keys.iter().position(|current| current.id == key.id) else {
            return Err(managed_key_not_found());
        };
        managed_keys[index] = key;
    } else {
        managed_keys.push(key);
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

fn apply_bundle_policy(
    metadata: &ManagedSshKeyMetadataRequest,
    bundle: &mut SshSecretBundle,
) -> Result<(), String> {
    std::str::from_utf8(bundle.private_key()).map_err(|_| managed_key_invalid())?;
    if let Some(public_key) = bundle.public_key() {
        std::str::from_utf8(public_key).map_err(|_| managed_key_invalid())?;
    }
    if let Some(certificate) = bundle.certificate() {
        std::str::from_utf8(certificate).map_err(|_| managed_key_invalid())?;
    }
    if let Some(passphrase) = bundle.passphrase() {
        std::str::from_utf8(passphrase).map_err(|_| managed_key_invalid())?;
    }

    match metadata.category {
        ManagedSshKeyCategoryRequest::Key if bundle.certificate().is_some() => {
            return Err(managed_key_error(
                MANAGED_KEY_INVALID,
                "A private-key record cannot contain an SSH certificate",
            ));
        }
        ManagedSshKeyCategoryRequest::Certificate if bundle.certificate().is_none() => {
            return Err(managed_key_error(
                MANAGED_KEY_INVALID,
                "A certificate record requires an SSH certificate",
            ));
        }
        ManagedSshKeyCategoryRequest::Key | ManagedSshKeyCategoryRequest::Certificate => {}
    }
    if !metadata.save_passphrase {
        bundle.discard_passphrase();
    }
    Ok(())
}

pub(crate) fn managed_key_error(code: &str, message: &str) -> String {
    format!("{code}: {message}")
}

pub(crate) fn managed_key_invalid() -> String {
    managed_key_error(
        MANAGED_KEY_INVALID,
        "The managed SSH key request is invalid",
    )
}

pub(crate) fn managed_key_not_found() -> String {
    managed_key_error(MANAGED_KEY_NOT_FOUND, "The managed SSH key was not found")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use netcatty_secret_store::SshSecretBundle;
    use netcatty_vault::{
        SavedHost, SavedHostDraft, SavedNotesSnippetsCatalog, SavedPasswordIdentity,
        SavedPasswordIdentityId, SavedPortForwardKind, SavedPortForwardRule, SavedProxyConfig,
        SavedProxyProfile, SavedProxyProfileId, SavedSecretObjectLocator, SavedSshKeyReferenceId,
        SavedVaultGraph, SavedVaultInventoryRevision,
    };

    use super::{
        CreateManagedSshKeyRequest, MANAGED_KEY_INVALID, ManagedSshKeyCategoryRequest,
        ManagedSshKeyMetadataRequest, ManagedSshKeyView, prepare_managed_key_creation,
        prepare_managed_key_deletion, prepare_managed_key_update,
    };

    fn metadata(
        category: ManagedSshKeyCategoryRequest,
        save_passphrase: bool,
    ) -> ManagedSshKeyMetadataRequest {
        ManagedSshKeyMetadataRequest {
            label: "Catalog key".to_owned(),
            category,
            save_passphrase,
        }
    }

    fn bundle(certificate: Option<&[u8]>, passphrase: Option<&[u8]>) -> SshSecretBundle {
        SshSecretBundle::new(
            [
                b"-----BEGIN OPENSSH PRIVATE".as_slice(),
                b" KEY-----".as_slice(),
            ]
            .concat(),
            Some(b"ssh-ed25519 public".to_vec()),
            certificate.map(<[u8]>::to_vec),
            passphrase.map(<[u8]>::to_vec),
        )
        .expect("bundle")
    }

    fn locator() -> SavedSecretObjectLocator {
        SavedSecretObjectLocator::from_hex("ab".repeat(32)).expect("locator")
    }

    fn password_identity() -> SavedPasswordIdentity {
        SavedPasswordIdentity::from_parts(
            SavedPasswordIdentityId::from_opaque("preserved-password-identity")
                .expect("password identity ID"),
            4,
            "Preserved password identity",
            "identity-user",
            true,
            10,
            20,
            BTreeMap::new(),
        )
        .expect("password identity")
    }

    #[test]
    fn create_applies_category_and_passphrase_policy_without_exposing_custody() {
        let id = SavedSshKeyReferenceId::new();
        let prepared = prepare_managed_key_creation(
            SavedVaultGraph::default(),
            metadata(ManagedSshKeyCategoryRequest::Certificate, false),
            bundle(
                Some(b"ssh-ed25519-cert-v01 certificate"),
                Some(b"discard-sentinel"),
            ),
            id.clone(),
            locator(),
            10,
        )
        .expect("creation");
        let (graph, key, staged) = prepared.into_parts();
        assert_eq!(graph.managed_ssh_keys(), std::slice::from_ref(&key));
        assert!(key.category.is_certificate());
        assert!(!key.has_saved_passphrase);
        assert!(staged.expect("publication").passphrase().is_none());

        let encoded = serde_json::to_string(&ManagedSshKeyView::from(&key)).expect("safe view");
        assert!(!encoded.contains(key.custody().backend_locator().as_str()));
        assert!(!encoded.contains("custody"));
        assert!(!encoded.contains("discard-sentinel"));
    }

    #[test]
    fn category_mismatches_fail_closed_with_fixed_errors() {
        let key_error = prepare_managed_key_creation(
            SavedVaultGraph::default(),
            metadata(ManagedSshKeyCategoryRequest::Key, true),
            bundle(Some(b"certificate-sentinel"), None),
            SavedSshKeyReferenceId::new(),
            locator(),
            10,
        )
        .err()
        .expect("key mismatch");
        let certificate_error = prepare_managed_key_creation(
            SavedVaultGraph::default(),
            metadata(ManagedSshKeyCategoryRequest::Certificate, true),
            bundle(None, None),
            SavedSshKeyReferenceId::new(),
            locator(),
            10,
        )
        .err()
        .expect("certificate mismatch");
        assert!(key_error.starts_with(MANAGED_KEY_INVALID));
        assert!(certificate_error.starts_with(MANAGED_KEY_INVALID));
        assert!(!key_error.contains("certificate-sentinel"));
    }

    #[test]
    fn metadata_update_preserves_custody_and_secret_update_increments_revision() {
        let id = SavedSshKeyReferenceId::new();
        let created = prepare_managed_key_creation(
            SavedVaultGraph::default(),
            metadata(ManagedSshKeyCategoryRequest::Key, true),
            bundle(None, Some(b"old-passphrase")),
            id.clone(),
            locator(),
            10,
        )
        .expect("creation");
        let (graph, original, _) = created.into_parts();

        let mut rename = metadata(ManagedSshKeyCategoryRequest::Key, true);
        rename.label = "Renamed key".to_owned();
        let renamed =
            prepare_managed_key_update(graph, &id, rename, None, 20).expect("metadata update");
        assert!(renamed.publication().is_none());
        assert_eq!(
            renamed.target_graph().managed_ssh_keys()[0]
                .custody()
                .custody_revision(),
            original.custody().custody_revision()
        );

        let (renamed_graph, _, _) = renamed.into_parts();
        let replaced = prepare_managed_key_update(
            renamed_graph,
            &id,
            metadata(ManagedSshKeyCategoryRequest::Key, false),
            Some(bundle(None, Some(b"new-passphrase"))),
            30,
        )
        .expect("secret update");
        let (_, updated, staged) = replaced.into_parts();
        assert_eq!(updated.custody().custody_revision(), 2);
        assert!(!updated.has_saved_passphrase);
        assert!(staged.expect("publication").passphrase().is_none());
    }

    #[test]
    fn deletion_removes_only_the_requested_catalog_record() {
        let id = SavedSshKeyReferenceId::new();
        let created = prepare_managed_key_creation(
            SavedVaultGraph::default(),
            metadata(ManagedSshKeyCategoryRequest::Key, false),
            bundle(None, None),
            id.clone(),
            locator(),
            10,
        )
        .expect("creation");
        let (graph, _, _) = created.into_parts();
        let deleted = prepare_managed_key_deletion(graph, &id).expect("delete");
        assert!(deleted.managed_ssh_keys().is_empty());
    }

    #[test]
    fn every_managed_key_mutation_preserves_all_newer_vault_catalogs() {
        let identity = password_identity();
        let profile = SavedProxyProfile::from_parts(
            SavedProxyProfileId::from_opaque("preserved-proxy-profile").expect("profile ID"),
            1,
            "Preserved proxy",
            SavedProxyConfig::command("proxy-helper --stdio").expect("proxy command"),
            10,
            10,
            BTreeMap::new(),
        )
        .expect("proxy profile");
        let host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("forward.example.com", "alice"),
            10,
        )
        .expect("saved host");
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
            SavedPortForwardKind::Local,
            15432,
            "127.0.0.1",
            Some("database.internal".to_owned()),
            Some(5432),
            host.id.as_str(),
            false,
            10,
            None,
            Some(0),
        )
        .expect("port-forward rule");
        let graph = SavedVaultGraph::new_with_port_forward_rules(
            vec![host],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![identity.clone()],
            vec![profile.clone()],
            Vec::new(),
            notes_snippets.clone(),
            vec![port_forward.clone()],
        );
        let id = SavedSshKeyReferenceId::new();
        let created = prepare_managed_key_creation(
            graph,
            metadata(ManagedSshKeyCategoryRequest::Key, false),
            bundle(None, None),
            id.clone(),
            locator(),
            30,
        )
        .expect("creation");
        assert_eq!(
            created.target_graph().password_identities(),
            std::slice::from_ref(&identity)
        );
        assert_eq!(
            created.target_graph().proxy_profiles(),
            std::slice::from_ref(&profile)
        );
        assert_eq!(created.target_graph().notes_snippets(), &notes_snippets);
        assert_eq!(
            created.target_graph().port_forward_rules(),
            std::slice::from_ref(&port_forward)
        );

        let (created_graph, _, _) = created.into_parts();
        let mut updated_metadata = metadata(ManagedSshKeyCategoryRequest::Key, false);
        updated_metadata.label = "Updated without catalog loss".to_owned();
        let updated = prepare_managed_key_update(created_graph, &id, updated_metadata, None, 40)
            .expect("update");
        assert_eq!(
            updated.target_graph().password_identities(),
            std::slice::from_ref(&identity)
        );
        assert_eq!(
            updated.target_graph().proxy_profiles(),
            std::slice::from_ref(&profile)
        );
        assert_eq!(updated.target_graph().notes_snippets(), &notes_snippets);
        assert_eq!(
            updated.target_graph().port_forward_rules(),
            std::slice::from_ref(&port_forward)
        );

        let (updated_graph, _, _) = updated.into_parts();
        let deleted = prepare_managed_key_deletion(updated_graph, &id).expect("delete");
        assert!(deleted.managed_ssh_keys().is_empty());
        assert_eq!(
            deleted.password_identities(),
            std::slice::from_ref(&identity)
        );
        assert_eq!(deleted.proxy_profiles(), std::slice::from_ref(&profile));
        assert_eq!(deleted.notes_snippets(), &notes_snippets);
        assert_eq!(
            deleted.port_forward_rules(),
            std::slice::from_ref(&port_forward)
        );
    }

    #[test]
    fn command_request_rejects_unknown_fields() {
        let request = serde_json::json!({
            "expectedInventoryRevision": {
                "storeId": "store",
                "loadedGeneration": 0,
                "maxSeenGeneration": 0,
                "seal": "00"
            },
            "metadata": {"label":"key","category":"key","savePassphrase":false},
            "stagedBundleReference":"keymem:v1:00000000-0000-4000-8000-000000000000",
            "unexpected": true
        });
        assert!(serde_json::from_value::<CreateManagedSshKeyRequest>(request).is_err());
        let _type_check: Option<SavedVaultInventoryRevision> = None;
    }
}
