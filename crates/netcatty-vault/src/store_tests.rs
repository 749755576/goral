// Test-only implementation extracted mechanically from the parent module.
// Keeping it separate makes the production boundary reviewable without changing behavior.

mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashSet};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::thread;

    use tempfile::TempDir;
    use uuid::Uuid;

    use super::{
        LoadedStore, SLOT_A_DIRECTORY, SLOT_B_DIRECTORY, SNAPSHOT_FORMAT_V1, SNAPSHOT_FORMAT_V2,
        SNAPSHOT_FORMAT_V3, SNAPSHOT_FORMAT_V4, SNAPSHOT_FORMAT_V5, SNAPSHOT_FORMAT_V6,
        SNAPSHOT_FORMAT_V7, SNAPSHOT_FORMAT_V8, SNAPSHOT_FORMAT_V9, SNAPSHOT_FORMAT_V10,
        SNAPSHOT_FORMAT_V11, SNAPSHOT_MAGIC, SavedHostImportDisposition, SavedHostStore,
        SavedVaultCommitDurability, SavedVaultEntityKind, SavedVaultGraph,
        SavedVaultGraphCommitment, Slot, SnapshotEnvelope, StoreError,
        TestDurabilityConfirmationFault, TestPublishFault, normalize_hosts, parse_snapshot_name,
        publish_named_no_overwrite, read_snapshot, snapshot_checksum_v1, snapshot_checksum_v2,
        snapshot_checksum_v3, snapshot_checksum_v4, snapshot_checksum_v5, snapshot_checksum_v6,
        snapshot_checksum_v7,
    };
    use crate::{
        SavedGroupCatalog, SavedGroupConfig, SavedGroupDefaults, SavedGroupHostChain, SavedGroupId,
        SavedGroupOverride, SavedGroupPath, SavedHost, SavedHostDraft, SavedHostId,
        SavedHostUpdate, SavedIdentityReference, SavedIdentityReferenceId, SavedManagedSshKey,
        SavedNotesSnippetsCatalog, SavedPasswordIdentity, SavedPasswordIdentityId,
        SavedProxyConfig, SavedProxyProfile, SavedProxyProfileId, SavedScriptLanguage,
        SavedScriptTrigger, SavedSecretObjectLocator, SavedSerialConfig, SavedSerialConfigError,
        SavedSnippet, SavedSnippetDraft, SavedSnippetKind, SavedSnippetMultiLineRunMode,
        SavedSshKeyCategory, SavedSshKeyCustodyReference, SavedSshKeyReference,
        SavedSshKeyReferenceId, SavedSshKeySource, SavedVaultNote, SavedVaultNoteDraft,
        ValidationError,
    };

    fn store() -> (TempDir, SavedHostStore) {
        let root = TempDir::new().expect("temporary root");
        let store = SavedHostStore::open(root.path().join("vault")).expect("open store");
        (root, store)
    }

    fn label_update(label: &str) -> SavedHostUpdate {
        let mut update = SavedHostUpdate::default();
        update.label = Some(label.to_owned());
        update
    }

    fn latest_snapshot(directory: &std::path::Path) -> std::path::PathBuf {
        fs::read_dir(directory)
            .expect("read slot")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("snapshot-"))
            .max_by_key(|entry| entry.file_name())
            .expect("latest snapshot")
            .path()
    }

    fn snapshot_count(root: &std::path::Path) -> usize {
        [SLOT_A_DIRECTORY, SLOT_B_DIRECTORY]
            .into_iter()
            .flat_map(|slot| fs::read_dir(root.join(slot)).expect("read slot"))
            .filter_map(Result::ok)
            .filter(|entry| parse_snapshot_name(&entry.file_name().to_string_lossy()).is_some())
            .count()
    }

    fn empty_snapshot_for_version(format_version: u32) -> SnapshotEnvelope {
        const STORE_ID: &str = "11111111111111111111111111111111";
        let mut envelope = SnapshotEnvelope {
            magic: SNAPSHOT_MAGIC.to_owned(),
            format_version,
            store_id: STORE_ID.to_owned(),
            slot: Slot::A,
            generation: 1,
            hosts: Vec::new(),
            ssh_key_references: None,
            managed_ssh_keys: None,
            identity_references: None,
            password_identities: None,
            proxy_profiles: None,
            groups: None,
            custom_groups: None,
            notes_snippets: None,
            port_forward_rules: None,
            known_hosts: None,
            connection_logs: None,
            checksum: String::new(),
        };
        envelope.checksum = match format_version {
            SNAPSHOT_FORMAT_V1 => snapshot_checksum_v1(STORE_ID, Slot::A, 1, &[]),
            SNAPSHOT_FORMAT_V2 => {
                envelope.ssh_key_references = Some(Some(Vec::new()));
                envelope.identity_references = Some(Some(Vec::new()));
                snapshot_checksum_v2(STORE_ID, Slot::A, 1, &[], &[], &[])
            }
            SNAPSHOT_FORMAT_V3 => {
                envelope.ssh_key_references = Some(Some(Vec::new()));
                envelope.managed_ssh_keys = Some(Some(Vec::new()));
                envelope.identity_references = Some(Some(Vec::new()));
                snapshot_checksum_v3(STORE_ID, Slot::A, 1, &[], &[], &[], &[])
            }
            SNAPSHOT_FORMAT_V4 => {
                envelope.ssh_key_references = Some(Some(Vec::new()));
                envelope.managed_ssh_keys = Some(Some(Vec::new()));
                envelope.identity_references = Some(Some(Vec::new()));
                envelope.password_identities = Some(Some(Vec::new()));
                snapshot_checksum_v4(STORE_ID, Slot::A, 1, &[], &[], &[], &[], &[])
            }
            SNAPSHOT_FORMAT_V5 => {
                envelope.ssh_key_references = Some(Some(Vec::new()));
                envelope.managed_ssh_keys = Some(Some(Vec::new()));
                envelope.identity_references = Some(Some(Vec::new()));
                envelope.password_identities = Some(Some(Vec::new()));
                envelope.proxy_profiles = Some(Some(Vec::new()));
                snapshot_checksum_v5(STORE_ID, Slot::A, 1, &[], &[], &[], &[], &[], &[])
            }
            SNAPSHOT_FORMAT_V6 => {
                envelope.ssh_key_references = Some(Some(Vec::new()));
                envelope.managed_ssh_keys = Some(Some(Vec::new()));
                envelope.identity_references = Some(Some(Vec::new()));
                envelope.password_identities = Some(Some(Vec::new()));
                envelope.proxy_profiles = Some(Some(Vec::new()));
                envelope.groups = Some(Some(Vec::new()));
                snapshot_checksum_v6(STORE_ID, Slot::A, 1, &[], &[], &[], &[], &[], &[], &[])
            }
            SNAPSHOT_FORMAT_V7 => {
                envelope.ssh_key_references = Some(Some(Vec::new()));
                envelope.managed_ssh_keys = Some(Some(Vec::new()));
                envelope.identity_references = Some(Some(Vec::new()));
                envelope.password_identities = Some(Some(Vec::new()));
                envelope.proxy_profiles = Some(Some(Vec::new()));
                envelope.groups = Some(Some(Vec::new()));
                envelope.notes_snippets = Some(Some(SavedNotesSnippetsCatalog::default()));
                snapshot_checksum_v7(
                    STORE_ID,
                    Slot::A,
                    1,
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &SavedNotesSnippetsCatalog::default(),
                )
            }
            SNAPSHOT_FORMAT_V8 => Ok(SnapshotEnvelope::new_with_proxy_profiles(
                STORE_ID.to_owned(),
                Slot::A,
                1,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                SavedNotesSnippetsCatalog::default(),
                Vec::new(),
            )
            .expect("v8 snapshot")
            .checksum),
            SNAPSHOT_FORMAT_V9 => Ok(SnapshotEnvelope::new_with_known_hosts(
                STORE_ID.to_owned(),
                Slot::A,
                1,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                SavedNotesSnippetsCatalog::default(),
                Vec::new(),
                Vec::new(),
            )
            .expect("v9 snapshot")
            .checksum),
            SNAPSHOT_FORMAT_V10 => Ok(SnapshotEnvelope::new_with_connection_logs(
                STORE_ID.to_owned(),
                Slot::A,
                1,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                SavedNotesSnippetsCatalog::default(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )
            .expect("v10 snapshot")
            .checksum),
            _ => panic!("unsupported test snapshot version {format_version}"),
        }
        .expect("snapshot checksum");

        match format_version {
            SNAPSHOT_FORMAT_V8 => {
                envelope.ssh_key_references = Some(Some(Vec::new()));
                envelope.managed_ssh_keys = Some(Some(Vec::new()));
                envelope.identity_references = Some(Some(Vec::new()));
                envelope.password_identities = Some(Some(Vec::new()));
                envelope.proxy_profiles = Some(Some(Vec::new()));
                envelope.groups = Some(Some(Vec::new()));
                envelope.notes_snippets = Some(Some(SavedNotesSnippetsCatalog::default()));
                envelope.port_forward_rules = Some(Some(Vec::new()));
            }
            SNAPSHOT_FORMAT_V9 => {
                envelope.ssh_key_references = Some(Some(Vec::new()));
                envelope.managed_ssh_keys = Some(Some(Vec::new()));
                envelope.identity_references = Some(Some(Vec::new()));
                envelope.password_identities = Some(Some(Vec::new()));
                envelope.proxy_profiles = Some(Some(Vec::new()));
                envelope.groups = Some(Some(Vec::new()));
                envelope.notes_snippets = Some(Some(SavedNotesSnippetsCatalog::default()));
                envelope.port_forward_rules = Some(Some(Vec::new()));
                envelope.known_hosts = Some(Some(Vec::new()));
            }
            SNAPSHOT_FORMAT_V10 => {
                envelope.ssh_key_references = Some(Some(Vec::new()));
                envelope.managed_ssh_keys = Some(Some(Vec::new()));
                envelope.identity_references = Some(Some(Vec::new()));
                envelope.password_identities = Some(Some(Vec::new()));
                envelope.proxy_profiles = Some(Some(Vec::new()));
                envelope.groups = Some(Some(Vec::new()));
                envelope.notes_snippets = Some(Some(SavedNotesSnippetsCatalog::default()));
                envelope.port_forward_rules = Some(Some(Vec::new()));
                envelope.known_hosts = Some(Some(Vec::new()));
                envelope.connection_logs = Some(Some(Vec::new()));
            }
            _ => {}
        }
        envelope
    }

    #[test]
    fn v11_checksum_authenticates_custom_groups_contents() {
        const STORE_ID: &str = "11111111111111111111111111111111";
        let custom_groups =
            SavedGroupCatalog::from_paths(["Operations/Empty"]).expect("custom groups");
        let envelope = SnapshotEnvelope::new_with_custom_groups(
            STORE_ID.to_owned(),
            Slot::A,
            1,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            custom_groups,
            SavedNotesSnippetsCatalog::default(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("v11 envelope");
        let baseline = serde_json::to_value(envelope).expect("v11 JSON");
        serde_json::from_value::<SnapshotEnvelope>(baseline.clone())
            .expect("decode authentic v11")
            .validate(STORE_ID, Slot::A, 1, PathBuf::from("authentic-v11.json"))
            .expect("authentic v11 validates");

        let mut tampered = baseline;
        tampered["customGroups"] = serde_json::json!(["Operations/Tampered"]);
        let decoded: SnapshotEnvelope =
            serde_json::from_value(tampered).expect("tampered v11 remains syntactically valid");
        assert!(matches!(
            decoded.validate(STORE_ID, Slot::A, 1, PathBuf::from("tampered-v11.json"),),
            Err(StoreError::BothSlotsCorrupt)
        ));
    }

    #[test]
    fn v1_through_v10_reject_injected_custom_groups_even_with_authentic_legacy_checksums() {
        const STORE_ID: &str = "11111111111111111111111111111111";
        for format_version in SNAPSHOT_FORMAT_V1..=SNAPSHOT_FORMAT_V10 {
            let mut baseline = serde_json::to_value(empty_snapshot_for_version(format_version))
                .expect("legacy snapshot JSON");
            baseline
                .as_object_mut()
                .expect("legacy snapshot object")
                .retain(|_, value| !value.is_null());
            serde_json::from_value::<SnapshotEnvelope>(baseline.clone())
                .expect("decode authentic legacy snapshot")
                .validate(
                    STORE_ID,
                    Slot::A,
                    1,
                    PathBuf::from(format!("authentic-v{format_version}.json")),
                )
                .expect("authentic legacy snapshot validates");

            for injected_custom_groups in [
                serde_json::Value::Null,
                serde_json::json!(["Injected/Group"]),
            ] {
                let mut injected = baseline.clone();
                injected["customGroups"] = injected_custom_groups;
                let decoded: SnapshotEnvelope = serde_json::from_value(injected)
                    .expect("injected legacy snapshot remains syntactically valid");
                assert!(
                    matches!(
                        decoded.validate(
                            STORE_ID,
                            Slot::A,
                            1,
                            PathBuf::from(format!("injected-v{format_version}.json")),
                        ),
                        Err(StoreError::BothSlotsCorrupt)
                    ),
                    "Vault v{format_version} accepted an injected customGroups field"
                );
            }
        }
    }

    #[test]
    fn corrupt_v11_active_slot_falls_back_with_previous_custom_groups_intact() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let custom_groups =
            SavedGroupCatalog::from_paths(["Operations/Empty"]).expect("custom groups");
        let initial = SavedVaultGraph::default().with_group_catalog(Some(custom_groups.clone()));
        let revision = store
            .assess_graph_import(&initial)
            .expect("custom-group assessment")
            .into_revision();
        store
            .commit_graph_import(revision, initial)
            .expect("generation one");

        store
            .create(SavedHostDraft::ssh_password(
                "active-slot.example.com",
                "alice",
            ))
            .expect("generation two host mutation");
        let active_path = latest_snapshot(&vault.join(SLOT_B_DIRECTORY));
        let mut active: serde_json::Value =
            serde_json::from_slice(&fs::read(&active_path).expect("read active v11 snapshot"))
                .expect("active v11 JSON");
        active["customGroups"] = serde_json::json!(["Operations/Tampered"]);
        fs::write(
            active_path,
            serde_json::to_vec(&active).expect("tampered v11 JSON"),
        )
        .expect("tamper active v11 snapshot without updating checksum");
        drop(store);

        let reopened = SavedHostStore::open(&vault).expect("fallback to generation one");
        assert!(reopened.list().expect("fallback hosts").is_empty());
        assert_eq!(
            reopened
                .graph()
                .expect("fallback graph")
                .group_catalog()
                .expect("fallback custom groups"),
            &custom_groups
        );
    }

    #[test]
    fn host_and_notes_mutations_preserve_custom_groups() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let custom_groups =
            SavedGroupCatalog::from_paths(["Operations/Empty", "Production/Databases/Reserved"])
                .expect("custom groups");
        let initial = SavedVaultGraph::default().with_group_catalog(Some(custom_groups.clone()));
        let revision = store
            .assess_graph_import(&initial)
            .expect("custom-group assessment")
            .into_revision();
        store
            .commit_graph_import(revision, initial)
            .expect("custom-group commit");

        store
            .create(SavedHostDraft::ssh_password(
                "sibling-host.example.com",
                "alice",
            ))
            .expect("host mutation");
        assert_eq!(
            store
                .graph()
                .expect("graph after host mutation")
                .group_catalog()
                .expect("custom groups after host mutation"),
            &custom_groups
        );

        let notes = SavedNotesSnippetsCatalog::from_parts(
            None,
            Some(vec!["preserved-package".to_owned()]),
            None,
            None,
        )
        .expect("notes catalog");
        let notes_candidate = graph_with_notes_snippets(Vec::new(), notes.clone());
        let revision = store
            .assess_graph_import(&notes_candidate)
            .expect("notes assessment")
            .into_revision();
        store
            .commit_graph_import(revision, notes_candidate)
            .expect("notes mutation");
        drop(store);

        let reopened = SavedHostStore::open(&vault).expect("reopen after sibling mutations");
        let graph = reopened.graph().expect("durable graph");
        assert_eq!(
            graph.group_catalog().expect("durable custom groups"),
            &custom_groups
        );
        assert_eq!(graph.notes_snippets(), &notes);
        assert_eq!(reopened.list().expect("durable host").len(), 1);
    }

    fn legacy_v3_snapshot_json(
        store_id: &str,
        slot: Slot,
        generation: u64,
        hosts: Vec<SavedHost>,
        ssh_key_references: Vec<SavedSshKeyReference>,
        managed_ssh_keys: Vec<SavedManagedSshKey>,
        identity_references: Vec<SavedIdentityReference>,
    ) -> serde_json::Value {
        let checksum = snapshot_checksum_v3(
            store_id,
            slot,
            generation,
            &hosts,
            &ssh_key_references,
            &managed_ssh_keys,
            &identity_references,
        )
        .expect("v3 checksum");
        let envelope = SnapshotEnvelope {
            magic: SNAPSHOT_MAGIC.to_owned(),
            format_version: SNAPSHOT_FORMAT_V3,
            store_id: store_id.to_owned(),
            slot,
            generation,
            hosts,
            ssh_key_references: Some(Some(ssh_key_references)),
            managed_ssh_keys: Some(Some(managed_ssh_keys)),
            identity_references: Some(Some(identity_references)),
            password_identities: None,
            proxy_profiles: None,
            groups: None,
            custom_groups: None,
            notes_snippets: None,
            port_forward_rules: None,
            known_hosts: None,
            connection_logs: None,
            checksum,
        };
        let mut value = serde_json::to_value(envelope).expect("v3 JSON");
        let object = value.as_object_mut().expect("v3 object");
        object.remove("passwordIdentities");
        object.remove("proxyProfiles");
        object.remove("groups");
        object.remove("notesSnippets");
        object.remove("portForwardRules");
        value
    }

    fn import_candidate(id: &str, hostname: &str) -> SavedHost {
        let mut host =
            SavedHost::from_draft(SavedHostDraft::ssh_password(hostname, "import-user"), 10)
                .expect("import candidate");
        host.id = SavedHostId::from_opaque(id).expect("opaque ID");
        host
    }

    fn reference_key(id: &str, label: &str, file_path: &str) -> SavedSshKeyReference {
        SavedSshKeyReference::from_parts(
            SavedSshKeyReferenceId::from_opaque(id).expect("key ID"),
            label,
            file_path,
            SavedSshKeyCategory::key(),
            10,
            10,
            BTreeMap::new(),
        )
        .expect("reference key")
    }

    fn identity_reference(id: &str, label: &str, key_id: &str) -> SavedIdentityReference {
        SavedIdentityReference::from_parts(
            SavedIdentityReferenceId::from_opaque(id).expect("identity ID"),
            label,
            "import-user",
            SavedSshKeyReferenceId::from_opaque(key_id).expect("key ID"),
            10,
            10,
            BTreeMap::new(),
        )
        .expect("identity reference")
    }

    fn password_identity(
        id: &str,
        label: &str,
        username: &str,
        has_saved_credential: bool,
    ) -> SavedPasswordIdentity {
        SavedPasswordIdentity::from_parts(
            SavedPasswordIdentityId::from_opaque(id).expect("password identity ID"),
            1,
            label,
            username,
            has_saved_credential,
            10,
            10,
            BTreeMap::new(),
        )
        .expect("password identity")
    }

    fn proxy_profile(id: &str, label: &str, config: SavedProxyConfig) -> SavedProxyProfile {
        SavedProxyProfile::from_parts(
            SavedProxyProfileId::from_opaque(id).expect("proxy profile ID"),
            1,
            label,
            config,
            10,
            10,
            BTreeMap::from([("order".to_owned(), serde_json::json!(1))]),
        )
        .expect("proxy profile")
    }

    fn managed_key(
        id: &str,
        label: &str,
        locator_byte: u8,
        custody_revision: u64,
        has_saved_passphrase: bool,
        category: SavedSshKeyCategory,
    ) -> SavedManagedSshKey {
        SavedManagedSshKey::from_parts(
            SavedSshKeyReferenceId::from_opaque(id).expect("managed key ID"),
            label,
            category,
            SavedSshKeySource::imported(),
            has_saved_passphrase,
            10,
            10,
            SavedSshKeyCustodyReference::new(
                SavedSecretObjectLocator::from_hex(format!("{locator_byte:02x}").repeat(32))
                    .expect("managed locator"),
                custody_revision,
            )
            .expect("managed custody"),
            BTreeMap::new(),
        )
        .expect("managed key")
    }

    fn publish_managed_snapshot(store: &SavedHostStore, managed: Vec<SavedManagedSshKey>) {
        let _guard = store.gate.lock().expect("store gate");
        let mut loaded = store.load_locked().expect("load before managed snapshot");
        loaded.managed_ssh_keys = managed;
        let publication = store
            .commit_locked(&loaded)
            .expect("publish managed snapshot");
        assert_eq!(publication.durability, SavedVaultCommitDurability::Durable);
    }

    fn graph_json_variant(
        graph: &SavedVaultGraph,
        mutate: impl FnOnce(&mut serde_json::Value),
    ) -> SavedVaultGraph {
        let mut value = serde_json::to_value(graph).expect("graph JSON");
        mutate(&mut value);
        serde_json::from_value(value).expect("valid graph variant")
    }

    fn relationship_host(
        id: &str,
        hostname: &str,
        auth_method: &str,
        identity_id: Option<&str>,
        key_id: Option<&str>,
    ) -> SavedHost {
        let mut value = serde_json::to_value(import_candidate(id, hostname)).expect("host JSON");
        value["authMethod"] = serde_json::json!(auth_method);
        if let Some(identity_id) = identity_id {
            value["identityId"] = serde_json::json!(identity_id);
        }
        if let Some(key_id) = key_id {
            value["identityFileId"] = serde_json::json!(key_id);
        }
        serde_json::from_value(value).expect("relationship host")
    }

    fn snippet(
        id: &str,
        label: &str,
        kind: SavedSnippetKind,
        targets: Option<Vec<&str>>,
    ) -> SavedSnippet {
        let mut draft = SavedSnippetDraft::new(id, label, format!("echo {label}"));
        draft.kind = Some(kind);
        draft.targets =
            targets.map(|targets| targets.into_iter().map(str::to_owned).collect::<Vec<_>>());
        SavedSnippet::from_draft(draft).expect("snippet")
    }

    fn note(id: &str, title: &str, linked_host_ids: Option<Vec<&str>>) -> SavedVaultNote {
        let mut draft =
            SavedVaultNoteDraft::new(id, title, format!("content for {title}"), 10.0, 11.0);
        draft.linked_host_ids =
            linked_host_ids.map(|ids| ids.into_iter().map(str::to_owned).collect::<Vec<_>>());
        SavedVaultNote::from_draft(draft).expect("note")
    }

    fn graph_with_notes_snippets(
        hosts: Vec<SavedHost>,
        catalog: SavedNotesSnippetsCatalog,
    ) -> SavedVaultGraph {
        SavedVaultGraph::new_with_notes_snippets(
            hosts,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            catalog,
        )
    }

    fn graph_with_groups_and_notes_snippets(
        groups: Vec<SavedGroupConfig>,
        catalog: SavedNotesSnippetsCatalog,
    ) -> SavedVaultGraph {
        SavedVaultGraph::new_with_notes_snippets(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            groups,
            catalog,
        )
    }

    fn group_with_script_field(id: &str, path: &str, script_id: &str) -> SavedGroupConfig {
        let mut defaults = crate::group_config::SavedGroupDefaults::default();
        defaults.login_script_id = SavedGroupOverride::Set(
            crate::group_config::SavedGroupOpaqueId::from_opaque(script_id)
                .expect("group script ID"),
        );
        SavedGroupConfig::from_parts(
            crate::group_config::SavedGroupId::from_opaque(id).expect("group ID"),
            1,
            crate::group::SavedGroupPath::new(path).expect("group path"),
            defaults,
            1,
            1,
        )
        .expect("group with script edge")
    }

    fn host_with_script_fields(id: &str, script_id: &str) -> SavedHost {
        let mut value = serde_json::to_value(import_candidate(id, &format!("{id}.example.com")))
            .expect("host JSON");
        value["loginScriptId"] = serde_json::json!(script_id);
        value["connectScriptIds"] = serde_json::json!([script_id]);
        value["outputTriggers"] = serde_json::json!([{
            "pattern": "ready",
            "scriptId": script_id
        }]);
        serde_json::from_value(value).expect("host with script edges")
    }

    fn replacement_graph(prefix: &str) -> SavedVaultGraph {
        let reference_id = format!("{prefix}-reference");
        let managed_id = format!("{prefix}-certificate");
        let key_identity_id = format!("{prefix}-key-identity");
        let certificate_identity_id = format!("{prefix}-certificate-identity");
        let reference = reference_key(
            &reference_id,
            "Replacement reference",
            "D:\\keys\\replacement",
        );
        let managed = managed_key(
            &managed_id,
            "Replacement certificate",
            0xa1,
            3,
            false,
            SavedSshKeyCategory::certificate(),
        );
        let key_identity =
            identity_reference(&key_identity_id, "Key identity", reference.id.as_str());
        let certificate_identity = SavedIdentityReference::from_certificate_parts(
            SavedIdentityReferenceId::from_opaque(&certificate_identity_id).expect("identity ID"),
            "Certificate identity",
            "cert-user",
            managed.id.clone(),
            10,
            10,
            BTreeMap::new(),
        )
        .expect("certificate identity");
        SavedVaultGraph::new_with_managed_ssh_keys(
            vec![
                relationship_host(
                    &format!("{prefix}-key-host"),
                    &format!("{prefix}-key.example.com"),
                    "key",
                    Some(key_identity.id.as_str()),
                    Some(reference.id.as_str()),
                ),
                relationship_host(
                    &format!("{prefix}-certificate-host"),
                    &format!("{prefix}-certificate.example.com"),
                    "certificate",
                    Some(certificate_identity.id.as_str()),
                    Some(managed.id.as_str()),
                ),
            ],
            vec![reference],
            vec![managed],
            vec![key_identity, certificate_identity],
        )
    }

    #[test]
    fn round_trip_is_stably_sorted_and_reopens() {
        let (root, store) = store();
        let mut beta = SavedHostDraft::ssh_password("beta.example.com", "root");
        beta.label = Some("Beta".to_owned());
        let mut alpha = SavedHostDraft::ssh_password("alpha.example.com", "alice@example.com");
        alpha.label = Some("alpha".to_owned());
        store.create(beta).expect("create beta");
        store.create(alpha).expect("create alpha");

        let listed = store.list().expect("list");
        assert_eq!(
            listed
                .iter()
                .map(|host| host.label.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "Beta"]
        );
        drop(store);
        let reopened = SavedHostStore::open(root.path().join("vault")).expect("reopen");
        assert_eq!(reopened.list().expect("reloaded"), listed);
    }

    #[test]
    fn telnet_host_round_trips_in_v11_without_activating_legacy_ssh_relationships() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let initial = SavedVaultGraph::default().with_group_catalog(Some(SavedGroupCatalog::new()));
        let revision = store
            .assess_graph_import(&initial)
            .expect("explicit-empty custom-group assessment")
            .into_revision();
        store
            .commit_graph_import(revision, initial)
            .expect("publish initial v11 graph");
        let host = store
            .create(
                SavedHostDraft::telnet("console.example.com", "")
                    .with_compatibility_field(
                        "identityId",
                        serde_json::json!("missing-legacy-identity"),
                    )
                    .expect("identity compatibility")
                    .with_compatibility_field(
                        "identityFileId",
                        serde_json::json!("missing-legacy-key"),
                    )
                    .expect("key compatibility")
                    .with_compatibility_field(
                        "proxyProfileId",
                        serde_json::json!("missing-legacy-proxy"),
                    )
                    .expect("proxy compatibility")
                    .with_compatibility_field(
                        "hostChain",
                        serde_json::json!({"hostIds":["missing-legacy-jump"]}),
                    )
                    .expect("jump compatibility"),
            )
            .expect("create Telnet host with inert legacy relationships");
        assert!(host.protocol.is_telnet());
        assert_eq!(host.port, 23);
        assert!(host.username.is_empty());
        assert!(host.proxy_profile_id().expect("inactive proxy").is_none());

        assert_eq!(snapshot_count(&vault), 2);
        let snapshot_path = [SLOT_A_DIRECTORY, SLOT_B_DIRECTORY]
            .into_iter()
            .flat_map(|slot| fs::read_dir(vault.join(slot)).expect("read slot"))
            .filter_map(Result::ok)
            .filter(|entry| parse_snapshot_name(&entry.file_name().to_string_lossy()).is_some())
            .max_by_key(|entry| entry.file_name())
            .expect("v11 snapshot")
            .path();
        let snapshot: serde_json::Value =
            serde_json::from_slice(&fs::read(snapshot_path).expect("read Telnet snapshot"))
                .expect("Telnet snapshot JSON");
        assert_eq!(snapshot["formatVersion"], SNAPSHOT_FORMAT_V11);
        assert_eq!(snapshot["hosts"][0]["protocol"], "telnet");
        assert_eq!(snapshot["hosts"][0]["authMethod"], "password");
        assert_eq!(snapshot["hosts"][0]["identityFileId"], "missing-legacy-key");
        assert_eq!(
            snapshot["hosts"][0]["proxyProfileId"],
            "missing-legacy-proxy"
        );
        assert_eq!(
            snapshot["hosts"][0]["hostChain"],
            serde_json::json!({"hostIds":["missing-legacy-jump"]})
        );

        drop(store);
        let reopened = SavedHostStore::open(&vault).expect("reopen v11 Telnet store");
        assert_eq!(reopened.get(&host.id).expect("read host"), Some(host));
    }

    #[test]
    fn serial_host_round_trips_in_v11_without_activating_network_relationships() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let initial = SavedVaultGraph::default().with_group_catalog(Some(SavedGroupCatalog::new()));
        let revision = store
            .assess_graph_import(&initial)
            .expect("explicit-empty custom-group assessment")
            .into_revision();
        store
            .commit_graph_import(revision, initial)
            .expect("publish initial v11 graph");

        let host = store
            .create(
                SavedHostDraft::serial(
                    SavedSerialConfig::new("/tmp/serial link", 921_600).expect("Serial config"),
                )
                .expect("Serial draft")
                .with_compatibility_field(
                    "identityId",
                    serde_json::json!("missing-legacy-identity"),
                )
                .expect("dormant SSH identity")
                .with_compatibility_field("identityFileId", serde_json::json!("missing-legacy-key"))
                .expect("dormant SSH key")
                .with_compatibility_field(
                    "telnetIdentityId",
                    serde_json::json!("missing-legacy-telnet-identity"),
                )
                .expect("dormant Telnet identity")
                .with_compatibility_field("hasSavedCredential", serde_json::json!(true))
                .expect("dormant password hint")
                .with_compatibility_field(
                    "proxyProfileId",
                    serde_json::json!("missing-legacy-proxy"),
                )
                .expect("dormant proxy")
                .with_compatibility_field(
                    "hostChain",
                    serde_json::json!({"hostIds":["missing-legacy-jump"]}),
                )
                .expect("dormant jump chain"),
            )
            .expect("create Serial host with inert network relationships");

        assert!(host.protocol.is_serial());
        assert_eq!(host.hostname, "/tmp/serial link");
        assert_eq!(host.port, 921_600);
        assert!(host.proxy_profile_id().expect("inactive proxy").is_none());
        assert_eq!(
            host.network_port(),
            Err(ValidationError::UnsupportedProtocol)
        );
        let mut inconsistent = host.clone();
        inconsistent.port = 115_200;
        assert!(matches!(
            normalize_hosts(std::slice::from_mut(&mut inconsistent)),
            Err(StoreError::Validation(
                ValidationError::InvalidSerialConfig(SavedSerialConfigError::EndpointMismatch)
            ))
        ));

        drop(store);
        let reopened = SavedHostStore::open(&vault).expect("reopen v11 Serial store");
        let reloaded = reopened
            .get(&host.id)
            .expect("read Serial host")
            .expect("Serial host exists");
        assert_eq!(reloaded, host);
        assert_eq!(
            reloaded
                .effective_serial_config()
                .expect("effective Serial config")
                .baud_rate,
            921_600
        );
    }

    #[test]
    fn persisted_json_contains_no_secret_or_credential_reference() {
        let (root, store) = store();
        store
            .create(SavedHostDraft::ssh_password("host.example.com", "user"))
            .expect("create");
        let root = root.path().join("vault");
        let encoded = [SLOT_A_DIRECTORY, SLOT_B_DIRECTORY]
            .into_iter()
            .flat_map(|slot| fs::read_dir(root.join(slot)).expect("slot"))
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("snapshot-"))
            .map(|entry| fs::read_to_string(entry.path()).expect("snapshot"))
            .collect::<String>();
        let lowered = encoded.to_lowercase();
        assert!(!lowered.contains("must-not-survive"));
        assert!(!lowered.contains("credentialreference"));
        assert!(!lowered.contains("credentialrefs"));
        assert!(!lowered.contains("\"password\":"));
    }

    #[test]
    fn notes_snippets_v7_round_trip_preserves_every_field_and_rejects_runtime_state() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let host = import_candidate("notes-host", "notes.example.com");

        let mut snippet_draft = SavedSnippetDraft::new("script-one", "Deploy", "echo deploy");
        snippet_draft.tags = Some(vec!["ops".to_owned(), String::new()]);
        snippet_draft.package = Some("builtin".to_owned());
        snippet_draft.targets = Some(vec![host.id.as_str().to_owned()]);
        snippet_draft.target_groups = Some(vec![r" Team\Ops ".to_owned()]);
        snippet_draft.targets_all_hosts = Some(false);
        snippet_draft.shortkey = Some("ctrl+d".to_owned());
        snippet_draft.no_auto_run = Some(true);
        snippet_draft.multi_line_run_mode = Some(SavedSnippetMultiLineRunMode::Paste);
        snippet_draft.order = Some(2.5);
        snippet_draft.kind = Some(SavedSnippetKind::Script);
        snippet_draft.language = Some(SavedScriptLanguage::JavaScript);
        snippet_draft.description = Some("deployment script".to_owned());
        snippet_draft.trigger = Some(SavedScriptTrigger::OnConnect);
        snippet_draft.trigger_pattern = Some("ready>".to_owned());
        let snippet = SavedSnippet::from_draft(snippet_draft).expect("full snippet");

        let mut note_draft = SavedVaultNoteDraft::new(
            "note-one",
            "  Runbook  ",
            "complete runbook body",
            100.25,
            101.5,
        );
        note_draft.group = Some(" Team / Ops ".to_owned());
        note_draft.tags = Some(vec![" urgent ".to_owned(), "urgent".to_owned()]);
        note_draft.linked_host_ids = Some(vec![host.id.as_str().to_owned()]);
        note_draft.order = Some(3.5);
        let note = SavedVaultNote::from_draft(note_draft).expect("full note");

        let catalog = SavedNotesSnippetsCatalog::from_parts(
            Some(vec![snippet]),
            Some(vec![
                "builtin".to_owned(),
                " builtin ".to_owned(),
                String::new(),
                "builtin".to_owned(),
            ]),
            Some(vec![note]),
            Some(vec![" Team / Ops ".to_owned(), "Team/Ops".to_owned()]),
        )
        .expect("catalog");
        let graph = graph_with_notes_snippets(vec![host], catalog.clone());
        let assessment = store.assess_graph_import(&graph).expect("assessment");
        assert_eq!(
            assessment.snippet_dispositions(),
            &[super::SavedVaultImportDisposition::Importable]
        );
        assert_eq!(
            assessment.note_dispositions(),
            &[super::SavedVaultImportDisposition::Importable]
        );
        let plan = store
            .plan_graph_import(assessment.into_revision(), &graph)
            .expect("plan");
        assert!(plan.has_changes());
        let committed = store
            .commit_planned_graph_import(plan, graph)
            .expect("commit");
        assert_eq!(committed.imported().notes_snippets(), &catalog);
        assert_eq!(
            store.graph().expect("stored graph").notes_snippets(),
            &catalog
        );

        let mut snapshot: serde_json::Value = serde_json::from_slice(
            &fs::read(latest_snapshot(&vault.join(SLOT_A_DIRECTORY))).expect("snapshot"),
        )
        .expect("snapshot JSON");
        assert_eq!(snapshot["formatVersion"], SNAPSHOT_FORMAT_V8);
        assert_eq!(
            snapshot["notesSnippets"],
            serde_json::to_value(&catalog).expect("catalog JSON")
        );
        let encoded = serde_json::to_string(&snapshot).expect("encoded snapshot");
        assert!(!encoded.contains("\"running\""));
        assert!(!encoded.contains("\"active\""));
        assert!(!encoded.contains("\"lastError\""));
        assert!(!encoded.contains("\"password\":"));

        snapshot["notesSnippets"]["snippets"][0]["running"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SnapshotEnvelope>(snapshot.clone()).is_err());
        snapshot["notesSnippets"]["snippets"][0]
            .as_object_mut()
            .expect("snippet object")
            .remove("running");
        snapshot["notesSnippets"]["notes"][0]["credentialSecret"] =
            serde_json::json!("must-not-survive");
        assert!(serde_json::from_value::<SnapshotEnvelope>(snapshot).is_err());
    }

    #[test]
    fn legacy_v6_snapshot_reopens_and_next_write_adds_absent_v7_catalog() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let checksum = snapshot_checksum_v6(
            store.store_id.as_ref(),
            Slot::A,
            1,
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
        )
        .expect("v6 checksum");
        let legacy = serde_json::json!({
            "magic": SNAPSHOT_MAGIC,
            "formatVersion": SNAPSHOT_FORMAT_V6,
            "storeId": store.store_id.as_ref(),
            "slot": "a",
            "generation": 1,
            "hosts": [],
            "sshKeyReferences": [],
            "managedSshKeys": [],
            "identityReferences": [],
            "passwordIdentities": [],
            "proxyProfiles": [],
            "groups": [],
            "checksum": checksum,
        });
        fs::write(
            vault
                .join(SLOT_A_DIRECTORY)
                .join("snapshot-00000000000000000001-77777777777777777777777777777777.json"),
            serde_json::to_vec(&legacy).expect("legacy JSON"),
        )
        .expect("seed v6 snapshot");
        drop(store);

        let reopened = SavedHostStore::open(&vault).expect("reopen v6");
        assert!(
            reopened
                .graph()
                .expect("v6 graph")
                .notes_snippets()
                .is_absent()
        );
        reopened
            .create(SavedHostDraft::ssh_password(
                "upgrade-v7.example.com",
                "alice",
            ))
            .expect("upgrade write");
        let upgraded: serde_json::Value = serde_json::from_slice(
            &fs::read(latest_snapshot(&vault.join(SLOT_B_DIRECTORY))).expect("v7 snapshot"),
        )
        .expect("v7 JSON");
        assert_eq!(upgraded["formatVersion"], SNAPSHOT_FORMAT_V8);
        assert_eq!(upgraded["notesSnippets"], serde_json::json!({}));
    }

    #[test]
    fn v7_requires_a_non_null_notes_snippets_object_and_v6_rejects_it() {
        let store_id = "11111111111111111111111111111111";
        let envelope = SnapshotEnvelope::new(
            store_id.to_owned(),
            Slot::A,
            1,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("v7 envelope");
        let mut missing = serde_json::to_value(&envelope).expect("v7 JSON");
        missing
            .as_object_mut()
            .expect("v7 object")
            .remove("notesSnippets");
        assert!(matches!(
            serde_json::from_value::<SnapshotEnvelope>(missing)
                .expect("decode missing field")
                .validate(store_id, Slot::A, 1, PathBuf::from("missing-v7.json")),
            Err(StoreError::BothSlotsCorrupt)
        ));

        let mut null = serde_json::to_value(&envelope).expect("v7 JSON");
        null["notesSnippets"] = serde_json::Value::Null;
        assert!(matches!(
            serde_json::from_value::<SnapshotEnvelope>(null)
                .expect("decode null field")
                .validate(store_id, Slot::A, 1, PathBuf::from("null-v7.json")),
            Err(StoreError::BothSlotsCorrupt)
        ));

        let mut v6 = serde_json::to_value(envelope).expect("v7 JSON");
        v6["formatVersion"] = serde_json::json!(SNAPSHOT_FORMAT_V6);
        v6["checksum"] = serde_json::json!(
            snapshot_checksum_v6(store_id, Slot::A, 1, &[], &[], &[], &[], &[], &[], &[])
                .expect("v6 checksum")
        );
        assert!(matches!(
            serde_json::from_value::<SnapshotEnvelope>(v6)
                .expect("decode v6 with extra catalog")
                .validate(store_id, Slot::A, 1, PathBuf::from("ambiguous-v6.json")),
            Err(StoreError::BothSlotsCorrupt)
        ));
    }

    #[test]
    fn legacy_v7_snapshot_without_port_forward_catalog_remains_readable() {
        let store_id = "22222222222222222222222222222222";
        let envelope = SnapshotEnvelope::new(
            store_id.to_owned(),
            Slot::A,
            1,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("v8 envelope");
        let mut legacy = serde_json::to_value(envelope).expect("snapshot JSON");
        legacy["formatVersion"] = serde_json::json!(SNAPSHOT_FORMAT_V7);
        legacy
            .as_object_mut()
            .expect("snapshot object")
            .remove("portForwardRules");
        legacy["checksum"] = serde_json::json!(
            snapshot_checksum_v7(
                store_id,
                Slot::A,
                1,
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &SavedNotesSnippetsCatalog::default(),
            )
            .expect("v7 checksum")
        );

        let validated = serde_json::from_value::<SnapshotEnvelope>(legacy)
            .expect("decode v7")
            .validate(store_id, Slot::A, 1, PathBuf::from("legacy-v7.json"))
            .expect("validate v7");
        assert!(validated.port_forward_rules.is_empty());
    }

    #[test]
    fn explicit_empty_notes_snippets_scope_imports_once_and_changes_commitment() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let before = store
            .confirm_current_snapshot_durability()
            .expect("empty durability");
        let catalog = SavedNotesSnippetsCatalog::from_parts(Some(Vec::new()), None, None, None)
            .expect("explicit empty snippets");
        let candidate = graph_with_notes_snippets(Vec::new(), catalog.clone());
        let plan = store
            .plan_graph_import(before.revision().clone(), &candidate)
            .expect("presence plan");
        assert!(plan.has_changes());
        assert_ne!(
            plan.before_graph_commitment(),
            plan.after_graph_commitment()
        );
        let committed = store
            .commit_planned_graph_import(plan, candidate.clone())
            .expect("presence commit");
        assert_eq!(
            committed.imported().notes_snippets().snippets(),
            Some(&[][..])
        );
        assert_eq!(snapshot_count(&vault), 1);

        let repeat_plan = store
            .plan_graph_import(committed.revision().clone(), &candidate)
            .expect("repeat plan");
        assert!(!repeat_plan.has_changes());
        let repeated = store
            .commit_planned_graph_import(repeat_plan, candidate)
            .expect("repeat commit");
        assert!(repeated.imported().notes_snippets().is_absent());
        assert_eq!(repeated.revision(), committed.revision());
        assert_eq!(snapshot_count(&vault), 1);

        let snapshot: serde_json::Value = serde_json::from_slice(
            &fs::read(latest_snapshot(&vault.join(SLOT_A_DIRECTORY))).expect("snapshot"),
        )
        .expect("snapshot JSON");
        assert_eq!(snapshot["notesSnippets"]["snippets"], serde_json::json!([]));
    }

    #[test]
    fn notes_snippets_import_classifies_conflicts_and_stably_appends_catalog_values() {
        let (_root, store) = store();
        let first_snippet = snippet("snippet-one", "One", SavedSnippetKind::Script, None);
        let first_note = note("note-one", "One", None);
        let initial_catalog = SavedNotesSnippetsCatalog::from_parts(
            Some(vec![first_snippet.clone()]),
            Some(vec!["base".to_owned()]),
            Some(vec![first_note.clone()]),
            Some(vec!["Root".to_owned()]),
        )
        .expect("initial catalog");
        let initial = graph_with_notes_snippets(Vec::new(), initial_catalog);
        let revision = store
            .assess_graph_import(&initial)
            .expect("initial assessment")
            .into_revision();
        store
            .commit_graph_import(revision, initial)
            .expect("initial import");

        let second_snippet = snippet("snippet-two", "Two", SavedSnippetKind::Snippet, None);
        let second_note = note("note-two", "Two", None);
        let candidate_catalog = SavedNotesSnippetsCatalog::from_parts(
            Some(vec![first_snippet.clone(), second_snippet.clone()]),
            Some(vec![
                "base".to_owned(),
                "extra".to_owned(),
                "base".to_owned(),
            ]),
            Some(vec![first_note.clone(), second_note.clone()]),
            Some(vec!["Root".to_owned(), "Child".to_owned()]),
        )
        .expect("candidate catalog");
        let candidate = graph_with_notes_snippets(Vec::new(), candidate_catalog);
        let assessment = store.assess_graph_import(&candidate).expect("assessment");
        assert_eq!(
            assessment.snippet_dispositions(),
            &[
                super::SavedVaultImportDisposition::Duplicate,
                super::SavedVaultImportDisposition::Importable,
            ]
        );
        assert_eq!(
            assessment.note_dispositions(),
            &[
                super::SavedVaultImportDisposition::Duplicate,
                super::SavedVaultImportDisposition::Importable,
            ]
        );
        let committed = store
            .commit_graph_import(assessment.into_revision(), candidate)
            .expect("append import");
        assert_eq!(
            committed.imported().notes_snippets().snippets(),
            Some(std::slice::from_ref(&second_snippet))
        );
        assert_eq!(
            committed.imported().notes_snippets().notes(),
            Some(std::slice::from_ref(&second_note))
        );
        assert_eq!(
            committed.imported().notes_snippets().snippet_packages(),
            Some(&["extra".to_owned()][..])
        );
        assert_eq!(
            store
                .graph()
                .expect("stored graph")
                .notes_snippets()
                .snippet_packages(),
            Some(&["base".to_owned(), "extra".to_owned()][..])
        );

        let changed_snippet = snippet("snippet-one", "Changed", SavedSnippetKind::Script, None);
        let conflict = graph_with_notes_snippets(
            Vec::new(),
            SavedNotesSnippetsCatalog::from_parts(Some(vec![changed_snippet]), None, None, None)
                .expect("snippet conflict"),
        );
        let conflict_assessment = store
            .assess_graph_import(&conflict)
            .expect("classification");
        assert_eq!(
            conflict_assessment.snippet_dispositions(),
            &[super::SavedVaultImportDisposition::Conflict]
        );
        assert!(matches!(
            store.commit_graph_import(conflict_assessment.into_revision(), conflict),
            Err(StoreError::GraphImportConflict(
                SavedVaultEntityKind::Snippet
            ))
        ));

        let changed_note = note("note-one", "Changed", None);
        let conflict = graph_with_notes_snippets(
            Vec::new(),
            SavedNotesSnippetsCatalog::from_parts(None, None, Some(vec![changed_note]), None)
                .expect("note conflict"),
        );
        let conflict_assessment = store
            .assess_graph_import(&conflict)
            .expect("classification");
        assert_eq!(
            conflict_assessment.note_dispositions(),
            &[super::SavedVaultImportDisposition::Conflict]
        );
        assert!(matches!(
            store.commit_graph_import(conflict_assessment.into_revision(), conflict),
            Err(StoreError::GraphImportConflict(SavedVaultEntityKind::Note))
        ));
    }

    #[test]
    fn planned_host_remap_commits_both_notes_edges_and_dangling_edges_fail_closed() {
        let (root, store) = store();
        let old_id = SavedHostId::from_opaque("legacy-host").expect("old host ID");
        let host = import_candidate("final-host", "final.example.com");
        let original = SavedNotesSnippetsCatalog::from_parts(
            Some(vec![snippet(
                "targeted-script",
                "Targeted",
                SavedSnippetKind::Script,
                Some(vec![old_id.as_str()]),
            )]),
            None,
            Some(vec![note(
                "linked-note",
                "Linked",
                Some(vec![old_id.as_str()]),
            )]),
            None,
        )
        .expect("unmapped catalog");
        let dangling = graph_with_notes_snippets(vec![host.clone()], original.clone());
        assert!(matches!(
            store.assess_graph_import(&dangling),
            Err(StoreError::MissingGraphReference {
                source: SavedVaultEntityKind::Snippet,
                target: SavedVaultEntityKind::Host,
            })
        ));
        assert_eq!(snapshot_count(&root.path().join("vault")), 0);

        let remap = BTreeMap::from([(old_id, host.id.clone())]);
        let final_ids = BTreeSet::from([host.id.clone()]);
        let projected = original
            .plan_host_id_remap(&remap, &final_ids)
            .expect("closed remap");
        assert_eq!(projected.remapped_snippet_targets(), 1);
        assert_eq!(projected.remapped_note_links(), 1);
        let graph = graph_with_notes_snippets(vec![host.clone()], projected.into_catalog());
        let assessment = store
            .assess_graph_import(&graph)
            .expect("remapped assessment");
        store
            .commit_graph_import(assessment.into_revision(), graph)
            .expect("atomic remapped import");
        assert_eq!(snapshot_count(&root.path().join("vault")), 1);
        let stored = store.graph().expect("stored graph");
        assert_eq!(stored.hosts(), std::slice::from_ref(&host));
        assert_eq!(
            stored.notes_snippets().snippets().expect("snippets")[0].targets(),
            Some(std::slice::from_ref(&host.id))
        );
        assert_eq!(
            stored.notes_snippets().notes().expect("notes")[0].linked_host_ids(),
            Some(std::slice::from_ref(&host.id))
        );
    }

    #[test]
    fn host_script_edges_require_an_included_script_catalog() {
        let (_root, store) = store();
        let host = host_with_script_fields("script-host", "startup-script");
        let valid = graph_with_notes_snippets(
            vec![host.clone()],
            SavedNotesSnippetsCatalog::from_parts(
                Some(vec![snippet(
                    "startup-script",
                    "Startup",
                    SavedSnippetKind::Script,
                    None,
                )]),
                None,
                None,
                None,
            )
            .expect("script catalog"),
        );
        store
            .assess_graph_import(&valid)
            .expect("valid script edge");

        let missing = graph_with_notes_snippets(
            vec![host.clone()],
            SavedNotesSnippetsCatalog::from_parts(Some(Vec::new()), None, None, None)
                .expect("empty script catalog"),
        );
        assert!(matches!(
            store.assess_graph_import(&missing),
            Err(StoreError::MissingGraphReference {
                source: SavedVaultEntityKind::Host,
                target: SavedVaultEntityKind::Snippet,
            })
        ));

        let incompatible = graph_with_notes_snippets(
            vec![host],
            SavedNotesSnippetsCatalog::from_parts(
                Some(vec![snippet(
                    "startup-script",
                    "Not a script",
                    SavedSnippetKind::Snippet,
                    None,
                )]),
                None,
                None,
                None,
            )
            .expect("normal snippet catalog"),
        );
        assert!(matches!(
            store.assess_graph_import(&incompatible),
            Err(StoreError::IncompatibleGraphReference {
                source: SavedVaultEntityKind::Host,
                target: SavedVaultEntityKind::Snippet,
            })
        ));

        let mut malformed = serde_json::to_value(import_candidate(
            "malformed-script-host",
            "malformed.example.com",
        ))
        .expect("host JSON");
        malformed["connectScriptIds"] = serde_json::json!({"scriptId": "startup-script"});
        let malformed = serde_json::from_value(malformed).expect("compatibility host");
        let malformed = graph_with_notes_snippets(
            vec![malformed],
            SavedNotesSnippetsCatalog::from_parts(
                Some(vec![snippet(
                    "startup-script",
                    "Startup",
                    SavedSnippetKind::Script,
                    None,
                )]),
                None,
                None,
                None,
            )
            .expect("script catalog"),
        );
        assert!(matches!(
            store.assess_graph_import(&malformed),
            Err(StoreError::MissingGraphReference {
                source: SavedVaultEntityKind::Host,
                target: SavedVaultEntityKind::Snippet,
            })
        ));

        let absent = SavedVaultGraph::new(
            vec![host_with_script_fields(
                "legacy-script-host",
                "missing-legacy-script",
            )],
            Vec::new(),
            Vec::new(),
        );
        store
            .assess_graph_import(&absent)
            .expect("absent catalog retains legacy compatibility fields");
    }

    #[test]
    fn group_script_edges_require_an_included_script_catalog() {
        let (_root, store) = store();
        let group = group_with_script_field("script-group", "Script/Group", "startup-script");
        let script_catalog = || {
            SavedNotesSnippetsCatalog::from_parts(
                Some(vec![snippet(
                    "startup-script",
                    "Startup",
                    SavedSnippetKind::Script,
                    None,
                )]),
                None,
                None,
                None,
            )
            .expect("script catalog")
        };
        let valid = graph_with_groups_and_notes_snippets(vec![group.clone()], script_catalog());
        store
            .assess_graph_import(&valid)
            .expect("valid group script edge");

        let missing = graph_with_groups_and_notes_snippets(
            vec![group.clone()],
            SavedNotesSnippetsCatalog::from_parts(Some(Vec::new()), None, None, None)
                .expect("empty script catalog"),
        );
        assert!(matches!(
            store.assess_graph_import(&missing),
            Err(StoreError::MissingGraphReference {
                source: SavedVaultEntityKind::Group,
                target: SavedVaultEntityKind::Snippet,
            })
        ));

        let incompatible = graph_with_groups_and_notes_snippets(
            vec![group.clone()],
            SavedNotesSnippetsCatalog::from_parts(
                Some(vec![snippet(
                    "startup-script",
                    "Not a script",
                    SavedSnippetKind::Snippet,
                    None,
                )]),
                None,
                None,
                None,
            )
            .expect("normal snippet catalog"),
        );
        assert!(matches!(
            store.assess_graph_import(&incompatible),
            Err(StoreError::IncompatibleGraphReference {
                source: SavedVaultEntityKind::Group,
                target: SavedVaultEntityKind::Snippet,
            })
        ));

        let absent = SavedVaultGraph::new_with_proxy_profiles(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![group],
        );
        let revision = store
            .assess_graph_import(&absent)
            .expect("absent catalog retains group script edge")
            .into_revision();
        store
            .commit_graph_import(revision, absent)
            .expect("persist group without an included snippet catalog");

        let explicit_empty = graph_with_notes_snippets(
            Vec::new(),
            SavedNotesSnippetsCatalog::from_parts(Some(Vec::new()), None, None, None)
                .expect("explicit empty snippets"),
        );
        assert!(matches!(
            store.assess_graph_import(&explicit_empty),
            Err(StoreError::MissingGraphReference {
                source: SavedVaultEntityKind::Group,
                target: SavedVaultEntityKind::Snippet,
            })
        ));
    }

    #[test]
    fn notes_snippets_survive_host_mutation_and_ab_fallback() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let catalog = SavedNotesSnippetsCatalog::from_parts(
            Some(vec![snippet(
                "fallback-script",
                "Fallback",
                SavedSnippetKind::Script,
                None,
            )]),
            Some(vec!["fallback-package".to_owned()]),
            Some(vec![note("fallback-note", "Fallback", None)]),
            Some(vec!["Fallback".to_owned()]),
        )
        .expect("catalog");
        let graph = graph_with_notes_snippets(Vec::new(), catalog.clone());
        let revision = store
            .assess_graph_import(&graph)
            .expect("assessment")
            .into_revision();
        store
            .commit_graph_import(revision, graph)
            .expect("generation one");

        store
            .create(SavedHostDraft::ssh_password(
                "ordinary.example.com",
                "alice",
            ))
            .expect("ordinary host mutation");
        assert_eq!(
            store.graph().expect("generation two").notes_snippets(),
            &catalog
        );
        fs::write(
            latest_snapshot(&vault.join(SLOT_B_DIRECTORY)),
            b"corrupt generation two",
        )
        .expect("corrupt latest");
        drop(store);

        let reopened = SavedHostStore::open(&vault).expect("fallback reopen");
        assert_eq!(
            reopened.graph().expect("fallback graph").notes_snippets(),
            &catalog
        );
        assert!(reopened.list().expect("fallback hosts").is_empty());
    }

    #[test]
    fn graph_replacement_seals_notes_snippets_and_can_remove_the_catalog() {
        let (_root, store) = store();
        let catalog = SavedNotesSnippetsCatalog::from_parts(
            Some(vec![snippet(
                "replacement-script",
                "Replacement",
                SavedSnippetKind::Script,
                None,
            )]),
            None,
            None,
            None,
        )
        .expect("catalog");
        let graph = graph_with_notes_snippets(Vec::new(), catalog);
        let revision = store
            .assess_graph_import(&graph)
            .expect("assessment")
            .into_revision();
        store
            .commit_graph_import(revision, graph)
            .expect("seed catalog");

        let durable = store
            .confirm_current_snapshot_durability()
            .expect("durable graph");
        let removal = SavedVaultGraph::default();
        let plan = store
            .plan_graph_replacement(durable.revision().clone(), &removal)
            .expect("removal plan");
        assert!(plan.has_changes());

        let changed_target = graph_with_notes_snippets(
            Vec::new(),
            SavedNotesSnippetsCatalog::from_parts(Some(Vec::new()), None, None, None)
                .expect("changed target"),
        );
        assert!(matches!(
            store.commit_planned_graph_replacement(plan, changed_target),
            Err(StoreError::GraphReplacementPlanMismatch)
        ));
        assert!(
            !store
                .graph()
                .expect("unchanged graph")
                .notes_snippets()
                .is_absent()
        );

        let current = store
            .confirm_current_snapshot_durability()
            .expect("current graph");
        let plan = store
            .plan_graph_replacement(current.revision().clone(), &removal)
            .expect("fresh removal plan");
        let committed = store
            .commit_planned_graph_replacement(plan, removal)
            .expect("remove catalog");
        assert!(committed.changed());
        assert!(committed.graph().notes_snippets().is_absent());
    }

    #[test]
    fn graph_commitment_covers_every_notes_snippets_persistent_field() {
        let (_root, store) = store();
        let host = import_candidate("commitment-notes-host", "commitment.example.com");
        let mut snippet_draft =
            SavedSnippetDraft::new("commitment-script", "Commitment", "echo commitment");
        snippet_draft.tags = Some(vec!["tag".to_owned()]);
        snippet_draft.package = Some("package".to_owned());
        snippet_draft.targets = Some(vec![host.id.as_str().to_owned()]);
        snippet_draft.target_groups = Some(vec!["Target/Group".to_owned()]);
        snippet_draft.targets_all_hosts = Some(false);
        snippet_draft.shortkey = Some("ctrl+k".to_owned());
        snippet_draft.no_auto_run = Some(false);
        snippet_draft.multi_line_run_mode = Some(SavedSnippetMultiLineRunMode::LineDelay);
        snippet_draft.order = Some(1.0);
        snippet_draft.kind = Some(SavedSnippetKind::Script);
        snippet_draft.language = Some(SavedScriptLanguage::JavaScript);
        snippet_draft.description = Some("description".to_owned());
        snippet_draft.trigger = Some(SavedScriptTrigger::OnConnect);
        snippet_draft.trigger_pattern = Some("pattern".to_owned());
        let snippet = SavedSnippet::from_draft(snippet_draft).expect("snippet");
        let mut note_draft = SavedVaultNoteDraft::new(
            "commitment-note",
            "Commitment note",
            "note content",
            10.0,
            11.0,
        );
        note_draft.group = Some("Note/Group".to_owned());
        note_draft.tags = Some(vec!["note-tag".to_owned()]);
        note_draft.linked_host_ids = Some(vec![host.id.as_str().to_owned()]);
        note_draft.order = Some(2.0);
        let note = SavedVaultNote::from_draft(note_draft).expect("note");
        let graph = graph_with_notes_snippets(
            vec![host],
            SavedNotesSnippetsCatalog::from_parts(
                Some(vec![snippet]),
                Some(vec!["package".to_owned()]),
                Some(vec![note]),
                Some(vec!["Note/Group".to_owned()]),
            )
            .expect("catalog"),
        );
        let revision = store
            .assess_graph_import(&graph)
            .expect("assessment")
            .into_revision();
        store
            .commit_graph_import(revision, graph)
            .expect("seed graph");
        let durable = store
            .confirm_current_snapshot_durability()
            .expect("durable graph");
        let baseline = durable.commitment().clone();
        let revision = durable.revision().clone();
        let graph = durable.graph().clone();

        let variants = [
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["snippets"][0]["id"] = serde_json::json!("changed-id")
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["snippets"][0]["label"] = serde_json::json!("Changed")
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["snippets"][0]["command"] = serde_json::json!("echo changed")
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["snippets"][0]["tags"] = serde_json::json!(["changed"])
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["snippets"][0]["package"] = serde_json::json!("changed")
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["snippets"][0]["targets"] = serde_json::json!([])
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["snippets"][0]["targetGroups"] = serde_json::json!([])
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["snippets"][0]["targetsAllHosts"] = serde_json::json!(true)
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["snippets"][0]["shortkey"] = serde_json::json!("ctrl+x")
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["snippets"][0]["noAutoRun"] = serde_json::json!(true)
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["snippets"][0]["multiLineRunMode"] =
                    serde_json::json!("paste")
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["snippets"][0]["order"] = serde_json::json!(3.0)
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["snippets"][0]["kind"] = serde_json::json!("snippet")
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["snippets"][0]["language"] = serde_json::json!("python")
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["snippets"][0]["description"] = serde_json::json!("changed")
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["snippets"][0]["trigger"] = serde_json::json!("manual")
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["snippets"][0]["triggerPattern"] =
                    serde_json::json!("changed")
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["snippetPackages"] = serde_json::json!(["changed"])
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["notes"][0]["id"] = serde_json::json!("changed-note-id")
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["notes"][0]["title"] = serde_json::json!("Changed")
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["notes"][0]["content"] = serde_json::json!("changed")
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["notes"][0]["group"] = serde_json::json!("Changed/Group")
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["notes"][0]["tags"] = serde_json::json!(["changed"])
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["notes"][0]["linkedHostIds"] = serde_json::json!([])
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["notes"][0]["createdAt"] = serde_json::json!(12.0)
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["notes"][0]["updatedAt"] = serde_json::json!(13.0)
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["notes"][0]["order"] = serde_json::json!(4.0)
            }),
            graph_json_variant(&graph, |value| {
                value["notesSnippets"]["noteGroups"] = serde_json::json!(["Changed/Group"])
            }),
        ];
        for variant in variants {
            let plan = store
                .plan_graph_replacement(revision.clone(), &variant)
                .expect("variant plan");
            assert_ne!(plan.after_graph_commitment(), &baseline);
        }

        let absent_plan = store
            .plan_graph_replacement(revision.clone(), &SavedVaultGraph::default())
            .expect("absent plan");
        let explicit_empty = graph_with_notes_snippets(
            Vec::new(),
            SavedNotesSnippetsCatalog::from_parts(Some(Vec::new()), None, None, None)
                .expect("explicit empty"),
        );
        let empty_plan = store
            .plan_graph_replacement(revision, &explicit_empty)
            .expect("explicit-empty plan");
        assert_ne!(
            absent_plan.after_graph_commitment(),
            empty_plan.after_graph_commitment()
        );
    }

    #[test]
    fn corrupt_latest_slot_recovers_the_other_slot() {
        let (root, store) = store();
        let created = store
            .create(SavedHostDraft::ssh_password("host.example.com", "user"))
            .expect("create");
        store
            .update(&created.id, created.revision, label_update("updated"))
            .expect("update");
        fs::write(
            latest_snapshot(&root.path().join("vault").join(SLOT_B_DIRECTORY)),
            b"corrupt",
        )
        .expect("corrupt latest");

        let reopened = SavedHostStore::open(root.path().join("vault")).expect("recover");
        let recovered = reopened.list().expect("list recovered");
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].label, "host.example.com");
        assert_eq!(recovered[0].revision, 1);
    }

    #[test]
    fn both_corrupt_slots_fail_closed() {
        let (root, store) = store();
        let created = store
            .create(SavedHostDraft::ssh_password("host.example.com", "user"))
            .expect("create");
        store
            .update(&created.id, created.revision, label_update("updated"))
            .expect("update");
        for slot in [SLOT_A_DIRECTORY, SLOT_B_DIRECTORY] {
            fs::write(
                latest_snapshot(&root.path().join("vault").join(slot)),
                b"corrupt",
            )
            .expect("corrupt slot");
        }
        assert!(matches!(
            SavedHostStore::open(root.path().join("vault")),
            Err(StoreError::BothSlotsCorrupt)
        ));
    }

    #[test]
    fn stale_revision_is_rejected_without_mutation() {
        let (_root, store) = store();
        let created = store
            .create(SavedHostDraft::ssh_password("host.example.com", "user"))
            .expect("create");
        let updated = store
            .update(&created.id, 1, label_update("new"))
            .expect("first update");
        assert!(matches!(
            store.update(&created.id, 1, label_update("stale")),
            Err(StoreError::RevisionConflict { actual: 2, .. })
        ));
        assert_eq!(store.get(&created.id).expect("get").expect("host"), updated);
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let (_root, store) = store();
        let host = store
            .create(SavedHostDraft::ssh_password("host.example.com", "user"))
            .expect("create");
        let mut hosts = vec![host.clone(), host];
        assert!(matches!(
            normalize_hosts(&mut hosts),
            Err(StoreError::DuplicateId(_))
        ));
    }

    #[test]
    fn validation_covers_ports_whitespace_controls_lengths_and_at_usernames() {
        let (_root, store) = store();
        let accepted = store
            .create(SavedHostDraft::ssh_password(
                "host.example.com",
                "alice@example.com",
            ))
            .expect("at-sign username");
        assert_eq!(accepted.username, "alice@example.com");

        for (hostname, port) in [
            ("bad host".to_owned(), None),
            ("bad\nhost".to_owned(), None),
            ("h".repeat(254), None),
            ("host".to_owned(), Some(0)),
            ("host".to_owned(), Some(65_536)),
        ] {
            let mut draft = SavedHostDraft::ssh_password(hostname, "user");
            draft.port = port;
            assert!(matches!(
                store.create(draft),
                Err(StoreError::Validation(_))
            ));
        }

        let mut bad_label = SavedHostDraft::ssh_password("host", "user");
        bad_label.label = Some("bad\0label".to_owned());
        assert!(matches!(
            store.create(bad_label),
            Err(StoreError::Validation(ValidationError::UnsafeCharacters(
                "label"
            )))
        ));
    }

    #[test]
    fn publication_never_overwrites_an_unknown_file() {
        let root = TempDir::new().expect("temp");
        let target = root.path().join("reserved.json");
        fs::write(&target, b"unknown").expect("seed unknown");
        assert!(matches!(
            publish_named_no_overwrite(root.path(), "reserved.json", ".test", b"netcatty"),
            Err(StoreError::ArtifactConflict)
        ));
        assert_eq!(fs::read(&target).expect("read unknown"), b"unknown");
    }

    #[test]
    fn clones_share_a_single_process_lock() {
        let (_root, store) = store();
        let store = Arc::new(store);
        let workers = (0..8)
            .map(|index| {
                let store = store.clone();
                thread::spawn(move || {
                    store
                        .create(SavedHostDraft::ssh_password(
                            format!("host-{index}.example.com"),
                            "user",
                        ))
                        .expect("concurrent create");
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().expect("worker");
        }
        assert_eq!(store.list().expect("list").len(), 8);
    }

    #[test]
    fn successful_commits_compact_only_owned_snapshots_in_the_written_slot() {
        let (root, store) = store();
        let mut current = store
            .create(SavedHostDraft::ssh_password("host.example.com", "user"))
            .expect("create");
        let vault = root.path().join("vault");
        let unknown_snapshot =
            "snapshot-00000000000000000000-11111111111111111111111111111111.json";
        let unknown_temp = ".snapshot-22222222222222222222222222222222.tmp";
        for directory in [SLOT_A_DIRECTORY, SLOT_B_DIRECTORY] {
            fs::write(vault.join(directory).join(unknown_snapshot), b"foreign")
                .expect("seed unknown snapshot");
            fs::write(vault.join(directory).join(unknown_temp), b"foreign")
                .expect("seed unknown temp");
        }

        for index in 0..7 {
            current = store
                .update(
                    &current.id,
                    current.revision,
                    label_update(&format!("updated-{index}")),
                )
                .expect("update");
        }

        for (directory, slot) in [(SLOT_A_DIRECTORY, Slot::A), (SLOT_B_DIRECTORY, Slot::B)] {
            let directory = vault.join(directory);
            let valid_snapshots = fs::read_dir(&directory)
                .expect("read slot")
                .filter_map(Result::ok)
                .filter_map(|entry| {
                    let generation = parse_snapshot_name(entry.file_name().to_str()?)?;
                    read_snapshot(&entry.path(), store.store_id.as_ref(), slot, generation)
                        .is_ok()
                        .then_some(())
                })
                .count();
            assert_eq!(valid_snapshots, 1);
            assert_eq!(
                fs::read(directory.join(unknown_snapshot)).expect("unknown snapshot retained"),
                b"foreign"
            );
            assert_eq!(
                fs::read(directory.join(unknown_temp)).expect("unknown temp retained"),
                b"foreign"
            );
        }
    }

    #[test]
    fn batch_import_appends_all_hosts_in_one_generation() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let candidates = vec![
            import_candidate("legacy-a", "a.example.com"),
            import_candidate("legacy-b", "b.example.com"),
            import_candidate("legacy-c", "c.example.com"),
        ];
        let assessment = store.assess_import(&candidates).expect("assess batch");
        assert_eq!(assessment.revision().loaded_generation(), 0);
        assert_eq!(assessment.revision().max_seen_generation(), 0);
        assert_eq!(
            assessment.dispositions(),
            &[
                SavedHostImportDisposition::Importable,
                SavedHostImportDisposition::Importable,
                SavedHostImportDisposition::Importable,
            ]
        );

        let revision_json = serde_json::to_string(assessment.revision()).expect("serialize token");
        let mut tampered_json: serde_json::Value =
            serde_json::from_str(&revision_json).expect("revision JSON");
        tampered_json["seal"] = serde_json::Value::String("00".repeat(32));
        let tampered = serde_json::from_value(tampered_json).expect("well-shaped forged token");
        assert!(matches!(
            store.commit_import(tampered, Vec::new()),
            Err(StoreError::InventoryRevisionConflict { .. })
        ));
        assert_eq!(snapshot_count(&vault), 0);

        let revision = serde_json::from_str(&revision_json).expect("deserialize token");
        let committed = store
            .commit_import(revision, candidates.clone())
            .expect("commit batch");
        assert_eq!(committed.imported(), candidates.as_slice());
        assert_eq!(committed.revision().loaded_generation(), 1);
        assert_eq!(committed.revision().max_seen_generation(), 1);
        assert_eq!(snapshot_count(&vault), 1);
        assert_eq!(store.list().expect("list imported").len(), 3);
    }

    #[test]
    fn stale_or_foreign_inventory_revision_is_rejected_before_import() {
        let (_root, primary_store) = store();
        let candidate = import_candidate("legacy-stale", "stale.example.com");
        let stale = primary_store
            .assess_import(std::slice::from_ref(&candidate))
            .expect("stale assessment")
            .into_revision();
        primary_store
            .create(SavedHostDraft::ssh_password(
                "concurrent.example.com",
                "user",
            ))
            .expect("concurrent mutation");

        let error = primary_store
            .commit_import(stale, vec![candidate.clone()])
            .expect_err("stale revision");
        assert!(matches!(
            error,
            StoreError::InventoryRevisionConflict { .. }
        ));
        assert!(primary_store.get(&candidate.id).expect("lookup").is_none());

        let (other_root, other_store) = store();
        let foreign = other_store
            .assess_import(std::slice::from_ref(&candidate))
            .expect("foreign assessment")
            .into_revision();
        assert!(matches!(
            primary_store.commit_import(foreign, vec![candidate]),
            Err(StoreError::InventoryRevisionConflict { .. })
        ));
        drop(other_root);
    }

    #[test]
    fn identical_ids_are_duplicates_but_changed_content_conflicts() {
        let (root, store) = store();
        let existing = store
            .create(SavedHostDraft::ssh_password("existing.example.com", "user"))
            .expect("existing host");
        let vault = root.path().join("vault");
        let before = snapshot_count(&vault);

        let mut duplicate = existing.clone();
        duplicate.record_version = 99;
        duplicate.revision = 77;
        duplicate.created_at = 1;
        duplicate.updated_at = 2;
        let duplicate_assessment = store
            .assess_import(std::slice::from_ref(&duplicate))
            .expect("assess duplicate");
        assert_eq!(
            duplicate_assessment.dispositions(),
            &[SavedHostImportDisposition::Duplicate]
        );
        let duplicate_commit = store
            .commit_import(duplicate_assessment.into_revision(), vec![duplicate])
            .expect("idempotent duplicate");
        assert!(duplicate_commit.imported().is_empty());
        assert_eq!(snapshot_count(&vault), before);

        let mut conflict = existing;
        conflict.label = "Different label".to_owned();
        let newcomer = import_candidate("new-before-conflict", "new.example.com");
        let conflicting_batch = vec![newcomer.clone(), conflict];
        let conflict_assessment = store
            .assess_import(&conflicting_batch)
            .expect("assess conflict");
        assert_eq!(
            conflict_assessment.dispositions(),
            &[
                SavedHostImportDisposition::Importable,
                SavedHostImportDisposition::Conflict,
            ]
        );
        assert!(matches!(
            store.commit_import(conflict_assessment.into_revision(), conflicting_batch),
            Err(StoreError::ImportConflict(_))
        ));
        assert!(store.get(&newcomer.id).expect("newcomer lookup").is_none());
        assert_eq!(snapshot_count(&vault), before);
    }

    #[test]
    fn duplicate_ids_inside_an_import_source_fail_without_a_snapshot() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let first = import_candidate("repeated-id", "first.example.com");
        let mut second = first.clone();
        second.hostname = "second.example.com".to_owned();
        second.label = second.hostname.clone();
        let candidates = vec![first, second];
        assert!(matches!(
            store.assess_import(&candidates),
            Err(StoreError::DuplicateId(_))
        ));

        let revision = store
            .assess_import(&[])
            .expect("empty assessment")
            .into_revision();
        assert!(matches!(
            store.commit_import(revision, candidates),
            Err(StoreError::DuplicateId(_))
        ));
        assert_eq!(snapshot_count(&vault), 0);
    }

    #[test]
    fn matching_endpoints_with_distinct_ids_are_both_importable() {
        let (_root, store) = store();
        let candidates = vec![
            import_candidate("endpoint-alias-a", "same.example.com"),
            import_candidate("endpoint-alias-b", "same.example.com"),
        ];
        let assessment = store.assess_import(&candidates).expect("assess aliases");
        assert_eq!(
            assessment.dispositions(),
            &[
                SavedHostImportDisposition::Importable,
                SavedHostImportDisposition::Importable,
            ]
        );
        let committed = store
            .commit_import(assessment.into_revision(), candidates)
            .expect("commit aliases");
        assert_eq!(committed.imported().len(), 2);
    }

    #[test]
    fn recovery_revision_keeps_max_seen_generation_and_never_rolls_back() {
        let (root, store) = store();
        let created = store
            .create(SavedHostDraft::ssh_password("host.example.com", "user"))
            .expect("generation one");
        store
            .update(
                &created.id,
                created.revision,
                label_update("generation two"),
            )
            .expect("generation two");
        let vault = root.path().join("vault");
        fs::write(
            latest_snapshot(&vault.join(SLOT_B_DIRECTORY)),
            b"corrupt generation two",
        )
        .expect("corrupt latest slot");

        let candidate = import_candidate("post-recovery", "recovered.example.com");
        let assessment = store
            .assess_import(std::slice::from_ref(&candidate))
            .expect("recover inventory");
        assert_eq!(assessment.revision().loaded_generation(), 1);
        assert_eq!(assessment.revision().max_seen_generation(), 2);
        let committed = store
            .commit_import(assessment.into_revision(), vec![candidate])
            .expect("commit after recovery");
        assert_eq!(committed.revision().loaded_generation(), 3);
        assert_eq!(committed.revision().max_seen_generation(), 3);

        let reopened = SavedHostStore::open(vault).expect("reopen generation three");
        let revision = reopened
            .assess_import(&[])
            .expect("load latest inventory")
            .into_revision();
        assert_eq!(revision.loaded_generation(), 3);
        assert_eq!(revision.max_seen_generation(), 3);
    }

    #[test]
    fn legacy_v1_host_snapshot_reopens_and_the_next_commit_writes_v4() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let host = import_candidate("legacy-v1-host", "legacy-v1.example.com");
        let checksum = snapshot_checksum_v1(
            store.store_id.as_ref(),
            Slot::A,
            1,
            std::slice::from_ref(&host),
        )
        .expect("v1 checksum");
        let legacy = serde_json::json!({
            "magic": SNAPSHOT_MAGIC,
            "formatVersion": 1,
            "storeId": store.store_id.as_ref(),
            "slot": "a",
            "generation": 1,
            "hosts": [host],
            "checksum": checksum
        });
        fs::write(
            vault
                .join(SLOT_A_DIRECTORY)
                .join("snapshot-00000000000000000001-11111111111111111111111111111111.json"),
            serde_json::to_vec(&legacy).expect("legacy JSON"),
        )
        .expect("seed v1 snapshot");
        drop(store);

        let reopened = SavedHostStore::open(&vault).expect("open legacy v1 store");
        assert_eq!(reopened.list().expect("legacy hosts").len(), 1);
        assert!(
            reopened
                .list_ssh_key_references()
                .expect("legacy keys")
                .is_empty()
        );
        assert!(
            reopened
                .list_identity_references()
                .expect("legacy identities")
                .is_empty()
        );
        reopened
            .create(SavedHostDraft::ssh_password("new.example.com", "user"))
            .expect("upgrade commit");

        let v4: serde_json::Value = serde_json::from_slice(
            &fs::read(latest_snapshot(&vault.join(SLOT_B_DIRECTORY))).expect("read v4"),
        )
        .expect("v4 JSON");
        assert_eq!(v4["formatVersion"], SNAPSHOT_FORMAT_V8);
        assert_eq!(v4["proxyProfiles"], serde_json::json!([]));
        assert_eq!(v4["groups"], serde_json::json!([]));
        assert!(v4["sshKeyReferences"].is_array());
        assert!(v4["managedSshKeys"].is_array());
        assert!(v4["identityReferences"].is_array());
        assert!(v4["passwordIdentities"].is_array());
    }

    #[test]
    fn legacy_v2_checksum_and_no_managed_commitment_remain_golden() {
        const STORE_ID: &str = "11111111111111111111111111111111";
        const V2_CHECKSUM: &str =
            "bc5cbd89930f887b485ffcd15a1ec7a372269ad5d0933615fd4b2b12e8b2d807";
        const V1_COMMITMENT: &str =
            "bf4094ef99ba447f3b710445e1c4738d38c806cbecd11d4fe18de131998b108f";
        const V3_EMPTY_CHECKSUM: &str =
            "e62440dc40a6fa87fe2bb38c367d776811ea2b433b654f0b90dea5abc8e98e71";

        let key = reference_key("legacy-v2-key", "Legacy V2 Key", "D:\\keys\\legacy-v2");
        let identity =
            identity_reference("legacy-v2-identity", "Legacy V2 Identity", key.id.as_str());
        let checksum = snapshot_checksum_v2(
            STORE_ID,
            Slot::A,
            1,
            &[],
            std::slice::from_ref(&key),
            std::slice::from_ref(&identity),
        )
        .expect("legacy v2 checksum");
        assert_eq!(checksum, V2_CHECKSUM);
        assert_eq!(
            snapshot_checksum_v3(STORE_ID, Slot::A, 1, &[], &[], &[], &[])
                .expect("legacy v3 empty checksum"),
            V3_EMPTY_CHECKSUM
        );

        let loaded = LoadedStore {
            generation: 1,
            max_seen_generation: 1,
            snapshot_path: None,
            hosts: Vec::new(),
            ssh_key_references: vec![key],
            managed_ssh_keys: Vec::new(),
            identity_references: vec![identity],
            password_identities: Vec::new(),
            proxy_profiles: Vec::new(),
            groups: Vec::new(),
            custom_groups: None,
            notes_snippets: Default::default(),
            port_forward_rules: Vec::new(),
            known_hosts: Vec::new(),
            connection_logs: Vec::new(),
        };
        assert_eq!(
            loaded
                .graph_commitment(STORE_ID)
                .expect("legacy graph commitment")
                .as_str(),
            V1_COMMITMENT
        );
    }

    #[test]
    fn legacy_v2_graph_snapshot_reopens_and_upgrades_without_auth_method_drift() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let mut key = reference_key("legacy-v2-open-key", "Legacy key", "D:\\keys\\legacy");
        // Snapshot v2 allowed compatibility categories. The path itself is
        // reselected before use, so upgrading must not reject that metadata.
        key.category = SavedSshKeyCategory::compatible("legacy-plugin-category");
        let identity = identity_reference(
            "legacy-v2-open-identity",
            "Legacy identity",
            key.id.as_str(),
        );
        let checksum = snapshot_checksum_v2(
            store.store_id.as_ref(),
            Slot::A,
            1,
            &[],
            std::slice::from_ref(&key),
            std::slice::from_ref(&identity),
        )
        .expect("v2 checksum");
        let mut identity_json = serde_json::to_value(&identity).expect("identity JSON");
        identity_json
            .as_object_mut()
            .expect("identity object")
            .remove("authMethod");
        let legacy = serde_json::json!({
            "magic": SNAPSHOT_MAGIC,
            "formatVersion": 2,
            "storeId": store.store_id.as_ref(),
            "slot": "a",
            "generation": 1,
            "hosts": [],
            "sshKeyReferences": [key],
            "identityReferences": [identity_json],
            "checksum": checksum
        });
        fs::write(
            vault
                .join(SLOT_A_DIRECTORY)
                .join("snapshot-00000000000000000001-22222222222222222222222222222222.json"),
            serde_json::to_vec(&legacy).expect("legacy v2 JSON"),
        )
        .expect("seed v2 snapshot");
        drop(store);

        let reopened = SavedHostStore::open(&vault).expect("open legacy v2 store");
        let identities = reopened
            .list_identity_references()
            .expect("legacy identities");
        assert_eq!(identities.len(), 1);
        assert!(identities[0].auth_method.is_key());
        reopened
            .create(SavedHostDraft::ssh_password("upgrade.example.com", "user"))
            .expect("v4 upgrade commit");
        let upgraded: serde_json::Value = serde_json::from_slice(
            &fs::read(latest_snapshot(&vault.join(SLOT_B_DIRECTORY))).expect("read v4"),
        )
        .expect("v4 JSON");
        assert_eq!(upgraded["formatVersion"], SNAPSHOT_FORMAT_V8);
        assert_eq!(upgraded["proxyProfiles"], serde_json::json!([]));
        assert_eq!(upgraded["groups"], serde_json::json!([]));
        assert_eq!(upgraded["managedSshKeys"], serde_json::json!([]));
        assert_eq!(upgraded["identityReferences"][0]["authMethod"], "key");
    }

    #[test]
    fn snapshot_versions_reject_managed_catalog_presence_ambiguity() {
        let key = reference_key("presence-key", "Presence key", "D:\\keys\\presence");
        let identity =
            identity_reference("presence-identity", "Presence identity", key.id.as_str());
        let checksum = snapshot_checksum_v2(
            "11111111111111111111111111111111",
            Slot::A,
            1,
            &[],
            std::slice::from_ref(&key),
            std::slice::from_ref(&identity),
        )
        .expect("v2 checksum");
        let mut identity_json = serde_json::to_value(identity).expect("identity JSON");
        identity_json
            .as_object_mut()
            .expect("identity object")
            .remove("authMethod");
        let base_v2 = serde_json::json!({
            "magic": SNAPSHOT_MAGIC,
            "formatVersion": 2,
            "storeId": "11111111111111111111111111111111",
            "slot": "a",
            "generation": 1,
            "hosts": [],
            "sshKeyReferences": [key],
            "identityReferences": [identity_json],
            "checksum": checksum
        });
        for managed_value in [serde_json::Value::Null, serde_json::json!([])] {
            let mut invalid = base_v2.clone();
            invalid["managedSshKeys"] = managed_value;
            let envelope: SnapshotEnvelope =
                serde_json::from_value(invalid).expect("syntactically valid v2 envelope");
            assert!(matches!(
                envelope.validate(
                    "11111111111111111111111111111111",
                    Slot::A,
                    1,
                    std::path::PathBuf::from("legacy-v2.json"),
                ),
                Err(StoreError::BothSlotsCorrupt)
            ));
        }

        let base_v3 = legacy_v3_snapshot_json(
            "11111111111111111111111111111111",
            Slot::A,
            1,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        for managed_value in [None, Some(serde_json::Value::Null)] {
            let mut invalid = base_v3.clone();
            match managed_value {
                None => {
                    invalid
                        .as_object_mut()
                        .expect("v3 object")
                        .remove("managedSshKeys");
                }
                Some(value) => invalid["managedSshKeys"] = value,
            }
            let envelope: SnapshotEnvelope =
                serde_json::from_value(invalid).expect("syntactically valid v3 envelope");
            assert!(matches!(
                envelope.validate(
                    "11111111111111111111111111111111",
                    Slot::A,
                    1,
                    std::path::PathBuf::from("v3.json"),
                ),
                Err(StoreError::BothSlotsCorrupt)
            ));
        }
    }

    #[test]
    fn graph_import_is_one_snapshot_and_round_trips_relationships() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let key = reference_key(
            "opaque-key-sentinel",
            "Sensitive label sentinel",
            "D:\\sensitive-path-sentinel\\id_ed25519",
        );
        let identity = identity_reference(
            "opaque-identity-sentinel",
            "Identity label sentinel",
            key.id.as_str(),
        );
        let mut host_json = serde_json::to_value(import_candidate(
            "opaque-host-sentinel",
            "key-host.example.com",
        ))
        .expect("host JSON");
        host_json["authMethod"] = serde_json::json!("key");
        host_json["identityId"] = serde_json::json!(identity.id.as_str());
        host_json["identityFileId"] = serde_json::json!(key.id.as_str());
        let host: SavedHost = serde_json::from_value(host_json).expect("host references");
        let graph = SavedVaultGraph::new(
            vec![host.clone()],
            vec![key.clone()],
            vec![identity.clone()],
        );

        let assessment = store.assess_graph_import(&graph).expect("assess graph");
        assert_eq!(
            assessment.host_dispositions(),
            &[SavedHostImportDisposition::Importable]
        );
        assert_eq!(
            assessment.ssh_key_reference_dispositions(),
            &[SavedHostImportDisposition::Importable]
        );
        assert_eq!(
            assessment.identity_reference_dispositions(),
            &[SavedHostImportDisposition::Importable]
        );
        let preview = serde_json::to_string(&assessment).expect("assessment JSON");
        for sensitive in [
            "opaque-key-sentinel",
            "opaque-identity-sentinel",
            "opaque-host-sentinel",
            "Sensitive label sentinel",
            "sensitive-path-sentinel",
        ] {
            assert!(!preview.contains(sensitive));
        }

        let committed = store
            .commit_graph_import(assessment.into_revision(), graph)
            .expect("commit graph");
        assert_eq!(committed.imported().hosts(), std::slice::from_ref(&host));
        assert_eq!(
            committed.imported().ssh_key_references(),
            std::slice::from_ref(&key)
        );
        assert_eq!(
            committed.imported().identity_references(),
            std::slice::from_ref(&identity)
        );
        assert_eq!(snapshot_count(&vault), 1);

        drop(store);
        let reopened = SavedHostStore::open(&vault).expect("reopen graph store");
        let loaded = reopened.graph().expect("load graph");
        assert_eq!(loaded.hosts(), std::slice::from_ref(&host));
        assert_eq!(loaded.ssh_key_references(), std::slice::from_ref(&key));
        assert_eq!(
            loaded.identity_references(),
            std::slice::from_ref(&identity)
        );

        let snapshot = fs::read_to_string(latest_snapshot(&vault.join(SLOT_A_DIRECTORY)))
            .expect("v2 snapshot");
        assert!(snapshot.contains("sensitive-path-sentinel"));
        let lowered = snapshot.to_ascii_lowercase();
        for forbidden in [
            "\"password\":",
            "privatekey",
            "passphrase",
            "credentialref",
            "must-not-survive",
        ] {
            assert!(!lowered.contains(forbidden));
        }
    }

    #[test]
    fn graph_commitment_is_canonical_and_redacted_outside_serde() {
        let commitment = SavedVaultGraphCommitment::from_digest([0xab; 32]);
        let expected = "ab".repeat(32);
        assert_eq!(commitment.as_str(), expected);

        let encoded = serde_json::to_string(&commitment).expect("commitment JSON");
        assert_eq!(encoded, format!("\"{expected}\""));
        let decoded: SavedVaultGraphCommitment =
            serde_json::from_str(&encoded).expect("commitment round trip");
        assert_eq!(decoded, commitment);

        let debug = format!("{commitment:?}");
        let display = commitment.to_string();
        assert_eq!(debug, "SavedVaultGraphCommitment([redacted])");
        assert_eq!(display, "[redacted Vault graph commitment]");
        assert!(!debug.contains(commitment.as_str()));
        assert!(!display.contains(commitment.as_str()));

        for invalid in [
            "AB".repeat(32),
            "g0".repeat(32),
            "a".repeat(63),
            "a".repeat(65),
        ] {
            let encoded = serde_json::to_string(&invalid).expect("invalid JSON string");
            assert!(
                serde_json::from_str::<SavedVaultGraphCommitment>(&encoded).is_err(),
                "accepted non-canonical commitment {invalid}"
            );
        }
        assert!(serde_json::from_str::<SavedVaultGraphCommitment>("null").is_err());
    }

    #[test]
    fn graph_import_plan_is_read_only_secret_free_and_matches_durable_commitment() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let key = reference_key(
            "plan-key-opaque-sentinel",
            "Plan key label sentinel",
            "D:\\plan-path-sentinel\\id_ed25519",
        )
        .with_compatibility_field(
            "pluginMetadata",
            serde_json::json!({ "value": "plan-key-compat-sentinel" }),
        )
        .expect("key compatibility");
        let identity = identity_reference(
            "plan-identity-opaque-sentinel",
            "Plan identity label sentinel",
            key.id.as_str(),
        )
        .with_compatibility_field(
            "pluginMetadata",
            serde_json::json!({ "value": "plan-identity-compat-sentinel" }),
        )
        .expect("identity compatibility");
        let mut draft = SavedHostDraft::ssh_password(
            "plan-hostname-sentinel.example.com",
            "plan-username-sentinel",
        )
        .with_compatibility_field(
            "pluginMetadata",
            serde_json::json!({ "value": "plan-host-compat-sentinel" }),
        )
        .expect("host compatibility");
        draft.label = Some("Plan host label sentinel".to_owned());
        draft.port = Some(2222);
        let mut host = SavedHost::from_draft(draft, 17).expect("plan host");
        host.id = SavedHostId::from_opaque("plan-host-opaque-sentinel").expect("host ID");
        let mut host_json = serde_json::to_value(host).expect("host JSON");
        host_json["authMethod"] = serde_json::json!("key");
        host_json["identityId"] = serde_json::json!(identity.id.as_str());
        host_json["identityFileId"] = serde_json::json!(key.id.as_str());
        let host: SavedHost = serde_json::from_value(host_json).expect("host relationships");
        let graph = SavedVaultGraph::new(vec![host], vec![key], vec![identity]);

        let initial = store
            .confirm_current_snapshot_durability()
            .expect("confirm empty Vault");
        let assessment = store.assess_graph_import(&graph).expect("assessment");
        assert_eq!(assessment.revision(), initial.revision());
        let plan = store
            .plan_graph_import(assessment.revision().clone(), &graph)
            .expect("plan graph");

        assert_eq!(plan.revision(), assessment.revision());
        assert!(plan.has_changes());
        assert_eq!(plan.before_graph_commitment(), initial.commitment());
        assert_ne!(
            plan.before_graph_commitment(),
            plan.after_graph_commitment()
        );
        assert_eq!(snapshot_count(&vault), 0, "planning must not publish");

        let plan_debug = format!("{plan:?}");
        let serialized_commitment =
            serde_json::to_string(plan.after_graph_commitment()).expect("commitment JSON");
        for sensitive in [
            "plan-key-opaque-sentinel",
            "Plan key label sentinel",
            "plan-path-sentinel",
            "plan-key-compat-sentinel",
            "plan-identity-opaque-sentinel",
            "Plan identity label sentinel",
            "plan-identity-compat-sentinel",
            "plan-hostname-sentinel",
            "plan-username-sentinel",
            "Plan host label sentinel",
            "plan-host-compat-sentinel",
        ] {
            assert!(!plan_debug.contains(sensitive));
            assert!(!serialized_commitment.contains(sensitive));
        }
        assert!(!plan_debug.contains(plan.before_graph_commitment().as_str()));
        assert!(!plan_debug.contains(plan.after_graph_commitment().as_str()));

        let committed = store
            .commit_graph_import(plan.revision().clone(), graph)
            .expect("commit planned graph");
        let durable = store
            .confirm_current_snapshot_durability()
            .expect("confirm committed graph");
        assert_eq!(committed.revision(), durable.revision());
        assert_eq!(plan.after_graph_commitment(), durable.commitment());
        assert_eq!(snapshot_count(&vault), 1);
    }

    #[test]
    fn graph_commitment_covers_every_normalized_serialized_graph_field() {
        let (root, store) = store();
        let vault = root.path().join("vault");

        let mut host_one = import_candidate("commit-host-one", "one.example.com");
        host_one.label = "Host One".to_owned();
        host_one.port = 2201;
        host_one.username = "alice".to_owned();
        let mut host_two = import_candidate("commit-host-two", "two.example.com");
        host_two.label = "Host Two".to_owned();
        host_two.port = 2202;
        host_two.username = "bob".to_owned();

        let key_one = reference_key("commit-key-one", "Key One", "D:\\keys\\one");
        let key_two = reference_key("commit-key-two", "Key Two", "D:\\keys\\two");
        let unused_key = reference_key(
            "commit-key-unreferenced",
            "Key Unreferenced",
            "D:\\keys\\unused",
        );
        let identity_one =
            identity_reference("commit-identity-one", "Identity One", key_one.id.as_str());
        let identity_two =
            identity_reference("commit-identity-two", "Identity Two", key_two.id.as_str());
        let baseline_graph = SavedVaultGraph::new(
            vec![host_one, host_two],
            vec![key_one, key_two, unused_key],
            vec![identity_one, identity_two],
        );
        let revision = store
            .assess_graph_import(&baseline_graph)
            .expect("baseline assessment")
            .into_revision();
        let baseline = store
            .plan_graph_import(revision.clone(), &baseline_graph)
            .expect("baseline plan")
            .after_graph_commitment()
            .clone();

        let variants = vec![
            (
                "host.recordVersion",
                graph_json_variant(&baseline_graph, |value| {
                    value["hosts"][0]["recordVersion"] = serde_json::json!(2);
                }),
            ),
            (
                "host.id",
                graph_json_variant(&baseline_graph, |value| {
                    value["hosts"][0]["id"] = serde_json::json!("commit-host-one-variant");
                }),
            ),
            (
                "host.revision",
                graph_json_variant(&baseline_graph, |value| {
                    value["hosts"][0]["revision"] = serde_json::json!(2);
                }),
            ),
            (
                "host.label",
                graph_json_variant(&baseline_graph, |value| {
                    value["hosts"][0]["label"] = serde_json::json!("Host One Variant");
                }),
            ),
            (
                "host.hostname",
                graph_json_variant(&baseline_graph, |value| {
                    value["hosts"][0]["hostname"] = serde_json::json!("one-variant.example.com");
                }),
            ),
            (
                "host.port",
                graph_json_variant(&baseline_graph, |value| {
                    value["hosts"][0]["port"] = serde_json::json!(2299);
                }),
            ),
            (
                "host.username",
                graph_json_variant(&baseline_graph, |value| {
                    value["hosts"][0]["username"] = serde_json::json!("carol");
                }),
            ),
            (
                "host.protocol",
                graph_json_variant(&baseline_graph, |value| {
                    value["hosts"][0]["protocol"] = serde_json::json!("ssh-compatible");
                }),
            ),
            (
                "host.authMethod",
                graph_json_variant(&baseline_graph, |value| {
                    value["hosts"][0]["authMethod"] = serde_json::json!("password-compatible");
                }),
            ),
            (
                "host.authPolicyVersion",
                graph_json_variant(&baseline_graph, |value| {
                    value["hosts"][0]["authPolicyVersion"] = serde_json::json!(2);
                }),
            ),
            (
                "host.createdAt",
                graph_json_variant(&baseline_graph, |value| {
                    value["hosts"][0]["createdAt"] = serde_json::json!(9);
                }),
            ),
            (
                "host.updatedAt",
                graph_json_variant(&baseline_graph, |value| {
                    value["hosts"][0]["updatedAt"] = serde_json::json!(11);
                }),
            ),
            (
                "host.compatibility",
                graph_json_variant(&baseline_graph, |value| {
                    value["hosts"][0]["hostPluginState"] = serde_json::json!({ "mode": "variant" });
                }),
            ),
            (
                "key.id",
                graph_json_variant(&baseline_graph, |value| {
                    value["sshKeyReferences"][2]["id"] =
                        serde_json::json!("commit-key-unreferenced-variant");
                }),
            ),
            (
                "key.label",
                graph_json_variant(&baseline_graph, |value| {
                    value["sshKeyReferences"][0]["label"] = serde_json::json!("Key One Variant");
                }),
            ),
            (
                "key.filePath",
                graph_json_variant(&baseline_graph, |value| {
                    value["sshKeyReferences"][0]["filePath"] =
                        serde_json::json!("D:\\keys\\one-variant");
                }),
            ),
            (
                "key.category",
                graph_json_variant(&baseline_graph, |value| {
                    value["sshKeyReferences"][2]["category"] = serde_json::json!("certificate");
                }),
            ),
            (
                "key.createdAt",
                graph_json_variant(&baseline_graph, |value| {
                    value["sshKeyReferences"][0]["createdAt"] = serde_json::json!(9);
                }),
            ),
            (
                "key.updatedAt",
                graph_json_variant(&baseline_graph, |value| {
                    value["sshKeyReferences"][0]["updatedAt"] = serde_json::json!(11);
                }),
            ),
            (
                "key.compatibility",
                graph_json_variant(&baseline_graph, |value| {
                    value["sshKeyReferences"][0]["keyPluginState"] =
                        serde_json::json!({ "mode": "variant" });
                }),
            ),
            (
                "identity.id",
                graph_json_variant(&baseline_graph, |value| {
                    value["identityReferences"][0]["id"] =
                        serde_json::json!("commit-identity-one-variant");
                }),
            ),
            (
                "identity.label",
                graph_json_variant(&baseline_graph, |value| {
                    value["identityReferences"][0]["label"] =
                        serde_json::json!("Identity One Variant");
                }),
            ),
            (
                "identity.username",
                graph_json_variant(&baseline_graph, |value| {
                    value["identityReferences"][0]["username"] = serde_json::json!("variant-user");
                }),
            ),
            (
                "identity.keyId",
                graph_json_variant(&baseline_graph, |value| {
                    value["identityReferences"][0]["keyId"] = serde_json::json!("commit-key-two");
                }),
            ),
            (
                "identity.createdAt",
                graph_json_variant(&baseline_graph, |value| {
                    value["identityReferences"][0]["createdAt"] = serde_json::json!(9);
                }),
            ),
            (
                "identity.updatedAt",
                graph_json_variant(&baseline_graph, |value| {
                    value["identityReferences"][0]["updatedAt"] = serde_json::json!(11);
                }),
            ),
            (
                "identity.compatibility",
                graph_json_variant(&baseline_graph, |value| {
                    value["identityReferences"][0]["identityPluginState"] =
                        serde_json::json!({ "mode": "variant" });
                }),
            ),
        ];

        let mut observed = HashSet::from([baseline.as_str().to_owned()]);
        for (field, graph) in variants {
            let commitment = store
                .plan_graph_import(revision.clone(), &graph)
                .unwrap_or_else(|error| panic!("plan {field}: {error}"))
                .after_graph_commitment()
                .clone();
            assert_ne!(commitment, baseline, "changing {field} was not committed");
            assert!(
                observed.insert(commitment.as_str().to_owned()),
                "changing {field} reused another field variant's commitment"
            );
        }

        let reordered = graph_json_variant(&baseline_graph, |value| {
            value["hosts"]
                .as_array_mut()
                .expect("hosts array")
                .reverse();
            value["sshKeyReferences"]
                .as_array_mut()
                .expect("keys array")
                .reverse();
            value["identityReferences"]
                .as_array_mut()
                .expect("identities array")
                .reverse();
        });
        let reordered_commitment = store
            .plan_graph_import(revision, &reordered)
            .expect("reordered plan")
            .after_graph_commitment()
            .clone();
        assert_eq!(reordered_commitment, baseline);
        assert_eq!(
            snapshot_count(&vault),
            0,
            "projections must remain read-only"
        );
    }

    #[test]
    fn managed_key_v3_round_trip_and_single_slot_fallback_preserve_custody() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let managed = managed_key(
            "managed-roundtrip-key",
            "Managed roundtrip key",
            0x31,
            7,
            true,
            SavedSshKeyCategory::key(),
        );
        let identity = identity_reference(
            "managed-roundtrip-identity",
            "Managed identity",
            managed.id.as_str(),
        );
        let graph = SavedVaultGraph::new_with_managed_ssh_keys(
            Vec::new(),
            Vec::new(),
            vec![managed.clone()],
            vec![identity.clone()],
        );
        let assessment = store
            .assess_graph_import(&graph)
            .expect("assess managed graph");
        assert_eq!(
            assessment.managed_ssh_key_dispositions(),
            &[SavedHostImportDisposition::Importable]
        );
        store
            .commit_graph_import(assessment.into_revision(), graph)
            .expect("commit managed graph");
        assert_eq!(
            store.list_managed_ssh_keys().expect("managed keys"),
            vec![managed.clone()]
        );
        assert_eq!(
            store.list_identity_references().expect("identities"),
            vec![identity]
        );

        store
            .create(SavedHostDraft::ssh_password(
                "generation-two.example.com",
                "user",
            ))
            .expect("generation two");
        let generation_two = latest_snapshot(&vault.join(SLOT_B_DIRECTORY));
        fs::write(&generation_two, b"corrupt managed generation two").expect("corrupt latest slot");
        drop(store);

        let reopened = SavedHostStore::open(&vault).expect("fallback to managed generation one");
        let recovered = reopened
            .list_managed_ssh_keys()
            .expect("recovered managed key");
        assert_eq!(recovered, vec![managed]);
        assert!(reopened.list().expect("fallback hosts").is_empty());
    }

    #[test]
    fn managed_secret_retention_unions_current_and_fallback_revisions() {
        let (_root, store) = store();
        let revision_one = managed_key(
            "retained-real-entity-id",
            "Retained key",
            0x81,
            1,
            false,
            SavedSshKeyCategory::key(),
        );
        let revision_two = managed_key(
            "retained-real-entity-id",
            "Retained key",
            0x81,
            2,
            true,
            SavedSshKeyCategory::key(),
        );
        publish_managed_snapshot(&store, vec![revision_one]);
        publish_managed_snapshot(&store, vec![revision_two]);

        let retained = store
            .managed_secret_retention_set()
            .expect("complete A/B retention set");
        assert_eq!(retained.len(), 2);
        assert!(retained.iter().all(|item| {
            item.entity_id().as_str() == "retained-real-entity-id"
                && item.backend_locator().as_str() == "81".repeat(32)
        }));
        assert_eq!(
            retained
                .iter()
                .map(|item| item.custody_revision())
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        let debug = format!("{retained:?}");
        assert!(!debug.contains("retained-real-entity-id"));
        assert!(!debug.contains(&"81".repeat(32)));
    }

    #[test]
    fn managed_secret_retention_deduplicates_repeated_snapshot_references() {
        let (_root, store) = store();
        let managed = managed_key(
            "deduplicated-managed-entity",
            "Deduplicated key",
            0x82,
            7,
            false,
            SavedSshKeyCategory::key(),
        );
        publish_managed_snapshot(&store, vec![managed.clone()]);
        publish_managed_snapshot(&store, vec![managed]);

        let retained = store
            .managed_secret_retention_set()
            .expect("deduplicated retention set");
        assert_eq!(retained.len(), 1);
        assert_eq!(
            retained[0].entity_id().as_str(),
            "deduplicated-managed-entity"
        );
        assert_eq!(retained[0].custody_revision(), 7);
    }

    #[test]
    fn managed_secret_retention_is_empty_when_snapshots_have_no_managed_keys() {
        let (_root, store) = store();
        store
            .create(SavedHostDraft::ssh_password(
                "retention-empty.example.com",
                "user",
            ))
            .expect("publish host-only snapshot");
        assert!(
            store
                .managed_secret_retention_set()
                .expect("host-only retention set")
                .is_empty()
        );
    }

    #[test]
    fn managed_secret_retention_rejects_a_corrupt_only_slot() {
        let (root, store) = store();
        publish_managed_snapshot(
            &store,
            vec![managed_key(
                "corrupt-only-managed-entity",
                "Corrupt only key",
                0x83,
                1,
                false,
                SavedSshKeyCategory::key(),
            )],
        );
        fs::write(
            latest_snapshot(&root.path().join("vault").join(SLOT_A_DIRECTORY)),
            b"corrupt only retention slot",
        )
        .expect("corrupt only slot");

        assert!(matches!(
            store.managed_secret_retention_set(),
            Err(StoreError::ManagedSecretRetentionUncertain)
        ));
    }

    #[test]
    fn managed_secret_retention_rejects_a_corrupt_higher_generation() {
        let (root, store) = store();
        publish_managed_snapshot(
            &store,
            vec![managed_key(
                "corrupt-higher-managed-entity",
                "Corrupt higher key",
                0x84,
                1,
                false,
                SavedSshKeyCategory::key(),
            )],
        );
        publish_managed_snapshot(
            &store,
            vec![managed_key(
                "corrupt-higher-managed-entity",
                "Corrupt higher key",
                0x84,
                2,
                false,
                SavedSshKeyCategory::key(),
            )],
        );
        fs::write(
            latest_snapshot(&root.path().join("vault").join(SLOT_B_DIRECTORY)),
            b"corrupt higher retention generation",
        )
        .expect("corrupt higher generation");

        assert!(matches!(
            store.managed_secret_retention_set(),
            Err(StoreError::ManagedSecretRetentionUncertain)
        ));
    }

    #[test]
    fn managed_secret_retention_rejects_unknown_or_mixed_owner_artifacts() {
        let (unknown_root, unknown_store) = store();
        fs::write(
            unknown_root
                .path()
                .join("vault")
                .join(SLOT_A_DIRECTORY)
                .join("unknown-artifact"),
            b"unknown",
        )
        .expect("seed unknown artifact");
        assert!(matches!(
            unknown_store.managed_secret_retention_set(),
            Err(StoreError::ManagedSecretRetentionUncertain)
        ));

        let (mixed_root, mixed_store) = store();
        let mixed = SnapshotEnvelope::new(
            Uuid::new_v4().to_string(),
            Slot::A,
            1,
            Vec::new(),
            Vec::new(),
            vec![managed_key(
                "foreign-managed-entity",
                "Foreign key",
                0x85,
                1,
                false,
                SavedSshKeyCategory::key(),
            )],
            Vec::new(),
            Vec::new(),
        )
        .expect("foreign snapshot envelope");
        fs::write(
            mixed_root
                .path()
                .join("vault")
                .join(SLOT_A_DIRECTORY)
                .join("snapshot-00000000000000000001-11111111111111111111111111111111.json"),
            serde_json::to_vec(&mixed).expect("encode foreign snapshot"),
        )
        .expect("seed mixed-owner snapshot");
        assert!(matches!(
            mixed_store.managed_secret_retention_set(),
            Err(StoreError::ManagedSecretRetentionUncertain)
        ));
    }

    #[test]
    fn managed_and_reference_keys_share_one_id_namespace() {
        let (_root, store) = store();
        let reference = reference_key("shared-key-id", "Reference", "D:\\keys\\shared");
        let managed = managed_key(
            "shared-key-id",
            "Managed",
            0x32,
            1,
            false,
            SavedSshKeyCategory::key(),
        );
        let duplicate_catalog_graph = SavedVaultGraph::new_with_managed_ssh_keys(
            Vec::new(),
            vec![reference.clone()],
            vec![managed.clone()],
            Vec::new(),
        );
        assert!(matches!(
            store.assess_graph_import(&duplicate_catalog_graph),
            Err(StoreError::DuplicateGraphEntityId(
                SavedVaultEntityKind::ManagedSshKey
            ))
        ));

        let seed = SavedVaultGraph::new_with_managed_ssh_keys(
            Vec::new(),
            Vec::new(),
            vec![managed],
            Vec::new(),
        );
        let seed_revision = store
            .assess_graph_import(&seed)
            .expect("assess managed seed")
            .into_revision();
        store
            .commit_graph_import(seed_revision, seed)
            .expect("seed managed key");
        let assessment = store
            .assess_graph_import(&SavedVaultGraph::new(
                Vec::new(),
                vec![reference],
                Vec::new(),
            ))
            .expect("cross-catalog conflict is assessable");
        assert_eq!(
            assessment.ssh_key_reference_dispositions(),
            &[SavedHostImportDisposition::Conflict]
        );
    }

    #[test]
    fn certificate_identities_require_managed_certificate_custody() {
        let (_root, store) = store();
        let reference = SavedSshKeyReference::from_parts(
            SavedSshKeyReferenceId::from_opaque("reference-certificate").expect("key ID"),
            "Reference certificate",
            "D:\\keys\\certificate",
            SavedSshKeyCategory::certificate(),
            10,
            10,
            BTreeMap::new(),
        )
        .expect("reference certificate metadata");
        let reference_identity = SavedIdentityReference::from_certificate_parts(
            SavedIdentityReferenceId::from_opaque("reference-certificate-identity")
                .expect("identity ID"),
            "Reference certificate identity",
            "user",
            reference.id.clone(),
            10,
            10,
            BTreeMap::new(),
        )
        .expect("certificate identity");
        assert!(matches!(
            store.assess_graph_import(&SavedVaultGraph::new(
                Vec::new(),
                vec![reference],
                vec![reference_identity],
            )),
            Err(StoreError::IncompatibleGraphReference {
                source: SavedVaultEntityKind::IdentityReference,
                target: SavedVaultEntityKind::SshKeyReference,
            })
        ));

        let managed = managed_key(
            "managed-certificate",
            "Managed certificate",
            0x71,
            1,
            false,
            SavedSshKeyCategory::certificate(),
        );
        let managed_identity = SavedIdentityReference::from_certificate_parts(
            SavedIdentityReferenceId::from_opaque("managed-certificate-identity")
                .expect("identity ID"),
            "Managed certificate identity",
            "user",
            managed.id.clone(),
            10,
            10,
            BTreeMap::new(),
        )
        .expect("managed certificate identity");
        store
            .assess_graph_import(&SavedVaultGraph::new_with_managed_ssh_keys(
                Vec::new(),
                Vec::new(),
                vec![managed],
                vec![managed_identity],
            ))
            .expect("managed certificate graph");
    }

    #[test]
    fn managed_graph_plan_binds_locator_revision_and_passphrase_status() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let managed = managed_key(
            "planned-managed-key",
            "Planned managed key",
            0x41,
            3,
            false,
            SavedSshKeyCategory::key(),
        );
        let identity = identity_reference(
            "planned-managed-identity",
            "Planned identity",
            managed.id.as_str(),
        );
        let graph = SavedVaultGraph::new_with_managed_ssh_keys(
            Vec::new(),
            Vec::new(),
            vec![managed],
            vec![identity],
        );
        let revision = store
            .assess_graph_import(&graph)
            .expect("assess planned graph")
            .into_revision();
        let plan = store
            .plan_graph_import(revision, &graph)
            .expect("plan managed graph");

        let variants = [
            graph_json_variant(&graph, |value| {
                value["managedSshKeys"][0]["custody"]["backendLocator"] =
                    serde_json::json!("42".repeat(32));
            }),
            graph_json_variant(&graph, |value| {
                value["managedSshKeys"][0]["custody"]["custodyRevision"] = serde_json::json!(4);
            }),
            graph_json_variant(&graph, |value| {
                value["managedSshKeys"][0]["hasSavedPassphrase"] = serde_json::json!(true);
            }),
        ];
        for variant in variants {
            assert!(matches!(
                store.commit_planned_graph_import(plan.clone(), variant),
                Err(StoreError::GraphImportPlanMismatch)
            ));
            assert_eq!(snapshot_count(&vault), 0);
        }

        let committed = store
            .commit_planned_graph_import(plan.clone(), graph)
            .expect("commit exact managed plan");
        assert_eq!(committed.imported().managed_ssh_keys().len(), 1);
        let durable = store
            .confirm_current_snapshot_durability()
            .expect("confirm managed graph");
        assert_eq!(durable.commitment(), plan.after_graph_commitment());
    }

    #[test]
    fn managed_commitment_covers_every_custody_metadata_field() {
        let (_root, store) = store();
        let baseline_graph = SavedVaultGraph::new_with_managed_ssh_keys(
            Vec::new(),
            Vec::new(),
            vec![managed_key(
                "commit-managed-key",
                "Commit managed key",
                0x51,
                9,
                false,
                SavedSshKeyCategory::identity(),
            )],
            Vec::new(),
        );
        let revision = store
            .assess_graph_import(&baseline_graph)
            .expect("assess baseline")
            .into_revision();
        let baseline = store
            .plan_graph_import(revision.clone(), &baseline_graph)
            .expect("baseline commitment")
            .after_graph_commitment()
            .clone();
        let variants = [
            graph_json_variant(&baseline_graph, |value| {
                value["managedSshKeys"][0]["label"] = serde_json::json!("Changed label");
            }),
            graph_json_variant(&baseline_graph, |value| {
                value["managedSshKeys"][0]["category"] = serde_json::json!("key");
            }),
            graph_json_variant(&baseline_graph, |value| {
                value["managedSshKeys"][0]["source"] = serde_json::json!("generated");
            }),
            graph_json_variant(&baseline_graph, |value| {
                value["managedSshKeys"][0]["hasSavedPassphrase"] = serde_json::json!(true);
            }),
            graph_json_variant(&baseline_graph, |value| {
                value["managedSshKeys"][0]["custody"]["backendLocator"] =
                    serde_json::json!("52".repeat(32));
            }),
            graph_json_variant(&baseline_graph, |value| {
                value["managedSshKeys"][0]["custody"]["custodyRevision"] = serde_json::json!(10);
            }),
            graph_json_variant(&baseline_graph, |value| {
                value["managedSshKeys"][0]["createdAt"] = serde_json::json!(9);
            }),
            graph_json_variant(&baseline_graph, |value| {
                value["managedSshKeys"][0]["updatedAt"] = serde_json::json!(11);
            }),
            graph_json_variant(&baseline_graph, |value| {
                value["managedSshKeys"][0]["safeDisplayHint"] = serde_json::json!("variant");
            }),
        ];
        let mut observed = HashSet::from([baseline.as_str().to_owned()]);
        for variant in variants {
            let commitment = store
                .plan_graph_import(revision.clone(), &variant)
                .expect("managed variant commitment")
                .after_graph_commitment()
                .clone();
            assert_ne!(commitment, baseline);
            assert!(observed.insert(commitment.as_str().to_owned()));
        }
    }

    #[test]
    fn graph_import_duplicate_plan_is_a_no_op_without_a_snapshot() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let key = reference_key("duplicate-plan-key", "Key", "D:\\keys\\duplicate");
        let identity = identity_reference("duplicate-plan-identity", "Identity", key.id.as_str());
        let graph = SavedVaultGraph::new(
            vec![import_candidate(
                "duplicate-plan-host",
                "duplicate-plan.example.com",
            )],
            vec![key],
            vec![identity],
        );
        let first = store.assess_graph_import(&graph).expect("first assessment");
        store
            .commit_graph_import(first.into_revision(), graph.clone())
            .expect("first commit");
        let durable_before = store
            .confirm_current_snapshot_durability()
            .expect("confirm first commit");
        let snapshots_before = snapshot_count(&vault);

        let duplicate = store
            .assess_graph_import(&graph)
            .expect("duplicate assessment");
        let plan = store
            .plan_graph_import(duplicate.into_revision(), &graph)
            .expect("duplicate plan");
        assert!(!plan.has_changes());
        assert_eq!(
            plan.before_graph_commitment(),
            plan.after_graph_commitment()
        );
        assert_eq!(plan.before_graph_commitment(), durable_before.commitment());
        assert_eq!(snapshot_count(&vault), snapshots_before);

        let committed = store
            .commit_graph_import(plan.revision().clone(), graph)
            .expect("duplicate commit");
        assert!(committed.imported().is_empty());
        assert_eq!(committed.revision(), plan.revision());
        assert_eq!(snapshot_count(&vault), snapshots_before);
        let durable_after = store
            .confirm_current_snapshot_durability()
            .expect("confirm no-op commit");
        assert_eq!(durable_after.commitment(), durable_before.commitment());
    }

    #[test]
    fn graph_import_classifies_each_catalog_and_is_idempotent() {
        let (_root, store) = store();
        let key = reference_key("key-id", "Key", "D:\\keys\\id");
        let identity = identity_reference("identity-id", "Identity", key.id.as_str());
        let host = import_candidate("host-id", "graph.example.com");
        let graph = SavedVaultGraph::new(
            vec![host.clone()],
            vec![key.clone()],
            vec![identity.clone()],
        );
        let assessment = store.assess_graph_import(&graph).expect("first assessment");
        store
            .commit_graph_import(assessment.into_revision(), graph.clone())
            .expect("first commit");

        let duplicate = store.assess_graph_import(&graph).expect("duplicate graph");
        assert_eq!(
            duplicate.host_dispositions(),
            &[SavedHostImportDisposition::Duplicate]
        );
        assert_eq!(
            duplicate.ssh_key_reference_dispositions(),
            &[SavedHostImportDisposition::Duplicate]
        );
        assert_eq!(
            duplicate.identity_reference_dispositions(),
            &[SavedHostImportDisposition::Duplicate]
        );

        let changed_key = reference_key("key-id", "Changed", "D:\\keys\\id");
        let changed_identity = identity_reference("identity-id", "Changed", "key-id");
        let mut changed_host = host;
        changed_host.label = "Changed".to_owned();
        let conflicts = store
            .assess_graph_import(&SavedVaultGraph::new(
                vec![changed_host],
                vec![changed_key],
                vec![changed_identity],
            ))
            .expect("conflict assessment");
        assert_eq!(
            conflicts.host_dispositions(),
            &[SavedHostImportDisposition::Conflict]
        );
        assert_eq!(
            conflicts.ssh_key_reference_dispositions(),
            &[SavedHostImportDisposition::Conflict]
        );
        assert_eq!(
            conflicts.identity_reference_dispositions(),
            &[SavedHostImportDisposition::Conflict]
        );
    }

    #[test]
    fn graph_import_rejects_source_duplicates_missing_targets_and_stale_cas() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let key = reference_key("duplicate-key", "Key", "D:\\keys\\id");
        let duplicates = SavedVaultGraph::new(Vec::new(), vec![key.clone(), key], Vec::new());
        assert!(matches!(
            store.assess_graph_import(&duplicates),
            Err(StoreError::DuplicateGraphEntityId(
                SavedVaultEntityKind::SshKeyReference
            ))
        ));
        assert_eq!(snapshot_count(&vault), 0);

        let host = import_candidate("duplicate-host", "duplicate.example.com");
        assert!(matches!(
            store.assess_graph_import(&SavedVaultGraph::new(
                vec![host.clone(), host],
                Vec::new(),
                Vec::new()
            )),
            Err(StoreError::DuplicateGraphEntityId(
                SavedVaultEntityKind::Host
            ))
        ));
        let key = reference_key("identity-key", "Identity key", "D:\\keys\\identity");
        let identity = identity_reference("duplicate-identity", "Identity", key.id.as_str());
        assert!(matches!(
            store.assess_graph_import(&SavedVaultGraph::new(
                Vec::new(),
                vec![key],
                vec![identity.clone(), identity]
            )),
            Err(StoreError::DuplicateGraphEntityId(
                SavedVaultEntityKind::IdentityReference
            ))
        ));

        let missing = SavedVaultGraph::new(
            Vec::new(),
            Vec::new(),
            vec![identity_reference(
                "missing-identity",
                "Missing",
                "missing-key",
            )],
        );
        let error = store
            .assess_graph_import(&missing)
            .expect_err("missing relationship");
        assert!(matches!(
            error,
            StoreError::MissingGraphReference {
                source: SavedVaultEntityKind::IdentityReference,
                target: SavedVaultEntityKind::SshKeyReference
            }
        ));
        let error_text = error.to_string();
        assert!(!error_text.contains("missing-key"));
        assert!(!error_text.contains("missing-identity"));
        assert_eq!(snapshot_count(&vault), 0);

        let graph = SavedVaultGraph::new(
            Vec::new(),
            vec![reference_key("stale-key", "Stale", "D:\\keys\\stale")],
            Vec::new(),
        );
        let stale = store
            .assess_graph_import(&graph)
            .expect("assessment")
            .into_revision();
        store
            .create(SavedHostDraft::ssh_password(
                "concurrent.example.com",
                "user",
            ))
            .expect("concurrent commit");
        assert!(matches!(
            store.plan_graph_import(stale.clone(), &graph),
            Err(StoreError::InventoryRevisionConflict { .. })
        ));
        assert!(matches!(
            store.commit_graph_import(stale, graph),
            Err(StoreError::InventoryRevisionConflict { .. })
        ));
        assert!(
            store
                .list_ssh_key_references()
                .expect("list keys")
                .is_empty()
        );
    }

    #[test]
    fn public_import_reports_revalidated_sync_failure_as_published_uncertain() {
        let (_root, store) = store();
        let host = import_candidate("sync-failure-host", "sync.example.com");
        let assessment = store
            .assess_import(std::slice::from_ref(&host))
            .expect("assessment");
        store.inject_next_publish_fault(TestPublishFault::SyncFailure);
        let committed = store
            .commit_import(assessment.into_revision(), vec![host.clone()])
            .expect("post-link sync failure remains a successful commit result");
        assert_eq!(
            committed.durability(),
            SavedVaultCommitDurability::PublishedDurabilityUncertain
        );
        assert_eq!(committed.imported(), std::slice::from_ref(&host));
        let mut encoded = serde_json::to_value(&committed).expect("commit JSON");
        assert_eq!(
            encoded.get("durability"),
            Some(&serde_json::Value::String(
                "publishedDurabilityUncertain".to_owned()
            ))
        );
        encoded
            .as_object_mut()
            .expect("commit object")
            .remove("durability");
        let legacy: super::SavedHostImportCommit =
            serde_json::from_value(encoded).expect("legacy commit without durability");
        assert_eq!(
            legacy.durability(),
            SavedVaultCommitDurability::Durable,
            "older serialized commit results retain their previous success semantics"
        );
        assert_eq!(store.list().expect("published inventory"), vec![host]);
    }

    #[test]
    fn public_import_reports_revalidation_read_failure_as_indeterminate() {
        let (_root, store) = store();
        let host = import_candidate("read-failure-host", "read.example.com");
        let assessment = store
            .assess_import(std::slice::from_ref(&host))
            .expect("assessment");
        store.inject_next_publish_fault(TestPublishFault::SyncFailureAndRevalidationReadFailure);
        let committed = store
            .commit_import(assessment.into_revision(), vec![host.clone()])
            .expect("a post-link read failure must not become an uncommitted error");
        assert_eq!(
            committed.durability(),
            SavedVaultCommitDurability::PublicationIndeterminate
        );
        assert_eq!(store.list().expect("later read succeeds"), vec![host]);
    }

    #[test]
    fn public_import_reports_deleted_post_link_target_as_indeterminate() {
        let (_root, store) = store();
        let host = import_candidate("deleted-target-host", "deleted.example.com");
        let assessment = store
            .assess_import(std::slice::from_ref(&host))
            .expect("assessment");
        store.inject_next_publish_fault(TestPublishFault::SyncFailureAndTargetDeletion);
        let committed = store
            .commit_import(assessment.into_revision(), vec![host])
            .expect("a deleted post-link target must remain an indeterminate publication");
        assert_eq!(
            committed.durability(),
            SavedVaultCommitDurability::PublicationIndeterminate
        );
        assert!(
            store
                .list()
                .expect("deleted target leaves old inventory")
                .is_empty(),
            "an indeterminate result must not claim later visibility"
        );
    }

    #[test]
    fn public_import_reports_corrupt_post_link_target_as_indeterminate() {
        let (_root, store) = store();
        let host = import_candidate("corrupt-target-host", "corrupt.example.com");
        let assessment = store
            .assess_import(std::slice::from_ref(&host))
            .expect("assessment");
        store.inject_next_publish_fault(TestPublishFault::SyncFailureAndTargetCorruption);
        let committed = store
            .commit_import(assessment.into_revision(), vec![host])
            .expect("a corrupt post-link target must remain an indeterminate publication");
        assert_eq!(
            committed.durability(),
            SavedVaultCommitDurability::PublicationIndeterminate
        );
        assert!(matches!(store.list(), Err(StoreError::BothSlotsCorrupt)));
    }

    #[test]
    fn durability_confirmation_supports_an_empty_vault() {
        let (_root, store) = store();
        let confirmed = store
            .confirm_current_snapshot_durability()
            .expect("confirm empty Vault");
        assert_eq!(confirmed.revision().loaded_generation(), 0);
        assert_eq!(confirmed.revision().max_seen_generation(), 0);
        assert!(confirmed.graph().hosts().is_empty());
        assert!(confirmed.graph().ssh_key_references().is_empty());
        assert!(confirmed.graph().identity_references().is_empty());
    }

    #[test]
    fn durability_confirmation_returns_the_exact_committed_revision_and_graph() {
        let (_root, store) = store();
        let host = import_candidate("confirmed-host", "confirmed.example.com");
        let assessment = store
            .assess_import(std::slice::from_ref(&host))
            .expect("assessment");
        let committed = store
            .commit_import(assessment.into_revision(), vec![host.clone()])
            .expect("commit");

        let confirmed = store
            .confirm_current_snapshot_durability()
            .expect("confirm committed snapshot");
        assert_eq!(confirmed.revision(), committed.revision());
        assert_eq!(confirmed.graph().hosts(), std::slice::from_ref(&host));
    }

    #[test]
    fn durability_confirmation_sync_failure_is_fail_closed_and_retryable() {
        let (root, store) = store();
        let host = store
            .create(SavedHostDraft::ssh_password("retry.example.com", "user"))
            .expect("seed snapshot");
        store.inject_next_durability_confirmation_fault(
            TestDurabilityConfirmationFault::SyncFailure,
        );

        assert!(matches!(
            store.confirm_current_snapshot_durability(),
            Err(StoreError::Io(_))
        ));
        drop(store);
        let reopened = SavedHostStore::open(root.path().join("vault")).expect("restart store");
        let confirmed = reopened
            .confirm_current_snapshot_durability()
            .expect("retry confirmation after restart");
        assert_eq!(confirmed.graph().hosts(), std::slice::from_ref(&host));
    }

    #[test]
    fn durability_confirmation_requires_the_competing_slot_to_sync() {
        let (_root, store) = store();
        let host = store
            .create(SavedHostDraft::ssh_password(
                "competing-slot.example.com",
                "user",
            ))
            .expect("seed snapshot");
        store.inject_next_durability_confirmation_fault(
            TestDurabilityConfirmationFault::CompetingSlotSyncFailure,
        );

        assert!(matches!(
            store.confirm_current_snapshot_durability(),
            Err(StoreError::Io(_))
        ));
        let confirmed = store
            .confirm_current_snapshot_durability()
            .expect("retry both-slot confirmation");
        assert_eq!(confirmed.graph().hosts(), std::slice::from_ref(&host));
    }

    #[test]
    fn durability_confirmation_rejects_valid_content_changed_after_sync() {
        let (_root, store) = store();
        store
            .create(SavedHostDraft::ssh_password(
                "content-change.example.com",
                "user",
            ))
            .expect("seed snapshot");
        store.inject_next_durability_confirmation_fault(
            TestDurabilityConfirmationFault::ContentChange,
        );

        let result = store.confirm_current_snapshot_durability();
        assert!(
            matches!(result, Err(StoreError::SnapshotDurabilityUnconfirmed)),
            "unexpected confirmation result: {result:?}"
        );
        let confirmed = store
            .confirm_current_snapshot_durability()
            .expect("changed snapshot is independently confirmable on retry");
        assert!(confirmed.graph().hosts()[0].label.ends_with(" changed"));
    }

    #[test]
    fn durability_confirmation_rejects_generation_changed_after_sync() {
        let (_root, store) = store();
        store
            .create(SavedHostDraft::ssh_password(
                "generation-change.example.com",
                "user",
            ))
            .expect("seed generation one");
        store.inject_next_durability_confirmation_fault(
            TestDurabilityConfirmationFault::GenerationChange,
        );

        assert!(matches!(
            store.confirm_current_snapshot_durability(),
            Err(StoreError::SnapshotDurabilityUnconfirmed)
        ));
        let confirmed = store
            .confirm_current_snapshot_durability()
            .expect("new generation is independently confirmable on retry");
        assert_eq!(confirmed.revision().loaded_generation(), 2);
        assert_eq!(confirmed.revision().max_seen_generation(), 2);
    }

    #[test]
    fn durability_confirmation_rejects_a_corrupt_higher_generation_fallback() {
        let (root, store) = store();
        let created = store
            .create(SavedHostDraft::ssh_password(
                "fallback-confirmation.example.com",
                "user",
            ))
            .expect("generation one");
        store
            .update(
                &created.id,
                created.revision,
                label_update("generation two"),
            )
            .expect("generation two");
        fs::write(
            latest_snapshot(&root.path().join("vault").join(SLOT_B_DIRECTORY)),
            b"injected corrupt higher generation",
        )
        .expect("corrupt generation two");

        assert!(matches!(
            store.confirm_current_snapshot_durability(),
            Err(StoreError::SnapshotDurabilityUnconfirmed)
        ));
    }

    #[test]
    fn graph_import_exposes_the_same_publication_durability_contract() {
        let (_root, store) = store();
        let graph = SavedVaultGraph::new(
            Vec::new(),
            vec![reference_key("indeterminate-key", "Key", "D:\\keys\\id")],
            Vec::new(),
        );
        let assessment = store.assess_graph_import(&graph).expect("assessment");
        store.inject_next_publish_fault(TestPublishFault::SyncFailureAndRevalidationReadFailure);
        let committed = store
            .commit_graph_import(assessment.into_revision(), graph)
            .expect("graph publication is represented by a successful result");
        assert_eq!(
            committed.durability(),
            SavedVaultCommitDurability::PublicationIndeterminate
        );
        assert_eq!(committed.imported().ssh_key_references().len(), 1);
    }

    #[test]
    fn graph_replacement_replaces_every_catalog_once_and_reordering_is_a_no_op() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let old = replacement_graph("old");
        let old_revision = store
            .assess_graph_import(&old)
            .expect("assess old graph")
            .into_revision();
        store
            .commit_graph_import(old_revision, old)
            .expect("seed old graph");
        let target = replacement_graph("new");
        let before = store
            .confirm_current_snapshot_durability()
            .expect("confirm old graph");
        let snapshots_before = snapshot_count(&vault);
        let plan = store
            .plan_graph_replacement(before.revision().clone(), &target)
            .expect("plan replacement");
        assert!(plan.has_changes());
        assert_eq!(plan.before_graph_commitment(), before.commitment());
        assert_eq!(snapshot_count(&vault), snapshots_before);

        let committed = store
            .commit_planned_graph_replacement(plan, target)
            .expect("commit replacement");
        assert!(committed.changed());
        assert_eq!(committed.durability(), SavedVaultCommitDurability::Durable);
        assert_eq!(committed.graph(), &store.graph().expect("stored graph"));
        assert_eq!(snapshot_count(&vault), snapshots_before + 1);
        assert!(
            committed
                .graph()
                .hosts()
                .iter()
                .all(|host| !host.id.as_str().starts_with("old-"))
        );
        let snapshot: serde_json::Value = serde_json::from_slice(
            &fs::read(latest_snapshot(&vault.join(SLOT_B_DIRECTORY))).expect("read replacement"),
        )
        .expect("replacement JSON");
        assert_eq!(snapshot["formatVersion"], SNAPSHOT_FORMAT_V8);
        assert_eq!(snapshot["proxyProfiles"], serde_json::json!([]));
        assert_eq!(snapshot["groups"], serde_json::json!([]));

        let reordered = graph_json_variant(committed.graph(), |value| {
            for catalog in [
                "hosts",
                "sshKeyReferences",
                "managedSshKeys",
                "identityReferences",
            ] {
                value[catalog]
                    .as_array_mut()
                    .expect("catalog array")
                    .reverse();
            }
        });
        let no_op_plan = store
            .plan_graph_replacement(committed.revision().clone(), &reordered)
            .expect("plan reordered replacement");
        assert!(!no_op_plan.has_changes());
        let snapshots_before_no_op = snapshot_count(&vault);
        let no_op = store
            .commit_planned_graph_replacement(no_op_plan, reordered)
            .expect("commit reordered no-op");
        assert!(!no_op.changed());
        assert_eq!(no_op.revision(), committed.revision());
        assert_eq!(no_op.graph(), committed.graph());
        assert_eq!(snapshot_count(&vault), snapshots_before_no_op);
    }

    #[test]
    fn graph_replacement_rejects_dangling_edges_stale_plans_and_changed_targets() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let revision = store
            .confirm_current_snapshot_durability()
            .expect("confirm empty")
            .revision()
            .clone();
        let key = reference_key("dangling-key", "Dangling key", "D:\\keys\\dangling");
        let identity = identity_reference("dangling-identity", "Identity", key.id.as_str());
        let identity_without_key =
            SavedVaultGraph::new(Vec::new(), Vec::new(), vec![identity.clone()]);
        assert!(matches!(
            store.plan_graph_replacement(revision.clone(), &identity_without_key),
            Err(StoreError::MissingGraphReference {
                source: SavedVaultEntityKind::IdentityReference,
                ..
            })
        ));
        let host_without_identity = SavedVaultGraph::new(
            vec![relationship_host(
                "dangling-identity-host",
                "dangling-identity.example.com",
                "key",
                Some(identity.id.as_str()),
                None,
            )],
            Vec::new(),
            Vec::new(),
        );
        assert!(matches!(
            store.plan_graph_replacement(revision.clone(), &host_without_identity),
            Err(StoreError::MissingGraphReference {
                source: SavedVaultEntityKind::Host,
                target: SavedVaultEntityKind::IdentityReference,
            })
        ));
        let host_without_key = SavedVaultGraph::new(
            vec![relationship_host(
                "dangling-key-host",
                "dangling-key.example.com",
                "key",
                None,
                Some(key.id.as_str()),
            )],
            Vec::new(),
            Vec::new(),
        );
        assert!(matches!(
            store.plan_graph_replacement(revision.clone(), &host_without_key),
            Err(StoreError::MissingGraphReference {
                source: SavedVaultEntityKind::Host,
                ..
            })
        ));

        let target = replacement_graph("sealed");
        let plan = store
            .plan_graph_replacement(revision, &target)
            .expect("plan sealed target");
        let changed_target = graph_json_variant(&target, |value| {
            value["managedSshKeys"][0]["custody"]["backendLocator"] =
                serde_json::json!("bb".repeat(32));
        });
        assert!(matches!(
            store.commit_planned_graph_replacement(plan.clone(), changed_target),
            Err(StoreError::GraphReplacementPlanMismatch)
        ));
        let mut tampered = plan.clone();
        tampered.before_graph_commitment = SavedVaultGraphCommitment::from_digest([0x77; 32]);
        assert!(matches!(
            store.commit_planned_graph_replacement(tampered, target.clone()),
            Err(StoreError::GraphReplacementPlanMismatch)
        ));
        store
            .create(SavedHostDraft::ssh_password(
                "concurrent.example.com",
                "user",
            ))
            .expect("concurrent mutation");
        assert!(matches!(
            store.commit_planned_graph_replacement(plan, target),
            Err(StoreError::InventoryRevisionConflict { .. })
        ));
        assert_eq!(snapshot_count(&vault), 1);
    }

    #[test]
    fn conflicting_host_identity_and_direct_key_edges_fail_closed_everywhere() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let identity_key = reference_key(
            "dual-edge-identity-key",
            "Identity key",
            "D:\\keys\\identity-key",
        );
        let direct_key =
            reference_key("dual-edge-direct-key", "Direct key", "D:\\keys\\direct-key");
        let identity = identity_reference(
            "dual-edge-identity",
            "Dual-edge identity",
            identity_key.id.as_str(),
        );
        let host = relationship_host(
            "dual-edge-host",
            "dual-edge.example.com",
            "key",
            Some(identity.id.as_str()),
            Some(direct_key.id.as_str()),
        );
        let contradictory =
            SavedVaultGraph::new(vec![host], vec![identity_key, direct_key], vec![identity]);
        let revision = store
            .confirm_current_snapshot_durability()
            .expect("confirm empty Vault")
            .revision()
            .clone();

        assert!(matches!(
            store.assess_graph_import(&contradictory),
            Err(StoreError::IncompatibleGraphReference {
                source: SavedVaultEntityKind::Host,
                target: SavedVaultEntityKind::IdentityReference,
            })
        ));
        assert!(matches!(
            store.plan_graph_replacement(revision, &contradictory),
            Err(StoreError::IncompatibleGraphReference {
                source: SavedVaultEntityKind::Host,
                target: SavedVaultEntityKind::IdentityReference,
            })
        ));
        assert_eq!(snapshot_count(&vault), 0);

        let (hosts, references, managed_keys, identities) = contradictory.into_parts();
        let envelope = legacy_v3_snapshot_json(
            store.store_id.as_ref(),
            Slot::A,
            1,
            hosts,
            references,
            managed_keys,
            identities,
        );
        let path = vault
            .join(SLOT_A_DIRECTORY)
            .join("snapshot-00000000000000000001-44444444444444444444444444444444.json");
        fs::write(&path, serde_json::to_vec(&envelope).expect("v3 JSON"))
            .expect("write contradictory v3 snapshot");
        assert!(matches!(
            read_snapshot(&path, store.store_id.as_ref(), Slot::A, 1),
            Err(StoreError::IncompatibleGraphReference {
                source: SavedVaultEntityKind::Host,
                target: SavedVaultEntityKind::IdentityReference,
            })
        ));
    }

    #[test]
    fn auth_and_key_categories_fail_closed_for_import_replacement_and_v3_load() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let revision = store
            .confirm_current_snapshot_durability()
            .expect("confirm empty")
            .revision()
            .clone();
        let valid = replacement_graph("category");
        let incompatible = [
            graph_json_variant(&valid, |value| {
                value["sshKeyReferences"][0]["category"] = serde_json::json!("certificate");
            }),
            graph_json_variant(&valid, |value| {
                value["managedSshKeys"][0]["category"] = serde_json::json!("key");
            }),
            graph_json_variant(&valid, |value| {
                value["hosts"][0]["authMethod"] = serde_json::json!("password");
            }),
            graph_json_variant(&valid, |value| {
                value["hosts"][0]["authMethod"] = serde_json::json!("certificate");
                value["hosts"][0]["identityFileId"] = serde_json::Value::Null;
            }),
        ];
        for graph in incompatible {
            assert!(matches!(
                store.assess_graph_import(&graph),
                Err(StoreError::IncompatibleGraphReference { .. })
            ));
            assert!(matches!(
                store.plan_graph_replacement(revision.clone(), &graph),
                Err(StoreError::IncompatibleGraphReference { .. })
            ));
        }
        assert_eq!(snapshot_count(&vault), 0);

        let null_password = graph_json_variant(&valid, |value| {
            value["hosts"][0]["authMethod"] = serde_json::json!("password");
            value["hosts"][0]["identityId"] = serde_json::Value::Null;
            value["hosts"][0]["identityFileId"] = serde_json::json!("");
        });
        store
            .plan_graph_replacement(revision, &null_password)
            .expect("null and empty password relationships are inert");

        let reference = reference_key("bad-v3-key", "Bad v3 key", "D:\\keys\\bad-v3");
        let invalid_host = relationship_host(
            "bad-v3-host",
            "bad-v3.example.com",
            "password",
            None,
            Some(reference.id.as_str()),
        );
        let envelope = legacy_v3_snapshot_json(
            store.store_id.as_ref(),
            Slot::A,
            1,
            vec![invalid_host],
            vec![reference],
            Vec::new(),
            Vec::new(),
        );
        let path = vault
            .join(SLOT_A_DIRECTORY)
            .join("snapshot-00000000000000000001-33333333333333333333333333333333.json");
        fs::write(&path, serde_json::to_vec(&envelope).expect("v3 JSON"))
            .expect("write malformed v3");
        assert!(matches!(
            read_snapshot(&path, store.store_id.as_ref(), Slot::A, 1),
            Err(StoreError::IncompatibleGraphReference { .. })
        ));
    }

    #[test]
    fn password_identity_graph_round_trips_with_v4_cas_and_strict_host_typing() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let identity = password_identity("shared-login", "Shared login", "alice", true);
        let host = relationship_host(
            "password-host",
            "password.example.com",
            "password",
            Some(identity.id.as_str()),
            None,
        );
        let graph = SavedVaultGraph::new_with_password_identities(
            vec![host.clone()],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![identity.clone()],
        );
        let assessment = store.assess_graph_import(&graph).expect("assessment");
        assert_eq!(
            assessment.password_identity_dispositions(),
            [SavedHostImportDisposition::Importable]
        );
        let committed = store
            .commit_graph_import(assessment.into_revision(), graph.clone())
            .expect("commit password identity graph");
        assert_eq!(committed.imported(), &graph);
        assert_eq!(
            store
                .list_password_identities()
                .expect("password identities"),
            vec![identity.clone()]
        );
        assert_eq!(store.graph().expect("stored graph"), graph);

        let snapshot: serde_json::Value = serde_json::from_slice(
            &fs::read(latest_snapshot(&vault.join(SLOT_A_DIRECTORY))).expect("read v4"),
        )
        .expect("v4 JSON");
        assert_eq!(snapshot["formatVersion"], SNAPSHOT_FORMAT_V8);
        assert_eq!(snapshot["proxyProfiles"], serde_json::json!([]));
        assert_eq!(snapshot["groups"], serde_json::json!([]));
        assert_eq!(snapshot["passwordIdentities"][0]["id"], "shared-login");
        assert_eq!(
            snapshot["passwordIdentities"][0]["hasSavedCredential"],
            true
        );
        let encoded = serde_json::to_string(&snapshot).expect("snapshot text");
        for forbidden in ["credentialReference", "credentialLocator", "keyringAccount"] {
            assert!(!encoded.contains(forbidden));
        }

        let key = reference_key("key", "Key", "D:\\keys\\key");
        let key_identity = identity_reference("key-login", "Key login", key.id.as_str());
        let password_host_with_key_identity = SavedVaultGraph::new(
            vec![relationship_host(
                "wrong-password-host",
                "wrong-password.example.com",
                "password",
                Some(key_identity.id.as_str()),
                None,
            )],
            vec![key],
            vec![key_identity],
        );
        assert!(matches!(
            store.assess_graph_import(&password_host_with_key_identity),
            Err(StoreError::IncompatibleGraphReference {
                source: SavedVaultEntityKind::Host,
                target: SavedVaultEntityKind::IdentityReference,
            })
        ));

        let key_host_with_password_identity = SavedVaultGraph::new_with_password_identities(
            vec![relationship_host(
                "wrong-key-host",
                "wrong-key.example.com",
                "key",
                Some("other-password-login"),
                None,
            )],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![password_identity(
                "other-password-login",
                "Other login",
                "bob",
                false,
            )],
        );
        assert!(matches!(
            store.assess_graph_import(&key_host_with_password_identity),
            Err(StoreError::IncompatibleGraphReference {
                source: SavedVaultEntityKind::Host,
                target: SavedVaultEntityKind::PasswordIdentity,
            })
        ));

        let missing = SavedVaultGraph::new(
            vec![relationship_host(
                "missing-password-host",
                "missing-password.example.com",
                "password",
                Some("missing-login"),
                None,
            )],
            Vec::new(),
            Vec::new(),
        );
        assert!(matches!(
            store.assess_graph_import(&missing),
            Err(StoreError::MissingGraphReference {
                source: SavedVaultEntityKind::Host,
                target: SavedVaultEntityKind::PasswordIdentity,
            })
        ));
    }

    #[test]
    fn password_identity_ids_are_unique_across_both_identity_catalogs() {
        let (_root, store) = store();
        let key = reference_key("cross-key", "Cross key", "D:\\keys\\cross");
        let key_identity = identity_reference("same-identity", "Key identity", key.id.as_str());
        let password = password_identity("same-identity", "Password identity", "alice", false);
        let cross_catalog = SavedVaultGraph::new_with_password_identities(
            Vec::new(),
            vec![key],
            Vec::new(),
            vec![key_identity],
            vec![password],
        );
        assert!(matches!(
            store.assess_graph_import(&cross_catalog),
            Err(StoreError::DuplicateGraphEntityId(
                SavedVaultEntityKind::PasswordIdentity
            ))
        ));

        let duplicate = password_identity("duplicate-password", "Duplicate", "alice", false);
        let duplicate_catalog = SavedVaultGraph::new_with_password_identities(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![duplicate.clone(), duplicate],
        );
        assert!(matches!(
            store.assess_graph_import(&duplicate_catalog),
            Err(StoreError::DuplicateGraphEntityId(
                SavedVaultEntityKind::PasswordIdentity
            ))
        ));

        let seed = SavedVaultGraph::new_with_password_identities(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![password_identity(
                "occupied-identity",
                "Occupied",
                "alice",
                false,
            )],
        );
        let seed_assessment = store.assess_graph_import(&seed).expect("seed assessment");
        store
            .commit_graph_import(seed_assessment.into_revision(), seed)
            .expect("seed password identity");
        let conflicting_key = reference_key("occupied-key", "Occupied key", "D:\\keys\\occupied");
        let conflicting_identity = identity_reference(
            "occupied-identity",
            "Occupied key identity",
            conflicting_key.id.as_str(),
        );
        let conflicting_graph = SavedVaultGraph::new(
            Vec::new(),
            vec![conflicting_key],
            vec![conflicting_identity],
        );
        let assessment = store
            .assess_graph_import(&conflicting_graph)
            .expect("cross-catalog assessment");
        assert_eq!(
            assessment.identity_reference_dispositions(),
            [SavedHostImportDisposition::Conflict]
        );
        assert!(matches!(
            store.commit_graph_import(assessment.into_revision(), conflicting_graph),
            Err(StoreError::GraphImportConflict(
                SavedVaultEntityKind::IdentityReference
            ))
        ));
    }

    #[test]
    fn password_identity_replacement_is_sorted_atomic_and_cas_sealed() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let zulu = password_identity("zulu-login", "Zulu", "zulu", false);
        let alpha = password_identity("alpha-login", "Alpha", "alpha", true);
        let target = SavedVaultGraph::new_with_password_identities(
            vec![relationship_host(
                "replacement-password-host",
                "replacement-password.example.com",
                "password",
                Some(alpha.id.as_str()),
                None,
            )],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![zulu, alpha],
        );
        let revision = store
            .confirm_current_snapshot_durability()
            .expect("empty durability")
            .revision()
            .clone();
        let plan = store
            .plan_graph_replacement(revision, &target)
            .expect("replacement plan");
        let committed = store
            .commit_planned_graph_replacement(plan, target)
            .expect("replacement commit");
        assert!(committed.changed());
        assert_eq!(snapshot_count(&vault), 1);
        assert_eq!(
            committed
                .graph()
                .password_identities()
                .iter()
                .map(|identity| identity.label.as_str())
                .collect::<Vec<_>>(),
            ["Alpha", "Zulu"]
        );

        let mut reordered = committed.graph().clone();
        reordered.password_identities.reverse();
        let no_op = store
            .plan_graph_replacement(committed.revision().clone(), &reordered)
            .expect("reordered plan");
        assert!(!no_op.has_changes());
        let snapshots_before = snapshot_count(&vault);
        let no_op = store
            .commit_planned_graph_replacement(no_op, reordered)
            .expect("reordered no-op");
        assert!(!no_op.changed());
        assert_eq!(snapshot_count(&vault), snapshots_before);
    }

    #[test]
    fn v6_requires_every_catalog_even_when_the_checksum_describes_empty_arrays() {
        let envelope = SnapshotEnvelope::new(
            "11111111111111111111111111111111".to_owned(),
            Slot::A,
            1,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("v6 envelope");
        let value = serde_json::to_value(envelope).expect("v6 JSON");

        for field in [
            "sshKeyReferences",
            "managedSshKeys",
            "identityReferences",
            "passwordIdentities",
            "proxyProfiles",
            "groups",
        ] {
            let mut missing = value.clone();
            missing.as_object_mut().expect("object").remove(field);
            let decoded: SnapshotEnvelope =
                serde_json::from_value(missing).expect("missing catalog parses distinctly");
            assert!(matches!(
                decoded.validate(
                    "11111111111111111111111111111111",
                    Slot::A,
                    1,
                    std::path::PathBuf::from("unused"),
                ),
                Err(StoreError::BothSlotsCorrupt)
            ));

            let mut null = value.clone();
            null[field] = serde_json::Value::Null;
            let decoded: SnapshotEnvelope =
                serde_json::from_value(null).expect("null catalog parses distinctly");
            assert!(matches!(
                decoded.validate(
                    "11111111111111111111111111111111",
                    Slot::A,
                    1,
                    std::path::PathBuf::from("unused"),
                ),
                Err(StoreError::BothSlotsCorrupt)
            ));
        }

        let mut wrong_type = value;
        wrong_type["passwordIdentities"] = serde_json::json!({});
        assert!(serde_json::from_value::<SnapshotEnvelope>(wrong_type).is_err());
    }

    #[test]
    fn v4_password_identity_recovers_from_one_corrupt_slot() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let first = SavedVaultGraph::new_with_password_identities(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![password_identity("fallback-login", "First", "alice", true)],
        );
        let assessment = store.assess_graph_import(&first).expect("assessment");
        store
            .commit_graph_import(assessment.into_revision(), first)
            .expect("generation one");
        let current = store.graph().expect("current graph");
        let second = graph_json_variant(&current, |value| {
            value["passwordIdentities"][0]["revision"] = serde_json::json!(2);
            value["passwordIdentities"][0]["label"] = serde_json::json!("Second");
            value["passwordIdentities"][0]["updatedAt"] = serde_json::json!(11);
        });
        let revision = store
            .confirm_current_snapshot_durability()
            .expect("generation one durability")
            .revision()
            .clone();
        let plan = store
            .plan_graph_replacement(revision, &second)
            .expect("generation two plan");
        store
            .commit_planned_graph_replacement(plan, second)
            .expect("generation two");
        fs::write(
            latest_snapshot(&vault.join(SLOT_B_DIRECTORY)),
            b"corrupt generation two",
        )
        .expect("corrupt latest");
        drop(store);

        let reopened = SavedHostStore::open(&vault).expect("fallback open");
        let identities = reopened
            .list_password_identities()
            .expect("fallback identities");
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].label, "First");
        assert_eq!(identities[0].revision, 1);
    }

    #[test]
    fn legacy_v3_snapshot_reopens_and_next_write_adds_password_catalog() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let key = reference_key("legacy-v3-key", "Legacy v3 key", "D:\\keys\\legacy-v3");
        let identity =
            identity_reference("legacy-v3-identity", "Legacy v3 identity", key.id.as_str());
        let host = relationship_host(
            "legacy-v3-host",
            "legacy-v3.example.com",
            "key",
            Some(identity.id.as_str()),
            Some(key.id.as_str()),
        );
        let checksum = snapshot_checksum_v3(
            store.store_id.as_ref(),
            Slot::A,
            1,
            std::slice::from_ref(&host),
            std::slice::from_ref(&key),
            &[],
            std::slice::from_ref(&identity),
        )
        .expect("v3 checksum");
        let legacy = serde_json::json!({
            "magic": SNAPSHOT_MAGIC,
            "formatVersion": 3,
            "storeId": store.store_id.as_ref(),
            "slot": "a",
            "generation": 1,
            "hosts": [host],
            "sshKeyReferences": [key],
            "managedSshKeys": [],
            "identityReferences": [identity],
            "checksum": checksum,
        });
        fs::write(
            vault
                .join(SLOT_A_DIRECTORY)
                .join("snapshot-00000000000000000001-11111111111111111111111111111111.json"),
            serde_json::to_vec(&legacy).expect("legacy JSON"),
        )
        .expect("publish v3");
        drop(store);

        let reopened = SavedHostStore::open(&vault).expect("open v3");
        assert_eq!(reopened.list().expect("hosts").len(), 1);
        assert_eq!(reopened.list_ssh_key_references().expect("keys").len(), 1);
        assert_eq!(
            reopened
                .list_identity_references()
                .expect("key identities")
                .len(),
            1
        );
        assert!(
            reopened
                .list_password_identities()
                .expect("password identities")
                .is_empty()
        );
        reopened
            .create(SavedHostDraft::ssh_password(
                "upgrade-v4.example.com",
                "user",
            ))
            .expect("upgrade to v4");
        let upgraded: serde_json::Value = serde_json::from_slice(
            &fs::read(latest_snapshot(&vault.join(SLOT_B_DIRECTORY))).expect("read v4"),
        )
        .expect("v4 JSON");
        assert_eq!(upgraded["formatVersion"], SNAPSHOT_FORMAT_V8);
        assert_eq!(upgraded["proxyProfiles"], serde_json::json!([]));
        assert_eq!(upgraded["groups"], serde_json::json!([]));
        assert_eq!(upgraded["passwordIdentities"], serde_json::json!([]));
    }

    #[test]
    fn graph_commitment_covers_every_password_identity_metadata_field() {
        let (_root, store) = store();
        let graph = SavedVaultGraph::new_with_password_identities(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![password_identity(
                "commitment-login",
                "Commitment login",
                "alice",
                false,
            )],
        );
        let assessment = store.assess_graph_import(&graph).expect("assessment");
        store
            .commit_graph_import(assessment.into_revision(), graph)
            .expect("seed graph");
        let durable = store
            .confirm_current_snapshot_durability()
            .expect("durable graph");
        let baseline = durable.commitment().clone();
        let revision = durable.revision().clone();
        let graph = durable.graph().clone();

        let variants = [
            graph_json_variant(&graph, |value| {
                value["passwordIdentities"][0]["id"] = serde_json::json!("changed-login")
            }),
            graph_json_variant(&graph, |value| {
                value["passwordIdentities"][0]["revision"] = serde_json::json!(2)
            }),
            graph_json_variant(&graph, |value| {
                value["passwordIdentities"][0]["label"] = serde_json::json!("Changed label")
            }),
            graph_json_variant(&graph, |value| {
                value["passwordIdentities"][0]["username"] = serde_json::json!("bob")
            }),
            graph_json_variant(&graph, |value| {
                value["passwordIdentities"][0]["hasSavedCredential"] = serde_json::json!(true)
            }),
            graph_json_variant(&graph, |value| {
                value["passwordIdentities"][0]["createdAt"] = serde_json::json!(9)
            }),
            graph_json_variant(&graph, |value| {
                value["passwordIdentities"][0]["updatedAt"] = serde_json::json!(11)
            }),
            graph_json_variant(&graph, |value| {
                value["passwordIdentities"][0]["order"] = serde_json::json!(3)
            }),
        ];
        for variant in variants {
            let plan = store
                .plan_graph_replacement(revision.clone(), &variant)
                .expect("variant plan");
            assert_ne!(plan.after_graph_commitment(), &baseline);
        }
    }

    #[test]
    fn legacy_v4_snapshot_without_proxy_catalog_remains_readable() {
        let store_id = "11111111111111111111111111111111";
        let password = password_identity("legacy-v4-login", "Legacy v4 login", "alice", false);
        let checksum = snapshot_checksum_v4(
            store_id,
            Slot::A,
            1,
            &[],
            &[],
            &[],
            &[],
            std::slice::from_ref(&password),
        )
        .expect("legacy v4 checksum");
        let envelope = SnapshotEnvelope {
            magic: SNAPSHOT_MAGIC.to_owned(),
            format_version: SNAPSHOT_FORMAT_V4,
            store_id: store_id.to_owned(),
            slot: Slot::A,
            generation: 1,
            hosts: Vec::new(),
            ssh_key_references: Some(Some(Vec::new())),
            managed_ssh_keys: Some(Some(Vec::new())),
            identity_references: Some(Some(Vec::new())),
            password_identities: Some(Some(vec![password.clone()])),
            proxy_profiles: None,
            groups: None,
            custom_groups: None,
            notes_snippets: None,
            port_forward_rules: None,
            known_hosts: None,
            connection_logs: None,
            checksum,
        };
        let mut encoded = serde_json::to_value(&envelope).expect("legacy v4 JSON");
        encoded
            .as_object_mut()
            .expect("legacy v4 object")
            .remove("proxyProfiles");
        encoded
            .as_object_mut()
            .expect("legacy v4 object")
            .remove("groups");
        encoded
            .as_object_mut()
            .expect("legacy v4 object")
            .remove("notesSnippets");
        encoded
            .as_object_mut()
            .expect("legacy v4 object")
            .remove("portForwardRules");
        assert!(encoded.get("proxyProfiles").is_none());
        let decoded: SnapshotEnvelope = serde_json::from_value(encoded).expect("decode v4");
        let validated = decoded
            .validate(
                store_id,
                Slot::A,
                1,
                std::path::PathBuf::from("legacy-v4.json"),
            )
            .expect("validate legacy v4");
        assert_eq!(validated.password_identities, vec![password]);
        assert!(validated.proxy_profiles.is_empty());
    }

    #[test]
    fn graph_replacement_debug_is_redacted_and_durability_is_preserved() {
        let (_root, store) = store();
        let target = replacement_graph("debug-secret-id");
        let revision = store
            .confirm_current_snapshot_durability()
            .expect("confirm empty")
            .revision()
            .clone();
        let plan = store
            .plan_graph_replacement(revision, &target)
            .expect("plan replacement");
        let plan_debug = format!("{plan:?}");
        assert!(!plan_debug.contains("debug-secret-id"));
        assert!(!plan_debug.contains(plan.after_graph_commitment().as_str()));

        store.inject_next_publish_fault(TestPublishFault::SyncFailure);
        let committed = store
            .commit_planned_graph_replacement(plan, target)
            .expect("published replacement");
        assert_eq!(
            committed.durability(),
            SavedVaultCommitDurability::PublishedDurabilityUncertain
        );
        let commit_debug = format!("{committed:?}");
        assert!(!commit_debug.contains("debug-secret-id"));
        assert!(!commit_debug.contains("a1".repeat(32).as_str()));
        assert_eq!(committed.graph().managed_ssh_keys().len(), 1);
    }

    #[test]
    fn proxy_profiles_round_trip_in_v5_and_survive_ab_fallback() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let login = password_identity("proxy-login", "Proxy login", "proxy-user", true);
        let profile = proxy_profile(
            "office-proxy",
            "Office proxy",
            SavedProxyConfig::http(
                "proxy.example.com",
                3128,
                Some(login.id.clone()),
                "shadowed-user",
                true,
            )
            .expect("HTTP proxy"),
        );
        let host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("server.example.com", "alice")
                .with_proxy_profile_id(profile.id.clone())
                .expect("profile binding"),
            10,
        )
        .expect("host");
        let graph = SavedVaultGraph::new_with_proxy_profiles(
            vec![host],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![login],
            vec![profile.clone()],
            Vec::new(),
        );
        let assessment = store.assess_graph_import(&graph).expect("assessment");
        assert_eq!(
            assessment.proxy_profile_dispositions(),
            &[SavedHostImportDisposition::Importable]
        );
        store
            .commit_graph_import(assessment.into_revision(), graph)
            .expect("v6 commit");

        let slot_a = latest_snapshot(&vault.join(SLOT_A_DIRECTORY));
        let snapshot: serde_json::Value =
            serde_json::from_slice(&fs::read(&slot_a).expect("read v6")).expect("v6 JSON");
        assert_eq!(snapshot["formatVersion"], SNAPSHOT_FORMAT_V8);
        assert_eq!(snapshot["proxyProfiles"].as_array().map(Vec::len), Some(1));
        assert_eq!(snapshot["groups"], serde_json::json!([]));
        let encoded = serde_json::to_string(&snapshot).expect("snapshot text");
        assert!(!encoded.contains("\"password\":"));
        assert!(!encoded.contains("shadowed-user"));

        // A host-only mutation writes slot B from the complete loaded graph.
        store
            .create(SavedHostDraft::ssh_password("second.example.com", "bob"))
            .expect("second generation");
        assert_eq!(
            store.list_proxy_profiles().expect("profiles"),
            vec![profile.clone()]
        );
        let slot_b = latest_snapshot(&vault.join(SLOT_B_DIRECTORY));
        fs::write(slot_b, b"corrupt latest slot").expect("corrupt B");

        let reopened = SavedHostStore::open(&vault).expect("fallback to A");
        assert_eq!(
            reopened.list_proxy_profiles().expect("fallback profiles"),
            vec![profile]
        );
        assert_eq!(
            reopened
                .graph()
                .expect("fallback graph")
                .proxy_profiles()
                .len(),
            1
        );
    }

    #[test]
    fn proxy_precedence_and_identity_relationships_fail_closed() {
        let (_root, store) = store();
        let password = password_identity("proxy-password", "Proxy password", "alice", true);
        let key = reference_key("proxy-key", "Proxy key", "D:\\keys\\proxy");
        let key_identity =
            identity_reference("proxy-key-identity", "Key identity", key.id.as_str());

        let inline_shadowing_missing_profile = SavedHost::from_draft(
            SavedHostDraft::ssh_password("inline.example.com", "host-user")
                .with_proxy_profile_id(
                    SavedProxyProfileId::from_opaque("missing-shadowed-profile").expect("ID"),
                )
                .expect("shadowed profile")
                .with_proxy_config(
                    SavedProxyConfig::socks5(
                        "inline.proxy",
                        1080,
                        Some(password.id.clone()),
                        "cleared",
                        true,
                    )
                    .expect("inline proxy"),
                )
                .expect("inline config"),
            10,
        )
        .expect("inline host");
        let valid = SavedVaultGraph::new_with_proxy_profiles(
            vec![inline_shadowing_missing_profile.clone()],
            vec![key.clone()],
            Vec::new(),
            vec![key_identity.clone()],
            vec![password.clone()],
            Vec::new(),
            Vec::new(),
        );
        store
            .assess_graph_import(&valid)
            .expect("inline wins absolutely");
        assert_eq!(
            inline_shadowing_missing_profile.compatibility_fields()["proxyProfileId"],
            "missing-shadowed-profile"
        );

        let invalid_inline = SavedHost::from_draft(
            SavedHostDraft::ssh_password("invalid-inline.example.com", "host-user")
                .with_proxy_profile_id(
                    SavedProxyProfileId::from_opaque("otherwise-valid-profile").expect("ID"),
                )
                .expect("profile")
                .with_compatibility_field(
                    "proxyConfig",
                    serde_json::json!({"type":"http","host":"bad host","port":8080}),
                )
                .expect("raw invalid inline"),
            10,
        )
        .expect("host accepts flattened compatibility");
        let fallback_profile = proxy_profile(
            "otherwise-valid-profile",
            "Valid profile",
            SavedProxyConfig::command("connect %h %p").expect("command proxy"),
        );
        let invalid_inline_graph = SavedVaultGraph::new_with_proxy_profiles(
            vec![invalid_inline],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![fallback_profile],
            Vec::new(),
        );
        assert!(matches!(
            store.assess_graph_import(&invalid_inline_graph),
            Err(StoreError::Validation(ValidationError::InvalidProxyConfig))
        ));

        let key_bound_inline = SavedHost::from_draft(
            SavedHostDraft::ssh_password("key-inline.example.com", "host-user")
                .with_proxy_config(
                    SavedProxyConfig::http(
                        "inline.proxy",
                        8080,
                        Some(
                            SavedPasswordIdentityId::from_opaque(key_identity.id.as_str())
                                .expect("cross-catalog ID"),
                        ),
                        "",
                        false,
                    )
                    .expect("inline proxy"),
                )
                .expect("inline config"),
            10,
        )
        .expect("key-bound host");
        let cross_catalog = SavedVaultGraph::new_with_proxy_profiles(
            vec![key_bound_inline],
            vec![key.clone()],
            Vec::new(),
            vec![key_identity.clone()],
            vec![password.clone()],
            Vec::new(),
            Vec::new(),
        );
        assert!(matches!(
            store.assess_graph_import(&cross_catalog),
            Err(StoreError::IncompatibleGraphReference {
                source: SavedVaultEntityKind::Host,
                target: SavedVaultEntityKind::IdentityReference,
            })
        ));

        let key_bound_profile = proxy_profile(
            "key-bound-profile",
            "Key-bound profile",
            SavedProxyConfig::socks5(
                "profile.proxy",
                1080,
                Some(
                    SavedPasswordIdentityId::from_opaque(key_identity.id.as_str())
                        .expect("cross-catalog ID"),
                ),
                "",
                false,
            )
            .expect("profile proxy"),
        );
        let profile_cross_catalog = SavedVaultGraph::new_with_proxy_profiles(
            Vec::new(),
            vec![key],
            Vec::new(),
            vec![key_identity],
            vec![password],
            vec![key_bound_profile],
            Vec::new(),
        );
        assert!(matches!(
            store.assess_graph_import(&profile_cross_catalog),
            Err(StoreError::IncompatibleGraphReference {
                source: SavedVaultEntityKind::ProxyProfile,
                target: SavedVaultEntityKind::IdentityReference,
            })
        ));

        let missing_identity_profile = proxy_profile(
            "missing-identity-profile",
            "Missing identity profile",
            SavedProxyConfig::http(
                "profile.proxy",
                8080,
                Some(SavedPasswordIdentityId::from_opaque("missing-proxy-login").expect("ID")),
                "",
                false,
            )
            .expect("profile proxy"),
        );
        assert!(matches!(
            store.assess_graph_import(&SavedVaultGraph::new_with_proxy_profiles(
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                vec![missing_identity_profile],
                Vec::new(),
            )),
            Err(StoreError::MissingGraphReference {
                source: SavedVaultEntityKind::ProxyProfile,
                target: SavedVaultEntityKind::PasswordIdentity,
            })
        ));

        let missing_profile_host = SavedHost::from_draft(
            SavedHostDraft::ssh_password("missing-profile.example.com", "host-user")
                .with_proxy_profile_id(
                    SavedProxyProfileId::from_opaque("actually-missing").expect("ID"),
                )
                .expect("profile binding"),
            10,
        )
        .expect("missing-profile host");
        assert!(matches!(
            store.assess_graph_import(&SavedVaultGraph::new(
                vec![missing_profile_host],
                Vec::new(),
                Vec::new(),
            )),
            Err(StoreError::MissingGraphReference {
                source: SavedVaultEntityKind::Host,
                target: SavedVaultEntityKind::ProxyProfile,
            })
        ));

        let duplicate = proxy_profile(
            "duplicate-proxy",
            "Duplicate proxy",
            SavedProxyConfig::command("connect %h %p").expect("command"),
        );
        assert!(matches!(
            store.assess_graph_import(&SavedVaultGraph::new_with_proxy_profiles(
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                vec![duplicate.clone(), duplicate],
                Vec::new(),
            )),
            Err(StoreError::DuplicateGraphEntityId(
                SavedVaultEntityKind::ProxyProfile
            ))
        ));
    }

    #[test]
    fn v5_checksum_and_commitment_cover_every_proxy_profile_field() {
        let (_root, store) = store();
        let login = password_identity("checksum-login", "Checksum login", "alice", false);
        let profile = proxy_profile(
            "checksum-proxy",
            "Checksum proxy",
            SavedProxyConfig::http("proxy.example.com", 8080, None, "manual-user", true)
                .expect("proxy"),
        );
        let graph = SavedVaultGraph::new_with_proxy_profiles(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![login],
            vec![profile],
            Vec::new(),
        );
        let assessment = store.assess_graph_import(&graph).expect("assessment");
        store
            .commit_graph_import(assessment.into_revision(), graph)
            .expect("seed v5");
        let durable = store
            .confirm_current_snapshot_durability()
            .expect("durable graph");
        let baseline_commitment = durable.commitment().clone();
        let revision = durable.revision().clone();
        let graph = durable.graph().clone();
        let baseline_checksum = snapshot_checksum_v5(
            "11111111111111111111111111111111",
            Slot::A,
            1,
            graph.hosts(),
            graph.ssh_key_references(),
            graph.managed_ssh_keys(),
            graph.identity_references(),
            graph.password_identities(),
            graph.proxy_profiles(),
        )
        .expect("baseline checksum");

        let variants = [
            graph_json_variant(&graph, |v| {
                v["proxyProfiles"][0]["id"] = serde_json::json!("changed-proxy")
            }),
            graph_json_variant(&graph, |v| {
                v["proxyProfiles"][0]["revision"] = serde_json::json!(2)
            }),
            graph_json_variant(&graph, |v| {
                v["proxyProfiles"][0]["label"] = serde_json::json!("Changed proxy")
            }),
            graph_json_variant(&graph, |v| {
                v["proxyProfiles"][0]["config"]["type"] = serde_json::json!("socks5")
            }),
            graph_json_variant(&graph, |v| {
                v["proxyProfiles"][0]["config"]["host"] = serde_json::json!("other.proxy")
            }),
            graph_json_variant(&graph, |v| {
                v["proxyProfiles"][0]["config"]["port"] = serde_json::json!(8081)
            }),
            graph_json_variant(&graph, |v| {
                v["proxyProfiles"][0]["config"]["username"] = serde_json::json!("other-user")
            }),
            graph_json_variant(&graph, |v| {
                v["proxyProfiles"][0]["config"]["hasSavedCredential"] = serde_json::json!(false)
            }),
            graph_json_variant(&graph, |v| {
                v["proxyProfiles"][0]["config"]["identityId"] = serde_json::json!("checksum-login")
            }),
            graph_json_variant(&graph, |v| {
                v["proxyProfiles"][0]["createdAt"] = serde_json::json!(9)
            }),
            graph_json_variant(&graph, |v| {
                v["proxyProfiles"][0]["updatedAt"] = serde_json::json!(11)
            }),
            graph_json_variant(&graph, |v| {
                v["proxyProfiles"][0]["order"] = serde_json::json!(2)
            }),
        ];
        for variant in variants {
            let plan = store
                .plan_graph_replacement(revision.clone(), &variant)
                .expect("valid proxy variant");
            assert_ne!(plan.after_graph_commitment(), &baseline_commitment);
            let checksum = snapshot_checksum_v5(
                "11111111111111111111111111111111",
                Slot::A,
                1,
                variant.hosts(),
                variant.ssh_key_references(),
                variant.managed_ssh_keys(),
                variant.identity_references(),
                variant.password_identities(),
                variant.proxy_profiles(),
            )
            .expect("variant checksum");
            assert_ne!(checksum, baseline_checksum);
        }
    }

    fn group_config(id: &str, path: &str, defaults: SavedGroupDefaults) -> SavedGroupConfig {
        SavedGroupConfig::from_parts(
            SavedGroupId::from_opaque(id).expect("group ID"),
            1,
            SavedGroupPath::new(path).expect("group path"),
            defaults,
            10,
            10,
        )
        .expect("group config")
    }

    #[test]
    fn legacy_v5_snapshot_without_groups_remains_readable() {
        let store_id = "11111111111111111111111111111111";
        let mut envelope = SnapshotEnvelope::new(
            store_id.to_owned(),
            Slot::A,
            1,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("envelope");
        envelope.format_version = SNAPSHOT_FORMAT_V5;
        envelope.groups = None;
        envelope.notes_snippets = None;
        envelope.checksum =
            snapshot_checksum_v5(store_id, Slot::A, 1, &[], &[], &[], &[], &[], &[])
                .expect("v5 checksum");
        let mut encoded = serde_json::to_value(envelope).expect("v5 JSON");
        encoded.as_object_mut().expect("object").remove("groups");
        encoded
            .as_object_mut()
            .expect("object")
            .remove("notesSnippets");
        encoded
            .as_object_mut()
            .expect("object")
            .remove("portForwardRules");
        let validated = serde_json::from_value::<SnapshotEnvelope>(encoded)
            .expect("decode v5")
            .validate(store_id, Slot::A, 1, std::path::PathBuf::from("unused"))
            .expect("validate v5");
        assert!(validated.groups.is_empty());
    }

    #[test]
    fn v6_group_catalog_is_imported_replaced_cas_bound_and_preserved_by_host_mutation() {
        let (root, store) = store();
        let vault = root.path().join("vault");
        let original = group_config("group-catalog-id", "Operations/Primary", Default::default());
        let graph = SavedVaultGraph::new_with_proxy_profiles(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![original.clone()],
        );
        let assessment = store.assess_graph_import(&graph).expect("assessment");
        assert_eq!(
            assessment.group_dispositions(),
            &[super::SavedVaultImportDisposition::Importable]
        );
        let stale_revision = assessment.revision().clone();
        let committed = store
            .commit_graph_import(assessment.into_revision(), graph)
            .expect("group import");
        assert_eq!(
            committed.imported().groups(),
            std::slice::from_ref(&original)
        );
        assert!(matches!(
            store.commit_graph_import(stale_revision, SavedVaultGraph::default()),
            Err(StoreError::InventoryRevisionConflict { .. })
        ));

        store
            .create(SavedHostDraft::ssh_password(
                "group-preservation.example",
                "alice",
            ))
            .expect("host mutation");
        assert_eq!(store.list_groups().expect("groups"), vec![original.clone()]);
        let snapshot: serde_json::Value = serde_json::from_slice(
            &fs::read(latest_snapshot(&vault.join(SLOT_B_DIRECTORY))).expect("v6 snapshot"),
        )
        .expect("v6 JSON");
        assert_eq!(snapshot["formatVersion"], SNAPSHOT_FORMAT_V8);
        assert_eq!(snapshot["groups"].as_array().map(Vec::len), Some(1));

        let current = store.graph().expect("current graph");
        let replacement = SavedVaultGraph::new_with_proxy_profiles(
            current.hosts().to_vec(),
            current.ssh_key_references().to_vec(),
            current.managed_ssh_keys().to_vec(),
            current.identity_references().to_vec(),
            current.password_identities().to_vec(),
            current.proxy_profiles().to_vec(),
            vec![group_config(
                "group-catalog-id",
                "Operations/Renamed",
                Default::default(),
            )],
        );
        let revision = store
            .assess_graph_import(&SavedVaultGraph::default())
            .expect("revision")
            .into_revision();
        let plan = store
            .plan_graph_replacement(revision, &replacement)
            .expect("replacement plan");
        assert!(plan.has_changes());
        let replaced = store
            .commit_planned_graph_replacement(plan, replacement)
            .expect("replacement");
        assert_eq!(
            replaced.graph().groups()[0].path.as_str(),
            "Operations/Renamed"
        );
    }

    #[test]
    fn group_catalog_rejects_duplicate_ids_paths_and_missing_references() {
        let (_root, store) = store();
        let same_id = SavedVaultGraph::new_with_proxy_profiles(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![
                group_config("duplicate-group", "A", Default::default()),
                group_config("duplicate-group", "B", Default::default()),
            ],
        );
        assert!(matches!(
            store.assess_graph_import(&same_id),
            Err(StoreError::DuplicateGraphEntityId(
                SavedVaultEntityKind::Group
            ))
        ));
        let same_path = SavedVaultGraph::new_with_proxy_profiles(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![
                group_config("group-a", "Same/Path", Default::default()),
                group_config("group-b", "Same/Path", Default::default()),
            ],
        );
        assert!(matches!(
            store.assess_graph_import(&same_path),
            Err(StoreError::DuplicateGraphEntityId(
                SavedVaultEntityKind::Group
            ))
        ));

        let missing_host = SavedHostId::from_opaque("missing-group-host").expect("host ID");
        let defaults = SavedGroupDefaults {
            host_chain: SavedGroupOverride::Set(
                SavedGroupHostChain::new(vec![missing_host]).expect("host chain"),
            ),
            ..Default::default()
        };
        let dangling = SavedVaultGraph::new_with_proxy_profiles(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![group_config("dangling-group", "Dangling", defaults)],
        );
        assert!(matches!(
            store.assess_graph_import(&dangling),
            Err(StoreError::MissingGraphReference {
                source: SavedVaultEntityKind::Group,
                target: SavedVaultEntityKind::Host,
            })
        ));
    }
}
