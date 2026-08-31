use std::collections::BTreeMap;

use netcatty_credentials::CredentialErrorCode;
use netcatty_credentials::test_support::{
    CredentialOperation, FailureTiming, InMemoryCredentialController, in_memory_credential_store,
    in_memory_master_key_store,
};
use netcatty_secret_store::SshSecretBundle;
use netcatty_vault::{
    SavedHost, SavedHostDraft, SavedIdentityReference, SavedIdentityReferenceId,
    SavedManagedSshKey, SavedVaultCommitDurability, SavedVaultGraph,
};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::managed_key_catalog::{
    MANAGED_KEY_IN_USE, MANAGED_KEY_INVALID, MANAGED_KEY_INVENTORY_CHANGED,
    MANAGED_KEY_PUBLICATION_FAILED, MANAGED_KEY_REPAIR_REQUIRED, ManagedSshKeyCategoryRequest,
    ManagedSshKeyMetadataRequest, managed_key_error,
};
use super::{
    DesktopState, LEGACY_VAULT_SECRET_STORE_FAILED, LEGACY_VAULT_SECRET_STORE_REPAIR_REQUIRED,
    ManagedSecretPublicationFailure, ManagedSshMasterKeyRotationStatus,
    begin_managed_master_key_rotation, create_managed_ssh_key_inner, delete_managed_ssh_key_inner,
    garbage_collect_managed_secret_blobs, run_saved_host_operation,
    run_saved_host_operation_with_rotation, update_managed_ssh_key_inner,
};

const CREATE_PRIVATE: &str = "catalog-create-private-material-sentinel";
const CREATE_PUBLIC: &str = "catalog-create-public-material-sentinel";
const CREATE_PASSPHRASE: &str = "catalog-create-passphrase-material-sentinel";
const UPDATED_PRIVATE: &str = "catalog-updated-private-material-sentinel";
const UPDATED_PUBLIC: &str = "catalog-updated-public-material-sentinel";
const UPDATED_PASSPHRASE: &str = "catalog-updated-passphrase-material-sentinel";

fn desktop_state(vault_root: &std::path::Path) -> (DesktopState, InMemoryCredentialController) {
    let (credentials, _) = in_memory_credential_store();
    let (master_keys, master_key_controller) = in_memory_master_key_store();
    let mut state = DesktopState::open(vault_root).expect("desktop state");
    state.persistent_credentials = credentials;
    state.master_keys = master_keys;
    (state, master_key_controller)
}

fn metadata(label: &str, save_passphrase: bool) -> ManagedSshKeyMetadataRequest {
    ManagedSshKeyMetadataRequest {
        label: label.to_owned(),
        category: ManagedSshKeyCategoryRequest::Key,
        save_passphrase,
    }
}

fn bundle(private_key: &str, public_key: &str, passphrase: &str) -> SshSecretBundle {
    SshSecretBundle::new(
        private_key.as_bytes().to_vec(),
        Some(public_key.as_bytes().to_vec()),
        None,
        Some(passphrase.as_bytes().to_vec()),
    )
    .expect("managed key bundle")
}

fn durable_revision(state: &DesktopState) -> netcatty_vault::SavedVaultInventoryRevision {
    state
        .saved_hosts
        .confirm_current_snapshot_durability()
        .expect("durable Vault snapshot")
        .revision()
        .clone()
}

async fn create_test_key(
    state: &DesktopState,
    label: &str,
) -> super::managed_key_catalog::ManagedSshKeyCatalog {
    let expected = durable_revision(state);
    let metadata = metadata(label, true);
    run_saved_host_operation(state.clone(), move |state| async move {
        create_managed_ssh_key_inner(
            &state,
            expected,
            metadata,
            bundle(CREATE_PRIVATE, CREATE_PUBLIC, CREATE_PASSPHRASE),
        )
        .await
    })
    .await
    .expect("create managed key")
}

async fn replace_test_key(
    state: &DesktopState,
    id: String,
    label: &str,
) -> super::managed_key_catalog::ManagedSshKeyCatalog {
    let expected = durable_revision(state);
    let metadata = metadata(label, true);
    run_saved_host_operation(state.clone(), move |state| async move {
        update_managed_ssh_key_inner(
            &state,
            id,
            expected,
            metadata,
            Some(bundle(UPDATED_PRIVATE, UPDATED_PUBLIC, UPDATED_PASSPHRASE)),
        )
        .await
    })
    .await
    .expect("replace managed key")
}

async fn prepare_unretained_blob_revision(
    state: &DesktopState,
    vault_root: &std::path::Path,
) -> SavedManagedSshKey {
    create_test_key(state, "Original managed key").await;
    let id = state
        .saved_hosts
        .graph()
        .expect("created graph")
        .managed_ssh_keys()[0]
        .id
        .as_str()
        .to_owned();
    replace_test_key(state, id, "Replaced managed key").await;
    let current = state
        .saved_hosts
        .graph()
        .expect("replaced graph")
        .managed_ssh_keys()[0]
        .clone();

    // Advancing the opposite Vault slot makes revision 1 unretained without
    // invoking managed-object GC. A stale request must leave this detectable
    // garbage untouched, proving CAS happened before cleanup side effects.
    state
        .saved_hosts
        .create(SavedHostDraft::ssh_password(
            "advance-without-managed-gc.example.test",
            "catalog-user",
        ))
        .expect("advance fallback without managed GC");
    assert_eq!(
        secret_blob_paths(&vault_root.join("secret-blobs")).len(),
        4,
        "test setup must retain one collectible blob revision"
    );
    current
}

fn persisted_files(root: &std::path::Path) -> Vec<Vec<u8>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_dir() {
            pending.extend(
                std::fs::read_dir(path)
                    .expect("read persisted directory")
                    .map(|entry| entry.expect("persisted entry").path()),
            );
        } else if metadata.is_file() {
            files.push(std::fs::read(path).expect("read persisted file"));
        }
    }
    files
}

fn saved_vault_snapshots(root: &std::path::Path) -> Vec<serde_json::Value> {
    let mut snapshots = persisted_files(root)
        .into_iter()
        .filter_map(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .filter(|value| value["magic"] == "netcatty-saved-host-snapshot")
        .collect::<Vec<_>>();
    snapshots.sort_by_key(|snapshot| snapshot["generation"].as_u64().unwrap_or_default());
    snapshots
}

fn secret_blob_paths(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut blobs = Vec::new();
    while let Some(path) = pending.pop() {
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_dir() {
            pending.extend(
                std::fs::read_dir(path)
                    .expect("read secret-store directory")
                    .map(|entry| entry.expect("secret-store entry").path()),
            );
        } else if metadata.is_file()
            && path.extension().and_then(std::ffi::OsStr::to_str) == Some("ncsb")
        {
            blobs.push(path);
        }
    }
    blobs
}

fn secret_blob_hashes(root: &std::path::Path) -> Vec<[u8; 32]> {
    let mut hashes = secret_blob_paths(root)
        .into_iter()
        .map(|path| Sha256::digest(std::fs::read(path).expect("read secret blob")).into())
        .collect::<Vec<_>>();
    hashes.sort_unstable();
    hashes
}

async fn resolve_bundle(state: &DesktopState, key: SavedManagedSshKey) -> SshSecretBundle {
    let secret_files = state.secret_files.clone();
    let master_keys = state.master_keys.clone();
    tokio::task::spawn_blocking(move || {
        let guard = secret_files.lock_exclusive().expect("secret-store lock");
        let store_state = guard.load_state().expect("secret-store state");
        let master_key = master_keys
            .load_blocking(
                store_state.store_id(),
                store_state.active_master_key_epoch(),
            )
            .expect("in-memory master key");
        let locator = guard
            .restore_object_locator(key.id.as_str(), key.custody().backend_locator().as_str())
            .expect("restore managed locator");
        guard
            .resolve_object(&master_key, &locator, key.custody().custody_revision())
            .expect("resolve managed key bundle")
    })
    .await
    .expect("managed bundle worker")
}

fn assert_safe_catalog_json(
    catalog: &super::managed_key_catalog::ManagedSshKeyCatalog,
    forbidden: &[&str],
) {
    let encoded = serde_json::to_string(catalog).expect("renderer-safe catalog JSON");
    for value in forbidden {
        assert!(
            !encoded.contains(value),
            "renderer catalog disclosed managed key custody or secret material"
        );
    }
    for forbidden_field in [
        "\"backendLocator\"",
        "\"custody\"",
        "\"privateKey\"",
        "\"publicKey\"",
        "\"certificate\"",
        "\"passphrase\"",
        "\"ciphertext\"",
    ] {
        assert!(
            !encoded.contains(forbidden_field),
            "renderer catalog contained a forbidden backend or secret field"
        );
    }
}

#[test]
fn publication_failure_dispositions_preserve_uncertainty_with_fixed_redacted_errors() {
    let before = ManagedSecretPublicationFailure::BeforePublication;
    let repair = ManagedSecretPublicationFailure::RepairRequired;
    let legacy_before = before.legacy_error();
    let legacy_repair = repair.legacy_error();
    let native_before = match before {
        ManagedSecretPublicationFailure::BeforePublication => managed_key_error(
            MANAGED_KEY_PUBLICATION_FAILED,
            "Managed SSH key material could not be published",
        ),
        ManagedSecretPublicationFailure::RepairRequired => unreachable!(),
    };
    let native_repair = match repair {
        ManagedSecretPublicationFailure::RepairRequired => managed_key_error(
            MANAGED_KEY_REPAIR_REQUIRED,
            "Managed SSH key publication requires recovery",
        ),
        ManagedSecretPublicationFailure::BeforePublication => unreachable!(),
    };

    assert!(legacy_before.starts_with(LEGACY_VAULT_SECRET_STORE_FAILED));
    assert!(legacy_repair.starts_with(LEGACY_VAULT_SECRET_STORE_REPAIR_REQUIRED));
    assert!(native_before.starts_with(MANAGED_KEY_PUBLICATION_FAILED));
    assert!(native_repair.starts_with(MANAGED_KEY_REPAIR_REQUIRED));
    let rendered = format!(
        "{before:?} {repair:?} {legacy_before} {legacy_repair} {native_before} {native_repair}"
    );
    for forbidden in [
        CREATE_PRIVATE,
        CREATE_PASSPHRASE,
        "backend-locator-secret-sentinel",
        "master-key-account-secret-sentinel",
    ] {
        assert!(!rendered.contains(forbidden));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_publishes_one_blob_revision_and_one_v6_vault_commit() {
    let directory = tempfile::tempdir().expect("temporary Vault");
    let vault_root = directory.path().join("catalog-create");
    let (state, master_key_controller) = desktop_state(&vault_root);

    let catalog = create_test_key(&state, "Created managed key").await;
    let snapshot = state
        .saved_hosts
        .confirm_current_snapshot_durability()
        .expect("created durable graph");
    assert_eq!(snapshot.revision().loaded_generation(), 1);
    assert_eq!(snapshot.graph().managed_ssh_keys().len(), 1);
    let key = snapshot.graph().managed_ssh_keys()[0].clone();
    assert_eq!(key.custody().custody_revision(), 1);
    assert_eq!(secret_blob_paths(&vault_root.join("secret-blobs")).len(), 2);
    assert_eq!(
        master_key_controller
            .operation_log()
            .count(CredentialOperation::Upsert),
        1
    );

    let snapshots = saved_vault_snapshots(&vault_root.join("saved-hosts"));
    assert_eq!(snapshots.len(), 1, "create must publish one Vault snapshot");
    assert_eq!(snapshots[0]["formatVersion"], 8);

    let resolved = resolve_bundle(&state, key.clone()).await;
    assert_eq!(resolved.private_key(), CREATE_PRIVATE.as_bytes());
    assert_eq!(resolved.public_key(), Some(CREATE_PUBLIC.as_bytes()));
    assert_eq!(resolved.passphrase(), Some(CREATE_PASSPHRASE.as_bytes()));
    assert_safe_catalog_json(
        &catalog,
        &[
            key.custody().backend_locator().as_str(),
            CREATE_PRIVATE,
            CREATE_PUBLIC,
            CREATE_PASSPHRASE,
        ],
    );
    for bytes in persisted_files(&vault_root) {
        for forbidden in [CREATE_PRIVATE, CREATE_PUBLIC, CREATE_PASSPHRASE] {
            assert!(
                !bytes
                    .windows(forbidden.len())
                    .any(|part| part == forbidden.as_bytes()),
                "plaintext managed key material reached persistent storage"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metadata_update_keeps_blob_revision_and_secret_update_retains_both_fallback_revisions() {
    let directory = tempfile::tempdir().expect("temporary Vault");
    let vault_root = directory.path().join("catalog-update");
    let (state, master_key_controller) = desktop_state(&vault_root);
    create_test_key(&state, "Original managed key").await;
    let original = state
        .saved_hosts
        .graph()
        .expect("created graph")
        .managed_ssh_keys()[0]
        .clone();
    let original_hashes = secret_blob_hashes(&vault_root.join("secret-blobs"));
    assert_eq!(original_hashes.len(), 2);

    let expected = durable_revision(&state);
    let id = original.id.as_str().to_owned();
    master_key_controller.clear_operation_log();
    let renamed_catalog = run_saved_host_operation(state.clone(), move |state| async move {
        update_managed_ssh_key_inner(
            &state,
            id,
            expected,
            metadata("Renamed managed key", true),
            None,
        )
        .await
    })
    .await
    .expect("metadata-only managed key update");
    let renamed = state
        .saved_hosts
        .graph()
        .expect("renamed graph")
        .managed_ssh_keys()[0]
        .clone();
    assert_eq!(renamed.label, "Renamed managed key");
    assert_eq!(renamed.custody(), original.custody());
    assert_eq!(
        secret_blob_hashes(&vault_root.join("secret-blobs")),
        original_hashes,
        "metadata-only update must not publish or rewrite ciphertext"
    );
    assert!(
        master_key_controller.operation_log().is_empty(),
        "metadata-only update must not access or mutate the master-key backend"
    );
    assert_eq!(durable_revision(&state).loaded_generation(), 2);
    assert_safe_catalog_json(
        &renamed_catalog,
        &[
            renamed.custody().backend_locator().as_str(),
            CREATE_PRIVATE,
            CREATE_PUBLIC,
            CREATE_PASSPHRASE,
        ],
    );

    let expected = durable_revision(&state);
    let id = renamed.id.as_str().to_owned();
    let updated_catalog = run_saved_host_operation(state.clone(), move |state| async move {
        update_managed_ssh_key_inner(
            &state,
            id,
            expected,
            metadata("Replaced managed key", true),
            Some(bundle(UPDATED_PRIVATE, UPDATED_PUBLIC, UPDATED_PASSPHRASE)),
        )
        .await
    })
    .await
    .expect("managed key secret update");
    let updated = state
        .saved_hosts
        .graph()
        .expect("updated graph")
        .managed_ssh_keys()[0]
        .clone();
    assert_eq!(updated.custody().custody_revision(), 2);
    assert_eq!(
        updated.custody().backend_locator(),
        original.custody().backend_locator()
    );
    assert_eq!(durable_revision(&state).loaded_generation(), 3);
    assert_eq!(
        secret_blob_paths(&vault_root.join("secret-blobs")).len(),
        4,
        "the current and fallback Vault snapshots must retain both A/B blob revisions"
    );

    let fallback = resolve_bundle(&state, original.clone()).await;
    assert_eq!(fallback.private_key(), CREATE_PRIVATE.as_bytes());
    let current = resolve_bundle(&state, updated.clone()).await;
    assert_eq!(current.private_key(), UPDATED_PRIVATE.as_bytes());
    assert_eq!(current.public_key(), Some(UPDATED_PUBLIC.as_bytes()));
    assert_eq!(current.passphrase(), Some(UPDATED_PASSPHRASE.as_bytes()));
    assert_safe_catalog_json(
        &updated_catalog,
        &[
            updated.custody().backend_locator().as_str(),
            CREATE_PRIVATE,
            CREATE_PUBLIC,
            CREATE_PASSPHRASE,
            UPDATED_PRIVATE,
            UPDATED_PUBLIC,
            UPDATED_PASSPHRASE,
        ],
    );
}

fn add_host_and_identity_reference(state: &DesktopState, key: &SavedManagedSshKey) {
    let before = state
        .saved_hosts
        .confirm_current_snapshot_durability()
        .expect("graph before relationship");
    let identity = SavedIdentityReference::from_parts(
        SavedIdentityReferenceId::from_opaque("catalog-referencing-identity").expect("identity ID"),
        "Catalog referencing identity",
        "catalog-user",
        key.id.clone(),
        10,
        10,
        BTreeMap::new(),
    )
    .expect("managed key identity");
    let host: SavedHost = serde_json::from_value(json!({
        "recordVersion": 1,
        "id": "catalog-referencing-host",
        "revision": 1,
        "label": "Catalog referencing host",
        "hostname": "catalog-reference.example.test",
        "port": 22,
        "username": "catalog-user",
        "protocol": "ssh",
        "authMethod": "key",
        "authPolicyVersion": 1,
        "identityId": identity.id.as_str(),
        "identityFileId": key.id.as_str(),
        "createdAt": 10,
        "updatedAt": 10
    }))
    .expect("managed key host relationship");
    let (mut hosts, references, managed_keys, mut identities) = before.graph().clone().into_parts();
    hosts.push(host);
    identities.push(identity);
    let target =
        SavedVaultGraph::new_with_managed_ssh_keys(hosts, references, managed_keys, identities);
    let plan = state
        .saved_hosts
        .plan_graph_replacement(before.revision().clone(), &target)
        .expect("plan relationship graph");
    let committed = state
        .saved_hosts
        .commit_planned_graph_replacement(plan, target)
        .expect("commit relationship graph");
    assert_eq!(committed.durability(), SavedVaultCommitDurability::Durable);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn referenced_delete_maps_to_in_use_and_writes_nothing() {
    let directory = tempfile::tempdir().expect("temporary Vault");
    let vault_root = directory.path().join("catalog-referenced-delete");
    let (state, _) = desktop_state(&vault_root);
    create_test_key(&state, "Referenced managed key").await;
    let key = state
        .saved_hosts
        .graph()
        .expect("created graph")
        .managed_ssh_keys()[0]
        .clone();
    add_host_and_identity_reference(&state, &key);
    let expected = durable_revision(&state);
    let snapshots_before = saved_vault_snapshots(&vault_root.join("saved-hosts")).len();
    let blobs_before = secret_blob_hashes(&vault_root.join("secret-blobs"));
    let id = key.id.as_str().to_owned();

    let error = run_saved_host_operation(state.clone(), move |state| async move {
        delete_managed_ssh_key_inner(&state, id, expected).await
    })
    .await
    .expect_err("referenced managed key deletion must fail closed");
    assert!(error.starts_with(MANAGED_KEY_IN_USE));
    assert_eq!(
        saved_vault_snapshots(&vault_root.join("saved-hosts")).len(),
        snapshots_before,
        "a dangling relationship must be rejected before snapshot publication"
    );
    assert_eq!(
        secret_blob_hashes(&vault_root.join("secret-blobs")),
        blobs_before
    );
    assert_eq!(
        state
            .saved_hosts
            .graph()
            .expect("unchanged graph")
            .managed_ssh_keys()
            .len(),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreferenced_delete_durably_removes_pointer_and_keeps_gc_best_effort_and_fallback_safe() {
    let directory = tempfile::tempdir().expect("temporary Vault");
    let vault_root = directory.path().join("catalog-unreferenced-delete");
    let (state, _) = desktop_state(&vault_root);
    create_test_key(&state, "Disposable managed key").await;
    let key = state
        .saved_hosts
        .graph()
        .expect("created graph")
        .managed_ssh_keys()[0]
        .clone();
    let secret_root = vault_root.join("secret-blobs");
    let unknown = secret_root.join("objects").join("zz");
    std::fs::write(&unknown, b"unknown-gc-artifact").expect("inject unknown GC artifact");

    let expected = durable_revision(&state);
    let id = key.id.as_str().to_owned();
    let catalog = run_saved_host_operation(state.clone(), move |state| async move {
        delete_managed_ssh_key_inner(&state, id, expected).await
    })
    .await
    .expect("delete remains successful when post-commit best-effort GC refuses unknown data");
    let durable = state
        .saved_hosts
        .confirm_current_snapshot_durability()
        .expect("durable deleted graph");
    assert_eq!(durable.revision().loaded_generation(), 2);
    assert!(durable.graph().managed_ssh_keys().is_empty());
    assert!(
        unknown.exists(),
        "unknown artifacts must never be removed by GC"
    );
    assert_eq!(secret_blob_paths(&secret_root).len(), 2);
    assert_safe_catalog_json(
        &catalog,
        &[
            key.custody().backend_locator().as_str(),
            CREATE_PRIVATE,
            CREATE_PUBLIC,
            CREATE_PASSPHRASE,
        ],
    );

    std::fs::remove_file(&unknown).expect("remove injected unknown artifact");
    state
        .saved_hosts
        .create(SavedHostDraft::ssh_password(
            "advance-fallback.example.test",
            "catalog-user",
        ))
        .expect("advance the opposite Vault slot");
    let report = run_saved_host_operation(state.clone(), |state| async move {
        garbage_collect_managed_secret_blobs(&state).await
    })
    .await
    .expect("retry best-effort GC after both fallback pointers are gone");
    assert_eq!(report.removed_blob_revisions, 1);
    assert_eq!(report.removed_objects, 1);
    assert!(secret_blob_paths(&secret_root).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_inventory_is_rejected_before_master_key_or_blob_publication() {
    let directory = tempfile::tempdir().expect("temporary Vault");
    let vault_root = directory.path().join("catalog-stale-create");
    let (state, master_key_controller) = desktop_state(&vault_root);
    let stale = durable_revision(&state);
    state
        .saved_hosts
        .create(SavedHostDraft::ssh_password(
            "concurrent-catalog.example.test",
            "catalog-user",
        ))
        .expect("concurrent Vault mutation");
    master_key_controller.clear_operation_log();

    let error = run_saved_host_operation(state.clone(), move |state| async move {
        create_managed_ssh_key_inner(
            &state,
            stale,
            metadata("Stale managed key", true),
            bundle(CREATE_PRIVATE, CREATE_PUBLIC, CREATE_PASSPHRASE),
        )
        .await
    })
    .await
    .expect_err("stale inventory must fail before blob publication");
    assert!(error.starts_with(MANAGED_KEY_INVENTORY_CHANGED));
    assert_eq!(
        master_key_controller
            .operation_log()
            .count(CredentialOperation::Upsert),
        0,
        "stale CAS must not create a master key"
    );
    assert!(secret_blob_paths(&vault_root.join("secret-blobs")).is_empty());
    let guard = state
        .secret_files
        .lock_exclusive()
        .expect("secret-store lock");
    assert!(
        guard
            .owner_id()
            .expect("secret-store owner lookup")
            .is_none()
    );
    drop(guard);
    assert_eq!(
        saved_vault_snapshots(&vault_root.join("saved-hosts")).len(),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_stale_mutation_is_rejected_before_keyring_blob_or_gc_side_effects() {
    let directory = tempfile::tempdir().expect("temporary Vault");
    let vault_root = directory.path().join("catalog-stale-all-mutations");
    let (state, master_key_controller) = desktop_state(&vault_root);
    let key = prepare_unretained_blob_revision(&state, &vault_root).await;
    let stale = durable_revision(&state);
    state
        .saved_hosts
        .create(SavedHostDraft::ssh_password(
            "make-managed-cas-stale.example.test",
            "catalog-user",
        ))
        .expect("make inventory revision stale");

    let blobs_before = secret_blob_hashes(&vault_root.join("secret-blobs"));
    let snapshots_before = saved_vault_snapshots(&vault_root.join("saved-hosts")).len();
    assert_eq!(
        blobs_before.len(),
        4,
        "setup includes collectible ciphertext"
    );
    master_key_controller.clear_operation_log();

    let create_stale = stale.clone();
    let create_error = run_saved_host_operation(state.clone(), move |state| async move {
        create_managed_ssh_key_inner(
            &state,
            create_stale,
            metadata("Stale create", true),
            bundle(CREATE_PRIVATE, CREATE_PUBLIC, CREATE_PASSPHRASE),
        )
        .await
    })
    .await
    .expect_err("stale create must fail");
    assert!(create_error.starts_with(MANAGED_KEY_INVENTORY_CHANGED));
    assert_eq!(
        secret_blob_hashes(&vault_root.join("secret-blobs")),
        blobs_before,
        "stale create must not run collectible-object GC"
    );
    assert!(master_key_controller.operation_log().is_empty());

    let update_stale = stale.clone();
    let update_id = key.id.as_str().to_owned();
    let update_error = run_saved_host_operation(state.clone(), move |state| async move {
        update_managed_ssh_key_inner(
            &state,
            update_id,
            update_stale,
            metadata("Stale update", true),
            Some(bundle(UPDATED_PRIVATE, UPDATED_PUBLIC, UPDATED_PASSPHRASE)),
        )
        .await
    })
    .await
    .expect_err("stale secret update must fail");
    assert!(update_error.starts_with(MANAGED_KEY_INVENTORY_CHANGED));
    assert_eq!(
        secret_blob_hashes(&vault_root.join("secret-blobs")),
        blobs_before,
        "stale update must not run collectible-object GC"
    );
    assert!(master_key_controller.operation_log().is_empty());

    let delete_id = key.id.as_str().to_owned();
    let delete_error = run_saved_host_operation(state.clone(), move |state| async move {
        delete_managed_ssh_key_inner(&state, delete_id, stale).await
    })
    .await
    .expect_err("stale delete must fail");
    assert!(delete_error.starts_with(MANAGED_KEY_INVENTORY_CHANGED));
    assert_eq!(
        secret_blob_hashes(&vault_root.join("secret-blobs")),
        blobs_before,
        "stale delete must not touch ciphertext"
    );
    assert!(master_key_controller.operation_log().is_empty());
    assert_eq!(
        saved_vault_snapshots(&vault_root.join("saved-hosts")).len(),
        snapshots_before,
        "stale mutations must not publish Vault snapshots"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_create_is_rejected_before_secret_store_or_master_key_initialization() {
    let directory = tempfile::tempdir().expect("temporary Vault");
    let vault_root = directory.path().join("catalog-invalid-create");
    let (state, master_key_controller) = desktop_state(&vault_root);
    let expected = durable_revision(&state);
    let invalid_bundle =
        SshSecretBundle::new(vec![0xff], None, None, None).expect("bounded invalid UTF-8 bundle");

    let error = run_saved_host_operation(state.clone(), move |state| async move {
        create_managed_ssh_key_inner(
            &state,
            expected,
            metadata("Invalid managed key", false),
            invalid_bundle,
        )
        .await
    })
    .await
    .expect_err("invalid managed key must fail preflight");
    assert!(error.starts_with(MANAGED_KEY_INVALID));
    assert!(master_key_controller.operation_log().is_empty());
    assert!(secret_blob_paths(&vault_root.join("secret-blobs")).is_empty());
    assert!(saved_vault_snapshots(&vault_root.join("saved-hosts")).is_empty());
    let guard = state
        .secret_files
        .lock_exclusive()
        .expect("secret-store lock");
    assert_eq!(guard.owner_id().expect("secret-store owner lookup"), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_secret_update_does_not_run_gc_or_access_the_master_key() {
    let directory = tempfile::tempdir().expect("temporary Vault");
    let vault_root = directory.path().join("catalog-invalid-update");
    let (state, master_key_controller) = desktop_state(&vault_root);
    let key = prepare_unretained_blob_revision(&state, &vault_root).await;
    let expected = durable_revision(&state);
    let blobs_before = secret_blob_hashes(&vault_root.join("secret-blobs"));
    let snapshots_before = saved_vault_snapshots(&vault_root.join("saved-hosts")).len();
    master_key_controller.clear_operation_log();
    let id = key.id.as_str().to_owned();
    let invalid_bundle =
        SshSecretBundle::new(vec![0xff], None, None, None).expect("bounded invalid UTF-8 bundle");

    let error = run_saved_host_operation(state.clone(), move |state| async move {
        update_managed_ssh_key_inner(
            &state,
            id,
            expected,
            metadata("Invalid update", false),
            Some(invalid_bundle),
        )
        .await
    })
    .await
    .expect_err("invalid managed key update must fail preflight");
    assert!(error.starts_with(MANAGED_KEY_INVALID));
    assert!(master_key_controller.operation_log().is_empty());
    assert_eq!(
        secret_blob_hashes(&vault_root.join("secret-blobs")),
        blobs_before,
        "invalid update must not collect or publish ciphertext"
    );
    assert_eq!(
        saved_vault_snapshots(&vault_root.join("saved-hosts")).len(),
        snapshots_before
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_create_finishes_after_the_caller_drops_its_waiter() {
    let directory = tempfile::tempdir().expect("temporary Vault");
    let vault_root = directory.path().join("catalog-caller-cancellation");
    let (state, _) = desktop_state(&vault_root);
    let expected = durable_revision(&state);

    // Keep the detached coordinator queued long enough to poll and then drop
    // the caller-facing future before any transaction work can begin.
    let process_guard = state.saved_host_mutations.clone().lock_owned().await;
    let (finished_sender, finished_receiver) = tokio::sync::oneshot::channel();
    let operation_state = state.clone();
    let mut waiter = Box::pin(run_saved_host_operation(
        operation_state,
        move |state| async move {
            let result = create_managed_ssh_key_inner(
                &state,
                expected,
                metadata("Cancellation-surviving managed key", true),
                bundle(CREATE_PRIVATE, CREATE_PUBLIC, CREATE_PASSPHRASE),
            )
            .await;
            let safe_result = result.as_ref().map(|_| ()).map_err(Clone::clone);
            let _ = finished_sender.send(safe_result);
            result
        },
    ));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut waiter)
            .await
            .is_err(),
        "coordinator must still be queued behind the held process lock"
    );
    drop(waiter);
    drop(process_guard);

    tokio::time::timeout(std::time::Duration::from_secs(10), finished_receiver)
        .await
        .expect("detached coordinator completed after caller cancellation")
        .expect("detached completion sender")
        .expect("managed create completed successfully");
    let durable = state
        .saved_hosts
        .confirm_current_snapshot_durability()
        .expect("durable graph after caller cancellation");
    assert_eq!(durable.graph().managed_ssh_keys().len(), 1);
    assert_eq!(secret_blob_paths(&vault_root.join("secret-blobs")).len(), 2);
    let resolved = resolve_bundle(&state, durable.graph().managed_ssh_keys()[0].clone()).await;
    assert_eq!(resolved.private_key(), CREATE_PRIVATE.as_bytes());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_vault_rotation_is_renderer_safe_and_has_no_keyring_side_effects() {
    let directory = tempfile::tempdir().expect("temporary Vault");
    let vault_root = directory.path().join("catalog-empty-master-key-rotation");
    let (state, master_key_controller) = desktop_state(&vault_root);

    let result = run_saved_host_operation(state.clone(), |state| async move {
        begin_managed_master_key_rotation(&state).await
    })
    .await
    .expect("empty Vault rotation result");

    assert_eq!(
        result.status,
        ManagedSshMasterKeyRotationStatus::NotInitialized
    );
    assert_eq!(result.retained_secret_revision_count, 0);
    assert!(
        master_key_controller.operation_log().is_empty(),
        "an empty Vault must not read, create, or delete a master key"
    );
    assert_eq!(
        serde_json::to_value(result).expect("renderer-safe rotation JSON"),
        json!({
            "status": "notInitialized",
            "retainedSecretRevisionCount": 0
        })
    );
    let encoded = serde_json::to_string(&result).expect("renderer-safe rotation JSON");
    for forbidden in [
        "storeId",
        "epoch",
        "backendLocator",
        "account",
        "masterKey",
        "privateKey",
        "ciphertext",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "rotation result disclosed a backend or secret field"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_only_initialization_is_resumed_with_its_existing_key_before_rotation() {
    let directory = tempfile::tempdir().expect("temporary Vault");
    let vault_root = directory
        .path()
        .join("catalog-owner-only-master-key-rotation");
    let (state, master_key_controller) = desktop_state(&vault_root);
    let owner = uuid::Uuid::new_v4();
    state
        .master_keys
        .create_if_absent(owner, 1)
        .await
        .expect("seed initial owner key");
    {
        let guard = state
            .secret_files
            .lock_exclusive()
            .expect("initial secret-store lock");
        guard
            .initialize(owner, 1)
            .expect("initialize test keyset")
            .into_durable()
            .expect("durable test keyset");
    }
    std::fs::remove_dir_all(vault_root.join("secret-blobs").join("keyset"))
        .expect("simulate owner-only initialization crash");
    master_key_controller.clear_operation_log();

    let result = run_saved_host_operation(state.clone(), |state| async move {
        begin_managed_master_key_rotation(&state).await
    })
    .await
    .expect("resume owner-only initialization and rotate");

    assert_eq!(result.status, ManagedSshMasterKeyRotationStatus::Completed);
    assert_eq!(result.retained_secret_revision_count, 0);
    assert_eq!(
        master_key_controller
            .operation_log()
            .count(CredentialOperation::Upsert),
        1,
        "only the new target epoch may be created; epoch one must be reused"
    );
    let state_after = state
        .secret_files
        .lock_exclusive()
        .expect("rotated secret-store lock")
        .load_state()
        .expect("rotated secret-store state");
    assert_eq!(state_after.store_id(), owner);
    assert_eq!(state_after.active_master_key_epoch(), 2);
    assert_eq!(
        state
            .master_keys
            .load(owner, 1)
            .await
            .expect_err("resumed source epoch is retired")
            .code(),
        CredentialErrorCode::NotFound
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_only_initialization_with_a_missing_key_never_regenerates_it() {
    let directory = tempfile::tempdir().expect("temporary Vault");
    let vault_root = directory
        .path()
        .join("catalog-owner-only-missing-master-key");
    let (state, master_key_controller) = desktop_state(&vault_root);
    let owner = uuid::Uuid::new_v4();
    state
        .master_keys
        .create_if_absent(owner, 1)
        .await
        .expect("seed initial owner key");
    {
        let guard = state
            .secret_files
            .lock_exclusive()
            .expect("initial secret-store lock");
        guard
            .initialize(owner, 1)
            .expect("initialize test keyset")
            .into_durable()
            .expect("durable test keyset");
    }
    std::fs::remove_dir_all(vault_root.join("secret-blobs").join("keyset"))
        .expect("simulate owner-only initialization crash");
    state
        .master_keys
        .delete(owner, 1)
        .await
        .expect("simulate missing owner key");
    master_key_controller.clear_operation_log();

    let error = run_saved_host_operation(state.clone(), |state| async move {
        begin_managed_master_key_rotation(&state).await
    })
    .await
    .expect_err("missing owner key must require repair");

    assert!(error.starts_with(MANAGED_KEY_REPAIR_REQUIRED));
    assert_eq!(
        master_key_controller
            .operation_log()
            .count(CredentialOperation::Upsert),
        0,
        "an existing owner must never receive a generated replacement key"
    );
    assert_eq!(
        state
            .master_keys
            .load(owner, 1)
            .await
            .expect_err("owner key remains missing")
            .code(),
        CredentialErrorCode::NotFound
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn desktop_master_key_rotation_reencrypts_current_and_fallback_revisions() {
    let directory = tempfile::tempdir().expect("temporary Vault");
    let vault_root = directory.path().join("catalog-master-key-rotation");
    let (state, _) = desktop_state(&vault_root);
    create_test_key(&state, "Rotation source key").await;
    let fallback = state
        .saved_hosts
        .graph()
        .expect("source graph")
        .managed_ssh_keys()[0]
        .clone();
    replace_test_key(
        &state,
        fallback.id.as_str().to_owned(),
        "Rotation target key",
    )
    .await;
    let current = state
        .saved_hosts
        .graph()
        .expect("updated rotation graph")
        .managed_ssh_keys()[0]
        .clone();
    let (owner, source_epoch) = {
        let guard = state
            .secret_files
            .lock_exclusive()
            .expect("source secret-store lock");
        let source = guard.load_state().expect("source state");
        (source.store_id(), source.active_master_key_epoch())
    };

    let result = run_saved_host_operation(state.clone(), |state| async move {
        begin_managed_master_key_rotation(&state).await
    })
    .await
    .expect("durable desktop master-key rotation");
    assert_eq!(result.status, ManagedSshMasterKeyRotationStatus::Completed);
    assert_eq!(result.retained_secret_revision_count, 2);

    let target_epoch = {
        let guard = state
            .secret_files
            .lock_exclusive()
            .expect("target secret-store lock");
        let target = guard.load_state().expect("target state");
        assert_eq!(target.store_id(), owner);
        assert_eq!(
            target.active_master_key_epoch(),
            source_epoch.checked_add(1).expect("target epoch")
        );
        target.active_master_key_epoch()
    };
    let old_error = state
        .master_keys
        .load(owner, source_epoch)
        .await
        .expect_err("source master key must be retired");
    assert_eq!(old_error.code(), CredentialErrorCode::NotFound);
    state
        .master_keys
        .load(owner, target_epoch)
        .await
        .expect("target master key remains available");

    let fallback_bundle = resolve_bundle(&state, fallback).await;
    assert_eq!(fallback_bundle.private_key(), CREATE_PRIVATE.as_bytes());
    let current_key = state
        .saved_hosts
        .graph()
        .expect("current graph after rotation")
        .managed_ssh_keys()
        .iter()
        .find(|key| key.id.as_str() == current.id.as_str())
        .expect("current key after rotation")
        .clone();
    let current_bundle = resolve_bundle(&state, current_key).await;
    assert_eq!(current_bundle.private_key(), UPDATED_PRIVATE.as_bytes());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_delete_after_side_effect_is_confirmed_by_reread_and_acknowledged() {
    let directory = tempfile::tempdir().expect("temporary Vault");
    let vault_root = directory
        .path()
        .join("catalog-master-key-delete-after-side-effect");
    let (state, master_key_controller) = desktop_state(&vault_root);
    create_test_key(&state, "Delete confirmation key").await;
    let (owner, source_epoch) = {
        let guard = state
            .secret_files
            .lock_exclusive()
            .expect("source secret-store lock");
        let source = guard.load_state().expect("source state");
        (source.store_id(), source.active_master_key_epoch())
    };
    master_key_controller.clear_operation_log();
    master_key_controller.set_failure(
        CredentialOperation::Delete,
        1,
        FailureTiming::AfterSideEffect,
        CredentialErrorCode::BackendFailure,
    );

    let result = run_saved_host_operation(state.clone(), |state| async move {
        begin_managed_master_key_rotation(&state).await
    })
    .await
    .expect("post-side-effect delete is confirmed by reread");

    assert_eq!(result.status, ManagedSshMasterKeyRotationStatus::Completed);
    assert_eq!(result.retained_secret_revision_count, 1);
    assert_eq!(
        master_key_controller
            .operation_log()
            .count(CredentialOperation::Delete),
        1
    );
    let source_error = state
        .master_keys
        .load(owner, source_epoch)
        .await
        .expect_err("source key must be authoritatively absent");
    assert_eq!(source_error.code(), CredentialErrorCode::NotFound);
    assert!(
        state
            .secret_files
            .lock_exclusive()
            .expect("post-rotation secret-store lock")
            .inspect_master_key_rotation()
            .expect("inspect acknowledged rotation")
            .is_none(),
        "a confirmed source deletion must durably acknowledge the lineage"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn target_key_final_reread_failure_never_deletes_source_and_is_recoverable() {
    let directory = tempfile::tempdir().expect("temporary Vault");
    let vault_root = directory
        .path()
        .join("catalog-master-key-target-reread-failure");
    let (state, master_key_controller) = desktop_state(&vault_root);
    create_test_key(&state, "Target reread key").await;
    let (owner, source_epoch) = {
        let guard = state
            .secret_files
            .lock_exclusive()
            .expect("source secret-store lock");
        let source = guard.load_state().expect("source state");
        (source.store_id(), source.active_master_key_epoch())
    };
    let target_epoch = source_epoch.checked_add(1).expect("target epoch");

    // Seed the exact orphan target key that a crash before the first rotation
    // artifact may leave. The new rotation must reuse it. Its keyring reads
    // are then: source confirmation, target reuse, and the final target
    // reread immediately before source retirement.
    state
        .master_keys
        .create_if_absent(owner, target_epoch)
        .await
        .expect("seed target master key");
    master_key_controller.clear_operation_log();
    master_key_controller.set_failure(
        CredentialOperation::Resolve,
        3,
        FailureTiming::BeforeSideEffect,
        CredentialErrorCode::StorageUnavailable,
    );

    let error = run_saved_host_operation(state.clone(), |state| async move {
        begin_managed_master_key_rotation(&state).await
    })
    .await
    .expect_err("an unavailable final target reread must fail closed");
    assert!(error.starts_with(MANAGED_KEY_REPAIR_REQUIRED));
    assert_eq!(
        master_key_controller
            .operation_log()
            .count(CredentialOperation::Resolve),
        3,
        "the injected failure must be the final target-key reread"
    );
    assert_eq!(
        master_key_controller
            .operation_log()
            .count(CredentialOperation::Delete),
        0,
        "source retirement must not start before the target key is reread"
    );
    state
        .master_keys
        .load(owner, source_epoch)
        .await
        .expect("source key remains after target reread failure");
    assert!(
        state
            .secret_files
            .lock_exclusive()
            .expect("completed target lock")
            .inspect_master_key_rotation()
            .expect("inspect completed target")
            .is_some_and(|recovery| recovery.completed()),
        "the stable target must remain restart-recoverable"
    );

    master_key_controller.clear_failures();
    run_saved_host_operation(state.clone(), |_state| async move { Ok(()) })
        .await
        .expect("a later operation completes target confirmation and retirement");
    let source_error = state
        .master_keys
        .load(owner, source_epoch)
        .await
        .expect_err("recovery retires the source key");
    assert_eq!(source_error.code(), CredentialErrorCode::NotFound);
    state
        .master_keys
        .load(owner, target_epoch)
        .await
        .expect("recovery retains the target key");
    assert!(
        state
            .secret_files
            .lock_exclusive()
            .expect("recovered target lock")
            .inspect_master_key_rotation()
            .expect("inspect recovered rotation")
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn completed_rotation_with_missing_target_key_never_generates_a_replacement() {
    let directory = tempfile::tempdir().expect("temporary Vault");
    let vault_root = directory
        .path()
        .join("catalog-master-key-completed-target-missing");
    let (state, master_key_controller) = desktop_state(&vault_root);
    create_test_key(&state, "Missing completed target key").await;
    let (owner, source_epoch) = {
        let guard = state
            .secret_files
            .lock_exclusive()
            .expect("source secret-store lock");
        let source = guard.load_state().expect("source state");
        (source.store_id(), source.active_master_key_epoch())
    };
    let target_epoch = source_epoch.checked_add(1).expect("target epoch");
    master_key_controller.set_failure(
        CredentialOperation::Delete,
        1,
        FailureTiming::BeforeSideEffect,
        CredentialErrorCode::BackendFailure,
    );
    let first = run_saved_host_operation(state.clone(), |state| async move {
        begin_managed_master_key_rotation(&state).await
    })
    .await
    .expect("stable target with retryable source cleanup");
    assert_eq!(
        first.status,
        ManagedSshMasterKeyRotationStatus::CompletedCleanupPending
    );
    assert!(
        state
            .secret_files
            .lock_exclusive()
            .expect("completed target lock")
            .inspect_master_key_rotation()
            .expect("inspect completed target")
            .is_some_and(|recovery| recovery.completed())
    );

    master_key_controller.clear_failures();
    state
        .master_keys
        .delete(owner, target_epoch)
        .await
        .expect("remove target key to simulate external loss");
    master_key_controller.clear_operation_log();

    let error = run_saved_host_operation(state.clone(), |_state| async move { Ok(()) })
        .await
        .expect_err("completed rotation with a missing target key must fail closed");
    assert!(error.starts_with(MANAGED_KEY_REPAIR_REQUIRED));
    assert_eq!(
        master_key_controller
            .operation_log()
            .count(CredentialOperation::Upsert),
        0,
        "recovery must never generate a replacement target key"
    );
    assert_eq!(
        master_key_controller
            .operation_log()
            .count(CredentialOperation::Delete),
        0,
        "recovery must retain the still-usable source key"
    );
    state
        .master_keys
        .load(owner, source_epoch)
        .await
        .expect("source key remains available for explicit repair");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn old_master_key_delete_failure_is_retryable_without_rolling_back_target() {
    let directory = tempfile::tempdir().expect("temporary Vault");
    let vault_root = directory.path().join("catalog-master-key-cleanup-retry");
    let (state, master_key_controller) = desktop_state(&vault_root);
    create_test_key(&state, "Cleanup retry key").await;
    let (owner, source_epoch) = {
        let guard = state
            .secret_files
            .lock_exclusive()
            .expect("source secret-store lock");
        let source = guard.load_state().expect("source state");
        (source.store_id(), source.active_master_key_epoch())
    };
    master_key_controller.set_failure(
        CredentialOperation::Delete,
        1,
        FailureTiming::BeforeSideEffect,
        CredentialErrorCode::BackendFailure,
    );

    let result = run_saved_host_operation(state.clone(), |state| async move {
        begin_managed_master_key_rotation(&state).await
    })
    .await
    .expect("rotation remains successful when old-key cleanup is retryable");
    assert_eq!(
        result.status,
        ManagedSshMasterKeyRotationStatus::CompletedCleanupPending
    );
    state
        .master_keys
        .load(owner, source_epoch)
        .await
        .expect("failed cleanup retains the source key");
    let target_epoch = source_epoch.checked_add(1).expect("target epoch");
    let target_before_retry = state
        .master_keys
        .load(owner, target_epoch)
        .await
        .expect("active target key after cleanup failure");
    drop(target_before_retry);

    master_key_controller.clear_failures();
    run_saved_host_operation(state.clone(), |_state| async move { Ok(()) })
        .await
        .expect("next coordinated operation retries retirement");
    let old_error = state
        .master_keys
        .load(owner, source_epoch)
        .await
        .expect_err("retry removes the source key");
    assert_eq!(old_error.code(), CredentialErrorCode::NotFound);
    state
        .master_keys
        .load(owner, target_epoch)
        .await
        .expect("retry never rolls back the target key");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn completed_historical_marker_allows_a_later_explicit_rotation() {
    let directory = tempfile::tempdir().expect("temporary Vault");
    let vault_root = directory
        .path()
        .join("catalog-repeated-master-key-rotation");
    let (state, _) = desktop_state(&vault_root);
    create_test_key(&state, "Repeated rotation key").await;
    let initial_epoch = {
        let guard = state
            .secret_files
            .lock_exclusive()
            .expect("initial secret-store lock");
        guard
            .load_state()
            .expect("initial state")
            .active_master_key_epoch()
    };
    run_saved_host_operation(state.clone(), |state| async move {
        begin_managed_master_key_rotation(&state).await
    })
    .await
    .expect("first rotation");

    assert!(
        state
            .secret_files
            .lock_exclusive()
            .expect("post-first-rotation lock")
            .inspect_master_key_rotation()
            .expect("inspect acknowledged first rotation")
            .is_none(),
        "durable source-key retirement must acknowledge the completed lineage"
    );

    let second =
        run_saved_host_operation_with_rotation(state.clone(), |state, recovered| async move {
            assert!(recovered.is_none(), "acknowledged lineage must stay hidden");
            begin_managed_master_key_rotation(&state).await
        })
        .await
        .expect("second explicit rotation");
    assert_eq!(second.status, ManagedSshMasterKeyRotationStatus::Completed);
    let final_epoch = state
        .secret_files
        .lock_exclusive()
        .expect("final secret-store lock")
        .load_state()
        .expect("final state")
        .active_master_key_epoch();
    assert_eq!(
        final_epoch,
        initial_epoch.checked_add(2).expect("second target epoch")
    );
}
