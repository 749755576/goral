use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use netcatty_secret_store::{
    EnvelopeMasterKey, SecretEnvelopeContext, SecretEnvelopeSlot, SecretFileMutation,
    SecretFileStore, SecretFileStoreError, SecretFileStoreErrorCode, SecretFileStoreState,
    SecretObjectLocator, SecretObjectRetention, SshSecretBundle, encrypt_ssh_secret_bundle,
};
use tempfile::TempDir;
use uuid::Uuid;

const LOCK_FILE: &str = "transaction.lock";
const OWNER_FILE: &str = "owner.json";

fn custody_root(temp: &TempDir, marker: &str) -> PathBuf {
    let parent = temp.path().join(marker).join("vault");
    fs::create_dir_all(&parent).expect("create app-data parent");
    parent.join("secret-blobs")
}

fn open_empty_store(marker: &str) -> (TempDir, PathBuf, SecretFileStore) {
    let temp = tempfile::tempdir().expect("temporary app-data directory");
    let root = custody_root(&temp, marker);
    let store = SecretFileStore::open(&root).expect("open empty secret store");
    (temp, root, store)
}

fn initialize(store: &SecretFileStore, store_id: Uuid, epoch: u32) -> SecretFileStoreState {
    store
        .with_exclusive_lock(|guard| guard.initialize(store_id, epoch))
        .expect("initialize secret store")
        .into_durable()
        .expect("initialization must be durable")
}

fn load_state(store: &SecretFileStore) -> SecretFileStoreState {
    store
        .with_exclusive_lock(|guard| guard.load_state())
        .expect("load secret store state")
}

fn derive_locator(store: &SecretFileStore, entity_id: &str) -> SecretObjectLocator {
    store
        .with_exclusive_lock(|guard| guard.derive_object_locator(entity_id))
        .expect("derive object locator")
}

fn bundle(marker: &str) -> SshSecretBundle {
    SshSecretBundle::new(
        format!("private-{marker}").into_bytes(),
        Some(format!("public-{marker}").into_bytes()),
        Some(format!("certificate-{marker}").into_bytes()),
        Some(format!("passphrase-{marker}").into_bytes()),
    )
    .expect("bounded SSH secret bundle")
}

fn publish_object(
    store: &SecretFileStore,
    state: &SecretFileStoreState,
    key: &EnvelopeMasterKey,
    locator: &SecretObjectLocator,
    revision: u64,
    marker: &str,
) {
    let prepared = store
        .with_exclusive_lock(|guard| {
            guard.prepare_object(state, key, locator, revision, bundle(marker))
        })
        .expect("prepare object");
    assert_eq!(prepared.revision(), revision);
    let mutation = store
        .with_exclusive_lock(|guard| guard.publish_object(key, &prepared))
        .expect("publish object");
    assert!(matches!(mutation, SecretFileMutation::Durable(())));
}

fn object_directory(root: &Path, locator: &SecretObjectLocator) -> PathBuf {
    let opaque = locator.backend_locator_hex();
    assert_eq!(opaque.len(), 64);
    assert!(
        opaque
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    root.join("objects").join(&opaque[..2]).join(opaque)
}

fn retention(
    entity_id: &str,
    locator: &SecretObjectLocator,
    revision: u64,
) -> SecretObjectRetention {
    SecretObjectRetention::new(entity_id, locator.backend_locator_hex(), revision)
        .expect("valid object retention")
}

fn regular_file_snapshot(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn visit(root: &Path, current: &Path, files: &mut Vec<(PathBuf, Vec<u8>)>) {
        let mut entries = fs::read_dir(current)
            .expect("read snapshot directory")
            .map(|entry| entry.expect("read snapshot entry"))
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                visit(root, &path, files);
            } else {
                files.push((
                    path.strip_prefix(root)
                        .expect("relative snapshot path")
                        .to_path_buf(),
                    fs::read(path).expect("read snapshot file"),
                ));
            }
        }
    }

    let mut files = Vec::new();
    visit(root, root, &mut files);
    files
}

fn only_regular_file(directory: &Path) -> PathBuf {
    let mut files = fs::read_dir(directory)
        .expect("read slot directory")
        .map(|entry| entry.expect("read directory entry").path())
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    files.sort();
    assert_eq!(files.len(), 1, "slot must contain exactly one file");
    files.pop().expect("one slot file")
}

fn regular_files(directory: &Path) -> Vec<PathBuf> {
    let mut files = fs::read_dir(directory)
        .expect("read directory")
        .map(|entry| entry.expect("read directory entry").path())
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    files.sort();
    files
}

fn assert_fixed_error(
    error: SecretFileStoreError,
    expected: SecretFileStoreErrorCode,
    forbidden: &[&str],
) {
    assert_eq!(error.code(), expected);
    let rendered = format!("{error} {error:?}");
    for marker in forbidden {
        if marker.is_empty() {
            continue;
        }
        assert!(
            !rendered.contains(marker),
            "fixed error disclosed forbidden marker {marker:?}: {rendered}"
        );
    }
}

fn assert_keyset_file_name(path: &Path, generation: u64) {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("UTF-8 keyset filename");
    let prefix = format!("keyset-{generation:020}-");
    assert!(
        name.starts_with(&prefix),
        "unexpected keyset filename: {name}"
    );
    assert!(name.ends_with(".json"), "unexpected keyset suffix: {name}");
    let random = &name[prefix.len()..name.len() - ".json".len()];
    assert_eq!(random.len(), 32);
    assert!(
        random
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
}

fn assert_blob_file_name(path: &Path, revision: u64, generation: u64) {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("UTF-8 blob filename");
    let prefix = format!("blob-{revision:020}-{generation:020}-");
    assert!(
        name.starts_with(&prefix),
        "unexpected blob filename: {name}"
    );
    assert!(name.ends_with(".ncsb"), "unexpected blob suffix: {name}");
    let random = &name[prefix.len()..name.len() - ".ncsb".len()];
    assert_eq!(random.len(), 32);
    assert!(
        random
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
}

fn assert_lower_hex(value: &str, length: usize) {
    assert_eq!(value.len(), length);
    assert!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "value is not canonical lowercase hex"
    );
}

#[test]
fn empty_open_creates_only_the_permanent_non_truncated_lock() {
    let (_temp, root, store) = open_empty_store("empty-root-marker");
    let names = fs::read_dir(&root)
        .expect("read root")
        .map(|entry| entry.expect("root entry").file_name())
        .collect::<Vec<_>>();
    assert_eq!(names, vec![LOCK_FILE]);

    let owner = store
        .with_exclusive_lock(|guard| guard.owner_id())
        .expect("inspect empty owner");
    assert_eq!(owner, None);
    let error = store
        .with_exclusive_lock(|guard| guard.load_state())
        .expect_err("empty store has no state");
    assert_fixed_error(
        error,
        SecretFileStoreErrorCode::NotInitialized,
        &["empty-root-marker", root.to_string_lossy().as_ref()],
    );

    drop(store);
    let lock_path = root.join(LOCK_FILE);
    let mut lock = OpenOptions::new()
        .append(true)
        .open(&lock_path)
        .expect("open lock marker");
    lock.write_all(b"lock-file-must-not-be-truncated")
        .expect("write lock marker");
    lock.sync_all().expect("sync lock marker");
    drop(lock);

    let error = SecretFileStore::open(&root).expect_err("non-empty lock fails closed");
    assert_eq!(error.code(), SecretFileStoreErrorCode::LockUnavailable);
    let mut bytes = Vec::new();
    fs::File::open(lock_path)
        .expect("read lock")
        .read_to_end(&mut bytes)
        .expect("read lock marker");
    assert_eq!(bytes, b"lock-file-must-not-be-truncated");
}

#[test]
fn roots_and_unknown_artifacts_fail_closed_without_disclosure_or_cleanup() {
    let relative_marker = "relative-secret-root-marker";
    let relative = SecretFileStore::open(relative_marker).expect_err("relative root is rejected");
    assert_fixed_error(
        relative,
        SecretFileStoreErrorCode::InvalidRoot,
        &[relative_marker],
    );

    let temp = tempfile::tempdir().expect("temporary app-data directory");
    let root = custody_root(&temp, "foreign-root-marker");
    fs::create_dir_all(&root).expect("create root");
    let foreign = root.join("foreign-artifact-must-survive");
    fs::write(&foreign, b"foreign artifact marker").expect("write foreign artifact");
    let error = SecretFileStore::open(&root).expect_err("unknown artifact is rejected");
    assert_fixed_error(
        error,
        SecretFileStoreErrorCode::ArtifactConflict,
        &["foreign-root-marker", "foreign-artifact-must-survive"],
    );
    assert_eq!(
        fs::read(foreign).expect("foreign artifact remains"),
        b"foreign artifact marker"
    );
}

#[test]
fn initialization_is_idempotent_and_freezes_owner_and_keyset_layout() {
    let (_temp, root, store) = open_empty_store("initialize-root-marker");
    let store_id = Uuid::new_v4();
    let state = initialize(&store, store_id, 7);
    assert_eq!(state.store_id(), store_id);
    assert_eq!(state.active_master_key_epoch(), 7);
    assert_eq!(state.keyset_generation(), 2);
    assert_eq!(load_state(&store), state);
    assert_eq!(
        store
            .with_exclusive_lock(|guard| guard.owner_id())
            .expect("load owner"),
        Some(store_id)
    );

    assert!(root.join(OWNER_FILE).is_file());
    assert!(root.join(LOCK_FILE).is_file());
    let slot_a = regular_files(&root.join("keyset").join("slot-a"));
    let slot_b = regular_files(&root.join("keyset").join("slot-b"));
    assert_eq!(slot_a.len(), 1);
    assert_eq!(slot_b.len(), 1);
    assert_keyset_file_name(&slot_a[0], 1);
    assert_keyset_file_name(&slot_b[0], 2);

    let repeated = store
        .with_exclusive_lock(|guard| guard.initialize(store_id, 7))
        .expect("retry identical initialization")
        .into_durable()
        .expect("identical initialization is durable");
    assert_eq!(repeated, state);
    assert_eq!(regular_files(&root.join("keyset").join("slot-a")), slot_a);
    assert_eq!(regular_files(&root.join("keyset").join("slot-b")), slot_b);

    let other_id = Uuid::new_v4();
    let error = store
        .with_exclusive_lock(|guard| guard.initialize(other_id, 7))
        .expect_err("foreign owner cannot replace existing owner");
    assert_fixed_error(
        error,
        SecretFileStoreErrorCode::InvalidOwner,
        &[
            "initialize-root-marker",
            &store_id.to_string(),
            &other_id.to_string(),
        ],
    );
    assert_eq!(load_state(&store), state);
}

#[test]
fn owner_only_crash_state_retries_initialization_without_replacing_owner() {
    let (_temp, root, store) = open_empty_store("owner-only-retry-root-marker");
    let store_id = Uuid::new_v4();
    initialize(&store, store_id, 19);
    let owner_before = fs::read(root.join(OWNER_FILE)).expect("read durable owner");
    drop(store);

    fs::remove_dir_all(root.join("keyset")).expect("simulate crash before keyset publication");
    fs::remove_dir_all(root.join("objects")).expect("simulate crash before object root creation");
    let reopened = SecretFileStore::open(&root).expect("owner-only state remains recoverable");
    assert_eq!(
        reopened
            .with_exclusive_lock(|guard| guard.owner_id())
            .expect("read retained owner"),
        Some(store_id)
    );
    let repaired = initialize(&reopened, store_id, 19);
    assert_eq!(repaired.store_id(), store_id);
    assert_eq!(repaired.active_master_key_epoch(), 19);
    assert_eq!(repaired.keyset_generation(), 2);
    assert_eq!(
        fs::read(root.join(OWNER_FILE)).expect("owner remains byte-identical"),
        owner_before
    );
}

#[test]
fn owner_with_missing_keyset_refuses_to_initialize_over_existing_objects() {
    let (_temp, root, store) = open_empty_store("owner-missing-keyset-object-root-marker");
    let store_id = Uuid::new_v4();
    let state = initialize(&store, store_id, 29);
    let key = EnvelopeMasterKey::from_bytes([0x39; 32]).expect("master key");
    let locator = derive_locator(&store, "owner-missing-keyset-object-entity");
    publish_object(
        &store,
        &state,
        &key,
        &locator,
        1,
        "owner-missing-keyset-object-secret",
    );
    let object = object_directory(&root, &locator);
    let blob_a = only_regular_file(&object.join("slot-a"));
    let blob_b = only_regular_file(&object.join("slot-b"));
    let before_a = fs::read(&blob_a).expect("read A blob");
    let before_b = fs::read(&blob_b).expect("read B blob");

    for slot in ["slot-a", "slot-b"] {
        for keyset in regular_files(&root.join("keyset").join(slot)) {
            fs::remove_file(keyset).expect("simulate loss before any keyset is visible");
        }
    }
    let error = store
        .with_exclusive_lock(|guard| guard.initialize(store_id, 29))
        .expect_err("an owner alone cannot authorize a fresh keyset over ciphertext");

    assert_fixed_error(
        error,
        SecretFileStoreErrorCode::InvalidKeyset,
        &[
            "owner-missing-keyset-object-root-marker",
            "owner-missing-keyset-object-entity",
            "owner-missing-keyset-object-secret",
            &store_id.to_string(),
            &locator.backend_locator_hex(),
        ],
    );
    assert!(regular_files(&root.join("keyset").join("slot-a")).is_empty());
    assert!(regular_files(&root.join("keyset").join("slot-b")).is_empty());
    assert_eq!(fs::read(blob_a).expect("A blob survives"), before_a);
    assert_eq!(fs::read(blob_b).expect("B blob survives"), before_b);
}

#[test]
fn owned_owner_temp_is_recoverable_only_with_the_visible_matching_owner() {
    let (_temp, root, store) = open_empty_store("owner-temp-recovery-root-marker");
    let store_id = Uuid::new_v4();
    initialize(&store, store_id, 23);
    drop(store);

    let owner = fs::read(root.join(OWNER_FILE)).expect("read owner");
    let temporary = root.join(format!(".owner-{}.tmp", Uuid::new_v4().simple()));
    fs::write(&temporary, &owner).expect("restore owned crash temp");
    let reopened = SecretFileStore::open(&root).expect("matching owner temp is recoverable");
    initialize(&reopened, store_id, 23);
    assert!(
        !temporary.exists(),
        "durable retry cleans only its owned temp"
    );

    let foreign = root.join(format!(".owner-{}.tmp", Uuid::new_v4().simple()));
    let other_root = custody_root(&_temp, "foreign-owner-temp-source");
    let other = SecretFileStore::open(&other_root).expect("open other store");
    initialize(&other, Uuid::new_v4(), 1);
    fs::write(
        &foreign,
        fs::read(other_root.join(OWNER_FILE)).expect("read foreign owner"),
    )
    .expect("write foreign owner temp");
    drop(reopened);
    let error = SecretFileStore::open(&root).expect_err("foreign owner temp fails closed");
    assert_eq!(error.code(), SecretFileStoreErrorCode::ArtifactConflict);
    assert!(foreign.exists(), "foreign owner temp is preserved");
}

#[test]
fn missing_permanent_lock_is_never_silently_recreated_for_an_owned_store() {
    let (_temp, root, store) = open_empty_store("missing-lock-root-marker");
    initialize(&store, Uuid::new_v4(), 1);
    drop(store);
    fs::remove_file(root.join(LOCK_FILE)).expect("simulate missing permanent lock");

    let error = SecretFileStore::open(&root).expect_err("owned store without lock fails closed");
    assert_eq!(error.code(), SecretFileStoreErrorCode::LockUnavailable);
    assert!(!root.join(LOCK_FILE).exists());
}

#[test]
fn owner_and_keyset_json_schemas_are_exact_bounded_and_checksummed() {
    let (_temp, root, store) = open_empty_store("metadata-schema-root-marker");
    let store_id = Uuid::new_v4();
    initialize(&store, store_id, 0x9abc_def0);

    let owner_bytes = fs::read(root.join(OWNER_FILE)).expect("read owner JSON");
    assert!(owner_bytes.len() <= 4 * 1_024);
    assert!(!owner_bytes.ends_with(b"\n"));
    let owner: serde_json::Value = serde_json::from_slice(&owner_bytes).expect("parse owner JSON");
    let owner_object = owner.as_object().expect("owner object");
    let mut owner_fields = owner_object.keys().map(String::as_str).collect::<Vec<_>>();
    owner_fields.sort_unstable();
    assert_eq!(
        owner_fields,
        vec!["checksum", "formatVersion", "magic", "storeId"]
    );
    assert_eq!(owner["magic"], "netcatty-secret-blob-store");
    assert_eq!(owner["formatVersion"], 1);
    assert_eq!(owner["storeId"], store_id.to_string());
    assert_lower_hex(
        owner["checksum"].as_str().expect("owner checksum string"),
        64,
    );

    for (slot_name, slot_tag, generation) in [("slot-a", "a", 1_u64), ("slot-b", "b", 2)] {
        let path = only_regular_file(&root.join("keyset").join(slot_name));
        let bytes = fs::read(path).expect("read keyset JSON");
        assert!(bytes.len() <= 8 * 1_024);
        assert!(!bytes.ends_with(b"\n"));
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("parse keyset JSON");
        let object = value.as_object().expect("keyset object");
        let mut fields = object.keys().map(String::as_str).collect::<Vec<_>>();
        fields.sort_unstable();
        assert_eq!(
            fields,
            vec![
                "activeMasterKeyEpoch",
                "checksum",
                "formatVersion",
                "generation",
                "magic",
                "slot",
                "storeId",
            ]
        );
        assert_eq!(value["magic"], "netcatty-secret-blob-keyset");
        assert_eq!(value["formatVersion"], 1);
        assert_eq!(value["storeId"], store_id.to_string());
        assert_eq!(value["slot"], slot_tag);
        assert_eq!(value["generation"], generation);
        assert_eq!(value["activeMasterKeyEpoch"], 0x9abc_def0_u64);
        assert_lower_hex(
            value["checksum"].as_str().expect("keyset checksum string"),
            64,
        );
    }
}

#[test]
fn owner_rejects_unknown_fields_even_when_known_fields_and_checksum_are_unchanged() {
    let (_temp, root, store) = open_empty_store("owner-unknown-field-root-marker");
    let store_id = Uuid::new_v4();
    initialize(&store, store_id, 1);
    drop(store);

    let owner_path = root.join(OWNER_FILE);
    let mut owner: serde_json::Value =
        serde_json::from_slice(&fs::read(&owner_path).expect("read owner")).expect("parse owner");
    owner
        .as_object_mut()
        .expect("owner object")
        .insert("unknownField".to_owned(), serde_json::Value::Bool(true));
    fs::write(
        &owner_path,
        serde_json::to_vec(&owner).expect("serialize owner with unknown field"),
    )
    .expect("replace owner for corruption test");

    let error = SecretFileStore::open(&root).expect_err("unknown owner field is rejected");
    assert_fixed_error(
        error,
        SecretFileStoreErrorCode::InvalidOwner,
        &[
            "owner-unknown-field-root-marker",
            "unknownField",
            &store_id.to_string(),
        ],
    );
}

#[test]
fn owner_truncation_and_unknown_nested_artifacts_are_preserved_and_rejected() {
    let (_temp, root, store) = open_empty_store("owner-corruption-root-marker");
    let store_id = Uuid::new_v4();
    initialize(&store, store_id, 1);
    drop(store);

    fs::write(root.join(OWNER_FILE), b"{").expect("truncate owner");
    let error = SecretFileStore::open(&root).expect_err("truncated owner is rejected");
    assert_fixed_error(
        error,
        SecretFileStoreErrorCode::InvalidOwner,
        &[
            "owner-corruption-root-marker",
            &store_id.to_string(),
            root.to_string_lossy().as_ref(),
        ],
    );

    let (_temp, root, store) = open_empty_store("nested-artifact-root-marker");
    initialize(&store, Uuid::new_v4(), 1);
    let foreign = root
        .join("keyset")
        .join("slot-a")
        .join("foreign-keyset-entry");
    fs::write(&foreign, b"preserve me").expect("write unknown nested artifact");
    let error = store
        .with_exclusive_lock(|guard| guard.load_state())
        .expect_err("unknown nested keyset artifact is rejected");
    assert_eq!(error.code(), SecretFileStoreErrorCode::ArtifactConflict);
    assert_eq!(
        fs::read(foreign).expect("unknown artifact remains"),
        b"preserve me"
    );
}

#[test]
fn keyset_single_slot_fallback_is_read_only_and_dual_corruption_fails_closed() {
    let (_temp, root, store) = open_empty_store("keyset-fallback-root-marker");
    let store_id = Uuid::new_v4();
    initialize(&store, store_id, 3);
    let slot_a = only_regular_file(&root.join("keyset").join("slot-a"));
    let slot_b = only_regular_file(&root.join("keyset").join("slot-b"));

    fs::write(&slot_b, b"{").expect("corrupt higher keyset slot");
    let fallback = load_state(&store);
    assert_eq!(fallback.store_id(), store_id);
    assert_eq!(fallback.active_master_key_epoch(), 3);
    assert_eq!(fallback.keyset_generation(), 1);

    let mutation_error = store
        .with_exclusive_lock(|guard| guard.activate_master_key_epoch(&fallback, 4))
        .expect_err("fallback state cannot mutate keyset");
    assert!(matches!(
        mutation_error.code(),
        SecretFileStoreErrorCode::InvalidKeyset | SecretFileStoreErrorCode::DurabilityUnconfirmed
    ));
    let confirmation_error = store
        .with_exclusive_lock(|guard| guard.confirm_keyset_durability(&fallback))
        .expect_err("fallback state cannot confirm durability");
    assert!(matches!(
        confirmation_error.code(),
        SecretFileStoreErrorCode::InvalidKeyset | SecretFileStoreErrorCode::DurabilityUnconfirmed
    ));

    fs::write(slot_a, b"[").expect("corrupt remaining keyset slot");
    let error = store
        .with_exclusive_lock(|guard| guard.load_state())
        .expect_err("both keyset slots corrupt");
    assert_fixed_error(
        error,
        SecretFileStoreErrorCode::BothKeysetSlotsCorrupt,
        &["keyset-fallback-root-marker", &store_id.to_string(), "3"],
    );
}

#[test]
fn missing_keyset_second_slot_is_repaired_but_existing_first_slot_is_immutable() {
    let (_temp, root, store) = open_empty_store("keyset-repair-root-marker");
    initialize(&store, Uuid::new_v4(), 5);
    let slot_a = only_regular_file(&root.join("keyset").join("slot-a"));
    let a_before = fs::read(&slot_a).expect("read existing keyset A");
    let slot_b = only_regular_file(&root.join("keyset").join("slot-b"));
    fs::remove_file(slot_b).expect("simulate crash before keyset B publication");

    let fallback = load_state(&store);
    assert_eq!(fallback.keyset_generation(), 1);
    let repaired = store
        .with_exclusive_lock(|guard| guard.activate_master_key_epoch(&fallback, 5))
        .expect("repair missing keyset B")
        .into_durable()
        .expect("repaired keyset is durable");
    assert_eq!(repaired.keyset_generation(), 2);
    assert_eq!(repaired.active_master_key_epoch(), 5);
    assert_eq!(fs::read(&slot_a).expect("read retained A"), a_before);
    assert_eq!(
        regular_files(&root.join("keyset").join("slot-a")),
        vec![slot_a]
    );
    let repaired_b = only_regular_file(&root.join("keyset").join("slot-b"));
    assert_keyset_file_name(&repaired_b, 2);
}

#[test]
fn keyset_activation_publishes_an_adjacent_pair_and_stale_state_cannot_write() {
    let (_temp, root, store) = open_empty_store("keyset-rotation-root-marker");
    let initial = initialize(&store, Uuid::new_v4(), 1);
    let activated = store
        .with_exclusive_lock(|guard| guard.activate_master_key_epoch(&initial, 2))
        .expect("activate next epoch")
        .into_durable()
        .expect("epoch activation is durable");
    assert_eq!(activated.active_master_key_epoch(), 2);
    assert_eq!(activated.keyset_generation(), 4);
    assert_eq!(load_state(&store), activated);
    assert_eq!(
        store
            .with_exclusive_lock(|guard| guard.confirm_keyset_durability(&activated))
            .expect("confirm exact keyset"),
        activated
    );

    let slot_a = regular_files(&root.join("keyset").join("slot-a"));
    let slot_b = regular_files(&root.join("keyset").join("slot-b"));
    assert_eq!(slot_a.len(), 1);
    assert_eq!(slot_b.len(), 1);
    assert_keyset_file_name(&slot_a[0], 3);
    assert_keyset_file_name(&slot_b[0], 4);

    let stale = store
        .with_exclusive_lock(|guard| guard.activate_master_key_epoch(&initial, 3))
        .expect_err("stale keyset view cannot publish");
    assert_eq!(stale.code(), SecretFileStoreErrorCode::InvalidKeyset);
}

#[test]
fn epoch_change_is_blocked_while_any_blob_object_exists() {
    let (_temp, _root, store) = open_empty_store("blocked-rotation-root-marker");
    let state = initialize(&store, Uuid::new_v4(), 1);
    let key = EnvelopeMasterKey::from_bytes([0x35; 32]).expect("master key");
    let locator = derive_locator(&store, "blocked-rotation-entity");
    publish_object(&store, &state, &key, &locator, 1, "rotation-guard-secret");

    let error = store
        .with_exclusive_lock(|guard| guard.activate_master_key_epoch(&state, 2))
        .expect_err("epoch cannot change before a future full blob rotation transaction");
    assert_eq!(error.code(), SecretFileStoreErrorCode::InvalidKeyset);
    let resolved = store
        .with_exclusive_lock(|guard| guard.resolve_object(&key, &locator, 1))
        .expect("blocked epoch change leaves old blob readable");
    assert_eq!(resolved.private_key(), b"private-rotation-guard-secret");
    assert_eq!(load_state(&store), state);
}

#[test]
fn object_locator_and_immutable_blob_layout_are_opaque_and_round_trip() {
    let (_temp, root, store) = open_empty_store("object-round-trip-root-marker");
    let state = initialize(&store, Uuid::new_v4(), 11);
    let key = EnvelopeMasterKey::from_bytes([0x41; 32]).expect("master key");
    let entity = "real-entity-id-must-not-be-a-path";
    let secret_marker = "blob-secret-marker-must-not-leak";
    let locator = derive_locator(&store, entity);
    assert_eq!(locator, derive_locator(&store, entity));
    assert!(!format!("{locator:?}").contains(entity));

    publish_object(&store, &state, &key, &locator, 5, secret_marker);
    store
        .with_exclusive_lock(|guard| guard.confirm_object_durability(&key, &locator, 5))
        .expect("confirm both object slots");
    let resolved = store
        .with_exclusive_lock(|guard| guard.resolve_object(&key, &locator, 5))
        .expect("resolve published object");
    assert_eq!(
        resolved.private_key(),
        format!("private-{secret_marker}").as_bytes()
    );
    assert_eq!(
        resolved.passphrase(),
        Some(format!("passphrase-{secret_marker}").as_bytes())
    );

    let object = object_directory(&root, &locator);
    let slot_a = only_regular_file(&object.join("slot-a"));
    let slot_b = only_regular_file(&object.join("slot-b"));
    assert_blob_file_name(&slot_a, 5, 9);
    assert_blob_file_name(&slot_b, 5, 10);
    let a_bytes = fs::read(&slot_a).expect("read A ciphertext");
    let b_bytes = fs::read(&slot_b).expect("read B ciphertext");
    assert_ne!(a_bytes, b_bytes, "A/B envelopes require independent nonces");
    for marker in [entity, secret_marker, "private-blob-secret-marker"] {
        assert!(!slot_a.to_string_lossy().contains(marker));
        assert!(!slot_b.to_string_lossy().contains(marker));
        assert!(
            !a_bytes
                .windows(marker.len())
                .any(|window| window == marker.as_bytes())
        );
        assert!(
            !b_bytes
                .windows(marker.len())
                .any(|window| window == marker.as_bytes())
        );
    }

    let wrong_key = EnvelopeMasterKey::from_bytes([0x42; 32]).expect("wrong master key");
    let wrong_key_error = store
        .with_exclusive_lock(|guard| guard.resolve_object(&wrong_key, &locator, 5))
        .expect_err("wrong key fails closed");
    assert_eq!(
        wrong_key_error.code(),
        SecretFileStoreErrorCode::ObjectUnavailable
    );
    let wrong_revision = store
        .with_exclusive_lock(|guard| guard.resolve_object(&key, &locator, 6))
        .expect_err("wrong revision fails closed");
    assert_eq!(
        wrong_revision.code(),
        SecretFileStoreErrorCode::ObjectUnavailable
    );
}

#[test]
fn locator_derivation_is_store_bound_deterministic_and_rejects_hostile_ids() {
    let (_first_temp, _first_root, first_store) = open_empty_store("locator-first-root-marker");
    initialize(&first_store, Uuid::new_v4(), 1);
    let first = derive_locator(&first_store, "locator-entity-marker");
    let repeated = derive_locator(&first_store, "locator-entity-marker");
    let other_entity = derive_locator(&first_store, "locator-other-entity-marker");
    assert_eq!(first, repeated);
    assert_ne!(first, other_entity);
    let backend = first.backend_locator_hex();
    let restored = first_store
        .with_exclusive_lock(|guard| {
            guard.restore_object_locator("locator-entity-marker", &backend)
        })
        .expect("restore exact backend locator");
    assert_eq!(restored, first);

    let mut noncanonical = backend.to_ascii_uppercase();
    if noncanonical == backend {
        noncanonical.replace_range(..1, "g");
    }
    let restore_error = first_store
        .with_exclusive_lock(|guard| {
            guard.restore_object_locator("locator-entity-marker", &noncanonical)
        })
        .expect_err("noncanonical backend locator is rejected");
    assert_fixed_error(
        restore_error,
        SecretFileStoreErrorCode::InvalidInput,
        &[&backend, &noncanonical, "locator-entity-marker"],
    );

    let (_second_temp, _second_root, second_store) = open_empty_store("locator-second-root-marker");
    initialize(&second_store, Uuid::new_v4(), 1);
    let other_store = derive_locator(&second_store, "locator-entity-marker");
    assert_ne!(first, other_store);

    for hostile in ["", "control\nentity"] {
        let error = first_store
            .with_exclusive_lock(|guard| guard.derive_object_locator(hostile))
            .expect_err("hostile entity ID is rejected");
        assert_fixed_error(
            error,
            SecretFileStoreErrorCode::InvalidInput,
            &[hostile, "locator-entity-marker"],
        );
    }
}

#[test]
fn missing_second_blob_slot_is_completed_idempotently_across_new_nonces() {
    let (_temp, root, store) = open_empty_store("object-retry-root-marker");
    let state = initialize(&store, Uuid::new_v4(), 1);
    let key = EnvelopeMasterKey::from_bytes([0x51; 32]).expect("master key");
    let locator = derive_locator(&store, "object-retry-entity");
    publish_object(&store, &state, &key, &locator, 3, "retry-secret");

    let object = object_directory(&root, &locator);
    let original_a = only_regular_file(&object.join("slot-a"));
    let original_a_bytes = fs::read(&original_a).expect("read existing A");
    let missing_b = only_regular_file(&object.join("slot-b"));
    fs::remove_file(&missing_b).expect("simulate crash before B publication");

    let second_preparation = store
        .with_exclusive_lock(|guard| {
            guard.prepare_object(&state, &key, &locator, 3, bundle("retry-secret"))
        })
        .expect("prepare same logical bundle with new nonces");
    let result = store
        .with_exclusive_lock(|guard| guard.publish_object(&key, &second_preparation))
        .expect("complete missing B slot")
        .into_durable();
    assert_eq!(result, Some(()));
    assert_eq!(
        fs::read(&original_a).expect("existing A remains immutable"),
        original_a_bytes
    );
    assert_eq!(regular_files(&object.join("slot-a")), vec![original_a]);
    assert_eq!(regular_files(&object.join("slot-b")).len(), 1);
    store
        .with_exclusive_lock(|guard| guard.confirm_object_durability(&key, &locator, 3))
        .expect("completed A/B pair is durable");
}

#[test]
fn corrupt_blob_falls_back_for_read_but_cannot_confirm_or_mutate() {
    let (_temp, root, store) = open_empty_store("object-fallback-root-marker");
    let state = initialize(&store, Uuid::new_v4(), 2);
    let key = EnvelopeMasterKey::from_bytes([0x61; 32]).expect("master key");
    let locator = derive_locator(&store, "object-fallback-entity");
    publish_object(&store, &state, &key, &locator, 4, "fallback-secret");
    let object = object_directory(&root, &locator);
    let slot_a = only_regular_file(&object.join("slot-a"));
    let slot_b = only_regular_file(&object.join("slot-b"));

    fs::write(&slot_b, b"truncated").expect("corrupt higher blob slot");
    let fallback = store
        .with_exclusive_lock(|guard| guard.resolve_object(&key, &locator, 4))
        .expect("one valid slot remains readable");
    assert_eq!(fallback.private_key(), b"private-fallback-secret");
    let confirmation = store
        .with_exclusive_lock(|guard| guard.confirm_object_durability(&key, &locator, 4))
        .expect_err("corrupt fallback cannot be confirmed durable");
    assert!(matches!(
        confirmation.code(),
        SecretFileStoreErrorCode::ObjectUnavailable
            | SecretFileStoreErrorCode::DurabilityUnconfirmed
    ));

    let prepared = store
        .with_exclusive_lock(|guard| {
            guard.prepare_object(&state, &key, &locator, 4, bundle("fallback-secret"))
        })
        .expect("prepare logical retry");
    let mutation = store
        .with_exclusive_lock(|guard| guard.publish_object(&key, &prepared))
        .expect("an already-visible A copy requires an explicit post-publication outcome");
    assert!(matches!(
        mutation,
        SecretFileMutation::PublicationIndeterminate
    ));
    assert_eq!(
        fs::read(&slot_b).expect("corrupt B artifact remains untouched"),
        b"truncated"
    );

    fs::write(slot_a, b"also truncated").expect("corrupt remaining blob slot");
    let dual = store
        .with_exclusive_lock(|guard| guard.resolve_object(&key, &locator, 4))
        .expect_err("both blob slots corrupt");
    assert_fixed_error(
        dual,
        SecretFileStoreErrorCode::ObjectUnavailable,
        &[
            "object-fallback-root-marker",
            "object-fallback-entity",
            "fallback-secret",
            &locator.backend_locator_hex(),
        ],
    );
}

#[test]
fn unknown_blob_artifact_blocks_fallback_and_is_preserved() {
    let (_temp, root, store) = open_empty_store("unknown-blob-root-marker");
    let state = initialize(&store, Uuid::new_v4(), 2);
    let key = EnvelopeMasterKey::from_bytes([0x62; 32]).expect("master key");
    let locator = derive_locator(&store, "unknown-blob-entity");
    publish_object(&store, &state, &key, &locator, 6, "unknown-blob-secret");
    let foreign = object_directory(&root, &locator)
        .join("slot-b")
        .join("foreign-artifact-marker");
    fs::write(&foreign, b"preserve unknown").expect("write unknown blob artifact");

    let error = store
        .with_exclusive_lock(|guard| guard.resolve_object(&key, &locator, 6))
        .expect_err("unknown artifact must not be treated as corrupt-slot fallback");
    assert_eq!(error.code(), SecretFileStoreErrorCode::ArtifactConflict);
    assert_eq!(
        fs::read(foreign).expect("unknown survives"),
        b"preserve unknown"
    );
}

#[test]
fn conflicting_valid_temp_for_the_same_revision_blocks_read_and_confirmation() {
    let (_temp, root, store) = open_empty_store("object-temp-conflict-root-marker");
    let store_id = Uuid::new_v4();
    let state = initialize(&store, store_id, 1);
    let key = EnvelopeMasterKey::from_bytes([0x66; 32]).expect("master key");
    let entity_id = "object-temp-conflict-entity";
    let locator = derive_locator(&store, entity_id);
    publish_object(&store, &state, &key, &locator, 2, "committed-secret");

    let context = SecretEnvelopeContext::new(store_id, entity_id, 2, SecretEnvelopeSlot::A, 3, 1)
        .expect("conflicting temp context");
    let conflicting = encrypt_ssh_secret_bundle(&key, &context, bundle("conflicting-secret"))
        .expect("encrypt conflicting but authentic temp");
    let temp_name = format!(".blob-{:020}-{:020}-{}.tmp", 2, 3, Uuid::new_v4().simple());
    let temp_path = object_directory(&root, &locator)
        .join("slot-a")
        .join(temp_name);
    fs::write(&temp_path, conflicting.as_bytes()).expect("write crash-like conflicting temp");

    let read_error = store
        .with_exclusive_lock(|guard| guard.resolve_object(&key, &locator, 2))
        .expect_err("conflicting authentic temp must block fallback read");
    assert!(matches!(
        read_error.code(),
        SecretFileStoreErrorCode::ArtifactConflict | SecretFileStoreErrorCode::ObjectUnavailable
    ));
    let confirm_error = store
        .with_exclusive_lock(|guard| guard.confirm_object_durability(&key, &locator, 2))
        .expect_err("conflicting authentic temp must block durability confirmation");
    assert!(matches!(
        confirm_error.code(),
        SecretFileStoreErrorCode::ArtifactConflict
            | SecretFileStoreErrorCode::ObjectUnavailable
            | SecretFileStoreErrorCode::DurabilityUnconfirmed
    ));
    assert!(
        temp_path.is_file(),
        "conflicting temp is never silently deleted"
    );
}

#[test]
fn excessive_authentic_blob_temps_fail_closed_without_unbounded_secret_retention() {
    let (_temp, root, store) = open_empty_store("object-temp-budget-root-marker");
    let state = initialize(&store, Uuid::new_v4(), 1);
    let key = EnvelopeMasterKey::from_bytes([0x67; 32]).expect("master key");
    let locator = derive_locator(&store, "object-temp-budget-entity");
    publish_object(
        &store,
        &state,
        &key,
        &locator,
        2,
        "object-temp-budget-secret",
    );

    let slot = object_directory(&root, &locator).join("slot-a");
    let published = fs::read(only_regular_file(&slot)).expect("read authentic ciphertext");
    let mut temps = Vec::new();
    for _ in 0..9 {
        let temp = slot.join(format!(
            ".blob-{:020}-{:020}-{}.tmp",
            2,
            3,
            Uuid::new_v4().simple()
        ));
        fs::write(&temp, &published).expect("write authentic crash temp");
        temps.push(temp);
    }

    let error = store
        .with_exclusive_lock(|guard| guard.resolve_object(&key, &locator, 2))
        .expect_err("the independent temp count is bounded below the slot entry bound");
    assert_fixed_error(
        error,
        SecretFileStoreErrorCode::ArtifactConflict,
        &[
            "object-temp-budget-root-marker",
            "object-temp-budget-entity",
            "object-temp-budget-secret",
            &locator.backend_locator_hex(),
        ],
    );
    assert!(temps.iter().all(|path| path.is_file()));
}

#[test]
fn context_swapped_blob_files_fail_authentication() {
    let (_temp, root, store) = open_empty_store("object-swap-root-marker");
    let state = initialize(&store, Uuid::new_v4(), 1);
    let key = EnvelopeMasterKey::from_bytes([0x71; 32]).expect("master key");
    let first = derive_locator(&store, "swap-entity-first");
    let second = derive_locator(&store, "swap-entity-second");
    publish_object(&store, &state, &key, &first, 2, "swap-first-secret");
    publish_object(&store, &state, &key, &second, 2, "swap-second-secret");

    let first_dir = object_directory(&root, &first);
    let second_dir = object_directory(&root, &second);
    let first_a = only_regular_file(&first_dir.join("slot-a"));
    let first_b = only_regular_file(&first_dir.join("slot-b"));
    let second_a = only_regular_file(&second_dir.join("slot-a"));
    let second_b = only_regular_file(&second_dir.join("slot-b"));
    fs::write(&first_a, fs::read(second_a).expect("read swapped A")).expect("swap A");
    fs::write(&first_b, fs::read(second_b).expect("read swapped B")).expect("swap B");

    let error = store
        .with_exclusive_lock(|guard| guard.resolve_object(&key, &first, 2))
        .expect_err("cross-entity slot substitution fails AEAD context");
    assert_eq!(error.code(), SecretFileStoreErrorCode::ObjectUnavailable);
}

#[test]
fn same_process_transaction_lock_serializes_threads() {
    let (_temp, _root, store) = open_empty_store("thread-lock-root-marker");
    let store = Arc::new(store);
    let (held_tx, held_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let first_store = Arc::clone(&store);
    let first = std::thread::spawn(move || {
        let _guard = first_store.lock_exclusive().expect("first lock");
        held_tx.send(()).expect("signal held lock");
        release_rx.recv().expect("wait for release");
    });
    held_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("first thread acquired lock");

    let (acquired_tx, acquired_rx) = mpsc::channel();
    let second_store = Arc::clone(&store);
    let second = std::thread::spawn(move || {
        let _guard = second_store.lock_exclusive().expect("second lock");
        acquired_tx.send(()).expect("signal second lock");
    });
    assert!(
        acquired_rx
            .recv_timeout(Duration::from_millis(200))
            .is_err(),
        "second thread acquired the transaction lock before release"
    );
    release_tx.send(()).expect("release first lock");
    acquired_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("second thread acquires after release");
    first.join().expect("first lock thread");
    second.join().expect("second lock thread");
}

#[test]
fn garbage_collection_retains_fallback_revisions_and_removes_only_unreferenced_ones() {
    let (_temp, root, store) = open_empty_store("gc-multi-revision-root-marker");
    let state = initialize(&store, Uuid::new_v4(), 9);
    let key = EnvelopeMasterKey::from_bytes([0x91; 32]).expect("master key");
    let entity_id = "gc-multi-revision-real-entity";
    let locator = derive_locator(&store, entity_id);
    for (revision, marker) in [
        (1, "gc-revision-one"),
        (2, "gc-revision-two"),
        (3, "gc-revision-three"),
    ] {
        publish_object(&store, &state, &key, &locator, revision, marker);
    }
    let object = object_directory(&root, &locator);
    let revision_three_a = regular_files(&object.join("slot-a"))
        .into_iter()
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("blob-00000000000000000003-"))
        })
        .expect("revision three A final");
    let retained_temp =
        object
            .join("slot-a")
            .join(format!(".blob-{:020}-{:020}-{}.tmp", 3, 5, "a".repeat(32)));
    fs::hard_link(&revision_three_a, &retained_temp)
        .expect("seed authentic retained-revision temp");

    let first = retention(entity_id, &locator, 1);
    let third = retention(entity_id, &locator, 3);
    let duplicate_third = retention(entity_id, &locator, 3);
    let locator_marker = locator.backend_locator_hex();
    let rendered = format!("{first:?} {third:?}");
    assert!(!rendered.contains(entity_id));
    assert!(!rendered.contains(&locator_marker));
    let report = store
        .with_exclusive_lock(|guard| {
            guard.garbage_collect_objects(&state, &key, &[first, third, duplicate_third])
        })
        .expect("fallback-aware garbage collection");
    assert_eq!(report.removed_blob_revisions(), 1);
    assert_eq!(report.removed_objects(), 0);
    assert!(
        !retained_temp.exists(),
        "an authenticated temp never substitutes for or outlives exact finals"
    );

    for (revision, marker) in [(1, "gc-revision-one"), (3, "gc-revision-three")] {
        let resolved = store
            .with_exclusive_lock(|guard| guard.resolve_object(&key, &locator, revision))
            .expect("retained revision resolves");
        assert_eq!(
            resolved.private_key(),
            format!("private-{marker}").as_bytes()
        );
    }
    let removed = store
        .with_exclusive_lock(|guard| guard.resolve_object(&key, &locator, 2))
        .expect_err("unreferenced revision was removed");
    assert_eq!(removed.code(), SecretFileStoreErrorCode::ObjectUnavailable);
    assert_eq!(regular_files(&object.join("slot-a")).len(), 2);
    assert_eq!(regular_files(&object.join("slot-b")).len(), 2);
}

#[test]
fn garbage_collection_empty_retention_removes_objects_and_repeats_idempotently() {
    let (_temp, root, store) = open_empty_store("gc-empty-retention-root-marker");
    let state = initialize(&store, Uuid::new_v4(), 4);
    let key = EnvelopeMasterKey::from_bytes([0x92; 32]).expect("master key");
    let first = derive_locator(&store, "gc-empty-first-entity");
    let second = derive_locator(&store, "gc-empty-second-entity");
    publish_object(&store, &state, &key, &first, 1, "gc-empty-first-one");
    publish_object(&store, &state, &key, &first, 2, "gc-empty-first-two");
    publish_object(&store, &state, &key, &second, 1, "gc-empty-second-one");

    let report = store
        .with_exclusive_lock(|guard| guard.garbage_collect_objects(&state, &key, &[]))
        .expect("remove all unreferenced blobs");
    assert_eq!(report.removed_blob_revisions(), 3);
    assert_eq!(report.removed_objects(), 2);
    assert!(
        fs::read_dir(root.join("objects"))
            .expect("read empty objects root")
            .next()
            .is_none()
    );

    let repeated = store
        .with_exclusive_lock(|guard| guard.garbage_collect_objects(&state, &key, &[]))
        .expect("repeat garbage collection");
    assert_eq!(repeated.removed_blob_revisions(), 0);
    assert_eq!(repeated.removed_objects(), 0);
    assert_eq!(load_state(&store), state);
}

#[test]
fn garbage_collection_unknown_or_corrupt_artifact_preflight_deletes_nothing() {
    let (_temp, root, store) = open_empty_store("gc-preflight-root-marker");
    let state = initialize(&store, Uuid::new_v4(), 5);
    let key = EnvelopeMasterKey::from_bytes([0x93; 32]).expect("master key");
    let first = derive_locator(&store, "gc-preflight-first-entity");
    let second = derive_locator(&store, "gc-preflight-second-entity");
    publish_object(&store, &state, &key, &first, 1, "gc-preflight-first");
    publish_object(&store, &state, &key, &second, 1, "gc-preflight-second");

    let unknown = object_directory(&root, &second)
        .join("slot-b")
        .join("gc-unknown-artifact-must-survive");
    fs::write(&unknown, b"unknown must survive").expect("seed unknown artifact");
    let before_unknown = regular_file_snapshot(&root);
    let error = store
        .with_exclusive_lock(|guard| guard.garbage_collect_objects(&state, &key, &[]))
        .expect_err("unknown artifact blocks the complete preflight");
    assert_eq!(
        error.code(),
        SecretFileStoreErrorCode::GarbageCollectionUncertain
    );
    assert_eq!(regular_file_snapshot(&root), before_unknown);

    fs::remove_file(&unknown).expect("remove test-only unknown artifact");
    let corrupt = only_regular_file(&object_directory(&root, &second).join("slot-a"));
    fs::write(&corrupt, b"corrupt authenticated blob").expect("corrupt blob");
    let before_corrupt = regular_file_snapshot(&root);
    let error = store
        .with_exclusive_lock(|guard| guard.garbage_collect_objects(&state, &key, &[]))
        .expect_err("corrupt blob blocks the complete preflight");
    assert_eq!(
        error.code(),
        SecretFileStoreErrorCode::GarbageCollectionUncertain
    );
    assert_eq!(regular_file_snapshot(&root), before_corrupt);
}

#[test]
fn garbage_collection_retained_revision_requires_exact_finals_before_any_delete() {
    let (_temp, root, store) = open_empty_store("gc-retained-missing-slot-root-marker");
    let state = initialize(&store, Uuid::new_v4(), 7);
    let key = EnvelopeMasterKey::from_bytes([0x96; 32]).expect("master key");
    let retained_entity = "gc-retained-missing-slot-entity";
    let retained_locator = derive_locator(&store, retained_entity);
    let disposable = derive_locator(&store, "gc-retained-missing-slot-disposable");
    publish_object(
        &store,
        &state,
        &key,
        &retained_locator,
        1,
        "gc-retained-missing-slot-secret",
    );
    publish_object(
        &store,
        &state,
        &key,
        &disposable,
        1,
        "gc-retained-missing-slot-disposable",
    );
    fs::remove_file(only_regular_file(
        &object_directory(&root, &retained_locator).join("slot-b"),
    ))
    .expect("remove retained B final");
    let before_missing = regular_file_snapshot(&root);
    let keep = retention(retained_entity, &retained_locator, 1);
    let error = store
        .with_exclusive_lock(|guard| guard.garbage_collect_objects(&state, &key, &[keep]))
        .expect_err("one retained final cannot authorize any cleanup");
    assert_eq!(
        error.code(),
        SecretFileStoreErrorCode::GarbageCollectionUncertain
    );
    assert_eq!(regular_file_snapshot(&root), before_missing);

    let (_temp, root, store) = open_empty_store("gc-retained-temp-only-root-marker");
    let state = initialize(&store, Uuid::new_v4(), 8);
    let key = EnvelopeMasterKey::from_bytes([0x97; 32]).expect("master key");
    let retained_entity = "gc-retained-temp-only-entity";
    let retained_locator = derive_locator(&store, retained_entity);
    let disposable = derive_locator(&store, "gc-retained-temp-only-disposable");
    publish_object(
        &store,
        &state,
        &key,
        &retained_locator,
        1,
        "gc-retained-temp-only-secret",
    );
    publish_object(
        &store,
        &state,
        &key,
        &disposable,
        1,
        "gc-retained-temp-only-disposable",
    );
    let retained_object = object_directory(&root, &retained_locator);
    for (slot, generation, artifact_id) in [
        ("slot-a", 1_u64, "b".repeat(32)),
        ("slot-b", 2_u64, "c".repeat(32)),
    ] {
        let final_path = only_regular_file(&retained_object.join(slot));
        let temp_path = retained_object.join(slot).join(format!(
            ".blob-{:020}-{generation:020}-{artifact_id}.tmp",
            1
        ));
        fs::rename(final_path, temp_path).expect("leave only an authentic temp");
    }
    let before_temp_only = regular_file_snapshot(&root);
    let keep = retention(retained_entity, &retained_locator, 1);
    let error = store
        .with_exclusive_lock(|guard| guard.garbage_collect_objects(&state, &key, &[keep]))
        .expect_err("temps cannot substitute for retained A/B finals");
    assert_eq!(
        error.code(),
        SecretFileStoreErrorCode::GarbageCollectionUncertain
    );
    assert_eq!(regular_file_snapshot(&root), before_temp_only);
}

#[test]
fn garbage_collection_rejects_wrong_master_key_keyset_fallback_and_locator_mismatch() {
    let (_temp, root, store) = open_empty_store("gc-key-authority-root-marker");
    let state = initialize(&store, Uuid::new_v4(), 6);
    let key = EnvelopeMasterKey::from_bytes([0x94; 32]).expect("master key");
    let wrong_key = EnvelopeMasterKey::from_bytes([0x95; 32]).expect("wrong master key");
    let entity_id = "gc-key-authority-entity";
    let locator = derive_locator(&store, entity_id);
    publish_object(&store, &state, &key, &locator, 1, "gc-key-authority-secret");

    let before_wrong_key = regular_file_snapshot(&root);
    let error = store
        .with_exclusive_lock(|guard| guard.garbage_collect_objects(&state, &wrong_key, &[]))
        .expect_err("wrong master key blocks cleanup");
    assert_eq!(
        error.code(),
        SecretFileStoreErrorCode::GarbageCollectionUncertain
    );
    assert_eq!(regular_file_snapshot(&root), before_wrong_key);

    let mismatched = SecretObjectRetention::new(entity_id, "aa".repeat(32), 1)
        .expect("canonical but mismatched locator input");
    let error = store
        .with_exclusive_lock(|guard| guard.garbage_collect_objects(&state, &key, &[mismatched]))
        .expect_err("real ID and backend locator must agree");
    assert_eq!(
        error.code(),
        SecretFileStoreErrorCode::GarbageCollectionUncertain
    );
    assert_eq!(regular_file_snapshot(&root), before_wrong_key);

    let keyset_b = only_regular_file(&root.join("keyset").join("slot-b"));
    fs::write(keyset_b, b"corrupt higher keyset").expect("corrupt keyset fallback");
    let before_fallback = regular_file_snapshot(&root);
    let error = store
        .with_exclusive_lock(|guard| guard.garbage_collect_objects(&state, &key, &[]))
        .expect_err("keyset fallback cannot authorize cleanup");
    assert_eq!(
        error.code(),
        SecretFileStoreErrorCode::GarbageCollectionUncertain
    );
    assert_eq!(regular_file_snapshot(&root), before_fallback);
}

#[test]
fn master_key_rotation_reencrypts_exact_retention_and_authorizes_old_key_deletion_only_after_confirmation()
 {
    let (_temp, root, store) = open_empty_store("rotation-success-root-marker");
    let state = initialize(&store, Uuid::new_v4(), 1);
    let old_key = EnvelopeMasterKey::from_bytes([0xb1; 32]).expect("old master key");
    let new_key = EnvelopeMasterKey::from_bytes([0xb2; 32]).expect("new master key");
    let retained_id = "rotation-retained-entity";
    let retained_locator = derive_locator(&store, retained_id);
    let orphan_locator = derive_locator(&store, "rotation-orphan-entity");
    publish_object(
        &store,
        &state,
        &old_key,
        &retained_locator,
        1,
        "rotation-retained-secret",
    );
    publish_object(
        &store,
        &state,
        &old_key,
        &orphan_locator,
        1,
        "rotation-orphan-secret",
    );
    let old_ciphertext = regular_file_snapshot(&root.join("objects"));
    let keep = retention(retained_id, &retained_locator, 1);

    let completion = store
        .with_exclusive_lock(|guard| {
            guard.rotate_master_key_epoch(&state, &old_key, 2, &new_key, &[keep])
        })
        .expect("rotate master key")
        .into_durable()
        .expect("rotation must be fully durable");
    assert_eq!(completion.source_epoch(), 1);
    assert_eq!(completion.target_epoch(), 2);
    assert_eq!(completion.retained_objects(), 1);
    assert!(completion.old_master_key_deletion_authorized());
    assert_eq!(completion.state().active_master_key_epoch(), 2);
    assert_eq!(regular_file_snapshot(&root.join("objects")), old_ciphertext);

    let resolved = store
        .with_exclusive_lock(|guard| guard.resolve_object(&new_key, &retained_locator, 1))
        .expect("rotated retained object resolves");
    assert_eq!(resolved.private_key(), b"private-rotation-retained-secret");
    let orphan_error = store
        .with_exclusive_lock(|guard| guard.resolve_object(&new_key, &orphan_locator, 1))
        .expect_err("unretained source object is not part of the target graph");
    assert_eq!(
        orphan_error.code(),
        SecretFileStoreErrorCode::ObjectUnavailable
    );

    // A normal managed mutation after completion changes the current
    // fallback-aware retention set. The historical manifest remains lineage,
    // not a permanent freeze of the old inventory.
    let later_id = "rotation-later-entity";
    let later_locator = derive_locator(&store, later_id);
    publish_object(
        &store,
        &completion.state(),
        &new_key,
        &later_locator,
        1,
        "rotation-later-secret",
    );

    // Stable target discovery/finalization does not depend on retaining the
    // source keyset pair. Only the stable v2 pair, manifest lineage, active
    // target key, and current retained graph are required.
    for slot in ["slot-a", "slot-b"] {
        for path in regular_files(&root.join("keyset").join(slot)) {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("keyset name");
            if name.starts_with("keyset-00000000000000000001-")
                || name.starts_with("keyset-00000000000000000002-")
            {
                fs::remove_file(path).expect("remove retired source keyset test artifact");
            }
        }
    }

    let recovery = store
        .with_exclusive_lock(|guard| guard.inspect_master_key_rotation())
        .expect("inspect completed rotation")
        .expect("completed marker");
    assert!(recovery.completed());
    assert_eq!(recovery.source_epoch(), 1);
    assert_eq!(recovery.target_epoch(), 2);
    let keep = retention(retained_id, &retained_locator, 1);
    let later = retention(later_id, &later_locator, 1);
    let wrong_target_key = EnvelopeMasterKey::from_bytes([0xb3; 32]).expect("wrong target key");
    let wrong_target_error = store
        .with_exclusive_lock(|guard| {
            guard.confirm_completed_master_key_rotation(
                &recovery,
                &wrong_target_key,
                &[
                    retention(retained_id, &retained_locator, 1),
                    retention(later_id, &later_locator, 1),
                ],
            )
        })
        .expect_err("wrong target key never confirms old-key deletion");
    assert_eq!(
        wrong_target_error.code(),
        SecretFileStoreErrorCode::MasterKeyRotationUncertain
    );
    let reconfirmed = store
        .with_exclusive_lock(|guard| {
            guard.confirm_completed_master_key_rotation(&recovery, &new_key, &[keep, later])
        })
        .expect("new-key-only completed confirmation");
    assert!(reconfirmed.old_master_key_deletion_authorized());
    assert_eq!(reconfirmed.retained_objects(), 2);
    let unavailable_source_key =
        EnvelopeMasterKey::from_bytes([0xbf; 32]).expect("unavailable source placeholder");
    let stable_retry = store
        .with_exclusive_lock(|guard| {
            guard.rotate_master_key_epoch(
                &state,
                &unavailable_source_key,
                2,
                &new_key,
                &[
                    retention(retained_id, &retained_locator, 1),
                    retention(later_id, &later_locator, 1),
                ],
            )
        })
        .expect("stable target retry uses only target key")
        .into_durable()
        .expect("stable target is idempotently durable");
    assert!(stable_retry.old_master_key_deletion_authorized());
    assert!(matches!(
        store
            .with_exclusive_lock(|guard| guard.acknowledge_source_key_retired(&stable_retry))
            .expect("acknowledge absent source key"),
        SecretFileMutation::Durable(())
    ));
    assert!(
        store
            .with_exclusive_lock(|guard| guard.inspect_master_key_rotation())
            .expect("inspect finalized rotation")
            .is_none(),
        "a durable retired-key marker removes completed recovery work"
    );
    assert!(matches!(
        store
            .with_exclusive_lock(|guard| guard.acknowledge_source_key_retired(&stable_retry))
            .expect("retired-key acknowledgement is idempotent"),
        SecretFileMutation::Durable(())
    ));

    let debug = format!("{completion:?} {recovery:?}");
    assert!(!debug.contains(retained_id));
    assert!(!debug.contains(&retained_locator.backend_locator_hex()));
    assert!(!debug.contains("rotation-retained-secret"));
}

#[test]
fn master_key_rotation_wrong_old_key_and_mixed_epoch_source_write_nothing() {
    let (_temp, root, store) = open_empty_store("rotation-preflight-root-marker");
    let state = initialize(&store, Uuid::new_v4(), 9);
    let old_key = EnvelopeMasterKey::from_bytes([0xc1; 32]).expect("old master key");
    let wrong_key = EnvelopeMasterKey::from_bytes([0xc2; 32]).expect("wrong master key");
    let new_key = EnvelopeMasterKey::from_bytes([0xc3; 32]).expect("new master key");
    let entity_id = "rotation-preflight-entity";
    let locator = derive_locator(&store, entity_id);
    publish_object(
        &store,
        &state,
        &old_key,
        &locator,
        1,
        "rotation-preflight-secret",
    );
    let keep = retention(entity_id, &locator, 1);
    let before = regular_file_snapshot(&root);
    let error = store
        .with_exclusive_lock(|guard| {
            guard.rotate_master_key_epoch(&state, &wrong_key, 10, &new_key, &[keep])
        })
        .expect_err("wrong source key fails before target publication");
    assert_eq!(
        error.code(),
        SecretFileStoreErrorCode::MasterKeyRotationUncertain
    );
    assert_eq!(regular_file_snapshot(&root), before);

    let object = object_directory(&root, &locator);
    let a_path = only_regular_file(&object.join("slot-a"));
    let mixed_context =
        SecretEnvelopeContext::new(state.store_id(), entity_id, 1, SecretEnvelopeSlot::A, 1, 10)
            .expect("mixed epoch context");
    let mixed = encrypt_ssh_secret_bundle(
        &new_key,
        &mixed_context,
        bundle("rotation-preflight-secret"),
    )
    .expect("mixed epoch envelope");
    fs::write(&a_path, mixed.as_bytes()).expect("seed authenticated mixed epoch");
    let keep = retention(entity_id, &locator, 1);
    let before_mixed = regular_file_snapshot(&root);
    let error = store
        .with_exclusive_lock(|guard| {
            guard.rotate_master_key_epoch(&state, &old_key, 10, &new_key, &[keep])
        })
        .expect_err("mixed source epoch fails closed");
    assert_eq!(
        error.code(),
        SecretFileStoreErrorCode::MasterKeyRotationUncertain
    );
    assert_eq!(regular_file_snapshot(&root), before_mixed);
    assert!(!root.join("epochs").exists());
}

#[cfg(unix)]
fn symlink_directory(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn symlink_directory(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_dir(target, link)
}

#[cfg(unix)]
fn symlink_file(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn symlink_file(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

fn link_creation_is_unavailable(error: &std::io::Error) -> bool {
    cfg!(windows)
        && (matches!(
            error.kind(),
            std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Unsupported
        ) || error.raw_os_error() == Some(1314))
}

#[test]
fn symlink_or_reparse_root_is_rejected_when_the_platform_allows_creation() {
    let temp = tempfile::tempdir().expect("temporary app-data directory");
    let real = temp.path().join("real-secret-root");
    fs::create_dir(&real).expect("create real root");
    let alias = temp.path().join("symlink-secret-root-marker");
    if let Err(error) = symlink_directory(&real, &alias) {
        if link_creation_is_unavailable(&error) {
            return;
        }
        panic!("create directory symlink: {error}");
    }
    let error = SecretFileStore::open(&alias).expect_err("symlink root is rejected");
    assert_fixed_error(
        error,
        SecretFileStoreErrorCode::InvalidRoot,
        &["symlink-secret-root-marker", "real-secret-root"],
    );
}

#[test]
fn symlink_lock_and_keyset_directory_are_rejected_without_touching_targets() {
    let (temp, root, store) = open_empty_store("symlink-entry-root-marker");
    drop(store);
    let lock_path = root.join(LOCK_FILE);
    fs::remove_file(&lock_path).expect("remove disposable lock for substitution test");
    let lock_target = temp.path().join("symlink-lock-target-marker");
    fs::write(&lock_target, b"target must remain unchanged").expect("write lock target");
    if let Err(error) = symlink_file(&lock_target, &lock_path) {
        if link_creation_is_unavailable(&error) {
            return;
        }
        panic!("create lock symlink: {error}");
    }
    let lock_error = SecretFileStore::open(&root).expect_err("symlink lock is rejected");
    assert!(matches!(
        lock_error.code(),
        SecretFileStoreErrorCode::ArtifactConflict | SecretFileStoreErrorCode::LockUnavailable
    ));
    assert_eq!(
        fs::read(&lock_target).expect("lock target survives"),
        b"target must remain unchanged"
    );

    fs::remove_file(&lock_path).expect("remove lock symlink");
    let store = SecretFileStore::open(&root).expect("restore real lock");
    initialize(&store, Uuid::new_v4(), 1);
    drop(store);
    let keyset = root.join("keyset");
    let keyset_target = temp.path().join("symlink-keyset-target-marker");
    fs::rename(&keyset, &keyset_target).expect("move keyset within disposable temp root");
    if let Err(error) = symlink_directory(&keyset_target, &keyset) {
        if link_creation_is_unavailable(&error) {
            return;
        }
        panic!("create keyset symlink: {error}");
    }
    let keyset_error = SecretFileStore::open(&root).expect_err("symlink keyset is rejected");
    assert_eq!(
        keyset_error.code(),
        SecretFileStoreErrorCode::ArtifactConflict
    );
    assert!(keyset_target.join("slot-a").is_dir());
    assert!(keyset_target.join("slot-b").is_dir());
}
