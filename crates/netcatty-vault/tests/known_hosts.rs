use netcatty_vault::{
    SavedHostStore, SavedKnownHost, SavedNotesSnippetsCatalog, SavedVaultGraph, StoreError,
};

fn known_host(id: &str) -> SavedKnownHost {
    SavedKnownHost {
        id: id.to_owned(),
        hostname: "server.example.test".to_owned(),
        port: 22,
        key_type: "ssh-ed25519".to_owned(),
        public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest".to_owned(),
        fingerprint: Some("fingerprint-without-prefix".to_owned()),
        discovered_at: 1,
        last_seen: None,
        converted_to_host_id: None,
        order: Some(0),
    }
}

#[test]
fn known_hosts_are_vault_persistent_cas_guarded_and_preserve_v8_catalogs() {
    let directory = tempfile::tempdir().expect("temporary Vault");
    let store = SavedHostStore::open(directory.path()).expect("open Vault");

    let explicit_notes = SavedNotesSnippetsCatalog::from_parts(
        Some(Vec::new()),
        Some(Vec::new()),
        Some(Vec::new()),
        Some(Vec::new()),
    )
    .expect("explicit empty Notes/Snippets catalog");
    let graph = SavedVaultGraph::new_with_notes_snippets(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        explicit_notes.clone(),
    );
    let initial = store.known_host_catalog().expect("initial catalog");
    let plan = store
        .plan_graph_replacement(initial.revision().clone(), &graph)
        .expect("plan graph");
    store
        .commit_planned_graph_replacement(plan, graph)
        .expect("publish graph");

    let before = store.known_host_catalog().expect("catalog before replace");
    let stale = before.revision().clone();
    let committed = store
        .replace_known_hosts(before.revision().clone(), vec![known_host("kh-1")])
        .expect("publish known host");
    assert_eq!(committed.known_hosts(), &[known_host("kh-1")]);
    assert_eq!(
        store.graph().expect("graph").notes_snippets(),
        &explicit_notes
    );

    let reopened = SavedHostStore::open(directory.path()).expect("reopen Vault");
    assert_eq!(
        reopened
            .known_host_catalog()
            .expect("reloaded catalog")
            .known_hosts(),
        &[known_host("kh-1")]
    );
    assert!(matches!(
        reopened.replace_known_hosts(stale, Vec::new()),
        Err(StoreError::InventoryRevisionConflict { .. })
    ));
}
