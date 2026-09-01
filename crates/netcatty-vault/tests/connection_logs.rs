use std::fs;
use std::path::{Path, PathBuf};

use netcatty_vault::{
    SavedConnectionLog, SavedConnectionLogHostOs, SavedConnectionLogProtocol, SavedHostDraft,
    SavedHostStore, SavedKnownHost, SavedNotesSnippetsCatalog, SavedVaultGraph, StoreError,
};

fn connection_log(id: &str, host_id: &str, start_time: u64) -> SavedConnectionLog {
    SavedConnectionLog {
        id: id.to_owned(),
        session_id: Some(format!("session-{id}")),
        host_id: host_id.to_owned(),
        host_label: "Production".to_owned(),
        hostname: "server.example.test".to_owned(),
        username: "operator".to_owned(),
        protocol: SavedConnectionLogProtocol::Ssh,
        host_os: Some(SavedConnectionLogHostOs::Linux),
        host_distro: Some("ubuntu".to_owned()),
        host_icon_mode: None,
        host_icon_id: None,
        host_icon_color_mode: None,
        host_icon_color: None,
        host_icon_color_custom: None,
        start_time,
        end_time: Some(start_time + 1),
        local_username: "local-user".to_owned(),
        local_hostname: "workstation".to_owned(),
        saved: false,
        theme_id: Some("netcatty-dark".to_owned()),
        font_size: Some(14.0),
    }
}

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

fn latest_snapshot(directory: &Path) -> PathBuf {
    fs::read_dir(directory)
        .expect("read snapshot slot")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("snapshot-"))
        .max_by_key(|entry| entry.file_name())
        .expect("latest snapshot")
        .path()
}

#[test]
fn connection_log_metadata_is_v10_persistent_cas_canonical_and_terminal_data_free() {
    let directory = tempfile::tempdir().expect("temporary Vault");
    let store = SavedHostStore::open(directory.path()).expect("open Vault");
    let initial = store.connection_log_catalog().expect("initial log catalog");

    let replay_secret = "TOP-SECRET terminal replay";
    let mut legacy_value =
        serde_json::to_value(connection_log("log-b", "deleted-host", 100)).expect("legacy JSON");
    legacy_value["terminalData"] = serde_json::json!(replay_secret);
    let legacy_log: SavedConnectionLog =
        serde_json::from_value(legacy_value).expect("read legacy terminalData");
    let same_time = connection_log("log-a", "deleted-host", 100);

    let committed = store
        .replace_connection_logs(
            initial.revision().clone(),
            vec![legacy_log.clone(), same_time.clone()],
        )
        .expect("publish log metadata");
    assert_eq!(
        committed
            .logs()
            .iter()
            .map(|log| log.id.as_str())
            .collect::<Vec<_>>(),
        ["log-a", "log-b"]
    );

    let generation = committed.revision().loaded_generation();
    let no_op = store
        .replace_connection_logs(
            committed.revision().clone(),
            vec![same_time.clone(), legacy_log.clone()],
        )
        .expect("canonical no-op");
    assert_eq!(no_op.revision().loaded_generation(), generation);

    let snapshot_path = latest_snapshot(&directory.path().join("slot-a"));
    let encoded = fs::read_to_string(&snapshot_path).expect("read v10 snapshot");
    let mut snapshot: serde_json::Value = serde_json::from_str(&encoded).expect("snapshot JSON");
    assert_eq!(snapshot["formatVersion"], 10);
    assert_eq!(snapshot["knownHosts"], serde_json::json!([]));
    assert_eq!(snapshot["connectionLogs"].as_array().map(Vec::len), Some(2));
    assert!(!encoded.contains("terminalData"));
    assert!(!encoded.contains(replay_secret));

    let reopened = SavedHostStore::open(directory.path()).expect("reopen Vault");
    assert_eq!(
        reopened
            .connection_log_catalog()
            .expect("reloaded logs")
            .logs(),
        committed.logs()
    );
    assert!(matches!(
        reopened.replace_connection_logs(initial.revision().clone(), Vec::new()),
        Err(StoreError::InventoryRevisionConflict { .. })
    ));

    snapshot["connectionLogs"][0]["terminalData"] = serde_json::json!(replay_secret);
    fs::write(
        &snapshot_path,
        serde_json::to_vec(&snapshot).expect("tampered snapshot JSON"),
    )
    .expect("write forbidden replay field");
    drop(reopened);
    drop(store);
    assert!(matches!(
        SavedHostStore::open(directory.path()),
        Err(StoreError::BothSlotsCorrupt)
    ));
}

#[test]
fn connection_logs_preserve_other_catalogs_survive_host_deletion_and_ab_fallback() {
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
    let initial = store.connection_log_catalog().expect("initial log catalog");
    let plan = store
        .plan_graph_replacement(initial.revision().clone(), &graph)
        .expect("plan graph");
    store
        .commit_planned_graph_replacement(plan, graph)
        .expect("publish graph");

    let known_state = store.known_host_catalog().expect("known hosts revision");
    store
        .replace_known_hosts(known_state.revision().clone(), vec![known_host("known-1")])
        .expect("publish known host");

    let host = store
        .create(SavedHostDraft::ssh_password(
            "server.example.test",
            "operator",
        ))
        .expect("create host");
    let history = connection_log("history", host.id.as_str(), 100);
    let logs_state = store.connection_log_catalog().expect("logs revision");
    store
        .replace_connection_logs(logs_state.revision().clone(), vec![history.clone()])
        .expect("publish history");
    store
        .delete(&host.id, host.revision)
        .expect("delete current host");

    assert!(store.list().expect("hosts after delete").is_empty());
    assert_eq!(
        store
            .connection_log_catalog()
            .expect("history after host delete")
            .logs(),
        &[history.clone()]
    );
    assert_eq!(
        store
            .graph()
            .expect("graph after log mutation")
            .notes_snippets(),
        &explicit_notes
    );
    assert_eq!(
        store
            .known_host_catalog()
            .expect("known hosts after log mutation")
            .known_hosts(),
        &[known_host("known-1")]
    );

    let before_latest = store
        .connection_log_catalog()
        .expect("revision before latest");
    store
        .replace_connection_logs(
            before_latest.revision().clone(),
            vec![
                history.clone(),
                connection_log("latest", "deleted-host", 200),
            ],
        )
        .expect("publish latest generation");
    let latest = latest_snapshot(&directory.path().join("slot-b"));
    fs::write(latest, b"{corrupt latest snapshot").expect("corrupt latest slot");

    let reopened = SavedHostStore::open(directory.path()).expect("fallback reopen");
    assert!(reopened.list().expect("fallback hosts").is_empty());
    assert_eq!(
        reopened
            .connection_log_catalog()
            .expect("fallback logs")
            .logs(),
        &[history]
    );
    assert_eq!(
        reopened.graph().expect("fallback graph").notes_snippets(),
        &explicit_notes
    );
    assert_eq!(
        reopened
            .known_host_catalog()
            .expect("fallback known hosts")
            .known_hosts(),
        &[known_host("known-1")]
    );
}

#[test]
fn clear_unsaved_connection_logs_filters_from_fresh_vault_snapshot_and_preserves_bookmarks() {
    let directory = tempfile::tempdir().expect("temporary Vault");
    let store = SavedHostStore::open(directory.path()).expect("open Vault");
    let initial = store.connection_log_catalog().expect("initial log catalog");
    let mut bookmarked = connection_log("bookmarked", "host-a", 100);
    bookmarked.saved = true;
    let transient = connection_log("transient", "host-b", 200);
    store
        .replace_connection_logs(
            initial.revision().clone(),
            vec![transient, bookmarked.clone()],
        )
        .expect("publish logs");

    let before_clear = store.connection_log_catalog().expect("logs before clear");
    let committed = store
        .clear_unsaved_connection_logs(before_clear.revision().clone())
        .expect("clear unsaved logs");
    assert_eq!(committed.logs(), &[bookmarked.clone()]);
    assert_eq!(
        store
            .connection_log_catalog()
            .expect("logs after clear")
            .logs(),
        &[bookmarked]
    );
    assert!(matches!(
        store.clear_unsaved_connection_logs(initial.revision().clone()),
        Err(StoreError::InventoryRevisionConflict { .. })
    ));
}
