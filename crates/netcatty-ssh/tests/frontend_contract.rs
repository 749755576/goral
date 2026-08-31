use netcatty_ssh::{
    DirectoryResumeCheckpoint, LocalTreeOptions, RemoteTreeOptions, SftpTransferEvent,
    SshAuthMethod, SshConnectionConfig, validate_connection,
};
use serde_json::{Value, json};

#[test]
fn frontend_payload_deserializes_and_result_uses_camel_case() {
    let payload = json!({
        "hostname": "diagnostic.netcatty.local",
        "username": "diagnostic",
        "legacyAlgorithms": true,
        "skipEcdsaHostKey": true,
        "auth": {
            "method": "auto",
            "useSshAgent": false
        },
        "timeouts": {
            "tcpConnectSeconds": 30
        }
    });
    let config: SshConnectionConfig = serde_json::from_value(payload).expect("frontend payload");
    let result = validate_connection(config);
    let serialized = serde_json::to_value(&result).expect("serializable validation result");

    assert!(result.valid);
    assert_eq!(result.auth_plan.method, SshAuthMethod::Auto);
    assert_eq!(serialized["valid"], Value::Bool(true));
    assert_eq!(serialized["normalized"]["port"], json!(22));
    assert_eq!(serialized["normalized"]["legacyAlgorithms"], json!(true));
    assert_eq!(serialized["normalized"]["skipEcdsaHostKey"], json!(true));
    assert_eq!(
        serialized["normalized"]["timeouts"]["tcpConnectSeconds"],
        json!(30)
    );
    assert!(serialized.get("authPlan").is_some());
    assert!(serialized.get("auth_plan").is_none());
}

#[test]
fn validation_contract_contains_no_plaintext_secret_fields() {
    let payload = json!({
        "hostname": "server.example.test",
        "username": "alice",
        "auth": {
            "method": "password",
            "hasPassword": true
        },
        "proxy": {
            "type": "http",
            "host": "proxy.example.test",
            "port": 8080,
            "hasPassword": true
        }
    });
    let config: SshConnectionConfig = serde_json::from_value(payload).expect("frontend payload");
    let serialized = serde_json::to_string(&validate_connection(config)).expect("JSON result");

    assert!(!serialized.contains("privateKey"));
    assert!(!serialized.contains("passphrase"));
    assert!(!serialized.contains("password\":"));
}

#[test]
fn directory_upload_contract_uses_camel_case_fields() {
    let options: LocalTreeOptions = serde_json::from_value(json!({
        "followDirectorySymlinks": true,
        "maxDirectories": 321,
        "maxEntries": 654
    }))
    .expect("directory options payload");
    assert!(options.follow_directory_symlinks);
    assert_eq!(options.max_directories, 321);
    assert_eq!(options.max_entries, 654);

    let remote_options: RemoteTreeOptions = serde_json::from_value(json!({
        "followDirectorySymlinks": true,
        "maxDirectories": 123,
        "maxEntries": 456
    }))
    .expect("remote directory options payload");
    assert!(remote_options.follow_directory_symlinks);
    assert_eq!(remote_options.max_directories, 123);
    assert_eq!(remote_options.max_entries, 456);

    let checkpoint = DirectoryResumeCheckpoint {
        version: 2,
        covered_entries: 3,
        completed_entries: 2,
        manifest_hash: "a".repeat(64),
    };
    let serialized = serde_json::to_value(SftpTransferEvent::DirectoryProgress {
        files_completed: 2,
        total_files: 4,
        bytes_transferred: 1024,
        total_bytes: 2048,
        current_path: None,
        checkpoint,
    })
    .expect("directory progress event");

    assert_eq!(serialized["type"], json!("directoryProgress"));
    assert_eq!(serialized["filesCompleted"], json!(2));
    assert_eq!(serialized["totalFiles"], json!(4));
    assert_eq!(serialized["bytesTransferred"], json!(1024));
    assert_eq!(serialized["totalBytes"], json!(2048));
    assert_eq!(serialized["currentPath"], Value::Null);
    assert_eq!(serialized["checkpoint"]["coveredEntries"], json!(3));
    assert!(serialized.get("files_completed").is_none());
}
