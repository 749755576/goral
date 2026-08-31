// Test-only implementation extracted mechanically from the parent module.
// Keeping it separate makes the production boundary reviewable without changing behavior.

mod tests {
    use super::{
        ClientAttemptId, CloneSshSessionRequest, CommitLegacyVaultImportRequest,
        CreateSavedHostRequest, DesktopState, InspectLegacyVaultRequest,
        LEGACY_VAULT_INVENTORY_CHANGED, LocalTransferSourceKind, SavedHost,
        SavedHostCredentialMutation, SavedHostDraftRequest, SavedHostId, SavedVaultGraph,
        StartSavedHostSessionRequest, StartSshSessionRequest, StartedSftpDownload,
        UpdateSavedHostRequest, activate_legacy_import_transaction, checked_managed_certificate,
        classify_local_transfer_metadata, commit_legacy_vault_document,
        connection_log_replay_manager_for_session, decode_interactive_response,
        disposition_requires_credential_reentry, frame_data, garbage_collect_managed_secret_blobs,
        inspect_legacy_vault_document, legacy_candidate_for_assessment,
        legacy_import_credential_references, legacy_source_fingerprint_token,
        load_legacy_import_transaction, load_legacy_vault_document, map_ssh_session_reuse_error,
        read_legacy_vault_file, recover_pending_legacy_import, run_saved_host_operation,
        saved_host_view, saved_host_view_from_graph, update_saved_host_inner,
        validate_legacy_source_fingerprint, validate_selected_identity_file_paths,
        validate_ssh_session_clone_source, verify_legacy_source_fingerprint,
    };
    use super::{
        LegacyImportCredentialOwnerKind, LegacyImportTransactionPhase,
        LegacyPreviousCredentialState,
    };
    use super::{ManagedSecretPublication, publish_managed_secret_objects};
    use crate::connection_log_replay::ConnectionLogReplayRuntime;
    use netcatty_credentials::test_support::{
        CredentialOperation, FailureTiming, InMemoryCredentialController,
        in_memory_credential_store, in_memory_master_key_store,
    };
    use netcatty_credentials::{
        CredentialErrorCode, CredentialKind, EphemeralCredentialReference, OsCredentialStore,
        SecretValue, StoredCredentialReference,
    };
    use netcatty_ssh::{ProxyType, SessionManagerError, SftpArtifactPlan, SftpDownloadPlan};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    #[test]
    fn ssh_session_clone_source_accepts_only_native_exact_session_ids() {
        assert_eq!(
            validate_ssh_session_clone_source("ssh-4242-17".to_owned()).expect("native ID"),
            "ssh-4242-17"
        );
        for invalid in [
            "",
            "ssh-4242",
            "ssh-4242-17-extra",
            "ssh-host.example-17",
            "ssh-4242-secret",
            "local-4242-17",
        ] {
            assert!(validate_ssh_session_clone_source(invalid.to_owned()).is_err());
        }
    }

    #[test]
    fn ssh_session_clone_errors_are_stable_and_non_secret() {
        assert!(
            map_ssh_session_reuse_error(SessionManagerError::NotFound)
                .starts_with("SSH_SESSION_REUSE_NOT_FOUND:")
        );
        assert!(
            map_ssh_session_reuse_error(SessionManagerError::NotConnected)
                .starts_with("SSH_SESSION_REUSE_NOT_CONNECTED:")
        );
        assert!(
            map_ssh_session_reuse_error(SessionManagerError::TransportSessionLimit)
                .starts_with("SSH_SESSION_REUSE_LIMIT:")
        );
    }

    #[test]
    fn ssh_session_clone_wire_contract_has_no_endpoint_or_credential_fields() {
        let request: CloneSshSessionRequest = serde_json::from_value(json!({
            "sourceSessionId": "ssh-4242-17"
        }))
        .expect("minimal clone request");
        assert_eq!(request.source_session_id, "ssh-4242-17");
        assert!(request.shell.is_none());

        for forbidden in [
            json!({
                "sourceSessionId": "ssh-4242-17",
                "hostname": "other.example.test"
            }),
            json!({
                "sourceSessionId": "ssh-4242-17",
                "credentialReference": "secret-capability"
            }),
            json!({
                "sourceSessionId": "ssh-4242-17",
                "clientAttemptId": "attempt-other"
            }),
        ] {
            assert!(serde_json::from_value::<CloneSshSessionRequest>(forbidden).is_err());
        }
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

    fn snapshot_count(root: &std::path::Path) -> usize {
        const MAGIC: &[u8] = b"netcatty-saved-host-snapshot";
        persisted_files(root)
            .into_iter()
            .filter(|bytes| bytes.windows(MAGIC.len()).any(|window| window == MAGIC))
            .count()
    }

    fn assert_bytes_do_not_contain(haystack: &[u8], forbidden: &str) {
        assert!(
            !haystack
                .windows(forbidden.len())
                .any(|window| window == forbidden.as_bytes()),
            "persisted data contained forbidden source material"
        );
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write as _;
            write!(encoded, "{byte:02x}").expect("write to String");
        }
        encoded
    }

    #[test]
    fn managed_secret_certificate_must_match_vault_category_exactly() {
        let certificate = b"certificate-secret-sentinel";
        assert_eq!(
            checked_managed_certificate("certificate", Some(certificate.as_slice()))
                .expect("certificate category"),
            Some(certificate.as_slice())
        );
        assert_eq!(
            checked_managed_certificate("key", None).expect("private-key category"),
            None
        );
        assert!(checked_managed_certificate("certificate", None).is_err());
        assert!(checked_managed_certificate("key", Some(certificate.as_slice())).is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn session_replay_manager_awaits_lazy_initialization_instead_of_skipping_capture() {
        let directory = tempfile::tempdir().expect("temporary app data");
        let mut state = DesktopState::open(directory.path().join("vault")).expect("desktop state");
        let (master_keys, _) = in_memory_master_key_store();
        let runtime =
            ConnectionLogReplayRuntime::new_with_master_key_store(directory.path(), master_keys);
        assert!(runtime.ready_manager().is_none());
        state.connection_log_replays = Some(runtime.clone());

        let manager = connection_log_replay_manager_for_session(&state)
            .await
            .expect("lazy manager must become available before session start");
        assert!(runtime.ready_manager().is_some());
        assert!(!format!("{manager:?}").contains(directory.path().to_string_lossy().as_ref()));

        let unavailable_root = directory.path().join("not-a-directory");
        std::fs::write(&unavailable_root, b"occupied").expect("blocking file");
        let (master_keys, _) = in_memory_master_key_store();
        state.connection_log_replays = Some(ConnectionLogReplayRuntime::new_with_master_key_store(
            &unavailable_root,
            master_keys,
        ));
        assert!(
            connection_log_replay_manager_for_session(&state)
                .await
                .is_none()
        );
    }

    fn desktop_state_with_memory_credentials(
        vault_path: &std::path::Path,
    ) -> (DesktopState, InMemoryCredentialController) {
        let (persistent_credentials, controller) = in_memory_credential_store();
        let (master_keys, _) = in_memory_master_key_store();
        let mut state = DesktopState::open(vault_path).expect("desktop state");
        state.persistent_credentials = persistent_credentials;
        state.master_keys = master_keys;
        (state, controller)
    }

    fn desktop_state_with_memory_credentials_and_master_keys(
        vault_path: &std::path::Path,
    ) -> (
        DesktopState,
        InMemoryCredentialController,
        InMemoryCredentialController,
    ) {
        let (persistent_credentials, credential_controller) = in_memory_credential_store();
        let (master_keys, master_key_controller) = in_memory_master_key_store();
        let mut state = DesktopState::open(vault_path).expect("desktop state");
        state.persistent_credentials = persistent_credentials;
        state.master_keys = master_keys;
        (state, credential_controller, master_key_controller)
    }

    fn restarted_desktop_state(
        vault_path: &std::path::Path,
        persistent_credentials: &OsCredentialStore,
    ) -> DesktopState {
        let mut state = DesktopState::open(vault_path).expect("restarted desktop state");
        state.persistent_credentials = persistent_credentials.clone();
        state
    }

    fn test_secret(value: &str) -> SecretValue {
        SecretValue::from_utf8(value.to_owned()).expect("test secret")
    }

    fn test_client_attempt_id() -> ClientAttemptId {
        ClientAttemptId::parse("attempt-test-123e4567-e89b-42d3-a456-426614174000".to_owned())
            .expect("test client attempt ID")
    }

    async fn prepare_test_saved_host_session(
        state: &DesktopState,
        owner: &str,
        request: StartSavedHostSessionRequest,
    ) -> Result<super::PreparedSavedHostSession, String> {
        let staged = super::drain_saved_host_session_secrets(state, owner, &request).await?;
        super::prepare_saved_host_session(state, request, staged).await
    }

    async fn assert_ephemeral_reference_consumed(
        state: &DesktopState,
        owner: &str,
        reference: &EphemeralCredentialReference,
    ) {
        let error = match state.ephemeral_credentials.take(owner, reference).await {
            Ok(_) => panic!("one-shot reference must already be consumed"),
            Err(error) => error,
        };
        assert_eq!(error.code(), CredentialErrorCode::NotFound);
    }

    fn saved_host_session_request_with_secrets(
        credential_reference: Option<EphemeralCredentialReference>,
        proxy_credential_reference: Option<EphemeralCredentialReference>,
        key_passphrase_reference: Option<EphemeralCredentialReference>,
    ) -> StartSavedHostSessionRequest {
        StartSavedHostSessionRequest {
            client_attempt_id: test_client_attempt_id(),
            host_id: "unreached-saved-host".to_owned(),
            expected_revision: 1,
            credential_reference,
            proxy_credential_reference,
            key_passphrase_reference,
            selected_identity_file_paths: Vec::new(),
            known_hosts: Vec::new(),
            verify_host_keys: true,
            shell: None,
        }
    }

    #[tokio::test]
    async fn saved_host_secret_drain_consumes_peer_references_after_the_first_error() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let state = DesktopState::open(directory.path()).expect("desktop state");
        let owner = "dual-reference-window";
        let key_passphrase = state
            .ephemeral_credentials
            .insert(owner, test_secret("dual-reference-passphrase-sentinel"))
            .await
            .expect("stage key passphrase");
        let proxy_password = state
            .ephemeral_credentials
            .insert(owner, test_secret("dual-reference-proxy-password-sentinel"))
            .await
            .expect("stage proxy password");
        let missing_password = loop {
            let candidate = EphemeralCredentialReference::new();
            if candidate != key_passphrase {
                break candidate;
            }
        };
        let request = saved_host_session_request_with_secrets(
            Some(missing_password),
            Some(proxy_password.clone()),
            Some(key_passphrase.clone()),
        );

        let error = super::drain_saved_host_session_secrets(&state, owner, &request)
            .await
            .err()
            .expect("missing password reference must fail");
        assert_eq!(error, CredentialErrorCode::NotFound.message());
        assert_ephemeral_reference_consumed(&state, owner, &proxy_password).await;
        assert_ephemeral_reference_consumed(&state, owner, &key_passphrase).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saved_host_secrets_are_consumed_before_the_file_lock_failure() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let mut state = DesktopState::open(directory.path()).expect("desktop state");
        state.saved_host_lock_path = std::sync::Arc::new(
            directory
                .path()
                .join("missing-lock-parent")
                .join("saved-host.lock"),
        );
        let owner = "lock-failure-window";
        let password = state
            .ephemeral_credentials
            .insert(owner, test_secret("lock-failure-password-sentinel"))
            .await
            .expect("stage password");
        let key_passphrase = state
            .ephemeral_credentials
            .insert(owner, test_secret("lock-failure-passphrase-sentinel"))
            .await
            .expect("stage key passphrase");
        let proxy_password = state
            .ephemeral_credentials
            .insert(owner, test_secret("lock-failure-proxy-password-sentinel"))
            .await
            .expect("stage proxy password");
        let request = saved_host_session_request_with_secrets(
            Some(password.clone()),
            Some(proxy_password.clone()),
            Some(key_passphrase.clone()),
        );

        let error =
            super::prepare_saved_host_session_operation(state.clone(), owner.to_owned(), request)
                .await
                .err()
                .expect("missing lock parent must fail");
        assert_eq!(error, "Saved-host transaction lock is unavailable");
        assert_ephemeral_reference_consumed(&state, owner, &password).await;
        assert_ephemeral_reference_consumed(&state, owner, &proxy_password).await;
        assert_ephemeral_reference_consumed(&state, owner, &key_passphrase).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saved_host_secrets_are_consumed_before_pending_recovery_fails() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let state = DesktopState::open(directory.path()).expect("desktop state");
        std::fs::create_dir_all(state.legacy_import_transaction_root.as_ref())
            .expect("transaction root");
        std::fs::write(
            state
                .legacy_import_transaction_root
                .join("legacy-credential-import-transaction-a.json"),
            b"corrupt-journal-slot",
        )
        .expect("corrupt journal slot");
        let owner = "recovery-failure-window";
        let password = state
            .ephemeral_credentials
            .insert(owner, test_secret("recovery-failure-password-sentinel"))
            .await
            .expect("stage password");
        let key_passphrase = state
            .ephemeral_credentials
            .insert(owner, test_secret("recovery-failure-passphrase-sentinel"))
            .await
            .expect("stage key passphrase");
        let proxy_password = state
            .ephemeral_credentials
            .insert(
                owner,
                test_secret("recovery-failure-proxy-password-sentinel"),
            )
            .await
            .expect("stage proxy password");
        let request = saved_host_session_request_with_secrets(
            Some(password.clone()),
            Some(proxy_password.clone()),
            Some(key_passphrase.clone()),
        );

        let error =
            super::prepare_saved_host_session_operation(state.clone(), owner.to_owned(), request)
                .await
                .err()
                .expect("corrupt recovery journal must fail");
        assert!(error.starts_with(super::LEGACY_VAULT_IMPORT_REPAIR_REQUIRED));
        assert_ephemeral_reference_consumed(&state, owner, &password).await;
        assert_ephemeral_reference_consumed(&state, owner, &proxy_password).await;
        assert_ephemeral_reference_consumed(&state, owner, &key_passphrase).await;
    }

    async fn assert_stored_secret(
        store: &OsCredentialStore,
        reference: &StoredCredentialReference,
        expected: &str,
    ) {
        assert_stored_secret_with_kind(store, reference, CredentialKind::SshPassword, expected)
            .await;
    }

    async fn assert_stored_secret_with_kind(
        store: &OsCredentialStore,
        reference: &StoredCredentialReference,
        kind: CredentialKind,
        expected: &str,
    ) {
        let actual = store
            .resolve(reference, kind)
            .await
            .expect("stored credential");
        assert_eq!(actual.as_utf8().expect("UTF-8 credential"), expected);
    }

    async fn assert_credential_missing(
        store: &OsCredentialStore,
        reference: &StoredCredentialReference,
    ) {
        assert_credential_missing_with_kind(store, reference, CredentialKind::SshPassword).await;
    }

    async fn assert_credential_missing_with_kind(
        store: &OsCredentialStore,
        reference: &StoredCredentialReference,
        kind: CredentialKind,
    ) {
        let error = store
            .resolve(reference, kind)
            .await
            .err()
            .expect("credential must be absent");
        assert_eq!(error.code(), CredentialErrorCode::NotFound);
    }

    fn legacy_credential_graph(ids: &[&str]) -> SavedVaultGraph {
        let source = legacy_plaintext_batch(ids);
        let document =
            netcatty_migration::parse_legacy_vault(&source, 10).expect("published host source");
        let hosts = document
            .candidates()
            .iter()
            .map(legacy_candidate_for_assessment)
            .collect::<Result<Vec<_>, _>>()
            .expect("published credential hosts");
        SavedVaultGraph::new(hosts, Vec::new(), Vec::new())
    }

    async fn begin_test_legacy_import_transaction(
        state: &DesktopState,
        ids: Vec<SavedHostId>,
    ) -> Result<super::LegacyImportTransaction, String> {
        let id_values = ids.iter().map(|id| id.as_str()).collect::<Vec<_>>();
        let graph = legacy_credential_graph(&id_values);
        let revision = state
            .saved_hosts
            .assess_graph_import(&graph)
            .expect("test graph assessment")
            .into_revision();
        let plan = state
            .saved_hosts
            .plan_graph_import(revision, &graph)
            .expect("test graph import plan");
        super::begin_legacy_import_transaction(
            state,
            ids,
            plan.before_graph_commitment().clone(),
            plan.after_graph_commitment().clone(),
        )
        .await
    }

    fn publish_legacy_credential_hosts(state: &DesktopState, ids: &[&str]) {
        let graph = legacy_credential_graph(ids);
        let revision = state
            .saved_hosts
            .assess_graph_import(&graph)
            .expect("published graph assessment")
            .into_revision();
        let committed = state
            .saved_hosts
            .commit_graph_import(revision, graph)
            .expect("published graph commit");
        assert_eq!(committed.imported().hosts().len(), ids.len());
    }

    fn assert_transaction_journal_excludes(root: &std::path::Path, forbidden_values: &[&str]) {
        let files = persisted_files(root);
        assert!(!files.is_empty(), "transaction journal must be durable");
        for bytes in files {
            for forbidden in forbidden_values {
                assert_bytes_do_not_contain(&bytes, forbidden);
            }
        }
    }

    fn legacy_plaintext_batch(ids: &[&str]) -> Vec<u8> {
        serde_json::to_vec(
            &ids.iter()
                .enumerate()
                .map(|(index, id)| {
                    json!({
                        "id": id,
                        "hostname": format!("host-{index}.example.test"),
                        "username": format!("user-{index}"),
                        "protocol": "ssh",
                        "authMethod": "password",
                        "authPolicyVersion": 1,
                        "savePassword": true,
                        "password": format!("new-secret-{index}"),
                        "createdAt": 1_700_000_000_000_u64 + index as u64,
                        "updatedAt": 1_700_000_000_000_u64 + index as u64
                    })
                })
                .collect::<Vec<_>>(),
        )
        .expect("legacy plaintext fixture")
    }

    fn legacy_password_identity_source(
        identity_id: &str,
        identity_label: &str,
        identity_username: &str,
        password: Option<serde_json::Value>,
        host_ids: &[&str],
    ) -> Vec<u8> {
        let mut identity = json!({
            "id": identity_id,
            "label": identity_label,
            "username": identity_username,
            "authMethod": "password",
            "created": 1_700_000_000_100_u64,
            "order": 1000
        });
        if let Some(password) = password {
            identity
                .as_object_mut()
                .expect("password identity object")
                .insert("password".to_owned(), password);
        }
        let hosts = host_ids
            .iter()
            .enumerate()
            .map(|(index, id)| {
                json!({
                    "id": id,
                    "label": format!("Password identity host {index}"),
                    "hostname": format!("password-identity-{index}.example.test"),
                    "username": format!("host-user-{index}"),
                    "protocol": "ssh",
                    "authMethod": "password",
                    "authPolicyVersion": 1,
                    "identityId": identity_id,
                    "createdAt": 1_700_000_000_200_u64 + index as u64,
                    "updatedAt": 1_700_000_000_200_u64 + index as u64
                })
            })
            .collect::<Vec<_>>();
        serde_json::to_vec(&json!({
            "hosts": hosts,
            "keys": [],
            "identities": [identity]
        }))
        .expect("legacy password identity fixture")
    }

    fn legacy_mixed_password_owner_source(
        host_id: &str,
        identity_host_id: &str,
        identity_id: &str,
    ) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "hosts": [
                {
                    "id": host_id,
                    "label": "Direct password host",
                    "hostname": "direct-password.example.test",
                    "username": "direct-user",
                    "protocol": "ssh",
                    "authMethod": "password",
                    "authPolicyVersion": 1,
                    "savePassword": true,
                    "password": "new-direct-host-secret-sentinel",
                    "createdAt": 1_700_000_000_300_u64,
                    "updatedAt": 1_700_000_000_300_u64
                },
                {
                    "id": identity_host_id,
                    "label": "Identity password host",
                    "hostname": "identity-password.example.test",
                    "username": "fallback-user",
                    "protocol": "ssh",
                    "authMethod": "password",
                    "authPolicyVersion": 1,
                    "identityId": identity_id,
                    "createdAt": 1_700_000_000_301_u64,
                    "updatedAt": 1_700_000_000_301_u64
                }
            ],
            "keys": [],
            "identities": [{
                "id": identity_id,
                "label": "Reusable password identity",
                "username": "identity-user",
                "authMethod": "password",
                "password": "new-identity-secret-sentinel",
                "created": 1_700_000_000_302_u64
            }]
        }))
        .expect("legacy mixed credential-owner fixture")
    }

    fn legacy_reference_graph_source(
        hostname: &str,
        host_label: &str,
        key_label: &str,
        identity_label: &str,
        referenced_path: &str,
        direct_path: &str,
    ) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "hosts": [{
                "id": "legacy-graph-host",
                "label": host_label,
                "hostname": hostname,
                "username": "graph-user",
                "protocol": "ssh",
                "authMethod": "key",
                "authPolicyVersion": 1,
                "identityId": "legacy-graph-identity",
                "identityFileId": "legacy-graph-key",
                "identityFilePaths": [direct_path]
            }],
            "keys": [{
                "id": "legacy-graph-key",
                "label": key_label,
                "type": "ED25519",
                "privateKey": "",
                "source": "reference",
                "category": "key",
                "created": 11,
                "filePath": referenced_path
            }],
            "identities": [{
                "id": "legacy-graph-identity",
                "label": identity_label,
                "username": "graph-user",
                "authMethod": "key",
                "keyId": "legacy-graph-key",
                "created": 12
            }]
        }))
        .expect("legacy reference graph fixture")
    }

    fn legacy_managed_graph_source(
        key_id: &str,
        host_id: Option<&str>,
        private_key: &str,
        public_key: Option<&str>,
        certificate: Option<&str>,
        passphrase: Option<&str>,
        save_passphrase: bool,
    ) -> Vec<u8> {
        let category = if certificate.is_some() {
            "certificate"
        } else {
            "key"
        };
        let auth_method = category;
        let mut key = json!({
            "id": key_id,
            "label": "Managed key metadata",
            "type": "ED25519",
            "source": "generated",
            "category": category,
            "privateKey": private_key,
            "savePassphrase": save_passphrase,
            "created": 41,
            "updatedAt": 43,
            "filePath": "legacy-managed-path-sentinel"
        });
        let key_object = key.as_object_mut().expect("managed key object");
        if let Some(public_key) = public_key {
            key_object.insert("publicKey".to_owned(), json!(public_key));
        }
        if let Some(certificate) = certificate {
            key_object.insert("certificate".to_owned(), json!(certificate));
        }
        if let Some(passphrase) = passphrase {
            key_object.insert("passphrase".to_owned(), json!(passphrase));
        }

        let (hosts, identities) = if let Some(host_id) = host_id {
            let identity_id = format!("{key_id}-identity");
            (
                vec![json!({
                    "id": host_id,
                    "label": "Managed host metadata",
                    "hostname": "managed.example.test",
                    "port": 2222,
                    "username": "legacy-user",
                    "protocol": "ssh",
                    "authMethod": auth_method,
                    "authPolicyVersion": 1,
                    "identityId": identity_id,
                    "createdAt": 47,
                    "updatedAt": 47
                })],
                vec![json!({
                    "id": identity_id,
                    "label": "Managed identity metadata",
                    "username": "managed-user",
                    "authMethod": auth_method,
                    "keyId": key_id,
                    "created": 45
                })],
            )
        } else {
            (Vec::new(), Vec::new())
        };

        serde_json::to_vec(&json!({
            "hosts": hosts,
            "keys": [key],
            "identities": identities
        }))
        .expect("legacy managed graph fixture")
    }

    fn legacy_password_and_managed_source(
        key_id: &str,
        private_key: &str,
        password: &str,
    ) -> Vec<u8> {
        let source =
            legacy_managed_graph_source(key_id, None, private_key, None, None, None, false);
        let mut value: serde_json::Value =
            serde_json::from_slice(&source).expect("managed graph JSON");
        value["hosts"] = json!([{
            "id": "password-and-managed-host",
            "label": "Password and managed batch host",
            "hostname": "password.example.test",
            "port": 22,
            "username": "password-user",
            "protocol": "ssh",
            "authMethod": "password",
            "authPolicyVersion": 1,
            "savePassword": true,
            "password": password,
            "createdAt": 51,
            "updatedAt": 51
        }]);
        serde_json::to_vec(&value).expect("password and managed graph fixture")
    }

    async fn resolve_test_managed_bundle(
        state: &DesktopState,
        key: netcatty_vault::SavedManagedSshKey,
    ) -> netcatty_secret_store::SshSecretBundle {
        let secret_files = state.secret_files.clone();
        let master_keys = state.master_keys.clone();
        tokio::task::spawn_blocking(move || {
            let guard = secret_files.lock_exclusive().expect("secret-store lock");
            let owner = guard
                .owner_id()
                .expect("secret-store owner read")
                .expect("secret-store owner");
            let store_state = guard.load_state().expect("secret-store state");
            assert!(
                owner == store_state.store_id(),
                "secret-store owner mismatch"
            );
            let master_key = master_keys
                .load_blocking(owner, store_state.active_master_key_epoch())
                .expect("test master key");
            let locator = guard
                .restore_object_locator(key.id.as_str(), key.custody().backend_locator().as_str())
                .expect("managed locator");
            guard
                .resolve_object(&master_key, &locator, key.custody().custody_revision())
                .expect("managed secret bundle")
        })
        .await
        .expect("managed bundle worker")
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

    fn saved_vault_snapshot_json(root: &std::path::Path) -> serde_json::Value {
        persisted_files(root)
            .into_iter()
            .filter_map(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .find(|value| value["magic"] == "netcatty-saved-host-snapshot")
            .expect("saved Vault snapshot JSON")
    }

    fn assert_renderer_json_excludes(encoded: &str, forbidden: &[&str]) {
        for value in forbidden {
            assert!(
                !encoded.contains(value),
                "renderer JSON contained forbidden managed-key material"
            );
        }
    }

    fn stored_host_reference(id: &str) -> StoredCredentialReference {
        StoredCredentialReference::for_saved_host(id).expect("deterministic host reference")
    }

    fn stored_identity_reference(id: &str) -> StoredCredentialReference {
        StoredCredentialReference::for_saved_identity(id).expect("deterministic identity reference")
    }

    fn four_legacy_credential_owners(id: &SavedHostId) -> Vec<super::LegacyImportCredentialOwner> {
        vec![
            super::LegacyImportCredentialOwner::for_saved_host(id),
            super::LegacyImportCredentialOwner::for_password_identity(id.as_str())
                .expect("password identity owner"),
            super::LegacyImportCredentialOwner::for_host_inline_proxy(id),
            super::LegacyImportCredentialOwner::for_proxy_profile(id.as_str())
                .expect("proxy profile owner"),
        ]
    }

    async fn create_test_host_with_password(
        state: &DesktopState,
        owner: &str,
        label: &str,
        password: &str,
    ) -> super::SavedHostView {
        let staged = state
            .ephemeral_credentials
            .insert(owner, test_secret(password))
            .await
            .expect("stage saved-host password");
        super::create_saved_host_inner(
            state,
            owner,
            CreateSavedHostRequest {
                draft: SavedHostDraftRequest {
                    label: Some(label.to_owned()),
                    hostname: format!("{}.example.test", label.to_ascii_lowercase()),
                    port: 22,
                    username: "saved-host-user".to_owned(),
                    protocol: Default::default(),
                    serial_config: None,
                    charset: None,
                    group: None,
                    auth_method: Default::default(),
                    managed_ssh_key_id: None,
                    tags: Vec::new(),
                    host_chain: None,
                    password_identity_id: None,
                    transport: Default::default(),
                    proxy: None,
                },
                staged_credential_reference: Some(staged),
            },
        )
        .await
        .expect("create saved host with password")
    }

    async fn activate_test_saved_host_transaction(
        state: &DesktopState,
        plan: &super::SavedVaultGraphReplacementPlan,
        id: &SavedHostId,
    ) -> (
        super::LegacyImportTransaction,
        StoredCredentialReference,
        StoredCredentialReference,
        LegacyPreviousCredentialState,
    ) {
        let owner = super::LegacyImportCredentialOwner::for_saved_host(id);
        let preparing = super::begin_legacy_import_transaction_for_owners(
            state,
            vec![owner.clone()],
            plan.before_graph_commitment().clone(),
            plan.after_graph_commitment().clone(),
        )
        .await
        .expect("begin saved-host transaction");
        let (target, backup) =
            super::legacy_import_credential_references_for_owner(&preparing, &owner)
                .expect("saved-host transaction references");
        let previous = match state
            .persistent_credentials
            .resolve(&target, CredentialKind::SshPassword)
            .await
        {
            Ok(secret) => {
                state
                    .persistent_credentials
                    .upsert(&backup, CredentialKind::SshPassword, secret)
                    .await
                    .expect("backup previous saved-host password");
                LegacyPreviousCredentialState::BackedUp
            }
            Err(error) if error.code() == CredentialErrorCode::NotFound => {
                LegacyPreviousCredentialState::Absent
            }
            Err(error) => panic!("unexpected credential probe error: {error}"),
        };
        let active = super::activate_legacy_import_transaction_for_owners(
            preparing,
            vec![(owner, previous)],
        )
        .await
        .expect("activate saved-host transaction");
        (active, target, backup, previous)
    }

    fn test_password_identity(
        id: &str,
        username: &str,
        has_saved_credential: bool,
    ) -> netcatty_vault::SavedPasswordIdentity {
        netcatty_vault::SavedPasswordIdentity::from_parts(
            netcatty_vault::SavedPasswordIdentityId::from_opaque(id).expect("identity ID"),
            1,
            "Shared password identity",
            username,
            has_saved_credential,
            10,
            10,
            Default::default(),
        )
        .expect("password identity")
    }

    fn test_password_identity_host(
        id: &str,
        identity_id: Option<&str>,
        has_saved_host_credential: bool,
    ) -> SavedHost {
        let mut value = json!({
            "recordVersion": 1,
            "id": id,
            "revision": 1,
            "label": "Password identity host",
            "hostname": "identity-host.example.test",
            "port": 22,
            "username": "host-user",
            "protocol": "ssh",
            "authMethod": "password",
            "authPolicyVersion": 1,
            "createdAt": 10,
            "updatedAt": 10,
            "hasSavedCredential": has_saved_host_credential
        });
        if let Some(identity_id) = identity_id {
            value["identityId"] = json!(identity_id);
        }
        serde_json::from_value(value).expect("password identity host")
    }

    fn publish_test_password_identity_graph(
        state: &DesktopState,
        host: Option<SavedHost>,
        identity: netcatty_vault::SavedPasswordIdentity,
    ) -> (Option<SavedHost>, netcatty_vault::SavedPasswordIdentity) {
        let candidate = SavedVaultGraph::new_with_password_identities(
            host.clone().into_iter().collect(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![identity.clone()],
        );
        let revision = state
            .saved_hosts
            .assess_graph_import(&candidate)
            .expect("password identity graph assessment")
            .into_revision();
        state
            .saved_hosts
            .commit_graph_import(revision, candidate)
            .expect("password identity graph commit");
        let graph = state.saved_hosts.graph().expect("persisted identity graph");
        (
            host.map(|host| {
                graph
                    .hosts()
                    .iter()
                    .find(|candidate| candidate.id == host.id)
                    .expect("persisted host")
                    .clone()
            }),
            graph
                .password_identities()
                .iter()
                .find(|candidate| candidate.id == identity.id)
                .expect("persisted identity")
                .clone(),
        )
    }

    fn saved_password_session_request(host: &SavedHost) -> StartSavedHostSessionRequest {
        StartSavedHostSessionRequest {
            client_attempt_id: test_client_attempt_id(),
            host_id: host.id.as_str().to_owned(),
            expected_revision: host.revision,
            credential_reference: None,
            proxy_credential_reference: None,
            key_passphrase_reference: None,
            selected_identity_file_paths: Vec::new(),
            known_hosts: Vec::new(),
            verify_host_keys: true,
            shell: None,
        }
    }

    fn test_chain_host(
        id: &str,
        protocol: &str,
        host_chain: Option<serde_json::Value>,
    ) -> SavedHost {
        let mut value = json!({
            "recordVersion": 1,
            "id": id,
            "revision": 1,
            "label": "Chain host",
            "hostname": "chain-host.example.test",
            "port": 22,
            "username": "chain-user",
            "protocol": protocol,
            "authMethod": "password",
            "authPolicyVersion": 1,
            "createdAt": 10,
            "updatedAt": 10,
            "hasSavedCredential": false
        });
        if let Some(host_chain) = host_chain {
            value["hostChain"] = host_chain;
        }
        serde_json::from_value(value).expect("chain host")
    }

    fn test_chain_graph(hosts: Vec<SavedHost>) -> SavedVaultGraph {
        SavedVaultGraph::new_with_proxy_profiles(
            hosts,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }

    fn test_persisted_known_host() -> netcatty_vault::SavedKnownHost {
        netcatty_vault::SavedKnownHost {
            id: "kh-vault-projection".to_owned(),
            hostname: "chain-host.example.test".to_owned(),
            port: 22,
            key_type: "ssh-ed25519".to_owned(),
            public_key: "ssh-ed25519 a2V5".to_owned(),
            fingerprint: Some("trusted-vault-fingerprint".to_owned()),
            discovered_at: 10,
            last_seen: None,
            converted_to_host_id: None,
            order: Some(0),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saved_host_and_port_forward_prepare_from_the_durable_vault_known_hosts_catalog() {
        let directory = tempfile::tempdir().expect("temporary Vault");
        let state = DesktopState::open(directory.path()).expect("desktop state");
        let host = test_chain_host("known-host-projection-target", "ssh", None);
        let rule = netcatty_vault::SavedPortForwardRule::new(
            "known-host-projection-rule",
            "Known Hosts projection",
            netcatty_vault::SavedPortForwardKind::Dynamic,
            1080,
            "127.0.0.1",
            None,
            None,
            host.id.as_str(),
            false,
            10,
            None,
            Some(0),
        )
        .expect("port-forward rule");
        let graph = SavedVaultGraph::new_with_port_forward_rules(
            vec![host.clone()],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Default::default(),
            vec![rule],
        );
        let initial = state
            .saved_hosts
            .known_host_catalog()
            .expect("initial Known Hosts catalog");
        let plan = state
            .saved_hosts
            .plan_graph_replacement(initial.revision().clone(), &graph)
            .expect("graph plan");
        state
            .saved_hosts
            .commit_planned_graph_replacement(plan, graph)
            .expect("graph publication");
        let before_known_hosts = state
            .saved_hosts
            .known_host_catalog()
            .expect("Known Hosts revision");
        let saved_known_host = test_persisted_known_host();
        let committed = state
            .saved_hosts
            .replace_known_hosts(
                before_known_hosts.revision().clone(),
                vec![saved_known_host.clone()],
            )
            .expect("Known Hosts publication");

        let saved_password = state
            .ephemeral_credentials
            .insert("saved-host-known-hosts", test_secret("saved-host-password"))
            .await
            .expect("saved-host password");
        let mut saved_request = saved_password_session_request(&host);
        saved_request.credential_reference = Some(saved_password);
        let prepared_saved =
            prepare_test_saved_host_session(&state, "saved-host-known-hosts", saved_request)
                .await
                .expect("SavedHost preparation");
        assert_eq!(prepared_saved.known_hosts.len(), 1);
        assert_eq!(prepared_saved.known_hosts[0].id, saved_known_host.id);
        assert_eq!(
            prepared_saved.known_hosts[0].fingerprint,
            saved_known_host.fingerprint
        );

        let prepared_quick_connect = super::load_connection_known_hosts(&state, Vec::new())
            .await
            .expect("Quick Connect Known Hosts preparation");
        assert_eq!(prepared_quick_connect.len(), 1);
        assert_eq!(prepared_quick_connect[0].id, saved_known_host.id);
        assert_eq!(
            prepared_quick_connect[0].fingerprint,
            saved_known_host.fingerprint
        );

        let prepared_forward = super::prepare_port_forward_start(
            &state,
            super::StartPortForwardRequest {
                id: "known-host-projection-rule".to_owned(),
                expected_inventory_revision: committed.revision().clone(),
                credential_reference: None,
                proxy_credential_reference: None,
                key_passphrase_reference: None,
                selected_identity_file_paths: Vec::new(),
                known_hosts: Vec::new(),
                verify_host_keys: true,
            },
            super::StagedSavedHostSessionSecrets {
                credential: Some(test_secret("port-forward-password")),
                proxy_credential: None,
                key_passphrase: None,
            },
        )
        .await
        .expect("PortForward preparation");
        assert_eq!(prepared_forward.session.known_hosts.len(), 1);
        assert_eq!(
            prepared_forward.session.known_hosts[0].id,
            saved_known_host.id
        );
    }

    fn with_test_host_fields(host: SavedHost, fields: serde_json::Value) -> SavedHost {
        let mut value = serde_json::to_value(host).expect("saved host JSON");
        let object = value.as_object_mut().expect("saved host object");
        object.extend(
            fields
                .as_object()
                .expect("saved host fields")
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        serde_json::from_value(value).expect("saved host fields")
    }

    fn publish_test_chain_graph(state: &DesktopState, graph: SavedVaultGraph) -> SavedVaultGraph {
        let revision = state
            .saved_hosts
            .assess_graph_import(&graph)
            .expect("chain graph assessment")
            .into_revision();
        state
            .saved_hosts
            .commit_graph_import(revision, graph)
            .expect("chain graph commit");
        state.saved_hosts.graph().expect("persisted chain graph")
    }

    #[test]
    fn saved_host_chain_plan_preserves_nearest_to_furthest_order() {
        let target = test_chain_host(
            "chain-target",
            "ssh",
            Some(json!({ "hostIds": ["nearest-jump", "furthest-jump"] })),
        );
        let graph = test_chain_graph(vec![
            target.clone(),
            test_chain_host("furthest-jump", "ssh", None),
            test_chain_host("nearest-jump", "ssh", None),
        ]);

        let plan = super::plan_saved_host_chain(&graph, &target).expect("saved host chain");
        assert_eq!(
            plan.jumps
                .iter()
                .map(|(id, _)| id.as_str())
                .collect::<Vec<_>>(),
            vec!["nearest-jump", "furthest-jump"]
        );
    }

    #[test]
    fn saved_host_chain_plan_fails_closed_for_missing_duplicate_and_self_references() {
        for (target_id, host_ids) in [
            ("missing-target", json!(["missing-jump"])),
            ("duplicate-target", json!(["jump", "jump"])),
            ("self-target", json!(["self-target"])),
        ] {
            let target = test_chain_host(target_id, "ssh", Some(json!({ "hostIds": host_ids })));
            let graph =
                test_chain_graph(vec![target.clone(), test_chain_host("jump", "ssh", None)]);
            let error = super::plan_saved_host_chain(&graph, &target)
                .err()
                .expect("invalid chain must fail");
            assert!(error.starts_with(super::SAVED_HOST_CHAIN_INVALID));
            assert!(!error.contains(target_id));
            assert!(!error.contains("missing-jump"));
        }
    }

    #[test]
    fn saved_host_chain_plan_fails_closed_for_non_ssh_and_malformed_hops() {
        let non_ssh_target = test_chain_host(
            "non-ssh-target",
            "ssh",
            Some(json!({ "hostIds": ["telnet-jump"] })),
        );
        let non_ssh_graph = test_chain_graph(vec![
            non_ssh_target.clone(),
            test_chain_host("telnet-jump", "telnet", None),
        ]);
        let error = super::plan_saved_host_chain(&non_ssh_graph, &non_ssh_target)
            .err()
            .expect("non-SSH jump must fail");
        assert!(error.starts_with(super::SAVED_HOST_CHAIN_INVALID));

        let malformed = test_chain_host(
            "malformed-target",
            "ssh",
            Some(json!({ "hostIds": "not-an-array" })),
        );
        let error =
            super::plan_saved_host_chain(&test_chain_graph(vec![malformed.clone()]), &malformed)
                .err()
                .expect("malformed chain must fail");
        assert!(error.starts_with(super::SAVED_HOST_CHAIN_INVALID));
    }

    #[tokio::test]
    async fn saved_host_chain_prepares_group_password_options_and_per_hop_proxy() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, controller) = desktop_state_with_memory_credentials(directory.path());
        let target = with_test_host_fields(
            test_chain_host(
                "prepared-chain-target",
                "ssh",
                Some(json!({ "hostIds": ["prepared-chain-jump"] })),
            ),
            json!({ "hasSavedCredential": true }),
        );
        let jump = with_test_host_fields(
            test_chain_host("prepared-chain-jump", "ssh", None),
            json!({
                "username": "",
                "group": "Bastions",
                "proxyConfig": {
                    "type": "http",
                    "host": "jump-proxy.example.test",
                    "port": 8080,
                    "username": "proxy-user",
                    "hasSavedCredential": true
                }
            }),
        );
        let group_id =
            netcatty_vault::SavedGroupId::from_opaque("bastion-group").expect("group ID");
        let group = netcatty_vault::SavedGroupConfig::from_parts(
            group_id.clone(),
            1,
            netcatty_vault::SavedGroupPath::new("Bastions").expect("group path"),
            netcatty_vault::SavedGroupDefaults {
                username: netcatty_vault::SavedGroupOverride::Set(
                    netcatty_vault::SavedGroupSingleLineText::new("group-jump-user")
                        .expect("group username"),
                ),
                password: netcatty_vault::SavedGroupCredentialOverride::StoredHint,
                legacy_algorithms: netcatty_vault::SavedGroupOverride::Set(true),
                ..netcatty_vault::SavedGroupDefaults::default()
            },
            10,
            10,
        )
        .expect("group config");
        let graph = publish_test_chain_graph(
            &state,
            SavedVaultGraph::new_with_proxy_profiles(
                vec![target, jump],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                vec![group],
            ),
        );
        let target = graph
            .hosts()
            .iter()
            .find(|host| host.id.as_str() == "prepared-chain-target")
            .expect("target host");
        let jump = graph
            .hosts()
            .iter()
            .find(|host| host.id.as_str() == "prepared-chain-jump")
            .expect("jump host");
        state
            .persistent_credentials
            .upsert(
                &StoredCredentialReference::for_saved_host(target.id.as_str())
                    .expect("target credential reference"),
                CredentialKind::SshPassword,
                test_secret("target-password-sentinel"),
            )
            .await
            .expect("target password");
        state
            .persistent_credentials
            .upsert(
                &StoredCredentialReference::for_saved_group_ssh(group_id.as_str())
                    .expect("group credential reference"),
                CredentialKind::SshPassword,
                test_secret("group-jump-password-sentinel"),
            )
            .await
            .expect("group jump password");
        state
            .persistent_credentials
            .upsert(
                &StoredCredentialReference::for_saved_host_proxy(jump.id.as_str())
                    .expect("jump proxy reference"),
                CredentialKind::ProxyPassword,
                test_secret("jump-proxy-password-sentinel"),
            )
            .await
            .expect("jump proxy password");
        controller.clear_operation_log();

        let prepared = prepare_test_saved_host_session(
            &state,
            "prepared-chain-window",
            saved_password_session_request(target),
        )
        .await
        .expect("prepared saved host chain");

        assert_eq!(prepared.config.jump_hosts.len(), 1);
        assert_eq!(prepared.config.jump_hosts[0].host_id, jump.id.as_str());
        assert_eq!(prepared.jump_hosts.len(), 1);
        let prepared_jump = &prepared.jump_hosts[0];
        assert_eq!(prepared_jump.host_id, jump.id.as_str());
        assert_eq!(prepared_jump.config.username, "group-jump-user");
        assert_eq!(prepared_jump.config.legacy_algorithms, Some(true));
        assert!(matches!(
            prepared_jump.config.proxy.as_ref(),
            Some(netcatty_ssh::ProxyConfig {
                proxy_type: ProxyType::Http,
                ..
            })
        ));
        assert_eq!(
            controller
                .operation_log()
                .count(CredentialOperation::Resolve),
            3
        );
    }

    #[tokio::test]
    async fn saved_host_chain_never_reuses_target_one_shot_for_a_jump() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let state = DesktopState::open(directory.path()).expect("desktop state");
        let target = test_chain_host(
            "one-shot-chain-target",
            "ssh",
            Some(json!({ "hostIds": ["one-shot-chain-jump"] })),
        );
        let graph = publish_test_chain_graph(
            &state,
            test_chain_graph(vec![
                target,
                test_chain_host("one-shot-chain-jump", "ssh", None),
            ]),
        );
        let target = graph
            .hosts()
            .iter()
            .find(|host| host.id.as_str() == "one-shot-chain-target")
            .expect("target host");
        let staged = state
            .ephemeral_credentials
            .insert(
                "one-shot-chain-window",
                test_secret("target-only-password-sentinel"),
            )
            .await
            .expect("target one-shot password");
        let mut request = saved_password_session_request(target);
        request.credential_reference = Some(staged.clone());

        let error = prepare_test_saved_host_session(&state, "one-shot-chain-window", request)
            .await
            .err()
            .expect("jump must require its own credential");
        assert!(error.starts_with(super::SAVED_HOST_CHAIN_CREDENTIAL_REQUIRED));
        assert!(!error.contains("target-only-password-sentinel"));
        assert_ephemeral_reference_consumed(&state, "one-shot-chain-window", &staged).await;
    }

    #[tokio::test]
    async fn saved_host_chain_resolves_a_jump_password_identity_independently() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, controller) = desktop_state_with_memory_credentials(directory.path());
        let target = test_chain_host(
            "identity-chain-target",
            "ssh",
            Some(json!({ "hostIds": ["identity-chain-jump"] })),
        );
        let jump = with_test_host_fields(
            test_chain_host("identity-chain-jump", "ssh", None),
            json!({ "identityId": "identity-chain-credential" }),
        );
        let identity =
            test_password_identity("identity-chain-credential", "identity-chain-user", true);
        let graph = publish_test_chain_graph(
            &state,
            SavedVaultGraph::new_with_proxy_profiles(
                vec![target, jump],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                vec![identity],
                Vec::new(),
                Vec::new(),
            ),
        );
        state
            .persistent_credentials
            .upsert(
                &StoredCredentialReference::for_saved_identity("identity-chain-credential")
                    .expect("identity credential reference"),
                CredentialKind::SshPassword,
                test_secret("identity-chain-password-sentinel"),
            )
            .await
            .expect("identity password");
        controller.clear_operation_log();
        let target = graph
            .hosts()
            .iter()
            .find(|host| host.id.as_str() == "identity-chain-target")
            .expect("target host");
        let staged = state
            .ephemeral_credentials
            .insert(
                "identity-chain-window",
                test_secret("identity-target-password-sentinel"),
            )
            .await
            .expect("target password");
        let mut request = saved_password_session_request(target);
        request.credential_reference = Some(staged);

        let prepared = prepare_test_saved_host_session(&state, "identity-chain-window", request)
            .await
            .expect("identity jump preparation");
        assert_eq!(prepared.jump_hosts.len(), 1);
        assert_eq!(
            prepared.jump_hosts[0].config.username,
            "identity-chain-user"
        );
        assert_eq!(
            controller
                .operation_log()
                .count(CredentialOperation::Resolve),
            1
        );
    }

    #[tokio::test]
    async fn saved_host_chain_reference_jump_requires_a_fresh_host_bound_picker() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let state = DesktopState::open(directory.path()).expect("desktop state");
        let target = test_chain_host(
            "reference-chain-target",
            "ssh",
            Some(json!({ "hostIds": ["reference-chain-jump"] })),
        );
        let jump = with_test_host_fields(
            test_chain_host("reference-chain-jump", "ssh", None),
            json!({
                "authMethod": "key",
                "identityFileId": "reference-chain-key"
            }),
        );
        let reference_path = r"Z:\must-not-be-opened\reference-chain-key";
        let reference = netcatty_vault::SavedSshKeyReference::from_parts(
            netcatty_vault::SavedSshKeyReferenceId::from_opaque("reference-chain-key")
                .expect("reference key ID"),
            "Reference chain key",
            reference_path,
            netcatty_vault::SavedSshKeyCategory::key(),
            10,
            10,
            Default::default(),
        )
        .expect("reference key");
        let graph = publish_test_chain_graph(
            &state,
            SavedVaultGraph::new_with_proxy_profiles(
                vec![target, jump],
                vec![reference],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
        );
        let target = graph
            .hosts()
            .iter()
            .find(|host| host.id.as_str() == "reference-chain-target")
            .expect("target host");
        let staged = state
            .ephemeral_credentials
            .insert(
                "reference-chain-window",
                test_secret("reference-target-password-sentinel"),
            )
            .await
            .expect("target one-shot password");
        let mut request = saved_password_session_request(target);
        request.credential_reference = Some(staged);

        let error = prepare_test_saved_host_session(&state, "reference-chain-window", request)
            .await
            .err()
            .expect("reference jump must require picker");
        assert!(error.starts_with(super::SAVED_HOST_CHAIN_CREDENTIAL_REQUIRED));
        assert!(!error.contains("reference-chain-key"));
        assert!(!error.contains(reference_path));
    }

    #[tokio::test]
    async fn direct_saved_host_preparation_keeps_the_direct_runtime_path() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let state = DesktopState::open(directory.path()).expect("desktop state");
        let graph = publish_test_chain_graph(
            &state,
            test_chain_graph(vec![test_chain_host("direct-regression-host", "ssh", None)]),
        );
        let host = &graph.hosts()[0];
        let staged = state
            .ephemeral_credentials
            .insert(
                "direct-regression-window",
                test_secret("direct-regression-password-sentinel"),
            )
            .await
            .expect("direct one-shot password");
        let mut request = saved_password_session_request(host);
        request.client_attempt_id =
            ClientAttemptId::parse("attempt-direct-route-preserved".to_owned())
                .expect("direct attempt ID");
        request.credential_reference = Some(staged);

        let prepared = prepare_test_saved_host_session(&state, "direct-regression-window", request)
            .await
            .expect("direct saved host preparation");
        assert_eq!(
            prepared.client_attempt_id.as_str(),
            "attempt-direct-route-preserved"
        );
        assert!(prepared.config.jump_hosts.is_empty());
        assert!(prepared.jump_hosts.is_empty());
    }

    fn test_proxy_host(
        id: &str,
        inline: Option<netcatty_vault::SavedProxyConfig>,
        profile_id: Option<&str>,
    ) -> SavedHost {
        let mut value = json!({
            "recordVersion": 1,
            "id": id,
            "revision": 1,
            "label": "Proxy connection host",
            "hostname": "proxy-target.example.test",
            "port": 22,
            "username": "ssh-user",
            "protocol": "ssh",
            "authMethod": "password",
            "authPolicyVersion": 1,
            "createdAt": 10,
            "updatedAt": 10,
            "hasSavedCredential": false
        });
        if let Some(inline) = inline {
            value["proxyConfig"] = serde_json::to_value(inline).expect("inline proxy JSON");
        }
        if let Some(profile_id) = profile_id {
            value["proxyProfileId"] = json!(profile_id);
        }
        serde_json::from_value(value).expect("proxy host")
    }

    fn test_malformed_inline_proxy_host(id: &str) -> SavedHost {
        serde_json::from_value(json!({
            "recordVersion": 1,
            "id": id,
            "revision": 1,
            "label": "Malformed inline proxy host",
            "hostname": "proxy-target.example.test",
            "port": 22,
            "username": "ssh-user",
            "protocol": "ssh",
            "authMethod": "password",
            "authPolicyVersion": 1,
            "createdAt": 10,
            "updatedAt": 10,
            "hasSavedCredential": false,
            "proxyConfig": {
                "type": "http",
                "port": 8080,
                "sensitiveMarker": "malformed-inline-sentinel"
            }
        }))
        .expect("malformed inline proxy host")
    }

    fn seed_legacy_malformed_inline_proxy_snapshot(vault_path: &std::path::Path, host: &SavedHost) {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct LegacyChecksumPayload<'a> {
            format_version: u32,
            store_id: &'a str,
            slot: &'a str,
            generation: u64,
            hosts: &'a [SavedHost],
        }

        let saved_hosts_path = vault_path.join("saved-hosts");
        let owner: serde_json::Value = serde_json::from_slice(
            &std::fs::read(saved_hosts_path.join("owner.json")).expect("saved-host owner"),
        )
        .expect("saved-host owner JSON");
        let store_id = owner["storeId"].as_str().expect("saved-host store ID");
        let hosts = std::slice::from_ref(host);
        let checksum_payload = serde_json::to_vec(&LegacyChecksumPayload {
            format_version: 1,
            store_id,
            slot: "a",
            generation: 1,
            hosts,
        })
        .expect("legacy checksum payload");
        let checksum = hex_encode(&Sha256::digest(checksum_payload));
        let snapshot = json!({
            "magic": "netcatty-saved-host-snapshot",
            "formatVersion": 1,
            "storeId": store_id,
            "slot": "a",
            "generation": 1,
            "hosts": hosts,
            "checksum": checksum
        });
        std::fs::write(
            saved_hosts_path
                .join("slot-a")
                .join("snapshot-00000000000000000001-11111111111111111111111111111111.json"),
            serde_json::to_vec(&snapshot).expect("legacy snapshot JSON"),
        )
        .expect("seed legacy malformed proxy snapshot");
    }

    fn test_proxy_profile(
        id: &str,
        config: netcatty_vault::SavedProxyConfig,
    ) -> netcatty_vault::SavedProxyProfile {
        netcatty_vault::SavedProxyProfile::from_parts(
            netcatty_vault::SavedProxyProfileId::from_opaque(id).expect("profile ID"),
            1,
            "Connection proxy",
            config,
            10,
            10,
            Default::default(),
        )
        .expect("proxy profile")
    }

    fn publish_test_proxy_graph(
        state: &DesktopState,
        host: SavedHost,
        identities: Vec<netcatty_vault::SavedPasswordIdentity>,
        profiles: Vec<netcatty_vault::SavedProxyProfile>,
    ) -> SavedVaultGraph {
        let candidate = SavedVaultGraph::new_with_proxy_profiles(
            vec![host],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            identities,
            profiles,
            Vec::new(),
        );
        let revision = state
            .saved_hosts
            .assess_graph_import(&candidate)
            .expect("proxy graph assessment")
            .into_revision();
        state
            .saved_hosts
            .commit_graph_import(revision, candidate)
            .expect("proxy graph commit");
        state.saved_hosts.graph().expect("persisted proxy graph")
    }

    async fn stage_saved_host_ssh_password(
        state: &DesktopState,
        owner: &str,
        marker: &str,
    ) -> EphemeralCredentialReference {
        state
            .ephemeral_credentials
            .insert(owner, test_secret(marker))
            .await
            .expect("stage SSH password")
    }

    #[test]
    fn terminal_frames_keep_output_bytes_raw() {
        assert_eq!(frame_data(0, None, vec![0, 255]), vec![0, 0, 255]);
        assert_eq!(
            frame_data(1, Some(7), vec![1, 2]),
            vec![1, 0, 0, 0, 7, 1, 2]
        );
    }

    #[test]
    fn raw_interactive_envelope_decodes_without_json_secrets() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&3_u16.to_be_bytes());
        bytes.extend_from_slice(b"req");
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&6_u32.to_be_bytes());
        bytes.extend_from_slice(b"123456");
        let (request, answers) = decode_interactive_response(&bytes).expect("envelope");
        assert_eq!(request, "req");
        assert_eq!(answers.len(), 1);
    }

    #[test]
    fn terminal_data_frame_preserves_large_binary_chunks() {
        let payload = vec![0xFF; 64 * 1024];
        let frame = frame_data(0, None, payload.clone());
        assert_eq!(frame.len(), payload.len() + 1);
        assert_eq!(&frame[1..], payload);
    }

    #[test]
    fn local_transfer_sources_distinguish_files_and_directories() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let directory = std::fs::metadata(manifest_dir).expect("desktop manifest directory");
        let file = std::fs::metadata(manifest_dir.join("src/lib.rs")).expect("desktop source file");

        assert_eq!(
            classify_local_transfer_metadata(&directory),
            Ok(LocalTransferSourceKind::Directory)
        );
        assert_eq!(
            classify_local_transfer_metadata(&file),
            Ok(LocalTransferSourceKind::File)
        );
    }

    #[test]
    fn started_download_preserves_the_reusable_artifact_plan() {
        let started = StartedSftpDownload {
            transfer_id: "transfer-1".to_owned(),
            plan: SftpDownloadPlan {
                artifacts: SftpArtifactPlan {
                    version: 1,
                    artifact_id: "artifact-1".to_owned(),
                    target_path: "C:\\downloads\\report.txt".to_owned(),
                    workspace_path: "C:\\downloads\\.netcatty-artifacts".to_owned(),
                    owner_path: "C:\\downloads\\.netcatty-artifacts\\artifact-1.owner".to_owned(),
                    staged_path: "C:\\downloads\\.netcatty-artifacts\\artifact-1.part".to_owned(),
                    backup_path: "C:\\downloads\\.netcatty-artifacts\\artifact-1.backup".to_owned(),
                },
            },
        };

        assert_eq!(started.transfer_id, "transfer-1");
        assert_eq!(started.plan.artifacts.version, 1);
        assert_eq!(started.plan.artifacts.artifact_id, "artifact-1");
        assert_eq!(
            started.plan.artifacts.staged_path,
            "C:\\downloads\\.netcatty-artifacts\\artifact-1.part"
        );
    }

    #[test]
    fn saved_host_view_exposes_presence_but_no_credential_reference() {
        let host: SavedHost = serde_json::from_value(json!({
            "recordVersion": 1,
            "id": "legacy-host-id",
            "revision": 3,
            "label": "Production",
            "hostname": "server.example.test",
            "port": 22,
            "username": "alice",
            "protocol": "ssh",
            "authMethod": "password",
            "authPolicyVersion": 1,
            "createdAt": 10,
            "updatedAt": 20,
            "hasSavedCredential": true
        }))
        .expect("saved host");
        let encoded = serde_json::to_string(&saved_host_view(&host)).expect("saved-host view");

        assert!(encoded.contains("\"hasSavedCredential\":true"));
        assert!(encoded.contains("\"hasSavedHostCredential\":true"));
        assert!(encoded.contains("\"passwordIdentity\":null"));
        assert!(!encoded.contains("credentialReference"));
        assert!(!encoded.contains("credentialId"));
        assert!(!encoded.contains("\"password\":"));
    }

    #[test]
    fn saved_host_view_projects_et_only_for_effective_ssh_without_mosh() {
        let inherited_et_host = with_test_host_fields(
            test_chain_host("et-renderer-host", "ssh", None),
            json!({ "group": "Operations" }),
        );
        let conflicting_host = with_test_host_fields(
            test_chain_host("et-mosh-renderer-host", "ssh", None),
            json!({
                "group": "Operations",
                "moshEnabled": true
            }),
        );
        let non_ssh_host = with_test_host_fields(
            test_chain_host("et-telnet-renderer-host", "telnet", None),
            json!({ "etEnabled": true }),
        );
        let group = netcatty_vault::SavedGroupConfig::from_parts(
            netcatty_vault::SavedGroupId::from_opaque("et-renderer-group").expect("group ID"),
            1,
            netcatty_vault::SavedGroupPath::new("Operations").expect("group path"),
            netcatty_vault::SavedGroupDefaults {
                et_enabled: netcatty_vault::SavedGroupOverride::Set(true),
                ..netcatty_vault::SavedGroupDefaults::default()
            },
            10,
            10,
        )
        .expect("ET group defaults");
        let graph = SavedVaultGraph::new_with_proxy_profiles(
            vec![inherited_et_host.clone(), conflicting_host.clone()],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![group],
        );

        let inherited = saved_host_view_from_graph(&inherited_et_host, &graph)
            .expect("inherited ET renderer view");
        assert_eq!(inherited.mosh_enabled, None);
        assert_eq!(inherited.et_enabled, None);
        assert_eq!(inherited.et_port, None);
        assert!(inherited.effective_et_enabled);
        assert!(!inherited.effective_mosh_enabled);
        assert_eq!(
            serde_json::to_value(&inherited).expect("ET renderer JSON")["effectiveEtEnabled"],
            json!(true)
        );

        let conflicting = saved_host_view_from_graph(&conflicting_host, &graph)
            .expect("conflicting renderer view");
        assert_eq!(conflicting.mosh_enabled, Some(true));
        assert_eq!(conflicting.et_enabled, None);
        assert!(conflicting.effective_mosh_enabled);
        assert!(!conflicting.effective_et_enabled);

        let non_ssh = saved_host_view(&non_ssh_host);
        assert!(!non_ssh.effective_et_enabled);
    }

    #[test]
    fn saved_host_transport_crud_round_trips_overrides_and_restores_inheritance() {
        let create: SavedHostDraftRequest = serde_json::from_value(json!({
            "hostname": "et-crud.example.test",
            "port": 22,
            "username": "alice",
            "etEnabled": true,
            "etPort": 2202
        }))
        .expect("typed ET host request");
        let host = SavedHost::from_draft(
            super::create_vault_draft(create, false).expect("ET host draft"),
            10,
        )
        .expect("ET host");

        assert_eq!(host.compatibility_fields()["moshEnabled"], json!(false));
        assert_eq!(host.compatibility_fields()["etEnabled"], json!(true));
        assert_eq!(host.compatibility_fields()["etPort"], json!(2202));
        let created_view = saved_host_view(&host);
        assert_eq!(created_view.mosh_enabled, Some(false));
        assert_eq!(created_view.et_enabled, Some(true));
        assert_eq!(created_view.et_port, Some(2202));
        assert!(!created_view.effective_mosh_enabled);
        assert!(created_view.effective_et_enabled);

        let select_mosh: SavedHostDraftRequest = serde_json::from_value(json!({
            "hostname": "et-crud.example.test",
            "port": 22,
            "username": "alice",
            "moshEnabled": true
        }))
        .expect("typed Mosh host request");
        let mosh_host = host
            .apply_update(
                super::create_vault_update(select_mosh, false).expect("Mosh host update"),
                20,
            )
            .expect("updated Mosh host");
        assert_eq!(mosh_host.compatibility_fields()["moshEnabled"], json!(true));
        assert_eq!(mosh_host.compatibility_fields()["etEnabled"], json!(false));
        assert!(!mosh_host.compatibility_fields().contains_key("etPort"));

        let inherit: SavedHostDraftRequest = serde_json::from_value(json!({
            "hostname": "et-crud.example.test",
            "port": 22,
            "username": "alice"
        }))
        .expect("inherit transport request");
        let inherited = mosh_host
            .apply_update(
                super::create_vault_update(inherit, false).expect("inherit transport update"),
                30,
            )
            .expect("inherited transport host");
        assert!(!inherited.compatibility_fields().contains_key("moshEnabled"));
        assert!(!inherited.compatibility_fields().contains_key("etEnabled"));
        assert!(!inherited.compatibility_fields().contains_key("etPort"));
        let payload = serde_json::to_value(saved_host_view(&inherited))
            .expect("renderer inherited transport view");
        assert_eq!(payload["moshEnabled"], serde_json::Value::Null);
        assert_eq!(payload["etEnabled"], serde_json::Value::Null);
        assert_eq!(payload["etPort"], serde_json::Value::Null);
    }

    #[test]
    fn saved_host_transport_crud_rejects_conflicts_invalid_ports_and_non_ssh_fields() {
        for invalid in [
            json!({
                "hostname": "invalid.example.test",
                "port": 22,
                "username": "alice",
                "moshEnabled": true,
                "etEnabled": true
            }),
            json!({
                "hostname": "invalid.example.test",
                "port": 22,
                "username": "alice",
                "etPort": 0
            }),
            json!({
                "hostname": "invalid.example.test",
                "port": 22,
                "username": "alice",
                "etPort": 65_536
            }),
            json!({
                "hostname": "invalid.example.test",
                "port": 23,
                "username": "alice",
                "protocol": "telnet",
                "etEnabled": false
            }),
        ] {
            let request: SavedHostDraftRequest =
                serde_json::from_value(invalid).expect("well-typed invalid transport request");
            assert!(super::create_vault_draft(request, false).is_err());
        }
    }

    #[test]
    fn saved_host_view_nests_only_renderer_safe_legacy_visual_metadata() {
        let host: SavedHost = serde_json::from_value(json!({
            "recordVersion": 1,
            "id": "legacy-visual-view-host",
            "revision": 3,
            "label": "Visual host",
            "hostname": "visual.example.test",
            "port": 22,
            "username": "alice",
            "protocol": "ssh",
            "authMethod": "password",
            "authPolicyVersion": 1,
            "createdAt": 10,
            "updatedAt": 20,
            "os": "linux",
            "distro": "Ubuntu 24.04 LTS",
            "distroMode": "manual",
            "manualDistro": "rocky",
            "iconMode": "custom",
            "iconId": "database",
            "iconColorMode": "manual",
            "iconColor": "violet",
            "iconColorCustom": "#12Ab34",
            "unrelatedPluginMetadata": "must-not-cross-visual-boundary"
        }))
        .expect("saved host with legacy visual metadata");

        let payload = serde_json::to_value(saved_host_view(&host)).expect("saved-host view");
        assert_eq!(
            payload["visual"],
            json!({
                "os": "linux",
                "distro": "ubuntu",
                "distroMode": "manual",
                "manualDistro": "rocky",
                "iconMode": "custom",
                "iconId": "database",
                "iconColorMode": "manual",
                "iconColor": "violet",
                "iconColorCustom": "#12Ab34"
            })
        );
        for flattened in [
            "os",
            "distro",
            "distroMode",
            "manualDistro",
            "iconMode",
            "iconId",
            "iconColorMode",
            "iconColor",
            "iconColorCustom",
        ] {
            assert_eq!(
                payload.get(flattened),
                None,
                "field {flattened} must stay nested"
            );
        }
        assert!(
            !payload
                .to_string()
                .contains("must-not-cross-visual-boundary")
        );
    }

    #[test]
    fn saved_host_view_projects_canonical_group_paths_and_root_null() {
        let grouped_host: SavedHost = serde_json::from_value(json!({
            "recordVersion": 1,
            "id": "grouped-renderer-host",
            "revision": 3,
            "label": "Grouped host",
            "hostname": "grouped.example.test",
            "port": 22,
            "username": "alice",
            "protocol": "ssh",
            "authMethod": "password",
            "authPolicyVersion": 1,
            "createdAt": 10,
            "updatedAt": 20,
            "group": r"Ops\DB// Team /./.."
        }))
        .expect("grouped saved host");
        let grouped_view = saved_host_view(&grouped_host);

        assert_eq!(grouped_view.group.as_deref(), Some(r"Ops\DB/ Team /./.."));
        assert_eq!(
            serde_json::to_value(&grouped_view).expect("grouped saved-host view")["group"],
            json!(r"Ops\DB/ Team /./..")
        );

        let root_host: SavedHost = serde_json::from_value(json!({
            "recordVersion": 1,
            "id": "root-renderer-host",
            "revision": 1,
            "label": "Root host",
            "hostname": "root.example.test",
            "port": 22,
            "username": "bob",
            "protocol": "ssh",
            "authMethod": "password",
            "authPolicyVersion": 1,
            "createdAt": 10,
            "updatedAt": 10
        }))
        .expect("root saved host");
        let root_view = saved_host_view(&root_host);

        assert!(root_view.group.is_none());
        assert_eq!(
            serde_json::to_value(root_view).expect("root saved-host view")["group"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn saved_host_view_projects_renderer_safe_effective_group_appearance_without_mutation() {
        let inherited_host = with_test_host_fields(
            test_chain_host("appearance-inherited-host", "ssh", None),
            json!({ "group": "Production/Databases" }),
        );
        let explicit_host = with_test_host_fields(
            test_chain_host("appearance-explicit-host", "ssh", None),
            json!({
                "group": "Production/Databases",
                "theme": "netcatty-dark",
                "themeOverride": false,
                "fontFamily": "Cascadia Code",
                "fontSize": 24,
                "fontSizeOverride": false
            }),
        );
        let parent = netcatty_vault::SavedGroupConfig::from_parts(
            netcatty_vault::SavedGroupId::from_opaque("appearance-parent").expect("group ID"),
            1,
            netcatty_vault::SavedGroupPath::new("Production").expect("group path"),
            netcatty_vault::SavedGroupDefaults {
                theme: netcatty_vault::SavedGroupOverride::Set(
                    netcatty_vault::SavedGroupSingleLineText::new("netcatty-light").expect("theme"),
                ),
                theme_override: netcatty_vault::SavedGroupOverride::Set(true),
                font_family: netcatty_vault::SavedGroupOverride::Set(
                    netcatty_vault::SavedGroupSingleLineText::new("menlo").expect("font family"),
                ),
                font_family_override: netcatty_vault::SavedGroupOverride::Set(true),
                font_size: netcatty_vault::SavedGroupOverride::Set(
                    netcatty_vault::SavedGroupFiniteNumber::new("fontSize", 16.0)
                        .expect("font size"),
                ),
                font_size_override: netcatty_vault::SavedGroupOverride::Set(true),
                font_weight: netcatty_vault::SavedGroupOverride::Set(
                    netcatty_vault::SavedGroupFiniteNumber::new("fontWeight", 500.0)
                        .expect("font weight"),
                ),
                font_weight_override: netcatty_vault::SavedGroupOverride::Set(true),
                ..netcatty_vault::SavedGroupDefaults::default()
            },
            10,
            10,
        )
        .expect("parent appearance defaults");
        let child = netcatty_vault::SavedGroupConfig::from_parts(
            netcatty_vault::SavedGroupId::from_opaque("appearance-child").expect("group ID"),
            1,
            netcatty_vault::SavedGroupPath::new("Production/Databases").expect("group path"),
            netcatty_vault::SavedGroupDefaults {
                // Legacy false ignores this same-level value and preserves the
                // parent value with legacy value-present override semantics.
                theme: netcatty_vault::SavedGroupOverride::Set(
                    netcatty_vault::SavedGroupSingleLineText::new("netcatty-dark").expect("theme"),
                ),
                theme_override: netcatty_vault::SavedGroupOverride::Set(false),
                font_size: netcatty_vault::SavedGroupOverride::Set(
                    netcatty_vault::SavedGroupFiniteNumber::new("fontSize", 18.0)
                        .expect("font size"),
                ),
                font_size_override: netcatty_vault::SavedGroupOverride::Set(true),
                ..netcatty_vault::SavedGroupDefaults::default()
            },
            20,
            20,
        )
        .expect("child appearance defaults");
        let graph = SavedVaultGraph::new_with_proxy_profiles(
            vec![inherited_host.clone(), explicit_host.clone()],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![parent, child],
        );

        let inherited = super::saved_host_view_from_graph(&inherited_host, &graph)
            .expect("inherited appearance view");
        assert_eq!(
            inherited.effective_appearance.theme_id.as_deref(),
            Some("netcatty-light")
        );
        assert_eq!(
            inherited.effective_appearance.font_family.as_deref(),
            Some("menlo")
        );
        assert_eq!(
            inherited
                .effective_appearance
                .font_size
                .as_ref()
                .and_then(serde_json::Number::as_f64),
            Some(18.0)
        );
        assert_eq!(
            inherited
                .effective_appearance
                .font_weight
                .as_ref()
                .and_then(serde_json::Number::as_f64),
            Some(500.0)
        );

        let explicit = super::saved_host_view_from_graph(&explicit_host, &graph)
            .expect("explicit appearance view");
        assert!(explicit.effective_appearance.theme_id.is_none());
        assert_eq!(
            explicit.effective_appearance.font_family.as_deref(),
            Some("Cascadia Code")
        );
        assert!(explicit.effective_appearance.font_size.is_none());
        assert_eq!(
            explicit
                .effective_appearance
                .font_weight
                .as_ref()
                .and_then(serde_json::Number::as_f64),
            Some(500.0)
        );
        assert_eq!(graph.hosts()[0], inherited_host);
        assert_eq!(graph.hosts()[1], explicit_host);

        let encoded = serde_json::to_value(inherited).expect("renderer appearance JSON");
        assert_eq!(encoded["effectiveAppearance"]["themeId"], "netcatty-light");
        assert_eq!(encoded["effectiveAppearance"]["fontFamily"], "menlo");
        assert_eq!(encoded["effectiveAppearance"]["fontSize"], 18.0);
        assert_eq!(encoded["effectiveAppearance"]["fontWeight"], 500.0);
        assert!(encoded.get("compatibilityFields").is_none());
    }

    #[test]
    fn create_vault_draft_preserves_saved_group_path_semantics() {
        let draft = super::create_vault_draft(
            SavedHostDraftRequest {
                label: Some("Grouped create".to_owned()),
                hostname: "create-group.example.test".to_owned(),
                port: 22,
                username: "alice".to_owned(),
                protocol: Default::default(),
                serial_config: None,
                charset: None,
                group: Some(r"Ops\DB// Team /./..".to_owned()),
                auth_method: Default::default(),
                managed_ssh_key_id: None,
                tags: Vec::new(),
                host_chain: None,
                password_identity_id: None,
                transport: Default::default(),
                proxy: None,
            },
            false,
        )
        .expect("grouped saved-host draft");
        let host = SavedHost::from_draft(draft, 10).expect("grouped saved host");

        assert_eq!(
            host.group_path()
                .expect("valid group path")
                .expect("group path")
                .as_str(),
            r"Ops\DB/ Team /./.."
        );
    }

    #[test]
    fn create_vault_update_replaces_and_clears_saved_group_path() {
        let host = SavedHost::from_draft(
            super::create_vault_draft(
                SavedHostDraftRequest {
                    label: Some("Grouped update".to_owned()),
                    hostname: "update-group.example.test".to_owned(),
                    port: 22,
                    username: "alice".to_owned(),
                    protocol: Default::default(),
                    serial_config: None,
                    charset: None,
                    group: Some("Initial/Group".to_owned()),
                    auth_method: Default::default(),
                    managed_ssh_key_id: None,
                    tags: Vec::new(),
                    host_chain: None,
                    password_identity_id: None,
                    transport: Default::default(),
                    proxy: None,
                },
                false,
            )
            .expect("initial grouped draft"),
            10,
        )
        .expect("initial grouped host");
        let replaced = host
            .apply_update(
                super::create_vault_update(
                    SavedHostDraftRequest {
                        label: Some(host.label.clone()),
                        hostname: host.hostname.clone(),
                        port: u32::from(host.port),
                        username: host.username.clone(),
                        protocol: Default::default(),
                        serial_config: None,
                        charset: None,
                        group: Some(r"Next// Ops\Prod /./..".to_owned()),
                        auth_method: Default::default(),
                        managed_ssh_key_id: None,
                        tags: Vec::new(),
                        host_chain: None,
                        password_identity_id: None,
                        transport: Default::default(),
                        proxy: None,
                    },
                    false,
                )
                .expect("replacement group update"),
                20,
            )
            .expect("replace group path");

        assert_eq!(
            replaced
                .group_path()
                .expect("valid replacement group path")
                .expect("replacement group path")
                .as_str(),
            r"Next/ Ops\Prod /./.."
        );

        let cleared = replaced
            .apply_update(
                super::create_vault_update(
                    SavedHostDraftRequest {
                        label: Some(replaced.label.clone()),
                        hostname: replaced.hostname.clone(),
                        port: u32::from(replaced.port),
                        username: replaced.username.clone(),
                        protocol: Default::default(),
                        serial_config: None,
                        charset: None,
                        group: None,
                        auth_method: Default::default(),
                        managed_ssh_key_id: None,
                        tags: Vec::new(),
                        host_chain: None,
                        password_identity_id: None,
                        transport: Default::default(),
                        proxy: None,
                    },
                    false,
                )
                .expect("clear group update"),
                30,
            )
            .expect("clear group path");

        assert_eq!(cleared.group_path(), Ok(None));
    }

    #[test]
    fn saved_host_draft_request_rejects_non_string_group_json() {
        for group in [json!(7), json!({ "path": "Ops" })] {
            let request: Result<SavedHostDraftRequest, _> = serde_json::from_value(json!({
                "hostname": "invalid-group.example.test",
                "port": 22,
                "username": "alice",
                "group": group
            }));

            assert!(request.is_err());
        }

        let root_request: SavedHostDraftRequest = serde_json::from_value(json!({
            "hostname": "root-group.example.test",
            "port": 22,
            "username": "alice",
            "group": null
        }))
        .expect("null group request");
        assert!(root_request.group.is_none());

        let empty_group = super::create_vault_draft(
            SavedHostDraftRequest {
                label: None,
                hostname: "empty-group.example.test".to_owned(),
                port: 22,
                username: "alice".to_owned(),
                protocol: Default::default(),
                serial_config: None,
                charset: None,
                group: Some(String::new()),
                auth_method: Default::default(),
                managed_ssh_key_id: None,
                tags: Vec::new(),
                host_chain: None,
                password_identity_id: None,
                transport: Default::default(),
                proxy: None,
            },
            false,
        );
        assert!(empty_group.is_err());
    }

    #[test]
    fn saved_host_draft_request_accepts_typed_parity_fields_and_rejects_unknown_fields() {
        let request: SavedHostDraftRequest = serde_json::from_value(json!({
            "hostname": "typed.example.test",
            "port": 22,
            "username": "alice",
            "authMethod": "certificate",
            "managedSshKeyId": "managed-certificate",
            "tags": ["production", "database"],
            "hostChain": { "hostIds": ["nearest", "furthest"] }
        }))
        .expect("typed saved-host request");
        assert!(matches!(
            request.auth_method,
            super::SavedHostAuthenticationMethodRequest::Certificate
        ));
        assert_eq!(
            request.managed_ssh_key_id.as_deref(),
            Some("managed-certificate")
        );
        assert_eq!(request.tags, ["production", "database"]);
        assert_eq!(
            request.host_chain.expect("typed host chain").host_ids,
            ["nearest", "furthest"]
        );
        assert_eq!(request.protocol, super::SavedHostProtocolRequest::Ssh);

        let telnet: SavedHostDraftRequest = serde_json::from_value(json!({
            "hostname": "console.example.test",
            "port": 23,
            "username": "console-user",
            "protocol": "telnet"
        }))
        .expect("strict Telnet protocol request");
        assert_eq!(telnet.protocol, super::SavedHostProtocolRequest::Telnet);
        let serial: SavedHostDraftRequest = serde_json::from_value(json!({
            "hostname": "COM9",
            "port": 115200,
            "username": "",
            "protocol": "serial"
        }))
        .expect("strict Serial protocol request");
        assert_eq!(serial.protocol, super::SavedHostProtocolRequest::Serial);
        for invalid_protocol in [json!("TELNET"), json!("mosh"), json!(7)] {
            let invalid: Result<SavedHostDraftRequest, _> = serde_json::from_value(json!({
                "hostname": "console.example.test",
                "port": 23,
                "username": "console-user",
                "protocol": invalid_protocol
            }));
            assert!(invalid.is_err());
        }

        let unknown: Result<SavedHostDraftRequest, _> = serde_json::from_value(json!({
            "hostname": "typed.example.test",
            "port": 22,
            "username": "alice",
            "plaintextPassword": "must-never-be-accepted"
        }));
        assert!(unknown.is_err());

        let malformed_chain: Result<SavedHostDraftRequest, _> = serde_json::from_value(json!({
            "hostname": "typed.example.test",
            "port": 22,
            "username": "alice",
            "hostChain": { "hostIds": ["nearest"], "extra": true }
        }));
        assert!(malformed_chain.is_err());
    }

    #[tokio::test]
    async fn saved_serial_crud_round_trips_complete_config_without_credentials() {
        let directory = tempfile::tempdir().expect("temporary Vault");
        let (state, _controller) = desktop_state_with_memory_credentials(directory.path());

        let mut initial_config = netcatty_vault::SavedSerialConfig::new(r"\\.\COM 42", 921_600)
            .expect("initial Serial config");
        initial_config.data_bits = netcatty_vault::SavedSerialDataBits::Seven;
        initial_config.stop_bits = netcatty_vault::SavedSerialStopBits::Two;
        initial_config.parity = netcatty_vault::SavedSerialParity::Even;
        initial_config.flow_control = netcatty_vault::SavedSerialFlowControl::XonXoff;
        initial_config.local_echo = true;
        initial_config.line_mode = true;
        initial_config.backspace_behavior =
            Some(netcatty_vault::SavedSerialBackspaceBehavior::CtrlH);

        let created = super::create_saved_host_inner(
            &state,
            "saved-serial-crud-window",
            CreateSavedHostRequest {
                draft: SavedHostDraftRequest {
                    label: Some("Bench serial".to_owned()),
                    hostname: initial_config.path.clone(),
                    port: initial_config.baud_rate,
                    username: String::new(),
                    protocol: super::SavedHostProtocolRequest::Serial,
                    serial_config: Some(initial_config.clone()),
                    charset: Some(" gbk ".to_owned()),
                    group: Some("Lab/Devices".to_owned()),
                    auth_method: Default::default(),
                    managed_ssh_key_id: None,
                    tags: vec!["hardware".to_owned(), "bench".to_owned()],
                    host_chain: None,
                    password_identity_id: None,
                    transport: Default::default(),
                    proxy: None,
                },
                staged_credential_reference: None,
            },
        )
        .await
        .expect("create Saved Serial host");

        assert_eq!(created.protocol, "serial");
        assert_eq!(created.hostname, initial_config.path);
        assert_eq!(created.port, 921_600);
        assert!(created.username.is_empty());
        assert_eq!(created.group.as_deref(), Some("Lab/Devices"));
        assert_eq!(created.tags, ["hardware", "bench"]);
        assert_eq!(created.charset.as_deref(), Some("gbk"));
        assert_eq!(created.serial_config.as_ref(), Some(&initial_config));
        assert_eq!(
            created.effective_serial_config.as_ref(),
            Some(&initial_config)
        );
        assert!(!created.has_saved_credential);
        assert!(!created.has_saved_host_credential);
        assert!(created.password_identity.is_none());
        assert!(created.proxy.is_none());
        assert!(created.host_chain.is_none());
        assert!(created.managed_ssh_key_id.is_none());

        let mut updated_config = netcatty_vault::SavedSerialConfig::new("COM 99", 115_200)
            .expect("updated Serial config");
        updated_config.data_bits = netcatty_vault::SavedSerialDataBits::Eight;
        updated_config.stop_bits = netcatty_vault::SavedSerialStopBits::One;
        updated_config.parity = netcatty_vault::SavedSerialParity::Odd;
        updated_config.flow_control = netcatty_vault::SavedSerialFlowControl::RtsCts;

        let updated = super::update_saved_host_inner(
            &state,
            "saved-serial-crud-window",
            UpdateSavedHostRequest {
                id: created.id.clone(),
                expected_revision: created.revision,
                draft: SavedHostDraftRequest {
                    label: Some("Rack serial".to_owned()),
                    hostname: updated_config.path.clone(),
                    port: updated_config.baud_rate,
                    username: String::new(),
                    protocol: super::SavedHostProtocolRequest::Serial,
                    serial_config: Some(updated_config.clone()),
                    charset: Some("windows-1252".to_owned()),
                    group: None,
                    auth_method: Default::default(),
                    managed_ssh_key_id: None,
                    tags: vec!["rack".to_owned()],
                    host_chain: None,
                    password_identity_id: None,
                    transport: Default::default(),
                    proxy: None,
                },
                credential_mutation: SavedHostCredentialMutation::Keep,
            },
        )
        .await
        .expect("update Saved Serial host");

        assert!(updated.revision > created.revision);
        assert_eq!(updated.label, "Rack serial");
        assert_eq!(updated.hostname, updated_config.path);
        assert_eq!(updated.port, 115_200);
        assert_eq!(updated.serial_config.as_ref(), Some(&updated_config));
        let mut expected_effective_config = updated_config.clone();
        expected_effective_config.backspace_behavior =
            Some(netcatty_vault::SavedSerialBackspaceBehavior::Default);
        assert_eq!(
            updated.effective_serial_config.as_ref(),
            Some(&expected_effective_config)
        );
        assert_eq!(updated.charset.as_deref(), Some("windows-1252"));
        assert!(updated.group.is_none());
        assert_eq!(updated.tags, ["rack"]);
        assert!(!updated.has_saved_credential);
        assert!(!updated.has_saved_host_credential);

        let persisted = state
            .saved_hosts
            .graph()
            .expect("persisted Saved Serial graph");
        let durable = persisted
            .hosts()
            .iter()
            .find(|host| host.id.as_str() == updated.id)
            .expect("persisted Saved Serial host");
        assert_eq!(
            durable.serial_config().expect("durable Serial config"),
            Some(updated_config)
        );

        super::delete_saved_host_inner(
            &state,
            super::DeleteSavedHostRequest {
                id: updated.id,
                expected_revision: updated.revision,
            },
        )
        .await
        .expect("delete Saved Serial host");
        assert!(
            state
                .saved_hosts
                .graph()
                .expect("post-delete Saved Serial graph")
                .hosts()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn saved_serial_prepare_projects_group_charset_backspace_and_log_metadata() {
        let directory = tempfile::tempdir().expect("temporary Vault");
        let (state, _controller) = desktop_state_with_memory_credentials(directory.path());

        let mut saved_config =
            netcatty_vault::SavedSerialConfig::new("COM 77", 230_400).expect("Saved Serial config");
        saved_config.data_bits = netcatty_vault::SavedSerialDataBits::Seven;
        saved_config.stop_bits = netcatty_vault::SavedSerialStopBits::Two;
        saved_config.parity = netcatty_vault::SavedSerialParity::Even;
        saved_config.flow_control = netcatty_vault::SavedSerialFlowControl::RtsCts;
        saved_config.local_echo = true;
        saved_config.line_mode = true;
        assert!(saved_config.backspace_behavior.is_none());

        let mut draft = netcatty_vault::SavedHostDraft::serial(saved_config.clone())
            .expect("Saved Serial draft")
            .with_group_path(
                netcatty_vault::SavedGroupPath::new("Hardware/Console").expect("Serial group path"),
            );
        draft.label = Some("Core switch console".to_owned());
        let host = SavedHost::from_draft(draft, 10).expect("Saved Serial host");
        let host_id = host.id.clone();

        let group = netcatty_vault::SavedGroupConfig::from_parts(
            netcatty_vault::SavedGroupId::from_opaque("saved-serial-group")
                .expect("Serial group ID"),
            1,
            netcatty_vault::SavedGroupPath::new("Hardware/Console").expect("Serial group path"),
            netcatty_vault::SavedGroupDefaults {
                charset: netcatty_vault::SavedGroupOverride::Set(
                    netcatty_vault::SavedGroupSingleLineText::new("GBK").expect("group charset"),
                ),
                backspace_behavior: netcatty_vault::SavedGroupOverride::Set(
                    netcatty_vault::SavedGroupBackspaceBehavior::CtrlH,
                ),
                ..netcatty_vault::SavedGroupDefaults::default()
            },
            10,
            10,
        )
        .expect("Saved Serial group");
        let graph = publish_test_chain_graph(
            &state,
            SavedVaultGraph::new_with_proxy_profiles(
                vec![host],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                vec![group],
            ),
        );
        let durable = graph
            .hosts()
            .iter()
            .find(|host| host.id == host_id)
            .expect("persisted Saved Serial host");
        let size: super::SerialTerminalSize = serde_json::from_value(json!({
            "columns": 132,
            "rows": 43,
            "pixelWidth": 1280,
            "pixelHeight": 720
        }))
        .expect("Serial terminal size");

        let prepared = super::prepare_saved_host_serial_session(
            &state,
            durable.id.clone(),
            durable.revision,
            size,
        )
        .await
        .expect("prepare Saved Serial session");
        let runtime = &prepared.config;
        assert_eq!(runtime.serial().path, saved_config.path);
        assert_eq!(runtime.serial().baud_rate, 230_400);
        assert_eq!(
            runtime.serial().data_bits,
            netcatty_serial::SerialDataBits::Seven
        );
        assert_eq!(
            runtime.serial().stop_bits,
            netcatty_serial::SerialStopBits::Two
        );
        assert_eq!(runtime.serial().parity, netcatty_serial::SerialParity::Even);
        assert_eq!(
            runtime.serial().flow_control,
            netcatty_serial::SerialFlowControl::RtsCts
        );
        assert!(runtime.serial().local_echo);
        assert!(runtime.serial().line_mode);
        assert_eq!(
            runtime.serial().backspace_behavior,
            netcatty_serial::SerialBackspaceBehavior::CtrlH
        );
        assert_eq!(runtime.charset().normalized_label(), "gb18030");
        assert_eq!(runtime.window_size().columns(), 132);
        assert_eq!(runtime.window_size().rows(), 43);

        let log = prepared
            .connection_log
            .into_started_log("123e4567-e89b-42d3-a456-426614174000", 100)
            .expect("Saved Serial connection log");
        assert_eq!(log.host_id, durable.id.as_str());
        assert_eq!(log.host_label, "Core switch console");
        assert_eq!(log.hostname, saved_config.path);
        assert_eq!(
            log.protocol,
            netcatty_vault::SavedConnectionLogProtocol::Serial
        );
        assert_eq!(log.username, log.local_username);

        let stale = super::prepare_saved_host_serial_session(
            &state,
            durable.id.clone(),
            durable.revision + 1,
            size,
        )
        .await
        .err()
        .expect("stale Saved Serial revision must fail");
        assert!(stale.starts_with(super::SAVED_HOST_REVISION_CONFLICT));
    }

    #[test]
    fn saved_telnet_update_removes_stale_legacy_endpoint_overrides() {
        let legacy = SavedHost::from_draft(
            netcatty_vault::SavedHostDraft::telnet("console.example.test", "old-base-user")
                .with_compatibility_field("telnetPort", json!(9923))
                .expect("legacy Telnet port")
                .with_compatibility_field("telnetUsername", json!("old-override-user"))
                .expect("legacy Telnet username"),
            10,
        )
        .expect("legacy Telnet host");
        let update = super::create_vault_update(
            SavedHostDraftRequest {
                label: Some(legacy.label.clone()),
                hostname: legacy.hostname.clone(),
                port: 2323,
                username: "new-console-user".to_owned(),
                protocol: super::SavedHostProtocolRequest::Telnet,
                serial_config: None,
                charset: None,
                group: None,
                auth_method: Default::default(),
                managed_ssh_key_id: None,
                tags: Vec::new(),
                host_chain: None,
                password_identity_id: None,
                transport: Default::default(),
                proxy: None,
            },
            false,
        )
        .expect("canonical Telnet update");
        let updated = legacy
            .apply_update(update, 20)
            .expect("updated Telnet host");
        assert_eq!(updated.port, 2323);
        assert_eq!(updated.username, "new-console-user");
        assert!(!updated.compatibility_fields().contains_key("telnetPort"));
        assert!(
            !updated
                .compatibility_fields()
                .contains_key("telnetUsername")
        );
    }

    #[test]
    fn saved_host_draft_and_update_round_trip_tags_and_jump_chain() {
        let draft = super::create_vault_draft(
            SavedHostDraftRequest {
                label: Some("Tagged chain target".to_owned()),
                hostname: "target.example.test".to_owned(),
                port: 2222,
                username: "alice".to_owned(),
                protocol: Default::default(),
                serial_config: None,
                charset: None,
                group: Some("Production/Databases".to_owned()),
                auth_method: Default::default(),
                managed_ssh_key_id: None,
                tags: vec!["production".to_owned(), "database".to_owned()],
                host_chain: Some(super::SavedHostChainRequest {
                    host_ids: vec!["nearest-jump".to_owned(), "furthest-jump".to_owned()],
                }),
                password_identity_id: None,
                transport: Default::default(),
                proxy: None,
            },
            false,
        )
        .expect("tagged chain draft");
        let host = SavedHost::from_draft(draft, 10).expect("tagged chain host");
        let view = super::saved_host_view(&host);

        assert_eq!(view.tags, ["production", "database"]);
        assert_eq!(
            view.host_chain.expect("renderer jump chain").host_ids,
            ["nearest-jump", "furthest-jump"]
        );

        let update = super::create_vault_update(
            SavedHostDraftRequest {
                label: Some(host.label.clone()),
                hostname: host.hostname.clone(),
                port: u32::from(host.port),
                username: host.username.clone(),
                protocol: Default::default(),
                serial_config: None,
                charset: None,
                group: host
                    .group_path()
                    .expect("group path")
                    .map(|path| path.as_str().to_owned()),
                auth_method: Default::default(),
                managed_ssh_key_id: None,
                tags: Vec::new(),
                host_chain: None,
                password_identity_id: None,
                transport: Default::default(),
                proxy: None,
            },
            false,
        )
        .expect("clear tags and chain update");
        let cleared = host
            .apply_update(update, 20)
            .expect("cleared host metadata");
        let cleared_view = super::saved_host_view(&cleared);
        assert!(cleared_view.tags.is_empty());
        assert!(cleared_view.host_chain.is_none());
    }

    #[test]
    fn saved_host_view_separates_effective_identity_and_host_credential_hints() {
        let identity_id = "renderer-password-identity";
        let identity = test_password_identity(identity_id, "identity-user", true);
        let host = test_password_identity_host("renderer-password-host", Some(identity_id), false);
        let graph = SavedVaultGraph::new_with_password_identities(
            vec![host.clone()],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![identity],
        );

        let view = super::saved_host_view_from_graph(&host, &graph).expect("saved host view");
        assert!(view.has_saved_credential);
        assert!(!view.has_saved_host_credential);
        assert!(view.proxy.is_none());
        let metadata = view.password_identity.expect("renderer-safe identity");
        assert_eq!(metadata.id, identity_id);
        assert_eq!(metadata.label, "Shared password identity");
        assert_eq!(metadata.username, "identity-user");
        assert!(metadata.has_saved_credential);

        let encoded = serde_json::to_string(
            &super::saved_host_view_from_graph(&host, &graph).expect("saved host view"),
        )
        .expect("saved host view JSON");
        assert!(encoded.contains("\"hasSavedCredential\":true"));
        assert!(encoded.contains("\"hasSavedHostCredential\":false"));
        assert!(encoded.contains("\"passwordIdentity\":{"));
        for forbidden in [
            "os:v1:",
            "credentialReference",
            "credentialId",
            "\"password\":",
        ] {
            assert!(!encoded.contains(forbidden));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn malformed_inline_proxy_fails_closed_for_view_list_and_keep_update() {
        let host = test_malformed_inline_proxy_host("malformed-inline-proxy-host");
        let graph = SavedVaultGraph::new_with_proxy_profiles(
            vec![host.clone()],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        let view_error = super::saved_host_view_from_graph(&host, &graph)
            .expect_err("malformed inline proxy must fail the host renderer");
        assert!(
            view_error
                .starts_with(super::saved_host_proxy_catalog::SAVED_HOST_PROXY_REPAIR_REQUIRED)
        );
        assert!(!view_error.contains("malformed-inline-sentinel"));

        let list_error = super::saved_host_views_from_graph(&graph)
            .expect_err("malformed inline proxy must fail the host list renderer");
        assert!(
            list_error
                .starts_with(super::saved_host_proxy_catalog::SAVED_HOST_PROXY_REPAIR_REQUIRED)
        );
        assert!(!list_error.contains("malformed-inline-sentinel"));

        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, controller) = desktop_state_with_memory_credentials(directory.path());
        seed_legacy_malformed_inline_proxy_snapshot(directory.path(), &host);
        let before = state
            .saved_hosts
            .graph()
            .expect("legacy malformed proxy graph");
        controller.clear_operation_log();

        let update_error = update_saved_host_inner(
            &state,
            "malformed-inline-window",
            UpdateSavedHostRequest {
                id: host.id.as_str().to_owned(),
                expected_revision: host.revision,
                draft: SavedHostDraftRequest {
                    label: Some(host.label.clone()),
                    hostname: host.hostname.clone(),
                    port: u32::from(host.port),
                    username: host.username.clone(),
                    protocol: Default::default(),
                    serial_config: None,
                    charset: None,
                    group: None,
                    auth_method: Default::default(),
                    managed_ssh_key_id: None,
                    tags: Vec::new(),
                    host_chain: None,
                    password_identity_id: None,
                    transport: Default::default(),
                    proxy: None,
                },
                credential_mutation: SavedHostCredentialMutation::Keep,
            },
        )
        .await
        .expect_err("proxy=None must validate the current inline proxy through Keep/Keep");
        assert!(
            update_error
                .starts_with(super::saved_host_proxy_catalog::SAVED_HOST_PROXY_REPAIR_REQUIRED)
        );
        assert!(!update_error.contains("malformed-inline-sentinel"));
        assert!(controller.operation_log().is_empty());
        assert_eq!(
            state.saved_hosts.graph().expect("unchanged proxy graph"),
            before
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saved_host_create_and_update_write_and_clear_password_identity_relationship() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, controller) = desktop_state_with_memory_credentials(directory.path());
        let identity_id = "crud-password-identity";
        publish_test_password_identity_graph(
            &state,
            None,
            test_password_identity(identity_id, "shared-user", true),
        );
        controller.clear_operation_log();

        let created = super::create_saved_host_inner(
            &state,
            "crud-window",
            CreateSavedHostRequest {
                draft: SavedHostDraftRequest {
                    label: Some("Identity host".to_owned()),
                    hostname: "crud.example.test".to_owned(),
                    port: 22,
                    username: "host-user".to_owned(),
                    protocol: Default::default(),
                    serial_config: None,
                    charset: None,
                    group: None,
                    auth_method: Default::default(),
                    managed_ssh_key_id: None,
                    tags: Vec::new(),
                    host_chain: None,
                    password_identity_id: Some(identity_id.to_owned()),
                    transport: Default::default(),
                    proxy: None,
                },
                staged_credential_reference: None,
            },
        )
        .await
        .expect("create identity-bound host");
        assert!(created.has_saved_credential);
        assert!(!created.has_saved_host_credential);
        assert_eq!(
            created
                .password_identity
                .as_ref()
                .expect("created identity metadata")
                .id,
            identity_id
        );
        let created_host = state
            .saved_hosts
            .get(&SavedHostId::from_opaque(created.id.clone()).expect("created host ID"))
            .expect("created host lookup")
            .expect("created host");
        assert_eq!(
            created_host.compatibility_fields()["identityId"],
            identity_id
        );

        let cleared = update_saved_host_inner(
            &state,
            "crud-window",
            UpdateSavedHostRequest {
                id: created.id.clone(),
                expected_revision: created.revision,
                draft: SavedHostDraftRequest {
                    label: Some(created.label.clone()),
                    hostname: created.hostname.clone(),
                    port: u32::from(created.port),
                    username: created.username.clone(),
                    protocol: Default::default(),
                    serial_config: None,
                    charset: None,
                    group: None,
                    auth_method: Default::default(),
                    managed_ssh_key_id: None,
                    tags: Vec::new(),
                    host_chain: None,
                    password_identity_id: None,
                    transport: Default::default(),
                    proxy: None,
                },
                credential_mutation: SavedHostCredentialMutation::Keep,
            },
        )
        .await
        .expect("clear password identity relationship");
        assert!(!cleared.has_saved_credential);
        assert!(!cleared.has_saved_host_credential);
        assert!(cleared.password_identity.is_none());
        let cleared_host = state
            .saved_hosts
            .get(&SavedHostId::from_opaque(cleared.id.clone()).expect("cleared host ID"))
            .expect("cleared host lookup")
            .expect("cleared host");
        assert!(
            !cleared_host
                .compatibility_fields()
                .contains_key("identityId")
        );

        let rebound = update_saved_host_inner(
            &state,
            "crud-window",
            UpdateSavedHostRequest {
                id: cleared.id.clone(),
                expected_revision: cleared.revision,
                draft: SavedHostDraftRequest {
                    label: Some(cleared.label.clone()),
                    hostname: cleared.hostname.clone(),
                    port: u32::from(cleared.port),
                    username: cleared.username.clone(),
                    protocol: Default::default(),
                    serial_config: None,
                    charset: None,
                    group: None,
                    auth_method: Default::default(),
                    managed_ssh_key_id: None,
                    tags: Vec::new(),
                    host_chain: None,
                    password_identity_id: Some(identity_id.to_owned()),
                    transport: Default::default(),
                    proxy: None,
                },
                credential_mutation: SavedHostCredentialMutation::Keep,
            },
        )
        .await
        .expect("restore password identity relationship");
        assert!(rebound.has_saved_credential);
        assert!(!rebound.has_saved_host_credential);
        assert_eq!(
            rebound
                .password_identity
                .expect("rebound identity metadata")
                .id,
            identity_id
        );
        assert!(controller.operation_log().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn invalid_password_identity_relationship_fails_before_consuming_host_password() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, controller) = desktop_state_with_memory_credentials(directory.path());
        let owner = "invalid-identity-window";
        let secret_marker = "invalid-identity-staged-secret";
        let staged = state
            .ephemeral_credentials
            .insert(owner, test_secret(secret_marker))
            .await
            .expect("stage host password");
        controller.clear_operation_log();

        let missing_id = "missing-password-identity";
        let error = super::create_saved_host_inner(
            &state,
            owner,
            CreateSavedHostRequest {
                draft: SavedHostDraftRequest {
                    label: Some("Invalid identity host".to_owned()),
                    hostname: "invalid-identity.example.test".to_owned(),
                    port: 22,
                    username: "host-user".to_owned(),
                    protocol: Default::default(),
                    serial_config: None,
                    charset: None,
                    group: None,
                    auth_method: Default::default(),
                    managed_ssh_key_id: None,
                    tags: Vec::new(),
                    host_chain: None,
                    password_identity_id: Some(missing_id.to_owned()),
                    transport: Default::default(),
                    proxy: None,
                },
                staged_credential_reference: Some(staged.clone()),
            },
        )
        .await
        .expect_err("missing identity must fail closed");
        assert!(
            error.starts_with(super::saved_host_auth_guard::SAVED_HOST_AUTH_RELATIONSHIP_INVALID)
        );
        assert!(!error.contains(missing_id));
        assert!(!error.contains(secret_marker));
        assert!(state.saved_hosts.list().expect("saved hosts").is_empty());
        assert!(controller.operation_log().is_empty());
        let retained = state
            .ephemeral_credentials
            .take(owner, &staged)
            .await
            .expect("invalid relationship must not consume staged password");
        assert_eq!(
            retained.as_utf8().expect("UTF-8 staged password"),
            secret_marker
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saved_telnet_crud_and_protocol_switches_keep_password_accounts_isolated() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, _) = desktop_state_with_memory_credentials(directory.path());
        let owner = "saved-telnet-crud-window";
        let created = create_test_host_with_password(
            &state,
            owner,
            "SavedTelnetIsolation",
            "ssh-password-private",
        )
        .await;
        let host_id = SavedHostId::from_opaque(created.id.clone()).expect("saved host ID");
        let ssh_reference = StoredCredentialReference::for_saved_host(host_id.as_str())
            .expect("SSH credential reference");
        let telnet_reference = StoredCredentialReference::for_saved_host_telnet(host_id.as_str())
            .expect("Telnet credential reference");

        let staged_telnet = state
            .ephemeral_credentials
            .insert(owner, test_secret("telnet-password-private"))
            .await
            .expect("stage Telnet password");
        let telnet = update_saved_host_inner(
            &state,
            owner,
            UpdateSavedHostRequest {
                id: created.id.clone(),
                expected_revision: created.revision,
                draft: SavedHostDraftRequest {
                    label: Some(created.label.clone()),
                    hostname: created.hostname.clone(),
                    port: 23,
                    username: "console-user".to_owned(),
                    protocol: super::SavedHostProtocolRequest::Telnet,
                    serial_config: None,
                    charset: None,
                    group: None,
                    auth_method: Default::default(),
                    managed_ssh_key_id: None,
                    tags: Vec::new(),
                    host_chain: None,
                    password_identity_id: None,
                    transport: Default::default(),
                    proxy: None,
                },
                credential_mutation: SavedHostCredentialMutation::Replace {
                    staged_credential_reference: staged_telnet,
                },
            },
        )
        .await
        .expect("switch host to Telnet with an isolated password");
        assert_eq!(telnet.protocol, "telnet");
        assert!(telnet.has_saved_credential);
        assert!(telnet.has_saved_host_credential);
        assert_stored_secret_with_kind(
            &state.persistent_credentials,
            &ssh_reference,
            CredentialKind::SshPassword,
            "ssh-password-private",
        )
        .await;
        assert_stored_secret_with_kind(
            &state.persistent_credentials,
            &telnet_reference,
            CredentialKind::TelnetPassword,
            "telnet-password-private",
        )
        .await;

        let ssh_again = update_saved_host_inner(
            &state,
            owner,
            UpdateSavedHostRequest {
                id: telnet.id.clone(),
                expected_revision: telnet.revision,
                draft: SavedHostDraftRequest {
                    label: Some(telnet.label.clone()),
                    hostname: telnet.hostname.clone(),
                    port: 22,
                    username: "ssh-user".to_owned(),
                    protocol: super::SavedHostProtocolRequest::Ssh,
                    serial_config: None,
                    charset: None,
                    group: None,
                    auth_method: Default::default(),
                    managed_ssh_key_id: None,
                    tags: Vec::new(),
                    host_chain: None,
                    password_identity_id: None,
                    transport: Default::default(),
                    proxy: None,
                },
                credential_mutation: SavedHostCredentialMutation::Keep,
            },
        )
        .await
        .expect("reactivate the existing SSH password without copying Telnet");
        assert_eq!(ssh_again.protocol, "ssh");
        assert!(ssh_again.has_saved_host_credential);

        let telnet_removed = update_saved_host_inner(
            &state,
            owner,
            UpdateSavedHostRequest {
                id: ssh_again.id.clone(),
                expected_revision: ssh_again.revision,
                draft: SavedHostDraftRequest {
                    label: Some(ssh_again.label.clone()),
                    hostname: ssh_again.hostname.clone(),
                    port: 23,
                    username: "console-user".to_owned(),
                    protocol: super::SavedHostProtocolRequest::Telnet,
                    serial_config: None,
                    charset: None,
                    group: None,
                    auth_method: Default::default(),
                    managed_ssh_key_id: None,
                    tags: Vec::new(),
                    host_chain: None,
                    password_identity_id: None,
                    transport: Default::default(),
                    proxy: None,
                },
                credential_mutation: SavedHostCredentialMutation::Remove,
            },
        )
        .await
        .expect("remove only the Telnet password");
        assert!(!telnet_removed.has_saved_host_credential);
        assert_stored_secret_with_kind(
            &state.persistent_credentials,
            &ssh_reference,
            CredentialKind::SshPassword,
            "ssh-password-private",
        )
        .await;
        assert_credential_missing_with_kind(
            &state.persistent_credentials,
            &telnet_reference,
            CredentialKind::TelnetPassword,
        )
        .await;

        super::delete_saved_host_inner(
            &state,
            super::DeleteSavedHostRequest {
                id: telnet_removed.id,
                expected_revision: telnet_removed.revision,
            },
        )
        .await
        .expect("delete host and every deterministic password account");
        assert_credential_missing_with_kind(
            &state.persistent_credentials,
            &ssh_reference,
            CredentialKind::SshPassword,
        )
        .await;
        assert_credential_missing_with_kind(
            &state.persistent_credentials,
            &telnet_reference,
            CredentialKind::TelnetPassword,
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saved_telnet_crud_maps_password_identity_to_telnet_metadata_and_safe_view() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, controller) = desktop_state_with_memory_credentials(directory.path());
        let identity_id = "saved-telnet-password-identity";
        publish_test_password_identity_graph(
            &state,
            None,
            test_password_identity(identity_id, "identity-console-user", true),
        );
        controller.clear_operation_log();

        let created = super::create_saved_host_inner(
            &state,
            "saved-telnet-identity-window",
            CreateSavedHostRequest {
                draft: SavedHostDraftRequest {
                    label: Some("Identity Telnet host".to_owned()),
                    hostname: "identity-console.example.test".to_owned(),
                    port: 2323,
                    username: "manual-console-user".to_owned(),
                    protocol: super::SavedHostProtocolRequest::Telnet,
                    serial_config: None,
                    charset: None,
                    group: None,
                    auth_method: Default::default(),
                    managed_ssh_key_id: None,
                    tags: vec!["console".to_owned()],
                    host_chain: None,
                    password_identity_id: Some(identity_id.to_owned()),
                    transport: Default::default(),
                    proxy: None,
                },
                staged_credential_reference: None,
            },
        )
        .await
        .expect("create identity-bound Telnet host");
        assert_eq!(created.protocol, "telnet");
        assert!(created.has_saved_credential);
        assert!(!created.has_saved_host_credential);
        let identity = created
            .password_identity
            .as_ref()
            .expect("renderer-safe Telnet identity metadata");
        assert_eq!(identity.id, identity_id);
        assert_eq!(identity.username, "identity-console-user");
        assert!(identity.has_saved_credential);

        let durable = state
            .saved_hosts
            .get(&SavedHostId::from_opaque(created.id).expect("created Telnet host ID"))
            .expect("load Telnet host")
            .expect("created Telnet host");
        assert!(durable.protocol.is_telnet());
        assert_eq!(durable.port, 2323);
        assert_eq!(
            durable.compatibility_fields()["telnetIdentityId"],
            identity_id
        );
        assert!(!durable.compatibility_fields().contains_key("identityId"));
        assert!(controller.operation_log().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saved_host_create_restart_before_vault_rolls_back_password_and_partial_host() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, _) = desktop_state_with_memory_credentials(&current_vault);
        let persistent_credentials = state.persistent_credentials.clone();
        let password = "create-crash-password-sentinel";
        let snapshot = super::confirm_current_saved_host_snapshot(&state)
            .await
            .expect("before snapshot");
        let draft = super::create_vault_draft(
            SavedHostDraftRequest {
                label: Some("CreateCrash".to_owned()),
                hostname: "create-crash.example.test".to_owned(),
                port: 22,
                username: "create-user".to_owned(),
                protocol: Default::default(),
                serial_config: None,
                charset: None,
                group: None,
                auth_method: Default::default(),
                managed_ssh_key_id: None,
                tags: Vec::new(),
                host_chain: None,
                password_identity_id: None,
                transport: Default::default(),
                proxy: None,
            },
            true,
        )
        .expect("complete create draft");
        let host = SavedHost::from_draft(draft, 10).expect("planned host");
        let target_graph =
            super::saved_host_graph_with_created_host(snapshot.graph().clone(), host.clone())
                .expect("create target graph");
        let plan = super::plan_saved_host_graph(&state, snapshot.revision().clone(), &target_graph)
            .await
            .expect("create graph plan");
        let (active, target, backup, previous) =
            activate_test_saved_host_transaction(&state, &plan, &host.id).await;
        assert_eq!(previous, LegacyPreviousCredentialState::Absent);
        state
            .persistent_credentials
            .upsert(&target, CredentialKind::SshPassword, test_secret(password))
            .await
            .expect("write create target");
        assert_transaction_journal_excludes(
            state.legacy_import_transaction_root.as_ref(),
            &[password],
        );

        drop(active);
        drop(state);
        let restarted = restarted_desktop_state(&current_vault, &persistent_credentials);
        recover_pending_legacy_import(&restarted)
            .await
            .expect("recover interrupted create");

        assert!(
            restarted
                .saved_hosts
                .graph()
                .expect("recovered create graph")
                .hosts()
                .is_empty()
        );
        assert_credential_missing(&persistent_credentials, &target).await;
        assert_credential_missing(&persistent_credentials, &backup).await;
        assert!(
            load_legacy_import_transaction(&restarted)
                .await
                .expect("load create journal after recovery")
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saved_host_remove_restart_before_vault_restores_old_password_and_graph() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, _) = desktop_state_with_memory_credentials(&current_vault);
        let persistent_credentials = state.persistent_credentials.clone();
        let old_password = "remove-crash-old-password-sentinel";
        let created = create_test_host_with_password(
            &state,
            "remove-crash-window",
            "RemoveCrash",
            old_password,
        )
        .await;
        let snapshot = super::confirm_current_saved_host_snapshot(&state)
            .await
            .expect("remove before snapshot");
        let id = SavedHostId::from_opaque(created.id).expect("remove host ID");
        let current = snapshot
            .graph()
            .hosts()
            .iter()
            .find(|host| host.id == id)
            .expect("remove current host")
            .clone();
        let update = super::create_vault_update(
            SavedHostDraftRequest {
                label: Some(current.label.clone()),
                hostname: current.hostname.clone(),
                port: u32::from(current.port),
                username: current.username.clone(),
                protocol: Default::default(),
                serial_config: None,
                charset: None,
                group: None,
                auth_method: Default::default(),
                managed_ssh_key_id: None,
                tags: Vec::new(),
                host_chain: None,
                password_identity_id: None,
                transport: Default::default(),
                proxy: None,
            },
            false,
        )
        .expect("remove update");
        let updated = current
            .apply_update(update, 20)
            .expect("remove target host");
        let target_graph =
            super::saved_host_graph_with_updated_host(snapshot.graph().clone(), updated)
                .expect("remove target graph");
        let plan = super::plan_saved_host_graph(&state, snapshot.revision().clone(), &target_graph)
            .await
            .expect("remove graph plan");
        let (active, target, backup, previous) =
            activate_test_saved_host_transaction(&state, &plan, &id).await;
        assert_eq!(previous, LegacyPreviousCredentialState::BackedUp);
        state
            .persistent_credentials
            .delete(&target)
            .await
            .expect("remove target password");

        drop(active);
        drop(state);
        let restarted = restarted_desktop_state(&current_vault, &persistent_credentials);
        recover_pending_legacy_import(&restarted)
            .await
            .expect("recover interrupted remove");

        assert_eq!(
            restarted
                .saved_hosts
                .graph()
                .expect("recovered remove graph"),
            *snapshot.graph()
        );
        assert_stored_secret(&persistent_credentials, &target, old_password).await;
        assert_credential_missing(&persistent_credentials, &backup).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saved_host_replace_restart_after_vault_keeps_new_password_and_full_graph() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, _) = desktop_state_with_memory_credentials(&current_vault);
        let persistent_credentials = state.persistent_credentials.clone();
        let identity_id = "replace-preserved-password-identity";
        publish_test_password_identity_graph(
            &state,
            None,
            test_password_identity(identity_id, "identity-user", false),
        );
        let old_password = "replace-crash-old-password-sentinel";
        let new_password = "replace-crash-new-password-sentinel";
        let created = create_test_host_with_password(
            &state,
            "replace-crash-window",
            "ReplaceCrash",
            old_password,
        )
        .await;
        let snapshot = super::confirm_current_saved_host_snapshot(&state)
            .await
            .expect("replace before snapshot");
        let id = SavedHostId::from_opaque(created.id).expect("replace host ID");
        let current = snapshot
            .graph()
            .hosts()
            .iter()
            .find(|host| host.id == id)
            .expect("replace current host")
            .clone();
        let update = super::create_vault_update(
            SavedHostDraftRequest {
                label: Some("Replaced host".to_owned()),
                hostname: current.hostname.clone(),
                port: u32::from(current.port),
                username: current.username.clone(),
                protocol: Default::default(),
                serial_config: None,
                charset: None,
                group: None,
                auth_method: Default::default(),
                managed_ssh_key_id: None,
                tags: Vec::new(),
                host_chain: None,
                password_identity_id: None,
                transport: Default::default(),
                proxy: None,
            },
            true,
        )
        .expect("replace update");
        let updated = current
            .apply_update(update, 20)
            .expect("replace target host");
        let target_graph =
            super::saved_host_graph_with_updated_host(snapshot.graph().clone(), updated.clone())
                .expect("replace target graph");
        let plan = super::plan_saved_host_graph(&state, snapshot.revision().clone(), &target_graph)
            .await
            .expect("replace graph plan");
        let (active, target, backup, previous) =
            activate_test_saved_host_transaction(&state, &plan, &id).await;
        assert_eq!(previous, LegacyPreviousCredentialState::BackedUp);
        state
            .persistent_credentials
            .upsert(
                &target,
                CredentialKind::SshPassword,
                test_secret(new_password),
            )
            .await
            .expect("write replacement password");
        state
            .saved_hosts
            .commit_planned_graph_replacement(plan, target_graph)
            .expect("publish replacement graph");
        state
            .saved_hosts
            .confirm_current_snapshot_durability()
            .expect("confirm replacement graph durability");
        assert_transaction_journal_excludes(
            state.legacy_import_transaction_root.as_ref(),
            &[old_password, new_password],
        );

        drop(active);
        drop(state);
        let restarted = restarted_desktop_state(&current_vault, &persistent_credentials);
        recover_pending_legacy_import(&restarted)
            .await
            .expect("recover committed replace");

        let recovered = restarted
            .saved_hosts
            .graph()
            .expect("recovered replace graph");
        let recovered_host = recovered
            .hosts()
            .iter()
            .find(|host| host.id == id)
            .expect("replaced host retained");
        assert_eq!(recovered_host.label, "Replaced host");
        assert_eq!(recovered_host.revision, updated.revision);
        assert!(super::has_saved_credential(recovered_host));
        assert_eq!(recovered.password_identities().len(), 1);
        assert_eq!(recovered.password_identities()[0].id.as_str(), identity_id);
        assert_stored_secret(&persistent_credentials, &target, new_password).await;
        assert_credential_missing(&persistent_credentials, &backup).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saved_host_delete_restart_after_vault_keeps_host_and_password_deleted() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, _) = desktop_state_with_memory_credentials(&current_vault);
        let persistent_credentials = state.persistent_credentials.clone();
        let identity_id = "delete-preserved-password-identity";
        publish_test_password_identity_graph(
            &state,
            None,
            test_password_identity(identity_id, "identity-user", false),
        );
        let old_password = "delete-crash-password-sentinel";
        let created = create_test_host_with_password(
            &state,
            "delete-crash-window",
            "DeleteCrash",
            old_password,
        )
        .await;
        let snapshot = super::confirm_current_saved_host_snapshot(&state)
            .await
            .expect("delete before snapshot");
        let id = SavedHostId::from_opaque(created.id).expect("delete host ID");
        let target_graph = super::saved_host_graph_without_host(snapshot.graph().clone(), &id)
            .expect("delete target graph");
        let plan = super::plan_saved_host_graph(&state, snapshot.revision().clone(), &target_graph)
            .await
            .expect("delete graph plan");
        let (active, target, backup, previous) =
            activate_test_saved_host_transaction(&state, &plan, &id).await;
        assert_eq!(previous, LegacyPreviousCredentialState::BackedUp);
        state
            .persistent_credentials
            .delete(&target)
            .await
            .expect("delete host target password");
        state
            .saved_hosts
            .commit_planned_graph_replacement(plan, target_graph)
            .expect("publish host deletion graph");
        state
            .saved_hosts
            .confirm_current_snapshot_durability()
            .expect("confirm host deletion durability");

        drop(active);
        drop(state);
        let restarted = restarted_desktop_state(&current_vault, &persistent_credentials);
        recover_pending_legacy_import(&restarted)
            .await
            .expect("recover committed delete");

        let recovered = restarted
            .saved_hosts
            .graph()
            .expect("recovered delete graph");
        assert!(recovered.hosts().iter().all(|host| host.id != id));
        assert_eq!(recovered.password_identities().len(), 1);
        assert_eq!(recovered.password_identities()[0].id.as_str(), identity_id);
        assert_credential_missing(&persistent_credentials, &target).await;
        assert_credential_missing(&persistent_credentials, &backup).await;
    }

    #[tokio::test]
    async fn stale_proxy_replace_does_not_consume_valid_host_capability() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, _) = desktop_state_with_memory_credentials(directory.path());
        let owner = "atomic-host-capability-window";
        let host_id = SavedHostId::from_opaque("atomic-host-capability").expect("host ID");
        let host_staged = state
            .ephemeral_credentials
            .insert(owner, test_secret("retained-host-secret"))
            .await
            .expect("stage host secret");
        let stale_proxy = EphemeralCredentialReference::new();
        let proxy_target = StoredCredentialReference::for_saved_host_proxy(host_id.as_str())
            .expect("proxy target");

        let result = super::materialize_saved_host_credential_actions(
            &state,
            owner,
            &host_id,
            super::SavedHostProtocolRequest::Ssh,
            super::PlannedSavedHostPasswordCredentialMutation::Replace {
                staged_credential_reference: host_staged,
            },
            Some(
                super::saved_host_proxy_catalog::PreparedHostInlineProxyCredentialMutation::Replace {
                    target: proxy_target,
                    staged_credential_reference: stale_proxy,
                },
            ),
        )
        .await;
        let error = match result {
            Ok(_) => panic!("stale proxy capability must reject the complete batch"),
            Err(error) => error,
        };
        assert!(error.starts_with(super::SAVED_HOST_CREDENTIAL_MUTATION_INVALID));
        let retained = state
            .ephemeral_credentials
            .take(owner, &host_staged)
            .await
            .expect("valid host capability remains staged");
        assert_eq!(retained.as_utf8(), Ok("retained-host-secret"));
    }

    #[tokio::test]
    async fn stale_host_replace_does_not_consume_valid_proxy_capability() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, _) = desktop_state_with_memory_credentials(directory.path());
        let owner = "atomic-proxy-capability-window";
        let host_id = SavedHostId::from_opaque("atomic-proxy-capability").expect("host ID");
        let stale_host = EphemeralCredentialReference::new();
        let proxy_staged = state
            .ephemeral_credentials
            .insert(owner, test_secret("retained-proxy-secret"))
            .await
            .expect("stage proxy secret");
        let proxy_target = StoredCredentialReference::for_saved_host_proxy(host_id.as_str())
            .expect("proxy target");

        let result = super::materialize_saved_host_credential_actions(
            &state,
            owner,
            &host_id,
            super::SavedHostProtocolRequest::Ssh,
            super::PlannedSavedHostPasswordCredentialMutation::Replace {
                staged_credential_reference: stale_host,
            },
            Some(
                super::saved_host_proxy_catalog::PreparedHostInlineProxyCredentialMutation::Replace {
                    target: proxy_target,
                    staged_credential_reference: proxy_staged,
                },
            ),
        )
        .await;
        let error = match result {
            Ok(_) => panic!("stale host capability must reject the complete batch"),
            Err(error) => error,
        };
        assert!(error.starts_with(super::SAVED_HOST_CREDENTIAL_MUTATION_INVALID));
        let retained = state
            .ephemeral_credentials
            .take(owner, &proxy_staged)
            .await
            .expect("valid proxy capability remains staged");
        assert_eq!(retained.as_utf8(), Ok("retained-proxy-secret"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saved_host_and_inline_proxy_credentials_share_one_recoverable_graph_transaction() {
        use super::saved_host_proxy_catalog::{
            HostInlineProxyConfigRequest, HostInlineProxyCredentialMutationRequest,
            HostInlineProxyMutationRequest, HostInlineProxyNetworkAuthRequest,
            HostProxyProfileMutationRequest, SavedHostProxyMutationRequest,
        };

        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, controller) = desktop_state_with_memory_credentials(directory.path());
        let window_owner = "dual-credential-window";
        let old_host_password = "old-host-password-sentinel";
        let old_proxy_password = "old-inline-proxy-password-sentinel";
        let host_staged = state
            .ephemeral_credentials
            .insert(window_owner, test_secret(old_host_password))
            .await
            .expect("stage host password");
        let proxy_staged = state
            .ephemeral_credentials
            .insert(window_owner, test_secret(old_proxy_password))
            .await
            .expect("stage proxy password");
        let created = super::create_saved_host_inner(
            &state,
            window_owner,
            CreateSavedHostRequest {
                draft: SavedHostDraftRequest {
                    label: Some("Dual credential host".to_owned()),
                    hostname: "dual-credential.example.test".to_owned(),
                    port: 22,
                    username: "ssh-user".to_owned(),
                    protocol: Default::default(),
                    serial_config: None,
                    charset: None,
                    group: None,
                    auth_method: Default::default(),
                    managed_ssh_key_id: None,
                    tags: Vec::new(),
                    host_chain: None,
                    password_identity_id: None,
                    transport: Default::default(),
                    proxy: Some(SavedHostProxyMutationRequest {
                        inline_proxy: HostInlineProxyMutationRequest::Replace {
                            config: HostInlineProxyConfigRequest::Http {
                                host: "old.proxy.example.test".to_owned(),
                                port: 3128,
                                auth: HostInlineProxyNetworkAuthRequest::Manual {
                                    username: "proxy-user".to_owned(),
                                    credential_mutation:
                                        HostInlineProxyCredentialMutationRequest::Replace {
                                            staged_credential_reference: proxy_staged,
                                        },
                                },
                            },
                        },
                        profile: HostProxyProfileMutationRequest::Remove,
                    }),
                },
                staged_credential_reference: Some(host_staged),
            },
        )
        .await
        .expect("create host and inline proxy in one transaction");
        let host_reference = stored_host_reference(&created.id);
        let proxy_reference = StoredCredentialReference::for_saved_host_proxy(&created.id)
            .expect("inline proxy reference");
        assert_stored_secret_with_kind(
            &state.persistent_credentials,
            &host_reference,
            CredentialKind::SshPassword,
            old_host_password,
        )
        .await;
        assert_stored_secret_with_kind(
            &state.persistent_credentials,
            &proxy_reference,
            CredentialKind::ProxyPassword,
            old_proxy_password,
        )
        .await;
        let encoded = serde_json::to_string(&created).expect("renderer-safe host JSON");
        assert!(!encoded.contains(old_host_password));
        assert!(!encoded.contains(old_proxy_password));
        assert!(
            created
                .proxy
                .as_ref()
                .is_some_and(|proxy| proxy.inline_proxy.is_some())
        );
        assert!(
            super::load_legacy_import_transaction(&state)
                .await
                .expect("completed transaction lookup")
                .is_none()
        );

        let new_host_password = "new-host-password-sentinel";
        let new_proxy_password = "new-inline-proxy-password-sentinel";
        let host_staged = state
            .ephemeral_credentials
            .insert(window_owner, test_secret(new_host_password))
            .await
            .expect("stage replacement host password");
        let proxy_staged = state
            .ephemeral_credentials
            .insert(window_owner, test_secret(new_proxy_password))
            .await
            .expect("stage replacement proxy password");
        controller.clear_operation_log();
        controller.set_failure(
            CredentialOperation::Upsert,
            4,
            FailureTiming::AfterSideEffect,
            CredentialErrorCode::BackendFailure,
        );
        let error = super::update_saved_host_inner(
            &state,
            window_owner,
            UpdateSavedHostRequest {
                id: created.id.clone(),
                expected_revision: created.revision,
                draft: SavedHostDraftRequest {
                    label: Some("Must roll back".to_owned()),
                    hostname: created.hostname.clone(),
                    port: u32::from(created.port),
                    username: created.username.clone(),
                    protocol: Default::default(),
                    serial_config: None,
                    charset: None,
                    group: None,
                    auth_method: Default::default(),
                    managed_ssh_key_id: None,
                    tags: Vec::new(),
                    host_chain: None,
                    password_identity_id: None,
                    transport: Default::default(),
                    proxy: Some(SavedHostProxyMutationRequest {
                        inline_proxy: HostInlineProxyMutationRequest::Replace {
                            config: HostInlineProxyConfigRequest::Socks5 {
                                host: "new.proxy.example.test".to_owned(),
                                port: 1080,
                                auth: HostInlineProxyNetworkAuthRequest::Manual {
                                    username: "new-proxy-user".to_owned(),
                                    credential_mutation:
                                        HostInlineProxyCredentialMutationRequest::Replace {
                                            staged_credential_reference: proxy_staged,
                                        },
                                },
                            },
                        },
                        profile: HostProxyProfileMutationRequest::Keep,
                    }),
                },
                credential_mutation: SavedHostCredentialMutation::Replace {
                    staged_credential_reference: host_staged,
                },
            },
        )
        .await
        .expect_err("second credential failure must roll back both owners and graph");
        assert!(error.starts_with(super::SAVED_HOST_PUBLICATION_FAILED));
        assert!(!error.contains(new_host_password));
        assert!(!error.contains(new_proxy_password));
        controller.clear_failures();
        let graph = state.saved_hosts.graph().expect("rolled-back graph");
        let rolled_back = graph
            .hosts()
            .iter()
            .find(|host| host.id.as_str() == created.id)
            .expect("rolled-back host");
        assert_eq!(rolled_back.revision, created.revision);
        assert_eq!(rolled_back.label, created.label);
        assert!(matches!(
            rolled_back.proxy_config().expect("inline proxy"),
            Some(netcatty_vault::SavedProxyConfig::Http { .. })
        ));
        assert_stored_secret_with_kind(
            &state.persistent_credentials,
            &host_reference,
            CredentialKind::SshPassword,
            old_host_password,
        )
        .await;
        assert_stored_secret_with_kind(
            &state.persistent_credentials,
            &proxy_reference,
            CredentialKind::ProxyPassword,
            old_proxy_password,
        )
        .await;
        assert!(
            super::load_legacy_import_transaction(&state)
                .await
                .expect("rolled-back transaction lookup")
                .is_none()
        );

        super::delete_saved_host_inner(
            &state,
            super::DeleteSavedHostRequest {
                id: created.id,
                expected_revision: created.revision,
            },
        )
        .await
        .expect("delete both deterministic accounts");
        assert_credential_missing_with_kind(
            &state.persistent_credentials,
            &host_reference,
            CredentialKind::SshPassword,
        )
        .await;
        assert_credential_missing_with_kind(
            &state.persistent_credentials,
            &proxy_reference,
            CredentialKind::ProxyPassword,
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stale_saved_host_replace_retains_staged_password_and_never_probes_keyring() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, controller) = desktop_state_with_memory_credentials(directory.path());
        let created = create_test_host_with_password(
            &state,
            "stale-host-window",
            "StaleHost",
            "stale-host-old-password",
        )
        .await;
        let staged = state
            .ephemeral_credentials
            .insert(
                "stale-host-window",
                test_secret("stale-host-new-password-sentinel"),
            )
            .await
            .expect("stage stale replacement");
        controller.clear_operation_log();

        let error = update_saved_host_inner(
            &state,
            "stale-host-window",
            UpdateSavedHostRequest {
                id: created.id,
                expected_revision: created.revision + 1,
                draft: SavedHostDraftRequest {
                    label: Some(created.label),
                    hostname: created.hostname,
                    port: u32::from(created.port),
                    username: created.username,
                    protocol: Default::default(),
                    serial_config: None,
                    charset: None,
                    group: None,
                    auth_method: Default::default(),
                    managed_ssh_key_id: None,
                    tags: Vec::new(),
                    host_chain: None,
                    password_identity_id: None,
                    transport: Default::default(),
                    proxy: None,
                },
                credential_mutation: SavedHostCredentialMutation::Replace {
                    staged_credential_reference: staged.clone(),
                },
            },
        )
        .await
        .expect_err("stale replace must fail");

        assert!(error.starts_with(super::SAVED_HOST_REVISION_CONFLICT));
        assert!(!error.contains("stale-host-new-password-sentinel"));
        assert!(controller.operation_log().is_empty());
        let retained = state
            .ephemeral_credentials
            .take("stale-host-window", &staged)
            .await
            .expect("stale request must retain staged password");
        assert_eq!(
            retained.as_utf8().expect("UTF-8 staged password"),
            "stale-host-new-password-sentinel"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saved_host_remove_and_delete_probe_false_hint_orphans() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, controller) = desktop_state_with_memory_credentials(directory.path());
        let created = super::create_saved_host_inner(
            &state,
            "false-hint-window",
            CreateSavedHostRequest {
                draft: SavedHostDraftRequest {
                    label: Some("False hint host".to_owned()),
                    hostname: "false-hint.example.test".to_owned(),
                    port: 22,
                    username: "false-hint-user".to_owned(),
                    protocol: Default::default(),
                    serial_config: None,
                    charset: None,
                    group: None,
                    auth_method: Default::default(),
                    managed_ssh_key_id: None,
                    tags: Vec::new(),
                    host_chain: None,
                    password_identity_id: None,
                    transport: Default::default(),
                    proxy: None,
                },
                staged_credential_reference: None,
            },
        )
        .await
        .expect("create metadata-only host");
        let target = stored_host_reference(&created.id);
        state
            .persistent_credentials
            .upsert(
                &target,
                CredentialKind::SshPassword,
                test_secret("false-hint-remove-orphan"),
            )
            .await
            .expect("seed remove orphan");
        controller.clear_operation_log();

        let removed = update_saved_host_inner(
            &state,
            "false-hint-window",
            UpdateSavedHostRequest {
                id: created.id.clone(),
                expected_revision: created.revision,
                draft: SavedHostDraftRequest {
                    label: Some(created.label.clone()),
                    hostname: created.hostname.clone(),
                    port: u32::from(created.port),
                    username: created.username.clone(),
                    protocol: Default::default(),
                    serial_config: None,
                    charset: None,
                    group: None,
                    auth_method: Default::default(),
                    managed_ssh_key_id: None,
                    tags: Vec::new(),
                    host_chain: None,
                    password_identity_id: None,
                    transport: Default::default(),
                    proxy: None,
                },
                credential_mutation: SavedHostCredentialMutation::Remove,
            },
        )
        .await
        .expect("remove false-hint orphan");
        assert_eq!(
            controller
                .operation_log()
                .count(CredentialOperation::Resolve),
            1
        );
        assert_credential_missing(&state.persistent_credentials, &target).await;
        let telnet_target =
            StoredCredentialReference::for_saved_host_telnet(&removed.id).expect("Telnet target");
        let proxy_target = StoredCredentialReference::for_saved_host_proxy(&removed.id)
            .expect("inline proxy target");
        assert_credential_missing_with_kind(
            &state.persistent_credentials,
            &telnet_target,
            CredentialKind::TelnetPassword,
        )
        .await;
        assert_credential_missing_with_kind(
            &state.persistent_credentials,
            &proxy_target,
            CredentialKind::ProxyPassword,
        )
        .await;

        state
            .persistent_credentials
            .upsert(
                &target,
                CredentialKind::SshPassword,
                test_secret("false-hint-delete-orphan"),
            )
            .await
            .expect("seed delete orphan");
        state
            .persistent_credentials
            .upsert(
                &telnet_target,
                CredentialKind::TelnetPassword,
                test_secret("false-hint-delete-telnet-orphan"),
            )
            .await
            .expect("seed Telnet delete orphan");
        state
            .persistent_credentials
            .upsert(
                &proxy_target,
                CredentialKind::ProxyPassword,
                test_secret("false-hint-delete-proxy-orphan"),
            )
            .await
            .expect("seed inline-proxy delete orphan");
        controller.clear_operation_log();
        super::delete_saved_host_inner(
            &state,
            super::DeleteSavedHostRequest {
                id: removed.id.clone(),
                expected_revision: removed.revision,
            },
        )
        .await
        .expect("delete false-hint orphan");
        assert_eq!(
            controller
                .operation_log()
                .count(CredentialOperation::Resolve),
            3,
            "host deletion probes the SSH, Telnet, and inline-proxy accounts"
        );
        assert_credential_missing(&state.persistent_credentials, &target).await;
        assert_credential_missing_with_kind(
            &state.persistent_credentials,
            &telnet_target,
            CredentialKind::TelnetPassword,
        )
        .await;
        assert_credential_missing_with_kind(
            &state.persistent_credentials,
            &proxy_target,
            CredentialKind::ProxyPassword,
        )
        .await;
        assert!(state.saved_hosts.list().expect("saved hosts").is_empty());
    }

    #[test]
    fn saved_host_graph_mutations_preserve_every_non_host_catalog_exactly() {
        let rule_host = SavedHost::from_draft(
            netcatty_vault::SavedHostDraft::ssh_password(
                "forward-owner.example.test",
                "forward-owner",
            ),
            9,
        )
        .expect("port-forward owner host");
        let host = SavedHost::from_draft(
            netcatty_vault::SavedHostDraft::ssh_password(
                "full-graph.example.test",
                "full-graph-user",
            ),
            10,
        )
        .expect("full-graph host");
        let identity =
            test_password_identity("full-graph-password-identity", "identity-user", false);
        let reference = netcatty_vault::SavedSshKeyReference::from_parts(
            netcatty_vault::SavedSshKeyReferenceId::from_opaque("full-graph-reference-key")
                .expect("reference key ID"),
            "Full graph reference key",
            r"D:\keys\full-graph-reference-key",
            netcatty_vault::SavedSshKeyCategory::key(),
            10,
            10,
            Default::default(),
        )
        .expect("reference key");
        let key_identity = netcatty_vault::SavedIdentityReference::from_parts(
            netcatty_vault::SavedIdentityReferenceId::from_opaque("full-graph-key-identity")
                .expect("key identity ID"),
            "Full graph key identity",
            "key-user",
            reference.id.clone(),
            10,
            10,
            Default::default(),
        )
        .expect("key identity");
        let managed = netcatty_vault::SavedManagedSshKey::from_parts(
            netcatty_vault::SavedSshKeyReferenceId::from_opaque("full-graph-managed-key")
                .expect("managed key ID"),
            "Full graph managed key",
            netcatty_vault::SavedSshKeyCategory::key(),
            netcatty_vault::SavedSshKeySource::generated(),
            false,
            10,
            10,
            netcatty_vault::SavedSshKeyCustodyReference::new(
                netcatty_vault::SavedSecretObjectLocator::from_hex("ab".repeat(32))
                    .expect("managed locator"),
                1,
            )
            .expect("managed custody"),
            Default::default(),
        )
        .expect("managed key");
        let proxy_profile = netcatty_vault::SavedProxyProfile::from_parts(
            netcatty_vault::SavedProxyProfileId::from_opaque("full-graph-proxy-profile")
                .expect("proxy profile ID"),
            1,
            "Full graph proxy profile",
            netcatty_vault::SavedProxyConfig::http(
                "proxy.example.test",
                8080,
                Some(identity.id.clone()),
                "",
                false,
            )
            .expect("proxy config"),
            10,
            10,
            Default::default(),
        )
        .expect("proxy profile");
        let notes_snippets = netcatty_vault::SavedNotesSnippetsCatalog::from_parts(
            Some(Vec::new()),
            None,
            None,
            None,
        )
        .expect("present notes/snippets catalog");
        let port_forward = netcatty_vault::SavedPortForwardRule::new(
            "full-graph-port-forward",
            "Full graph SOCKS tunnel",
            netcatty_vault::SavedPortForwardKind::Dynamic,
            1080,
            "127.0.0.1",
            None,
            None,
            rule_host.id.as_str(),
            false,
            10,
            None,
            None,
        )
        .expect("port-forward rule");
        let graph = SavedVaultGraph::new_with_port_forward_rules(
            vec![rule_host.clone()],
            vec![reference.clone()],
            vec![managed.clone()],
            vec![key_identity.clone()],
            vec![identity.clone()],
            vec![proxy_profile.clone()],
            Vec::new(),
            notes_snippets.clone(),
            vec![port_forward.clone()],
        );
        let created = super::saved_host_graph_with_created_host(graph, host.clone())
            .expect("create host in complete graph");
        assert_eq!(
            created.ssh_key_references(),
            std::slice::from_ref(&reference)
        );
        assert_eq!(created.managed_ssh_keys(), std::slice::from_ref(&managed));
        assert_eq!(
            created.identity_references(),
            std::slice::from_ref(&key_identity)
        );
        assert_eq!(
            created.password_identities(),
            std::slice::from_ref(&identity)
        );
        assert_eq!(
            created.proxy_profiles(),
            std::slice::from_ref(&proxy_profile)
        );
        assert_eq!(created.notes_snippets(), &notes_snippets);
        assert_eq!(
            created.port_forward_rules(),
            std::slice::from_ref(&port_forward)
        );

        let mut update = netcatty_vault::SavedHostUpdate::default();
        update.label = Some("Updated full graph host".to_owned());
        let updated = host.apply_update(update, 20).expect("updated host");

        let replaced = super::saved_host_graph_with_updated_host(created, updated)
            .expect("replace host in complete graph");
        assert_eq!(
            replaced.ssh_key_references(),
            std::slice::from_ref(&reference)
        );
        assert_eq!(replaced.managed_ssh_keys(), std::slice::from_ref(&managed));
        assert_eq!(
            replaced.identity_references(),
            std::slice::from_ref(&key_identity)
        );
        assert_eq!(
            replaced.password_identities(),
            std::slice::from_ref(&identity)
        );
        assert_eq!(
            replaced.proxy_profiles(),
            std::slice::from_ref(&proxy_profile)
        );
        assert_eq!(replaced.notes_snippets(), &notes_snippets);
        assert_eq!(
            replaced.port_forward_rules(),
            std::slice::from_ref(&port_forward)
        );

        let deleted = super::saved_host_graph_without_host(replaced, &host.id)
            .expect("delete host from complete graph");
        assert_eq!(deleted.hosts(), std::slice::from_ref(&rule_host));
        assert_eq!(
            deleted.ssh_key_references(),
            std::slice::from_ref(&reference)
        );
        assert_eq!(deleted.managed_ssh_keys(), std::slice::from_ref(&managed));
        assert_eq!(
            deleted.identity_references(),
            std::slice::from_ref(&key_identity)
        );
        assert_eq!(
            deleted.password_identities(),
            std::slice::from_ref(&identity)
        );
        assert_eq!(
            deleted.proxy_profiles(),
            std::slice::from_ref(&proxy_profile)
        );
        assert_eq!(deleted.notes_snippets(), &notes_snippets);
        assert_eq!(
            deleted.port_forward_rules(),
            std::slice::from_ref(&port_forward)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saved_inline_proxy_one_shot_has_priority_and_builds_http_config() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, controller) = desktop_state_with_memory_credentials(directory.path());
        let host = test_proxy_host(
            "inline-proxy-connection-host",
            Some(
                netcatty_vault::SavedProxyConfig::http(
                    "inline.proxy.example",
                    8080,
                    None,
                    "inline-user",
                    true,
                )
                .expect("inline proxy"),
            ),
            None,
        );
        let graph = publish_test_proxy_graph(&state, host, Vec::new(), Vec::new());
        let host = graph.hosts()[0].clone();
        state
            .persistent_credentials
            .upsert(
                &StoredCredentialReference::for_saved_host_proxy(host.id.as_str())
                    .expect("inline proxy reference"),
                CredentialKind::ProxyPassword,
                test_secret("persisted-inline-proxy-password"),
            )
            .await
            .expect("store inline proxy password");

        let owner = "inline-proxy-window";
        let ssh_password =
            stage_saved_host_ssh_password(&state, owner, "one-shot-ssh-password").await;
        let proxy_password = state
            .ephemeral_credentials
            .insert(owner, test_secret("one-shot-proxy-password"))
            .await
            .expect("stage proxy password");
        let mut request = saved_password_session_request(&host);
        request.credential_reference = Some(ssh_password.clone());
        request.proxy_credential_reference = Some(proxy_password.clone());
        controller.clear_operation_log();

        let prepared = prepare_test_saved_host_session(&state, owner, request)
            .await
            .expect("inline proxy preparation");
        let proxy = prepared.config.proxy.as_ref().expect("proxy config");
        assert_eq!(proxy.proxy_type, ProxyType::Http);
        assert_eq!(proxy.host, "inline.proxy.example");
        assert_eq!(proxy.port, Some(8080));
        assert_eq!(proxy.username.as_deref(), Some("inline-user"));
        assert!(proxy.identity_id.is_none());
        assert!(proxy.has_password);
        assert_eq!(
            controller
                .operation_log()
                .count(CredentialOperation::Resolve),
            0,
            "one-shot SSH and proxy passwords must bypass persistent custody"
        );
        assert_ephemeral_reference_consumed(&state, owner, &ssh_password).await;
        assert_ephemeral_reference_consumed(&state, owner, &proxy_password).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saved_profile_proxy_uses_profile_proxy_password_custody() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, controller) = desktop_state_with_memory_credentials(directory.path());
        let profile_id = "connection-manual-profile";
        let profile = test_proxy_profile(
            profile_id,
            netcatty_vault::SavedProxyConfig::socks5(
                "profile.proxy.example",
                1080,
                None,
                "profile-user",
                true,
            )
            .expect("profile proxy"),
        );
        let host = test_proxy_host("profile-proxy-connection-host", None, Some(profile_id));
        let graph = publish_test_proxy_graph(&state, host, Vec::new(), vec![profile]);
        let host = graph.hosts()[0].clone();
        state
            .persistent_credentials
            .upsert(
                &StoredCredentialReference::for_saved_proxy_profile(profile_id)
                    .expect("profile proxy reference"),
                CredentialKind::ProxyPassword,
                test_secret("profile-proxy-password"),
            )
            .await
            .expect("store profile proxy password");
        let owner = "profile-proxy-window";
        let ssh_password =
            stage_saved_host_ssh_password(&state, owner, "one-shot-ssh-password").await;
        let mut request = saved_password_session_request(&host);
        request.credential_reference = Some(ssh_password);
        controller.clear_operation_log();

        let prepared = prepare_test_saved_host_session(&state, owner, request)
            .await
            .expect("profile proxy preparation");
        let proxy = prepared.config.proxy.as_ref().expect("proxy config");
        assert_eq!(proxy.proxy_type, ProxyType::Socks5);
        assert_eq!(proxy.host, "profile.proxy.example");
        assert_eq!(proxy.port, Some(1080));
        assert_eq!(proxy.username.as_deref(), Some("profile-user"));
        assert!(proxy.has_password);
        assert_eq!(
            controller
                .operation_log()
                .count(CredentialOperation::Resolve),
            1
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saved_proxy_identity_uses_ssh_password_custody_and_identity_username() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, controller) = desktop_state_with_memory_credentials(directory.path());
        let shared_id = "shared-profile-identity-connection-id";
        let identity = test_password_identity(shared_id, "proxy-identity-user", true);
        let profile = test_proxy_profile(
            shared_id,
            netcatty_vault::SavedProxyConfig::http(
                "identity.proxy.example",
                3128,
                Some(identity.id.clone()),
                "",
                false,
            )
            .expect("identity proxy"),
        );
        let host = test_proxy_host("identity-proxy-connection-host", None, Some(shared_id));
        let graph = publish_test_proxy_graph(&state, host, vec![identity], vec![profile]);
        let host = graph.hosts()[0].clone();
        state
            .persistent_credentials
            .upsert(
                &StoredCredentialReference::for_saved_identity(shared_id)
                    .expect("identity reference"),
                CredentialKind::SshPassword,
                test_secret("identity-proxy-password"),
            )
            .await
            .expect("store identity password");
        let owner = "identity-proxy-window";
        let ssh_password =
            stage_saved_host_ssh_password(&state, owner, "one-shot-ssh-password").await;
        let mut request = saved_password_session_request(&host);
        request.credential_reference = Some(ssh_password);
        controller.clear_operation_log();

        let prepared = prepare_test_saved_host_session(&state, owner, request)
            .await
            .expect("identity proxy preparation");
        let proxy = prepared.config.proxy.as_ref().expect("proxy config");
        assert_eq!(proxy.proxy_type, ProxyType::Http);
        assert_eq!(proxy.username.as_deref(), Some("proxy-identity-user"));
        assert!(proxy.identity_id.is_none());
        assert!(proxy.has_password);
        assert_eq!(
            controller
                .operation_log()
                .count(CredentialOperation::Resolve),
            1
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saved_command_proxy_builds_command_config_without_credentials() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let state = DesktopState::open(directory.path()).expect("desktop state");
        let command = "ssh -W %h:%p proxy-gateway";
        let host = test_proxy_host(
            "command-proxy-connection-host",
            Some(netcatty_vault::SavedProxyConfig::command(command).expect("command proxy")),
            None,
        );
        let graph = publish_test_proxy_graph(&state, host, Vec::new(), Vec::new());
        let host = graph.hosts()[0].clone();
        let owner = "command-proxy-window";
        let ssh_password =
            stage_saved_host_ssh_password(&state, owner, "one-shot-ssh-password").await;
        let mut request = saved_password_session_request(&host);
        request.credential_reference = Some(ssh_password);

        let prepared = prepare_test_saved_host_session(&state, owner, request)
            .await
            .expect("command proxy preparation");
        let proxy = prepared.config.proxy.as_ref().expect("proxy config");
        assert_eq!(proxy.proxy_type, ProxyType::Command);
        assert_eq!(proxy.command.as_deref(), Some(command));
        assert!(proxy.host.is_empty());
        assert!(proxy.port.is_none());
        assert!(proxy.username.is_none());
        assert!(!proxy.has_password);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn missing_inline_proxy_password_repairs_only_inline_hint() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, controller) = desktop_state_with_memory_credentials(directory.path());
        let host = test_proxy_host(
            "missing-inline-proxy-password",
            Some(
                netcatty_vault::SavedProxyConfig::http(
                    "missing.inline.proxy.example",
                    8080,
                    None,
                    "inline-user",
                    true,
                )
                .expect("inline proxy"),
            ),
            None,
        );
        let graph = publish_test_proxy_graph(&state, host, Vec::new(), Vec::new());
        let host = graph.hosts()[0].clone();
        let owner = "missing-inline-proxy-window";
        let ssh_password =
            stage_saved_host_ssh_password(&state, owner, "one-shot-ssh-password").await;
        let mut request = saved_password_session_request(&host);
        request.credential_reference = Some(ssh_password);
        controller.clear_operation_log();

        let error = prepare_test_saved_host_session(&state, owner, request)
            .await
            .err()
            .expect("missing inline proxy password must require prompt");
        assert!(error.starts_with(super::SAVED_CREDENTIAL_NOT_FOUND));
        let repaired = state.saved_hosts.graph().expect("repaired graph");
        let repaired_host = &repaired.hosts()[0];
        assert_eq!(repaired_host.revision, host.revision + 1);
        assert!(matches!(
            repaired_host
                .proxy_config()
                .expect("inline proxy parse")
                .expect("inline proxy"),
            netcatty_vault::SavedProxyConfig::Http {
                has_saved_credential: false,
                ..
            }
        ));
        assert!(repaired.proxy_profiles().is_empty());
        assert!(repaired.password_identities().is_empty());
        assert_eq!(
            controller
                .operation_log()
                .count(CredentialOperation::Resolve),
            1
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn missing_proxy_identity_password_repairs_only_identity_hint() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, controller) = desktop_state_with_memory_credentials(directory.path());
        let identity_id = "missing-proxy-identity-password";
        let identity = test_password_identity(identity_id, "proxy-identity-user", true);
        let host = test_proxy_host(
            "missing-proxy-identity-host",
            Some(
                netcatty_vault::SavedProxyConfig::socks5(
                    "missing.identity.proxy.example",
                    1080,
                    Some(identity.id.clone()),
                    "",
                    false,
                )
                .expect("identity proxy"),
            ),
            None,
        );
        let graph = publish_test_proxy_graph(&state, host, vec![identity], Vec::new());
        let host = graph.hosts()[0].clone();
        let original_identity = graph.password_identities()[0].clone();
        let owner = "missing-proxy-identity-window";
        let ssh_password =
            stage_saved_host_ssh_password(&state, owner, "one-shot-ssh-password").await;
        let mut request = saved_password_session_request(&host);
        request.credential_reference = Some(ssh_password);
        controller.clear_operation_log();

        let error = prepare_test_saved_host_session(&state, owner, request)
            .await
            .err()
            .expect("missing proxy identity password must require prompt");
        assert!(error.starts_with(super::SAVED_CREDENTIAL_NOT_FOUND));
        assert!(!error.contains(identity_id));
        let repaired = state.saved_hosts.graph().expect("repaired graph");
        let repaired_identity = &repaired.password_identities()[0];
        assert_eq!(repaired_identity.revision, original_identity.revision + 1);
        assert!(!repaired_identity.has_saved_credential);
        assert_eq!(repaired.hosts()[0].revision, host.revision);
        assert!(repaired.proxy_profiles().is_empty());
        assert_eq!(
            controller
                .operation_log()
                .count(CredentialOperation::Resolve),
            1
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn missing_profile_proxy_password_repairs_only_profile_hint() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, controller) = desktop_state_with_memory_credentials(directory.path());
        let profile_id = "missing-connection-profile-password";
        let profile = test_proxy_profile(
            profile_id,
            netcatty_vault::SavedProxyConfig::http(
                "missing.proxy.example",
                8080,
                None,
                "profile-user",
                true,
            )
            .expect("profile proxy"),
        );
        let host = test_proxy_host("missing-profile-proxy-host", None, Some(profile_id));
        let graph = publish_test_proxy_graph(&state, host, Vec::new(), vec![profile]);
        let host = graph.hosts()[0].clone();
        let original_profile = graph.proxy_profiles()[0].clone();
        let owner = "missing-profile-proxy-window";
        let ssh_password =
            stage_saved_host_ssh_password(&state, owner, "one-shot-ssh-password").await;
        let mut request = saved_password_session_request(&host);
        request.credential_reference = Some(ssh_password);
        controller.clear_operation_log();

        let error = prepare_test_saved_host_session(&state, owner, request)
            .await
            .err()
            .expect("missing proxy password must require prompt");
        assert!(error.starts_with(super::SAVED_CREDENTIAL_NOT_FOUND));
        assert!(!error.contains(profile_id));
        let repaired = state.saved_hosts.graph().expect("repaired graph");
        let repaired_profile = &repaired.proxy_profiles()[0];
        assert_eq!(repaired_profile.revision, original_profile.revision + 1);
        assert!(matches!(
            &repaired_profile.config,
            netcatty_vault::SavedProxyConfig::Http {
                has_saved_credential: false,
                ..
            }
        ));
        let unchanged_host = &repaired.hosts()[0];
        assert_eq!(unchanged_host.revision, host.revision);
        assert_eq!(
            controller
                .operation_log()
                .count(CredentialOperation::Resolve),
            1
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn corrupt_profile_proxy_password_fails_closed_without_hint_repair() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, controller) = desktop_state_with_memory_credentials(directory.path());
        let profile_id = "corrupt-connection-profile-password";
        let profile = test_proxy_profile(
            profile_id,
            netcatty_vault::SavedProxyConfig::http(
                "corrupt.proxy.example",
                8080,
                None,
                "profile-user",
                true,
            )
            .expect("profile proxy"),
        );
        let host = test_proxy_host("corrupt-profile-proxy-host", None, Some(profile_id));
        let graph = publish_test_proxy_graph(&state, host, Vec::new(), vec![profile]);
        let host = graph.hosts()[0].clone();
        let original_profile = graph.proxy_profiles()[0].clone();
        let owner = "corrupt-profile-proxy-window";
        let ssh_password =
            stage_saved_host_ssh_password(&state, owner, "one-shot-ssh-password").await;
        let mut request = saved_password_session_request(&host);
        request.credential_reference = Some(ssh_password);
        controller.clear_operation_log();
        controller.set_failure(
            CredentialOperation::Resolve,
            1,
            FailureTiming::BeforeSideEffect,
            CredentialErrorCode::CorruptRecord,
        );

        let error = prepare_test_saved_host_session(&state, owner, request)
            .await
            .err()
            .expect("corrupt proxy credential must fail closed");
        assert_eq!(error, CredentialErrorCode::CorruptRecord.message());
        let unchanged = state.saved_hosts.graph().expect("unchanged graph");
        assert_eq!(unchanged.proxy_profiles()[0], original_profile);
        assert_eq!(unchanged.hosts()[0].revision, host.revision);
        assert_eq!(
            controller
                .operation_log()
                .count(CredentialOperation::Resolve),
            1
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saved_password_connection_prefers_one_shot_then_identity_and_overrides_username() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, controller) = desktop_state_with_memory_credentials(directory.path());
        let identity_id = "connection-priority-identity";
        let host = test_password_identity_host("connection-priority-host", Some(identity_id), true);
        let (host, _) = publish_test_password_identity_graph(
            &state,
            Some(host),
            test_password_identity(identity_id, "identity-user", true),
        );
        let host = host.expect("persisted host");
        state
            .persistent_credentials
            .upsert(
                &stored_identity_reference(identity_id),
                CredentialKind::SshPassword,
                test_secret("identity-password-sentinel"),
            )
            .await
            .expect("store identity password");
        state
            .persistent_credentials
            .upsert(
                &stored_host_reference(host.id.as_str()),
                CredentialKind::SshPassword,
                test_secret("host-password-sentinel"),
            )
            .await
            .expect("store host password");

        let owner = "connection-priority-window";
        let staged = state
            .ephemeral_credentials
            .insert(owner, test_secret("one-shot-password-sentinel"))
            .await
            .expect("stage one-shot password");
        controller.clear_operation_log();
        let mut one_shot_request = saved_password_session_request(&host);
        one_shot_request.credential_reference = Some(staged.clone());
        let prepared = prepare_test_saved_host_session(&state, owner, one_shot_request)
            .await
            .expect("one-shot password preparation");
        assert_eq!(prepared.config.username, "identity-user");
        assert_eq!(
            controller
                .operation_log()
                .count(CredentialOperation::Resolve),
            0,
            "one-shot password must avoid both persisted accounts"
        );
        assert_ephemeral_reference_consumed(&state, owner, &staged).await;

        controller.clear_operation_log();
        let prepared =
            prepare_test_saved_host_session(&state, owner, saved_password_session_request(&host))
                .await
                .expect("identity password preparation");
        assert_eq!(prepared.config.username, "identity-user");
        assert_eq!(
            controller
                .operation_log()
                .count(CredentialOperation::Resolve),
            1,
            "identity password must be resolved before the host account"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn missing_identity_password_clears_only_identity_hint_and_falls_back_to_host() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, controller) = desktop_state_with_memory_credentials(directory.path());
        let identity_id = "missing-connection-identity";
        let host = test_password_identity_host("missing-connection-host", Some(identity_id), true);
        let (host, identity) = publish_test_password_identity_graph(
            &state,
            Some(host),
            test_password_identity(identity_id, "fallback-identity-user", true),
        );
        let host = host.expect("persisted host");
        state
            .persistent_credentials
            .upsert(
                &stored_host_reference(host.id.as_str()),
                CredentialKind::SshPassword,
                test_secret("fallback-host-password-sentinel"),
            )
            .await
            .expect("store host fallback password");
        controller.clear_operation_log();

        let prepared = prepare_test_saved_host_session(
            &state,
            "fallback-window",
            saved_password_session_request(&host),
        )
        .await
        .expect("host password fallback");
        assert_eq!(prepared.config.username, "fallback-identity-user");
        assert_eq!(
            controller
                .operation_log()
                .count(CredentialOperation::Resolve),
            2
        );

        let graph = state.saved_hosts.graph().expect("repaired graph");
        let repaired_identity = graph
            .password_identities()
            .iter()
            .find(|candidate| candidate.id == identity.id)
            .expect("repaired identity");
        assert!(!repaired_identity.has_saved_credential);
        assert_eq!(repaired_identity.revision, identity.revision + 1);
        let unchanged_host = graph
            .hosts()
            .iter()
            .find(|candidate| candidate.id == host.id)
            .expect("unchanged host");
        assert_eq!(unchanged_host.revision, host.revision);
        assert!(super::has_saved_credential(unchanged_host));
        let view =
            super::saved_host_view_from_graph(unchanged_host, &graph).expect("saved host view");
        assert!(view.has_saved_credential);
        assert!(view.has_saved_host_credential);
        assert!(
            !view
                .password_identity
                .expect("identity metadata")
                .has_saved_credential
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn missing_identity_or_host_password_clears_its_hint_then_requires_prompt() {
        let identity_directory = tempfile::tempdir().expect("identity vault");
        let (identity_state, _) = desktop_state_with_memory_credentials(identity_directory.path());
        let identity_id = "prompt-missing-identity";
        let identity_host =
            test_password_identity_host("prompt-identity-host", Some(identity_id), false);
        let (identity_host, identity) = publish_test_password_identity_graph(
            &identity_state,
            Some(identity_host),
            test_password_identity(identity_id, "identity-user", true),
        );
        let identity_host = identity_host.expect("identity host");
        let error = prepare_test_saved_host_session(
            &identity_state,
            "identity-prompt-window",
            saved_password_session_request(&identity_host),
        )
        .await
        .err()
        .expect("missing identity password must require prompt");
        assert!(error.starts_with(super::SAVED_CREDENTIAL_NOT_FOUND));
        assert!(!error.contains(identity_id));
        let graph = identity_state
            .saved_hosts
            .graph()
            .expect("identity repair graph");
        assert!(
            !graph
                .password_identities()
                .iter()
                .find(|candidate| candidate.id == identity.id)
                .expect("identity")
                .has_saved_credential
        );
        assert!(!super::has_saved_credential(&graph.hosts()[0]));

        let host_directory = tempfile::tempdir().expect("host vault");
        let (host_state, _) = desktop_state_with_memory_credentials(host_directory.path());
        let host_identity_id = "prompt-host-identity";
        let host = test_password_identity_host("prompt-missing-host", Some(host_identity_id), true);
        let (host, identity) = publish_test_password_identity_graph(
            &host_state,
            Some(host),
            test_password_identity(host_identity_id, "", false),
        );
        let host = host.expect("host fallback record");
        let error = prepare_test_saved_host_session(
            &host_state,
            "host-prompt-window",
            saved_password_session_request(&host),
        )
        .await
        .err()
        .expect("missing host password must require prompt");
        assert!(error.starts_with(super::SAVED_CREDENTIAL_NOT_FOUND));
        let graph = host_state.saved_hosts.graph().expect("host repair graph");
        let repaired_host = graph
            .hosts()
            .iter()
            .find(|candidate| candidate.id == host.id)
            .expect("repaired host");
        assert!(!super::has_saved_credential(repaired_host));
        assert_eq!(repaired_host.revision, host.revision + 1);
        let unchanged_identity = graph
            .password_identities()
            .iter()
            .find(|candidate| candidate.id == identity.id)
            .expect("unchanged identity");
        assert_eq!(unchanged_identity.revision, identity.revision);
        assert!(!unchanged_identity.has_saved_credential);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn corrupt_identity_password_fails_closed_without_host_fallback_or_hint_change() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, controller) = desktop_state_with_memory_credentials(directory.path());
        let identity_id = "corrupt-connection-identity";
        let host = test_password_identity_host("corrupt-connection-host", Some(identity_id), true);
        let (host, identity) = publish_test_password_identity_graph(
            &state,
            Some(host),
            test_password_identity(identity_id, "identity-user", true),
        );
        let host = host.expect("persisted host");
        state
            .persistent_credentials
            .upsert(
                &stored_host_reference(host.id.as_str()),
                CredentialKind::SshPassword,
                test_secret("must-not-fallback-host-password"),
            )
            .await
            .expect("store forbidden fallback password");
        controller.clear_operation_log();
        controller.set_failure(
            CredentialOperation::Resolve,
            1,
            FailureTiming::BeforeSideEffect,
            CredentialErrorCode::CorruptRecord,
        );

        let error = prepare_test_saved_host_session(
            &state,
            "corrupt-window",
            saved_password_session_request(&host),
        )
        .await
        .err()
        .expect("corrupt identity credential must fail closed");
        assert_eq!(error, CredentialErrorCode::CorruptRecord.message());
        assert_eq!(
            controller
                .operation_log()
                .count(CredentialOperation::Resolve),
            1
        );
        let graph = state.saved_hosts.graph().expect("unchanged graph");
        let unchanged_identity = graph
            .password_identities()
            .iter()
            .find(|candidate| candidate.id == identity.id)
            .expect("unchanged identity");
        assert_eq!(unchanged_identity.revision, identity.revision);
        assert!(unchanged_identity.has_saved_credential);
        let unchanged_host = graph
            .hosts()
            .iter()
            .find(|candidate| candidate.id == host.id)
            .expect("unchanged host");
        assert_eq!(unchanged_host.revision, host.revision);
        assert!(super::has_saved_credential(unchanged_host));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn identity_hint_repair_rejects_stale_record_revision_without_mutation() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, _) = desktop_state_with_memory_credentials(directory.path());
        let identity_id = "stale-hint-repair-identity";
        let (_, identity) = publish_test_password_identity_graph(
            &state,
            None,
            test_password_identity(identity_id, "identity-user", true),
        );

        let error = super::clear_missing_password_identity_credential_hint(
            &state,
            identity.id.clone(),
            identity.revision + 1,
        )
        .await
        .expect_err("stale record revision must fail closed");
        assert!(error.starts_with(super::SAVED_PASSWORD_IDENTITY_HINT_REPAIR_FAILED));
        assert!(!error.contains(identity_id));
        let unchanged = state
            .saved_hosts
            .graph()
            .expect("unchanged graph")
            .password_identities()[0]
            .clone();
        assert_eq!(unchanged.revision, identity.revision);
        assert!(unchanged.has_saved_credential);
    }

    #[test]
    fn selected_identity_file_paths_are_bounded_without_touching_the_filesystem() {
        assert!(
            validate_selected_identity_file_paths(Vec::new())
                .expect_err("selection is required")
                .starts_with(super::SAVED_HOST_KEY_FILE_CONFIRMATION_REQUIRED)
        );
        assert!(
            validate_selected_identity_file_paths(vec![" ".to_owned()])
                .expect_err("blank path")
                .starts_with(super::SAVED_HOST_KEY_FILE_SELECTION_INVALID)
        );
        assert!(
            validate_selected_identity_file_paths(vec![
                "C:\\keys\\same".to_owned(),
                "C:\\keys\\same".to_owned(),
            ])
            .expect_err("duplicate path")
            .starts_with(super::SAVED_HOST_KEY_FILE_SELECTION_INVALID)
        );
        assert!(
            validate_selected_identity_file_paths(vec!["bad\0path".to_owned()])
                .expect_err("NUL path")
                .starts_with(super::SAVED_HOST_KEY_FILE_SELECTION_INVALID)
        );
        assert!(
            validate_selected_identity_file_paths(vec!["C:\\keys\\bad\npath".to_owned()])
                .expect_err("control-character path")
                .starts_with(super::SAVED_HOST_KEY_FILE_SELECTION_INVALID)
        );
        assert!(
            validate_selected_identity_file_paths(vec![
                "C:\\keys\\one".to_owned(),
                "C:\\keys\\two".to_owned(),
            ])
            .is_ok()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn key_host_rejects_password_replacement_without_consuming_the_staged_secret() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, controller) = desktop_state_with_memory_credentials(directory.path());
        let host: SavedHost = serde_json::from_value(json!({
            "recordVersion": 1,
            "id": "key-host-password-guard",
            "revision": 1,
            "label": "Key host",
            "hostname": "key.example.test",
            "port": 22,
            "username": "alice",
            "protocol": "ssh",
            "authMethod": "key",
            "authPolicyVersion": 1,
            "createdAt": 10,
            "updatedAt": 10,
            "hasSavedCredential": false,
            "identityFilePaths": ["C:\\legacy\\reference-key"]
        }))
        .expect("key host model");
        let revision = state
            .saved_hosts
            .assess_import(std::slice::from_ref(&host))
            .expect("key host assessment")
            .into_revision();
        state
            .saved_hosts
            .commit_import(revision, vec![host.clone()])
            .expect("key host commit");
        let staged = state
            .ephemeral_credentials
            .insert(
                "test-window",
                SecretValue::from_utf8("must-remain-staged".to_owned()).expect("secret"),
            )
            .await
            .expect("stage password");
        controller.clear_operation_log();

        let error = update_saved_host_inner(
            &state,
            "test-window",
            UpdateSavedHostRequest {
                id: host.id.as_str().to_owned(),
                expected_revision: host.revision,
                draft: SavedHostDraftRequest {
                    label: Some(host.label.clone()),
                    hostname: host.hostname.clone(),
                    port: u32::from(host.port),
                    username: host.username.clone(),
                    protocol: Default::default(),
                    serial_config: None,
                    charset: None,
                    group: None,
                    auth_method: super::SavedHostAuthenticationMethodRequest::Key,
                    managed_ssh_key_id: None,
                    tags: Vec::new(),
                    host_chain: None,
                    password_identity_id: None,
                    transport: Default::default(),
                    proxy: None,
                },
                credential_mutation: SavedHostCredentialMutation::Replace {
                    staged_credential_reference: staged.clone(),
                },
            },
        )
        .await
        .expect_err("key hosts must reject password replacement");
        assert!(error.starts_with(super::SAVED_HOST_CREDENTIAL_MUTATION_INVALID));
        assert!(controller.operation_log().is_empty());
        let retained = state
            .ephemeral_credentials
            .take("test-window", &staged)
            .await
            .expect("rejected mutation must not consume staged password");
        assert_eq!(
            retained.as_utf8().expect("UTF-8 secret"),
            "must-remain-staged"
        );
        assert_eq!(
            state
                .saved_hosts
                .get(&host.id)
                .expect("saved host lookup")
                .expect("saved host")
                .revision,
            host.revision
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn imported_key_path_is_never_used_without_current_user_selection() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let state = DesktopState::open(directory.path()).expect("desktop state");
        let imported_path = "C:\\attacker-controlled\\must-not-be-opened";
        let selected_path = "C:\\user-selected\\id_ed25519";
        let host: SavedHost = serde_json::from_value(json!({
            "recordVersion": 1,
            "id": "legacy-key-host",
            "revision": 1,
            "label": "Imported key host",
            "hostname": "key.example.test",
            "port": 22,
            "username": "alice",
            "protocol": "ssh",
            "authMethod": "key",
            "authPolicyVersion": 1,
            "createdAt": 10,
            "updatedAt": 10,
            "identityFilePaths": [imported_path]
        }))
        .expect("key host model");
        let revision = state
            .saved_hosts
            .assess_import(std::slice::from_ref(&host))
            .expect("key host assessment")
            .into_revision();
        state
            .saved_hosts
            .commit_import(revision, vec![host.clone()])
            .expect("key host commit");

        let missing_selection = prepare_test_saved_host_session(
            &state,
            "test-window",
            StartSavedHostSessionRequest {
                client_attempt_id: test_client_attempt_id(),
                host_id: host.id.as_str().to_owned(),
                expected_revision: host.revision,
                credential_reference: None,
                proxy_credential_reference: None,
                key_passphrase_reference: None,
                selected_identity_file_paths: Vec::new(),
                known_hosts: Vec::new(),
                verify_host_keys: true,
                shell: None,
            },
        )
        .await
        .err()
        .expect("key selection must be required");
        assert!(missing_selection.starts_with(super::SAVED_HOST_KEY_FILE_CONFIRMATION_REQUIRED));
        assert!(!missing_selection.contains(imported_path));

        let prepared = prepare_test_saved_host_session(
            &state,
            "test-window",
            StartSavedHostSessionRequest {
                client_attempt_id: test_client_attempt_id(),
                host_id: host.id.as_str().to_owned(),
                expected_revision: host.revision,
                credential_reference: None,
                proxy_credential_reference: None,
                key_passphrase_reference: None,
                selected_identity_file_paths: vec![selected_path.to_owned()],
                known_hosts: Vec::new(),
                verify_host_keys: true,
                shell: None,
            },
        )
        .await
        .expect("explicitly selected key is prepared without reading it");
        assert_eq!(
            prepared.config.auth.identity_file_paths,
            vec![selected_path.to_owned()]
        );
        assert!(
            !prepared
                .config
                .auth
                .identity_file_paths
                .iter()
                .any(|path| path == imported_path)
        );
        assert_eq!(prepared.config.auth.use_ssh_agent, Some(false));
        assert_eq!(prepared.config.auth.identities_only, Some(true));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reference_key_identity_graph_imports_atomically_and_connects_only_with_reselection() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, controller) = desktop_state_with_memory_credentials(&current_vault);
        let referenced_path = r"\\never-open.invalid\share\reference-path-sentinel";
        let direct_path = r"Z:\missing\direct-path-sentinel";
        let selected_path = r"C:\user-selected\id_ed25519";
        let key_label = "key-label-sentinel";
        let identity_label = "identity-label-sentinel";
        let source = legacy_reference_graph_source(
            "graph.example.test",
            "Graph host",
            key_label,
            identity_label,
            referenced_path,
            direct_path,
        );

        let inspect_document =
            netcatty_migration::parse_legacy_vault(&source, 10).expect("graph inspection");
        let inspection = inspect_legacy_vault_document(state.clone(), inspect_document)
            .await
            .expect("graph assessment");
        assert_eq!(inspection.preview.importable_count, 1);
        assert_eq!(inspection.source_ssh_key_count, 1);
        assert_eq!(inspection.importable_ssh_key_reference_count, 1);
        assert_eq!(inspection.source_identity_count, 1);
        assert_eq!(inspection.importable_identity_reference_count, 1);
        assert_eq!(inspection.remapped_entity_count, 0);
        let inspection_json = serde_json::to_string(&inspection).expect("inspection JSON");
        for forbidden in [
            referenced_path,
            direct_path,
            key_label,
            identity_label,
            "legacy-graph-key",
            "legacy-graph-identity",
            "legacy-graph-host",
        ] {
            assert!(!inspection_json.contains(forbidden));
        }
        assert!(controller.operation_log().is_empty());

        let commit_document =
            netcatty_migration::parse_legacy_vault(&source, 10).expect("graph commit");
        let result =
            commit_legacy_vault_document(&state, inspection.inventory_revision, commit_document)
                .await
                .expect("atomic graph import");
        assert_eq!(result.imported_count, 1);
        assert_eq!(result.ssh_key_references_imported_count, 1);
        assert_eq!(result.identity_references_imported_count, 1);
        assert_eq!(result.credentials_stored_count, 0);
        assert_eq!(result.remapped_entity_count, 0);
        assert!(controller.operation_log().is_empty());
        assert_eq!(snapshot_count(&current_vault.join("saved-hosts")), 1);

        let graph = state.saved_hosts.graph().expect("saved graph");
        assert_eq!(graph.hosts().len(), 1);
        assert_eq!(graph.ssh_key_references().len(), 1);
        assert_eq!(graph.identity_references().len(), 1);
        let host = &graph.hosts()[0];
        let key = &graph.ssh_key_references()[0];
        let identity = &graph.identity_references()[0];
        assert_eq!(identity.key_id, key.id);
        assert_eq!(
            host.compatibility_fields()["identityId"],
            identity.id.as_str()
        );
        assert_eq!(
            host.compatibility_fields()["identityFileId"],
            key.id.as_str()
        );

        let prepared = prepare_test_saved_host_session(
            &state,
            "test-window",
            StartSavedHostSessionRequest {
                client_attempt_id: test_client_attempt_id(),
                host_id: host.id.as_str().to_owned(),
                expected_revision: host.revision,
                credential_reference: None,
                proxy_credential_reference: None,
                key_passphrase_reference: None,
                selected_identity_file_paths: vec![selected_path.to_owned()],
                known_hosts: Vec::new(),
                verify_host_keys: true,
                shell: None,
            },
        )
        .await
        .expect("selected key connection preparation");
        assert_eq!(
            prepared.config.auth.identity_file_paths,
            vec![selected_path.to_owned()]
        );
        assert!(
            !prepared
                .config
                .auth
                .identity_file_paths
                .iter()
                .any(|path| path == referenced_path || path == direct_path)
        );

        let repeat_document =
            netcatty_migration::parse_legacy_vault(&source, 10).expect("repeat inspection");
        let repeat = inspect_legacy_vault_document(state.clone(), repeat_document)
            .await
            .expect("idempotent graph assessment");
        assert_eq!(repeat.preview.importable_count, 0);
        assert_eq!(repeat.preview.duplicate_count, 1);
        assert_eq!(repeat.importable_ssh_key_reference_count, 0);
        assert_eq!(repeat.duplicate_ssh_key_reference_count, 1);
        assert_eq!(repeat.importable_identity_reference_count, 0);
        assert_eq!(repeat.duplicate_identity_reference_count, 1);
        let before = snapshot_count(&current_vault.join("saved-hosts"));
        let repeat_commit =
            netcatty_migration::parse_legacy_vault(&source, 10).expect("repeat commit");
        let repeat_result =
            commit_legacy_vault_document(&state, repeat.inventory_revision, repeat_commit)
                .await
                .expect("idempotent graph commit");
        assert_eq!(repeat_result.imported_count, 0);
        assert_eq!(repeat_result.ssh_key_references_imported_count, 0);
        assert_eq!(repeat_result.identity_references_imported_count, 0);
        assert_eq!(snapshot_count(&current_vault.join("saved-hosts")), before);
        assert!(controller.operation_log().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reference_graph_conflicts_are_fully_remapped_and_repeat_as_duplicates() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, controller) = desktop_state_with_memory_credentials(&current_vault);

        let current_source = legacy_reference_graph_source(
            "current-conflict.example.test",
            "Current graph host",
            "Current key label",
            "Current identity label",
            r"C:\current\reference-key",
            r"C:\current\direct-key",
        );
        let current_inspection_document =
            netcatty_migration::parse_legacy_vault(&current_source, 10)
                .expect("current graph inspection document");
        let current_inspection =
            inspect_legacy_vault_document(state.clone(), current_inspection_document)
                .await
                .expect("current graph inspection");
        let current_commit_document = netcatty_migration::parse_legacy_vault(&current_source, 10)
            .expect("current graph commit document");
        let current_result = commit_legacy_vault_document(
            &state,
            current_inspection.inventory_revision,
            current_commit_document,
        )
        .await
        .expect("seed current graph");
        assert_eq!(current_result.imported_count, 1);
        assert_eq!(current_result.ssh_key_references_imported_count, 1);
        assert_eq!(current_result.identity_references_imported_count, 1);
        assert_eq!(current_result.remapped_entity_count, 0);

        let current_graph = state.saved_hosts.graph().expect("current saved graph");
        let current_host = current_graph.hosts()[0].clone();
        let current_key = current_graph.ssh_key_references()[0].clone();
        let current_identity = current_graph.identity_references()[0].clone();

        let candidate_source_name = "candidate-conflict-source-path-sentinel.json";
        let candidate_source_path = directory.path().join(candidate_source_name);
        let candidate_hostname = "candidate-conflict.example.test";
        let candidate_host_label = "Candidate host label sentinel";
        let candidate_key_label = "Candidate key label sentinel";
        let candidate_identity_label = "Candidate identity label sentinel";
        let candidate_referenced_path = r"\\source.invalid\candidate-reference-path-sentinel";
        let candidate_direct_path = r"Z:\candidate\direct-path-sentinel";
        let candidate_source = legacy_reference_graph_source(
            candidate_hostname,
            candidate_host_label,
            candidate_key_label,
            candidate_identity_label,
            candidate_referenced_path,
            candidate_direct_path,
        );
        std::fs::write(&candidate_source_path, &candidate_source)
            .expect("candidate conflict source");
        let candidate_source_display = candidate_source_path.display().to_string();

        let inspection_document = load_legacy_vault_document(candidate_source_display.clone())
            .await
            .expect("conflicting graph inspection document");
        let inspection = inspect_legacy_vault_document(state.clone(), inspection_document)
            .await
            .expect("conflicting graph inspection");
        assert_eq!(inspection.preview.importable_count, 1);
        assert_eq!(inspection.preview.duplicate_count, 0);
        assert_eq!(inspection.preview.conflict_count, 0);
        assert_eq!(inspection.importable_ssh_key_reference_count, 1);
        assert_eq!(inspection.duplicate_ssh_key_reference_count, 0);
        assert_eq!(inspection.conflict_ssh_key_reference_count, 0);
        assert_eq!(inspection.importable_identity_reference_count, 1);
        assert_eq!(inspection.duplicate_identity_reference_count, 0);
        assert_eq!(inspection.conflict_identity_reference_count, 0);
        assert_eq!(inspection.remapped_entity_count, 3);
        let inspection_json = serde_json::to_string(&inspection).expect("inspection JSON");
        for forbidden in [
            candidate_source_name,
            candidate_source_display.as_str(),
            candidate_hostname,
            candidate_host_label,
            candidate_key_label,
            candidate_identity_label,
            candidate_referenced_path,
            candidate_direct_path,
            "legacy-graph-host",
            "legacy-graph-key",
            "legacy-graph-identity",
        ] {
            assert!(
                !inspection_json.contains(forbidden),
                "inspection leaked conflicting source material"
            );
        }
        assert!(controller.operation_log().is_empty());

        let commit_document = load_legacy_vault_document(candidate_source_display.clone())
            .await
            .expect("conflicting graph commit document");
        let result =
            commit_legacy_vault_document(&state, inspection.inventory_revision, commit_document)
                .await
                .expect("remapped graph import");
        assert_eq!(result.imported_count, 1);
        assert_eq!(result.ssh_key_references_imported_count, 1);
        assert_eq!(result.identity_references_imported_count, 1);
        assert_eq!(result.remapped_entity_count, 3);
        assert_eq!(result.duplicate_count, 0);
        assert_eq!(result.conflict_count, 0);
        assert_eq!(result.credentials_stored_count, 0);
        assert_eq!(snapshot_count(&current_vault.join("saved-hosts")), 2);
        assert!(controller.operation_log().is_empty());

        let imported_graph = state.saved_hosts.graph().expect("remapped saved graph");
        assert_eq!(imported_graph.hosts().len(), 2);
        assert_eq!(imported_graph.ssh_key_references().len(), 2);
        assert_eq!(imported_graph.identity_references().len(), 2);
        assert_eq!(
            imported_graph
                .hosts()
                .iter()
                .find(|host| host.id.as_str() == current_host.id.as_str()),
            Some(&current_host)
        );
        assert_eq!(
            imported_graph
                .ssh_key_references()
                .iter()
                .find(|key| key.id.as_str() == current_key.id.as_str()),
            Some(&current_key)
        );
        assert_eq!(
            imported_graph
                .identity_references()
                .iter()
                .find(|identity| identity.id.as_str() == current_identity.id.as_str()),
            Some(&current_identity)
        );

        let imported_host = imported_graph
            .hosts()
            .iter()
            .find(|host| host.hostname == candidate_hostname)
            .expect("remapped candidate host");
        let imported_key = imported_graph
            .ssh_key_references()
            .iter()
            .find(|key| key.label == candidate_key_label)
            .expect("remapped candidate key");
        let imported_identity = imported_graph
            .identity_references()
            .iter()
            .find(|identity| identity.label == candidate_identity_label)
            .expect("remapped candidate identity");
        for remapped_id in [
            imported_host.id.as_str(),
            imported_key.id.as_str(),
            imported_identity.id.as_str(),
        ] {
            assert_eq!(remapped_id.len(), 64);
            assert!(
                remapped_id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            );
            assert!(!remapped_id.starts_with("legacy-graph-"));
        }
        assert_ne!(imported_host.id.as_str(), imported_key.id.as_str());
        assert_ne!(imported_host.id.as_str(), imported_identity.id.as_str());
        assert_ne!(imported_key.id.as_str(), imported_identity.id.as_str());
        assert_eq!(imported_identity.key_id, imported_key.id);
        assert_eq!(
            imported_host.compatibility_fields()["identityId"],
            imported_identity.id.as_str()
        );
        assert_eq!(
            imported_host.compatibility_fields()["identityFileId"],
            imported_key.id.as_str()
        );

        let repeat_inspection_document =
            load_legacy_vault_document(candidate_source_display.clone())
                .await
                .expect("repeat graph inspection document");
        let repeat = inspect_legacy_vault_document(state.clone(), repeat_inspection_document)
            .await
            .expect("repeat remapped graph inspection");
        assert_eq!(repeat.preview.importable_count, 0);
        assert_eq!(repeat.preview.duplicate_count, 1);
        assert_eq!(repeat.preview.conflict_count, 0);
        assert_eq!(repeat.importable_ssh_key_reference_count, 0);
        assert_eq!(repeat.duplicate_ssh_key_reference_count, 1);
        assert_eq!(repeat.importable_identity_reference_count, 0);
        assert_eq!(repeat.duplicate_identity_reference_count, 1);
        assert_eq!(repeat.remapped_entity_count, 3);
        let snapshots_before_repeat = snapshot_count(&current_vault.join("saved-hosts"));
        let repeat_commit_document = load_legacy_vault_document(candidate_source_display)
            .await
            .expect("repeat graph commit document");
        let repeat_result =
            commit_legacy_vault_document(&state, repeat.inventory_revision, repeat_commit_document)
                .await
                .expect("repeat remapped graph commit");
        assert_eq!(repeat_result.imported_count, 0);
        assert_eq!(repeat_result.ssh_key_references_imported_count, 0);
        assert_eq!(repeat_result.identity_references_imported_count, 0);
        assert_eq!(repeat_result.duplicate_count, 1);
        assert_eq!(repeat_result.conflict_count, 0);
        assert_eq!(repeat_result.remapped_entity_count, 3);
        assert_eq!(
            snapshot_count(&current_vault.join("saved-hosts")),
            snapshots_before_repeat
        );
        assert_eq!(
            state.saved_hosts.graph().expect("graph after repeat"),
            imported_graph
        );
        assert!(controller.operation_log().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn password_identity_import_uses_final_remapped_owner_once_and_repeats_without_keyring() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, controller) = desktop_state_with_memory_credentials(&current_vault);
        let source_identity_id = "shared-password-identity-remap-sentinel";
        let old_secret = "old-password-identity-secret-sentinel";
        let new_secret = "new-password-identity-secret-sentinel";

        let seed = legacy_password_identity_source(
            source_identity_id,
            "Current password identity",
            "current-user",
            Some(json!(old_secret)),
            &[],
        );
        let seed_inspection = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&seed, 10).expect("seed inspection"),
        )
        .await
        .expect("seed identity assessment");
        let seed_result = commit_legacy_vault_document(
            &state,
            seed_inspection.inventory_revision,
            netcatty_migration::parse_legacy_vault(&seed, 10).expect("seed commit"),
        )
        .await
        .expect("seed password identity");
        assert_eq!(seed_result.password_identities_imported_count, 1);
        assert_eq!(seed_result.password_identity_credentials_stored_count, 1);
        assert_stored_secret(
            &state.persistent_credentials,
            &stored_identity_reference(source_identity_id),
            old_secret,
        )
        .await;

        controller.clear_operation_log();
        let candidate = legacy_password_identity_source(
            source_identity_id,
            "Candidate password identity",
            "candidate-user",
            Some(json!(new_secret)),
            &["shared-identity-host-a", "shared-identity-host-b"],
        );
        let inspection = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&candidate, 11).expect("candidate inspection"),
        )
        .await
        .expect("remapped identity assessment");
        assert_eq!(inspection.preview.importable_count, 2);
        assert_eq!(inspection.source_password_identity_count, 1);
        assert_eq!(inspection.importable_password_identity_count, 1);
        assert_eq!(inspection.recoverable_password_identity_credential_count, 1);
        assert_eq!(
            inspection.password_identity_credential_reentry_required_count,
            0
        );
        assert_eq!(inspection.remapped_entity_count, 1);
        let renderer_json = serde_json::to_string(&inspection).expect("inspection JSON");
        for forbidden in [
            source_identity_id,
            "Candidate password identity",
            "candidate-user",
            new_secret,
        ] {
            assert!(!renderer_json.contains(forbidden));
        }
        assert!(controller.operation_log().is_empty());

        let result = commit_legacy_vault_document(
            &state,
            inspection.inventory_revision,
            netcatty_migration::parse_legacy_vault(&candidate, 11).expect("candidate commit"),
        )
        .await
        .expect("remapped password identity import");
        assert_eq!(result.imported_count, 2);
        assert_eq!(result.password_identities_imported_count, 1);
        assert_eq!(result.credentials_stored_count, 1);
        assert_eq!(result.password_identity_credentials_stored_count, 1);
        assert_eq!(result.remapped_entity_count, 1);
        assert_eq!(
            controller
                .operation_log()
                .count(CredentialOperation::Upsert),
            1
        );

        let graph = state.saved_hosts.graph().expect("imported graph");
        let imported_identity = graph
            .password_identities()
            .iter()
            .find(|identity| identity.label == "Candidate password identity")
            .expect("remapped identity");
        assert_ne!(imported_identity.id.as_str(), source_identity_id);
        assert_eq!(imported_identity.id.as_str().len(), 64);
        assert!(imported_identity.has_saved_credential);
        for host in graph.hosts() {
            assert_eq!(
                host.compatibility_fields()["identityId"],
                imported_identity.id.as_str()
            );
        }
        let remapped_reference = stored_identity_reference(imported_identity.id.as_str());
        assert_stored_secret(
            &state.persistent_credentials,
            &remapped_reference,
            new_secret,
        )
        .await;
        assert_stored_secret(
            &state.persistent_credentials,
            &stored_identity_reference(source_identity_id),
            old_secret,
        )
        .await;

        controller.clear_operation_log();
        let repeat = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&candidate, 11).expect("repeat inspection"),
        )
        .await
        .expect("repeat identity assessment");
        assert_eq!(repeat.preview.importable_count, 0);
        assert_eq!(repeat.preview.duplicate_count, 2);
        assert_eq!(repeat.duplicate_password_identity_count, 1);
        assert_eq!(repeat.importable_password_identity_count, 0);
        let repeat_result = commit_legacy_vault_document(
            &state,
            repeat.inventory_revision,
            netcatty_migration::parse_legacy_vault(&candidate, 11).expect("repeat commit"),
        )
        .await
        .expect("idempotent password identity import");
        assert_eq!(repeat_result.imported_count, 0);
        assert_eq!(repeat_result.password_identities_imported_count, 0);
        assert_eq!(repeat_result.credentials_stored_count, 0);
        assert_eq!(repeat_result.password_identity_credentials_stored_count, 0);
        assert!(controller.operation_log().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unrecoverable_password_identity_imports_metadata_and_requires_one_reentry() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, controller) = desktop_state_with_memory_credentials(&current_vault);
        let ciphertext = "enc:v1:device-bound-password-identity-sentinel";
        let source = legacy_password_identity_source(
            "encrypted-password-identity",
            "Encrypted password identity",
            "encrypted-user",
            Some(json!(ciphertext)),
            &["encrypted-identity-host-a", "encrypted-identity-host-b"],
        );
        let inspection = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&source, 20).expect("inspection"),
        )
        .await
        .expect("encrypted identity assessment");
        assert_eq!(inspection.preview.importable_count, 2);
        assert_eq!(inspection.importable_password_identity_count, 1);
        assert_eq!(inspection.recoverable_password_identity_credential_count, 0);
        assert_eq!(
            inspection.password_identity_credential_reentry_required_count,
            1
        );
        assert!(
            !serde_json::to_string(&inspection)
                .expect("inspection JSON")
                .contains(ciphertext)
        );

        let result = commit_legacy_vault_document(
            &state,
            inspection.inventory_revision,
            netcatty_migration::parse_legacy_vault(&source, 20).expect("commit"),
        )
        .await
        .expect("metadata-only password identity import");
        assert_eq!(result.imported_count, 2);
        assert_eq!(result.password_identities_imported_count, 1);
        assert_eq!(result.credentials_stored_count, 0);
        assert_eq!(result.password_identity_credentials_stored_count, 0);
        assert_eq!(
            result.password_identity_credential_reentry_required_count,
            1
        );
        assert_eq!(result.requires_credential_reentry_count, 1);
        assert!(controller.operation_log().is_empty());
        let graph = state.saved_hosts.graph().expect("metadata graph");
        assert!(!graph.password_identities()[0].has_saved_credential);
        for bytes in persisted_files(&current_vault) {
            assert_bytes_do_not_contain(&bytes, ciphertext);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mixed_host_and_identity_owners_recover_together_after_final_write_failure() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, controller) = desktop_state_with_memory_credentials(&current_vault);
        let host_id = "mixed-owner-direct-host";
        let identity_host_id = "mixed-owner-identity-host";
        let identity_id = "mixed-owner-password-identity";
        let host_reference = stored_host_reference(host_id);
        let identity_reference = stored_identity_reference(identity_id);
        state
            .persistent_credentials
            .upsert(
                &host_reference,
                CredentialKind::SshPassword,
                test_secret("old-direct-host-secret-sentinel"),
            )
            .await
            .expect("seed host credential");
        state
            .persistent_credentials
            .upsert(
                &identity_reference,
                CredentialKind::SshPassword,
                test_secret("old-identity-secret-sentinel"),
            )
            .await
            .expect("seed identity credential");
        controller.clear_operation_log();

        let source = legacy_mixed_password_owner_source(host_id, identity_host_id, identity_id);
        let inspection = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&source, 30).expect("inspection"),
        )
        .await
        .expect("mixed-owner assessment");
        controller.set_failure(
            CredentialOperation::Upsert,
            4,
            FailureTiming::AfterSideEffect,
            CredentialErrorCode::BackendFailure,
        );
        controller.add_failure(
            CredentialOperation::Upsert,
            5,
            FailureTiming::BeforeSideEffect,
            CredentialErrorCode::StorageUnavailable,
        );

        let error = commit_legacy_vault_document(
            &state,
            inspection.inventory_revision,
            netcatty_migration::parse_legacy_vault(&source, 30).expect("commit"),
        )
        .await
        .expect_err("failed identity write and first repair must retain the journal");
        assert!(error.starts_with(super::LEGACY_VAULT_CREDENTIAL_FAILED));
        assert!(error.contains(super::LEGACY_VAULT_CREDENTIAL_REPAIR_FAILED));
        for forbidden in [
            host_id,
            identity_host_id,
            identity_id,
            "new-direct-host-secret-sentinel",
            "new-identity-secret-sentinel",
        ] {
            assert!(!error.contains(forbidden));
        }
        let pending = load_legacy_import_transaction(&state)
            .await
            .expect("load mixed-owner journal")
            .expect("journal retained for repair");
        assert_eq!(pending.phase(), LegacyImportTransactionPhase::Active);
        assert_eq!(pending.entries().len(), 2);
        assert_eq!(
            pending.entries()[0].owner_kind(),
            LegacyImportCredentialOwnerKind::Host
        );
        assert_eq!(
            pending.entries()[1].owner_kind(),
            LegacyImportCredentialOwnerKind::PasswordIdentity
        );
        drop(pending);
        assert!(
            state
                .saved_hosts
                .graph()
                .expect("before graph")
                .hosts()
                .is_empty()
        );

        controller.clear_failures();
        recover_pending_legacy_import(&state)
            .await
            .expect("mixed-owner rollback retry");
        assert_stored_secret(
            &state.persistent_credentials,
            &host_reference,
            "old-direct-host-secret-sentinel",
        )
        .await;
        assert_stored_secret(
            &state.persistent_credentials,
            &identity_reference,
            "old-identity-secret-sentinel",
        )
        .await;
        assert!(
            load_legacy_import_transaction(&state)
                .await
                .expect("load after repair")
                .is_none()
        );
        assert!(
            state
                .saved_hosts
                .graph()
                .expect("rolled-back graph")
                .hosts()
                .is_empty()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v5_four_owner_references_kinds_and_preparing_cleanup_are_isolated() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, _) = desktop_state_with_memory_credentials(directory.path());
        let id = SavedHostId::from_opaque("v5-shared-four-owner-id").expect("shared owner ID");
        let owners = four_legacy_credential_owners(&id);
        let snapshot = super::confirm_current_legacy_vault_snapshot(&state)
            .await
            .expect("durable before graph");
        let transaction = super::begin_legacy_import_transaction_for_owners(
            &state,
            owners.clone(),
            snapshot.commitment().clone(),
            netcatty_vault::SavedVaultGraphCommitment::from_digest([0xa5; 32]),
        )
        .await
        .expect("begin four-owner preparing transaction");

        let expected_kinds = [
            CredentialKind::SshPassword,
            CredentialKind::SshPassword,
            CredentialKind::ProxyPassword,
            CredentialKind::ProxyPassword,
        ];
        let mut references = Vec::new();
        for (index, (owner, expected_kind)) in owners.iter().zip(expected_kinds).enumerate() {
            assert_eq!(
                super::legacy_import_credential_kind_for_owner(owner),
                expected_kind
            );
            let (target, backup) =
                super::legacy_import_credential_references_for_owner(&transaction, owner)
                    .expect("derive isolated owner references");
            state
                .persistent_credentials
                .upsert(
                    &backup,
                    expected_kind,
                    test_secret(&format!("preparing-backup-{index}")),
                )
                .await
                .expect("seed preparing backup");
            references.push((target, backup, expected_kind));
        }
        for left in 0..references.len() {
            assert_ne!(references[left].0, references[left].1);
            for right in (left + 1)..references.len() {
                assert_ne!(references[left].0, references[right].0);
                assert_ne!(references[left].1, references[right].1);
                assert_ne!(references[left].0, references[right].1);
                assert_ne!(references[left].1, references[right].0);
            }
        }
        drop(transaction);

        super::recover_pending_legacy_import(&state)
            .await
            .expect("recover four-owner Preparing transaction");
        for (_, backup, kind) in references {
            assert_credential_missing_with_kind(&state.persistent_credentials, &backup, kind).await;
        }
        assert!(
            super::load_legacy_import_transaction(&state)
                .await
                .expect("load after preparing cleanup")
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v5_four_owner_active_recovery_restores_each_kind_and_cleans_backups() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, _) = desktop_state_with_memory_credentials(directory.path());
        let id =
            SavedHostId::from_opaque("v5-active-shared-four-owner-id").expect("shared owner ID");
        let owners = four_legacy_credential_owners(&id);
        let snapshot = super::confirm_current_legacy_vault_snapshot(&state)
            .await
            .expect("durable before graph");
        let preparing = super::begin_legacy_import_transaction_for_owners(
            &state,
            owners.clone(),
            snapshot.commitment().clone(),
            netcatty_vault::SavedVaultGraphCommitment::from_digest([0xa6; 32]),
        )
        .await
        .expect("begin four-owner Active transaction");

        let mut coordinates = Vec::new();
        let mut previous_states = Vec::new();
        for (index, owner) in owners.iter().enumerate() {
            let kind = super::legacy_import_credential_kind_for_owner(owner);
            let (target, backup) =
                super::legacy_import_credential_references_for_owner(&preparing, owner)
                    .expect("derive active owner references");
            let old = format!("active-old-{index}");
            state
                .persistent_credentials
                .upsert(&target, kind, test_secret(&old))
                .await
                .expect("seed final credential");
            let previous = state
                .persistent_credentials
                .resolve(&target, kind)
                .await
                .expect("probe final credential");
            state
                .persistent_credentials
                .upsert(&backup, kind, previous)
                .await
                .expect("backup final credential");
            previous_states.push((owner.clone(), LegacyPreviousCredentialState::BackedUp));
            coordinates.push((target, backup, kind, old));
        }
        let active =
            super::activate_legacy_import_transaction_for_owners(preparing, previous_states)
                .await
                .expect("dual-publish four-owner Active transaction");
        for (index, (target, _, kind, _)) in coordinates.iter().enumerate() {
            state
                .persistent_credentials
                .upsert(target, *kind, test_secret(&format!("active-new-{index}")))
                .await
                .expect("mutate final credential");
        }
        drop(active);

        super::recover_pending_legacy_import(&state)
            .await
            .expect("rollback mixed four-owner Active transaction");
        for (target, backup, kind, old) in coordinates {
            assert_stored_secret_with_kind(&state.persistent_credentials, &target, kind, &old)
                .await;
            assert_credential_missing_with_kind(&state.persistent_credentials, &backup, kind).await;
        }
        assert!(
            super::load_legacy_import_transaction(&state)
                .await
                .expect("load after active rollback")
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v5_proxy_backup_kind_mismatch_fails_closed_with_safe_diagnostics() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, _) = desktop_state_with_memory_credentials(directory.path());
        let id =
            SavedHostId::from_opaque("proxy-kind-mismatch-owner-sentinel").expect("proxy owner ID");
        let owner = super::LegacyImportCredentialOwner::for_host_inline_proxy(&id);
        let snapshot = super::confirm_current_legacy_vault_snapshot(&state)
            .await
            .expect("durable before graph");
        let preparing = super::begin_legacy_import_transaction_for_owners(
            &state,
            vec![owner.clone()],
            snapshot.commitment().clone(),
            netcatty_vault::SavedVaultGraphCommitment::from_digest([0xa7; 32]),
        )
        .await
        .expect("begin kind-mismatch transaction");
        let (_, backup) = super::legacy_import_credential_references_for_owner(&preparing, &owner)
            .expect("derive proxy backup");
        state
            .persistent_credentials
            .upsert(
                &backup,
                CredentialKind::SshPassword,
                test_secret("wrong-kind-backup-secret-sentinel"),
            )
            .await
            .expect("seed wrong-kind backup");
        let active = super::activate_legacy_import_transaction_for_owners(
            preparing,
            vec![(owner, LegacyPreviousCredentialState::BackedUp)],
        )
        .await
        .expect("activate kind-mismatch transaction");
        drop(active);

        let error = super::recover_pending_legacy_import(&state)
            .await
            .expect_err("wrong backup kind must fail closed");
        assert_eq!(error, super::legacy_credential_repair_error());
        assert!(!error.contains(id.as_str()));
        assert!(!error.contains("wrong-kind-backup-secret-sentinel"));
        assert_eq!(
            super::load_legacy_import_transaction(&state)
                .await
                .expect("load retained mismatch transaction")
                .expect("mismatch journal retained")
                .phase(),
            LegacyImportTransactionPhase::Active
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v5_four_owner_single_slot_vault_durable_recovery_cleans_backups_and_journal() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let (state, _) = desktop_state_with_memory_credentials(directory.path());
        let id =
            SavedHostId::from_opaque("v5-terminal-shared-four-owner-id").expect("shared owner ID");
        let owners = four_legacy_credential_owners(&id);
        let snapshot = super::confirm_current_legacy_vault_snapshot(&state)
            .await
            .expect("durable before graph");
        let preparing = super::begin_legacy_import_transaction_for_owners(
            &state,
            owners.clone(),
            snapshot.commitment().clone(),
            netcatty_vault::SavedVaultGraphCommitment::from_digest([0xa8; 32]),
        )
        .await
        .expect("begin four-owner terminal transaction");
        let mut backups = Vec::new();
        let mut previous_states = Vec::new();
        for (index, owner) in owners.iter().enumerate() {
            let kind = super::legacy_import_credential_kind_for_owner(owner);
            let (_, backup) =
                super::legacy_import_credential_references_for_owner(&preparing, owner)
                    .expect("derive terminal backup");
            state
                .persistent_credentials
                .upsert(
                    &backup,
                    kind,
                    test_secret(&format!("terminal-backup-{index}")),
                )
                .await
                .expect("seed terminal backup");
            backups.push((backup, kind));
            previous_states.push((owner.clone(), LegacyPreviousCredentialState::BackedUp));
        }
        let active =
            super::activate_legacy_import_transaction_for_owners(preparing, previous_states)
                .await
                .expect("dual-publish terminal Active transaction");
        let durable = super::mark_legacy_vault_durable(active)
            .await
            .expect("dual-publish terminal VaultDurable transaction");
        drop(durable);

        let older_slot = state
            .legacy_import_transaction_root
            .join("legacy-credential-import-transaction-b.json");
        std::fs::remove_file(&older_slot).expect("simulate crash after old terminal slot deletion");
        super::recover_pending_legacy_import(&state)
            .await
            .expect("recover single-slot terminal transaction");
        for (backup, kind) in backups {
            assert_credential_missing_with_kind(&state.persistent_credentials, &backup, kind).await;
        }
        assert!(
            super::load_legacy_import_transaction(&state)
                .await
                .expect("load after terminal cleanup")
                .is_none()
        );
    }

    #[test]
    fn ssh_client_attempt_ids_are_required_bounded_safe_and_preserved() {
        let exact = "Attempt:route_1.2-123e4567-e89b-42d3-a456-426614174000";
        assert_eq!(
            ClientAttemptId::parse(exact.to_owned())
                .expect("valid client attempt ID")
                .as_str(),
            exact
        );
        assert!(ClientAttemptId::parse("a".repeat(128)).is_ok());
        for invalid in [
            String::new(),
            "-leading-dash".to_owned(),
            " attempt".to_owned(),
            "attempt ".to_owned(),
            "attempt/other".to_owned(),
            "attempt\nother".to_owned(),
            "尝试".to_owned(),
            "a".repeat(129),
        ] {
            assert_eq!(
                ClientAttemptId::parse(invalid),
                Err(super::SSH_CLIENT_ATTEMPT_ID_INVALID)
            );
        }

        let quick = json!({
            "clientAttemptId": exact,
            "config": {
                "hostname": "quick.example.test",
                "username": "alice",
                "auth": { "method": "password", "hasPassword": true }
            },
            "credentialReference": EphemeralCredentialReference::new()
        });
        let parsed = serde_json::from_value::<StartSshSessionRequest>(quick.clone())
            .expect("valid Quick SSH attempt ID");
        assert_eq!(parsed.client_attempt_id.as_str(), exact);
        let mut missing_quick = quick.clone();
        missing_quick
            .as_object_mut()
            .expect("Quick SSH request")
            .remove("clientAttemptId");
        assert!(serde_json::from_value::<StartSshSessionRequest>(missing_quick).is_err());
        let mut unsafe_quick = quick;
        unsafe_quick["clientAttemptId"] = json!("attempt/unsafe");
        assert!(serde_json::from_value::<StartSshSessionRequest>(unsafe_quick).is_err());

        let saved = json!({
            "clientAttemptId": exact,
            "hostId": "host-1",
            "expectedRevision": 7
        });
        let parsed = serde_json::from_value::<StartSavedHostSessionRequest>(saved.clone())
            .expect("valid SavedHost SSH attempt ID");
        assert_eq!(parsed.client_attempt_id.as_str(), exact);
        let mut missing_saved = saved.clone();
        missing_saved
            .as_object_mut()
            .expect("SavedHost SSH request")
            .remove("clientAttemptId");
        assert!(serde_json::from_value::<StartSavedHostSessionRequest>(missing_saved).is_err());
        let mut unsafe_saved = saved;
        unsafe_saved["clientAttemptId"] = json!("attempt with spaces");
        assert!(serde_json::from_value::<StartSavedHostSessionRequest>(unsafe_saved).is_err());
    }

    #[test]
    fn saved_host_json_commands_reject_plaintext_password_fields() {
        let reference = EphemeralCredentialReference::new().to_string();
        let valid = json!({
            "draft": {
                "label": "Production",
                "hostname": "server.example.test",
                "port": 22,
                "username": "alice"
            },
            "stagedCredentialReference": reference
        });
        serde_json::from_value::<CreateSavedHostRequest>(valid.clone()).expect("safe request");

        let mut unsafe_top_level = valid.clone();
        unsafe_top_level["password"] = json!("must-not-enter-json");
        assert!(serde_json::from_value::<CreateSavedHostRequest>(unsafe_top_level).is_err());

        let mut unsafe_draft = valid;
        unsafe_draft["draft"]["password"] = json!("must-not-enter-json");
        assert!(serde_json::from_value::<CreateSavedHostRequest>(unsafe_draft).is_err());

        let valid_inline_proxy = json!({
            "draft": {
                "label": "Proxied production",
                "hostname": "proxied.example.test",
                "port": 22,
                "username": "alice",
                "proxy": {
                    "inlineProxy": {
                        "action": "replace",
                        "config": {
                            "type": "http",
                            "host": "proxy.example.test",
                            "port": 8080,
                            "auth": {
                                "mode": "manual",
                                "username": "proxy-user",
                                "credentialMutation": { "action": "keep" }
                            }
                        }
                    },
                    "profile": { "action": "remove" }
                }
            }
        });
        serde_json::from_value::<CreateSavedHostRequest>(valid_inline_proxy.clone())
            .expect("typed inline proxy mutation");
        let mut unsafe_inline_proxy = valid_inline_proxy;
        unsafe_inline_proxy["draft"]["proxy"]["inlineProxy"]["password"] =
            json!("plaintext-proxy-password-must-not-enter-json");
        assert!(serde_json::from_value::<CreateSavedHostRequest>(unsafe_inline_proxy).is_err());

        let saved_start = json!({
            "clientAttemptId": "attempt-saved-host-contract",
            "hostId": "host-1",
            "expectedRevision": 7,
            "verifyHostKeys": true
        });
        serde_json::from_value::<StartSavedHostSessionRequest>(saved_start.clone())
            .expect("revision-bound saved start");
        let mut proxy_start = saved_start.clone();
        proxy_start["proxyCredentialReference"] = json!(EphemeralCredentialReference::new());
        serde_json::from_value::<StartSavedHostSessionRequest>(proxy_start)
            .expect("one-shot proxy credential reference");
        let mut key_start = saved_start.clone();
        key_start["selectedIdentityFilePaths"] = json!(["C:\\selected\\id_ed25519"]);
        serde_json::from_value::<StartSavedHostSessionRequest>(key_start)
            .expect("explicitly selected key path");
        let mut missing_revision = saved_start.clone();
        missing_revision
            .as_object_mut()
            .expect("request object")
            .remove("expectedRevision");
        assert!(serde_json::from_value::<StartSavedHostSessionRequest>(missing_revision).is_err());
        let mut unsafe_start = saved_start;
        unsafe_start["password"] = json!("must-not-enter-json");
        assert!(serde_json::from_value::<StartSavedHostSessionRequest>(unsafe_start).is_err());
        let unsafe_imported_path = json!({
            "clientAttemptId": "attempt-unsafe-imported-path",
            "hostId": "host-1",
            "expectedRevision": 7,
            "identityFilePaths": ["C:\\unconfirmed\\legacy-key"]
        });
        assert!(
            serde_json::from_value::<StartSavedHostSessionRequest>(unsafe_imported_path).is_err()
        );
    }

    #[test]
    fn legacy_import_json_contract_rejects_extra_or_secret_fields() {
        let inspect = json!({ "path": "C:\\backup\\vault.json" });
        serde_json::from_value::<InspectLegacyVaultRequest>(inspect.clone())
            .expect("safe inspection request");
        let mut unsafe_inspect = inspect;
        unsafe_inspect["password"] = json!("must-not-enter-json");
        assert!(serde_json::from_value::<InspectLegacyVaultRequest>(unsafe_inspect).is_err());

        let commit = json!({
            "path": "C:\\backup\\vault.json",
            "sourceFingerprint": "00",
            "inventoryRevision": {
                "storeId": "opaque",
                "loadedGeneration": 0,
                "maxSeenGeneration": 0,
                "seal": "00"
            }
        });
        serde_json::from_value::<CommitLegacyVaultImportRequest>(commit.clone())
            .expect("safe commit request");
        let mut unsafe_commit = commit;
        unsafe_commit["sourceContents"] = json!("must-not-enter-json");
        assert!(serde_json::from_value::<CommitLegacyVaultImportRequest>(unsafe_commit).is_err());

        assert!(validate_legacy_source_fingerprint(&"a5".repeat(32)).is_ok());
        assert!(validate_legacy_source_fingerprint(&"A5".repeat(32)).is_ok());
        assert!(validate_legacy_source_fingerprint(&"a5".repeat(31)).is_err());
        assert!(validate_legacy_source_fingerprint(&format!("{}0", "a5".repeat(32))).is_err());
        assert!(validate_legacy_source_fingerprint(&format!(" {}", "a5".repeat(32))).is_err());
        assert!(validate_legacy_source_fingerprint(&"zz".repeat(32)).is_err());
        assert!(validate_legacy_source_fingerprint(&"é".repeat(32)).is_err());
        assert!(validate_legacy_source_fingerprint(&"a".repeat(4_096)).is_err());

        let raw_sha256 = [0xa5; 32];
        let raw_sha256_hex = "a5".repeat(32);
        let sealed = legacy_source_fingerprint_token(&raw_sha256);
        assert_ne!(sealed, raw_sha256_hex);
        assert_eq!(
            sealed,
            legacy_source_fingerprint_token(&raw_sha256),
            "the process-static key must keep an inspection token stable within one run"
        );
        assert!(verify_legacy_source_fingerprint(&raw_sha256, &sealed));
        assert!(!verify_legacy_source_fingerprint(
            &raw_sha256,
            &raw_sha256_hex
        ));
        assert!(!verify_legacy_source_fingerprint(&[0xa4; 32], &sealed));
        let mut tampered = sealed.into_bytes();
        tampered[0] = if tampered[0] == b'0' { b'1' } else { b'0' };
        assert!(!verify_legacy_source_fingerprint(
            &raw_sha256,
            std::str::from_utf8(&tampered).expect("ASCII token"),
        ));
    }

    #[test]
    fn legacy_vault_reader_rejects_non_files_and_oversized_sources() {
        let directory = tempfile::tempdir().expect("temporary import directory");
        assert!(read_legacy_vault_file(directory.path()).is_err());

        let oversized = directory.path().join("oversized.json");
        let file = std::fs::File::create(&oversized).expect("oversized fixture");
        file.set_len((netcatty_migration::MAX_LEGACY_BACKUP_BYTES + 1) as u64)
            .expect("sparse fixture length");
        assert!(read_legacy_vault_file(&oversized).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_reparse_attribute_and_available_symlinks_are_rejected() {
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        assert!(super::legacy_file_attributes_are_reparse_point(
            FILE_ATTRIBUTE_REPARSE_POINT
        ));
        assert!(super::legacy_file_attributes_are_reparse_point(
            FILE_ATTRIBUTE_REPARSE_POINT | 0x20
        ));
        assert!(!super::legacy_file_attributes_are_reparse_point(0x20));

        let directory = tempfile::tempdir().expect("temporary reparse directory");
        let target = directory.path().join("target.json");
        let link = directory.path().join("link.json");
        std::fs::write(&target, b"[]").expect("symlink target");
        match std::os::windows::fs::symlink_file(&target, &link) {
            Ok(()) => {
                let metadata = std::fs::symlink_metadata(&link).expect("link metadata");
                assert!(super::legacy_source_is_reparse_point(&metadata));
                let error = match read_legacy_vault_file(&link) {
                    Ok(_) => panic!("reparse source must fail"),
                    Err(error) => error,
                };
                assert!(error.starts_with(super::LEGACY_VAULT_SOURCE_NOT_REGULAR));
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::PermissionDenied
                    || error.raw_os_error() == Some(1314) =>
            {
                // Windows without Developer Mode may forbid unprivileged test
                // symlink creation. The attribute predicate above still
                // covers the platform-specific fail-closed decision.
            }
            Err(error) => panic!("unexpected symlink creation failure: {error}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn legacy_source_errors_never_echo_contents_or_source_path() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let source_name = "opaque-source-path-must-not-be-returned.json";
        let source_path = directory.path().join(source_name);
        let plaintext = "invalid-json-plaintext-password";
        let ciphertext = "enc:v1:invalid-json-ciphertext";
        let credential_reference = "invalid-json-credential-reference";
        let identity_reference = "invalid-json-identity-reference";
        std::fs::write(
            &source_path,
            format!(
                r#"{{"password":"{plaintext}","cipher":"{ciphertext}","credentialRef":"{credential_reference}","identityId":"{identity_reference}""#
            ),
        )
        .expect("invalid legacy fixture");

        let error = load_legacy_vault_document(source_path.display().to_string())
            .await
            .err()
            .expect("invalid source must fail");
        let encoded = serde_json::to_string(&error).expect("error JSON");
        for forbidden in [
            plaintext,
            ciphertext,
            credential_reference,
            identity_reference,
            source_name,
            &source_path.display().to_string(),
        ] {
            assert!(!encoded.contains(forbidden), "error leaked source material");
        }

        let missing_name = "missing-source-path-must-not-be-returned.json";
        let missing = directory.path().join(missing_name);
        let missing_error = load_legacy_vault_document(missing.display().to_string())
            .await
            .err()
            .expect("missing source must fail");
        let missing_encoded = serde_json::to_string(&missing_error).expect("missing error JSON");
        assert!(!missing_encoded.contains(missing_name));
        assert!(!missing_encoded.contains(&missing.display().to_string()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn safe_storage_preview_and_commit_rejection_never_echo_ciphertext() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let source_name = "safe-storage-source-path-must-not-return.json";
        let source_path = directory.path().join(source_name);
        let ciphertext = "safe-storage-ciphertext-must-never-return-or-persist";
        let source_bytes = serde_json::to_vec(&json!({
            "formatVersion": 1,
            "payloadEncoding": "safeStorage-v1",
            "payloadData": ciphertext
        }))
        .expect("safeStorage fixture JSON");
        let raw_sha256: [u8; 32] = Sha256::digest(&source_bytes).into();
        let raw_sha256_hex = hex_encode(&raw_sha256);
        std::fs::write(&source_path, &source_bytes).expect("safeStorage fixture");
        let current_vault = directory.path().join("current");
        let state = DesktopState::open(&current_vault).expect("desktop state");

        let inspect_document = load_legacy_vault_document(source_path.display().to_string())
            .await
            .expect("safeStorage document");
        let inspection = inspect_legacy_vault_document(state.clone(), inspect_document)
            .await
            .expect("safeStorage inspection");
        let inspection_json = serde_json::to_string(&inspection).expect("inspection JSON");
        assert!(inspection.preview.source_recovery_required());
        assert_ne!(inspection.source_fingerprint, raw_sha256_hex);
        assert!(verify_legacy_source_fingerprint(
            &raw_sha256,
            &inspection.source_fingerprint
        ));
        assert!(!inspection_json.contains(&raw_sha256_hex));
        assert!(!inspection_json.contains(ciphertext));
        assert!(!inspection_json.contains(source_name));
        assert!(!inspection_json.contains(&source_path.display().to_string()));

        let commit_document = load_legacy_vault_document(source_path.display().to_string())
            .await
            .expect("safeStorage commit document");
        let error =
            commit_legacy_vault_document(&state, inspection.inventory_revision, commit_document)
                .await
                .expect_err("safeStorage backup must not commit");
        let error_json = serde_json::to_string(&error).expect("commit error JSON");
        assert!(error.contains(super::LEGACY_VAULT_RECOVERY_REQUIRED));
        assert!(!error_json.contains(ciphertext));
        assert!(!error_json.contains(source_name));
        assert!(!error_json.contains(&source_path.display().to_string()));
        assert!(state.saved_hosts.list().expect("saved hosts").is_empty());
        assert_eq!(snapshot_count(&current_vault.join("saved-hosts")), 0);
    }

    #[test]
    fn legacy_reentry_count_includes_missing_and_policy_disabled_passwords() {
        assert!(disposition_requires_credential_reentry(
            netcatty_migration::LegacyCredentialDisposition::ReentryRequiredMissing
        ));
        assert!(disposition_requires_credential_reentry(
            netcatty_migration::LegacyCredentialDisposition::NotSavedByPolicy
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn duplicate_candidate_assessment_fails_without_echoing_opaque_id() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let state = DesktopState::open(&current_vault).expect("desktop state");
        let host = state
            .saved_hosts
            .create(netcatty_vault::SavedHostDraft::ssh_password(
                "duplicate.example.test",
                "user",
            ))
            .expect("saved host");
        let opaque_id = host.id.as_str().to_owned();
        let duplicate_batch = vec![host.clone(), host];
        let before = snapshot_count(&current_vault.join("saved-hosts"));
        let error = super::assess_legacy_hosts(state.saved_hosts.clone(), duplicate_batch.clone())
            .await
            .expect_err("duplicate assessment batch must fail closed");

        assert!(error.contains(super::LEGACY_VAULT_ASSESSMENT_FAILED));
        assert!(!error.contains(&opaque_id));

        let revision = state
            .saved_hosts
            .assess_import(&[])
            .expect("empty assessment")
            .into_revision();
        assert!(
            state
                .saved_hosts
                .commit_import(revision, duplicate_batch)
                .is_err(),
            "duplicate commit batch must fail closed"
        );
        assert_eq!(snapshot_count(&current_vault.join("saved-hosts")), before);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn plaintext_final_metadata_is_idempotent_without_accessing_the_os_keyring() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let state = DesktopState::open(&current_vault).expect("desktop state");
        let plaintext = "idempotent-plaintext-that-must-never-persist";
        let source = format!(
            r#"[{{"id":"legacy-idempotent","hostname":"idempotent.example.test","username":"alice","protocol":"ssh","authMethod":"password","authPolicyVersion":1,"savePassword":true,"password":"{plaintext}"}}]"#
        );

        let seed_document =
            netcatty_migration::parse_legacy_vault(source.as_bytes(), 10).expect("seed document");
        let seed_candidate = seed_document
            .into_candidates()
            .pop()
            .expect("seed candidate");
        let assessed_host =
            legacy_candidate_for_assessment(&seed_candidate).expect("assessment host");
        assert_eq!(
            assessed_host
                .compatibility_fields()
                .get("hasSavedCredential"),
            Some(&serde_json::Value::Bool(true))
        );
        let (raw_host, secret, disposition) = seed_candidate.into_parts();
        assert_eq!(
            disposition,
            netcatty_migration::LegacyCredentialDisposition::PlaintextCandidate
        );
        let prepared_host = super::saved_host_with_credential_hint(raw_host, secret.is_some())
            .expect("prepared host");
        assert_eq!(assessed_host, prepared_host);
        drop(secret);

        let seed_revision = state
            .saved_hosts
            .assess_import(std::slice::from_ref(&assessed_host))
            .expect("seed assessment")
            .into_revision();
        state
            .saved_hosts
            .commit_import(seed_revision, vec![assessed_host])
            .expect("seed final metadata");
        let before = snapshot_count(&current_vault.join("saved-hosts"));

        let inspect_document = netcatty_migration::parse_legacy_vault(source.as_bytes(), 10)
            .expect("inspection document");
        let inspection = inspect_legacy_vault_document(state.clone(), inspect_document)
            .await
            .expect("duplicate inspection");
        assert_eq!(inspection.preview.importable_count, 0);
        assert_eq!(inspection.preview.duplicate_count, 1);
        assert_eq!(inspection.preview.conflict_count, 0);
        assert_eq!(inspection.preview.recoverable_credential_count, 0);

        let commit_document =
            netcatty_migration::parse_legacy_vault(source.as_bytes(), 10).expect("commit document");
        let result =
            commit_legacy_vault_document(&state, inspection.inventory_revision, commit_document)
                .await
                .expect("idempotent duplicate commit");
        assert_eq!(result.imported_count, 0);
        assert_eq!(result.duplicate_count, 1);
        assert_eq!(result.conflict_count, 0);
        assert_eq!(result.credentials_stored_count, 0);
        assert_eq!(snapshot_count(&current_vault.join("saved-hosts")), before);
        for bytes in persisted_files(&current_vault.join("saved-hosts")) {
            assert_bytes_do_not_contain(&bytes, plaintext);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn plaintext_final_metadata_conflicts_with_existing_false_credential_hint() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let state = DesktopState::open(&current_vault).expect("desktop state");
        let source = br#"[{"id":"legacy-hint-conflict","hostname":"conflict.example.test","username":"alice","protocol":"ssh","authMethod":"password","authPolicyVersion":1,"savePassword":true,"password":"never-touch-keyring"}]"#;

        let seed_document =
            netcatty_migration::parse_legacy_vault(source, 10).expect("seed document");
        let false_hint_host = seed_document.candidates()[0].host().clone();
        assert_eq!(
            false_hint_host
                .compatibility_fields()
                .get("hasSavedCredential"),
            Some(&serde_json::Value::Bool(false))
        );
        drop(seed_document);
        let seed_revision = state
            .saved_hosts
            .assess_import(std::slice::from_ref(&false_hint_host))
            .expect("seed assessment")
            .into_revision();
        state
            .saved_hosts
            .commit_import(seed_revision, vec![false_hint_host])
            .expect("seed false metadata");
        let before = snapshot_count(&current_vault.join("saved-hosts"));

        let inspect_document =
            netcatty_migration::parse_legacy_vault(source, 10).expect("inspection document");
        let inspection = inspect_legacy_vault_document(state.clone(), inspect_document)
            .await
            .expect("conflict inspection");
        assert_eq!(inspection.preview.importable_count, 0);
        assert_eq!(inspection.preview.duplicate_count, 0);
        assert_eq!(inspection.preview.conflict_count, 1);

        let commit_document =
            netcatty_migration::parse_legacy_vault(source, 10).expect("commit document");
        let result =
            commit_legacy_vault_document(&state, inspection.inventory_revision, commit_document)
                .await
                .expect("conflicting record is skipped");
        assert_eq!(result.imported_count, 0);
        assert_eq!(result.conflict_count, 1);
        assert_eq!(result.credentials_stored_count, 0);
        assert_eq!(snapshot_count(&current_vault.join("saved-hosts")), before);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn duplicate_conflict_and_stale_imports_never_access_credentials() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, controller) = desktop_state_with_memory_credentials(&current_vault);
        let source = legacy_plaintext_batch(&["legacy-duplicate", "legacy-conflict"]);
        let seed_document =
            netcatty_migration::parse_legacy_vault(&source, 10).expect("seed legacy document");
        let mut seed_hosts = seed_document
            .candidates()
            .iter()
            .map(legacy_candidate_for_assessment)
            .collect::<Result<Vec<_>, _>>()
            .expect("assessment hosts");
        let mut conflicting = serde_json::to_value(seed_hosts.pop().expect("conflict host"))
            .expect("serialize conflict host");
        conflicting.as_object_mut().expect("host object").insert(
            "hostname".to_owned(),
            serde_json::Value::String("different.example.test".to_owned()),
        );
        seed_hosts.push(serde_json::from_value(conflicting).expect("conflicting current host"));
        let seed_revision = state
            .saved_hosts
            .assess_import(&seed_hosts)
            .expect("seed assessment")
            .into_revision();
        state
            .saved_hosts
            .commit_import(seed_revision, seed_hosts)
            .expect("seed current hosts");

        let inspect_document =
            netcatty_migration::parse_legacy_vault(&source, 10).expect("inspection document");
        let inspection = inspect_legacy_vault_document(state.clone(), inspect_document)
            .await
            .expect("inspection");
        assert_eq!(inspection.preview.importable_count, 0);
        assert_eq!(inspection.preview.duplicate_count, 1);
        assert_eq!(inspection.preview.conflict_count, 1);
        let commit_document =
            netcatty_migration::parse_legacy_vault(&source, 10).expect("commit document");
        let result =
            commit_legacy_vault_document(&state, inspection.inventory_revision, commit_document)
                .await
                .expect("duplicate/conflict records are skipped");
        assert_eq!(result.imported_count, 0);
        assert_eq!(result.duplicate_count, 1);
        assert_eq!(result.conflict_count, 1);
        assert!(controller.operation_log().is_empty());

        let stale_source = legacy_plaintext_batch(&["legacy-stale"]);
        let stale_document = netcatty_migration::parse_legacy_vault(&stale_source, 10)
            .expect("stale inspection document");
        let stale_inspection = inspect_legacy_vault_document(state.clone(), stale_document)
            .await
            .expect("stale inspection");
        state
            .saved_hosts
            .create(netcatty_vault::SavedHostDraft::ssh_password(
                "concurrent.example.test",
                "user",
            ))
            .expect("concurrent saved host");
        let stale_commit = netcatty_migration::parse_legacy_vault(&stale_source, 10)
            .expect("stale commit document");
        let error =
            commit_legacy_vault_document(&state, stale_inspection.inventory_revision, stale_commit)
                .await
                .expect_err("stale inventory must fail before credentials");
        assert!(error.contains(LEGACY_VAULT_INVENTORY_CHANGED));
        assert!(controller.operation_log().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn second_resolve_failure_never_writes_final_credentials_and_cleans_backups() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, controller) = desktop_state_with_memory_credentials(&current_vault);
        let source = legacy_plaintext_batch(&["legacy-resolve-a", "legacy-resolve-b"]);
        let inspect_document =
            netcatty_migration::parse_legacy_vault(&source, 10).expect("inspection document");
        let inspection = inspect_legacy_vault_document(state.clone(), inspect_document)
            .await
            .expect("inspection");
        controller.set_failure(
            CredentialOperation::Resolve,
            2,
            FailureTiming::BeforeSideEffect,
            CredentialErrorCode::StorageUnavailable,
        );

        let commit_document =
            netcatty_migration::parse_legacy_vault(&source, 10).expect("commit document");
        let error =
            commit_legacy_vault_document(&state, inspection.inventory_revision, commit_document)
                .await
                .expect_err("second resolve must abort the transaction");
        assert!(error.contains(super::LEGACY_VAULT_CREDENTIAL_FAILED));
        assert!(!error.contains(super::LEGACY_VAULT_CREDENTIAL_REPAIR_FAILED));
        assert!(!error.contains("new-secret-0"));
        assert!(!error.contains("legacy-resolve-a"));
        assert!(state.saved_hosts.list().expect("saved hosts").is_empty());
        assert_eq!(snapshot_count(&current_vault.join("saved-hosts")), 0);
        let operations = controller
            .operation_log()
            .entries()
            .iter()
            .map(|entry| entry.operation())
            .collect::<Vec<_>>();
        assert_eq!(
            operations,
            vec![
                CredentialOperation::Resolve,
                CredentialOperation::Resolve,
                CredentialOperation::Delete,
                CredentialOperation::Delete,
            ]
        );

        controller.clear_failures();
        for id in ["legacy-resolve-a", "legacy-resolve-b"] {
            let error = state
                .persistent_credentials
                .resolve(&stored_host_reference(id), CredentialKind::SshPassword)
                .await
                .err()
                .expect("rolled-back credential must be absent");
            assert_eq!(error.code(), CredentialErrorCode::NotFound);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn after_effect_upsert_failure_restores_old_secrets_in_reverse_order() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, controller) = desktop_state_with_memory_credentials(&current_vault);
        let first_reference = stored_host_reference("legacy-upsert-a");
        let second_reference = stored_host_reference("legacy-upsert-b");
        state
            .persistent_credentials
            .upsert(
                &second_reference,
                CredentialKind::SshPassword,
                SecretValue::from_utf8("old-secret-b".to_owned()).expect("old secret"),
            )
            .await
            .expect("seed second credential");
        controller.clear_operation_log();

        let source = legacy_plaintext_batch(&["legacy-upsert-a", "legacy-upsert-b"]);
        let inspect_document =
            netcatty_migration::parse_legacy_vault(&source, 10).expect("inspection document");
        let inspection = inspect_legacy_vault_document(state.clone(), inspect_document)
            .await
            .expect("inspection");
        controller.set_failure(
            CredentialOperation::Upsert,
            3,
            FailureTiming::AfterSideEffect,
            CredentialErrorCode::BackendFailure,
        );

        let commit_document =
            netcatty_migration::parse_legacy_vault(&source, 10).expect("commit document");
        let error =
            commit_legacy_vault_document(&state, inspection.inventory_revision, commit_document)
                .await
                .expect_err("after-effect failure must compensate");
        assert!(error.contains(super::LEGACY_VAULT_CREDENTIAL_FAILED));
        assert!(!error.contains(super::LEGACY_VAULT_CREDENTIAL_REPAIR_FAILED));
        assert!(state.saved_hosts.list().expect("saved hosts").is_empty());
        let operations = controller
            .operation_log()
            .entries()
            .iter()
            .map(|entry| entry.operation())
            .collect::<Vec<_>>();
        assert_eq!(
            operations,
            vec![
                CredentialOperation::Resolve,
                CredentialOperation::Resolve,
                CredentialOperation::Upsert,
                CredentialOperation::Upsert,
                CredentialOperation::Upsert,
                CredentialOperation::Resolve,
                CredentialOperation::Upsert,
                CredentialOperation::Delete,
                CredentialOperation::Delete,
                CredentialOperation::Delete,
            ],
            "the failed second write is restored before the first write is removed"
        );

        controller.clear_failures();
        let first_error = state
            .persistent_credentials
            .resolve(&first_reference, CredentialKind::SshPassword)
            .await
            .err()
            .expect("first credential must be removed");
        assert_eq!(first_error.code(), CredentialErrorCode::NotFound);
        let restored = state
            .persistent_credentials
            .resolve(&second_reference, CredentialKind::SshPassword)
            .await
            .expect("second credential must be restored");
        assert_eq!(restored.as_utf8().expect("UTF-8 secret"), "old-secret-b");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn compensation_failure_returns_fixed_repair_code_and_never_commits_vault() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, controller) = desktop_state_with_memory_credentials(&current_vault);
        let source = legacy_plaintext_batch(&["legacy-repair"]);
        let inspect_document =
            netcatty_migration::parse_legacy_vault(&source, 10).expect("inspection document");
        let inspection = inspect_legacy_vault_document(state.clone(), inspect_document)
            .await
            .expect("inspection");
        controller.set_failure(
            CredentialOperation::Upsert,
            1,
            FailureTiming::AfterSideEffect,
            CredentialErrorCode::BackendFailure,
        );
        controller.set_failure(
            CredentialOperation::Delete,
            1,
            FailureTiming::BeforeSideEffect,
            CredentialErrorCode::StorageUnavailable,
        );

        let commit_document =
            netcatty_migration::parse_legacy_vault(&source, 10).expect("commit document");
        let error =
            commit_legacy_vault_document(&state, inspection.inventory_revision, commit_document)
                .await
                .expect_err("failed compensation must surface repair code");
        assert!(error.starts_with(super::LEGACY_VAULT_CREDENTIAL_FAILED));
        assert!(error.contains(&format!(
            "; {}:",
            super::LEGACY_VAULT_CREDENTIAL_REPAIR_FAILED
        )));
        assert!(!error.contains("new-secret-0"));
        assert!(!error.contains("legacy-repair"));
        assert!(state.saved_hosts.list().expect("saved hosts").is_empty());
        assert_eq!(snapshot_count(&current_vault.join("saved-hosts")), 0);
        let operations = controller
            .operation_log()
            .entries()
            .iter()
            .map(|entry| entry.operation())
            .collect::<Vec<_>>();
        assert_eq!(
            operations,
            vec![
                CredentialOperation::Resolve,
                CredentialOperation::Upsert,
                CredentialOperation::Delete,
            ]
        );

        controller.clear_failures();
        let orphan = state
            .persistent_credentials
            .resolve(
                &stored_host_reference("legacy-repair"),
                CredentialKind::SshPassword,
            )
            .await
            .expect("failed delete leaves a repairable credential");
        assert_eq!(orphan.as_utf8().expect("UTF-8 secret"), "new-secret-0");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restart_recovers_preparing_by_cleaning_only_partial_backups() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, controller) = desktop_state_with_memory_credentials(&current_vault);
        let persistent_credentials = state.persistent_credentials.clone();
        let first =
            SavedHostId::from_opaque("preparing-restart-host-a").expect("first saved-host ID");
        let second =
            SavedHostId::from_opaque("preparing-restart-host-b").expect("second saved-host ID");
        let old_first = "preparing-old-target-secret-a";
        let old_second = "preparing-old-target-secret-b";
        let transaction =
            begin_test_legacy_import_transaction(&state, vec![first.clone(), second.clone()])
                .await
                .expect("begin Preparing transaction");
        let (first_target, first_backup) =
            legacy_import_credential_references(&transaction, &first).expect("first references");
        let (second_target, second_backup) =
            legacy_import_credential_references(&transaction, &second).expect("second references");
        state
            .persistent_credentials
            .upsert(
                &first_target,
                CredentialKind::SshPassword,
                test_secret(old_first),
            )
            .await
            .expect("seed first target");
        state
            .persistent_credentials
            .upsert(
                &second_target,
                CredentialKind::SshPassword,
                test_secret(old_second),
            )
            .await
            .expect("seed second target");
        state
            .persistent_credentials
            .upsert(
                &first_backup,
                CredentialKind::SshPassword,
                test_secret(old_first),
            )
            .await
            .expect("write only the first backup");
        assert_eq!(transaction.phase(), LegacyImportTransactionPhase::Preparing);
        assert_transaction_journal_excludes(
            state.legacy_import_transaction_root.as_ref(),
            &[old_first, old_second],
        );

        drop(transaction);
        drop(state);
        controller.clear_operation_log();
        let restarted = restarted_desktop_state(&current_vault, &persistent_credentials);
        recover_pending_legacy_import(&restarted)
            .await
            .expect("Preparing recovery");

        assert_stored_secret(&persistent_credentials, &first_target, old_first).await;
        assert_stored_secret(&persistent_credentials, &second_target, old_second).await;
        assert_credential_missing(&persistent_credentials, &first_backup).await;
        assert_credential_missing(&persistent_credentials, &second_backup).await;
        assert!(
            load_legacy_import_transaction(&restarted)
                .await
                .expect("load after Preparing recovery")
                .is_none()
        );
        assert!(
            restarted
                .saved_hosts
                .list()
                .expect("saved hosts")
                .is_empty()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restart_rolls_back_active_unpublished_targets_in_reverse_order() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, controller) = desktop_state_with_memory_credentials(&current_vault);
        let persistent_credentials = state.persistent_credentials.clone();
        let absent = SavedHostId::from_opaque("active-unpublished-absent").expect("absent host ID");
        let backed_up =
            SavedHostId::from_opaque("active-unpublished-backed-up").expect("backed-up host ID");
        let old_secret = "active-unpublished-old-secret";
        let new_absent_secret = "active-unpublished-new-absent";
        let new_backed_secret = "active-unpublished-new-backed";
        state
            .persistent_credentials
            .upsert(
                &stored_host_reference(backed_up.as_str()),
                CredentialKind::SshPassword,
                test_secret(old_secret),
            )
            .await
            .expect("seed backed-up target");
        let preparing =
            begin_test_legacy_import_transaction(&state, vec![absent.clone(), backed_up.clone()])
                .await
                .expect("begin transaction");
        let (absent_target, absent_backup) =
            legacy_import_credential_references(&preparing, &absent).expect("absent references");
        let (backed_target, backed_backup) =
            legacy_import_credential_references(&preparing, &backed_up)
                .expect("backed-up references");
        state
            .persistent_credentials
            .upsert(
                &backed_backup,
                CredentialKind::SshPassword,
                test_secret(old_secret),
            )
            .await
            .expect("persist old-secret backup");
        let active = activate_legacy_import_transaction(
            preparing,
            vec![
                (absent.clone(), LegacyPreviousCredentialState::Absent),
                (backed_up.clone(), LegacyPreviousCredentialState::BackedUp),
            ],
        )
        .await
        .expect("activate transaction");
        state
            .persistent_credentials
            .upsert(
                &absent_target,
                CredentialKind::SshPassword,
                test_secret(new_absent_secret),
            )
            .await
            .expect("write formerly absent target");
        state
            .persistent_credentials
            .upsert(
                &backed_target,
                CredentialKind::SshPassword,
                test_secret(new_backed_secret),
            )
            .await
            .expect("replace backed-up target");
        assert_transaction_journal_excludes(
            state.legacy_import_transaction_root.as_ref(),
            &[old_secret, new_absent_secret, new_backed_secret],
        );

        drop(active);
        drop(state);
        controller.clear_operation_log();
        let restarted = restarted_desktop_state(&current_vault, &persistent_credentials);
        recover_pending_legacy_import(&restarted)
            .await
            .expect("rollback unpublished targets");
        let operations = controller
            .operation_log()
            .entries()
            .iter()
            .map(|entry| entry.operation())
            .collect::<Vec<_>>();
        assert_eq!(
            operations,
            vec![
                CredentialOperation::Resolve,
                CredentialOperation::Upsert,
                CredentialOperation::Delete,
                CredentialOperation::Delete,
                CredentialOperation::Delete,
            ],
            "the backed-up second target is restored before the absent first target is deleted"
        );

        assert_credential_missing(&persistent_credentials, &absent_target).await;
        assert_stored_secret(&persistent_credentials, &backed_target, old_secret).await;
        assert_credential_missing(&persistent_credentials, &absent_backup).await;
        assert_credential_missing(&persistent_credentials, &backed_backup).await;
        assert!(
            load_legacy_import_transaction(&restarted)
                .await
                .expect("load after rollback")
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restart_keeps_active_targets_when_the_atomic_vault_graph_was_published() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, controller) = desktop_state_with_memory_credentials(&current_vault);
        let persistent_credentials = state.persistent_credentials.clone();
        let absent_id = "active-published-absent";
        let backed_id = "active-published-backed";
        let absent = SavedHostId::from_opaque(absent_id).expect("absent host ID");
        let backed_up = SavedHostId::from_opaque(backed_id).expect("backed-up host ID");
        let old_secret = "active-published-old-secret";
        let new_absent_secret = "active-published-new-absent";
        let new_backed_secret = "active-published-new-backed";
        let preparing =
            begin_test_legacy_import_transaction(&state, vec![absent.clone(), backed_up.clone()])
                .await
                .expect("begin transaction");
        let (absent_target, absent_backup) =
            legacy_import_credential_references(&preparing, &absent).expect("absent references");
        let (backed_target, backed_backup) =
            legacy_import_credential_references(&preparing, &backed_up)
                .expect("backed-up references");
        state
            .persistent_credentials
            .upsert(
                &backed_backup,
                CredentialKind::SshPassword,
                test_secret(old_secret),
            )
            .await
            .expect("persist old-secret backup");
        let active = activate_legacy_import_transaction(
            preparing,
            vec![
                (absent.clone(), LegacyPreviousCredentialState::Absent),
                (backed_up.clone(), LegacyPreviousCredentialState::BackedUp),
            ],
        )
        .await
        .expect("activate transaction");
        state
            .persistent_credentials
            .upsert(
                &absent_target,
                CredentialKind::SshPassword,
                test_secret(new_absent_secret),
            )
            .await
            .expect("write absent target");
        state
            .persistent_credentials
            .upsert(
                &backed_target,
                CredentialKind::SshPassword,
                test_secret(new_backed_secret),
            )
            .await
            .expect("write backed target");
        publish_legacy_credential_hosts(&state, &[absent_id, backed_id]);
        assert_transaction_journal_excludes(
            state.legacy_import_transaction_root.as_ref(),
            &[old_secret, new_absent_secret, new_backed_secret],
        );

        drop(active);
        drop(state);
        controller.clear_operation_log();
        let restarted = restarted_desktop_state(&current_vault, &persistent_credentials);
        recover_pending_legacy_import(&restarted)
            .await
            .expect("published graph recovery");
        let operations = controller
            .operation_log()
            .entries()
            .iter()
            .map(|entry| entry.operation())
            .collect::<Vec<_>>();
        assert_eq!(
            operations,
            vec![CredentialOperation::Delete, CredentialOperation::Delete],
            "published targets are retained; only isolated backups are removed"
        );

        assert_stored_secret(&persistent_credentials, &absent_target, new_absent_secret).await;
        assert_stored_secret(&persistent_credentials, &backed_target, new_backed_secret).await;
        assert_credential_missing(&persistent_credentials, &absent_backup).await;
        assert_credential_missing(&persistent_credentials, &backed_backup).await;
        assert!(
            load_legacy_import_transaction(&restarted)
                .await
                .expect("load after published recovery")
                .is_none()
        );
        assert_eq!(restarted.saved_hosts.list().expect("saved hosts").len(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restart_retries_committed_backup_cleanup_without_reverting_final_targets() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, controller) = desktop_state_with_memory_credentials(&current_vault);
        let persistent_credentials = state.persistent_credentials.clone();
        let first_id = "vault-durable-retry-a";
        let second_id = "vault-durable-retry-b";
        let first = SavedHostId::from_opaque(first_id).expect("first host ID");
        let second = SavedHostId::from_opaque(second_id).expect("second host ID");
        let old_secret = "vault-durable-old-secret";
        let new_first_secret = "vault-durable-new-first";
        let new_second_secret = "vault-durable-new-second";

        let preparing =
            begin_test_legacy_import_transaction(&state, vec![first.clone(), second.clone()])
                .await
                .expect("begin transaction");
        let (first_target, first_backup) =
            legacy_import_credential_references(&preparing, &first).expect("first references");
        let (second_target, second_backup) =
            legacy_import_credential_references(&preparing, &second).expect("second references");
        state
            .persistent_credentials
            .upsert(
                &second_backup,
                CredentialKind::SshPassword,
                test_secret(old_secret),
            )
            .await
            .expect("persist old-secret backup");
        let active = activate_legacy_import_transaction(
            preparing,
            vec![
                (first.clone(), LegacyPreviousCredentialState::Absent),
                (second.clone(), LegacyPreviousCredentialState::BackedUp),
            ],
        )
        .await
        .expect("activate transaction");
        state
            .persistent_credentials
            .upsert(
                &first_target,
                CredentialKind::SshPassword,
                test_secret(new_first_secret),
            )
            .await
            .expect("write first target");
        state
            .persistent_credentials
            .upsert(
                &second_target,
                CredentialKind::SshPassword,
                test_secret(new_second_secret),
            )
            .await
            .expect("write second target");
        publish_legacy_credential_hosts(&state, &[first_id, second_id]);
        drop(active);
        drop(state);

        let first_restart = restarted_desktop_state(&current_vault, &persistent_credentials);
        controller.clear_operation_log();
        controller.set_failure(
            CredentialOperation::Delete,
            2,
            FailureTiming::AfterSideEffect,
            CredentialErrorCode::StorageUnavailable,
        );
        let error = recover_pending_legacy_import(&first_restart)
            .await
            .expect_err("uncertain backup deletion must remain retryable");
        assert!(error.starts_with(super::LEGACY_VAULT_CREDENTIAL_REPAIR_FAILED));
        for forbidden in [
            first.as_str(),
            second.as_str(),
            old_secret,
            new_first_secret,
            new_second_secret,
            &current_vault.display().to_string(),
        ] {
            assert!(!error.contains(forbidden));
        }
        let pending = load_legacy_import_transaction(&first_restart)
            .await
            .expect("load committed transaction")
            .expect("committed transaction retained");
        assert_eq!(pending.phase(), LegacyImportTransactionPhase::VaultDurable);
        drop(pending);
        assert_stored_secret(&persistent_credentials, &first_target, new_first_secret).await;
        assert_stored_secret(&persistent_credentials, &second_target, new_second_secret).await;
        assert_credential_missing(&persistent_credentials, &first_backup).await;
        assert_credential_missing(&persistent_credentials, &second_backup).await;

        drop(first_restart);
        controller.clear_failures();
        controller.clear_operation_log();
        let second_restart = restarted_desktop_state(&current_vault, &persistent_credentials);
        recover_pending_legacy_import(&second_restart)
            .await
            .expect("committed cleanup retry");
        assert_stored_secret(&persistent_credentials, &first_target, new_first_secret).await;
        assert_stored_secret(&persistent_credentials, &second_target, new_second_secret).await;
        assert!(
            load_legacy_import_transaction(&second_restart)
                .await
                .expect("load after committed cleanup")
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restart_retries_backup_cleanup_after_restored_phase_delete_uncertainty() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, controller) = desktop_state_with_memory_credentials(&current_vault);
        let persistent_credentials = state.persistent_credentials.clone();
        let absent = SavedHostId::from_opaque("restored-retry-absent").expect("absent host ID");
        let backed_up = SavedHostId::from_opaque("restored-retry-backed").expect("backed host ID");
        let old_secret = "restored-retry-old-secret";
        let new_absent_secret = "restored-retry-new-absent";
        let new_backed_secret = "restored-retry-new-backed";
        let preparing =
            begin_test_legacy_import_transaction(&state, vec![absent.clone(), backed_up.clone()])
                .await
                .expect("begin transaction");
        let (absent_target, absent_backup) =
            legacy_import_credential_references(&preparing, &absent).expect("absent references");
        let (backed_target, backed_backup) =
            legacy_import_credential_references(&preparing, &backed_up)
                .expect("backed-up references");
        state
            .persistent_credentials
            .upsert(
                &backed_backup,
                CredentialKind::SshPassword,
                test_secret(old_secret),
            )
            .await
            .expect("persist old-secret backup");
        let active = activate_legacy_import_transaction(
            preparing,
            vec![
                (absent.clone(), LegacyPreviousCredentialState::Absent),
                (backed_up.clone(), LegacyPreviousCredentialState::BackedUp),
            ],
        )
        .await
        .expect("activate transaction");
        let transaction_id = active.transaction_id().to_string();
        state
            .persistent_credentials
            .upsert(
                &absent_target,
                CredentialKind::SshPassword,
                test_secret(new_absent_secret),
            )
            .await
            .expect("write absent target");
        state
            .persistent_credentials
            .upsert(
                &backed_target,
                CredentialKind::SshPassword,
                test_secret(new_backed_secret),
            )
            .await
            .expect("write backed target");
        assert_transaction_journal_excludes(
            state.legacy_import_transaction_root.as_ref(),
            &[old_secret, new_absent_secret, new_backed_secret],
        );
        let journal_path = state.legacy_import_transaction_root.display().to_string();

        drop(active);
        drop(state);
        let first_restart = restarted_desktop_state(&current_vault, &persistent_credentials);
        controller.clear_operation_log();
        controller.set_failure(
            CredentialOperation::Delete,
            2,
            FailureTiming::AfterSideEffect,
            CredentialErrorCode::StorageUnavailable,
        );
        let error = recover_pending_legacy_import(&first_restart)
            .await
            .expect_err("first backup cleanup is uncertain");
        assert!(error.starts_with(super::LEGACY_VAULT_CREDENTIAL_REPAIR_FAILED));
        for forbidden in [
            absent.as_str(),
            backed_up.as_str(),
            transaction_id.as_str(),
            journal_path.as_str(),
            old_secret,
            new_absent_secret,
            new_backed_secret,
        ] {
            assert!(!error.contains(forbidden));
        }
        let pending = load_legacy_import_transaction(&first_restart)
            .await
            .expect("load restored transaction")
            .expect("restored transaction retained");
        assert_eq!(
            pending.phase(),
            LegacyImportTransactionPhase::RollbackTargetsRestored
        );
        drop(pending);
        assert_credential_missing(&persistent_credentials, &absent_target).await;
        assert_stored_secret(&persistent_credentials, &backed_target, old_secret).await;
        assert_credential_missing(&persistent_credentials, &absent_backup).await;
        assert_stored_secret(&persistent_credentials, &backed_backup, old_secret).await;

        drop(first_restart);
        controller.clear_failures();
        controller.clear_operation_log();
        let second_restart = restarted_desktop_state(&current_vault, &persistent_credentials);
        recover_pending_legacy_import(&second_restart)
            .await
            .expect("idempotent second-start cleanup");
        assert_credential_missing(&persistent_credentials, &absent_backup).await;
        assert_credential_missing(&persistent_credentials, &backed_backup).await;
        assert_stored_secret(&persistent_credentials, &backed_target, old_secret).await;
        assert!(
            load_legacy_import_transaction(&second_restart)
                .await
                .expect("load after retry")
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restart_fails_closed_on_mixed_credential_host_publication() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, controller) = desktop_state_with_memory_credentials(&current_vault);
        let persistent_credentials = state.persistent_credentials.clone();
        let first_id = "mixed-publication-host-a";
        let second_id = "mixed-publication-host-b";
        let first = SavedHostId::from_opaque(first_id).expect("first host ID");
        let second = SavedHostId::from_opaque(second_id).expect("second host ID");
        let old_secret = "mixed-publication-old-secret";
        let new_first_secret = "mixed-publication-new-first";
        let new_second_secret = "mixed-publication-new-second";
        let preparing =
            begin_test_legacy_import_transaction(&state, vec![first.clone(), second.clone()])
                .await
                .expect("begin transaction");
        let (first_target, first_backup) =
            legacy_import_credential_references(&preparing, &first).expect("first references");
        let (second_target, second_backup) =
            legacy_import_credential_references(&preparing, &second).expect("second references");
        state
            .persistent_credentials
            .upsert(
                &second_backup,
                CredentialKind::SshPassword,
                test_secret(old_secret),
            )
            .await
            .expect("persist old-secret backup");
        let active = activate_legacy_import_transaction(
            preparing,
            vec![
                (first.clone(), LegacyPreviousCredentialState::Absent),
                (second.clone(), LegacyPreviousCredentialState::BackedUp),
            ],
        )
        .await
        .expect("activate transaction");
        let transaction_id = active.transaction_id().to_string();
        state
            .persistent_credentials
            .upsert(
                &first_target,
                CredentialKind::SshPassword,
                test_secret(new_first_secret),
            )
            .await
            .expect("write first final target");
        state
            .persistent_credentials
            .upsert(
                &second_target,
                CredentialKind::SshPassword,
                test_secret(new_second_secret),
            )
            .await
            .expect("write second final target");
        publish_legacy_credential_hosts(&state, &[first_id]);
        assert_transaction_journal_excludes(
            state.legacy_import_transaction_root.as_ref(),
            &[old_secret, new_first_secret, new_second_secret],
        );
        let journal_path = state.legacy_import_transaction_root.display().to_string();

        drop(active);
        drop(state);
        controller.clear_operation_log();
        let restarted = restarted_desktop_state(&current_vault, &persistent_credentials);
        let error = recover_pending_legacy_import(&restarted)
            .await
            .expect_err("mixed publication must fail closed");
        assert!(error.starts_with(super::LEGACY_VAULT_IMPORT_REPAIR_REQUIRED));
        assert!(controller.operation_log().is_empty());
        for forbidden in [
            first.as_str(),
            second.as_str(),
            transaction_id.as_str(),
            journal_path.as_str(),
            old_secret,
            new_first_secret,
            new_second_secret,
        ] {
            assert!(!error.contains(forbidden));
        }
        assert_stored_secret(&persistent_credentials, &first_target, new_first_secret).await;
        assert_stored_secret(&persistent_credentials, &second_target, new_second_secret).await;
        assert_credential_missing(&persistent_credentials, &first_backup).await;
        assert_stored_secret(&persistent_credentials, &second_backup, old_secret).await;
        let pending = load_legacy_import_transaction(&restarted)
            .await
            .expect("load mixed transaction")
            .expect("mixed transaction retained");
        assert_eq!(pending.phase(), LegacyImportTransactionPhase::Active);
        assert_eq!(restarted.saved_hosts.list().expect("saved hosts").len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restart_rejects_a_durable_third_graph_even_when_every_target_id_is_visible() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, controller) = desktop_state_with_memory_credentials(&current_vault);
        let persistent_credentials = state.persistent_credentials.clone();
        let target_id = "full-commitment-target";
        let unrelated_id = "full-commitment-unrelated";
        let target = SavedHostId::from_opaque(target_id).expect("target host ID");
        let new_secret = "full-commitment-new-secret";
        let preparing = begin_test_legacy_import_transaction(&state, vec![target.clone()])
            .await
            .expect("begin transaction");
        let (target_reference, backup_reference) =
            legacy_import_credential_references(&preparing, &target).expect("references");
        let active = activate_legacy_import_transaction(
            preparing,
            vec![(target.clone(), LegacyPreviousCredentialState::Absent)],
        )
        .await
        .expect("activate transaction");
        state
            .persistent_credentials
            .upsert(
                &target_reference,
                CredentialKind::SshPassword,
                test_secret(new_secret),
            )
            .await
            .expect("write final target");

        // Every transaction ID is present, but the durable graph contains an
        // extra record and therefore is neither the journal's exact before
        // nor exact after state. ID counting alone would incorrectly finish.
        publish_legacy_credential_hosts(&state, &[target_id, unrelated_id]);
        drop(active);
        drop(state);
        controller.clear_operation_log();

        let restarted = restarted_desktop_state(&current_vault, &persistent_credentials);
        let error = recover_pending_legacy_import(&restarted)
            .await
            .expect_err("a third graph must fail closed");
        assert!(error.starts_with(super::LEGACY_VAULT_IMPORT_REPAIR_REQUIRED));
        assert!(controller.operation_log().is_empty());
        for forbidden in [
            target.as_str(),
            unrelated_id,
            new_secret,
            &current_vault.display().to_string(),
        ] {
            assert!(!error.contains(forbidden));
        }
        assert_stored_secret(&persistent_credentials, &target_reference, new_secret).await;
        assert_credential_missing(&persistent_credentials, &backup_reference).await;
        let pending = load_legacy_import_transaction(&restarted)
            .await
            .expect("load retained transaction")
            .expect("third-graph transaction retained");
        assert_eq!(pending.phase(), LegacyImportTransactionPhase::Active);
        assert_eq!(restarted.saved_hosts.list().expect("saved hosts").len(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn legacy_inspection_and_snapshot_never_serialize_source_secrets_or_references() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let source_name = "source-path-must-never-be-returned.json";
        let source_path = directory.path().join(source_name);
        let plaintext = "legacy-plaintext-password-must-never-persist";
        let duplicate_plaintext = "duplicate-password-must-never-persist";
        let ciphertext = "enc:v1:opaque-ciphertext-must-never-persist";
        let credential_reference = "opaque-credential-ref-must-never-persist";
        let identity_reference = "opaque-identity-ref-must-never-persist";
        let identity_file_reference = "opaque-identity-file-ref-must-never-persist";
        let identity_path = "/opaque/identity/path/must-never-persist";
        std::fs::write(
            &source_path,
            format!(
                r#"[
                    {{"id":"legacy-plain","hostname":"plain.example.test","username":"alice","protocol":"ssh","authMethod":"password","authPolicyVersion":1,"savePassword":false,"password":"{plaintext}"}},
                    {{"id":"legacy-encrypted","hostname":"encrypted.example.test","username":"bob","protocol":"ssh","authMethod":"password","authPolicyVersion":1,"password":"{ciphertext}"}},
                    {{"id":"legacy-credential-ref","hostname":"credential.example.test","username":"carol","protocol":"ssh","authMethod":"password","authPolicyVersion":1,"pluginConfig":{{"credentialRef":"{credential_reference}"}}}},
                    {{"id":"legacy-identity-ref","hostname":"identity.example.test","username":"dave","protocol":"ssh","authMethod":"password","authPolicyVersion":1,"identityId":"{identity_reference}","identityFileId":"{identity_file_reference}","identityFilePaths":["{identity_path}"]}},
                    {{"id":"legacy-plain","hostname":"duplicate.example.test","username":"mallory","protocol":"ssh","authMethod":"password","authPolicyVersion":1,"password":"{duplicate_plaintext}"}}
                ]"#
            ),
        )
        .expect("legacy fixture");
        let current_vault = directory.path().join("current");
        let saved_host_vault = current_vault.join("saved-hosts");
        let state = DesktopState::open(&current_vault).expect("desktop state");
        let document = load_legacy_vault_document(source_path.display().to_string())
            .await
            .expect("legacy document");
        let inspection = inspect_legacy_vault_document(state.clone(), document)
            .await
            .expect("safe inspection");
        let encoded = serde_json::to_string(&inspection).expect("inspection JSON");
        let source_bytes = std::fs::read(&source_path).expect("source bytes");
        let raw_sha256: [u8; 32] = Sha256::digest(&source_bytes).into();
        let raw_sha256_hex = hex_encode(&raw_sha256);

        for forbidden in [
            plaintext,
            duplicate_plaintext,
            ciphertext,
            credential_reference,
            identity_reference,
            identity_file_reference,
            identity_path,
            source_name,
            &source_path.display().to_string(),
        ] {
            assert!(
                !encoded.contains(forbidden),
                "inspection leaked source material"
            );
        }
        assert!(encoded.contains("inventoryRevision"));
        assert!(encoded.contains("sourceFingerprint"));
        assert!(!encoded.contains(&raw_sha256_hex));
        assert!(verify_legacy_source_fingerprint(
            &raw_sha256,
            &inspection.source_fingerprint
        ));
        assert_eq!(inspection.preview.source_count, 5);
        assert_eq!(inspection.preview.importable_count, 2);
        assert_eq!(inspection.preview.duplicate_count, 1);
        assert_eq!(inspection.preview.unsupported_count, 2);
        assert_eq!(inspection.preview.recoverable_credential_count, 0);

        let commit_document = load_legacy_vault_document(source_path.display().to_string())
            .await
            .expect("commit document");
        let result = run_saved_host_operation(state.clone(), move |state| async move {
            commit_legacy_vault_document(&state, inspection.inventory_revision, commit_document)
                .await
        })
        .await
        .expect("secret-free batch import");
        assert_eq!(result.imported_count, 2);
        assert_eq!(result.duplicate_count, 1);
        assert_eq!(result.conflict_count, 0);
        assert_eq!(result.credentials_stored_count, 0);

        let persisted = persisted_files(&saved_host_vault);
        assert_eq!(snapshot_count(&saved_host_vault), 1);
        for bytes in &persisted {
            for forbidden in [
                plaintext,
                duplicate_plaintext,
                ciphertext,
                "enc:v1:",
                credential_reference,
                identity_reference,
                identity_file_reference,
                identity_path,
                source_name,
                &source_path.display().to_string(),
                "\"credentialRef\"",
                "\"identityId\"",
                "\"identityFileId\"",
                "\"identityFilePaths\"",
            ] {
                assert_bytes_do_not_contain(bytes, forbidden);
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn legacy_batch_without_passwords_is_atomic_and_revision_bound() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let source_path = directory.path().join("legacy.json");
        std::fs::write(
            &source_path,
            br#"[
                {"id":"legacy-a","hostname":"a.example.test","username":"alice","protocol":"ssh","authMethod":"password","authPolicyVersion":1},
                {"id":"legacy-b","hostname":"b.example.test","username":"bob","protocol":"ssh","authMethod":"password","authPolicyVersion":1}
            ]"#,
        )
        .expect("legacy fixture");
        let state = DesktopState::open(directory.path().join("current")).expect("desktop state");

        let inspected_document = load_legacy_vault_document(source_path.display().to_string())
            .await
            .expect("legacy document");
        let stale_inspection = inspect_legacy_vault_document(state.clone(), inspected_document)
            .await
            .expect("inspection");
        state
            .saved_hosts
            .create(netcatty_vault::SavedHostDraft::ssh_password(
                "concurrent.example.test",
                "user",
            ))
            .expect("concurrent saved host");

        let stale_document = load_legacy_vault_document(source_path.display().to_string())
            .await
            .expect("reloaded document");
        let stale_revision = stale_inspection.inventory_revision;
        let stale_error = run_saved_host_operation(state.clone(), move |state| async move {
            commit_legacy_vault_document(&state, stale_revision, stale_document).await
        })
        .await
        .expect_err("stale import must fail");
        assert!(stale_error.contains(LEGACY_VAULT_INVENTORY_CHANGED));

        let fresh_document = load_legacy_vault_document(source_path.display().to_string())
            .await
            .expect("fresh document");
        let fresh_inspection = inspect_legacy_vault_document(state.clone(), fresh_document)
            .await
            .expect("fresh inspection");
        let commit_document = load_legacy_vault_document(source_path.display().to_string())
            .await
            .expect("commit document");
        let fresh_revision = fresh_inspection.inventory_revision;
        let result = run_saved_host_operation(state.clone(), move |state| async move {
            commit_legacy_vault_document(&state, fresh_revision, commit_document).await
        })
        .await
        .expect("batch import");

        assert_eq!(result.imported_count, 2);
        assert_eq!(result.credentials_stored_count, 0);
        assert_eq!(result.requires_credential_reentry_count, 2);
        let hosts = state.saved_hosts.list().expect("saved hosts");
        assert_eq!(hosts.len(), 3);
        for host in hosts
            .iter()
            .filter(|host| host.id.as_str().starts_with("legacy-"))
        {
            assert_eq!(
                host.compatibility_fields().get("hasSavedCredential"),
                Some(&serde_json::Value::Bool(false))
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn managed_only_import_publishes_v5_metadata_and_decryptable_renderer_safe_secret() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, controller) = desktop_state_with_memory_credentials(&current_vault);
        let private_key = "managed-private-renderer-sentinel";
        let public_key = "managed-public-renderer-sentinel";
        let certificate = "managed-certificate-renderer-sentinel";
        let passphrase = "managed-passphrase-renderer-sentinel";
        let source = legacy_managed_graph_source(
            "managed-only-key",
            None,
            private_key,
            Some(public_key),
            Some(certificate),
            Some(passphrase),
            true,
        );

        let inspected_document =
            netcatty_migration::parse_legacy_vault(&source, 100).expect("managed inspection");
        let inspection = inspect_legacy_vault_document(state.clone(), inspected_document)
            .await
            .expect("managed assessment");
        assert_eq!(inspection.source_managed_ssh_key_count, 1);
        assert_eq!(inspection.importable_managed_ssh_key_count, 1);
        assert_eq!(inspection.managed_ssh_key_recovery_required_count, 0);
        let inspection_json = serde_json::to_string(&inspection).expect("inspection JSON");
        assert_renderer_json_excludes(
            &inspection_json,
            &[
                private_key,
                public_key,
                certificate,
                passphrase,
                "legacy-managed-path-sentinel",
                "\"privateKey\"",
                "\"publicKey\"",
                "\"certificate\"",
                "\"passphrase\"",
                "\"ciphertext\"",
                "\"backendLocator\"",
            ],
        );
        assert!(controller.operation_log().is_empty());

        let commit_document =
            netcatty_migration::parse_legacy_vault(&source, 100).expect("managed commit");
        let result =
            commit_legacy_vault_document(&state, inspection.inventory_revision, commit_document)
                .await
                .expect("managed-only import");
        assert_eq!(result.imported_count, 0);
        assert_eq!(result.managed_ssh_keys_imported_count, 1);
        assert_eq!(result.managed_secret_blobs_published_count, 1);
        assert_eq!(result.credentials_stored_count, 0);
        assert_eq!(snapshot_count(&current_vault.join("saved-hosts")), 1);

        let graph = state.saved_hosts.graph().expect("managed graph");
        assert!(graph.hosts().is_empty());
        assert_eq!(graph.managed_ssh_keys().len(), 1);
        let key = graph.managed_ssh_keys()[0].clone();
        assert_eq!(key.label, "Managed key metadata");
        assert_eq!(key.category.as_str(), "certificate");
        assert_eq!(key.source.as_str(), "generated");
        assert!(key.has_saved_passphrase);
        assert_eq!(key.custody().custody_revision(), 1);
        assert_eq!(key.compatibility_fields()["type"], "ED25519");
        assert!(!key.compatibility_fields().contains_key("filePath"));
        let backend_locator = key.custody().backend_locator().as_str().to_owned();
        let secret_store_id = {
            let guard = state
                .secret_files
                .lock_exclusive()
                .expect("secret-store lock");
            guard
                .load_state()
                .expect("secret-store state")
                .store_id()
                .hyphenated()
                .to_string()
        };

        let bundle = resolve_test_managed_bundle(&state, key).await;
        assert!(
            bundle.private_key() == private_key.as_bytes(),
            "managed private key did not round-trip"
        );
        assert!(
            bundle.public_key() == Some(public_key.as_bytes()),
            "managed public key did not round-trip"
        );
        assert!(
            bundle.certificate() == Some(certificate.as_bytes()),
            "managed certificate did not round-trip"
        );
        assert!(
            bundle.passphrase() == Some(passphrase.as_bytes()),
            "managed passphrase did not round-trip"
        );

        let snapshot = saved_vault_snapshot_json(&current_vault.join("saved-hosts"));
        assert_eq!(snapshot["formatVersion"], 8);
        let managed_metadata = snapshot["managedSshKeys"]
            .as_array()
            .expect("managed metadata array");
        assert_eq!(managed_metadata.len(), 1);
        assert!(
            managed_metadata[0]["custody"]["backendLocator"].as_str()
                == Some(backend_locator.as_str()),
            "snapshot custody locator mismatch"
        );
        let snapshot_json = serde_json::to_string(&snapshot).expect("snapshot JSON");
        assert_renderer_json_excludes(
            &snapshot_json,
            &[
                private_key,
                public_key,
                certificate,
                passphrase,
                &secret_store_id,
            ],
        );
        for bytes in persisted_files(&current_vault) {
            for forbidden in [private_key, public_key, certificate, passphrase] {
                assert_bytes_do_not_contain(&bytes, forbidden);
            }
        }

        let repeat_document =
            netcatty_migration::parse_legacy_vault(&source, 100).expect("repeat inspection");
        let repeat = inspect_legacy_vault_document(state.clone(), repeat_document)
            .await
            .expect("repeat managed assessment");
        let repeat_json = serde_json::to_string(&repeat).expect("repeat inspection JSON");
        let result_json = serde_json::to_string(&result).expect("managed result JSON");
        for encoded in [&repeat_json, &result_json] {
            assert_renderer_json_excludes(
                encoded,
                &[
                    private_key,
                    public_key,
                    certificate,
                    passphrase,
                    &backend_locator,
                    &secret_store_id,
                    "\"privateKey\"",
                    "\"publicKey\"",
                    "\"certificate\"",
                    "\"passphrase\"",
                    "\"ciphertext\"",
                    "\"backendLocator\"",
                ],
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn desktop_gc_uses_all_vault_retention_and_removes_only_orphan_revision() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, _) = desktop_state_with_memory_credentials(&current_vault);
        let retained_private_key = "desktop-gc-retained-private-sentinel";
        let orphan_private_key = "desktop-gc-orphan-private-sentinel";
        let source = legacy_managed_graph_source(
            "desktop-gc-managed-key",
            None,
            retained_private_key,
            None,
            None,
            None,
            false,
        );
        let inspection = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&source, 100).expect("GC inspection"),
        )
        .await
        .expect("GC assessment");
        commit_legacy_vault_document(
            &state,
            inspection.inventory_revision,
            netcatty_migration::parse_legacy_vault(&source, 100).expect("GC commit"),
        )
        .await
        .expect("managed key import before GC");

        let managed = state
            .saved_hosts
            .graph()
            .expect("managed graph")
            .managed_ssh_keys()[0]
            .clone();
        let publication = ManagedSecretPublication {
            entity_id: managed.id.as_str().to_owned(),
            backend_locator: managed.custody().backend_locator().as_str().to_owned(),
            custody_revision: 2,
            bundle: netcatty_secret_store::SshSecretBundle::new(
                orphan_private_key.as_bytes().to_vec(),
                None,
                None,
                None,
            )
            .expect("orphan bundle"),
        };
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
                .expect("test master key");
            assert_eq!(
                publish_managed_secret_objects(
                    &guard,
                    &store_state,
                    &master_key,
                    vec![publication],
                )
                .expect("publish orphan revision"),
                1
            );
        })
        .await
        .expect("orphan publication worker");
        assert_eq!(
            secret_blob_paths(&current_vault.join("secret-blobs")).len(),
            4
        );

        let report = run_saved_host_operation(state.clone(), |state| async move {
            garbage_collect_managed_secret_blobs(&state).await
        })
        .await
        .expect("fallback-aware desktop GC");
        assert_eq!(report.removed_blob_revisions, 1);
        assert_eq!(report.removed_objects, 0);
        assert_eq!(
            secret_blob_paths(&current_vault.join("secret-blobs")).len(),
            2
        );
        let encoded = serde_json::to_string(&report).expect("safe GC report JSON");
        assert!(!encoded.contains("desktop-gc-managed-key"));
        assert!(!encoded.contains(retained_private_key));
        assert!(!encoded.contains(orphan_private_key));

        let retained = resolve_test_managed_bundle(&state, managed).await;
        assert_eq!(retained.private_key(), retained_private_key.as_bytes());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn password_and_managed_key_share_one_vault_commit_and_transaction() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, _) = desktop_state_with_memory_credentials(&current_vault);
        let private_key = "managed-batch-private-sentinel";
        let password = "managed-batch-password-sentinel";
        let source = legacy_password_and_managed_source("managed-batch-key", private_key, password);

        let inspected_document =
            netcatty_migration::parse_legacy_vault(&source, 200).expect("batch inspection");
        let inspection = inspect_legacy_vault_document(state.clone(), inspected_document)
            .await
            .expect("batch assessment");
        assert_eq!(inspection.preview.importable_count, 1);
        assert_eq!(inspection.importable_managed_ssh_key_count, 1);
        let commit_document =
            netcatty_migration::parse_legacy_vault(&source, 200).expect("batch commit");
        let result =
            commit_legacy_vault_document(&state, inspection.inventory_revision, commit_document)
                .await
                .expect("password and managed import");

        assert_eq!(result.imported_count, 1);
        assert_eq!(result.managed_ssh_keys_imported_count, 1);
        assert_eq!(result.managed_secret_blobs_published_count, 1);
        assert_eq!(result.credentials_stored_count, 1);
        assert_eq!(snapshot_count(&current_vault.join("saved-hosts")), 1);
        let durable = state
            .saved_hosts
            .confirm_current_snapshot_durability()
            .expect("durable batch snapshot");
        assert_eq!(durable.revision().loaded_generation(), 1);
        assert_eq!(durable.graph().hosts().len(), 1);
        assert_eq!(durable.graph().managed_ssh_keys().len(), 1);

        let reference = stored_host_reference("password-and-managed-host");
        let stored = state
            .persistent_credentials
            .resolve(&reference, CredentialKind::SshPassword)
            .await
            .expect("batch password");
        assert!(
            stored.as_utf8().ok() == Some(password),
            "batch password did not round-trip"
        );
        let bundle =
            resolve_test_managed_bundle(&state, durable.graph().managed_ssh_keys()[0].clone())
                .await;
        assert!(
            bundle.private_key() == private_key.as_bytes(),
            "batch private key did not round-trip"
        );
        assert!(
            load_legacy_import_transaction(&state)
                .await
                .expect("completed transaction lookup")
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn duplicate_managed_metadata_with_changed_secret_fails_without_replacement() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, _) = desktop_state_with_memory_credentials(&current_vault);
        let original_private_key = "managed-duplicate-original-sentinel";
        let replacement_private_key = "managed-duplicate-replacement-sentinel";
        let original = legacy_managed_graph_source(
            "managed-duplicate-key",
            None,
            original_private_key,
            None,
            None,
            None,
            false,
        );
        let inspected = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&original, 300).expect("original inspection"),
        )
        .await
        .expect("original assessment");
        commit_legacy_vault_document(
            &state,
            inspected.inventory_revision,
            netcatty_migration::parse_legacy_vault(&original, 300).expect("original commit"),
        )
        .await
        .expect("original managed import");

        let changed = legacy_managed_graph_source(
            "managed-duplicate-key",
            None,
            replacement_private_key,
            None,
            None,
            None,
            false,
        );
        let changed_inspection = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&changed, 300).expect("changed inspection"),
        )
        .await
        .expect("changed assessment");
        assert_eq!(changed_inspection.duplicate_managed_ssh_key_count, 1);
        assert_eq!(changed_inspection.importable_managed_ssh_key_count, 0);
        let error = commit_legacy_vault_document(
            &state,
            changed_inspection.inventory_revision,
            netcatty_migration::parse_legacy_vault(&changed, 300).expect("changed commit"),
        )
        .await
        .expect_err("changed secret must not be accepted as a duplicate");
        assert!(
            error.starts_with(super::LEGACY_VAULT_SECRET_STORE_FAILED)
                || error.starts_with(super::LEGACY_VAULT_SECRET_STORE_REPAIR_REQUIRED)
        );
        assert!(!error.contains(original_private_key));
        assert!(!error.contains(replacement_private_key));
        assert_eq!(snapshot_count(&current_vault.join("saved-hosts")), 1);

        let graph = state.saved_hosts.graph().expect("unchanged managed graph");
        let bundle = resolve_test_managed_bundle(&state, graph.managed_ssh_keys()[0].clone()).await;
        assert!(
            bundle.private_key() == original_private_key.as_bytes(),
            "original managed secret changed"
        );
        assert!(
            bundle.private_key() != replacement_private_key.as_bytes(),
            "replacement managed secret was published"
        );
        assert!(
            load_legacy_import_transaction(&state)
                .await
                .expect("duplicate transaction lookup")
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn managed_saved_host_prepares_without_picker_and_accepts_only_one_shot_passphrase() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, _) = desktop_state_with_memory_credentials(&current_vault);
        let private_key = "managed-connection-private-sentinel";
        let supplied_passphrase = "managed-one-shot-passphrase-sentinel";
        let source = legacy_managed_graph_source(
            "managed-connection-key",
            Some("managed-connection-host"),
            private_key,
            None,
            None,
            None,
            false,
        );
        let inspection = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&source, 400).expect("managed host inspection"),
        )
        .await
        .expect("managed host assessment");
        let result = commit_legacy_vault_document(
            &state,
            inspection.inventory_revision,
            netcatty_migration::parse_legacy_vault(&source, 400).expect("managed host commit"),
        )
        .await
        .expect("managed host import");
        assert_eq!(result.imported_count, 1);
        assert_eq!(result.managed_ssh_keys_imported_count, 1);
        assert_eq!(result.identity_references_imported_count, 1);

        let graph = state.saved_hosts.graph().expect("managed host graph");
        let host = graph.hosts()[0].clone();
        let view = super::saved_host_view_from_graph(&host, &graph).expect("managed host view");
        assert_eq!(view.key_source, super::SavedHostKeySource::Managed);
        assert!(!view.has_saved_key_passphrase);
        let view_json = serde_json::to_string(&view).expect("managed host view");
        assert_renderer_json_excludes(
            &view_json,
            &[
                private_key,
                supplied_passphrase,
                graph.managed_ssh_keys()[0]
                    .custody()
                    .backend_locator()
                    .as_str(),
            ],
        );

        let staged = state
            .ephemeral_credentials
            .insert("managed-window", test_secret(supplied_passphrase))
            .await
            .expect("stage managed passphrase");
        let prepared = prepare_test_saved_host_session(
            &state,
            "managed-window",
            StartSavedHostSessionRequest {
                client_attempt_id: test_client_attempt_id(),
                host_id: host.id.as_str().to_owned(),
                expected_revision: host.revision,
                credential_reference: None,
                proxy_credential_reference: None,
                key_passphrase_reference: Some(staged.clone()),
                selected_identity_file_paths: Vec::new(),
                known_hosts: Vec::new(),
                verify_host_keys: true,
                shell: None,
            },
        )
        .await
        .expect("managed host preparation without picker");
        assert!(prepared.config.auth.has_private_key);
        assert!(!prepared.config.auth.has_certificate);
        assert!(prepared.config.auth.identity_file_paths.is_empty());
        assert_eq!(prepared.config.auth.use_ssh_agent, Some(false));
        assert_eq!(prepared.config.auth.identities_only, Some(true));
        drop(prepared);
        assert!(
            state
                .ephemeral_credentials
                .take("managed-window", &staged)
                .await
                .is_err(),
            "managed passphrase reference was not one-shot"
        );

        let picker_error = prepare_test_saved_host_session(
            &state,
            "managed-window",
            StartSavedHostSessionRequest {
                client_attempt_id: test_client_attempt_id(),
                host_id: host.id.as_str().to_owned(),
                expected_revision: host.revision,
                credential_reference: None,
                proxy_credential_reference: None,
                key_passphrase_reference: None,
                selected_identity_file_paths: vec!["C:\\must-not-be-used".to_owned()],
                known_hosts: Vec::new(),
                verify_host_keys: true,
                shell: None,
            },
        )
        .await
        .err()
        .expect("managed host must reject picker input");
        assert!(picker_error.starts_with(super::SAVED_HOST_KEY_FILE_SELECTION_INVALID));
        assert!(!picker_error.contains(private_key));
        assert!(!picker_error.contains(supplied_passphrase));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn managed_key_jump_is_resolved_from_custody_without_target_secret_reuse() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, _) = desktop_state_with_memory_credentials(&current_vault);
        let private_key = "managed-chain-private-sentinel";
        let saved_passphrase = "managed-chain-passphrase-sentinel";
        let source = legacy_managed_graph_source(
            "managed-chain-key",
            Some("managed-chain-jump"),
            private_key,
            None,
            None,
            Some(saved_passphrase),
            true,
        );
        let inspection = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&source, 500).expect("managed chain inspection"),
        )
        .await
        .expect("managed chain assessment");
        commit_legacy_vault_document(
            &state,
            inspection.inventory_revision,
            netcatty_migration::parse_legacy_vault(&source, 500).expect("managed chain commit"),
        )
        .await
        .expect("managed chain import");

        let snapshot = state
            .saved_hosts
            .confirm_current_snapshot_durability()
            .expect("managed chain snapshot");
        let (
            mut hosts,
            references,
            managed_keys,
            identities,
            password_identities,
            proxy_profiles,
            groups,
        ) = snapshot.graph().clone().into_complete_parts();
        hosts.push(test_chain_host(
            "managed-chain-target",
            "ssh",
            Some(json!({ "hostIds": ["managed-chain-jump"] })),
        ));
        let replacement = SavedVaultGraph::new_with_proxy_profiles(
            hosts,
            references,
            managed_keys,
            identities,
            password_identities,
            proxy_profiles,
            groups,
        );
        let plan = state
            .saved_hosts
            .plan_graph_replacement(snapshot.revision().clone(), &replacement)
            .expect("managed chain replacement plan");
        state
            .saved_hosts
            .commit_planned_graph_replacement(plan, replacement)
            .expect("managed chain replacement");
        let graph = state.saved_hosts.graph().expect("managed chain graph");
        let target = graph
            .hosts()
            .iter()
            .find(|host| host.id.as_str() == "managed-chain-target")
            .expect("managed chain target");
        let staged = state
            .ephemeral_credentials
            .insert(
                "managed-chain-window",
                test_secret("managed-target-password-sentinel"),
            )
            .await
            .expect("target password");
        let mut request = saved_password_session_request(target);
        request.credential_reference = Some(staged);

        let prepared = prepare_test_saved_host_session(&state, "managed-chain-window", request)
            .await
            .expect("managed jump preparation");
        assert_eq!(prepared.jump_hosts.len(), 1);
        let jump = &prepared.jump_hosts[0];
        assert_eq!(jump.host_id, "managed-chain-jump");
        assert!(jump.config.auth.has_private_key);
        assert!(!jump.config.auth.has_certificate);
        assert!(jump.config.auth.identity_file_paths.is_empty());
        assert_eq!(jump.config.auth.use_ssh_agent, Some(false));
        assert_eq!(jump.config.auth.identities_only, Some(true));
        let debug = format!("{:?}", jump.config);
        assert!(!debug.contains(private_key));
        assert!(!debug.contains(saved_passphrase));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn password_and_reference_hosts_reject_managed_key_passphrase_references() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let state = DesktopState::open(directory.path()).expect("desktop state");
        let password_host: SavedHost = serde_json::from_value(json!({
            "recordVersion": 1,
            "id": "passphrase-boundary-password-host",
            "revision": 1,
            "label": "Password host",
            "hostname": "password-boundary.example.test",
            "port": 22,
            "username": "alice",
            "protocol": "ssh",
            "authMethod": "password",
            "authPolicyVersion": 1,
            "createdAt": 1,
            "updatedAt": 1,
            "hasSavedCredential": false
        }))
        .expect("password host");
        let reference_host: SavedHost = serde_json::from_value(json!({
            "recordVersion": 1,
            "id": "passphrase-boundary-reference-host",
            "revision": 1,
            "label": "Reference host",
            "hostname": "reference-boundary.example.test",
            "port": 22,
            "username": "bob",
            "protocol": "ssh",
            "authMethod": "key",
            "authPolicyVersion": 1,
            "createdAt": 1,
            "updatedAt": 1,
            "identityFilePaths": ["C:\\legacy\\reference-key"]
        }))
        .expect("reference host");
        let hosts = vec![password_host.clone(), reference_host.clone()];
        let revision = state
            .saved_hosts
            .assess_import(&hosts)
            .expect("passphrase boundary assessment")
            .into_revision();
        state
            .saved_hosts
            .commit_import(revision, hosts)
            .expect("passphrase boundary commit");

        for (host, selected_paths, marker) in [
            (
                password_host,
                Vec::new(),
                "password-host-passphrase-sentinel",
            ),
            (
                reference_host,
                vec!["C:\\selected\\reference-key".to_owned()],
                "reference-host-passphrase-sentinel",
            ),
        ] {
            let staged = state
                .ephemeral_credentials
                .insert("passphrase-boundary-window", test_secret(marker))
                .await
                .expect("stage rejected key passphrase");
            let error = prepare_test_saved_host_session(
                &state,
                "passphrase-boundary-window",
                StartSavedHostSessionRequest {
                    client_attempt_id: test_client_attempt_id(),
                    host_id: host.id.as_str().to_owned(),
                    expected_revision: host.revision,
                    credential_reference: None,
                    proxy_credential_reference: None,
                    key_passphrase_reference: Some(staged.clone()),
                    selected_identity_file_paths: selected_paths,
                    known_hosts: Vec::new(),
                    verify_host_keys: true,
                    shell: None,
                },
            )
            .await
            .err()
            .expect("non-managed host must reject managed passphrase");
            assert!(error.starts_with(super::SAVED_HOST_KEY_FILE_SELECTION_INVALID));
            assert!(!error.contains(marker));
            assert!(
                state
                    .ephemeral_credentials
                    .take("passphrase-boundary-window", &staged)
                    .await
                    .is_err(),
                "rejected passphrase reference was not consumed"
            );
        }
    }

    fn remove_secret_store_keyset_and_objects(secret_root: &std::path::Path) {
        for directory in ["keyset", "objects"] {
            let path = secret_root.join(directory);
            if path.exists() {
                std::fs::remove_dir_all(&path).expect("remove test secret-store directory");
            }
        }
    }

    fn assert_no_master_key_creation_or_deletion(controller: &InMemoryCredentialController) {
        let operations = controller.operation_log();
        assert_eq!(operations.count(CredentialOperation::Upsert), 0);
        assert_eq!(operations.count(CredentialOperation::Delete), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn managed_vault_locator_prevents_reinitializing_an_erased_secret_store() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, _, master_controller) =
            desktop_state_with_memory_credentials_and_master_keys(&current_vault);
        let first_source = legacy_managed_graph_source(
            "initial-managed-key",
            None,
            "initial-managed-private-key-sentinel",
            None,
            None,
            None,
            false,
        );
        let first_inspection = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&first_source, 500)
                .expect("initial managed inspection"),
        )
        .await
        .expect("initial managed assessment");
        commit_legacy_vault_document(
            &state,
            first_inspection.inventory_revision,
            netcatty_migration::parse_legacy_vault(&first_source, 500)
                .expect("initial managed commit"),
        )
        .await
        .expect("initial managed import");

        let second_source = legacy_managed_graph_source(
            "second-managed-key",
            None,
            "second-managed-private-key-sentinel",
            None,
            None,
            None,
            false,
        );
        let second_inspection = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&second_source, 501)
                .expect("second managed inspection"),
        )
        .await
        .expect("second managed assessment");

        let secret_root = current_vault.join("secret-blobs");
        remove_secret_store_keyset_and_objects(&secret_root);
        std::fs::remove_file(secret_root.join("owner.json")).expect("remove test owner marker");
        let mut remaining = std::fs::read_dir(&secret_root)
            .expect("read erased secret store")
            .map(|entry| {
                entry
                    .expect("erased secret-store entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        remaining.sort();
        assert_eq!(remaining, vec!["transaction.lock"]);
        master_controller.clear_operation_log();

        let error = commit_legacy_vault_document(
            &state,
            second_inspection.inventory_revision,
            netcatty_migration::parse_legacy_vault(&second_source, 501)
                .expect("second managed commit"),
        )
        .await
        .expect_err("Vault locator must forbid replacement secret-store initialization");
        assert!(error.starts_with(super::LEGACY_VAULT_SECRET_STORE_REPAIR_REQUIRED));
        assert_no_master_key_creation_or_deletion(&master_controller);
        let guard = state
            .secret_files
            .lock_exclusive()
            .expect("secret-store lock after rejected initialization");
        assert!(guard.owner_id().expect("owner lookup").is_none());
        drop(guard);
        assert_eq!(snapshot_count(&current_vault.join("saved-hosts")), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn managed_vault_locator_prevents_rebuilding_a_missing_keyset_for_an_existing_owner() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, _, master_controller) =
            desktop_state_with_memory_credentials_and_master_keys(&current_vault);
        let first_source = legacy_managed_graph_source(
            "owner-retained-managed-key",
            None,
            "owner-retained-private-key-sentinel",
            None,
            None,
            None,
            false,
        );
        let first_inspection = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&first_source, 510)
                .expect("owner-retained managed inspection"),
        )
        .await
        .expect("owner-retained managed assessment");
        commit_legacy_vault_document(
            &state,
            first_inspection.inventory_revision,
            netcatty_migration::parse_legacy_vault(&first_source, 510)
                .expect("owner-retained managed commit"),
        )
        .await
        .expect("owner-retained managed import");
        let owner = {
            let guard = state
                .secret_files
                .lock_exclusive()
                .expect("secret-store lock before keyset erasure");
            guard
                .owner_id()
                .expect("owner lookup")
                .expect("initialized owner")
        };

        let second_source = legacy_managed_graph_source(
            "owner-retained-second-key",
            None,
            "owner-retained-second-private-key-sentinel",
            None,
            None,
            None,
            false,
        );
        let second_inspection = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&second_source, 511)
                .expect("owner-retained second inspection"),
        )
        .await
        .expect("owner-retained second assessment");

        let secret_root = current_vault.join("secret-blobs");
        remove_secret_store_keyset_and_objects(&secret_root);
        let owner_bytes = std::fs::read(secret_root.join("owner.json"))
            .expect("retained owner marker before rejected initialization");
        master_controller.clear_operation_log();

        let error = commit_legacy_vault_document(
            &state,
            second_inspection.inventory_revision,
            netcatty_migration::parse_legacy_vault(&second_source, 511)
                .expect("owner-retained second commit"),
        )
        .await
        .expect_err("Vault locator must forbid rebuilding an erased keyset");
        assert!(error.starts_with(super::LEGACY_VAULT_SECRET_STORE_REPAIR_REQUIRED));
        assert_no_master_key_creation_or_deletion(&master_controller);
        assert_eq!(
            std::fs::read(secret_root.join("owner.json")).expect("retained owner marker"),
            owner_bytes
        );
        assert!(!secret_root.join("keyset").exists());
        assert!(!secret_root.join("objects").exists());
        let guard = state
            .secret_files
            .lock_exclusive()
            .expect("secret-store lock after rejected keyset rebuild");
        assert_eq!(guard.owner_id().expect("owner lookup"), Some(owner));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pending_import_journal_prevents_first_secret_store_initialization() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, _, master_controller) =
            desktop_state_with_memory_credentials_and_master_keys(&current_vault);
        let source = legacy_managed_graph_source(
            "journal-gated-managed-key",
            None,
            "journal-gated-private-key-sentinel",
            None,
            None,
            None,
            false,
        );
        let inspection = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&source, 520).expect("journal-gated inspection"),
        )
        .await
        .expect("journal-gated assessment");
        let before = state
            .saved_hosts
            .confirm_current_snapshot_durability()
            .expect("empty durable Vault")
            .commitment()
            .clone();
        let mut after = netcatty_vault::SavedVaultGraphCommitment::from_digest([0xC3; 32]);
        if after == before {
            after = netcatty_vault::SavedVaultGraphCommitment::from_digest([0x3C; 32]);
        }
        let pending =
            super::begin_legacy_import_transaction_with_blobs(&state, Vec::new(), before, after)
                .await
                .expect("pending managed journal");
        master_controller.clear_operation_log();

        let error = commit_legacy_vault_document(
            &state,
            inspection.inventory_revision,
            netcatty_migration::parse_legacy_vault(&source, 520).expect("journal-gated commit"),
        )
        .await
        .expect_err("pending journal must forbid first secret-store initialization");
        assert!(error.starts_with(super::LEGACY_VAULT_IMPORT_REPAIR_REQUIRED));
        assert_no_master_key_creation_or_deletion(&master_controller);
        let guard = state
            .secret_files
            .lock_exclusive()
            .expect("secret-store lock after journal gate");
        assert!(guard.owner_id().expect("owner lookup").is_none());
        drop(guard);
        assert_eq!(pending.phase(), LegacyImportTransactionPhase::Preparing);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn missing_initial_keyset_slot_b_is_repaired_by_the_next_managed_operation() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, _) = desktop_state_with_memory_credentials(&current_vault);
        let private_key = "managed-keyset-repair-private-sentinel";
        let source = legacy_managed_graph_source(
            "managed-keyset-repair-key",
            None,
            private_key,
            None,
            None,
            None,
            false,
        );
        let inspection = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&source, 450).expect("keyset repair inspection"),
        )
        .await
        .expect("keyset repair assessment");
        commit_legacy_vault_document(
            &state,
            inspection.inventory_revision,
            netcatty_migration::parse_legacy_vault(&source, 450).expect("keyset repair commit"),
        )
        .await
        .expect("initial managed import");

        let slot_b = current_vault.join("secret-blobs/keyset/slot-b");
        let initial_slot_b_files = std::fs::read_dir(&slot_b)
            .expect("initial keyset slot B")
            .map(|entry| entry.expect("initial keyset entry").path())
            .filter(|path| path.is_file())
            .collect::<Vec<_>>();
        assert_eq!(initial_slot_b_files.len(), 1);
        std::fs::remove_file(&initial_slot_b_files[0]).expect("remove initial keyset slot B");

        let repeat_inspection = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&source, 450)
                .expect("keyset repair repeat inspection"),
        )
        .await
        .expect("fallback keyset remains inspectable");
        let repeat_result = commit_legacy_vault_document(
            &state,
            repeat_inspection.inventory_revision,
            netcatty_migration::parse_legacy_vault(&source, 450)
                .expect("keyset repair repeat commit"),
        )
        .await
        .expect("managed operation repairs missing keyset slot B");
        assert_eq!(repeat_result.managed_ssh_keys_imported_count, 0);
        assert_eq!(repeat_result.managed_secret_blobs_published_count, 1);

        let repaired_slot_b_files = std::fs::read_dir(&slot_b)
            .expect("repaired keyset slot B")
            .map(|entry| entry.expect("repaired keyset entry").path())
            .filter(|path| path.is_file())
            .collect::<Vec<_>>();
        assert_eq!(repaired_slot_b_files.len(), 1);
        assert!(repaired_slot_b_files[0] != initial_slot_b_files[0]);
        let confirmed = {
            let guard = state
                .secret_files
                .lock_exclusive()
                .expect("secret-store lock");
            let store_state = guard.load_state().expect("repaired keyset state");
            guard
                .confirm_keyset_durability(&store_state)
                .expect("repaired keyset durability")
        };
        assert_eq!(confirmed.keyset_generation(), 2);
        let graph = state.saved_hosts.graph().expect("repaired managed graph");
        let bundle = resolve_test_managed_bundle(&state, graph.managed_ssh_keys()[0].clone()).await;
        assert!(
            bundle.private_key() == private_key.as_bytes(),
            "managed secret was unavailable after keyset repair"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn corrupt_initial_keyset_slot_b_is_not_overwritten_and_remains_repair_required() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, _) = desktop_state_with_memory_credentials(&current_vault);
        let private_key = "managed-keyset-corrupt-private-sentinel";
        let source = legacy_managed_graph_source(
            "managed-keyset-corrupt-key",
            None,
            private_key,
            None,
            None,
            None,
            false,
        );
        let inspection = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&source, 460)
                .expect("corrupt keyset inspection"),
        )
        .await
        .expect("corrupt keyset assessment");
        commit_legacy_vault_document(
            &state,
            inspection.inventory_revision,
            netcatty_migration::parse_legacy_vault(&source, 460).expect("corrupt keyset commit"),
        )
        .await
        .expect("initial managed import");

        let slot_b = current_vault.join("secret-blobs/keyset/slot-b");
        let slot_b_files = std::fs::read_dir(&slot_b)
            .expect("initial keyset slot B")
            .map(|entry| entry.expect("initial keyset entry").path())
            .filter(|path| path.is_file())
            .collect::<Vec<_>>();
        assert_eq!(slot_b_files.len(), 1);
        let corrupt_bytes = b"corrupt-keyset-slot-b";
        std::fs::write(&slot_b_files[0], corrupt_bytes).expect("corrupt keyset slot B");

        let operation_error = match inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&source, 460)
                .expect("corrupt keyset repeat inspection"),
        )
        .await
        {
            Ok(repeat_inspection) => commit_legacy_vault_document(
                &state,
                repeat_inspection.inventory_revision,
                netcatty_migration::parse_legacy_vault(&source, 460)
                    .expect("corrupt keyset repeat commit"),
            )
            .await
            .expect_err("corrupt keyset must reject managed commit"),
            Err(error) => error,
        };
        assert!(operation_error.starts_with(super::LEGACY_VAULT_SECRET_STORE_REPAIR_REQUIRED));
        assert!(!operation_error.contains(private_key));
        let retained_slot_b_files = std::fs::read_dir(&slot_b)
            .expect("retained corrupt keyset slot B")
            .map(|entry| entry.expect("retained keyset entry").path())
            .filter(|path| path.is_file())
            .collect::<Vec<_>>();
        assert_eq!(retained_slot_b_files.len(), 1);
        assert!(retained_slot_b_files[0] == slot_b_files[0]);
        let retained_bytes =
            std::fs::read(&retained_slot_b_files[0]).expect("read retained corrupt keyset");
        assert!(
            retained_bytes == corrupt_bytes,
            "corrupt keyset artifact was overwritten"
        );
        assert_eq!(snapshot_count(&current_vault.join("saved-hosts")), 1);
    }

    #[test]
    fn initialization_failure_cleanup_requires_an_authoritatively_absent_owner() {
        use super::{
            SecretStoreInitializationFailureDisposition,
            secret_store_initialization_failure_disposition,
        };

        let expected_owner = uuid::Uuid::new_v4();
        let conflicting_owner = uuid::Uuid::new_v4();
        assert_eq!(
            secret_store_initialization_failure_disposition(expected_owner, Ok(None)),
            SecretStoreInitializationFailureDisposition::DeleteUnownedMasterKey
        );
        assert_eq!(
            secret_store_initialization_failure_disposition(
                expected_owner,
                Ok(Some(expected_owner)),
            ),
            SecretStoreInitializationFailureDisposition::RetainForRetry
        );
        assert_eq!(
            secret_store_initialization_failure_disposition(
                expected_owner,
                Ok(Some(conflicting_owner)),
            ),
            SecretStoreInitializationFailureDisposition::RetainForRepair
        );
        assert_eq!(
            secret_store_initialization_failure_disposition(
                expected_owner,
                Err(netcatty_secret_store::SecretFileStoreError::new(
                    netcatty_secret_store::SecretFileStoreErrorCode::StorageUnavailable,
                )),
            ),
            SecretStoreInitializationFailureDisposition::RetainForRepair
        );
    }

    #[test]
    fn visible_owner_after_incomplete_initialization_retains_its_master_key() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (master_keys, master_controller) = in_memory_master_key_store();
        let mut state = DesktopState::open(&current_vault).expect("desktop state");
        state.master_keys = master_keys;
        let owner = uuid::Uuid::new_v4();
        let master_key = state
            .master_keys
            .create_if_absent_blocking(owner, 1)
            .expect("initial master key");
        let guard = state
            .secret_files
            .lock_exclusive()
            .expect("secret-store lock");
        let mutation = guard
            .initialize(owner, 1)
            .expect("initial secret-store layout");
        super::confirm_secret_store_initialization(&guard, mutation)
            .expect("initial secret-store durability");
        drop(master_key);
        drop(guard);

        for slot in ["slot-a", "slot-b"] {
            let directory = current_vault.join("secret-blobs/keyset").join(slot);
            for entry in std::fs::read_dir(directory).expect("keyset slot") {
                let path = entry.expect("keyset entry").path();
                if path.is_file() {
                    std::fs::remove_file(path).expect("remove incomplete keyset copy");
                }
            }
        }
        std::fs::write(
            current_vault.join("secret-blobs/objects/unexpected-artifact"),
            b"non-secret-artifact",
        )
        .expect("create incomplete object artifact");
        master_controller.clear_operation_log();

        let guard = state
            .secret_files
            .lock_exclusive()
            .expect("incomplete secret-store lock");
        let error = super::load_or_initialize_secret_store(&guard, &state.master_keys, true)
            .expect_err("visible owner with ambiguous objects must require repair");
        assert!(error.starts_with(super::LEGACY_VAULT_SECRET_STORE_REPAIR_REQUIRED));
        assert_eq!(
            master_controller
                .operation_log()
                .count(CredentialOperation::Delete),
            0
        );
        assert!(guard.owner_id().ok().flatten() == Some(owner));
        drop(guard);
        assert!(state.master_keys.load_blocking(owner, 1).is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn uncertain_owner_check_retains_the_existing_master_key() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (master_keys, master_controller) = in_memory_master_key_store();
        let mut state = DesktopState::open(&current_vault).expect("desktop state");
        state.master_keys = master_keys;
        let owner = uuid::Uuid::new_v4();
        let master_key = state
            .master_keys
            .create_if_absent(owner, 1)
            .await
            .expect("initial master key");
        {
            let guard = state
                .secret_files
                .lock_exclusive()
                .expect("secret-store lock");
            let mutation = guard
                .initialize(owner, 1)
                .expect("initial secret-store layout");
            super::confirm_secret_store_initialization(&guard, mutation)
                .expect("initial secret-store durability");
        }
        drop(master_key);
        let owner_path = current_vault.join("secret-blobs/owner.json");
        let uncertain_owner_bytes = b"uncertain-owner-artifact";
        std::fs::write(&owner_path, uncertain_owner_bytes).expect("corrupt owner artifact");
        master_controller.clear_operation_log();

        let error = super::SecretStoreTransactionLease::start(&state, true)
            .await
            .err()
            .expect("uncertain owner must fail closed");
        assert!(error.starts_with(super::LEGACY_VAULT_SECRET_STORE_REPAIR_REQUIRED));
        assert_eq!(
            master_controller
                .operation_log()
                .count(CredentialOperation::Delete),
            0
        );
        assert!(state.master_keys.load(owner, 1).await.is_ok());
        let retained = std::fs::read(owner_path).expect("retained uncertain owner");
        assert!(
            retained == uncertain_owner_bytes,
            "uncertain owner artifact was overwritten"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blobs_durable_restart_with_exact_before_graph_clears_the_journal() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, _) = desktop_state_with_memory_credentials(&current_vault);
        let before = state
            .saved_hosts
            .confirm_current_snapshot_durability()
            .expect("empty durable Vault")
            .commitment()
            .clone();
        let mut after = netcatty_vault::SavedVaultGraphCommitment::from_digest([0xA5; 32]);
        if after == before {
            after = netcatty_vault::SavedVaultGraphCommitment::from_digest([0x5A; 32]);
        }
        let transaction =
            super::begin_legacy_import_transaction_with_blobs(&state, Vec::new(), before, after)
                .await
                .expect("begin blob journal");
        let transaction = super::mark_legacy_blobs_durable(transaction)
            .await
            .expect("mark blobs durable");
        assert_eq!(
            transaction.phase(),
            LegacyImportTransactionPhase::BlobsDurable
        );
        drop(transaction);

        let persistent_credentials = state.persistent_credentials.clone();
        let master_keys = state.master_keys.clone();
        let mut restarted = restarted_desktop_state(&current_vault, &persistent_credentials);
        restarted.master_keys = master_keys;
        recover_pending_legacy_import(&restarted)
            .await
            .expect("exact-before BlobsDurable recovery");
        assert!(
            load_legacy_import_transaction(&restarted)
                .await
                .expect("journal lookup after recovery")
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn active_exact_after_with_missing_or_corrupt_managed_blobs_fails_closed() {
        for corrupt_instead_of_remove in [false, true] {
            let directory = tempfile::tempdir().expect("temporary vault");
            let current_vault = directory.path().join("current");
            let (state, _) = desktop_state_with_memory_credentials(&current_vault);
            let private_key = "managed-recovery-private-sentinel";
            let source = legacy_managed_graph_source(
                "managed-recovery-key",
                None,
                private_key,
                None,
                None,
                None,
                false,
            );
            let inspection = inspect_legacy_vault_document(
                state.clone(),
                netcatty_migration::parse_legacy_vault(&source, 500).expect("recovery inspection"),
            )
            .await
            .expect("recovery assessment");
            commit_legacy_vault_document(
                &state,
                inspection.inventory_revision,
                netcatty_migration::parse_legacy_vault(&source, 500).expect("recovery commit"),
            )
            .await
            .expect("recovery managed import");
            let after = state
                .saved_hosts
                .confirm_current_snapshot_durability()
                .expect("managed durable Vault")
                .commitment()
                .clone();
            let mut before = netcatty_vault::SavedVaultGraphCommitment::from_digest([0xC3; 32]);
            if before == after {
                before = netcatty_vault::SavedVaultGraphCommitment::from_digest([0x3C; 32]);
            }
            let transaction = super::begin_legacy_import_transaction_with_blobs(
                &state,
                Vec::new(),
                before,
                after,
            )
            .await
            .expect("begin active blob journal");
            let transaction = super::mark_legacy_blobs_durable(transaction)
                .await
                .expect("mark recovery blobs durable");
            let transaction = activate_legacy_import_transaction(transaction, Vec::new())
                .await
                .expect("activate recovery journal");
            assert_eq!(transaction.phase(), LegacyImportTransactionPhase::Active);
            drop(transaction);

            let blob_paths = secret_blob_paths(&current_vault.join("secret-blobs"));
            assert_eq!(blob_paths.len(), 2);
            for path in blob_paths {
                if corrupt_instead_of_remove {
                    std::fs::write(path, b"corrupt-managed-blob").expect("corrupt managed blob");
                } else {
                    std::fs::remove_file(path).expect("remove managed blob");
                }
            }

            let persistent_credentials = state.persistent_credentials.clone();
            let master_keys = state.master_keys.clone();
            let mut restarted = restarted_desktop_state(&current_vault, &persistent_credentials);
            restarted.master_keys = master_keys;
            let error = recover_pending_legacy_import(&restarted)
                .await
                .expect_err("missing or corrupt managed blobs must fail closed");
            assert!(error.starts_with(super::LEGACY_VAULT_SECRET_STORE_REPAIR_REQUIRED));
            assert!(!error.contains(private_key));
            let pending = load_legacy_import_transaction(&restarted)
                .await
                .expect("retained repair journal")
                .expect("active journal retained");
            assert_eq!(pending.phase(), LegacyImportTransactionPhase::Active);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn active_exact_after_repairs_missing_keyset_slot_b_before_blob_confirmation() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, _) = desktop_state_with_memory_credentials(&current_vault);
        let private_key = "managed-active-keyset-repair-sentinel";
        let source = legacy_managed_graph_source(
            "managed-active-keyset-repair-key",
            None,
            private_key,
            None,
            None,
            None,
            false,
        );
        let inspection = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&source, 520)
                .expect("active keyset repair inspection"),
        )
        .await
        .expect("active keyset repair assessment");
        commit_legacy_vault_document(
            &state,
            inspection.inventory_revision,
            netcatty_migration::parse_legacy_vault(&source, 520)
                .expect("active keyset repair commit"),
        )
        .await
        .expect("active keyset repair import");

        let after = state
            .saved_hosts
            .confirm_current_snapshot_durability()
            .expect("active keyset durable Vault")
            .commitment()
            .clone();
        let mut before = netcatty_vault::SavedVaultGraphCommitment::from_digest([0xD4; 32]);
        if before == after {
            before = netcatty_vault::SavedVaultGraphCommitment::from_digest([0x4D; 32]);
        }
        let transaction =
            super::begin_legacy_import_transaction_with_blobs(&state, Vec::new(), before, after)
                .await
                .expect("begin active keyset repair journal");
        let transaction = super::mark_legacy_blobs_durable(transaction)
            .await
            .expect("mark active keyset blobs durable");
        let transaction = activate_legacy_import_transaction(transaction, Vec::new())
            .await
            .expect("activate keyset repair journal");
        assert_eq!(transaction.phase(), LegacyImportTransactionPhase::Active);
        drop(transaction);

        let slot_b = current_vault.join("secret-blobs/keyset/slot-b");
        let slot_b_files = std::fs::read_dir(&slot_b)
            .expect("initial active keyset slot B")
            .map(|entry| entry.expect("initial active keyset entry").path())
            .filter(|path| path.is_file())
            .collect::<Vec<_>>();
        assert_eq!(slot_b_files.len(), 1);
        std::fs::remove_file(&slot_b_files[0]).expect("remove active keyset slot B");

        let persistent_credentials = state.persistent_credentials.clone();
        let master_keys = state.master_keys.clone();
        let mut restarted = restarted_desktop_state(&current_vault, &persistent_credentials);
        restarted.master_keys = master_keys;
        recover_pending_legacy_import(&restarted)
            .await
            .expect("Active exact-after keyset repair and blob confirmation");
        assert!(
            load_legacy_import_transaction(&restarted)
                .await
                .expect("completed active keyset journal lookup")
                .is_none()
        );
        let repaired_slot_b_files = std::fs::read_dir(&slot_b)
            .expect("repaired active keyset slot B")
            .map(|entry| entry.expect("repaired active keyset entry").path())
            .filter(|path| path.is_file())
            .collect::<Vec<_>>();
        assert_eq!(repaired_slot_b_files.len(), 1);
        assert!(repaired_slot_b_files[0] != slot_b_files[0]);
        let confirmed = {
            let guard = restarted
                .secret_files
                .lock_exclusive()
                .expect("repaired active secret-store lock");
            let store_state = guard.load_state().expect("repaired active keyset state");
            guard
                .confirm_keyset_durability(&store_state)
                .expect("repaired active keyset durability")
        };
        assert_eq!(confirmed.keyset_generation(), 2);
        let graph = restarted
            .saved_hosts
            .graph()
            .expect("recovered managed graph");
        let bundle =
            resolve_test_managed_bundle(&restarted, graph.managed_ssh_keys()[0].clone()).await;
        assert!(
            bundle.private_key() == private_key.as_bytes(),
            "managed blob was not confirmed after keyset repair"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn saved_host_coordinator_survives_waiter_cancellation_and_cross_state_races() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::time::Duration;

        let directory = tempfile::tempdir().expect("temporary vault");
        let first_state = DesktopState::open(directory.path()).expect("first state");
        let second_state = DesktopState::open(directory.path()).expect("second state");
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let first_started = Arc::new(tokio::sync::Notify::new());
        let first_finished = Arc::new(AtomicBool::new(false));

        let waiter = tokio::spawn({
            let active = active.clone();
            let max_active = max_active.clone();
            let first_started = first_started.clone();
            let first_finished = first_finished.clone();
            async move {
                run_saved_host_operation(first_state, move |_| async move {
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    max_active.fetch_max(current, Ordering::SeqCst);
                    first_started.notify_one();
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    first_finished.store(true, Ordering::SeqCst);
                    Ok(())
                })
                .await
            }
        });
        first_started.notified().await;
        waiter.abort();
        let _ = waiter.await;

        run_saved_host_operation(second_state, {
            let active = active.clone();
            let max_active = max_active.clone();
            move |_| async move {
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                max_active.fetch_max(current, Ordering::SeqCst);
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            }
        })
        .await
        .expect("second operation");

        assert!(first_finished.load(Ordering::SeqCst));
        assert_eq!(max_active.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn legacy_import_publishes_groups_scripts_and_notes_in_one_graph() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, controller) = desktop_state_with_memory_credentials(&current_vault);
        let source = serde_json::to_vec(&json!({
            "hosts": [{
                "id": "notes-import-host",
                "label": "Imported host",
                "hostname": "notes-import.example.test",
                "port": 22,
                "username": "alice",
                "protocol": "ssh",
                "authMethod": "password",
                "authPolicyVersion": 1,
                "loginScriptId": "notes-import-script"
            }],
            "customGroups": ["Imported/Operations"],
            "groupConfigs": [{
                "path": "Imported/Operations",
                "loginScriptId": "notes-import-script"
            }],
            "snippets": [{
                "id": "notes-import-script",
                "label": "Imported script",
                "command": "echo imported",
                "kind": "script",
                "targets": ["notes-import-host"]
            }],
            "snippetPackages": ["Imported package"],
            "notes": [{
                "id": "notes-import-note",
                "title": "Imported note",
                "content": "Imported note content",
                "linkedHostIds": ["notes-import-host"],
                "createdAt": 1,
                "updatedAt": 1
            }],
            "noteGroups": ["Imported notes"]
        }))
        .expect("legacy source JSON");

        let inspection = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&source, 100)
                .expect("legacy import inspection document"),
        )
        .await
        .expect("legacy import inspection");
        assert_eq!(inspection.preview.importable_count, 1);
        assert_eq!(inspection.importable_custom_group_count, 1);
        assert_eq!(inspection.importable_group_config_count, 1);
        assert_eq!(inspection.importable_snippet_count, 1);
        assert_eq!(inspection.importable_snippet_package_count, 1);
        assert_eq!(inspection.importable_note_count, 1);
        assert_eq!(inspection.importable_note_group_count, 1);

        let result = commit_legacy_vault_document(
            &state,
            inspection.inventory_revision,
            netcatty_migration::parse_legacy_vault(&source, 100)
                .expect("legacy import commit document"),
        )
        .await
        .expect("legacy import commit");
        assert_eq!(result.imported_count, 1);
        assert_eq!(result.custom_groups_imported_count, 1);
        assert_eq!(result.group_configs_imported_count, 1);
        assert_eq!(result.snippets_imported_count, 1);
        assert_eq!(result.snippet_packages_imported_count, 1);
        assert_eq!(result.notes_imported_count, 1);
        assert_eq!(result.note_groups_imported_count, 1);
        assert!(controller.operation_log().is_empty());

        let graph = state.saved_hosts.graph().expect("published import graph");
        let published_graph = graph.clone();
        assert_eq!(graph.hosts().len(), 1);
        assert_eq!(
            graph
                .group_catalog()
                .expect("published custom groups")
                .explicit_paths()
                .iter()
                .map(|path| path.as_str())
                .collect::<Vec<_>>(),
            ["Imported/Operations"]
        );
        assert_eq!(graph.groups().len(), 1);
        assert_eq!(
            graph.groups()[0].path.as_str(),
            "Imported/Operations",
            "group configuration was retained"
        );
        let snippets = graph
            .notes_snippets()
            .snippets()
            .expect("published snippets");
        assert_eq!(snippets.len(), 1);
        assert_eq!(
            snippets[0].targets().expect("script targets")[0],
            graph.hosts()[0].id
        );
        let notes = graph.notes_snippets().notes().expect("published notes");
        assert_eq!(notes.len(), 1);
        assert_eq!(
            notes[0].linked_host_ids().expect("note links")[0],
            graph.hosts()[0].id
        );
        assert_eq!(
            graph
                .notes_snippets()
                .snippet_packages()
                .expect("published snippet packages"),
            ["Imported package"]
        );
        assert_eq!(
            graph
                .notes_snippets()
                .note_groups()
                .expect("published note groups")
                .iter()
                .map(|group| group.as_str())
                .collect::<Vec<_>>(),
            ["Imported notes"]
        );

        let repeated_inspection = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&source, 100)
                .expect("repeated legacy import inspection document"),
        )
        .await
        .expect("repeated legacy import inspection");
        assert_eq!(repeated_inspection.preview.importable_count, 0);
        assert_eq!(repeated_inspection.importable_custom_group_count, 0);
        assert_eq!(repeated_inspection.importable_group_config_count, 0);
        assert_eq!(repeated_inspection.importable_snippet_count, 0);
        assert_eq!(repeated_inspection.importable_snippet_package_count, 0);
        assert_eq!(repeated_inspection.importable_note_count, 0);
        assert_eq!(repeated_inspection.importable_note_group_count, 0);
        let repeated_result = commit_legacy_vault_document(
            &state,
            repeated_inspection.inventory_revision,
            netcatty_migration::parse_legacy_vault(&source, 100)
                .expect("repeated legacy import commit document"),
        )
        .await
        .expect("repeated legacy import commit");
        assert_eq!(repeated_result.imported_count, 0);
        assert_eq!(repeated_result.custom_groups_imported_count, 0);
        assert_eq!(repeated_result.group_configs_imported_count, 0);
        assert_eq!(repeated_result.snippets_imported_count, 0);
        assert_eq!(repeated_result.snippet_packages_imported_count, 0);
        assert_eq!(repeated_result.notes_imported_count, 0);
        assert_eq!(repeated_result.note_groups_imported_count, 0);
        assert_eq!(
            state.saved_hosts.graph().expect("repeated import graph"),
            published_graph,
            "an identical legacy import must not mutate the graph"
        );
        assert!(controller.operation_log().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn legacy_import_persists_explicit_empty_catalog_scopes() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, controller) = desktop_state_with_memory_credentials(&current_vault);
        let source = serde_json::to_vec(&json!({
            "hosts": [],
            "customGroups": [],
            "snippets": [],
            "snippetPackages": [],
            "notes": [],
            "noteGroups": []
        }))
        .expect("explicit empty legacy source JSON");

        let inspection = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&source, 101)
                .expect("empty catalog inspection document"),
        )
        .await
        .expect("empty catalog inspection");
        assert!(inspection.catalog_scope_change_count > 0);
        let result = commit_legacy_vault_document(
            &state,
            inspection.inventory_revision,
            netcatty_migration::parse_legacy_vault(&source, 101)
                .expect("empty catalog commit document"),
        )
        .await
        .expect("empty catalog import");
        assert_eq!(result.imported_count, 0);
        assert_eq!(result.custom_groups_imported_count, 0);
        assert_eq!(result.snippets_imported_count, 0);
        assert_eq!(result.snippet_packages_imported_count, 0);
        assert_eq!(result.notes_imported_count, 0);
        assert_eq!(result.note_groups_imported_count, 0);

        let graph = state.saved_hosts.graph().expect("empty-scope graph");
        assert_eq!(
            graph
                .group_catalog()
                .expect("explicit empty custom groups")
                .len(),
            0
        );
        assert_eq!(
            graph
                .notes_snippets()
                .snippets()
                .expect("explicit empty snippets")
                .len(),
            0
        );
        assert_eq!(
            graph
                .notes_snippets()
                .snippet_packages()
                .expect("explicit empty snippet packages")
                .len(),
            0
        );
        assert_eq!(
            graph
                .notes_snippets()
                .notes()
                .expect("explicit empty notes")
                .len(),
            0
        );
        assert_eq!(
            graph
                .notes_snippets()
                .note_groups()
                .expect("explicit empty note groups")
                .len(),
            0
        );

        let repeated_inspection = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&source, 101)
                .expect("repeated empty catalog inspection document"),
        )
        .await
        .expect("repeated empty catalog inspection");
        assert_eq!(repeated_inspection.catalog_scope_change_count, 0);
        let repeated_result = commit_legacy_vault_document(
            &state,
            repeated_inspection.inventory_revision,
            netcatty_migration::parse_legacy_vault(&source, 101)
                .expect("repeated empty catalog commit document"),
        )
        .await
        .expect("repeated empty catalog import");
        assert_eq!(repeated_result.imported_count, 0);
        assert_eq!(repeated_result.custom_groups_imported_count, 0);
        assert_eq!(repeated_result.snippets_imported_count, 0);
        assert_eq!(repeated_result.snippet_packages_imported_count, 0);
        assert_eq!(repeated_result.notes_imported_count, 0);
        assert_eq!(repeated_result.note_groups_imported_count, 0);
        assert!(controller.operation_log().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn managed_import_structural_failure_does_not_initialize_secret_storage() {
        for invalid_edge in ["host", "group"] {
            let directory = tempfile::tempdir().expect("temporary vault");
            let current_vault = directory.path().join(invalid_edge);
            let (state, credential_controller, master_key_controller) =
                desktop_state_with_memory_credentials_and_master_keys(&current_vault);
            let mut source: serde_json::Value =
                serde_json::from_slice(&legacy_managed_graph_source(
                    "preflight-managed-key",
                    Some("preflight-managed-host"),
                    "preflight-private-key-sentinel",
                    None,
                    None,
                    None,
                    false,
                ))
                .expect("managed preflight source");
            source["snippets"] = json!([]);
            if invalid_edge == "host" {
                source["hosts"][0]["loginScriptId"] = json!("missing-preflight-script");
            } else {
                source["groupConfigs"] = json!([{
                    "path": "Preflight/Managed",
                    "loginScriptId": "missing-preflight-script"
                }]);
            }
            let source = serde_json::to_vec(&source).expect("encode managed preflight source");
            let expected_revision =
                super::assess_legacy_graph(state.saved_hosts.clone(), SavedVaultGraph::default())
                    .await
                    .expect("current inventory assessment")
                    .into_revision();
            let before_graph = state.saved_hosts.graph().expect("before graph");
            let secret_root = current_vault.join("secret-blobs");
            let mut before_secret_files = persisted_files(&secret_root);
            before_secret_files.sort();
            assert!(!secret_root.join("owner.json").exists());
            assert!(!secret_root.join("keyset").exists());
            assert!(credential_controller.operation_log().is_empty());
            assert!(master_key_controller.operation_log().is_empty());

            let error = commit_legacy_vault_document(
                &state,
                expected_revision,
                netcatty_migration::parse_legacy_vault(&source, 102)
                    .expect("managed structural failure document"),
            )
            .await
            .expect_err("dangling script edge must reject the complete import");

            assert!(error.contains(super::LEGACY_VAULT_ASSESSMENT_FAILED));
            assert_eq!(
                state.saved_hosts.graph().expect("after graph"),
                before_graph
            );
            assert!(credential_controller.operation_log().is_empty());
            assert!(master_key_controller.operation_log().is_empty());
            let mut after_secret_files = persisted_files(&secret_root);
            after_secret_files.sort();
            assert_eq!(after_secret_files, before_secret_files);
            assert!(!secret_root.join("owner.json").exists());
            assert!(!secret_root.join("keyset").exists());
            assert!(
                load_legacy_import_transaction(&state)
                    .await
                    .expect("transaction lookup")
                    .is_none()
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn legacy_primary_telnet_password_uses_isolated_owner_and_repeats_without_keyring() {
        let directory = tempfile::tempdir().expect("temporary vault");
        let current_vault = directory.path().join("current");
        let (state, controller) = desktop_state_with_memory_credentials(&current_vault);
        let host_id = "legacy-primary-telnet-owner";
        let telnet_secret = "legacy-telnet-secret-private-sentinel";
        let ignored_ssh_secret = "legacy-ssh-secret-must-not-win";
        let source = serde_json::to_vec(&json!([{
            "id": host_id,
            "label": "Legacy console",
            "hostname": "console.example.test",
            "port": 22,
            "username": "ssh-user",
            "protocol": "telnet",
            "authMethod": "password",
            "savePassword": true,
            "password": ignored_ssh_secret,
            "telnetPort": 2323,
            "telnetUsername": "console-user",
            "telnetPassword": telnet_secret,
            "charset": "GBK",
            "createdAt": 1_700_000_000_000_u64,
            "updatedAt": 1_700_000_000_000_u64
        }]))
        .expect("legacy Telnet source");

        let inspection = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&source, 10)
                .expect("legacy Telnet inspection document"),
        )
        .await
        .expect("legacy Telnet inspection");
        assert_eq!(inspection.preview.importable_count, 1);
        assert_eq!(inspection.preview.recoverable_credential_count, 1);
        assert_eq!(inspection.recoverable_telnet_credential_count, 1);
        assert_eq!(inspection.telnet_credential_reentry_required_count, 0);
        assert_eq!(inspection.preview.counts().telnet_password_candidates, 1);
        assert_eq!(
            inspection
                .preview
                .counts()
                .telnet_credential_reentry_required,
            0
        );
        let inspection_json = serde_json::to_string(&inspection).expect("inspection JSON");
        assert!(!inspection_json.contains(telnet_secret));
        assert!(!inspection_json.contains(ignored_ssh_secret));
        assert!(controller.operation_log().is_empty());

        let result = commit_legacy_vault_document(
            &state,
            inspection.inventory_revision,
            netcatty_migration::parse_legacy_vault(&source, 10)
                .expect("legacy Telnet commit document"),
        )
        .await
        .expect("legacy Telnet import");
        assert_eq!(result.imported_count, 1);
        assert_eq!(result.credentials_stored_count, 1);
        assert_eq!(result.telnet_credentials_stored_count, 1);
        assert_eq!(result.telnet_credential_reentry_required_count, 0);
        assert_eq!(result.requires_credential_reentry_count, 0);

        let graph = state.saved_hosts.graph().expect("imported Telnet graph");
        let host = graph.hosts().first().expect("imported Telnet host");
        assert!(host.protocol.is_telnet());
        assert!(super::has_saved_credential(host));
        assert_eq!(host.port, 2323);
        assert_eq!(host.username, "console-user");
        let telnet_reference = StoredCredentialReference::for_saved_host_telnet(host.id.as_str())
            .expect("Telnet reference");
        assert_stored_secret_with_kind(
            &state.persistent_credentials,
            &telnet_reference,
            CredentialKind::TelnetPassword,
            telnet_secret,
        )
        .await;
        let ssh_reference =
            StoredCredentialReference::for_saved_host(host.id.as_str()).expect("SSH reference");
        assert_credential_missing_with_kind(
            &state.persistent_credentials,
            &ssh_reference,
            CredentialKind::SshPassword,
        )
        .await;
        for bytes in persisted_files(&current_vault) {
            assert_bytes_do_not_contain(&bytes, telnet_secret);
            assert_bytes_do_not_contain(&bytes, ignored_ssh_secret);
        }

        controller.clear_operation_log();
        let repeat = inspect_legacy_vault_document(
            state.clone(),
            netcatty_migration::parse_legacy_vault(&source, 10)
                .expect("repeated Telnet inspection document"),
        )
        .await
        .expect("repeated Telnet inspection");
        assert_eq!(repeat.preview.importable_count, 0);
        assert_eq!(repeat.preview.duplicate_count, 1);
        let repeated_result = commit_legacy_vault_document(
            &state,
            repeat.inventory_revision,
            netcatty_migration::parse_legacy_vault(&source, 10)
                .expect("repeated Telnet commit document"),
        )
        .await
        .expect("repeated Telnet import");
        assert_eq!(repeated_result.imported_count, 0);
        assert_eq!(repeated_result.credentials_stored_count, 0);
        assert_eq!(repeated_result.telnet_credentials_stored_count, 0);
        assert!(controller.operation_log().is_empty());
    }
}
