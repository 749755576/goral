//! Atomic desktop coordination for password-identity catalog mutations.
//!
//! The catalog module prepares and validates complete-graph proposals. This
//! module is the only native password-identity path allowed to coordinate
//! those proposals with the OS keyring. Callers must run these functions from
//! the saved-host coordinator so the process and cross-process Vault locks are
//! retained for the whole operation.

use netcatty_credentials::{
    CredentialErrorCode, CredentialKind, SecretValue, StoredCredentialReference,
};
use netcatty_vault::{
    SavedVaultDurableSnapshot, SavedVaultGraph, SavedVaultGraphCommitment,
    SavedVaultGraphReplacementPlan, SavedVaultInventoryRevision, StoreError,
};

use super::legacy_import_transaction::{
    LegacyImportCredentialOwner, LegacyPreviousCredentialState,
};
use super::password_identity_catalog::{
    PASSWORD_IDENTITY_INVALID, PasswordIdentityCatalog, PreparedPasswordCredentialMutation,
    PreparedPasswordIdentityDeletion, PreparedPasswordIdentityMutation, password_identity_error,
    password_identity_inventory_changed, password_identity_publication_failed,
    password_identity_repair_required,
};
use super::{
    DesktopState, activate_legacy_import_transaction_for_owners,
    begin_legacy_import_transaction_for_owners, cleanup_legacy_import_backups,
    finish_legacy_import_transaction, legacy_import_credential_references_for_owner,
    mark_legacy_vault_durable, recover_pending_legacy_import,
};

enum CredentialAction {
    Remove {
        target: StoredCredentialReference,
    },
    Replace {
        target: StoredCredentialReference,
        secret: SecretValue,
    },
}

impl CredentialAction {
    const fn target(&self) -> &StoredCredentialReference {
        match self {
            Self::Remove { target } | Self::Replace { target, .. } => target,
        }
    }
}

/// Loads one directory-durable, renderer-safe password-identity catalog.
/// Pending cross-store recovery is normally completed by the outer saved-host
/// coordinator before this function is entered.
pub(crate) async fn load_password_identity_catalog(
    state: &DesktopState,
) -> Result<PasswordIdentityCatalog, String> {
    let snapshot = confirm_password_identity_snapshot(state).await?;
    Ok(PasswordIdentityCatalog::from_graph(
        snapshot.revision().clone(),
        snapshot.graph(),
    ))
}

/// Commits a prepared create or update proposal. `owner` is the Tauri window
/// label that owns an optional one-shot credential. Metadata and the complete
/// inventory CAS are checked before that reference is consumed.
pub(crate) async fn commit_password_identity_mutation(
    state: &DesktopState,
    owner: &str,
    prepared: PreparedPasswordIdentityMutation,
) -> Result<PasswordIdentityCatalog, String> {
    let (expected_revision, target_graph, identity, credential) = prepared.into_parts();
    let identity_owner = LegacyImportCredentialOwner::for_password_identity(identity.id.as_str())
        .map_err(|_| password_identity_repair_required())?;
    let expected_target = StoredCredentialReference::for_saved_identity(identity.id.as_str())
        .map_err(|_| password_identity_repair_required())?;
    if credential.target() != &expected_target {
        return fail_before_journal(state, password_identity_repair_required()).await;
    }

    let plan = match plan_password_identity_graph(state, expected_revision, &target_graph).await {
        Ok(plan) => plan,
        Err(primary) => return fail_before_journal(state, primary).await,
    };

    match credential {
        PreparedPasswordCredentialMutation::Keep { .. } => {
            commit_password_identity_graph_without_credentials(state, plan, target_graph).await
        }
        PreparedPasswordCredentialMutation::Remove { target } => {
            commit_password_identity_graph_with_credential(
                state,
                plan,
                target_graph,
                identity_owner,
                CredentialAction::Remove { target },
            )
            .await
        }
        PreparedPasswordCredentialMutation::Replace {
            target,
            staged_credential_reference,
        } => {
            // The complete graph, metadata, inventory token, identity owner,
            // and deterministic target were all validated above. Only now may
            // the owner-bound one-shot secret leave the staging store.
            let secret = match state
                .ephemeral_credentials
                .take(owner, &staged_credential_reference)
                .await
            {
                Ok(secret) => secret,
                Err(_) => {
                    return fail_before_journal(
                        state,
                        password_identity_error(
                            PASSWORD_IDENTITY_INVALID,
                            "The staged password identity credential is unavailable",
                        ),
                    )
                    .await;
                }
            };
            commit_password_identity_graph_with_credential(
                state,
                plan,
                target_graph,
                identity_owner,
                CredentialAction::Replace { target, secret },
            )
            .await
        }
    }
}

/// Commits a prepared deletion. Deletion always probes and removes the
/// deterministic identity account, even when Vault's credential-presence hint
/// is false.
pub(crate) async fn commit_password_identity_deletion(
    state: &DesktopState,
    prepared: PreparedPasswordIdentityDeletion,
) -> Result<PasswordIdentityCatalog, String> {
    let (expected_revision, target_graph, identity_id, credential) = prepared.into_parts();
    let identity_owner = LegacyImportCredentialOwner::for_password_identity(identity_id.as_str())
        .map_err(|_| password_identity_repair_required())?;
    let expected_target = StoredCredentialReference::for_saved_identity(identity_id.as_str())
        .map_err(|_| password_identity_repair_required())?;
    let PreparedPasswordCredentialMutation::Remove { target } = credential else {
        return fail_before_journal(state, password_identity_repair_required()).await;
    };
    if target != expected_target {
        return fail_before_journal(state, password_identity_repair_required()).await;
    }

    let plan = match plan_password_identity_graph(state, expected_revision, &target_graph).await {
        Ok(plan) => plan,
        Err(primary) => return fail_before_journal(state, primary).await,
    };
    commit_password_identity_graph_with_credential(
        state,
        plan,
        target_graph,
        identity_owner,
        CredentialAction::Remove { target },
    )
    .await
}

async fn plan_password_identity_graph(
    state: &DesktopState,
    expected_revision: SavedVaultInventoryRevision,
    target_graph: &SavedVaultGraph,
) -> Result<SavedVaultGraphReplacementPlan, String> {
    let store = state.saved_hosts.clone();
    let target_graph = target_graph.clone();
    tokio::task::spawn_blocking(move || {
        store.plan_graph_replacement(expected_revision, &target_graph)
    })
    .await
    .map_err(|_| password_identity_repair_required())?
    .map_err(map_password_identity_preflight_error)
}

async fn commit_password_identity_graph_without_credentials(
    state: &DesktopState,
    plan: SavedVaultGraphReplacementPlan,
    target_graph: SavedVaultGraph,
) -> Result<PasswordIdentityCatalog, String> {
    let before = plan.before_graph_commitment().clone();
    let after = plan.after_graph_commitment().clone();
    let committed = match commit_planned_password_identity_graph(state, plan, target_graph).await {
        Ok(committed) => committed,
        Err(primary) => return fail_before_journal(state, primary).await,
    };

    match confirm_exact_password_identity_commit(
        state,
        committed.revision().clone(),
        &after,
        committed.graph(),
    )
    .await
    {
        Ok(catalog) => Ok(catalog),
        Err(primary) => {
            recover_post_commit(
                state,
                &before,
                &after,
                committed.revision(),
                committed.graph(),
                primary,
            )
            .await
        }
    }
}

async fn commit_password_identity_graph_with_credential(
    state: &DesktopState,
    plan: SavedVaultGraphReplacementPlan,
    target_graph: SavedVaultGraph,
    owner: LegacyImportCredentialOwner,
    action: CredentialAction,
) -> Result<PasswordIdentityCatalog, String> {
    if !plan.has_changes() {
        return fail_before_journal(state, password_identity_repair_required()).await;
    }
    let before = plan.before_graph_commitment().clone();
    let after = plan.after_graph_commitment().clone();
    let mut transaction = match begin_legacy_import_transaction_for_owners(
        state,
        vec![owner.clone()],
        before.clone(),
        after.clone(),
    )
    .await
    {
        Ok(transaction) => transaction,
        Err(_) => {
            return fail_before_journal(state, password_identity_repair_required()).await;
        }
    };

    let (target, backup) = match legacy_import_credential_references_for_owner(&transaction, &owner)
    {
        Ok(references) => references,
        Err(_) => {
            return fail_after_journal(state, password_identity_repair_required()).await;
        }
    };
    if &target != action.target() {
        return fail_after_journal(state, password_identity_repair_required()).await;
    }

    // A Vault hint is never accepted as proof that the deterministic account
    // is absent. Resolve it on every remove/replace/delete and isolate an old
    // value in the transaction-specific identity backup namespace.
    let previous = match state
        .persistent_credentials
        .resolve(&target, CredentialKind::SshPassword)
        .await
    {
        Ok(previous) => Some(previous),
        Err(error) if error.code() == CredentialErrorCode::NotFound => None,
        Err(_) => {
            return fail_after_journal(state, password_identity_repair_required()).await;
        }
    };
    let previous_state = if let Some(previous) = previous {
        if state
            .persistent_credentials
            .upsert(&backup, CredentialKind::SshPassword, previous)
            .await
            .is_err()
        {
            return fail_after_journal(state, password_identity_publication_failed()).await;
        }
        LegacyPreviousCredentialState::BackedUp
    } else {
        LegacyPreviousCredentialState::Absent
    };

    transaction = match activate_legacy_import_transaction_for_owners(
        transaction,
        vec![(owner, previous_state)],
    )
    .await
    {
        Ok(transaction) => transaction,
        Err(_) => {
            return fail_after_journal(state, password_identity_repair_required()).await;
        }
    };

    let mutation = match action {
        CredentialAction::Remove { target } => state.persistent_credentials.delete(&target).await,
        CredentialAction::Replace { target, secret } => {
            state
                .persistent_credentials
                .upsert(&target, CredentialKind::SshPassword, secret)
                .await
        }
    };
    if mutation.is_err() {
        return fail_after_journal(state, password_identity_publication_failed()).await;
    }

    let committed = match commit_planned_password_identity_graph(state, plan, target_graph).await {
        Ok(committed) => committed,
        Err(_) => {
            return fail_after_journal(state, password_identity_publication_failed()).await;
        }
    };
    let committed_revision = committed.revision().clone();
    let committed_graph = committed.graph().clone();
    let catalog = match confirm_exact_password_identity_commit(
        state,
        committed_revision.clone(),
        &after,
        &committed_graph,
    )
    .await
    {
        Ok(catalog) => catalog,
        Err(primary) => {
            return recover_post_commit(
                state,
                &before,
                &after,
                &committed_revision,
                &committed_graph,
                primary,
            )
            .await;
        }
    };

    transaction = match mark_legacy_vault_durable(transaction).await {
        Ok(transaction) => transaction,
        Err(_) => {
            return recover_post_commit(
                state,
                &before,
                &after,
                &committed_revision,
                &committed_graph,
                password_identity_repair_required(),
            )
            .await;
        }
    };
    if cleanup_legacy_import_backups(state, &transaction)
        .await
        .is_err()
    {
        return recover_post_commit(
            state,
            &before,
            &after,
            &committed_revision,
            &committed_graph,
            password_identity_repair_required(),
        )
        .await;
    }
    if finish_legacy_import_transaction(transaction).await.is_err() {
        return recover_post_commit(
            state,
            &before,
            &after,
            &committed_revision,
            &committed_graph,
            password_identity_repair_required(),
        )
        .await;
    }
    Ok(catalog)
}

async fn commit_planned_password_identity_graph(
    state: &DesktopState,
    plan: SavedVaultGraphReplacementPlan,
    target_graph: SavedVaultGraph,
) -> Result<netcatty_vault::SavedVaultGraphReplacementCommit, String> {
    let store = state.saved_hosts.clone();
    tokio::task::spawn_blocking(move || store.commit_planned_graph_replacement(plan, target_graph))
        .await
        .map_err(|_| password_identity_repair_required())?
        .map_err(map_password_identity_commit_error)
}

async fn confirm_password_identity_snapshot(
    state: &DesktopState,
) -> Result<SavedVaultDurableSnapshot, String> {
    let store = state.saved_hosts.clone();
    tokio::task::spawn_blocking(move || store.confirm_current_snapshot_durability())
        .await
        .map_err(|_| password_identity_repair_required())?
        .map_err(|_| password_identity_repair_required())
}

async fn confirm_exact_password_identity_commit(
    state: &DesktopState,
    expected_revision: SavedVaultInventoryRevision,
    expected_commitment: &SavedVaultGraphCommitment,
    expected_graph: &SavedVaultGraph,
) -> Result<PasswordIdentityCatalog, String> {
    let snapshot = confirm_password_identity_snapshot(state).await?;
    if snapshot.revision() != &expected_revision
        || snapshot.commitment() != expected_commitment
        || snapshot.graph() != expected_graph
    {
        return Err(password_identity_repair_required());
    }
    Ok(PasswordIdentityCatalog::from_graph(
        snapshot.revision().clone(),
        snapshot.graph(),
    ))
}

async fn fail_before_journal<T>(state: &DesktopState, primary: String) -> Result<T, String> {
    match recover_pending_legacy_import(state).await {
        Ok(()) => Err(primary),
        Err(_) => Err(password_identity_repair_required()),
    }
}

async fn fail_after_journal<T>(state: &DesktopState, primary: String) -> Result<T, String> {
    match recover_pending_legacy_import(state).await {
        Ok(()) => Err(primary),
        Err(_) => Err(password_identity_repair_required()),
    }
}

async fn recover_post_commit(
    state: &DesktopState,
    before: &SavedVaultGraphCommitment,
    after: &SavedVaultGraphCommitment,
    expected_revision: &SavedVaultInventoryRevision,
    expected_graph: &SavedVaultGraph,
    primary: String,
) -> Result<PasswordIdentityCatalog, String> {
    if recover_pending_legacy_import(state).await.is_err() {
        return Err(password_identity_repair_required());
    }
    let snapshot = confirm_password_identity_snapshot(state).await?;
    if snapshot.commitment() == after {
        if snapshot.revision() != expected_revision || snapshot.graph() != expected_graph {
            return Err(password_identity_repair_required());
        }
        return Ok(PasswordIdentityCatalog::from_graph(
            snapshot.revision().clone(),
            snapshot.graph(),
        ));
    }
    if snapshot.commitment() == before {
        return Err(primary);
    }
    Err(password_identity_repair_required())
}

fn map_password_identity_preflight_error(error: StoreError) -> String {
    match error {
        StoreError::InventoryRevisionConflict { .. } => password_identity_inventory_changed(),
        StoreError::Validation(_)
        | StoreError::DuplicateGraphEntityId(_)
        | StoreError::MissingGraphReference { .. }
        | StoreError::IncompatibleGraphReference { .. } => password_identity_error(
            PASSWORD_IDENTITY_INVALID,
            "The password identity has incompatible relationships",
        ),
        StoreError::InvalidOwner
        | StoreError::BothSlotsCorrupt
        | StoreError::ConflictingGeneration
        | StoreError::GraphReplacementPlanMismatch
        | StoreError::SnapshotDurabilityUnconfirmed
        | StoreError::ManagedSecretRetentionUncertain
        | StoreError::ArtifactConflict => password_identity_repair_required(),
        _ => password_identity_publication_failed(),
    }
}

fn map_password_identity_commit_error(error: StoreError) -> String {
    match error {
        StoreError::InventoryRevisionConflict { .. } => password_identity_inventory_changed(),
        StoreError::InvalidOwner
        | StoreError::BothSlotsCorrupt
        | StoreError::ConflictingGeneration
        | StoreError::GraphReplacementPlanMismatch
        | StoreError::SnapshotDurabilityUnconfirmed
        | StoreError::ManagedSecretRetentionUncertain
        | StoreError::ArtifactConflict => password_identity_repair_required(),
        _ => password_identity_publication_failed(),
    }
}

#[cfg(test)]
mod tests {
    use netcatty_credentials::test_support::{
        CredentialOperation, FailureTiming, InMemoryCredentialController,
        in_memory_credential_store, in_memory_master_key_store,
    };
    use netcatty_credentials::{
        CredentialErrorCode, CredentialKind, EphemeralCredentialReference, SecretValue,
        StoredCredentialReference,
    };
    use netcatty_vault::{SavedHostDraft, SavedPasswordIdentityId, SavedVaultDurableSnapshot};

    use super::super::DesktopState;
    use super::super::legacy_import_transaction::LegacyImportTransaction;
    use super::super::password_identity_catalog::{
        CreatePasswordIdentityRequest, DeletePasswordIdentityRequest,
        PASSWORD_IDENTITY_INVENTORY_CHANGED, PASSWORD_IDENTITY_PUBLICATION_FAILED,
        PasswordIdentityCredentialMutationRequest, PasswordIdentityMetadataRequest,
        UpdatePasswordIdentityRequest, prepare_password_identity_creation,
        prepare_password_identity_deletion, prepare_password_identity_update,
    };
    use super::{
        commit_password_identity_deletion, commit_password_identity_mutation,
        load_password_identity_catalog,
    };

    const OWNER: &str = "password-identity-test-window";
    const OLD_SECRET: &str = "password-identity-old-secret-sentinel";
    const NEW_SECRET: &str = "password-identity-new-secret-sentinel";

    fn desktop_state(vault_root: &std::path::Path) -> (DesktopState, InMemoryCredentialController) {
        let (credentials, controller) = in_memory_credential_store();
        let (master_keys, _) = in_memory_master_key_store();
        let mut state = DesktopState::open(vault_root).expect("desktop state");
        state.persistent_credentials = credentials;
        state.master_keys = master_keys;
        (state, controller)
    }

    fn durable_snapshot(state: &DesktopState) -> SavedVaultDurableSnapshot {
        state
            .saved_hosts
            .confirm_current_snapshot_durability()
            .expect("durable Vault snapshot")
    }

    fn metadata(label: &str, username: &str) -> PasswordIdentityMetadataRequest {
        PasswordIdentityMetadataRequest {
            label: label.to_owned(),
            username: username.to_owned(),
        }
    }

    fn create_request(
        state: &DesktopState,
        staged_credential_reference: Option<EphemeralCredentialReference>,
        label: &str,
    ) -> CreatePasswordIdentityRequest {
        CreatePasswordIdentityRequest {
            expected_inventory_revision: durable_snapshot(state).revision().clone(),
            metadata: metadata(label, "identity-user"),
            staged_credential_reference,
        }
    }

    async fn create_metadata_only_identity(
        state: &DesktopState,
        id: &str,
    ) -> SavedPasswordIdentityId {
        let id = SavedPasswordIdentityId::from_opaque(id).expect("identity ID");
        let snapshot = durable_snapshot(state);
        let prepared = prepare_password_identity_creation(
            snapshot.graph().clone(),
            create_request(state, None, "Original identity"),
            id.clone(),
            10,
        )
        .expect("creation plan");
        commit_password_identity_mutation(state, OWNER, prepared)
            .await
            .expect("metadata-only identity");
        id
    }

    async fn stage(state: &DesktopState, value: &str) -> EphemeralCredentialReference {
        state
            .ephemeral_credentials
            .insert(
                OWNER,
                SecretValue::from_utf8(value.to_owned()).expect("test secret"),
            )
            .await
            .expect("stage secret")
    }

    fn update_request(
        snapshot: &SavedVaultDurableSnapshot,
        id: &SavedPasswordIdentityId,
        action: PasswordIdentityCredentialMutationRequest,
    ) -> UpdatePasswordIdentityRequest {
        let identity = snapshot
            .graph()
            .password_identities()
            .iter()
            .find(|identity| &identity.id == id)
            .expect("current identity");
        UpdatePasswordIdentityRequest {
            id: id.as_str().to_owned(),
            expected_revision: identity.revision,
            expected_inventory_revision: snapshot.revision().clone(),
            metadata: metadata("Updated identity", "updated-user"),
            credential_mutation: action,
        }
    }

    fn target(id: &SavedPasswordIdentityId) -> StoredCredentialReference {
        StoredCredentialReference::for_saved_identity(id.as_str()).expect("identity target")
    }

    fn assert_no_pending_journal(state: &DesktopState) {
        assert!(
            LegacyImportTransaction::load(state.legacy_import_transaction_root.as_ref())
                .expect("load journal")
                .is_none(),
            "completed mutation must remove the recovery journal"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn metadata_only_keep_uses_pure_vault_and_never_touches_keyring_or_journal() {
        let directory = tempfile::tempdir().expect("temporary Vault");
        let (state, controller) = desktop_state(directory.path());
        let snapshot = durable_snapshot(&state);
        let id =
            SavedPasswordIdentityId::from_opaque("metadata-only-identity").expect("identity ID");
        let prepared = prepare_password_identity_creation(
            snapshot.graph().clone(),
            create_request(&state, None, "Metadata only"),
            id.clone(),
            10,
        )
        .expect("creation plan");

        let catalog = commit_password_identity_mutation(&state, "", prepared)
            .await
            .expect("pure Vault creation");

        assert!(controller.operation_log().is_empty());
        assert_no_pending_journal(&state);
        let current = durable_snapshot(&state);
        assert_eq!(current.graph().password_identities().len(), 1);
        assert_eq!(current.graph().password_identities()[0].id, id);
        assert!(!current.graph().password_identities()[0].has_saved_credential);
        let encoded = serde_json::to_string(&catalog).expect("renderer catalog");
        assert!(!encoded.contains("credentialReference"));
        assert!(!encoded.contains("os:v1:"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stale_replace_is_rejected_before_staged_secret_or_keyring_is_touched() {
        let directory = tempfile::tempdir().expect("temporary Vault");
        let (state, controller) = desktop_state(directory.path());
        let id = create_metadata_only_identity(&state, "stale-replace-identity").await;
        controller.clear_operation_log();
        let reference = stage(&state, NEW_SECRET).await;
        let snapshot = durable_snapshot(&state);
        let request = update_request(
            &snapshot,
            &id,
            PasswordIdentityCredentialMutationRequest::Replace {
                staged_credential_reference: reference,
            },
        );
        let prepared = prepare_password_identity_update(snapshot.graph().clone(), request, 20)
            .expect("update plan");
        state
            .saved_hosts
            .create(SavedHostDraft::ssh_password(
                "advance-stale-password-identity.example.test",
                "host-user",
            ))
            .expect("advance complete inventory");

        let error = commit_password_identity_mutation(&state, OWNER, prepared)
            .await
            .expect_err("stale request");

        assert!(error.starts_with(PASSWORD_IDENTITY_INVENTORY_CHANGED));
        assert!(controller.operation_log().is_empty());
        state
            .ephemeral_credentials
            .take(OWNER, &reference)
            .await
            .expect("stale preflight must retain staged secret");
        assert_no_pending_journal(&state);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replace_backs_up_an_orphan_even_when_the_vault_hint_is_false() {
        let directory = tempfile::tempdir().expect("temporary Vault");
        let (state, controller) = desktop_state(directory.path());
        let id = create_metadata_only_identity(&state, "orphan-replace-identity").await;
        let target = target(&id);
        state
            .persistent_credentials
            .upsert(
                &target,
                CredentialKind::SshPassword,
                SecretValue::from_utf8(OLD_SECRET.to_owned()).expect("old secret"),
            )
            .await
            .expect("seed orphan account");
        controller.clear_operation_log();
        let staged = stage(&state, NEW_SECRET).await;
        let snapshot = durable_snapshot(&state);
        let request = update_request(
            &snapshot,
            &id,
            PasswordIdentityCredentialMutationRequest::Replace {
                staged_credential_reference: staged,
            },
        );
        let prepared = prepare_password_identity_update(snapshot.graph().clone(), request, 20)
            .expect("replace plan");

        commit_password_identity_mutation(&state, OWNER, prepared)
            .await
            .expect("replace credential");

        let log = controller.operation_log();
        assert_eq!(log.count(CredentialOperation::Resolve), 1);
        assert_eq!(log.count(CredentialOperation::Upsert), 2);
        assert_eq!(log.count(CredentialOperation::Delete), 1);
        assert_no_pending_journal(&state);
        let current = durable_snapshot(&state);
        assert!(current.graph().password_identities()[0].has_saved_credential);
        let resolved = state
            .persistent_credentials
            .resolve(&target, CredentialKind::SshPassword)
            .await
            .expect("new credential");
        assert_eq!(resolved.as_utf8(), Ok(NEW_SECRET));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn target_upsert_failure_rolls_back_graph_and_old_credential() {
        let directory = tempfile::tempdir().expect("temporary Vault");
        let (state, controller) = desktop_state(directory.path());
        let id = create_metadata_only_identity(&state, "failed-upsert-identity").await;
        let target = target(&id);
        state
            .persistent_credentials
            .upsert(
                &target,
                CredentialKind::SshPassword,
                SecretValue::from_utf8(OLD_SECRET.to_owned()).expect("old secret"),
            )
            .await
            .expect("seed old account");
        let staged = stage(&state, NEW_SECRET).await;
        let before = durable_snapshot(&state);
        let request = update_request(
            &before,
            &id,
            PasswordIdentityCredentialMutationRequest::Replace {
                staged_credential_reference: staged,
            },
        );
        let prepared = prepare_password_identity_update(before.graph().clone(), request, 20)
            .expect("replace plan");
        controller.clear_operation_log();
        controller.set_failure(
            CredentialOperation::Upsert,
            2,
            FailureTiming::BeforeSideEffect,
            CredentialErrorCode::BackendFailure,
        );

        let error = commit_password_identity_mutation(&state, OWNER, prepared)
            .await
            .expect_err("target upsert failure");

        assert!(error.starts_with(PASSWORD_IDENTITY_PUBLICATION_FAILED));
        assert_eq!(durable_snapshot(&state).graph(), before.graph());
        assert_no_pending_journal(&state);
        let old = state
            .persistent_credentials
            .resolve(&target, CredentialKind::SshPassword)
            .await
            .expect("old credential restored");
        assert_eq!(old.as_utf8(), Ok(OLD_SECRET));
        let staged_error = match state.ephemeral_credentials.take(OWNER, &staged).await {
            Ok(_) => panic!("staged credential must be one-shot"),
            Err(error) => error,
        };
        assert_eq!(staged_error.code(), CredentialErrorCode::NotFound);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn remove_checks_false_hint_and_deletes_the_deterministic_account() {
        let directory = tempfile::tempdir().expect("temporary Vault");
        let (state, controller) = desktop_state(directory.path());
        let id = create_metadata_only_identity(&state, "false-hint-remove-identity").await;
        let target = target(&id);
        state
            .persistent_credentials
            .upsert(
                &target,
                CredentialKind::SshPassword,
                SecretValue::from_utf8(OLD_SECRET.to_owned()).expect("old secret"),
            )
            .await
            .expect("seed orphan account");
        controller.clear_operation_log();
        let snapshot = durable_snapshot(&state);
        let request = update_request(
            &snapshot,
            &id,
            PasswordIdentityCredentialMutationRequest::Remove,
        );
        let prepared = prepare_password_identity_update(snapshot.graph().clone(), request, 20)
            .expect("remove plan");

        commit_password_identity_mutation(&state, OWNER, prepared)
            .await
            .expect("remove credential");

        let log = controller.operation_log();
        assert_eq!(log.count(CredentialOperation::Resolve), 1);
        assert_eq!(log.count(CredentialOperation::Upsert), 1);
        assert_eq!(log.count(CredentialOperation::Delete), 2);
        assert_no_pending_journal(&state);
        let target_error = match state
            .persistent_credentials
            .resolve(&target, CredentialKind::SshPassword)
            .await
        {
            Ok(_) => panic!("target must be removed"),
            Err(error) => error,
        };
        assert_eq!(target_error.code(), CredentialErrorCode::NotFound);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn delete_after_side_effect_failure_restores_identity_and_credential() {
        let directory = tempfile::tempdir().expect("temporary Vault");
        let (state, controller) = desktop_state(directory.path());
        let id = create_metadata_only_identity(&state, "failed-delete-identity").await;
        let target = target(&id);
        state
            .persistent_credentials
            .upsert(
                &target,
                CredentialKind::SshPassword,
                SecretValue::from_utf8(OLD_SECRET.to_owned()).expect("old secret"),
            )
            .await
            .expect("seed old account");
        let before = durable_snapshot(&state);
        let current = &before.graph().password_identities()[0];
        let prepared = prepare_password_identity_deletion(
            before.graph().clone(),
            DeletePasswordIdentityRequest {
                id: id.as_str().to_owned(),
                expected_revision: current.revision,
                expected_inventory_revision: before.revision().clone(),
            },
        )
        .expect("delete plan");
        controller.clear_operation_log();
        controller.set_failure(
            CredentialOperation::Delete,
            1,
            FailureTiming::AfterSideEffect,
            CredentialErrorCode::BackendFailure,
        );

        let error = commit_password_identity_deletion(&state, prepared)
            .await
            .expect_err("ambiguous target deletion");

        assert!(error.starts_with(PASSWORD_IDENTITY_PUBLICATION_FAILED));
        assert_eq!(durable_snapshot(&state).graph(), before.graph());
        assert_no_pending_journal(&state);
        let old = state
            .persistent_credentials
            .resolve(&target, CredentialKind::SshPassword)
            .await
            .expect("old credential restored");
        assert_eq!(old.as_utf8(), Ok(OLD_SECRET));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn successful_delete_removes_both_identity_and_account_and_returns_safe_catalog() {
        let directory = tempfile::tempdir().expect("temporary Vault");
        let (state, controller) = desktop_state(directory.path());
        let id = create_metadata_only_identity(&state, "successful-delete-identity").await;
        let target = target(&id);
        state
            .persistent_credentials
            .upsert(
                &target,
                CredentialKind::SshPassword,
                SecretValue::from_utf8(OLD_SECRET.to_owned()).expect("old secret"),
            )
            .await
            .expect("seed old account");
        let before = durable_snapshot(&state);
        let current = &before.graph().password_identities()[0];
        let prepared = prepare_password_identity_deletion(
            before.graph().clone(),
            DeletePasswordIdentityRequest {
                id: id.as_str().to_owned(),
                expected_revision: current.revision,
                expected_inventory_revision: before.revision().clone(),
            },
        )
        .expect("delete plan");
        controller.clear_operation_log();

        let catalog = commit_password_identity_deletion(&state, prepared)
            .await
            .expect("delete identity");

        assert!(
            durable_snapshot(&state)
                .graph()
                .password_identities()
                .is_empty()
        );
        assert_no_pending_journal(&state);
        let target_error = match state
            .persistent_credentials
            .resolve(&target, CredentialKind::SshPassword)
            .await
        {
            Ok(_) => panic!("target must be removed"),
            Err(error) => error,
        };
        assert_eq!(target_error.code(), CredentialErrorCode::NotFound);
        let encoded = serde_json::to_string(&catalog).expect("renderer-safe catalog");
        assert!(!encoded.contains(OLD_SECRET));
        assert!(!encoded.contains("credentialReference"));
        assert!(!encoded.contains("os:v1:"));
        assert!(controller.operation_count(CredentialOperation::Resolve) >= 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn list_returns_only_safe_metadata_from_a_durable_snapshot() {
        let directory = tempfile::tempdir().expect("temporary Vault");
        let (state, _) = desktop_state(directory.path());
        create_metadata_only_identity(&state, "listed-password-identity").await;

        let catalog = load_password_identity_catalog(&state)
            .await
            .expect("password identity catalog");
        let encoded = serde_json::to_string(&catalog).expect("renderer-safe catalog");
        assert!(encoded.contains("listed-password-identity"));
        for forbidden in [OLD_SECRET, NEW_SECRET, "credentialReference", "os:v1:"] {
            assert!(!encoded.contains(forbidden));
        }
    }
}
