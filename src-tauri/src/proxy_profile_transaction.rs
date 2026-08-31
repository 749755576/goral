//! Atomic Vault/keyring coordination for proxy-profile catalog mutations.

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
use super::proxy_profile_catalog::{
    PROXY_PROFILE_INVALID, PreparedProxyCredentialMutation, PreparedProxyProfileDeletion,
    PreparedProxyProfileMutation, ProxyProfileCatalog, proxy_profile_error,
    proxy_profile_inventory_changed, proxy_profile_publication_failed,
    proxy_profile_repair_required,
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

pub(crate) async fn load_proxy_profile_catalog(
    state: &DesktopState,
) -> Result<ProxyProfileCatalog, String> {
    let snapshot = confirm_proxy_profile_snapshot(state).await?;
    Ok(ProxyProfileCatalog::from_graph(
        snapshot.revision().clone(),
        snapshot.graph(),
    ))
}

pub(crate) async fn commit_proxy_profile_mutation(
    state: &DesktopState,
    window_owner: &str,
    prepared: PreparedProxyProfileMutation,
) -> Result<ProxyProfileCatalog, String> {
    let (expected_revision, target_graph, profile, credential) = prepared.into_parts();
    let owner = LegacyImportCredentialOwner::for_proxy_profile(profile.id.as_str())
        .map_err(|_| proxy_profile_repair_required())?;
    let expected_target = StoredCredentialReference::for_saved_proxy_profile(profile.id.as_str())
        .map_err(|_| proxy_profile_repair_required())?;
    if credential.target() != &expected_target {
        return fail_before_journal(state, proxy_profile_repair_required()).await;
    }

    let plan = match plan_proxy_profile_graph(state, expected_revision, &target_graph).await {
        Ok(plan) => plan,
        Err(primary) => return fail_before_journal(state, primary).await,
    };
    match credential {
        PreparedProxyCredentialMutation::Keep { .. } => {
            commit_proxy_profile_graph_without_credentials(state, plan, target_graph).await
        }
        PreparedProxyCredentialMutation::Remove { target } => {
            commit_proxy_profile_graph_with_credential(
                state,
                plan,
                target_graph,
                owner,
                CredentialAction::Remove { target },
            )
            .await
        }
        PreparedProxyCredentialMutation::Replace {
            target,
            staged_credential_reference,
        } => {
            let secret = match state
                .ephemeral_credentials
                .take(window_owner, &staged_credential_reference)
                .await
            {
                Ok(secret) => secret,
                Err(_) => {
                    return fail_before_journal(
                        state,
                        proxy_profile_error(
                            PROXY_PROFILE_INVALID,
                            "The staged proxy credential is unavailable",
                        ),
                    )
                    .await;
                }
            };
            commit_proxy_profile_graph_with_credential(
                state,
                plan,
                target_graph,
                owner,
                CredentialAction::Replace { target, secret },
            )
            .await
        }
    }
}

pub(crate) async fn commit_proxy_profile_deletion(
    state: &DesktopState,
    prepared: PreparedProxyProfileDeletion,
) -> Result<ProxyProfileCatalog, String> {
    let (expected_revision, target_graph, profile_id, credential) = prepared.into_parts();
    let owner = LegacyImportCredentialOwner::for_proxy_profile(profile_id.as_str())
        .map_err(|_| proxy_profile_repair_required())?;
    let expected_target = StoredCredentialReference::for_saved_proxy_profile(profile_id.as_str())
        .map_err(|_| proxy_profile_repair_required())?;
    let PreparedProxyCredentialMutation::Remove { target } = credential else {
        return fail_before_journal(state, proxy_profile_repair_required()).await;
    };
    if target != expected_target {
        return fail_before_journal(state, proxy_profile_repair_required()).await;
    }
    let plan = match plan_proxy_profile_graph(state, expected_revision, &target_graph).await {
        Ok(plan) => plan,
        Err(primary) => return fail_before_journal(state, primary).await,
    };
    commit_proxy_profile_graph_with_credential(
        state,
        plan,
        target_graph,
        owner,
        CredentialAction::Remove { target },
    )
    .await
}

async fn plan_proxy_profile_graph(
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
    .map_err(|_| proxy_profile_repair_required())?
    .map_err(map_proxy_profile_preflight_error)
}

async fn commit_proxy_profile_graph_without_credentials(
    state: &DesktopState,
    plan: SavedVaultGraphReplacementPlan,
    target_graph: SavedVaultGraph,
) -> Result<ProxyProfileCatalog, String> {
    let before = plan.before_graph_commitment().clone();
    let after = plan.after_graph_commitment().clone();
    let committed = match commit_planned_proxy_profile_graph(state, plan, target_graph).await {
        Ok(committed) => committed,
        Err(primary) => return fail_before_journal(state, primary).await,
    };
    match confirm_exact_proxy_profile_commit(
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

async fn commit_proxy_profile_graph_with_credential(
    state: &DesktopState,
    plan: SavedVaultGraphReplacementPlan,
    target_graph: SavedVaultGraph,
    owner: LegacyImportCredentialOwner,
    action: CredentialAction,
) -> Result<ProxyProfileCatalog, String> {
    if !plan.has_changes() {
        return fail_before_journal(state, proxy_profile_repair_required()).await;
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
        Err(_) => return fail_before_journal(state, proxy_profile_repair_required()).await,
    };

    let (target, backup) = match legacy_import_credential_references_for_owner(&transaction, &owner)
    {
        Ok(references) => references,
        Err(_) => return fail_after_journal(state, proxy_profile_repair_required()).await,
    };
    if &target != action.target() {
        return fail_after_journal(state, proxy_profile_repair_required()).await;
    }

    // Remove/replace/delete always resolve the deterministic account. The
    // Vault hint is deliberately not accepted as proof of absence.
    let previous = match state
        .persistent_credentials
        .resolve(&target, CredentialKind::ProxyPassword)
        .await
    {
        Ok(previous) => Some(previous),
        Err(error) if error.code() == CredentialErrorCode::NotFound => None,
        Err(_) => return fail_after_journal(state, proxy_profile_repair_required()).await,
    };
    let previous_state = if let Some(previous) = previous {
        if state
            .persistent_credentials
            .upsert(&backup, CredentialKind::ProxyPassword, previous)
            .await
            .is_err()
        {
            return fail_after_journal(state, proxy_profile_publication_failed()).await;
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
        Err(_) => return fail_after_journal(state, proxy_profile_repair_required()).await,
    };

    let mutation = match action {
        CredentialAction::Remove { target } => state.persistent_credentials.delete(&target).await,
        CredentialAction::Replace { target, secret } => {
            state
                .persistent_credentials
                .upsert(&target, CredentialKind::ProxyPassword, secret)
                .await
        }
    };
    if mutation.is_err() {
        return fail_after_journal(state, proxy_profile_publication_failed()).await;
    }

    let committed = match commit_planned_proxy_profile_graph(state, plan, target_graph).await {
        Ok(committed) => committed,
        Err(_) => return fail_after_journal(state, proxy_profile_publication_failed()).await,
    };
    let committed_revision = committed.revision().clone();
    let committed_graph = committed.graph().clone();
    let catalog = match confirm_exact_proxy_profile_commit(
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
                proxy_profile_repair_required(),
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
            proxy_profile_repair_required(),
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
            proxy_profile_repair_required(),
        )
        .await;
    }
    Ok(catalog)
}

async fn commit_planned_proxy_profile_graph(
    state: &DesktopState,
    plan: SavedVaultGraphReplacementPlan,
    target_graph: SavedVaultGraph,
) -> Result<netcatty_vault::SavedVaultGraphReplacementCommit, String> {
    let store = state.saved_hosts.clone();
    tokio::task::spawn_blocking(move || store.commit_planned_graph_replacement(plan, target_graph))
        .await
        .map_err(|_| proxy_profile_repair_required())?
        .map_err(map_proxy_profile_commit_error)
}

async fn confirm_proxy_profile_snapshot(
    state: &DesktopState,
) -> Result<SavedVaultDurableSnapshot, String> {
    let store = state.saved_hosts.clone();
    tokio::task::spawn_blocking(move || store.confirm_current_snapshot_durability())
        .await
        .map_err(|_| proxy_profile_repair_required())?
        .map_err(|_| proxy_profile_repair_required())
}

async fn confirm_exact_proxy_profile_commit(
    state: &DesktopState,
    expected_revision: SavedVaultInventoryRevision,
    expected_commitment: &SavedVaultGraphCommitment,
    expected_graph: &SavedVaultGraph,
) -> Result<ProxyProfileCatalog, String> {
    let snapshot = confirm_proxy_profile_snapshot(state).await?;
    if snapshot.revision() != &expected_revision
        || snapshot.commitment() != expected_commitment
        || snapshot.graph() != expected_graph
    {
        return Err(proxy_profile_repair_required());
    }
    Ok(ProxyProfileCatalog::from_graph(
        snapshot.revision().clone(),
        snapshot.graph(),
    ))
}

async fn fail_before_journal<T>(state: &DesktopState, primary: String) -> Result<T, String> {
    match recover_pending_legacy_import(state).await {
        Ok(()) => Err(primary),
        Err(_) => Err(proxy_profile_repair_required()),
    }
}

async fn fail_after_journal<T>(state: &DesktopState, primary: String) -> Result<T, String> {
    match recover_pending_legacy_import(state).await {
        Ok(()) => Err(primary),
        Err(_) => Err(proxy_profile_repair_required()),
    }
}

async fn recover_post_commit(
    state: &DesktopState,
    before: &SavedVaultGraphCommitment,
    after: &SavedVaultGraphCommitment,
    expected_revision: &SavedVaultInventoryRevision,
    expected_graph: &SavedVaultGraph,
    primary: String,
) -> Result<ProxyProfileCatalog, String> {
    if recover_pending_legacy_import(state).await.is_err() {
        return Err(proxy_profile_repair_required());
    }
    let snapshot = confirm_proxy_profile_snapshot(state).await?;
    if snapshot.commitment() == after {
        if snapshot.revision() != expected_revision || snapshot.graph() != expected_graph {
            return Err(proxy_profile_repair_required());
        }
        return Ok(ProxyProfileCatalog::from_graph(
            snapshot.revision().clone(),
            snapshot.graph(),
        ));
    }
    if snapshot.commitment() == before {
        return Err(primary);
    }
    Err(proxy_profile_repair_required())
}

fn map_proxy_profile_preflight_error(error: StoreError) -> String {
    match error {
        StoreError::InventoryRevisionConflict { .. } => proxy_profile_inventory_changed(),
        StoreError::Validation(_)
        | StoreError::DuplicateGraphEntityId(_)
        | StoreError::MissingGraphReference { .. }
        | StoreError::IncompatibleGraphReference { .. } => proxy_profile_error(
            PROXY_PROFILE_INVALID,
            "The proxy profile has incompatible relationships",
        ),
        StoreError::InvalidOwner
        | StoreError::BothSlotsCorrupt
        | StoreError::ConflictingGeneration
        | StoreError::GraphReplacementPlanMismatch
        | StoreError::SnapshotDurabilityUnconfirmed
        | StoreError::ManagedSecretRetentionUncertain
        | StoreError::ArtifactConflict => proxy_profile_repair_required(),
        _ => proxy_profile_publication_failed(),
    }
}

fn map_proxy_profile_commit_error(error: StoreError) -> String {
    match error {
        StoreError::InventoryRevisionConflict { .. } => proxy_profile_inventory_changed(),
        StoreError::InvalidOwner
        | StoreError::BothSlotsCorrupt
        | StoreError::ConflictingGeneration
        | StoreError::GraphReplacementPlanMismatch
        | StoreError::SnapshotDurabilityUnconfirmed
        | StoreError::ManagedSecretRetentionUncertain
        | StoreError::ArtifactConflict => proxy_profile_repair_required(),
        _ => proxy_profile_publication_failed(),
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
    use netcatty_vault::{SavedProxyProfileId, SavedVaultDurableSnapshot};

    use super::super::DesktopState;
    use super::super::legacy_import_transaction::LegacyImportTransaction;
    use super::super::proxy_profile_catalog::{
        CreateProxyProfileRequest, DeleteProxyProfileRequest, PROXY_PROFILE_PUBLICATION_FAILED,
        ProxyNetworkAuthRequest, ProxyProfileConfigRequest, ProxyProfileCredentialMutationRequest,
        ProxyProfileMetadataRequest, UpdateProxyProfileRequest, prepare_proxy_profile_creation,
        prepare_proxy_profile_deletion, prepare_proxy_profile_update,
    };
    use super::{
        commit_proxy_profile_deletion, commit_proxy_profile_mutation, load_proxy_profile_catalog,
    };

    const OWNER: &str = "proxy-profile-test-window";
    const OLD_SECRET: &str = "proxy-profile-old-secret-sentinel";
    const NEW_SECRET: &str = "proxy-profile-new-secret-sentinel";

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
            .expect("durable snapshot")
    }

    fn metadata(action: ProxyProfileCredentialMutationRequest) -> ProxyProfileMetadataRequest {
        ProxyProfileMetadataRequest {
            label: "Proxy profile".to_owned(),
            config: ProxyProfileConfigRequest::Http {
                host: "proxy.example.test".to_owned(),
                port: 8080,
                auth: ProxyNetworkAuthRequest::Manual {
                    username: "proxy-user".to_owned(),
                    credential_mutation: action,
                },
            },
        }
    }

    async fn stage(state: &DesktopState, value: &str) -> EphemeralCredentialReference {
        state
            .ephemeral_credentials
            .insert(
                OWNER,
                SecretValue::from_utf8(value.to_owned()).expect("secret"),
            )
            .await
            .expect("stage secret")
    }

    async fn create_metadata_only_profile(state: &DesktopState, id: &str) -> SavedProxyProfileId {
        let id = SavedProxyProfileId::from_opaque(id).expect("profile ID");
        let snapshot = durable_snapshot(state);
        let prepared = prepare_proxy_profile_creation(
            snapshot.graph().clone(),
            CreateProxyProfileRequest {
                expected_inventory_revision: snapshot.revision().clone(),
                metadata: metadata(ProxyProfileCredentialMutationRequest::Keep),
            },
            id.clone(),
            10,
        )
        .expect("creation plan");
        commit_proxy_profile_mutation(state, OWNER, prepared)
            .await
            .expect("metadata-only profile");
        id
    }

    fn update_request(
        snapshot: &SavedVaultDurableSnapshot,
        id: &SavedProxyProfileId,
        action: ProxyProfileCredentialMutationRequest,
    ) -> UpdateProxyProfileRequest {
        let profile = snapshot
            .graph()
            .proxy_profiles()
            .iter()
            .find(|profile| &profile.id == id)
            .expect("current profile");
        UpdateProxyProfileRequest {
            id: id.as_str().to_owned(),
            expected_revision: profile.revision,
            expected_inventory_revision: snapshot.revision().clone(),
            metadata: metadata(action),
        }
    }

    fn target(id: &SavedProxyProfileId) -> StoredCredentialReference {
        StoredCredentialReference::for_saved_proxy_profile(id.as_str()).expect("target")
    }

    fn assert_no_pending_journal(state: &DesktopState) {
        assert!(
            LegacyImportTransaction::load(state.legacy_import_transaction_root.as_ref())
                .expect("load journal")
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn keep_is_pure_vault_and_catalog_json_is_secret_safe() {
        let directory = tempfile::tempdir().expect("temporary Vault");
        let (state, controller) = desktop_state(directory.path());
        let id = create_metadata_only_profile(&state, "metadata-only-proxy").await;

        assert!(controller.operation_log().is_empty());
        assert_no_pending_journal(&state);
        let snapshot = durable_snapshot(&state);
        assert_eq!(snapshot.graph().proxy_profiles()[0].id, id);
        let catalog = load_proxy_profile_catalog(&state).await.expect("catalog");
        let encoded = serde_json::to_string(&catalog).expect("catalog JSON");
        for forbidden in [OLD_SECRET, NEW_SECRET, "credentialReference", "os:v1:"] {
            assert!(!encoded.contains(forbidden));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replace_uses_proxy_password_owner_and_cleans_journal_and_backup() {
        let directory = tempfile::tempdir().expect("temporary Vault");
        let (state, controller) = desktop_state(directory.path());
        let id = create_metadata_only_profile(&state, "replace-proxy").await;
        let staged = stage(&state, NEW_SECRET).await;
        let snapshot = durable_snapshot(&state);
        let prepared = prepare_proxy_profile_update(
            snapshot.graph().clone(),
            update_request(
                &snapshot,
                &id,
                ProxyProfileCredentialMutationRequest::Replace {
                    staged_credential_reference: staged,
                },
            ),
            20,
        )
        .expect("replace plan");
        controller.clear_operation_log();

        let catalog = commit_proxy_profile_mutation(&state, OWNER, prepared)
            .await
            .expect("replace credential");

        let saved = state
            .persistent_credentials
            .resolve(&target(&id), CredentialKind::ProxyPassword)
            .await
            .expect("proxy credential");
        assert_eq!(saved.as_utf8(), Ok(NEW_SECRET));
        assert_no_pending_journal(&state);
        assert!(controller.operation_count(CredentialOperation::Resolve) >= 1);
        let encoded = serde_json::to_string(&catalog).expect("catalog JSON");
        assert!(!encoded.contains(NEW_SECRET));
        assert!(!encoded.contains("os:v1:"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn remove_probes_false_hint_and_deletes_deterministic_account() {
        let directory = tempfile::tempdir().expect("temporary Vault");
        let (state, controller) = desktop_state(directory.path());
        let id = create_metadata_only_profile(&state, "false-hint-proxy").await;
        let target = target(&id);
        state
            .persistent_credentials
            .upsert(
                &target,
                CredentialKind::ProxyPassword,
                SecretValue::from_utf8(OLD_SECRET.to_owned()).expect("old secret"),
            )
            .await
            .expect("seed orphan account");
        controller.clear_operation_log();
        let snapshot = durable_snapshot(&state);
        let prepared = prepare_proxy_profile_update(
            snapshot.graph().clone(),
            update_request(
                &snapshot,
                &id,
                ProxyProfileCredentialMutationRequest::Remove,
            ),
            20,
        )
        .expect("remove plan");

        commit_proxy_profile_mutation(&state, OWNER, prepared)
            .await
            .expect("remove credential");

        assert!(controller.operation_count(CredentialOperation::Resolve) >= 1);
        assert_no_pending_journal(&state);
        let error = match state
            .persistent_credentials
            .resolve(&target, CredentialKind::ProxyPassword)
            .await
        {
            Ok(_) => panic!("target must be removed"),
            Err(error) => error,
        };
        assert_eq!(error.code(), CredentialErrorCode::NotFound);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ambiguous_delete_failure_restores_graph_and_proxy_credential() {
        let directory = tempfile::tempdir().expect("temporary Vault");
        let (state, controller) = desktop_state(directory.path());
        let id = create_metadata_only_profile(&state, "failed-delete-proxy").await;
        let target = target(&id);
        state
            .persistent_credentials
            .upsert(
                &target,
                CredentialKind::ProxyPassword,
                SecretValue::from_utf8(OLD_SECRET.to_owned()).expect("old secret"),
            )
            .await
            .expect("seed old account");
        let before = durable_snapshot(&state);
        let current = &before.graph().proxy_profiles()[0];
        let prepared = prepare_proxy_profile_deletion(
            before.graph().clone(),
            DeleteProxyProfileRequest {
                id: id.as_str().to_owned(),
                expected_revision: current.revision,
                expected_inventory_revision: before.revision().clone(),
            },
            30,
        )
        .expect("deletion plan");
        controller.clear_operation_log();
        controller.set_failure(
            CredentialOperation::Delete,
            1,
            FailureTiming::AfterSideEffect,
            CredentialErrorCode::BackendFailure,
        );

        let error = commit_proxy_profile_deletion(&state, prepared)
            .await
            .expect_err("ambiguous delete");

        assert!(error.starts_with(PROXY_PROFILE_PUBLICATION_FAILED));
        assert_eq!(durable_snapshot(&state).graph(), before.graph());
        assert_no_pending_journal(&state);
        let restored = state
            .persistent_credentials
            .resolve(&target, CredentialKind::ProxyPassword)
            .await
            .expect("restored credential");
        assert_eq!(restored.as_utf8(), Ok(OLD_SECRET));
    }
}
