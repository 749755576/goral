//! Durable desktop coordination for GroupConfig catalog mutations.
//!
//! Metadata-only requests use a complete-Vault-graph CAS without touching
//! credential custody. SSH, Telnet, and inline-proxy replace/remove actions
//! atomically consume owner-bound one-shot references only after that CAS
//! preflight, then use the existing multi-owner recovery journal so a crash
//! cannot publish a graph/account mixture that cannot be repaired on restart.

use netcatty_credentials::{CredentialErrorCode, SecretValue, StoredCredentialReference};
use netcatty_vault::{
    SavedVaultDurableSnapshot, SavedVaultGraph, SavedVaultGraphCommitment,
    SavedVaultGraphReplacementPlan, SavedVaultInventoryRevision, StoreError,
};

use super::group_config_catalog::{
    GROUP_CONFIG_INVALID, GroupConfigCatalog, PreparedGroupConfigDeletion,
    PreparedGroupConfigMutation, PreparedGroupCredentialDeletions, PreparedGroupCredentialMutation,
    PreparedGroupCredentialMutations, group_config_error, group_config_invalid,
    group_config_inventory_changed, group_config_publication_failed, group_config_repair_required,
};
use super::legacy_import_transaction::{
    LegacyImportCredentialOwner, LegacyPreviousCredentialState,
};
use super::{
    DesktopState, activate_legacy_import_transaction_for_owners,
    begin_legacy_import_transaction_for_owners, cleanup_legacy_import_backups,
    finish_legacy_import_transaction, legacy_import_credential_kind_for_owner,
    legacy_import_credential_references_for_owner, mark_legacy_vault_durable,
    recover_pending_legacy_import,
};

enum GroupCredentialAction {
    Remove {
        target: StoredCredentialReference,
    },
    Replace {
        target: StoredCredentialReference,
        secret: SecretValue,
    },
}

impl GroupCredentialAction {
    const fn target(&self) -> &StoredCredentialReference {
        match self {
            Self::Remove { target } | Self::Replace { target, .. } => target,
        }
    }
}

struct GroupCredentialWork {
    owner: LegacyImportCredentialOwner,
    action: GroupCredentialAction,
}

pub(crate) async fn load_group_config_catalog(
    state: &DesktopState,
) -> Result<GroupConfigCatalog, String> {
    let snapshot = confirm_group_config_snapshot(state).await?;
    Ok(GroupConfigCatalog::from_graph(
        snapshot.revision().clone(),
        snapshot.graph(),
    ))
}

/// Commits one create/update proposal. Complete-inventory CAS and deterministic
/// owner/target checks happen before any one-shot credential is consumed.
pub(crate) async fn commit_group_config_mutation(
    state: &DesktopState,
    window_owner: &str,
    prepared: PreparedGroupConfigMutation,
) -> Result<GroupConfigCatalog, String> {
    let (expected_revision, target_graph, group, credential_mutations) = prepared.into_parts();
    let plan = match plan_group_config_graph(state, expected_revision, &target_graph).await {
        Ok(plan) => plan,
        Err(primary) => return fail_before_journal(state, primary).await,
    };
    let actions = match materialize_group_credential_actions(
        state,
        window_owner,
        group.id.as_str(),
        credential_mutations,
    )
    .await
    {
        Ok(actions) => actions,
        Err(primary) => return fail_before_journal(state, primary).await,
    };
    if actions.is_empty() {
        commit_group_config_graph_without_credentials(state, plan, target_graph).await
    } else {
        commit_group_config_graph_with_credentials(state, plan, target_graph, actions).await
    }
}

/// Removes one group and all three isolated deterministic credential owners.
/// Accounts are probed even when Vault says no credential is present; a stale
/// false hint must not leave an orphaned secret behind.
pub(crate) async fn commit_group_config_deletion(
    state: &DesktopState,
    prepared: PreparedGroupConfigDeletion,
) -> Result<GroupConfigCatalog, String> {
    let (expected_revision, target_graph, group_id, credential_deletions) = prepared.into_parts();
    let actions = validate_group_credential_deletions(group_id.as_str(), credential_deletions)?;
    let plan = match plan_group_config_graph(state, expected_revision, &target_graph).await {
        Ok(plan) => plan,
        Err(primary) => return fail_before_journal(state, primary).await,
    };
    commit_group_config_graph_with_credentials(state, plan, target_graph, actions).await
}

fn validate_group_credential_deletions(
    group_id: &str,
    prepared: PreparedGroupCredentialDeletions,
) -> Result<Vec<GroupCredentialWork>, String> {
    let owners = [
        LegacyImportCredentialOwner::for_group_ssh(group_id),
        LegacyImportCredentialOwner::for_group_telnet(group_id),
        LegacyImportCredentialOwner::for_group_proxy(group_id),
    ]
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .map_err(|_| group_config_repair_required())?;
    let targets = [
        prepared.ssh().target().clone(),
        prepared.telnet().target().clone(),
        prepared.proxy().target().clone(),
    ];
    let expected_targets = [
        StoredCredentialReference::for_saved_group_ssh(group_id),
        StoredCredentialReference::for_saved_group_telnet(group_id),
        StoredCredentialReference::for_saved_group_proxy(group_id),
    ]
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .map_err(|_| group_config_repair_required())?;

    if targets.as_slice() != expected_targets.as_slice() {
        return Err(group_config_repair_required());
    }
    Ok(owners
        .into_iter()
        .zip(targets)
        .map(|(owner, target)| GroupCredentialWork {
            owner,
            action: GroupCredentialAction::Remove { target },
        })
        .collect())
}

async fn materialize_group_credential_actions(
    state: &DesktopState,
    window_owner: &str,
    group_id: &str,
    prepared: PreparedGroupCredentialMutations,
) -> Result<Vec<GroupCredentialWork>, String> {
    let owners = [
        LegacyImportCredentialOwner::for_group_ssh(group_id),
        LegacyImportCredentialOwner::for_group_telnet(group_id),
        LegacyImportCredentialOwner::for_group_proxy(group_id),
    ]
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .map_err(|_| group_config_repair_required())?;
    let expected_targets = [
        StoredCredentialReference::for_saved_group_ssh(group_id),
        StoredCredentialReference::for_saved_group_telnet(group_id),
        StoredCredentialReference::for_saved_group_proxy(group_id),
    ]
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .map_err(|_| group_config_repair_required())?;
    let (ssh, telnet, proxy) = prepared.into_parts();
    let mutations = [ssh, telnet, proxy];
    if mutations
        .iter()
        .zip(&expected_targets)
        .any(|(mutation, expected)| mutation.target() != expected)
    {
        return Err(group_config_repair_required());
    }

    // Claim the complete capability set atomically under one staging-store
    // lock. One missing, duplicate, expired, or wrong-window reference leaves
    // every otherwise valid reference available for a corrected retry.
    let staged_references = mutations
        .iter()
        .filter_map(PreparedGroupCredentialMutation::staged_credential_reference)
        .copied()
        .collect::<Vec<_>>();
    let mut staged_secrets = state
        .ephemeral_credentials
        .take_many(window_owner, &staged_references)
        .await
        .map_err(|_| group_config_invalid())?
        .into_iter();

    let mut actions = Vec::with_capacity(3);
    for ((owner, mutation), expected_target) in
        owners.into_iter().zip(mutations).zip(expected_targets)
    {
        match mutation {
            PreparedGroupCredentialMutation::Keep { .. } => {}
            PreparedGroupCredentialMutation::Remove { .. } => {
                actions.push(GroupCredentialWork {
                    owner,
                    action: GroupCredentialAction::Remove {
                        target: expected_target,
                    },
                });
            }
            PreparedGroupCredentialMutation::Replace { .. } => {
                let secret = staged_secrets
                    .next()
                    .ok_or_else(group_config_repair_required)?;
                actions.push(GroupCredentialWork {
                    owner,
                    action: GroupCredentialAction::Replace {
                        target: expected_target,
                        secret,
                    },
                });
            }
        }
    }
    if staged_secrets.next().is_some() {
        return Err(group_config_repair_required());
    }
    Ok(actions)
}

async fn plan_group_config_graph(
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
    .map_err(|_| group_config_repair_required())?
    .map_err(map_group_config_preflight_error)
}

async fn commit_group_config_graph_without_credentials(
    state: &DesktopState,
    plan: SavedVaultGraphReplacementPlan,
    target_graph: SavedVaultGraph,
) -> Result<GroupConfigCatalog, String> {
    let before = plan.before_graph_commitment().clone();
    let after = plan.after_graph_commitment().clone();
    let committed = match commit_planned_group_config_graph(state, plan, target_graph).await {
        Ok(committed) => committed,
        Err(primary) => return fail_before_journal(state, primary).await,
    };
    match confirm_exact_group_config_commit(
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

async fn commit_group_config_graph_with_credentials(
    state: &DesktopState,
    plan: SavedVaultGraphReplacementPlan,
    target_graph: SavedVaultGraph,
    actions: Vec<GroupCredentialWork>,
) -> Result<GroupConfigCatalog, String> {
    if !plan.has_changes() || actions.is_empty() || actions.len() > 3 {
        return fail_before_journal(state, group_config_repair_required()).await;
    }
    let before = plan.before_graph_commitment().clone();
    let after = plan.after_graph_commitment().clone();
    let owners = actions
        .iter()
        .map(|work| work.owner.clone())
        .collect::<Vec<_>>();
    let mut transaction = match begin_legacy_import_transaction_for_owners(
        state,
        owners.clone(),
        before.clone(),
        after.clone(),
    )
    .await
    {
        Ok(transaction) => transaction,
        Err(_) => return fail_before_journal(state, group_config_repair_required()).await,
    };

    let mut previous_states = Vec::with_capacity(actions.len());
    for work in &actions {
        let (target, backup) =
            match legacy_import_credential_references_for_owner(&transaction, &work.owner) {
                Ok(references) => references,
                Err(_) => return fail_after_journal(state, group_config_repair_required()).await,
            };
        if &target != work.action.target() {
            return fail_after_journal(state, group_config_repair_required()).await;
        }
        let kind = legacy_import_credential_kind_for_owner(&work.owner);
        let previous = match state.persistent_credentials.resolve(&target, kind).await {
            Ok(previous) => Some(previous),
            Err(error) if error.code() == CredentialErrorCode::NotFound => None,
            Err(_) => return fail_after_journal(state, group_config_repair_required()).await,
        };
        let previous_state = if let Some(previous) = previous {
            if state
                .persistent_credentials
                .upsert(&backup, kind, previous)
                .await
                .is_err()
            {
                return fail_after_journal(state, group_config_publication_failed()).await;
            }
            LegacyPreviousCredentialState::BackedUp
        } else {
            LegacyPreviousCredentialState::Absent
        };
        previous_states.push((work.owner.clone(), previous_state));
    }

    transaction =
        match activate_legacy_import_transaction_for_owners(transaction, previous_states).await {
            Ok(transaction) => transaction,
            Err(_) => return fail_after_journal(state, group_config_repair_required()).await,
        };

    for work in actions {
        let kind = legacy_import_credential_kind_for_owner(&work.owner);
        let result = match work.action {
            GroupCredentialAction::Remove { target } => {
                state.persistent_credentials.delete(&target).await
            }
            GroupCredentialAction::Replace { target, secret } => {
                state
                    .persistent_credentials
                    .upsert(&target, kind, secret)
                    .await
            }
        };
        if result.is_err() {
            return fail_after_journal(state, group_config_publication_failed()).await;
        }
    }

    let committed = match commit_planned_group_config_graph(state, plan, target_graph).await {
        Ok(committed) => committed,
        Err(_) => return fail_after_journal(state, group_config_publication_failed()).await,
    };
    let committed_revision = committed.revision().clone();
    let committed_graph = committed.graph().clone();
    let catalog = match confirm_exact_group_config_commit(
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
                group_config_repair_required(),
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
            group_config_repair_required(),
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
            group_config_repair_required(),
        )
        .await;
    }
    Ok(catalog)
}

async fn commit_planned_group_config_graph(
    state: &DesktopState,
    plan: SavedVaultGraphReplacementPlan,
    target_graph: SavedVaultGraph,
) -> Result<netcatty_vault::SavedVaultGraphReplacementCommit, String> {
    let store = state.saved_hosts.clone();
    tokio::task::spawn_blocking(move || store.commit_planned_graph_replacement(plan, target_graph))
        .await
        .map_err(|_| group_config_repair_required())?
        .map_err(map_group_config_commit_error)
}

async fn confirm_group_config_snapshot(
    state: &DesktopState,
) -> Result<SavedVaultDurableSnapshot, String> {
    let store = state.saved_hosts.clone();
    tokio::task::spawn_blocking(move || store.confirm_current_snapshot_durability())
        .await
        .map_err(|_| group_config_repair_required())?
        .map_err(|_| group_config_repair_required())
}

async fn confirm_exact_group_config_commit(
    state: &DesktopState,
    expected_revision: SavedVaultInventoryRevision,
    expected_commitment: &SavedVaultGraphCommitment,
    expected_graph: &SavedVaultGraph,
) -> Result<GroupConfigCatalog, String> {
    let snapshot = confirm_group_config_snapshot(state).await?;
    if snapshot.revision() != &expected_revision
        || snapshot.commitment() != expected_commitment
        || snapshot.graph() != expected_graph
    {
        return Err(group_config_repair_required());
    }
    Ok(GroupConfigCatalog::from_graph(
        snapshot.revision().clone(),
        snapshot.graph(),
    ))
}

async fn fail_before_journal<T>(state: &DesktopState, primary: String) -> Result<T, String> {
    match recover_pending_legacy_import(state).await {
        Ok(()) => Err(primary),
        Err(_) => Err(group_config_repair_required()),
    }
}

async fn fail_after_journal<T>(state: &DesktopState, primary: String) -> Result<T, String> {
    match recover_pending_legacy_import(state).await {
        Ok(()) => Err(primary),
        Err(_) => Err(group_config_repair_required()),
    }
}

async fn recover_post_commit(
    state: &DesktopState,
    before: &SavedVaultGraphCommitment,
    after: &SavedVaultGraphCommitment,
    expected_revision: &SavedVaultInventoryRevision,
    expected_graph: &SavedVaultGraph,
    primary: String,
) -> Result<GroupConfigCatalog, String> {
    if recover_pending_legacy_import(state).await.is_err() {
        return Err(group_config_repair_required());
    }
    let snapshot = confirm_group_config_snapshot(state).await?;
    if snapshot.commitment() == after {
        if snapshot.revision() != expected_revision || snapshot.graph() != expected_graph {
            return Err(group_config_repair_required());
        }
        return Ok(GroupConfigCatalog::from_graph(
            snapshot.revision().clone(),
            snapshot.graph(),
        ));
    }
    if snapshot.commitment() == before {
        return Err(primary);
    }
    Err(group_config_repair_required())
}

fn map_group_config_preflight_error(error: StoreError) -> String {
    match error {
        StoreError::InventoryRevisionConflict { .. } => group_config_inventory_changed(),
        StoreError::Validation(_)
        | StoreError::DuplicateGraphEntityId(_)
        | StoreError::MissingGraphReference { .. }
        | StoreError::IncompatibleGraphReference { .. } => group_config_error(
            GROUP_CONFIG_INVALID,
            "The group configuration has incompatible relationships",
        ),
        StoreError::InvalidOwner
        | StoreError::BothSlotsCorrupt
        | StoreError::ConflictingGeneration
        | StoreError::GraphReplacementPlanMismatch
        | StoreError::SnapshotDurabilityUnconfirmed
        | StoreError::ManagedSecretRetentionUncertain
        | StoreError::ArtifactConflict => group_config_repair_required(),
        _ => group_config_publication_failed(),
    }
}

fn map_group_config_commit_error(error: StoreError) -> String {
    match error {
        StoreError::InventoryRevisionConflict { .. } => group_config_inventory_changed(),
        StoreError::InvalidOwner
        | StoreError::BothSlotsCorrupt
        | StoreError::ConflictingGeneration
        | StoreError::GraphReplacementPlanMismatch
        | StoreError::SnapshotDurabilityUnconfirmed
        | StoreError::ManagedSecretRetentionUncertain
        | StoreError::ArtifactConflict => group_config_repair_required(),
        _ => group_config_publication_failed(),
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
    use netcatty_vault::{
        SavedGroupCredentialOverride, SavedGroupDefaults, SavedGroupId, SavedGroupProxyOverride,
        SavedProxyConfig, SavedVaultDurableSnapshot,
    };
    use serde_json::json;

    use super::super::DesktopState;
    use super::super::group_config_catalog::{
        CreateGroupConfigRequest, DeleteGroupConfigRequest, GROUP_CONFIG_INVENTORY_CHANGED,
        GROUP_CONFIG_PUBLICATION_FAILED, UpdateGroupConfigRequest, prepare_group_config_creation,
        prepare_group_config_deletion, prepare_group_config_update,
    };
    use super::super::legacy_import_transaction::LegacyImportTransaction;
    use super::{
        commit_group_config_deletion, commit_group_config_mutation, load_group_config_catalog,
    };

    const SSH_SECRET: &str = "group-ssh-secret-sentinel";
    const TELNET_SECRET: &str = "group-telnet-secret-sentinel";
    const PROXY_SECRET: &str = "group-proxy-secret-sentinel";
    const OWNER: &str = "group-config-test-window";

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

    fn create_request(
        snapshot: &SavedVaultDurableSnapshot,
        path: &str,
    ) -> CreateGroupConfigRequest {
        serde_json::from_value(json!({
            "expectedInventoryRevision": snapshot.revision(),
            "metadata": {
                "path": path,
                "defaults": serde_json::to_value(SavedGroupDefaults::default())
                    .expect("default group metadata")
            }
        }))
        .expect("group create request")
    }

    fn replace_all_request(
        snapshot: &SavedVaultDurableSnapshot,
        path: &str,
        references: [EphemeralCredentialReference; 3],
    ) -> CreateGroupConfigRequest {
        let defaults = SavedGroupDefaults {
            proxy: SavedGroupProxyOverride::Inline(
                SavedProxyConfig::http("proxy.example.test", 8080, None, "proxy-user", false)
                    .expect("manual inline proxy"),
            ),
            ..SavedGroupDefaults::default()
        };
        serde_json::from_value(json!({
            "expectedInventoryRevision": snapshot.revision(),
            "metadata": {
                "path": path,
                "defaults": serde_json::to_value(defaults).expect("group metadata")
            },
            "credentialMutations": {
                "sshPassword": {
                    "action": "replace",
                    "stagedCredentialReference": references[0]
                },
                "telnetPassword": {
                    "action": "replace",
                    "stagedCredentialReference": references[1]
                },
                "proxyPassword": {
                    "action": "replace",
                    "stagedCredentialReference": references[2]
                }
            }
        }))
        .expect("group replace request")
    }

    async fn stage_three_group_credentials(
        state: &DesktopState,
    ) -> [EphemeralCredentialReference; 3] {
        let mut references = Vec::with_capacity(3);
        for value in [SSH_SECRET, TELNET_SECRET, PROXY_SECRET] {
            references.push(
                state
                    .ephemeral_credentials
                    .insert(
                        OWNER,
                        SecretValue::from_utf8(value.to_owned()).expect("test secret"),
                    )
                    .await
                    .expect("stage group credential"),
            );
        }
        references.try_into().expect("three staged references")
    }

    async fn create_group(state: &DesktopState, id: &str, path: &str) -> SavedGroupId {
        let snapshot = durable_snapshot(state);
        let id = SavedGroupId::from_opaque(id).expect("group ID");
        let prepared = prepare_group_config_creation(
            snapshot.graph().clone(),
            create_request(&snapshot, path),
            id.clone(),
            10,
        )
        .expect("group creation plan");
        commit_group_config_mutation(state, OWNER, prepared)
            .await
            .expect("group creation");
        id
    }

    fn targets(
        id: &SavedGroupId,
    ) -> [(StoredCredentialReference, CredentialKind, &'static str); 3] {
        [
            (
                StoredCredentialReference::for_saved_group_ssh(id.as_str())
                    .expect("group SSH target"),
                CredentialKind::SshPassword,
                SSH_SECRET,
            ),
            (
                StoredCredentialReference::for_saved_group_telnet(id.as_str())
                    .expect("group Telnet target"),
                CredentialKind::TelnetPassword,
                TELNET_SECRET,
            ),
            (
                StoredCredentialReference::for_saved_group_proxy(id.as_str())
                    .expect("group proxy target"),
                CredentialKind::ProxyPassword,
                PROXY_SECRET,
            ),
        ]
    }

    async fn seed_group_credentials(state: &DesktopState, id: &SavedGroupId) {
        for (target, kind, value) in targets(id) {
            state
                .persistent_credentials
                .upsert(
                    &target,
                    kind,
                    SecretValue::from_utf8(value.to_owned()).expect("test secret"),
                )
                .await
                .expect("seed group credential");
        }
    }

    fn deletion_request(
        snapshot: &SavedVaultDurableSnapshot,
        id: &SavedGroupId,
    ) -> DeleteGroupConfigRequest {
        let group = snapshot
            .graph()
            .groups()
            .iter()
            .find(|group| &group.id == id)
            .expect("current group");
        DeleteGroupConfigRequest {
            id: id.as_str().to_owned(),
            expected_revision: group.revision,
            expected_inventory_revision: snapshot.revision().clone(),
        }
    }

    fn assert_no_pending_journal(state: &DesktopState) {
        assert!(
            LegacyImportTransaction::load(state.legacy_import_transaction_root.as_ref())
                .expect("load recovery journal")
                .is_none(),
            "completed GroupConfig mutation must remove its recovery journal"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn metadata_create_and_list_use_only_the_vault_and_return_safe_json() {
        let directory = tempfile::tempdir().expect("temporary Vault");
        let (state, controller) = desktop_state(directory.path());
        let id = create_group(&state, "listed-group", "Operations/Primary").await;

        assert!(controller.operation_log().is_empty());
        assert_no_pending_journal(&state);
        let catalog = load_group_config_catalog(&state)
            .await
            .expect("group catalog");
        let encoded = serde_json::to_string(&catalog).expect("renderer-safe group catalog");
        assert!(encoded.contains(id.as_str()));
        assert!(encoded.contains("Operations/Primary"));
        for forbidden in [
            SSH_SECRET,
            TELNET_SECRET,
            PROXY_SECRET,
            "credentialReference",
            "keyringAccount",
            "os:v1:",
        ] {
            assert!(!encoded.contains(forbidden));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_replaces_all_three_credentials_durably_and_returns_safe_json() {
        let directory = tempfile::tempdir().expect("temporary Vault");
        let (state, _) = desktop_state(directory.path());
        let snapshot = durable_snapshot(&state);
        let references = stage_three_group_credentials(&state).await;
        let reference_strings = references.map(|reference| reference.to_string());
        let id = SavedGroupId::from_opaque("credential-group").expect("group ID");
        let prepared = prepare_group_config_creation(
            snapshot.graph().clone(),
            replace_all_request(&snapshot, "Credentials", references),
            id.clone(),
            20,
        )
        .expect("group credential creation plan");

        let catalog = commit_group_config_mutation(&state, OWNER, prepared)
            .await
            .expect("durable group credential creation");

        let durable = durable_snapshot(&state);
        let saved = durable
            .graph()
            .groups()
            .iter()
            .find(|group| group.id == id)
            .expect("durable group");
        assert_eq!(
            saved.defaults.password,
            SavedGroupCredentialOverride::StoredHint
        );
        assert_eq!(
            saved.defaults.telnet_password,
            SavedGroupCredentialOverride::StoredHint
        );
        assert!(matches!(
            &saved.defaults.proxy,
            SavedGroupProxyOverride::Inline(SavedProxyConfig::Http {
                identity_id: None,
                has_saved_credential: true,
                ..
            })
        ));
        assert_no_pending_journal(&state);
        assert!(state.ephemeral_credentials.is_empty().await);
        for (target, kind, expected) in targets(&id) {
            let stored = state
                .persistent_credentials
                .resolve(&target, kind)
                .await
                .expect("stored group credential");
            assert_eq!(stored.as_utf8(), Ok(expected));
        }
        let encoded = serde_json::to_string(&catalog).expect("renderer-safe group catalog");
        for forbidden in [SSH_SECRET, TELNET_SECRET, PROXY_SECRET, "os:v1:"]
            .into_iter()
            .chain(reference_strings.iter().map(String::as_str))
        {
            assert!(!encoded.contains(forbidden));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stale_inventory_rejects_before_consuming_any_staged_group_credential() {
        let directory = tempfile::tempdir().expect("temporary Vault");
        let (state, controller) = desktop_state(directory.path());
        let stale = durable_snapshot(&state);
        let references = stage_three_group_credentials(&state).await;
        let id = SavedGroupId::from_opaque("staged-stale-group").expect("group ID");
        let prepared = prepare_group_config_creation(
            stale.graph().clone(),
            replace_all_request(&stale, "Staged stale", references),
            id,
            20,
        )
        .expect("stale group credential plan");
        create_group(&state, "inventory-advance-group", "Advance").await;
        controller.clear_operation_log();

        let error = commit_group_config_mutation(&state, OWNER, prepared)
            .await
            .expect_err("stale inventory must fail before staged claims");

        assert!(error.starts_with(GROUP_CONFIG_INVENTORY_CHANGED));
        assert!(controller.operation_log().is_empty());
        assert_no_pending_journal(&state);
        for (reference, expected) in
            references
                .into_iter()
                .zip([SSH_SECRET, TELNET_SECRET, PROXY_SECRET])
        {
            let retained = state
                .ephemeral_credentials
                .take(OWNER, &reference)
                .await
                .expect("staged credential remains available");
            assert_eq!(retained.as_utf8(), Ok(expected));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn update_remove_deletes_every_group_account_and_clears_presence_hints() {
        let directory = tempfile::tempdir().expect("temporary Vault");
        let (state, _) = desktop_state(directory.path());
        let initial = durable_snapshot(&state);
        let references = stage_three_group_credentials(&state).await;
        let id = SavedGroupId::from_opaque("remove-credentials-group").expect("group ID");
        let create = prepare_group_config_creation(
            initial.graph().clone(),
            replace_all_request(&initial, "Remove credentials", references),
            id.clone(),
            20,
        )
        .expect("group credential creation plan");
        commit_group_config_mutation(&state, OWNER, create)
            .await
            .expect("group credential creation");

        let before_remove = durable_snapshot(&state);
        let current = before_remove
            .graph()
            .groups()
            .iter()
            .find(|group| group.id == id)
            .expect("current group");
        let request: UpdateGroupConfigRequest = serde_json::from_value(json!({
            "id": id.as_str(),
            "expectedRevision": current.revision,
            "expectedInventoryRevision": before_remove.revision(),
            "metadata": {
                "path": current.path.as_str(),
                "defaults": serde_json::to_value(SavedGroupDefaults::default())
                    .expect("default group metadata")
            },
            "credentialMutations": {
                "sshPassword": {"action": "remove"},
                "telnetPassword": {"action": "remove"},
                "proxyPassword": {"action": "remove"}
            }
        }))
        .expect("group credential removal request");
        let remove = prepare_group_config_update(before_remove.graph().clone(), request, 30)
            .expect("group credential removal plan");

        commit_group_config_mutation(&state, OWNER, remove)
            .await
            .expect("durable group credential removal");

        let durable = durable_snapshot(&state);
        let saved = durable
            .graph()
            .groups()
            .iter()
            .find(|group| group.id == id)
            .expect("updated group");
        assert_ne!(
            saved.defaults.password,
            SavedGroupCredentialOverride::StoredHint
        );
        assert_ne!(
            saved.defaults.telnet_password,
            SavedGroupCredentialOverride::StoredHint
        );
        assert!(!matches!(
            &saved.defaults.proxy,
            SavedGroupProxyOverride::Inline(
                SavedProxyConfig::Http {
                    has_saved_credential: true,
                    ..
                } | SavedProxyConfig::Socks5 {
                    has_saved_credential: true,
                    ..
                }
            )
        ));
        assert_no_pending_journal(&state);
        for (target, kind, _) in targets(&id) {
            let error = match state.persistent_credentials.resolve(&target, kind).await {
                Ok(_) => panic!("removed group credential must be absent"),
                Err(error) => error,
            };
            assert_eq!(error.code(), CredentialErrorCode::NotFound);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn delete_removes_all_three_accounts_even_when_presence_hints_are_false() {
        let directory = tempfile::tempdir().expect("temporary Vault");
        let (state, controller) = desktop_state(directory.path());
        let id = create_group(&state, "deleted-group", "Deleted").await;
        seed_group_credentials(&state, &id).await;
        let before = durable_snapshot(&state);
        let prepared =
            prepare_group_config_deletion(before.graph().clone(), deletion_request(&before, &id))
                .expect("group deletion plan");
        controller.clear_operation_log();

        let catalog = commit_group_config_deletion(&state, prepared)
            .await
            .expect("group deletion");

        assert!(durable_snapshot(&state).graph().groups().is_empty());
        assert_no_pending_journal(&state);
        for (target, kind, _) in targets(&id) {
            let error = match state.persistent_credentials.resolve(&target, kind).await {
                Ok(_) => panic!("group credential must be absent"),
                Err(error) => error,
            };
            assert_eq!(error.code(), CredentialErrorCode::NotFound);
        }
        assert!(controller.operation_count(CredentialOperation::Resolve) >= 3);
        let encoded = serde_json::to_string(&catalog).expect("renderer-safe catalog");
        for forbidden in [SSH_SECRET, TELNET_SECRET, PROXY_SECRET, "os:v1:"] {
            assert!(!encoded.contains(forbidden));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ambiguous_second_account_delete_restores_graph_and_every_secret() {
        let directory = tempfile::tempdir().expect("temporary Vault");
        let (state, controller) = desktop_state(directory.path());
        let id = create_group(&state, "rollback-group", "Rollback").await;
        seed_group_credentials(&state, &id).await;
        let before = durable_snapshot(&state);
        let prepared =
            prepare_group_config_deletion(before.graph().clone(), deletion_request(&before, &id))
                .expect("group deletion plan");
        controller.clear_operation_log();
        controller.set_failure(
            CredentialOperation::Delete,
            2,
            FailureTiming::AfterSideEffect,
            CredentialErrorCode::BackendFailure,
        );

        let error = commit_group_config_deletion(&state, prepared)
            .await
            .expect_err("ambiguous group credential delete");

        assert!(error.starts_with(GROUP_CONFIG_PUBLICATION_FAILED));
        assert_eq!(durable_snapshot(&state).graph(), before.graph());
        assert_no_pending_journal(&state);
        for (target, kind, expected) in targets(&id) {
            let restored = state
                .persistent_credentials
                .resolve(&target, kind)
                .await
                .expect("restored group credential");
            assert_eq!(restored.as_utf8(), Ok(expected));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stale_inventory_is_rejected_before_any_group_account_is_touched() {
        let directory = tempfile::tempdir().expect("temporary Vault");
        let (state, controller) = desktop_state(directory.path());
        let id = create_group(&state, "stale-group", "Stale").await;
        seed_group_credentials(&state, &id).await;
        let stale = durable_snapshot(&state);
        let prepared =
            prepare_group_config_deletion(stale.graph().clone(), deletion_request(&stale, &id))
                .expect("stale group deletion plan");
        create_group(&state, "inventory-advance-group", "Advance").await;
        controller.clear_operation_log();

        let error = commit_group_config_deletion(&state, prepared)
            .await
            .expect_err("stale inventory must fail");

        assert!(error.starts_with(GROUP_CONFIG_INVENTORY_CHANGED));
        assert!(controller.operation_log().is_empty());
        assert_no_pending_journal(&state);
        for (target, kind, expected) in targets(&id) {
            let retained = state
                .persistent_credentials
                .resolve(&target, kind)
                .await
                .expect("untouched group credential");
            assert_eq!(retained.as_utf8(), Ok(expected));
        }
    }
}
