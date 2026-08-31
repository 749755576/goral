use netcatty_vault::{SavedVaultCommitDurability, StoreError};
use tauri::State;

use super::{DesktopState, current_unix_millis, run_saved_host_operation};
use crate::known_hosts_catalog::{
    self, KNOWN_HOSTS_INVENTORY_CHANGED, KNOWN_HOSTS_PUBLICATION_FAILED,
    KNOWN_HOSTS_REPAIR_REQUIRED, KnownHostsCatalog, ReplaceKnownHostsRequest, SystemKnownHostsScan,
    known_hosts_error, known_hosts_invalid,
};

fn map_known_hosts_store_error(error: StoreError) -> String {
    match error {
        StoreError::InventoryRevisionConflict { .. } => known_hosts_error(
            KNOWN_HOSTS_INVENTORY_CHANGED,
            "The Known Hosts catalog changed; refresh and retry",
        ),
        StoreError::Serialization | StoreError::DuplicateGraphEntityId(_) => known_hosts_invalid(),
        StoreError::InvalidOwner
        | StoreError::BothSlotsCorrupt
        | StoreError::ConflictingGeneration
        | StoreError::SnapshotDurabilityUnconfirmed
        | StoreError::ManagedSecretRetentionUncertain
        | StoreError::ArtifactConflict => known_hosts_error(
            KNOWN_HOSTS_REPAIR_REQUIRED,
            "Known Hosts storage requires reconciliation",
        ),
        _ => known_hosts_error(
            KNOWN_HOSTS_PUBLICATION_FAILED,
            "The Known Hosts catalog could not be updated",
        ),
    }
}

fn normalize_known_hosts_command_error(error: String) -> String {
    if error.starts_with("KNOWN_HOSTS_") {
        error
    } else {
        known_hosts_error(
            KNOWN_HOSTS_REPAIR_REQUIRED,
            "Known Hosts storage requires reconciliation",
        )
    }
}

async fn run_known_hosts_vault<T, F>(operation: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, StoreError> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| {
            known_hosts_error(
                KNOWN_HOSTS_PUBLICATION_FAILED,
                "The Known Hosts storage worker failed",
            )
        })?
        .map_err(map_known_hosts_store_error)
}

async fn load_known_hosts_catalog_inner(state: &DesktopState) -> Result<KnownHostsCatalog, String> {
    let store = state.saved_hosts.clone();
    run_known_hosts_vault(move || {
        let snapshot = store.confirm_current_snapshot_durability()?;
        Ok(KnownHostsCatalog {
            inventory_revision: snapshot.revision().clone(),
            known_hosts: snapshot.known_hosts().to_vec(),
        })
    })
    .await
}

#[tauri::command]
pub(super) async fn list_known_hosts(
    state: State<'_, DesktopState>,
) -> Result<KnownHostsCatalog, String> {
    run_saved_host_operation(state.inner().clone(), |state| async move {
        load_known_hosts_catalog_inner(&state).await
    })
    .await
    .map_err(normalize_known_hosts_command_error)
}

#[tauri::command]
pub(super) async fn replace_known_hosts(
    state: State<'_, DesktopState>,
    request: ReplaceKnownHostsRequest,
) -> Result<KnownHostsCatalog, String> {
    run_saved_host_operation(state.inner().clone(), move |state| async move {
        let store = state.saved_hosts.clone();
        run_known_hosts_vault(move || {
            let committed = store
                .replace_known_hosts(request.expected_inventory_revision, request.known_hosts)?;
            if committed.durability() == SavedVaultCommitDurability::Durable {
                return Ok(KnownHostsCatalog::from_commit(&committed));
            }
            let confirmed = store.confirm_current_snapshot_durability()?;
            if confirmed.revision() != committed.revision()
                || confirmed.known_hosts() != committed.known_hosts()
            {
                return Err(StoreError::SnapshotDurabilityUnconfirmed);
            }
            Ok(KnownHostsCatalog {
                inventory_revision: confirmed.revision().clone(),
                known_hosts: confirmed.known_hosts().to_vec(),
            })
        })
        .await
    })
    .await
    .map_err(normalize_known_hosts_command_error)
}

#[tauri::command]
pub(super) async fn scan_system_known_hosts() -> Result<SystemKnownHostsScan, String> {
    let now = current_unix_millis().map_err(|_| known_hosts_catalog::known_hosts_scan_failed())?;
    tokio::task::spawn_blocking(move || known_hosts_catalog::scan_system_known_hosts(now))
        .await
        .map_err(|_| known_hosts_catalog::known_hosts_scan_failed())?
}
