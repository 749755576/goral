use serde::Serialize;
use tauri::{AppHandle, Emitter, State};

use super::DesktopState;
use crate::settings_catalog::{
    RendererSafeSettingsSnapshot, ReplaceRendererSafeSettingsRequest, list_settings as load,
    replace_settings as commit,
};

pub(crate) const SETTINGS_CHANGED_EVENT: &str = "goral:settings-changed";

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SettingsChangedNotification {
    inventory_revision: crate::settings_catalog::SettingsInventoryRevision,
}

fn settings_changed_notification(
    snapshot: &RendererSafeSettingsSnapshot,
) -> SettingsChangedNotification {
    SettingsChangedNotification {
        inventory_revision: snapshot.inventory_revision.clone(),
    }
}

#[tauri::command]
pub(super) async fn list_settings(
    state: State<'_, DesktopState>,
) -> Result<RendererSafeSettingsSnapshot, String> {
    load(state.settings.clone()).await
}

#[tauri::command]
pub(super) async fn replace_settings(
    app: AppHandle,
    state: State<'_, DesktopState>,
    request: ReplaceRendererSafeSettingsRequest,
) -> Result<RendererSafeSettingsSnapshot, String> {
    let snapshot = commit(state.settings.clone(), request).await?;
    #[cfg(desktop)]
    crate::window_lifecycle::refresh_native_locale(
        &app,
        crate::window_lifecycle::NativeUiLocale::from_locale_tag(snapshot.native_ui_locale()),
    );
    // Publication already succeeded, so a transient renderer-notification
    // failure must not turn the committed CAS operation into a false failure.
    let _ = app.emit(
        SETTINGS_CHANGED_EVENT,
        settings_changed_notification(&snapshot),
    );
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::{SETTINGS_CHANGED_EVENT, settings_changed_notification};
    use crate::settings_catalog::RendererSafeSettingsStore;

    #[test]
    fn notification_is_fixed_and_contains_only_the_renderer_safe_revision() {
        let directory = tempfile::tempdir().expect("temporary settings directory");
        let store = RendererSafeSettingsStore::open(directory.path()).expect("settings store");
        let snapshot = store.load().expect("settings snapshot");
        let payload = serde_json::to_value(settings_changed_notification(&snapshot))
            .expect("settings notification JSON");

        assert_eq!(SETTINGS_CHANGED_EVENT, "goral:settings-changed");
        assert_eq!(
            payload
                .as_object()
                .expect("notification object")
                .keys()
                .collect::<Vec<_>>(),
            vec!["inventoryRevision"]
        );
        let revision = payload["inventoryRevision"]
            .as_object()
            .expect("revision object");
        assert_eq!(revision.len(), 2);
        assert!(revision["generation"].is_u64());
        assert_eq!(revision["checksum"].as_str().map(str::len), Some(64));
        let encoded = payload.to_string().to_ascii_lowercase();
        for forbidden in ["settings", "apikey", "password", "privatekey", "secret"] {
            assert!(!encoded.contains(forbidden));
        }
    }
}
