use tauri::{
    AppHandle, Manager, PhysicalPosition, State, WebviewUrl, WebviewWindow, WebviewWindowBuilder,
};

use crate::app_data_compat::CompatibleWebviewDataRoot;

pub(crate) const SETTINGS_WINDOW_LABEL: &str = "settings";
const AI_PROVIDER_SETTINGS_TARGET: &str = "ai-providers";
const SETTINGS_WINDOW_WIDTH: f64 = 980.0;
const SETTINGS_WINDOW_HEIGHT: f64 = 720.0;
const SETTINGS_WINDOW_MIN_WIDTH: f64 = 820.0;
const SETTINGS_WINDOW_MIN_HEIGHT: f64 = 600.0;

#[tauri::command]
pub(crate) async fn open_settings_window(
    app: AppHandle,
    window: WebviewWindow,
    webview_data: State<'_, CompatibleWebviewDataRoot>,
    locale: String,
    target: Option<String>,
) -> Result<(), String> {
    let target = validate_settings_window_target(target.as_deref())?;
    let task_app = app.clone();
    let webview_data = webview_data.path().to_owned();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    app.run_on_main_thread(move || {
        let result =
            open_settings_window_on_main_thread(task_app, window, &webview_data, &locale, target);
        let _ = sender.send(result);
    })
    .map_err(|_| settings_window_error())?;
    receiver.await.map_err(|_| settings_window_error())?
}

pub(crate) fn open_settings_window_from_tray(app: &AppHandle, locale: &str) -> Result<(), String> {
    let window = app
        .get_webview_window("main")
        .ok_or_else(settings_window_error)?;
    let webview_data = app
        .try_state::<CompatibleWebviewDataRoot>()
        .map(|root| root.path().to_owned())
        .ok_or_else(settings_window_error)?;
    let task_app = app.clone();
    let locale = locale.to_owned();
    app.run_on_main_thread(move || {
        let _ = open_settings_window_on_main_thread(task_app, window, &webview_data, &locale, None);
    })
    .map_err(|_| settings_window_error())
}

fn open_settings_window_on_main_thread(
    app: AppHandle,
    window: WebviewWindow,
    webview_data: &std::path::Path,
    locale: &str,
    target: Option<&'static str>,
) -> Result<(), String> {
    if let Some(settings) = app.get_webview_window(SETTINGS_WINDOW_LABEL) {
        settings
            .set_title(settings_window_title(locale))
            .map_err(|_| settings_window_error())?;
        settings.unminimize().map_err(|_| settings_window_error())?;
        settings.show().map_err(|_| settings_window_error())?;
        if let Some(script) = settings_window_focus_script(target) {
            settings.eval(script).map_err(|_| settings_window_error())?;
        }
        settings.set_focus().map_err(|_| settings_window_error())?;
        return Ok(());
    }

    let initialization_script = settings_window_initialization_script(target);
    let mut builder = WebviewWindowBuilder::new(
        &app,
        SETTINGS_WINDOW_LABEL,
        WebviewUrl::App("index.html".into()),
    )
    .initialization_script(initialization_script)
    .title(settings_window_title(locale))
    .inner_size(SETTINGS_WINDOW_WIDTH, SETTINGS_WINDOW_HEIGHT)
    .min_inner_size(SETTINGS_WINDOW_MIN_WIDTH, SETTINGS_WINDOW_MIN_HEIGHT)
    .resizable(true)
    .visible(true);

    #[cfg(any(target_os = "windows", target_os = "linux"))]
    {
        builder = builder.data_directory(webview_data.to_owned());
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let _ = webview_data;

    #[cfg(target_os = "macos")]
    {
        builder = builder
            .decorations(true)
            .title_bar_style(tauri::TitleBarStyle::Overlay)
            .hidden_title(true);
    }
    #[cfg(not(target_os = "macos"))]
    {
        builder = builder.decorations(false);
    }

    let settings = builder.build().map_err(|_| settings_window_error())?;
    center_on_source_monitor(&window, &settings);
    // The new window is already visible and focused by the builder. Return to
    // the Windows event loop so WebView2 can finish creating its render child;
    // forcing another focus operation here can leave the controller pending.
    Ok(())
}

fn validate_settings_window_target(target: Option<&str>) -> Result<Option<&'static str>, String> {
    match target {
        None => Ok(None),
        Some(AI_PROVIDER_SETTINGS_TARGET) => Ok(Some(AI_PROVIDER_SETTINGS_TARGET)),
        Some(_) => Err("SETTINGS_WINDOW_TARGET_INVALID".to_owned()),
    }
}

fn settings_window_initialization_script(target: Option<&str>) -> String {
    let target_literal = if target == Some(AI_PROVIDER_SETTINGS_TARGET) {
        r#""ai-providers""#
    } else {
        "null"
    };
    format!(
        "globalThis.__GORAL_SETTINGS_WINDOW__ = true; globalThis.__GORAL_SETTINGS_TARGET__ = {target_literal};"
    )
}

fn settings_window_focus_script(target: Option<&str>) -> Option<&'static str> {
    if target != Some(AI_PROVIDER_SETTINGS_TARGET) {
        return None;
    }
    Some(
        r#"globalThis.__GORAL_SETTINGS_TARGET__ = "ai-providers"; globalThis.dispatchEvent(new CustomEvent("goral:settings-focus", { detail: "ai-providers" }));"#,
    )
}

#[tauri::command]
pub(crate) fn hide_settings_window(window: WebviewWindow) -> Result<(), String> {
    if window.label() != SETTINGS_WINDOW_LABEL {
        return Err(settings_window_error());
    }
    window.hide().map_err(|_| settings_window_error())
}

fn center_on_source_monitor(source: &WebviewWindow, target: &WebviewWindow) {
    let Ok(Some(monitor)) = source.current_monitor() else {
        let _ = target.center();
        return;
    };
    let Ok(target_size) = target.outer_size() else {
        let _ = target.center();
        return;
    };
    let origin = monitor.position();
    let size = monitor.size();
    let x = centered_axis(origin.x, size.width, target_size.width);
    let y = centered_axis(origin.y, size.height, target_size.height);
    let _ = target.set_position(PhysicalPosition::new(x, y));
}

fn centered_axis(origin: i32, available: u32, requested: u32) -> i32 {
    let available = i64::from(available);
    let requested = i64::from(requested.min(available as u32));
    let centered = i64::from(origin) + (available - requested) / 2;
    centered.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

fn settings_window_error() -> String {
    "SETTINGS_WINDOW_UNAVAILABLE: The Settings window could not be opened".to_owned()
}

fn settings_window_title(locale: &str) -> &'static str {
    if locale == "en-US" {
        "Goral Settings"
    } else {
        "Goral 设置 · 斑羚"
    }
}

#[cfg(test)]
mod tests {
    use super::{
        centered_axis, settings_window_initialization_script, settings_window_title,
        validate_settings_window_target,
    };

    #[test]
    fn centers_inside_the_source_monitor_in_physical_pixels() {
        assert_eq!(centered_axis(1_920, 2_560, 980), 2_710);
        assert_eq!(centered_axis(-1_920, 1_920, 980), -1_450);
    }

    #[test]
    fn oversized_windows_anchor_to_the_monitor_origin() {
        assert_eq!(centered_axis(-1_280, 1_280, 1_800), -1_280);
    }

    #[test]
    fn localizes_the_native_window_title_with_chinese_fallback() {
        assert_eq!(settings_window_title("en-US"), "Goral Settings");
        assert_eq!(settings_window_title("zh-CN"), "Goral 设置 · 斑羚");
        assert_eq!(settings_window_title("unsupported"), "Goral 设置 · 斑羚");
    }

    #[test]
    fn accepts_only_the_registered_settings_focus_target() {
        assert_eq!(validate_settings_window_target(None).unwrap(), None);
        assert_eq!(
            validate_settings_window_target(Some("ai-providers")).unwrap(),
            Some("ai-providers")
        );
        assert_eq!(
            validate_settings_window_target(Some("ai-agents")).unwrap_err(),
            "SETTINGS_WINDOW_TARGET_INVALID"
        );
    }

    #[test]
    fn seeds_new_settings_windows_with_the_requested_target() {
        let targeted = settings_window_initialization_script(Some("ai-providers"));
        assert!(targeted.contains("__GORAL_SETTINGS_WINDOW__ = true"));
        assert!(targeted.contains("__GORAL_SETTINGS_TARGET__ = \"ai-providers\""));

        let untargeted = settings_window_initialization_script(None);
        assert!(untargeted.contains("__GORAL_SETTINGS_TARGET__ = null"));
    }
}
