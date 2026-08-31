use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use tauri::{
    App, AppHandle, Manager, Window, WindowEvent,
    image::Image,
    menu::{Menu, MenuBuilder},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};
use tauri_plugin_dialog::{
    DialogExt, MessageDialogButtons, MessageDialogKind, MessageDialogResult,
};

use crate::settings_window::{SETTINGS_WINDOW_LABEL, open_settings_window_from_tray};

pub(crate) const MAIN_WINDOW_LABEL: &str = "main";
const TRAY_ICON_ID: &str = "goral-main-tray";
const TRAY_SHOW_ID: &str = "goral-tray-show";
const TRAY_HIDE_ID: &str = "goral-tray-hide";
const TRAY_SETTINGS_ID: &str = "goral-tray-settings";
const TRAY_EXIT_ID: &str = "goral-tray-exit";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum NativeUiLocale {
    EnUs,
    #[default]
    ZhCn,
}

impl NativeUiLocale {
    pub(crate) fn from_locale_tag(locale: &str) -> Self {
        match locale {
            "en-US" => Self::EnUs,
            "system" => locale_for_system_language(system_language().as_deref()),
            _ => Self::ZhCn,
        }
    }

    fn locale_tag(self) -> &'static str {
        match self {
            Self::EnUs => "en-US",
            Self::ZhCn => "zh-CN",
        }
    }

    fn encoded(self) -> u8 {
        match self {
            Self::EnUs => 1,
            Self::ZhCn => 2,
        }
    }

    fn decode(value: u8) -> Self {
        match value {
            1 => Self::EnUs,
            _ => Self::ZhCn,
        }
    }
}

fn locale_for_system_language(system_language: Option<&str>) -> NativeUiLocale {
    if system_language
        .is_some_and(|language| language.trim().to_ascii_lowercase().starts_with("en"))
    {
        NativeUiLocale::EnUs
    } else {
        NativeUiLocale::ZhCn
    }
}

#[cfg(windows)]
fn system_language() -> Option<String> {
    // LOCALE_NAME_MAX_LENGTH is 85 UTF-16 code units. Keeping the bound
    // local avoids enabling the much larger Win32 SystemServices surface for
    // one constant while GetUserDefaultLocaleName remains the authority.
    let mut locale = [0_u16; 85];
    // SAFETY: `locale` is a valid writable buffer for the exact length passed
    // to the Win32 API, and the returned count is checked before slicing.
    let written = unsafe {
        windows_sys::Win32::Globalization::GetUserDefaultLocaleName(
            locale.as_mut_ptr(),
            i32::try_from(locale.len()).ok()?,
        )
    };
    let payload_length = usize::try_from(written).ok()?.checked_sub(1)?;
    String::from_utf16(locale.get(..payload_length)?).ok()
}

#[cfg(not(windows))]
fn system_language() -> Option<String> {
    ["LC_ALL", "LC_MESSAGES", "LANG"]
        .into_iter()
        .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
}

#[derive(Debug)]
pub(crate) struct WindowLifecycleState {
    close_prompt_open: AtomicBool,
    locale: AtomicU8,
}

impl WindowLifecycleState {
    pub(crate) fn new(locale: NativeUiLocale) -> Self {
        Self {
            close_prompt_open: AtomicBool::new(false),
            locale: AtomicU8::new(locale.encoded()),
        }
    }

    fn begin_close_prompt(&self) -> bool {
        self.close_prompt_open
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn finish_close_prompt(&self, choice: ClosePromptChoice) -> Option<ClosePromptEffect> {
        if self
            .close_prompt_open
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return None;
        }
        Some(match choice {
            ClosePromptChoice::Exit => ClosePromptEffect::ExitApplication,
            ClosePromptChoice::MinimizeToTray => ClosePromptEffect::HideWindows,
            ClosePromptChoice::Cancel => ClosePromptEffect::None,
        })
    }

    fn locale(&self) -> NativeUiLocale {
        NativeUiLocale::decode(self.locale.load(Ordering::Acquire))
    }

    fn set_locale(&self, locale: NativeUiLocale) {
        self.locale.store(locale.encoded(), Ordering::Release);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClosePromptChoice {
    Exit,
    MinimizeToTray,
    Cancel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClosePromptEffect {
    ExitApplication,
    HideWindows,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TrayAction {
    Show,
    Hide,
    Settings,
    Exit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TrayCopy {
    show: &'static str,
    hide: &'static str,
    settings: &'static str,
    exit: &'static str,
    tooltip: &'static str,
}

impl TrayCopy {
    fn for_locale(locale: NativeUiLocale) -> Self {
        match locale {
            NativeUiLocale::EnUs => Self {
                show: "Show Main Window",
                hide: "Hide Windows",
                settings: "Settings",
                exit: "Exit Goral",
                tooltip: "Goral",
            },
            NativeUiLocale::ZhCn => Self {
                show: "显示主窗口",
                hide: "隐藏窗口",
                settings: "设置",
                exit: "退出 Goral（斑羚）",
                tooltip: "Goral · 斑羚",
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CloseDialogCopy {
    title: &'static str,
    message: &'static str,
    exit: &'static str,
    minimize: &'static str,
    cancel: &'static str,
}

impl CloseDialogCopy {
    fn for_locale(locale: NativeUiLocale) -> Self {
        match locale {
            NativeUiLocale::EnUs => Self {
                title: "Exit Goral?",
                message: "Choose whether to exit Goral, minimize it to the system tray, or cancel.",
                exit: "Exit Goral",
                minimize: "Minimize to tray",
                cancel: "Cancel",
            },
            NativeUiLocale::ZhCn => Self {
                title: "退出 Goral？",
                message: "请选择退出应用、最小化到系统托盘，或取消本次操作。",
                exit: "退出 Goral",
                minimize: "最小化到托盘",
                cancel: "取消",
            },
        }
    }

    fn choice_for_result(self, result: MessageDialogResult) -> ClosePromptChoice {
        match result {
            MessageDialogResult::Yes | MessageDialogResult::Ok => ClosePromptChoice::Exit,
            MessageDialogResult::No => ClosePromptChoice::MinimizeToTray,
            MessageDialogResult::Custom(label) if label == self.exit => ClosePromptChoice::Exit,
            MessageDialogResult::Custom(label) if label == self.minimize => {
                ClosePromptChoice::MinimizeToTray
            }
            MessageDialogResult::Cancel | MessageDialogResult::Custom(_) => {
                ClosePromptChoice::Cancel
            }
        }
    }
}

pub(crate) fn install_tray(app: &App) -> tauri::Result<()> {
    let locale = app
        .try_state::<WindowLifecycleState>()
        .map(|state| state.locale())
        .unwrap_or_default();
    let copy = TrayCopy::for_locale(locale);
    let menu = build_tray_menu(app.handle(), copy)?;
    let icon = Image::from_bytes(include_bytes!("../icons/icon.png"))?;

    TrayIconBuilder::with_id(TRAY_ICON_ID)
        .menu(&menu)
        .icon(icon)
        .tooltip(copy.tooltip)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| handle_tray_menu_action(app, event.id().as_ref()))
        .on_tray_icon_event(|tray, event| {
            if is_left_release(&event) {
                show_main_window(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

pub(crate) fn refresh_native_locale(app: &AppHandle, locale: NativeUiLocale) {
    if let Some(state) = app.try_state::<WindowLifecycleState>() {
        state.set_locale(locale);
    }

    let Some(tray) = app.tray_by_id(TRAY_ICON_ID) else {
        return;
    };
    let copy = TrayCopy::for_locale(locale);
    if let Ok(menu) = build_tray_menu(app, copy) {
        let _ = tray.set_menu(Some(menu));
        let _ = tray.set_tooltip(Some(copy.tooltip));
    }
}

fn build_tray_menu(app: &AppHandle, copy: TrayCopy) -> tauri::Result<Menu<tauri::Wry>> {
    MenuBuilder::new(app)
        .text(TRAY_SHOW_ID, copy.show)
        .text(TRAY_HIDE_ID, copy.hide)
        .text(TRAY_SETTINGS_ID, copy.settings)
        .separator()
        .text(TRAY_EXIT_ID, copy.exit)
        .build()
}

fn tray_action(menu_id: &str) -> Option<TrayAction> {
    match menu_id {
        TRAY_SHOW_ID => Some(TrayAction::Show),
        TRAY_HIDE_ID => Some(TrayAction::Hide),
        TRAY_SETTINGS_ID => Some(TrayAction::Settings),
        TRAY_EXIT_ID => Some(TrayAction::Exit),
        _ => None,
    }
}

fn handle_tray_menu_action(app: &AppHandle, menu_id: &str) {
    match tray_action(menu_id) {
        Some(TrayAction::Show) => show_main_window(app),
        Some(TrayAction::Hide) => hide_application_windows(app),
        Some(TrayAction::Settings) => {
            let locale = app
                .try_state::<WindowLifecycleState>()
                .map(|state| state.locale())
                .unwrap_or_default();
            let _ = open_settings_window_from_tray(app, locale.locale_tag());
        }
        Some(TrayAction::Exit) => app.exit(0),
        None => {}
    }
}

fn is_left_release(event: &TrayIconEvent) -> bool {
    matches!(
        event,
        TrayIconEvent::Click {
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
        }
    )
}

fn show_main_window(app: &AppHandle) {
    let Some(window) = app.get_webview_window(MAIN_WINDOW_LABEL) else {
        return;
    };
    let _ = window.unminimize();
    let _ = window.show();
    let _ = window.set_focus();
}

fn hide_application_windows(app: &AppHandle) {
    if let Some(settings) = app.get_webview_window(SETTINGS_WINDOW_LABEL) {
        let _ = settings.hide();
    }
    if let Some(main) = app.get_webview_window(MAIN_WINDOW_LABEL) {
        let _ = main.hide();
    }
}

/// Returns true when this module consumed the event and the caller should not
/// apply another close policy to the same native event.
pub(crate) fn handle_window_event(window: &Window, event: &WindowEvent) -> bool {
    let WindowEvent::CloseRequested { api, .. } = event else {
        return false;
    };

    if window.label() == SETTINGS_WINDOW_LABEL {
        api.prevent_close();
        let _ = window.hide();
        return true;
    }

    if window.label() != MAIN_WINDOW_LABEL {
        return false;
    }
    let Some(state) = window.try_state::<WindowLifecycleState>() else {
        return false;
    };

    api.prevent_close();
    if !state.begin_close_prompt() {
        return true;
    }

    show_close_prompt(window, state.locale());
    true
}

fn show_close_prompt(window: &Window, locale: NativeUiLocale) {
    let copy = CloseDialogCopy::for_locale(locale);
    let app = window.app_handle().clone();
    window
        .dialog()
        .message(copy.message)
        .title(copy.title)
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::YesNoCancelCustom(
            copy.exit.to_owned(),
            copy.minimize.to_owned(),
            copy.cancel.to_owned(),
        ))
        .parent(window)
        .show_with_result(move |result| {
            let Some(state) = app.try_state::<WindowLifecycleState>() else {
                return;
            };
            let Some(effect) = state.finish_close_prompt(copy.choice_for_result(result)) else {
                return;
            };
            match effect {
                ClosePromptEffect::ExitApplication => app.exit(0),
                ClosePromptEffect::HideWindows => hide_application_windows(&app),
                ClosePromptEffect::None => {}
            }
        });
}

#[cfg(test)]
mod tests {
    use tauri_plugin_dialog::MessageDialogResult;

    use super::{
        CloseDialogCopy, ClosePromptChoice, ClosePromptEffect, NativeUiLocale, TRAY_EXIT_ID,
        TRAY_HIDE_ID, TRAY_SETTINGS_ID, TRAY_SHOW_ID, TrayAction, TrayCopy, WindowLifecycleState,
        locale_for_system_language, tray_action,
    };

    #[test]
    fn native_locale_uses_chinese_as_the_safe_default() {
        assert_eq!(
            NativeUiLocale::from_locale_tag("en-US"),
            NativeUiLocale::EnUs
        );
        assert_eq!(
            NativeUiLocale::from_locale_tag("zh-CN"),
            NativeUiLocale::ZhCn
        );
        assert_eq!(
            NativeUiLocale::from_locale_tag("unsupported"),
            NativeUiLocale::ZhCn
        );
    }

    #[test]
    fn system_language_matches_the_renderer_english_or_chinese_rule() {
        for english in ["en-US", "en_GB.UTF-8", "EN-au"] {
            assert_eq!(
                locale_for_system_language(Some(english)),
                NativeUiLocale::EnUs
            );
        }
        for chinese in [Some("zh-CN"), Some("ja-JP"), None] {
            assert_eq!(locale_for_system_language(chinese), NativeUiLocale::ZhCn);
        }
    }

    #[test]
    fn tray_copy_is_complete_in_both_supported_locales() {
        let chinese = TrayCopy::for_locale(NativeUiLocale::ZhCn);
        assert_eq!(chinese.show, "显示主窗口");
        assert_eq!(chinese.hide, "隐藏窗口");
        assert_eq!(chinese.settings, "设置");
        assert_eq!(chinese.exit, "退出 Goral（斑羚）");

        let english = TrayCopy::for_locale(NativeUiLocale::EnUs);
        assert_eq!(english.show, "Show Main Window");
        assert_eq!(english.hide, "Hide Windows");
        assert_eq!(english.settings, "Settings");
        assert_eq!(english.exit, "Exit Goral");
    }

    #[test]
    fn tray_ids_resolve_only_to_the_four_real_actions() {
        assert_eq!(tray_action(TRAY_SHOW_ID), Some(TrayAction::Show));
        assert_eq!(tray_action(TRAY_HIDE_ID), Some(TrayAction::Hide));
        assert_eq!(tray_action(TRAY_SETTINGS_ID), Some(TrayAction::Settings));
        assert_eq!(tray_action(TRAY_EXIT_ID), Some(TrayAction::Exit));
        assert_eq!(tray_action("goral-tray-sessions"), None);
        assert_eq!(tray_action("goral-tray-forwarding"), None);
    }

    #[test]
    fn duplicate_close_requests_cannot_open_duplicate_prompts() {
        let lifecycle = WindowLifecycleState::new(NativeUiLocale::ZhCn);
        assert!(lifecycle.begin_close_prompt());
        assert!(!lifecycle.begin_close_prompt());
        assert_eq!(
            lifecycle.finish_close_prompt(ClosePromptChoice::Cancel),
            Some(ClosePromptEffect::None)
        );
        assert!(lifecycle.begin_close_prompt());
    }

    #[test]
    fn each_prompt_result_is_consumed_exactly_once() {
        let lifecycle = WindowLifecycleState::new(NativeUiLocale::EnUs);
        assert!(lifecycle.begin_close_prompt());
        assert_eq!(
            lifecycle.finish_close_prompt(ClosePromptChoice::MinimizeToTray),
            Some(ClosePromptEffect::HideWindows)
        );
        assert_eq!(lifecycle.finish_close_prompt(ClosePromptChoice::Exit), None);

        assert!(lifecycle.begin_close_prompt());
        assert_eq!(
            lifecycle.finish_close_prompt(ClosePromptChoice::Exit),
            Some(ClosePromptEffect::ExitApplication)
        );
    }

    #[test]
    fn custom_close_buttons_map_to_exit_hide_and_cancel() {
        for locale in [NativeUiLocale::ZhCn, NativeUiLocale::EnUs] {
            let copy = CloseDialogCopy::for_locale(locale);
            assert_eq!(
                copy.choice_for_result(MessageDialogResult::Custom(copy.exit.to_owned())),
                ClosePromptChoice::Exit
            );
            assert_eq!(
                copy.choice_for_result(MessageDialogResult::Custom(copy.minimize.to_owned())),
                ClosePromptChoice::MinimizeToTray
            );
            assert_eq!(
                copy.choice_for_result(MessageDialogResult::Custom(copy.cancel.to_owned())),
                ClosePromptChoice::Cancel
            );
        }
    }

    #[test]
    fn locale_refresh_changes_later_dialog_copy_without_resetting_prompt_state() {
        let lifecycle = WindowLifecycleState::new(NativeUiLocale::ZhCn);
        assert!(lifecycle.begin_close_prompt());
        lifecycle.set_locale(NativeUiLocale::EnUs);
        assert_eq!(lifecycle.locale(), NativeUiLocale::EnUs);
        assert!(!lifecycle.begin_close_prompt());
        assert_eq!(
            lifecycle.finish_close_prompt(ClosePromptChoice::Cancel),
            Some(ClosePromptEffect::None)
        );
    }
}
