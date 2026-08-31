use std::collections::HashSet;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const SETTINGS_INVALID: &str = "SETTINGS_INVALID";
pub(crate) const SETTINGS_INVENTORY_CHANGED: &str = "SETTINGS_INVENTORY_CHANGED";
pub(crate) const SETTINGS_PUBLICATION_FAILED: &str = "SETTINGS_PUBLICATION_FAILED";
pub(crate) const SETTINGS_REPAIR_REQUIRED: &str = "SETTINGS_REPAIR_REQUIRED";

const SETTINGS_SCHEMA_VERSION: u8 = 4;
const PRE_AI_RESPONSE_TIMEOUT_SETTINGS_SCHEMA_VERSION: u8 = 3;
const SINGLE_AI_SETTINGS_SCHEMA_VERSION: u8 = 2;
const LEGACY_SETTINGS_SCHEMA_VERSION: u8 = 1;
const SNAPSHOT_FORMAT_VERSION: u8 = 1;
const MAX_SETTINGS_SNAPSHOT_BYTES: u64 = 256 * 1_024;
const SETTINGS_SLOT_A: &str = "renderer-settings-a.json";
const SETTINGS_SLOT_B: &str = "renderer-settings-b.json";
const SETTINGS_LOCK_FILE: &str = "renderer-settings.lock";
const MAX_LOCAL_SHELL_COMMAND_BYTES: usize = 32 * 1_024;
const MAX_LOCAL_SHELL_ARGUMENTS: usize = 32;
const MAX_LOCAL_SHELL_ARGUMENT_BYTES: usize = 4 * 1_024;
const MAX_LOCAL_START_DIRECTORY_BYTES: usize = 32 * 1_024;
const MAX_AI_PROVIDER_PROFILES: usize = 32;
const MAX_AI_PROFILE_NAME_BYTES: usize = 256;
const MAX_AI_PROVIDER_ID_BYTES: usize = 128;
const MAX_AI_BASE_URL_BYTES: usize = 2_048;
const MAX_AI_MODEL_BYTES: usize = 256;
pub(crate) const DEFAULT_AI_RESPONSE_IDLE_TIMEOUT_SECONDS: u32 = 120;
pub(crate) const MIN_AI_RESPONSE_IDLE_TIMEOUT_SECONDS: u32 = 1;
pub(crate) const MAX_AI_RESPONSE_IDLE_TIMEOUT_SECONDS: u32 = 86_400;
const LEGACY_DEEPSEEK_CONSOLE_BASE_URL: &str = "https://platform.deepseek.com/v1";
const DEEPSEEK_API_BASE_URL: &str = "https://api.deepseek.com/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum SettingsPlatform {
    #[serde(rename = "mac")]
    Mac,
    #[serde(rename = "windows")]
    Windows,
    #[serde(rename = "linux")]
    Linux,
    #[serde(rename = "other")]
    Other,
}

impl SettingsPlatform {
    pub(crate) const fn current() -> Self {
        #[cfg(target_os = "macos")]
        {
            return Self::Mac;
        }
        #[cfg(target_os = "windows")]
        {
            return Self::Windows;
        }
        #[cfg(target_os = "linux")]
        {
            return Self::Linux;
        }
        #[allow(unreachable_code)]
        Self::Other
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum UiLanguage {
    #[serde(rename = "system")]
    System,
    #[serde(rename = "en-US")]
    EnUs,
    #[serde(rename = "zh-CN")]
    ZhCn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ColorMode {
    Light,
    Dark,
    System,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum AccentMode {
    Theme,
    Custom,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum HostClickBehavior {
    Connect,
    Select,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum FontSmoothing {
    Auto,
    Antialiased,
    Subpixel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum TerminalEmulationType {
    #[serde(rename = "xterm-256color")]
    Xterm256Color,
    #[serde(rename = "xterm")]
    Xterm,
    #[serde(rename = "vt100")]
    Vt100,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum CursorStyle {
    Block,
    Underline,
    Bar,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TerminalRenderer {
    Auto,
    Webgl,
    Canvas,
    Dom,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum WorkspaceFocusStyle {
    Border,
    Glow,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PasswordPromptAssist {
    Off,
    Hint,
    Auto,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ShortcutScheme {
    Disabled,
    Mac,
    Pc,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SftpDoubleClickBehavior {
    Open,
    Transfer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SftpViewMode {
    List,
    Tree,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SftpDefaultOpener {
    System,
    Editor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum NetworkProxyMode {
    System,
    None,
    Manual,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum StartupLanding {
    Vault,
    Terminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum AiCommandPermissionMode {
    #[serde(alias = "deny")]
    Observer,
    #[serde(alias = "ask")]
    Confirm,
    Auto,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RendererSafeSettings {
    schema_version: u8,
    appearance: AppearanceSettings,
    terminal: TerminalSettings,
    shortcuts: ShortcutSettings,
    sftp: SftpSettings,
    ai: AiSettings,
    system: SystemSettings,
}

impl fmt::Debug for RendererSafeSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RendererSafeSettings")
            .field("schema_version", &self.schema_version)
            .field("custom_css_bytes", &self.appearance.custom_css.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LocalTerminalSettings {
    pub(crate) shell: String,
    pub(crate) shell_args: Vec<String>,
    pub(crate) start_directory: String,
}

impl fmt::Debug for LocalTerminalSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalTerminalSettings")
            .field("shell_configured", &!self.shell.is_empty())
            .field("argument_count", &self.shell_args.len())
            .field(
                "start_directory_configured",
                &!self.start_directory.is_empty(),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AppearanceSettings {
    ui_language: UiLanguage,
    ui_font_family_id: String,
    window_opacity: f64,
    color_mode: ColorMode,
    light_ui_theme_id: String,
    dark_ui_theme_id: String,
    accent_mode: AccentMode,
    custom_accent: String,
    app_icon_variant: String,
    show_recent_hosts: bool,
    host_click_behavior: HostClickBehavior,
    show_only_ungrouped_hosts_in_root: bool,
    show_sftp_tab: bool,
    show_host_tree_sidebar: bool,
    auto_import_system_known_hosts: bool,
    custom_css: String,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalSettings {
    follow_app_theme: bool,
    theme_id: String,
    font_family_id: String,
    fallback_font: String,
    font_size: f64,
    font_weight: f64,
    bold_font_weight: f64,
    font_smoothing: FontSmoothing,
    line_padding: f64,
    emulation_type: TerminalEmulationType,
    cursor_style: CursorStyle,
    cursor_blink: bool,
    highlight_cursor_line: bool,
    alt_as_meta: bool,
    option_arrow_word_jump: bool,
    kitty_keyboard_protocol: bool,
    minimum_contrast_ratio: f64,
    copy_on_select: bool,
    bracketed_paste: bool,
    scrollback_rows: u32,
    auto_close_on_exit: bool,
    dynamic_tab_title: bool,
    local_shell: String,
    local_shell_args: Vec<String>,
    local_start_dir: String,
    verify_host_keys: bool,
    ssh_auto_reconnect: bool,
    keepalive_interval_seconds: u32,
    renderer: TerminalRenderer,
    inline_images_enabled: bool,
    workspace_focus_style: WorkspaceFocusStyle,
    autocomplete_enabled: bool,
    password_prompt_assist: PasswordPromptAssist,
}

// Renderer settings snapshots created before Local PTY persistence did not
// contain the three local-shell fields. Keep this exact historical shape only
// for checksum-authenticated one-time reads; all renderer responses and new
// writes use `TerminalSettings` above.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyTerminalSettings {
    follow_app_theme: bool,
    theme_id: String,
    font_family_id: String,
    fallback_font: String,
    font_size: f64,
    font_weight: f64,
    bold_font_weight: f64,
    font_smoothing: FontSmoothing,
    line_padding: f64,
    emulation_type: TerminalEmulationType,
    cursor_style: CursorStyle,
    cursor_blink: bool,
    highlight_cursor_line: bool,
    alt_as_meta: bool,
    option_arrow_word_jump: bool,
    kitty_keyboard_protocol: bool,
    minimum_contrast_ratio: f64,
    copy_on_select: bool,
    bracketed_paste: bool,
    scrollback_rows: u32,
    auto_close_on_exit: bool,
    dynamic_tab_title: bool,
    verify_host_keys: bool,
    ssh_auto_reconnect: bool,
    keepalive_interval_seconds: u32,
    renderer: TerminalRenderer,
    inline_images_enabled: bool,
    workspace_focus_style: WorkspaceFocusStyle,
    autocomplete_enabled: bool,
    password_prompt_assist: PasswordPromptAssist,
}

impl From<LegacyTerminalSettings> for TerminalSettings {
    fn from(legacy: LegacyTerminalSettings) -> Self {
        Self {
            follow_app_theme: legacy.follow_app_theme,
            theme_id: legacy.theme_id,
            font_family_id: legacy.font_family_id,
            fallback_font: legacy.fallback_font,
            font_size: legacy.font_size,
            font_weight: legacy.font_weight,
            bold_font_weight: legacy.bold_font_weight,
            font_smoothing: legacy.font_smoothing,
            line_padding: legacy.line_padding,
            emulation_type: legacy.emulation_type,
            cursor_style: legacy.cursor_style,
            cursor_blink: legacy.cursor_blink,
            highlight_cursor_line: legacy.highlight_cursor_line,
            alt_as_meta: legacy.alt_as_meta,
            option_arrow_word_jump: legacy.option_arrow_word_jump,
            kitty_keyboard_protocol: legacy.kitty_keyboard_protocol,
            minimum_contrast_ratio: legacy.minimum_contrast_ratio,
            copy_on_select: legacy.copy_on_select,
            bracketed_paste: legacy.bracketed_paste,
            scrollback_rows: legacy.scrollback_rows,
            auto_close_on_exit: legacy.auto_close_on_exit,
            dynamic_tab_title: legacy.dynamic_tab_title,
            local_shell: String::new(),
            local_shell_args: Vec::new(),
            local_start_dir: String::new(),
            verify_host_keys: legacy.verify_host_keys,
            ssh_auto_reconnect: legacy.ssh_auto_reconnect,
            keepalive_interval_seconds: legacy.keepalive_interval_seconds,
            renderer: legacy.renderer,
            inline_images_enabled: legacy.inline_images_enabled,
            workspace_focus_style: legacy.workspace_focus_style,
            autocomplete_enabled: legacy.autocomplete_enabled,
            password_prompt_assist: legacy.password_prompt_assist,
        }
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ShortcutSettings {
    scheme: ShortcutScheme,
    disable_terminal_font_zoom: bool,
    shell_only_tab_number_shortcuts: bool,
    show_tab_number_badges: bool,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SftpSettings {
    double_click_behavior: SftpDoubleClickBehavior,
    default_view_mode: SftpViewMode,
    show_hidden_files: bool,
    auto_sync: bool,
    follow_terminal_cwd: bool,
    auto_open_sidebar: bool,
    transfer_concurrency: u8,
    default_opener: SftpDefaultOpener,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum AiProviderProtocol {
    OpenAiChatCompletions,
    AnthropicMessages,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AiProviderProfile {
    pub(crate) id: String,
    pub(crate) provider_id: String,
    pub(crate) name: String,
    pub(crate) protocol: AiProviderProtocol,
    pub(crate) base_url: String,
    pub(crate) model: String,
    pub(crate) enabled: bool,
}

impl AiProviderProfile {
    fn default_openai_compatible() -> Self {
        Self {
            // Keeping the migrated/default profile ID equal to the historical
            // provider namespace preserves the endpoint-bound OS credential
            // locator without ever reading or migrating provider-only keys.
            id: "openai-compatible".to_owned(),
            provider_id: "openai-compatible".to_owned(),
            name: "OpenAI".to_owned(),
            protocol: AiProviderProtocol::OpenAiChatCompletions,
            base_url: "https://api.openai.com/v1".to_owned(),
            model: "gpt-4o-mini".to_owned(),
            enabled: true,
        }
    }

    fn from_single_provider(settings: V2AiSettings) -> Self {
        let name = migrated_provider_name(&settings.provider_id);
        let mut profile = Self {
            id: settings.provider_id.clone(),
            provider_id: settings.provider_id,
            name,
            protocol: AiProviderProtocol::OpenAiChatCompletions,
            base_url: settings.base_url,
            model: settings.model,
            enabled: true,
        };
        profile.repair_known_legacy_endpoint();
        profile
    }

    fn repair_known_legacy_endpoint(&mut self) -> bool {
        if self.protocol != AiProviderProtocol::OpenAiChatCompletions
            || self.provider_id != "deepseek"
        {
            return false;
        }
        let Ok(endpoint) = netcatty_ai::normalize_endpoint(&self.base_url) else {
            return false;
        };
        let Ok(legacy) = netcatty_ai::normalize_endpoint(LEGACY_DEEPSEEK_CONSOLE_BASE_URL) else {
            return false;
        };
        if endpoint != legacy {
            return false;
        }
        self.base_url = DEEPSEEK_API_BASE_URL.to_owned();
        true
    }

    fn validate(&self) -> bool {
        valid_ai_provider_id(&self.id)
            && valid_ai_provider_id(&self.provider_id)
            && bounded_native_text(&self.name, MAX_AI_PROFILE_NAME_BYTES, false)
            && bounded_native_text(&self.base_url, MAX_AI_BASE_URL_BYTES, false)
            && bounded_native_text(&self.model, MAX_AI_MODEL_BYTES, false)
    }
}

fn migrated_provider_name(provider_id: &str) -> String {
    match provider_id {
        "openai-compatible" => "OpenAI",
        "deepseek" => "DeepSeek",
        "qwen" => "Qwen",
        "moonshot" => "Moonshot",
        "siliconflow" => "SiliconFlow",
        "ollama" => "Ollama",
        "lm-studio" => "LM Studio",
        _ => provider_id,
    }
    .to_owned()
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AiSettings {
    providers: Vec<AiProviderProfile>,
    active_provider_id: String,
    command_permission_mode: AiCommandPermissionMode,
    response_idle_timeout_seconds: u32,
}

impl AiSettings {
    fn default_openai_compatible() -> Self {
        let profile = AiProviderProfile::default_openai_compatible();
        Self {
            active_provider_id: profile.id.clone(),
            providers: vec![profile],
            command_permission_mode: AiCommandPermissionMode::Confirm,
            response_idle_timeout_seconds: DEFAULT_AI_RESPONSE_IDLE_TIMEOUT_SECONDS,
        }
    }

    fn from_single_provider(settings: V2AiSettings) -> Self {
        let command_permission_mode = settings.command_permission_mode;
        let profile = AiProviderProfile::from_single_provider(settings);
        Self {
            active_provider_id: profile.id.clone(),
            providers: vec![profile],
            command_permission_mode,
            response_idle_timeout_seconds: DEFAULT_AI_RESPONSE_IDLE_TIMEOUT_SECONDS,
        }
    }

    fn validate(&self) -> bool {
        if self.providers.is_empty()
            || self.providers.len() > MAX_AI_PROVIDER_PROFILES
            || !valid_ai_provider_id(&self.active_provider_id)
        {
            return false;
        }
        let mut ids = HashSet::with_capacity(self.providers.len());
        let mut active_enabled = false;
        for profile in &self.providers {
            if !profile.validate() || !ids.insert(profile.id.as_str()) {
                return false;
            }
            if profile.id == self.active_provider_id {
                active_enabled = profile.enabled;
            }
        }
        active_enabled
            && (MIN_AI_RESPONSE_IDLE_TIMEOUT_SECONDS..=MAX_AI_RESPONSE_IDLE_TIMEOUT_SECONDS)
                .contains(&self.response_idle_timeout_seconds)
    }

    fn profile(&self, profile_id: &str) -> Option<&AiProviderProfile> {
        self.providers
            .iter()
            .find(|profile| profile.id == profile_id)
    }

    fn repair_known_legacy_endpoints(&mut self) -> bool {
        self.providers.iter_mut().fold(false, |repaired, profile| {
            profile.repair_known_legacy_endpoint() || repaired
        })
    }
}

// Settings v3 predates the configurable provider response-idle timeout. Keep
// its exact shape so checksum-authenticated snapshots can be upgraded without
// silently accepting a renderer-supplied default into the old checksum.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V3AiSettings {
    providers: Vec<AiProviderProfile>,
    active_provider_id: String,
    command_permission_mode: AiCommandPermissionMode,
}

impl V3AiSettings {
    fn into_current(self) -> AiSettings {
        AiSettings {
            providers: self.providers,
            active_provider_id: self.active_provider_id,
            command_permission_mode: self.command_permission_mode,
            response_idle_timeout_seconds: DEFAULT_AI_RESPONSE_IDLE_TIMEOUT_SECONDS,
        }
    }
}

// Settings v2 stored exactly one provider. This type is retained only for an
// authenticated one-time migration into the v3 provider catalog.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V2AiSettings {
    provider_id: String,
    base_url: String,
    model: String,
    command_permission_mode: AiCommandPermissionMode,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SystemSettings {
    auto_update_enabled: bool,
    network_proxy_mode: NetworkProxyMode,
    startup_landing: StartupLanding,
    restore_previous_session: bool,
    restore_terminal_cwd: bool,
    session_logs_enabled: bool,
    ssh_deep_link_enabled: bool,
    jms_deep_link_enabled: bool,
    explorer_context_menu_enabled: bool,
    ssh_debug_logs_enabled: bool,
    global_hotkey_enabled: bool,
    toggle_window_hotkey: String,
    close_to_tray: bool,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V2RendererSafeSettings {
    schema_version: u8,
    appearance: AppearanceSettings,
    terminal: TerminalSettings,
    shortcuts: ShortcutSettings,
    sftp: SftpSettings,
    ai: V2AiSettings,
    system: SystemSettings,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V3RendererSafeSettings {
    schema_version: u8,
    appearance: AppearanceSettings,
    terminal: TerminalSettings,
    shortcuts: ShortcutSettings,
    sftp: SftpSettings,
    ai: V3AiSettings,
    system: SystemSettings,
}

impl V3RendererSafeSettings {
    fn into_current(self) -> RendererSafeSettings {
        let mut settings = RendererSafeSettings {
            schema_version: SETTINGS_SCHEMA_VERSION,
            appearance: self.appearance,
            terminal: self.terminal,
            shortcuts: self.shortcuts,
            sftp: self.sftp,
            ai: self.ai.into_current(),
            system: self.system,
        };
        settings.repair_known_legacy_values();
        settings
    }
}

impl V2RendererSafeSettings {
    fn into_current(self) -> RendererSafeSettings {
        let mut settings = RendererSafeSettings {
            schema_version: SETTINGS_SCHEMA_VERSION,
            appearance: self.appearance,
            terminal: self.terminal,
            shortcuts: self.shortcuts,
            sftp: self.sftp,
            ai: AiSettings::from_single_provider(self.ai),
            system: self.system,
        };
        settings.repair_known_legacy_values();
        settings
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyRendererSafeSettings {
    schema_version: u8,
    appearance: AppearanceSettings,
    terminal: TerminalSettings,
    shortcuts: ShortcutSettings,
    sftp: SftpSettings,
    system: SystemSettings,
}

impl LegacyRendererSafeSettings {
    fn into_current(self) -> RendererSafeSettings {
        let mut settings = RendererSafeSettings {
            schema_version: SETTINGS_SCHEMA_VERSION,
            appearance: self.appearance,
            terminal: self.terminal,
            shortcuts: self.shortcuts,
            sftp: self.sftp,
            ai: AiSettings::default_openai_compatible(),
            system: self.system,
        };
        settings.repair_known_legacy_values();
        settings
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreLocalPtyRendererSafeSettings {
    schema_version: u8,
    appearance: AppearanceSettings,
    terminal: LegacyTerminalSettings,
    shortcuts: ShortcutSettings,
    sftp: SftpSettings,
    system: SystemSettings,
}

impl PreLocalPtyRendererSafeSettings {
    fn into_current(self) -> RendererSafeSettings {
        LegacyRendererSafeSettings {
            schema_version: self.schema_version,
            appearance: self.appearance,
            terminal: self.terminal.into(),
            shortcuts: self.shortcuts,
            sftp: self.sftp,
            system: self.system,
        }
        .into_current()
    }
}

impl RendererSafeSettings {
    fn repair_known_legacy_values(&mut self) -> bool {
        let repaired_font = if self.appearance.ui_font_family_id == "mona-sans" {
            self.appearance.ui_font_family_id = "inter".to_owned();
            true
        } else {
            false
        };
        self.ai.repair_known_legacy_endpoints() || repaired_font
    }

    pub(crate) fn local_terminal_settings(&self) -> LocalTerminalSettings {
        LocalTerminalSettings {
            shell: self.terminal.local_shell.clone(),
            shell_args: self.terminal.local_shell_args.clone(),
            start_directory: self.terminal.local_start_dir.clone(),
        }
    }

    pub(crate) fn platform_default(platform: SettingsPlatform) -> Self {
        let is_mac = platform == SettingsPlatform::Mac;
        Self {
            schema_version: SETTINGS_SCHEMA_VERSION,
            appearance: AppearanceSettings {
                ui_language: UiLanguage::ZhCn,
                ui_font_family_id: "inter".to_owned(),
                window_opacity: 1.0,
                color_mode: ColorMode::System,
                light_ui_theme_id: "snow".to_owned(),
                dark_ui_theme_id: "midnight".to_owned(),
                accent_mode: AccentMode::Theme,
                custom_accent: "221.2 83.2% 53.3%".to_owned(),
                app_icon_variant: "default".to_owned(),
                show_recent_hosts: true,
                host_click_behavior: HostClickBehavior::Connect,
                show_only_ungrouped_hosts_in_root: false,
                show_sftp_tab: true,
                show_host_tree_sidebar: true,
                auto_import_system_known_hosts: false,
                custom_css: String::new(),
            },
            terminal: TerminalSettings {
                follow_app_theme: true,
                theme_id: "netcatty-dark".to_owned(),
                font_family_id: "menlo".to_owned(),
                fallback_font: String::new(),
                font_size: 14.0,
                font_weight: 400.0,
                bold_font_weight: 700.0,
                font_smoothing: FontSmoothing::Auto,
                line_padding: 0.0,
                emulation_type: TerminalEmulationType::Xterm256Color,
                cursor_style: CursorStyle::Block,
                cursor_blink: true,
                highlight_cursor_line: false,
                alt_as_meta: is_mac,
                option_arrow_word_jump: is_mac,
                kitty_keyboard_protocol: false,
                minimum_contrast_ratio: 1.0,
                copy_on_select: false,
                bracketed_paste: true,
                scrollback_rows: 10_000,
                auto_close_on_exit: false,
                dynamic_tab_title: true,
                local_shell: String::new(),
                local_shell_args: Vec::new(),
                local_start_dir: String::new(),
                verify_host_keys: true,
                ssh_auto_reconnect: false,
                keepalive_interval_seconds: 30,
                renderer: TerminalRenderer::Auto,
                inline_images_enabled: true,
                workspace_focus_style: WorkspaceFocusStyle::Border,
                autocomplete_enabled: true,
                password_prompt_assist: PasswordPromptAssist::Hint,
            },
            shortcuts: ShortcutSettings {
                scheme: if is_mac {
                    ShortcutScheme::Mac
                } else {
                    ShortcutScheme::Pc
                },
                disable_terminal_font_zoom: false,
                shell_only_tab_number_shortcuts: false,
                show_tab_number_badges: true,
            },
            sftp: SftpSettings {
                double_click_behavior: SftpDoubleClickBehavior::Open,
                default_view_mode: SftpViewMode::List,
                show_hidden_files: false,
                auto_sync: false,
                follow_terminal_cwd: false,
                auto_open_sidebar: false,
                transfer_concurrency: 2,
                default_opener: SftpDefaultOpener::System,
            },
            ai: AiSettings::default_openai_compatible(),
            system: SystemSettings {
                auto_update_enabled: true,
                network_proxy_mode: NetworkProxyMode::System,
                startup_landing: StartupLanding::Vault,
                restore_previous_session: true,
                restore_terminal_cwd: true,
                session_logs_enabled: false,
                ssh_deep_link_enabled: true,
                jms_deep_link_enabled: false,
                explorer_context_menu_enabled: platform == SettingsPlatform::Windows,
                ssh_debug_logs_enabled: false,
                global_hotkey_enabled: true,
                toggle_window_hotkey: if is_mac {
                    "\u{2318} + `".to_owned()
                } else {
                    "Ctrl + `".to_owned()
                },
                close_to_tray: true,
            },
        }
    }

    pub(crate) fn validate(&self) -> Result<(), SettingsValidationError> {
        if self.schema_version != SETTINGS_SCHEMA_VERSION
            || !bounded_text(&self.appearance.ui_font_family_id, 80)
            || !finite_range(self.appearance.window_opacity, 0.5, 1.0)
            || !bounded_text(&self.appearance.light_ui_theme_id, 80)
            || !bounded_text(&self.appearance.dark_ui_theme_id, 80)
            || !bounded_text(&self.appearance.custom_accent, 80)
            || !bounded_text(&self.appearance.app_icon_variant, 80)
            || !bounded_text(&self.appearance.custom_css, 64 * 1_024)
            || !bounded_text(&self.terminal.theme_id, 80)
            || !bounded_text(&self.terminal.font_family_id, 120)
            || !bounded_text(&self.terminal.fallback_font, 120)
            || !finite_range(self.terminal.font_size, 6.0, 72.0)
            || !finite_range(self.terminal.font_weight, 100.0, 900.0)
            || !finite_range(self.terminal.bold_font_weight, 100.0, 900.0)
            || !finite_range(self.terminal.line_padding, 0.0, 12.0)
            || !finite_range(self.terminal.minimum_contrast_ratio, 1.0, 21.0)
            || !(100..=1_000_000).contains(&self.terminal.scrollback_rows)
            || !bounded_native_text(
                &self.terminal.local_shell,
                MAX_LOCAL_SHELL_COMMAND_BYTES,
                true,
            )
            || self.terminal.local_shell_args.len() > MAX_LOCAL_SHELL_ARGUMENTS
            || !self
                .terminal
                .local_shell_args
                .iter()
                .all(|argument| bounded_native_text(argument, MAX_LOCAL_SHELL_ARGUMENT_BYTES, true))
            || !bounded_native_text(
                &self.terminal.local_start_dir,
                MAX_LOCAL_START_DIRECTORY_BYTES,
                true,
            )
            || self.terminal.keepalive_interval_seconds > 3_600
            || !(1..=16).contains(&self.sftp.transfer_concurrency)
            || !self.ai.validate()
            || !bounded_text(&self.system.toggle_window_hotkey, 80)
        {
            return Err(SettingsValidationError);
        }
        Ok(())
    }
}

fn bounded_text(value: &str, max_utf16_units: usize) -> bool {
    value.encode_utf16().take(max_utf16_units + 1).count() <= max_utf16_units
}

fn bounded_native_text(value: &str, maximum_bytes: usize, allow_empty: bool) -> bool {
    (allow_empty || !value.is_empty())
        && value.len() <= maximum_bytes
        && !value.contains(['\0', '\r', '\n'])
}

fn valid_ai_provider_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    let Some(first) = bytes.first() else {
        return false;
    };
    bytes.len() <= MAX_AI_PROVIDER_ID_BYTES
        && (first.is_ascii_lowercase() || first.is_ascii_digit())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn finite_range(value: f64, minimum: f64, maximum: f64) -> bool {
    value.is_finite() && (minimum..=maximum).contains(&value)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SettingsValidationError;

impl fmt::Debug for SettingsValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SettingsValidationError")
    }
}

impl fmt::Display for SettingsValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("renderer-safe Settings metadata is invalid")
    }
}

impl std::error::Error for SettingsValidationError {}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SettingsInventoryRevision {
    generation: u64,
    checksum: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SettingsInventoryRevisionDocument {
    generation: u64,
    checksum: String,
}

impl<'de> Deserialize<'de> for SettingsInventoryRevision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let document = SettingsInventoryRevisionDocument::deserialize(deserializer)?;
        let revision = Self {
            generation: document.generation,
            checksum: document.checksum,
        };
        if !revision.is_valid() {
            return Err(serde::de::Error::custom(
                "Settings inventory revision is invalid",
            ));
        }
        Ok(revision)
    }
}

impl SettingsInventoryRevision {
    fn is_valid(&self) -> bool {
        self.checksum.len() == 64
            && self
                .checksum
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    }
}

impl fmt::Debug for SettingsInventoryRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SettingsInventoryRevision")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RendererSafeSettingsSnapshot {
    pub(crate) settings: RendererSafeSettings,
    pub(crate) inventory_revision: SettingsInventoryRevision,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AiProviderAuthoritySettings {
    pub(crate) profile_id: String,
    pub(crate) provider_id: String,
    pub(crate) protocol: AiProviderProtocol,
    pub(crate) base_url: String,
    pub(crate) model: String,
    pub(crate) enabled: bool,
    pub(crate) command_permission_mode: AiCommandPermissionMode,
    pub(crate) response_idle_timeout_seconds: u32,
}

impl fmt::Debug for AiProviderAuthoritySettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AiProviderAuthoritySettings")
            .field("protocol", &self.protocol)
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for RendererSafeSettingsSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RendererSafeSettingsSnapshot")
            .field("inventory_revision", &self.inventory_revision)
            .finish_non_exhaustive()
    }
}

impl RendererSafeSettingsSnapshot {
    pub(crate) fn native_ui_locale(&self) -> &'static str {
        match self.settings.appearance.ui_language {
            UiLanguage::EnUs => "en-US",
            // Native surfaces use the product's required Simplified-Chinese
            // fallback when the saved value is `system` or otherwise cannot
            // be resolved inside the native process.
            UiLanguage::System | UiLanguage::ZhCn => "zh-CN",
        }
    }

    pub(crate) fn local_terminal_settings(&self) -> LocalTerminalSettings {
        self.settings.local_terminal_settings()
    }

    pub(crate) fn ai_command_permission_mode(&self) -> AiCommandPermissionMode {
        self.settings.ai.command_permission_mode
    }

    /// Resolve one renderer-named profile through the authenticated durable
    /// catalog. Endpoint, model, protocol, enabled state, and command policy
    /// always come from this snapshot rather than the request payload.
    pub(crate) fn ai_provider_authority(
        &self,
        profile_id: &str,
    ) -> Option<AiProviderAuthoritySettings> {
        let profile = self.settings.ai.profile(profile_id)?;
        Some(AiProviderAuthoritySettings {
            profile_id: profile.id.clone(),
            provider_id: profile.provider_id.clone(),
            protocol: profile.protocol,
            base_url: profile.base_url.clone(),
            model: profile.model.clone(),
            enabled: profile.enabled,
            command_permission_mode: self.settings.ai.command_permission_mode,
            response_idle_timeout_seconds: self.settings.ai.response_idle_timeout_seconds,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReplaceRendererSafeSettingsRequest {
    settings: RendererSafeSettings,
    expected_inventory_revision: SettingsInventoryRevision,
}

impl ReplaceRendererSafeSettingsRequest {
    pub(crate) fn into_parts(self) -> (SettingsInventoryRevision, RendererSafeSettings) {
        (self.expected_inventory_revision, self.settings)
    }
}

#[derive(Clone)]
pub(crate) struct RendererSafeSettingsStore {
    shared: Arc<RendererSafeSettingsStoreShared>,
}

struct RendererSafeSettingsStoreShared {
    root: PathBuf,
    platform: SettingsPlatform,
    gate: Mutex<()>,
}

impl fmt::Debug for RendererSafeSettingsStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RendererSafeSettingsStore")
            .field("platform", &self.shared.platform)
            .finish_non_exhaustive()
    }
}

impl RendererSafeSettingsStore {
    pub(crate) fn open(root: impl AsRef<Path>) -> Result<Self, SettingsStoreError> {
        Self::open_with_platform(root, SettingsPlatform::current())
    }

    fn open_with_platform(
        root: impl AsRef<Path>,
        platform: SettingsPlatform,
    ) -> Result<Self, SettingsStoreError> {
        std::fs::create_dir_all(root.as_ref()).map_err(|_| SettingsStoreError::Unavailable)?;
        Ok(Self {
            shared: Arc::new(RendererSafeSettingsStoreShared {
                root: root.as_ref().to_path_buf(),
                platform,
                gate: Mutex::new(()),
            }),
        })
    }

    pub(crate) fn load(&self) -> Result<RendererSafeSettingsSnapshot, SettingsStoreError> {
        let _gate = self
            .shared
            .gate
            .lock()
            .map_err(|_| SettingsStoreError::Unavailable)?;
        let _file_lock = SettingsFileLock::acquire(&self.shared.root)?;
        self.load_locked()
    }

    pub(crate) fn replace(
        &self,
        expected_inventory_revision: SettingsInventoryRevision,
        settings: RendererSafeSettings,
    ) -> Result<RendererSafeSettingsSnapshot, SettingsStoreError> {
        if !expected_inventory_revision.is_valid() {
            return Err(SettingsStoreError::Invalid);
        }
        settings
            .validate()
            .map_err(|_| SettingsStoreError::Invalid)?;
        let _gate = self
            .shared
            .gate
            .lock()
            .map_err(|_| SettingsStoreError::Unavailable)?;
        let _file_lock = SettingsFileLock::acquire(&self.shared.root)?;
        let current = self.load_locked()?;
        if current.inventory_revision != expected_inventory_revision {
            return Err(SettingsStoreError::InventoryRevisionConflict);
        }
        if current.settings == settings {
            return Ok(current);
        }
        let generation = current
            .inventory_revision
            .generation
            .checked_add(1)
            .ok_or(SettingsStoreError::PublicationFailed)?;
        let snapshot = DurableSettingsSnapshot::new(generation, settings)?;
        self.publish_locked(&snapshot)?;
        Ok(snapshot.renderer_snapshot())
    }

    fn load_locked(&self) -> Result<RendererSafeSettingsSnapshot, SettingsStoreError> {
        match load_durable_snapshot(&self.shared.root)? {
            Some(snapshot) => Ok(snapshot.renderer_snapshot()),
            None => {
                let settings = RendererSafeSettings::platform_default(self.shared.platform);
                let checksum = settings_checksum(0, &settings)?;
                Ok(RendererSafeSettingsSnapshot {
                    settings,
                    inventory_revision: SettingsInventoryRevision {
                        generation: 0,
                        checksum,
                    },
                })
            }
        }
    }

    fn publish_locked(&self, snapshot: &DurableSettingsSnapshot) -> Result<(), SettingsStoreError> {
        let slot = if snapshot.generation % 2 == 0 {
            SETTINGS_SLOT_A
        } else {
            SETTINGS_SLOT_B
        };
        let target = self.shared.root.join(slot);
        let temporary = self
            .shared
            .root
            .join(format!(".renderer-settings-{}.tmp", uuid::Uuid::new_v4()));
        let encoded = serde_json::to_vec(snapshot).map_err(|_| SettingsStoreError::Invalid)?;
        if u64::try_from(encoded.len()).unwrap_or(u64::MAX) > MAX_SETTINGS_SNAPSHOT_BYTES {
            return Err(SettingsStoreError::Invalid);
        }

        let temporary_guard = TemporarySettingsFile::new(temporary.clone());
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|_| SettingsStoreError::PublicationFailed)?;
        file.write_all(&encoded)
            .and_then(|_| file.sync_all())
            .map_err(|_| SettingsStoreError::PublicationFailed)?;
        drop(file);

        #[cfg(windows)]
        if target.exists() {
            std::fs::remove_file(&target).map_err(|_| SettingsStoreError::PublicationFailed)?;
        }
        std::fs::rename(&temporary, &target).map_err(|_| SettingsStoreError::PublicationFailed)?;
        temporary_guard.disarm();
        sync_settings_directory(&self.shared.root)?;

        // Read the just-published slot before reporting success. The other
        // slot remains untouched and provides crash/corruption fallback.
        let confirmed = read_settings_slot(&target)?;
        match confirmed {
            SlotRead::Valid(confirmed) if confirmed == *snapshot => Ok(()),
            _ => Err(SettingsStoreError::SnapshotDurabilityUnconfirmed),
        }
    }
}

struct SettingsFileLock(File);

impl SettingsFileLock {
    fn acquire(root: &Path) -> Result<Self, SettingsStoreError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join(SETTINGS_LOCK_FILE))
            .map_err(|_| SettingsStoreError::Unavailable)?;
        fs2::FileExt::lock_exclusive(&file).map_err(|_| SettingsStoreError::Unavailable)?;
        Ok(Self(file))
    }
}

impl Drop for SettingsFileLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.0);
    }
}

struct TemporarySettingsFile {
    path: PathBuf,
    armed: std::cell::Cell<bool>,
}

impl TemporarySettingsFile {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            armed: std::cell::Cell::new(true),
        }
    }

    fn disarm(&self) {
        self.armed.set(false);
    }
}

impl Drop for TemporarySettingsFile {
    fn drop(&mut self) {
        if self.armed.get() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(unix)]
fn sync_settings_directory(root: &Path) -> Result<(), SettingsStoreError> {
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| SettingsStoreError::PublicationFailed)
}

#[cfg(not(unix))]
fn sync_settings_directory(_root: &Path) -> Result<(), SettingsStoreError> {
    Ok(())
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DurableSettingsSnapshot {
    format_version: u8,
    generation: u64,
    settings: RendererSafeSettings,
    checksum: String,
}

impl DurableSettingsSnapshot {
    fn new(generation: u64, settings: RendererSafeSettings) -> Result<Self, SettingsStoreError> {
        settings
            .validate()
            .map_err(|_| SettingsStoreError::Invalid)?;
        if generation == 0 {
            return Err(SettingsStoreError::Invalid);
        }
        let checksum = settings_checksum(generation, &settings)?;
        Ok(Self {
            format_version: SNAPSHOT_FORMAT_VERSION,
            generation,
            settings,
            checksum,
        })
    }

    fn validate(&self) -> Result<(), SettingsStoreError> {
        if self.format_version != SNAPSHOT_FORMAT_VERSION || self.generation == 0 {
            return Err(SettingsStoreError::Corrupt);
        }
        self.settings
            .validate()
            .map_err(|_| SettingsStoreError::Corrupt)?;
        let expected = settings_checksum(self.generation, &self.settings)
            .map_err(|_| SettingsStoreError::Corrupt)?;
        if !constant_time_text_eq(&self.checksum, &expected) {
            return Err(SettingsStoreError::Corrupt);
        }
        Ok(())
    }

    fn renderer_snapshot(&self) -> RendererSafeSettingsSnapshot {
        RendererSafeSettingsSnapshot {
            settings: self.settings.clone(),
            inventory_revision: SettingsInventoryRevision {
                generation: self.generation,
                checksum: self.checksum.clone(),
            },
        }
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V3DurableSettingsSnapshot {
    format_version: u8,
    generation: u64,
    settings: V3RendererSafeSettings,
    checksum: String,
}

impl V3DurableSettingsSnapshot {
    fn validate_and_upgrade(self) -> Result<DurableSettingsSnapshot, SettingsStoreError> {
        if self.format_version != SNAPSHOT_FORMAT_VERSION
            || self.generation == 0
            || self.settings.schema_version != PRE_AI_RESPONSE_TIMEOUT_SETTINGS_SCHEMA_VERSION
        {
            return Err(SettingsStoreError::Corrupt);
        }
        let expected = v3_settings_checksum(self.generation, &self.settings)
            .map_err(|_| SettingsStoreError::Corrupt)?;
        if !constant_time_text_eq(&self.checksum, &expected) {
            return Err(SettingsStoreError::Corrupt);
        }
        let settings = self.settings.into_current();
        settings
            .validate()
            .map_err(|_| SettingsStoreError::Corrupt)?;
        let checksum = settings_checksum(self.generation, &settings)
            .map_err(|_| SettingsStoreError::Corrupt)?;
        Ok(DurableSettingsSnapshot {
            format_version: self.format_version,
            generation: self.generation,
            settings,
            checksum,
        })
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V2DurableSettingsSnapshot {
    format_version: u8,
    generation: u64,
    settings: V2RendererSafeSettings,
    checksum: String,
}

impl V2DurableSettingsSnapshot {
    fn validate_and_upgrade(self) -> Result<DurableSettingsSnapshot, SettingsStoreError> {
        if self.format_version != SNAPSHOT_FORMAT_VERSION
            || self.generation == 0
            || self.settings.schema_version != SINGLE_AI_SETTINGS_SCHEMA_VERSION
        {
            return Err(SettingsStoreError::Corrupt);
        }
        let expected = v2_settings_checksum(self.generation, &self.settings)
            .map_err(|_| SettingsStoreError::Corrupt)?;
        if !constant_time_text_eq(&self.checksum, &expected) {
            let legacy_expected =
                pre_agent_permission_settings_checksum(self.generation, &self.settings)
                    .map_err(|_| SettingsStoreError::Corrupt)?;
            if !constant_time_text_eq(&self.checksum, &legacy_expected) {
                return Err(SettingsStoreError::Corrupt);
            }
        }
        let settings = self.settings.into_current();
        settings
            .validate()
            .map_err(|_| SettingsStoreError::Corrupt)?;
        let checksum = settings_checksum(self.generation, &settings)
            .map_err(|_| SettingsStoreError::Corrupt)?;
        Ok(DurableSettingsSnapshot {
            format_version: self.format_version,
            generation: self.generation,
            settings,
            checksum,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyDurableSettingsSnapshot {
    format_version: u8,
    generation: u64,
    settings: LegacyRendererSafeSettings,
    checksum: String,
}

impl LegacyDurableSettingsSnapshot {
    fn validate_and_upgrade(self) -> Result<DurableSettingsSnapshot, SettingsStoreError> {
        if self.format_version != SNAPSHOT_FORMAT_VERSION
            || self.generation == 0
            || self.settings.schema_version != LEGACY_SETTINGS_SCHEMA_VERSION
        {
            return Err(SettingsStoreError::Corrupt);
        }
        let expected = legacy_settings_checksum(self.generation, &self.settings)
            .map_err(|_| SettingsStoreError::Corrupt)?;
        if !constant_time_text_eq(&self.checksum, &expected) {
            return Err(SettingsStoreError::Corrupt);
        }
        let settings = self.settings.into_current();
        settings
            .validate()
            .map_err(|_| SettingsStoreError::Corrupt)?;
        let checksum = settings_checksum(self.generation, &settings)
            .map_err(|_| SettingsStoreError::Corrupt)?;
        Ok(DurableSettingsSnapshot {
            format_version: self.format_version,
            generation: self.generation,
            settings,
            checksum,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreLocalPtyDurableSettingsSnapshot {
    format_version: u8,
    generation: u64,
    settings: PreLocalPtyRendererSafeSettings,
    checksum: String,
}

impl PreLocalPtyDurableSettingsSnapshot {
    fn validate_and_upgrade(self) -> Result<DurableSettingsSnapshot, SettingsStoreError> {
        if self.format_version != SNAPSHOT_FORMAT_VERSION
            || self.generation == 0
            || self.settings.schema_version != LEGACY_SETTINGS_SCHEMA_VERSION
        {
            return Err(SettingsStoreError::Corrupt);
        }
        let expected = pre_local_pty_settings_checksum(self.generation, &self.settings)
            .map_err(|_| SettingsStoreError::Corrupt)?;
        if !constant_time_text_eq(&self.checksum, &expected) {
            return Err(SettingsStoreError::Corrupt);
        }
        let settings = self.settings.into_current();
        settings
            .validate()
            .map_err(|_| SettingsStoreError::Corrupt)?;
        let checksum = settings_checksum(self.generation, &settings)
            .map_err(|_| SettingsStoreError::Corrupt)?;
        Ok(DurableSettingsSnapshot {
            format_version: self.format_version,
            generation: self.generation,
            settings,
            checksum,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SettingsChecksumDocument<'a> {
    format_version: u8,
    generation: u64,
    settings: &'a RendererSafeSettings,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct V2SettingsChecksumDocument<'a> {
    format_version: u8,
    generation: u64,
    settings: &'a V2RendererSafeSettings,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct V3SettingsChecksumDocument<'a> {
    format_version: u8,
    generation: u64,
    settings: &'a V3RendererSafeSettings,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum PreAgentPermissionMode {
    Ask,
    Auto,
    Deny,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreAgentAiSettings<'a> {
    provider_id: &'a str,
    base_url: &'a str,
    model: &'a str,
    command_permission_mode: PreAgentPermissionMode,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreAgentRendererSafeSettings<'a> {
    schema_version: u8,
    appearance: &'a AppearanceSettings,
    terminal: &'a TerminalSettings,
    shortcuts: &'a ShortcutSettings,
    sftp: &'a SftpSettings,
    ai: PreAgentAiSettings<'a>,
    system: &'a SystemSettings,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreAgentSettingsChecksumDocument<'a> {
    format_version: u8,
    generation: u64,
    settings: PreAgentRendererSafeSettings<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LegacySettingsChecksumDocument<'a> {
    format_version: u8,
    generation: u64,
    settings: &'a LegacyRendererSafeSettings,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreLocalPtySettingsChecksumDocument<'a> {
    format_version: u8,
    generation: u64,
    settings: &'a PreLocalPtyRendererSafeSettings,
}

fn settings_checksum(
    generation: u64,
    settings: &RendererSafeSettings,
) -> Result<String, SettingsStoreError> {
    let encoded = serde_json::to_vec(&SettingsChecksumDocument {
        format_version: SNAPSHOT_FORMAT_VERSION,
        generation,
        settings,
    })
    .map_err(|_| SettingsStoreError::Invalid)?;
    let digest = Sha256::digest(encoded);
    Ok(hex_encode(&digest))
}

fn v2_settings_checksum(
    generation: u64,
    settings: &V2RendererSafeSettings,
) -> Result<String, SettingsStoreError> {
    let encoded = serde_json::to_vec(&V2SettingsChecksumDocument {
        format_version: SNAPSHOT_FORMAT_VERSION,
        generation,
        settings,
    })
    .map_err(|_| SettingsStoreError::Invalid)?;
    let digest = Sha256::digest(encoded);
    Ok(hex_encode(&digest))
}

fn v3_settings_checksum(
    generation: u64,
    settings: &V3RendererSafeSettings,
) -> Result<String, SettingsStoreError> {
    let encoded = serde_json::to_vec(&V3SettingsChecksumDocument {
        format_version: SNAPSHOT_FORMAT_VERSION,
        generation,
        settings,
    })
    .map_err(|_| SettingsStoreError::Invalid)?;
    let digest = Sha256::digest(encoded);
    Ok(hex_encode(&digest))
}

fn pre_agent_permission_settings_checksum(
    generation: u64,
    settings: &V2RendererSafeSettings,
) -> Result<String, SettingsStoreError> {
    let command_permission_mode = match settings.ai.command_permission_mode {
        AiCommandPermissionMode::Observer => PreAgentPermissionMode::Deny,
        AiCommandPermissionMode::Confirm => PreAgentPermissionMode::Ask,
        AiCommandPermissionMode::Auto => PreAgentPermissionMode::Auto,
    };
    let encoded = serde_json::to_vec(&PreAgentSettingsChecksumDocument {
        format_version: SNAPSHOT_FORMAT_VERSION,
        generation,
        settings: PreAgentRendererSafeSettings {
            schema_version: settings.schema_version,
            appearance: &settings.appearance,
            terminal: &settings.terminal,
            shortcuts: &settings.shortcuts,
            sftp: &settings.sftp,
            ai: PreAgentAiSettings {
                provider_id: &settings.ai.provider_id,
                base_url: &settings.ai.base_url,
                model: &settings.ai.model,
                command_permission_mode,
            },
            system: &settings.system,
        },
    })
    .map_err(|_| SettingsStoreError::Invalid)?;
    let digest = Sha256::digest(encoded);
    Ok(hex_encode(&digest))
}

fn legacy_settings_checksum(
    generation: u64,
    settings: &LegacyRendererSafeSettings,
) -> Result<String, SettingsStoreError> {
    let encoded = serde_json::to_vec(&LegacySettingsChecksumDocument {
        format_version: SNAPSHOT_FORMAT_VERSION,
        generation,
        settings,
    })
    .map_err(|_| SettingsStoreError::Invalid)?;
    let digest = Sha256::digest(encoded);
    Ok(hex_encode(&digest))
}

fn pre_local_pty_settings_checksum(
    generation: u64,
    settings: &PreLocalPtyRendererSafeSettings,
) -> Result<String, SettingsStoreError> {
    let encoded = serde_json::to_vec(&PreLocalPtySettingsChecksumDocument {
        format_version: SNAPSHOT_FORMAT_VERSION,
        generation,
        settings,
    })
    .map_err(|_| SettingsStoreError::Invalid)?;
    let digest = Sha256::digest(encoded);
    Ok(hex_encode(&digest))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn constant_time_text_eq(left: &str, right: &str) -> bool {
    use subtle::ConstantTimeEq as _;
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

enum SlotRead {
    Missing,
    Corrupt,
    Valid(DurableSettingsSnapshot),
}

fn load_durable_snapshot(
    root: &Path,
) -> Result<Option<DurableSettingsSnapshot>, SettingsStoreError> {
    let first = read_settings_slot(&root.join(SETTINGS_SLOT_A))?;
    let second = read_settings_slot(&root.join(SETTINGS_SLOT_B))?;
    let had_artifact = !matches!(first, SlotRead::Missing) || !matches!(second, SlotRead::Missing);
    let mut valid = Vec::with_capacity(2);
    if let SlotRead::Valid(snapshot) = first {
        valid.push(snapshot);
    }
    if let SlotRead::Valid(snapshot) = second {
        valid.push(snapshot);
    }
    if valid.is_empty() {
        return if had_artifact {
            Err(SettingsStoreError::BothSlotsCorrupt)
        } else {
            Ok(None)
        };
    }
    if valid.len() == 2 && valid[0].generation == valid[1].generation && valid[0] != valid[1] {
        return Err(SettingsStoreError::ConflictingGeneration);
    }
    valid.sort_by_key(|snapshot| snapshot.generation);
    Ok(valid.pop())
}

fn read_settings_slot(path: &Path) -> Result<SlotRead, SettingsStoreError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(SlotRead::Missing),
        Err(_) => return Err(SettingsStoreError::Unavailable),
    };
    let metadata = file
        .metadata()
        .map_err(|_| SettingsStoreError::Unavailable)?;
    if !metadata.is_file() || metadata.len() > MAX_SETTINGS_SNAPSHOT_BYTES {
        return Ok(SlotRead::Corrupt);
    }
    let mut encoded = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    if file.read_to_end(&mut encoded).is_err() {
        return Err(SettingsStoreError::Unavailable);
    }
    let snapshot = match serde_json::from_slice::<DurableSettingsSnapshot>(&encoded) {
        Ok(mut snapshot) => {
            if snapshot.validate().is_err() {
                return Ok(SlotRead::Corrupt);
            }
            snapshot.settings.repair_known_legacy_values();
            snapshot.checksum = settings_checksum(snapshot.generation, &snapshot.settings)
                .map_err(|_| SettingsStoreError::Corrupt)?;
            snapshot
        }
        Err(_) => {
            if let Ok(v3) = serde_json::from_slice::<V3DurableSettingsSnapshot>(&encoded) {
                match v3.validate_and_upgrade() {
                    Ok(snapshot) => snapshot,
                    Err(_) => return Ok(SlotRead::Corrupt),
                }
            } else if let Ok(v2) = serde_json::from_slice::<V2DurableSettingsSnapshot>(&encoded) {
                match v2.validate_and_upgrade() {
                    Ok(snapshot) => snapshot,
                    Err(_) => return Ok(SlotRead::Corrupt),
                }
            } else if let Ok(legacy) =
                serde_json::from_slice::<LegacyDurableSettingsSnapshot>(&encoded)
            {
                match legacy.validate_and_upgrade() {
                    Ok(snapshot) => snapshot,
                    Err(_) => return Ok(SlotRead::Corrupt),
                }
            } else {
                let legacy =
                    match serde_json::from_slice::<PreLocalPtyDurableSettingsSnapshot>(&encoded) {
                        Ok(snapshot) => snapshot,
                        Err(_) => return Ok(SlotRead::Corrupt),
                    };
                match legacy.validate_and_upgrade() {
                    Ok(snapshot) => snapshot,
                    Err(_) => return Ok(SlotRead::Corrupt),
                }
            }
        }
    };
    Ok(SlotRead::Valid(snapshot))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SettingsStoreError {
    Invalid,
    InventoryRevisionConflict,
    Corrupt,
    BothSlotsCorrupt,
    ConflictingGeneration,
    SnapshotDurabilityUnconfirmed,
    PublicationFailed,
    Unavailable,
}

impl fmt::Debug for SettingsStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "SettingsStoreError::Invalid",
            Self::InventoryRevisionConflict => "SettingsStoreError::InventoryRevisionConflict",
            Self::Corrupt => "SettingsStoreError::Corrupt",
            Self::BothSlotsCorrupt => "SettingsStoreError::BothSlotsCorrupt",
            Self::ConflictingGeneration => "SettingsStoreError::ConflictingGeneration",
            Self::SnapshotDurabilityUnconfirmed => {
                "SettingsStoreError::SnapshotDurabilityUnconfirmed"
            }
            Self::PublicationFailed => "SettingsStoreError::PublicationFailed",
            Self::Unavailable => "SettingsStoreError::Unavailable",
        })
    }
}

impl fmt::Display for SettingsStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "renderer-safe Settings metadata is invalid",
            Self::InventoryRevisionConflict => "the Settings inventory changed",
            Self::Corrupt
            | Self::BothSlotsCorrupt
            | Self::ConflictingGeneration
            | Self::SnapshotDurabilityUnconfirmed => "Settings storage requires reconciliation",
            Self::PublicationFailed | Self::Unavailable => "Settings storage is unavailable",
        })
    }
}

impl std::error::Error for SettingsStoreError {}

pub(crate) async fn list_settings(
    store: RendererSafeSettingsStore,
) -> Result<RendererSafeSettingsSnapshot, String> {
    tokio::task::spawn_blocking(move || store.load())
        .await
        .map_err(|_| settings_error(SETTINGS_PUBLICATION_FAILED))?
        .map_err(map_settings_store_error)
}

pub(crate) async fn replace_settings(
    store: RendererSafeSettingsStore,
    request: ReplaceRendererSafeSettingsRequest,
) -> Result<RendererSafeSettingsSnapshot, String> {
    let (expected_inventory_revision, settings) = request.into_parts();
    tokio::task::spawn_blocking(move || store.replace(expected_inventory_revision, settings))
        .await
        .map_err(|_| settings_error(SETTINGS_PUBLICATION_FAILED))?
        .map_err(map_settings_store_error)
}

fn map_settings_store_error(error: SettingsStoreError) -> String {
    match error {
        SettingsStoreError::Invalid => settings_error(SETTINGS_INVALID),
        SettingsStoreError::InventoryRevisionConflict => settings_error(SETTINGS_INVENTORY_CHANGED),
        SettingsStoreError::Corrupt
        | SettingsStoreError::BothSlotsCorrupt
        | SettingsStoreError::ConflictingGeneration
        | SettingsStoreError::SnapshotDurabilityUnconfirmed => {
            settings_error(SETTINGS_REPAIR_REQUIRED)
        }
        SettingsStoreError::PublicationFailed | SettingsStoreError::Unavailable => {
            settings_error(SETTINGS_PUBLICATION_FAILED)
        }
    }
}

fn settings_error(code: &str) -> String {
    match code {
        SETTINGS_INVALID => {
            format!("{SETTINGS_INVALID}: Renderer-safe Settings metadata is invalid")
        }
        SETTINGS_INVENTORY_CHANGED => {
            format!("{SETTINGS_INVENTORY_CHANGED}: Settings changed; refresh and retry")
        }
        SETTINGS_REPAIR_REQUIRED => {
            format!("{SETTINGS_REPAIR_REQUIRED}: Settings storage requires reconciliation")
        }
        _ => format!("{SETTINGS_PUBLICATION_FAILED}: Settings could not be loaded or updated"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AiCommandPermissionMode, ColorMode, LegacyDurableSettingsSnapshot,
        LegacyRendererSafeSettings, PreLocalPtyDurableSettingsSnapshot,
        PreLocalPtyRendererSafeSettings, RendererSafeSettings, RendererSafeSettingsStore,
        ReplaceRendererSafeSettingsRequest, SETTINGS_INVENTORY_CHANGED, SETTINGS_SLOT_A,
        SETTINGS_SLOT_B, SettingsPlatform, SettingsStoreError, V2AiSettings,
        V2DurableSettingsSnapshot, V2RendererSafeSettings, V3AiSettings, V3DurableSettingsSnapshot,
        V3RendererSafeSettings, legacy_settings_checksum, list_settings,
        pre_local_pty_settings_checksum, replace_settings, settings_checksum, v2_settings_checksum,
        v3_settings_checksum,
    };
    use serde_json::json;

    fn v1_settings_value(platform: SettingsPlatform) -> serde_json::Value {
        let mut value = serde_json::to_value(RendererSafeSettings::platform_default(platform))
            .expect("settings JSON");
        value["schemaVersion"] = json!(1);
        value.as_object_mut().expect("settings object").remove("ai");
        value
    }

    fn v2_settings(platform: SettingsPlatform) -> V2RendererSafeSettings {
        let current = RendererSafeSettings::platform_default(platform);
        V2RendererSafeSettings {
            schema_version: 2,
            appearance: current.appearance,
            terminal: current.terminal,
            shortcuts: current.shortcuts,
            sftp: current.sftp,
            ai: V2AiSettings {
                provider_id: "openai-compatible".to_owned(),
                base_url: "https://api.openai.com/v1".to_owned(),
                model: "gpt-4o-mini".to_owned(),
                command_permission_mode: AiCommandPermissionMode::Confirm,
            },
            system: current.system,
        }
    }

    fn v3_settings(platform: SettingsPlatform) -> V3RendererSafeSettings {
        let current = RendererSafeSettings::platform_default(platform);
        V3RendererSafeSettings {
            schema_version: 3,
            appearance: current.appearance,
            terminal: current.terminal,
            shortcuts: current.shortcuts,
            sftp: current.sftp,
            ai: V3AiSettings {
                providers: current.ai.providers,
                active_provider_id: current.ai.active_provider_id,
                command_permission_mode: current.ai.command_permission_mode,
            },
            system: current.system,
        }
    }

    #[test]
    fn ai_provider_protocol_uses_the_exact_camel_case_wire_contract() {
        assert_eq!(
            serde_json::to_value(super::AiProviderProtocol::OpenAiChatCompletions)
                .expect("OpenAI protocol JSON"),
            json!("openAiChatCompletions")
        );
        assert_eq!(
            serde_json::to_value(super::AiProviderProtocol::AnthropicMessages)
                .expect("Anthropic protocol JSON"),
            json!("anthropicMessages")
        );
        assert_eq!(
            serde_json::from_value::<super::AiProviderProtocol>(json!("anthropicMessages"))
                .expect("Anthropic protocol"),
            super::AiProviderProtocol::AnthropicMessages
        );
        assert!(
            serde_json::from_value::<super::AiProviderProtocol>(json!("anthropic-messages"))
                .is_err()
        );
    }

    #[test]
    fn defaults_match_the_renderer_contract_on_each_platform() {
        let windows = RendererSafeSettings::platform_default(SettingsPlatform::Windows);
        assert_eq!(windows.schema_version, 4);
        assert_eq!(windows.appearance.ui_language, super::UiLanguage::ZhCn);
        assert_eq!(windows.appearance.ui_font_family_id, "inter");
        assert_eq!(windows.appearance.window_opacity, 1.0);
        assert_eq!(windows.appearance.light_ui_theme_id, "snow");
        assert_eq!(windows.appearance.dark_ui_theme_id, "midnight");
        assert_eq!(windows.terminal.theme_id, "netcatty-dark");
        assert_eq!(windows.terminal.font_size, 14.0);
        assert_eq!(windows.terminal.scrollback_rows, 10_000);
        assert!(windows.terminal.local_shell.is_empty());
        assert!(windows.terminal.local_shell_args.is_empty());
        assert!(windows.terminal.local_start_dir.is_empty());
        assert_eq!(windows.sftp.transfer_concurrency, 2);
        assert_eq!(windows.ai.active_provider_id, "openai-compatible");
        assert_eq!(windows.ai.providers.len(), 1);
        let provider = &windows.ai.providers[0];
        assert_eq!(provider.id, "openai-compatible");
        assert_eq!(provider.provider_id, "openai-compatible");
        assert_eq!(provider.name, "OpenAI");
        assert_eq!(
            provider.protocol,
            super::AiProviderProtocol::OpenAiChatCompletions
        );
        assert_eq!(provider.base_url, "https://api.openai.com/v1");
        assert_eq!(provider.model, "gpt-4o-mini");
        assert!(provider.enabled);
        assert_eq!(
            windows.ai.command_permission_mode,
            AiCommandPermissionMode::Confirm
        );
        assert_eq!(windows.ai.response_idle_timeout_seconds, 120);
        assert!(windows.system.explorer_context_menu_enabled);
        assert_eq!(windows.system.toggle_window_hotkey, "Ctrl + `");

        let mac = RendererSafeSettings::platform_default(SettingsPlatform::Mac);
        assert!(mac.terminal.alt_as_meta);
        assert!(mac.terminal.option_arrow_word_jump);
        assert_eq!(mac.system.toggle_window_hotkey, "\u{2318} + `");
        assert!(!mac.system.explorer_context_menu_enabled);
    }

    #[test]
    fn strict_dto_rejects_unknown_sensitive_fields_without_echoing_values() {
        let settings = RendererSafeSettings::platform_default(SettingsPlatform::Windows);
        let revision = super::SettingsInventoryRevision {
            generation: 0,
            checksum: "0".repeat(64),
        };
        let mut request = json!({
            "settings": settings,
            "expectedInventoryRevision": revision
        });
        request["settings"]["system"]["apiKey"] = json!("secret-api-key-sentinel");
        let error = serde_json::from_value::<ReplaceRendererSafeSettingsRequest>(request)
            .err()
            .expect("unknown secret field must fail")
            .to_string();
        assert!(!error.contains("secret-api-key-sentinel"));

        for (field, sentinel) in [
            ("apiKey", "secret-ai-key-sentinel"),
            ("hasSavedKey", "secret-saved-key-state-sentinel"),
            ("credentialReference", "secret-keyring-reference-sentinel"),
        ] {
            let mut settings = serde_json::to_value(RendererSafeSettings::platform_default(
                SettingsPlatform::Windows,
            ))
            .expect("settings JSON");
            settings["ai"][field] = json!(sentinel);
            let error = serde_json::from_value::<RendererSafeSettings>(settings)
                .err()
                .expect("AI secret custody fields must fail")
                .to_string();
            assert!(!error.contains(sentinel));
        }

        let mut root_secret = serde_json::to_value(RendererSafeSettings::platform_default(
            SettingsPlatform::Windows,
        ))
        .expect("settings JSON");
        root_secret["credential"] = json!("secret-credential-sentinel");
        let error = serde_json::from_value::<RendererSafeSettings>(root_secret)
            .err()
            .expect("unknown root secret field must fail")
            .to_string();
        assert!(!error.contains("secret-credential-sentinel"));

        let invalid_revision = json!({
            "settings": RendererSafeSettings::platform_default(SettingsPlatform::Windows),
            "expectedInventoryRevision": { "generation": 0, "checksum": "too-long-or-short" }
        });
        assert!(
            serde_json::from_value::<ReplaceRendererSafeSettingsRequest>(invalid_revision).is_err()
        );
    }

    #[test]
    fn numeric_utf16_and_enum_validation_matches_renderer_bounds() {
        let defaults = RendererSafeSettings::platform_default(SettingsPlatform::Windows);
        let mut value = serde_json::to_value(&defaults).expect("settings JSON");
        value["appearance"]["windowOpacity"] = json!(0.49);
        let invalid: RendererSafeSettings = serde_json::from_value(value).expect("typed settings");
        assert!(invalid.validate().is_err());

        let mut value = serde_json::to_value(&defaults).expect("settings JSON");
        value["terminal"]["scrollbackRows"] = json!(1_000_001);
        let invalid: RendererSafeSettings = serde_json::from_value(value).expect("typed settings");
        assert!(invalid.validate().is_err());

        let mut value = serde_json::to_value(&defaults).expect("settings JSON");
        value["appearance"]["uiFontFamilyId"] = json!("😀".repeat(40));
        let boundary: RendererSafeSettings = serde_json::from_value(value).expect("typed settings");
        assert!(boundary.validate().is_ok());

        let mut value = serde_json::to_value(&defaults).expect("settings JSON");
        value["appearance"]["uiFontFamilyId"] = json!("😀".repeat(41));
        let invalid: RendererSafeSettings = serde_json::from_value(value).expect("typed settings");
        assert!(invalid.validate().is_err());

        let mut value = serde_json::to_value(&defaults).expect("settings JSON");
        value["terminal"]["renderer"] = json!("unsafe-native-renderer");
        assert!(serde_json::from_value::<RendererSafeSettings>(value).is_err());

        for valid_timeout in [1, 86_400] {
            let mut boundary = defaults.clone();
            boundary.ai.response_idle_timeout_seconds = valid_timeout;
            boundary.validate().expect("AI response timeout boundary");
        }
        for invalid_timeout in [0, 86_401] {
            let mut invalid = defaults.clone();
            invalid.ai.response_idle_timeout_seconds = invalid_timeout;
            assert!(invalid.validate().is_err());
        }
        for invalid_wire_timeout in [json!(-1), json!(1.5), json!("120")] {
            let mut value = serde_json::to_value(&defaults).expect("settings JSON");
            value["ai"]["responseIdleTimeoutSeconds"] = invalid_wire_timeout;
            assert!(serde_json::from_value::<RendererSafeSettings>(value).is_err());
        }
    }

    #[test]
    fn ai_provider_profiles_enforce_catalog_identity_and_native_text_bounds() {
        let defaults = RendererSafeSettings::platform_default(SettingsPlatform::Windows);

        let mut boundary = defaults.clone();
        let boundary_id = format!("a{}", "x".repeat(127));
        boundary.ai.active_provider_id = boundary_id.clone();
        boundary.ai.providers[0].id = boundary_id;
        boundary.ai.providers[0].provider_id = format!("p{}", "x".repeat(127));
        boundary.ai.providers[0].name = "n".repeat(256);
        boundary.ai.providers[0].base_url =
            format!("https://example.invalid/{}", "x".repeat(2_024));
        boundary.ai.providers[0].model = "m".repeat(256);
        boundary.validate().expect("AI values at byte limits");

        for profile_id in ["", "OpenAI", "-openai", &"a".repeat(129)] {
            let mut invalid = defaults.clone();
            invalid.ai.providers[0].id = profile_id.to_owned();
            invalid.ai.active_provider_id = profile_id.to_owned();
            assert!(invalid.validate().is_err());
        }

        for provider_id in ["", "OpenAI", "-openai", &"a".repeat(129)] {
            let mut invalid = defaults.clone();
            invalid.ai.providers[0].provider_id = provider_id.to_owned();
            assert!(invalid.validate().is_err());
        }

        let mut invalid = defaults.clone();
        invalid.ai.providers[0].name = String::new();
        assert!(invalid.validate().is_err());

        let mut invalid = defaults.clone();
        invalid.ai.providers[0].name = "unsafe\nname".to_owned();
        assert!(invalid.validate().is_err());

        let mut invalid = defaults.clone();
        invalid.ai.providers[0].name = "n".repeat(257);
        assert!(invalid.validate().is_err());

        let mut invalid = defaults.clone();
        invalid.ai.providers[0].base_url = String::new();
        assert!(invalid.validate().is_err());

        let mut invalid = defaults.clone();
        invalid.ai.providers[0].base_url = "https://example.invalid/\nunsafe".to_owned();
        assert!(invalid.validate().is_err());

        let mut invalid = defaults.clone();
        invalid.ai.providers[0].base_url = "x".repeat(2_049);
        assert!(invalid.validate().is_err());

        let mut invalid = defaults.clone();
        invalid.ai.providers[0].model = String::new();
        assert!(invalid.validate().is_err());

        let mut invalid = defaults.clone();
        invalid.ai.providers[0].model = "m".repeat(257);
        assert!(invalid.validate().is_err());

        let mut value = serde_json::to_value(defaults).expect("settings JSON");
        value["ai"]["commandPermissionMode"] = json!("always");
        assert!(serde_json::from_value::<RendererSafeSettings>(value).is_err());
    }

    #[test]
    fn ai_provider_catalog_requires_a_unique_enabled_active_profile() {
        let defaults = RendererSafeSettings::platform_default(SettingsPlatform::Windows);

        let mut empty = defaults.clone();
        empty.ai.providers.clear();
        assert!(empty.validate().is_err());

        let mut too_many = defaults.clone();
        too_many.ai.providers = (0..33)
            .map(|index| {
                let mut profile = defaults.ai.providers[0].clone();
                profile.id = format!("profile-{index}");
                profile
            })
            .collect();
        too_many.ai.active_provider_id = "profile-0".to_owned();
        assert!(too_many.validate().is_err());

        let mut duplicate = defaults.clone();
        duplicate
            .ai
            .providers
            .push(duplicate.ai.providers[0].clone());
        assert!(duplicate.validate().is_err());

        let mut unknown_active = defaults.clone();
        unknown_active.ai.active_provider_id = "unknown-profile".to_owned();
        assert!(unknown_active.validate().is_err());

        let mut disabled_active = defaults.clone();
        disabled_active.ai.providers[0].enabled = false;
        assert!(disabled_active.validate().is_err());
    }

    #[test]
    fn authority_resolution_distinguishes_unknown_and_disabled_profiles() {
        let mut settings = RendererSafeSettings::platform_default(SettingsPlatform::Windows);
        let mut disabled = settings.ai.providers[0].clone();
        disabled.id = "openai-disabled".to_owned();
        disabled.name = "Disabled OpenAI".to_owned();
        disabled.enabled = false;
        settings.ai.providers.push(disabled);
        settings
            .validate()
            .expect("a non-active disabled profile remains durable");

        let snapshot = super::RendererSafeSettingsSnapshot {
            settings,
            inventory_revision: super::SettingsInventoryRevision {
                generation: 1,
                checksum: "0".repeat(64),
            },
        };
        let active = snapshot
            .ai_provider_authority("openai-compatible")
            .expect("active profile authority");
        assert!(active.enabled);
        assert_eq!(active.profile_id, "openai-compatible");
        assert_eq!(active.provider_id, "openai-compatible");
        assert_eq!(active.base_url, "https://api.openai.com/v1");
        assert_eq!(active.model, "gpt-4o-mini");
        assert_eq!(active.response_idle_timeout_seconds, 120);

        let disabled = snapshot
            .ai_provider_authority("openai-disabled")
            .expect("disabled profile metadata remains resolvable for key custody");
        assert!(!disabled.enabled);
        assert_eq!(disabled.profile_id, "openai-disabled");
        assert!(snapshot.ai_provider_authority("unknown-profile").is_none());
    }

    #[test]
    fn local_terminal_settings_are_direct_argv_bounded_and_path_redacted() {
        let mut settings = RendererSafeSettings::platform_default(SettingsPlatform::Windows);
        settings.terminal.local_shell = "C:\\Program Files\\PowerShell\\7\\pwsh.exe".to_owned();
        settings.terminal.local_shell_args = vec![
            "-NoLogo".to_owned(),
            "-WorkingDirectory".to_owned(),
            "C:\\work tree".to_owned(),
        ];
        settings.terminal.local_start_dir = "C:\\work tree".to_owned();
        settings
            .validate()
            .expect("bounded Local Terminal settings");

        let projection = settings.local_terminal_settings();
        assert_eq!(projection.shell, settings.terminal.local_shell);
        assert_eq!(projection.shell_args, settings.terminal.local_shell_args);
        assert_eq!(
            projection.start_directory,
            settings.terminal.local_start_dir
        );
        let debug = format!("{projection:?}");
        assert!(!debug.contains("PowerShell"));
        assert!(!debug.contains("work tree"));

        let mut invalid = settings.clone();
        invalid.terminal.local_shell.push('\n');
        assert!(invalid.validate().is_err());

        let mut invalid = settings.clone();
        invalid.terminal.local_shell_args = (0..33).map(|_| "-i".to_owned()).collect();
        assert!(invalid.validate().is_err());

        let mut invalid = settings.clone();
        invalid.terminal.local_shell_args = vec!["x".repeat(4 * 1_024 + 1)];
        assert!(invalid.validate().is_err());

        let mut invalid = settings;
        invalid.terminal.local_start_dir.push('\0');
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn v3_snapshot_upgrades_with_the_default_ai_response_timeout() {
        let directory = tempfile::tempdir().expect("temp directory");
        let store = RendererSafeSettingsStore::open_with_platform(
            directory.path(),
            SettingsPlatform::Windows,
        )
        .expect("settings store");

        let mut settings = v3_settings(SettingsPlatform::Windows);
        settings.appearance.ui_font_family_id = "mona-sans".to_owned();
        settings.ai.active_provider_id = "openai-compatible".to_owned();
        let generation = 11;
        let v3_checksum = v3_settings_checksum(generation, &settings).expect("v3 checksum");
        let snapshot = V3DurableSettingsSnapshot {
            format_version: 1,
            generation,
            settings,
            checksum: v3_checksum.clone(),
        };
        std::fs::write(
            directory.path().join(SETTINGS_SLOT_A),
            serde_json::to_vec(&snapshot).expect("v3 snapshot JSON"),
        )
        .expect("v3 settings slot");

        let loaded = store.load().expect("upgraded v4 settings");
        assert_eq!(loaded.inventory_revision.generation, generation);
        assert_ne!(loaded.inventory_revision.checksum, v3_checksum);
        assert_eq!(loaded.settings.schema_version, 4);
        assert_eq!(loaded.settings.ai.response_idle_timeout_seconds, 120);
        assert_eq!(loaded.settings.appearance.ui_font_family_id, "inter");
        assert_eq!(
            loaded.inventory_revision.checksum,
            settings_checksum(generation, &loaded.settings).expect("v4 checksum")
        );
    }

    #[test]
    fn v2_single_provider_snapshot_upgrades_to_an_authenticated_v4_profile() {
        let directory = tempfile::tempdir().expect("temp directory");
        let store = RendererSafeSettingsStore::open_with_platform(
            directory.path(),
            SettingsPlatform::Windows,
        )
        .expect("settings store");

        let mut settings = v2_settings(SettingsPlatform::Windows);
        settings.appearance.color_mode = ColorMode::Dark;
        settings.ai = V2AiSettings {
            provider_id: "deepseek".to_owned(),
            base_url: "https://platform.deepseek.com/v1".to_owned(),
            model: "deepseek-chat".to_owned(),
            command_permission_mode: AiCommandPermissionMode::Auto,
        };
        let generation = 8;
        let v2_checksum = v2_settings_checksum(generation, &settings).expect("v2 checksum");
        let snapshot = V2DurableSettingsSnapshot {
            format_version: 1,
            generation,
            settings,
            checksum: v2_checksum.clone(),
        };
        std::fs::write(
            directory.path().join(SETTINGS_SLOT_A),
            serde_json::to_vec(&snapshot).expect("v2 snapshot JSON"),
        )
        .expect("v2 settings slot");

        let loaded = store.load().expect("upgraded v4 settings");
        assert_eq!(loaded.inventory_revision.generation, generation);
        assert_ne!(loaded.inventory_revision.checksum, v2_checksum);
        assert_eq!(loaded.settings.schema_version, 4);
        assert_eq!(loaded.settings.appearance.color_mode, ColorMode::Dark);
        assert_eq!(loaded.settings.ai.active_provider_id, "deepseek");
        assert_eq!(loaded.settings.ai.providers.len(), 1);
        let provider = &loaded.settings.ai.providers[0];
        assert_eq!(provider.id, "deepseek");
        assert_eq!(provider.provider_id, "deepseek");
        assert_eq!(provider.name, "DeepSeek");
        assert_eq!(
            provider.protocol,
            super::AiProviderProtocol::OpenAiChatCompletions
        );
        assert_eq!(provider.base_url, "https://api.deepseek.com/v1");
        assert_eq!(provider.model, "deepseek-chat");
        assert!(provider.enabled);
        assert_eq!(
            loaded.settings.ai.command_permission_mode,
            AiCommandPermissionMode::Auto
        );
        assert_eq!(
            loaded.inventory_revision.checksum,
            settings_checksum(generation, &loaded.settings).expect("v4 checksum")
        );
    }

    #[test]
    fn authenticated_current_deepseek_console_endpoint_is_repaired_on_load() {
        let directory = tempfile::tempdir().expect("temp directory");
        let store = RendererSafeSettingsStore::open_with_platform(
            directory.path(),
            SettingsPlatform::Windows,
        )
        .expect("settings store");
        let mut settings = RendererSafeSettings::platform_default(SettingsPlatform::Windows);
        let profile = &mut settings.ai.providers[0];
        profile.id = "deepseek".to_owned();
        profile.provider_id = "deepseek".to_owned();
        profile.name = "DeepSeek".to_owned();
        profile.base_url = super::LEGACY_DEEPSEEK_CONSOLE_BASE_URL.to_owned();
        profile.model = "deepseek-chat".to_owned();
        settings.ai.active_provider_id = profile.id.clone();
        let generation = 9;
        let snapshot = super::DurableSettingsSnapshot::new(generation, settings)
            .expect("legacy endpoint current snapshot");
        let original_checksum = snapshot.checksum.clone();
        std::fs::write(
            directory.path().join(SETTINGS_SLOT_B),
            serde_json::to_vec(&snapshot).expect("current snapshot JSON"),
        )
        .expect("current settings slot");

        let loaded = store.load().expect("repaired current settings");
        assert_eq!(
            loaded.settings.ai.providers[0].base_url,
            super::DEEPSEEK_API_BASE_URL
        );
        assert_ne!(loaded.inventory_revision.checksum, original_checksum);
        assert_eq!(
            loaded.inventory_revision.checksum,
            settings_checksum(generation, &loaded.settings).expect("repaired checksum")
        );
    }

    #[test]
    fn v1_local_pty_snapshot_upgrades_without_losing_existing_settings() {
        let directory = tempfile::tempdir().expect("temp directory");
        let store = RendererSafeSettingsStore::open_with_platform(
            directory.path(),
            SettingsPlatform::Windows,
        )
        .expect("settings store");

        let mut legacy_value = v1_settings_value(SettingsPlatform::Windows);
        legacy_value["appearance"]["colorMode"] = json!("dark");
        legacy_value["terminal"]["localShell"] = json!("pwsh");
        legacy_value["terminal"]["localShellArgs"] = json!(["-NoLogo"]);
        let legacy_settings: LegacyRendererSafeSettings =
            serde_json::from_value(legacy_value).expect("v1 Local PTY settings shape");
        let generation = 7;
        let legacy_checksum =
            legacy_settings_checksum(generation, &legacy_settings).expect("v1 checksum");
        let legacy_snapshot = LegacyDurableSettingsSnapshot {
            format_version: 1,
            generation,
            settings: legacy_settings,
            checksum: legacy_checksum.clone(),
        };
        std::fs::write(
            directory.path().join(SETTINGS_SLOT_B),
            serde_json::to_vec(&legacy_snapshot).expect("v1 snapshot JSON"),
        )
        .expect("v1 settings slot");

        let loaded = store.load().expect("upgraded settings");
        assert_eq!(loaded.inventory_revision.generation, generation);
        assert_ne!(loaded.inventory_revision.checksum, legacy_checksum);
        assert_eq!(loaded.settings.schema_version, 4);
        assert_eq!(loaded.settings.appearance.color_mode, ColorMode::Dark);
        assert_eq!(loaded.settings.terminal.local_shell, "pwsh");
        assert_eq!(loaded.settings.terminal.local_shell_args, ["-NoLogo"]);
        assert_eq!(loaded.settings.ai.active_provider_id, "openai-compatible");
        assert_eq!(loaded.settings.ai.providers[0].id, "openai-compatible");
        assert_eq!(loaded.settings.ai.providers[0].model, "gpt-4o-mini");
        assert_eq!(
            loaded.inventory_revision.checksum,
            settings_checksum(generation, &loaded.settings).expect("v4 checksum")
        );
    }

    #[test]
    fn pre_local_pty_snapshot_upgrades_without_losing_existing_settings() {
        let directory = tempfile::tempdir().expect("temp directory");
        let store = RendererSafeSettingsStore::open_with_platform(
            directory.path(),
            SettingsPlatform::Windows,
        )
        .expect("settings store");

        let mut legacy_value = v1_settings_value(SettingsPlatform::Windows);
        let terminal = legacy_value["terminal"]
            .as_object_mut()
            .expect("terminal settings object");
        terminal.remove("localShell");
        terminal.remove("localShellArgs");
        terminal.remove("localStartDir");
        legacy_value["appearance"]["colorMode"] = json!("dark");
        let legacy_settings: PreLocalPtyRendererSafeSettings =
            serde_json::from_value(legacy_value).expect("historical settings shape");
        let generation = 7;
        let legacy_checksum = pre_local_pty_settings_checksum(generation, &legacy_settings)
            .expect("pre-Local-PTY checksum");
        let legacy_snapshot = PreLocalPtyDurableSettingsSnapshot {
            format_version: 1,
            generation,
            settings: legacy_settings,
            checksum: legacy_checksum.clone(),
        };
        std::fs::write(
            directory.path().join(SETTINGS_SLOT_B),
            serde_json::to_vec(&legacy_snapshot).expect("legacy snapshot JSON"),
        )
        .expect("legacy settings slot");

        let loaded = store.load().expect("upgraded settings");
        assert_eq!(loaded.inventory_revision.generation, generation);
        assert_ne!(loaded.inventory_revision.checksum, legacy_checksum);
        assert_eq!(loaded.settings.schema_version, 4);
        assert_eq!(loaded.settings.appearance.color_mode, ColorMode::Dark);
        assert!(loaded.settings.terminal.local_shell.is_empty());
        assert!(loaded.settings.terminal.local_shell_args.is_empty());
        assert!(loaded.settings.terminal.local_start_dir.is_empty());
        assert_eq!(loaded.settings.ai.active_provider_id, "openai-compatible");
        assert_eq!(loaded.settings.ai.providers[0].id, "openai-compatible");
        assert_eq!(
            loaded.settings.ai.providers[0].base_url,
            "https://api.openai.com/v1"
        );
        assert_eq!(loaded.settings.ai.providers[0].model, "gpt-4o-mini");
        assert_eq!(
            loaded.settings.ai.command_permission_mode,
            AiCommandPermissionMode::Confirm
        );
        assert_eq!(
            loaded.inventory_revision.checksum,
            settings_checksum(generation, &loaded.settings).expect("v4 checksum")
        );

        let mut changed = loaded.settings;
        changed.terminal.local_shell = "pwsh".to_owned();
        changed.terminal.local_shell_args = vec!["-NoLogo".to_owned()];
        let committed = store
            .replace(loaded.inventory_revision, changed)
            .expect("replace upgraded settings");
        assert_eq!(committed.inventory_revision.generation, generation + 1);
        assert_eq!(committed.settings.terminal.local_shell, "pwsh");
    }

    #[test]
    fn both_v1_shapes_verify_their_original_checksum_before_migration() {
        let current_directory = tempfile::tempdir().expect("current v1 temp directory");
        let current_settings: LegacyRendererSafeSettings =
            serde_json::from_value(v1_settings_value(SettingsPlatform::Windows))
                .expect("v1 Local PTY settings");
        let current_generation = 3;
        let current_snapshot = LegacyDurableSettingsSnapshot {
            format_version: 1,
            generation: current_generation,
            checksum: legacy_settings_checksum(current_generation, &current_settings)
                .expect("v1 checksum"),
            settings: current_settings,
        };
        let mut tampered = serde_json::to_value(current_snapshot).expect("v1 snapshot document");
        tampered["settings"]["system"]["closeToTray"] = json!(false);
        std::fs::write(
            current_directory.path().join(SETTINGS_SLOT_B),
            serde_json::to_vec(&tampered).expect("tampered v1 snapshot JSON"),
        )
        .expect("tampered v1 slot");
        let current_store = RendererSafeSettingsStore::open_with_platform(
            current_directory.path(),
            SettingsPlatform::Windows,
        )
        .expect("current v1 store");
        assert_eq!(
            current_store
                .load()
                .expect_err("tampered v1 snapshot must not migrate"),
            SettingsStoreError::BothSlotsCorrupt
        );

        let pre_local_directory = tempfile::tempdir().expect("pre-Local-PTY temp directory");
        let mut pre_local_value = v1_settings_value(SettingsPlatform::Windows);
        let terminal = pre_local_value["terminal"]
            .as_object_mut()
            .expect("terminal settings object");
        terminal.remove("localShell");
        terminal.remove("localShellArgs");
        terminal.remove("localStartDir");
        let pre_local_settings: PreLocalPtyRendererSafeSettings =
            serde_json::from_value(pre_local_value).expect("pre-Local-PTY settings");
        let pre_local_generation = 4;
        let pre_local_snapshot = PreLocalPtyDurableSettingsSnapshot {
            format_version: 1,
            generation: pre_local_generation,
            checksum: pre_local_pty_settings_checksum(pre_local_generation, &pre_local_settings)
                .expect("pre-Local-PTY checksum"),
            settings: pre_local_settings,
        };
        let mut tampered =
            serde_json::to_value(pre_local_snapshot).expect("pre-Local-PTY snapshot document");
        tampered["settings"]["appearance"]["colorMode"] = json!("dark");
        std::fs::write(
            pre_local_directory.path().join(SETTINGS_SLOT_A),
            serde_json::to_vec(&tampered).expect("tampered pre-Local-PTY snapshot JSON"),
        )
        .expect("tampered pre-Local-PTY slot");
        let pre_local_store = RendererSafeSettingsStore::open_with_platform(
            pre_local_directory.path(),
            SettingsPlatform::Windows,
        )
        .expect("pre-Local-PTY store");
        assert_eq!(
            pre_local_store
                .load()
                .expect_err("tampered pre-Local-PTY snapshot must not migrate"),
            SettingsStoreError::BothSlotsCorrupt
        );
    }

    #[test]
    fn every_non_default_renderer_enum_spelling_round_trips_exactly() {
        let mut value = serde_json::to_value(RendererSafeSettings::platform_default(
            SettingsPlatform::Windows,
        ))
        .expect("settings JSON");
        for (section, field, selected) in [
            ("appearance", "uiLanguage", "en-US"),
            ("appearance", "colorMode", "dark"),
            ("appearance", "accentMode", "custom"),
            ("appearance", "hostClickBehavior", "select"),
            ("terminal", "fontSmoothing", "antialiased"),
            ("terminal", "emulationType", "vt100"),
            ("terminal", "cursorStyle", "underline"),
            ("terminal", "renderer", "webgl"),
            ("terminal", "workspaceFocusStyle", "glow"),
            ("terminal", "passwordPromptAssist", "auto"),
            ("shortcuts", "scheme", "disabled"),
            ("sftp", "doubleClickBehavior", "transfer"),
            ("sftp", "defaultViewMode", "tree"),
            ("sftp", "defaultOpener", "editor"),
            ("ai", "commandPermissionMode", "auto"),
            ("system", "networkProxyMode", "manual"),
            ("system", "startupLanding", "terminal"),
        ] {
            value[section][field] = json!(selected);
        }
        let settings: RendererSafeSettings =
            serde_json::from_value(value.clone()).expect("all renderer enum values");
        settings.validate().expect("valid settings");
        assert_eq!(serde_json::to_value(settings).expect("round trip"), value);
    }

    #[test]
    fn legacy_ask_and_deny_permissions_verify_then_upgrade_to_canonical_values() {
        for (legacy, canonical) in [
            ("ask", AiCommandPermissionMode::Confirm),
            ("deny", AiCommandPermissionMode::Observer),
        ] {
            let directory = tempfile::tempdir().expect("temp directory");
            let mut settings = v2_settings(SettingsPlatform::Windows);
            settings.ai.command_permission_mode = canonical;
            let generation = 9;
            let legacy_checksum =
                super::pre_agent_permission_settings_checksum(generation, &settings)
                    .expect("legacy permission checksum");
            let mut value = serde_json::to_value(&settings).expect("settings JSON");
            value["ai"]["commandPermissionMode"] = json!(legacy);
            let snapshot = json!({
                "formatVersion": 1,
                "generation": generation,
                "settings": value,
                "checksum": legacy_checksum,
            });
            std::fs::write(
                directory.path().join(SETTINGS_SLOT_A),
                serde_json::to_vec(&snapshot).expect("snapshot JSON"),
            )
            .expect("legacy permission slot");

            let store = RendererSafeSettingsStore::open_with_platform(
                directory.path(),
                SettingsPlatform::Windows,
            )
            .expect("settings store");
            let loaded = store.load().expect("upgraded permission settings");
            assert_eq!(loaded.settings.schema_version, 4);
            assert_eq!(loaded.settings.ai.active_provider_id, "openai-compatible");
            assert_eq!(loaded.settings.ai.command_permission_mode, canonical);
            assert_eq!(
                loaded.inventory_revision.checksum,
                settings_checksum(generation, &loaded.settings).expect("canonical checksum")
            );
            assert_ne!(loaded.inventory_revision.checksum, legacy_checksum);
        }
    }

    #[test]
    fn replace_is_durable_restart_safe_and_noop_stable() {
        let directory = tempfile::tempdir().expect("temp directory");
        let store = RendererSafeSettingsStore::open_with_platform(
            directory.path(),
            SettingsPlatform::Windows,
        )
        .expect("settings store");
        let initial = store.load().expect("initial settings");
        assert_eq!(initial.inventory_revision.generation, 0);
        let mut changed = initial.settings.clone();
        changed.appearance.color_mode = ColorMode::Dark;
        let mut deepseek = changed.ai.providers[0].clone();
        deepseek.id = "deepseek-work".to_owned();
        deepseek.provider_id = "deepseek".to_owned();
        deepseek.name = "DeepSeek Work".to_owned();
        deepseek.base_url = "https://api.deepseek.com/v1".to_owned();
        deepseek.model = "deepseek-chat".to_owned();
        changed.ai.providers.push(deepseek);
        changed.ai.active_provider_id = "deepseek-work".to_owned();
        changed.ai.command_permission_mode = AiCommandPermissionMode::Auto;
        let committed = store
            .replace(initial.inventory_revision, changed.clone())
            .expect("replace settings");
        assert_eq!(committed.inventory_revision.generation, 1);
        assert_eq!(committed.settings, changed);

        let unchanged = store
            .replace(committed.inventory_revision.clone(), changed.clone())
            .expect("no-op replace");
        assert_eq!(unchanged.inventory_revision, committed.inventory_revision);

        let restarted = RendererSafeSettingsStore::open_with_platform(
            directory.path(),
            SettingsPlatform::Other,
        )
        .expect("restarted store")
        .load()
        .expect("restarted settings");
        assert_eq!(restarted.settings, changed);
        assert_eq!(restarted.inventory_revision, committed.inventory_revision);
    }

    #[test]
    fn stale_complete_inventory_revision_is_rejected() {
        let directory = tempfile::tempdir().expect("temp directory");
        let store = RendererSafeSettingsStore::open_with_platform(
            directory.path(),
            SettingsPlatform::Linux,
        )
        .expect("settings store");
        let initial = store.load().expect("initial settings");
        let stale = initial.inventory_revision.clone();
        let mut first = initial.settings.clone();
        first.system.close_to_tray = false;
        store
            .replace(initial.inventory_revision, first)
            .expect("first replacement");
        let mut second = initial.settings;
        second.system.auto_update_enabled = false;
        assert_eq!(
            store.replace(stale, second).expect_err("stale CAS"),
            SettingsStoreError::InventoryRevisionConflict
        );
    }

    #[test]
    fn concurrent_same_revision_writers_have_one_winner() {
        let directory = tempfile::tempdir().expect("temp directory");
        let first_store = RendererSafeSettingsStore::open_with_platform(
            directory.path(),
            SettingsPlatform::Windows,
        )
        .expect("first store");
        let second_store = RendererSafeSettingsStore::open_with_platform(
            directory.path(),
            SettingsPlatform::Windows,
        )
        .expect("second store");
        let initial = first_store.load().expect("initial settings");
        let mut first = initial.settings.clone();
        first.system.close_to_tray = false;
        let mut second = initial.settings;
        second.system.auto_update_enabled = false;
        let first_revision = initial.inventory_revision.clone();
        let second_revision = initial.inventory_revision;
        let first = std::thread::spawn(move || first_store.replace(first_revision, first));
        let second = std::thread::spawn(move || second_store.replace(second_revision, second));
        let results = [
            first.join().expect("first writer"),
            second.join().expect("second writer"),
        ];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(
                    result,
                    Err(SettingsStoreError::InventoryRevisionConflict)
                ))
                .count(),
            1
        );
    }

    #[test]
    fn a_corrupt_newest_slot_falls_back_to_the_previous_durable_snapshot() {
        let directory = tempfile::tempdir().expect("temp directory");
        let store = RendererSafeSettingsStore::open_with_platform(
            directory.path(),
            SettingsPlatform::Windows,
        )
        .expect("settings store");
        let initial = store.load().expect("initial settings");
        let mut first_settings = initial.settings;
        first_settings.appearance.color_mode = ColorMode::Dark;
        let first = store
            .replace(initial.inventory_revision, first_settings.clone())
            .expect("first commit");
        let mut second_settings = first.settings.clone();
        second_settings.system.close_to_tray = false;
        let second = store
            .replace(first.inventory_revision, second_settings)
            .expect("second commit");
        assert_eq!(second.inventory_revision.generation, 2);

        std::fs::write(directory.path().join(SETTINGS_SLOT_A), b"truncated")
            .expect("corrupt newest slot");
        let recovered = store.load().expect("fallback snapshot");
        assert_eq!(recovered.inventory_revision.generation, 1);
        assert_eq!(recovered.settings, first_settings);
    }

    #[test]
    fn both_corrupt_slots_require_repair_and_ignore_unpublished_temp_files() {
        let directory = tempfile::tempdir().expect("temp directory");
        let store = RendererSafeSettingsStore::open_with_platform(
            directory.path(),
            SettingsPlatform::Windows,
        )
        .expect("settings store");
        std::fs::write(
            directory.path().join(".renderer-settings-crash.tmp"),
            b"partial",
        )
        .expect("crash temp");
        assert_eq!(
            store
                .load()
                .expect("temp ignored")
                .inventory_revision
                .generation,
            0
        );

        std::fs::write(directory.path().join(SETTINGS_SLOT_A), b"corrupt-a")
            .expect("corrupt slot A");
        std::fs::write(directory.path().join(SETTINGS_SLOT_B), b"corrupt-b")
            .expect("corrupt slot B");
        assert_eq!(
            store.load().expect_err("both slots must fail closed"),
            SettingsStoreError::BothSlotsCorrupt
        );
    }

    #[test]
    fn checksum_binds_the_complete_settings_inventory() {
        let directory = tempfile::tempdir().expect("temp directory");
        let store = RendererSafeSettingsStore::open_with_platform(
            directory.path(),
            SettingsPlatform::Windows,
        )
        .expect("settings store");
        let initial = store.load().expect("initial settings");
        let mut settings = initial.settings;
        settings.system.close_to_tray = false;
        store
            .replace(initial.inventory_revision, settings)
            .expect("first commit");

        let slot = directory.path().join(SETTINGS_SLOT_B);
        let mut document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&slot).expect("snapshot bytes"))
                .expect("snapshot JSON");
        document["settings"]["ai"]["providers"][0]["model"] = json!("tampered-model");
        std::fs::write(&slot, serde_json::to_vec(&document).expect("tampered JSON"))
            .expect("tampered snapshot");
        assert_eq!(
            store.load().expect_err("tamper must fail checksum"),
            SettingsStoreError::BothSlotsCorrupt
        );
    }

    #[tokio::test]
    async fn registerable_functions_return_stable_codes_and_snapshots() {
        let directory = tempfile::tempdir().expect("temp directory");
        let store = RendererSafeSettingsStore::open_with_platform(
            directory.path(),
            SettingsPlatform::Windows,
        )
        .expect("settings store");
        let initial = list_settings(store.clone()).await.expect("list settings");
        let stale_revision = initial.inventory_revision.clone();
        let mut settings = initial.settings;
        settings.system.close_to_tray = false;
        let committed = replace_settings(
            store.clone(),
            ReplaceRendererSafeSettingsRequest {
                settings: settings.clone(),
                expected_inventory_revision: initial.inventory_revision,
            },
        )
        .await
        .expect("replace settings");
        assert_eq!(committed.inventory_revision.generation, 1);
        assert_eq!(committed.settings, settings);

        let error = replace_settings(
            store,
            ReplaceRendererSafeSettingsRequest {
                settings: committed.settings,
                expected_inventory_revision: stale_revision,
            },
        )
        .await
        .expect_err("stale wrapper CAS");
        assert!(error.starts_with(SETTINGS_INVENTORY_CHANGED));
    }
}
