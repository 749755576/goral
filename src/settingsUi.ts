export const SETTINGS_PAGE_IDS = [
  "application",
  "plugins",
  "appearance",
  "terminal",
  "shortcuts",
  "file-associations",
  "ai",
  "sync",
  "system",
] as const;

export type SettingsPageId = (typeof SETTINGS_PAGE_IDS)[number];
export type SettingsNestedTab =
  | "ai-providers"
  | "ai-agents"
  | "ai-tools"
  | "ai-search"
  | "ai-safety"
  | "sync-providers"
  | "sync-status";

export type SettingsPageDefinition = {
  id: SettingsPageId;
  label: string;
  glyph: "app" | "plugin" | "palette" | "terminal" | "keyboard" | "file" | "ai" | "cloud" | "system";
  conditional?: "plugins";
};

export const SETTINGS_PAGES: readonly SettingsPageDefinition[] = [
  { id: "application", label: "Application", glyph: "app" },
  { id: "plugins", label: "Plugins", glyph: "plugin", conditional: "plugins" },
  { id: "appearance", label: "Appearance", glyph: "palette" },
  { id: "terminal", label: "Terminal", glyph: "terminal" },
  { id: "shortcuts", label: "Shortcuts", glyph: "keyboard" },
  { id: "file-associations", label: "SFTP", glyph: "file" },
  { id: "ai", label: "AI", glyph: "ai" },
  { id: "sync", label: "Sync & Cloud", glyph: "cloud" },
  { id: "system", label: "System", glyph: "system" },
] as const;

/** Pages retained in the settings schema for import compatibility but hidden
 * from the public UI until they have a complete runtime implementation. */
export const SETTINGS_PUBLIC_HIDDEN_PAGE_IDS = ["plugins", "shortcuts", "sync"] as const satisfies readonly SettingsPageId[];

const SETTINGS_PUBLIC_HIDDEN_PAGE_SET = new Set<SettingsPageId>(
  SETTINGS_PUBLIC_HIDDEN_PAGE_IDS,
);

export const SETTINGS_PUBLIC_PAGES: readonly SettingsPageDefinition[] = SETTINGS_PAGES.filter(
  (page) => !SETTINGS_PUBLIC_HIDDEN_PAGE_SET.has(page.id),
);

export const isPublicSettingsPageId = (page: SettingsPageId): boolean =>
  !SETTINGS_PUBLIC_HIDDEN_PAGE_SET.has(page);

export const SETTINGS_ANCHORS = {
  application: [
    "application-check-updates",
    "application-report-problem",
    "application-community",
    "application-github",
    "application-whats-new",
  ],
  plugins: ["plugins-root"],
  appearance: [
    "appearance-language",
    "appearance-ui-font",
    "appearance-window-opacity",
    "appearance-theme",
    "appearance-theme-color",
    "appearance-accent-mode",
    "appearance-app-icon",
    "appearance-vault-show-recent",
    "appearance-vault-select-before-connect",
    "appearance-vault-ungrouped-root",
    "appearance-vault-show-sftp-tab",
    "appearance-vault-host-tree",
    "appearance-vault-auto-import-known-hosts",
    "appearance-custom-css",
  ],
  terminal: [
    "terminal-theme-follow-app",
    "terminal-font-family",
    "terminal-font-cjk",
    "terminal-font-size",
    "terminal-font-weight",
    "terminal-font-weight-bold",
    "terminal-font-smoothing",
    "terminal-font-line-padding",
    "terminal-emulation-type",
    "terminal-cursor-style",
    "terminal-cursor-blink",
    "terminal-cursor-highlight-line",
    "terminal-alt-as-meta",
    "terminal-option-arrow-word-jump",
    "terminal-kitty-protocol",
    "terminal-min-contrast",
    "terminal-auto-close-on-exit",
    "terminal-right-click",
    "terminal-copy-on-select",
    "terminal-normalize-text-on-copy",
    "terminal-middle-click",
    "terminal-word-separators",
    "terminal-bracketed-paste",
    "terminal-auto-upload-clipboard-image",
    "terminal-shift-enter-newline",
    "terminal-clear-wipes-scrollback",
    "terminal-dynamic-tab-title",
    "terminal-osc-notifications",
    "terminal-osc52-clipboard",
    "terminal-scrollback-rows",
    "terminal-startup-command-delay",
    "terminal-side-panel-auto-open",
    "terminal-keyword-highlight",
    "terminal-local-shell",
    "terminal-verify-host-keys",
    "terminal-ssh-auto-reconnect",
    "terminal-keepalive-interval",
    "terminal-x11-display",
    "terminal-server-stats-show",
    "terminal-renderer",
    "terminal-inline-images-enabled",
    "terminal-workspace-focus-style",
    "terminal-autocomplete-enabled",
    "terminal-password-prompt-assist",
  ],
  shortcuts: [
    "shortcuts-scheme",
    "shortcuts-disable-terminal-font-zoom",
    "shortcuts-shell-only-tab-numbers",
    "shortcuts-show-tab-number-badges",
    "shortcuts-section-custom",
  ],
  "file-associations": [
    "sftp-double-click",
    "sftp-default-view-mode",
    "sftp-show-hidden-files",
    "sftp-auto-sync",
    "sftp-follow-terminal-cwd",
    "sftp-auto-open-sidebar",
    "sftp-transfer-concurrency",
    "sftp-default-opener",
    "sftp-file-associations-list",
  ],
  ai: [
    "ai-providers",
    "ai-codex",
    "ai-claude",
    "ai-copilot",
    "ai-cursor",
    "ai-codebuddy",
    "ai-default-agent",
    "ai-chat-shortcuts-selection",
    "ai-tool-access-mode",
    "ai-terminal-execute",
    "ai-external-mcp",
    "ai-user-skills",
    "ai-quick-messages",
    "ai-web-search-enable",
    "ai-web-search-provider",
    "ai-safety-permission-mode",
    "ai-safety-response-timeout",
    "ai-safety-command-timeout",
    "ai-safety-blocklist",
    "ai-safety-grants",
  ],
  sync: [
    "sync-providers",
    "sync-auto-sync",
    "sync-strategy",
    "sync-local-backups",
    "sync-clear-local",
  ],
  system: [
    "system-update",
    "system-auto-update",
    "system-network-proxy-mode",
    "system-app-lock",
    "system-credentials",
    "system-temp-directory",
    "system-crash-logs",
    "system-startup-landing",
    "system-session-restore",
    "system-restore-terminal-cwd",
    "system-session-logs-enable",
    "system-ssh-deep-link",
    "system-jms-deep-link",
    "system-explorer-context-menu",
    "system-ssh-debug-logs",
    "system-global-hotkey-enabled",
    "system-global-hotkey-toggle",
    "system-close-to-tray",
  ],
} as const satisfies Record<SettingsPageId, readonly string[]>;

export type SettingsAnchorId = (typeof SETTINGS_ANCHORS)[SettingsPageId][number];

/** Reserved parity anchors that stay out of the preview UI until their feature is usable. */
export const SETTINGS_PREVIEW_HIDDEN_ANCHORS = [
  ...SETTINGS_ANCHORS.application,
  ...SETTINGS_ANCHORS.plugins,
  "appearance-window-opacity",
  "appearance-theme-color",
  "appearance-accent-mode",
  "appearance-app-icon",
  "appearance-vault-show-recent",
  "appearance-vault-select-before-connect",
  "appearance-vault-ungrouped-root",
  "appearance-vault-host-tree",
  "appearance-vault-auto-import-known-hosts",
  "appearance-custom-css",
  "terminal-font-smoothing",
  "terminal-emulation-type",
  "terminal-cursor-highlight-line",
  "terminal-alt-as-meta",
  "terminal-option-arrow-word-jump",
  "terminal-kitty-protocol",
  "terminal-auto-close-on-exit",
  "terminal-right-click",
  "terminal-copy-on-select",
  "terminal-normalize-text-on-copy",
  "terminal-middle-click",
  "terminal-word-separators",
  "terminal-bracketed-paste",
  "terminal-auto-upload-clipboard-image",
  "terminal-shift-enter-newline",
  "terminal-clear-wipes-scrollback",
  "terminal-dynamic-tab-title",
  "terminal-osc-notifications",
  "terminal-osc52-clipboard",
  "terminal-startup-command-delay",
  "terminal-side-panel-auto-open",
  "terminal-keyword-highlight",
  "terminal-verify-host-keys",
  "terminal-ssh-auto-reconnect",
  "terminal-keepalive-interval",
  "terminal-x11-display",
  "terminal-server-stats-show",
  "terminal-inline-images-enabled",
  "terminal-workspace-focus-style",
  "terminal-autocomplete-enabled",
  "terminal-password-prompt-assist",
  ...SETTINGS_ANCHORS.shortcuts,
  "sftp-double-click",
  "sftp-default-view-mode",
  "sftp-auto-sync",
  "sftp-follow-terminal-cwd",
  "sftp-transfer-concurrency",
  "sftp-default-opener",
  "sftp-file-associations-list",
  "ai-codex",
  "ai-claude",
  "ai-copilot",
  "ai-cursor",
  "ai-codebuddy",
  "ai-default-agent",
  "ai-chat-shortcuts-selection",
  "ai-external-mcp",
  "ai-user-skills",
  "ai-quick-messages",
  "ai-web-search-enable",
  "ai-web-search-provider",
  ...SETTINGS_ANCHORS.sync,
  "system-update",
  "system-auto-update",
  "system-network-proxy-mode",
  "system-app-lock",
  "system-credentials",
  "system-temp-directory",
  "system-crash-logs",
  "system-startup-landing",
  "system-restore-terminal-cwd",
  "system-session-logs-enable",
  "system-ssh-deep-link",
  "system-jms-deep-link",
  "system-explorer-context-menu",
  "system-ssh-debug-logs",
  "system-global-hotkey-enabled",
  "system-global-hotkey-toggle",
  "system-close-to-tray",
] as const satisfies readonly SettingsAnchorId[];

const SETTINGS_PREVIEW_HIDDEN_ANCHOR_SET = new Set<SettingsAnchorId>(
  SETTINGS_PREVIEW_HIDDEN_ANCHORS,
);

const LABEL_OVERRIDES: Partial<Record<SettingsAnchorId, string>> = {
  "application-check-updates": "Check for Updates",
  "application-report-problem": "Report a Problem",
  "application-community": "Community",
  "application-github": "GitHub",
  "application-whats-new": "What's New",
  "appearance-ui-font": "Interface Font",
  "appearance-window-opacity": "Window Opacity",
  "appearance-theme": "Color Mode",
  "appearance-theme-color": "Theme Color",
  "appearance-accent-mode": "Custom Accent Color",
  "appearance-app-icon": "App Icon",
  "appearance-vault-show-recent": "Show Recent Hosts",
  "appearance-vault-select-before-connect": "Select Host Before Connecting",
  "appearance-vault-ungrouped-root": "Only Ungrouped Hosts at Root",
  "appearance-vault-show-sftp-tab": "Show SFTP Tab",
  "appearance-vault-host-tree": "Show Host Tree Sidebar",
  "appearance-vault-auto-import-known-hosts": "Auto-import System Known Hosts",
  "appearance-custom-css": "Custom CSS",
  "terminal-theme-follow-app": "Follow App Theme",
  "terminal-font-cjk": "CJK Fallback Font",
  "terminal-font-weight-bold": "Bold Font Weight",
  "terminal-font-smoothing": "Font Smoothing",
  "terminal-font-line-padding": "Line Padding",
  "terminal-emulation-type": "Terminal Emulation",
  "terminal-cursor-highlight-line": "Highlight Cursor Line",
  "terminal-option-arrow-word-jump": "Option + Arrow Word Jump",
  "terminal-kitty-protocol": "Kitty Keyboard Protocol",
  "terminal-min-contrast": "Minimum Contrast",
  "terminal-auto-close-on-exit": "Auto-close on Exit",
  "terminal-copy-on-select": "Copy on Select",
  "terminal-normalize-text-on-copy": "Normalize Text on Copy",
  "terminal-word-separators": "Word Separators",
  "terminal-bracketed-paste": "Bracketed Paste",
  "terminal-auto-upload-clipboard-image": "Upload Clipboard Images",
  "terminal-clear-wipes-scrollback": "Clear Wipes Scrollback",
  "terminal-dynamic-tab-title": "Dynamic Tab Title",
  "terminal-osc-notifications": "OSC Notifications",
  "terminal-osc52-clipboard": "OSC 52 Clipboard",
  "terminal-scrollback-rows": "Scrollback Rows",
  "terminal-startup-command-delay": "Startup Command Delay",
  "terminal-side-panel-auto-open": "Auto-open Side Panel",
  "terminal-keyword-highlight": "Keyword Highlighting",
  "terminal-local-shell": "Local Shell",
  "terminal-verify-host-keys": "Verify Host Keys",
  "terminal-ssh-auto-reconnect": "SSH Auto-reconnect",
  "terminal-keepalive-interval": "Keepalive Interval",
  "terminal-x11-display": "X11 Display",
  "terminal-server-stats-show": "Show Server Stats",
  "terminal-inline-images-enabled": "Inline Images",
  "terminal-workspace-focus-style": "Workspace Focus Style",
  "terminal-autocomplete-enabled": "Autocomplete",
  "terminal-password-prompt-assist": "Password Prompt Assist",
  "shortcuts-disable-terminal-font-zoom": "Disable Terminal Font Zoom",
  "shortcuts-shell-only-tab-numbers": "Tab Numbers Only in Shell",
  "shortcuts-show-tab-number-badges": "Show Tab Number Badges",
  "shortcuts-section-custom": "Custom Shortcuts",
  "sftp-double-click": "Double-click Behavior",
  "sftp-default-view-mode": "Default View Mode",
  "sftp-show-hidden-files": "Show Hidden Files",
  "sftp-auto-sync": "Auto Sync",
  "sftp-follow-terminal-cwd": "Follow Terminal Directory",
  "sftp-auto-open-sidebar": "Auto-open SFTP Sidebar",
  "sftp-transfer-concurrency": "Transfer Concurrency",
  "sftp-default-opener": "Default Opener",
  "sftp-file-associations-list": "File Associations",
  "ai-chat-shortcuts-selection": "Selection Chat Shortcut",
  "ai-tool-access-mode": "Tool Access Mode",
  "ai-terminal-execute": "Terminal Execution Tool",
  "ai-external-mcp": "External MCP Servers",
  "ai-user-skills": "User Skills",
  "ai-quick-messages": "Quick Messages",
  "ai-web-search-enable": "Enable Web Search",
  "ai-web-search-provider": "Web Search Provider",
  "ai-safety-permission-mode": "Permission Mode",
  "ai-safety-response-timeout": "Provider Response Timeout",
  "ai-safety-command-timeout": "Command Output Capture Timeout",
  "ai-safety-blocklist": "Command Blocklist",
  "ai-safety-grants": "Permission Grants",
  "sync-auto-sync": "Automatic Sync",
  "sync-local-backups": "Local Backups",
  "sync-clear-local": "Clear Local Data",
  "system-auto-update": "Automatic Updates",
  "system-network-proxy-mode": "Network Proxy",
  "system-app-lock": "App Lock",
  "system-credentials": "Stored Credentials",
  "system-temp-directory": "Temporary Directory",
  "system-crash-logs": "Crash Logs",
  "system-startup-landing": "Startup Landing Page",
  "system-session-restore": "Restore Previous Session",
  "system-restore-terminal-cwd": "Restore Terminal Working Directory",
  "system-session-logs-enable": "Automatically Save Session Logs",
  "system-ssh-deep-link": "SSH Deep Links",
  "system-jms-deep-link": "JMS Deep Links",
  "system-explorer-context-menu": "Explorer Context Menu",
  "system-ssh-debug-logs": "SSH Debug Logs",
  "system-global-hotkey-enabled": "Global Hotkey",
  "system-global-hotkey-toggle": "Toggle Window Hotkey",
  "system-close-to-tray": "Close to System Tray",
};

const WORD_REPLACEMENTS: Record<string, string> = {
  ai: "AI",
  api: "API",
  cjk: "CJK",
  css: "CSS",
  jms: "JMS",
  mcp: "MCP",
  osc: "OSC",
  sftp: "SFTP",
  ssh: "SSH",
  x11: "X11",
};

export function settingsAnchorLabel(id: SettingsAnchorId): string {
  const override = LABEL_OVERRIDES[id];
  if (override) return override;
  return id
    .split("-")
    .slice(1)
    .map((word) => WORD_REPLACEMENTS[word] ?? `${word.charAt(0).toUpperCase()}${word.slice(1)}`)
    .join(" ");
}

function nestedTabForAnchor(id: SettingsAnchorId): SettingsNestedTab | undefined {
  if (id === "sync-providers") return "sync-providers";
  if (id.startsWith("sync-")) return "sync-status";
  if (!id.startsWith("ai-")) return undefined;
  if (["ai-providers"].includes(id)) return "ai-providers";
  if (["ai-codex", "ai-claude", "ai-copilot", "ai-cursor", "ai-codebuddy", "ai-default-agent"].includes(id)) {
    return "ai-agents";
  }
  if (id.startsWith("ai-web-search")) return "ai-search";
  if (id.startsWith("ai-safety")) return "ai-safety";
  return "ai-tools";
}

export type SettingsSearchEntry = {
  id: SettingsAnchorId;
  page: SettingsPageId;
  pageLabel: string;
  label: string;
  nestedTab?: SettingsNestedTab;
  searchText: string;
};

export const SETTINGS_SEARCH_CATALOG: readonly SettingsSearchEntry[] = SETTINGS_PAGES.flatMap((page) =>
  SETTINGS_ANCHORS[page.id]
    .filter((id) => !SETTINGS_PREVIEW_HIDDEN_ANCHOR_SET.has(id))
    .map((id) => {
    const label = settingsAnchorLabel(id);
    return {
      id,
      page: page.id,
      pageLabel: page.label,
      label,
      nestedTab: nestedTabForAnchor(id),
      searchText: `${label} ${page.label} ${id.replaceAll("-", " ")}`.toLocaleLowerCase(),
    };
  }),
);

export function findSettingsSearchHits(
  query: string,
  options: { limit?: number } = {},
): SettingsSearchEntry[] {
  const normalized = query.trim().toLocaleLowerCase();
  if (!normalized) return [];
  const terms = normalized.split(/\s+/).filter(Boolean);
  const scored = SETTINGS_SEARCH_CATALOG
    .filter((entry) => terms.every((term) => entry.searchText.includes(term)))
    .map((entry) => {
      const label = entry.label.toLocaleLowerCase();
      const score = label === normalized ? 0 : label.startsWith(normalized) ? 1 : entry.searchText.indexOf(normalized) >= 0 ? 2 : 3;
      return { entry, score };
    })
    .sort((left, right) => left.score - right.score || left.entry.label.localeCompare(right.entry.label));
  return scored.slice(0, options.limit ?? 12).map(({ entry }) => entry);
}

export type AiProviderProtocol = "openAiChatCompletions" | "anthropicMessages";

export type AiProviderProfile = {
  /** Stable profile identity. API-key custody is bound to this value. */
  id: string;
  /** Provider family/preset identity; multiple profiles may share it. */
  providerId: string;
  name: string;
  protocol: AiProviderProtocol;
  baseUrl: string;
  model: string;
  enabled: boolean;
};

export type RendererSafeSettings = {
  schemaVersion: 4;
  appearance: {
    uiLanguage: "system" | "en-US" | "zh-CN";
    uiFontFamilyId: string;
    windowOpacity: number;
    colorMode: "light" | "dark" | "system";
    lightUiThemeId: string;
    darkUiThemeId: string;
    accentMode: "theme" | "custom";
    customAccent: string;
    appIconVariant: string;
    showRecentHosts: boolean;
    hostClickBehavior: "connect" | "select";
    showOnlyUngroupedHostsInRoot: boolean;
    showSftpTab: boolean;
    showHostTreeSidebar: boolean;
    autoImportSystemKnownHosts: boolean;
    customCss: string;
  };
  terminal: {
    followAppTheme: boolean;
    themeId: string;
    fontFamilyId: string;
    fallbackFont: string;
    fontSize: number;
    fontWeight: number;
    boldFontWeight: number;
    fontSmoothing: "auto" | "antialiased" | "subpixel";
    linePadding: number;
    emulationType: "xterm-256color" | "xterm" | "vt100";
    cursorStyle: "block" | "underline" | "bar";
    cursorBlink: boolean;
    highlightCursorLine: boolean;
    altAsMeta: boolean;
    optionArrowWordJump: boolean;
    kittyKeyboardProtocol: boolean;
    minimumContrastRatio: number;
    copyOnSelect: boolean;
    bracketedPaste: boolean;
    scrollbackRows: number;
    autoCloseOnExit: boolean;
    dynamicTabTitle: boolean;
    localShell: string;
    localShellArgs: string[];
    localStartDir: string;
    verifyHostKeys: boolean;
    sshAutoReconnect: boolean;
    keepaliveIntervalSeconds: number;
    renderer: "auto" | "webgl" | "canvas" | "dom";
    inlineImagesEnabled: boolean;
    workspaceFocusStyle: "border" | "glow" | "none";
    autocompleteEnabled: boolean;
    passwordPromptAssist: "off" | "hint" | "auto";
  };
  shortcuts: {
    scheme: "disabled" | "mac" | "pc";
    disableTerminalFontZoom: boolean;
    shellOnlyTabNumberShortcuts: boolean;
    showTabNumberBadges: boolean;
  };
  sftp: {
    doubleClickBehavior: "open" | "transfer";
    defaultViewMode: "list" | "tree";
    showHiddenFiles: boolean;
    autoSync: boolean;
    followTerminalCwd: boolean;
    autoOpenSidebar: boolean;
    transferConcurrency: number;
    defaultOpener: "system" | "editor";
  };
  ai: {
    /** Non-secret provider profiles. API keys are never stored here. */
    providers: AiProviderProfile[];
    /** Exact enabled profile used by the built-in agent. */
    activeProviderId: string;
    /** Native agent tool policy. Legacy `ask`/`deny` values normalize below. */
    commandPermissionMode: "observer" | "confirm" | "auto";
    /** Seconds without provider headers/body data before native I/O times out. */
    responseIdleTimeoutSeconds: number;
  };
  system: {
    autoUpdateEnabled: boolean;
    networkProxyMode: "system" | "none" | "manual";
    startupLanding: "vault" | "terminal";
    restorePreviousSession: boolean;
    restoreTerminalCwd: boolean;
    sessionLogsEnabled: boolean;
    sshDeepLinkEnabled: boolean;
    jmsDeepLinkEnabled: boolean;
    explorerContextMenuEnabled: boolean;
    sshDebugLogsEnabled: boolean;
    globalHotkeyEnabled: boolean;
    toggleWindowHotkey: string;
    closeToTray: boolean;
  };
};

export type RendererSafeSettingsSnapshot = {
  settings: RendererSafeSettings;
  inventoryRevision: unknown;
};

export type ReplaceRendererSafeSettingsRequest = {
  settings: RendererSafeSettings;
  expectedInventoryRevision: unknown;
};

/**
 * Native implementations persist only this renderer-safe DTO. API keys,
 * passwords, app-lock material, sync credentials, proxy credentials and
 * keyring locators belong to separate one-shot/native custody commands.
 */
export interface RendererSafeSettingsAdapter {
  load(): Promise<RendererSafeSettingsSnapshot>;
  replace(request: ReplaceRendererSafeSettingsRequest): Promise<RendererSafeSettingsSnapshot>;
}

export type PlatformFamily = "mac" | "windows" | "linux" | "other";

export type AiCommandPermissionMode = RendererSafeSettings["ai"]["commandPermissionMode"];

export type AiProviderPreset = Readonly<{
  id: string;
  label: string;
  protocol: AiProviderProtocol;
  baseUrl: string;
  model: string;
}>;

/** Provider presets supported by the native client. */
export const AI_PROVIDER_PRESETS: readonly AiProviderPreset[] = Object.freeze([
  Object.freeze({ id: "openai-compatible", label: "OpenAI", protocol: "openAiChatCompletions", baseUrl: "https://api.openai.com/v1", model: "gpt-4o-mini" }),
  Object.freeze({ id: "anthropic", label: "Anthropic", protocol: "anthropicMessages", baseUrl: "https://api.anthropic.com/v1", model: "claude-sonnet-4-5" }),
  Object.freeze({ id: "google-ai", label: "Google AI", protocol: "openAiChatCompletions", baseUrl: "https://generativelanguage.googleapis.com/v1beta/openai", model: "gemini-2.5-flash" }),
  Object.freeze({ id: "openrouter", label: "OpenRouter", protocol: "openAiChatCompletions", baseUrl: "https://openrouter.ai/api/v1", model: "openai/gpt-4o-mini" }),
  Object.freeze({ id: "deepseek", label: "DeepSeek", protocol: "openAiChatCompletions", baseUrl: "https://api.deepseek.com/v1", model: "deepseek-chat" }),
  Object.freeze({ id: "qwen", label: "Qwen", protocol: "openAiChatCompletions", baseUrl: "https://dashscope.aliyuncs.com/compatible-mode/v1", model: "qwen-plus" }),
  Object.freeze({ id: "moonshot", label: "Moonshot", protocol: "openAiChatCompletions", baseUrl: "https://api.moonshot.cn/v1", model: "moonshot-v1-8k" }),
  Object.freeze({ id: "zhipu", label: "Zhipu AI", protocol: "openAiChatCompletions", baseUrl: "https://open.bigmodel.cn/api/paas/v4", model: "glm-4-flash" }),
  Object.freeze({ id: "doubao", label: "Doubao", protocol: "openAiChatCompletions", baseUrl: "https://ark.cn-beijing.volces.com/api/v3", model: "doubao-1-5-pro-32k-250115" }),
  Object.freeze({ id: "xiaomi-mimo", label: "Xiaomi MiMo", protocol: "openAiChatCompletions", baseUrl: "https://api.xiaomimimo.com/v1", model: "mimo-v2-flash" }),
  Object.freeze({ id: "siliconflow", label: "SiliconFlow", protocol: "openAiChatCompletions", baseUrl: "https://api.siliconflow.cn/v1", model: "deepseek-ai/DeepSeek-V3" }),
  Object.freeze({ id: "ollama", label: "Ollama", protocol: "openAiChatCompletions", baseUrl: "http://127.0.0.1:11434/v1", model: "qwen2.5-coder" }),
  Object.freeze({ id: "lm-studio", label: "LM Studio", protocol: "openAiChatCompletions", baseUrl: "http://127.0.0.1:1234/v1", model: "local-model" }),
  Object.freeze({ id: "custom", label: "Custom", protocol: "openAiChatCompletions", baseUrl: "https://api.example.com/v1", model: "model-name" }),
]);

export const AI_PROVIDER_PROFILE_LIMIT = 32;
export const AI_RESPONSE_IDLE_TIMEOUT_DEFAULT_SECONDS = 120;
export const AI_RESPONSE_IDLE_TIMEOUT_MIN_SECONDS = 1;
export const AI_RESPONSE_IDLE_TIMEOUT_MAX_SECONDS = 86_400;

export function createAiProviderProfile(
  preset: AiProviderPreset,
  id: string,
): AiProviderProfile {
  return {
    id,
    providerId: preset.id,
    name: preset.label,
    protocol: preset.protocol,
    baseUrl: preset.baseUrl,
    model: preset.model,
    enabled: true,
  };
}

export function detectSettingsPlatform(): PlatformFamily {
  if (typeof navigator === "undefined") return "other";
  const platform = `${navigator.platform ?? ""} ${navigator.userAgent ?? ""}`;
  if (/Mac|iPhone|iPad/i.test(platform)) return "mac";
  if (/Win/i.test(platform)) return "windows";
  if (/Linux/i.test(platform)) return "linux";
  return "other";
}

export function createDefaultRendererSafeSettings(platform: PlatformFamily = detectSettingsPlatform()): RendererSafeSettings {
  const defaultAiProfile = createAiProviderProfile(AI_PROVIDER_PRESETS[0], "openai-compatible");
  return {
    schemaVersion: 4,
    appearance: {
      // Keep first-run settings deterministic and accessible; Chinese is the
      // product's canonical fallback locale instead of inheriting the OS.
      uiLanguage: "zh-CN",
      // Canonical definition and the stack it resolves to live in
      // useUiFontFamily.ts; kept literal here so this module stays
      // dependency-free for the Node-based contract tests.
      uiFontFamilyId: "inter",
      windowOpacity: 1,
      colorMode: "system",
      lightUiThemeId: "snow",
      darkUiThemeId: "midnight",
      accentMode: "theme",
      customAccent: "221.2 83.2% 53.3%",
      appIconVariant: "default",
      showRecentHosts: true,
      hostClickBehavior: "connect",
      showOnlyUngroupedHostsInRoot: false,
      showSftpTab: true,
      showHostTreeSidebar: true,
      autoImportSystemKnownHosts: false,
      customCss: "",
    },
    terminal: {
      followAppTheme: true,
      themeId: "netcatty-dark",
      fontFamilyId: "menlo",
      fallbackFont: "",
      fontSize: 14,
      fontWeight: 400,
      boldFontWeight: 700,
      fontSmoothing: "auto",
      linePadding: 0,
      emulationType: "xterm-256color",
      cursorStyle: "block",
      cursorBlink: true,
      highlightCursorLine: false,
      altAsMeta: platform === "mac",
      optionArrowWordJump: platform === "mac",
      kittyKeyboardProtocol: false,
      minimumContrastRatio: 1,
      copyOnSelect: false,
      bracketedPaste: true,
      scrollbackRows: 10_000,
      autoCloseOnExit: false,
      dynamicTabTitle: true,
      localShell: "",
      localShellArgs: [],
      localStartDir: "",
      verifyHostKeys: true,
      sshAutoReconnect: false,
      keepaliveIntervalSeconds: 30,
      renderer: "auto",
      inlineImagesEnabled: true,
      workspaceFocusStyle: "border",
      autocompleteEnabled: true,
      passwordPromptAssist: "hint",
    },
    shortcuts: {
      scheme: platform === "mac" ? "mac" : "pc",
      disableTerminalFontZoom: false,
      shellOnlyTabNumberShortcuts: false,
      showTabNumberBadges: true,
    },
    sftp: {
      doubleClickBehavior: "open",
      defaultViewMode: "list",
      showHiddenFiles: false,
      autoSync: false,
      followTerminalCwd: false,
      autoOpenSidebar: false,
      transferConcurrency: 2,
      defaultOpener: "system",
    },
    ai: {
      providers: [defaultAiProfile],
      activeProviderId: defaultAiProfile.id,
      commandPermissionMode: "confirm",
      responseIdleTimeoutSeconds: AI_RESPONSE_IDLE_TIMEOUT_DEFAULT_SECONDS,
    },
    system: {
      autoUpdateEnabled: true,
      networkProxyMode: "system",
      startupLanding: "vault",
      restorePreviousSession: true,
      restoreTerminalCwd: true,
      sessionLogsEnabled: false,
      sshDeepLinkEnabled: true,
      jmsDeepLinkEnabled: false,
      explorerContextMenuEnabled: platform === "windows",
      sshDebugLogsEnabled: false,
      globalHotkeyEnabled: true,
      toggleWindowHotkey: platform === "mac" ? "⌃ + `" : "Ctrl + `",
      closeToTray: true,
    },
  };
}

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function bool(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function text(value: unknown, fallback: string, maxLength = 256): string {
  return typeof value === "string" && value.length <= maxLength ? value : fallback;
}

export const LOCAL_SHELL_LIMITS = Object.freeze({
  commandBytes: 32 * 1_024,
  argumentCount: 32,
  argumentBytes: 4 * 1_024,
  startDirectoryBytes: 32 * 1_024,
});

const utf8Length = (value: string): number => new TextEncoder().encode(value).byteLength;

const isSafeNativeText = (
  value: unknown,
  maximumBytes: number,
  allowEmpty: boolean,
): value is string => typeof value === "string"
  && (allowEmpty || value.length > 0)
  && utf8Length(value) <= maximumBytes
  && !/[\0\r\n]/.test(value);

export const isRendererSafeLocalShell = (value: unknown): value is string =>
  isSafeNativeText(value, LOCAL_SHELL_LIMITS.commandBytes, false);

export const isRendererSafeLocalStartDir = (value: unknown): value is string =>
  isSafeNativeText(value, LOCAL_SHELL_LIMITS.startDirectoryBytes, true);

export const isRendererSafeLocalShellArgs = (value: unknown): value is string[] =>
  Array.isArray(value)
  && value.length <= LOCAL_SHELL_LIMITS.argumentCount
  && value.every((argument, index) => Object.hasOwn(value, index)
    && isSafeNativeText(argument, LOCAL_SHELL_LIMITS.argumentBytes, true));

function nativeText(value: unknown, fallback: string, maximumBytes: number): string {
  return isSafeNativeText(value, maximumBytes, true) ? value : fallback;
}

function requiredNativeText(value: unknown, fallback: string, maximumBytes: number): string {
  return isSafeNativeText(value, maximumBytes, false) ? value : fallback;
}

function aiProviderId(value: unknown, fallback: string): string {
  return typeof value === "string"
    && utf8Length(value) <= 128
    && /^[a-z0-9][a-z0-9._-]*$/.test(value)
    ? value
    : fallback;
}

function normalizeAiProviderProfiles(
  ai: Record<string, unknown>,
  fallback: AiProviderProfile,
): { providers: AiProviderProfile[]; activeProviderId: string } {
  let candidates: unknown[] = Array.isArray(ai.providers)
    ? ai.providers.slice(0, AI_PROVIDER_PROFILE_LIMIT)
    : [];

  // Browser previews and defensive callers may still hand us the former v2
  // single-provider shape. Native persistence performs the same migration.
  if (candidates.length === 0 && typeof ai.providerId === "string") {
    const providerId = aiProviderId(ai.providerId, fallback.providerId);
    const preset = AI_PROVIDER_PRESETS.find((candidate) => candidate.id === providerId);
    candidates = [{
      id: providerId,
      providerId,
      name: preset?.label ?? providerId,
      protocol: preset?.protocol ?? "openAiChatCompletions",
      baseUrl: ai.baseUrl,
      model: ai.model,
      enabled: true,
    }];
  }

  const seen = new Set<string>();
  const providers: AiProviderProfile[] = [];
  for (const candidate of candidates) {
    const profile = record(candidate);
    const id = aiProviderId(profile.id, "");
    const providerId = aiProviderId(profile.providerId, "");
    if (!id || !providerId || seen.has(id)) continue;
    const preset = AI_PROVIDER_PRESETS.find((entry) => entry.id === providerId);
    seen.add(id);
    providers.push({
      id,
      providerId,
      name: requiredNativeText(profile.name, preset?.label ?? providerId, 256),
      protocol: oneOf(
        profile.protocol,
        ["openAiChatCompletions", "anthropicMessages"] as const,
        preset?.protocol ?? "openAiChatCompletions",
      ),
      baseUrl: requiredNativeText(profile.baseUrl, preset?.baseUrl ?? fallback.baseUrl, 2_048),
      model: requiredNativeText(profile.model, preset?.model ?? fallback.model, 256),
      enabled: bool(profile.enabled, true),
    });
  }

  if (providers.length === 0) providers.push(structuredClone(fallback));
  let activeProviderId = aiProviderId(ai.activeProviderId, "");
  if (!providers.some((profile) => profile.id === activeProviderId && profile.enabled)) {
    const firstEnabled = providers.find((profile) => profile.enabled);
    if (firstEnabled) activeProviderId = firstEnabled.id;
    else {
      providers[0].enabled = true;
      activeProviderId = providers[0].id;
    }
  }
  return { providers, activeProviderId };
}

function localShellArgs(value: unknown, fallback: readonly string[]): string[] {
  return isRendererSafeLocalShellArgs(value) ? [...value] : [...fallback];
}

/**
 * Splits the editable launch-arguments field without involving a command
 * shell. Backslashes remain literal so Windows paths survive, while either
 * quote style can group whitespace. The returned values are later passed as
 * direct argv entries by the native PTY runtime.
 */
export function parseLocalShellArgs(input: string): string[] {
  const args: string[] = [];
  let current = "";
  let inToken = false;
  let quote: "\"" | "'" | null = null;

  for (let index = 0; index < input.length; index += 1) {
    const character = input[index];
    if (quote) {
      if (character === quote) quote = null;
      else current += character;
      continue;
    }
    if (character === "\\" && input[index + 1] === "'") {
      current += "'";
      inToken = true;
      index += 1;
      continue;
    }
    if (character === "\"" || character === "'") {
      quote = character;
      inToken = true;
      continue;
    }
    if (/\s/.test(character)) {
      if (inToken) {
        args.push(current);
        current = "";
        inToken = false;
      }
      continue;
    }
    current += character;
    inToken = true;
  }
  if (inToken) args.push(current);
  return args;
}

export function formatLocalShellArgs(args: readonly string[]): string {
  return args.map((argument) => {
    if (argument === "") return "''";
    if (!/[\s\"']/.test(argument)) return argument;
    return `'${argument.replaceAll("'", "'\\''")}'`;
  }).join(" ");
}

function numberInRange(value: unknown, fallback: number, min: number, max: number): number {
  return typeof value === "number" && Number.isFinite(value)
    ? Math.min(max, Math.max(min, value))
    : fallback;
}

function integerInRange(value: unknown, fallback: number, min: number, max: number): number {
  return Math.round(numberInRange(value, fallback, min, max));
}

function oneOf<const T extends readonly string[]>(value: unknown, values: T, fallback: T[number]): T[number] {
  return typeof value === "string" && values.includes(value) ? value as T[number] : fallback;
}

export function normalizeRendererSafeSettings(
  value: unknown,
  platform: PlatformFamily = detectSettingsPlatform(),
): RendererSafeSettings {
  const defaults = createDefaultRendererSafeSettings(platform);
  const root = record(value);
  const appearance = record(root.appearance);
  const terminal = record(root.terminal);
  const shortcuts = record(root.shortcuts);
  const sftp = record(root.sftp);
  const ai = record(root.ai);
  const system = record(root.system);
  const normalizedAi = normalizeAiProviderProfiles(ai, defaults.ai.providers[0]);
  return {
    schemaVersion: 4,
    appearance: {
      uiLanguage: oneOf(appearance.uiLanguage, ["system", "en-US", "zh-CN"] as const, defaults.appearance.uiLanguage),
      uiFontFamilyId: text(appearance.uiFontFamilyId, defaults.appearance.uiFontFamilyId, 80),
      windowOpacity: numberInRange(appearance.windowOpacity, defaults.appearance.windowOpacity, 0.5, 1),
      colorMode: oneOf(appearance.colorMode, ["light", "dark", "system"] as const, defaults.appearance.colorMode),
      lightUiThemeId: text(appearance.lightUiThemeId, defaults.appearance.lightUiThemeId, 80),
      darkUiThemeId: text(appearance.darkUiThemeId, defaults.appearance.darkUiThemeId, 80),
      accentMode: oneOf(appearance.accentMode, ["theme", "custom"] as const, defaults.appearance.accentMode),
      customAccent: text(appearance.customAccent, defaults.appearance.customAccent, 80),
      appIconVariant: text(appearance.appIconVariant, defaults.appearance.appIconVariant, 80),
      showRecentHosts: bool(appearance.showRecentHosts, defaults.appearance.showRecentHosts),
      hostClickBehavior: oneOf(appearance.hostClickBehavior, ["connect", "select"] as const, defaults.appearance.hostClickBehavior),
      showOnlyUngroupedHostsInRoot: bool(appearance.showOnlyUngroupedHostsInRoot, defaults.appearance.showOnlyUngroupedHostsInRoot),
      showSftpTab: bool(appearance.showSftpTab, defaults.appearance.showSftpTab),
      showHostTreeSidebar: bool(appearance.showHostTreeSidebar, defaults.appearance.showHostTreeSidebar),
      autoImportSystemKnownHosts: bool(appearance.autoImportSystemKnownHosts, defaults.appearance.autoImportSystemKnownHosts),
      customCss: text(appearance.customCss, defaults.appearance.customCss, 64 * 1024),
    },
    terminal: {
      followAppTheme: bool(terminal.followAppTheme, defaults.terminal.followAppTheme),
      themeId: text(terminal.themeId, defaults.terminal.themeId, 80),
      fontFamilyId: text(terminal.fontFamilyId, defaults.terminal.fontFamilyId, 120),
      fallbackFont: text(terminal.fallbackFont, defaults.terminal.fallbackFont, 120),
      fontSize: numberInRange(terminal.fontSize, defaults.terminal.fontSize, 6, 72),
      fontWeight: numberInRange(terminal.fontWeight, defaults.terminal.fontWeight, 100, 900),
      boldFontWeight: numberInRange(terminal.boldFontWeight, defaults.terminal.boldFontWeight, 100, 900),
      fontSmoothing: oneOf(terminal.fontSmoothing, ["auto", "antialiased", "subpixel"] as const, defaults.terminal.fontSmoothing),
      linePadding: numberInRange(terminal.linePadding, defaults.terminal.linePadding, 0, 12),
      emulationType: oneOf(terminal.emulationType, ["xterm-256color", "xterm", "vt100"] as const, defaults.terminal.emulationType),
      cursorStyle: oneOf(terminal.cursorStyle, ["block", "underline", "bar"] as const, defaults.terminal.cursorStyle),
      cursorBlink: bool(terminal.cursorBlink, defaults.terminal.cursorBlink),
      highlightCursorLine: bool(terminal.highlightCursorLine, defaults.terminal.highlightCursorLine),
      altAsMeta: bool(terminal.altAsMeta, defaults.terminal.altAsMeta),
      optionArrowWordJump: bool(terminal.optionArrowWordJump, defaults.terminal.optionArrowWordJump),
      kittyKeyboardProtocol: bool(terminal.kittyKeyboardProtocol, defaults.terminal.kittyKeyboardProtocol),
      minimumContrastRatio: numberInRange(terminal.minimumContrastRatio, defaults.terminal.minimumContrastRatio, 1, 21),
      copyOnSelect: bool(terminal.copyOnSelect, defaults.terminal.copyOnSelect),
      bracketedPaste: bool(terminal.bracketedPaste, defaults.terminal.bracketedPaste),
      scrollbackRows: Math.round(numberInRange(terminal.scrollbackRows, defaults.terminal.scrollbackRows, 100, 1_000_000)),
      autoCloseOnExit: bool(terminal.autoCloseOnExit, defaults.terminal.autoCloseOnExit),
      dynamicTabTitle: bool(terminal.dynamicTabTitle, defaults.terminal.dynamicTabTitle),
      localShell: nativeText(terminal.localShell, defaults.terminal.localShell, LOCAL_SHELL_LIMITS.commandBytes),
      localShellArgs: localShellArgs(terminal.localShellArgs, defaults.terminal.localShellArgs),
      localStartDir: nativeText(terminal.localStartDir, defaults.terminal.localStartDir, LOCAL_SHELL_LIMITS.startDirectoryBytes),
      verifyHostKeys: bool(terminal.verifyHostKeys, defaults.terminal.verifyHostKeys),
      sshAutoReconnect: bool(terminal.sshAutoReconnect, defaults.terminal.sshAutoReconnect),
      keepaliveIntervalSeconds: Math.round(numberInRange(terminal.keepaliveIntervalSeconds, defaults.terminal.keepaliveIntervalSeconds, 0, 3_600)),
      renderer: oneOf(terminal.renderer, ["auto", "webgl", "canvas", "dom"] as const, defaults.terminal.renderer),
      inlineImagesEnabled: bool(terminal.inlineImagesEnabled, defaults.terminal.inlineImagesEnabled),
      workspaceFocusStyle: oneOf(terminal.workspaceFocusStyle, ["border", "glow", "none"] as const, defaults.terminal.workspaceFocusStyle),
      autocompleteEnabled: bool(terminal.autocompleteEnabled, defaults.terminal.autocompleteEnabled),
      passwordPromptAssist: oneOf(terminal.passwordPromptAssist, ["off", "hint", "auto"] as const, defaults.terminal.passwordPromptAssist),
    },
    shortcuts: {
      scheme: oneOf(shortcuts.scheme, ["disabled", "mac", "pc"] as const, defaults.shortcuts.scheme),
      disableTerminalFontZoom: bool(shortcuts.disableTerminalFontZoom, defaults.shortcuts.disableTerminalFontZoom),
      shellOnlyTabNumberShortcuts: bool(shortcuts.shellOnlyTabNumberShortcuts, defaults.shortcuts.shellOnlyTabNumberShortcuts),
      showTabNumberBadges: bool(shortcuts.showTabNumberBadges, defaults.shortcuts.showTabNumberBadges),
    },
    sftp: {
      doubleClickBehavior: oneOf(sftp.doubleClickBehavior, ["open", "transfer"] as const, defaults.sftp.doubleClickBehavior),
      defaultViewMode: oneOf(sftp.defaultViewMode, ["list", "tree"] as const, defaults.sftp.defaultViewMode),
      showHiddenFiles: bool(sftp.showHiddenFiles, defaults.sftp.showHiddenFiles),
      autoSync: bool(sftp.autoSync, defaults.sftp.autoSync),
      followTerminalCwd: bool(sftp.followTerminalCwd, defaults.sftp.followTerminalCwd),
      autoOpenSidebar: bool(sftp.autoOpenSidebar, defaults.sftp.autoOpenSidebar),
      transferConcurrency: Math.round(numberInRange(sftp.transferConcurrency, defaults.sftp.transferConcurrency, 1, 16)),
      defaultOpener: oneOf(sftp.defaultOpener, ["system", "editor"] as const, defaults.sftp.defaultOpener),
    },
    ai: {
      providers: normalizedAi.providers,
      activeProviderId: normalizedAi.activeProviderId,
      commandPermissionMode: ai.commandPermissionMode === "deny"
        ? "observer"
        : ai.commandPermissionMode === "ask"
          ? "confirm"
          : oneOf(
              ai.commandPermissionMode,
              ["observer", "confirm", "auto"] as const,
              defaults.ai.commandPermissionMode,
            ),
      responseIdleTimeoutSeconds: integerInRange(
        ai.responseIdleTimeoutSeconds,
        defaults.ai.responseIdleTimeoutSeconds,
        AI_RESPONSE_IDLE_TIMEOUT_MIN_SECONDS,
        AI_RESPONSE_IDLE_TIMEOUT_MAX_SECONDS,
      ),
    },
    system: {
      autoUpdateEnabled: bool(system.autoUpdateEnabled, defaults.system.autoUpdateEnabled),
      networkProxyMode: oneOf(system.networkProxyMode, ["system", "none", "manual"] as const, defaults.system.networkProxyMode),
      startupLanding: oneOf(system.startupLanding, ["vault", "terminal"] as const, defaults.system.startupLanding),
      restorePreviousSession: bool(system.restorePreviousSession, defaults.system.restorePreviousSession),
      restoreTerminalCwd: bool(system.restoreTerminalCwd, defaults.system.restoreTerminalCwd),
      sessionLogsEnabled: bool(system.sessionLogsEnabled, defaults.system.sessionLogsEnabled),
      sshDeepLinkEnabled: bool(system.sshDeepLinkEnabled, defaults.system.sshDeepLinkEnabled),
      jmsDeepLinkEnabled: bool(system.jmsDeepLinkEnabled, defaults.system.jmsDeepLinkEnabled),
      explorerContextMenuEnabled: bool(system.explorerContextMenuEnabled, defaults.system.explorerContextMenuEnabled),
      sshDebugLogsEnabled: bool(system.sshDebugLogsEnabled, defaults.system.sshDebugLogsEnabled),
      globalHotkeyEnabled: bool(system.globalHotkeyEnabled, defaults.system.globalHotkeyEnabled),
      toggleWindowHotkey: text(system.toggleWindowHotkey, defaults.system.toggleWindowHotkey, 80),
      closeToTray: bool(system.closeToTray, defaults.system.closeToTray),
    },
  };
}

export function updateRendererSafeSettings(
  current: RendererSafeSettings,
  updater: (draft: RendererSafeSettings) => void,
): RendererSafeSettings {
  const draft = structuredClone(current);
  updater(draft);
  return normalizeRendererSafeSettings(draft);
}

export function rendererSafeSettingsJson(settings: RendererSafeSettings): string {
  return JSON.stringify(normalizeRendererSafeSettings(settings));
}
