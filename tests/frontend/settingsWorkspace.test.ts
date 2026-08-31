import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { createTranslator, type MessageKey } from "../../src/i18n.ts";
import {
  AI_PROVIDER_PRESETS,
  AI_RESPONSE_IDLE_TIMEOUT_DEFAULT_SECONDS,
  AI_RESPONSE_IDLE_TIMEOUT_MAX_SECONDS,
  AI_RESPONSE_IDLE_TIMEOUT_MIN_SECONDS,
  createAiProviderProfile,
  createDefaultRendererSafeSettings,
  findSettingsSearchHits,
  formatLocalShellArgs,
  normalizeRendererSafeSettings,
  parseLocalShellArgs,
  rendererSafeSettingsJson,
  SETTINGS_ANCHORS,
  SETTINGS_PAGES,
  SETTINGS_PREVIEW_HIDDEN_ANCHORS,
  SETTINGS_PUBLIC_HIDDEN_PAGE_IDS,
  SETTINGS_PUBLIC_PAGES,
  SETTINGS_SEARCH_CATALOG,
  type SettingsPageId,
} from "../../src/settingsUi.ts";

const componentUrl = new URL("../../src/SettingsWorkspace.tsx", import.meta.url);
const modelUrl = new URL("../../src/settingsUi.ts", import.meta.url);
const apiUrl = new URL("../../src/settingsApi.ts", import.meta.url);
const routeUrl = new URL("../../src/SettingsRoute.tsx", import.meta.url);
const stylesUrl = new URL("../../src/settings.css", import.meta.url);
const skinUrl = new URL("../../src/settingsSkin.css", import.meta.url);

const componentSlice = (source: string, startMarker: string, endMarker: string): string => {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.notEqual(start, -1, `missing source marker: ${startMarker}`);
  assert.notEqual(end, -1, `missing source marker: ${endMarker}`);
  return source.slice(start, end);
};

const topLevelConstContaining = (source: string, markerIndex: number): string => {
  assert.ok(markerIndex >= 0, "missing async setup-flow marker");
  const start = source.lastIndexOf("\n  const ", markerIndex);
  const end = source.indexOf("\n  const ", markerIndex + 1);
  assert.notEqual(start, -1, "setup flow must be a component-level declaration");
  return source.slice(start, end === -1 ? source.length : end);
};

const EXPECTED_ANCHORS: Record<SettingsPageId, readonly string[]> = {
  application: ["application-check-updates", "application-report-problem", "application-community", "application-github", "application-whats-new"],
  plugins: ["plugins-root"],
  appearance: ["appearance-language", "appearance-ui-font", "appearance-window-opacity", "appearance-theme", "appearance-theme-color", "appearance-accent-mode", "appearance-app-icon", "appearance-vault-show-recent", "appearance-vault-select-before-connect", "appearance-vault-ungrouped-root", "appearance-vault-show-sftp-tab", "appearance-vault-host-tree", "appearance-vault-auto-import-known-hosts", "appearance-custom-css"],
  terminal: ["terminal-theme-follow-app", "terminal-font-family", "terminal-font-cjk", "terminal-font-size", "terminal-font-weight", "terminal-font-weight-bold", "terminal-font-smoothing", "terminal-font-line-padding", "terminal-emulation-type", "terminal-cursor-style", "terminal-cursor-blink", "terminal-cursor-highlight-line", "terminal-alt-as-meta", "terminal-option-arrow-word-jump", "terminal-kitty-protocol", "terminal-min-contrast", "terminal-auto-close-on-exit", "terminal-right-click", "terminal-copy-on-select", "terminal-normalize-text-on-copy", "terminal-middle-click", "terminal-word-separators", "terminal-bracketed-paste", "terminal-auto-upload-clipboard-image", "terminal-shift-enter-newline", "terminal-clear-wipes-scrollback", "terminal-dynamic-tab-title", "terminal-osc-notifications", "terminal-osc52-clipboard", "terminal-scrollback-rows", "terminal-startup-command-delay", "terminal-side-panel-auto-open", "terminal-keyword-highlight", "terminal-local-shell", "terminal-verify-host-keys", "terminal-ssh-auto-reconnect", "terminal-keepalive-interval", "terminal-x11-display", "terminal-server-stats-show", "terminal-renderer", "terminal-inline-images-enabled", "terminal-workspace-focus-style", "terminal-autocomplete-enabled", "terminal-password-prompt-assist"],
  shortcuts: ["shortcuts-scheme", "shortcuts-disable-terminal-font-zoom", "shortcuts-shell-only-tab-numbers", "shortcuts-show-tab-number-badges", "shortcuts-section-custom"],
  "file-associations": ["sftp-double-click", "sftp-default-view-mode", "sftp-show-hidden-files", "sftp-auto-sync", "sftp-follow-terminal-cwd", "sftp-auto-open-sidebar", "sftp-transfer-concurrency", "sftp-default-opener", "sftp-file-associations-list"],
  ai: ["ai-providers", "ai-codex", "ai-claude", "ai-copilot", "ai-cursor", "ai-codebuddy", "ai-default-agent", "ai-chat-shortcuts-selection", "ai-tool-access-mode", "ai-terminal-execute", "ai-external-mcp", "ai-user-skills", "ai-quick-messages", "ai-web-search-enable", "ai-web-search-provider", "ai-safety-permission-mode", "ai-safety-response-timeout", "ai-safety-command-timeout", "ai-safety-blocklist", "ai-safety-grants"],
  sync: ["sync-providers", "sync-auto-sync", "sync-strategy", "sync-local-backups", "sync-clear-local"],
  system: ["system-update", "system-auto-update", "system-network-proxy-mode", "system-app-lock", "system-credentials", "system-temp-directory", "system-crash-logs", "system-startup-landing", "system-session-restore", "system-restore-terminal-cwd", "system-session-logs-enable", "system-ssh-deep-link", "system-jms-deep-link", "system-explorer-context-menu", "system-ssh-debug-logs", "system-global-hotkey-enabled", "system-global-hotkey-toggle", "system-close-to-tray"],
};

test("Settings preserves imported page metadata while exposing only implemented public pages and anchors", () => {
  assert.deepEqual(SETTINGS_PAGES.map((page) => page.id), ["application", "plugins", "appearance", "terminal", "shortcuts", "file-associations", "ai", "sync", "system"]);
  assert.equal(SETTINGS_PAGES.find((page) => page.id === "plugins")?.conditional, "plugins");
  assert.deepEqual(SETTINGS_PUBLIC_HIDDEN_PAGE_IDS, ["plugins", "shortcuts", "sync"]);
  assert.deepEqual(SETTINGS_PUBLIC_PAGES.map((page) => page.id), ["application", "appearance", "terminal", "file-associations", "ai", "system"]);
  assert.deepEqual(SETTINGS_ANCHORS, EXPECTED_ANCHORS);

  const ids = SETTINGS_SEARCH_CATALOG.map((entry) => entry.id);
  const hidden = new Set<string>(SETTINGS_PREVIEW_HIDDEN_ANCHORS);
  const expected = Object.values(EXPECTED_ANCHORS).flat().filter((id) => !hidden.has(id));
  assert.equal(new Set(ids).size, ids.length);
  assert.deepEqual(new Set(ids), new Set(expected));
});

test("Settings labels and search anchors are complete in both supported locales", async () => {
  const component = await readFile(componentUrl, "utf8");
  const english = createTranslator("en-US");
  const chinese = createTranslator("zh-CN");
  const brandOnlyChineseAnchors = new Set([
    "application-github",
    "ai-codex",
    "ai-claude",
    "ai-copilot",
    "ai-cursor",
    "ai-codebuddy",
  ]);

  assert.match(component, /SettingsTranslationContext\.Provider value=\{t\}/);
  assert.match(component, /label \?\? settingsAnchorText\(t, id\)/);
  assert.match(component, /findLocalizedSettingsSearchHits\(searchQuery, t\)/);
  assert.doesNotMatch(component, /<SectionTitle>(?!SFTP<)[^<{]+<\/SectionTitle>/);
  assert.doesNotMatch(component, /\b(?:aria-label|placeholder|description|label)="[^"]+"/);

  for (const id of Object.values(SETTINGS_ANCHORS).flat()) {
    const key = `settings.anchor.${id}` as MessageKey;
    const englishLabel = english(key);
    const chineseLabel = chinese(key);
    assert.notEqual(englishLabel, key, `missing English Settings anchor: ${key}`);
    assert.notEqual(chineseLabel, key, `missing Chinese Settings anchor: ${key}`);
    assert.doesNotMatch(englishLabel, /[一-龥]/u, `English Settings anchor contains Chinese: ${key}`);
    if (!brandOnlyChineseAnchors.has(id)) {
      assert.match(chineseLabel, /[一-龥]/u, `Chinese Settings anchor is not localized: ${key}`);
    }
  }
});

test("search hides unfinished AI surfaces and routes usable nested results", () => {
  assert.equal(findSettingsSearchHits("Claude").length, 0);
  assert.equal(findSettingsSearchHits("terminal execution")[0]?.nestedTab, "ai-tools");
  assert.equal(findSettingsSearchHits("web search provider").length, 0);
  assert.equal(findSettingsSearchHits("MCP").length, 0);
  assert.equal(findSettingsSearchHits("user skills").length, 0);
  assert.equal(findSettingsSearchHits("permission grants")[0]?.nestedTab, "ai-safety");
  assert.equal(findSettingsSearchHits("local backups").length, 0);
  assert.equal(findSettingsSearchHits("plugins").length, 0);
});

test("public Settings cannot navigate to skeleton pages or unsupported operating-system controls", async () => {
  const [component, route] = await Promise.all([
    readFile(componentUrl, "utf8"),
    readFile(routeUrl, "utf8"),
  ]);

  for (const query of [
    "custom shortcuts",
    "file associations",
    "SSH deep links",
    "app lock",
    "global hotkey",
    "close to system tray",
    "automatic updates",
  ]) {
    assert.equal(findSettingsSearchHits(query).length, 0, `${query} must not appear in public search`);
  }

  assert.doesNotMatch(component, /function (?:NestedSkeletonPage|PluginsPage|ShortcutsPage)\b/);
  assert.doesNotMatch(component, /settings-placeholder/);
  assert.doesNotMatch(component, /id="(?:system-ssh-deep-link|system-app-lock|system-global-hotkey-enabled|system-global-hotkey-toggle|system-close-to-tray)"/);
  assert.match(component, /id="system-session-restore"/);
  assert.match(component, /onNativeAction \? <div className="settings-action-list">/);
  assert.doesNotMatch(route, /onNativeAction=/);
});

test("renderer-safe defaults retain confirmed legacy values and platform gates", () => {
  const windows = createDefaultRendererSafeSettings("windows");
  assert.equal(windows.appearance.colorMode, "system");
  assert.equal(windows.appearance.windowOpacity, 1);
  assert.equal(windows.appearance.lightUiThemeId, "snow");
  assert.equal(windows.appearance.darkUiThemeId, "midnight");
  assert.equal(windows.appearance.customAccent, "221.2 83.2% 53.3%");
  assert.equal(windows.terminal.themeId, "netcatty-dark");
  assert.equal(windows.terminal.followAppTheme, true);
  assert.equal(windows.terminal.fontFamilyId, "menlo");
  assert.equal(windows.terminal.fontSize, 14);
  assert.equal(windows.terminal.localShell, "");
  assert.deepEqual(windows.terminal.localShellArgs, []);
  assert.equal(windows.terminal.localStartDir, "");
  assert.equal(windows.shortcuts.scheme, "pc");
  assert.equal(windows.sftp.doubleClickBehavior, "open");
  assert.equal(windows.sftp.defaultViewMode, "list");
  assert.deepEqual(windows.ai, {
    providers: [{
      id: "openai-compatible",
      providerId: "openai-compatible",
      name: "OpenAI",
      protocol: "openAiChatCompletions",
      baseUrl: "https://api.openai.com/v1",
      model: "gpt-4o-mini",
      enabled: true,
    }],
    activeProviderId: "openai-compatible",
    commandPermissionMode: "confirm",
    responseIdleTimeoutSeconds: AI_RESPONSE_IDLE_TIMEOUT_DEFAULT_SECONDS,
  });
  assert.equal(windows.system.sessionLogsEnabled, false);
  assert.equal(windows.system.sshDeepLinkEnabled, true);
  assert.equal(windows.system.jmsDeepLinkEnabled, false);
  assert.equal(windows.system.explorerContextMenuEnabled, true);
  assert.equal(createDefaultRendererSafeSettings("mac").shortcuts.scheme, "mac");
  assert.equal(createDefaultRendererSafeSettings("linux").system.explorerContextMenuEnabled, false);
});

test("AI settings normalize multiple independent profiles and migrate the former single-provider shape", () => {
  const base = createDefaultRendererSafeSettings("windows");
  const deepseekPreset = AI_PROVIDER_PRESETS.find((preset) => preset.id === "deepseek");
  assert.ok(deepseekPreset);
  const first = createAiProviderProfile(deepseekPreset, "ai-deepseek-work");
  const second = {
    ...createAiProviderProfile(deepseekPreset, "ai-deepseek-personal"),
    name: "DeepSeek Personal",
    model: "deepseek-reasoner",
  };
  const custom = {
    id: "custom-gateway",
    providerId: "custom",
    name: "Private gateway",
    protocol: "openAiChatCompletions" as const,
    baseUrl: "https://ai.example.test/v1",
    model: "company-model",
    enabled: false,
  };
  const normalized = normalizeRendererSafeSettings({
    ...base,
    ai: {
      providers: [first, second, custom],
      activeProviderId: second.id,
      commandPermissionMode: "auto",
    },
  }, "windows");
  assert.deepEqual(normalized.ai.providers, [first, second, custom]);
  assert.equal(normalized.ai.activeProviderId, second.id);
  assert.equal(normalized.ai.commandPermissionMode, "auto");

  const migrated = normalizeRendererSafeSettings({
    ...base,
    schemaVersion: 2,
    ai: {
      providerId: "deepseek",
      baseUrl: "https://api.deepseek.com/v1",
      model: "deepseek-chat",
      commandPermissionMode: "ask",
    },
  }, "windows");
  assert.deepEqual(migrated.ai, {
    providers: [{
      id: "deepseek",
      providerId: "deepseek",
      name: "DeepSeek",
      protocol: "openAiChatCompletions",
      baseUrl: "https://api.deepseek.com/v1",
      model: "deepseek-chat",
      enabled: true,
    }],
    activeProviderId: "deepseek",
    commandPermissionMode: "confirm",
    responseIdleTimeoutSeconds: AI_RESPONSE_IDLE_TIMEOUT_DEFAULT_SECONDS,
  });
});

test("Anthropic preset keeps its direct Messages protocol through normalization", () => {
  const anthropicPreset = AI_PROVIDER_PRESETS.find((preset) => preset.id === "anthropic");
  assert.ok(anthropicPreset);
  assert.equal(anthropicPreset.protocol, "anthropicMessages");
  assert.equal(anthropicPreset.baseUrl, "https://api.anthropic.com/v1");

  const anthropic = createAiProviderProfile(anthropicPreset, "anthropic-work");
  const settings = createDefaultRendererSafeSettings("windows");
  const normalized = normalizeRendererSafeSettings({
    ...settings,
    ai: {
      providers: [anthropic],
      activeProviderId: anthropic.id,
      commandPermissionMode: "confirm",
    },
  }, "windows");
  assert.deepEqual(normalized.ai.providers, [anthropic]);
  assert.equal(normalized.ai.providers[0].protocol, "anthropicMessages");
});

test("normalization clamps public settings and discards injected secret-bearing fields", () => {
  const normalized = normalizeRendererSafeSettings({
    schemaVersion: 99,
    appearance: { windowOpacity: 0.1, customCss: "body{}" },
    terminal: { fontSize: 500, scrollbackRows: -1 },
    system: { networkProxyMode: "manual", proxyPassword: "raw-marker" },
    apiKey: "raw-marker",
    syncToken: "raw-marker",
    appLockPassword: "raw-marker",
  }, "windows");
  assert.equal(normalized.schemaVersion, 4);
  assert.equal(normalized.appearance.windowOpacity, 0.5);
  assert.equal(normalized.terminal.fontSize, 72);
  assert.equal(normalized.terminal.scrollbackRows, 100);
  assert.equal(normalized.system.networkProxyMode, "manual");
  assert.deepEqual(normalized.ai, {
    providers: [{
      id: "openai-compatible",
      providerId: "openai-compatible",
      name: "OpenAI",
      protocol: "openAiChatCompletions",
      baseUrl: "https://api.openai.com/v1",
      model: "gpt-4o-mini",
      enabled: true,
    }],
    activeProviderId: "openai-compatible",
    commandPermissionMode: "confirm",
    responseIdleTimeoutSeconds: AI_RESPONSE_IDLE_TIMEOUT_DEFAULT_SECONDS,
  });
  const json = rendererSafeSettingsJson(normalized);
  assert.equal(json.includes("raw-marker"), false);
  assert.equal(json.includes("proxyPassword"), false);
  assert.equal(json.includes("apiKey"), false);
  assert.equal(json.includes("syncToken"), false);
  assert.equal(json.includes("appLockPassword"), false);
  assert.equal(json.includes("savedApiKey"), false);
  assert.equal(json.includes("hasSavedKey"), false);
});

test("AI response idle timeout defaults, clamps, remains an integer, and is editable", async () => {
  const defaults = createDefaultRendererSafeSettings("windows");
  assert.equal(defaults.schemaVersion, 4);
  assert.equal(
    defaults.ai.responseIdleTimeoutSeconds,
    AI_RESPONSE_IDLE_TIMEOUT_DEFAULT_SECONDS,
  );

  const minimum = normalizeRendererSafeSettings({
    ...defaults,
    ai: { ...defaults.ai, responseIdleTimeoutSeconds: 0 },
  }, "windows");
  assert.equal(minimum.ai.responseIdleTimeoutSeconds, AI_RESPONSE_IDLE_TIMEOUT_MIN_SECONDS);

  const maximum = normalizeRendererSafeSettings({
    ...defaults,
    ai: { ...defaults.ai, responseIdleTimeoutSeconds: 100_000 },
  }, "windows");
  assert.equal(maximum.ai.responseIdleTimeoutSeconds, AI_RESPONSE_IDLE_TIMEOUT_MAX_SECONDS);

  const rounded = normalizeRendererSafeSettings({
    ...defaults,
    ai: { ...defaults.ai, responseIdleTimeoutSeconds: 12.6 },
  }, "windows");
  assert.equal(rounded.ai.responseIdleTimeoutSeconds, 13);

  const [component, api] = await Promise.all([
    readFile(componentUrl, "utf8"),
    readFile(apiUrl, "utf8"),
  ]);
  assert.match(component, /id="ai-safety-response-timeout"[\s\S]*?<NumberControl[\s\S]*?responseIdleTimeoutSeconds/);
  assert.match(component, /min=\{AI_RESPONSE_IDLE_TIMEOUT_MIN_SECONDS\}/);
  assert.match(component, /max=\{AI_RESPONSE_IDLE_TIMEOUT_MAX_SECONDS\}/);
  assert.match(api, /const AI_KEYS = \[[\s\S]*?"responseIdleTimeoutSeconds"[\s\S]*?\] as const/);
});

test("local terminal settings preserve direct argv and reject unbounded native text", () => {
  const parsed = parseLocalShellArgs("--login 'project with spaces' C:\\msys64\\usr\\bin ''");
  assert.deepEqual(parsed, ["--login", "project with spaces", "C:\\msys64\\usr\\bin", ""]);
  assert.deepEqual(parseLocalShellArgs(formatLocalShellArgs(parsed)), parsed);
  const quoted = ["it's", "a\"b", "C:\\path with spaces\\", ""];
  assert.deepEqual(parseLocalShellArgs(formatLocalShellArgs(quoted)), quoted);

  const normalized = normalizeRendererSafeSettings({
    terminal: {
      localShell: "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
      localShellArgs: ["-NoLogo", "-WorkingDirectory", "C:\\work tree"],
      localStartDir: "C:\\work tree",
    },
  }, "windows");
  assert.equal(normalized.terminal.localShell, "C:\\Program Files\\PowerShell\\7\\pwsh.exe");
  assert.deepEqual(normalized.terminal.localShellArgs, ["-NoLogo", "-WorkingDirectory", "C:\\work tree"]);
  assert.equal(normalized.terminal.localStartDir, "C:\\work tree");

  const rejected = normalizeRendererSafeSettings({
    terminal: {
      localShell: `pwsh\nprivate-native-path`,
      localShellArgs: Array.from({ length: 33 }, () => "-i"),
      localStartDir: `C:\\work\0private-native-path`,
    },
  }, "windows");
  assert.equal(rejected.terminal.localShell, "");
  assert.deepEqual(rejected.terminal.localShellArgs, []);
  assert.equal(rejected.terminal.localStartDir, "");
  assert.equal(rendererSafeSettingsJson(rejected).includes("private-native-path"), false);
});

test("Settings native API uses the exact two-command request boundary and stable runtime adapters", async () => {
  const [api, app, route] = await Promise.all([
    readFile(apiUrl, "utf8"),
    readFile(new URL("../../src/App.tsx", import.meta.url), "utf8"),
    readFile(routeUrl, "utf8"),
  ]);
  assert.match(api, /list: "list_settings"/);
  assert.match(api, /replace: "replace_settings"/);
  assert.match(api, /invoke<unknown>\(SETTINGS_COMMANDS\.list\)/);
  assert.match(api, /invoke<unknown>\(SETTINGS_COMMANDS\.replace, \{ request: safeRequest \}\)/);
  assert.match(api, /const safeRequest: ReplaceRendererSafeSettingsRequest = \{[\s\S]*?settings,[\s\S]*?expectedInventoryRevision:/);
  assert.match(api, /NATIVE_SETTINGS_ADAPTER/);
  assert.match(api, /BROWSER_SETTINGS_ADAPTER = createMemorySettingsAdapter\(\)/);
  assert.match(api, /SETTINGS_ADAPTER:[\s\S]*?isTauri\(\)/);
  assert.match(app, /import\("\.\/SettingsRoute"\)/);
  assert.doesNotMatch(app, /from "\.\/settingsApi"/);
  assert.match(route, /import \{ SETTINGS_ADAPTER \} from "\.\/settingsApi"/);
  assert.match(route, /<SettingsWorkspace[\s\S]*?adapter=\{SETTINGS_ADAPTER\}/);
});

test("Settings response validation is exact and the DTO contains no sensitive fields", async () => {
  const [api, model] = await Promise.all([
    readFile(apiUrl, "utf8"),
    readFile(modelUrl, "utf8"),
  ]);
  const dto = model.slice(
    model.indexOf("export type RendererSafeSettings ="),
    model.indexOf("export type RendererSafeSettingsSnapshot ="),
  );
  assert.doesNotMatch(dto, /\b(?:apiKey|password|token|secret|credential|appLockMaterial)\??\s*:/i);
  assert.match(api, /hasExactKeys\(value, SETTINGS_KEYS\)/);
  assert.match(api, /hasExactKeys\(value\.appearance, APPEARANCE_KEYS\)/);
  assert.match(api, /hasExactKeys\(value\.terminal, TERMINAL_KEYS\)/);
  assert.match(api, /hasExactKeys\(value, \["settings", "inventoryRevision"\]\)/);
  assert.match(api, /if \(!sameJsonValue\(value, normalized\)\)/);
  assert.match(api, /SETTINGS_RESPONSE_INVALID/);
  assert.match(api, /new Error\(classifySettingsApiError\(reason\)\.message\)/);
  assert.doesNotMatch(api, /new Error\(`[^`]*\$\{reason\}/);
});

test("browser Settings adapter keeps cloned in-memory state and enforces CAS", async () => {
  const api = await readFile(apiUrl, "utf8");
  const memory = api.slice(
    api.indexOf("export const createMemorySettingsAdapter"),
    api.indexOf("export const NATIVE_SETTINGS_ADAPTER"),
  );
  assert.match(memory, /let snapshot: RendererSafeSettingsSnapshot/);
  assert.match(memory, /return structuredClone\(snapshot\)/g);
  assert.match(memory, /sameJsonValue\(request\.expectedInventoryRevision, snapshot\.inventoryRevision\)/);
  assert.match(memory, /throw fixedSettingsError\("SETTINGS_INVENTORY_CHANGED"\)/);
  assert.match(memory, /generation \+= 1/);
  assert.match(memory, /settings = validateRendererSafeSettings\(request\.settings\)/);
});

test("workspace is adapter-injected, browser-safe, mounted-after-visit, and search-focus capable", async () => {
  const [component, model, styles] = await Promise.all([
    readFile(componentUrl, "utf8"),
    readFile(modelUrl, "utf8"),
    readFile(stylesUrl, "utf8"),
  ]);

  assert.match(component, /adapter\?: RendererSafeSettingsAdapter/);
  assert.match(component, /if \(!adapter\)/);
  assert.match(component, /const snapshot = await adapter\.load\(\)/);
  assert.match(component, /adapter\.replace\(\{[\s\S]{0,200}?settings:\s*next,[\s\S]{0,200}?expectedInventoryRevision:\s*revisionRef\.current/);
  assert.match(component, /window\.addEventListener\("focus", reloadVisibleSettings\)/);
  assert.match(component, /document\.addEventListener\("visibilitychange", reloadVisibleSettings\)/);
  assert.match(component, /await saveQueueRef\.current/);
  assert.doesNotMatch(component, /\binvoke\s*\(/);
  assert.doesNotMatch(component, /localStorage|sessionStorage/);
  assert.doesNotMatch(model, /localStorage|sessionStorage/);
  assert.match(component, /new Set\(\[\.\.\.current, page\]\)/);
  assert.match(component, /hidden=\{activePage !== page\.id\}/);
  assert.match(component, /event\.ctrlKey \|\| event\.metaKey/);
  assert.match(component, /scrollIntoView\(\{ block: "center", behavior: "smooth" \}\)/);
  assert.match(component, /setNestedTab\(hit\.nestedTab\)/);
  assert.match(component, /import "\.\/settings\.css"/);
  assert.match(component, /isTauri\(\) \? listLocalShells\(\) : Promise\.resolve\(\[\]\)/);
  assert.match(component, /directory: true/);
  assert.match(component, /draft\.terminal\.localShell = trimmedCustomShell/);
  assert.match(component, /draft\.terminal\.localShellArgs = parsedCustomArgs/);
  assert.match(component, /draft\.terminal\.localStartDir = selected/);
  assert.match(component, /draft\.terminal\.localStartDir = ""/);
  assert.match(component, /"terminal-local-shell"/);
  assert.doesNotMatch(component, /console\.(?:log|warn|error).*localStartDir/);

  assert.match(styles, /\.settings-layout\s*\{[\s\S]*?grid-template-columns:\s*224px minmax\(0, 1fr\)/);
  assert.match(styles, /min-width:\s*820px/);
  assert.match(styles, /min-height:\s*600px/);
  assert.match(styles, /\.settings-anchor-highlight/);
});

test("AI settings expose multi-provider management, profile-bound keyring, and command permissions", async () => {
  const [component, model, api] = await Promise.all([
    readFile(componentUrl, "utf8"),
    readFile(modelUrl, "utf8"),
    readFile(apiUrl, "utf8"),
  ]);

  assert.match(component, /settings\.ai\.providers\.map/);
  assert.match(component, /createAiProviderProfile\(preset, id\)/);
  assert.match(component, /const profile = \{ \.\.\.createAiProviderProfile\(preset, id\), enabled: false \}/);
  assert.match(component, /draft\.ai\.providers\.push\(profile\)/);
  assert.match(component, /draft\.ai\.activeProviderId = profile\.id/);
  assert.match(component, /draft\.ai\.providers = remaining/);
  assert.match(component, /draft\.ai\.providers\[index\] = profile/);
  assert.match(component, /className="settings-ai-delete-confirm" role="alertdialog"/);
  assert.doesNotMatch(component, /window\.confirm/);
  assert.match(component, /hasSavedAiApiKey\(profile\.id\)/);
  assert.match(component, /saveAiApiKey\([^,]+,\s*keyDraft\)/);
  assert.match(component, /deleteSavedAiApiKey\(profile\.id\)/);
  assert.match(component, /await listAiModels\([^)]+\.id\)/);
  assert.match(component, /hasErrorCode\(error, "AI_MODELS_EMPTY"\)[\s\S]*?setModelCatalogState\("empty"\)/);
  assert.match(component, /setModelCatalogError\(aiModelCatalogFailureMessage\(error, t\)\)/);
  assert.match(component, /className="settings-ai-[^"]*model[^"]*"[\s\S]*?value=\{draft\.model\}/);
  assert.match(model, /id: "anthropic"[\s\S]*?protocol: "anthropicMessages"[\s\S]*?api\.anthropic\.com\/v1/);
  assert.match(component, /protocol: preset\.protocol/);
  assert.match(component, /type="password"[\s\S]*?autoComplete="off"/);
  assert.match(component, /draft\.ai\.commandPermissionMode = value/);
  assert.match(component, /id="ai-terminal-execute"/);
  assert.match(component, /ai\.settings\.terminalToolAvailable/);
  assert.match(component, /ai\.settings\.safety\.limitsDescription/);
  assert.match(component, /const AI_VISIBLE_TAB_IDS = \["ai-providers", "ai-tools", "ai-safety"\]/);
  assert.doesNotMatch(component, /ai\.settings\.unavailableTitle/);
  assert.doesNotMatch(component, /ai\.settings\.builtinAgentActive/);
  assert.doesNotMatch(component, /draft\.ai\.(?:apiKey|hasSavedKey|credentialReference)/);
  assert.match(model, /providers: AiProviderProfile\[\]/);
  assert.match(model, /activeProviderId: string/);
  assert.match(model, /protocol: AiProviderProtocol/);
  assert.match(model, /commandPermissionMode: "observer" \| "confirm" \| "auto"/);
  assert.match(api, /const AI_KEYS = \[[\s\S]*?"providers"[\s\S]*?"activeProviderId"[\s\S]*?"commandPermissionMode"[\s\S]*?"responseIdleTimeoutSeconds"[\s\S]*?\] as const/);
  assert.match(api, /const AI_PROVIDER_KEYS = \["id", "providerId", "name", "protocol", "baseUrl", "model", "enabled"\]/);
  assert.match(api, /value\.ai\.providers\.every\(\(profile\) => hasExactKeys\(profile, AI_PROVIDER_KEYS\)\)/);
});

test("AI provider editing is one compact form with a model selector and folded manual fallback", async () => {
  const component = await readFile(componentUrl, "utf8");
  const card = componentSlice(component, "function AiProviderCard(", "function AiSettingsPage(");
  const semanticForms = card.match(/(?:<form\b|settings-ai-unified-form)/g) ?? [];
  assert.equal(semanticForms.length, 1, "the provider editor must expose one unified setup surface");

  const semanticFormMarker = card.search(/(?:<form\b|settings-ai-unified-form)/);
  const form = card.slice(semanticFormMarker);

  for (const binding of ["draft.name", "draft.baseUrl", "draft.protocol", "draft.model", "keyDraft"]) {
    assert.ok(form.includes(binding), `${binding} must remain inside the single setup form`);
  }

  const protocolValue = /value\s*=\s*\{draft\.protocol\}/.exec(form);
  assert.ok(protocolValue, "protocol must be editable from the setup form");
  const protocolSelectStart = form.lastIndexOf("<select", protocolValue.index);
  const protocolSelectEnd = form.indexOf("</select>", protocolValue.index);
  assert.ok(protocolSelectStart >= 0 && protocolSelectEnd > protocolSelectStart, "protocol must use a select control");
  const protocolSelect = form.slice(protocolSelectStart, protocolSelectEnd);
  assert.match(protocolSelect, /openAiChatCompletions/);
  assert.match(protocolSelect, /anthropicMessages/);

  const modelValue = /value\s*=\s*\{draft\.model\}/.exec(form);
  assert.ok(modelValue, "the current model must be bound to the compact model control");
  const modelSelectStart = form.lastIndexOf("<select", modelValue.index);
  const modelSelectEnd = form.indexOf("</select>", modelValue.index);
  assert.ok(modelSelectStart >= 0 && modelSelectEnd > modelSelectStart, "the everyday model control must be a select");
  const modelSelect = form.slice(modelSelectStart, modelSelectEnd);
  assert.match(modelSelect, /availableModels\.map\(/);
  assert.match(form, /setDraft\(\(current\) => \(\{ \.\.\.current, model: event\.target\.value \}\)\)/);
  assert.match(form, /<details className="settings-ai-advanced">/);
  assert.doesNotMatch(form, /<details className="settings-ai-advanced"\s+open/);
  const advanced = componentSlice(form, '<details className="settings-ai-advanced">', "</details>");
  assert.match(advanced, /ai\.settings\.chooseProvider/);
  assert.match(advanced, /ai\.settings\.manualModel/);
  assert.match(advanced, /<input\b[\s\S]*?value=\{draft\.model\}/);
  assert.doesNotMatch(form, /settings-ai-editor-intro|settings-ai-step-index|settings-ai-form-section|1—3/);
  assert.match(form, /type="password"[\s\S]*?value=\{keyDraft\}/);
  assert.match(card, /next\.protocol === "openAiChatCompletions" && isLoopbackAiProfileEndpoint\(next\.baseUrl\)/);
  assert.match(createTranslator("en-US")("ai.settings.connectAndFetchModels"), /^Test connection/u);
  assert.match(createTranslator("zh-CN")("ai.settings.connectAndFetchModels"), /^测试连接/u);
  assert.equal(createTranslator("zh-CN")("ai.settings.advancedOptions"), "高级选项");
  assert.equal(createTranslator("zh-CN")("ai.settings.manualModel"), "手动模型 ID");
  assert.equal(createTranslator("zh-CN")("ai.settings.cancelEdit"), "取消");
});

test("AI provider editor directly accepts remote HTTP and explains test versus enable actions", async () => {
  const component = await readFile(componentUrl, "utf8");
  const endpointNormalizer = componentSlice(
    component,
    "const normalizedAiProfileEndpoint",
    "const isLoopbackAiProfileEndpoint",
  );
  const card = componentSlice(component, "function AiProviderCard(", "function AiSettingsPage(");

  assert.match(endpointNormalizer, /endpoint\.protocol !== "https:" && endpoint\.protocol !== "http:"/);
  assert.doesNotMatch(endpointNormalizer, /loopback|localhost|allowInsecureHttp/);
  assert.doesNotMatch(component, /allowInsecureHttp|insecureHttpConfirm/);
  assert.match(card, /ai\.settings\.connectionTestDescription/);
  assert.equal(
    createTranslator("zh-CN")("ai.settings.endpointHint"),
    "请填写服务商的 HTTP 或 HTTPS API 接口地址。",
  );
  assert.match(createTranslator("zh-CN")("ai.settings.saveAndUse"), /启用/u);
});

test("AI provider actions share one compact footer without a duplicate save action", async () => {
  const [component, skin] = await Promise.all([
    readFile(componentUrl, "utf8"),
    readFile(skinUrl, "utf8"),
  ]);
  const card = componentSlice(component, "function AiProviderCard(", "function AiSettingsPage(");

  assert.equal(
    card.match(/onClick=\{\(\) => void saveAndUse\(\)\}/gu)?.length,
    1,
    "the editor must expose one unambiguous save-and-use action",
  );
  const actionBar = componentSlice(card, '<div className="settings-ai-editor-actions settings-ai-save-bar">', "</div>");
  assert.match(actionBar, /cancelEdit/);
  assert.match(actionBar, /connectAndFetchModels/);
  assert.match(actionBar, /saveAndUse/);
  for (const [, selector, body] of skin.matchAll(/([^{}]+)\{([^{}]*)\}/gu)) {
    if (selector.includes("settings-ai-profile") && selector.includes("settings-primary-button")) {
      assert.doesNotMatch(body, /display\s*:\s*none/u, "CSS must not hide an editor save action");
    }
  }
});

test("AI provider endpoint replacement accepts a newly entered endpoint-bound key", async () => {
  const component = await readFile(componentUrl, "utf8");
  const card = componentSlice(component, "function AiProviderCard(", "function AiSettingsPage(");
  const validation = componentSlice(card, "const validatedDraft", "const hasCredentialFor");

  assert.match(validation, /nextEndpoint !== currentEndpoint/);
  assert.match(validation, /keyState !== "missing"[\s\S]*?keyDraft\.trim\(\)\.length === 0/);
  assert.match(
    createTranslator("zh-CN")("ai.settings.removeKeyBeforeEndpointChange"),
    /替换密钥/u,
  );
});

test("AI model discovery maps safe failure codes to actionable localized reasons", async () => {
  const component = await readFile(componentUrl, "utf8");
  const mapper = componentSlice(
    component,
    "const aiModelCatalogFailureMessage",
    "function AiProviderCard(",
  );

  for (const code of [
    "AI_STORED_KEY_NOT_FOUND",
    "AI_HTTP_ERROR:401",
    "AI_HTTP_ERROR:404",
    "AI_HTTP_ERROR:429",
    "AI_TIMEOUT",
    "AI_RESPONSE_INVALID",
  ]) assert.match(mapper, new RegExp(code.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
  assert.match(mapper, /localizeAiError\(error, t\)/);
  assert.match(createTranslator("zh-CN")("ai.settings.modelsFailedAuthentication"), /401\/403/u);
  assert.match(createTranslator("en-US")("ai.settings.modelsFailedEndpoint"), /404/u);
});

test("AI provider editing is exclusive and endpoint-bound key drafts never cross editors", async () => {
  const component = await readFile(componentUrl, "utf8");
  const card = componentSlice(component, "function AiProviderCard(", "function AiSettingsPage(");
  const page = componentSlice(component, "function AiSettingsPage(", "export function SettingsWorkspace(");

  assert.match(card, /editLocked: boolean;/);
  assert.match(
    card,
    /disabled=\{editLocked\} onClick=\{onEdit\}/,
    "profiles outside the open editor must keep their Edit action locked",
  );
  assert.match(card, /className="settings-ai-editor-actions settings-ai-save-bar"[\s\S]*?onClick=\{cancelEdit\}/);
  assert.match(page, /editLocked=\{editingProviderId !== null && editingProviderId !== profile\.id\}/);
  assert.match(page, /if \(editingProviderId !== null && editingProviderId !== profileId\) return;/);
  assert.match(
    page,
    /disabled=\{settings\.ai\.providers\.length >= AI_PROVIDER_PROFILE_LIMIT \|\| editingProviderId !== null\}/,
    "adding another provider must not replace an in-progress editor",
  );

  const keyRefresh = componentSlice(card, "useEffect(() => {\n    setKeyDraft", "const removeKey");
  assert.match(keyRefresh, /setKeyDraft\(""\)/);
  assert.match(keyRefresh, /void refreshKeyState\(\)/);
  assert.match(keyRefresh, /\[editing, refreshKeyState\]/);
  assert.doesNotMatch(
    card,
    /onChange=\{[^}]*setKeyDraft\(""\)/,
    "ordinary edits within one open form must not erase the Key the user just entered",
  );
});

test("AI provider actions wait until endpoint-bound key discovery finishes", async () => {
  const component = await readFile(componentUrl, "utf8");
  const card = componentSlice(component, "function AiProviderCard(", "function AiSettingsPage(");
  const connect = componentSlice(card, "const connectAndFetchModels", "const saveAndUse");
  const save = componentSlice(card, "const saveAndUse", "const keyStatus");

  assert.match(connect, /operationState !== "idle"[\s\S]*?operationLockRef\.current[\s\S]*?keyState === "loading"/);
  assert.match(save, /operationState !== "idle"[\s\S]*?operationLockRef\.current[\s\S]*?keyState === "loading"/);
  assert.match(connect, /operationLockRef\.current = true[\s\S]*?finally[\s\S]*?operationLockRef\.current = false/);
  assert.match(save, /operationLockRef\.current = true[\s\S]*?finally[\s\S]*?operationLockRef\.current = false/);
  assert.equal(
    card.match(/disabled=\{!settingsReady \|\| operationState !== "idle" \|\| keyState === "loading" \|\| keyState === "saving" \|\| keyState === "removing"\}/g)?.length,
    2,
    "Fetch and Save must stay disabled while the saved-Key state is loading",
  );
});

test("connect-and-fetch serializes profile, key, and model discovery without closing the editor", async () => {
  const component = await readFile(componentUrl, "utf8");
  const card = componentSlice(component, "function AiProviderCard(", "function AiSettingsPage(");
  const profileCommit = /await\s+onSave\([\s\S]{0,300}?,\s*false\)/.exec(card);
  assert.ok(profileCommit, "connect-and-fetch must await the non-activating profile commit");
  const flow = topLevelConstContaining(card, profileCommit.index);

  const profileIndex = flow.search(/await\s+onSave\(/);
  const keyIndex = flow.slice(profileIndex).search(/await\s+(?:persistDraftKey|saveAiApiKey)\s*\(/) + profileIndex;
  const modelsIndex = flow.indexOf("await listAiModels(", keyIndex);
  assert.ok(profileIndex >= 0 && keyIndex > profileIndex && modelsIndex > keyIndex, "setup order must be profile -> key -> models");
  assert.doesNotMatch(flow, /anthropicMessages|unsupported/, "every supported provider protocol uses native model discovery");

  const profileFailureGuard = flow.slice(profileIndex, keyIndex);
  assert.match(profileFailureGuard, /(?:!==\s*"succeeded"|===\s*"failed")[\s\S]*?return/);
  assert.doesNotMatch(flow.slice(0, modelsIndex), /setKeyDraft\(""\)|setDraft\(structuredClone\(profile\)\)/);
  assert.doesNotMatch(flow, /onCancelEdit\(\)/, "fetching models must keep the form open for model choice");

  const failureStart = flow.indexOf("catch");
  if (failureStart >= 0) {
    const failureBranch = flow.slice(failureStart);
    assert.doesNotMatch(failureBranch, /setKeyDraft\(""\)|setDraft\(structuredClone\(profile\)\)|onCancelEdit\(\)/);
  }

  if (card.includes("const persistDraftKey")) {
    const keyPersistence = componentSlice(card, "const persistDraftKey", "const connectAndFetchModels");
    const nativeWrite = keyPersistence.indexOf("await saveAiApiKey(");
    const clear = keyPersistence.indexOf('setKeyDraft("")');
    assert.ok(nativeWrite >= 0 && clear > nativeWrite, "the key input may clear only after the native keyring write succeeds");
    const keyFailure = keyPersistence.slice(keyPersistence.indexOf("catch"));
    assert.doesNotMatch(keyFailure, /setKeyDraft\(""\)|setDraft\(structuredClone\(profile\)\)|onCancelEdit\(\)/);
  }
});

test("save-and-use retains drafts on failure and exits editing only after complete success", async () => {
  const component = await readFile(componentUrl, "utf8");
  const card = componentSlice(component, "function AiProviderCard(", "function AiSettingsPage(");
  const page = componentSlice(component, "function AiSettingsPage(", "export function SettingsWorkspace(");

  assert.match(card, /onSave: \(profile: AiProviderProfile,\s*activate: boolean\) => Promise<SettingsSaveOutcome>/);
  const activatingCommit = /await\s+onSave\([\s\S]{0,300}?,\s*true\)/.exec(card);
  assert.ok(activatingCommit, "save-and-use must await the activating profile commit");
  const flow = topLevelConstContaining(card, activatingCommit.index);

  const profileIndex = flow.search(/await\s+onSave\(/);
  const keyIndex = flow.slice(profileIndex).search(/await\s+(?:persistDraftKey|saveAiApiKey)\s*\(/) + profileIndex;
  const activationIndex = flow.lastIndexOf("await onSave(");
  const exitIndex = flow.indexOf("onCancelEdit()", activationIndex);
  assert.ok(profileIndex >= 0 && keyIndex > profileIndex && activationIndex > keyIndex && exitIndex > activationIndex, "the editor may close only after profile, key, and activation persistence succeed");
  assert.match(flow.slice(profileIndex, keyIndex), /(?:!==\s*"succeeded"|===\s*"failed")[\s\S]*?return/);
  assert.match(flow.slice(activationIndex, exitIndex), /(?:!==\s*"succeeded"|===\s*"failed")[\s\S]*?return/);

  const keyClearIndex = flow.indexOf('setKeyDraft("")');
  assert.ok(keyClearIndex === -1 || keyClearIndex > keyIndex, "the key draft may only clear after its successful save");
  const failureStart = flow.indexOf("catch");
  if (failureStart >= 0) {
    const failureBranch = flow.slice(failureStart);
    assert.doesNotMatch(failureBranch, /setKeyDraft\(""\)|setDraft\(structuredClone\(profile\)\)|onCancelEdit\(\)/);
  }

  assert.equal(flow.match(/onCancelEdit\(\);/g)?.length, 1, "save-and-use may exit editing only on its successful path");
  const saveProvider = componentSlice(page, "const saveProvider =", "const deleteProvider =");
  assert.doesNotMatch(saveProvider, /setEditingProviderId\(null\)/, "the parent profile commit must not close an editor before durable success");
});

test("visible-window Settings refresh cannot overwrite a dirty AI provider draft", async () => {
  const component = await readFile(componentUrl, "utf8");
  const card = componentSlice(component, "function AiProviderCard(", "function AiSettingsPage(");
  const load = componentSlice(component, "const loadSettings = useCallback", "const patch = useCallback");
  const reloadStart = component.indexOf("const reloadVisibleSettings");
  const reloadEnd = component.indexOf('window.addEventListener("focus", reloadVisibleSettings)', reloadStart);
  assert.ok(reloadStart >= 0 && reloadEnd > reloadStart, "visible-window reload handler is missing");
  const reload = component.slice(reloadStart, reloadEnd);
  const reloadHasDraftGuard = /\b(?:dirty|unsaved|editingProviderId|aiDraft)\w*/i.test(`${load}\n${reload}`);

  const syncCall = card.indexOf("setDraft(structuredClone(profile))");
  let draftSyncIsSafe = false;
  if (syncCall >= 0) {
    const effectStart = card.lastIndexOf("useEffect(", syncCall);
    const effectTail = card.slice(effectStart, syncCall + 500);
    const dependencies = /\},\s*\[([^\]]*)\]\);/.exec(effectTail)?.[1] ?? "";
    const hasDirtyGuard = /\b(?:dirty|unsaved)\w*/i.test(card.slice(effectStart, syncCall));
    const dependsOnWholeProfile = dependencies.split(",").some((dependency) => dependency.trim() === "profile");
    draftSyncIsSafe = hasDirtyGuard || !dependsOnWholeProfile;
  }

  assert.ok(reloadHasDraftGuard || draftSyncIsSafe, "focus/visibility reload must be guarded or profile synchronization must preserve the local draft");
});

test("AI keyring operations still wait for durable Settings authority", async () => {
  const component = await readFile(componentUrl, "utf8");

  assert.match(component, /keyState === "saving"[\s\S]*?ai\.settings\.savingKey/);
  assert.match(component, /keyState === "removing"[\s\S]*?ai\.settings\.removingKey/);
  assert.match(component, /waitForSettingsSave: \(\) => Promise<SettingsSaveOutcome>/);
  assert.match(component, /const waitForSettingsSave = useCallback\(async \(\): Promise<SettingsSaveOutcome> => \{[\s\S]*?const queuedSave = saveQueueRef\.current;[\s\S]*?const outcome = await queuedSave;[\s\S]*?queuedSave === saveQueueRef\.current\) return outcome/);
  assert.match(component, /settingsReady=\{!loading\}/);
  assert.match(component, /if \(!settingsReady\) \{[\s\S]*?setKeyState\("loading"\);[\s\S]*?return;/);
  const queueBlock = component.slice(
    component.indexOf("const patch = useCallback"),
    component.indexOf("const visiblePages = useMemo"),
  );

  assert.match(component, /type SettingsSaveOutcome = "succeeded" \| "failed"/);
  assert.match(component, /useRef<Promise<SettingsSaveOutcome>>\(Promise\.resolve\("succeeded"\)\)/);
  assert.match(queueBlock, /const queuedSave = saveQueueRef\.current\.then\(async \(\): Promise<SettingsSaveOutcome> => \{[\s\S]*?try \{[\s\S]*?await adapter\.replace\([\s\S]*?return "succeeded";[\s\S]*?\} catch \{[\s\S]*?setSaveState\("error"\);[\s\S]*?return "failed";[\s\S]*?\}\s*\}\);/);
  assert.match(queueBlock, /saveQueueRef\.current = queuedSave;[\s\S]*?return queuedSave;/);
  assert.doesNotMatch(queueBlock, /saveQueueRef\.current[\s\S]*?\.catch\s*\(/);
  assert.match(component, /const settingsSaveOutcome = await saveQueueRef\.current;[\s\S]*?if \(settingsSaveOutcome !== "succeeded"\) \{[\s\S]*?setSaveState\("error"\);[\s\S]*?return;/);

  for (const apiCall of ["hasSavedAiApiKey", "deleteSavedAiApiKey"] as const) {
    const callIndex = component.indexOf(`${apiCall}(profile.id`);
    assert.notEqual(callIndex, -1, `${apiCall} call is missing`);
    const guard = component.slice(Math.max(0, callIndex - 900), callIndex);
    assert.match(guard, /const settingsSaveOutcome = await waitForSettingsSave\(\);[\s\S]*?if \(settingsSaveOutcome !== "succeeded"\) \{[\s\S]*?return;[\s\S]*?\}/, `${apiCall} must stop after a revision or IO save failure`);
  }
});

test("legacy AI permission values normalize to canonical agent policies", () => {
  const base = createDefaultRendererSafeSettings("windows");
  assert.equal(normalizeRendererSafeSettings({ ...base, ai: { ...base.ai, commandPermissionMode: "ask" } }, "windows").ai.commandPermissionMode, "confirm");
  assert.equal(normalizeRendererSafeSettings({ ...base, ai: { ...base.ai, commandPermissionMode: "deny" } }, "windows").ai.commandPermissionMode, "observer");
  assert.equal(normalizeRendererSafeSettings({ ...base, ai: { ...base.ai, commandPermissionMode: "auto" } }, "windows").ai.commandPermissionMode, "auto");
});

test("the main shell opens a reusable native Settings window and renders its dedicated route", async () => {
  const [app, route, workspace, api, nativeWindow, capability] = await Promise.all([
    readFile(new URL("../../src/App.tsx", import.meta.url), "utf8"),
    readFile(routeUrl, "utf8"),
    readFile(new URL("../../src/TerminalWorkspace.tsx", import.meta.url), "utf8"),
    readFile(new URL("../../src/settingsWindowApi.ts", import.meta.url), "utf8"),
    readFile(new URL("../../src-tauri/src/settings_window.rs", import.meta.url), "utf8"),
    readFile(new URL("../../src-tauri/capabilities/default.json", import.meta.url), "utf8"),
  ]);

  assert.match(api, /open_settings_window/);
  assert.match(api, /hide_settings_window/);
  assert.match(api, /get\("window"\) === "settings"/);
  assert.match(app, /isSettingsWindowLocation\(\)/);
  assert.match(app, /<SettingsRoute/);
  assert.match(route, /<SettingsWorkspace/);
  assert.match(route, /hideSettingsWindow\(\)/);
  assert.match(workspace, /openSettingsWindow\(rendererLocale\)/);
  assert.match(workspace, /openSettingsWindow\(rendererLocale, "ai-providers"\)/);
  assert.match(api, /target \? \{ locale, target \} : \{ locale \}/);
  assert.match(api, /SETTINGS_WINDOW_FOCUS_EVENT = "goral:settings-focus"/);
  assert.match(api, /__GORAL_SETTINGS_TARGET__/);
  assert.match(route, /<SettingsWorkspace/);
  assert.match(await readFile(componentUrl, "utf8"), /window\.addEventListener\(SETTINGS_WINDOW_FOCUS_EVENT, handleSettingsFocus\)/);
  assert.doesNotMatch(workspace, /Settings 正在迁移/);
  assert.match(nativeWindow, /SETTINGS_WINDOW_WIDTH:\s*f64 = 980\.0/);
  assert.match(nativeWindow, /SETTINGS_WINDOW_HEIGHT:\s*f64 = 720\.0/);
  assert.match(nativeWindow, /SETTINGS_WINDOW_MIN_WIDTH:\s*f64 = 820\.0/);
  assert.match(nativeWindow, /SETTINGS_WINDOW_MIN_HEIGHT:\s*f64 = 600\.0/);
  assert.match(nativeWindow, /get_webview_window\(SETTINGS_WINDOW_LABEL\)/);
  assert.match(nativeWindow, /WebviewUrl::App\("index\.html"\.into\(\)\)/);
  assert.match(nativeWindow, /initialization_script\(initialization_script\)/);
  assert.match(nativeWindow, /async fn open_settings_window/);
  assert.match(nativeWindow, /validate_settings_window_target/);
  assert.match(nativeWindow, /settings\.eval\(script\)/);
  assert.match(nativeWindow, /__GORAL_SETTINGS_TARGET__/);
  assert.match(nativeWindow, /settings_window_title\(locale\)/);
  assert.match(nativeWindow, /run_on_main_thread/);
  assert.match(api, /__GORAL_SETTINGS_WINDOW__/);
  assert.match(nativeWindow, /center_on_source_monitor/);
  assert.equal(JSON.parse(capability).windows.includes("settings"), true);
});
