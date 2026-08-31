import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

import {
  createDefaultRendererSafeSettings,
  detectSettingsPlatform,
  normalizeRendererSafeSettings,
  type RendererSafeSettings,
  type RendererSafeSettingsAdapter,
  type RendererSafeSettingsSnapshot,
  type ReplaceRendererSafeSettingsRequest,
} from "./settingsUi";

export type {
  RendererSafeSettings,
  RendererSafeSettingsAdapter,
  RendererSafeSettingsSnapshot,
  ReplaceRendererSafeSettingsRequest,
};

export const SETTINGS_COMMANDS = {
  list: "list_settings",
  replace: "replace_settings",
} as const;

export const SETTINGS_CHANGED_EVENT = "goral:settings-changed";

export type SettingsChangedNotification = Readonly<{
  inventoryRevision: Readonly<{
    generation: number;
    checksum: string;
  }>;
}>;

const SETTINGS_KEYS = ["schemaVersion", "appearance", "terminal", "shortcuts", "sftp", "ai", "system"] as const;
const APPEARANCE_KEYS = [
  "uiLanguage",
  "uiFontFamilyId",
  "windowOpacity",
  "colorMode",
  "lightUiThemeId",
  "darkUiThemeId",
  "accentMode",
  "customAccent",
  "appIconVariant",
  "showRecentHosts",
  "hostClickBehavior",
  "showOnlyUngroupedHostsInRoot",
  "showSftpTab",
  "showHostTreeSidebar",
  "autoImportSystemKnownHosts",
  "customCss",
] as const;
const TERMINAL_KEYS = [
  "followAppTheme",
  "themeId",
  "fontFamilyId",
  "fallbackFont",
  "fontSize",
  "fontWeight",
  "boldFontWeight",
  "fontSmoothing",
  "linePadding",
  "emulationType",
  "cursorStyle",
  "cursorBlink",
  "highlightCursorLine",
  "altAsMeta",
  "optionArrowWordJump",
  "kittyKeyboardProtocol",
  "minimumContrastRatio",
  "copyOnSelect",
  "bracketedPaste",
  "scrollbackRows",
  "autoCloseOnExit",
  "dynamicTabTitle",
  "localShell",
  "localShellArgs",
  "localStartDir",
  "verifyHostKeys",
  "sshAutoReconnect",
  "keepaliveIntervalSeconds",
  "renderer",
  "inlineImagesEnabled",
  "workspaceFocusStyle",
  "autocompleteEnabled",
  "passwordPromptAssist",
] as const;
const SHORTCUT_KEYS = [
  "scheme",
  "disableTerminalFontZoom",
  "shellOnlyTabNumberShortcuts",
  "showTabNumberBadges",
] as const;
const SFTP_KEYS = [
  "doubleClickBehavior",
  "defaultViewMode",
  "showHiddenFiles",
  "autoSync",
  "followTerminalCwd",
  "autoOpenSidebar",
  "transferConcurrency",
  "defaultOpener",
] as const;
const AI_KEYS = [
  "providers",
  "activeProviderId",
  "commandPermissionMode",
  "responseIdleTimeoutSeconds",
] as const;
const AI_PROVIDER_KEYS = ["id", "providerId", "name", "protocol", "baseUrl", "model", "enabled"] as const;
const SYSTEM_KEYS = [
  "autoUpdateEnabled",
  "networkProxyMode",
  "startupLanding",
  "restorePreviousSession",
  "restoreTerminalCwd",
  "sessionLogsEnabled",
  "sshDeepLinkEnabled",
  "jmsDeepLinkEnabled",
  "explorerContextMenuEnabled",
  "sshDebugLogsEnabled",
  "globalHotkeyEnabled",
  "toggleWindowHotkey",
  "closeToTray",
] as const;

const OPAQUE_REVISION_MAX_JSON_BYTES = 8 * 1024;
const OPAQUE_REVISION_MAX_DEPTH = 4;
const OPAQUE_REVISION_MAX_KEYS = 32;

type PlainRecord = Record<string, unknown>;

const plainRecord = (value: unknown): PlainRecord | null =>
  value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as PlainRecord
    : null;

const hasExactKeys = (value: unknown, expected: readonly string[]): value is PlainRecord => {
  const candidate = plainRecord(value);
  if (!candidate) return false;
  const actual = Object.keys(candidate);
  return actual.length === expected.length && expected.every((key) => Object.hasOwn(candidate, key));
};

export const isSettingsChangedNotification = (
  value: unknown,
): value is SettingsChangedNotification => {
  if (!hasExactKeys(value, ["inventoryRevision"])) return false;
  const revision = value.inventoryRevision;
  return hasExactKeys(revision, ["generation", "checksum"])
    && typeof revision.generation === "number"
    && Number.isSafeInteger(revision.generation)
    && revision.generation >= 0
    && typeof revision.checksum === "string"
    && /^[0-9a-f]{64}$/u.test(revision.checksum);
};

const sameJsonValue = (left: unknown, right: unknown): boolean => {
  if (Object.is(left, right)) return true;
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left)
      && Array.isArray(right)
      && left.length === right.length
      && left.every((entry, index) => sameJsonValue(entry, right[index]));
  }
  const leftRecord = plainRecord(left);
  const rightRecord = plainRecord(right);
  if (!leftRecord || !rightRecord) return false;
  const leftKeys = Object.keys(leftRecord);
  const rightKeys = Object.keys(rightRecord);
  return leftKeys.length === rightKeys.length
    && leftKeys.every((key) => Object.hasOwn(rightRecord, key)
      && sameJsonValue(leftRecord[key], rightRecord[key]));
};

const hasStrictSettingsShape = (value: unknown): value is RendererSafeSettings => {
  if (!hasExactKeys(value, SETTINGS_KEYS)) return false;
  return hasExactKeys(value.appearance, APPEARANCE_KEYS)
    && hasExactKeys(value.terminal, TERMINAL_KEYS)
    && hasExactKeys(value.shortcuts, SHORTCUT_KEYS)
    && hasExactKeys(value.sftp, SFTP_KEYS)
    && hasExactKeys(value.ai, AI_KEYS)
    && Array.isArray(value.ai.providers)
    && value.ai.providers.every((profile) => hasExactKeys(profile, AI_PROVIDER_KEYS))
    && hasExactKeys(value.system, SYSTEM_KEYS);
};

const safeOpaqueJsonValue = (value: unknown, depth = 0): boolean => {
  if (depth > OPAQUE_REVISION_MAX_DEPTH) return false;
  if (value === null) return true;
  if (typeof value === "string") return value.length <= OPAQUE_REVISION_MAX_JSON_BYTES;
  if (typeof value === "number") return Number.isSafeInteger(value) && value >= 0;
  if (typeof value === "boolean") return true;
  if (Array.isArray(value)) {
    return value.length <= OPAQUE_REVISION_MAX_KEYS
      && value.every((entry) => safeOpaqueJsonValue(entry, depth + 1));
  }
  const candidate = plainRecord(value);
  if (!candidate) return false;
  const keys = Object.keys(candidate);
  return keys.length <= OPAQUE_REVISION_MAX_KEYS
    && keys.every((key) => key.length <= 128
      && safeOpaqueJsonValue(candidate[key], depth + 1));
};

export const isSafeSettingsInventoryRevision = (value: unknown): boolean => {
  if (value === undefined || value === null || !safeOpaqueJsonValue(value)) return false;
  try {
    const encoded = JSON.stringify(value);
    return encoded !== undefined && new TextEncoder().encode(encoded).byteLength <= OPAQUE_REVISION_MAX_JSON_BYTES;
  } catch {
    return false;
  }
};

export const validateRendererSafeSettings = (value: unknown): RendererSafeSettings => {
  if (!hasStrictSettingsShape(value)) {
    throw new Error("SETTINGS_RESPONSE_INVALID: Settings response has an invalid shape");
  }
  const normalized = normalizeRendererSafeSettings(value, detectSettingsPlatform());
  if (!sameJsonValue(value, normalized)) {
    throw new Error("SETTINGS_RESPONSE_INVALID: Settings response contains invalid values");
  }
  return structuredClone(normalized);
};

export const validateRendererSafeSettingsSnapshot = (
  value: unknown,
): RendererSafeSettingsSnapshot => {
  if (!hasExactKeys(value, ["settings", "inventoryRevision"])) {
    throw new Error("SETTINGS_RESPONSE_INVALID: Settings snapshot has an invalid shape");
  }
  if (!isSafeSettingsInventoryRevision(value.inventoryRevision)) {
    throw new Error("SETTINGS_RESPONSE_INVALID: Settings revision is invalid");
  }
  return {
    settings: validateRendererSafeSettings(value.settings),
    inventoryRevision: structuredClone(value.inventoryRevision),
  };
};

export type SettingsApiError = {
  inventoryChanged: boolean;
  message: string;
};

export const classifySettingsApiError = (reason: unknown): SettingsApiError => {
  const code = reason instanceof Error
    ? reason.message.toUpperCase()
    : typeof reason === "string"
      ? reason.toUpperCase()
      : "";
  if (code.includes("SETTINGS_INVENTORY_CHANGED")) {
    return {
      inventoryChanged: true,
      message: "Settings changed in another window. Reopen Settings and try again.",
    };
  }
  if (code.includes("SETTINGS_RESPONSE_INVALID") || code.includes("SETTINGS_INVALID")) {
    return {
      inventoryChanged: false,
      message: "The Settings data is invalid and was not applied.",
    };
  }
  if (code.includes("SETTINGS_REPAIR_REQUIRED")) {
    return {
      inventoryChanged: false,
      message: "Settings storage needs repair before it can be changed.",
    };
  }
  return {
    inventoryChanged: false,
    message: "Settings could not be loaded or saved.",
  };
};

const fixedSettingsError = (reason: unknown): Error =>
  new Error(classifySettingsApiError(reason).message);

export const listSettings = async (): Promise<RendererSafeSettingsSnapshot> => {
  try {
    return validateRendererSafeSettingsSnapshot(
      await invoke<unknown>(SETTINGS_COMMANDS.list),
    );
  } catch (reason) {
    throw fixedSettingsError(reason);
  }
};

export const replaceSettings = async (
  request: ReplaceRendererSafeSettingsRequest,
): Promise<RendererSafeSettingsSnapshot> => {
  try {
    const settings = validateRendererSafeSettings(request.settings);
    if (!isSafeSettingsInventoryRevision(request.expectedInventoryRevision)) {
      throw new Error("SETTINGS_INVALID: Settings revision is invalid");
    }
    const safeRequest: ReplaceRendererSafeSettingsRequest = {
      settings,
      expectedInventoryRevision: structuredClone(request.expectedInventoryRevision),
    };
    return validateRendererSafeSettingsSnapshot(
      await invoke<unknown>(SETTINGS_COMMANDS.replace, { request: safeRequest }),
    );
  } catch (reason) {
    throw fixedSettingsError(reason);
  }
};

/**
 * Native Settings changes carry only a non-secret inventory revision. The
 * consumer must reload the complete renderer-safe snapshot from Rust.
 * Browser previews intentionally have no cross-window event transport.
 */
export const subscribeSettingsChanges = async (
  listener: (notification: SettingsChangedNotification) => void,
): Promise<UnlistenFn | null> => {
  if (!isTauri()) return null;
  return listen<unknown>(SETTINGS_CHANGED_EVENT, (event) => {
    if (!isSettingsChangedNotification(event.payload)) return;
    listener({
      inventoryRevision: {
        generation: event.payload.inventoryRevision.generation,
        checksum: event.payload.inventoryRevision.checksum,
      },
    });
  });
};

const previewRevision = (generation: number) => ({
  storeId: "browser-preview",
  loadedGeneration: generation,
  maxSeenGeneration: generation,
  seal: `browser-preview-${generation}`,
});

export const createMemorySettingsAdapter = (
  initialSettings: RendererSafeSettings = createDefaultRendererSafeSettings(),
): RendererSafeSettingsAdapter => {
  let generation = 0;
  let snapshot: RendererSafeSettingsSnapshot = {
    settings: validateRendererSafeSettings(initialSettings),
    inventoryRevision: previewRevision(generation),
  };
  return Object.freeze({
    async load() {
      return structuredClone(snapshot);
    },
    async replace(request: ReplaceRendererSafeSettingsRequest) {
      if (
        !isSafeSettingsInventoryRevision(request.expectedInventoryRevision)
        || !sameJsonValue(request.expectedInventoryRevision, snapshot.inventoryRevision)
      ) {
        throw fixedSettingsError("SETTINGS_INVENTORY_CHANGED");
      }
      const settings = validateRendererSafeSettings(request.settings);
      generation += 1;
      snapshot = {
        settings,
        inventoryRevision: previewRevision(generation),
      };
      return structuredClone(snapshot);
    },
  });
};

export const NATIVE_SETTINGS_ADAPTER: RendererSafeSettingsAdapter = Object.freeze({
  load: listSettings,
  replace: replaceSettings,
});

export const BROWSER_SETTINGS_ADAPTER = createMemorySettingsAdapter();

/** Stable for the lifetime of the Settings webview. */
export const SETTINGS_ADAPTER: RendererSafeSettingsAdapter = isTauri()
  ? NATIVE_SETTINGS_ADAPTER
  : BROWSER_SETTINGS_ADAPTER;
