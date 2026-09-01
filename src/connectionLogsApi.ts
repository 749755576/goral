import { invoke } from "@tauri-apps/api/core";
import { normalizeLocale, type Locale, type Translate } from "./i18n.ts";

export type SavedConnectionLogProtocol =
  | "ssh"
  | "telnet"
  | "local"
  | "mosh"
  | "et"
  | "serial";

export type SavedConnectionLogHostOs = "linux" | "windows" | "macos";
export type SavedConnectionLogIconMode = "auto" | "custom";
export type SavedConnectionLogIconColorMode = "auto" | "manual";
export type SavedConnectionLogIconId =
  | "server"
  | "terminal"
  | "database"
  | "cloud"
  | "router"
  | "shield"
  | "code"
  | "box"
  | "globe"
  | "cpu"
  | "hard-drive"
  | "network"
  | "wifi"
  | "lock"
  | "key"
  | "monitor"
  | "container"
  | "activity"
  | "zap"
  | "server-cog";
export type SavedConnectionLogIconColorId =
  | "blue"
  | "green"
  | "red"
  | "amber"
  | "purple"
  | "cyan"
  | "orange"
  | "slate"
  | "violet"
  | "pink"
  | "rose"
  | "lime"
  | "teal"
  | "sky"
  | "indigo"
  | "zinc";

/** Renderer-safe legacy Connection Log metadata returned by Vault v10. */
export type SavedConnectionLog = {
  id: string;
  sessionId?: string;
  hostId: string;
  hostLabel: string;
  hostname: string;
  username: string;
  protocol: SavedConnectionLogProtocol;
  hostOs?: SavedConnectionLogHostOs;
  hostDistro?: string;
  hostIconMode?: SavedConnectionLogIconMode;
  hostIconId?: SavedConnectionLogIconId;
  hostIconColorMode?: SavedConnectionLogIconColorMode;
  hostIconColor?: SavedConnectionLogIconColorId;
  hostIconColorCustom?: string;
  startTime: number;
  endTime?: number;
  localUsername: string;
  localHostname: string;
  saved: boolean;
  themeId?: string;
  fontSize?: number;
};

export type ConnectionLogsCatalog = {
  inventoryRevision: unknown;
  logs: SavedConnectionLog[];
};

export type ReplaceConnectionLogsRequest = {
  expectedInventoryRevision: unknown;
  logs: SavedConnectionLog[];
};

export type ClearUnsavedConnectionLogsRequest = {
  expectedInventoryRevision: unknown;
};

/** Secret-bearing payload returned only for one explicitly opened log. */
export type ConnectionLogReplay = {
  logId: string;
  terminalData: string;
};

export type ExportConnectionLogResponse = {
  success: boolean;
  canceled?: boolean;
};

export const CONNECTION_LOGS_COMMANDS = {
  exportLog: "export_connection_log",
  list: "list_connection_logs",
  replace: "replace_connection_logs",
  clearUnsaved: "clear_unsaved_connection_logs",
  readReplay: "read_connection_log_replay",
} as const;

export const exportConnectionLog = (
  logId: string,
  locale: Locale,
): Promise<ExportConnectionLogResponse> =>
  invoke<ExportConnectionLogResponse>(CONNECTION_LOGS_COMMANDS.exportLog, {
    request: { logId, locale: normalizeLocale(locale) },
  });

export const listConnectionLogs = (): Promise<ConnectionLogsCatalog> =>
  invoke<ConnectionLogsCatalog>(CONNECTION_LOGS_COMMANDS.list);

export const replaceConnectionLogs = (
  request: ReplaceConnectionLogsRequest,
): Promise<ConnectionLogsCatalog> =>
  invoke<ConnectionLogsCatalog>(CONNECTION_LOGS_COMMANDS.replace, { request });

export const clearUnsavedConnectionLogs = (
  request: ClearUnsavedConnectionLogsRequest,
): Promise<ConnectionLogsCatalog> =>
  invoke<ConnectionLogsCatalog>(CONNECTION_LOGS_COMMANDS.clearUnsaved, { request });

export const readConnectionLogReplay = (logId: string): Promise<ConnectionLogReplay> =>
  invoke<ConnectionLogReplay>(CONNECTION_LOGS_COMMANDS.readReplay, { request: { logId } });

export type ConnectionLogsError = {
  inventoryChanged: boolean;
  message: string;
};

export type ConnectionLogReplayError = {
  unavailable: boolean;
  message: string;
};

/** Converts native failures to fixed renderer messages without reflecting data. */
export const classifyConnectionLogsError = (
  reason: unknown,
  t: Translate,
): ConnectionLogsError => {
  const code = reason instanceof Error
    ? reason.message.toUpperCase()
    : typeof reason === "string"
      ? reason.toUpperCase()
      : "";
  if (code.includes("CONNECTION_LOGS_INVENTORY_CHANGED")) {
    return {
      inventoryChanged: true,
      message: t("connectionLogs.error.stale"),
    };
  }
  if (code.includes("CONNECTION_LOGS_INVALID")) {
    return {
      inventoryChanged: false,
      message: t("connectionLogs.error.invalid"),
    };
  }
  if (code.includes("CONNECTION_LOGS_REPAIR_REQUIRED")) {
    return {
      inventoryChanged: false,
      message: t("connectionLogs.error.repair"),
    };
  }
  return {
    inventoryChanged: false,
    message: t("connectionLogs.error.failed"),
  };
};

/** Keeps replay-store failures fixed and distinguishes an absent capture. */
export const classifyConnectionLogReplayError = (
  reason: unknown,
  t: Translate,
): ConnectionLogReplayError => {
  const code = reason instanceof Error
    ? reason.message.toUpperCase()
    : typeof reason === "string"
      ? reason.toUpperCase()
      : "";
  if (
    code.includes("CONNECTION_LOG_REPLAY_UNAVAILABLE")
    || code.includes("REPLAY_UNAVAILABLE")
    || code.includes("REPLAY_NOT_FOUND")
  ) {
    return {
      unavailable: true,
      message: t("connectionLogs.replay.unavailable"),
    };
  }
  if (code.includes("REPLAY_CORRUPT") || code.includes("CORRUPT_STORE")) {
    return {
      unavailable: false,
      message: t("connectionLogs.replay.corrupt"),
    };
  }
  return {
    unavailable: false,
    message: t("connectionLogs.replay.failed"),
  };
};
