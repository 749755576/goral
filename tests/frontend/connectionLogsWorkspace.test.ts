import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  classifyConnectionLogReplayError,
  classifyConnectionLogsError,
} from "../../src/connectionLogsApi.ts";
import { createTranslator } from "../../src/i18n.ts";

const t = createTranslator("en-US");

const apiUrl = new URL("../../src/connectionLogsApi.ts", import.meta.url);
const componentUrl = new URL("../../src/ConnectionLogsWorkspace.tsx", import.meta.url);
const stylesUrl = new URL("../../src/connectionLogs.css", import.meta.url);

test("Connection Logs DTO is strict camelCase Vault v10 metadata", async () => {
  const api = await readFile(apiUrl, "utf8");
  const record = api.slice(
    api.indexOf("export type SavedConnectionLog ="),
    api.indexOf("export type ConnectionLogsCatalog ="),
  );
  for (const field of [
    "id: string;",
    "sessionId?: string;",
    "hostId: string;",
    "hostLabel: string;",
    "hostname: string;",
    "username: string;",
    "protocol: SavedConnectionLogProtocol;",
    "hostOs?: SavedConnectionLogHostOs;",
    "hostDistro?: string;",
    "hostIconMode?: SavedConnectionLogIconMode;",
    "hostIconId?: SavedConnectionLogIconId;",
    "hostIconColorMode?: SavedConnectionLogIconColorMode;",
    "hostIconColor?: SavedConnectionLogIconColorId;",
    "hostIconColorCustom?: string;",
    "startTime: number;",
    "endTime?: number;",
    "localUsername: string;",
    "localHostname: string;",
    "saved: boolean;",
    "themeId?: string;",
    "fontSize?: number;",
  ]) {
    assert.ok(record.includes(field), `missing ${field}`);
  }
  assert.doesNotMatch(record, /\w+_\w+/);
  const listBoundary = api.slice(
    api.indexOf("export type SavedConnectionLog ="),
    api.indexOf("export type ConnectionLogReplay ="),
  );
  assert.doesNotMatch(listBoundary, /terminalData|terminal_data/);
  assert.match(api, /"ssh"[\s\S]*?"telnet"[\s\S]*?"local"[\s\S]*?"mosh"[\s\S]*?"et"[\s\S]*?"serial"/);
});

test("Connection Logs API separates list/CAS metadata from one-log replay and export operations", async () => {
  const api = await readFile(apiUrl, "utf8");
  assert.match(api, /exportLog: "export_connection_log"/);
  assert.match(api, /list: "list_connection_logs"/);
  assert.match(api, /replace: "replace_connection_logs"/);
  assert.match(api, /clearUnsaved: "clear_unsaved_connection_logs"/);
  assert.match(api, /readReplay: "read_connection_log_replay"/);
  assert.match(api, /expectedInventoryRevision: unknown;/);
  assert.match(api, /invoke<ConnectionLogsCatalog>\(CONNECTION_LOGS_COMMANDS\.list\)/);
  assert.match(api, /invoke<ConnectionLogsCatalog>\(CONNECTION_LOGS_COMMANDS\.replace, \{ request \}\)/);
  assert.match(api, /invoke<ConnectionLogsCatalog>\(CONNECTION_LOGS_COMMANDS\.clearUnsaved, \{ request \}\)/);
  assert.match(api, /invoke<ConnectionLogReplay>\(CONNECTION_LOGS_COMMANDS\.readReplay, \{ request: \{ logId \} \}\)/);
  assert.match(api, /export const exportConnectionLog = \(\s*logId: string,\s*locale: Locale,/);
  assert.match(
    api,
    /invoke<ExportConnectionLogResponse>\(CONNECTION_LOGS_COMMANDS\.exportLog, \{\s*request: \{ logId, locale: normalizeLocale\(locale\) \},\s*\}\)/,
  );
  const exportBoundary = api.slice(
    api.indexOf("export const exportConnectionLog"),
    api.indexOf("export const listConnectionLogs"),
  );
  assert.doesNotMatch(exportBoundary, /path|terminalData|terminal_data/);
  assert.match(api, /export type ConnectionLogReplay = \{[\s\S]*?logId: string;[\s\S]*?terminalData: string;/);
  assert.match(api, /export type ExportConnectionLogResponse = \{[\s\S]*?success: boolean;[\s\S]*?canceled\?: boolean;/);
  assert.doesNotMatch(api, /append_|capture_/);
});

test("native errors become fixed messages and never reflect attacker-controlled text", () => {
  const stale = classifyConnectionLogsError(
    new Error("CONNECTION_LOGS_INVENTORY_CHANGED: private-hostname-marker"),
    t,
  );
  assert.equal(stale.inventoryChanged, true);
  assert.equal(stale.message.includes("private-hostname-marker"), false);

  const invalid = classifyConnectionLogsError(
    new Error("CONNECTION_LOGS_INVALID: private-username-marker"),
    t,
  );
  assert.equal(invalid.inventoryChanged, false);
  assert.equal(invalid.message.includes("private-username-marker"), false);

  const fallback = classifyConnectionLogsError("arbitrary private endpoint", t);
  assert.equal(fallback.inventoryChanged, false);
  assert.equal(fallback.message.includes("private endpoint"), false);

  const unavailable = classifyConnectionLogReplayError(
    new Error("CONNECTION_LOG_REPLAY_UNAVAILABLE: private-log-id"),
    t,
  );
  assert.equal(unavailable.unavailable, true);
  assert.equal(unavailable.message.includes("private-log-id"), false);

  const replayFailure = classifyConnectionLogReplayError(
    new Error("arbitrary replay failure: private-output-marker"),
    t,
  );
  assert.equal(replayFailure.unavailable, false);
  assert.equal(replayFailure.message.includes("private-output-marker"), false);
});

test("workspace is browser-safe and never invokes native commands in preview", async () => {
  const component = await readFile(componentUrl, "utf8");
  assert.match(component, /api !== undefined \|\| isTauri\(\)/);
  assert.match(component, /if \(!nativeRuntimeAvailable\) \{[\s\S]*?applyCatalog\(EMPTY_CATALOG\)/);
  const guard = component.indexOf("if (!nativeRuntimeAvailable)");
  const list = component.indexOf("const next = await adapter.list()", guard);
  assert.ok(guard >= 0 && list > guard, "native list must remain behind the runtime guard");
  assert.match(component, /if \(!nativeRuntimeAvailable\) \{[\s\S]*?status: "ready", terminalData: ""/);
  assert.match(component, /useI18n\(locale\)/);
  assert.match(component, /t\("connectionLogs\.empty"\)/);
  assert.match(component, /t\("connectionLogs\.emptyDescription"\)/);
});

test("legacy table ordering, columns, icons, row navigation, and pagination are preserved", async () => {
  const component = await readFile(componentUrl, "utf8");
  assert.match(component, /export const CONNECTION_LOGS_PAGE_SIZE = 30/);
  assert.match(component, /sortConnectionLogsNewestFirst/);
  assert.match(component, /right\.startTime > left\.startTime \? 1 : -1/);
  assert.match(component, /sortedLogs\.slice\(0, renderLimit\)/);
  assert.match(component, /t\("connectionLogs\.date"\)/);
  assert.match(component, /t\("connectionLogs\.user"\)/);
  assert.match(component, /t\("connectionLogs\.host"\)/);
  assert.match(component, /t\("connectionLogs\.saved"\)/);
  assert.match(component, /log\.protocol === "local"/);
  assert.match(component, /log\.protocol === "serial"/);
  assert.match(component, /t\("connectionLogs\.protocol\.local"\)/);
  assert.match(component, /t\("connectionLogs\.protocol\.serial"\)/);
  assert.match(component, /t\("connectionLogs\.protocol\.detail", \{/);
  assert.match(component, /<small title=\{targetSubtitle\}>[\s\S]*?\{targetSubtitle\}/);
  assert.match(component, /ConnectionLogGlyph name="usb"/);
  assert.match(component, /ConnectionLogGlyph name="server"/);
  assert.match(component, /data-icon-id=\{log\.hostIconId\}/);
  assert.match(component, /data-host-distro=\{log\.hostDistro\}/);
  assert.match(component, /onClick=\{\(\) => void openReplay\(log\.id\)\}/);
  assert.match(component, /event\.stopPropagation\(\)/);
  assert.match(component, /limit \+ CONNECTION_LOGS_PAGE_SIZE/);
});

test("bookmark, delete, and clear use complete-inventory CAS with one conflict retry", async () => {
  const component = await readFile(componentUrl, "utf8");
  const mutation = component.slice(
    component.indexOf("const mutateCatalog = useCallback"),
    component.indexOf("const toggleSaved = useCallback"),
  );
  assert.match(mutation, /for \(let attempt = 0; attempt < 2; attempt \+= 1\)/);
  assert.match(mutation, /expectedInventoryRevision: base\.inventoryRevision/);
  assert.match(mutation, /if \(!failure\.inventoryChanged \|\| attempt > 0\) throw reason/);
  assert.match(mutation, /base = await adapter\.list\(\)/);
  assert.match(mutation, /applyCatalog\(base\)/);
  assert.match(component, /saved: !log\.saved/);
  assert.match(component, /logs\.filter\(\(log\) => log\.id !== id\)/);
  assert.match(component, /logs\.filter\(\(log\) => log\.saved\)/);
  assert.match(component, /t\([\s\S]*?"connectionLogs\.clearDescriptionOne"[\s\S]*?"connectionLogs\.clearDescription"/);
  assert.match(mutation, /pendingNotice = t\("connectionLogs\.updating"\)/);
  assert.match(mutation, /setMutationPendingLabel\(pendingNotice\)/);
  const clearStart = component.indexOf("const clearUnsaved = useCallback");
  const clear = component.slice(clearStart, clearStart + 520);
  assert.match(clear, /t\("connectionLogs\.clearing"\)/);
});

test("clearing logs dismisses the blocking backdrop before native cleanup and retires late reads", async () => {
  const component = await readFile(componentUrl, "utf8");
  const mutationStart = component.indexOf("mutationLock.current = true;");
  const mutationGuard = component.slice(mutationStart, mutationStart + 420);
  assert.match(mutationGuard, /loadSequence\.current \+= 1/);

  const confirmStart = component.indexOf("className=\"danger\"");
  const confirm = component.slice(confirmStart, confirmStart + 520);
  assert.match(confirm, /setClearConfirmationOpen\(false\)/);
  assert.match(confirm, /void clearUnsaved\(\)/);
  assert.ok(
    confirm.indexOf("setClearConfirmationOpen(false)") < confirm.indexOf("void clearUnsaved()"),
    "the clear dialog must close before awaiting native Vault/replay cleanup",
  );
  assert.match(component, /className="connection-logs-message pending"/);
  assert.match(component, /t\("connectionLogs\.clearing"\)/);
});

test("single-log replay writes captured data into read-only xterm and handles every state", async () => {
  const component = await readFile(componentUrl, "utf8");
  assert.match(component, /import \{ FitAddon \} from "@xterm\/addon-fit"/);
  assert.match(component, /import \{ Terminal \} from "@xterm\/xterm"/);
  assert.match(component, /disableStdin: true/);
  assert.doesNotMatch(component, /\.onData\(/);
  assert.match(component, /const fitter = new FitAddon\(\)/);
  assert.match(component, /new ResizeObserver\(fit\)/);
  assert.match(component, /const response = await adapter\.readReplay\(logId\)/);
  assert.match(component, /validateReplayPayload\(response, logId\)/);
  assert.match(component, /CONNECTION_LOG_REPLAY_MAX_BYTES = 1_000_000/);
  assert.match(component, /instance\.write\(replayData\)/);
  assert.match(component, /safeMetadataText\(log\.hostname\)/);
  assert.match(component, /t\("connectionLogs\.replay\.emptyNotice"\)/);
  assert.match(component, /t\("connectionLogs\.replay\.loading"\)/);
  assert.match(component, /t\("connectionLogs\.replay\.openFailed"\)/);
  for (const field of ["host", "user", "protocol", "time", "duration"]) {
    assert.match(component, new RegExp(`t\\("connectionLogs\\.replay\\.${field}Prefix"\\)`));
  }
  assert.doesNotMatch(
    component,
    /t\("connectionLogs\.replay\.(?:host|user|protocol|time|duration)"\)\}:/,
  );
  assert.match(component, /onRetry=\{\(\) => void openReplay\(selectedLog\.id\)\}/);
  assert.match(component, /t\("connectionLogs\.replay\.readOnly"\)/);
  assert.match(component, /onFontSizeChange/);
  assert.match(component, /exportLog: typeof exportConnectionLog/);
  assert.match(component, /exportLog: exportConnectionLog/);
  assert.match(component, /replay\.status === "ready" && replay\.terminalData\.length > 0/);
  assert.match(component, /className="connection-log-replay-export"/);
  assert.match(component, /disabled=\{disabled \|\| exporting\}/);
  assert.match(component, /const exportLock = useRef\(false\)/);
  assert.match(component, /if \(disabled \|\| !nativeRuntimeAvailable \|\| exportLock\.current\) return;/);
  assert.match(component, /replayState\?\.logId !== logId[\s\S]*?replayState\.status !== "ready"[\s\S]*?replayState\.terminalData\.length === 0/);
  assert.match(component, /const response = await adapter\.exportLog\(logId, locale\)/);
  assert.match(component, /\[adapter, disabled, locale, nativeRuntimeAvailable, replayState\]/);
  assert.match(component, /console\.error\("Connection log export failed\."\)/);
  assert.doesNotMatch(component, /console\.error\("Connection log export failed\.",/);
});

test("Connection Logs styles preserve the legacy light Vault table and replay shell", async () => {
  const styles = await readFile(stylesUrl, "utf8");
  assert.match(styles, /\.surface-vault \.connection-panel > \.connection-logs-view/);
  assert.match(styles, /\.connection-logs-toolbar\s*\{[\s\S]*?56px/);
  assert.match(styles, /grid-template-columns: 128px 224px minmax\(190px, 1fr\) 80px/);
  assert.match(styles, /\.connection-log-row\s*\{[\s\S]*?min-height: 64px/);
  assert.match(styles, /\.connection-log-target-icon\.local/);
  assert.match(styles, /\.connection-log-target-icon\.serial/);
  assert.match(styles, /\.connection-log-target-icon\.host\.snapshot/);
  assert.match(styles, /\.connection-log-replay-terminal \.xterm/);
  assert.match(styles, /\.connection-log-replay-state/);
  assert.match(styles, /\.connection-log-replay-actions button\.connection-log-replay-export/);
  assert.match(styles, /\.connection-log-replay-export \.connection-log-glyph/);
  assert.match(styles, /@keyframes connection-log-replay-spin/);
  assert.match(styles, /\.connection-logs-dialog-backdrop/);
  assert.match(styles, /\.connection-logs-workspace\s*\{[\s\S]*?container-type:\s*inline-size/);
  assert.match(styles, /\.connection-logs-toolbar > div:first-child\s*\{[\s\S]*?flex:\s*1 1 auto/);
  assert.match(styles, /@container \(max-width: 520px\)[\s\S]*?flex-wrap:\s*wrap/);
});

test("TerminalWorkspace enables the original Logs navigation and mounts the catalog", async () => {
  const [workspace, backend] = await Promise.all([
    readFile(new URL("../../src/TerminalWorkspace.tsx", import.meta.url), "utf8"),
    readFile(new URL("../../src/backend.ts", import.meta.url), "utf8"),
  ]);

  assert.match(workspace, /\| "logs"/);
  assert.match(workspace, /showVaultView\("logs"\)/);
  assert.match(workspace, /<ConnectionLogsWorkspace/);
  assert.match(workspace, /className="connection-logs-view"/);
  assert.doesNotMatch(workspace, /Connection Logs 正在迁移/);
  assert.match(backend, /from "\.\/connectionLogsApi"/);
});
