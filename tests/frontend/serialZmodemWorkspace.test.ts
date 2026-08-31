import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const backendUrl = new URL("../../src/backend.ts", import.meta.url);
const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);
const driverUrl = new URL("../../src-tauri/src/serial_zmodem.rs", import.meta.url);

const sliceBetween = (source: string, start: string, end: string): string => {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex + start.length);
  assert.ok(startIndex >= 0, `missing start marker: ${start}`);
  assert.ok(endIndex > startIndex, `missing end marker after ${start}: ${end}`);
  return source.slice(startIndex, endIndex);
};

test("ZMODEM renderer requests contain only exact transfer identity, direction, and locale", async () => {
  const backend = await readFile(backendUrl, "utf8");
  const command = sliceBetween(
    backend,
    "export const startSerialZmodem",
    "export const resizeLocalPtySession",
  );

  assert.match(backend, /export type SerialZmodemDirection = "send" \| "receive"/);
  assert.match(backend, /export type SerialZmodemProgressStage = "header" \| "data" \| "finalizing" \| "complete"/);
  assert.match(command, /direction: SerialZmodemDirection,[\s\S]*?locale: Locale,[\s\S]*?onControl:/);
  assert.match(command, /new Channel<SshControlEvent>\(\)/);
  assert.match(command, /invoke<SerialZmodemResponse>\("start_serial_zmodem", \{[\s\S]*?request: \{ sessionId, transferId, direction, locale \},[\s\S]*?onControl: controlChannel/);
  assert.match(command, /invoke\("cancel_serial_zmodem", \{ sessionId, transferId \}\)/);
  assert.doesNotMatch(
    command,
    /localPath|destinationPath|filePath|selectedPath|fileContents|fileBytes|directoryPath/,
  );
});

test("ZMODEM native picker defaults only locale while preserving the strict request boundary", async () => {
  const driver = await readFile(driverUrl, "utf8");

  assert.match(driver, /#\[serde\(rename_all = "camelCase", deny_unknown_fields\)\][\s\S]*?struct StartSerialZmodemRequest/);
  assert.match(driver, /#\[serde\(default\)\]\s*pub\(crate\) locale: SerialTransferDialogLocale/);
  assert.match(driver, /drive_detected_serial_zmodem\([\s\S]*?locale: SerialTransferDialogLocale/);
  assert.match(driver, /send_title: "选择要通过 ZMODEM 发送的文件"/);
  assert.match(driver, /receive_title: "选择保存 ZMODEM 接收文件的文件夹"/);
  assert.match(driver, /send_title: "Select files to send with ZMODEM"/);
  assert.match(driver, /receive_title: "Select a folder for received ZMODEM files"/);
  assert.match(driver, /\.set_title\(text\.send_title\)[\s\S]*?\.add_filter\(text\.all_files_filter, &\["\*"\]\)/);
  assert.match(driver, /\.set_title\(text\.receive_title\)[\s\S]*?\.pick_folder/);
  assert.doesNotMatch(
    driver.slice(driver.indexOf("pub(crate) struct StartSerialZmodemRequest"), driver.indexOf("pub(crate) struct SerialZmodemResponse")),
    /path|contents|bytes/i,
  );
});

test("detected ZMODEM starts once and progress stays bound to its exact operation", async () => {
  const workspace = await readFile(workspaceUrl, "utf8");
  const control = sliceBetween(workspace, "const handleSessionControl", "const handleSessionData");

  assert.match(control, /case "serialZmodemDetected"/);
  assert.match(control, /operation\.protocol !== "serial" \|\| operation\.cancelRequested/);
  assert.match(control, /if \(!operation\.handle\)[\s\S]*?operation\.pendingSerialZmodemDetection \?\?=/);
  assert.match(control, /operation\.handle\.sessionId !== control\.sessionId/);
  assert.match(control, /existing\?\.sessionId === control\.sessionId[\s\S]*?existing\.transferId === control\.transferId/);
  assert.match(control, /existing \|\| serialYmodemTransferOwner\.current/);
  assert.match(control, /transferId: control\.transferId,[\s\S]*?operation,[\s\S]*?cancelRequested: false/);
  assert.match(control, /startSerialZmodem\([\s\S]*?owner\.sessionId,[\s\S]*?owner\.transferId,[\s\S]*?owner\.direction,[\s\S]*?rendererLocale,[\s\S]*?handleSessionControlRef\.current\?\.\(operation, event\)/);
  assert.match(control, /owner\.operation !== operation/);
  assert.match(control, /owner\.sessionId !== control\.sessionId/);
  assert.ok(
    (control.match(/owner\.transferId !== control\.transferId/g) ?? []).length >= 4,
    "progress and every terminal ZMODEM event must reject the wrong transfer",
  );
  assert.match(control, /control\.stage === "finalizing" \? "finalizing" : "transferring"/);
  assert.match(control, /phase: owner\.cancelRequested \? "canceling" : owner\.resumePhase/);
  assert.ok(
    (control.match(/owner\.direction !== control\.direction/g) ?? []).length >= 4,
    "progress and every terminal ZMODEM event must reject the wrong direction",
  );
  assert.match(control, /startSerialZmodem\([\s\S]*?\.then\(\(response\) => \{[\s\S]*?serialZmodemTransferOwner\.current !== owner/);
  assert.match(control, /\.catch\(\(\) => \{[\s\S]*?serialZmodemTransferOwner\.current !== owner/);
  assert.ok(
    (control.match(/setSerialZmodemTransfer\(\(current\) => current\?\.token === owner\.token/g) ?? []).length >= 4,
    "late responses and events may only clear the exact frontend transfer token",
  );
});

test("ZMODEM progress and cancel controls replace YMODEM controls while active", async () => {
  const workspace = await readFile(workspaceUrl, "utf8");
  const labels = sliceBetween(workspace, "const serialZmodemProgressPercent", "return (");
  const toolbar = sliceBetween(workspace, '<div className="terminal-actions">', "{sftpTabVisible && (");

  assert.match(labels, /transferredBytes[\s\S]*?totalBytes[\s\S]*?100/);
  assert.match(labels, /serialZmodemTransfer\.phase === "finalizing"[\s\S]*?t\("workspace\.transferFinalizing"\)/);
  assert.match(workspace, /className="serial-ymodem-status serial-zmodem-status"/);
  assert.match(toolbar, /!serialYmodemTransfer[\s\S]*?!serialZmodemTransfer[\s\S]*?startSerialYmodemTransfer\("send"\)/);
  assert.match(toolbar, /serialZmodemTransfer[\s\S]*?requestSerialZmodemCancel\(\)/);
  assert.match(toolbar, /aria-label=\{t\("workspace\.cancelZmodem"\)\}/);
});

test("Ctrl+C, session close, and a new connection invalidate the exact ZMODEM owner", async () => {
  const workspace = await readFile(workspaceUrl, "utf8");
  const input = sliceBetween(workspace, "const dispatchInput", "const observer = new ResizeObserver");
  const control = sliceBetween(workspace, "const handleSessionControl", "const handleSessionData");
  const activate = sliceBetween(workspace, "const activateSession", "const connect = async");
  const cancel = sliceBetween(workspace, "const requestSerialZmodemCancel", "const disconnect = async");

  assert.match(input, /zmodemOwner\?\.sessionId === active\.sessionId/);
  assert.match(input, /prepared\.text\.includes\("\\x03"\)[\s\S]*?cancelSerialZmodem\(active\.sessionId, zmodemOwner\.transferId\)/);
  assert.match(input, /cancelSerialZmodem[\s\S]*?return;[\s\S]*?const transferOwner = serialYmodemTransferOwner\.current/);
  assert.match(input, /phase: zmodemOwner\.resumePhase/);
  assert.match(cancel, /serialZmodemTransferOwner\.current === owner/);
  assert.match(cancel, /cancelSerialZmodem\(owner\.sessionId, owner\.transferId\)/);
  assert.match(cancel, /phase: owner\.resumePhase/);
  assert.match(control, /case "closed":[\s\S]*?serialZmodemTransferOwner\.current = null[\s\S]*?setSerialZmodemTransfer\(null\)/);
  assert.match(activate, /serialZmodemTransferOwner\.current = null[\s\S]*?setSerialZmodemTransfer\(null\)/);
  assert.match(activate, /pendingSerialZmodemDetection\?\.sessionId === active\.sessionId[\s\S]*?handleSessionControlRef\.current\?\.\(operation/);
});
