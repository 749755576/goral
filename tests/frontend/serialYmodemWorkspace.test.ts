import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const backendUrl = new URL("../../src/backend.ts", import.meta.url);
const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);
const driverUrl = new URL("../../src-tauri/src/serial_ymodem.rs", import.meta.url);

const sliceBetween = (source: string, start: string, end: string): string => {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex + start.length);
  assert.ok(startIndex >= 0, `missing start marker: ${start}`);
  assert.ok(endIndex > startIndex, `missing end marker after ${start}: ${end}`);
  return source.slice(startIndex, endIndex);
};

test("YMODEM renderer boundary keeps native paths out of requests and exposes typed progress", async () => {
  const backend = await readFile(backendUrl, "utf8");
  const command = sliceBetween(backend, "const runSerialYmodemCommand", "export const resizeLocalPtySession");

  assert.match(backend, /export type SerialYmodemDirection = "send" \| "receive"/);
  assert.match(backend, /export type SerialYmodemProgressEvent = \{[\s\S]*?transferId: string;[\s\S]*?transferredBytes: number;[\s\S]*?totalBytes: number;[\s\S]*?fileName\?: string/);
  assert.match(command, /sessionId: string,[\s\S]*?locale: Locale,[\s\S]*?onProgress:/);
  assert.match(command, /new Channel<SerialYmodemProgressEvent>\(\)/);
  assert.match(command, /invoke<T>\(command, \{ sessionId, locale, onProgress: progressChannel \}\)/);
  assert.match(command, /"send_serial_ymodem"/);
  assert.match(command, /"receive_serial_ymodem"/);
  assert.match(command, /invoke\("cancel_serial_ymodem", \{ sessionId, transferId \}\)/);
  assert.doesNotMatch(command, /localPath|destinationPath|filePath/);
});

test("YMODEM native picker defaults missing or non-English locales to Chinese", async () => {
  const driver = await readFile(driverUrl, "utf8");

  assert.match(driver, /impl<'de> Deserialize<'de> for SerialTransferDialogLocale/);
  assert.match(driver, /if locale == "en-US" \{[\s\S]*?Self::EnUs[\s\S]*?\} else \{[\s\S]*?Self::ZhCn/);
  assert.match(driver, /serial_transfer_dialog_locale\([\s\S]*?locale\.unwrap_or_default\(\)/);
  assert.match(driver, /send_serial_ymodem\([\s\S]*?locale: Option<SerialTransferDialogLocale>/);
  assert.match(driver, /receive_serial_ymodem\([\s\S]*?locale: Option<SerialTransferDialogLocale>/);
  assert.match(driver, /send_title: "选择要通过 YMODEM 发送的文件"/);
  assert.match(driver, /receive_title: "选择保存 YMODEM 接收文件的文件夹"/);
  assert.match(driver, /send_title: "Select a file to send with YMODEM"/);
  assert.match(driver, /receive_title: "Select a folder for received YMODEM files"/);
  assert.match(driver, /\.set_title\(text\.send_title\)[\s\S]*?\.add_filter\(text\.all_files_filter, &\["\*"\]\)/);
  assert.match(driver, /\.set_title\(text\.receive_title\)[\s\S]*?\.pick_folder/);
});

test("YMODEM native progress publishes its opaque ID and cancel matches it atomically", async () => {
  const driver = await readFile(driverUrl, "utf8");
  const cancel = sliceBetween(driver, "pub(crate) fn cancel_serial_ymodem", "async fn choose_send_file");

  assert.match(driver, /pub\(crate\) struct SerialYmodemProgressEvent \{[\s\S]*?transfer_id: String/);
  assert.match(driver, /let transfer_id = transfer\.transfer_id\(\)\.clone\(\)/);
  assert.match(driver, /transfer_id: transfer_id\.as_str\(\)\.to_owned\(\)/);
  assert.match(cancel, /parse_transfer_id\(&transfer_id\)/);
  assert.match(cancel, /request_transfer_cancel_exact\(&session_id, &transfer_id\)/);
  assert.doesNotMatch(cancel, /active_transfer_kind|request_transfer_cancel\(&session_id\)/);
  assert.equal(
    (driver.match(/\.write_protocol_abort\(&YMODEM_CANCEL_SEQUENCE\)/g) ?? []).length,
    2,
    "both send and receive failures must use the exact-token abort write",
  );
  assert.match(driver, /fn should_send_protocol_abort[\s\S]*?YmodemError::RemoteCancelled/);
});

test("connected Serial sessions expose send, receive, progress, and cancel controls", async () => {
  const workspace = await readFile(workspaceUrl, "utf8");

  assert.match(workspace, /connectionTarget\?\.protocol === "serial"[\s\S]*?startSerialYmodemTransfer\("send"\)/);
  assert.match(workspace, /connectionTarget\?\.protocol === "serial"[\s\S]*?startSerialYmodemTransfer\("receive"\)/);
  assert.match(workspace, /className="serial-ymodem-status"/);
  assert.match(workspace, /requestSerialYmodemCancel\(\)/);
  assert.match(workspace, /aria-label=\{t\("workspace\.cancelYmodem"\)\}/);
  assert.match(workspace, /sendSerialYmodem\(owner\.sessionId, rendererLocale, onProgress\)/);
  assert.match(workspace, /receiveSerialYmodem\(owner\.sessionId, rendererLocale, onProgress\)/);
});

test("YMODEM callbacks and terminal input remain bound to the exact Serial session generation", async () => {
  const workspace = await readFile(workspaceUrl, "utf8");
  const input = sliceBetween(workspace, "const dispatchInput", "const observer = new ResizeObserver");
  const transfer = sliceBetween(workspace, "const startSerialYmodemTransfer", "const requestSerialYmodemCancel");
  const cancel = sliceBetween(workspace, "const requestSerialYmodemCancel", "const requestSerialZmodemCancel");
  const disconnect = sliceBetween(
    workspace,
    "const disconnect = async",
    "const refreshDependentCatalogsAfterKnownHostsMutation",
  );
  const closed = sliceBetween(workspace, 'case "closed":', 'case "exitStatus":');

  assert.match(input, /transferOwner\?\.sessionId === active\.sessionId/);
  assert.match(input, /prepared\.text\.includes\("\\x03"\)[\s\S]*?transferOwner\.transferId !== null[\s\S]*?cancelSerialYmodem\(active\.sessionId, transferOwner\.transferId\)/);
  assert.match(input, /return;[\s\S]*?const config = serialInputConfig\.current/);
  assert.match(transfer, /serialYmodemTransferOwner\.current !== owner/);
  assert.match(transfer, /session\.current\?\.sessionId !== owner\.sessionId/);
  assert.match(transfer, /connectionOperation\.current !== operation/);
  assert.match(transfer, /owner\.transferId !== null && owner\.transferId !== progress\.transferId/);
  assert.match(transfer, /owner\.transferId = progress\.transferId/);
  assert.match(cancel, /cancelSerialYmodem\(owner\.sessionId, owner\.transferId\)/);
  assert.match(disconnect, /cancelSerialYmodem\(active\.sessionId, transferOwner\.transferId\)/);
  assert.match(closed, /serialYmodemTransferOwner\.current = null/);
  assert.match(closed, /setSerialYmodemTransfer\(null\)/);
});
