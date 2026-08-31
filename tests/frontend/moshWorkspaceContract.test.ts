import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const backendUrl = new URL("../../src/backend.ts", import.meta.url);
const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);

const sliceBetween = (source: string, start: string, end: string): string => {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex + start.length);
  assert.ok(startIndex >= 0, `missing start marker: ${start}`);
  assert.ok(endIndex > startIndex, `missing end marker after ${start}: ${end}`);
  return source.slice(startIndex, endIndex);
};

test("Mosh renderer API exposes only SSH metadata, opaque credentials, and terminal size", async () => {
  const backend = await readFile(backendUrl, "utf8");
  const request = sliceBetween(
    backend,
    "export type StartMoshSessionRequest",
    "export const getBackendStatus",
  );

  assert.match(request, /config: SshConnectionConfig/);
  assert.match(request, /credentialReference: string/);
  assert.match(request, /knownHosts\?: StartSshSessionRequest\["knownHosts"\]/);
  assert.match(request, /verifyHostKeys\?: boolean/);
  assert.match(request, /size: TerminalSize/);
  assert.doesNotMatch(request, /moshKey|clientPath|executable|command:|environment/);
  assert.match(backend, /startSessionWithChannels\("start_mosh_session", request, callbacks\)/);
  assert.match(backend, /startSessionWithChannels\("start_saved_mosh_session", request, callbacks\)/);
});

test("Mosh uses the bounded raw session lifecycle and never enables SFTP", async () => {
  const [backend, workspace] = await Promise.all([
    readFile(backendUrl, "utf8"),
    readFile(workspaceUrl, "utf8"),
  ]);
  const input = sliceBetween(workspace, "const dispatchInput", "const observer = new ResizeObserver");
  const close = sliceBetween(workspace, "const closeTerminalSession", "const cancelTerminalSession");
  const cancel = sliceBetween(workspace, "const cancelTerminalSession", "const isSavedCredentialNotFound");
  const legacyActivation = sliceBetween(workspace, "const activateSession = useCallback", "const connect = async");

  assert.match(backend, /sendRawSessionInput\("mosh_session_input_raw", sessionId, data\)/);
  assert.match(backend, /invoke\("resize_mosh_session", \{ sessionId, size \}\)/);
  assert.match(backend, /invoke\("close_mosh_session", \{ sessionId \}\)/);
  assert.match(backend, /invoke\("cancel_mosh_session", \{ sessionId \}\)/);
  assert.match(input, /active\.protocol === "mosh"[\s\S]*?sendChunks\(prepared\.chunks, sendMoshInput\)/);
  assert.match(workspace, /active\.protocol === "mosh"[\s\S]*?resizeMoshSession\(sessionId, size\)/);
  assert.match(close, /active\.protocol === "mosh"[\s\S]*?closeMoshSession\(active\.sessionId\)/);
  assert.match(cancel, /active\.protocol === "mosh"[\s\S]*?cancelMoshSession\(active\.sessionId\)/);
  assert.match(
    workspace,
    /sftpAvailable = activeSshSession !== null \|\| connectionTarget\?\.protocol === "ssh"/,
  );
  assert.match(legacyActivation, /terminalSessionCatalog\.snapshot\.order\.length > 0/);
});

test("Quick Connect offers Mosh and stages its password through the SSH raw channel", async () => {
  const workspace = await readFile(workspaceUrl, "utf8");
  const connect = sliceBetween(workspace, "const connect = async", "const retryTelnetConnection");

  assert.match(workspace, /<option value="mosh">Mosh<\/option>/);
  assert.match(connect, /quickProtocol === "mosh"/);
  assert.match(connect, /stageSshPassword\(passwordToStage\)/);
  assert.match(connect, /startMoshSession\(\{/);
  assert.match(connect, /verifyHostKeys: true/);
  assert.match(connect, /size: buildShellRequest\(\)\.size/);
  assert.match(connect, /return \{ \.\.\.active, protocol: "mosh" \}/);
  assert.doesNotMatch(connect, /moshKey|clientPath|executable|mosh-server/);
});

test("Saved hosts use only the Rust-projected Mosh switch and reuse native SSH custody", async () => {
  const [backend, workspace] = await Promise.all([
    readFile(backendUrl, "utf8"),
    readFile(workspaceUrl, "utf8"),
  ]);
  const connectSaved = sliceBetween(
    workspace,
    "const connectSavedHost",
    "const beginSavedHostConnection",
  );
  const beginSaved = sliceBetween(
    workspace,
    "const beginSavedHostConnection",
    "const openCreateSavedHost",
  );

  assert.match(backend, /effectiveMoshEnabled\?: boolean/);
  assert.match(
    connectSaved,
    /host\.effectiveMoshEnabled[\s\S]*?\? "mosh"[\s\S]*?: isSavedEtHost\(host\)[\s\S]*?\? "et"[\s\S]*?: "ssh"/,
  );
  assert.match(connectSaved, /stageSshPassword\(passwordToStage\)/);
  assert.match(connectSaved, /const active = await startSavedMoshSession\(\{/);
  assert.match(connectSaved, /return \{ \.\.\.active, protocol: "mosh" \}/);
  assert.match(connectSaved, /size: buildShellRequest\(\)\.size/);
  assert.doesNotMatch(connectSaved, /moshKey|clientPath|executable|mosh-server/);
  assert.match(beginSaved, /!host\.effectiveMoshEnabled[\s\S]*?&& !isSavedEtHost\(host\)/);
  assert.match(
    beginSaved,
    /!usesSharedSshRuntime && terminalSessionCatalog\.snapshot\.order\.length > 0/,
  );
});
