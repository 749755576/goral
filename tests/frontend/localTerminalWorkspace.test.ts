import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const backendUrl = new URL("../../src/backend.ts", import.meta.url);
const controllerUrl = new URL("../../src/localTerminalSessionController.ts", import.meta.url);
const panelUrl = new URL("../../src/LocalTerminalPanel.tsx", import.meta.url);
const sessionsUrl = new URL("../../src/LocalTerminalSessions.tsx", import.meta.url);
const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);

const sliceBetween = (source: string, start: string, end: string): string => {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex + start.length);
  assert.ok(startIndex >= 0, `missing start marker: ${start}`);
  assert.ok(endIndex > startIndex, `missing end marker after ${start}: ${end}`);
  return source.slice(startIndex, endIndex);
};

test("local PTY backend contract discovers shells and owns the complete session lifecycle", async () => {
  const backend = await readFile(backendUrl, "utf8");

  assert.match(backend, /export type DiscoveredLocalShell = \{[\s\S]*?id: string;[\s\S]*?command: string;[\s\S]*?args: string\[\];[\s\S]*?isDefault: boolean/);
  assert.match(backend, /invoke<DiscoveredLocalShell\[\]>\("list_local_shells"\)/);
  assert.match(backend, /startSessionWithChannels\("start_local_pty_session", request, callbacks\)/);
  assert.match(backend, /sendRawSessionInput\("local_pty_session_input_raw", sessionId, data\)/);
  assert.match(backend, /invoke\("resize_local_pty_session", \{ sessionId, size \}\)/);
  assert.match(backend, /invoke\("close_local_pty_session", \{ sessionId \}\)/);
  assert.match(backend, /invoke\("cancel_local_pty_session", \{ sessionId \}\)/);
});

test("local terminal panel selects only discovered shell IDs and supports an optional native cwd", async () => {
  const panel = await readFile(panelUrl, "utf8");

  assert.match(panel, /shellSource = listLocalShells/);
  assert.match(panel, /result\.find\(\(shell\) => shell\.isDefault\)\?\.id/);
  assert.match(panel, /directory: true/);
  assert.match(panel, /initialCwd\?: string/);
  assert.match(panel, /useState\(initialCwd\)/);
  assert.match(panel, /shellId: selectedShell\.id/);
  assert.match(panel, /shell: selectedShell/);
  assert.doesNotMatch(panel, /startLocalPtySession|invoke\(/);
});

test("Terminal action delegates the complete Local PTY lifecycle to the multi-session controller", async () => {
  const [workspace, sessions, controller] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(sessionsUrl, "utf8"),
    readFile(controllerUrl, "utf8"),
  ]);
  const connect = sliceBetween(workspace, "const handleLocalTerminalConnect", "const openQuickSerialPanel");

  assert.match(workspace, /onClick=\{openLocalTerminalPanel\}[\s\S]*?<VaultGlyph name="terminal" \/> \{t\("workspace\.localTerminal"\)\}/);
  assert.match(workspace, /<LocalTerminalPanel[\s\S]*?onConnect=\{handleLocalTerminalConnect\}/);
  assert.match(workspace, /initialCwd=\{rendererSettings\.terminal\.localStartDir\}/);
  assert.match(
    workspace,
    /useLocalTerminalSessions\(\s*localTerminalAppearance,\s*terminalSessionCatalog,\s*t,\s*\)/,
  );
  assert.match(
    workspace,
    /useSshTerminalSessions\(\s*terminalSessionCatalog,\s*resolveSshTerminalAppearance,\s*t,\s*\)/,
  );
  assert.match(workspace, /const sharedTerminalRegistry = localTerminals\.registry/);
  assert.match(workspace, /<LocalTerminalSessionViewports[\s\S]*?registry=\{sharedTerminalRegistry\}/);
  assert.match(connect, /localTerminals\.open\(\{[\s\S]*?shell: submission\.shell/);

  for (const backendCall of [
    "startLocalPtySession",
    "sendLocalPtyInput",
    "resizeLocalPtySession",
    "closeLocalPtySession",
    "cancelLocalPtySession",
  ]) {
    assert.doesNotMatch(
      workspace,
      new RegExp(`\\b${backendCall}\\s*\\(`),
      `${backendCall} must not leak back into TerminalWorkspace's legacy singleton`,
    );
  }

  assert.match(sessions, /backend:\s*\{[\s\S]*?start: startLocalPtySession,[\s\S]*?sendInput: sendLocalPtyInput,[\s\S]*?resize: resizeLocalPtySession,[\s\S]*?close: closeLocalPtySession,[\s\S]*?cancel: cancelLocalPtySession/);
  assert.match(controller, /#dependencies\.backend\.start\(\{[\s\S]*?shellId: runtime\.target\.shell\.id/);
  assert.match(controller, /term: "xterm-256color"/);
  assert.match(controller, /createTerminalInputBinding\(terminal, dispatchInput\)/);
  assert.match(controller, /getByBackendSessionId\(backendSessionId\) === runtime/);
  assert.match(controller, /inputWriteQueue\.enqueue\([\s\S]*?backend\.sendInput\([\s\S]*?backendSessionId/);
  assert.match(controller, /terminal\.onData\(runtime\.inputBinding\.handleData\)/);
  assert.match(controller, /createResizeCoordinator\([\s\S]*?getByBackendSessionId\(backendSessionId\) !== runtime[\s\S]*?backend\.resize\(backendSessionId, size\)/);
  assert.match(controller, /async retry\(id: WorkspaceSessionId\)[\s\S]*?#startRuntime\(runtime, true\)/);
  assert.match(controller, /operation\.connected[\s\S]*?#dependencies\.backend\.close[\s\S]*?#dependencies\.backend\.cancel/);
});

test("local terminal remains isolated from SSH credentials, host CRUD, and SFTP", async () => {
  const workspace = await readFile(workspaceUrl, "utf8");
  const connect = sliceBetween(workspace, "const handleLocalTerminalConnect", "const openQuickSerialPanel");
  const connectionTypes = sliceBetween(workspace, "type ConnectionProtocol", "type TerminalSidePanelResize");
  const close = sliceBetween(workspace, "const closeTerminalSession", "const cancelTerminalSession");
  const cancel = sliceBetween(workspace, "const cancelTerminalSession", "const isSavedCredentialNotFound");

  assert.doesNotMatch(connect, /stageSshPassword|stageTelnetPassword|credentialReference|createSavedHost|updateSavedHost/);
  assert.match(
    workspace,
    /sftpAvailable = activeSshSession !== null \|\| connectionTarget\?\.protocol === "ssh"/,
  );
  assert.doesNotMatch(connectionTypes, /"local"|localShell|localCwd/);
  assert.doesNotMatch(connect, /hostname|port|username|credential|sftp/i);
  for (const protocol of ["telnet", "serial", "mosh", "et"]) {
    assert.match(close, new RegExp(`active\\.protocol === "${protocol}"`));
    assert.match(cancel, new RegExp(`active\\.protocol === "${protocol}"`));
  }
  assert.match(close, /closeSshSession\(active\.sessionId\)/);
  assert.match(cancel, /cancelSshSession\(active\.sessionId\)/);
  assert.doesNotMatch(close, /local/i);
  assert.doesNotMatch(cancel, /local/i);
});
