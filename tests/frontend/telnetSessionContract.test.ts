import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const backendUrl = new URL("../../src/backend.ts", import.meta.url);
const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);
const savedHostEditorDialogUrl = new URL("../../src/SavedHostEditorDialog.tsx", import.meta.url);

test("Telnet client keeps passwords on raw staging and exposes a typed session boundary", async () => {
  const backend = await readFile(backendUrl, "utf8");
  assert.match(backend, /invoke<string>\("stage_telnet_password", payload\)/);
  assert.match(backend, /stageTelnetPassword[\s\S]*?finally \{[\s\S]*?payload\.fill\(0\)/);
  assert.match(backend, /"start_telnet_session"/);
  assert.match(backend, /"telnet_session_input_raw"/);
  assert.match(backend, /"resize_telnet_session"/);
  assert.match(backend, /"close_telnet_session"/);
  assert.match(backend, /"cancel_telnet_session"/);

  const request = backend.slice(
    backend.indexOf("export type StartTelnetSessionRequest"),
    backend.indexOf("export const getBackendStatus"),
  );
  assert.match(request, /credentialReference\?: string/);
  assert.match(request, /username\?: string/);
  assert.match(request, /startupCommand\?: string/);
  assert.doesNotMatch(request, /password\??:/);
  assert.doesNotMatch(backend, /telnetAutoLoginComplete|telnetAutoLoginCancelled/);
  assert.match(backend, /dispose: \(\) => void/);
  assert.match(backend, /catch \(reason\) \{[\s\S]*?dispose\(\);[\s\S]*?throw reason/);
});

test("Quick SSH uses the shared controller while Telnet never gains SFTP authority", async () => {
  const workspace = await readFile(workspaceUrl, "utf8");
  const quickConnect = workspace.slice(
    workspace.indexOf("const connect = async"),
    workspace.indexOf("const retryTelnetConnection"),
  );
  const legacySftpBinding = workspace.slice(
    workspace.indexOf("const bindSftpSessionOwner"),
    workspace.indexOf("const isCurrentSftpOwner"),
  );
  const telnetBranch = quickConnect.slice(
    quickConnect.indexOf('if (quickProtocol === "telnet")'),
    quickConnect.indexOf("if (connectionOperation.current"),
  );
  assert.match(workspace, /useState<NetworkConnectionProtocol>\("ssh"\)/);
  assert.match(workspace, /<option value="ssh">SSH<\/option>/);
  assert.match(workspace, /<option value="telnet">Telnet<\/option>/);
  assert.match(workspace, /resolveQuickConnectProtocolPort\([\s\S]*?quickProtocol,[\s\S]*?nextProtocol/);
  assert.match(quickConnect, /quickProtocol === "telnet"[\s\S]*?activateSession\([\s\S]*?stageTelnetPassword/);
  assert.match(quickConnect, /startTelnetSession\(\{/);
  assert.match(quickConnect, /return \{ \.\.\.active, protocol: "telnet" \}/);
  assert.match(quickConnect, /sshTerminals\.open\(\{[\s\S]*?kind: "quick"/);
  assert.match(quickConnect, /bindSftpWorkspace\(result\.id\)/);
  assert.match(workspace, /active\.protocol === "telnet"[\s\S]*?sendTelnetInput/);
  assert.match(workspace, /active\.protocol === "telnet"[\s\S]*?resizeTelnetSession/);
  assert.match(workspace, /active\.protocol === "telnet"[\s\S]*?closeTelnetSession/);
  assert.match(legacySftpBinding, /legacy[\s\S]*?singleton no longer starts SSH[\s\S]*?return false/);
  assert.doesNotMatch(telnetBranch, /bindSftpWorkspace|sftpController/);
  assert.match(workspace, /activeSftpWorkspaceIdRef\.current = activeSshSession\?\.id \?\? null/);
  assert.match(workspace, /sftpAvailable = activeSshSession !== null \|\| connectionTarget\?\.protocol === "ssh"/);
  assert.match(workspace, /sftpTabVisible = sftpAvailable && rendererSettings\.appearance\.showSftpTab/);
  assert.match(workspace, /\{sftpTabVisible && \([\s\S]*?title="SFTP"/);
});

test("Telnet echo negotiation updates the local xterm echo path", async () => {
  const [backend, workspace] = await Promise.all([
    readFile(backendUrl, "utf8"),
    readFile(workspaceUrl, "utf8"),
  ]);
  assert.match(backend, /type: "telnetEchoMode"; remoteEcho: boolean; localEcho: boolean/);
  assert.match(workspace, /case "telnetEchoMode"/);
  assert.match(workspace, /telnetLocalEcho\.current = control\.localEcho/);
  assert.match(workspace, /formatTelnetLocalEcho\(prepared\.text\)/);
});

test("Telnet retires stale generations and offers only an explicit scrollback-preserving retry", async () => {
  const workspace = await readFile(workspaceUrl, "utf8");
  const controlHandler = workspace.slice(
    workspace.indexOf("const handleSessionControl"),
    workspace.indexOf("const handleSessionData"),
  );
  const dataHandler = workspace.slice(
    workspace.indexOf("const handleSessionData"),
    workspace.indexOf("const buildShellRequest"),
  );
  const retry = workspace.slice(
    workspace.indexOf("const retryTelnetConnection"),
    workspace.indexOf("const connectSavedHost"),
  );

  assert.match(controlHandler, /connectionOperation\.current !== operation\) return/);
  assert.match(dataHandler, /connectionOperation\.current !== operation \|\| operation\.cancelRequested\) return/);
  assert.match(controlHandler, /telnetLocalEcho\.current = false/);
  assert.match(controlHandler, /operation\.handle\?\.dispose\(\)/);
  assert.match(retry, /connectionState !== "disconnected"/);
  assert.match(retry, /startTelnetSession\(\{/);
  assert.doesNotMatch(retry, /stageTelnetPassword/);
  assert.match(retry, /\{ preserveScrollback: true \}/);
  assert.match(workspace, /aria-label=\{t\("workspace\.retryTelnet"\)\}[\s\S]*?onClick=\{\(\) => void retryTelnetConnection\(\)\}/);
  assert.doesNotMatch(workspace, /setTimeout\([\s\S]{0,200}retryTelnetConnection/);
});

test("SavedHost Telnet keeps protocol, credentials, retry, and SSH-only features separated", async () => {
  const [backend, workspace, savedHostEditorDialog] = await Promise.all([
    readFile(backendUrl, "utf8"),
    readFile(workspaceUrl, "utf8"),
    readFile(savedHostEditorDialogUrl, "utf8"),
  ]);
  const savedRequest = backend.slice(
    backend.indexOf("export type StartSavedTelnetSessionRequest"),
    backend.indexOf("export type StartTelnetSessionRequest"),
  );
  assert.match(backend, /protocol\?: "ssh" \| "telnet" \| "serial"/);
  assert.match(backend, /"start_saved_telnet_session"/);
  assert.match(savedRequest, /hostId: string/);
  assert.match(savedRequest, /expectedRevision: number/);
  assert.match(savedRequest, /credentialReference\?: string/);
  assert.doesNotMatch(savedRequest, /password\??:/);

  const connectSaved = workspace.slice(
    workspace.indexOf("const connectSavedHost"),
    workspace.indexOf("const beginSavedHostConnection"),
  );
  assert.match(connectSaved, /isSavedTelnetHost\(host\)/);
  assert.match(connectSaved, /stageTelnetPassword\(passwordToStage\)/);
  assert.match(connectSaved, /startSavedTelnetSession\(\{/);
  assert.match(connectSaved, /return \{ \.\.\.active, protocol: "telnet" \}/);
  assert.match(workspace, /target\.savedHost[\s\S]*?startSavedTelnetSession\(\{/);
  assert.match(savedHostEditorDialog, /editor\.protocol === "ssh" && \(/);
  assert.match(workspace, /protocol: editor\.protocol/);
  assert.match(workspace, /editor\.authMethod === "password" && editor\.passwordIdentityId/);
  assert.match(
    connectSaved,
    /username: protocol === "serial" \? "" : savedHostEffectiveUsername\(host\)/,
  );
});
