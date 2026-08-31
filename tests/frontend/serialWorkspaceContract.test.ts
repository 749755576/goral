import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);

const sliceBetween = (source: string, start: string, end: string): string => {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex + start.length);
  assert.ok(startIndex >= 0, `missing start marker: ${start}`);
  assert.ok(endIndex > startIndex, `missing end marker after ${start}: ${end}`);
  return source.slice(startIndex, endIndex);
};

test("TerminalWorkspace renders the shared Serial panel for Quick, create, and edit routes", async () => {
  const workspace = await readFile(workspaceUrl, "utf8");

  assert.match(
    workspace,
    /import\s+\{[\s\S]*?SerialConnectPanel[\s\S]*?\}\s+from "\.\/SerialConnectPanel"/,
  );
  assert.match(
    workspace,
    /type SerialPanelState =[\s\S]*?\{ mode: "quick" \}[\s\S]*?\{ mode: "create" \}[\s\S]*?\{ mode: "saved"; hostId: string \}/,
  );
  assert.match(workspace, /<SerialConnectPanel[\s\S]*?mode="quick"[\s\S]*?onConnect=\{handleQuickSerialConnect\}/);
  assert.match(workspace, /<SerialConnectPanel[\s\S]*?mode="create"[\s\S]*?onSave=\{handleCreateSavedSerial\}/);
  assert.match(workspace, /<SerialConnectPanel[\s\S]*?mode="saved"[\s\S]*?onSave=\{handleUpdateSavedSerial\}/);
  assert.equal(
    [...workspace.matchAll(/<SerialConnectPanel[\s\S]*?locale=\{rendererLocale\}/g)].length,
    3,
  );
});

test("Quick Serial has a real entry point and starts the selected config", async () => {
  const workspace = await readFile(workspaceUrl, "utf8");
  const openQuick = sliceBetween(workspace, "const openQuickSerialPanel", "const openCreateSerialPanel");
  const connectQuick = sliceBetween(
    workspace,
    "const handleQuickSerialConnect",
    "const handleCreateSavedSerial",
  );

  assert.match(openQuick, /setSerialPanel\(\{ mode: "quick" \}\)/);
  assert.match(workspace, /<VaultGlyph name="serial" \/> \{t\("workspace\.serial"\)\}/);
  assert.match(workspace, /onClick=\{openQuickSerialPanel\}/);
  assert.doesNotMatch(workspace, /disabled title="Serial[^\n]*迁移/);

  assert.match(connectQuick, /activateSession\(/);
  assert.match(connectQuick, /protocol: "serial"/);
  assert.match(connectQuick, /serialConfig: submission\.config/);
  assert.match(connectQuick, /charset: submission\.charset/);
  assert.match(connectQuick, /startSerialSession\(\{/);
  assert.match(connectQuick, /config: submission\.config/);
  assert.match(connectQuick, /return \{ \.\.\.active, protocol: "serial" \}/);
});

test("Saved Serial create and edit routes remain credential-free", async () => {
  const workspace = await readFile(workspaceUrl, "utf8");
  const create = sliceBetween(
    workspace,
    "const handleCreateSavedSerial",
    "const handleUpdateSavedSerial",
  );
  const update = sliceBetween(
    workspace,
    "const handleUpdateSavedSerial",
    "const connectSavedHost",
  );
  const openEdit = sliceBetween(workspace, "const openEditSavedHost", "const closeSavedHostEditor");

  assert.match(workspace, /const openCreateSerialPanel[\s\S]*?setSerialPanel\(\{ mode: "create" \}\)/);
  assert.match(workspace, /const openSavedSerialPanel[\s\S]*?mode: "saved", hostId: host\.id/);
  assert.match(openEdit, /isSavedSerialHost\(host\)[\s\S]*?openSavedSerialPanel\(host\)[\s\S]*?return/);

  assert.match(create, /createSavedHost\(\{ draft: submission\.draft \}\)/);
  assert.doesNotMatch(create, /stageSshPassword|stageTelnetPassword|stagedCredentialReference|password/);
  assert.match(update, /updateSavedHost\(\{[\s\S]*?id: submission\.id[\s\S]*?expectedRevision: submission\.expectedRevision[\s\S]*?draft: submission\.draft[\s\S]*?credentialMutation: \{ action: "keep" \}/);
  assert.doesNotMatch(update, /stageSshPassword|stageTelnetPassword|stagedCredentialReference|password/);
});

test("Serial sessions own input, resize, close, cancel, and scrollback-preserving retry", async () => {
  const workspace = await readFile(workspaceUrl, "utf8");
  const input = sliceBetween(workspace, "const dispatchInput", "const observer = new ResizeObserver");
  const close = sliceBetween(workspace, "const closeTerminalSession", "const cancelTerminalSession");
  const cancel = sliceBetween(workspace, "const cancelTerminalSession", "const isSavedCredentialNotFound");
  const savedStart = sliceBetween(workspace, "const connectSavedHost", "const beginSavedHostConnection");
  const retry = sliceBetween(workspace, "const retrySerialConnection", "const connectSavedHost");

  assert.match(input, /active\.protocol === "serial"/);
  assert.match(input, /mapTerminalBackspaceInput/);
  assert.match(input, /handleSerialLineModeInput/);
  assert.match(input, /formatSerialLocalEcho/);
  assert.match(input, /sendChunks\([\s\S]*?sendSerialInput/);

  assert.match(workspace, /active\.protocol === "serial"[\s\S]*?resizeSerialSession\(sessionId, size\)/);
  assert.match(close, /active\.protocol === "serial"[\s\S]*?closeSerialSession\(active\.sessionId\)/);
  assert.match(cancel, /active\.protocol === "serial"[\s\S]*?cancelSerialSession\(active\.sessionId\)/);
  assert.match(savedStart, /protocol === "serial"[\s\S]*?startSavedSerialSession\(\{/);
  assert.match(savedStart, /return \{ \.\.\.active, protocol: "serial" \}/);
  assert.match(retry, /target\.protocol !== "serial"/);
  assert.match(retry, /startSavedSerialSession\(\{/);
  assert.match(retry, /startSerialSession\(\{/);
  assert.match(retry, /\{ preserveScrollback: true \}/);
  assert.match(workspace, /onClick=\{\(\) => void retrySerialConnection\(\)\}/);
});

test("Serial sessions never expose SSH-only SFTP", async () => {
  const workspace = await readFile(workspaceUrl, "utf8");
  const quickSerial = sliceBetween(
    workspace,
    "const handleQuickSerialConnect",
    "const handleCreateSavedSerial",
  );
  const openQuickSerial = sliceBetween(
    workspace,
    "const openQuickSerialPanel",
    "const openCreateSerialPanel",
  );
  const sftpBinding = sliceBetween(
    workspace,
    "const bindSftpWorkspace",
    "const getTerminalSidePanelContainerWidth",
  );
  const savedConnection = sliceBetween(
    workspace,
    "const beginSavedHostConnection",
    "const openCreateSavedHost",
  );

  assert.match(
    workspace,
    /sftpAvailable = activeSshSession !== null \|\| connectionTarget\?\.protocol === "ssh"/,
  );
  assert.match(workspace, /sftpTabVisible = sftpAvailable && rendererSettings\.appearance\.showSftpTab/);
  assert.match(workspace, /\{sftpTabVisible && \([\s\S]*?title="SFTP"/);
  assert.match(sftpBinding, /sshTerminals\.backendSessionIdFor\(workspaceId\)/);
  assert.match(sftpBinding, /sshTerminals\.operationGenerationFor\(workspaceId\)/);
  assert.doesNotMatch(quickSerial, /bindSftpWorkspace|sftpController|backendSessionIdFor/);
  assert.match(openQuickSerial, /terminalSessionCatalog\.snapshot\.order\.length > 0/);
  assert.match(
    savedConnection,
    /!usesSharedSshRuntime && terminalSessionCatalog\.snapshot\.order\.length > 0/,
  );
  assert.doesNotMatch(workspace, /connectionTarget\?\.protocol === "serial"[\s\S]{0,300}title="SFTP"/);
});
