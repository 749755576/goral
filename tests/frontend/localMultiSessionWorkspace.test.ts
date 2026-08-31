import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);
const sessionsUrl = new URL("../../src/LocalTerminalSessions.tsx", import.meta.url);

function sourceBetween(source: string, start: string, end: string): string {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex + start.length);
  assert.ok(startIndex >= 0, `missing source marker: ${start}`);
  assert.ok(endIndex > startIndex, `missing source marker after ${start}: ${end}`);
  return source.slice(startIndex, endIndex);
}

test("projected terminal tabs and Local viewports follow global order without unmounting inactive Local xterms", async () => {
  const [workspace, sessions] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(sessionsUrl, "utf8"),
  ]);
  const tabs = sourceBetween(
    workspace,
    "{terminalWorkspaceTabs.map((tab) => {",
    '<div className="chrome-drag-region"',
  );
  const viewport = sourceBetween(
    sessions,
    "function LocalTerminalViewport",
    "type LocalTerminalSessionViewportsProps",
  );
  const viewports = sessions.slice(sessions.indexOf("export function LocalTerminalSessionViewports"));

  assert.match(tabs, /if \(tab\.type === "workspace"\)/);
  assert.match(tabs, /data-terminal-pane-count=\{tab\.sessionIds\.length\}/);
  assert.match(tabs, /const id = tab\.sessionId/);
  assert.match(tabs, /const terminalSession = sharedTerminalRegistry\.sessions\[id\]/);
  assert.doesNotMatch(tabs, /belongsToPaneWorkspace/);
  assert.match(tabs, /key=\{id\}[\s\S]*?className=\{`local-session-tab/);
  assert.match(tabs, /data-workspace-session-id=\{id\}/);
  assert.match(
    workspace,
    /<LocalTerminalSessionViewports[\s\S]*?registry=\{sharedTerminalRegistry\}/,
  );
  assert.match(viewports, /registry\.order\.map\(\(id\) => \(/);
  assert.match(viewports, /registry\.sessions\[id\]\?\.protocol === "local"/);
  assert.match(viewports, /<LocalTerminalViewport[\s\S]*?key=\{id\}[\s\S]*?id=\{id\}/);
  assert.match(viewports, /placement=\{placementFor\(id\)\}/);
  assert.doesNotMatch(viewports, /activeSessionId\s*&&\s*<LocalTerminalViewport/);
  assert.match(viewport, /className=\{`local-terminal-viewport terminal-pane-viewport/);
  assert.match(viewport, /data-workspace-session-id=\{id\}/);
  assert.match(viewport, /hidden=\{!placement\}/);
});

test("shared tab activation and close route to the exact Local or SSH controller", async () => {
  const workspace = await readFile(workspaceUrl, "utf8");
  const tabs = sourceBetween(
    workspace,
    "{terminalWorkspaceTabs.map((tab) => {",
    '<div className="chrome-drag-region"',
  );
  const sessionTabs = tabs.slice(tabs.indexOf("const id = tab.sessionId;"));
  const activateButtonStart = sessionTabs.indexOf("<button");
  const activateButtonEnd = sessionTabs.indexOf("</button>", activateButtonStart);
  const closeButtonClass = sessionTabs.indexOf('className="local-session-tab-close"');

  assert.ok(activateButtonStart >= 0, "Local activation button is present");
  assert.ok(activateButtonEnd > activateButtonStart, "Local activation button closes explicitly");
  assert.ok(closeButtonClass > activateButtonEnd, "Local close button is a sibling, not a nested button");

  const activation = sessionTabs.slice(activateButtonStart, activateButtonEnd);
  assert.match(activation, /activateSharedTerminalSession\(id, false\)/);
  assert.match(
    workspace,
    /const activateSharedTerminalSession[\s\S]*?snapshot\.protocol === "local"[\s\S]*?localTerminals\.activate\(workspaceSessionId\)[\s\S]*?snapshot\.protocol === "ssh"[\s\S]*?sshTerminals\.activate\(workspaceSessionId\)/,
  );
  assert.doesNotMatch(activation, /\.close\(|\.disconnect\(|cancelLocalPtySession|closeLocalPtySession/);
  assert.match(
    sessionTabs,
    /className="local-session-tab-close"[\s\S]*?terminalSession\.protocol === "local"[\s\S]*?localTerminals\.close\(id\)[\s\S]*?else void closeSshWorkspace\(id\)/,
  );
});

test("Local retry, disconnect, close, and final Vault fallback retain exact workspace IDs", async () => {
  const [workspace, sessions] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(sessionsUrl, "utf8"),
  ]);
  const retry = sourceBetween(
    workspace,
    "const retryLocalTerminalConnection",
    "const openLocalTerminalPanel",
  );
  const disconnect = sourceBetween(
    workspace,
    "const disconnectActiveTerminal",
    "const refreshDependentCatalogsAfterKnownHostsMutation",
  );
  const finalFallback = sourceBetween(
    workspace,
    "const previousSharedSessionCount",
    "const getTerminalSidePanelContainerWidth",
  );

  assert.match(retry, /const active = localTerminals\.activeSession/);
  assert.match(retry, /localTerminals\.retry\(active\.id\)/);
  assert.match(disconnect, /const activeLocal = localTerminals\.activeSession/);
  assert.match(disconnect, /localTerminals\.disconnect\(activeLocal\.id\)/);
  assert.match(disconnect, /const failure = await localTerminals\.disconnect\(activeLocal\.id\)/);
  assert.match(disconnect, /if \(failure\) setError\(t\("terminal\.runtime\.disconnectFailed"\)\)/);
  assert.match(disconnect, /const activeSsh = sshTerminals\.activeSession/);
  assert.match(disconnect, /disconnectSshWorkspace\(activeSsh\.id\)/);
  const stopSsh = sourceBetween(
    workspace,
    "const stopSshWorkspace",
    "const disconnectSshWorkspace",
  );
  const suspensionIndex = stopSsh.indexOf("suspendSftpWorkspaceForStop(workspaceId)");
  assert.ok(
    suspensionIndex < stopSsh.indexOf("sshTerminals.disconnect(workspaceId)", suspensionIndex),
    "SSH disconnect suspends exact SFTP authority before native stop",
  );
  assert.ok(
    suspensionIndex < stopSsh.indexOf("sshTerminals.close(workspaceId)", suspensionIndex),
    "SSH close suspends exact SFTP authority before native stop",
  );
  assert.match(stopSsh, /catch \{[\s\S]*recoverSftpAfterFailure\(\)[\s\S]*SSH_SESSION_STOP_ERROR/);
  assert.match(finalFallback, /previousSharedSessionCount\.current > 0/);
  assert.match(finalFallback, /sessionCount === 0/);
  assert.match(finalFallback, /connectionTarget === null/);
  assert.match(finalFallback, /activeSurface === "terminal"/);
  assert.match(finalFallback, /setActiveSurface\("vault"\)/);
  assert.match(sessions, /disconnect:\s*\(id: WorkspaceSessionId\) => Promise<string \| null>/);
  assert.match(sessions, /close:\s*\(id: WorkspaceSessionId\) => Promise<string \| null>/);
  assert.match(
    sessions,
    /const disconnect = useCallback\([\s\S]*?controller\.disconnect\(id\)[\s\S]*?const close = useCallback\([\s\S]*?controller\.close\(id\)/,
  );
});

test("Local and SSH tabs share one bound while legacy singleton protocols stay mutually exclusive", async () => {
  const workspace = await readFile(workspaceUrl, "utf8");
  const activateLegacy = sourceBetween(
    workspace,
    "const activateSession = useCallback",
    "const connect = async",
  );
  const openLocal = sourceBetween(
    workspace,
    "const openLocalTerminalPanel",
    "const handleLocalTerminalConnect",
  );
  const connectLocal = sourceBetween(
    workspace,
    "const handleLocalTerminalConnect",
    "const openQuickSerialPanel",
  );
  const busyState = sourceBetween(
    workspace,
    "const legacyBusy = connectionState !== \"disconnected\"",
    "const savedProxyProfileLabel",
  );
  const savedConnection = sourceBetween(
    workspace,
    "const beginSavedHostConnection",
    "const openCreateSavedHost",
  );
  const panelStart = workspace.lastIndexOf("<LocalTerminalPanel");
  assert.ok(panelStart >= 0, "Local terminal panel is rendered");
  const panel = workspace.slice(panelStart, panelStart + 700);

  assert.match(
    activateLegacy,
    /connectionOperation\.current[\s\S]*?\|\| session\.current[\s\S]*?\|\| terminalSessionCatalog\.snapshot\.order\.length > 0/,
  );
  assert.match(openLocal, /if \(connectionOperation\.current \|\| session\.current\) return/);
  assert.match(openLocal, /terminalSessionCatalog\.snapshot\.order\.length >= MAX_WORKSPACE_SESSIONS/);
  assert.doesNotMatch(openLocal, /hasSessions\(\)|snapshot\.order\.length > 0/);
  assert.match(connectLocal, /if \(connectionOperation\.current \|\| session\.current\)/);
  assert.match(connectLocal, /localTerminals\.open\(\{/);
  assert.doesNotMatch(connectLocal, /hasSessions\(\)|snapshot\.order\.length > 0/);
  assert.match(busyState, /const legacyBusy = connectionState !== "disconnected"/);
  assert.match(busyState, /const busy = legacyBusy/);
  assert.match(
    busyState,
    /const quickConnectionBlocked = legacyBusy[\s\S]*?quickProtocol !== "ssh" && hasSharedTerminalSessions/,
  );
  assert.match(busyState, /const savedActionsDisabled = busy \|\| savedHostSubmitting/);
  assert.match(
    savedConnection,
    /!usesSharedSshRuntime && terminalSessionCatalog\.snapshot\.order\.length > 0/,
  );
  assert.match(panel, /disabled=\{legacyBusy[\s\S]*?sharedTerminalRegistry\.order\.length >= MAX_WORKSPACE_SESSIONS\}/);
  assert.doesNotMatch(panel, /disabled=\{busy\}/);
});
