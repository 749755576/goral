import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);

function sourceBetween(source: string, start: string, end: string): string {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex + start.length);
  assert.ok(startIndex >= 0, `missing source marker: ${start}`);
  assert.ok(endIndex > startIndex, `missing source marker after ${start}: ${end}`);
  return source.slice(startIndex, endIndex);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

test("TerminalWorkspace creates one stable catalog and injects it into Local and SSH controllers", async () => {
  const source = await readFile(workspaceUrl, "utf8");

  assert.match(
    source,
    /import\s*\{[\s\S]*?createTerminalSessionCatalog[\s\S]*?\}\s*from\s*"\.\/terminalSessionCatalog"/,
  );
  assert.match(
    source,
    /import\s*\{[\s\S]*?SshTerminalSessionViewports[\s\S]*?\}\s*from\s*"\.\/SshTerminalSessions"/,
  );
  assert.match(source, /\buseSshTerminalSessions\b/);

  const memoCatalogDeclaration = source.match(
    /const\s+([A-Za-z_$][\w$]*)\s*=\s*useMemo\(\s*\(\)\s*=>\s*createTerminalSessionCatalog\(\)\s*,\s*\[\]\s*\)/,
  );
  const refCatalogDeclaration = source.match(
    /const\s+([A-Za-z_$][\w$]*)Ref\s*=\s*useRef<[^>]*TerminalSessionCatalog[^>]*>\(null\);[\s\S]{0,300}?if\s*\(!\1Ref\.current\)\s*\{[\s\S]{0,200}?\1Ref\.current\s*=\s*createTerminalSessionCatalog\(\);[\s\S]{0,200}?const\s+([A-Za-z_$][\w$]*)\s*=\s*\1Ref\.current/,
  );
  const catalogVariable = memoCatalogDeclaration?.[1] ?? refCatalogDeclaration?.[2];
  assert.ok(catalogVariable, "the shared catalog must have component-stable identity");
  const catalogName = escapeRegExp(catalogVariable);

  assert.match(
    source,
    new RegExp(`useLocalTerminalSessions\\([\\s\\S]{0,300}?${catalogName}\\s*,[\\s\\S]{0,100}?\\bt\\s*,?\\s*\\)`),
  );
  assert.match(
    source,
    new RegExp(`useSshTerminalSessions\\(\\s*${catalogName}\\s*,`),
  );
  assert.equal(
    source.match(/createTerminalSessionCatalog\(\)/g)?.length,
    1,
    "TerminalWorkspace must not create a second protocol-specific catalog",
  );
});

test("Local and SSH viewports consume the same registry snapshot", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  const localViewport = source.match(
    /<LocalTerminalSessionViewports[\s\S]{0,500}?registry=\{([^}]+)\}[\s\S]{0,500}?\/>/,
  );
  const sshViewport = source.match(
    /<SshTerminalSessionViewports[\s\S]{0,600}?registry=\{([^}]+)\}[\s\S]{0,600}?\/>/,
  );

  assert.ok(localViewport, "Local per-session viewports are rendered");
  assert.ok(sshViewport, "SSH per-session viewports are rendered");
  assert.equal(
    localViewport[1].trim(),
    sshViewport[1].trim(),
    "both viewport families must follow the same global order and active ID",
  );
  assert.match(sshViewport[0], /owns=\{sshTerminals\.owns\}/);
  assert.match(sshViewport[0], /mountViewport=\{sshTerminals\.mountViewport\}/);
  assert.match(sshViewport[0], /unmountViewport=\{sshTerminals\.unmountViewport\}/);
});

test("the chrome projects one global Local plus SSH order into session or Workspace tabs", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  const tabs = sourceBetween(
    source,
    '<div className="surface-tabs"',
    '<div className="chrome-drag-region"',
  );
  assert.match(
    source,
    /createTerminalWorkspaceTabs\([\s\S]*?sharedTerminalRegistry\.order,[\s\S]*?hasTerminalPaneWorkspace \? terminalPaneSessionIds : \[\]/,
  );
  assert.match(tabs, /terminalWorkspaceTabs\.map\(\(tab\) => \{/);
  assert.match(tabs, /if \(tab\.type === "workspace"\)/);
  assert.match(tabs, /data-terminal-pane-count=\{tab\.sessionIds\.length\}/);
  assert.match(tabs, /const id = tab\.sessionId/);
  assert.match(tabs, /sharedTerminalRegistry\.sessions\[id\]/);
  assert.match(tabs, /activateSharedTerminalSession\(id, false\)/);
  assert.match(
    source,
    /const activateSharedTerminalSession[\s\S]*?localTerminals\.activate\(workspaceSessionId\)[\s\S]*?sshTerminals\.activate\(workspaceSessionId\)/,
  );
  assert.match(tabs, /localTerminals\.close\(id\)/);
  assert.match(tabs, /closeSshWorkspace\(id\)/);
  assert.match(
    source,
    /const stopSshWorkspace[\s\S]*?suspendSftpWorkspaceForStop\(workspaceId\)[\s\S]*?sshTerminals\.close\(workspaceId\)[\s\S]*?finalizeSuspension\(suspension, pending\.remove\)/,
  );
  assert.match(
    source,
    /const closeSshWorkspace[\s\S]*?stopSshWorkspace\(workspaceId, true\)/,
  );
  assert.doesNotMatch(tabs, /localTerminals\.registry\.order\.map/);
  assert.doesNotMatch(tabs, /sshTerminals\.registry\.order\.map/);
});

test("Quick and SavedHost SSH open through per-tab starters with exact size and attempt IDs", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  const quick = sourceBetween(source, "const connect = async", "const retryTelnetConnection");
  const saved = sourceBetween(source, "const connectSavedHost", "const beginSavedHostConnection");

  assert.match(quick, /sshTerminals\.open\([\s\S]*?kind:\s*"quick"/);
  assert.doesNotMatch(quick, /activateSession\(\s*\{\s*protocol:\s*"ssh"/);
  assert.match(quick, /async\s*\(\s*callbacks\s*,\s*initialSize\s*,\s*clientAttemptId\s*\)/);
  assert.match(quick, /startSshSession\(\{[\s\S]*?clientAttemptId\b/);
  assert.match(quick, /startSshSession\(\{[\s\S]*?size:\s*initialSize\b/);

  assert.match(saved, /sshTerminals\.open\([\s\S]*?kind:\s*"saved"/);
  assert.match(saved, /savedHostId:\s*host\.id/);
  assert.match(saved, /async\s*\(\s*callbacks\s*,\s*initialSize\s*,\s*clientAttemptId\s*\)/);
  assert.match(saved, /startSavedHostSession\(\{[\s\S]*?clientAttemptId\b/);
  assert.match(saved, /startSavedHostSession\(\{[\s\S]*?size:\s*initialSize\b/);

  assert.doesNotMatch(quick + saved, /createSshClientAttemptId\(/);
});

test("Quick and SavedHost retry use fresh one-shot starters while legacy protocols reject every shared tab", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  const legacyActivation = sourceBetween(
    source,
    "const activateSession = useCallback",
    "const connect = async",
  );
  const quick = sourceBetween(source, "const connect = async", "const retryTelnetConnection");
  const saved = sourceBetween(source, "const connectSavedHost", "const beginSavedHostConnection");
  const localOpen = sourceBetween(
    source,
    "const openLocalTerminalPanel",
    "const handleLocalTerminalConnect",
  );

  assert.match(quick, /const\s+\w+\s*:\s*SshTerminalStart\s*=\s*async\s*\(\s*callbacks\s*,\s*initialSize\s*,\s*clientAttemptId\s*\)/);
  assert.match(quick, /sshTerminals\.retry\([^,]+,\s*\w+\s*\)/);
  assert.match(saved, /const\s+\w+\s*:\s*SshTerminalStart\s*=\s*async\s*\(\s*callbacks\s*,\s*initialSize\s*,\s*clientAttemptId\s*\)/);
  assert.match(saved, /sshTerminals\.retry\([^,]+,\s*\w+\s*\)/);

  const directSharedGuard = /(?:(?:shared|terminal)\w*(?:Registry|Sessions)\.order|terminalSessionCatalog\.snapshot\.order)\.length\s*>\s*0/i;
  const namedSharedGuard = /hasShared\w*Sessions/i;
  const bothControllersGuard = /(?:localTerminals\.hasSessions\(\)[\s\S]{0,160}sshTerminals\.hasSessions\(\)|sshTerminals\.hasSessions\(\)[\s\S]{0,160}localTerminals\.hasSessions\(\))/;
  assert.ok(
    directSharedGuard.test(legacyActivation)
      || namedSharedGuard.test(legacyActivation)
      || bothControllersGuard.test(legacyActivation),
    "Telnet/Mosh/ET/Serial singleton activation must reject both Local and SSH tabs",
  );

  assert.doesNotMatch(quick, /localTerminals\.hasSessions\(\)/);
  assert.doesNotMatch(saved, /localTerminals\.hasSessions\(\)/);
  assert.doesNotMatch(localOpen, /sshTerminals\.hasSessions\(\)/);
});

test("SSH split panes clone the exact authenticated transport without credentials or reconnect fallback", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  const split = sourceBetween(
    source,
    "const splitActiveTerminalPane",
    "const handleTerminalPaneShortcut",
  );

  assert.match(split, /sshTerminals\.backendSessionIdFor\(source\.id\)/);
  assert.match(split, /source\.state\s*!==\s*"connected"/);
  assert.match(
    split,
    /cloneSshSession\(\{[\s\S]*?sourceSessionId:\s*sourceBackendSessionId[\s\S]*?size:\s*initialSize/,
  );
  assert.match(split, /sshTerminals\.open\(target,\s*startClone\)/);
  assert.match(
    split,
    /if \(cloned\.error\)[\s\S]*?await sshTerminals\.close\(cloned\.id\)[\s\S]*?return;[\s\S]*?bindSftpWorkspace\(cloned\.id\)[\s\S]*?commitTerminalPaneClone/,
  );
  assert.match(split, /bindSftpWorkspace\(cloned\.id\)/);
  assert.match(split, /commitTerminalPaneClone\(source\.id,\s*cloned\.id,\s*direction\)/);

  assert.doesNotMatch(
    split,
    /stageSshPassword|startSshSession|startSavedHostSession|connectSavedHost/,
  );
  assert.doesNotMatch(source, /PendingQuickTerminalSplit|pendingQuickTerminalSplit/);
  assert.doesNotMatch(source, /重新输入一次密码来创建新分屏/);
  assert.equal(
    source.match(/disabled=\{activeSharedSession\.state !== "connected"/g)?.length,
    2,
    "both visible split controls must reject non-connected sessions",
  );
});
