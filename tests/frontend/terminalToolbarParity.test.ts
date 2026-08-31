import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

function sourceBetween(source: string, start: string, end: string): string {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex + start.length);
  assert.notEqual(startIndex, -1, `missing source marker: ${start}`);
  assert.notEqual(endIndex, -1, `missing source marker: ${end}`);
  return source.slice(startIndex, endIndex);
}

test("terminal toolbar derives one active legacy-or-shared summary and routes disconnect exactly", async () => {
  const workspace = await readFile(
    new URL("../../src/TerminalWorkspace.tsx", import.meta.url),
    "utf8",
  );
  const toolbar = sourceBetween(
    workspace,
    '<div className="terminal-toolbar">',
    'className="terminal-container legacy-terminal-viewport"',
  );
  const disconnectActive = sourceBetween(
    workspace,
    "const disconnectActiveTerminal",
    "const refreshDependentCatalogsAfterKnownHostsMutation",
  );
  const summary = sourceBetween(
    workspace,
    "const terminalAddress",
    "const serialYmodemProgressPercent",
  );

  assert.match(toolbar, /className="terminal-session-summary"/);
  assert.match(workspace, /connectionStateLabel\(terminalConnectionState, t\)/);
  assert.match(toolbar, /\{terminalConnectionStateLabel\}/);
  assert.match(toolbar, /\{terminalAddress\}/);
  assert.match(toolbar, /className=\{`connection-dot state-\$\{terminalConnectionState\}`\}/);
  assert.match(toolbar, /\{terminalProtocolLabel\}/);
  assert.match(
    toolbar,
    /aria-label=\{sftpOpen \? t\("terminal\.closeSftpPanel"\) : t\("terminal\.openSftpPanel"\)\}/,
  );
  assert.match(toolbar, /title="SFTP"/);
  assert.match(toolbar, /<VaultGlyph name="folder" \/>/);
  assert.match(toolbar, /terminalSidePanelOpen && terminalSidePanelTab === "sftp"/);
  assert.match(toolbar, /setTerminalSidePanelOpen\(false\)/);
  assert.match(toolbar, /setTerminalSidePanelOpen\(true\)/);
  assert.match(toolbar, /setTerminalSidePanelTab\("sftp"\)/);
  assert.match(toolbar, /className="terminal-tool-button terminal-disconnect-button"/);
  assert.match(toolbar, /onClick=\{\(\) => void disconnectActiveTerminal\(\)\}/);
  assert.match(summary, /activeLocalSession\?\.title \?\? \(activeSshTarget/);
  assert.match(summary, /terminalConnectionState = activeSharedSession\?\.state \?\? connectionState/);
  assert.match(summary, /terminalProtocolLabel = activeSharedSession[\s\S]*?activeSharedSession\.protocol\.toUpperCase\(\)/);
  assert.match(disconnectActive, /const activeLocal = localTerminals\.activeSession/);
  assert.match(disconnectActive, /localTerminals\.disconnect\(activeLocal\.id\)/);
  assert.match(disconnectActive, /const activeSsh = sshTerminals\.activeSession/);
  assert.match(disconnectActive, /disconnectSshWorkspace\(activeSsh\.id\)/);
  assert.match(disconnectActive, /await disconnect\(\)/);
  const localRoute = disconnectActive.indexOf("localTerminals.disconnect(activeLocal.id)");
  const sshRoute = disconnectActive.indexOf("disconnectSshWorkspace(activeSsh.id)");
  const legacyRoute = disconnectActive.indexOf("await disconnect()");
  assert.ok(localRoute >= 0 && localRoute < sshRoute && sshRoute < legacyRoute);
  assert.doesNotMatch(toolbar, /Catty Agent|terminalSidePanelTab === "ai"/);
});

test("SFTP action row uses accessible icon buttons without changing behavior", async () => {
  const workspace = await readFile(
    new URL("../../src/SftpBrowserPanel.tsx", import.meta.url),
    "utf8",
  );
  const actionRow = sourceBetween(
    workspace,
    '<div className="sftp-action-row">',
    "</div>",
  );

  assert.match(actionRow, /className="sftp-icon-button"/);
  assert.match(actionRow, /aria-label=\{t\("sftp\.uploadFile"\)\}/);
  assert.match(actionRow, /void onChooseUpload\("file"\)/);
  assert.match(actionRow, /aria-label=\{t\("sftp\.uploadFolder"\)\}/);
  assert.match(actionRow, /void onChooseUpload\("directory"\)/);
  assert.match(actionRow, /aria-label=\{t\("sftp\.newFolder"\)\}/);
  assert.match(actionRow, /title=\{t\("sftp\.newFolder"\)\}/);
  assert.match(actionRow, /glyph\("folder"\)/);
  assert.match(actionRow, /void onCreateFolder\(\)/);
  assert.match(actionRow, /aria-label=\{loading \? t\("sftp\.refreshingDirectory"\) : t\("sftp\.refreshDirectory"\)\}/);
  assert.match(actionRow, /title=\{t\("sftp\.refreshDirectory"\)\}/);
  assert.match(actionRow, /glyph\("refresh"\)/);
  assert.match(actionRow, /void onLoadPath\(path\)/);
  assert.doesNotMatch(actionRow, />\s*(?:\+ New folder|Refresh|Loading)/);
});

test("terminal and SFTP icon controls preserve the compact legacy dimensions", async () => {
  const styles = await readFile(new URL("../../src/styles.css", import.meta.url), "utf8");

  assert.match(styles, /\.surface-terminal \.terminal-toolbar \{[\s\S]*?min-height: 36px;/);
  assert.match(styles, /\.terminal-tool-button \{[\s\S]*?width: 25px;[\s\S]*?height: 25px;/);
  assert.match(styles, /\.terminal-tool-button\.active \{[\s\S]*?background:/);
  assert.match(styles, /\.sftp-action-row \.sftp-icon-button \{[\s\S]*?width: 26px;[\s\S]*?height: 26px;/);
});
