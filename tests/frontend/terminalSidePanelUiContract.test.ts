import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);
const transferQueueUrl = new URL("../../src/SftpTransferQueue.tsx", import.meta.url);
const stylesUrl = new URL("../../src/styles.css", import.meta.url);

test("terminal uses one sibling side panel for SFTP and the AI workspace", async () => {
  const [source, panelSource] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(new URL("../../src/SftpBrowserPanel.tsx", import.meta.url), "utf8"),
  ]);
  const terminalPanel = source.indexOf('className="terminal-panel"');
  const terminalContainer = source.indexOf(
    'className="terminal-container legacy-terminal-viewport"',
    terminalPanel,
  );
  const localViewports = source.indexOf("<LocalTerminalSessionViewports", terminalContainer);
  const sshViewports = source.indexOf("<SshTerminalSessionViewports", localViewports);
  const sidePanel = source.indexOf('className="terminal-side-panel"', sshViewports);
  const sftpPanel = source.indexOf("<SftpBrowserPanel");

  assert.ok(terminalPanel >= 0, "terminal-panel is present");
  assert.ok(terminalContainer > terminalPanel, "legacy terminal container remains inside terminal-panel");
  assert.ok(localViewports > terminalContainer, "Local multi-session viewports share terminal-panel");
  assert.ok(sshViewports > localViewports, "SSH multi-session viewports share terminal-panel");
  assert.ok(sidePanel > sshViewports, "unified side panel follows all terminal renderers");
  assert.ok(sftpPanel > sidePanel, "SFTP is rendered by the unified side panel");
  assert.match(panelSource, /className="sftp-panel"/);

  const terminalClosingRegion = source.slice(terminalPanel, sidePanel);
  assert.match(terminalClosingRegion, /className="terminal-container legacy-terminal-viewport"[\s\S]*?hidden=\{activeSharedSession !== null\}/);
  assert.match(terminalClosingRegion, /<LocalTerminalSessionViewports[\s\S]*?registry=\{sharedTerminalRegistry\}/);
  assert.match(terminalClosingRegion, /<SshTerminalSessionViewports[\s\S]*?registry=\{sharedTerminalRegistry\}[\s\S]*?owns=\{sshTerminals\.owns\}/);
  assert.doesNotMatch(terminalClosingRegion, /className="sftp-panel"/);
  assert.doesNotMatch(source, /terminal-panel\$\{[^}]*sftp-open/);
  assert.match(source, /sftpAvailable = activeSshSession !== null \|\| connectionTarget\?\.protocol === "ssh"/);
  assert.match(source, /activeSftpWorkspaceIdRef\.current = activeSshSession\?\.id \?\? null/);
  assert.match(source, /hidden=\{activeSurface !== "terminal" \|\| !terminalSidePanelVisible\}/);

  const sidePanelSource = source.slice(sidePanel);
  assert.match(
    sidePanelSource,
    /terminalSidePanelTab === "sftp" \? \([\s\S]*?className="terminal-side-panel-header"/,
  );
  assert.doesNotMatch(sidePanelSource, /terminalSidePanelTab === "ai" \? t\("ai\.title"\) : "SFTP"/);
  assert.match(
    sidePanelSource,
    /aria-label=\{t\("terminal\.closeSftpPanel"\)\}/,
  );
  assert.match(sidePanelSource, /<AiWorkspace[\s\S]*complete=\{openAiCompatibleCompletion\}/);
  assert.match(sidePanelSource, /<AiWorkspace[\s\S]*onClose=\{\(\) => \{/);
  assert.match(
    sidePanelSource,
    /sftpOpen && !activeSftpRender && !NATIVE_DESKTOP_RUNTIME_AVAILABLE[\s\S]*?sftp\.previewUnavailableTitle[\s\S]*?sftp\.previewUnavailableDescription/,
  );

  const sftpGuard = source
    .slice(Math.max(0, sftpPanel - 1_000), sftpPanel)
    .match(/([A-Za-z_$][\w$]*)\s*===\s*"sftp"/);
  assert.ok(sftpGuard, "SFTP content has an explicit active-tab guard");
  assert.doesNotMatch(source, /className="catty-agent-panel"|>Catty Agent<|向 Catty Agent 提问/);
});

test("AI context and approved commands stay pinned to the captured terminal generation", async () => {
  const source = await readFile(workspaceUrl, "utf8");

  assert.match(
    source,
    /activeLocalSession[\s\S]{0,160}localTerminals\.operationGenerationFor\(activeLocalSession\.id\)/,
  );
  assert.match(
    source,
    /activeSshSession[\s\S]{0,160}sshTerminals\.operationGenerationFor\(activeSshSession\.id\)/,
  );
  assert.match(source, /routeId: activeLocalSession\.id[\s\S]{0,160}protocol: "local"/);
  assert.match(source, /routeId: activeSshSession\.id[\s\S]{0,160}protocol: "ssh"/);
  assert.match(source, /generation: legacyAiOperation\.token/);
  assert.match(source, /commandExecutionSupported: legacyAiOperation\.protocol !== "serial"/);

  assert.match(
    source,
    /localTerminals\.operationGenerationFor\(workspaceSessionId\) !== scope\.generation[\s\S]{0,180}localTerminals\.readSelectedText\(workspaceSessionId\)/,
  );
  assert.match(
    source,
    /sshTerminals\.operationGenerationFor\(workspaceSessionId\) !== scope\.generation[\s\S]{0,180}sshTerminals\.readSelectedText\(workspaceSessionId\)/,
  );
  assert.match(source, /operation\.token !== scope\.generation/);
  assert.match(source, /active\.sessionId !== scope\.routeId/);

  assert.match(
    source,
    /localTerminals\.sendText\([\s\S]{0,160}scope\.generation/,
  );
  assert.match(
    source,
    /sshTerminals\.sendText\([\s\S]{0,160}scope\.generation/,
  );
  assert.match(source, /const data = `\$\{command\}\\r`/);
  assert.match(source, /throw new Error\("TERMINAL_SEND_PROTOCOL_UNSUPPORTED"\)/);

  assert.match(source, /<div hidden=\{!aiOpen\}/);
  assert.match(source, /terminalScope=\{aiTerminalScope\}/);
  assert.match(source, /sendApprovedCommand=\{sendAiApprovedCommand\}/);
  assert.doesNotMatch(source, /\{aiOpen && \(\s*<AiWorkspace/);
});

test("terminal side panel is resizable and the obsolete SFTP terminal-grid modifier is gone", async () => {
  const [source, styles] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(stylesUrl, "utf8"),
  ]);

  assert.match(source, /className="terminal-side-panel-resizer"/);
  assert.match(source, /on(?:Pointer|Mouse)Down=\{/);
  assert.match(styles, /\.terminal-side-panel\s*\{/);
  assert.match(styles, /\.terminal-side-panel-resizer\s*\{[\s\S]*?cursor:\s*col-resize/);
  assert.doesNotMatch(styles, /\.terminal-panel\.sftp-open/);
  assert.doesNotMatch(styles, /\.surface-terminal \.terminal-panel\.sftp-open/);
});

test("SFTP keeps a name and size table, then renders transfer controls after the file list", async () => {
  const [source, panelSource] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(new URL("../../src/SftpBrowserPanel.tsx", import.meta.url), "utf8"),
  ]);
  const sftp = panelSource;

  assert.match(sftp, /className="sftp-list-header"[\s\S]*?t\("sftp\.name"\)[\s\S]*?t\("sftp\.size"\)/);
  const fileList = sftp.indexOf('className="sftp-list"');
  const transferQueue = sftp.indexOf("<SftpTransferQueue");
  assert.ok(fileList >= 0, "SFTP file list is present");
  assert.ok(transferQueue > fileList, "transfer queue follows the file list");

  assert.match(source, /sftpController\.canControlTransfer\(owner, transferId\)/);
  assert.match(source, /onControlTransfer=\{controlOwnedSftpTransfer\}/);
  assert.match(source, /onRetryTransfer=\{retryTransfer\}/);
  const transferUi = await readFile(transferQueueUrl, "utf8");
  assert.match(transferUi, /className="sftp-transfers"/);
  assert.match(transferUi, /onControlTransfer\(transfer, "pause"\)/);
  assert.match(transferUi, /onControlTransfer\(transfer, "resume"\)/);
  assert.match(transferUi, /onControlTransfer\(transfer, "cancel"\)/);
  assert.match(transferUi, /onRetryTransfer\(transfer\)/);
  assert.doesNotMatch(transferUi, /backendTransferId|transfer\.transferId|pauseSftpTransfer|resumeSftpTransfer|cancelSftpTransfer/);
});
