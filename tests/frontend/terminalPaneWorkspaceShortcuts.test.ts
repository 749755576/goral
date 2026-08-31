import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);
const stylesUrl = new URL("../../src/styles.css", import.meta.url);

function sourceBetween(source: string, start: string, end: string): string {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex + start.length);
  assert.ok(startIndex >= 0, `missing source marker: ${start}`);
  assert.ok(endIndex > startIndex, `missing source marker after ${start}: ${end}`);
  return source.slice(startIndex, endIndex);
}

test("workspace shortcuts use geometric wrapped focus and exact shared-session activation", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  const shortcuts = sourceBetween(
    source,
    "const handleTerminalPaneShortcut",
    "const showTerminalPaneWorkspace",
  );

  assert.match(shortcuts, /event\.ctrlKey[\s\S]*?event\.altKey[\s\S]*?!event\.shiftKey/);
  assert.match(shortcuts, /ArrowUp:\s*"up"/);
  assert.match(shortcuts, /ArrowDown:\s*"down"/);
  assert.match(shortcuts, /ArrowLeft:\s*"left"/);
  assert.match(shortcuts, /ArrowRight:\s*"right"/);
  assert.match(shortcuts, /findNextTerminalPaneFocusSessionId\([\s\S]*?direction/);
  assert.match(shortcuts, /activateSharedTerminalSession\(nextSessionId, true\)/);
});

test("Ctrl+Shift+Enter zooms one mounted pane and navigation moves the zoom", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  const shortcuts = sourceBetween(
    source,
    "const handleTerminalPaneShortcut",
    "const showTerminalPaneWorkspace",
  );
  const placements = sourceBetween(
    source,
    "const terminalViewportPlacements",
    "const hasTerminalPaneWorkspace",
  );

  assert.match(shortcuts, /event\.key === "Enter"/);
  assert.match(shortcuts, /terminalPaneZoomedSessionId === activeSharedSession\.id[\s\S]*?null[\s\S]*?: activeSharedSession\.id/);
  assert.match(shortcuts, /terminalPaneZoomedSessionId[\s\S]*?setTerminalPaneZoomedSessionId\(nextSessionId\)/);
  assert.match(placements, /\[terminalPaneZoomedSessionId\][\s\S]*?x:\s*0[\s\S]*?y:\s*0[\s\S]*?width:\s*1[\s\S]*?height:\s*1/);
  assert.match(source, /terminalPaneZoomedSessionId === null[\s\S]*?terminalPaneGeometry\?\.handles\.map/);
  assert.match(source, /<LocalTerminalSessionViewports[\s\S]*?placements=\{terminalViewportPlacements\}/);
  assert.match(source, /<SshTerminalSessionViewports[\s\S]*?placements=\{terminalViewportPlacements\}/);
});

test("xterm helper textarea keeps shortcuts while ordinary form editors are untouched", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  const shortcuts = sourceBetween(
    source,
    "const handleTerminalPaneShortcut",
    "const showTerminalPaneWorkspace",
  );

  assert.match(shortcuts, /classList\.contains\("xterm-helper-textarea"\)/);
  assert.match(shortcuts, /HTMLTextAreaElement && !terminalHelperTextarea/);
  assert.match(shortcuts, /HTMLInputElement/);
  assert.match(shortcuts, /HTMLSelectElement/);
  assert.match(shortcuts, /isContentEditable/);
  assert.match(shortcuts, /event\.stopPropagation\(\)/);
  assert.match(source, /addEventListener\("keydown", handleTerminalPaneShortcut, true\)/);
  assert.match(source, /removeEventListener\("keydown", handleTerminalPaneShortcut, true\)/);
});

test("zoom is retired on invalidation, close, explicit dissolve, and one-pane collapse", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  const pruning = sourceBetween(
    source,
    "const liveSessionIds = new Set(sharedTerminalRegistry.order)",
    "if (!terminalPaneResize) return",
  );
  const shortcuts = sourceBetween(
    source,
    "const handleTerminalPaneShortcut",
    "const showTerminalPaneWorkspace",
  );
  const dissolve = sourceBetween(
    source,
    "const dissolveTerminalPaneWorkspace",
    "const resizeTerminalPaneFromKeyboard",
  );

  assert.match(pruning, /shouldDissolveTerminalPaneLayout\(pruned\)/);
  assert.match(pruning, /setTerminalPaneZoomedSessionId\(null\)/);
  assert.match(shortcuts, /event\.code === "KeyW"[\s\S]*?setTerminalPaneZoomedSessionId\(null\)/);
  assert.match(dissolve, /setTerminalPaneLayout\(null\)/);
  assert.match(dissolve, /setTerminalPaneZoomedSessionId\(null\)/);
});

test("every pane visibility transition schedules exact protocol-aware fits", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  const fit = sourceBetween(
    source,
    "const fitSharedTerminalSessionsOnNextFrame",
    "const sftpAvailable",
  );
  const shortcuts = sourceBetween(
    source,
    "const handleTerminalPaneShortcut",
    "const showTerminalPaneWorkspace",
  );

  assert.match(fit, /window\.requestAnimationFrame/);
  assert.match(fit, /snapshot\?\.protocol === "local"[\s\S]*?localTerminals\.fit\(workspaceSessionId\)/);
  assert.match(fit, /snapshot\?\.protocol === "ssh"[\s\S]*?sshTerminals\.owns\(workspaceSessionId\)[\s\S]*?sshTerminals\.fit\(workspaceSessionId\)/);
  assert.match(shortcuts, /fitSharedTerminalSessionsOnNextFrame\([\s\S]*?collectTerminalPaneSessionIds\(terminalPaneLayout\.root\)/);
  assert.match(source, /fitSharedTerminalSessionsOnNextFrame\(\[sourceSessionId, clonedSessionId\]\)/);
});

test("closing a focused pane activates its in-workspace successor before runtime removal", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  const close = sourceBetween(
    source,
    "const closeActiveTerminalPane",
    "const handleTerminalPaneShortcut",
  );
  const shortcuts = sourceBetween(
    source,
    "const handleTerminalPaneShortcut",
    "const showTerminalPaneWorkspace",
  );

  assert.match(close, /removeTerminalPane\(terminalPaneLayout, closingSession\.id\)/);
  assert.match(close, /nextSessionId = remainder\?\.focusedSessionId/);
  assert.match(
    close,
    /activateSharedTerminalSession\(nextSessionId, true\)[\s\S]*?(?:localTerminals\.close|closeSshWorkspace)/,
  );
  assert.match(shortcuts, /event\.code === "KeyW"[\s\S]*?closeActiveTerminalPane\(\)/);
  assert.match(
    source,
    /aria-label=\{t\("workspace\.closeCurrentPane"\)\}[\s\S]*?onClick=\{\(\) => void closeActiveTerminalPane\(\)\}/,
  );
});

test("narrow terminal host-rail rules follow the base palette rule in cascade order", async () => {
  const styles = await readFile(stylesUrl, "utf8");
  const baseIndex = styles.lastIndexOf("--terminal-host-panel-width: 236px;");
  const narrowIndex = styles.lastIndexOf("@media (max-width: 900px)");
  const compactIndex = styles.lastIndexOf("@media (max-width: 700px)");

  assert.ok(baseIndex >= 0);
  assert.ok(narrowIndex > baseIndex, "900px rail override must follow the base variable");
  assert.ok(compactIndex > narrowIndex, "700px overlay override must remain last");
  assert.match(
    styles.slice(narrowIndex, compactIndex),
    /--terminal-host-panel-width:\s*44px[\s\S]*?grid-template-columns:\s*44px 0/,
  );
});
