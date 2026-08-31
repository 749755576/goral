import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);

test("standalone tabs drag into exact pane edges without recreating runtimes", async () => {
  const source = await readFile(workspaceUrl, "utf8");

  assert.match(source, /import\s*\{[\s\S]*?resolveTerminalPaneDropHint[\s\S]*?\}\s*from\s*"\.\/terminalPaneDrag"/);
  assert.match(source, /draggable=\{terminalSession\.state !== "closing"\}/);
  assert.match(source, /setDraggedTerminalSessionId\(id\)/);
  assert.match(source, /const resolveDraggedTerminalPaneHint[\s\S]*?getBoundingClientRect\(\)[\s\S]*?resolveTerminalPaneDropHint\(base/);
  assert.match(source, /const commitDraggedTerminalPane[\s\S]*?splitTerminalPaneAtPosition\([\s\S]*?setTerminalPaneLayout\(next\)[\s\S]*?setTerminalPaneWorkspaceVisible\(true\)/);
  assert.doesNotMatch(
    source.match(/const commitDraggedTerminalPane[\s\S]*?const resizeTerminalPaneFromKeyboard/)?.[0] ?? "",
    /localTerminals\.open|sshTerminals\.open|close\(|disconnect\(/,
  );
});

test("drag preview, stale guards, and focused-pane detach preserve exact sessions", async () => {
  const source = await readFile(workspaceUrl, "utf8");

  assert.match(source, /terminalPaneLayout !== null && !terminalPaneWorkspaceVisible/);
  assert.match(
    source,
    /const splitActiveTerminalPane[\s\S]*?terminalPaneLayout !== null && !terminalPaneWorkspaceVisible[\s\S]*?t\("terminal\.pane\.workspaceExists"\)/,
  );
  assert.match(source, /terminalPaneLayoutContains\(base, draggedTerminalSessionId\)/);
  assert.match(source, /hint\?\.targetSessionId === draggedTerminalSessionId \? null : hint/);
  assert.match(source, /className="terminal-pane-drop-preview"[\s\S]*?data-terminal-pane-drop-target=\{terminalPaneDropHint\.targetSessionId\}/);
  assert.match(source, /const detachFocusedTerminalPane[\s\S]*?removeTerminalPane\(terminalPaneLayout, detachedSessionId\)[\s\S]*?setTerminalPaneWorkspaceVisible\(false\)/);
  assert.match(source, /aria-label=\{t\("workspace\.detachCurrentPane"\)\}[\s\S]*?onClick=\{detachFocusedTerminalPane\}/);
});
