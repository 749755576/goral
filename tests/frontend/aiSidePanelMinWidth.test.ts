import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);
const panelStylesUrl = new URL("../../src/aiPanel.css", import.meta.url);
const frameStylesUrl = new URL("../../src/mainWorkspaceFrame.css", import.meta.url);

test("AI side panel owns a readable minimum without changing SFTP/Docker bounds", async () => {
  const [workspace, panelStyles, frameStyles] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(panelStylesUrl, "utf8"),
    readFile(frameStylesUrl, "utf8"),
  ]);

  assert.match(workspace, /const AI_SIDE_PANEL_MIN_WIDTH = 420;/u);
  assert.match(workspace, /data-ai-panel-open=\{aiOpen\}/u);
  assert.match(
    workspace,
    /"--terminal-side-panel-min-width": aiOpen\s*\?\s*`\$\{AI_SIDE_PANEL_MIN_WIDTH\}px`\s*:\s*"0px"/u,
  );
  assert.match(
    workspace,
    /aria-valuemin=\{activeTerminalSidePanelWidthBounds\.min\}/u,
  );
  assert.match(
    workspace,
    /clampActiveTerminalSidePanelWidth\([\s\S]*?resizeTerminalSidePanelWidth/u,
  );
  assert.match(
    frameStyles,
    /grid-template-columns:[\s\S]*?minmax\(var\(--terminal-side-panel-min-width, 0px\), var\(--terminal-side-panel-width, 0px\)\)/u,
  );
  assert.match(
    frameStyles,
    /\.surface-terminal \.terminal-side-panel\[data-ai-panel-open="true"\]\s*\{[\s\S]*?min-width:\s*var\(--terminal-side-panel-min-width, 420px\);/u,
  );
  assert.match(
    panelStyles,
    /\.surface-terminal\[data-ai-panel-open="true"\][\s\S]*?--terminal-side-panel-min-width:\s*420px;/u,
  );
  assert.match(
    panelStyles,
    /@media \(max-width: 700px\)[\s\S]*?\.surface-terminal\[data-ai-panel-open="true"\]\s*\{[\s\S]*?grid-template-columns:\s*44px minmax\(320px, 1fr\);[\s\S]*?\.surface-terminal\[data-ai-panel-open="true"\] \.terminal-side-panel\s*\{[\s\S]*?position:\s*fixed;[\s\S]*?grid-column:\s*auto;[\s\S]*?grid-row:\s*auto;[\s\S]*?top:\s*46px;[\s\S]*?right:\s*0;[\s\S]*?justify-self:\s*end;[\s\S]*?min-width:\s*min\([\s\S]*?max-width:\s*calc\(100% - 44px\);/u,
  );
});
