import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const stylesUrl = new URL("../../src/styles.css", import.meta.url);
const aiPanelStylesUrl = new URL("../../src/aiPanel.css", import.meta.url);
const composerUrl = new URL("../../src/ai/AiComposer.tsx", import.meta.url);

test("AI side panel keeps the conversation layout readable and keyboard accessible", async () => {
  const [styles, aiPanelStyles, composer] = await Promise.all([
    readFile(stylesUrl, "utf8"),
    readFile(aiPanelStylesUrl, "utf8"),
    readFile(composerUrl, "utf8"),
  ]);

  assert.match(
    styles,
    /\.terminal-side-panel \.ai-workspace\s*\{[\s\S]*?grid-row:\s*1\s*\/\s*-1;/u,
    "the AI workspace must span the side-panel header and content rows",
  );
  assert.match(
    styles,
    /\.ai-markdown strong\s*\{[\s\S]*?display:\s*inline;[\s\S]*?font-size:\s*inherit;/u,
    "Markdown emphasis must not inherit the legacy block-style message label",
  );
  assert.match(
    styles,
    /\.ai-workspace button:focus-visible,[\s\S]*?\.ai-workspace select:focus-visible/u,
    "interactive AI controls must expose a keyboard focus state",
  );
  assert.match(
    styles,
    /@container ai-workspace \(max-width:\s*319px\)/u,
    "the minimum-width side panel must retain a dedicated compact layout",
  );
  assert.match(
    composer,
    /<form className="ai-workspace-composer"[\s\S]*?<div className="ai-composer-context"[\s\S]*?<textarea[\s\S]*?<footer>[\s\S]*?<div className="ai-composer-controls"/u,
    "the extracted Composer must keep the CSS-dependent DOM hierarchy",
  );
  assert.match(
    composer,
    /<div className="ai-composer-main-controls">[\s\S]*?<AiContextMenu[\s\S]*?<AiProviderMenu[\s\S]*?<div className="ai-composer-routing-controls">[\s\S]*?ai-composer-mode-select[\s\S]*?<AiPermissionMenu[\s\S]*?<AiContextUsageRing/u,
    "the narrow composer must use two intentional control groups in reading order",
  );
  assert.match(
    aiPanelStyles,
    /\.ai-workspace-composer footer\s*\{[\s\S]*?display:\s*grid;[\s\S]*?grid-template-columns:\s*minmax\(0, 1fr\) var\(--ld-space-32\);/u,
    "the send button must own a fixed right-hand column",
  );
  assert.match(
    aiPanelStyles,
    /@container ai-workspace \(min-width:\s*520px\)[\s\S]*?\.ai-composer-main-controls,[\s\S]*?\.ai-composer-routing-controls\s*\{[\s\S]*?display:\s*contents;/u,
    "wide panels must deliberately collapse the two groups to one row",
  );
  // Every control keeps its localized accessible name. Routing controls
  // stay directly visible in the footer instead of hiding behind an
  // overflow disclosure.
  for (const key of ["ai.inputPlaceholder", "ai.selectMode", "ai.stop", "ai.send"]) {
    assert.ok(
      composer.includes(`aria-label={t("${key}")}`),
      `Composer must keep the localized accessible name for ${key}`,
    );
  }
  assert.doesNotMatch(composer, /<details|ai-composer-advanced|ai-send-inline/u);
  assert.match(composer, /<footer>[\s\S]*?ai-composer-mode-select[\s\S]*?<AiPermissionMenu/u);
});
