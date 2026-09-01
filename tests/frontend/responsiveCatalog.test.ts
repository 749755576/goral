import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const frameStylesUrl = new URL("../../src/mainWorkspaceFrame.css", import.meta.url);
const knownHostsStylesUrl = new URL("../../src/knownHosts.css", import.meta.url);

test("compact Vault catalogs keep headers and controls inside their grid cell", async () => {
  const [css, knownHostsCss] = await Promise.all([
    readFile(frameStylesUrl, "utf8"),
    readFile(knownHostsStylesUrl, "utf8"),
  ]);
  const compact = css.slice(css.indexOf("/* Compact catalog layout"));

  assert.match(compact, /managed-keys-view,[\s\S]*?grid-template-columns:\s*minmax\(0, 1fr\)/);
  assert.match(compact, /managed-keys-view > \.panel-title,[\s\S]*?managed-keys-view > \.managed-keys-toolbar[\s\S]*?width:\s*100%/);
  assert.match(compact, /managed-key-list[\s\S]*?grid-template-columns:\s*minmax\(0, 1fr\)/);
  assert.match(compact, /port-forward-page-heading[\s\S]*?grid-template-areas:[\s\S]*?"new new"[\s\S]*?"search refresh"/);
  assert.match(compact, /port-forward-filter-bar[\s\S]*?grid-template-columns:\s*repeat\(4, minmax\(0, 1fr\)\)/);
  assert.match(compact, /known-hosts-search[\s\S]*?min-width:\s*0[\s\S]*?flex-basis:\s*100%/);
  assert.match(knownHostsCss, /\.known-hosts-menu:not\(\[open\]\)\s*>\s*\.known-hosts-menu-popover\s*\{[\s\S]*?display:\s*none/);
  assert.match(knownHostsCss, /@media \(max-width: 720px\)[\s\S]*?\.known-hosts-menu-popover\s*\{[\s\S]*?right:\s*auto[\s\S]*?left:\s*0/);
});
