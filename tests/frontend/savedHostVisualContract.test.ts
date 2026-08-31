import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const backendUrl = new URL("../../src/backend.ts", import.meta.url);
const visualUrl = new URL("../../src/hostVisual.ts", import.meta.url);
const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);
const catalogCardUrl = new URL("../../src/SavedHostCatalogCard.tsx", import.meta.url);
const tauriUrl = new URL("../../src-tauri/src/lib.rs", import.meta.url);
const rustVisualUrl = new URL("../../src-tauri/src/saved_host_visual.rs", import.meta.url);

test("SavedHost exposes one nested renderer-safe visual DTO across Rust and TypeScript", async () => {
  const [backend, visual, tauri, rustVisual] = await Promise.all([
    readFile(backendUrl, "utf8"),
    readFile(visualUrl, "utf8"),
    readFile(tauriUrl, "utf8"),
    readFile(rustVisualUrl, "utf8"),
  ]);

  const savedHost = backend.slice(
    backend.indexOf("export type SavedHost ="),
    backend.indexOf("export type SavedHostEffectiveAppearance ="),
  );
  assert.match(savedHost, /visual: HostVisual;/);
  assert.match(backend, /export type \{ HostVisual \} from "\.\/hostVisual";/);

  const visualDto = visual.slice(
    visual.indexOf("export type HostVisual ="),
    visual.indexOf("export type HostVisualSource ="),
  );
  for (const field of [
    "os",
    "distro",
    "distroMode",
    "manualDistro",
    "iconMode",
    "iconId",
    "iconColorMode",
    "iconColor",
    "iconColorCustom",
  ]) {
    assert.match(visualDto, new RegExp(`\\b${field}:`));
  }
  assert.doesNotMatch(visualDto, /password|credential|privateKey|passphrase|secret/i);

  const rustView = rustVisual.slice(
    rustVisual.indexOf("pub(crate) struct SavedHostVisualView"),
    rustVisual.indexOf("impl SavedHostVisualView"),
  );
  assert.match(rustVisual, /#\[serde\(rename_all = "camelCase"\)\]/);
  assert.match(tauri, /visual: SavedHostVisualView,/);
  assert.match(tauri, /visual: SavedHostVisualView::from_host\(host\),/);
  assert.doesNotMatch(rustView, /password|credential|private_key|passphrase|secret/i);
});

test("saved-host cards resolve protocol plus the native visual projection without a hardcoded distro", async () => {
  const [workspace, card] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(catalogCardUrl, "utf8"),
  ]);

  assert.match(card, /<HostAvatar/);
  assert.match(card, /host=\{\{ protocol: host\.protocol, \.\.\.host\.visual \}\}/);
  assert.match(card, /size=\{avatarSize\}/);
  assert.match(card, /className="saved-host-avatar"/);
  assert.match(workspace, /avatarSize=\{activeSurface === "terminal" \? "tree" : "lg"\}/);
  assert.doesNotMatch(card, /distro:\s*"linux"|\/distro\/linux\.svg/);
});
