import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);
const capabilityUrl = new URL(
  "../../src-tauri/capabilities/main-window-controls.json",
  import.meta.url,
);
const settingsCapabilityUrl = new URL(
  "../../src-tauri/capabilities/settings-window-title.json",
  import.meta.url,
);
const settingsWorkspaceUrl = new URL("../../src/SettingsWorkspace.tsx", import.meta.url);

test("the frameless main window can execute every visible title-bar control", async () => {
  const [workspace, capabilitySource] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(capabilityUrl, "utf8"),
  ]);
  const capability = JSON.parse(capabilitySource) as {
    identifier: string;
    windows: string[];
    permissions: string[];
  };

  assert.equal(capability.identifier, "main-window-controls");
  assert.deepEqual(capability.windows, ["main"]);
  // Pinned deliberately: widening a window capability must be a visible,
  // reviewed edit rather than a side effect. `allow-start-dragging` is
  // required by the `data-tauri-drag-region` element this window already
  // renders — without it the runtime refuses the drag and the frameless
  // window cannot be moved at all.
  assert.deepEqual(capability.permissions, [
    "core:window:allow-minimize",
    "core:window:allow-toggle-maximize",
    "core:window:allow-close",
    "core:window:allow-set-title",
    "core:window:allow-start-dragging",
  ]);

  assert.match(workspace, /appWindow\.minimize\(\)/);
  assert.match(workspace, /appWindow\.toggleMaximize\(\)/);
  assert.match(workspace, /appWindow\.close\(\)/);
  assert.match(workspace, /getCurrentWindow\(\)\.setTitle\(title\)/);
  assert.match(workspace, /runWindowCommand\("minimize"\)/);
  assert.match(workspace, /runWindowCommand\("maximize"\)/);
  assert.match(workspace, /runWindowCommand\("close"\)/);
  // The caption glyphs are drawn, not typed. They were the literal
  // characters "−", "□" and "×" set in a symbol font, which carry their own
  // side bearings and so never aligned or matched stroke weight.
  assert.match(workspace, /<WindowControlGlyph name="minimize" \/>/);
  assert.match(workspace, /<WindowControlGlyph name="maximize" \/>/);
  assert.match(workspace, /<WindowControlGlyph name="close" \/>/);
});

test("each native window can keep its title synchronized with the selected locale", async () => {
  const [workspace, settingsWorkspace, capabilitySource] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(settingsWorkspaceUrl, "utf8"),
    readFile(settingsCapabilityUrl, "utf8"),
  ]);
  const capability = JSON.parse(capabilitySource) as {
    windows: string[];
    permissions: string[];
  };

  assert.deepEqual(capability.windows, ["settings"]);
  // The Settings window also renders `data-tauri-drag-region` in its own
  // title bar, so it needs the same drag permission; double-clicking that
  // bar is expected to maximise, which needs toggle-maximize.
  assert.deepEqual(capability.permissions, [
    "core:window:allow-set-title",
    "core:window:allow-start-dragging",
    "core:window:allow-toggle-maximize",
  ]);
  assert.match(workspace, /t\("app\.mainWindowTitle"\)/);
  assert.match(settingsWorkspace, /t\("app\.settingsWindowTitle"\)/);
  assert.match(settingsWorkspace, /getCurrentWindow\(\)\.setTitle\(title\)/);
});
