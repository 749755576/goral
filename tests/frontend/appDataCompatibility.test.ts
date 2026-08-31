import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const configUrl = new URL("../../src-tauri/tauri.conf.json", import.meta.url);
const desktopUrl = new URL("../../src-tauri/src/lib.rs", import.meta.url);
const settingsWindowUrl = new URL("../../src-tauri/src/settings_window.rs", import.meta.url);

test("Goral creates both WebViews with the selected compatible profile root", async () => {
  const [configSource, desktop, settingsWindow] = await Promise.all([
    readFile(configUrl, "utf8"),
    readFile(desktopUrl, "utf8"),
    readFile(settingsWindowUrl, "utf8"),
  ]);
  const config = JSON.parse(configSource) as {
    identifier: string;
    app: { windows: Array<{ label: string; create?: boolean }> };
  };
  const main = config.app.windows.find((window) => window.label === "main");

  assert.equal(config.identifier, "io.github.749755576.goral");
  assert.equal(main?.create, false);
  assert.match(
    desktop,
    /compatible_data_roots\([\s\S]*?app\.path\(\)\.app_data_dir\(\)\?[\s\S]*?app\.path\(\)\.app_local_data_dir\(\)\?/u,
  );
  assert.match(desktop, /DesktopState::open\(app_data\.join\("vault"\)\)/u);
  assert.match(desktop, /SavedHostStore::open\(vault_path\.as_ref\(\)\.join\("saved-hosts"\)\)/u);
  assert.match(desktop, /RendererSafeSettingsStore::open\(vault_path\.as_ref\(\)\.join\("settings"\)\)/u);
  assert.match(desktop, /SecretFileStore::open\(vault_path\.as_ref\(\)\.join\("secret-blobs"\)\)/u);
  assert.match(desktop, /ConnectionLogReplayRuntime::new\(&app_data\)/u);
  assert.match(desktop, /WebviewWindowBuilder::from_config\(app, main_window_config\)\?/u);
  assert.match(desktop, /main_window_builder\.data_directory\(webview_data\)/u);
  assert.match(settingsWindow, /State<'_, CompatibleWebviewDataRoot>/u);
  assert.match(settingsWindow, /builder = builder\.data_directory\(webview_data\.to_owned\(\)\)/u);
});
