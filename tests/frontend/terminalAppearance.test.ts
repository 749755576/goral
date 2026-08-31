import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  getTerminalTheme,
  resolveTerminalAppearance,
  resolveTerminalFontFamily,
  shouldAttemptWebgl,
  tryInstallWebglAddon,
} from "../../src/terminalAppearance.ts";
import { createDefaultRendererSafeSettings } from "../../src/settingsUi.ts";

const defaults = createDefaultRendererSafeSettings("windows").terminal;

test("legacy Netcatty dark and light themes retain their exact core ANSI palettes", () => {
  const dark = getTerminalTheme("netcatty-dark");
  const light = getTerminalTheme("netcatty-light");
  assert.deepEqual(
    [dark?.theme.background, dark?.theme.foreground, dark?.theme.cursor, dark?.theme.red, dark?.theme.brightWhite],
    ["#0d1117", "#c9d1d9", "#58a6ff", "#ff7b72", "#f0f6fc"],
  );
  assert.deepEqual(
    [light?.theme.background, light?.theme.foreground, light?.theme.cursor, light?.theme.red, light?.theme.brightWhite],
    ["#f6f8fa", "#24292f", "#0969da", "#cf222e", "#8c959f"],
  );
});

test("live and replay appearance share settings while valid log overrides win", () => {
  const globalLight = { ...defaults, themeId: "netcatty-light", fontSize: 15 };
  const live = resolveTerminalAppearance(globalLight);
  const replay = resolveTerminalAppearance(globalLight, { themeId: "netcatty-dark", fontSize: 19 });
  assert.equal(live.themeId, "netcatty-light");
  assert.equal(live.xtermOptions.fontSize, 15);
  assert.equal(replay.themeId, "netcatty-dark");
  assert.equal(replay.xtermOptions.fontSize, 19);
});

test("follow-app selects the matching core theme while an explicit replay theme still wins", () => {
  const followed = resolveTerminalAppearance(
    { ...defaults, followAppTheme: true, themeId: "netcatty-dark" },
    { appColorMode: "light" },
  );
  const explicitReplay = resolveTerminalAppearance(
    { ...defaults, followAppTheme: true, themeId: "netcatty-light" },
    { appColorMode: "light", themeId: "netcatty-dark" },
  );
  assert.equal(followed.themeId, "netcatty-light");
  assert.equal(explicitReplay.themeId, "netcatty-dark");
});

test("follow-app ignores SavedHost themes while preserving legacy host font overrides", () => {
  const followed = resolveTerminalAppearance(
    {
      ...defaults,
      followAppTheme: true,
      themeId: "netcatty-dark",
      fontFamilyId: "menlo",
      fontSize: 14,
      fontWeight: 400,
    },
    {
      appColorMode: "light",
      themeId: "netcatty-dark",
      fontFamily: "Cascadia Code",
      fontSize: 19,
      fontWeight: 650,
      isHostAppearance: true,
    },
  );
  assert.equal(followed.themeId, "netcatty-light");
  assert.match(followed.xtermOptions.fontFamily, /^"Cascadia Code",/);
  assert.equal(followed.xtermOptions.fontSize, 19);
  assert.equal(followed.xtermOptions.fontWeight, 650);

  const manual = resolveTerminalAppearance(
    { ...defaults, followAppTheme: false, themeId: "netcatty-light" },
    { themeId: "netcatty-dark", isHostAppearance: true },
  );
  assert.equal(manual.themeId, "netcatty-dark");
});

test("unknown imported theme IDs safely fall back to the known global theme and then Netcatty Dark", () => {
  const knownGlobal = resolveTerminalAppearance(
    { ...defaults, themeId: "netcatty-light" },
    { themeId: "missing-custom-theme" },
  );
  const unknownGlobal = resolveTerminalAppearance(
    { ...defaults, themeId: "missing-global-theme" },
    { themeId: "missing-log-theme" },
  );
  assert.equal(knownGlobal.themeId, "netcatty-light");
  assert.equal(unknownGlobal.themeId, "netcatty-dark");
});

test("terminal options preserve renderer-safe settings and bounded replay font sizes", () => {
  const appearance = resolveTerminalAppearance({
    ...defaults,
    cursorBlink: false,
    cursorStyle: "bar",
    fontWeight: 500,
    boldFontWeight: 800,
    linePadding: 2,
    minimumContrastRatio: 4.5,
    scrollbackRows: 42_000,
  }, { fontSize: 1_000 });
  assert.equal(appearance.xtermOptions.cursorBlink, false);
  assert.equal(appearance.xtermOptions.cursorStyle, "bar");
  assert.equal(appearance.xtermOptions.fontWeight, 500);
  assert.equal(appearance.xtermOptions.fontWeightBold, 800);
  assert.equal(appearance.xtermOptions.lineHeight, 1.2);
  assert.equal(appearance.xtermOptions.minimumContrastRatio, 4.5);
  assert.equal(appearance.xtermOptions.scrollback, 42_000);
  assert.equal(appearance.xtermOptions.fontSize, 256);
  assert.match(resolveTerminalFontFamily("menlo", "Microsoft YaHei"), /^Menlo, "Microsoft YaHei",/);
});

test("WebGL policy is opportunistic and every load failure leaves the built-in renderer usable", () => {
  assert.equal(shouldAttemptWebgl("auto"), true);
  assert.equal(shouldAttemptWebgl("webgl"), true);
  assert.equal(shouldAttemptWebgl("canvas"), false);
  assert.equal(shouldAttemptWebgl("dom"), false);

  let disposed = 0;
  const addon = {
    activate() {},
    dispose() { disposed += 1; },
  };
  const loaded = tryInstallWebglAddon({ loadAddon() {} }, "auto", () => addon);
  assert.equal(loaded, addon);
  const fallback = tryInstallWebglAddon({ loadAddon() { throw new Error("no webgl"); } }, "webgl", () => addon);
  assert.equal(fallback, null);
  assert.equal(disposed, 1);
  assert.equal(tryInstallWebglAddon({ loadAddon() {} }, "dom", () => addon), null);
});

test("live terminal and replay are wired to the same lazy appearance and WebGL runtime", async () => {
  const [workspace, replay, pkg] = await Promise.all([
    readFile(new URL("../../src/TerminalWorkspace.tsx", import.meta.url), "utf8"),
    readFile(new URL("../../src/ConnectionLogsWorkspace.tsx", import.meta.url), "utf8"),
    readFile(new URL("../../package.json", import.meta.url), "utf8"),
  ]);
  for (const source of [workspace, replay]) {
    assert.match(source, /resolveTerminalAppearance/);
    assert.match(source, /applyResolvedTerminalAppearance/);
    assert.match(source, /installPreferredWebglAddon/);
    assert.match(source, /shouldAttemptWebgl/);
  }
  assert.match(workspace, /SETTINGS_ADAPTER\.load\(\)/);
  assert.match(replay, /themeId: log\.themeId/);
  assert.match(replay, /fontSize: log\.fontSize/);
  assert.match(pkg, /"@xterm\/addon-webgl": "0\.20\.0-beta\.291"/);
});

test("SavedHost effective appearance crosses the typed boundary and only saved sessions apply it", async () => {
  const [backend, workspace] = await Promise.all([
    readFile(new URL("../../src/backend.ts", import.meta.url), "utf8"),
    readFile(new URL("../../src/TerminalWorkspace.tsx", import.meta.url), "utf8"),
  ]);
  assert.match(backend, /effectiveAppearance: SavedHostEffectiveAppearance;/);
  for (const field of ["themeId", "fontFamily", "fontSize", "fontWeight"]) {
    assert.match(backend, new RegExp(`${field}: (?:string|number) \\| null;`));
  }
  assert.match(workspace, /effectiveAppearance: host\.effectiveAppearance/);
  assert.match(workspace, /themeId: connectionTarget\.effectiveAppearance\.themeId \?\? undefined/);
  assert.match(workspace, /fontFamily: connectionTarget\.effectiveAppearance\.fontFamily \?\? undefined/);
  assert.match(workspace, /fontWeight: connectionTarget\.effectiveAppearance\.fontWeight \?\? undefined/);
  assert.match(workspace, /isHostAppearance: true/);
  assert.match(workspace, /\{ hostname, port: numericPort, username \}/);
});
