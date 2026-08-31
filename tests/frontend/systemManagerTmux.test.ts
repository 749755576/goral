import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { createTranslator, LOCALES } from "../../src/i18n.ts";

const backendUrl = new URL("../../src/backend.ts", import.meta.url);
const panelUrl = new URL("../../src/TmuxPanel.tsx", import.meta.url);
const systemManagerUrl = new URL("../../src/DockerPanel.tsx", import.meta.url);
const systemManagerCssUrl = new URL("../../src/systemManager.css", import.meta.url);
const commandsUrl = new URL("../../src-tauri/src/system_manager_commands.rs", import.meta.url);
const desktopUrl = new URL("../../src-tauri/src/lib.rs", import.meta.url);

test("tmux operations are crate-planned, bounded and registered as four thin commands", async () => {
  const [backend, commands, desktop] = await Promise.all([
    readFile(backendUrl, "utf8"),
    readFile(commandsUrl, "utf8"),
    readFile(desktopUrl, "utf8"),
  ]);

  for (const command of [
    "list_tmux_sessions",
    "create_tmux_session",
    "rename_tmux_session",
    "kill_tmux_session",
  ]) {
    assert.ok(backend.includes(`invoke("${command}"`), `${command} needs a typed renderer API`);
    assert.ok(desktop.includes(command), `${command} needs Tauri registration`);
  }

  assert.match(commands, /tmux::plan_operation\(operation\)/u);
  assert.match(commands, /plan\.shell_command\(\)/u);
  assert.match(commands, /max_output_bytes: plan\.max_output_bytes\(\)/u);
  assert.match(commands, /tmux::parse_sessions\(&stdout\)/u);
  assert.match(commands, /tmux::is_no_server_message/u);
  const tmuxStart = commands.indexOf(" * tmux session catalog");
  const tmuxEnd = commands.indexOf(" * Process, port and service inventory", tmuxStart);
  assert.ok(tmuxStart >= 0 && tmuxEnd > tmuxStart, "tmux adapter slice must be present");
  assert.doesNotMatch(commands.slice(tmuxStart, tmuxEnd), /sudo/u);
  assert.doesNotMatch(backend, /attach_tmux_session/u);
  assert.doesNotMatch(desktop, /attach_tmux_session/u);
});

test("the independent tmux panel sends names as data and never assembles shell or sudo input", async () => {
  const [backend, panel, systemManager] = await Promise.all([
    readFile(backendUrl, "utf8"),
    readFile(panelUrl, "utf8"),
    readFile(systemManagerUrl, "utf8"),
  ]);

  assert.match(backend, /export type TmuxSession/u);
  for (const field of ["name", "windows", "attached", "created", "lastActivity"]) {
    assert.ok(backend.includes(`${field}:`), `TmuxSession needs ${field}`);
    assert.ok(panel.includes(`session.${field}`), `the panel needs to render ${field}`);
  }
  assert.match(panel, /createTmuxSession\(sessionId, createName\)/u);
  assert.match(panel, /renameTmuxSession\(sessionId, target\.name, target\.newName\)/u);
  assert.match(panel, /killTmuxSession\(sessionId, target\.name\)/u);
  assert.match(panel, /new TextEncoder\(\)\.encode\(name\)\.byteLength/u);
  assert.doesNotMatch(panel, /sudo|password|shell_command|exec_capture/u);
  assert.doesNotMatch(panel, /tmux\s+(?:new-session|rename-session|kill-session|attach-session)/u);

  assert.match(systemManager, /import TmuxPanel from "\.\/TmuxPanel"/u);
  assert.match(systemManager, /"tmux" \| InventoryTab/u);
  assert.match(systemManager, /<TmuxPanel sessionId=\{sessionId\} locale=\{locale\} t=\{t\}/u);
});

test("unfinished tmux attach stays out of the public interface", async () => {
  const [backend, panel, commands] = await Promise.all([
    readFile(backendUrl, "utf8"),
    readFile(panelUrl, "utf8"),
    readFile(commandsUrl, "utf8"),
  ]);

  assert.doesNotMatch(backend, /attachTmux|TMUX_ATTACH_SUPPORTED/u);
  assert.doesNotMatch(panel, /systemManager\.tmux\.attach(?:Unavailable)?"|attachBoundaryId/u);
  assert.match(commands, /TmuxOperationPlan::TerminalAttach\(_\)/u);
  assert.match(commands, /SYSTEM_MANAGER_TMUX_ATTACH_UNAVAILABLE/u);
});

test("all eight System Manager tabs remain readable at the narrow panel width", async () => {
  const css = await readFile(systemManagerCssUrl, "utf8");

  assert.match(css, /grid-template-columns: repeat\(4, minmax\(0, 1fr\)\)/u);
  assert.match(
    css,
    /@container system-manager \(max-width: 340px\)[\s\S]*?repeat\(2, minmax\(0, 1fr\)\)/u,
  );
  assert.match(css, /overflow-wrap: anywhere/u);
  assert.doesNotMatch(css, /grid-auto-flow: column/u);
});

test("non-container tabs never inherit the Docker running summary", async () => {
  const panel = await readFile(systemManagerUrl, "utf8");

  for (const key of [
    "systemManager.processes.summary",
    "systemManager.ports.summary",
    "systemManager.services.summary",
    "systemManager.gpu.summary",
    "systemManager.tmux.summary",
  ]) {
    assert.ok(panel.includes(key), `${key} must own its header summary`);
  }
  assert.match(panel, /case "images":[\s\S]*?systemManager\.rowCount/u);
  assert.match(panel, /case "containers":[\s\S]*?systemManager\.docker\.summary/u);
});

test("tmux requests retire stale session, refresh and action ownership", async () => {
  const panel = await readFile(panelUrl, "utf8");

  assert.match(panel, /sessionGenerationRef/u);
  assert.match(panel, /viewSessionIdRef/u);
  assert.match(panel, /refreshGenerationRef/u);
  assert.match(panel, /actionGenerationRef/u);
  assert.match(panel, /const isCurrentRefresh/u);
  assert.match(panel, /const isCurrentAction/u);
  assert.match(panel, /if \(viewSessionIdRef\.current !== sessionId\)/u);
  assert.match(
    panel,
    /setSessions\(\[\]\);[\s\S]*?setBusy\(null\);[\s\S]*?setRenameDraft\(null\);[\s\S]*?setPendingKill\(null\);/u,
  );
});

test("tmux copy is complete in English and Simplified Chinese", () => {
  const keys = [
    "systemManager.tmux.title",
    "systemManager.tmux.summary",
    "systemManager.tmux.emptyTitle",
    "systemManager.tmux.emptyBody",
    "systemManager.tmux.listFailed",
    "systemManager.tmux.createName",
    "systemManager.tmux.nameHint",
    "systemManager.tmux.nameInvalid",
    "systemManager.tmux.create",
    "systemManager.tmux.createFailed",
    "systemManager.tmux.attached",
    "systemManager.tmux.detached",
    "systemManager.tmux.windowCount",
    "systemManager.tmux.created",
    "systemManager.tmux.lastActivity",
    "systemManager.tmux.rename",
    "systemManager.tmux.newName",
    "systemManager.tmux.renameFailed",
    "systemManager.tmux.kill",
    "systemManager.tmux.killFailed",
    "systemManager.tmux.confirmKillTitle",
    "systemManager.tmux.confirmKillBody",
  ] as const;

  for (const key of keys) {
    assert.ok(LOCALES["en-US"][key], `missing English ${key}`);
    assert.ok(LOCALES["zh-CN"][key], `missing Chinese ${key}`);
  }

  const en = createTranslator("en-US");
  const zh = createTranslator("zh-CN");
  assert.equal(en("systemManager.tmux.windowCount", { count: 3 }), "Windows: 3");
  assert.equal(zh("systemManager.tmux.confirmKillBody", { name: "发布" }), "tmux 会话 发布 及其全部窗口都将被终止。");
});
