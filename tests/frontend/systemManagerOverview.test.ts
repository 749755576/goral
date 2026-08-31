import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { createTranslator } from "../../src/i18n.ts";

const backendUrl = new URL("../../src/backend.ts", import.meta.url);
const panelUrl = new URL("../../src/DockerPanel.tsx", import.meta.url);
const i18nUrl = new URL("../../src/i18n.ts", import.meta.url);
const commandsUrl = new URL("../../src-tauri/src/system_manager_commands.rs", import.meta.url);
const desktopUrl = new URL("../../src-tauri/src/lib.rs", import.meta.url);
const overviewCrateUrl = new URL(
  "../../crates/netcatty-sysmanager/src/overview.rs",
  import.meta.url,
);

test("system overview command is native-owned, fixed and strictly bounded", async () => {
  const [backend, commands, desktop, overviewCrate] = await Promise.all([
    readFile(backendUrl, "utf8"),
    readFile(commandsUrl, "utf8"),
    readFile(desktopUrl, "utf8"),
    readFile(overviewCrateUrl, "utf8"),
  ]);

  assert.match(backend, /invoke\("get_system_overview", \{ sessionId \}\)/u);
  assert.doesNotMatch(backend, /GET_SYSTEM_OVERVIEW|\/proc\/meminfo|hw\.memsize|df -kP/u);
  assert.match(commands, /overview::GET_SYSTEM_OVERVIEW/u);
  assert.match(commands, /max_output_bytes: overview::MAX_OVERVIEW_OUTPUT_BYTES/u);
  assert.match(commands, /if output\.truncated \{[\s\S]*?SYSTEM_MANAGER_RESPONSE_TOO_LARGE/u);
  assert.match(commands, /if output\.timed_out \{[\s\S]*?SYSTEM_MANAGER_COMMAND_TIMEOUT/u);
  assert.match(commands, /overview::parse_system_overview/u);
  assert.doesNotMatch(commands, /failure_message\(/u);
  assert.match(desktop, /get_system_overview/u);
  assert.match(overviewCrate, /pub const GET_SYSTEM_OVERVIEW: &str/u);
  const commandStart = overviewCrate.indexOf("pub const GET_SYSTEM_OVERVIEW");
  const commandEnd = overviewCrate.indexOf('"#;', commandStart);
  assert.ok(commandStart >= 0 && commandEnd > commandStart);
  assert.doesNotMatch(overviewCrate.slice(commandStart, commandEnd), /sudo/u);
});

test("overview is the first tab and owns stale request protection", async () => {
  const panel = await readFile(panelUrl, "utf8");

  assert.match(panel, /const \[tab, setTab\] = useState<SystemTab>\("overview"\)/u);
  assert.match(panel, /const TAB_ORDER:[\s\S]*?\[\s*"overview",\s*"containers"/u);
  assert.match(panel, /overview: "systemManager\.overview\.title"/u);
  assert.match(panel, /await getSystemOverview\(sessionId\)/u);

  const refreshStart = panel.indexOf("const refreshOverview = useCallback(");
  const sessionCapture = panel.indexOf(
    "const sessionGeneration = sessionGenerationRef.current;",
    refreshStart,
  );
  const requestGeneration = panel.indexOf(
    "const overviewGeneration = ++overviewGenerationRef.current;",
    sessionCapture,
  );
  const nativeCall = panel.indexOf("await getSystemOverview(sessionId);", requestGeneration);
  const staleGuard = panel.indexOf("if (!isCurrentOverviewRequest()) return;", nativeCall);
  assert.ok(
    refreshStart >= 0
      && sessionCapture > refreshStart
      && requestGeneration > sessionCapture
      && nativeCall > requestGeneration
      && staleGuard > nativeCall,
    "overview replies must retain exact session and request ownership",
  );
  assert.match(panel, /overviewGenerationRef\.current \+= 1;/u);
});

test("overview renders every required field with renderer-owned errors", async () => {
  const panel = await readFile(panelUrl, "utf8");

  for (const field of [
    "hostname",
    "osName",
    "kernelRelease",
    "uptimeSeconds",
    "loadAverage",
    "cpuCount",
    "memoryTotalBytes",
    "memoryUsedBytes",
    "rootDiskTotalBytes",
    "rootDiskUsedBytes",
  ]) {
    assert.ok(panel.includes(`overview.${field}`), `overview must display ${field}`);
  }
  assert.match(
    panel,
    /catch \{[\s\S]*?setOverviewError\(t\("systemManager\.overview\.listFailed"\)\)/u,
  );
  assert.doesNotMatch(panel, /SYSTEM_MANAGER_[A-Z_]+|\.message/u);
});

test("overview copy is complete in English and Simplified Chinese", async () => {
  const i18n = await readFile(i18nUrl, "utf8");
  const keys = [
    "systemManager.overview.title",
    "systemManager.overview.summary",
    "systemManager.overview.snapshot",
    "systemManager.overview.listFailed",
    "systemManager.overview.notAvailable",
    "systemManager.overview.hostname",
    "systemManager.overview.os",
    "systemManager.overview.kernel",
    "systemManager.overview.uptime",
    "systemManager.overview.uptimeValue",
    "systemManager.overview.loadAverage",
    "systemManager.overview.cpuCount",
    "systemManager.overview.cpuCountValue",
    "systemManager.overview.memory",
    "systemManager.overview.rootDisk",
    "systemManager.overview.usageValue",
  ];
  for (const key of keys) {
    assert.equal(
      i18n.split(`"${key}"`).length - 1,
      2,
      `${key} must exist once in each locale`,
    );
  }

  const en = createTranslator("en-US");
  const zh = createTranslator("zh-CN");
  assert.equal(
    en("systemManager.overview.uptimeValue", { days: 2, hours: 3, minutes: 4 }),
    "2d 3h 4m",
  );
  assert.equal(
    zh("systemManager.overview.cpuCountValue", { count: 16 }),
    "16 个逻辑处理器",
  );
});
