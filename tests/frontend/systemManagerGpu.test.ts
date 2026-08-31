import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { createTranslator } from "../../src/i18n.ts";

const backendUrl = new URL("../../src/backend.ts", import.meta.url);
const panelUrl = new URL("../../src/DockerPanel.tsx", import.meta.url);
const inventoryUrl = new URL("../../src/SystemInventory.tsx", import.meta.url);
const i18nUrl = new URL("../../src/i18n.ts", import.meta.url);
const commandsUrl = new URL("../../src-tauri/src/system_manager_commands.rs", import.meta.url);
const desktopUrl = new URL("../../src-tauri/src/lib.rs", import.meta.url);
const gpuCrateUrl = new URL("../../crates/netcatty-sysmanager/src/gpu.rs", import.meta.url);

test("GPU inventory is a fixed native query and the renderer only names the operation", async () => {
  const [backend, inventory, gpuCrate, commands, desktop] = await Promise.all([
    readFile(backendUrl, "utf8"),
    readFile(inventoryUrl, "utf8"),
    readFile(gpuCrateUrl, "utf8"),
    readFile(commandsUrl, "utf8"),
    readFile(desktopUrl, "utf8"),
  ]);

  assert.match(backend, /invoke\("list_nvidia_gpus", \{ sessionId \}\)/u);
  assert.doesNotMatch(backend, /nvidia-smi|--query-gpu/u);
  assert.doesNotMatch(inventory, /nvidia-smi|--query-gpu|sudo/u);

  assert.match(
    gpuCrate,
    /--query-gpu=index,uuid,name,utilization\.gpu,memory\.used,memory\.total,/u,
  );
  assert.match(
    gpuCrate,
    /--format=csv,noheader,nounits/u,
  );
  assert.match(commands, /gpu::LIST_NVIDIA_GPUS/u);
  assert.match(commands, /gpu::MAX_NVIDIA_OUTPUT_BYTES/u);
  assert.match(commands, /gpu::parse_nvidia_gpus/u);
  assert.match(desktop, /list_nvidia_gpus/u);
});

test("GPU inventory has a visible tab and typed renderer fields", async () => {
  const [backend, panel, inventory] = await Promise.all([
    readFile(backendUrl, "utf8"),
    readFile(panelUrl, "utf8"),
    readFile(inventoryUrl, "utf8"),
  ]);

  for (const field of [
    "utilizationPercent",
    "memoryUsedMib",
    "memoryTotalMib",
    "temperatureC",
    "powerDrawW",
    "powerLimitW",
    "fanPercent",
    "driverVersion",
  ]) {
    assert.ok(backend.includes(field), `NvidiaGpu must expose ${field}`);
  }
  assert.match(panel, /"services",\s*"gpu"/u);
  assert.match(panel, /gpu: "systemManager\.gpu\.title"/u);
  assert.match(inventory, /listNvidiaGpus\(sessionId\)/u);
  assert.match(inventory, /tab === "gpu"/u);
});

test("GPU presentation is complete in English and Simplified Chinese", async () => {
  const [inventory, i18n] = await Promise.all([
    readFile(inventoryUrl, "utf8"),
    readFile(i18nUrl, "utf8"),
  ]);
  const keys = [
    "systemManager.gpu.title",
    "systemManager.gpu.emptyTitle",
    "systemManager.gpu.emptyBody",
    "systemManager.gpu.listFailed",
    "systemManager.gpu.index",
    "systemManager.gpu.uuid",
    "systemManager.gpu.driver",
    "systemManager.gpu.utilization",
    "systemManager.gpu.memory",
    "systemManager.gpu.temperature",
    "systemManager.gpu.power",
    "systemManager.gpu.powerDraw",
    "systemManager.gpu.fan",
  ];
  const resolvedByTabKey = new Set([
    "systemManager.gpu.title",
    "systemManager.gpu.emptyTitle",
    "systemManager.gpu.emptyBody",
  ]);

  for (const key of keys) {
    assert.ok(inventory.includes(key) || resolvedByTabKey.has(key), `${key} must be used`);
    assert.equal(
      i18n.split(`"${key}"`).length - 1,
      2,
      `${key} must exist once in each locale`,
    );
  }

  // GPU failures use a renderer-owned sentence. Remote stderr must not be
  // reflected into this new panel.
  assert.match(
    inventory,
    /tab === "gpu"[\s\S]*?t\("systemManager\.gpu\.listFailed"\)/u,
  );

  const en = createTranslator("en-US");
  const zh = createTranslator("zh-CN");
  assert.equal(
    en("systemManager.gpu.memory", { used: "1024", total: "24576" }),
    "Memory 1024 / 24576 MiB",
  );
  assert.equal(
    zh("systemManager.gpu.power", { draw: "120.5", limit: "450" }),
    "功耗 120.5 / 450 W",
  );
});
