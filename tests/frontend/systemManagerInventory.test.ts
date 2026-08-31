import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const inventoryUrl = new URL("../../src/SystemInventory.tsx", import.meta.url);
const backendUrl = new URL("../../src/backend.ts", import.meta.url);
const commandsUrl = new URL("../../src-tauri/src/system_manager_commands.rs", import.meta.url);
const inventoryCrateUrl = new URL(
  "../../crates/netcatty-sysmanager/src/inventory.rs",
  import.meta.url,
);

const code = (source: string): string =>
  source.replace(new RegExp("\\/\\*[\\s\\S]*?\\*\\/", "g"), "").replace(new RegExp("^\\s*\\/\\/.*$", "gm"), "");

test("inventory session/tab changes retire requests and clear every transient state", async () => {
  const source = await readFile(inventoryUrl, "utf8");

  assert.match(source, /const sessionGenerationRef = useRef\(0\)/u);
  assert.match(source, /const refreshGenerationRef = useRef\(0\)/u);
  assert.match(source, /const pendingActionsRef = useRef\(new Map<string, PendingInventoryAction>\(\)\)/u);
  assert.doesNotMatch(source, /actionGenerationRef/u);

  const effect = source.indexOf("useEffect(() => {");
  const establish = source.indexOf(
    "const sessionGeneration = ++sessionGenerationRef.current;",
    effect,
  );
  const firstRefresh = source.indexOf("void refresh();", establish);
  assert.ok(effect >= 0 && establish > effect && firstRefresh > establish);

  const resetBlock = source.slice(establish, firstRefresh);
  for (const reset of [
    "setProcesses([]);",
    "setPorts([]);",
    "setServices([]);",
    "setGpus([]);",
    "setLoading(false);",
    "setListError(null);",
    "setActionError(null);",
    "setBusyTargets(new Set());",
    "setPendingKill(null);",
  ]) {
    assert.ok(resetBlock.includes(reset), `scope switch must run ${reset}`);
  }
  assert.match(source, /\}, \[refresh, sessionId, tab\]\);/u);
});

test("inventory mutations have independent target/action ownership and final refreshes", async () => {
  const source = await readFile(inventoryUrl, "utf8");

  assert.match(
    source,
    /const refreshGeneration = \+\+refreshGenerationRef\.current;[\s\S]*?const isCurrentRefresh/u,
  );
  assert.match(
    source,
    /sessionGenerationRef\.current === sessionGeneration[\s\S]*?refreshGenerationRef\.current === refreshGeneration/u,
  );

  for (const [start, nativeCall] of [
    ["const sendSignal = useCallback(", "await signalRemoteProcess("],
    ["const runService = useCallback(", "await runSystemServiceAction("],
  ] as const) {
    const actionStart = source.indexOf(start);
    const actionEnd = source.indexOf("  );", actionStart);
    const body = source.slice(actionStart, actionEnd);
    const target = body.indexOf("const targetKey = ");
    const duplicateGuard = body.indexOf(
      "if (pendingActionsRef.current.has(targetKey)) return;",
      target,
    );
    const tokenRegistration = body.indexOf(
      "pendingActionsRef.current.set(targetKey,",
      duplicateGuard,
    );
    const native = body.indexOf(nativeCall);
    const failure = body.indexOf("setActionError(t(", native);
    const finallyBlock = body.indexOf("} finally {", failure);
    const refresh = body.indexOf("if (isCurrentAction()) await refresh();", finallyBlock);
    const cleanup = body.indexOf("pendingActionsRef.current.delete(targetKey);", refresh);
    assert.ok(actionStart >= 0 && native >= 0, `${start} must call native operation`);
    assert.ok(
      target >= 0
        && duplicateGuard > target
        && tokenRegistration > duplicateGuard
        && native > tokenRegistration,
      "each target must be claimed synchronously before its native mutation",
    );
    assert.ok(
      failure > native && finallyBlock > failure && refresh > finallyBlock && cleanup > refresh,
      "success and failure must both reconcile before releasing the exact target",
    );
    assert.match(
      body,
      /sessionGenerationRef\.current === sessionGeneration[\s\S]*?pendingActionsRef\.current\.get\(targetKey\)\?\.action === (?:signal|action)[\s\S]*?\.token === actionToken/u,
    );
    assert.match(body, /const startsActionBatch = pendingActionsRef\.current\.size === 0/u);
    assert.match(body, /if \(startsActionBatch\) setActionError\(null\)/u);
    assert.match(body, /setBusyTargets\(\(current\) => new Set\(current\)\.add\(targetKey\)\)/u);
  }

  assert.match(source, /busyTargets\.has\(processTargetKey\(process\.pid\)\)/u);
  assert.match(source, /busyTargets\.has\(serviceTargetKey\(service\.unit\)\)/u);
  assert.match(
    source,
    /signalRemoteProcess\(sessionId, process\.pid, process\.startTimeToken, signal\)/u,
    "the renderer must round-trip the native opaque process identity token",
  );
  const refreshStart = source.indexOf("const refresh = useCallback(");
  const refreshEnd = source.indexOf("useEffect(() => {", refreshStart);
  assert.doesNotMatch(
    source.slice(refreshStart, refreshEnd),
    /setActionError/u,
    "a reconciliation refresh must preserve a concurrent mutation failure",
  );
});

test("inventory errors are renderer-owned fallbacks and GPU remains available", async () => {
  const source = await readFile(inventoryUrl, "utf8");

  assert.doesNotMatch(source, /readableError|\.message|String\(cause\)|String\(error\)/u);
  for (const key of [
    "systemManager.listFailed",
    "systemManager.gpu.listFailed",
    "systemManager.process.signalFailed",
    "systemManager.service.actionFailed",
  ]) {
    assert.ok(source.includes(`t("${key}")`), `must render ${key}`);
  }
  assert.match(source, /export type InventoryTab = "processes" \| "ports" \| "services" \| "gpu"/u);
  assert.match(source, /await listNvidiaGpus\(sessionId\)/u);
  assert.match(source, /tab === "gpu"/u);
});

test("process and service routes are probed before one non-replayed mutation", async () => {
  const [commands, crate] = await Promise.all([
    readFile(commandsUrl, "utf8"),
    readFile(inventoryCrateUrl, "utf8"),
  ]);

  assert.match(crate, /pub enum InventoryActionRoute/u);
  assert.match(crate, /pub struct InventoryActionPlan/u);
  assert.match(crate, /pub const fn probe_order/u);
  assert.match(crate, /pub fn probe_command/u);
  assert.match(crate, /pub fn command/u);
  assert.doesNotMatch(crate, /classify_action_result|has_explicit_permission_denial/u);

  const probeStart = commands.indexOf("async fn run_inventory_probe(");
  const runnerStart = commands.indexOf("async fn run_inventory_action(", probeStart);
  const probe = commands.slice(probeStart, runnerStart);
  assert.ok(probeStart >= 0 && runnerStart > probeStart, "native route probe must exist");
  assert.match(probe, /plan\.probe_command\(route\)/u);
  assert.match(probe, /Some\(0\) => InventoryProbeResult::Available/u);
  assert.doesNotMatch(probe, /stderr/u, "route selection must ignore localized diagnostics");

  const runnerEnd = commands.indexOf("#[tauri::command]", runnerStart);
  const runner = commands.slice(runnerStart, runnerEnd);
  const probeOrder = runner.indexOf("for route in plan.probe_order()");
  const routeProbe = runner.indexOf("run_inventory_probe(state, session_id, &plan, route)");
  const mutation = runner.indexOf("plan.command(route)");
  assert.ok(runnerStart >= 0 && runnerEnd > runnerStart, "native action runner must exist");
  assert.ok(
    probeOrder >= 0 && routeProbe > probeOrder && mutation > routeProbe,
    "all route probes must finish before the selected mutation runs",
  );
  assert.equal(
    runner.match(/plan\.command\(route\)/gu)?.length,
    1,
    "a mutation must have exactly one execution site and no fallback replay",
  );
  assert.doesNotMatch(runner, /stderr|classify_action_result|PermissionDenied/u);
  assert.match(
    runner,
    /Some\(PROCESS_IDENTITY_MISMATCH_EXIT_STATUS\)[\s\S]*?SYSTEM_MANAGER_INVALID_TARGET/u,
    "a PID reused between probe and mutation must fail with the stable target error",
  );

  const signalStart = commands.indexOf("pub(super) async fn signal_remote_process(");
  const serviceStart = commands.indexOf("pub(super) async fn run_system_service_action(", signalStart);
  const signal = commands.slice(signalStart, serviceStart);
  assert.match(signal, /start_time_token: String/u);
  assert.match(signal, /inventory::signal_action_plan\(signal, pid, &start_time_token\)/u);
  assert.match(signal, /SYSTEM_MANAGER_INVALID_TARGET/u);
  assert.match(signal, /run_inventory_action/u);
  assert.doesNotMatch(code(signal), /run_plain|sudo/u);
});

test("process identity token crosses Rust, IPC and renderer without being rewritten", async () => {
  const [crate, commands, backend, inventory] = await Promise.all([
    readFile(inventoryCrateUrl, "utf8"),
    readFile(commandsUrl, "utf8"),
    readFile(backendUrl, "utf8"),
    readFile(inventoryUrl, "utf8"),
  ]);

  assert.match(
    crate,
    /#\[serde\(rename_all = "camelCase"\)\][\s\S]*?pub struct RemoteProcess[\s\S]*?pub start_time_token: String/u,
  );
  assert.match(backend, /export type RemoteProcess[\s\S]*?startTimeToken: string/u);
  assert.match(
    backend,
    /signalRemoteProcess[\s\S]*?startTimeToken: string[\s\S]*?invoke\("signal_remote_process", \{[\s\S]*?startTimeToken/u,
  );
  assert.match(
    inventory,
    /signalRemoteProcess\(sessionId, process\.pid, process\.startTimeToken, signal\)/u,
  );
  assert.match(
    commands,
    /signal_remote_process\([\s\S]*?start_time_token: String[\s\S]*?signal_action_plan\(signal, pid, &start_time_token\)/u,
  );
});

test("signal planning rejects PID zero and values outside signed remote pid_t", async () => {
  const crate = await readFile(inventoryCrateUrl, "utf8");

  assert.match(crate, /pub fn signal_action_plan/u);
  assert.match(crate, /pid == 0 \|\| pid > i32::MAX as u32/u);
  assert.match(crate, /signal_action_plan\(ProcessSignal::Term, 0, token\)\.is_none\(\)/u);
  assert.match(
    crate,
    /signal_action_plan\(ProcessSignal::Kill, i32::MAX as u32 \+ 1, token\)\.is_none\(\)/u,
  );
  assert.match(crate, /signal_action_plan\(ProcessSignal::Term, 42, invalid\)\.is_none\(\)/u);
});
