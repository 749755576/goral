import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  classifyPortForwardError,
  createPortForwardBulkPresentation,
  normalizePortForwardDraft,
  portForwardRuleSummary,
  runPortForwardBulkAction,
  selectPortForwardBulkTargetIds,
} from "../../src/portForwardingUi.ts";
import type {
  PortForwardCatalog,
  PortForwardRule,
  PortForwardRuntime,
} from "../../src/backend.ts";
import { createTranslator, type MessageKey } from "../../src/i18n.ts";

const backendSourceUrl = new URL("../../src/backend.ts", import.meta.url);
const componentSourceUrl = new URL("../../src/PortForwardingCatalog.tsx", import.meta.url);
const stylesSourceUrl = new URL("../../src/styles.css", import.meta.url);

const bulkRule = (id: string, label = id): PortForwardRule => ({
  id,
  label,
  type: "local",
  localPort: 8_000,
  bindAddress: "127.0.0.1",
  remoteHost: "127.0.0.1",
  remotePort: 80,
  hostId: "host-1",
  autoStart: false,
  createdAt: 1,
});

const bulkCatalog = (
  inventoryRevision: unknown,
  rules: PortForwardRule[],
  runtime: PortForwardRuntime[],
): PortForwardCatalog => ({ inventoryRevision, rules, runtime });

test("port forwarding drafts preserve local, remote, and dynamic rule semantics", () => {
  const base = {
    label: " Database ",
    localPort: " 8080 ",
    bindAddress: " 127.0.0.1 ",
    remoteHost: " db.internal ",
    remotePort: "3306",
    hostId: " relay-1 ",
    autoStart: true,
  };
  assert.deepEqual(normalizePortForwardDraft({ ...base, type: "local" }), {
    label: "Database",
    type: "local",
    localPort: 8080,
    bindAddress: "127.0.0.1",
    remoteHost: "db.internal",
    remotePort: 3306,
    hostId: "relay-1",
    autoStart: true,
  });
  assert.deepEqual(normalizePortForwardDraft({
    ...base,
    label: "",
    type: "dynamic",
    localPort: "1080",
    remoteHost: "ignored",
    remotePort: "9999",
  }), {
    label: "SOCKS:1080",
    type: "dynamic",
    localPort: 1080,
    bindAddress: "127.0.0.1",
    hostId: "relay-1",
    autoStart: true,
  });
  assert.equal(normalizePortForwardDraft({ ...base, type: "remote", localPort: "0" }), null);
  assert.equal(normalizePortForwardDraft({ ...base, type: "local", remoteHost: "bad host" }), null);
  assert.equal(normalizePortForwardDraft({ ...base, type: "local", hostId: "" }), null);
});

test("port forwarding summaries remain compatible with the original cards", () => {
  const common = {
    id: "rule-1",
    label: "Rule",
    localPort: 8080,
    bindAddress: "127.0.0.1",
    hostId: "host-1",
    autoStart: false,
    createdAt: 1,
  };
  assert.equal(portForwardRuleSummary({
    ...common,
    type: "local",
    remoteHost: "db.internal",
    remotePort: 3306,
  }), "127.0.0.1:8080 → db.internal:3306");
  assert.equal(portForwardRuleSummary({ ...common, type: "dynamic" }), "SOCKS5 · 127.0.0.1:8080");
});

test("fixed port forwarding errors map to safe user messages", () => {
  const cases = [
    ["PORT_FORWARD_INVALID: fixed", "invalid", false],
    ["PORT_FORWARD_NOT_FOUND: fixed", "notFound", true],
    ["PORT_FORWARD_INVENTORY_CHANGED: fixed", "stale", true],
    ["PORT_FORWARD_PUBLICATION_FAILED: fixed", "publication", true],
    ["PORT_FORWARD_ALREADY_RUNNING: fixed", "alreadyRunning", true],
    ["PORT_FORWARD_NOT_RUNNING: fixed", "notRunning", true],
    ["PORT_FORWARD_CONNECTION_FAILED: fixed", "connection", true],
  ] as const;
  for (const [raw, kind, refreshCatalog] of cases) {
    const issue = classifyPortForwardError(new Error(raw));
    assert.equal(issue.kind, kind);
    assert.equal(issue.refreshCatalog, refreshCatalog);
    assert.ok(issue.message.length > 0);
    assert.equal(issue.message.includes(raw), false);
  }
  const marker = "raw-port-forward-error-must-not-reach-renderer";
  assert.equal(classifyPortForwardError(new Error(marker)).message.includes(marker), false);
});

test("bulk forwarding targets skip rules that already match the requested state", () => {
  const catalog = bulkCatalog(
    "revision-1",
    [bulkRule("inactive"), bulkRule("active"), bulkRule("connecting"), bulkRule("error")],
    [
      { ruleId: "active", phase: "active" },
      { ruleId: "connecting", phase: "connecting" },
      { ruleId: "error", phase: "error", error: "PORT_FORWARD_CONNECTION_FAILED: fixed" },
      { ruleId: "orphan-runtime", phase: "active" },
    ],
  );

  assert.deepEqual(selectPortForwardBulkTargetIds(catalog, "start"), ["inactive", "error"]);
  assert.deepEqual(
    selectPortForwardBulkTargetIds(catalog, "stop"),
    ["active", "connecting", "error", "orphan-runtime"],
  );
});

test("bulk start is sequential, threads inventory revisions, collects failures, and refreshes last", async () => {
  const inactive = bulkRule("inactive", "Inactive rule");
  const active = bulkRule("active", "Active rule");
  const retry = bulkRule("retry", "Retry rule");
  const followup = bulkRule("followup", "Follow-up rule");
  const allRules = [retry, active, inactive, followup];
  const initial = bulkCatalog("revision-1", allRules, [
    { ruleId: active.id, phase: "active" },
    { ruleId: retry.id, phase: "error", error: "PORT_FORWARD_CONNECTION_FAILED: fixed" },
  ]);
  const afterFirst = bulkCatalog("revision-2", allRules, [
    { ruleId: inactive.id, phase: "active" },
    { ruleId: active.id, phase: "active" },
    { ruleId: retry.id, phase: "error", error: "PORT_FORWARD_CONNECTION_FAILED: fixed" },
  ]);
  const afterSecond = bulkCatalog("revision-3", allRules, [
    ...afterFirst.runtime,
    { ruleId: followup.id, phase: "active" },
  ]);
  const finalCatalog = bulkCatalog("revision-4", allRules, afterSecond.runtime);
  const requests: Array<{ id: string; expectedInventoryRevision: unknown }> = [];
  let inFlight = 0;
  let maxInFlight = 0;
  let refreshCalls = 0;

  const result = await runPortForwardBulkAction("start", initial, {
    start: async (request) => {
      requests.push(request);
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await Promise.resolve();
      inFlight -= 1;
      if (request.id === retry.id) {
        throw new Error("PORT_FORWARD_CONNECTION_FAILED: backend detail");
      }
      return {
        ruleId: request.id,
        tunnelId: `tunnel-${request.id}`,
        address: "127.0.0.1",
        port: 8_000,
        catalog: request.id === inactive.id ? afterFirst : afterSecond,
      };
    },
    stop: async () => {
      throw new Error("stop must not run during bulk start");
    },
    refresh: async () => {
      refreshCalls += 1;
      return refreshCalls === 1 ? initial : finalCatalog;
    },
  });

  assert.deepEqual(requests, [
    { id: retry.id, expectedInventoryRevision: "revision-1" },
    { id: inactive.id, expectedInventoryRevision: "revision-1" },
    { id: followup.id, expectedInventoryRevision: "revision-2" },
  ]);
  assert.equal(maxInFlight, 1);
  assert.equal(refreshCalls, 2, "one failure reconciliation plus one mandatory final refresh");
  assert.equal(result.attempted, 3);
  assert.equal(result.succeeded, 2);
  assert.equal(result.skipped, 1);
  assert.equal(result.failures.length, 1);
  assert.equal(result.failures[0]?.ruleId, retry.id);
  assert.equal(result.failures[0]?.label, retry.label);
  assert.equal(result.failures[0]?.issue.kind, "connection");
  assert.equal(result.catalog.inventoryRevision, "revision-4");
  assert.equal(result.refreshIssue, undefined);
});

test("bulk stop cleans error runtimes and treats a concurrent not-running result as skipped", async () => {
  const active = bulkRule("active", "Active rule");
  const errored = bulkRule("errored", "Errored rule");
  const inactive = bulkRule("inactive", "Inactive rule");
  const initial = bulkCatalog("revision-1", [active, errored, inactive], [
    { ruleId: active.id, phase: "active" },
    { ruleId: errored.id, phase: "error", error: "PORT_FORWARD_CONNECTION_FAILED: fixed" },
  ]);
  const afterRace = bulkCatalog("revision-1", [active, errored, inactive], [
    { ruleId: errored.id, phase: "error", error: "PORT_FORWARD_CONNECTION_FAILED: fixed" },
  ]);
  const stopped = bulkCatalog("revision-1", [active, errored, inactive], []);
  const stoppedIds: string[] = [];
  let refreshCalls = 0;

  const result = await runPortForwardBulkAction("stop", initial, {
    start: async () => {
      throw new Error("start must not run during bulk stop");
    },
    stop: async ({ id }) => {
      stoppedIds.push(id);
      if (id === active.id) throw new Error("PORT_FORWARD_NOT_RUNNING: fixed");
      return stopped;
    },
    refresh: async () => {
      refreshCalls += 1;
      return refreshCalls === 1 ? afterRace : stopped;
    },
  });

  assert.deepEqual(stoppedIds, [active.id, errored.id]);
  assert.equal(result.attempted, 2);
  assert.equal(result.succeeded, 1);
  assert.equal(result.skipped, 2, "one initially inactive rule plus one target-state race");
  assert.deepEqual(result.failures, []);
  assert.equal(refreshCalls, 2);
  assert.deepEqual(result.catalog.runtime, []);
});

test("bulk actions expose a safe final-refresh failure without discarding completed results", async () => {
  const rule = bulkRule("rule-1", "Rule one");
  const initial = bulkCatalog("revision-1", [rule], []);
  const startedCatalog = bulkCatalog("revision-2", [rule], [
    { ruleId: rule.id, phase: "active" },
  ]);

  const result = await runPortForwardBulkAction("start", initial, {
    start: async () => ({
      ruleId: rule.id,
      tunnelId: "tunnel-1",
      address: "127.0.0.1",
      port: 8_000,
      catalog: startedCatalog,
    }),
    stop: async () => {
      throw new Error("stop must not run during bulk start");
    },
    refresh: async () => {
      throw new Error("raw-final-refresh-detail");
    },
  });

  assert.equal(result.succeeded, 1);
  assert.equal(result.failures.length, 0);
  assert.equal(result.catalog.inventoryRevision, "revision-2");
  assert.equal(result.refreshIssue?.kind, "failed");
  assert.equal("message" in result.refreshIssue!, false);
});

test("bulk presentation localizes with the locale selected after an async action starts", async () => {
  const rule = bulkRule("rule-1", "Rule one");
  const initial = bulkCatalog("revision-1", [rule], []);
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  let currentTranslator = createTranslator("en-US");

  const pending = runPortForwardBulkAction("start", initial, {
    start: async () => {
      await gate;
      throw new Error("PORT_FORWARD_CONNECTION_FAILED: backend detail");
    },
    stop: async () => {
      throw new Error("stop must not run during bulk start");
    },
    refresh: async () => initial,
  });

  currentTranslator = createTranslator("zh-CN");
  release();
  const result = await pending;
  const presentation = createPortForwardBulkPresentation(result, currentTranslator);
  const english = createPortForwardBulkPresentation(result, createTranslator("en-US"));

  assert.equal(presentation.error, currentTranslator("portForward.bulkStartFailed", { failed: 1 }));
  assert.notEqual(presentation.error, english.error);
  assert.notEqual(presentation.failureItems[0]?.text, english.failureItems[0]?.text);
  assert.equal("message" in result.failures[0]!.issue, false);
  assert.equal(JSON.stringify(result).includes("backend detail"), false);
});

test("backend client uses all six exact Rust port forwarding commands", async () => {
  const source = await readFile(backendSourceUrl, "utf8");
  assert.match(source, /invoke<PortForwardCatalog>\("list_port_forward_rules"\)/);
  for (const command of [
    "create_port_forward_rule",
    "update_port_forward_rule",
    "delete_port_forward_rule",
    "stop_port_forward",
  ]) {
    assert.match(source, new RegExp(`invoke<PortForwardCatalog>\\("${command}", \\{ request \\}\\)`));
  }
  assert.match(source, /invoke<StartPortForwardResult>\("start_port_forward", \{ request \}\)/);
});

test("durable rules exclude runtime status and errors while requests stay camelCase", async () => {
  const source = await readFile(backendSourceUrl, "utf8");
  const durableRule = source.slice(
    source.indexOf("export type PortForwardRule ="),
    source.indexOf("export type PortForwardRuntime ="),
  );
  assert.match(durableRule, /localPort: number/);
  assert.match(durableRule, /bindAddress: string/);
  assert.match(durableRule, /remoteHost\?: string/);
  assert.match(durableRule, /hostId: string/);
  assert.match(durableRule, /autoStart: boolean/);
  assert.doesNotMatch(durableRule, /\bstatus\??\s*:/);
  assert.doesNotMatch(durableRule, /\berror\??\s*:/);

  const runtime = source.slice(
    source.indexOf("export type PortForwardRuntime ="),
    source.indexOf("export type PortForwardCatalog ="),
  );
  assert.match(runtime, /phase: "connecting" \| "active" \| "error"/);
  assert.match(runtime, /error\?: string/);

  const requests = source.slice(
    source.indexOf("export type PortForwardRuleMetadata ="),
    source.indexOf("export type GroupConfigOverride"),
  );
  assert.match(requests, /expectedInventoryRevision: unknown/);
  assert.match(requests, /credentialReference\?: string/);
  assert.match(requests, /selectedIdentityFilePaths\?: string\[\]/);
  assert.doesNotMatch(requests, /expected_inventory_revision|local_port|bind_address|host_id/);
});

test("management page exposes CRUD, host selection, and all runtime states", async () => {
  const source = await readFile(componentSourceUrl, "utf8");
  for (const call of [
    "listPortForwardRules",
    "createPortForwardRule",
    "updatePortForwardRule",
    "deletePortForwardRule",
    "startPortForward",
    "stopPortForward",
  ]) {
    assert.match(source, new RegExp(`\\b${call}\\b`));
  }
  assert.match(source, /hosts\.map\(\(host\) => <option/);
  assert.match(source, /t\("portForward\.type\.local"\)[\s\S]*t\("portForward\.type\.remote"\)[\s\S]*t\("portForward\.type\.dynamic"\)/);
  assert.match(source, /"connecting"[\s\S]*"active"[\s\S]*"error"/);
  assert.match(source, /t\("portForward\.start"\)/);
  assert.match(source, /t\("portForward\.stop"\)/);
  assert.match(source, /t\("portForward\.edit"\)/);
  assert.match(source, /t\("portForward\.delete"\)/);
  assert.match(source, /t\("portForward\.empty"\)/);
  assert.match(source, /nativeRuntimeAvailable/);
});

test("bulk controls use synchronous ownership guards and render per-rule failures", async () => {
  const source = await readFile(componentSourceUrl, "utf8");
  const backend = await readFile(backendSourceUrl, "utf8");

  assert.match(source, /bulkActionLock\.current = true[\s\S]*runPortForwardBulkAction\(/);
  assert.match(source, /runtimeActionLocks\.current\.size > 0/);
  const runtimeHandlers = source.slice(
    source.indexOf("const beginRule"),
    source.indexOf("const confirmDelete"),
  );
  assert.equal(
    runtimeHandlers.match(/mutationLock\.current/g)?.length,
    2,
    "both single-rule runtime handlers synchronously reject an active CRUD mutation",
  );
  assert.equal(
    runtimeHandlers.match(/runtimeActionLocks\.current\.size > 0/g)?.length,
    2,
    "different rule IDs must share one catalog-revision runtime mutation lock",
  );
  assert.doesNotMatch(runtimeHandlers, /runtimeActionLocks\.current\.has\(rule\.id\)/);
  assert.match(
    source,
    /const actionsDisabled = [\s\S]*pendingRuleIds\.size > 0/,
    "a pending single-rule mutation disables every other rule action",
  );
  assert.match(source, /selectPortForwardBulkTargetIds\(snapshot, action\)/);
  assert.match(source, /t\("portForward\.startAll"\)/);
  assert.match(source, /t\("portForward\.stopAll"\)/);
  assert.match(source, /createPortForwardBulkPresentation\(bulkReport, t\)/);
  assert.match(source, /bulkPresentation\.failureItems\.map/);
  assert.doesNotMatch(source, /failure\.issue\.message/);
  assert.doesNotMatch(backend, /start_all_port_forwards|stop_all_port_forwards/);
});

test("bulk forwarding copy is complete in English and Simplified Chinese", () => {
  const keys = [
    "portForward.startAll",
    "portForward.stopAll",
    "portForward.startingAll",
    "portForward.stoppingAll",
    "portForward.bulkStarted",
    "portForward.bulkStopped",
    "portForward.bulkStartPartial",
    "portForward.bulkStopPartial",
    "portForward.bulkStartFailed",
    "portForward.bulkStopFailed",
    "portForward.bulkNoChanges",
    "portForward.bulkRefreshFailed",
    "portForward.bulkFailureItem",
  ] as const satisfies readonly MessageKey[];
  const en = createTranslator("en-US");
  const zh = createTranslator("zh-CN");

  for (const key of keys) {
    assert.notEqual(en(key), key);
    assert.notEqual(zh(key), key);
    assert.notEqual(en(key), zh(key));
  }
});

test("port forwarding editor stays theme-aware and leaves room for host addresses", async () => {
  const styles = await readFile(stylesSourceUrl, "utf8");
  const editorStyles = styles.slice(
    styles.indexOf(".port-forward-details-panel"),
    styles.indexOf("/* Legacy-compatible Group Defaults manager"),
  );

  assert.match(
    editorStyles,
    /\.port-forward-details-panel \.field-row\s*\{[\s\S]*?grid-template-columns:\s*minmax\(15ch, 1fr\) minmax\(8ch, 0\.45fr\)/,
  );
  assert.match(editorStyles, /\.port-forward-traffic\s*\{[\s\S]*?background:\s*var\(--ld-surface-muted\)/);
  assert.match(editorStyles, /\.port-forward-type-picker button\s*\{[\s\S]*?background:\s*var\(--ld-surface-raised\)/);
  assert.match(editorStyles, /\.port-forward-type-picker button\.active\s*\{[\s\S]*?background:\s*var\(--ld-accent-soft\)/);
});
