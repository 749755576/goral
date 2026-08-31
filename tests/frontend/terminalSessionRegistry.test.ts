import assert from "node:assert/strict";
import test from "node:test";

import {
  activateTerminalSessionSnapshot,
  addTerminalSessionSnapshot,
  createTerminalSessionRegistrySnapshot,
  createWorkspaceSessionId,
  getTerminalSessionSnapshot,
  removeTerminalSessionSnapshot,
  TerminalSessionRuntimeRegistry,
  updateTerminalSessionSnapshot,
  workspaceSessionIdFrom,
  type TerminalSessionProtocol,
  type WorkspaceSessionId,
} from "../../src/terminalSessionRegistry.ts";

const uuid = (suffix: string): string => `00000000-0000-4000-8000-${suffix.padStart(12, "0")}`;
const id = (suffix: string): WorkspaceSessionId => workspaceSessionIdFrom(`ws-${uuid(suffix)}`);

const add = (
  registry: ReturnType<typeof createTerminalSessionRegistrySnapshot>,
  sessionId: WorkspaceSessionId,
  title: string,
  protocol: TerminalSessionProtocol = "ssh",
  options?: Readonly<{ activate?: boolean; limit?: number }>,
) => addTerminalSessionSnapshot(registry, {
  id: sessionId,
  protocol,
  title,
  state: "connecting",
}, options);

test("workspace IDs are stable, branded, and strictly validated", () => {
  const generated = createWorkspaceSessionId(() => uuid("1"));
  assert.equal(generated, `ws-${uuid("1")}`);
  assert.equal(createWorkspaceSessionId(() => uuid("1")), generated);
  assert.throws(() => workspaceSessionIdFrom("session-a"), /WORKSPACE_SESSION_ID_INVALID/);
  const alphabeticUuid = uuid("abcdefabcdef");
  assert.throws(
    () => workspaceSessionIdFrom(`ws-${alphabeticUuid.toUpperCase()}`),
    /WORKSPACE_SESSION_ID_INVALID/,
  );
});

test("adding B preserves A and produces an immutable render snapshot", () => {
  const a = id("1");
  const b = id("2");
  let registry = add(createTerminalSessionRegistrySnapshot(), a, "alpha");
  registry = add(registry, b, "beta", "telnet");

  assert.deepEqual(registry.order, [a, b]);
  assert.equal(registry.activeSessionId, b);
  assert.deepEqual(getTerminalSessionSnapshot(registry, a), {
    id: a,
    protocol: "ssh",
    title: "alpha",
    state: "connecting",
    error: null,
  });
  assert.equal(getTerminalSessionSnapshot(registry, b)?.protocol, "telnet");
  assert.ok(Object.isFrozen(registry));
  assert.ok(Object.isFrozen(registry.order));
  assert.ok(Object.isFrozen(registry.sessions));
  assert.ok(Object.isFrozen(getTerminalSessionSnapshot(registry, a)!));
});

test("out-of-order callbacks update only their exact workspace ID", () => {
  const a = id("1");
  const b = id("2");
  let registry = add(createTerminalSessionRegistrySnapshot(), a, "alpha");
  registry = add(registry, b, "beta");
  registry = updateTerminalSessionSnapshot(registry, b, { state: "connected" });
  registry = updateTerminalSessionSnapshot(registry, a, {
    state: "disconnected",
    error: "alpha failed late",
  });

  assert.equal(getTerminalSessionSnapshot(registry, a)?.state, "disconnected");
  assert.equal(getTerminalSessionSnapshot(registry, a)?.error, "alpha failed late");
  assert.equal(getTerminalSessionSnapshot(registry, b)?.state, "connected");
  assert.equal(getTerminalSessionSnapshot(registry, b)?.error, null);

  const retired = id("99");
  assert.equal(updateTerminalSessionSnapshot(registry, retired, { state: "connected" }), registry);
});

test("activating a tab changes presentation only and never closes runtimes", () => {
  const a = id("1");
  const b = id("2");
  let registry = add(createTerminalSessionRegistrySnapshot(), a, "alpha");
  registry = add(registry, b, "beta");
  let closeCount = 0;
  const runtimes = new TerminalSessionRuntimeRegistry<{ close(): void }>();
  runtimes.bindExact(a, { close: () => { closeCount += 1; } });
  runtimes.bindExact(b, { close: () => { closeCount += 1; } });

  registry = activateTerminalSessionSnapshot(registry, a);
  assert.equal(registry.activeSessionId, a);
  assert.equal(closeCount, 0);
  assert.equal(runtimes.size, 2);
});

test("removing a background tab deletes only its exact snapshot and runtime", () => {
  const a = id("1");
  const b = id("2");
  let registry = add(createTerminalSessionRegistrySnapshot(), a, "alpha");
  registry = add(registry, b, "beta");
  const runtimeA = { name: "runtime-a" };
  const runtimeB = { name: "runtime-b" };
  const runtimes = new TerminalSessionRuntimeRegistry<typeof runtimeA>();
  runtimes.bindExact(a, runtimeA);
  runtimes.bindExact(b, runtimeB);

  registry = removeTerminalSessionSnapshot(registry, a);
  assert.deepEqual(registry.order, [b]);
  assert.equal(registry.activeSessionId, b);
  assert.equal(runtimes.deleteExact(a), runtimeA);
  assert.equal(runtimes.getExact(b), runtimeB);
  assert.equal(runtimes.size, 1);
});

test("active removal prefers the original right neighbour, then left, then Vault", () => {
  const a = id("1");
  const b = id("2");
  const c = id("3");
  let registry = add(createTerminalSessionRegistrySnapshot(), a, "alpha");
  registry = add(registry, b, "beta");
  registry = add(registry, c, "gamma");

  registry = activateTerminalSessionSnapshot(registry, b);
  registry = removeTerminalSessionSnapshot(registry, b);
  assert.deepEqual(registry.order, [a, c]);
  assert.equal(registry.activeSessionId, c);

  registry = removeTerminalSessionSnapshot(registry, c);
  assert.deepEqual(registry.order, [a]);
  assert.equal(registry.activeSessionId, a);

  registry = removeTerminalSessionSnapshot(registry, a);
  assert.deepEqual(registry.order, []);
  assert.equal(registry.activeSessionId, null);
});

test("exact native-session bindings support retry and reject cross-session reuse", () => {
  const a = id("1");
  const b = id("2");
  const runtimeA = { name: "runtime-a", secret: "never-render-this" };
  const runtimeB = { name: "runtime-b", handle: { dispose() {} } };
  const runtimes = new TerminalSessionRuntimeRegistry<typeof runtimeA | typeof runtimeB>();
  runtimes.bindExact(a, runtimeA);
  runtimes.bindExact(b, runtimeB);
  runtimes.bindBackendSessionId(a, "backend-a-1");
  runtimes.bindBackendSessionId(b, "backend-b-1");

  assert.equal(runtimes.getByBackendSessionId("backend-a-1"), runtimeA);
  assert.equal(runtimes.workspaceSessionIdForBackend("backend-b-1"), b);
  assert.throws(
    () => runtimes.bindBackendSessionId(b, "backend-a-1"),
    /BACKEND_SESSION_ID_DUPLICATE/,
  );

  runtimes.bindBackendSessionId(a, "backend-a-2");
  assert.equal(runtimes.getByBackendSessionId("backend-a-1"), undefined);
  assert.equal(runtimes.getByBackendSessionId("backend-a-2"), runtimeA);
  assert.equal(runtimes.unbindBackendSessionId(a, "stale-backend-a"), false);
  assert.equal(runtimes.getByBackendSessionId("backend-a-2"), runtimeA);
  assert.equal(runtimes.unbindBackendSessionId(a, "backend-a-2"), true);
  assert.equal(runtimes.getByBackendSessionId("backend-a-2"), undefined);
  runtimes.bindBackendSessionId(a, "backend-a-3");
  assert.equal(runtimes.deleteByBackendSessionId("backend-b-1"), runtimeB);
  assert.equal(runtimes.getExact(a), runtimeA);
  assert.equal(runtimes.getExact(b), undefined);

  const snapshot = add(createTerminalSessionRegistrySnapshot(), a, "alpha");
  const serialized = JSON.stringify(snapshot);
  assert.doesNotMatch(serialized, /never-render-this|dispose|backend-a-3|handle|secret/);
});

test("duplicate, invalid, and over-limit state/runtime entries fail closed", () => {
  const a = id("1");
  const b = id("2");
  let registry = add(createTerminalSessionRegistrySnapshot(), a, "alpha", "ssh", { limit: 1 });
  assert.throws(() => add(registry, a, "duplicate", "ssh", { limit: 1 }), /WORKSPACE_SESSION_DUPLICATE/);
  assert.throws(() => add(registry, b, "overflow", "ssh", { limit: 1 }), /WORKSPACE_SESSION_LIMIT_REACHED/);
  assert.throws(
    () => activateTerminalSessionSnapshot(registry, b),
    /WORKSPACE_SESSION_NOT_FOUND/,
  );

  const forged = "ws-not-a-uuid" as WorkspaceSessionId;
  assert.throws(() => updateTerminalSessionSnapshot(registry, forged, { state: "connected" }), /WORKSPACE_SESSION_ID_INVALID/);

  const runtimes = new TerminalSessionRuntimeRegistry<object>(1);
  runtimes.bindExact(a, {});
  assert.throws(() => runtimes.bindExact(a, {}), /WORKSPACE_SESSION_RUNTIME_DUPLICATE/);
  assert.throws(() => runtimes.bindExact(b, {}), /WORKSPACE_SESSION_LIMIT_REACHED/);
  assert.throws(() => runtimes.bindBackendSessionId(a, " bad "), /BACKEND_SESSION_ID_INVALID/);
});
