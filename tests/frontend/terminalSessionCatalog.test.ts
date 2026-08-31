import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import type {
  SshSessionCallbacks,
  StartLocalPtySessionRequest,
  TerminalSize,
} from "../../src/backend.ts";
import {
  LocalTerminalSessionController,
  type LocalTerminalBackend,
  type LocalTerminalXterm,
} from "../../src/localTerminalSessionController.ts";
import { createTerminalSessionCatalog } from "../../src/terminalSessionCatalog.ts";
import {
  MAX_WORKSPACE_SESSIONS,
  workspaceSessionIdFrom,
  type WorkspaceSessionId,
} from "../../src/terminalSessionRegistry.ts";
import type { Translate } from "../../src/i18n.ts";

const translate: Translate = (key, variables) => (
  `${key}${variables ? `:${JSON.stringify(variables)}` : ""}`
);

class FakeTerminal implements LocalTerminalXterm {
  readonly cols = 80;
  readonly rows = 24;

  write(): void {}
  writeln(): void {}
  clear(): void {}
  focus(): void {}
  dispose(): void {}

  onData() {
    return { dispose() {} };
  }
}

type StartCall = Readonly<{
  sessionId: string;
  callbacks: SshSessionCallbacks;
}>;

class FakeBackend implements LocalTerminalBackend {
  readonly calls: StartCall[] = [];
  readonly prefix: string;

  constructor(prefix: string) {
    this.prefix = prefix;
  }

  start = async (
    _request: StartLocalPtySessionRequest,
    callbacks: SshSessionCallbacks,
  ) => {
    const sessionId = `${this.prefix}-${this.calls.length + 1}`;
    this.calls.push({ sessionId, callbacks });
    return { sessionId, dispose() {} };
  };

  sendInput = async (_sessionId: string, _data: Uint8Array) => {};
  resize = async (_sessionId: string, _size: TerminalSize) => {};
  close = async (_sessionId: string) => {};
  cancel = async (_sessionId: string) => {};
}

const fixedId = (sequence: number): WorkspaceSessionId => workspaceSessionIdFrom(
  `ws-00000000-0000-4000-8000-${String(sequence).padStart(12, "0")}`,
);

const target = (sequence: number) => ({
  shell: {
    id: `shell-${sequence}`,
    name: `Local ${sequence}`,
    command: `local-${sequence}.exe`,
    args: [],
    icon: "terminal",
    isDefault: false,
  },
});

const createController = (
  catalog: ReturnType<typeof createTerminalSessionCatalog>,
  prefix: string,
  firstId: number,
  observed: WorkspaceSessionId[][],
) => {
  const backend = new FakeBackend(prefix);
  let nextId = firstId - 1;
  const controller = new LocalTerminalSessionController<FakeTerminal>({
    catalog,
    backend,
    translate,
    createId: () => fixedId(++nextId),
    createXterm: () => ({
      terminal: new FakeTerminal(),
      fit: { fit: () => true },
    }),
    createResizeCoordinator: () => ({
      request() {},
      reset() {},
      dispose() {},
    }),
    scheduler: {
      request: () => 1,
      cancel() {},
    },
    onRegistryChange: (snapshot) => observed.push([...snapshot.order]),
  });
  return { backend, controller };
};

const openReady = async (
  controller: LocalTerminalSessionController<FakeTerminal>,
  sequence: number,
): Promise<WorkspaceSessionId> => {
  const opening = controller.open(target(sequence));
  const id = controller.registry.activeSessionId!;
  controller.markViewportReady(id);
  const result = await opening;
  assert.equal(result.id, id);
  assert.equal(result.error, null);
  return id;
};

test("Local React sessions create the catalog interface by default and inject one stable authority", async () => {
  const source = await readFile(
    new URL("../../src/LocalTerminalSessions.tsx", import.meta.url),
    "utf8",
  );

  assert.match(source, /sharedCatalog: TerminalSessionCatalog \| undefined/);
  assert.match(source, /catalogRef\.current = sharedCatalog \?\? createTerminalSessionCatalog\(\)/);
  assert.match(source, /\(\) => catalog\.snapshot/);
  assert.match(source, /new LocalTerminalSessionController<Terminal>\(\{[\s\S]*?catalog,/);
  assert.doesNotMatch(source, /createTerminalSessionRegistrySnapshot/);
});

test("shared catalog keeps cross-controller order, active ownership, and one global 64-session limit", async () => {
  const catalog = createTerminalSessionCatalog();
  const observedA: WorkspaceSessionId[][] = [];
  const observedB: WorkspaceSessionId[][] = [];
  const a = createController(catalog, "native-a", 1, observedA);
  const b = createController(catalog, "native-b", 33, observedB);
  const aIds: WorkspaceSessionId[] = [];
  const bIds: WorkspaceSessionId[] = [];

  for (let sequence = 1; sequence <= 32; sequence += 1) {
    aIds.push(await openReady(a.controller, sequence));
  }
  for (let sequence = 33; sequence <= MAX_WORKSPACE_SESSIONS; sequence += 1) {
    bIds.push(await openReady(b.controller, sequence));
  }

  assert.deepEqual(catalog.snapshot.order, [...aIds, ...bIds]);
  assert.equal(catalog.snapshot.order.length, MAX_WORKSPACE_SESSIONS);
  assert.equal(a.controller.registry, catalog.snapshot);
  assert.equal(b.controller.registry, catalog.snapshot);
  assert.deepEqual(observedA.at(-1), catalog.snapshot.order);
  assert.deepEqual(observedB.at(-1), catalog.snapshot.order);

  await assert.rejects(
    b.controller.open(target(MAX_WORKSPACE_SESSIONS + 1)),
    /WORKSPACE_SESSION_LIMIT_REACHED/,
  );
  assert.deepEqual(catalog.snapshot.order, [...aIds, ...bIds]);
  assert.equal(b.controller.getRuntime(fixedId(65)), undefined);

  const lastA = aIds.at(-1)!;
  const firstB = bIds[0]!;
  a.controller.activate(lastA);
  assert.equal(catalog.snapshot.activeSessionId, lastA);
  assert.equal(a.controller.activeSession?.id, lastA);
  assert.equal(b.controller.activeSession, null);

  await a.controller.close(lastA);
  a.backend.calls.at(-1)!.callbacks.onControl({ type: "closed" });
  assert.equal(catalog.snapshot.activeSessionId, firstB);
  assert.equal(a.controller.activeSession, null);
  assert.equal(b.controller.activeSession?.id, firstB);
  assert.equal(catalog.snapshot.order.length, MAX_WORKSPACE_SESSIONS - 1);
  assert.ok(!catalog.snapshot.order.includes(lastA));

  a.controller.dispose();
  assert.deepEqual(catalog.snapshot.order, bIds);
  assert.equal(b.controller.hasSessions(), true);
  assert.equal(b.controller.activeSession?.id, firstB);

  b.controller.dispose();
  assert.deepEqual(catalog.snapshot.order, []);
  assert.equal(catalog.snapshot.activeSessionId, null);
});
