import assert from "node:assert/strict";
import test from "node:test";

import type {
  SshSessionCallbacks,
  TerminalSize,
} from "../../src/backend.ts";
import {
  sshClientAttemptIdFrom,
  SshTerminalSessionController,
  type SshClientAttemptId,
  type SshTerminalAttempt,
  type SshTerminalBackend,
  type SshTerminalFrameScheduler,
  type SshTerminalResizeCoordinator,
  type SshTerminalStart,
  type SshTerminalTarget,
  type SshTerminalXterm,
} from "../../src/sshTerminalSessionController.ts";
import { createTerminalSessionCatalog } from "../../src/terminalSessionCatalog.ts";
import {
  getTerminalSessionSnapshot,
  workspaceSessionIdFrom,
  type WorkspaceSessionId,
} from "../../src/terminalSessionRegistry.ts";
import type { Translate } from "../../src/i18n.ts";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const translate: Translate = (key, variables) => (
  `${key}${variables ? `:${JSON.stringify(variables)}` : ""}`
);

const deferred = <Value>() => {
  let resolve!: (value: Value) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<Value>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
};

const flushMicrotasks = async () => {
  await Promise.resolve();
  await Promise.resolve();
};

const frame = (value: string): Uint8Array => {
  const body = encoder.encode(value);
  const output = new Uint8Array(body.length + 1);
  output[0] = 0;
  output.set(body, 1);
  return output;
};

const target = (name: string): SshTerminalTarget => ({
  kind: "quick",
  title: name,
  hostname: `${name.toLowerCase()}.example.test`,
  port: 22,
  username: "tester",
});

class FakeTerminal implements SshTerminalXterm {
  readonly cols = 100;
  readonly rows = 30;
  readonly byteWrites: Uint8Array[] = [];
  readonly lines: string[] = [];
  readonly inputListeners = new Set<(data: string) => void>();
  clearCount = 0;
  focusCount = 0;
  disposeCount = 0;
  constructionFailure: "input" | null = null;
  selectedText = "";
  contextLines: string[] = [];

  getSelection(): string {
    return this.selectedText;
  }

  get buffer() {
    const lines = this.contextLines;
    return {
      active: {
        baseY: Math.max(0, lines.length - 1),
        cursorY: 0,
        length: lines.length,
        getLine: (index: number) => lines[index] === undefined
          ? undefined
          : { translateToString: () => lines[index]! },
      },
    };
  }

  write(data: string | Uint8Array): void {
    this.byteWrites.push(typeof data === "string" ? encoder.encode(data) : data.slice());
  }

  writeln(data: string): void {
    this.lines.push(data);
  }

  clear(): void {
    this.clearCount += 1;
  }

  focus(): void {
    this.focusCount += 1;
  }

  onData(listener: (data: string) => void) {
    this.inputListeners.add(listener);
    if (this.constructionFailure === "input") {
      throw new Error("SSH_TEST_INPUT_LISTENER_FAILED");
    }
    return { dispose: () => this.inputListeners.delete(listener) };
  }

  emitInput(data: string): void {
    for (const listener of this.inputListeners) listener(data);
  }

  dataText(): string {
    return this.byteWrites.map((value) => decoder.decode(value)).join("");
  }

  dispose(): void {
    this.disposeCount += 1;
    this.inputListeners.clear();
  }
}

type FakeHandle = {
  sessionId: string;
  dispose: () => void;
};

type StartCall = {
  callbacks: SshSessionCallbacks;
  initialSize: TerminalSize;
  clientAttemptId: SshClientAttemptId;
  pending: ReturnType<typeof deferred<FakeHandle>>;
  handleDisposeCount: number;
};

class FakeStarts {
  readonly calls: StartCall[] = [];

  create(): SshTerminalStart {
    return (callbacks, initialSize, clientAttemptId) => {
      const call: StartCall = {
        callbacks,
        initialSize: { ...initialSize },
        clientAttemptId,
        pending: deferred<FakeHandle>(),
        handleDisposeCount: 0,
      };
      this.calls.push(call);
      return call.pending.promise;
    };
  }

  resolve(index: number, sessionId: string): StartCall {
    const call = this.calls[index]!;
    call.pending.resolve({
      sessionId,
      dispose: () => {
        call.handleDisposeCount += 1;
      },
    });
    return call;
  }
}

class FakeBackend implements SshTerminalBackend {
  readonly inputCalls: Array<{ sessionId: string; text: string }> = [];
  readonly resizeCalls: Array<{ sessionId: string; size: TerminalSize }> = [];
  readonly closeCalls: string[] = [];
  readonly cancelCalls: string[] = [];
  closeFailure: Error | null = null;
  cancelFailure: Error | null = null;
  inputFailure: Error | null = null;

  sendInput = async (sessionId: string, data: Uint8Array) => {
    this.inputCalls.push({ sessionId, text: decoder.decode(data) });
    if (this.inputFailure) throw this.inputFailure;
  };

  resize = async (sessionId: string, size: TerminalSize) => {
    this.resizeCalls.push({ sessionId, size: { ...size } });
  };

  close = async (sessionId: string) => {
    this.closeCalls.push(sessionId);
    if (this.closeFailure) throw this.closeFailure;
  };

  cancel = async (sessionId: string) => {
    this.cancelCalls.push(sessionId);
    if (this.cancelFailure) throw this.cancelFailure;
  };
}

class FakeResizeCoordinator implements SshTerminalResizeCoordinator {
  readonly requests: Array<{ sessionId: string; size: TerminalSize }> = [];
  readonly transport: (sessionId: string, size: TerminalSize) => Promise<void>;
  resetCount = 0;
  disposeCount = 0;

  constructor(transport: (sessionId: string, size: TerminalSize) => Promise<void>) {
    this.transport = transport;
  }

  request(sessionId: string, size: TerminalSize): void {
    this.requests.push({ sessionId, size: { ...size } });
    void this.transport(sessionId, size);
  }

  reset(): void {
    this.resetCount += 1;
  }

  dispose(): void {
    this.disposeCount += 1;
  }
}

const createScheduler = () => {
  let nextId = 0;
  const callbacks = new Map<number, () => void>();
  const scheduler: SshTerminalFrameScheduler = {
    request(callback) {
      const id = ++nextId;
      callbacks.set(id, callback);
      return id;
    },
    cancel(frameId) {
      callbacks.delete(frameId);
    },
  };
  return {
    scheduler,
    flush() {
      const queued = [...callbacks.values()];
      callbacks.clear();
      for (const callback of queued) callback();
    },
  };
};

const fixedId = (sequence: number): WorkspaceSessionId => workspaceSessionIdFrom(
  `ws-10000000-0000-4000-8000-${String(sequence).padStart(12, "0")}`,
);

const fixedAttemptId = (sequence: number): SshClientAttemptId => sshClientAttemptIdFrom(
  `attempt-30000000-0000-4000-8000-${String(sequence).padStart(12, "0")}`,
);

const createHarness = (options: Readonly<{
  limit?: number;
  constructionFailure?: "resize" | "input";
}> = {}) => {
  const backend = new FakeBackend();
  const starts = new FakeStarts();
  const frames = createScheduler();
  const catalog = createTerminalSessionCatalog({ limit: options.limit });
  const terminals = new Map<WorkspaceSessionId, FakeTerminal>();
  const resizers = new Map<WorkspaceSessionId, FakeResizeCoordinator>();
  const destroyed: WorkspaceSessionId[] = [];
  let nextId = 0;
  let nextAttemptId = 0;
  let attemptClock = 0;
  const controller = new SshTerminalSessionController<FakeTerminal>({
    catalog,
    backend,
    translate,
    createId: () => fixedId(++nextId),
    createXterm(id) {
      const terminal = new FakeTerminal();
      terminal.constructionFailure = options.constructionFailure === "input" ? "input" : null;
      terminals.set(id, terminal);
      return { terminal, fit: { fit: () => true } };
    },
    createResizeCoordinator(transport, id) {
      if (options.constructionFailure === "resize") {
        throw new Error("SSH_TEST_RESIZE_COORDINATOR_FAILED");
      }
      const coordinator = new FakeResizeCoordinator(transport);
      resizers.set(id, coordinator);
      return coordinator;
    },
    scheduler: frames.scheduler,
    now: () => attemptClock,
    onRuntimeDestroyed(runtime) {
      destroyed.push(runtime.id);
    },
  });
  return {
    backend,
    catalog,
    controller,
    destroyed,
    frames,
    resizers,
    starts,
    terminals,
    advanceAttemptClock(milliseconds: number): void {
      attemptClock += milliseconds;
    },
    createAttempt(): SshTerminalAttempt {
      return {
        clientAttemptId: fixedAttemptId(++nextAttemptId),
        start: starts.create(),
      };
    },
  };
};

const beginOpen = async (
  harness: ReturnType<typeof createHarness>,
  name: string,
  attempt: SshTerminalAttempt = harness.createAttempt(),
) => {
  const opening = harness.controller.open(target(name), attempt);
  const id = harness.catalog.snapshot.order.at(-1)!;
  harness.controller.markViewportReady(id);
  await flushMicrotasks();
  return { attempt, id, opening, start: harness.starts.calls.at(-1)! };
};

test("A/B SSH runtimes keep exact data, input, resize, close, and hidden scrollback ownership", async () => {
  const harness = createHarness();
  const a = await beginOpen(harness, "Alpha");
  harness.starts.resolve(0, "native-a");
  await a.opening;
  a.start.callbacks.onControl({ type: "connected" });

  const b = await beginOpen(harness, "Beta");
  harness.starts.resolve(1, "native-b");
  await b.opening;
  b.start.callbacks.onControl({ type: "connected" });
  assert.deepEqual(harness.catalog.snapshot.order, [a.id, b.id]);
  assert.equal(harness.catalog.snapshot.activeSessionId, b.id);

  a.start.callbacks.onData(frame("alpha-hidden\n"));
  b.start.callbacks.onData(frame("beta-visible\n"));
  const terminalA = harness.terminals.get(a.id)!;
  const terminalB = harness.terminals.get(b.id)!;
  assert.equal(terminalA.dataText(), "alpha-hidden\n");
  assert.equal(terminalB.dataText(), "beta-visible\n");

  terminalA.emitInput("a");
  terminalB.emitInput("b");
  await flushMicrotasks();
  assert.deepEqual(harness.backend.inputCalls, [
    { sessionId: "native-a", text: "a" },
    { sessionId: "native-b", text: "b" },
  ]);

  harness.controller.activate(a.id);
  harness.frames.flush();
  await flushMicrotasks();
  assert.equal(harness.catalog.snapshot.activeSessionId, a.id);
  assert.deepEqual(harness.backend.closeCalls, []);
  assert.deepEqual(harness.backend.cancelCalls, []);
  assert.equal(terminalA.focusCount, 1);
  assert.ok(harness.backend.resizeCalls.some((call) => call.sessionId === "native-a"));

  await harness.controller.close(b.id);
  assert.deepEqual(harness.backend.closeCalls, ["native-b"]);
  b.start.callbacks.onControl({ type: "closed" });
  assert.deepEqual(harness.catalog.snapshot.order, [a.id]);
  assert.equal(harness.catalog.snapshot.activeSessionId, a.id);
  assert.equal(terminalA.disposeCount, 0);
  assert.equal(terminalB.disposeCount, 1);
});

test("SSH terminal splits short plain input but keeps ANSI sequences atomic", async () => {
  const harness = createHarness();
  const session = await beginOpen(harness, "WireInput");
  harness.starts.resolve(0, "native-wire-input");
  await session.opening;
  session.start.callbacks.onControl({ type: "connected" });
  const terminal = harness.terminals.get(session.id)!;

  terminal.emitInput("中国");
  for (let index = 0; index < 8; index += 1) await Promise.resolve();
  assert.deepEqual(harness.backend.inputCalls, [
    { sessionId: "native-wire-input", text: "中" },
    { sessionId: "native-wire-input", text: "国" },
  ]);

  terminal.emitInput("\x1b[A");
  for (let index = 0; index < 4; index += 1) await Promise.resolve();
  assert.deepEqual(harness.backend.inputCalls.at(-1), {
    sessionId: "native-wire-input",
    text: "\x1b[A",
  });
});

test("SSH programmatic text shares the user-input queue without interleaving", async () => {
  const harness = createHarness();
  const session = await beginOpen(harness, "OrderedBridgeInput");
  harness.starts.resolve(0, "native-ordered-bridge");
  await session.opening;
  session.start.callbacks.onControl({ type: "connected" });

  const firstWriteGate = deferred<void>();
  harness.backend.sendInput = async (sessionId, data) => {
    const text = decoder.decode(data);
    harness.backend.inputCalls.push({ sessionId, text });
    if (text === "a") await firstWriteGate.promise;
  };
  const terminal = harness.terminals.get(session.id)!;
  terminal.emitInput("ab");
  await flushMicrotasks();
  const programmatic = harness.controller.sendText(session.id, "AI\r");
  terminal.emitInput("z");
  await flushMicrotasks();
  assert.deepEqual(harness.backend.inputCalls, [
    { sessionId: "native-ordered-bridge", text: "a" },
  ]);

  firstWriteGate.resolve();
  assert.equal(await programmatic, null);
  await flushMicrotasks();
  assert.deepEqual(harness.backend.inputCalls, [
    { sessionId: "native-ordered-bridge", text: "a" },
    { sessionId: "native-ordered-bridge", text: "b" },
    { sessionId: "native-ordered-bridge", text: "AI\r" },
    { sessionId: "native-ordered-bridge", text: "z" },
  ]);
});

test("SSH retry does not let a stalled retired write block or leak into the new session", async () => {
  const harness = createHarness();
  const first = await beginOpen(harness, "QueuedRetry");
  harness.starts.resolve(0, "native-queue-old");
  await first.opening;
  first.start.callbacks.onControl({ type: "connected" });

  const oldWriteGate = deferred<void>();
  harness.backend.sendInput = async (sessionId, data) => {
    const text = decoder.decode(data);
    harness.backend.inputCalls.push({ sessionId, text });
    if (sessionId === "native-queue-old" && text === "旧") {
      await oldWriteGate.promise;
    }
  };
  const terminal = harness.terminals.get(first.id)!;
  terminal.emitInput("旧队");
  await flushMicrotasks();
  assert.deepEqual(harness.backend.inputCalls, [
    { sessionId: "native-queue-old", text: "旧" },
  ]);

  const queuedProgrammatic = harness.controller.sendText(first.id, "must-not-cross-retry");
  await flushMicrotasks();

  first.start.callbacks.onControl({ type: "closed" });
  const retrying = harness.controller.retry(first.id, harness.createAttempt());
  await flushMicrotasks();
  const retryStart = harness.starts.calls[1]!;
  harness.starts.resolve(1, "native-queue-new");
  assert.equal(await retrying, null);
  retryStart.callbacks.onControl({ type: "connected" });
  terminal.emitInput("新");
  await flushMicrotasks();
  assert.deepEqual(harness.backend.inputCalls, [
    { sessionId: "native-queue-old", text: "旧" },
    { sessionId: "native-queue-new", text: "新" },
  ]);

  oldWriteGate.resolve();
  assert.equal(await queuedProgrammatic, "TERMINAL_SEND_SESSION_CLOSING");
  for (let index = 0; index < 4; index += 1) await Promise.resolve();
  assert.equal(
    harness.backend.inputCalls.some((call) => call.text === "must-not-cross-retry"),
    false,
  );
  assert.equal(
    harness.backend.inputCalls.some((call) => call.text === "队"),
    false,
  );
});

test("SSH terminal bridge reads and sends only the requested connected runtime", async () => {
  const harness = createHarness();
  const a = await beginOpen(harness, "BridgeA");
  harness.starts.resolve(0, "native-bridge-a");
  await a.opening;
  a.start.callbacks.onControl({ type: "connected" });
  const b = await beginOpen(harness, "BridgeB");
  harness.starts.resolve(1, "native-bridge-b");
  await b.opening;
  b.start.callbacks.onControl({ type: "connected" });

  const terminalA = harness.terminals.get(a.id)!;
  const terminalB = harness.terminals.get(b.id)!;
  terminalA.selectedText = "alpha selection";
  terminalA.contextLines = ["alpha old", "alpha recent"];
  terminalB.selectedText = "beta selection";
  terminalB.contextLines = ["beta recent"];

  assert.equal(harness.controller.readSelectedText(a.id), "alpha selection");
  assert.equal(harness.controller.readRecentOutput(a.id), "alpha old\nalpha recent");
  assert.equal(harness.controller.readSelectedText(b.id), "beta selection");
  assert.equal(await harness.controller.sendText(a.id, "echo alpha"), null);
  assert.equal(await harness.controller.sendText(b.id, "echo beta\r"), null);
  assert.deepEqual(harness.backend.inputCalls, [
    { sessionId: "native-bridge-a", text: "echo alpha" },
    { sessionId: "native-bridge-b", text: "echo beta\r" },
  ]);

  assert.equal(
    await harness.controller.sendText(a.id, ""),
    "TERMINAL_SEND_TEXT_EMPTY",
  );
  assert.equal(
    await harness.controller.sendText(a.id, "bad\0text"),
    "TERMINAL_SEND_TEXT_CONTAINS_NUL",
  );
  assert.equal(harness.backend.inputCalls.length, 2);

  const stopping = harness.controller.disconnect(b.id);
  assert.equal(
    await harness.controller.sendText(b.id, "must-not-send"),
    "TERMINAL_SEND_SESSION_CLOSING",
  );
  await stopping;
  assert.equal(harness.backend.inputCalls.length, 2);

  harness.backend.inputFailure = new Error("backend secret must not escape");
  assert.equal(
    await harness.controller.sendText(a.id, "safe-text"),
    "TERMINAL_SEND_FAILED",
  );
  assert.equal(
    await harness.controller.sendText(fixedId(99), "safe-text"),
    "TERMINAL_SEND_SESSION_NOT_FOUND",
  );
});

test("pending SSH send remains bound to its old native generation during retry", async () => {
  const harness = createHarness();
  const first = await beginOpen(harness, "SendRace");
  harness.starts.resolve(0, "native-send-old");
  await first.opening;
  first.start.callbacks.onControl({ type: "connected" });
  const approvedGeneration = harness.controller.getRuntime(first.id)!.operationGeneration;

  const sendGate = deferred<void>();
  const immediateSend = harness.backend.sendInput;
  harness.backend.sendInput = async (sessionId, data) => {
    harness.backend.inputCalls.push({ sessionId, text: decoder.decode(data) });
    await sendGate.promise;
  };
  const pendingSend = harness.controller.sendText(first.id, "old-generation");
  await Promise.resolve();
  assert.deepEqual(harness.backend.inputCalls, [
    { sessionId: "native-send-old", text: "old-generation" },
  ]);

  first.start.callbacks.onControl({ type: "closed" });
  const retryAttempt = harness.createAttempt();
  const retrying = harness.controller.retry(first.id, retryAttempt);
  await flushMicrotasks();
  const retryStart = harness.starts.calls[1]!;
  harness.starts.resolve(1, "native-send-new");
  assert.equal(await retrying, null);
  retryStart.callbacks.onControl({ type: "connected" });

  sendGate.resolve();
  assert.equal(await pendingSend, null);
  harness.backend.sendInput = immediateSend;
  assert.equal(
    await harness.controller.sendText(first.id, "must-not-cross-retry", approvedGeneration),
    "TERMINAL_SEND_ROUTE_STALE",
  );
  assert.equal(await harness.controller.sendText(first.id, "new-generation"), null);
  assert.deepEqual(harness.backend.inputCalls, [
    { sessionId: "native-send-old", text: "old-generation" },
    { sessionId: "native-send-new", text: "new-generation" },
  ]);
});

test("new SSH tab ID is notified synchronously after connecting registration and before native start", async () => {
  const harness = createHarness();
  const attempt = harness.createAttempt();
  let notifiedId: WorkspaceSessionId | undefined;
  let openingSettled = false;

  const opening = harness.controller.open(target("Notify"), attempt, {
    onSessionCreated(id) {
      notifiedId = id;
      assert.equal(
        getTerminalSessionSnapshot(harness.catalog.snapshot, id)?.state,
        "connecting",
      );
      assert.equal(harness.starts.calls.length, 0);
      assert.equal(openingSettled, false);
    },
  });
  void opening.finally(() => {
    openingSettled = true;
  });

  assert.equal(notifiedId, fixedId(1));
  assert.equal(openingSettled, false);
  assert.equal(harness.starts.calls.length, 0);

  harness.controller.markViewportReady(notifiedId!);
  await flushMicrotasks();
  assert.equal(harness.starts.calls.length, 1);
  assert.equal(openingSettled, false);

  harness.starts.resolve(0, "native-notify");
  assert.deepEqual(await opening, { id: notifiedId, error: null });
});

test("new SSH tab observer failures do not change lifecycle or resource cleanup", async () => {
  const harness = createHarness();
  const opening = harness.controller.open(target("ObserverFailure"), harness.createAttempt(), {
    onSessionCreated() {
      throw new Error("RENDERER_OBSERVER_FAILED");
    },
  });
  const id = harness.catalog.snapshot.order.at(-1)!;

  assert.equal(getTerminalSessionSnapshot(harness.catalog.snapshot, id)?.state, "connecting");
  harness.controller.markViewportReady(id);
  await flushMicrotasks();
  harness.starts.resolve(0, "native-observer-failure");
  assert.deepEqual(await opening, { id, error: null });

  await harness.controller.close(id);
  harness.starts.calls[0]!.callbacks.onControl({ type: "closed" });
  assert.equal(harness.controller.owns(id), false);
  assert.equal(harness.terminals.get(id)?.disposeCount, 1);
  assert.equal(harness.starts.calls[0]!.handleDisposeCount, 1);
});

test("close while connecting cancels only the exact late SSH handle", async () => {
  const harness = createHarness();
  const a = await beginOpen(harness, "DeferredA");
  const b = await beginOpen(harness, "LiveB");
  harness.starts.resolve(1, "native-b");
  await b.opening;
  b.start.callbacks.onControl({ type: "connected" });

  await harness.controller.close(a.id);
  assert.equal(getTerminalSessionSnapshot(harness.catalog.snapshot, a.id)?.state, "closing");
  harness.starts.resolve(0, "native-a-late");
  await a.opening;
  assert.deepEqual(harness.backend.cancelCalls, ["native-a-late"]);
  assert.equal(harness.controller.backendSessionIdFor(b.id), "native-b");

  a.start.callbacks.onControl({ type: "closed" });
  assert.deepEqual(harness.catalog.snapshot.order, [b.id]);
  assert.equal(harness.catalog.snapshot.activeSessionId, b.id);
  assert.equal(getTerminalSessionSnapshot(harness.catalog.snapshot, b.id)?.state, "connected");
});

test("closed-before-handle and retry replace only that generation and require a new starter", async () => {
  const harness = createHarness();
  const firstAttempt = harness.createAttempt();
  const first = await beginOpen(harness, "Retryable", firstAttempt);
  assert.equal(
    harness.controller.workspaceSessionIdForAttempt(firstAttempt.clientAttemptId),
    first.id,
  );
  assert.equal(
    harness.controller.isExactAttemptRoute(firstAttempt.clientAttemptId, first.id),
    true,
  );
  first.start.callbacks.onControl({ type: "closed" });
  assert.equal(
    harness.controller.workspaceSessionIdForAttempt(firstAttempt.clientAttemptId),
    undefined,
  );
  const late = harness.starts.resolve(0, "native-closed-before-handle");
  await first.opening;
  assert.equal(late.handleDisposeCount, 1);
  assert.equal(harness.controller.backendSessionIdFor(first.id), undefined);
  assert.equal(
    getTerminalSessionSnapshot(harness.catalog.snapshot, first.id)?.state,
    "disconnected",
  );

  await assert.rejects(
    harness.controller.retry(first.id, firstAttempt),
    /SSH_CLIENT_ATTEMPT_ID_DUPLICATE/,
  );

  const retryAttempt = harness.createAttempt();
  const retrying = harness.controller.retry(first.id, retryAttempt);
  await flushMicrotasks();
  const second = harness.starts.calls[1]!;
  assert.equal(second.clientAttemptId, retryAttempt.clientAttemptId);
  assert.equal(
    harness.controller.workspaceSessionIdForAttempt(retryAttempt.clientAttemptId),
    first.id,
  );
  harness.starts.resolve(1, "native-new");
  assert.equal(await retrying, null);
  second.callbacks.onControl({ type: "connected" });
  assert.equal(
    harness.controller.workspaceSessionIdForAttempt(retryAttempt.clientAttemptId),
    undefined,
  );

  first.start.callbacks.onData(frame("stale-data"));
  first.start.callbacks.onControl({ type: "error", code: "STALE", message: "stale" });
  first.start.callbacks.onControl({ type: "closed" });
  second.callbacks.onData(frame("new-data"));
  assert.equal(harness.terminals.get(first.id)?.dataText(), "new-data");
  assert.equal(harness.controller.backendSessionIdFor(first.id), "native-new");
  assert.equal(getTerminalSessionSnapshot(harness.catalog.snapshot, first.id)?.state, "connected");
  assert.equal(harness.terminals.get(first.id)?.clearCount, 1);
});

test("close/cancel double failure retains only the exact SSH tab and exposes its own error", async (t) => {
  for (const connected of [false, true]) {
    await t.test(connected ? "connected" : "connecting", async () => {
      const harness = createHarness();
      const a = await beginOpen(harness, connected ? "ConnectedA" : "ConnectingA");
      harness.starts.resolve(0, "native-a");
      await a.opening;
      if (connected) a.start.callbacks.onControl({ type: "connected" });

      const b = await beginOpen(harness, "LiveB");
      harness.starts.resolve(1, "native-b");
      await b.opening;
      b.start.callbacks.onControl({ type: "connected" });
      harness.backend.closeFailure = new Error("close-denied");
      harness.backend.cancelFailure = new Error("cancel-denied");

      const error = await harness.controller.close(a.id);
      const snapshotA = getTerminalSessionSnapshot(harness.catalog.snapshot, a.id)!;
      const snapshotB = getTerminalSessionSnapshot(harness.catalog.snapshot, b.id)!;
      assert.deepEqual(harness.catalog.snapshot.order, [a.id, b.id]);
      assert.equal(snapshotA.state, connected ? "connected" : "connecting");
      assert.equal(snapshotA.error, error);
      assert.doesNotMatch(error!, /close-denied|cancel-denied/);
      assert.equal(snapshotB.state, "connected");
      assert.equal(snapshotB.error, null);
      assert.match(
        harness.terminals.get(a.id)!.lines.at(-1)!,
        /terminal\.runtime\.disconnectFailed/,
      );
      assert.doesNotMatch(harness.terminals.get(a.id)!.lines.at(-1)!, /primary|fallback/i);
      assert.equal(harness.terminals.get(b.id)!.lines.some((line) => line.includes("Unable")), false);
    });
  }
});

test("shared catalog enforces a cross-protocol limit and cleans a rejected SSH runtime", async () => {
  const harness = createHarness({ limit: 1 });
  const localId = workspaceSessionIdFrom("ws-20000000-0000-4000-8000-000000000001");
  harness.catalog.add({
    id: localId,
    protocol: "local",
    title: "Existing Local",
    state: "connected",
  });

  await assert.rejects(
    harness.controller.open(target("Overflow"), harness.createAttempt()),
    /WORKSPACE_SESSION_LIMIT_REACHED/,
  );
  assert.deepEqual(harness.catalog.snapshot.order, [localId]);
  assert.equal(harness.starts.calls.length, 0);
  assert.deepEqual(harness.destroyed, [fixedId(1)]);
  assert.equal(harness.terminals.get(fixedId(1))?.disposeCount, 1);
});

test("restored SSH placeholder stays disconnected and starts only through explicit retry", async () => {
  const harness = createHarness();
  const localId = workspaceSessionIdFrom("ws-20000000-0000-4000-8000-000000000003");
  const restoredId = fixedId(50);
  harness.catalog.add({
    id: localId,
    protocol: "local",
    title: "Existing Local",
    state: "connected",
  });
  const unsafeInput = {
    ...target("Restored"),
    credentialReference: "must-not-survive",
    password: "must-not-survive",
    selectedIdentityFilePaths: ["C:\\secret-key"],
  } as unknown as SshTerminalTarget;

  assert.deepEqual(
    await harness.controller.restoreDisconnected(restoredId, unsafeInput, { activate: false }),
    { id: restoredId, error: null },
  );
  assert.deepEqual(harness.catalog.snapshot.order, [localId, restoredId]);
  assert.equal(harness.catalog.snapshot.activeSessionId, localId);
  assert.equal(
    getTerminalSessionSnapshot(harness.catalog.snapshot, restoredId)?.state,
    "disconnected",
  );
  assert.equal(harness.starts.calls.length, 0);
  assert.deepEqual(harness.backend.inputCalls, []);
  assert.deepEqual(harness.backend.resizeCalls, []);
  assert.deepEqual(harness.backend.closeCalls, []);
  assert.deepEqual(harness.backend.cancelCalls, []);
  assert.deepEqual(
    Object.keys(
      harness.controller.getRuntime(restoredId)!.target as unknown as Record<string, unknown>,
    ).sort(),
    ["hostname", "kind", "port", "title", "username"],
  );

  const retryAttempt = harness.createAttempt();
  assert.equal(
    harness.controller.workspaceSessionIdForAttempt(retryAttempt.clientAttemptId),
    undefined,
  );
  harness.controller.markViewportReady(restoredId);
  const retrying = harness.controller.retry(restoredId, retryAttempt);
  await flushMicrotasks();
  assert.equal(harness.starts.calls.length, 1);
  assert.equal(
    harness.controller.workspaceSessionIdForAttempt(retryAttempt.clientAttemptId),
    restoredId,
  );
  harness.starts.resolve(0, "native-restored");
  assert.equal(await retrying, null);
  assert.equal(harness.controller.backendSessionIdFor(restoredId), "native-restored");
});

test("duplicate SSH restore ID fails without replacing or allocating runtime state", async () => {
  const harness = createHarness();
  const duplicateId = fixedId(51);
  await harness.controller.restoreDisconnected(duplicateId, target("Original"));
  const originalRuntime = harness.controller.getRuntime(duplicateId);
  const originalTerminal = harness.terminals.get(duplicateId)!;
  const originalResizer = harness.resizers.get(duplicateId)!;

  await assert.rejects(
    harness.controller.restoreDisconnected(duplicateId, target("Duplicate")),
    /SSH_TERMINAL_RESTORE_DUPLICATE/,
  );
  assert.equal(harness.controller.getRuntime(duplicateId), originalRuntime);
  assert.equal(harness.terminals.get(duplicateId), originalTerminal);
  assert.equal(harness.resizers.get(duplicateId), originalResizer);
  assert.equal(originalTerminal.disposeCount, 0);
  assert.equal(originalResizer.disposeCount, 0);
  assert.deepEqual(harness.destroyed, []);
  assert.equal(harness.starts.calls.length, 0);
  assert.deepEqual(harness.catalog.snapshot.order, [duplicateId]);
});

test("SSH restore limit failure disposes every newly allocated renderer resource", async () => {
  const harness = createHarness({ limit: 1 });
  const localId = workspaceSessionIdFrom("ws-20000000-0000-4000-8000-000000000004");
  const rejectedId = fixedId(52);
  harness.catalog.add({
    id: localId,
    protocol: "local",
    title: "Existing Local",
    state: "connected",
  });

  await assert.rejects(
    harness.controller.restoreDisconnected(rejectedId, target("Overflow")),
    /WORKSPACE_SESSION_LIMIT_REACHED/,
  );
  assert.deepEqual(harness.catalog.snapshot.order, [localId]);
  assert.equal(harness.controller.owns(rejectedId), false);
  assert.equal(harness.terminals.get(rejectedId)?.disposeCount, 1);
  assert.equal(harness.resizers.get(rejectedId)?.disposeCount, 1);
  assert.deepEqual(harness.destroyed, [rejectedId]);
  assert.equal(harness.starts.calls.length, 0);
  assert.deepEqual(harness.backend.inputCalls, []);
  assert.deepEqual(harness.backend.resizeCalls, []);
  assert.deepEqual(harness.backend.closeCalls, []);
  assert.deepEqual(harness.backend.cancelCalls, []);
});

test("invalid SSH restore target fails before allocating renderer resources", async () => {
  const harness = createHarness();
  const rejectedId = fixedId(53);
  const invalidTarget = { ...target("Invalid"), port: 0 };

  await assert.rejects(
    harness.controller.restoreDisconnected(rejectedId, invalidTarget),
    /SSH_TERMINAL_TARGET_PORT_INVALID/,
  );
  assert.deepEqual(harness.catalog.snapshot.order, []);
  assert.equal(harness.controller.owns(rejectedId), false);
  assert.equal(harness.terminals.has(rejectedId), false);
  assert.equal(harness.resizers.has(rejectedId), false);
  assert.deepEqual(harness.destroyed, []);
  assert.equal(harness.starts.calls.length, 0);
});

test("SSH restore construction failures dispose partial renderer resources atomically", async (t) => {
  for (const [index, failure] of (["resize", "input"] as const).entries()) {
    await t.test(failure, async () => {
      const harness = createHarness({ constructionFailure: failure });
      const rejectedId = fixedId(60 + index);

      await assert.rejects(
        harness.controller.restoreDisconnected(rejectedId, target(`Failure${index}`)),
        failure === "resize"
          ? /SSH_TEST_RESIZE_COORDINATOR_FAILED/
          : /SSH_TEST_INPUT_LISTENER_FAILED/,
      );
      assert.deepEqual(harness.catalog.snapshot.order, []);
      assert.equal(harness.controller.owns(rejectedId), false);
      assert.equal(harness.terminals.get(rejectedId)?.disposeCount, 1);
      assert.equal(harness.terminals.get(rejectedId)?.inputListeners.size, 0);
      if (failure === "resize") {
        assert.equal(harness.resizers.has(rejectedId), false);
      } else {
        assert.equal(harness.resizers.get(rejectedId)?.disposeCount, 1);
      }
      assert.deepEqual(harness.destroyed, [rejectedId]);
      assert.equal(harness.starts.calls.length, 0);
    });
  }
});

test("target sanitization drops unknown authority fields and dispose removes only owned SSH tabs", async () => {
  const harness = createHarness();
  const localId = workspaceSessionIdFrom("ws-20000000-0000-4000-8000-000000000002");
  harness.catalog.add({
    id: localId,
    protocol: "local",
    title: "Local",
    state: "connected",
  });
  const unsafeInput = {
    ...target("Sanitized"),
    credentialReference: "must-not-survive",
    password: "must-not-survive",
    selectedIdentityFilePaths: ["C:\\secret-key"],
  } as unknown as SshTerminalTarget;
  const opening = harness.controller.open(unsafeInput, harness.createAttempt());
  const sshId = harness.catalog.snapshot.order.at(-1)!;
  harness.controller.markViewportReady(sshId);
  await flushMicrotasks();
  harness.starts.resolve(0, "native-safe");
  await opening;

  const runtimeTarget = harness.controller.getRuntime(sshId)!.target as unknown as Record<string, unknown>;
  assert.deepEqual(Object.keys(runtimeTarget).sort(), [
    "hostname",
    "kind",
    "port",
    "title",
    "username",
  ]);
  assert.doesNotMatch(JSON.stringify(harness.catalog.snapshot), /credential|password|secret-key/);

  harness.controller.dispose();
  assert.deepEqual(harness.catalog.snapshot.order, [localId]);
  assert.deepEqual(harness.backend.cancelCalls, ["native-safe"]);
  assert.equal(harness.terminals.get(sshId)?.disposeCount, 1);
});

test("retired attempt IDs reject replay for the broker TTL and expire without unbounded retention", async () => {
  const harness = createHarness();
  const firstAttempt = harness.createAttempt();
  const first = await beginOpen(harness, "ReplayGuard", firstAttempt);
  first.start.callbacks.onControl({ type: "closed" });
  harness.starts.resolve(0, "native-retired");
  await first.opening;

  await assert.rejects(
    harness.controller.retry(first.id, firstAttempt),
    /SSH_CLIENT_ATTEMPT_ID_DUPLICATE/,
  );

  harness.advanceAttemptClock(5 * 60 * 1_000);
  const retrying = harness.controller.retry(first.id, firstAttempt);
  await flushMicrotasks();
  const replayAfterTtl = harness.starts.calls[1]!;
  assert.equal(replayAfterTtl.clientAttemptId, firstAttempt.clientAttemptId);
  harness.starts.resolve(1, "native-after-ttl");
  assert.equal(await retrying, null);
});
