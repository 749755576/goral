import assert from "node:assert/strict";
import test from "node:test";

import type {
  DiscoveredLocalShell,
  SshSessionCallbacks,
  StartLocalPtySessionRequest,
  TerminalSize,
} from "../../src/backend.ts";
import {
  LocalTerminalSessionController,
  type LocalTerminalBackend,
  type LocalTerminalFrameScheduler,
  type LocalTerminalResizeCoordinator,
  type LocalTerminalRestoreRequest,
  type LocalTerminalTarget,
  type LocalTerminalXterm,
} from "../../src/localTerminalSessionController.ts";
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

const target = (name: string): LocalTerminalTarget => ({
  shell: {
    id: `shell-${name.toLowerCase()}`,
    name,
    command: `${name}.exe`,
    args: [],
    icon: "terminal",
    isDefault: false,
  },
});

class FakeTerminal implements LocalTerminalXterm {
  readonly cols = 100;
  readonly rows = 30;
  readonly byteWrites: Uint8Array[] = [];
  readonly lines: string[] = [];
  readonly inputListeners = new Set<(data: string) => void>();
  readonly oscHandlers = new Map<number, (payload: string) => boolean>();
  readonly parser = {
    registerOscHandler: (identifier: number, callback: (payload: string) => boolean) => {
      this.oscHandlers.set(identifier, callback);
      if (this.constructionFailure === `osc${identifier}`) {
        throw new Error(`LOCAL_TEST_OSC_${identifier}_FAILED`);
      }
      return {
        dispose: () => {
          this.oscDisposeCount += 1;
          if (this.oscHandlers.get(identifier) === callback) {
            this.oscHandlers.delete(identifier);
          }
        },
      };
    },
  };
  clearCount = 0;
  focusCount = 0;
  disposeCount = 0;
  oscDisposeCount = 0;
  constructionFailure: "input" | "osc7" | "osc9" | null = null;
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
      throw new Error("LOCAL_TEST_INPUT_LISTENER_FAILED");
    }
    return { dispose: () => this.inputListeners.delete(listener) };
  }

  emitInput(data: string): void {
    for (const listener of this.inputListeners) listener(data);
  }

  emitOsc(identifier: number, payload: string): boolean | undefined {
    return this.oscHandlers.get(identifier)?.(payload);
  }

  dataText(): string {
    return this.byteWrites.map((value) => decoder.decode(value)).join("");
  }

  dispose(): void {
    this.disposeCount += 1;
    this.inputListeners.clear();
    this.oscHandlers.clear();
  }
}

type FakeHandle = {
  sessionId: string;
  dispose: () => void;
};

type StartCall = {
  request: StartLocalPtySessionRequest;
  callbacks: SshSessionCallbacks;
  pending: ReturnType<typeof deferred<FakeHandle>>;
  handleDisposeCount: number;
};

class FakeBackend implements LocalTerminalBackend {
  readonly shells: DiscoveredLocalShell[] = [];
  readonly starts: StartCall[] = [];
  readonly inputCalls: Array<{ sessionId: string; text: string }> = [];
  readonly resizeCalls: Array<{ sessionId: string; size: TerminalSize }> = [];
  readonly closeCalls: string[] = [];
  readonly cancelCalls: string[] = [];
  closeFailure: Error | null = null;
  cancelFailure: Error | null = null;
  inputFailure: Error | null = null;
  listShellCalls = 0;

  listShells = async () => {
    this.listShellCalls += 1;
    return this.shells;
  };

  start = (request: StartLocalPtySessionRequest, callbacks: SshSessionCallbacks) => {
    const call: StartCall = {
      request,
      callbacks,
      pending: deferred<FakeHandle>(),
      handleDisposeCount: 0,
    };
    this.starts.push(call);
    return call.pending.promise;
  };

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

  resolveStart(index: number, sessionId: string): StartCall {
    const call = this.starts[index]!;
    call.pending.resolve({
      sessionId,
      dispose: () => {
        call.handleDisposeCount += 1;
      },
    });
    return call;
  }
}

class FakeResizeCoordinator implements LocalTerminalResizeCoordinator {
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
  const scheduler: LocalTerminalFrameScheduler = {
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
  `ws-00000000-0000-4000-8000-${String(sequence).padStart(12, "0")}`,
);

const createHarness = (options: Readonly<{
  catalogLimit?: number;
  constructionFailure?: "resize" | "input" | "osc7" | "osc9";
}> = {}) => {
  const backend = new FakeBackend();
  const frames = createScheduler();
  const terminals = new Map<WorkspaceSessionId, FakeTerminal>();
  const fits = new Map<WorkspaceSessionId, { count: number }>();
  const resizers = new Map<WorkspaceSessionId, FakeResizeCoordinator>();
  const destroyed: WorkspaceSessionId[] = [];
  let nextId = 0;
  const controller = new LocalTerminalSessionController<FakeTerminal>({
    backend,
    translate,
    ...(options.catalogLimit
      ? { catalog: createTerminalSessionCatalog({ limit: options.catalogLimit }) }
      : {}),
    createId: () => fixedId(++nextId),
    createXterm(id) {
      const terminal = new FakeTerminal();
      terminal.constructionFailure = options.constructionFailure === "resize"
        ? null
        : options.constructionFailure ?? null;
      const fit = { count: 0 };
      terminals.set(id, terminal);
      fits.set(id, fit);
      return {
        terminal,
        fit: {
          fit() {
            fit.count += 1;
            return true;
          },
        },
      };
    },
    createResizeCoordinator(transport, id) {
      if (options.constructionFailure === "resize") {
        throw new Error("LOCAL_TEST_RESIZE_COORDINATOR_FAILED");
      }
      const coordinator = new FakeResizeCoordinator(transport);
      resizers.set(id, coordinator);
      return coordinator;
    },
    scheduler: frames.scheduler,
    onRuntimeDestroyed(runtime) {
      destroyed.push(runtime.id);
    },
  });
  return { backend, controller, destroyed, fits, frames, resizers, terminals };
};

const beginOpen = async (
  harness: ReturnType<typeof createHarness>,
  shellName: string,
) => {
  const opening = harness.controller.open(target(shellName));
  const id = harness.controller.registry.order.at(-1)!;
  harness.controller.markViewportReady(id);
  await flushMicrotasks();
  return { id, opening, start: harness.backend.starts.at(-1)! };
};

test("disconnected restore resolves the current Shell catalog without starting native PTY", async () => {
  const harness = createHarness();
  const anchorId = fixedId(49);
  const restoredId = fixedId(50);
  const anchorShell = target("Anchor").shell;
  const currentShell = target("Restored").shell;
  harness.backend.shells.push(anchorShell, currentShell);

  await harness.controller.restoreDisconnected({
    workspaceSessionId: anchorId,
    shellId: anchorShell.id,
  });

  const restored = await harness.controller.restoreDisconnected({
    workspaceSessionId: restoredId,
    shellId: currentShell.id,
  }, { activate: false });

  assert.deepEqual(restored, { id: restoredId, error: null });
  assert.equal(harness.backend.listShellCalls, 2);
  assert.equal(harness.backend.starts.length, 0);
  assert.equal(
    harness.controller.registry.activeSessionId,
    anchorId,
    "activate:false retains the existing active presentation",
  );
  assert.deepEqual(harness.controller.registry.order, [anchorId, restoredId]);
  assert.deepEqual(getTerminalSessionSnapshot(harness.controller.registry, restoredId), {
    id: restoredId,
    protocol: "local",
    title: "Restored",
    state: "disconnected",
    error: null,
  });
  assert.equal(harness.controller.targetFor(restoredId)?.shell, currentShell);
  assert.ok(harness.controller.getRuntime(restoredId));
  assert.ok(harness.terminals.get(restoredId));

  harness.controller.markViewportReady(restoredId);
  const retrying = harness.controller.retry(restoredId);
  await flushMicrotasks();
  assert.equal(harness.backend.starts.length, 1, "only explicit retry starts the PTY");
  assert.equal(harness.backend.starts[0].request.shellId, currentShell.id);
  harness.backend.resolveStart(0, "native-restored");
  assert.equal(await retrying, null);
});

test("restore input rejects paths and missing Shell IDs without partial state", async () => {
  const harness = createHarness();
  const restoredId = fixedId(51);
  const shell = target("Safe").shell;
  harness.backend.shells.push(shell);

  for (const forbidden of [
    { cwd: "D:\\private" },
    { command: "C:\\Windows\\System32\\cmd.exe" },
    { args: ["/c", "secret"] },
    { path: "D:\\private\\shell.exe" },
  ]) {
    await assert.rejects(
      harness.controller.restoreDisconnected({
        workspaceSessionId: restoredId,
        shellId: shell.id,
        ...forbidden,
      } as unknown as LocalTerminalRestoreRequest),
      /LOCAL_TERMINAL_RESTORE_REQUEST_INVALID/,
    );
  }
  await assert.rejects(
    harness.controller.restoreDisconnected({
      workspaceSessionId: restoredId,
      shellId: "missing-shell",
    }),
    /LOCAL_TERMINAL_RESTORE_SHELL_NOT_FOUND/,
  );
  await assert.rejects(
    harness.controller.restoreDisconnected({
      workspaceSessionId: restoredId,
      shellId: "C:\\shell.exe",
    }),
    /LOCAL_TERMINAL_RESTORE_SHELL_ID_INVALID/,
  );

  assert.deepEqual(harness.controller.registry.order, []);
  assert.equal(harness.controller.getRuntime(restoredId), undefined);
  assert.equal(harness.terminals.size, 0);
  assert.equal(harness.backend.starts.length, 0);
});

test("duplicate and over-limit restores leave no second runtime or catalog entry", async () => {
  const harness = createHarness({ catalogLimit: 1 });
  const firstId = fixedId(52);
  const secondId = fixedId(53);
  const firstShell = target("First").shell;
  const secondShell = target("Second").shell;
  harness.backend.shells.push(firstShell, secondShell);

  await harness.controller.restoreDisconnected({
    workspaceSessionId: firstId,
    shellId: firstShell.id,
  }, { activate: false });
  await assert.rejects(
    harness.controller.restoreDisconnected({
      workspaceSessionId: firstId,
      shellId: firstShell.id,
    }),
    /LOCAL_TERMINAL_RESTORE_DUPLICATE/,
  );
  await assert.rejects(
    harness.controller.restoreDisconnected({
      workspaceSessionId: secondId,
      shellId: secondShell.id,
    }, { activate: false }),
    /WORKSPACE_SESSION_LIMIT_REACHED/,
  );

  assert.deepEqual(harness.controller.registry.order, [firstId]);
  assert.equal(harness.controller.registry.activeSessionId, firstId);
  assert.ok(harness.controller.getRuntime(firstId));
  assert.equal(harness.controller.getRuntime(secondId), undefined);
  assert.equal(harness.terminals.get(firstId)?.disposeCount, 0);
  assert.equal(harness.terminals.get(secondId)?.disposeCount, 1);
  assert.equal(harness.backend.starts.length, 0);
});

test("Local restore cannot revive a controller disposed while Shell discovery is pending", async () => {
  const harness = createHarness();
  const restoredId = fixedId(54);
  const shell = target("Deferred").shell;
  const entered = deferred<void>();
  const shellCatalog = deferred<DiscoveredLocalShell[]>();
  harness.backend.listShells = () => {
    harness.backend.listShellCalls += 1;
    entered.resolve(undefined);
    return shellCatalog.promise;
  };

  const restoring = harness.controller.restoreDisconnected({
    workspaceSessionId: restoredId,
    shellId: shell.id,
  });
  await entered.promise;
  const rejected = assert.rejects(restoring, /LOCAL_TERMINAL_CONTROLLER_DISPOSED/);
  harness.controller.dispose();
  shellCatalog.resolve([shell]);
  await rejected;

  assert.deepEqual(harness.controller.registry.order, []);
  assert.equal(harness.controller.getRuntime(restoredId), undefined);
  assert.equal(harness.terminals.has(restoredId), false);
  assert.equal(harness.resizers.has(restoredId), false);
  assert.deepEqual(harness.destroyed, []);
  assert.equal(harness.backend.starts.length, 0);
});

test("Local restore construction failures dispose partial renderer resources atomically", async (t) => {
  for (const [index, failure] of (["resize", "input", "osc9"] as const).entries()) {
    await t.test(failure, async () => {
      const harness = createHarness({ constructionFailure: failure });
      const rejectedId = fixedId(55 + index);
      const shell = target(`Failure${index}`).shell;
      harness.backend.shells.push(shell);

      await assert.rejects(
        harness.controller.restoreDisconnected({
          workspaceSessionId: rejectedId,
          shellId: shell.id,
        }),
        failure === "resize"
          ? /LOCAL_TEST_RESIZE_COORDINATOR_FAILED/
          : failure === "input"
            ? /LOCAL_TEST_INPUT_LISTENER_FAILED/
            : /LOCAL_TEST_OSC_9_FAILED/,
      );
      const terminal = harness.terminals.get(rejectedId)!;
      assert.deepEqual(harness.controller.registry.order, []);
      assert.equal(harness.controller.getRuntime(rejectedId), undefined);
      assert.equal(terminal.disposeCount, 1);
      assert.equal(terminal.inputListeners.size, 0);
      assert.equal(terminal.oscHandlers.size, 0);
      if (failure === "resize") {
        assert.equal(harness.resizers.has(rejectedId), false);
      } else {
        assert.equal(harness.resizers.get(rejectedId)?.disposeCount, 1);
      }
      assert.equal(terminal.oscDisposeCount, failure === "osc9" ? 1 : 0);
      assert.deepEqual(harness.destroyed, [rejectedId]);
      assert.equal(harness.backend.starts.length, 0);
    });
  }
});

test("A/B runtimes keep exact input, output, close, resize, and hidden scrollback ownership", async () => {
  const harness = createHarness();
  const a = await beginOpen(harness, "Alpha");
  harness.backend.resolveStart(0, "native-a");
  await a.opening;
  a.start.callbacks.onControl({ type: "connected" });

  const b = await beginOpen(harness, "Beta");
  harness.backend.resolveStart(1, "native-b");
  await b.opening;
  b.start.callbacks.onControl({ type: "connected" });
  assert.equal(harness.controller.registry.activeSessionId, b.id);

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

  const closeCountBeforeSwitch = harness.backend.closeCalls.length;
  const cancelCountBeforeSwitch = harness.backend.cancelCalls.length;
  harness.controller.activate(a.id);
  harness.frames.flush();
  await flushMicrotasks();
  assert.equal(harness.controller.registry.activeSessionId, a.id);
  assert.equal(harness.backend.closeCalls.length, closeCountBeforeSwitch);
  assert.equal(harness.backend.cancelCalls.length, cancelCountBeforeSwitch);
  assert.equal(terminalA.focusCount, 1);
  assert.ok(harness.backend.resizeCalls.some((call) => call.sessionId === "native-a"));
  assert.equal(harness.controller.getRuntime(a.id)?.terminal, terminalA);
  assert.equal(terminalA.dataText(), "alpha-hidden\n");

  await harness.controller.close(b.id);
  assert.deepEqual(harness.backend.closeCalls, ["native-b"]);
  assert.deepEqual(harness.backend.cancelCalls, []);
  b.start.callbacks.onControl({ type: "closed" });
  assert.deepEqual(harness.controller.registry.order, [a.id]);
  assert.equal(harness.controller.registry.activeSessionId, a.id);
  assert.equal(harness.controller.getRuntime(a.id)?.terminal, terminalA);
  assert.equal(terminalA.disposeCount, 0);
  assert.equal(terminalB.disposeCount, 1);
});

test("Local terminal splits short plain input but keeps ANSI sequences atomic", async () => {
  const harness = createHarness();
  const session = await beginOpen(harness, "WireInput");
  harness.backend.resolveStart(0, "native-local-wire-input");
  await session.opening;
  session.start.callbacks.onControl({ type: "connected" });
  const terminal = harness.terminals.get(session.id)!;

  terminal.emitInput("中国");
  for (let index = 0; index < 8; index += 1) await Promise.resolve();
  assert.deepEqual(harness.backend.inputCalls, [
    { sessionId: "native-local-wire-input", text: "中" },
    { sessionId: "native-local-wire-input", text: "国" },
  ]);

  terminal.emitInput("\x1b[A");
  for (let index = 0; index < 4; index += 1) await Promise.resolve();
  assert.deepEqual(harness.backend.inputCalls.at(-1), {
    sessionId: "native-local-wire-input",
    text: "\x1b[A",
  });
});

test("Local programmatic text shares the user-input queue without interleaving", async () => {
  const harness = createHarness();
  const session = await beginOpen(harness, "OrderedBridgeInput");
  harness.backend.resolveStart(0, "native-local-ordered-bridge");
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
    { sessionId: "native-local-ordered-bridge", text: "a" },
  ]);

  firstWriteGate.resolve();
  assert.equal(await programmatic, null);
  await flushMicrotasks();
  assert.deepEqual(harness.backend.inputCalls, [
    { sessionId: "native-local-ordered-bridge", text: "a" },
    { sessionId: "native-local-ordered-bridge", text: "b" },
    { sessionId: "native-local-ordered-bridge", text: "AI\r" },
    { sessionId: "native-local-ordered-bridge", text: "z" },
  ]);
});

test("queued Local programmatic text is dropped with its retired generation", async () => {
  const harness = createHarness();
  const first = await beginOpen(harness, "QueuedBridgeRetry");
  harness.backend.resolveStart(0, "native-local-queued-bridge-old");
  await first.opening;
  first.start.callbacks.onControl({ type: "connected" });

  const oldWriteGate = deferred<void>();
  harness.backend.sendInput = async (sessionId, data) => {
    const text = decoder.decode(data);
    harness.backend.inputCalls.push({ sessionId, text });
    if (sessionId === "native-local-queued-bridge-old" && text === "a") {
      await oldWriteGate.promise;
    }
  };
  const terminal = harness.terminals.get(first.id)!;
  terminal.emitInput("ab");
  await flushMicrotasks();
  const queuedProgrammatic = harness.controller.sendText(first.id, "must-not-cross-retry");
  await flushMicrotasks();

  first.start.callbacks.onControl({ type: "closed" });
  const retrying = harness.controller.retry(first.id);
  await flushMicrotasks();
  const retryStart = harness.backend.starts[1]!;
  harness.backend.resolveStart(1, "native-local-queued-bridge-new");
  assert.equal(await retrying, null);
  retryStart.callbacks.onControl({ type: "connected" });
  terminal.emitInput("n");
  await flushMicrotasks();

  oldWriteGate.resolve();
  assert.equal(await queuedProgrammatic, "TERMINAL_SEND_SESSION_CLOSING");
  await flushMicrotasks();
  assert.deepEqual(harness.backend.inputCalls, [
    { sessionId: "native-local-queued-bridge-old", text: "a" },
    { sessionId: "native-local-queued-bridge-new", text: "n" },
  ]);
});

test("Local terminal bridge reads and sends only the requested connected runtime", async () => {
  const harness = createHarness();
  const a = await beginOpen(harness, "BridgeA");
  harness.backend.resolveStart(0, "native-local-bridge-a");
  await a.opening;
  a.start.callbacks.onControl({ type: "connected" });
  const b = await beginOpen(harness, "BridgeB");
  harness.backend.resolveStart(1, "native-local-bridge-b");
  await b.opening;
  b.start.callbacks.onControl({ type: "connected" });

  const terminalA = harness.terminals.get(a.id)!;
  const terminalB = harness.terminals.get(b.id)!;
  terminalA.selectedText = "local alpha selection";
  terminalA.contextLines = ["local alpha old", "local alpha recent"];
  terminalB.selectedText = "local beta selection";
  terminalB.contextLines = ["local beta recent"];

  assert.equal(harness.controller.readSelectedText(a.id), "local alpha selection");
  assert.equal(
    harness.controller.readRecentOutput(a.id),
    "local alpha old\nlocal alpha recent",
  );
  assert.equal(harness.controller.readSelectedText(b.id), "local beta selection");
  assert.equal(await harness.controller.sendText(a.id, "pwd"), null);
  assert.equal(await harness.controller.sendText(b.id, "dir\r"), null);
  assert.deepEqual(harness.backend.inputCalls, [
    { sessionId: "native-local-bridge-a", text: "pwd" },
    { sessionId: "native-local-bridge-b", text: "dir\r" },
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

test("pending Local send remains bound to its old native generation during retry", async () => {
  const harness = createHarness();
  const first = await beginOpen(harness, "SendRace");
  harness.backend.resolveStart(0, "native-local-send-old");
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
    { sessionId: "native-local-send-old", text: "old-generation" },
  ]);

  first.start.callbacks.onControl({ type: "closed" });
  const retrying = harness.controller.retry(first.id);
  await flushMicrotasks();
  const retryStart = harness.backend.starts[1]!;
  harness.backend.resolveStart(1, "native-local-send-new");
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
    { sessionId: "native-local-send-old", text: "old-generation" },
    { sessionId: "native-local-send-new", text: "new-generation" },
  ]);
});

test("split target inherits the exact pane's latest trusted cwd and safely falls back", async () => {
  const harness = createHarness();
  const startingTarget: LocalTerminalTarget = {
    ...target("Cwd"),
    cwd: "D:\\initial",
  };
  const opening = harness.controller.open(startingTarget);
  const id = harness.controller.registry.order[0]!;
  harness.controller.markViewportReady(id);
  await flushMicrotasks();
  assert.deepEqual(harness.controller.targetFor(id), startingTarget);

  const terminal = harness.terminals.get(id)!;
  assert.equal(terminal.emitOsc(7, "file://DESKTOP/D:/project/current%20work"), true);
  assert.equal(harness.controller.targetFor(id)?.cwd, "D:\\project\\current work");

  terminal.emitOsc(7, "file://server/share");
  terminal.emitOsc(7, "https://example.test/D:/stolen");
  terminal.emitOsc(7, "file://host/D:/project/../secret");
  terminal.emitOsc(9, "9;\\\\server\\share");
  terminal.emitOsc(9, "9;relative\\path");
  assert.equal(
    harness.controller.targetFor(id)?.cwd,
    "D:\\project\\current work",
    "untrusted OSC metadata must not replace the last trusted cwd",
  );

  terminal.emitOsc(9, "9;E:\\live\\cwd");
  assert.equal(harness.controller.targetFor(id)?.cwd, "E:\\live\\cwd");

  const closing = harness.controller.close(id);
  harness.backend.resolveStart(0, "native-cwd");
  await opening;
  await closing;
  assert.equal(terminal.oscHandlers.size, 0);
});

test("closed-before-handle retires only that generation and disposes its late handle", async () => {
  const harness = createHarness();
  const session = await beginOpen(harness, "EarlyClose");

  session.start.callbacks.onControl({ type: "closed" });
  assert.equal(
    getTerminalSessionSnapshot(harness.controller.registry, session.id)?.state,
    "disconnected",
  );
  assert.equal(harness.controller.backendSessionIdFor(session.id), undefined);

  const call = harness.backend.resolveStart(0, "native-closed-before-handle");
  await session.opening;
  assert.equal(call.handleDisposeCount, 1);
  assert.deepEqual(harness.backend.cancelCalls, []);
  assert.deepEqual(harness.backend.closeCalls, []);
  assert.equal(harness.controller.backendSessionIdFor(session.id), undefined);
  assert.ok(harness.controller.getRuntime(session.id));
});

test("close while connecting cancels the exact deferred handle when it arrives", async () => {
  const harness = createHarness();
  const session = await beginOpen(harness, "Deferred");

  await harness.controller.close(session.id);
  assert.equal(
    getTerminalSessionSnapshot(harness.controller.registry, session.id)?.state,
    "closing",
  );
  assert.deepEqual(harness.backend.cancelCalls, []);

  harness.backend.resolveStart(0, "native-deferred");
  await session.opening;
  assert.deepEqual(harness.backend.cancelCalls, ["native-deferred"]);
  assert.deepEqual(harness.backend.closeCalls, []);
  assert.equal(harness.controller.backendSessionIdFor(session.id), undefined);
  assert.deepEqual(harness.controller.registry.order, []);
  assert.equal(harness.controller.registry.activeSessionId, null);

  // A late native completion remains harmless after the accepted stop request
  // has already retired the explicitly closed tab.
  session.start.callbacks.onControl({ type: "closed" });
  assert.deepEqual(harness.controller.registry.order, []);
  assert.equal(harness.controller.registry.activeSessionId, null);
  assert.equal(harness.controller.backendSessionIdFor(session.id), undefined);
});

test("explicit close retires the tab after stop acknowledgement without requiring closed", async () => {
  const harness = createHarness();
  const session = await beginOpen(harness, "NoClosedEvent");
  const call = harness.backend.resolveStart(0, "native-no-closed-event");
  await session.opening;
  session.start.callbacks.onControl({ type: "connected" });

  assert.equal(await harness.controller.close(session.id), null);
  assert.deepEqual(harness.backend.closeCalls, ["native-no-closed-event"]);
  assert.deepEqual(harness.controller.registry.order, []);
  assert.equal(harness.controller.getRuntime(session.id), undefined);
  assert.equal(call.handleDisposeCount, 1);
});

test("an acknowledged disconnect can still be explicitly closed when closed is lost", async () => {
  const harness = createHarness();
  const session = await beginOpen(harness, "DisconnectThenClose");
  const call = harness.backend.resolveStart(0, "native-disconnect-no-closed");
  await session.opening;
  session.start.callbacks.onControl({ type: "connected" });

  assert.equal(await harness.controller.disconnect(session.id), null);
  assert.equal(
    getTerminalSessionSnapshot(harness.controller.registry, session.id)?.state,
    "closing",
  );
  assert.deepEqual(harness.backend.closeCalls, ["native-disconnect-no-closed"]);

  assert.equal(await harness.controller.close(session.id), null);
  assert.deepEqual(harness.controller.registry.order, []);
  assert.equal(harness.controller.getRuntime(session.id), undefined);
  assert.deepEqual(
    harness.backend.closeCalls,
    ["native-disconnect-no-closed"],
    "the accepted stop request is not issued twice",
  );
  assert.equal(call.handleDisposeCount, 1);
});

test("retry replaces the native ID while stale generation events and resizes stay inert", async () => {
  const harness = createHarness();
  const first = await beginOpen(harness, "Retryable");
  const firstHandle = harness.backend.resolveStart(0, "native-old");
  await first.opening;
  first.start.callbacks.onControl({ type: "connected" });
  first.start.callbacks.onData(frame("old-valid\n"));
  const terminal = harness.terminals.get(first.id)!;

  first.start.callbacks.onControl({ type: "closed" });
  assert.equal(firstHandle.handleDisposeCount, 1);
  assert.equal(harness.controller.backendSessionIdFor(first.id), undefined);
  assert.equal(
    getTerminalSessionSnapshot(harness.controller.registry, first.id)?.state,
    "disconnected",
  );

  const retrying = harness.controller.retry(first.id);
  await flushMicrotasks();
  const second = harness.backend.starts[1]!;
  harness.backend.resolveStart(1, "native-new");
  assert.equal(await retrying, null);
  second.callbacks.onControl({ type: "connected" });
  assert.equal(harness.controller.backendSessionIdFor(first.id), "native-new");

  first.start.callbacks.onData(frame("stale-data\n"));
  first.start.callbacks.onControl({
    type: "error",
    code: "STALE",
    message: "stale error",
  });
  first.start.callbacks.onControl({ type: "closed" });
  assert.equal(harness.controller.backendSessionIdFor(first.id), "native-new");
  assert.equal(
    getTerminalSessionSnapshot(harness.controller.registry, first.id)?.state,
    "connected",
  );
  assert.equal(getTerminalSessionSnapshot(harness.controller.registry, first.id)?.error, null);

  second.callbacks.onData(frame("new-valid\n"));
  terminal.emitInput("n");
  await flushMicrotasks();
  assert.equal(terminal.dataText(), "old-valid\nnew-valid\n");
  assert.equal(terminal.clearCount, 1);
  assert.deepEqual(harness.backend.inputCalls.at(-1), {
    sessionId: "native-new",
    text: "n",
  });

  const resizer = harness.resizers.get(first.id)!;
  await resizer.transport("native-old", {
    columns: 120,
    rows: 40,
    pixelWidth: 0,
    pixelHeight: 0,
  });
  assert.equal(
    harness.backend.resizeCalls.filter((call) => call.sessionId === "native-old").length,
    1,
    "only the resize sent while native-old was current is allowed",
  );
  await resizer.transport("native-new", {
    columns: 121,
    rows: 41,
    pixelWidth: 0,
    pixelHeight: 0,
  });
  assert.ok(harness.backend.resizeCalls.some((call) => (
    call.sessionId === "native-new" && call.size.columns === 121
  )));
});

test("close/cancel double failure retains the tab and restores its exact live state and error", async (t) => {
  for (const connected of [false, true]) {
    await t.test(connected ? "connected session" : "connecting session", async () => {
      const harness = createHarness();
      const session = await beginOpen(harness, connected ? "Connected" : "Connecting");
      harness.backend.resolveStart(0, connected ? "native-connected" : "native-connecting");
      await session.opening;
      if (connected) session.start.callbacks.onControl({ type: "connected" });

      harness.backend.closeFailure = new Error("close-denied");
      harness.backend.cancelFailure = new Error("cancel-denied");
      const error = await harness.controller.close(session.id);
      const snapshot = getTerminalSessionSnapshot(harness.controller.registry, session.id)!;

      assert.deepEqual(harness.controller.registry.order, [session.id]);
      assert.equal(snapshot.state, connected ? "connected" : "connecting");
      assert.equal(snapshot.error, error);
      assert.match(error!, /terminal\.runtime\.disconnectFailed/);
      assert.doesNotMatch(error!, /primary|fallback/i);
      assert.doesNotMatch(error!, /close-denied|cancel-denied/);
      assert.equal(
        harness.controller.backendSessionIdFor(session.id),
        connected ? "native-connected" : "native-connecting",
      );
      assert.equal(harness.terminals.get(session.id)?.disposeCount, 0);
      assert.deepEqual(
        connected
          ? [harness.backend.closeCalls, harness.backend.cancelCalls]
          : [harness.backend.cancelCalls, harness.backend.closeCalls],
        connected
          ? [["native-connected"], ["native-connected"]]
          : [["native-connecting"], ["native-connecting"]],
      );

      harness.terminals.get(session.id)!.emitInput("x");
      await flushMicrotasks();
      assert.deepEqual(harness.backend.inputCalls, [{
        sessionId: connected ? "native-connected" : "native-connecting",
        text: "x",
      }]);
    });
  }
});
