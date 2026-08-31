import type {
  DiscoveredLocalShell,
  SshControlEvent,
  SshSessionCallbacks,
  StartLocalPtySessionRequest,
  TerminalSize,
} from "./backend";
import {
  createTerminalSessionCatalog,
  type TerminalSessionCatalog,
} from "./terminalSessionCatalog.ts";
import {
  parseTrustedLocalOsc7Cwd,
  parseTrustedLocalOsc9Cwd,
  type LocalTerminalCwdPlatform,
} from "./localTerminalCwd.ts";
import {
  createWorkspaceSessionId,
  getTerminalSessionSnapshot,
  TerminalSessionRuntimeRegistry,
  workspaceSessionIdFrom,
  type TerminalSessionRegistrySnapshot,
  type TerminalSessionSnapshot,
  type TerminalSessionSnapshotUpdate,
  type WorkspaceSessionId,
} from "./terminalSessionRegistry.ts";
import {
  prepareTerminalText,
  readTerminalRecentOutput,
  readTerminalSelectedText,
  type TerminalContextSource,
  type TerminalSendTextErrorCode,
} from "./terminalSessionBridge.ts";
import type { Translate } from "./i18n.ts";
import {
  createTerminalInputBinding,
  type TerminalInputBinding,
} from "./terminalImeTextInput.ts";
import {
  TerminalInputWriteQueue,
  type PreparedTerminalTextInput,
} from "./terminalPerCharacterInput.ts";

export type LocalTerminalTarget = Readonly<{
  shell: DiscoveredLocalShell;
  cwd?: string;
}>;

export type LocalTerminalOpenResult = Readonly<{
  id: WorkspaceSessionId;
  error: string | null;
}>;

/**
 * Safe restart input. The persisted hint can name only a current native Shell
 * catalog entry; cwd, command, arguments, and filesystem paths are rejected.
 */
export type LocalTerminalRestoreRequest = Readonly<{
  workspaceSessionId: WorkspaceSessionId;
  shellId: string;
}>;

export type LocalTerminalRestoreOptions = Readonly<{
  activate?: boolean;
}>;

export type LocalTerminalHandle = Readonly<{
  sessionId: string;
  dispose: () => void;
}>;

export type LocalTerminalBackend = Readonly<{
  /** Renderer-safe current catalog; Rust remains authoritative at spawn. */
  listShells?: () => Promise<DiscoveredLocalShell[]>;
  start: (
    request: StartLocalPtySessionRequest,
    callbacks: SshSessionCallbacks,
  ) => Promise<LocalTerminalHandle>;
  sendInput: (sessionId: string, data: Uint8Array) => Promise<void>;
  resize: (sessionId: string, size: TerminalSize) => Promise<void>;
  close: (sessionId: string) => Promise<void>;
  cancel: (sessionId: string) => Promise<void>;
}>;

export type LocalTerminalDisposable = Readonly<{
  dispose: () => void;
}>;

/** The small xterm surface used by the controller and by deterministic tests. */
export type LocalTerminalXterm = TerminalContextSource & {
  readonly element?: HTMLElement;
  readonly textarea?: HTMLTextAreaElement;
  readonly cols: number;
  readonly rows: number;
  write: (data: string | Uint8Array) => void;
  writeln: (data: string) => void;
  clear: () => void;
  focus: () => void;
  attachCustomKeyEventHandler?: (
    handler: (event: KeyboardEvent) => boolean,
  ) => void;
  onData: (listener: (data: string) => void) => LocalTerminalDisposable;
  readonly parser?: Readonly<{
    registerOscHandler: (
      identifier: number,
      callback: (payload: string) => boolean,
    ) => LocalTerminalDisposable;
  }>;
  dispose: () => void;
};

export type LocalTerminalFit = Readonly<{
  /** Returning false suppresses a resize when the viewport has no layout yet. */
  fit: () => boolean | void;
}>;

export type LocalTerminalResizeCoordinator = Readonly<{
  request: (sessionId: string, size: TerminalSize) => void;
  reset: () => void;
  dispose: () => void;
}>;

export type LocalTerminalFrameScheduler = Readonly<{
  request: (callback: () => void) => number;
  cancel: (frameId: number) => void;
}>;

type ViewportBarrier = {
  promise: Promise<void>;
  resolve: () => void;
  resolved: boolean;
};

type LocalTerminalOperation = {
  generation: number;
  handle: LocalTerminalHandle | null;
  connected: boolean;
  stopRequested: boolean;
  stopAcknowledged: boolean;
  closed: boolean;
  removeWhenClosed: boolean;
};

export type LocalTerminalRuntime<TerminalType extends LocalTerminalXterm> = {
  readonly id: WorkspaceSessionId;
  readonly target: LocalTerminalTarget;
  readonly terminal: TerminalType;
  readonly fit: LocalTerminalFit;
  readonly resizeCoordinator: LocalTerminalResizeCoordinator;
  readonly operationGeneration: number;
  readonly destroyed: boolean;
};

type MutableLocalTerminalRuntime<TerminalType extends LocalTerminalXterm> = {
  id: WorkspaceSessionId;
  target: LocalTerminalTarget;
  terminal: TerminalType;
  fit: LocalTerminalFit;
  resizeCoordinator: LocalTerminalResizeCoordinator;
  viewportBarrier: ViewportBarrier;
  inputDisposable: LocalTerminalDisposable | null;
  inputBinding: TerminalInputBinding | null;
  inputWriteQueue: TerminalInputWriteQueue;
  cwdDisposables: LocalTerminalDisposable[];
  trustedCwd: string | null;
  operationGeneration: number;
  operation: LocalTerminalOperation | null;
  destroyed: boolean;
};

export type LocalTerminalSessionControllerDependencies<
  TerminalType extends LocalTerminalXterm,
> = Readonly<{
  backend: LocalTerminalBackend;
  createXterm: (
    id: WorkspaceSessionId,
    target: LocalTerminalTarget,
  ) => Readonly<{ terminal: TerminalType; fit: LocalTerminalFit }>;
  createResizeCoordinator: (
    transport: (sessionId: string, size: TerminalSize) => Promise<void>,
    id: WorkspaceSessionId,
  ) => LocalTerminalResizeCoordinator;
  scheduler: LocalTerminalFrameScheduler;
  /** Resolves every renderer-visible status without reflecting backend text. */
  translate: Translate;
  cwdPlatform?: LocalTerminalCwdPlatform;
  catalog?: TerminalSessionCatalog;
  createId?: () => WorkspaceSessionId;
  onRegistryChange?: (registry: TerminalSessionRegistrySnapshot) => void;
  onRuntimeDestroyed?: (runtime: LocalTerminalRuntime<TerminalType>) => void;
}>;

const INERT_RESIZE_COORDINATOR: LocalTerminalResizeCoordinator = Object.freeze({
  request: () => undefined,
  reset: () => undefined,
  dispose: () => undefined,
});

const disposeSilently = (disposable: Readonly<{ dispose: () => void }> | null | undefined): void => {
  try {
    disposable?.dispose();
  } catch {
    // Cleanup is best-effort, but one broken disposer cannot retain later resources.
  }
};

const utf8 = new TextEncoder();

const makeViewportBarrier = (): ViewportBarrier => {
  let resolvePromise!: () => void;
  const barrier: ViewportBarrier = {
    promise: new Promise<void>((resolve) => {
      resolvePromise = resolve;
    }),
    resolve: () => undefined,
    resolved: false,
  };
  barrier.resolve = () => {
    if (barrier.resolved) return;
    barrier.resolved = true;
    resolvePromise();
  };
  return barrier;
};

const RESTORE_SHELL_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,127}$/;

const normalizeRestoreRequest = (value: unknown): LocalTerminalRestoreRequest => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("LOCAL_TERMINAL_RESTORE_REQUEST_INVALID");
  }
  const candidate = value as Record<string, unknown>;
  const prototype = Object.getPrototypeOf(candidate);
  const keys = Object.keys(candidate);
  if (
    (prototype !== Object.prototype && prototype !== null)
    || keys.length !== 2
    || !Object.hasOwn(candidate, "workspaceSessionId")
    || !Object.hasOwn(candidate, "shellId")
  ) {
    throw new Error("LOCAL_TERMINAL_RESTORE_REQUEST_INVALID");
  }
  const workspaceSessionId = workspaceSessionIdFrom(candidate.workspaceSessionId as string);
  if (
    typeof candidate.shellId !== "string"
    || !RESTORE_SHELL_ID_PATTERN.test(candidate.shellId)
  ) {
    throw new Error("LOCAL_TERMINAL_RESTORE_SHELL_ID_INVALID");
  }
  return Object.freeze({
    workspaceSessionId,
    shellId: candidate.shellId,
  });
};

const framePayload = (frame: Uint8Array): Uint8Array => (
  frame.subarray(frame[0] === 1 ? 5 : 1)
);

const sessionTitle = (target: LocalTerminalTarget, translate: Translate): string => (
  target.shell.name.trim() || translate("localTerminal.title")
);

/**
 * Owns Local PTY authority independently from React presentation state.
 *
 * Every native callback closes over an exact runtime and operation generation.
 * A retry keeps the workspace/xterm identity but replaces the operation and
 * native session ID, so stale data/control/closed events become harmless.
 */
export class LocalTerminalSessionController<
  TerminalType extends LocalTerminalXterm,
> {
  readonly #dependencies: LocalTerminalSessionControllerDependencies<TerminalType>;
  readonly #runtimes = new TerminalSessionRuntimeRegistry<
    MutableLocalTerminalRuntime<TerminalType>
  >();
  readonly #scheduledFrames = new Set<number>();
  readonly #catalog: TerminalSessionCatalog;
  readonly #unsubscribeCatalog: () => void;
  #disposed = false;

  constructor(dependencies: LocalTerminalSessionControllerDependencies<TerminalType>) {
    this.#dependencies = dependencies;
    this.#catalog = dependencies.catalog ?? createTerminalSessionCatalog();
    this.#unsubscribeCatalog = this.#catalog.subscribe((registry) => {
      if (!this.#disposed) this.#dependencies.onRegistryChange?.(registry);
    });
  }

  get registry(): TerminalSessionRegistrySnapshot {
    return this.#catalog.snapshot;
  }

  get activeSession(): TerminalSessionSnapshot | null {
    const id = this.#catalog.snapshot.activeSessionId;
    return id && this.#runtimes.hasExact(id)
      ? getTerminalSessionSnapshot(this.#catalog.snapshot, id) ?? null
      : null;
  }

  hasSessions(): boolean {
    return this.#runtimes.size > 0;
  }

  getRuntime(id: WorkspaceSessionId): LocalTerminalRuntime<TerminalType> | undefined {
    return this.#runtimes.getExact(id);
  }

  readSelectedText(id: WorkspaceSessionId): string {
    try {
      return readTerminalSelectedText(this.#runtimes.getExact(id)?.terminal);
    } catch {
      return "";
    }
  }

  readRecentOutput(id: WorkspaceSessionId): string {
    try {
      return readTerminalRecentOutput(this.#runtimes.getExact(id)?.terminal);
    } catch {
      return "";
    }
  }

  /**
   * Send exact text to one connected PTY generation. This does not echo,
   * persist, log, or append a line ending, and all failures are stable codes.
   */
  async sendText(
    id: WorkspaceSessionId,
    data: string,
    expectedGeneration?: number,
  ): Promise<TerminalSendTextErrorCode | null> {
    const prepared = prepareTerminalText(data);
    if (prepared.error) return prepared.error;

    try {
      const runtime = this.#runtimes.getExact(id);
      if (!runtime) return "TERMINAL_SEND_SESSION_NOT_FOUND";
      const operation = runtime.operation;
      if (
        expectedGeneration !== undefined
        && (!Number.isSafeInteger(expectedGeneration)
          || operation?.generation !== expectedGeneration)
      ) {
        return "TERMINAL_SEND_ROUTE_STALE";
      }
      const snapshot = getTerminalSessionSnapshot(this.registry, id);
      if (operation?.stopRequested || operation?.closed || snapshot?.state === "closing") {
        return "TERMINAL_SEND_SESSION_CLOSING";
      }
      const backendSessionId = operation?.handle?.sessionId;
      if (
        !operation
        || !operation.connected
        || !backendSessionId
        || snapshot?.state !== "connected"
      ) {
        return "TERMINAL_SEND_SESSION_NOT_CONNECTED";
      }
      if (
        !this.#isExactOperation(runtime, operation)
        || this.#runtimes.backendSessionIdFor(id) !== backendSessionId
        || this.#runtimes.getByBackendSessionId(backendSessionId) !== runtime
      ) {
        return "TERMINAL_SEND_ROUTE_STALE";
      }
      const isCurrent = (): boolean => Boolean(
        this.#isExactOperation(runtime, operation)
        && !operation.stopRequested
        && !operation.closed
        && this.#runtimes.backendSessionIdFor(id) === backendSessionId
        && this.#runtimes.getByBackendSessionId(backendSessionId) === runtime,
      );
      const written = await runtime.inputWriteQueue.enqueue(
        [prepared.bytes!],
        (bytes) => this.#dependencies.backend.sendInput(backendSessionId, bytes),
        isCurrent,
      );
      if (!written) {
        const current = getTerminalSessionSnapshot(this.registry, id);
        return operation.stopRequested || operation.closed || current?.state === "closing"
          ? "TERMINAL_SEND_SESSION_CLOSING"
          : "TERMINAL_SEND_ROUTE_STALE";
      }
      return null;
    } catch {
      return "TERMINAL_SEND_FAILED";
    }
  }

  backendSessionIdFor(id: WorkspaceSessionId): string | undefined {
    return this.#runtimes.backendSessionIdFor(id);
  }

  targetFor(id: WorkspaceSessionId): LocalTerminalTarget | undefined {
    const runtime = this.#runtimes.getExact(id);
    if (!runtime) return undefined;
    const cwd = runtime.trustedCwd ?? runtime.target.cwd;
    return {
      shell: runtime.target.shell,
      ...(cwd ? { cwd } : {}),
    };
  }

  #patchSession(
    id: WorkspaceSessionId,
    update: TerminalSessionSnapshotUpdate,
  ): void {
    this.#catalog.update(id, update);
  }

  #isExactRuntime(runtime: MutableLocalTerminalRuntime<TerminalType>): boolean {
    return !this.#disposed
      && !runtime.destroyed
      && this.#runtimes.getExact(runtime.id) === runtime;
  }

  #isExactOperation(
    runtime: MutableLocalTerminalRuntime<TerminalType>,
    operation: LocalTerminalOperation,
  ): boolean {
    return this.#isExactRuntime(runtime)
      && runtime.operation === operation
      && runtime.operationGeneration === operation.generation;
  }

  #schedule(callback: () => void): void {
    if (this.#disposed) return;
    let frameId = 0;
    frameId = this.#dependencies.scheduler.request(() => {
      this.#scheduledFrames.delete(frameId);
      if (!this.#disposed) callback();
    });
    this.#scheduledFrames.add(frameId);
  }

  #fitRuntime(runtime: MutableLocalTerminalRuntime<TerminalType>): void {
    if (
      !this.#isExactRuntime(runtime)
      || !runtime.viewportBarrier.resolved
    ) return;
    // Split workspaces can keep multiple native PTYs visible. The injected fit
    // adapter returns false for hidden/zero-sized viewports, which is the exact
    // presentation authority required here; catalog focus alone is too narrow.
    if (runtime.fit.fit() === false) return;
    const backendSessionId = this.#runtimes.backendSessionIdFor(runtime.id);
    if (!backendSessionId) return;
    runtime.resizeCoordinator.request(backendSessionId, {
      columns: runtime.terminal.cols,
      rows: runtime.terminal.rows,
      pixelWidth: 0,
      pixelHeight: 0,
    });
  }

  fit(id: WorkspaceSessionId): void {
    const runtime = this.#runtimes.getExact(id);
    if (runtime) this.#fitRuntime(runtime);
  }

  fitActive(): void {
    const id = this.#catalog.snapshot.activeSessionId;
    if (id) this.fit(id);
  }

  markViewportReady(id: WorkspaceSessionId): void {
    const runtime = this.#runtimes.getExact(id);
    if (!runtime) return;
    runtime.inputBinding?.bindDom();
    runtime.viewportBarrier.resolve();
    this.#schedule(() => this.#fitRuntime(runtime));
  }

  #disposeRuntime(runtime: MutableLocalTerminalRuntime<TerminalType>): void {
    if (runtime.destroyed) return;
    runtime.destroyed = true;
    disposeSilently(runtime.operation?.handle);
    runtime.operation = null;
    try {
      this.#dependencies.onRuntimeDestroyed?.(runtime);
    } catch {
      // Presentation cleanup cannot retain native/session authority.
    }
    for (const disposable of [...runtime.cwdDisposables].reverse()) {
      disposeSilently(disposable);
    }
    runtime.cwdDisposables = [];
    const inputDisposable = runtime.inputDisposable;
    runtime.inputDisposable = null;
    runtime.inputWriteQueue.invalidate();
    runtime.inputBinding?.dispose();
    runtime.inputBinding = null;
    disposeSilently(inputDisposable);
    disposeSilently(runtime.resizeCoordinator);
    disposeSilently(runtime.terminal);
  }

  #destroyRuntime(id: WorkspaceSessionId): void {
    const runtime = this.#runtimes.deleteExact(id);
    if (runtime) this.#disposeRuntime(runtime);
  }

  #removeSession(id: WorkspaceSessionId): void {
    this.#destroyRuntime(id);
    this.#catalog.remove(id);
    const activeId = this.#catalog.snapshot.activeSessionId;
    if (activeId) {
      const active = this.#runtimes.getExact(activeId);
      if (active) this.#schedule(() => this.#fitRuntime(active));
    }
  }

  #handleControl(
    runtime: MutableLocalTerminalRuntime<TerminalType>,
    operation: LocalTerminalOperation,
    control: SshControlEvent,
  ): void {
    if (!this.#isExactOperation(runtime, operation)) return;
    switch (control.type) {
      case "connecting":
        if (!operation.stopRequested) this.#patchSession(runtime.id, { state: "connecting" });
        break;
      case "connected":
        operation.connected = true;
        if (!operation.stopRequested) this.#patchSession(runtime.id, { state: "connected" });
        break;
      case "error":
        if (!operation.stopRequested) {
          const message = this.#dependencies.translate("terminal.local.startFailed");
          this.#patchSession(runtime.id, { error: message });
          runtime.terminal.writeln(`\r\n\x1b[31m${message}\x1b[0m`);
        }
        break;
      case "exitStatus":
        runtime.terminal.writeln(
          `\r\n\x1b[90m${this.#dependencies.translate("terminal.local.exited", {
            status: control.status,
          })}\x1b[0m`,
        );
        break;
      case "closed": {
        operation.closed = true;
        runtime.trustedCwd = null;
        const backendSessionId = operation.handle?.sessionId;
        operation.handle?.dispose();
        operation.handle = null;
        if (backendSessionId) {
          this.#runtimes.unbindBackendSessionId(runtime.id, backendSessionId);
        }
        runtime.resizeCoordinator.reset();
        runtime.operation = null;
        runtime.terminal.writeln(
          `\r\n\x1b[90m${this.#dependencies.translate("terminal.local.closed")}\x1b[0m`,
        );
        if (operation.removeWhenClosed) {
          this.#removeSession(runtime.id);
        } else {
          this.#patchSession(runtime.id, { state: "disconnected" });
        }
        break;
      }
      case "ready":
      case "eof":
      case "telnetEchoMode":
      case "serialZmodemDetected":
      case "serialZmodemProgress":
      case "serialZmodemCompleted":
      case "serialZmodemCanceled":
      case "serialZmodemError":
        break;
    }
  }

  #handleData(
    runtime: MutableLocalTerminalRuntime<TerminalType>,
    operation: LocalTerminalOperation,
    frame: Uint8Array,
  ): void {
    if (
      !this.#isExactOperation(runtime, operation)
      || operation.stopRequested
      || operation.closed
    ) return;
    // Hidden tabs retain this exact xterm instance and keep receiving output.
    runtime.terminal.write(framePayload(frame));
  }

  async #stopStartedHandle(
    runtime: MutableLocalTerminalRuntime<TerminalType>,
    operation: LocalTerminalOperation,
    handle: LocalTerminalHandle,
  ): Promise<string | null> {
    const primary = operation.connected
      ? this.#dependencies.backend.close
      : this.#dependencies.backend.cancel;
    const fallback = operation.connected
      ? this.#dependencies.backend.cancel
      : this.#dependencies.backend.close;
    try {
      await primary(handle.sessionId);
      operation.stopAcknowledged = true;
      // Native close/cancel commands acknowledge that the stop request was
      // accepted; completion is reported separately through `closed`. An
      // explicit tab close must not remain stuck forever if that final IPC
      // notification is lost. Retiring the local presentation authority here
      // is safe because the accepted native stop continues independently and
      // any late callback is rejected by the exact-runtime guard.
      if (
        operation.removeWhenClosed
        && this.#isExactOperation(runtime, operation)
        && !operation.closed
      ) {
        this.#removeSession(runtime.id);
      }
      return null;
    } catch {
      if (!this.#isExactOperation(runtime, operation) || operation.closed) return null;
      try {
        await fallback(handle.sessionId);
        operation.stopAcknowledged = true;
        if (
          operation.removeWhenClosed
          && this.#isExactOperation(runtime, operation)
          && !operation.closed
        ) {
          this.#removeSession(runtime.id);
        }
        return null;
      } catch {
        if (!this.#isExactOperation(runtime, operation) || operation.closed) return null;
        operation.stopRequested = false;
        const error = this.#dependencies.translate("terminal.runtime.disconnectFailed");
        this.#patchSession(runtime.id, {
          state: operation.connected ? "connected" : "connecting",
          error,
        });
        return error;
      }
    }
  }

  async #startRuntime(
    runtime: MutableLocalTerminalRuntime<TerminalType>,
    preserveScrollback: boolean,
  ): Promise<string | null> {
    if (!this.#isExactRuntime(runtime) || runtime.operation) {
      return "LOCAL_TERMINAL_ALREADY_ACTIVE";
    }
    runtime.inputWriteQueue.invalidate();
    runtime.inputBinding?.reset();
    const operation: LocalTerminalOperation = {
      generation: ++runtime.operationGeneration,
      handle: null,
      connected: false,
      stopRequested: false,
      stopAcknowledged: false,
      closed: false,
      removeWhenClosed: false,
    };
    runtime.operation = operation;
    // A retry starts a new process at the original target. Until that process
    // reports a fresh OSC cwd, the previous generation is no longer current.
    runtime.trustedCwd = null;
    runtime.resizeCoordinator.reset();
    this.#patchSession(runtime.id, { state: "connecting", error: null });
    if (!preserveScrollback) runtime.terminal.clear();
    runtime.terminal.writeln(
      `\x1b[90m${this.#dependencies.translate("terminal.local.opening", {
        target: sessionTitle(runtime.target, this.#dependencies.translate),
      })}\x1b[0m`,
    );

    try {
      await runtime.viewportBarrier.promise;
      if (!this.#isExactOperation(runtime, operation)) return null;
      if (this.#catalog.snapshot.activeSessionId === runtime.id) runtime.fit.fit();
      const callbacks: SshSessionCallbacks = {
        onControl: (control) => this.#handleControl(runtime, operation, control),
        onData: (frame) => this.#handleData(runtime, operation, frame),
      };
      const handle = await this.#dependencies.backend.start({
        shellId: runtime.target.shell.id,
        ...(runtime.target.cwd ? { cwd: runtime.target.cwd } : {}),
        columns: runtime.terminal.cols,
        rows: runtime.terminal.rows,
        environment: {
          term: "xterm-256color",
          colorTerm: "truecolor",
        },
      }, callbacks);
      operation.handle = handle;
      if (!this.#isExactOperation(runtime, operation) || operation.closed) {
        handle.dispose();
        if (!operation.closed) {
          await this.#dependencies.backend.cancel(handle.sessionId).catch(() => undefined);
        }
        return null;
      }
      try {
        this.#runtimes.bindBackendSessionId(runtime.id, handle.sessionId);
      } catch (reason) {
        handle.dispose();
        operation.handle = null;
        await this.#dependencies.backend.cancel(handle.sessionId).catch(() => undefined);
        throw reason;
      }
      if (operation.stopRequested) {
        return await this.#stopStartedHandle(runtime, operation, handle);
      }
      this.#fitRuntime(runtime);
      return null;
    } catch {
      const message = operation.stopRequested
        ? this.#dependencies.translate("terminal.local.startCanceled")
        : this.#dependencies.translate("terminal.local.startFailed");
      if (!this.#isExactOperation(runtime, operation) || operation.closed) return null;
      const backendSessionId = operation.handle?.sessionId;
      operation.handle?.dispose();
      operation.handle = null;
      if (backendSessionId) {
        this.#runtimes.unbindBackendSessionId(runtime.id, backendSessionId);
      }
      runtime.operation = null;
      runtime.resizeCoordinator.reset();
      if (operation.removeWhenClosed) {
        this.#removeSession(runtime.id);
        return null;
      }
      this.#patchSession(runtime.id, {
        state: "disconnected",
        error: operation.stopRequested ? null : message,
      });
      runtime.terminal.writeln(operation.stopRequested
        ? `\r\n\x1b[90m${message}\x1b[0m`
        : `\r\n\x1b[31m${message}\x1b[0m`);
      return operation.stopRequested ? null : message;
    }
  }

  #createRuntime(
    id: WorkspaceSessionId,
    target: LocalTerminalTarget,
  ): MutableLocalTerminalRuntime<TerminalType> {
    const { terminal, fit } = this.#dependencies.createXterm(id, target);
    const runtime: MutableLocalTerminalRuntime<TerminalType> = {
      id,
      target,
      terminal,
      fit,
      resizeCoordinator: INERT_RESIZE_COORDINATOR,
      viewportBarrier: makeViewportBarrier(),
      inputDisposable: null,
      inputBinding: null,
      inputWriteQueue: new TerminalInputWriteQueue(),
      cwdDisposables: [],
      trustedCwd: null,
      operationGeneration: 0,
      operation: null,
      destroyed: false,
    };
    try {
      runtime.resizeCoordinator = this.#dependencies.createResizeCoordinator(
        (backendSessionId, size) => {
          const operation = runtime.operation;
          if (
            !this.#isExactRuntime(runtime)
            || !operation
            || operation.handle?.sessionId !== backendSessionId
            || operation.stopRequested
            || operation.closed
            || this.#runtimes.getByBackendSessionId(backendSessionId) !== runtime
          ) return Promise.resolve();
          return this.#dependencies.backend.resize(backendSessionId, size);
        },
        id,
      );
      const dispatchInput = (input: PreparedTerminalTextInput): void => {
        if (!this.#isExactRuntime(runtime)) return;
        const operation = runtime.operation;
        const backendSessionId = operation?.handle?.sessionId;
        const isCurrent = (): boolean => Boolean(
          !operation
          ? false
          : backendSessionId
            && this.#isExactOperation(runtime, operation)
            && !operation.stopRequested
            && !operation.closed
            && this.#runtimes.getByBackendSessionId(backendSessionId) === runtime,
        );
        if (!operation || !backendSessionId || !isCurrent()) return;
        void runtime.inputWriteQueue.enqueue(
          input.chunks,
          (chunk) => this.#dependencies.backend.sendInput(
            backendSessionId,
            utf8.encode(chunk),
          ),
          isCurrent,
        ).catch(() => undefined);
      };
      runtime.inputBinding = createTerminalInputBinding(terminal, dispatchInput);
      runtime.inputDisposable = terminal.onData(runtime.inputBinding.handleData);
      const parser = terminal.parser;
      if (parser) {
        const cwdPlatform = this.#dependencies.cwdPlatform ?? "windows";
        const track = (cwd: string | null): boolean => {
          if (cwd && this.#isExactRuntime(runtime)) runtime.trustedCwd = cwd;
          return true;
        };
        runtime.cwdDisposables.push(parser.registerOscHandler(7, (payload) => (
          track(parseTrustedLocalOsc7Cwd(payload, cwdPlatform))
        )));
        runtime.cwdDisposables.push(parser.registerOscHandler(9, (payload) => (
          track(parseTrustedLocalOsc9Cwd(payload, cwdPlatform))
        )));
      }
      return runtime;
    } catch (reason) {
      this.#disposeRuntime(runtime);
      throw reason;
    }
  }

  /**
   * Recreate one disconnected presentation runtime without launching a native
   * process. The persisted request carries only an opaque Shell ID; the full
   * launch target is resolved afresh from Rust's current renderer-safe catalog.
   */
  async restoreDisconnected(
    requestInput: LocalTerminalRestoreRequest,
    options: LocalTerminalRestoreOptions = {},
  ): Promise<LocalTerminalOpenResult> {
    if (this.#disposed) throw new Error("LOCAL_TERMINAL_CONTROLLER_DISPOSED");
    const request = normalizeRestoreRequest(requestInput);
    if (
      this.#runtimes.hasExact(request.workspaceSessionId)
      || this.#catalog.snapshot.sessions[request.workspaceSessionId]
    ) {
      throw new Error("LOCAL_TERMINAL_RESTORE_DUPLICATE");
    }
    const listShells = this.#dependencies.backend.listShells;
    if (!listShells) throw new Error("LOCAL_TERMINAL_SHELL_CATALOG_UNAVAILABLE");
    const shells = await listShells();
    if (this.#disposed) throw new Error("LOCAL_TERMINAL_CONTROLLER_DISPOSED");
    const shell = shells.find((candidate) => candidate.id === request.shellId);
    if (!shell) throw new Error("LOCAL_TERMINAL_RESTORE_SHELL_NOT_FOUND");

    const target: LocalTerminalTarget = { shell };
    const runtime = this.#createRuntime(request.workspaceSessionId, target);
    try {
      this.#runtimes.bindExact(request.workspaceSessionId, runtime);
      this.#catalog.add({
        id: request.workspaceSessionId,
        protocol: "local",
        title: sessionTitle(target, this.#dependencies.translate),
        state: "disconnected",
      }, { activate: options.activate ?? true });
    } catch (reason) {
      if (this.#runtimes.getExact(request.workspaceSessionId) === runtime) {
        this.#runtimes.deleteExact(request.workspaceSessionId);
      }
      this.#disposeRuntime(runtime);
      throw reason;
    }
    return { id: request.workspaceSessionId, error: null };
  }

  async open(target: LocalTerminalTarget): Promise<LocalTerminalOpenResult> {
    if (this.#disposed) throw new Error("LOCAL_TERMINAL_CONTROLLER_DISPOSED");
    const id = this.#dependencies.createId?.() ?? createWorkspaceSessionId();
    const runtime = this.#createRuntime(id, target);
    try {
      this.#runtimes.bindExact(id, runtime);
      this.#catalog.add({
        id,
        protocol: "local",
        title: sessionTitle(target, this.#dependencies.translate),
        state: "connecting",
      });
    } catch (reason) {
      if (this.#runtimes.getExact(id) === runtime) this.#runtimes.deleteExact(id);
      this.#disposeRuntime(runtime);
      throw reason;
    }
    const error = await this.#startRuntime(runtime, false);
    return { id, error };
  }

  activate(id: WorkspaceSessionId): void {
    const runtime = this.#runtimes.getExact(id);
    if (!runtime) throw new Error("LOCAL_TERMINAL_SESSION_NOT_FOUND");
    this.#catalog.activate(id);
    this.#schedule(() => {
      if (
        !this.#isExactRuntime(runtime)
        || this.#catalog.snapshot.activeSessionId !== id
      ) return;
      this.#fitRuntime(runtime);
      runtime.terminal.focus();
    });
  }

  async retry(id: WorkspaceSessionId): Promise<string | null> {
    const runtime = this.#runtimes.getExact(id);
    const snapshot = getTerminalSessionSnapshot(this.#catalog.snapshot, id);
    if (!runtime || !snapshot || snapshot.state !== "disconnected" || runtime.operation) {
      return "LOCAL_TERMINAL_RETRY_UNAVAILABLE";
    }
    return await this.#startRuntime(runtime, true);
  }

  async #requestStop(
    id: WorkspaceSessionId,
    removeWhenClosed: boolean,
  ): Promise<string | null> {
    const runtime = this.#runtimes.getExact(id);
    if (!runtime) return null;
    const operation = runtime.operation;
    if (!operation) {
      if (removeWhenClosed) this.#removeSession(id);
      return null;
    }
    operation.removeWhenClosed ||= removeWhenClosed;
    if (operation.stopRequested) {
      // A disconnect whose accepted stop later loses its `closed` event must
      // still be removable through an explicit tab close. Do not retire while
      // the original stop acknowledgement is still pending, because a double
      // failure must keep the live session available to the user.
      if (operation.removeWhenClosed && operation.stopAcknowledged) {
        this.#removeSession(id);
      }
      return null;
    }
    operation.stopRequested = true;
    this.#patchSession(id, { state: "closing", error: null });
    if (!operation.handle) return null;
    return await this.#stopStartedHandle(runtime, operation, operation.handle);
  }

  async disconnect(id: WorkspaceSessionId): Promise<string | null> {
    return await this.#requestStop(id, false);
  }

  async close(id: WorkspaceSessionId): Promise<string | null> {
    return await this.#requestStop(id, true);
  }

  dispose(): void {
    if (this.#disposed) return;
    const ownedIds = this.#catalog.snapshot.order.filter((id) => this.#runtimes.hasExact(id));
    this.#disposed = true;
    this.#unsubscribeCatalog();
    for (const frameId of this.#scheduledFrames) {
      this.#dependencies.scheduler.cancel(frameId);
    }
    this.#scheduledFrames.clear();
    for (const id of ownedIds) {
      const runtime = this.#runtimes.getExact(id);
      const backendSessionId = runtime?.operation?.handle?.sessionId;
      if (backendSessionId) {
        void this.#dependencies.backend.cancel(backendSessionId).catch(() => undefined);
      }
      this.#destroyRuntime(id);
      this.#catalog.remove(id);
    }
  }
}
