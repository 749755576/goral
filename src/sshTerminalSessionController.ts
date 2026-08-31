import type {
  SshControlEvent,
  SshSessionCallbacks,
  TerminalSize,
} from "./backend.ts";
import type { TerminalSessionCatalog } from "./terminalSessionCatalog.ts";
import {
  createWorkspaceSessionId,
  getTerminalSessionSnapshot,
  TerminalSessionRuntimeRegistry,
  workspaceSessionIdFrom,
  type TerminalSessionRegistrySnapshot,
  type TerminalSessionSnapshot,
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

export type SshTerminalTarget = Readonly<{
  kind: "quick" | "saved";
  title: string;
  hostname: string;
  port: number;
  username: string;
  savedHostId?: string;
  appearanceOverride?: SshTerminalAppearanceOverride;
}>;

/** Safe, presentation-only SavedHost/Group appearance captured for this tab. */
export type SshTerminalAppearanceOverride = Readonly<{
  themeId?: string;
  fontFamily?: string;
  fontSize?: number;
  fontWeight?: number;
}>;

export type SshClientAttemptId = string & {
  readonly __sshClientAttemptId: unique symbol;
};

export type SshTerminalHandle = Readonly<{
  sessionId: string;
  dispose: () => void;
}>;

/**
 * A one-shot starter supplied by the form/workspace layer for one attempt.
 *
 * Credential references, selected native paths, and plaintext secrets may be
 * captured by this callback while the attempt is pending, but the controller
 * never stores it on the runtime and never reuses it for retry.
 */
export type SshTerminalStart = (
  callbacks: SshSessionCallbacks,
  initialSize: TerminalSize,
  clientAttemptId: SshClientAttemptId,
) => Promise<SshTerminalHandle>;

export type SshTerminalAttempt = Readonly<{
  clientAttemptId: SshClientAttemptId;
  start: SshTerminalStart;
}>;

export type SshTerminalBackend = Readonly<{
  sendInput: (sessionId: string, data: Uint8Array) => Promise<void>;
  resize: (sessionId: string, size: TerminalSize) => Promise<void>;
  close: (sessionId: string) => Promise<void>;
  cancel: (sessionId: string) => Promise<void>;
}>;

export type SshTerminalDisposable = Readonly<{
  dispose: () => void;
}>;

export type SshTerminalXterm = TerminalContextSource & {
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
  onData: (listener: (data: string) => void) => SshTerminalDisposable;
  dispose: () => void;
};

export type SshTerminalFit = Readonly<{
  /** Returning false suppresses resize while the viewport has no layout. */
  fit: () => boolean | void;
}>;

export type SshTerminalResizeCoordinator = Readonly<{
  request: (sessionId: string, size: TerminalSize) => void;
  reset: () => void;
  dispose: () => void;
}>;

export type SshTerminalFrameScheduler = Readonly<{
  request: (callback: () => void) => number;
  cancel: (frameId: number) => void;
}>;

type ViewportBarrier = {
  promise: Promise<void>;
  resolve: () => void;
  resolved: boolean;
};

type SshTerminalOperation = {
  generation: number;
  clientAttemptId: SshClientAttemptId;
  handle: SshTerminalHandle | null;
  connected: boolean;
  stopRequested: boolean;
  closed: boolean;
  removeWhenClosed: boolean;
};

export type SshTerminalRuntime<TerminalType extends SshTerminalXterm> = {
  readonly id: WorkspaceSessionId;
  readonly target: SshTerminalTarget;
  readonly terminal: TerminalType;
  readonly fit: SshTerminalFit;
  readonly resizeCoordinator: SshTerminalResizeCoordinator;
  readonly operationGeneration: number;
  readonly destroyed: boolean;
};

type MutableSshTerminalRuntime<TerminalType extends SshTerminalXterm> = {
  id: WorkspaceSessionId;
  target: SshTerminalTarget;
  terminal: TerminalType;
  fit: SshTerminalFit;
  resizeCoordinator: SshTerminalResizeCoordinator;
  viewportBarrier: ViewportBarrier;
  inputDisposable: SshTerminalDisposable | null;
  inputBinding: TerminalInputBinding | null;
  inputWriteQueue: TerminalInputWriteQueue;
  operationGeneration: number;
  operation: SshTerminalOperation | null;
  destroyed: boolean;
};

export type SshTerminalSessionControllerDependencies<
  TerminalType extends SshTerminalXterm,
> = Readonly<{
  catalog: TerminalSessionCatalog;
  backend: SshTerminalBackend;
  createXterm: (
    id: WorkspaceSessionId,
    target: SshTerminalTarget,
  ) => Readonly<{ terminal: TerminalType; fit: SshTerminalFit }>;
  createResizeCoordinator: (
    transport: (sessionId: string, size: TerminalSize) => Promise<void>,
    id: WorkspaceSessionId,
  ) => SshTerminalResizeCoordinator;
  scheduler: SshTerminalFrameScheduler;
  /** Resolves every renderer-visible status without reflecting backend text. */
  translate: Translate;
  createId?: () => WorkspaceSessionId;
  now?: () => number;
  onRuntimeDestroyed?: (runtime: SshTerminalRuntime<TerminalType>) => void;
}>;

export type SshTerminalOpenResult = Readonly<{
  id: WorkspaceSessionId;
  error: string | null;
}>;

/**
 * Synchronous renderer-only notification for a newly registered SSH tab.
 *
 * The callback receives only the opaque workspace ID. It never receives the
 * one-shot starter, credentials, attempt ID, or a native backend session ID.
 * Observer failures are intentionally isolated from the session lifecycle.
 */
export type SshTerminalSessionCreated = (id: WorkspaceSessionId) => void;

export type SshTerminalOpenOptions = Readonly<{
  onSessionCreated?: SshTerminalSessionCreated;
}>;

export type SshTerminalRestoreOptions = Readonly<{
  activate?: boolean;
}>;

const INERT_RESIZE_COORDINATOR: SshTerminalResizeCoordinator = Object.freeze({
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

const TARGET_TEXT_LIMIT = 512;
const HOSTNAME_TEXT_LIMIT = 1024;
const CLIENT_ATTEMPT_RETIREMENT_TTL_MS = 5 * 60 * 1_000;
const CLIENT_ATTEMPT_GUARD_LIMIT = 4_096;
const CLIENT_ATTEMPT_ID_PATTERN = /^attempt-[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const utf8 = new TextEncoder();

const assertSafeText = (
  value: string,
  field: string,
  maximumBytes: number,
  allowEmpty = false,
): string => {
  if (
    typeof value !== "string"
    || (!allowEmpty && value.trim().length === 0)
    || utf8.encode(value).byteLength > maximumBytes
    || /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new Error(`${field.toUpperCase()}_INVALID`);
  }
  return value;
};

export const sshClientAttemptIdFrom = (value: string): SshClientAttemptId => {
  if (typeof value !== "string" || !CLIENT_ATTEMPT_ID_PATTERN.test(value)) {
    throw new Error("SSH_CLIENT_ATTEMPT_ID_INVALID");
  }
  return value as SshClientAttemptId;
};

export const createSshClientAttemptId = (
  randomUuid: () => string = () => crypto.randomUUID(),
): SshClientAttemptId => sshClientAttemptIdFrom(`attempt-${randomUuid()}`);

const sanitizeAppearanceOverride = (
  appearance: SshTerminalAppearanceOverride | undefined,
): SshTerminalAppearanceOverride | undefined => {
  if (appearance === undefined) return undefined;
  const fontSize = appearance.fontSize;
  const fontWeight = appearance.fontWeight;
  if (fontSize !== undefined && (!Number.isFinite(fontSize) || fontSize < 4 || fontSize > 256)) {
    throw new Error("SSH_TERMINAL_APPEARANCE_FONT_SIZE_INVALID");
  }
  if (
    fontWeight !== undefined
    && (!Number.isFinite(fontWeight) || fontWeight < 100 || fontWeight > 900)
  ) {
    throw new Error("SSH_TERMINAL_APPEARANCE_FONT_WEIGHT_INVALID");
  }
  return Object.freeze({
    ...(appearance.themeId === undefined ? {} : {
      themeId: assertSafeText(
        appearance.themeId,
        "ssh_terminal_appearance_theme_id",
        TARGET_TEXT_LIMIT,
        true,
      ),
    }),
    ...(appearance.fontFamily === undefined ? {} : {
      fontFamily: assertSafeText(
        appearance.fontFamily,
        "ssh_terminal_appearance_font_family",
        TARGET_TEXT_LIMIT,
        true,
      ),
    }),
    ...(fontSize === undefined ? {} : { fontSize }),
    ...(fontWeight === undefined ? {} : { fontWeight }),
  });
};

const sanitizeTarget = (target: SshTerminalTarget): SshTerminalTarget => {
  if (target.kind !== "quick" && target.kind !== "saved") {
    throw new Error("SSH_TERMINAL_TARGET_KIND_INVALID");
  }
  if (!Number.isSafeInteger(target.port) || target.port < 1 || target.port > 65_535) {
    throw new Error("SSH_TERMINAL_TARGET_PORT_INVALID");
  }
  const savedHostId = target.savedHostId === undefined
    ? undefined
    : assertSafeText(target.savedHostId, "ssh_terminal_saved_host_id", TARGET_TEXT_LIMIT);
  if (target.kind === "saved" && savedHostId === undefined) {
    throw new Error("SSH_TERMINAL_SAVED_HOST_ID_REQUIRED");
  }
  if (target.kind === "quick" && savedHostId !== undefined) {
    throw new Error("SSH_TERMINAL_SAVED_HOST_ID_INVALID");
  }
  const appearanceOverride = sanitizeAppearanceOverride(target.appearanceOverride);
  return Object.freeze({
    kind: target.kind,
    title: assertSafeText(target.title, "ssh_terminal_title", TARGET_TEXT_LIMIT),
    hostname: assertSafeText(target.hostname, "ssh_terminal_hostname", HOSTNAME_TEXT_LIMIT),
    port: target.port,
    username: assertSafeText(
      target.username,
      "ssh_terminal_username",
      TARGET_TEXT_LIMIT,
      true,
    ),
    ...(savedHostId === undefined ? {} : { savedHostId }),
    ...(appearanceOverride === undefined ? {} : { appearanceOverride }),
  });
};

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

const framePayload = (frame: Uint8Array): Uint8Array => (
  frame.subarray(frame[0] === 1 ? 5 : 1)
);

/**
 * Owns SSH terminal authority while sharing only serializable tab state with
 * other protocol controllers through TerminalSessionCatalog.
 */
export class SshTerminalSessionController<
  TerminalType extends SshTerminalXterm,
> {
  readonly #dependencies: SshTerminalSessionControllerDependencies<TerminalType>;
  readonly #runtimes = new TerminalSessionRuntimeRegistry<
    MutableSshTerminalRuntime<TerminalType>
  >();
  readonly #scheduledFrames = new Set<number>();
  readonly #attemptToWorkspace = new Map<SshClientAttemptId, WorkspaceSessionId>();
  readonly #retiredAttemptIds = new Map<SshClientAttemptId, number>();
  #lastAttemptClock = Number.NEGATIVE_INFINITY;
  #disposed = false;

  constructor(dependencies: SshTerminalSessionControllerDependencies<TerminalType>) {
    this.#dependencies = dependencies;
  }

  get registry(): TerminalSessionRegistrySnapshot {
    return this.#dependencies.catalog.snapshot;
  }

  get activeSession(): TerminalSessionSnapshot | null {
    const id = this.registry.activeSessionId;
    if (!id || !this.#runtimes.hasExact(id)) return null;
    return getTerminalSessionSnapshot(this.registry, id) ?? null;
  }

  owns(id: WorkspaceSessionId): boolean {
    return this.#runtimes.hasExact(id);
  }

  hasSessions(): boolean {
    return this.#runtimes.size > 0;
  }

  getRuntime(id: WorkspaceSessionId): SshTerminalRuntime<TerminalType> | undefined {
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
   * Send exact text to one connected SSH generation. This does not echo,
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

  workspaceSessionIdForAttempt(clientAttemptId: string): WorkspaceSessionId | undefined {
    if (!CLIENT_ATTEMPT_ID_PATTERN.test(clientAttemptId)) return undefined;
    return this.#attemptToWorkspace.get(clientAttemptId as SshClientAttemptId);
  }

  isExactAttemptRoute(
    clientAttemptId: string,
    workspaceSessionId: WorkspaceSessionId,
  ): boolean {
    return this.workspaceSessionIdForAttempt(clientAttemptId) === workspaceSessionId
      && this.#runtimes.hasExact(workspaceSessionId);
  }

  #patchSession(
    id: WorkspaceSessionId,
    update: Parameters<TerminalSessionCatalog["update"]>[1],
  ): void {
    this.#dependencies.catalog.update(id, update);
  }

  #isExactRuntime(runtime: MutableSshTerminalRuntime<TerminalType>): boolean {
    return !this.#disposed
      && !runtime.destroyed
      && this.#runtimes.getExact(runtime.id) === runtime;
  }

  #isExactOperation(
    runtime: MutableSshTerminalRuntime<TerminalType>,
    operation: SshTerminalOperation,
  ): boolean {
    return this.#isExactRuntime(runtime)
      && runtime.operation === operation
      && runtime.operationGeneration === operation.generation;
  }

  #bindAttemptRoute(
    runtime: MutableSshTerminalRuntime<TerminalType>,
    operation: SshTerminalOperation,
  ): void {
    const now = this.#attemptClock();
    this.#pruneRetiredAttemptIds(now);
    if (
      this.#attemptToWorkspace.has(operation.clientAttemptId)
      || this.#retiredAttemptIds.has(operation.clientAttemptId)
    ) {
      throw new Error("SSH_CLIENT_ATTEMPT_ID_DUPLICATE");
    }
    if (
      this.#attemptToWorkspace.size + this.#retiredAttemptIds.size
      >= CLIENT_ATTEMPT_GUARD_LIMIT
    ) {
      throw new Error("SSH_CLIENT_ATTEMPT_ID_GUARD_SATURATED");
    }
    this.#attemptToWorkspace.set(operation.clientAttemptId, runtime.id);
  }

  #attemptClock(): number {
    const sampled = this.#dependencies.now?.() ?? Date.now();
    if (!Number.isFinite(sampled)) throw new Error("SSH_CLIENT_ATTEMPT_CLOCK_INVALID");
    this.#lastAttemptClock = Math.max(this.#lastAttemptClock, sampled);
    return this.#lastAttemptClock;
  }

  #pruneRetiredAttemptIds(now: number): void {
    for (const [clientAttemptId, retiredAt] of this.#retiredAttemptIds) {
      if (now - retiredAt < CLIENT_ATTEMPT_RETIREMENT_TTL_MS) break;
      this.#retiredAttemptIds.delete(clientAttemptId);
    }
  }

  #unbindExactAttemptRoute(
    runtime: MutableSshTerminalRuntime<TerminalType>,
    operation: SshTerminalOperation,
  ): boolean {
    if (this.#attemptToWorkspace.get(operation.clientAttemptId) !== runtime.id) return false;
    this.#attemptToWorkspace.delete(operation.clientAttemptId);
    this.#retiredAttemptIds.set(operation.clientAttemptId, this.#attemptClock());
    return true;
  }

  #schedule(callback: () => void): void {
    if (this.#disposed) return;
    let frameId: number | undefined;
    let completedSynchronously = false;
    frameId = this.#dependencies.scheduler.request(() => {
      completedSynchronously = true;
      if (frameId !== undefined) this.#scheduledFrames.delete(frameId);
      if (!this.#disposed) callback();
    });
    if (!completedSynchronously) this.#scheduledFrames.add(frameId);
  }

  #fitRuntime(runtime: MutableSshTerminalRuntime<TerminalType>): void {
    if (
      !this.#isExactRuntime(runtime)
      || !runtime.viewportBarrier.resolved
    ) return;
    // A split workspace can expose several exact runtimes at once. The view's
    // fit adapter rejects hidden/zero-sized panes, so visibility rather than
    // global tab focus decides whether a native resize may be published.
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
    const id = this.registry.activeSessionId;
    if (id && this.#runtimes.hasExact(id)) this.fit(id);
  }

  markViewportReady(id: WorkspaceSessionId): void {
    const runtime = this.#runtimes.getExact(id);
    if (!runtime) return;
    runtime.inputBinding?.bindDom();
    runtime.viewportBarrier.resolve();
    this.#schedule(() => this.#fitRuntime(runtime));
  }

  #disposeRuntimeResources(runtime: MutableSshTerminalRuntime<TerminalType>): void {
    if (runtime.destroyed) return;
    runtime.destroyed = true;
    try {
      if (runtime.operation) this.#unbindExactAttemptRoute(runtime, runtime.operation);
    } catch {
      // Route retirement failure cannot block renderer resource cleanup.
    }
    disposeSilently(runtime.operation?.handle);
    runtime.operation = null;
    try {
      this.#dependencies.onRuntimeDestroyed?.(runtime);
    } catch {
      // Presentation cleanup cannot retain terminal/session authority.
    }
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
    if (runtime) this.#disposeRuntimeResources(runtime);
  }

  #removeSession(id: WorkspaceSessionId): void {
    this.#destroyRuntime(id);
    this.#dependencies.catalog.remove(id);
    const activeId = this.registry.activeSessionId;
    if (activeId) {
      const active = this.#runtimes.getExact(activeId);
      if (active) this.#schedule(() => this.#fitRuntime(active));
    }
  }

  #handleControl(
    runtime: MutableSshTerminalRuntime<TerminalType>,
    operation: SshTerminalOperation,
    control: SshControlEvent,
  ): void {
    if (!this.#isExactOperation(runtime, operation)) return;
    switch (control.type) {
      case "connecting":
        if (!operation.stopRequested) this.#patchSession(runtime.id, { state: "connecting" });
        break;
      case "connected":
        operation.connected = true;
        this.#unbindExactAttemptRoute(runtime, operation);
        if (!operation.stopRequested) this.#patchSession(runtime.id, { state: "connected" });
        break;
      case "error":
        if (!operation.stopRequested) {
          const message = this.#dependencies.translate("terminal.runtime.sshFailed");
          this.#patchSession(runtime.id, { error: message });
          runtime.terminal.writeln(`\r\n\x1b[31m${message}\x1b[0m`);
        }
        break;
      case "exitStatus":
        runtime.terminal.writeln(
          `\r\n\x1b[90m${this.#dependencies.translate("terminal.runtime.remoteExited", {
            status: control.status,
          })}\x1b[0m`,
        );
        break;
      case "closed": {
        operation.closed = true;
        this.#unbindExactAttemptRoute(runtime, operation);
        const backendSessionId = operation.handle?.sessionId;
        operation.handle?.dispose();
        operation.handle = null;
        if (backendSessionId) {
          this.#runtimes.unbindBackendSessionId(runtime.id, backendSessionId);
        }
        runtime.resizeCoordinator.reset();
        runtime.operation = null;
        runtime.terminal.writeln(
          `\r\n\x1b[90m${this.#dependencies.translate("terminal.runtime.connectionClosed")}\x1b[0m`,
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
    runtime: MutableSshTerminalRuntime<TerminalType>,
    operation: SshTerminalOperation,
    frame: Uint8Array,
  ): void {
    if (
      !this.#isExactOperation(runtime, operation)
      || operation.stopRequested
      || operation.closed
    ) return;
    runtime.terminal.write(framePayload(frame));
  }

  async #stopStartedHandle(
    runtime: MutableSshTerminalRuntime<TerminalType>,
    operation: SshTerminalOperation,
    handle: SshTerminalHandle,
  ): Promise<string | null> {
    const primary = operation.connected
      ? this.#dependencies.backend.close
      : this.#dependencies.backend.cancel;
    const fallback = operation.connected
      ? this.#dependencies.backend.cancel
      : this.#dependencies.backend.close;
    try {
      await primary(handle.sessionId);
      return null;
    } catch {
      if (!this.#isExactOperation(runtime, operation) || operation.closed) return null;
      try {
        await fallback(handle.sessionId);
        return null;
      } catch {
        if (!this.#isExactOperation(runtime, operation) || operation.closed) return null;
        operation.stopRequested = false;
        const error = this.#dependencies.translate("terminal.runtime.disconnectFailed");
        this.#patchSession(runtime.id, {
          state: operation.connected ? "connected" : "connecting",
          error,
        });
        runtime.terminal.writeln(`\r\n\x1b[31m${error}\x1b[0m`);
        return error;
      }
    }
  }

  async #startRuntime(
    runtime: MutableSshTerminalRuntime<TerminalType>,
    attempt: SshTerminalAttempt,
    preserveScrollback: boolean,
  ): Promise<string | null> {
    if (!this.#isExactRuntime(runtime) || runtime.operation) {
      return "SSH_TERMINAL_ALREADY_ACTIVE";
    }
    runtime.inputWriteQueue.invalidate();
    runtime.inputBinding?.reset();
    const clientAttemptId = sshClientAttemptIdFrom(attempt.clientAttemptId);
    if (typeof attempt.start !== "function") throw new Error("SSH_TERMINAL_START_INVALID");
    const operation: SshTerminalOperation = {
      generation: ++runtime.operationGeneration,
      clientAttemptId,
      handle: null,
      connected: false,
      stopRequested: false,
      closed: false,
      removeWhenClosed: false,
    };
    this.#bindAttemptRoute(runtime, operation);
    runtime.operation = operation;
    runtime.resizeCoordinator.reset();
    this.#patchSession(runtime.id, { state: "connecting", error: null });
    if (!preserveScrollback) runtime.terminal.clear();
    runtime.terminal.writeln(
      `\x1b[90m${this.#dependencies.translate("terminal.runtime.connecting", {
        target: `${runtime.target.hostname}:${runtime.target.port}`,
      })}\x1b[0m`,
    );

    try {
      await runtime.viewportBarrier.promise;
      if (!this.#isExactOperation(runtime, operation)) return null;
      if (this.registry.activeSessionId === runtime.id) runtime.fit.fit();
      const callbacks: SshSessionCallbacks = {
        onControl: (control) => this.#handleControl(runtime, operation, control),
        onData: (frame) => this.#handleData(runtime, operation, frame),
      };
      const handle = await attempt.start(callbacks, {
        columns: runtime.terminal.cols,
        rows: runtime.terminal.rows,
        pixelWidth: 0,
        pixelHeight: 0,
      }, operation.clientAttemptId);
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
        ? this.#dependencies.translate("terminal.runtime.connectionCanceled")
        : this.#dependencies.translate("terminal.runtime.sshFailed");
      if (!this.#isExactOperation(runtime, operation) || operation.closed) return null;
      this.#unbindExactAttemptRoute(runtime, operation);
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
    target: SshTerminalTarget,
  ): MutableSshTerminalRuntime<TerminalType> {
    const { terminal, fit } = this.#dependencies.createXterm(id, target);
    const runtime: MutableSshTerminalRuntime<TerminalType> = {
      id,
      target,
      terminal,
      fit,
      resizeCoordinator: INERT_RESIZE_COORDINATOR,
      viewportBarrier: makeViewportBarrier(),
      inputDisposable: null,
      inputBinding: null,
      inputWriteQueue: new TerminalInputWriteQueue(),
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
      return runtime;
    } catch (reason) {
      this.#disposeRuntimeResources(runtime);
      throw reason;
    }
  }

  /** Recreate a renderer-only disconnected tab without starting native SSH. */
  async restoreDisconnected(
    idInput: WorkspaceSessionId,
    targetInput: SshTerminalTarget,
    options: SshTerminalRestoreOptions = {},
  ): Promise<SshTerminalOpenResult> {
    if (this.#disposed) throw new Error("SSH_TERMINAL_CONTROLLER_DISPOSED");
    const id = workspaceSessionIdFrom(idInput);
    const target = sanitizeTarget(targetInput);
    if (this.#runtimes.hasExact(id) || this.registry.sessions[id]) {
      throw new Error("SSH_TERMINAL_RESTORE_DUPLICATE");
    }

    const runtime = this.#createRuntime(id, target);
    try {
      this.#runtimes.bindExact(id, runtime);
      this.#dependencies.catalog.add({
        id,
        protocol: "ssh",
        title: target.title,
        state: "disconnected",
      }, { activate: options.activate ?? true });
    } catch (reason) {
      if (this.#runtimes.getExact(id) === runtime) {
        this.#runtimes.deleteExact(id);
      }
      this.#disposeRuntimeResources(runtime);
      throw reason;
    }
    return { id, error: null };
  }

  async open(
    targetInput: SshTerminalTarget,
    attempt: SshTerminalAttempt,
    options: SshTerminalOpenOptions = {},
  ): Promise<SshTerminalOpenResult> {
    if (this.#disposed) throw new Error("SSH_TERMINAL_CONTROLLER_DISPOSED");
    const target = sanitizeTarget(targetInput);
    const id = this.#dependencies.createId?.() ?? createWorkspaceSessionId();
    const runtime = this.#createRuntime(id, target);
    try {
      this.#runtimes.bindExact(id, runtime);
      this.#dependencies.catalog.add({
        id,
        protocol: "ssh",
        title: target.title,
        state: "connecting",
      });
    } catch (reason) {
      this.#runtimes.deleteExact(id);
      this.#disposeRuntimeResources(runtime);
      throw reason;
    }
    try {
      options.onSessionCreated?.(id);
    } catch {
      // This is a best-effort renderer notification. An observer exception
      // must not abort, leak, or otherwise change the registered SSH runtime.
    }
    try {
      const error = await this.#startRuntime(runtime, attempt, false);
      return { id, error };
    } catch (reason) {
      if (this.#runtimes.getExact(id) === runtime) this.#removeSession(id);
      throw reason;
    }
  }

  activate(id: WorkspaceSessionId): void {
    const runtime = this.#runtimes.getExact(id);
    if (!runtime) throw new Error("SSH_TERMINAL_SESSION_NOT_FOUND");
    this.#dependencies.catalog.activate(id);
    this.#schedule(() => {
      if (!this.#isExactRuntime(runtime) || this.registry.activeSessionId !== id) return;
      this.#fitRuntime(runtime);
      runtime.terminal.focus();
    });
  }

  async retry(
    id: WorkspaceSessionId,
    attempt: SshTerminalAttempt,
  ): Promise<string | null> {
    const runtime = this.#runtimes.getExact(id);
    const snapshot = getTerminalSessionSnapshot(this.registry, id);
    if (!runtime || !snapshot || snapshot.state !== "disconnected" || runtime.operation) {
      return "SSH_TERMINAL_RETRY_UNAVAILABLE";
    }
    return await this.#startRuntime(runtime, attempt, true);
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
    if (operation.stopRequested) return null;
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
    for (const frameId of this.#scheduledFrames) {
      this.#dependencies.scheduler.cancel(frameId);
    }
    this.#scheduledFrames.clear();
    const ownedIds = this.registry.order.filter((id) => this.#runtimes.hasExact(id));
    for (const id of ownedIds) {
      const runtime = this.#runtimes.getExact(id);
      const backendSessionId = runtime?.operation?.handle?.sessionId;
      if (backendSessionId) {
        void this.#dependencies.backend.cancel(backendSessionId).catch(() => undefined);
      }
      this.#destroyRuntime(id);
      this.#dependencies.catalog.remove(id);
    }
    this.#attemptToWorkspace.clear();
    this.#retiredAttemptIds.clear();
    this.#disposed = true;
  }
}
