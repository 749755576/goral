/**
 * Stable renderer-owned identity for one terminal tab.
 *
 * This is intentionally distinct from a native protocol session ID. The UI
 * identity exists before a native session starts and survives an explicit
 * reconnect that produces a different native ID.
 */
export type WorkspaceSessionId = string & {
  readonly __workspaceSessionId: unique symbol;
};

export type TerminalSessionProtocol =
  | "ssh"
  | "telnet"
  | "mosh"
  | "et"
  | "serial"
  | "local";

export type TerminalSessionState =
  | "disconnected"
  | "connecting"
  | "connected"
  | "closing";

/**
 * The complete React-facing session shape. Keep this deliberately small and
 * serializable: native handles, xterm instances, operations, transfer owners,
 * credentials, and other authority-bearing objects belong in
 * TerminalSessionRuntimeRegistry instead.
 */
export type TerminalSessionSnapshot = Readonly<{
  id: WorkspaceSessionId;
  protocol: TerminalSessionProtocol;
  title: string;
  state: TerminalSessionState;
  error: string | null;
}>;

export type TerminalSessionRegistrySnapshot = Readonly<{
  order: readonly WorkspaceSessionId[];
  activeSessionId: WorkspaceSessionId | null;
  sessions: Readonly<Record<string, TerminalSessionSnapshot>>;
}>;

export type CreateTerminalSessionSnapshot = Readonly<{
  id: WorkspaceSessionId;
  protocol: TerminalSessionProtocol;
  title: string;
  state?: TerminalSessionState;
  error?: string | null;
}>;

export type TerminalSessionSnapshotUpdate = Readonly<{
  title?: string;
  state?: TerminalSessionState;
  error?: string | null;
}>;

export const MAX_WORKSPACE_SESSIONS = 64;

const MAX_SESSION_TITLE_BYTES = 512;
const MAX_SESSION_ERROR_BYTES = 4 * 1024;
const WORKSPACE_SESSION_ID_PATTERN = /^ws-[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const BACKEND_SESSION_ID_MAX_BYTES = 256;
const utf8 = new TextEncoder();
const TERMINAL_SESSION_PROTOCOLS = new Set<TerminalSessionProtocol>([
  "ssh",
  "telnet",
  "mosh",
  "et",
  "serial",
  "local",
]);
const TERMINAL_SESSION_STATES = new Set<TerminalSessionState>([
  "disconnected",
  "connecting",
  "connected",
  "closing",
]);

const byteLength = (value: string): number => utf8.encode(value).byteLength;

const assertBoundedText = (
  value: string,
  field: string,
  maximumBytes: number,
  allowEmpty: boolean,
): void => {
  if (typeof value !== "string") throw new Error(`${field.toUpperCase()}_INVALID`);
  if ((!allowEmpty && value.trim().length === 0) || byteLength(value) > maximumBytes) {
    throw new Error(`${field.toUpperCase()}_INVALID`);
  }
};

const assertSessionLimit = (limit: number): void => {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_WORKSPACE_SESSIONS) {
    throw new Error("WORKSPACE_SESSION_LIMIT_INVALID");
  }
};

export const isWorkspaceSessionId = (value: unknown): value is WorkspaceSessionId => (
  typeof value === "string" && WORKSPACE_SESSION_ID_PATTERN.test(value)
);

export const workspaceSessionIdFrom = (value: string): WorkspaceSessionId => {
  if (!isWorkspaceSessionId(value)) throw new Error("WORKSPACE_SESSION_ID_INVALID");
  return value;
};

export const createWorkspaceSessionId = (
  randomUuid: () => string = () => crypto.randomUUID(),
): WorkspaceSessionId => workspaceSessionIdFrom(`ws-${randomUuid()}`);

const freezeSnapshot = (
  input: CreateTerminalSessionSnapshot | TerminalSessionSnapshot,
): TerminalSessionSnapshot => {
  if (!isWorkspaceSessionId(input.id)) throw new Error("WORKSPACE_SESSION_ID_INVALID");
  if (!TERMINAL_SESSION_PROTOCOLS.has(input.protocol)) {
    throw new Error("WORKSPACE_SESSION_PROTOCOL_INVALID");
  }
  if (input.state !== undefined && !TERMINAL_SESSION_STATES.has(input.state)) {
    throw new Error("WORKSPACE_SESSION_STATE_INVALID");
  }
  assertBoundedText(input.title, "workspace_session_title", MAX_SESSION_TITLE_BYTES, false);
  if (input.error !== undefined && input.error !== null) {
    assertBoundedText(input.error, "workspace_session_error", MAX_SESSION_ERROR_BYTES, true);
  }
  return Object.freeze({
    id: input.id,
    protocol: input.protocol,
    title: input.title,
    state: input.state ?? "connecting",
    error: input.error ?? null,
  });
};

const freezeRegistry = (
  order: readonly WorkspaceSessionId[],
  activeSessionId: WorkspaceSessionId | null,
  sessions: Readonly<Record<string, TerminalSessionSnapshot>>,
): TerminalSessionRegistrySnapshot => Object.freeze({
  order: Object.freeze([...order]),
  activeSessionId,
  sessions: Object.freeze({ ...sessions }),
});

export const createTerminalSessionRegistrySnapshot = (): TerminalSessionRegistrySnapshot => (
  freezeRegistry([], null, {})
);

export const getTerminalSessionSnapshot = (
  registry: TerminalSessionRegistrySnapshot,
  id: WorkspaceSessionId,
): TerminalSessionSnapshot | undefined => registry.sessions[id];

export const addTerminalSessionSnapshot = (
  registry: TerminalSessionRegistrySnapshot,
  input: CreateTerminalSessionSnapshot,
  options: Readonly<{ activate?: boolean; limit?: number }> = {},
): TerminalSessionRegistrySnapshot => {
  const limit = options.limit ?? MAX_WORKSPACE_SESSIONS;
  assertSessionLimit(limit);
  const next = freezeSnapshot(input);
  if (registry.sessions[next.id]) throw new Error("WORKSPACE_SESSION_DUPLICATE");
  if (registry.order.length >= limit) throw new Error("WORKSPACE_SESSION_LIMIT_REACHED");

  return freezeRegistry(
    [...registry.order, next.id],
    options.activate === false && registry.activeSessionId !== null
      ? registry.activeSessionId
      : next.id,
    { ...registry.sessions, [next.id]: next },
  );
};

export const activateTerminalSessionSnapshot = (
  registry: TerminalSessionRegistrySnapshot,
  id: WorkspaceSessionId,
): TerminalSessionRegistrySnapshot => {
  if (!isWorkspaceSessionId(id) || !registry.sessions[id]) {
    throw new Error("WORKSPACE_SESSION_NOT_FOUND");
  }
  if (registry.activeSessionId === id) return registry;
  return freezeRegistry(registry.order, id, registry.sessions);
};

export const updateTerminalSessionSnapshot = (
  registry: TerminalSessionRegistrySnapshot,
  id: WorkspaceSessionId,
  update: TerminalSessionSnapshotUpdate,
): TerminalSessionRegistrySnapshot => {
  if (!isWorkspaceSessionId(id)) throw new Error("WORKSPACE_SESSION_ID_INVALID");
  const current = registry.sessions[id];
  // A late callback from a retired session is harmless and must not be
  // redirected to whichever tab happens to be active now.
  if (!current) return registry;

  const next = freezeSnapshot({
    id: current.id,
    protocol: current.protocol,
    title: update.title ?? current.title,
    state: update.state ?? current.state,
    error: update.error === undefined ? current.error : update.error,
  });
  if (
    next.title === current.title
    && next.state === current.state
    && next.error === current.error
  ) return registry;

  return freezeRegistry(registry.order, registry.activeSessionId, {
    ...registry.sessions,
    [id]: next,
  });
};

export const removeTerminalSessionSnapshot = (
  registry: TerminalSessionRegistrySnapshot,
  id: WorkspaceSessionId,
): TerminalSessionRegistrySnapshot => {
  if (!isWorkspaceSessionId(id)) throw new Error("WORKSPACE_SESSION_ID_INVALID");
  const removedIndex = registry.order.indexOf(id);
  if (removedIndex < 0 || !registry.sessions[id]) return registry;

  const nextOrder = registry.order.filter((candidate) => candidate !== id);
  const nextSessions: Record<string, TerminalSessionSnapshot> = {};
  for (const candidate of nextOrder) {
    const snapshot = registry.sessions[candidate];
    if (snapshot) nextSessions[candidate] = snapshot;
  }

  let nextActiveSessionId = registry.activeSessionId;
  if (registry.activeSessionId === id) {
    // Prefer the original right neighbour, then the original left neighbour.
    nextActiveSessionId = registry.order[removedIndex + 1]
      ?? registry.order[removedIndex - 1]
      ?? null;
  }

  return freezeRegistry(nextOrder, nextActiveSessionId, nextSessions);
};

const assertBackendSessionId = (value: string): void => {
  assertBoundedText(value, "backend_session_id", BACKEND_SESSION_ID_MAX_BYTES, false);
  if (value !== value.trim() || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error("BACKEND_SESSION_ID_INVALID");
  }
};

/**
 * Non-serializable authority registry for xterm instances, native handles,
 * connection operations, and protocol-specific ownership state.
 *
 * Keep this object in a React ref or an external controller. Never put it, or
 * values returned from it, into TerminalSessionRegistrySnapshot.
 */
export class TerminalSessionRuntimeRegistry<Runtime extends object> {
  readonly #limit: number;
  readonly #runtimes = new Map<WorkspaceSessionId, Runtime>();
  readonly #backendToWorkspace = new Map<string, WorkspaceSessionId>();
  readonly #workspaceToBackend = new Map<WorkspaceSessionId, string>();

  constructor(limit = MAX_WORKSPACE_SESSIONS) {
    assertSessionLimit(limit);
    this.#limit = limit;
  }

  get size(): number {
    return this.#runtimes.size;
  }

  bindExact(id: WorkspaceSessionId, runtime: Runtime): void {
    if (!isWorkspaceSessionId(id)) throw new Error("WORKSPACE_SESSION_ID_INVALID");
    if (this.#runtimes.has(id)) throw new Error("WORKSPACE_SESSION_RUNTIME_DUPLICATE");
    if (this.#runtimes.size >= this.#limit) throw new Error("WORKSPACE_SESSION_LIMIT_REACHED");
    this.#runtimes.set(id, runtime);
  }

  hasExact(id: WorkspaceSessionId): boolean {
    return isWorkspaceSessionId(id) && this.#runtimes.has(id);
  }

  getExact(id: WorkspaceSessionId): Runtime | undefined {
    if (!isWorkspaceSessionId(id)) throw new Error("WORKSPACE_SESSION_ID_INVALID");
    return this.#runtimes.get(id);
  }

  bindBackendSessionId(id: WorkspaceSessionId, backendSessionId: string): void {
    if (!isWorkspaceSessionId(id)) throw new Error("WORKSPACE_SESSION_ID_INVALID");
    if (!this.#runtimes.has(id)) throw new Error("WORKSPACE_SESSION_RUNTIME_NOT_FOUND");
    assertBackendSessionId(backendSessionId);

    const existingOwner = this.#backendToWorkspace.get(backendSessionId);
    if (existingOwner && existingOwner !== id) {
      throw new Error("BACKEND_SESSION_ID_DUPLICATE");
    }
    const previousBackendSessionId = this.#workspaceToBackend.get(id);
    if (previousBackendSessionId === backendSessionId) return;
    if (previousBackendSessionId) {
      // Delete only the exact reverse entry. A forged/stale index can never
      // retire another workspace session's authority.
      if (this.#backendToWorkspace.get(previousBackendSessionId) === id) {
        this.#backendToWorkspace.delete(previousBackendSessionId);
      }
    }
    this.#workspaceToBackend.set(id, backendSessionId);
    this.#backendToWorkspace.set(backendSessionId, id);
  }

  backendSessionIdFor(id: WorkspaceSessionId): string | undefined {
    if (!isWorkspaceSessionId(id)) throw new Error("WORKSPACE_SESSION_ID_INVALID");
    return this.#workspaceToBackend.get(id);
  }

  unbindBackendSessionId(
    id: WorkspaceSessionId,
    expectedBackendSessionId: string,
  ): boolean {
    if (!isWorkspaceSessionId(id)) throw new Error("WORKSPACE_SESSION_ID_INVALID");
    assertBackendSessionId(expectedBackendSessionId);
    const currentBackendSessionId = this.#workspaceToBackend.get(id);
    if (
      currentBackendSessionId === undefined
      || currentBackendSessionId !== expectedBackendSessionId
    ) return false;
    if (this.#backendToWorkspace.get(currentBackendSessionId) === id) {
      this.#backendToWorkspace.delete(currentBackendSessionId);
    }
    this.#workspaceToBackend.delete(id);
    return true;
  }

  workspaceSessionIdForBackend(backendSessionId: string): WorkspaceSessionId | undefined {
    assertBackendSessionId(backendSessionId);
    return this.#backendToWorkspace.get(backendSessionId);
  }

  getByBackendSessionId(backendSessionId: string): Runtime | undefined {
    const id = this.workspaceSessionIdForBackend(backendSessionId);
    return id ? this.#runtimes.get(id) : undefined;
  }

  deleteExact(id: WorkspaceSessionId): Runtime | undefined {
    if (!isWorkspaceSessionId(id)) throw new Error("WORKSPACE_SESSION_ID_INVALID");
    const runtime = this.#runtimes.get(id);
    if (runtime === undefined) return undefined;
    const backendSessionId = this.#workspaceToBackend.get(id);
    if (backendSessionId !== undefined) this.unbindBackendSessionId(id, backendSessionId);
    this.#runtimes.delete(id);
    return runtime;
  }

  deleteByBackendSessionId(backendSessionId: string): Runtime | undefined {
    const id = this.workspaceSessionIdForBackend(backendSessionId);
    return id ? this.deleteExact(id) : undefined;
  }
}
