import {
  MAX_WORKSPACE_SESSIONS,
  isWorkspaceSessionId,
  workspaceSessionIdFrom,
  type TerminalSessionProtocol,
  type TerminalSessionRegistrySnapshot,
  type TerminalSessionSnapshot,
  type WorkspaceSessionId,
} from "./terminalSessionRegistry.ts";

/**
 * The restart file is deliberately a presentation hint, not a connection
 * resume token.  A new process must create fresh runtime/native ownership and
 * ask the normal connection flow for credentials again.
 */
export const SESSION_RESTORE_VERSION = 2 as const;
export const SESSION_RESTORE_STORAGE_KEY = "goral.session-restore.v2";
const LEGACY_SESSION_RESTORE_STORAGE_KEY = "lumendock.session-restore.v2";
export const MAX_SESSION_RESTORE_ENTRIES = MAX_WORKSPACE_SESSIONS;
export const MAX_SESSION_RESTORE_BYTES = 64 * 1024;
export const MAX_SESSION_RESTORE_PANE_NODES = (MAX_WORKSPACE_SESSIONS * 2) - 1;
export const MAX_SESSION_RESTORE_PANE_DEPTH = MAX_WORKSPACE_SESSIONS;

const MAX_TARGET_LABEL_BYTES = 512;
const MAX_HOSTNAME_BYTES = 512;
const MAX_SAVED_HOST_ID_BYTES = 256;
const MAX_LOCAL_SHELL_ID_BYTES = 128;
const MAX_PANE_NODE_ID_BYTES = 256;
const MIN_PANE_RATIO = 0.01;
const MAX_PANE_RATIO = 0.99;
const utf8 = new TextEncoder();

export type SessionRestoreTarget = Readonly<
  | {
      kind: "saved";
      savedHostId: string;
      label: string;
    }
  | {
      kind: "quick";
      label: string;
      hostname: string;
      port: number;
    }
  | {
      kind: "local";
      label: string;
      shellId: string;
    }
  | {
      kind: "serial";
      label: string;
    }
>;

export type SessionRestoreEntry = Readonly<{
  workspaceSessionId: WorkspaceSessionId;
  protocol: TerminalSessionProtocol;
  target: SessionRestoreTarget;
}>;

export type SessionRestorePaneNode = Readonly<{
  id: string;
  type: "pane";
  sessionId: WorkspaceSessionId;
}>;

export type SessionRestorePaneSplitNode = Readonly<{
  id: string;
  type: "split";
  direction: "horizontal" | "vertical";
  ratio: number;
  first: SessionRestorePaneLayoutNode;
  second: SessionRestorePaneLayoutNode;
}>;

export type SessionRestorePaneLayoutNode = SessionRestorePaneNode | SessionRestorePaneSplitNode;

export type SessionRestorePaneLayout = Readonly<{
  root: SessionRestorePaneLayoutNode;
  focusedSessionId: WorkspaceSessionId;
}>;

export type SessionRestoreSnapshot = Readonly<{
  version: typeof SESSION_RESTORE_VERSION;
  activeSessionId: WorkspaceSessionId | null;
  sessions: readonly SessionRestoreEntry[];
  paneLayout?: SessionRestorePaneLayout;
}>;

export type SessionRestoreStorage = Readonly<{
  getItem: (key: string) => string | null;
  setItem: (key: string, value: string) => void;
  removeItem: (key: string) => void;
}>;

export type SessionRestoreTargetCandidate = Exclude<SessionRestoreTarget, { kind: "local" }> | Readonly<{
  kind: "local";
  label: string;
  shellId?: string;
}>;

export type SessionRestoreTargetResolver = (
  id: WorkspaceSessionId,
  session: TerminalSessionSnapshot,
) => SessionRestoreTargetCandidate | null;

const PROTOCOLS = new Set<TerminalSessionProtocol>([
  "ssh",
  "telnet",
  "mosh",
  "et",
  "serial",
  "local",
]);

const hasExactKeys = (value: unknown, expected: readonly string[]): value is Record<string, unknown> => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const candidate = value as Record<string, unknown>;
  const prototype = Object.getPrototypeOf(candidate);
  if (prototype !== Object.prototype && prototype !== null) return false;
  const keys = Object.keys(candidate);
  return keys.length === expected.length && expected.every((key) => Object.hasOwn(candidate, key));
};

const byteLength = (value: string): number => utf8.encode(value).byteLength;

const assertText = (value: unknown, field: string, maximumBytes: number): string => {
  if (typeof value !== "string" || value.trim().length === 0 || byteLength(value) > maximumBytes) {
    throw new Error(`${field.toUpperCase()}_INVALID`);
  }
  if (value !== value.trim() || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error(`${field.toUpperCase()}_INVALID`);
  }
  return value;
};

const assertOpaqueSavedHostId = (value: unknown): string => {
  const id = assertText(value, "session_restore_saved_host_id", MAX_SAVED_HOST_ID_BYTES);
  // IDs are references only.  Reject path-like and URI-like values so a
  // malformed restore file cannot turn this field into a filesystem hint.
  if (/[\\/]/.test(id) || id.includes("://")) {
    throw new Error("SESSION_RESTORE_SAVED_HOST_ID_INVALID");
  }
  return id;
};

const assertHostname = (value: unknown): string => {
  const hostname = assertText(value, "session_restore_hostname", MAX_HOSTNAME_BYTES);
  // A hostname may contain ':' for IPv6, but never a path separator or URI.
  if (/[\\/]/.test(hostname) || hostname.includes("://")) {
    throw new Error("SESSION_RESTORE_HOSTNAME_INVALID");
  }
  return hostname;
};

const assertPort = (value: unknown): number => {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > 65_535) {
    throw new Error("SESSION_RESTORE_PORT_INVALID");
  }
  return value as number;
};

const assertLocalShellId = (value: unknown): string => {
  const shellId = assertText(value, "session_restore_shell_id", MAX_LOCAL_SHELL_ID_BYTES);
  if (!/^[a-z0-9][a-z0-9._-]*$/.test(shellId) || shellId.includes("..")) {
    throw new Error("SESSION_RESTORE_SHELL_ID_INVALID");
  }
  return shellId;
};

const assertPaneNodeId = (value: unknown): string => {
  const nodeId = assertText(value, "session_restore_pane_node_id", MAX_PANE_NODE_ID_BYTES);
  if (/[\\/]/.test(nodeId) || nodeId.includes("://")) {
    throw new Error("SESSION_RESTORE_PANE_NODE_ID_INVALID");
  }
  return nodeId;
};

const assertPaneRatio = (value: unknown): number => {
  if (
    typeof value !== "number"
    || !Number.isFinite(value)
    || value < MIN_PANE_RATIO
    || value > MAX_PANE_RATIO
  ) {
    throw new Error("SESSION_RESTORE_PANE_RATIO_INVALID");
  }
  return value;
};

const normalizeTarget = (value: unknown, protocol: TerminalSessionProtocol): SessionRestoreTarget => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("SESSION_RESTORE_TARGET_INVALID");
  }
  const candidate = value as Record<string, unknown>;
  if (candidate.kind === "saved") {
    if (!hasExactKeys(candidate, ["kind", "savedHostId", "label"])) {
      throw new Error("SESSION_RESTORE_TARGET_INVALID");
    }
    if (protocol === "local") throw new Error("SESSION_RESTORE_TARGET_PROTOCOL_INVALID");
    return Object.freeze({
      kind: "saved" as const,
      savedHostId: assertOpaqueSavedHostId(candidate.savedHostId),
      label: assertText(candidate.label, "session_restore_target_label", MAX_TARGET_LABEL_BYTES),
    });
  }
  if (candidate.kind === "quick") {
    if (!hasExactKeys(candidate, ["kind", "label", "hostname", "port"])) {
      throw new Error("SESSION_RESTORE_TARGET_INVALID");
    }
    if (protocol === "local") throw new Error("SESSION_RESTORE_TARGET_PROTOCOL_INVALID");
    return Object.freeze({
      kind: "quick" as const,
      label: assertText(candidate.label, "session_restore_target_label", MAX_TARGET_LABEL_BYTES),
      hostname: assertHostname(candidate.hostname),
      port: assertPort(candidate.port),
    });
  }
  if (candidate.kind === "local") {
    if (!hasExactKeys(candidate, ["kind", "label", "shellId"])) {
      throw new Error("SESSION_RESTORE_TARGET_INVALID");
    }
    if (protocol !== "local") {
      throw new Error("SESSION_RESTORE_TARGET_PROTOCOL_INVALID");
    }
    return Object.freeze({
      kind: "local" as const,
      label: assertText(candidate.label, "session_restore_target_label", MAX_TARGET_LABEL_BYTES),
      shellId: assertLocalShellId(candidate.shellId),
    });
  }
  if (candidate.kind === "serial") {
    if (!hasExactKeys(candidate, ["kind", "label"]) || protocol !== "serial") {
      throw new Error("SESSION_RESTORE_TARGET_PROTOCOL_INVALID");
    }
    // Quick Serial restore deliberately retains no native port/device path or
    // line settings. The normal picker is the only way back into a session.
    return Object.freeze({
      kind: "serial" as const,
      label: assertText(candidate.label, "session_restore_target_label", MAX_TARGET_LABEL_BYTES),
    });
  }
  throw new Error("SESSION_RESTORE_TARGET_KIND_INVALID");
};

const normalizeEntry = (value: unknown): SessionRestoreEntry => {
  if (!hasExactKeys(value, ["workspaceSessionId", "protocol", "target"])) {
    throw new Error("SESSION_RESTORE_ENTRY_INVALID");
  }
  if (!isWorkspaceSessionId(value.workspaceSessionId)) {
    throw new Error("SESSION_RESTORE_WORKSPACE_SESSION_ID_INVALID");
  }
  if (typeof value.protocol !== "string" || !PROTOCOLS.has(value.protocol as TerminalSessionProtocol)) {
    throw new Error("SESSION_RESTORE_PROTOCOL_INVALID");
  }
  return Object.freeze({
    workspaceSessionId: workspaceSessionIdFrom(value.workspaceSessionId),
    protocol: value.protocol as TerminalSessionProtocol,
    target: normalizeTarget(value.target, value.protocol as TerminalSessionProtocol),
  });
};

const normalizePaneLayout = (
  value: unknown,
  retainedSessionIds: ReadonlySet<string>,
  pruneMissingSessions: boolean,
): SessionRestorePaneLayout | undefined => {
  if (!hasExactKeys(value, ["root", "focusedSessionId"])) {
    throw new Error("SESSION_RESTORE_PANE_LAYOUT_INVALID");
  }
  if (!isWorkspaceSessionId(value.focusedSessionId)) {
    throw new Error("SESSION_RESTORE_PANE_FOCUS_INVALID");
  }

  let nodeCount = 0;
  const nodeIds = new Set<string>();
  const leafSessionIds = new Set<string>();
  const retainedLeafSessionIds = new Set<string>();

  const visit = (rawNode: unknown, depth: number): SessionRestorePaneLayoutNode | null => {
    if (depth > MAX_SESSION_RESTORE_PANE_DEPTH) {
      throw new Error("SESSION_RESTORE_PANE_DEPTH_LIMIT");
    }
    nodeCount += 1;
    if (nodeCount > MAX_SESSION_RESTORE_PANE_NODES) {
      throw new Error("SESSION_RESTORE_PANE_NODE_LIMIT");
    }
    if (rawNode === null || typeof rawNode !== "object" || Array.isArray(rawNode)) {
      throw new Error("SESSION_RESTORE_PANE_NODE_INVALID");
    }
    const candidate = rawNode as Record<string, unknown>;
    if (candidate.type === "pane") {
      if (!hasExactKeys(candidate, ["id", "type", "sessionId"])) {
        throw new Error("SESSION_RESTORE_PANE_NODE_INVALID");
      }
      const id = assertPaneNodeId(candidate.id);
      if (nodeIds.has(id)) throw new Error("SESSION_RESTORE_PANE_NODE_DUPLICATE");
      nodeIds.add(id);
      if (!isWorkspaceSessionId(candidate.sessionId)) {
        throw new Error("SESSION_RESTORE_PANE_SESSION_INVALID");
      }
      const sessionId = workspaceSessionIdFrom(candidate.sessionId);
      if (leafSessionIds.has(sessionId)) {
        throw new Error("SESSION_RESTORE_PANE_SESSION_DUPLICATE");
      }
      leafSessionIds.add(sessionId);
      if (!retainedSessionIds.has(sessionId)) {
        if (pruneMissingSessions) return null;
        throw new Error("SESSION_RESTORE_PANE_SESSION_INVALID");
      }
      retainedLeafSessionIds.add(sessionId);
      return Object.freeze({ id, type: "pane" as const, sessionId });
    }
    if (candidate.type === "split") {
      if (!hasExactKeys(candidate, ["id", "type", "direction", "ratio", "first", "second"])) {
        throw new Error("SESSION_RESTORE_PANE_NODE_INVALID");
      }
      const id = assertPaneNodeId(candidate.id);
      if (nodeIds.has(id)) throw new Error("SESSION_RESTORE_PANE_NODE_DUPLICATE");
      nodeIds.add(id);
      if (candidate.direction !== "horizontal" && candidate.direction !== "vertical") {
        throw new Error("SESSION_RESTORE_PANE_DIRECTION_INVALID");
      }
      const ratio = assertPaneRatio(candidate.ratio);
      const first = visit(candidate.first, depth + 1);
      const second = visit(candidate.second, depth + 1);
      if (!first) return second;
      if (!second) return first;
      return Object.freeze({
        id,
        type: "split" as const,
        direction: candidate.direction,
        ratio,
        first,
        second,
      });
    }
    throw new Error("SESSION_RESTORE_PANE_NODE_INVALID");
  };

  const root = visit(value.root, 1);
  if (!root) return undefined;
  const requestedFocus = workspaceSessionIdFrom(value.focusedSessionId);
  if (!retainedLeafSessionIds.has(requestedFocus) && !pruneMissingSessions) {
    throw new Error("SESSION_RESTORE_PANE_FOCUS_INVALID");
  }
  const focusedSessionId = retainedLeafSessionIds.has(requestedFocus)
    ? requestedFocus
    : workspaceSessionIdFrom(retainedLeafSessionIds.values().next().value as string);
  return Object.freeze({ root, focusedSessionId });
};

/** Validate and deep-freeze an untrusted snapshot before it enters UI state. */
export const validateSessionRestoreSnapshot = (value: unknown): SessionRestoreSnapshot => {
  const hasPaneLayout = hasExactKeys(value, ["version", "activeSessionId", "sessions", "paneLayout"]);
  if (!hasPaneLayout && !hasExactKeys(value, ["version", "activeSessionId", "sessions"])) {
    throw new Error("SESSION_RESTORE_SNAPSHOT_INVALID");
  }
  if (value.version !== SESSION_RESTORE_VERSION || !Array.isArray(value.sessions)) {
    throw new Error("SESSION_RESTORE_SNAPSHOT_INVALID");
  }
  if (value.sessions.length > MAX_SESSION_RESTORE_ENTRIES) {
    throw new Error("SESSION_RESTORE_LIMIT_REACHED");
  }
  const sessions: SessionRestoreEntry[] = [];
  const ids = new Set<string>();
  for (const rawEntry of value.sessions) {
    const entry = normalizeEntry(rawEntry);
    if (ids.has(entry.workspaceSessionId)) throw new Error("SESSION_RESTORE_DUPLICATE");
    ids.add(entry.workspaceSessionId);
    sessions.push(entry);
  }
  let activeSessionId: WorkspaceSessionId | null = null;
  if (value.activeSessionId !== null) {
    if (!isWorkspaceSessionId(value.activeSessionId) || !ids.has(value.activeSessionId)) {
      throw new Error("SESSION_RESTORE_ACTIVE_SESSION_INVALID");
    }
    activeSessionId = workspaceSessionIdFrom(value.activeSessionId);
  }
  const paneLayout = hasPaneLayout
    ? normalizePaneLayout(value.paneLayout, ids, false)
    : undefined;
  return Object.freeze({
    version: SESSION_RESTORE_VERSION,
    activeSessionId,
    sessions: Object.freeze(sessions),
    ...(paneLayout ? { paneLayout } : {}),
  });
};

export const createSessionRestoreSnapshot = (
  sessions: readonly SessionRestoreEntry[],
  activeSessionId: WorkspaceSessionId | null = null,
  paneLayout: SessionRestorePaneLayout | null = null,
): SessionRestoreSnapshot => {
  const withoutPaneLayout = validateSessionRestoreSnapshot({
    version: SESSION_RESTORE_VERSION,
    activeSessionId,
    sessions,
  });
  if (paneLayout === null) return withoutPaneLayout;
  const retainedIds = new Set(withoutPaneLayout.sessions.map((entry) => entry.workspaceSessionId));
  const prunedPaneLayout = normalizePaneLayout(paneLayout, retainedIds, true);
  if (!prunedPaneLayout) return withoutPaneLayout;
  return validateSessionRestoreSnapshot({
    ...withoutPaneLayout,
    paneLayout: prunedPaneLayout,
  });
};

/**
 * Project the live presentation catalog into a restart hint. Runtime owners
 * that cannot provide a secret-free target are deliberately omitted.
 */
export const createSessionRestoreSnapshotFromRegistry = (
  registry: TerminalSessionRegistrySnapshot,
  resolveTarget: SessionRestoreTargetResolver,
  paneLayout: SessionRestorePaneLayout | null = null,
): SessionRestoreSnapshot => {
  const sessions: SessionRestoreEntry[] = [];
  for (const id of registry.order) {
    const session = registry.sessions[id];
    if (!session) continue;
    const target = resolveTarget(id, session);
    if (target === null) continue;
    let normalizedTarget: SessionRestoreTarget;
    try {
      normalizedTarget = normalizeTarget(target, session.protocol);
    } catch {
      // A presentation resolver may still be on an older model (notably a
      // Local target without v2's opaque shell ID). Omit it rather than infer
      // executable/path authority or disrupt persistence of other sessions.
      continue;
    }
    sessions.push({
      workspaceSessionId: id,
      protocol: session.protocol,
      target: normalizedTarget,
    });
  }
  const retainedIds = new Set(sessions.map((entry) => entry.workspaceSessionId));
  return createSessionRestoreSnapshot(
    sessions,
    registry.activeSessionId !== null && retainedIds.has(registry.activeSessionId)
      ? registry.activeSessionId
      : null,
    paneLayout,
  );
};

export const encodeSessionRestoreSnapshot = (snapshot: SessionRestoreSnapshot): string => {
  const normalized = validateSessionRestoreSnapshot(snapshot);
  const encoded = JSON.stringify(normalized);
  if (encoded === undefined || byteLength(encoded) > MAX_SESSION_RESTORE_BYTES) {
    throw new Error("SESSION_RESTORE_SIZE_LIMIT");
  }
  return encoded;
};

export const decodeSessionRestoreSnapshot = (encoded: string): SessionRestoreSnapshot => {
  if (typeof encoded !== "string" || byteLength(encoded) > MAX_SESSION_RESTORE_BYTES) {
    throw new Error("SESSION_RESTORE_SIZE_LIMIT");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(encoded) as unknown;
  } catch {
    throw new Error("SESSION_RESTORE_JSON_INVALID");
  }
  return validateSessionRestoreSnapshot(parsed);
};

/** A storage adapter keeps browser/native persistence outside this data boundary. */
export const createSessionRestoreStore = (storage: SessionRestoreStorage) => Object.freeze({
  load(): SessionRestoreSnapshot | null {
    for (const key of [SESSION_RESTORE_STORAGE_KEY, LEGACY_SESSION_RESTORE_STORAGE_KEY]) {
      let encoded: string | null;
      try {
        encoded = storage.getItem(key);
      } catch {
        continue;
      }
      if (encoded === null) continue;
      try {
        const snapshot = decodeSessionRestoreSnapshot(encoded);
        if (key === LEGACY_SESSION_RESTORE_STORAGE_KEY) {
          try {
            storage.setItem(SESSION_RESTORE_STORAGE_KEY, encoded);
            storage.removeItem(LEGACY_SESSION_RESTORE_STORAGE_KEY);
          } catch {
            // Return the valid legacy hint even when optional one-time key
            // migration is denied. The original remains available to retry.
          }
        }
        return snapshot;
      } catch {
        // A corrupt hint must never prevent startup. Try the compatibility
        // key before treating the optional presentation hint as missing.
      }
    }
    return null;
  },
  save(snapshot: SessionRestoreSnapshot): void {
    try {
      storage.setItem(
        SESSION_RESTORE_STORAGE_KEY,
        encodeSessionRestoreSnapshot(snapshot),
      );
      storage.removeItem(LEGACY_SESSION_RESTORE_STORAGE_KEY);
    } catch {
      // Invalid/oversized optional hints and persistence denial must not affect
      // the live session. Callers can use the explicit encoder when they need
      // validation failures instead of best-effort persistence.
    }
  },
  clear(): void {
    for (const key of [SESSION_RESTORE_STORAGE_KEY, LEGACY_SESSION_RESTORE_STORAGE_KEY]) {
      try {
        storage.removeItem(key);
      } catch {
        // A denied browser store is equivalent to a missing optional hint.
      }
    }
  },
});
