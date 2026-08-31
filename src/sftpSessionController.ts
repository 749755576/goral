import type {
  DirectoryResumeCheckpoint,
  SftpDownloadPlan,
  SftpEntry,
  SftpTransferCheckpoint,
  SftpTransferEvent,
  SftpUploadPlan,
} from "./backend.ts";
import {
  isWorkspaceSessionId,
  type WorkspaceSessionId,
} from "./terminalSessionRegistry.ts";

/**
 * The complete identity of one SFTP authority lease.
 *
 * `workspaceId` identifies the renderer tab.  `operationGeneration` changes
 * for every SSH retry, while `backendSessionId` identifies the native SSH
 * session for that attempt.  `sftpGeneration` changes whenever the SFTP
 * state is reset/bound, so a callback retained by an old operation can never
 * write into a newer state object.
 */
export type SftpSessionOwner = Readonly<{
  workspaceId: WorkspaceSessionId;
  operationGeneration: number;
  backendSessionId: string;
  sftpGeneration: number;
}>;

/**
 * Opaque capability returned while an SSH stop is in flight.
 *
 * Object identity is part of the capability: callers cannot recreate a
 * suspension from its serializable fields.  A failed SSH stop may resume the
 * exact suspended workspace under a fresh owner without discarding its
 * transfer controls.
 */
export type SftpSessionSuspension = Readonly<{
  workspaceId: WorkspaceSessionId;
  suspensionId: number;
}>;

export type SftpTransferDirection = "upload" | "download";

export type SftpTransferStatus =
  | "queued"
  | "scanning"
  | "running"
  | "paused"
  | "completed"
  | "cancelled"
  | "failed";

const isTerminalTransferStatus = (status: SftpTransferStatus): boolean => (
  status === "completed" || status === "cancelled" || status === "failed"
);

/**
 * Serializable transfer state.  Native channels, promises, and control
 * callbacks are deliberately absent; those live in a private authority map.
 */
export type SftpTransferSnapshot = Readonly<{
  id: string;
  direction: SftpTransferDirection;
  isDirectory: boolean;
  localPath?: string;
  remotePath?: string;
  label?: string;
  status: SftpTransferStatus;
  bytesTransferred: number;
  totalBytes: number;
  filesCompleted: number;
  totalFiles: number;
  skippedEntries: number;
  failedFiles: number;
  currentPath?: string;
  error?: string;
  plan?: SftpUploadPlan;
  downloadPlan?: SftpDownloadPlan;
  checkpoint?: SftpTransferCheckpoint;
  directoryCheckpoint?: DirectoryResumeCheckpoint;
}>;

/** Minimal input accepted when a transfer is first published. */
export type SftpTransferSnapshotInput = Readonly<{
  id: string;
  direction?: SftpTransferDirection;
  isDirectory?: boolean;
  localPath?: string;
  remotePath?: string;
  label?: string;
  status?: SftpTransferStatus;
  bytesTransferred?: number;
  totalBytes?: number;
  filesCompleted?: number;
  totalFiles?: number;
  skippedEntries?: number;
  failedFiles?: number;
  currentPath?: string;
  error?: string;
  plan?: SftpUploadPlan;
  downloadPlan?: SftpDownloadPlan;
  checkpoint?: SftpTransferCheckpoint;
  directoryCheckpoint?: DirectoryResumeCheckpoint;
}>;

export type SftpTransferSnapshotPatch = Readonly<Partial<Omit<SftpTransferSnapshot, "id">>>;

/** Metadata that may arrive with a native starter after its transfer events. */
export type SftpTransferStarterPatch = Readonly<Pick<
  SftpTransferSnapshot,
  "plan" | "downloadPlan"
>>;

/** React-facing, immutable, serializable state for one workspace. */
export type SftpSessionSnapshot = Readonly<{
  workspaceId: WorkspaceSessionId;
  path: string;
  entries: readonly SftpEntry[];
  loading: boolean;
  error: string | null;
  latestListingToken: number;
  transfers: readonly SftpTransferSnapshot[];
}>;

export type SftpSessionListener = (
  snapshot: SftpSessionSnapshot,
  previous: SftpSessionSnapshot | undefined,
) => void;

export type SftpTransferControlAction = "pause" | "resume" | "cancel";

export type SftpTransferControlRequest = Readonly<{
  owner: SftpSessionOwner;
  snapshotId: string;
  backendTransferId: string;
  action: SftpTransferControlAction;
}>;

/** A per-transfer non-serializable authority, useful for channel wrappers. */
export type SftpTransferControl = Readonly<{
  backendTransferId: string;
  pause?: () => Promise<void>;
  resume?: () => Promise<void>;
  cancel?: () => Promise<void>;
  /** Retains a native event-channel wrapper without exposing it in snapshots. */
  retention?: object;
  dispose?: () => void;
}>;

export type SftpTransferControlTransport = (
  request: SftpTransferControlRequest,
) => Promise<void>;

export type SftpSessionControllerDependencies = Readonly<{
  readDirectory: (backendSessionId: string, path: string) => Promise<readonly SftpEntry[]>;
  /** Optional native action transport.  Per-transfer controls may be used too. */
  transferControl?: SftpTransferControlTransport;
  /** Converts backend errors into a safe user-visible string. */
  formatError?: (reason: unknown) => string;
}>;

export type SftpSessionBindInput = Readonly<{
  workspaceId: WorkspaceSessionId;
  operationGeneration: number;
  backendSessionId: string;
}>;

export type SftpSessionStateOptions = Readonly<{
  /** Maximum number of remembered snapshots. Defaults to 20. */
  transferLimit?: number;
}>;

const DEFAULT_TRANSFER_LIMIT = 20;
const MAX_TRANSFER_LIMIT = 20;
const MAX_BACKEND_ID_BYTES = 256;
const MAX_PATH_BYTES = 8 * 1024;
const MAX_TRANSFER_ID_BYTES = 512;
const MAX_ERROR_BYTES = 4 * 1024;
const utf8 = new TextEncoder();

const boundedText = (
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
  ) throw new Error(`${field.toUpperCase()}_INVALID`);
  return value;
};

const assertWorkspaceId = (workspaceId: WorkspaceSessionId): void => {
  if (!isWorkspaceSessionId(workspaceId)) throw new Error("WORKSPACE_SESSION_ID_INVALID");
};

const assertGeneration = (generation: number, field: string): void => {
  if (!Number.isSafeInteger(generation) || generation < 0) {
    throw new Error(`${field.toUpperCase()}_INVALID`);
  }
};

const assertBackendSessionId = (backendSessionId: string): void => {
  boundedText(backendSessionId, "backend_session_id", MAX_BACKEND_ID_BYTES);
};

const assertPath = (path: string): void => {
  boundedText(path, "sftp_path", MAX_PATH_BYTES);
};

const assertTransferId = (transferId: string): void => {
  boundedText(transferId, "sftp_transfer_id", MAX_TRANSFER_ID_BYTES);
};

const freezeEntry = (entry: SftpEntry): SftpEntry => Object.freeze({
  name: entry.name,
  path: entry.path,
  metadata: Object.freeze({ ...entry.metadata }),
});

const cloneEntries = (entries: readonly SftpEntry[]): readonly SftpEntry[] => Object.freeze(
  entries.map(freezeEntry),
);

const freezeJsonValue = <T>(value: T): T => {
  // Plans/checkpoints contain only bounded JSON values.  structuredClone is
  // unavailable in a few browser preview environments, so use a small
  // recursive clone for plain arrays/objects instead.
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) {
    return Object.freeze(value.map((item) => freezeJsonValue(item))) as T;
  }
  const output: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    output[key] = freezeJsonValue(item);
  }
  return Object.freeze(output) as T;
};

const freezeTransfer = (input: SftpTransferSnapshotInput | SftpTransferSnapshot): SftpTransferSnapshot => {
  assertTransferId(input.id);
  const direction = input.direction ?? "upload";
  if (direction !== "upload" && direction !== "download") {
    throw new Error("SFTP_TRANSFER_DIRECTION_INVALID");
  }
  const status = input.status ?? "queued";
  const statuses: readonly SftpTransferStatus[] = [
    "queued", "scanning", "running", "paused", "completed", "cancelled", "failed",
  ];
  if (!statuses.includes(status)) throw new Error("SFTP_TRANSFER_STATUS_INVALID");
  const numberField = (value: number | undefined, field: string): number => {
    const normalized = value ?? 0;
    if (!Number.isFinite(normalized) || normalized < 0) {
      throw new Error(`${field.toUpperCase()}_INVALID`);
    }
    return normalized;
  };
  const output: SftpTransferSnapshot = {
    id: input.id,
    direction,
    isDirectory: input.isDirectory ?? false,
    ...(input.localPath === undefined ? {} : { localPath: boundedText(input.localPath, "sftp_local_path", MAX_PATH_BYTES, true) }),
    ...(input.remotePath === undefined ? {} : { remotePath: boundedText(input.remotePath, "sftp_remote_path", MAX_PATH_BYTES, true) }),
    ...(input.label === undefined ? {} : { label: boundedText(input.label, "sftp_transfer_label", MAX_PATH_BYTES, true) }),
    status,
    bytesTransferred: numberField(input.bytesTransferred, "sftp_bytes_transferred"),
    totalBytes: numberField(input.totalBytes, "sftp_total_bytes"),
    filesCompleted: numberField(input.filesCompleted, "sftp_files_completed"),
    totalFiles: numberField(input.totalFiles, "sftp_total_files"),
    skippedEntries: numberField(input.skippedEntries, "sftp_skipped_entries"),
    failedFiles: numberField(input.failedFiles, "sftp_failed_files"),
    ...(input.currentPath === undefined ? {} : { currentPath: boundedText(input.currentPath, "sftp_current_path", MAX_PATH_BYTES, true) }),
    ...(input.error === undefined ? {} : { error: boundedText(input.error, "sftp_transfer_error", MAX_ERROR_BYTES, true) }),
    ...(input.plan === undefined ? {} : { plan: freezeJsonValue(input.plan) }),
    ...(input.downloadPlan === undefined ? {} : { downloadPlan: freezeJsonValue(input.downloadPlan) }),
    ...(input.checkpoint === undefined ? {} : { checkpoint: freezeJsonValue(input.checkpoint) }),
    ...(input.directoryCheckpoint === undefined ? {} : { directoryCheckpoint: freezeJsonValue(input.directoryCheckpoint) }),
  };
  return Object.freeze(output);
};

const freezeSnapshot = (input: {
  workspaceId: WorkspaceSessionId;
  path: string;
  entries: readonly SftpEntry[];
  loading: boolean;
  error: string | null;
  latestListingToken: number;
  transfers: readonly SftpTransferSnapshot[];
}): SftpSessionSnapshot => Object.freeze({
  workspaceId: input.workspaceId,
  path: input.path,
  entries: cloneEntries(input.entries),
  loading: input.loading,
  error: input.error,
  latestListingToken: input.latestListingToken,
  transfers: Object.freeze(input.transfers.map((transfer) => freezeTransfer(transfer))),
});

const ownersEqual = (left: SftpSessionOwner | null, right: SftpSessionOwner): boolean => (
  left !== null
  && left.workspaceId === right.workspaceId
  && left.operationGeneration === right.operationGeneration
  && left.backendSessionId === right.backendSessionId
  && left.sftpGeneration === right.sftpGeneration
);

type MutableTransferControl = SftpTransferControl;

type MutableSftpSession = {
  workspaceId: WorkspaceSessionId;
  owner: SftpSessionOwner | null;
  suspension: Readonly<{
    token: SftpSessionSuspension;
    owner: SftpSessionOwner;
  }> | null;
  transferEventOwners: Map<string, SftpSessionOwner>;
  pendingControlOwners: Map<string, SftpSessionOwner>;
  highestOperationGeneration: number;
  lastBackendSessionId: string | null;
  path: string;
  entries: readonly SftpEntry[];
  loading: boolean;
  error: string | null;
  latestListingToken: number;
  transfers: Map<string, SftpTransferSnapshot>;
  controls: Map<string, MutableTransferControl>;
  snapshot: SftpSessionSnapshot;
  listeners: Set<SftpSessionListener>;
};

const emptySnapshot = (workspaceId: WorkspaceSessionId): SftpSessionSnapshot => freezeSnapshot({
  workspaceId,
  path: "/",
  entries: [],
  loading: false,
  error: null,
  latestListingToken: 0,
  transfers: [],
});

/**
 * Pure renderer-side SFTP state/authority coordinator.
 *
 * It has no React dependency and no direct backend import.  A caller can keep
 * one instance for the whole workbench and bind one exact SSH owner per tab.
 */
export class SftpSessionController {
  readonly #dependencies: SftpSessionControllerDependencies;
  readonly #transferLimit: number;
  readonly #sessions = new Map<WorkspaceSessionId, MutableSftpSession>();
  readonly #backendSessionOwners = new Map<string, WorkspaceSessionId>();
  readonly #backendTransferOwners = new Map<string, Readonly<{
    workspaceId: WorkspaceSessionId;
    snapshotId: string;
    control: MutableTransferControl;
  }>>();
  #activeWorkspaceId: WorkspaceSessionId | null = null;
  #nextOwnerGeneration = 0;
  #nextSuspensionId = 0;
  #disposed = false;

  constructor(
    dependencies: SftpSessionControllerDependencies,
    options: SftpSessionStateOptions = {},
  ) {
    if (typeof dependencies.readDirectory !== "function") {
      throw new Error("SFTP_DIRECTORY_READER_INVALID");
    }
    const limit = options.transferLimit ?? DEFAULT_TRANSFER_LIMIT;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_TRANSFER_LIMIT) {
      throw new Error("SFTP_TRANSFER_LIMIT_INVALID");
    }
    this.#dependencies = dependencies;
    this.#transferLimit = limit;
  }

  get activeWorkspaceId(): WorkspaceSessionId | null {
    return this.#activeWorkspaceId;
  }

  get activeSnapshot(): SftpSessionSnapshot | null {
    return this.#activeWorkspaceId
      ? this.getSnapshot(this.#activeWorkspaceId) ?? null
      : null;
  }

  /** Return an immutable snapshot, or undefined for an unknown workspace. */
  getSnapshot(workspaceId: WorkspaceSessionId): SftpSessionSnapshot | undefined {
    assertWorkspaceId(workspaceId);
    return this.#sessions.get(workspaceId)?.snapshot;
  }

  /** Alias useful to external state-store adapters. */
  snapshot(workspaceId: WorkspaceSessionId): SftpSessionSnapshot | undefined {
    return this.getSnapshot(workspaceId);
  }

  getOwner(workspaceId: WorkspaceSessionId): SftpSessionOwner | undefined {
    assertWorkspaceId(workspaceId);
    const session = this.#sessions.get(workspaceId);
    const owner = session?.suspension ? null : session?.owner;
    return owner ? { ...owner } : undefined;
  }

  isSuspended(workspaceId: WorkspaceSessionId): boolean {
    assertWorkspaceId(workspaceId);
    return this.#sessions.get(workspaceId)?.suspension !== null
      && this.#sessions.get(workspaceId)?.suspension !== undefined;
  }

  isActive(workspaceId: WorkspaceSessionId): boolean {
    assertWorkspaceId(workspaceId);
    return this.#activeWorkspaceId === workspaceId;
  }

  isExactOwner(owner: SftpSessionOwner): boolean {
    if (this.#disposed || !owner || !isWorkspaceSessionId(owner.workspaceId)) return false;
    const session = this.#sessions.get(owner.workspaceId);
    return session !== undefined
      && session.suspension === null
      && ownersEqual(session.owner, owner);
  }

  /** Publish a safe operation error for one exact workspace owner. */
  setError(owner: SftpSessionOwner, error: string | null): boolean {
    if (!this.isExactOwner(owner)) return false;
    const session = this.#sessions.get(owner.workspaceId)!;
    this.#mutate(session, () => {
      session.error = error === null
        ? null
        : boundedText(error, "sftp_error", MAX_ERROR_BYTES, true);
    });
    return true;
  }

  /** Make a workspace the SFTP-active workspace without changing its owner. */
  activate(workspaceId: WorkspaceSessionId): boolean {
    assertWorkspaceId(workspaceId);
    if (!this.#sessions.has(workspaceId)) return false;
    this.#activeWorkspaceId = workspaceId;
    return true;
  }

  /** `active` is intentionally a query alias for callers that use that name. */
  active(workspaceId?: WorkspaceSessionId): SftpSessionSnapshot | boolean | null {
    if (workspaceId !== undefined) return this.isActive(workspaceId);
    return this.activeSnapshot;
  }

  /**
   * Subscribe to one workspace.  A listener receives immutable snapshots and
   * cannot block authority even if it throws.
   */
  subscribe(workspaceId: WorkspaceSessionId, listener: SftpSessionListener): () => void;
  /** Subscribe to all workspace changes. */
  subscribe(listener: SftpSessionListener): () => void;
  subscribe(
    workspaceOrListener: WorkspaceSessionId | SftpSessionListener,
    maybeListener?: SftpSessionListener,
  ): () => void {
    const scopedWorkspace = typeof workspaceOrListener === "function"
      ? null
      : workspaceOrListener;
    const listener = typeof workspaceOrListener === "function"
      ? workspaceOrListener
      : maybeListener;
    if (scopedWorkspace !== null) assertWorkspaceId(scopedWorkspace);
    if (typeof listener !== "function") throw new Error("SFTP_LISTENER_INVALID");
    const wrapped: SftpSessionListener = (snapshot, previous) => {
      if (scopedWorkspace !== null && snapshot.workspaceId !== scopedWorkspace) return;
      try {
        listener(snapshot, previous);
      } catch {
        // Presentation observers are never allowed to corrupt authority.
      }
    };
    if (scopedWorkspace !== null) {
      const session = this.#sessions.get(scopedWorkspace);
      if (session) session.listeners.add(wrapped);
      else {
        // Keep a lazy placeholder so a subscription made before bind works.
        const created = this.#createSession(scopedWorkspace);
        created.listeners.add(wrapped);
      }
    } else {
      // Global listeners live on the controller sentinel.  This avoids putting
      // a non-serializable listener into any session snapshot.
      this.#globalListeners.add(wrapped);
    }
    return () => {
      if (scopedWorkspace !== null) this.#sessions.get(scopedWorkspace)?.listeners.delete(wrapped);
      else this.#globalListeners.delete(wrapped);
    };
  }

  readonly #globalListeners = new Set<SftpSessionListener>();

  #createSession(workspaceId: WorkspaceSessionId): MutableSftpSession {
    const session: MutableSftpSession = {
      workspaceId,
      owner: null,
      suspension: null,
      transferEventOwners: new Map(),
      pendingControlOwners: new Map(),
      highestOperationGeneration: -1,
      lastBackendSessionId: null,
      path: "/",
      entries: [],
      loading: false,
      error: null,
      latestListingToken: 0,
      transfers: new Map(),
      controls: new Map(),
      snapshot: emptySnapshot(workspaceId),
      listeners: new Set(),
    };
    this.#sessions.set(workspaceId, session);
    return session;
  }

  #session(workspaceId: WorkspaceSessionId): MutableSftpSession {
    assertWorkspaceId(workspaceId);
    return this.#sessions.get(workspaceId) ?? this.#createSession(workspaceId);
  }

  #emit(session: MutableSftpSession, previous: SftpSessionSnapshot): void {
    // Map insertion order is oldest to newest so eviction is O(1); renderer
    // snapshots keep the legacy newest-first presentation order.
    const transfers = [...session.transfers.values()].reverse();
    session.snapshot = freezeSnapshot({
      workspaceId: session.workspaceId,
      path: session.path,
      entries: session.entries,
      loading: session.loading,
      error: session.error,
      latestListingToken: session.latestListingToken,
      transfers,
    });
    for (const listener of [...session.listeners]) listener(session.snapshot, previous);
    for (const listener of [...this.#globalListeners]) {
      try {
        listener(session.snapshot, previous);
      } catch {
        // Ignore observer failures.
      }
    }
  }

  #mutate(session: MutableSftpSession, mutation: () => void): void {
    const previous = session.snapshot;
    mutation();
    this.#emit(session, previous);
  }

  #clearState(session: MutableSftpSession): void {
    session.path = "/";
    session.entries = [];
    session.loading = false;
    session.error = null;
    // Owner generation is the cross-bind invalidation guard; listing tokens
    // are local to the newly reset generation and start from zero.
    session.latestListingToken = 0;
    session.transfers.clear();
    this.#clearControls(session);
    session.transferEventOwners.clear();
    session.pendingControlOwners.clear();
    session.suspension = null;
  }

  #releaseControl(
    session: MutableSftpSession,
    snapshotId: string,
  ): void {
    const control = session.controls.get(snapshotId);
    if (!control) {
      session.transferEventOwners.delete(snapshotId);
      session.pendingControlOwners.delete(snapshotId);
      return;
    }
    const indexed = this.#backendTransferOwners.get(control.backendTransferId);
    if (
      indexed?.workspaceId === session.workspaceId
      && indexed.snapshotId === snapshotId
      && indexed.control === control
    ) this.#backendTransferOwners.delete(control.backendTransferId);
    session.controls.delete(snapshotId);
    session.transferEventOwners.delete(snapshotId);
    session.pendingControlOwners.delete(snapshotId);
    try {
      control.dispose?.();
    } catch {
      // A channel wrapper cannot retain or corrupt controller authority.
    }
  }

  #clearControls(session: MutableSftpSession): void {
    for (const snapshotId of [...session.controls.keys()]) {
      this.#releaseControl(session, snapshotId);
    }
  }

  #safeError(reason: unknown): string {
    let message = "SFTP operation failed";
    try {
      message = this.#dependencies.formatError?.(reason) ?? message;
    } catch {
      // A formatter is a presentation dependency and cannot break cleanup.
    }
    if (typeof message !== "string" || message.trim().length === 0) {
      return "SFTP operation failed";
    }
    if (utf8.encode(message).byteLength <= MAX_ERROR_BYTES) return message;
    // Preserve valid UTF-16 boundaries while bounding the renderer payload.
    let end = Math.min(message.length, MAX_ERROR_BYTES);
    while (end > 0 && utf8.encode(message.slice(0, end)).byteLength > MAX_ERROR_BYTES) end -= 1;
    return message.slice(0, end) || "SFTP operation failed";
  }

  #allocateOwnerGeneration(): number {
    if (this.#nextOwnerGeneration >= Number.MAX_SAFE_INTEGER) {
      throw new Error("SFTP_OWNER_GENERATION_EXHAUSTED");
    }
    this.#nextOwnerGeneration += 1;
    return this.#nextOwnerGeneration;
  }

  #allocateSuspensionId(): number {
    if (this.#nextSuspensionId >= Number.MAX_SAFE_INTEGER) {
      throw new Error("SFTP_SUSPENSION_ID_EXHAUSTED");
    }
    this.#nextSuspensionId += 1;
    return this.#nextSuspensionId;
  }

  /**
   * Bind (or rebind after SSH retry) an exact native session to a workspace.
   * Rebinding invalidates all old listing promises and transfer callbacks.
   */
  bindSession(
    workspaceId: WorkspaceSessionId,
    operationGeneration: number,
    backendSessionId: string,
  ): SftpSessionOwner;
  bindSession(input: SftpSessionBindInput): SftpSessionOwner;
  bindSession(
    workspaceOrInput: WorkspaceSessionId | SftpSessionBindInput,
    operationGeneration?: number,
    backendSessionId?: string,
  ): SftpSessionOwner {
    const input: SftpSessionBindInput = typeof workspaceOrInput === "string"
      ? {
        workspaceId: workspaceOrInput,
        operationGeneration: operationGeneration as number,
        backendSessionId: backendSessionId as string,
      }
      : workspaceOrInput;
    assertWorkspaceId(input.workspaceId);
    assertGeneration(input.operationGeneration, "sftp_operation_generation");
    assertBackendSessionId(input.backendSessionId);
    if (this.#disposed) throw new Error("SFTP_CONTROLLER_DISPOSED");
    const session = this.#session(input.workspaceId);
    if (session.suspension) throw new Error("SFTP_SESSION_SUSPENDED");
    if (
      session.owner
      && session.owner.operationGeneration === input.operationGeneration
      && session.owner.backendSessionId === input.backendSessionId
    ) return { ...session.owner };
    if (input.operationGeneration < session.highestOperationGeneration) {
      throw new Error("SFTP_OPERATION_GENERATION_STALE");
    }
    if (
      input.operationGeneration === session.highestOperationGeneration
      && session.lastBackendSessionId !== null
      && session.lastBackendSessionId !== input.backendSessionId
    ) throw new Error("SFTP_OPERATION_BINDING_CONFLICT");
    const backendOwner = this.#backendSessionOwners.get(input.backendSessionId);
    if (backendOwner !== undefined && backendOwner !== input.workspaceId) {
      throw new Error("SFTP_BACKEND_SESSION_ID_DUPLICATE");
    }
    const previous = session.snapshot;
    const previousBackendSessionId = session.owner?.backendSessionId;
    if (
      previousBackendSessionId
      && this.#backendSessionOwners.get(previousBackendSessionId) === input.workspaceId
    ) this.#backendSessionOwners.delete(previousBackendSessionId);
    session.highestOperationGeneration = Math.max(
      session.highestOperationGeneration,
      input.operationGeneration,
    );
    session.lastBackendSessionId = input.backendSessionId;
    session.owner = Object.freeze({
      workspaceId: input.workspaceId,
      operationGeneration: input.operationGeneration,
      backendSessionId: input.backendSessionId,
      sftpGeneration: this.#allocateOwnerGeneration(),
    });
    this.#backendSessionOwners.set(input.backendSessionId, input.workspaceId);
    this.#clearState(session);
    this.#emit(session, previous);
    if (this.#activeWorkspaceId === null) this.#activeWorkspaceId = input.workspaceId;
    return { ...session.owner };
  }

  /**
   * Revoke ordinary SFTP authority while an SSH disconnect/close is pending,
   * but retain private transfer controls so a failed stop can be rolled back.
   */
  suspendSession(
    workspaceId: WorkspaceSessionId,
    expectedOwner?: SftpSessionOwner,
  ): SftpSessionSuspension | null {
    if (this.#disposed || !isWorkspaceSessionId(workspaceId)) return null;
    const session = this.#sessions.get(workspaceId);
    if (!session?.owner || session.suspension) return null;
    if (expectedOwner && !ownersEqual(session.owner, expectedOwner)) return null;
    const owner = Object.freeze({ ...session.owner });
    const token = Object.freeze({
      workspaceId,
      suspensionId: this.#allocateSuspensionId(),
    });
    session.suspension = Object.freeze({ token, owner });
    for (const [transferId, transfer] of session.transfers) {
      if (
        !isTerminalTransferStatus(transfer.status)
        && !session.transferEventOwners.has(transferId)
      ) {
        session.transferEventOwners.set(transferId, owner);
      }
      if (
        !isTerminalTransferStatus(transfer.status)
        && !session.controls.has(transferId)
        && !session.pendingControlOwners.has(transferId)
      ) {
        session.pendingControlOwners.set(transferId, owner);
      }
    }
    const previous = session.snapshot;
    session.latestListingToken += 1;
    session.loading = false;
    this.#emit(session, previous);
    return token;
  }

  /** Resume a failed SSH stop under a fresh, non-reusable SFTP owner. */
  resumeSession(suspension: SftpSessionSuspension): SftpSessionOwner | null {
    if (
      this.#disposed
      || !suspension
      || !isWorkspaceSessionId(suspension.workspaceId)
    ) return null;
    const session = this.#sessions.get(suspension.workspaceId);
    const suspended = session?.suspension;
    if (!session || !suspended || suspended.token !== suspension) return null;
    const previous = session.snapshot;
    const owner = Object.freeze({
      ...suspended.owner,
      sftpGeneration: this.#allocateOwnerGeneration(),
    });
    session.owner = owner;
    session.suspension = null;
    this.#backendSessionOwners.set(owner.backendSessionId, owner.workspaceId);
    this.#emit(session, previous);
    return { ...owner };
  }

  /** Commit a successful SSH stop and discard the suspended SFTP workspace. */
  finalizeSuspension(
    suspension: SftpSessionSuspension,
    remove: boolean,
  ): boolean {
    if (
      this.#disposed
      || !suspension
      || !isWorkspaceSessionId(suspension.workspaceId)
    ) return false;
    const session = this.#sessions.get(suspension.workspaceId);
    const suspended = session?.suspension;
    if (!session || !suspended || suspended.token !== suspension) return false;
    session.suspension = null;
    return remove
      ? this.removeSession(suspension.workspaceId, suspended.owner)
      : this.resetSession(suspension.workspaceId, suspended.owner);
  }

  /**
   * Invalidate an owner while retaining the workspace record for a later
   * retry.  A mismatching expected owner is rejected without touching state.
   */
  resetSession(workspaceId: WorkspaceSessionId, expectedOwner?: SftpSessionOwner): boolean {
    if (this.#disposed || !isWorkspaceSessionId(workspaceId)) return false;
    const session = this.#sessions.get(workspaceId);
    if (!session) return false;
    if (expectedOwner && !ownersEqual(session.owner, expectedOwner)) return false;
    const previous = session.snapshot;
    const backendSessionId = session.owner?.backendSessionId;
    if (
      backendSessionId
      && this.#backendSessionOwners.get(backendSessionId) === workspaceId
    ) this.#backendSessionOwners.delete(backendSessionId);
    session.owner = null;
    this.#clearState(session);
    this.#emit(session, previous);
    return true;
  }

  /** Remove one workspace and all of its private transfer authorities. */
  removeSession(workspaceId: WorkspaceSessionId, expectedOwner?: SftpSessionOwner): boolean {
    if (this.#disposed || !isWorkspaceSessionId(workspaceId)) return false;
    const session = this.#sessions.get(workspaceId);
    if (!session) return false;
    if (expectedOwner && !ownersEqual(session.owner, expectedOwner)) return false;
    const backendSessionId = session.owner?.backendSessionId;
    if (
      backendSessionId
      && this.#backendSessionOwners.get(backendSessionId) === workspaceId
    ) this.#backendSessionOwners.delete(backendSessionId);
    session.owner = null;
    session.suspension = null;
    this.#clearControls(session);
    session.transfers.clear();
    session.transferEventOwners.clear();
    session.pendingControlOwners.clear();
    session.listeners.clear();
    this.#sessions.delete(workspaceId);
    if (this.#activeWorkspaceId === workspaceId) this.#activeWorkspaceId = null;
    return true;
  }

  /** Load a directory under an exact owner and latest-request token. */
  async load(
    workspaceId: WorkspaceSessionId,
    path: string,
    expectedOwner?: SftpSessionOwner,
  ): Promise<boolean> {
    if (this.#disposed || !isWorkspaceSessionId(workspaceId)) return false;
    assertPath(path);
    const session = this.#sessions.get(workspaceId);
    if (!session || !session.owner) return false;
    const owner = expectedOwner ?? session.owner;
    if (!ownersEqual(session.owner, owner)) return false;
    const requestToken = session.latestListingToken + 1;
    this.#mutate(session, () => {
      session.latestListingToken = requestToken;
      session.loading = true;
      session.error = null;
    });
    try {
      const entries = await this.#dependencies.readDirectory(owner.backendSessionId, path);
      if (
        this.#disposed
        || !this.#sessions.has(workspaceId)
        || session.latestListingToken !== requestToken
        || !ownersEqual(session.owner, owner)
      ) return false;
      const copied = [...entries].map(freezeEntry);
      copied.sort((left, right) => {
        if (left.metadata.kind === "directory" && right.metadata.kind !== "directory") return -1;
        if (left.metadata.kind !== "directory" && right.metadata.kind === "directory") return 1;
        return left.name.localeCompare(right.name);
      });
      this.#mutate(session, () => {
        session.path = path;
        session.entries = Object.freeze(copied);
        session.loading = false;
        session.error = null;
      });
      return true;
    } catch (reason) {
      if (
        this.#disposed
        || !this.#sessions.has(workspaceId)
        || session.latestListingToken !== requestToken
        || !ownersEqual(session.owner, owner)
      ) return false;
      this.#mutate(session, () => {
        session.loading = false;
        session.error = this.#safeError(reason);
      });
      return false;
    }
  }

  /** Alias for callers that prefer a workspace-first verb. */
  loadPath(
    workspaceId: WorkspaceSessionId,
    path: string,
    expectedOwner?: SftpSessionOwner,
  ): Promise<boolean> {
    return this.load(workspaceId, path, expectedOwner);
  }

  /** Publish a transfer snapshot and optional private control authority. */
  addTransfer(
    owner: SftpSessionOwner,
    input: SftpTransferSnapshotInput | SftpTransferSnapshot,
    control?: SftpTransferControl,
  ): boolean {
    if (!this.isExactOwner(owner)) return false;
    const session = this.#sessions.get(owner.workspaceId)!;
    const transfer = freezeTransfer(input);
    if (control) {
      assertTransferId(control.backendTransferId);
      const indexed = this.#backendTransferOwners.get(control.backendTransferId);
      if (
        indexed
        && (indexed.workspaceId !== session.workspaceId || indexed.snapshotId !== transfer.id)
      ) return false;
    }
    const previous = session.snapshot;
    this.#releaseControl(session, transfer.id);
    session.transfers.delete(transfer.id);
    session.transfers.set(transfer.id, transfer);
    while (session.transfers.size > this.#transferLimit) {
      const oldest = session.transfers.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      session.transfers.delete(oldest);
      this.#releaseControl(session, oldest);
    }
    if (control) this.#bindControl(session, transfer.id, control);
    this.#emit(session, previous);
    return true;
  }

  /** Alias matching the vocabulary used by transfer-start adapters. */
  registerTransfer(
    owner: SftpSessionOwner,
    input: SftpTransferSnapshotInput | SftpTransferSnapshot,
    control?: SftpTransferControl,
  ): boolean {
    return this.addTransfer(owner, input, control);
  }

  registerTransferControl(
    owner: SftpSessionOwner,
    transferId: string,
    control: SftpTransferControl,
    starterPatch: Partial<SftpTransferStarterPatch> = {},
  ): boolean {
    if (this.#disposed || !owner || !isWorkspaceSessionId(owner.workspaceId)) return false;
    assertTransferId(transferId);
    const session = this.#sessions.get(owner.workspaceId);
    if (!session) return false;
    const exactOwner = this.isExactOwner(owner);
    const pendingControlOwner = session.pendingControlOwners.get(transferId);
    const retainedPendingOwner = ownersEqual(pendingControlOwner ?? null, owner);
    if (!exactOwner && !retainedPendingOwner) return false;
    if (retainedPendingOwner && session.controls.has(transferId)) return false;
    const transfer = session.transfers.get(transferId);
    if (!transfer || isTerminalTransferStatus(transfer.status)) return false;
    const next = freezeTransfer({
      ...transfer,
      ...starterPatch,
      id: transferId,
    });
    const retainedRoute = session.transferEventOwners.get(transferId);
    if (!this.#bindControl(session, transferId, control)) return false;
    session.pendingControlOwners.delete(transferId);
    if (retainedPendingOwner && retainedRoute) {
      session.transferEventOwners.set(transferId, retainedRoute);
    }
    if (JSON.stringify(next) !== JSON.stringify(transfer)) {
      const previous = session.snapshot;
      session.transfers.set(transferId, next);
      this.#emit(session, previous);
    }
    return true;
  }

  /**
   * Settle a starter which failed before returning a native control handle.
   * A retired owner is accepted only for the exact pre-existing transfer that
   * was retained across a failed SSH stop; generic stale-owner updates remain
   * forbidden.
   */
  failTransferStart(
    owner: SftpSessionOwner,
    transferId: string,
    reason: unknown,
  ): boolean {
    if (this.#disposed || !owner || !isWorkspaceSessionId(owner.workspaceId)) return false;
    assertTransferId(transferId);
    const session = this.#sessions.get(owner.workspaceId);
    if (!session) return false;
    const pendingControlOwner = session.pendingControlOwners.get(transferId);
    if (
      !this.isExactOwner(owner)
      && !ownersEqual(pendingControlOwner ?? null, owner)
    ) return false;
    const transfer = session.transfers.get(transferId);
    if (!transfer || isTerminalTransferStatus(transfer.status)) return false;
    const previous = session.snapshot;
    session.transfers.set(transferId, freezeTransfer({
      ...transfer,
      id: transferId,
      status: "failed",
      error: this.#safeError(reason),
    }));
    this.#releaseControl(session, transferId);
    this.#emit(session, previous);
    return true;
  }

  canControlTransfer(owner: SftpSessionOwner, transferId: string): boolean {
    if (!this.isExactOwner(owner)) return false;
    assertTransferId(transferId);
    return this.#sessions.get(owner.workspaceId)?.controls.has(transferId) === true;
  }

  #bindControl(
    session: MutableSftpSession,
    snapshotId: string,
    control: SftpTransferControl,
  ): boolean {
    assertTransferId(control.backendTransferId);
    const indexed = this.#backendTransferOwners.get(control.backendTransferId);
    if (
      indexed
      && (indexed.workspaceId !== session.workspaceId || indexed.snapshotId !== snapshotId)
    ) return false;
    this.#releaseControl(session, snapshotId);
    session.controls.set(snapshotId, control);
    this.#backendTransferOwners.set(control.backendTransferId, {
      workspaceId: session.workspaceId,
      snapshotId,
      control,
    });
    return true;
  }

  updateTransfer(
    owner: SftpSessionOwner,
    transferId: string,
    patch: SftpTransferSnapshotPatch,
  ): boolean {
    if (!this.isExactOwner(owner)) return false;
    assertTransferId(transferId);
    const session = this.#sessions.get(owner.workspaceId)!;
    const current = session.transfers.get(transferId);
    if (!current) return false;
    const next = freezeTransfer({ ...current, ...patch, id: transferId });
    if (JSON.stringify(next) === JSON.stringify(current)) return true;
    const previous = session.snapshot;
    session.transfers.set(transferId, next);
    this.#emit(session, previous);
    return true;
  }

  /** Apply a backend event only when owner and transfer identity are exact. */
  handleTransferEvent(
    owner: SftpSessionOwner,
    transferId: string,
    event: SftpTransferEvent,
  ): boolean {
    if (this.#disposed || !owner || !isWorkspaceSessionId(owner.workspaceId)) return false;
    assertTransferId(transferId);
    const session = this.#sessions.get(owner.workspaceId);
    if (!session?.owner) return false;
    const exactOwner = this.isExactOwner(owner);
    const retainedEventOwner = session.transferEventOwners.get(transferId);
    if (!exactOwner && !ownersEqual(retainedEventOwner ?? null, owner)) return false;
    const current = session.transfers.get(transferId);
    if (!current) return false;
    let patch: SftpTransferSnapshotPatch;
    let terminalEvent = false;
    switch (event.type) {
      case "queued":
        patch = { status: "queued" };
        break;
      case "started":
      case "resumed":
        patch = { status: "running" };
        break;
      case "progress":
        patch = {
          status: "running",
          bytesTransferred: event.bytesTransferred,
          totalBytes: event.totalBytes,
        };
        break;
      case "paused":
        patch = { status: "paused", checkpoint: event.checkpoint };
        break;
      case "completed":
        terminalEvent = true;
        patch = {
          status: "completed",
          bytesTransferred: event.checkpoint.totalBytes,
          totalBytes: event.checkpoint.totalBytes,
          checkpoint: event.checkpoint,
          error: undefined,
        };
        break;
      case "cancelled":
        terminalEvent = true;
        patch = { status: "cancelled", checkpoint: event.checkpoint };
        break;
      case "failed":
        terminalEvent = true;
        patch = {
          status: "failed",
          error: this.#safeError(event.message),
          checkpoint: event.checkpoint,
        };
        break;
      case "directoryScanning":
        patch = { status: "scanning", currentPath: undefined };
        break;
      case "directoryProgress":
        patch = {
          status: "running",
          filesCompleted: event.filesCompleted,
          totalFiles: event.totalFiles,
          bytesTransferred: event.bytesTransferred,
          totalBytes: event.totalBytes,
          currentPath: event.currentPath ?? undefined,
          directoryCheckpoint: event.checkpoint,
        };
        break;
      case "directoryCompleted":
        terminalEvent = true;
        patch = {
          status: "completed",
          filesCompleted: event.filesCompleted,
          totalFiles: event.filesCompleted,
          bytesTransferred: event.totalBytes,
          totalBytes: event.totalBytes,
          skippedEntries: event.skippedEntries,
          currentPath: undefined,
          directoryCheckpoint: event.checkpoint,
          error: undefined,
        };
        break;
      case "directoryCancelled":
        terminalEvent = true;
        patch = {
          status: "cancelled",
          currentPath: undefined,
          directoryCheckpoint: event.checkpoint,
        };
        break;
      case "directoryFailed":
        terminalEvent = true;
        patch = {
          status: "failed",
          error: this.#safeError(event.message),
          failedFiles: event.failedFiles,
          currentPath: undefined,
          directoryCheckpoint: event.checkpoint,
        };
        break;
      default: {
        const exhaustive: never = event;
        return exhaustive;
      }
    }
    const next = freezeTransfer({ ...current, ...patch, id: transferId });
    if (JSON.stringify(next) !== JSON.stringify(current)) {
      const previous = session.snapshot;
      session.transfers.set(transferId, next);
      this.#emit(session, previous);
    }
    if (terminalEvent) this.#releaseControl(session, transferId);
    return true;
  }

  /**
   * Invoke an injected native transfer action.  The exact owner is checked
   * immediately before invocation and again after it resolves; a forged or
   * stale backend ID can therefore never control another SSH session.
   */
  async controlTransfer(
    owner: SftpSessionOwner,
    transferId: string,
    action: SftpTransferControlAction,
  ): Promise<boolean> {
    if (!this.isExactOwner(owner)) return false;
    assertTransferId(transferId);
    const session = this.#sessions.get(owner.workspaceId)!;
    if (!session.transfers.has(transferId)) return false;
    const request: SftpTransferControlRequest = Object.freeze({
      owner: { ...owner },
      snapshotId: transferId,
      backendTransferId: session.controls.get(transferId)?.backendTransferId ?? "",
      action,
    });
    const privateControl = session.controls.get(transferId);
    if (!privateControl) return false;
    const localAction = privateControl?.[action];
    if (!localAction && !this.#dependencies.transferControl) return false;
    try {
      if (localAction) await localAction();
      else await this.#dependencies.transferControl!(request);
    } catch (reason) {
      if (this.isExactOwner(owner)) {
        this.updateTransfer(owner, transferId, {
          status: "failed",
          error: this.#safeError(reason),
        });
      }
      return false;
    }
    return this.isExactOwner(owner);
  }

  /** Alias used by control-button adapters. */
  control(
    owner: SftpSessionOwner,
    transferId: string,
    action: SftpTransferControlAction,
  ): Promise<boolean> {
    return this.controlTransfer(owner, transferId, action);
  }

  /** Drop all state and make every outstanding callback inert. */
  dispose(): void {
    if (this.#disposed) return;
    this.#disposed = true;
    for (const session of this.#sessions.values()) {
      session.owner = null;
      session.suspension = null;
      this.#clearControls(session);
      session.transfers.clear();
      session.transferEventOwners.clear();
      session.pendingControlOwners.clear();
      session.listeners.clear();
    }
    this.#sessions.clear();
    this.#backendSessionOwners.clear();
    this.#backendTransferOwners.clear();
    this.#globalListeners.clear();
    this.#activeWorkspaceId = null;
  }
}

export const createSftpSessionController = (
  dependencies: SftpSessionControllerDependencies,
  options?: SftpSessionStateOptions,
): SftpSessionController => new SftpSessionController(dependencies, options);
