import type {
  SftpSessionOwner,
  SftpSessionSnapshot,
} from "./sftpSessionController.ts";
import type { WorkspaceSessionId } from "./terminalSessionRegistry.ts";

/** One render-safe SFTP view: state and authority always belong to one workspace. */
export type ActiveSftpProjection = Readonly<{
  workspaceId: WorkspaceSessionId;
  owner: SftpSessionOwner;
  snapshot: SftpSessionSnapshot;
}>;

const ownersEqual = (left: SftpSessionOwner, right: SftpSessionOwner): boolean => (
  left.workspaceId === right.workspaceId
  && left.operationGeneration === right.operationGeneration
  && left.backendSessionId === right.backendSessionId
  && left.sftpGeneration === right.sftpGeneration
);

export const createActiveSftpProjection = (
  owner: SftpSessionOwner,
  snapshot: SftpSessionSnapshot,
): ActiveSftpProjection => {
  if (owner.workspaceId !== snapshot.workspaceId) {
    throw new Error("SFTP_ACTIVE_PROJECTION_WORKSPACE_MISMATCH");
  }
  return Object.freeze({
    workspaceId: owner.workspaceId,
    owner: Object.freeze({ ...owner }),
    snapshot,
  });
};

/**
 * Select a projection only when the active tab, snapshot and exact authority
 * all agree. A stale tab snapshot must never be paired with the new tab owner.
 */
export const resolveActiveSftpProjection = (
  activeWorkspaceId: WorkspaceSessionId | null,
  projection: ActiveSftpProjection | null,
  isExactOwner: (owner: SftpSessionOwner) => boolean,
): ActiveSftpProjection | null => {
  if (
    activeWorkspaceId === null
    || projection === null
    || projection.workspaceId !== activeWorkspaceId
    || projection.owner.workspaceId !== activeWorkspaceId
    || projection.snapshot.workspaceId !== activeWorkspaceId
    || !isExactOwner(projection.owner)
  ) return null;
  return projection;
};

/** Exact guard used again when a mutation resumes after an async boundary. */
export const projectionOwnsSftpMutation = (
  projection: ActiveSftpProjection | null,
  activeWorkspaceId: WorkspaceSessionId | null,
  owner: SftpSessionOwner,
  isExactOwner: (candidate: SftpSessionOwner) => boolean,
): boolean => {
  const active = resolveActiveSftpProjection(
    activeWorkspaceId,
    projection,
    isExactOwner,
  );
  return active !== null && ownersEqual(active.owner, owner);
};
