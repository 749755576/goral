import type { WorkspaceSessionId } from "./terminalSessionRegistry.ts";

export type TerminalWorkspaceSessionTab = Readonly<{
  type: "session";
  sessionId: WorkspaceSessionId;
}>;

export type TerminalWorkspaceGroupTab = Readonly<{
  type: "workspace";
  sessionIds: readonly WorkspaceSessionId[];
}>;

export type TerminalWorkspaceTab = TerminalWorkspaceSessionTab | TerminalWorkspaceGroupTab;

/**
 * Collapse every tiled session into one chrome slot without changing the
 * registry order. The workspace occupies the position of its first live
 * member; dissolving it therefore restores every session to its original
 * deterministic position without moving or recreating any runtime.
 */
export const createTerminalWorkspaceTabs = (
  order: readonly WorkspaceSessionId[],
  tiledSessionIds: readonly WorkspaceSessionId[],
): readonly TerminalWorkspaceTab[] => {
  const liveIds = new Set(order);
  const tiledIds = new Set(
    tiledSessionIds.filter((sessionId) => liveIds.has(sessionId)),
  );
  if (tiledIds.size < 2) {
    return Object.freeze(order.map((sessionId) => Object.freeze({
      type: "session" as const,
      sessionId,
    })));
  }

  const orderedWorkspaceIds = Object.freeze(
    order.filter((sessionId) => tiledIds.has(sessionId)),
  );
  const tabs: TerminalWorkspaceTab[] = [];
  let workspaceInserted = false;
  for (const sessionId of order) {
    if (!tiledIds.has(sessionId)) {
      tabs.push(Object.freeze({ type: "session", sessionId }));
      continue;
    }
    if (!workspaceInserted) {
      tabs.push(Object.freeze({
        type: "workspace",
        sessionIds: orderedWorkspaceIds,
      }));
      workspaceInserted = true;
    }
  }
  return Object.freeze(tabs);
};
