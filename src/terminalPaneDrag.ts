import {
  computeTerminalPaneGeometry,
  type TerminalPaneLayoutSnapshot,
  type TerminalPaneRect,
  type TerminalPaneSplitDirection,
  type TerminalPaneSplitPosition,
} from "./terminalPaneLayout.ts";
import type { WorkspaceSessionId } from "./terminalSessionRegistry.ts";

export type TerminalPaneDropHint = Readonly<{
  targetSessionId: WorkspaceSessionId;
  direction: TerminalPaneSplitDirection;
  position: TerminalPaneSplitPosition;
  previewRect: TerminalPaneRect;
}>;

/** Resolve the legacy four-edge drop gesture from normalized stage coordinates. */
export const resolveTerminalPaneDropHint = (
  layout: TerminalPaneLayoutSnapshot,
  point: Readonly<{ x: number; y: number }>,
): TerminalPaneDropHint | null => {
  if (
    !Number.isFinite(point.x)
    || !Number.isFinite(point.y)
    || point.x < 0
    || point.x > 1
    || point.y < 0
    || point.y > 1
  ) return null;

  const geometry = computeTerminalPaneGeometry(layout);
  const target = Object.entries(geometry.panes).find(([, rect]) => (
    point.x >= rect.x
    && point.x <= rect.x + rect.width
    && point.y >= rect.y
    && point.y <= rect.y + rect.height
  ));
  if (!target) return null;

  const [targetSessionId, rect] = target as [WorkspaceSessionId, TerminalPaneRect];
  const relativeX = (point.x - rect.x) / rect.width;
  const relativeY = (point.y - rect.y) / rect.height;
  const vertical = Math.abs(relativeX - 0.5) > Math.abs(relativeY - 0.5);
  const direction: TerminalPaneSplitDirection = vertical ? "vertical" : "horizontal";
  const position: TerminalPaneSplitPosition = vertical
    ? (relativeX < 0.5 ? "before" : "after")
    : (relativeY < 0.5 ? "before" : "after");

  const previewRect: TerminalPaneRect = direction === "vertical"
    ? {
        x: position === "before" ? rect.x : rect.x + rect.width / 2,
        y: rect.y,
        width: rect.width / 2,
        height: rect.height,
      }
    : {
        x: rect.x,
        y: position === "before" ? rect.y : rect.y + rect.height / 2,
        width: rect.width,
        height: rect.height / 2,
      };

  return Object.freeze({
    targetSessionId,
    direction,
    position,
    previewRect: Object.freeze(previewRect),
  });
};
