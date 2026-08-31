import type { WorkspaceSessionId } from "./terminalSessionRegistry.ts";

export type TerminalPaneSplitDirection = "horizontal" | "vertical";

export type TerminalPaneFocusDirection = "up" | "down" | "left" | "right";

export type TerminalPaneSplitPosition = "before" | "after";

export type TerminalPaneNode = Readonly<{
  id: string;
  type: "pane";
  sessionId: WorkspaceSessionId;
}>;

export type TerminalPaneSplitNode = Readonly<{
  id: string;
  type: "split";
  direction: TerminalPaneSplitDirection;
  ratio: number;
  first: TerminalPaneLayoutNode;
  second: TerminalPaneLayoutNode;
}>;

export type TerminalPaneLayoutNode = TerminalPaneNode | TerminalPaneSplitNode;

export type TerminalPaneLayoutSnapshot = Readonly<{
  root: TerminalPaneLayoutNode;
  focusedSessionId: WorkspaceSessionId;
}>;

export type TerminalPaneRect = Readonly<{
  x: number;
  y: number;
  width: number;
  height: number;
}>;

export type TerminalPanePlacement = Readonly<{
  rect: TerminalPaneRect;
  focused: boolean;
}>;

export type TerminalPaneSplitHandle = Readonly<{
  splitId: string;
  direction: TerminalPaneSplitDirection;
  ratio: number;
  rect: TerminalPaneRect;
}>;

export type TerminalPaneGeometry = Readonly<{
  panes: Readonly<Record<string, TerminalPaneRect>>;
  handles: readonly TerminalPaneSplitHandle[];
}>;

// The global terminal catalog already enforces the product's 64-session bound.
// Terminal workspaces use the same ceiling; the legacy terminal workspace did
// not share the unrelated eight-pane side-panel-tool limit.
export const MAX_TERMINAL_PANES = 64;
export const MIN_TERMINAL_PANE_PIXELS = 120;
const ABSOLUTE_MIN_TERMINAL_PANE_RATIO = 0.01;
const ABSOLUTE_MAX_TERMINAL_PANE_RATIO = 0.99;

type IdFactory = () => string;

const createNodeId = (prefix: "pane" | "split", idFactory: IdFactory): string => {
  const suffix = idFactory();
  if (typeof suffix !== "string" || suffix.length === 0 || suffix.length > 128) {
    throw new Error("TERMINAL_PANE_NODE_ID_INVALID");
  }
  return `${prefix}-${suffix}`;
};

const freezeNode = (node: TerminalPaneLayoutNode): TerminalPaneLayoutNode => {
  if (node.type === "pane") return Object.freeze({ ...node });
  return Object.freeze({
    ...node,
    first: freezeNode(node.first),
    second: freezeNode(node.second),
  });
};

const freezeLayout = (
  root: TerminalPaneLayoutNode,
  focusedSessionId: WorkspaceSessionId,
): TerminalPaneLayoutSnapshot => Object.freeze({
  root: freezeNode(root),
  focusedSessionId,
});

const defaultIdFactory = (): string => crypto.randomUUID();

export const createTerminalPaneLayout = (
  sessionId: WorkspaceSessionId,
  idFactory: IdFactory = defaultIdFactory,
): TerminalPaneLayoutSnapshot => freezeLayout({
  id: createNodeId("pane", idFactory),
  type: "pane",
  sessionId,
}, sessionId);

export const collectTerminalPaneSessionIds = (
  node: TerminalPaneLayoutNode,
): readonly WorkspaceSessionId[] => (
  node.type === "pane"
    ? [node.sessionId]
    : [
        ...collectTerminalPaneSessionIds(node.first),
        ...collectTerminalPaneSessionIds(node.second),
      ]
);

export const terminalPaneLayoutContains = (
  layout: TerminalPaneLayoutSnapshot,
  sessionId: WorkspaceSessionId,
): boolean => collectTerminalPaneSessionIds(layout.root).includes(sessionId);

const insertTerminalPane = (
  layout: TerminalPaneLayoutSnapshot,
  targetSessionId: WorkspaceSessionId,
  newSessionId: WorkspaceSessionId,
  direction: TerminalPaneSplitDirection,
  position: TerminalPaneSplitPosition,
  idFactory: IdFactory,
): TerminalPaneLayoutSnapshot => {
  const sessionIds = collectTerminalPaneSessionIds(layout.root);
  if (!sessionIds.includes(targetSessionId)) {
    throw new Error("TERMINAL_PANE_TARGET_NOT_FOUND");
  }
  if (sessionIds.includes(newSessionId)) {
    throw new Error("TERMINAL_PANE_SESSION_DUPLICATE");
  }
  if (sessionIds.length >= MAX_TERMINAL_PANES) {
    throw new Error("TERMINAL_PANE_LIMIT_REACHED");
  }
  if (direction !== "horizontal" && direction !== "vertical") {
    throw new Error("TERMINAL_PANE_DIRECTION_INVALID");
  }
  if (position !== "before" && position !== "after") {
    throw new Error("TERMINAL_PANE_POSITION_INVALID");
  }

  const newPane: TerminalPaneNode = {
    id: createNodeId("pane", idFactory),
    type: "pane",
    sessionId: newSessionId,
  };
  let replaced = false;
  const insert = (node: TerminalPaneLayoutNode): TerminalPaneLayoutNode => {
    if (node.type === "pane") {
      if (node.sessionId !== targetSessionId) return node;
      replaced = true;
      return {
        id: createNodeId("split", idFactory),
        type: "split",
        direction,
        ratio: 0.5,
        first: position === "before" ? newPane : node,
        second: position === "before" ? node : newPane,
      };
    }
    return {
      ...node,
      first: insert(node.first),
      second: insert(node.second),
    };
  };
  const root = insert(layout.root);
  if (!replaced) throw new Error("TERMINAL_PANE_TARGET_NOT_FOUND");
  return freezeLayout(root, layout.focusedSessionId);
};

export const splitTerminalPane = (
  layout: TerminalPaneLayoutSnapshot,
  targetSessionId: WorkspaceSessionId,
  newSessionId: WorkspaceSessionId,
  direction: TerminalPaneSplitDirection,
  idFactory: IdFactory = defaultIdFactory,
): TerminalPaneLayoutSnapshot => insertTerminalPane(
  layout,
  targetSessionId,
  newSessionId,
  direction,
  "after",
  idFactory,
);

/** Insert a pre-existing tab at the exact edge selected by a drag/drop hint. */
export const splitTerminalPaneAtPosition = (
  layout: TerminalPaneLayoutSnapshot,
  targetSessionId: WorkspaceSessionId,
  newSessionId: WorkspaceSessionId,
  direction: TerminalPaneSplitDirection,
  position: TerminalPaneSplitPosition,
  idFactory: IdFactory = defaultIdFactory,
): TerminalPaneLayoutSnapshot => insertTerminalPane(
  layout,
  targetSessionId,
  newSessionId,
  direction,
  position,
  idFactory,
);

export const focusTerminalPane = (
  layout: TerminalPaneLayoutSnapshot,
  sessionId: WorkspaceSessionId,
): TerminalPaneLayoutSnapshot => {
  if (!terminalPaneLayoutContains(layout, sessionId)) {
    throw new Error("TERMINAL_PANE_SESSION_NOT_FOUND");
  }
  if (layout.focusedSessionId === sessionId) return layout;
  return freezeLayout(layout.root, sessionId);
};

const removeSessionNode = (
  node: TerminalPaneLayoutNode,
  sessionId: WorkspaceSessionId,
): TerminalPaneLayoutNode | null => {
  if (node.type === "pane") return node.sessionId === sessionId ? null : node;
  const first = removeSessionNode(node.first, sessionId);
  const second = removeSessionNode(node.second, sessionId);
  if (!first) return second;
  if (!second) return first;
  if (first === node.first && second === node.second) return node;
  return { ...node, first, second };
};

export const removeTerminalPane = (
  layout: TerminalPaneLayoutSnapshot,
  sessionId: WorkspaceSessionId,
): TerminalPaneLayoutSnapshot | null => {
  const previousIds = collectTerminalPaneSessionIds(layout.root);
  const removedIndex = previousIds.indexOf(sessionId);
  if (removedIndex < 0) return layout;
  const root = removeSessionNode(layout.root, sessionId);
  if (!root) return null;
  const nextIds = collectTerminalPaneSessionIds(root);
  const focusedSessionId = layout.focusedSessionId === sessionId
    ? previousIds.slice(removedIndex + 1).find((id) => nextIds.includes(id))
      ?? previousIds.slice(0, removedIndex).reverse().find((id) => nextIds.includes(id))
      ?? nextIds[0]
    : layout.focusedSessionId;
  return freezeLayout(root, focusedSessionId);
};

export const pruneTerminalPaneLayout = (
  layout: TerminalPaneLayoutSnapshot,
  liveSessionIds: ReadonlySet<WorkspaceSessionId>,
): TerminalPaneLayoutSnapshot | null => {
  let next: TerminalPaneLayoutSnapshot | null = layout;
  for (const sessionId of collectTerminalPaneSessionIds(layout.root)) {
    if (!liveSessionIds.has(sessionId) && next) {
      next = removeTerminalPane(next, sessionId);
    }
  }
  return next;
};

const clampRatio = (ratio: number): number => {
  if (!Number.isFinite(ratio)) throw new Error("TERMINAL_PANE_RATIO_INVALID");
  return Math.min(
    ABSOLUTE_MAX_TERMINAL_PANE_RATIO,
    Math.max(ABSOLUTE_MIN_TERMINAL_PANE_RATIO, ratio),
  );
};

/** Match the legacy pane rule: 120px minimum, or an equal half when smaller. */
export const clampTerminalPaneRatio = (
  ratio: number,
  splitSizePixels: number,
): number => {
  if (!Number.isFinite(splitSizePixels) || splitSizePixels <= 0) {
    throw new Error("TERMINAL_PANE_SPLIT_SIZE_INVALID");
  }
  const minimumPixels = Math.min(MIN_TERMINAL_PANE_PIXELS, splitSizePixels / 2);
  const minimumRatio = minimumPixels / splitSizePixels;
  return Math.min(1 - minimumRatio, Math.max(minimumRatio, ratio));
};

export const resizeTerminalPaneSplit = (
  layout: TerminalPaneLayoutSnapshot,
  splitId: string,
  ratio: number,
): TerminalPaneLayoutSnapshot => {
  const normalizedRatio = clampRatio(ratio);
  let matched = false;
  const patch = (node: TerminalPaneLayoutNode): TerminalPaneLayoutNode => {
    if (node.type === "pane") return node;
    if (node.id === splitId) {
      matched = true;
      if (node.ratio === normalizedRatio) return node;
      return { ...node, ratio: normalizedRatio };
    }
    return {
      ...node,
      first: patch(node.first),
      second: patch(node.second),
    };
  };
  const root = patch(layout.root);
  if (!matched) throw new Error("TERMINAL_PANE_SPLIT_NOT_FOUND");
  if (root === layout.root) return layout;
  return freezeLayout(root, layout.focusedSessionId);
};

export const computeTerminalPaneGeometry = (
  layout: TerminalPaneLayoutSnapshot,
): TerminalPaneGeometry => {
  const panes: Record<string, TerminalPaneRect> = {};
  const handles: TerminalPaneSplitHandle[] = [];
  const visit = (node: TerminalPaneLayoutNode, rect: TerminalPaneRect): void => {
    if (node.type === "pane") {
      panes[node.sessionId] = Object.freeze({ ...rect });
      return;
    }
    const ratio = clampRatio(node.ratio);
    handles.push(Object.freeze({
      splitId: node.id,
      direction: node.direction,
      ratio,
      rect: Object.freeze({ ...rect }),
    }));
    if (node.direction === "vertical") {
      visit(node.first, {
        ...rect,
        width: rect.width * ratio,
      });
      visit(node.second, {
        x: rect.x + rect.width * ratio,
        y: rect.y,
        width: rect.width * (1 - ratio),
        height: rect.height,
      });
      return;
    }
    visit(node.first, {
      ...rect,
      height: rect.height * ratio,
    });
    visit(node.second, {
      x: rect.x,
      y: rect.y + rect.height * ratio,
      width: rect.width,
      height: rect.height * (1 - ratio),
    });
  };
  visit(layout.root, { x: 0, y: 0, width: 1, height: 1 });
  return Object.freeze({
    panes: Object.freeze(panes),
    handles: Object.freeze(handles),
  });
};

export const createTerminalPanePlacements = (
  layout: TerminalPaneLayoutSnapshot,
  focusedSessionId: WorkspaceSessionId,
): Readonly<Record<string, TerminalPanePlacement>> => {
  const geometry = computeTerminalPaneGeometry(layout);
  const placements: Record<string, TerminalPanePlacement> = {};
  for (const [sessionId, rect] of Object.entries(geometry.panes)) {
    placements[sessionId] = Object.freeze({
      rect,
      focused: sessionId === focusedSessionId,
    });
  }
  return Object.freeze(placements);
};

const TERMINAL_PANE_GEOMETRY_EPSILON = 1e-9;

type TerminalPaneFocusCandidate = Readonly<{
  sessionId: WorkspaceSessionId;
  rect: TerminalPaneRect;
}>;

const compareFocusCandidates = (
  current: TerminalPaneRect,
  direction: TerminalPaneFocusDirection,
  left: TerminalPaneFocusCandidate,
  right: TerminalPaneFocusCandidate,
): number => {
  const horizontal = direction === "left" || direction === "right";
  const currentAxisCenter = horizontal
    ? current.x + current.width / 2
    : current.y + current.height / 2;
  const currentCrossCenter = horizontal
    ? current.y + current.height / 2
    : current.x + current.width / 2;
  const currentCrossStart = horizontal ? current.y : current.x;
  const currentCrossEnd = currentCrossStart + (horizontal ? current.height : current.width);

  const score = (candidate: TerminalPaneFocusCandidate): readonly number[] => {
    const axisStart = horizontal ? candidate.rect.x : candidate.rect.y;
    const axisSize = horizontal ? candidate.rect.width : candidate.rect.height;
    const crossStart = horizontal ? candidate.rect.y : candidate.rect.x;
    const crossSize = horizontal ? candidate.rect.height : candidate.rect.width;
    const axisCenter = axisStart + axisSize / 2;
    const crossCenter = crossStart + crossSize / 2;
    const crossEnd = crossStart + crossSize;
    const crossGap = Math.max(
      0,
      currentCrossStart - crossEnd,
      crossStart - currentCrossEnd,
    );
    return [
      crossGap > TERMINAL_PANE_GEOMETRY_EPSILON ? 1 : 0,
      Math.abs(axisCenter - currentAxisCenter),
      crossGap,
      Math.abs(crossCenter - currentCrossCenter),
    ];
  };

  const leftScore = score(left);
  const rightScore = score(right);
  for (let index = 0; index < leftScore.length; index += 1) {
    const delta = leftScore[index] - rightScore[index];
    if (Math.abs(delta) > TERMINAL_PANE_GEOMETRY_EPSILON) return delta;
  }

  // Session IDs are globally unique and stable, so this final comparison makes
  // an otherwise geometrically ambiguous choice independent of tree order.
  return String(left.sessionId).localeCompare(String(right.sessionId));
};

/**
 * Resolve Ctrl+Alt+Arrow pane navigation from computed pane rectangles.
 * At an outer edge navigation wraps to the opposite-most row or column.
 */
export const findNextTerminalPaneFocusSessionId = (
  layout: TerminalPaneLayoutSnapshot,
  currentSessionId: WorkspaceSessionId,
  direction: TerminalPaneFocusDirection,
): WorkspaceSessionId | null => {
  const geometry = computeTerminalPaneGeometry(layout);
  const current = geometry.panes[currentSessionId];
  if (!current) return null;

  const candidates: TerminalPaneFocusCandidate[] = Object.entries(geometry.panes)
    .filter(([sessionId]) => sessionId !== currentSessionId)
    .map(([sessionId, rect]) => ({
      sessionId: sessionId as WorkspaceSessionId,
      rect,
    }));
  if (candidates.length === 0) return null;

  const currentRight = current.x + current.width;
  const currentBottom = current.y + current.height;
  let directional = candidates.filter(({ rect }) => {
    switch (direction) {
      case "left":
        return rect.x + rect.width <= current.x + TERMINAL_PANE_GEOMETRY_EPSILON;
      case "right":
        return rect.x >= currentRight - TERMINAL_PANE_GEOMETRY_EPSILON;
      case "up":
        return rect.y + rect.height <= current.y + TERMINAL_PANE_GEOMETRY_EPSILON;
      case "down":
        return rect.y >= currentBottom - TERMINAL_PANE_GEOMETRY_EPSILON;
    }
  });

  if (directional.length === 0) {
    const edge = (candidate: TerminalPaneFocusCandidate): number => {
      switch (direction) {
        case "left": return candidate.rect.x + candidate.rect.width;
        case "right": return candidate.rect.x;
        case "up": return candidate.rect.y + candidate.rect.height;
        case "down": return candidate.rect.y;
      }
    };
    const targetEdge = direction === "left" || direction === "up"
      ? Math.max(...candidates.map(edge))
      : Math.min(...candidates.map(edge));
    directional = candidates.filter((candidate) => (
      Math.abs(edge(candidate) - targetEdge) <= TERMINAL_PANE_GEOMETRY_EPSILON
    ));
  }

  directional.sort((left, right) => (
    compareFocusCandidates(current, direction, left, right)
  ));
  return directional[0]?.sessionId ?? null;
};

export const moveTerminalPaneFocus = (
  layout: TerminalPaneLayoutSnapshot,
  direction: TerminalPaneFocusDirection,
): TerminalPaneLayoutSnapshot => {
  const nextSessionId = findNextTerminalPaneFocusSessionId(
    layout,
    layout.focusedSessionId,
    direction,
  );
  return nextSessionId ? focusTerminalPane(layout, nextSessionId) : layout;
};

/** A one-pane tree no longer needs workspace chrome and can become a normal tab. */
export const shouldDissolveTerminalPaneLayout = (
  layout: TerminalPaneLayoutSnapshot,
): boolean => layout.root.type === "pane";

/** Pick the nearest tab to the right, then to the left, that is not already tiled. */
export const findTerminalPaneSplitCandidate = (
  order: readonly WorkspaceSessionId[],
  targetSessionId: WorkspaceSessionId,
  tiledSessionIds: ReadonlySet<WorkspaceSessionId>,
): WorkspaceSessionId | null => {
  const targetIndex = order.indexOf(targetSessionId);
  if (targetIndex < 0) return null;
  for (let index = targetIndex + 1; index < order.length; index += 1) {
    const candidate = order[index];
    if (!tiledSessionIds.has(candidate)) return candidate;
  }
  for (let index = targetIndex - 1; index >= 0; index -= 1) {
    const candidate = order[index];
    if (!tiledSessionIds.has(candidate)) return candidate;
  }
  return null;
};
