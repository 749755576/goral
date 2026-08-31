import assert from "node:assert/strict";
import test from "node:test";

import {
  clampTerminalPaneRatio,
  collectTerminalPaneSessionIds,
  computeTerminalPaneGeometry,
  createTerminalPaneLayout,
  createTerminalPanePlacements,
  findNextTerminalPaneFocusSessionId,
  findTerminalPaneSplitCandidate,
  focusTerminalPane,
  MAX_TERMINAL_PANES,
  pruneTerminalPaneLayout,
  removeTerminalPane,
  resizeTerminalPaneSplit,
  shouldDissolveTerminalPaneLayout,
  splitTerminalPane,
  terminalPaneLayoutContains,
  moveTerminalPaneFocus,
} from "../../src/terminalPaneLayout.ts";
import {
  workspaceSessionIdFrom,
  type WorkspaceSessionId,
} from "../../src/terminalSessionRegistry.ts";

const uuid = (suffix: string): string => `00000000-0000-4000-8000-${suffix.padStart(12, "0")}`;
const sessionId = (suffix: string): WorkspaceSessionId => (
  workspaceSessionIdFrom(`ws-${uuid(suffix)}`)
);

const nodeIds = () => {
  let next = 0;
  return () => String(++next);
};

test("vertical split creates independent left and right panes and keeps source focus", () => {
  const a = sessionId("1");
  const b = sessionId("2");
  const ids = nodeIds();
  const base = createTerminalPaneLayout(a, ids);
  const layout = splitTerminalPane(base, a, b, "vertical", ids);
  const geometry = computeTerminalPaneGeometry(layout);

  assert.deepEqual(collectTerminalPaneSessionIds(layout.root), [a, b]);
  assert.equal(layout.focusedSessionId, a);
  assert.deepEqual(geometry.panes[a], { x: 0, y: 0, width: 0.5, height: 1 });
  assert.deepEqual(geometry.panes[b], { x: 0.5, y: 0, width: 0.5, height: 1 });
  assert.equal(geometry.handles[0].direction, "vertical");
  assert.ok(Object.isFrozen(layout));
  assert.ok(Object.isFrozen(layout.root));
});

test("horizontal split nests beside the exact focused pane without disturbing its sibling", () => {
  const a = sessionId("1");
  const b = sessionId("2");
  const c = sessionId("3");
  const ids = nodeIds();
  let layout = createTerminalPaneLayout(a, ids);
  layout = splitTerminalPane(layout, a, b, "vertical", ids);
  layout = splitTerminalPane(layout, a, c, "horizontal", ids);
  const geometry = computeTerminalPaneGeometry(layout);

  assert.deepEqual(geometry.panes[a], { x: 0, y: 0, width: 0.5, height: 0.5 });
  assert.deepEqual(geometry.panes[c], { x: 0, y: 0.5, width: 0.5, height: 0.5 });
  assert.deepEqual(geometry.panes[b], { x: 0.5, y: 0, width: 0.5, height: 1 });
  assert.equal(layout.focusedSessionId, a);
});

test("focus and render placements change presentation without changing the tree", () => {
  const a = sessionId("1");
  const b = sessionId("2");
  const ids = nodeIds();
  const layout = splitTerminalPane(createTerminalPaneLayout(a, ids), a, b, "vertical", ids);
  const focused = focusTerminalPane(layout, b);
  const placements = createTerminalPanePlacements(focused, b);

  assert.equal(focused.root === layout.root, false, "snapshots stay deeply immutable");
  assert.equal(focused.focusedSessionId, b);
  assert.equal(placements[a].focused, false);
  assert.equal(placements[b].focused, true);
  assert.equal(terminalPaneLayoutContains(focused, a), true);
  assert.throws(() => focusTerminalPane(focused, sessionId("99")), /SESSION_NOT_FOUND/);
});

test("resize preserves the legacy dynamic 120px minimum", () => {
  assert.equal(clampTerminalPaneRatio(0, 1_000), 0.12);
  assert.equal(clampTerminalPaneRatio(1, 1_000), 0.88);
  assert.equal(clampTerminalPaneRatio(0, 200), 0.5);
  assert.equal(clampTerminalPaneRatio(1, 200), 0.5);

  const a = sessionId("1");
  const b = sessionId("2");
  const ids = nodeIds();
  const layout = splitTerminalPane(createTerminalPaneLayout(a, ids), a, b, "vertical", ids);
  assert.equal(layout.root.type, "split");
  const resized = resizeTerminalPaneSplit(layout, layout.root.id, 0.3);
  const geometry = computeTerminalPaneGeometry(resized);
  assert.equal(geometry.panes[a].width, 0.3);
  assert.equal(geometry.panes[b].width, 0.7);
  assert.throws(() => resizeTerminalPaneSplit(layout, "missing", 0.4), /SPLIT_NOT_FOUND/);
});

test("closing a pane collapses only its exact branch and selects right then left", () => {
  const a = sessionId("1");
  const b = sessionId("2");
  const c = sessionId("3");
  const ids = nodeIds();
  let layout = createTerminalPaneLayout(a, ids);
  layout = splitTerminalPane(layout, a, b, "vertical", ids);
  layout = splitTerminalPane(layout, a, c, "horizontal", ids);
  layout = focusTerminalPane(layout, a);

  const withoutA = removeTerminalPane(layout, a)!;
  assert.deepEqual(collectTerminalPaneSessionIds(withoutA.root), [c, b]);
  assert.equal(withoutA.focusedSessionId, c);
  const withoutC = removeTerminalPane(withoutA, c)!;
  assert.deepEqual(collectTerminalPaneSessionIds(withoutC.root), [b]);
  assert.equal(withoutC.focusedSessionId, b);
  assert.equal(removeTerminalPane(withoutC, b), null);
});

test("pruning retired sessions never redirects a stale pane to a live runtime", () => {
  const a = sessionId("1");
  const b = sessionId("2");
  const c = sessionId("3");
  const ids = nodeIds();
  let layout = createTerminalPaneLayout(a, ids);
  layout = splitTerminalPane(layout, a, b, "vertical", ids);
  layout = splitTerminalPane(layout, b, c, "horizontal", ids);

  const pruned = pruneTerminalPaneLayout(layout, new Set([a, c]))!;
  assert.deepEqual(collectTerminalPaneSessionIds(pruned.root), [a, c]);
  assert.equal(terminalPaneLayoutContains(pruned, b), false);
  assert.equal(JSON.stringify(pruned).includes(b), false);
});

test("duplicates and the global 64-session workspace bound fail closed", () => {
  const ids = nodeIds();
  const first = sessionId("1");
  let layout = createTerminalPaneLayout(first, ids);
  assert.throws(
    () => splitTerminalPane(layout, first, first, "vertical", ids),
    /SESSION_DUPLICATE/,
  );
  for (let index = 2; index <= MAX_TERMINAL_PANES; index += 1) {
    layout = splitTerminalPane(
      layout,
      first,
      sessionId(String(index)),
      "vertical",
      ids,
    );
  }
  assert.equal(collectTerminalPaneSessionIds(layout.root).length, MAX_TERMINAL_PANES);
  assert.throws(
    () => splitTerminalPane(layout, first, sessionId("65"), "vertical", ids),
    /PANE_LIMIT_REACHED/,
  );
});

test("existing-tab merge candidate remains a separate right-then-left helper", () => {
  const a = sessionId("1");
  const b = sessionId("2");
  const c = sessionId("3");
  const d = sessionId("4");
  assert.equal(findTerminalPaneSplitCandidate([a, b, c, d], b, new Set([b, c])), d);
  assert.equal(findTerminalPaneSplitCandidate([a, b, c], b, new Set([b, c])), a);
  assert.equal(findTerminalPaneSplitCandidate([a], a, new Set([a])), null);
});

test("arrow focus uses resized pane geometry instead of tree order", () => {
  const a = sessionId("1");
  const b = sessionId("2");
  const c = sessionId("3");
  const ids = nodeIds();
  let layout = createTerminalPaneLayout(a, ids);
  layout = splitTerminalPane(layout, a, b, "vertical", ids);
  layout = splitTerminalPane(layout, b, c, "horizontal", ids);
  assert.equal(layout.root.type, "split");
  assert.equal(layout.root.second.type, "split");
  layout = resizeTerminalPaneSplit(layout, layout.root.second.id, 0.2);

  // B occurs first in the tree, but C's larger lower rectangle has its centre
  // closer to the centre of A and is therefore the geometric right neighbour.
  assert.equal(findNextTerminalPaneFocusSessionId(layout, a, "right"), c);
  assert.equal(findNextTerminalPaneFocusSessionId(layout, c, "left"), a);
  assert.equal(findNextTerminalPaneFocusSessionId(layout, sessionId("99"), "left"), null);
});

test("arrow focus wraps across every outer edge", () => {
  const a = sessionId("1");
  const b = sessionId("2");
  const c = sessionId("3");
  const d = sessionId("4");
  const ids = nodeIds();
  let layout = createTerminalPaneLayout(a, ids);
  layout = splitTerminalPane(layout, a, b, "vertical", ids);
  layout = splitTerminalPane(layout, a, c, "horizontal", ids);
  layout = splitTerminalPane(layout, b, d, "horizontal", ids);

  assert.equal(findNextTerminalPaneFocusSessionId(layout, a, "left"), b);
  assert.equal(findNextTerminalPaneFocusSessionId(layout, b, "right"), a);
  assert.equal(findNextTerminalPaneFocusSessionId(layout, a, "up"), c);
  assert.equal(findNextTerminalPaneFocusSessionId(layout, c, "down"), a);
});

test("geometric ties have a stable session-id tie-break independent of tree order", () => {
  const a = sessionId("1");
  const b = sessionId("2");
  const c = sessionId("3");
  const ids = nodeIds();
  let layout = createTerminalPaneLayout(a, ids);
  layout = splitTerminalPane(layout, a, c, "vertical", ids);
  layout = splitTerminalPane(layout, c, b, "horizontal", ids);

  assert.deepEqual(collectTerminalPaneSessionIds(layout.root), [a, c, b]);
  assert.equal(findNextTerminalPaneFocusSessionId(layout, a, "right"), b);
});

test("focus movement is immutable and a one-pane remainder requests workspace dissolve", () => {
  const a = sessionId("1");
  const b = sessionId("2");
  const ids = nodeIds();
  const single = createTerminalPaneLayout(a, ids);

  assert.equal(shouldDissolveTerminalPaneLayout(single), true);
  assert.equal(moveTerminalPaneFocus(single, "right"), single);

  const split = splitTerminalPane(single, a, b, "vertical", ids);
  assert.equal(shouldDissolveTerminalPaneLayout(split), false);
  const moved = moveTerminalPaneFocus(split, "right");
  assert.equal(moved.focusedSessionId, b);
  assert.notEqual(moved, split);
  assert.ok(Object.isFrozen(moved));

  const remainder = removeTerminalPane(moved, a)!;
  assert.equal(shouldDissolveTerminalPaneLayout(remainder), true);
  assert.equal(remainder.root.type, "pane");
  assert.equal(JSON.parse(JSON.stringify(remainder)).focusedSessionId, b);
});
