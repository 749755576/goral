import assert from "node:assert/strict";
import test from "node:test";

import { resolveTerminalPaneDropHint } from "../../src/terminalPaneDrag.ts";
import {
  collectTerminalPaneSessionIds,
  computeTerminalPaneGeometry,
  createTerminalPaneLayout,
  splitTerminalPane,
  splitTerminalPaneAtPosition,
} from "../../src/terminalPaneLayout.ts";
import {
  workspaceSessionIdFrom,
  type WorkspaceSessionId,
} from "../../src/terminalSessionRegistry.ts";

const sessionId = (suffix: string): WorkspaceSessionId => workspaceSessionIdFrom(
  `ws-00000000-0000-4000-8000-${suffix.padStart(12, "0")}`,
);
const nodeIds = () => {
  let next = 0;
  return () => String(++next);
};

test("drop hints target the exact nested pane and preview its selected edge", () => {
  const [a, b, c] = ["1", "2", "3"].map(sessionId);
  const ids = nodeIds();
  const layout = splitTerminalPane(createTerminalPaneLayout(a, ids), a, b, "vertical", ids);

  const hint = resolveTerminalPaneDropHint(layout, { x: 0.6, y: 0.9 });
  assert.deepEqual(hint, {
    targetSessionId: b,
    direction: "horizontal",
    position: "after",
    previewRect: { x: 0.5, y: 0.5, width: 0.5, height: 0.5 },
  });

  const inserted = splitTerminalPaneAtPosition(
    layout,
    hint!.targetSessionId,
    c,
    hint!.direction,
    hint!.position,
    ids,
  );
  assert.deepEqual(collectTerminalPaneSessionIds(inserted.root), [a, b, c]);
  assert.deepEqual(computeTerminalPaneGeometry(inserted).panes[c], {
    x: 0.5,
    y: 0.5,
    width: 0.5,
    height: 0.5,
  });
  assert.equal(inserted.focusedSessionId, a, "dragging a tab must not steal pane focus");
});

test("left and top drops insert before the target while right and bottom insert after", () => {
  const [a, b, c, d, e] = ["1", "2", "3", "4", "5"].map(sessionId);
  const ids = nodeIds();
  const base = createTerminalPaneLayout(a, ids);

  const left = resolveTerminalPaneDropHint(base, { x: 0.05, y: 0.5 })!;
  assert.deepEqual([left.direction, left.position], ["vertical", "before"]);
  let layout = splitTerminalPaneAtPosition(base, a, b, left.direction, left.position, ids);
  assert.deepEqual(collectTerminalPaneSessionIds(layout.root), [b, a]);

  const top = resolveTerminalPaneDropHint(layout, { x: 0.75, y: 0.05 })!;
  assert.deepEqual([top.targetSessionId, top.direction, top.position], [a, "horizontal", "before"]);
  layout = splitTerminalPaneAtPosition(layout, a, c, top.direction, top.position, ids);

  const right = resolveTerminalPaneDropHint(layout, { x: 0.95, y: 0.75 })!;
  assert.deepEqual([right.targetSessionId, right.direction, right.position], [a, "vertical", "after"]);
  layout = splitTerminalPaneAtPosition(layout, a, d, right.direction, right.position, ids);

  const bottom = resolveTerminalPaneDropHint(layout, { x: 0.6, y: 0.48 })!;
  assert.equal(bottom.position, "after");
  layout = splitTerminalPaneAtPosition(
    layout,
    bottom.targetSessionId,
    e,
    bottom.direction,
    bottom.position,
    ids,
  );
  assert.equal(collectTerminalPaneSessionIds(layout.root).length, 5);
});

test("drop hint rejects non-finite and out-of-stage coordinates", () => {
  const layout = createTerminalPaneLayout(sessionId("1"), nodeIds());
  assert.equal(resolveTerminalPaneDropHint(layout, { x: -0.1, y: 0.5 }), null);
  assert.equal(resolveTerminalPaneDropHint(layout, { x: 0.5, y: 1.1 }), null);
  assert.equal(resolveTerminalPaneDropHint(layout, { x: Number.NaN, y: 0.5 }), null);
});
