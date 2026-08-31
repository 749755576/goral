import assert from "node:assert/strict";
import test from "node:test";

import { createTerminalWorkspaceTabs } from "../../src/terminalWorkspaceTabs.ts";
import {
  workspaceSessionIdFrom,
  type WorkspaceSessionId,
} from "../../src/terminalSessionRegistry.ts";

const sessionId = (suffix: string): WorkspaceSessionId => workspaceSessionIdFrom(
  `ws-00000000-0000-4000-8000-${suffix.padStart(12, "0")}`,
);

test("tiled sessions collapse into one slot at the first member position", () => {
  const [a, b, c, d] = ["1", "2", "3", "4"].map(sessionId);
  const tabs = createTerminalWorkspaceTabs([a, b, c, d], [b, d]);

  assert.deepEqual(tabs, [
    { type: "session", sessionId: a },
    { type: "workspace", sessionIds: [b, d] },
    { type: "session", sessionId: c },
  ]);
  assert.ok(Object.isFrozen(tabs));
  assert.ok(Object.isFrozen(tabs[1]));
  assert.ok(tabs[1].type === "workspace" && Object.isFrozen(tabs[1].sessionIds));
});

test("workspace member tree order cannot reorder the global chrome catalog", () => {
  const [a, b, c, d] = ["1", "2", "3", "4"].map(sessionId);
  const tabs = createTerminalWorkspaceTabs([a, b, c, d], [d, b, c]);

  assert.deepEqual(tabs, [
    { type: "session", sessionId: a },
    { type: "workspace", sessionIds: [b, c, d] },
  ]);
});

test("dissolved, stale, or single-pane layouts expose ordinary tabs", () => {
  const [a, b, stale] = ["1", "2", "3"].map(sessionId);

  assert.deepEqual(createTerminalWorkspaceTabs([a, b], []), [
    { type: "session", sessionId: a },
    { type: "session", sessionId: b },
  ]);
  assert.deepEqual(createTerminalWorkspaceTabs([a, b], [a, stale]), [
    { type: "session", sessionId: a },
    { type: "session", sessionId: b },
  ]);
});
