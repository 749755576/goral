import assert from "node:assert/strict";
import test from "node:test";

import {
  clampTerminalSidePanelWidth,
  getTerminalSidePanelWidthBounds,
  resizeTerminalSidePanelWidth,
  TERMINAL_CENTER_MIN_WIDTH,
  TERMINAL_SIDE_PANEL_MAX_WIDTH,
  TERMINAL_SIDE_PANEL_MIN_WIDTH,
  type TerminalSidePanelId,
} from "../../src/terminalSidePanel.ts";

test("terminal side panel exposes the implemented SFTP and AI tools", () => {
  const slots: readonly TerminalSidePanelId[] = ["sftp", "ai"];
  assert.deepEqual(slots, ["sftp", "ai"]);
});

test("terminal side panel width keeps the legacy minimum and a 320px terminal", () => {
  const containerWidth = 1_000;
  const bounds = getTerminalSidePanelWidthBounds(containerWidth);

  assert.deepEqual(bounds, {
    min: TERMINAL_SIDE_PANEL_MIN_WIDTH,
    max: containerWidth - TERMINAL_CENTER_MIN_WIDTH,
  });
  assert.equal(clampTerminalSidePanelWidth(100, containerWidth), 280);
  assert.equal(clampTerminalSidePanelWidth(400, containerWidth), 400);
  assert.equal(clampTerminalSidePanelWidth(900, containerWidth), 680);
});

test("terminal side panel retains the legacy 1200px upper bound in wide containers", () => {
  assert.equal(
    getTerminalSidePanelWidthBounds(2_000).max,
    TERMINAL_SIDE_PANEL_MAX_WIDTH,
  );
  assert.equal(clampTerminalSidePanelWidth(1_500, 2_000), 1_200);
});

test("right-docked resize grows leftward, shrinks rightward, and clamps both ends", () => {
  assert.equal(resizeTerminalSidePanelWidth(400, 900, 820, 1_000), 480);
  assert.equal(resizeTerminalSidePanelWidth(400, 900, 980, 1_000), 320);
  assert.equal(resizeTerminalSidePanelWidth(400, 900, 1_200, 1_000), 280);
  assert.equal(resizeTerminalSidePanelWidth(650, 900, 700, 1_000), 680);
});

test("invalid measurements fail to stable finite bounds", () => {
  assert.deepEqual(getTerminalSidePanelWidthBounds(Number.NaN), { min: 280, max: 280 });
  assert.equal(clampTerminalSidePanelWidth(Number.POSITIVE_INFINITY, 1_000), 280);
  assert.equal(resizeTerminalSidePanelWidth(400, Number.NaN, 500, 1_000), 400);
});
