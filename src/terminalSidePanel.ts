export type TerminalSidePanelId = "sftp" | "ai" | "docker";

export const TERMINAL_SIDE_PANEL_MIN_WIDTH = 280;
export const TERMINAL_SIDE_PANEL_MAX_WIDTH = 1_200;
export const TERMINAL_CENTER_MIN_WIDTH = 320;

export type TerminalSidePanelWidthBounds = Readonly<{
  min: number;
  max: number;
}>;

/**
 * Resolves the legacy panel limits for the width shared by the terminal and its
 * right-side auxiliary panel. If the container itself is narrower than the two
 * minimums combined, the panel minimum wins because both constraints cannot be
 * satisfied simultaneously.
 */
export function getTerminalSidePanelWidthBounds(
  containerWidth: number,
): TerminalSidePanelWidthBounds {
  const safeContainerWidth = Number.isFinite(containerWidth)
    ? Math.max(0, containerWidth)
    : TERMINAL_SIDE_PANEL_MIN_WIDTH + TERMINAL_CENTER_MIN_WIDTH;
  return {
    min: TERMINAL_SIDE_PANEL_MIN_WIDTH,
    max: Math.max(
      TERMINAL_SIDE_PANEL_MIN_WIDTH,
      Math.min(
        TERMINAL_SIDE_PANEL_MAX_WIDTH,
        safeContainerWidth - TERMINAL_CENTER_MIN_WIDTH,
      ),
    ),
  };
}

export function clampTerminalSidePanelWidth(
  requestedWidth: number,
  containerWidth: number,
): number {
  const bounds = getTerminalSidePanelWidthBounds(containerWidth);
  const safeRequestedWidth = Number.isFinite(requestedWidth)
    ? requestedWidth
    : bounds.min;
  return Math.min(bounds.max, Math.max(bounds.min, safeRequestedWidth));
}

/**
 * Computes a right-docked panel width from a horizontal pointer drag. Moving
 * the divider left increases the panel; moving it right decreases the panel.
 */
export function resizeTerminalSidePanelWidth(
  startWidth: number,
  startClientX: number,
  currentClientX: number,
  containerWidth: number,
): number {
  const pointerDelta = Number.isFinite(startClientX) && Number.isFinite(currentClientX)
    ? startClientX - currentClientX
    : 0;
  return clampTerminalSidePanelWidth(startWidth + pointerDelta, containerWidth);
}
