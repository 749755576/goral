export type AiMenuNavigationKey = "ArrowDown" | "ArrowUp" | "Home" | "End";

/**
 * Resolve the next focusable item for a single-column popup menu.
 * A negative current index means focus is still on the trigger.
 */
export function resolveAiMenuFocusIndex(
  key: AiMenuNavigationKey,
  currentIndex: number,
  itemCount: number,
): number | null {
  if (!Number.isInteger(itemCount) || itemCount <= 0) return null;
  if (key === "Home") return 0;
  if (key === "End") return itemCount - 1;
  if (key === "ArrowDown") return currentIndex < 0 ? 0 : (currentIndex + 1) % itemCount;
  return currentIndex < 0 ? itemCount - 1 : (currentIndex - 1 + itemCount) % itemCount;
}
