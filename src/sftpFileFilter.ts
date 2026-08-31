export const MAX_SFTP_FILE_FILTER_LENGTH = 256;

export type SftpFilterEntry = Readonly<{
  name: string;
}>;

export type SftpFilterOwnerScope = Readonly<{
  workspaceId: string;
  operationGeneration: number;
  backendSessionId: string;
  sftpGeneration: number;
}>;

export type SftpFilterShortcutEvent = Readonly<{
  key: string;
  ctrlKey?: boolean;
  metaKey?: boolean;
  altKey?: boolean;
  shiftKey?: boolean;
  isComposing?: boolean;
  defaultPrevented?: boolean;
  target?: EventTarget | null;
}>;

type ElementLike = Readonly<{
  tagName?: unknown;
  isContentEditable?: unknown;
  closest?: (selectors: string) => unknown;
}>;

/** Bound user input before it is retained by the current directory view. */
export const limitSftpFileFilter = (value: string): string => (
  Array.from(value).slice(0, MAX_SFTP_FILE_FILTER_LENGTH).join("")
);

export const normalizeSftpFileFilter = (value: string): string => (
  limitSftpFileFilter(value).trim().toLowerCase()
);

/**
 * Filters only the caller-owned current directory snapshot. No path, session,
 * or backend state is consulted, and clearing returns the complete input list.
 */
export const filterSftpEntries = <Entry extends SftpFilterEntry>(
  entries: readonly Entry[],
  filter: string,
): readonly Entry[] => {
  const normalized = normalizeSftpFileFilter(filter);
  if (!normalized) return entries;
  return entries.filter((entry) => entry.name.toLowerCase().includes(normalized));
};

export const createSftpFilterSessionScopeKey = (
  owner: SftpFilterOwnerScope | null,
): string => JSON.stringify(owner
  ? [
      owner.workspaceId,
      owner.operationGeneration,
      owner.backendSessionId,
      owner.sftpGeneration,
    ]
  : [null]);

export const createSftpFilterDirectoryScopeKey = (
  owner: SftpFilterOwnerScope | null,
  path: string,
): string => JSON.stringify([createSftpFilterSessionScopeKey(owner), path]);

/** Ordinary editors keep ownership of their own Ctrl/Cmd+F shortcut. */
export const isEditableSftpFilterShortcutTarget = (
  target: EventTarget | null | undefined,
): boolean => {
  if (!target || typeof target !== "object") return false;
  const element = target as ElementLike;
  const tagName = typeof element.tagName === "string"
    ? element.tagName.toUpperCase()
    : "";
  if (tagName === "INPUT" || tagName === "TEXTAREA" || tagName === "SELECT") {
    return true;
  }
  if (element.isContentEditable === true) return true;
  if (typeof element.closest !== "function") return false;
  try {
    return Boolean(element.closest(
      '[contenteditable="true"], [contenteditable=""], [role="textbox"], '
      + ".monaco-editor, .monaco-diff-editor, .monaco-inputbox",
    ));
  } catch {
    return false;
  }
};

export const isSftpFilterShortcut = (event: SftpFilterShortcutEvent): boolean => (
  event.defaultPrevented !== true
  && event.isComposing !== true
  && event.key.toLowerCase() === "f"
  && Boolean(event.ctrlKey || event.metaKey)
  && event.altKey !== true
  && event.shiftKey !== true
);

/**
 * The active SFTP surface may claim search from its own controls, but never
 * from a terminal search box, xterm textarea, AI composer, or ordinary editor.
 * Repeating the shortcut inside the SFTP filter itself is explicitly allowed.
 */
export const shouldFocusSftpFileFilter = (
  event: SftpFilterShortcutEvent,
  active: boolean,
  filterInputTarget: EventTarget | null = null,
): boolean => {
  if (!active || !isSftpFilterShortcut(event)) return false;
  if (event.target === filterInputTarget && filterInputTarget !== null) return true;
  return !isEditableSftpFilterShortcutTarget(event.target);
};

export type SftpFilterEscapeAction = "clear" | "close";

export const resolveSftpFilterEscapeAction = (
  filter: string,
): SftpFilterEscapeAction => filter.length > 0 ? "clear" : "close";
