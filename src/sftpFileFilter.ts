export const MAX_SFTP_FILE_FILTER_LENGTH = 256;

const utf8 = new TextEncoder();

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

/**
 * Small renderer-only memory for the SFTP filter affordance.
 *
 * `SftpBrowserPanel` is intentionally mounted only while the panel is visible,
 * so its React state disappears when the user switches to another terminal
 * tab or opens the AI/System tool.  The directory listing itself already
 * lives in `SftpSessionController`; this companion memory keeps the filter
 * presentation aligned with that listing without putting UI-only data into a
 * native request or a durable Vault snapshot.
 *
 * Keys are the exact owner+directory scope generated above.  The bounded LRU
 * makes the module-level instance safe for long-lived workbenches and ensures
 * a retired session cannot accumulate unbounded presentation state.
 */
export type SftpFilterMemoryValue = Readonly<{
  open: boolean;
  value: string;
}>;

export type SftpFilterMemory = Readonly<{
  read: (scopeKey: string) => SftpFilterMemoryValue | undefined;
  write: (scopeKey: string, value: SftpFilterMemoryValue) => void;
  clear: () => void;
}>;

const DEFAULT_SFTP_FILTER_MEMORY_LIMIT = 64;
const MAX_SFTP_FILTER_SCOPE_KEY_BYTES = 8 * 1024;

const validFilterMemoryKey = (scopeKey: string): boolean => (
  typeof scopeKey === "string"
  && scopeKey.length > 0
  && utf8.encode(scopeKey).byteLength <= MAX_SFTP_FILTER_SCOPE_KEY_BYTES
);

/** Create an isolated bounded memory store (also useful for pure tests). */
export const createSftpFilterMemory = (
  maximumEntries = DEFAULT_SFTP_FILTER_MEMORY_LIMIT,
): SftpFilterMemory => {
  const limit = Number.isSafeInteger(maximumEntries)
    ? Math.max(1, Math.min(maximumEntries, DEFAULT_SFTP_FILTER_MEMORY_LIMIT))
    : DEFAULT_SFTP_FILTER_MEMORY_LIMIT;
  const entries = new Map<string, SftpFilterMemoryValue>();

  const read = (scopeKey: string): SftpFilterMemoryValue | undefined => {
    if (!validFilterMemoryKey(scopeKey)) return undefined;
    const value = entries.get(scopeKey);
    if (!value) return undefined;
    // Touch the entry so frequently revisited tabs stay in the bounded set.
    entries.delete(scopeKey);
    entries.set(scopeKey, value);
    return value;
  };

  const write = (scopeKey: string, value: SftpFilterMemoryValue): void => {
    if (!validFilterMemoryKey(scopeKey) || typeof value?.open !== "boolean") return;
    const boundedValue = limitSftpFileFilter(typeof value.value === "string" ? value.value : "");
    entries.delete(scopeKey);
    entries.set(scopeKey, Object.freeze({ open: value.open, value: boundedValue }));
    while (entries.size > limit) {
      const oldest = entries.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      entries.delete(oldest);
    }
  };

  return Object.freeze({
    read,
    write,
    clear: () => entries.clear(),
  });
};

/** Shared only within this renderer process; no credentials or paths are kept. */
export const sftpFilterMemory = createSftpFilterMemory();
