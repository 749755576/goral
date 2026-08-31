import type {
  SavedSnippet,
  SavedSnippetDraft,
  SavedVaultNote,
  SavedVaultNoteDraft,
} from "./notesSnippetsApi";
import type { Translate } from "./i18n.ts";

export type NotesScriptsHost = {
  id: string;
  label: string;
  hostname: string;
  username?: string;
  group?: string;
};

export type NotesSnippetsIssue = {
  code: "catalogChanged" | "notFound" | "invalid" | "operationFailed";
  message: string;
  refreshCatalog: boolean;
};

const compareOptionalOrder = (
  left: { order?: number },
  right: { order?: number },
): number => {
  const leftOrder = left.order;
  const rightOrder = right.order;
  if (typeof leftOrder === "number" && typeof rightOrder === "number") {
    return leftOrder - rightOrder;
  }
  if (typeof leftOrder === "number") return -1;
  if (typeof rightOrder === "number") return 1;
  return 0;
};

export const splitListInput = (value: string): string[] | undefined => {
  const values = Array.from(new Set(
    value
      .split(/[,\n]/)
      .map((item) => item.trim())
      .filter(Boolean),
  ));
  return values.length > 0 ? values : undefined;
};

export const sortVaultNotes = (
  notes: readonly SavedVaultNote[],
): SavedVaultNote[] => [...notes].sort((left, right) => {
  const byOrder = compareOptionalOrder(left, right);
  if (byOrder !== 0) return byOrder;
  if (left.updatedAt !== right.updatedAt) return right.updatedAt - left.updatedAt;
  return left.title.localeCompare(right.title);
});

export const sortSavedSnippets = (
  snippets: readonly SavedSnippet[],
): SavedSnippet[] => [...snippets].sort((left, right) => {
  const byOrder = compareOptionalOrder(left, right);
  if (byOrder !== 0) return byOrder;
  return left.label.localeCompare(right.label);
});

const hostSearchText = (
  ids: readonly string[] | undefined,
  hosts: readonly NotesScriptsHost[],
): string => {
  if (!ids?.length) return "";
  const idSet = new Set(ids);
  return hosts
    .filter((host) => idSet.has(host.id))
    .map((host) => `${host.label} ${host.hostname} ${host.username ?? ""} ${host.group ?? ""}`)
    .join(" ");
};

export const matchesVaultNoteSearch = (
  note: SavedVaultNote,
  query: string,
  hosts: readonly NotesScriptsHost[] = [],
): boolean => {
  const needle = query.trim().toLocaleLowerCase();
  if (!needle) return true;
  const haystack = [
    note.title,
    note.content,
    note.group ?? "",
    ...(note.tags ?? []),
    hostSearchText(note.linkedHostIds, hosts),
  ].join("\n").toLocaleLowerCase();
  return haystack.includes(needle);
};

export const matchesSavedSnippetSearch = (
  snippet: SavedSnippet,
  query: string,
  hosts: readonly NotesScriptsHost[] = [],
): boolean => {
  const needle = query.trim().toLocaleLowerCase();
  if (!needle) return true;
  const haystack = [
    snippet.label,
    snippet.command,
    snippet.description ?? "",
    snippet.package ?? "",
    snippet.shortkey ?? "",
    snippet.language ?? "",
    snippet.trigger ?? "",
    snippet.triggerPattern ?? "",
    ...(snippet.tags ?? []),
    ...(snippet.targetGroups ?? []),
    hostSearchText(snippet.targets, hosts),
  ].join("\n").toLocaleLowerCase();
  return haystack.includes(needle);
};

export const vaultNoteToDraft = (
  note: SavedVaultNote,
): SavedVaultNoteDraft => {
  const {
    id: _id,
    createdAt: _createdAt,
    updatedAt: _updatedAt,
    ...draft
  } = note;
  return draft;
};

export const savedSnippetToDraft = (
  snippet: SavedSnippet,
): SavedSnippetDraft => {
  const { id: _id, ...draft } = snippet;
  return draft;
};

export const createEmptyVaultNoteDraft = (
  order?: number,
): SavedVaultNoteDraft => ({
  title: "",
  content: "",
  ...(typeof order === "number" ? { order } : {}),
});

export const createEmptySavedSnippetDraft = (
  order?: number,
): SavedSnippetDraft => ({
  label: "",
  command: "",
  kind: "script",
  language: "javascript",
  trigger: "manual",
  ...(typeof order === "number" ? { order } : {}),
});

const safeErrorText = (reason: unknown): string => {
  if (reason instanceof Error) return reason.message.toUpperCase();
  return typeof reason === "string" ? reason.toUpperCase() : "";
};

export const classifyNotesSnippetsError = (
  reason: unknown,
  entityLabel: string,
  t: Translate,
): NotesSnippetsIssue => {
  const text = safeErrorText(reason);
  if (text.includes("INVENTORY_CHANGED") || text.includes("REVISION_CHANGED")) {
    return {
      code: "catalogChanged",
      message: t("notesScripts.error.catalogChanged", { entity: entityLabel }),
      refreshCatalog: true,
    };
  }
  if (text.includes("NOT_FOUND")) {
    return {
      code: "notFound",
      message: t("notesScripts.error.notFound", { entity: entityLabel }),
      refreshCatalog: true,
    };
  }
  if (text.includes("INVALID") || text.includes("VALIDATION")) {
    return {
      code: "invalid",
      message: t("notesScripts.error.invalid", { entity: entityLabel }),
      refreshCatalog: false,
    };
  }
  return {
    code: "operationFailed",
    message: t("notesScripts.error.operationFailed", { entity: entityLabel }),
    refreshCatalog: false,
  };
};

export const nextCatalogOrder = (
  values: readonly { order?: number }[],
): number => values.reduce(
  (maximum, value) => typeof value.order === "number"
    ? Math.max(maximum, value.order)
    : maximum,
  -1,
) + 1;
