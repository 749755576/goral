import { invoke } from "@tauri-apps/api/core";

/**
 * Persistent Notes fields. Keep this in lockstep with
 * `netcatty_vault::SavedVaultNote`; renderer-only state does not belong here.
 */
export type SavedVaultNote = {
  id: string;
  title: string;
  content: string;
  group?: string;
  tags?: string[];
  linkedHostIds?: string[];
  createdAt: number;
  updatedAt: number;
  order?: number;
};

/** Rust owns note IDs and timestamps on both create and update. */
export type SavedVaultNoteDraft = Omit<
  SavedVaultNote,
  "id" | "createdAt" | "updatedAt"
>;

export type SavedSnippetKind = "snippet" | "script";
export type SavedSnippetMultiLineRunMode = "lineDelay" | "paste";
export type SavedScriptLanguage = "javascript" | "python";
export type SavedScriptTrigger = "manual" | "onConnect" | "onOutput";

/**
 * Persistent Snippet fields. This deliberately excludes run handles, active
 * state, last errors, output, and every other runtime-only script property.
 */
export type SavedSnippet = {
  id: string;
  label: string;
  command: string;
  tags?: string[];
  package?: string;
  targets?: string[];
  targetGroups?: string[];
  targetsAllHosts?: boolean;
  shortkey?: string;
  noAutoRun?: boolean;
  multiLineRunMode?: SavedSnippetMultiLineRunMode;
  order?: number;
  kind?: SavedSnippetKind;
  language?: SavedScriptLanguage;
  description?: string;
  trigger?: SavedScriptTrigger;
  triggerPattern?: string;
};

/** Rust owns snippet IDs; ordinary renderer drafts cannot forge them. */
export type SavedSnippetDraft = Omit<SavedSnippet, "id">;

/**
 * Renderer projection of the shared v7 catalog. The four catalog arrays are
 * normalized to empty arrays by the Tauri adapter; the Rust persistence model
 * remains responsible for legacy absent-versus-empty import semantics.
 */
export type NotesSnippetsCatalog = {
  inventoryRevision: unknown;
  notes: SavedVaultNote[];
  noteGroups: string[];
  snippets: SavedSnippet[];
  snippetPackages: string[];
};

export type CreateVaultNoteRequest = {
  expectedInventoryRevision: unknown;
  draft: SavedVaultNoteDraft;
};

export type UpdateVaultNoteRequest = {
  id: string;
  expectedInventoryRevision: unknown;
  draft: SavedVaultNoteDraft;
};

export type DeleteVaultNoteRequest = {
  id: string;
  expectedInventoryRevision: unknown;
};

export type CreateSavedSnippetRequest = {
  expectedInventoryRevision: unknown;
  draft: SavedSnippetDraft;
};

export type UpdateSavedSnippetRequest = {
  id: string;
  expectedInventoryRevision: unknown;
  draft: SavedSnippetDraft;
};

export type DeleteSavedSnippetRequest = {
  id: string;
  expectedInventoryRevision: unknown;
};

export const NOTES_SNIPPETS_COMMANDS = {
  listNotes: "list_vault_notes",
  createNote: "create_vault_note",
  updateNote: "update_vault_note",
  deleteNote: "delete_vault_note",
  listSnippets: "list_saved_snippets",
  createSnippet: "create_saved_snippet",
  updateSnippet: "update_saved_snippet",
  deleteSnippet: "delete_saved_snippet",
} as const;

export const listVaultNotes = (): Promise<NotesSnippetsCatalog> =>
  invoke<NotesSnippetsCatalog>(NOTES_SNIPPETS_COMMANDS.listNotes);

export const createVaultNote = (
  request: CreateVaultNoteRequest,
): Promise<NotesSnippetsCatalog> =>
  invoke<NotesSnippetsCatalog>(NOTES_SNIPPETS_COMMANDS.createNote, { request });

export const updateVaultNote = (
  request: UpdateVaultNoteRequest,
): Promise<NotesSnippetsCatalog> =>
  invoke<NotesSnippetsCatalog>(NOTES_SNIPPETS_COMMANDS.updateNote, { request });

export const deleteVaultNote = (
  request: DeleteVaultNoteRequest,
): Promise<NotesSnippetsCatalog> =>
  invoke<NotesSnippetsCatalog>(NOTES_SNIPPETS_COMMANDS.deleteNote, { request });

export const listSavedSnippets = (): Promise<NotesSnippetsCatalog> =>
  invoke<NotesSnippetsCatalog>(NOTES_SNIPPETS_COMMANDS.listSnippets);

export const createSavedSnippet = (
  request: CreateSavedSnippetRequest,
): Promise<NotesSnippetsCatalog> =>
  invoke<NotesSnippetsCatalog>(NOTES_SNIPPETS_COMMANDS.createSnippet, { request });

export const updateSavedSnippet = (
  request: UpdateSavedSnippetRequest,
): Promise<NotesSnippetsCatalog> =>
  invoke<NotesSnippetsCatalog>(NOTES_SNIPPETS_COMMANDS.updateSnippet, { request });

export const deleteSavedSnippet = (
  request: DeleteSavedSnippetRequest,
): Promise<NotesSnippetsCatalog> =>
  invoke<NotesSnippetsCatalog>(NOTES_SNIPPETS_COMMANDS.deleteSnippet, { request });
