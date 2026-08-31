import { isTauri } from "@tauri-apps/api/core";
import {
  useCallback,
  useDeferredValue,
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
} from "react";

import {
  createVaultNote,
  deleteVaultNote,
  listVaultNotes,
  updateVaultNote,
  type NotesSnippetsCatalog,
  type SavedVaultNote,
  type SavedVaultNoteDraft,
} from "./notesSnippetsApi";
import {
  classifyNotesSnippetsError,
  createEmptyVaultNoteDraft,
  matchesVaultNoteSearch,
  nextCatalogOrder,
  sortVaultNotes,
  splitListInput,
  vaultNoteToDraft,
  type NotesScriptsHost,
} from "./notesSnippetsUi";
import {
  formatWorkspaceTimestamp,
  HostChecklist,
  WorkspaceGlyph,
} from "./NotesScriptsShared";
import { useI18n, type Locale, type Translate } from "./i18n";

export type NotesWorkspaceApi = {
  list: typeof listVaultNotes;
  create: typeof createVaultNote;
  update: typeof updateVaultNote;
  delete: typeof deleteVaultNote;
};

export type NotesWorkspaceProps = {
  locale?: Locale;
  hosts?: readonly NotesScriptsHost[];
  disabled?: boolean;
  refreshKey?: string | number;
  api?: NotesWorkspaceApi;
  onCatalogChange?: (catalog: NotesSnippetsCatalog) => void;
  onOpenHost?: (host: NotesScriptsHost) => void;
};

type NoteEditorState = {
  mode: "create" | "update";
  id?: string;
  expectedInventoryRevision: unknown;
  draft: SavedVaultNoteDraft;
  tagsInput: string;
};

type NoteDeletePrompt = {
  id: string;
  expectedInventoryRevision: unknown;
};

const EMPTY_CATALOG: NotesSnippetsCatalog = {
  inventoryRevision: null,
  notes: [],
  noteGroups: [],
  snippets: [],
  snippetPackages: [],
};

const DEFAULT_API: NotesWorkspaceApi = {
  list: listVaultNotes,
  create: createVaultNote,
  update: updateVaultNote,
  delete: deleteVaultNote,
};

const noteEditorFromRecord = (
  note: SavedVaultNote,
  expectedInventoryRevision: unknown,
): NoteEditorState => ({
  mode: "update",
  id: note.id,
  expectedInventoryRevision,
  draft: vaultNoteToDraft(note),
  tagsInput: note.tags?.join(", ") ?? "",
});

const localizeNotesIssue = (reason: unknown, t: Translate) => {
  const issue = classifyNotesSnippetsError(reason, t("notes.entity"), t);
  const key = {
    catalogChanged: "notesScripts.error.catalogChanged",
    notFound: "notesScripts.error.notFound",
    invalid: "notesScripts.error.invalid",
    operationFailed: "notesScripts.error.operationFailed",
  } as const;
  return {
    ...issue,
    message: t(key[issue.code], { entity: t("notes.entity") }),
  };
};

export const NotesWorkspace = ({
  locale = "zh-CN",
  hosts = [],
  disabled = false,
  refreshKey,
  api,
  onCatalogChange,
  onOpenHost,
}: NotesWorkspaceProps) => {
  const { t } = useI18n(locale);
  const notesApi = api ?? DEFAULT_API;
  const nativeRuntimeAvailable = api !== undefined || isTauri();
  const [catalog, setCatalog] = useState<NotesSnippetsCatalog | null>(null);
  const [loading, setLoading] = useState(true);
  const [mutationPending, setMutationPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const deferredQuery = useDeferredValue(query);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editor, setEditor] = useState<NoteEditorState | null>(null);
  const [deletePrompt, setDeletePrompt] = useState<NoteDeletePrompt | null>(null);
  const mounted = useRef(true);
  const loadSequence = useRef(0);
  const mutationLock = useRef(false);
  const onCatalogChangeRef = useRef(onCatalogChange);
  const observedRefreshKey = useRef(refreshKey);

  useEffect(() => {
    onCatalogChangeRef.current = onCatalogChange;
  }, [onCatalogChange]);

  const applyCatalog = useCallback((next: NotesSnippetsCatalog, preferredId?: string) => {
    setCatalog(next);
    onCatalogChangeRef.current?.(next);
    setSelectedId((current) => {
      if (preferredId && next.notes.some((note) => note.id === preferredId)) {
        return preferredId;
      }
      if (current && next.notes.some((note) => note.id === current)) {
        return current;
      }
      return sortVaultNotes(next.notes)[0]?.id ?? null;
    });
  }, []);

  const refreshCatalog = useCallback(async (preserveError = false): Promise<boolean> => {
    const sequence = ++loadSequence.current;
    setLoading(true);
    if (!preserveError) setError(null);

    if (!nativeRuntimeAvailable) {
      if (mounted.current && sequence === loadSequence.current) {
        applyCatalog(EMPTY_CATALOG);
        setLoading(false);
      }
      return true;
    }

    try {
      const next = await notesApi.list();
      if (!mounted.current || sequence !== loadSequence.current) return false;
      applyCatalog(next);
      return true;
    } catch (reason) {
      if (mounted.current && sequence === loadSequence.current) {
        setError(localizeNotesIssue(reason, t).message);
      }
      return false;
    } finally {
      if (mounted.current && sequence === loadSequence.current) setLoading(false);
    }
  }, [applyCatalog, nativeRuntimeAvailable, notesApi, t]);

  useEffect(() => {
    mounted.current = true;
    void refreshCatalog();
    return () => {
      mounted.current = false;
      loadSequence.current += 1;
    };
  }, [refreshCatalog]);

  useEffect(() => {
    if (Object.is(observedRefreshKey.current, refreshKey)) return;
    observedRefreshKey.current = refreshKey;
    setEditor(null);
    setDeletePrompt(null);
    void refreshCatalog();
  }, [refreshCatalog, refreshKey]);

  const sortedNotes = useMemo(
    () => sortVaultNotes(catalog?.notes ?? []),
    [catalog?.notes],
  );
  const visibleNotes = useMemo(
    () => sortedNotes.filter((note) => matchesVaultNoteSearch(note, deferredQuery, hosts)),
    [deferredQuery, hosts, sortedNotes],
  );
  const selectedNote = useMemo(
    () => sortedNotes.find((note) => note.id === selectedId) ?? null,
    [selectedId, sortedNotes],
  );
  const linkedHosts = useMemo(() => {
    const linkedIds = new Set(selectedNote?.linkedHostIds ?? []);
    return hosts.filter((host) => linkedIds.has(host.id));
  }, [hosts, selectedNote?.linkedHostIds]);

  const openCreateEditor = () => {
    if (!catalog || disabled || mutationPending) return;
    setError(null);
    setDeletePrompt(null);
    setEditor({
      mode: "create",
      expectedInventoryRevision: catalog.inventoryRevision,
      draft: createEmptyVaultNoteDraft(nextCatalogOrder(catalog.notes)),
      tagsInput: "",
    });
  };

  const openUpdateEditor = (note: SavedVaultNote) => {
    if (!catalog || disabled || mutationPending) return;
    setError(null);
    setDeletePrompt(null);
    setSelectedId(note.id);
    setEditor(noteEditorFromRecord(note, catalog.inventoryRevision));
  };

  const updateEditorDraft = (patch: Partial<SavedVaultNoteDraft>) => {
    setEditor((current) => current
      ? { ...current, draft: { ...current.draft, ...patch } }
      : current);
  };

  const toggleLinkedHost = (hostId: string, checked: boolean) => {
    setEditor((current) => {
      if (!current) return current;
      const linked = new Set(current.draft.linkedHostIds ?? []);
      if (checked) linked.add(hostId);
      else linked.delete(hostId);
      return {
        ...current,
        draft: {
          ...current.draft,
          linkedHostIds: linked.size > 0 ? Array.from(linked) : undefined,
        },
      };
    });
  };

  const handleMutationFailure = async (reason: unknown) => {
    const issue = localizeNotesIssue(reason, t);
    if (issue.refreshCatalog) {
      setEditor(null);
      setDeletePrompt(null);
      await refreshCatalog(true);
    }
    if (mounted.current) setError(issue.message);
  };

  const submitEditor = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const snapshot = editor;
    const catalogSnapshot = catalog;
    if (!snapshot || !catalogSnapshot || disabled || mutationLock.current) return;

    const title = snapshot.draft.title.trim();
    if (!title) {
      setError(t("notes.titleRequired"));
      return;
    }
    const group = snapshot.draft.group
      ?.split("/")
      .map((segment) => segment.trim())
      .filter(Boolean)
      .join("/");
    const draft: SavedVaultNoteDraft = {
      ...snapshot.draft,
      title,
      ...(group ? { group } : { group: undefined }),
      tags: splitListInput(snapshot.tagsInput),
    };

    mutationLock.current = true;
    loadSequence.current += 1;
    setMutationPending(true);
    setError(null);
    try {
      const beforeIds = new Set(catalogSnapshot.notes.map((note) => note.id));
      const next = snapshot.mode === "create"
        ? await notesApi.create({
          expectedInventoryRevision: snapshot.expectedInventoryRevision,
          draft,
        })
        : await notesApi.update({
          id: snapshot.id!,
          expectedInventoryRevision: snapshot.expectedInventoryRevision,
          draft,
        });
      const createdId = snapshot.mode === "create"
        ? next.notes.find((note) => !beforeIds.has(note.id))?.id
        : snapshot.id;
      applyCatalog(next, createdId);
      setEditor(null);
      setDeletePrompt(null);
    } catch (reason) {
      await handleMutationFailure(reason);
    } finally {
      mutationLock.current = false;
      if (mounted.current) setMutationPending(false);
    }
  };

  const confirmDelete = async () => {
    const prompt = deletePrompt;
    if (!prompt || !catalog || disabled || mutationLock.current) return;
    mutationLock.current = true;
    loadSequence.current += 1;
    setMutationPending(true);
    setError(null);
    try {
      const next = await notesApi.delete({
        id: prompt.id,
        expectedInventoryRevision: prompt.expectedInventoryRevision,
      });
      applyCatalog(next);
      setDeletePrompt(null);
      setEditor(null);
    } catch (reason) {
      await handleMutationFailure(reason);
    } finally {
      mutationLock.current = false;
      if (mounted.current) setMutationPending(false);
    }
  };

  return (
    <section className="notes-scripts-workspace notes-workspace" aria-label={t("notes.workspaceAria")}>
      <header className="notes-scripts-header">
        <div className="notes-scripts-title">
          <span className="notes-scripts-title-icon"><WorkspaceGlyph name="note" /></span>
          <div>
            <h1>{t("notes.title")}</h1>
            <p>{t("notes.count", { count: catalog?.notes.length ?? 0 })}</p>
          </div>
        </div>
        <div className="notes-scripts-header-actions">
          <label className="notes-scripts-search">
            <WorkspaceGlyph name="search" />
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.currentTarget.value)}
              placeholder={t("notes.searchPlaceholder")}
              aria-label={t("notes.searchAria")}
            />
          </label>
          <button
            type="button"
            className="notes-scripts-icon-button"
            onClick={() => void refreshCatalog()}
            disabled={loading || mutationPending}
            aria-label={t("notes.refreshAria")}
            title={t("notesScripts.action.refresh")}
          >
            <WorkspaceGlyph name="refresh" />
          </button>
          <button
            type="button"
            className="notes-scripts-primary-button"
            onClick={openCreateEditor}
            disabled={!catalog || disabled || mutationPending}
          >
            <WorkspaceGlyph name="plus" />{t("notes.new")}
          </button>
        </div>
      </header>

      {error ? <div className="notes-scripts-error" role="alert">{error}</div> : null}

      <div className="notes-scripts-layout">
        <aside className="notes-scripts-list-panel" aria-label={t("notes.listAria")}>
          <div className="notes-scripts-list-summary">
            <span>{query
              ? t("notes.matchCount", { count: visibleNotes.length })
              : t("notes.all")}</span>
            {query ? <button type="button" onClick={() => setQuery("")}>{t("notesScripts.action.clearSearch")}</button> : null}
          </div>
          <div className="notes-scripts-list">
            {loading && !catalog ? (
              <div className="notes-scripts-loading">{t("notes.loading")}</div>
            ) : visibleNotes.length === 0 ? (
              <div className="notes-scripts-list-empty">
                <WorkspaceGlyph name={query ? "search" : "note"} />
                <strong>{query ? t("notes.noMatches") : t("notes.emptyListTitle")}</strong>
                <span>{query
                  ? t("notesScripts.search.tryDifferent")
                  : t("notes.emptyListDescription")}</span>
              </div>
            ) : visibleNotes.map((note) => (
              <article
                className={`notes-scripts-list-item${selectedId === note.id ? " selected" : ""}`}
                key={note.id}
              >
                <button
                  type="button"
                  className="notes-scripts-list-main"
                  onClick={() => {
                    setSelectedId(note.id);
                    setEditor(null);
                    setDeletePrompt(null);
                  }}
                >
                  <span className="notes-scripts-item-icon"><WorkspaceGlyph name="note" /></span>
                  <span className="notes-scripts-item-copy">
                    <strong>{note.title || t("notes.untitled")}</strong>
                    <small>{note.content.trim().replace(/\s+/g, " ") || t("notes.emptyExcerpt")}</small>
                    <span>
                      {note.group ? <em><WorkspaceGlyph name="folder" />{note.group}</em> : null}
                      <time>{formatWorkspaceTimestamp(note.updatedAt, locale)}</time>
                    </span>
                  </span>
                </button>
                <button
                  type="button"
                  className="notes-scripts-row-action"
                  onClick={() => openUpdateEditor(note)}
                  aria-label={t("notes.editAria", { title: note.title })}
                  title={t("notesScripts.action.edit")}
                >
                  <WorkspaceGlyph name="edit" />
                </button>
              </article>
            ))}
          </div>
        </aside>

        <main className="notes-scripts-detail-panel">
          {editor ? (
            <form className="notes-scripts-editor" onSubmit={submitEditor}>
              <div className="notes-scripts-editor-header">
                <div>
                  <span>{editor.mode === "create" ? t("notes.newEyebrow") : t("notes.editEyebrow")}</span>
                  <h2>{editor.mode === "create" ? t("notes.createTitle") : t("notes.editTitle")}</h2>
                </div>
                <div className="notes-scripts-editor-actions">
                  <button
                    type="button"
                    className="notes-scripts-secondary-button"
                    onClick={() => setEditor(null)}
                    disabled={mutationPending}
                  >{t("notesScripts.action.cancel")}</button>
                  <button
                    type="submit"
                    className="notes-scripts-primary-button"
                    disabled={disabled || mutationPending}
                  >{mutationPending ? t("notesScripts.action.saving") : t("notes.save")}</button>
                </div>
              </div>

              <div className="notes-scripts-form-grid notes-form-grid">
                <label className="notes-scripts-field notes-scripts-field-wide">
                  <span>{t("notes.titleLabel")} <b>*</b></span>
                  <input
                    autoFocus
                    value={editor.draft.title}
                    onChange={(event) => updateEditorDraft({ title: event.currentTarget.value })}
                    placeholder={t("notes.titlePlaceholder")}
                    maxLength={32768}
                  />
                </label>
                <label className="notes-scripts-field">
                  <span><WorkspaceGlyph name="folder" />{t("notes.groupLabel")}</span>
                  <input
                    list="notes-workspace-groups"
                    value={editor.draft.group ?? ""}
                    onChange={(event) => updateEditorDraft({ group: event.currentTarget.value || undefined })}
                    placeholder={t("notes.groupPlaceholder")}
                  />
                  <datalist id="notes-workspace-groups">
                    {catalog?.noteGroups.map((group) => <option value={group} key={group} />)}
                  </datalist>
                </label>
                <label className="notes-scripts-field">
                  <span><WorkspaceGlyph name="tag" />{t("notes.tagsLabel")}</span>
                  <input
                    value={editor.tagsInput}
                    onChange={(event) => setEditor((current) => current
                      ? { ...current, tagsInput: event.currentTarget.value }
                      : current)}
                    placeholder={t("notes.tagsPlaceholder")}
                  />
                </label>
                <label className="notes-scripts-field notes-scripts-field-wide notes-scripts-body-field">
                  <span>{t("notes.bodyLabel")}</span>
                  <textarea
                    value={editor.draft.content}
                    onChange={(event) => updateEditorDraft({ content: event.currentTarget.value })}
                    placeholder={t("notes.bodyPlaceholder")}
                    spellCheck="false"
                  />
                </label>
              </div>

              <HostChecklist
                locale={locale}
                hosts={hosts}
                selectedIds={editor.draft.linkedHostIds ?? []}
                disabled={disabled || mutationPending}
                onToggle={toggleLinkedHost}
              />
            </form>
          ) : selectedNote ? (
            <article className="notes-scripts-preview">
              <header className="notes-scripts-preview-header">
                <div>
                  <div className="notes-scripts-preview-kicker">
                    {selectedNote.group
                      ? <span><WorkspaceGlyph name="folder" />{selectedNote.group}</span>
                      : t("notes.kicker")}
                  </div>
                  <h2>{selectedNote.title}</h2>
                  <p>{t("notes.updatedAt", {
                    timestamp: formatWorkspaceTimestamp(selectedNote.updatedAt, locale),
                  })}</p>
                </div>
                <div className="notes-scripts-editor-actions">
                  <button
                    type="button"
                    className="notes-scripts-secondary-button"
                    onClick={() => openUpdateEditor(selectedNote)}
                    disabled={disabled || mutationPending}
                  ><WorkspaceGlyph name="edit" />{t("notesScripts.action.edit")}</button>
                  <button
                    type="button"
                    className="notes-scripts-danger-button"
                    onClick={() => catalog && setDeletePrompt({
                      id: selectedNote.id,
                      expectedInventoryRevision: catalog.inventoryRevision,
                    })}
                    disabled={disabled || mutationPending}
                  ><WorkspaceGlyph name="trash" />{t("notesScripts.action.delete")}</button>
                </div>
              </header>

              {selectedNote.tags?.length ? (
                <div className="notes-scripts-chips" aria-label={t("notes.tagsAria")}>
                  {selectedNote.tags.map((tag) => <span key={tag}>#{tag}</span>)}
                </div>
              ) : null}

              <pre className="notes-scripts-note-body">{selectedNote.content || t("notes.emptyBody")}</pre>

              <section className="notes-scripts-linked-hosts">
                <div className="notes-scripts-field-heading">
                  <span><WorkspaceGlyph name="host" />{t("notesScripts.hosts.linked")}</span>
                  <span>{linkedHosts.length}</span>
                </div>
                {linkedHosts.length === 0 ? (
                  <p>{t("notes.noLinkedHosts")}</p>
                ) : (
                  <div className="notes-scripts-host-chip-list">
                    {linkedHosts.map((host) => (
                      <button
                        type="button"
                        key={host.id}
                        onClick={() => onOpenHost?.(host)}
                        disabled={!onOpenHost}
                      >
                        <span className="notes-scripts-host-dot" />
                        <span><strong>{host.label || host.hostname}</strong><small>{host.hostname}</small></span>
                      </button>
                    ))}
                  </div>
                )}
              </section>

              {deletePrompt?.id === selectedNote.id ? (
                <div className="notes-scripts-delete-confirm" role="alertdialog" aria-label={t("notes.deleteDialogAria")}>
                  <div>
                    <strong>{t("notes.deleteQuestion", { title: selectedNote.title })}</strong>
                    <span>{t("notes.deleteDescription")}</span>
                  </div>
                  <button type="button" onClick={() => setDeletePrompt(null)}>{t("notesScripts.action.cancel")}</button>
                  <button type="button" className="danger" onClick={() => void confirmDelete()} disabled={mutationPending}>
                    {mutationPending ? t("notesScripts.action.deleting") : t("notesScripts.action.confirmDelete")}
                  </button>
                </div>
              ) : null}
            </article>
          ) : (
            <div className="notes-scripts-empty-state">
              <span className="notes-scripts-empty-icon"><WorkspaceGlyph name="note" /></span>
              <h2>{query && catalog?.notes.length
                ? t("notesScripts.search.selectResult")
                : t("notes.emptyPageTitle")}</h2>
              <p>{t("notes.emptyPageDescription")}</p>
              <button
                type="button"
                className="notes-scripts-primary-button"
                onClick={openCreateEditor}
                disabled={!catalog || disabled || mutationPending}
              ><WorkspaceGlyph name="plus" />{t("notes.new")}</button>
            </div>
          )}
        </main>
      </div>
    </section>
  );
};
