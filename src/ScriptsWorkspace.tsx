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
  createSavedSnippet,
  deleteSavedSnippet,
  listSavedSnippets,
  updateSavedSnippet,
  type NotesSnippetsCatalog,
  type SavedSnippet,
  type SavedSnippetDraft,
  type SavedSnippetKind,
} from "./notesSnippetsApi";
import {
  classifyNotesSnippetsError,
  createEmptySavedSnippetDraft,
  matchesSavedSnippetSearch,
  nextCatalogOrder,
  savedSnippetToDraft,
  sortSavedSnippets,
  splitListInput,
  type NotesScriptsHost,
} from "./notesSnippetsUi";
import { HostChecklist, WorkspaceGlyph } from "./NotesScriptsShared";
import { useI18n, type Locale, type Translate } from "./i18n";

export type ScriptsWorkspaceApi = {
  list: typeof listSavedSnippets;
  create: typeof createSavedSnippet;
  update: typeof updateSavedSnippet;
  delete: typeof deleteSavedSnippet;
};

export type ScriptsWorkspaceProps = {
  locale?: Locale;
  hosts?: readonly NotesScriptsHost[];
  disabled?: boolean;
  refreshKey?: string | number;
  api?: ScriptsWorkspaceApi;
  onCatalogChange?: (catalog: NotesSnippetsCatalog) => void;
  onOpenHost?: (host: NotesScriptsHost) => void;
};

type ScriptKindFilter = "all" | SavedSnippetKind;

type ScriptEditorState = {
  mode: "create" | "update";
  id?: string;
  expectedInventoryRevision: unknown;
  draft: SavedSnippetDraft;
  tagsInput: string;
  targetGroupsInput: string;
  targetGroupsExplicit: boolean;
  targetsExplicit: boolean;
};

type ScriptDeletePrompt = {
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

const DEFAULT_API: ScriptsWorkspaceApi = {
  list: listSavedSnippets,
  create: createSavedSnippet,
  update: updateSavedSnippet,
  delete: deleteSavedSnippet,
};

const effectiveKind = (snippet: Pick<SavedSnippet, "kind">): SavedSnippetKind =>
  snippet.kind ?? "snippet";

const scriptEditorFromRecord = (
  snippet: SavedSnippet,
  expectedInventoryRevision: unknown,
): ScriptEditorState => ({
  mode: "update",
  id: snippet.id,
  expectedInventoryRevision,
  draft: savedSnippetToDraft(snippet),
  tagsInput: snippet.tags?.join(", ") ?? "",
  targetGroupsInput: snippet.targetGroups?.join("\n") ?? "",
  targetGroupsExplicit: snippet.targetGroups !== undefined,
  targetsExplicit: snippet.targets !== undefined,
});

const cleanGroupTargets = (input: string): string[] | undefined => {
  const values = splitListInput(input)?.map((value) => value
    .replaceAll("\\", "/")
    .split("/")
    .map((segment) => segment.trim())
    .filter(Boolean)
    .join("/"))
    .filter(Boolean);
  if (!values?.length) return undefined;
  return Array.from(new Set(values));
};

const localizeScriptsIssue = (reason: unknown, t: Translate) => {
  const issue = classifyNotesSnippetsError(reason, t("scripts.entity"), t);
  const key = {
    catalogChanged: "notesScripts.error.catalogChanged",
    notFound: "notesScripts.error.notFound",
    invalid: "notesScripts.error.invalid",
    operationFailed: "notesScripts.error.operationFailed",
  } as const;
  return {
    ...issue,
    message: t(key[issue.code], { entity: t("scripts.entity") }),
  };
};

export const ScriptsWorkspace = ({
  locale = "zh-CN",
  hosts = [],
  disabled = false,
  refreshKey,
  api,
  onCatalogChange,
  onOpenHost,
}: ScriptsWorkspaceProps) => {
  const { t } = useI18n(locale);
  const scriptsApi = api ?? DEFAULT_API;
  const nativeRuntimeAvailable = api !== undefined || isTauri();
  const nativeUnavailableMessage = nativeRuntimeAvailable
    ? null
    : t("notesScripts.desktopOnly");
  const [catalog, setCatalog] = useState<NotesSnippetsCatalog | null>(null);
  const [loading, setLoading] = useState(true);
  const [mutationPending, setMutationPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const deferredQuery = useDeferredValue(query);
  const [kindFilter, setKindFilter] = useState<ScriptKindFilter>("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editor, setEditor] = useState<ScriptEditorState | null>(null);
  const [deletePrompt, setDeletePrompt] = useState<ScriptDeletePrompt | null>(null);
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
      if (preferredId && next.snippets.some((snippet) => snippet.id === preferredId)) {
        return preferredId;
      }
      if (current && next.snippets.some((snippet) => snippet.id === current)) {
        return current;
      }
      return sortSavedSnippets(next.snippets)[0]?.id ?? null;
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
      const next = await scriptsApi.list();
      if (!mounted.current || sequence !== loadSequence.current) return false;
      applyCatalog(next);
      return true;
    } catch (reason) {
      if (mounted.current && sequence === loadSequence.current) {
        setError(localizeScriptsIssue(reason, t).message);
      }
      return false;
    } finally {
      if (mounted.current && sequence === loadSequence.current) setLoading(false);
    }
  }, [applyCatalog, nativeRuntimeAvailable, scriptsApi, t]);

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

  const sortedSnippets = useMemo(
    () => sortSavedSnippets(catalog?.snippets ?? []),
    [catalog?.snippets],
  );
  const visibleSnippets = useMemo(() => sortedSnippets.filter((snippet) => (
    (kindFilter === "all" || effectiveKind(snippet) === kindFilter)
    && matchesSavedSnippetSearch(snippet, deferredQuery, hosts)
  )), [deferredQuery, hosts, kindFilter, sortedSnippets]);
  const selectedSnippet = useMemo(
    () => sortedSnippets.find((snippet) => snippet.id === selectedId) ?? null,
    [selectedId, sortedSnippets],
  );
  const selectedTargetHosts = useMemo(() => {
    if (selectedSnippet?.targetsAllHosts) return hosts;
    const targetIds = new Set(selectedSnippet?.targets ?? []);
    return hosts.filter((host) => targetIds.has(host.id));
  }, [hosts, selectedSnippet?.targets, selectedSnippet?.targetsAllHosts]);

  const openCreateEditor = () => {
    if (!catalog || disabled || !nativeRuntimeAvailable || mutationPending) return;
    setError(null);
    setDeletePrompt(null);
    setEditor({
      mode: "create",
      expectedInventoryRevision: catalog.inventoryRevision,
      draft: createEmptySavedSnippetDraft(nextCatalogOrder(catalog.snippets)),
      tagsInput: "",
      targetGroupsInput: "",
      targetGroupsExplicit: false,
      targetsExplicit: false,
    });
  };

  const openUpdateEditor = (snippet: SavedSnippet) => {
    if (!catalog || disabled || !nativeRuntimeAvailable || mutationPending) return;
    setError(null);
    setDeletePrompt(null);
    setSelectedId(snippet.id);
    setEditor(scriptEditorFromRecord(snippet, catalog.inventoryRevision));
  };

  const updateEditorDraft = (patch: Partial<SavedSnippetDraft>) => {
    setEditor((current) => current
      ? { ...current, draft: { ...current.draft, ...patch } }
      : current);
  };

  const updateKind = (kind: SavedSnippetKind) => {
    setEditor((current) => {
      if (!current) return current;
      if (kind === "script") {
        const {
          multiLineRunMode: _multiLineRunMode,
          noAutoRun: _noAutoRun,
          ...rest
        } = current.draft;
        return {
          ...current,
          draft: {
            ...rest,
            kind,
            language: current.draft.language ?? "javascript",
            trigger: current.draft.trigger ?? "manual",
          },
        };
      }
      const {
        language: _language,
        description: _description,
        trigger: _trigger,
        triggerPattern: _triggerPattern,
        ...rest
      } = current.draft;
      return { ...current, draft: { ...rest, kind } };
    });
  };

  const toggleTargetHost = (hostId: string, checked: boolean) => {
    setEditor((current) => {
      if (!current) return current;
      const targets = new Set(current.draft.targets ?? []);
      if (checked) targets.add(hostId);
      else targets.delete(hostId);
      return {
        ...current,
        targetsExplicit: true,
        draft: {
          ...current.draft,
          targets: targets.size > 0 ? Array.from(targets) : [],
          targetsAllHosts: undefined,
        },
      };
    });
  };

  const handleMutationFailure = async (reason: unknown) => {
    const issue = localizeScriptsIssue(reason, t);
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
    if (!nativeRuntimeAvailable) {
      setError(nativeUnavailableMessage ?? t("notesScripts.desktopOnly"));
      return;
    }

    const label = snapshot.draft.label.trim();
    if (!label) {
      setError(t("scripts.nameRequired"));
      return;
    }

    const allHosts = snapshot.draft.targetsAllHosts === true;
    const targetGroups = cleanGroupTargets(snapshot.targetGroupsInput);
    const packageName = snapshot.draft.package?.trim();
    const shortkey = snapshot.draft.shortkey?.trim();
    const description = snapshot.draft.description?.trim();
    const triggerPattern = snapshot.draft.trigger === "onOutput"
      ? snapshot.draft.triggerPattern?.trim()
      : undefined;
    const draft: SavedSnippetDraft = {
      ...snapshot.draft,
      label,
      tags: splitListInput(snapshot.tagsInput),
      package: packageName || undefined,
      shortkey: shortkey || undefined,
      description: description || undefined,
      triggerPattern: triggerPattern || undefined,
      targetsAllHosts: allHosts || undefined,
      targets: allHosts
        ? undefined
        : snapshot.targetsExplicit
          ? snapshot.draft.targets ?? []
          : undefined,
      targetGroups: allHosts
        ? undefined
        : targetGroups ?? (snapshot.targetGroupsExplicit ? [] : undefined),
    };

    mutationLock.current = true;
    loadSequence.current += 1;
    setMutationPending(true);
    setError(null);
    try {
      const beforeIds = new Set(catalogSnapshot.snippets.map((snippet) => snippet.id));
      const next = snapshot.mode === "create"
        ? await scriptsApi.create({
          expectedInventoryRevision: snapshot.expectedInventoryRevision,
          draft,
        })
        : await scriptsApi.update({
          id: snapshot.id!,
          expectedInventoryRevision: snapshot.expectedInventoryRevision,
          draft,
        });
      const createdId = snapshot.mode === "create"
        ? next.snippets.find((snippet) => !beforeIds.has(snippet.id))?.id
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
    if (!prompt || !catalog || disabled || !nativeRuntimeAvailable || mutationLock.current) return;
    mutationLock.current = true;
    loadSequence.current += 1;
    setMutationPending(true);
    setError(null);
    try {
      const next = await scriptsApi.delete({
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
    <section className="notes-scripts-workspace scripts-workspace" aria-label={t("scripts.workspaceAria")}>
      <header className="notes-scripts-header">
        <div className="notes-scripts-title">
          <span className="notes-scripts-title-icon"><WorkspaceGlyph name="script" /></span>
          <div>
            <h1>{t("scripts.title")}</h1>
            <p>{t("scripts.count", { count: catalog?.snippets.length ?? 0 })}</p>
          </div>
        </div>
        <div className="notes-scripts-header-actions">
          <label className="notes-scripts-search">
            <WorkspaceGlyph name="search" />
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.currentTarget.value)}
              placeholder={t("scripts.searchPlaceholder")}
              aria-label={t("scripts.searchAria")}
            />
          </label>
          <button
            type="button"
            className="notes-scripts-icon-button"
            onClick={() => void refreshCatalog()}
            disabled={loading || mutationPending}
            aria-label={t("scripts.refreshAria")}
            title={t("notesScripts.action.refresh")}
          ><WorkspaceGlyph name="refresh" /></button>
          <button
            type="button"
            className="notes-scripts-primary-button"
            onClick={openCreateEditor}
            disabled={!catalog || disabled || !nativeRuntimeAvailable || mutationPending}
            title={nativeUnavailableMessage ?? undefined}
          ><WorkspaceGlyph name="plus" />{t("scripts.new")}</button>
        </div>
      </header>

      {nativeUnavailableMessage ? (
        <p className="notes-scripts-native-notice" role="status">
          {nativeUnavailableMessage}
        </p>
      ) : null}

      {error ? <div className="notes-scripts-error" role="alert">{error}</div> : null}

      <div className="notes-scripts-filterbar" aria-label={t("scripts.filterAria")}>
        {(["all", "snippet", "script"] as const).map((kind) => (
          <button
            type="button"
            key={kind}
            className={kindFilter === kind ? "active" : ""}
            onClick={() => setKindFilter(kind)}
          >
            {kind === "all"
              ? t("scripts.filterAll")
              : kind === "snippet"
                ? t("scripts.filterSnippets")
                : t("scripts.filterScripts")}
            <span>{kind === "all"
              ? sortedSnippets.length
              : sortedSnippets.filter((item) => effectiveKind(item) === kind).length}</span>
          </button>
        ))}
      </div>

      <div className="notes-scripts-layout">
        <aside className="notes-scripts-list-panel" aria-label={t("scripts.listAria")}>
          <div className="notes-scripts-list-summary">
            <span>{query
              ? t("scripts.matchCount", { count: visibleSnippets.length })
              : t("scripts.library")}</span>
            {query ? <button type="button" onClick={() => setQuery("")}>{t("notesScripts.action.clearSearch")}</button> : null}
          </div>
          <div className="notes-scripts-list">
            {loading && !catalog ? (
              <div className="notes-scripts-loading">{t("scripts.loading")}</div>
            ) : visibleSnippets.length === 0 ? (
              <div className="notes-scripts-list-empty">
                <WorkspaceGlyph name={query ? "search" : "script"} />
                <strong>{query ? t("scripts.noMatches") : t("scripts.emptyListTitle")}</strong>
                <span>{query
                  ? t("notesScripts.search.tryDifferent")
                  : t("scripts.emptyListDescription")}</span>
              </div>
            ) : visibleSnippets.map((snippet) => (
              <article
                className={`notes-scripts-list-item${selectedId === snippet.id ? " selected" : ""}`}
                key={snippet.id}
              >
                <button
                  type="button"
                  className="notes-scripts-list-main"
                  onClick={() => {
                    setSelectedId(snippet.id);
                    setEditor(null);
                    setDeletePrompt(null);
                  }}
                >
                  <span className={`notes-scripts-item-icon ${effectiveKind(snippet)}`}>
                    <WorkspaceGlyph name={effectiveKind(snippet) === "script" ? "script" : "code"} />
                  </span>
                  <span className="notes-scripts-item-copy">
                    <strong>{snippet.label || t("scripts.untitled")}</strong>
                    <small>{snippet.command.trim().split(/\r?\n/, 1)[0] || t("scripts.emptyExcerpt")}</small>
                    <span>
                      <em>{effectiveKind(snippet) === "script"
                        ? t("scripts.badgeScript")
                        : t("scripts.badgeSnippet")}</em>
                      {snippet.package ? <em><WorkspaceGlyph name="folder" />{snippet.package}</em> : null}
                    </span>
                  </span>
                </button>
                <button
                  type="button"
                  className="notes-scripts-row-action"
                  onClick={() => openUpdateEditor(snippet)}
                  disabled={!nativeRuntimeAvailable || disabled || mutationPending}
                  aria-label={t("scripts.editAria", { title: snippet.label })}
                  title={t("notesScripts.action.edit")}
                ><WorkspaceGlyph name="edit" /></button>
              </article>
            ))}
          </div>
        </aside>

        <main className="notes-scripts-detail-panel">
          {editor ? (
            <form className="notes-scripts-editor" onSubmit={submitEditor}>
              <div className="notes-scripts-editor-header">
                <div>
                  <span>{editor.mode === "create" ? t("scripts.newEyebrow") : t("scripts.editEyebrow")}</span>
                  <h2>{editor.mode === "create" ? t("scripts.createTitle") : t("scripts.editTitle")}</h2>
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
                    disabled={disabled || !nativeRuntimeAvailable || mutationPending}
                  >{mutationPending ? t("notesScripts.action.saving") : t("scripts.save")}</button>
                </div>
              </div>

              <div className="notes-scripts-form-grid scripts-form-grid">
                <label className="notes-scripts-field notes-scripts-field-wide">
                  <span>{t("scripts.nameLabel")} <b>*</b></span>
                  <input
                    autoFocus
                    value={editor.draft.label}
                    onChange={(event) => updateEditorDraft({ label: event.currentTarget.value })}
                    placeholder={t("scripts.namePlaceholder")}
                  />
                </label>
                <label className="notes-scripts-field">
                  <span>{t("scripts.typeLabel")}</span>
                  <select
                    value={effectiveKind(editor.draft)}
                    onChange={(event) => updateKind(event.currentTarget.value as SavedSnippetKind)}
                  >
                    <option value="snippet">{t("scripts.typeSnippet")}</option>
                    <option value="script">{t("scripts.typeScript")}</option>
                  </select>
                </label>
                <label className="notes-scripts-field">
                  <span><WorkspaceGlyph name="folder" />{t("scripts.packageLabel")}</span>
                  <input
                    list="scripts-workspace-packages"
                    value={editor.draft.package ?? ""}
                    onChange={(event) => updateEditorDraft({ package: event.currentTarget.value || undefined })}
                    placeholder={t("scripts.packagePlaceholder")}
                  />
                  <datalist id="scripts-workspace-packages">
                    {catalog?.snippetPackages.map((item) => <option value={item} key={item} />)}
                  </datalist>
                </label>
                <label className="notes-scripts-field">
                  <span><WorkspaceGlyph name="tag" />{t("scripts.tagsLabel")}</span>
                  <input
                    value={editor.tagsInput}
                    onChange={(event) => setEditor((current) => current
                      ? { ...current, tagsInput: event.currentTarget.value }
                      : current)}
                    placeholder={t("scripts.tagsPlaceholder")}
                  />
                </label>
                <label className="notes-scripts-field">
                  <span>{t("scripts.shortcutLabel")}</span>
                  <input
                    value={editor.draft.shortkey ?? ""}
                    onChange={(event) => updateEditorDraft({ shortkey: event.currentTarget.value || undefined })}
                    placeholder={t("scripts.shortcutPlaceholder")}
                  />
                </label>

                {effectiveKind(editor.draft) === "script" ? (
                  <>
                    <label className="notes-scripts-field">
                      <span>{t("scripts.languageLabel")}</span>
                      <select
                        value={editor.draft.language ?? "javascript"}
                        onChange={(event) => updateEditorDraft({
                          language: event.currentTarget.value as "javascript" | "python",
                        })}
                      >
                        <option value="javascript">JavaScript</option>
                        <option value="python">Python</option>
                      </select>
                    </label>
                    <label className="notes-scripts-field notes-scripts-field-wide">
                      <span>{t("scripts.descriptionLabel")}</span>
                      <input
                        value={editor.draft.description ?? ""}
                        onChange={(event) => updateEditorDraft({ description: event.currentTarget.value || undefined })}
                        placeholder={t("scripts.descriptionPlaceholder")}
                      />
                    </label>
                  </>
                ) : (
                  <>
                    <label className="notes-scripts-field">
                      <span>{t("scripts.multiLineLabel")}</span>
                      <select
                        value={editor.draft.multiLineRunMode ?? "paste"}
                        onChange={(event) => updateEditorDraft({
                          multiLineRunMode: event.currentTarget.value as "paste" | "lineDelay",
                        })}
                      >
                        <option value="paste">{t("scripts.multiLinePaste")}</option>
                        <option value="lineDelay">{t("scripts.multiLineByLine")}</option>
                      </select>
                    </label>
                    <label className="notes-scripts-check-field">
                      <input
                        type="checkbox"
                        checked={editor.draft.noAutoRun === true}
                        onChange={(event) => updateEditorDraft({ noAutoRun: event.currentTarget.checked || undefined })}
                      />
                      <span><strong>{t("scripts.noAutoRunTitle")}</strong><small>{t("scripts.noAutoRunDescription")}</small></span>
                    </label>
                  </>
                )}

                <label className="notes-scripts-field notes-scripts-field-wide notes-scripts-body-field">
                  <span>{t("scripts.bodyLabel")}</span>
                  <textarea
                    className="notes-scripts-code-input"
                    value={editor.draft.command}
                    onChange={(event) => updateEditorDraft({ command: event.currentTarget.value })}
                    placeholder={effectiveKind(editor.draft) === "script"
                      ? t("scripts.bodyPlaceholderScript")
                      : t("scripts.bodyPlaceholderSnippet")}
                    spellCheck="false"
                  />
                </label>
                <label className="notes-scripts-field notes-scripts-field-wide">
                  <span><WorkspaceGlyph name="folder" />{t("scripts.targetGroupsLabel")}</span>
                  <textarea
                    className="notes-scripts-compact-textarea"
                    value={editor.targetGroupsInput}
                    disabled={editor.draft.targetsAllHosts === true}
                    onChange={(event) => setEditor((current) => current ? {
                      ...current,
                      targetGroupsInput: event.currentTarget.value,
                      targetGroupsExplicit: true,
                    } : current)}
                    placeholder={t("scripts.targetGroupsPlaceholder")}
                  />
                </label>
              </div>

              <HostChecklist
                locale={locale}
                hosts={hosts}
                selectedIds={editor.draft.targets ?? []}
                allHosts={editor.draft.targetsAllHosts === true}
                disabled={disabled || !nativeRuntimeAvailable || mutationPending}
                onAllHostsChange={(checked) => updateEditorDraft({ targetsAllHosts: checked || undefined })}
                onToggle={toggleTargetHost}
              />
            </form>
          ) : selectedSnippet ? (
            <article className="notes-scripts-preview scripts-preview">
              <header className="notes-scripts-preview-header">
                <div>
                  <div className="notes-scripts-preview-kicker">
                    <span><WorkspaceGlyph name={effectiveKind(selectedSnippet) === "script" ? "script" : "code"} />
                      {effectiveKind(selectedSnippet) === "script"
                        ? t("scripts.previewScript")
                        : t("scripts.previewSnippet")}
                    </span>
                    {selectedSnippet.package ? <span><WorkspaceGlyph name="folder" />{selectedSnippet.package}</span> : null}
                  </div>
                  <h2>{selectedSnippet.label}</h2>
                  {selectedSnippet.description ? <p>{selectedSnippet.description}</p> : null}
                </div>
                <div className="notes-scripts-editor-actions">
                  <button
                    type="button"
                    className="notes-scripts-secondary-button"
                    onClick={() => openUpdateEditor(selectedSnippet)}
                    disabled={disabled || !nativeRuntimeAvailable || mutationPending}
                  ><WorkspaceGlyph name="edit" />{t("notesScripts.action.edit")}</button>
                  <button
                    type="button"
                    className="notes-scripts-danger-button"
                    onClick={() => catalog && setDeletePrompt({
                      id: selectedSnippet.id,
                      expectedInventoryRevision: catalog.inventoryRevision,
                    })}
                    disabled={disabled || !nativeRuntimeAvailable || mutationPending}
                  ><WorkspaceGlyph name="trash" />{t("notesScripts.action.delete")}</button>
                </div>
              </header>

              <div className="notes-scripts-script-meta">
                <span><b>{t("scripts.metaLanguage")}</b>{selectedSnippet.language ?? (effectiveKind(selectedSnippet) === "script" ? "javascript" : "shell")}</span>
                <span><b>{t("scripts.metaShortcut")}</b>{selectedSnippet.shortkey ?? "—"}</span>
              </div>

              {selectedSnippet.tags?.length ? (
                <div className="notes-scripts-chips" aria-label={t("scripts.tagsAria")}>
                  {selectedSnippet.tags.map((tag) => <span key={tag}>#{tag}</span>)}
                </div>
              ) : null}

              <div className="notes-scripts-code-block">
                <div><span>{selectedSnippet.language ?? "shell"}</span><span>{t("scripts.lineCount", {
                  count: selectedSnippet.command.split(/\r?\n/).length,
                })}</span></div>
                <pre>{selectedSnippet.command || t("scripts.emptyBody")}</pre>
              </div>

              <section className="notes-scripts-linked-hosts">
                <div className="notes-scripts-field-heading">
                  <span><WorkspaceGlyph name="host" />{t("scripts.targetHosts")}</span>
                  <span>{selectedSnippet.targetsAllHosts ? t("scripts.allTargets") : selectedTargetHosts.length}</span>
                </div>
                {selectedTargetHosts.length === 0 && !selectedSnippet.targetsAllHosts ? (
                  <p>{t("scripts.noTargetHosts")}</p>
                ) : (
                  <div className="notes-scripts-host-chip-list">
                    {selectedTargetHosts.map((host) => (
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
                {selectedSnippet.targetGroups?.length ? (
                  <div className="notes-scripts-target-groups">
                    {selectedSnippet.targetGroups.map((group) => <span key={group}><WorkspaceGlyph name="folder" />{group}</span>)}
                  </div>
                ) : null}
              </section>

              {deletePrompt?.id === selectedSnippet.id ? (
                <div className="notes-scripts-delete-confirm" role="alertdialog" aria-label={t("scripts.deleteDialogAria")}>
                  <div>
                    <strong>{t("scripts.deleteQuestion", { title: selectedSnippet.label })}</strong>
                    <span>{t("scripts.deleteDescription")}</span>
                  </div>
                  <button type="button" onClick={() => setDeletePrompt(null)}>{t("notesScripts.action.cancel")}</button>
                  <button type="button" className="danger" onClick={() => void confirmDelete()} disabled={!nativeRuntimeAvailable || mutationPending}>
                    {mutationPending ? t("notesScripts.action.deleting") : t("notesScripts.action.confirmDelete")}
                  </button>
                </div>
              ) : null}
            </article>
          ) : (
            <div className="notes-scripts-empty-state">
              <span className="notes-scripts-empty-icon"><WorkspaceGlyph name="script" /></span>
              <h2>{query && catalog?.snippets.length
                ? t("notesScripts.search.selectResult")
                : t("scripts.emptyPageTitle")}</h2>
              <p>{t("scripts.emptyPageDescription")}</p>
              <button
                type="button"
                className="notes-scripts-primary-button"
                onClick={openCreateEditor}
                disabled={!catalog || disabled || !nativeRuntimeAvailable || mutationPending}
                title={nativeUnavailableMessage ?? undefined}
              ><WorkspaceGlyph name="plus" />{t("scripts.new")}</button>
            </div>
          )}
        </main>
      </div>
    </section>
  );
};
