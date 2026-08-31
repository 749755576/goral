import { isTauri } from "@tauri-apps/api/core";
import {
  useCallback,
  useDeferredValue,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type DragEvent,
} from "react";

import {
  listKnownHosts,
  replaceKnownHosts,
  scanSystemKnownHosts,
  type KnownHostsCatalog,
  type SavedKnownHost,
  type SystemKnownHostsScan,
} from "./knownHostsApi";
import {
  classifyKnownHostsError,
  dedupeKnownHostsForDisplay,
  matchesKnownHostSearch,
  mergeKnownHosts,
  parseKnownHostsFile,
  reorderKnownHosts,
  sortKnownHosts,
  withoutPublicServiceKnownHosts,
  KNOWN_HOSTS_IMPORT_MAX_BYTES,
  type KnownHostsSortMode,
  type KnownHostsViewMode,
} from "./knownHostsUi";
import { useI18n, type Locale } from "./i18n";

export type KnownHostsWorkspaceApi = {
  list: typeof listKnownHosts;
  replace: typeof replaceKnownHosts;
  scanSystem: typeof scanSystemKnownHosts;
};

export type KnownHostsSavedHost = {
  id: string;
  hostname: string;
  port: number;
};

export type KnownHostsWorkspaceProps = {
  locale?: Locale;
  hosts?: readonly KnownHostsSavedHost[];
  disabled?: boolean;
  refreshKey?: string | number;
  autoScanSystem?: boolean;
  api?: KnownHostsWorkspaceApi;
  onCatalogChange?: (catalog: KnownHostsCatalog) => void;
  onConvertToHost?: (knownHost: SavedKnownHost) => Promise<string>;
};

type KnownHostsGlyphName =
  | "arrow"
  | "chevron"
  | "folder"
  | "grid"
  | "import"
  | "list"
  | "refresh"
  | "search"
  | "server"
  | "shield"
  | "sort"
  | "trash";

type Replacement = {
  knownHosts?: SavedKnownHost[];
  notice?: string;
};

type ContextMenuState = {
  id: string;
  x: number;
  y: number;
};

const EMPTY_CATALOG: KnownHostsCatalog = {
  inventoryRevision: null,
  knownHosts: [],
};

const DEFAULT_API: KnownHostsWorkspaceApi = {
  list: listKnownHosts,
  replace: replaceKnownHosts,
  scanSystem: scanSystemKnownHosts,
};

const RENDER_LIMIT = 100;
const VIEW_MODE_STORAGE_KEY = "netcatty:vault-known-hosts-view-mode";

const GLYPH_PATHS: Record<KnownHostsGlyphName, string[]> = {
  arrow: ["M5 12h14M14 6l6 6-6 6"],
  chevron: ["m8 10 4 4 4-4"],
  folder: ["M3 6h7l2 2h9v11H3z"],
  grid: ["M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z"],
  import: ["M12 3v12M7 10l5 5 5-5M4 20h16"],
  list: ["M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"],
  refresh: ["M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7"],
  search: ["M10.8 18.3a7.5 7.5 0 1 1 0-15 7.5 7.5 0 0 1 0 15ZM16.2 16.2 21 21"],
  server: ["M5 4h14v6H5zM5 14h14v6H5zM8 7h.01M8 17h.01M12 7h4M12 17h4"],
  shield: ["M12 3 4.5 6v5.5c0 4.8 3.1 8.2 7.5 9.5 4.4-1.3 7.5-4.7 7.5-9.5V6zM9 12l2 2 4-5"],
  sort: ["M8 6h12M8 12h8M8 18h4M4 4v16M2 18l2 2 2-2"],
  trash: ["M4 7h16M9 7V4h6v3M7 7l1 14h8l1-14M10 11v6M14 11v6"],
};

const KnownHostsGlyph = ({ name }: { name: KnownHostsGlyphName }) => (
  <svg
    aria-hidden="true"
    className="known-hosts-glyph"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    {GLYPH_PATHS[name].map((path) => <path d={path} key={path} />)}
  </svg>
);

const readStoredViewMode = (): KnownHostsViewMode => {
  try {
    const stored = globalThis.localStorage?.getItem(VIEW_MODE_STORAGE_KEY);
    return stored === "list" ? "list" : "grid";
  } catch {
    return "grid";
  }
};

const storeViewMode = (mode: KnownHostsViewMode) => {
  try {
    globalThis.localStorage?.setItem(VIEW_MODE_STORAGE_KEY, mode);
  } catch {
    // A private browser preview may not expose storage; the in-memory mode still works.
  }
};

const closeOwnerDetails = (element: HTMLElement) => {
  element.closest("details")?.removeAttribute("open");
};

export const KnownHostsWorkspace = ({
  locale = "zh-CN",
  hosts = [],
  disabled = false,
  refreshKey,
  autoScanSystem = true,
  api,
  onCatalogChange,
  onConvertToHost,
}: KnownHostsWorkspaceProps) => {
  const { t } = useI18n(locale);
  const knownHostsApi = api ?? DEFAULT_API;
  const nativeRuntimeAvailable = api !== undefined || isTauri();
  const [catalog, setCatalog] = useState<KnownHostsCatalog | null>(null);
  const [loading, setLoading] = useState(true);
  const [mutationPending, setMutationPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const deferredQuery = useDeferredValue(query);
  const [viewMode, setViewModeState] = useState<KnownHostsViewMode>(readStoredViewMode);
  const [sortMode, setSortMode] = useState<KnownHostsSortMode>("manual");
  const [deleteTargetId, setDeleteTargetId] = useState<string | null>(null);
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);
  const fileInput = useRef<HTMLInputElement | null>(null);
  const mounted = useRef(true);
  const loadSequence = useRef(0);
  const mutationLock = useRef(false);
  const autoScanAttempted = useRef(false);
  const observedRefreshKey = useRef(refreshKey);
  const onCatalogChangeRef = useRef(onCatalogChange);

  useEffect(() => {
    onCatalogChangeRef.current = onCatalogChange;
  }, [onCatalogChange]);

  const applyCatalog = useCallback((next: KnownHostsCatalog) => {
    setCatalog(next);
    onCatalogChangeRef.current?.(next);
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
      const next = await knownHostsApi.list();
      if (!mounted.current || sequence !== loadSequence.current) return false;
      applyCatalog(next);
      return true;
    } catch (reason) {
      if (mounted.current && sequence === loadSequence.current) {
        setError(classifyKnownHostsError(reason, t).message);
      }
      return false;
    } finally {
      if (mounted.current && sequence === loadSequence.current) setLoading(false);
    }
  }, [applyCatalog, knownHostsApi, nativeRuntimeAvailable, t]);

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
    setDeleteTargetId(null);
    setContextMenu(null);
    void refreshCatalog();
  }, [refreshCatalog, refreshKey]);

  useEffect(() => {
    if (!contextMenu) return undefined;
    const close = () => setContextMenu(null);
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") close();
    };
    globalThis.addEventListener("pointerdown", close);
    globalThis.addEventListener("keydown", handleKey);
    return () => {
      globalThis.removeEventListener("pointerdown", close);
      globalThis.removeEventListener("keydown", handleKey);
    };
  }, [contextMenu]);

  const runReplacement = useCallback(async (
    build: (snapshot: KnownHostsCatalog) => Promise<Replacement> | Replacement,
  ): Promise<boolean> => {
    const snapshot = catalog;
    if (!snapshot || disabled || mutationLock.current) return false;
    if (!nativeRuntimeAvailable) {
      setNotice(t("knownHosts.desktopOnly"));
      return false;
    }
    mutationLock.current = true;
    loadSequence.current += 1;
    setMutationPending(true);
    setError(null);
    setNotice(null);
    try {
      const replacement = await build(snapshot);
      if (!replacement.knownHosts) {
        if (mounted.current) setNotice(replacement.notice ?? null);
        return true;
      }
      const next = await knownHostsApi.replace({
        expectedInventoryRevision: snapshot.inventoryRevision,
        knownHosts: replacement.knownHosts,
      });
      if (!mounted.current) return false;
      applyCatalog(next);
      setNotice(replacement.notice ?? null);
      return true;
    } catch (reason) {
      const issue = classifyKnownHostsError(reason, t);
      if (issue.refreshCatalog) await refreshCatalog(true);
      if (mounted.current) setError(issue.message);
      return false;
    } finally {
      mutationLock.current = false;
      if (mounted.current) setMutationPending(false);
    }
  }, [applyCatalog, catalog, disabled, knownHostsApi, nativeRuntimeAvailable, refreshCatalog, t]);

  const scanSystem = useCallback(async (silent = false) => {
    await runReplacement(async (snapshot) => {
      const scan: SystemKnownHostsScan = await knownHostsApi.scanSystem();
      const importable = withoutPublicServiceKnownHosts(scan.knownHosts);
      if (scan.sourceCount === 0 || importable.length === 0) {
        return {
          notice: silent ? undefined : t("knownHosts.noUsableSystem"),
        };
      }
      const merged = mergeKnownHosts(snapshot.knownHosts, importable);
      const filteredPublicServices = scan.knownHosts.length - importable.length;
      const omitted = scan.omittedCount + filteredPublicServices;
      return {
        knownHosts: merged,
        notice: silent
          ? undefined
          : t("knownHosts.scanResult", {
            source: scan.sourceCount,
            imported: importable.length,
            omitted: omitted ? t("knownHosts.omittedSuffix", { count: omitted }) : "",
          }),
      };
    });
  }, [knownHostsApi, runReplacement, t]);

  useEffect(() => {
    if (!autoScanSystem || !nativeRuntimeAvailable || !catalog || autoScanAttempted.current) return;
    autoScanAttempted.current = true;
    const timer = globalThis.setTimeout(() => void scanSystem(true), 100);
    return () => globalThis.clearTimeout(timer);
  }, [autoScanSystem, catalog, nativeRuntimeAvailable, scanSystem]);

  const setViewMode = (mode: KnownHostsViewMode) => {
    setViewModeState(mode);
    storeViewMode(mode);
  };

  const visibleHosts = useMemo(() => sortKnownHosts(
    dedupeKnownHostsForDisplay(catalog?.knownHosts ?? [])
      .filter((knownHost) => matchesKnownHostSearch(knownHost, deferredQuery)),
    sortMode,
  ), [catalog?.knownHosts, deferredQuery, sortMode]);
  const displayedHosts = visibleHosts.slice(0, RENDER_LIMIT);
  const savedHostIds = useMemo(() => new Set(hosts.map((host) => host.id)), [hosts]);
  const convertedBySelector = useMemo(() => new Set(
    hosts.map((host) => `${host.hostname.trim().toLocaleLowerCase()}:${host.port}`),
  ), [hosts]);
  const deleteTarget = catalog?.knownHosts.find((knownHost) => knownHost.id === deleteTargetId) ?? null;
  const contextTarget = catalog?.knownHosts.find((knownHost) => knownHost.id === contextMenu?.id) ?? null;

  const isConverted = useCallback((knownHost: SavedKnownHost): boolean => (
    (Boolean(knownHost.convertedToHostId) && savedHostIds.has(knownHost.convertedToHostId!))
    || convertedBySelector.has(`${knownHost.hostname.trim().toLocaleLowerCase()}:${knownHost.port}`)
  ), [convertedBySelector, savedHostIds]);

  const importFile = async (file: File) => {
    if (file.size > KNOWN_HOSTS_IMPORT_MAX_BYTES) {
      setError(t("knownHosts.fileTooLarge"));
      setNotice(null);
      return;
    }
    await runReplacement(async (snapshot) => {
      const parsed = withoutPublicServiceKnownHosts(await parseKnownHostsFile(await file.text()));
      if (parsed.length === 0) return { notice: t("knownHosts.noUsableFile") };
      return {
        knownHosts: mergeKnownHosts(snapshot.knownHosts, parsed),
        notice: t("knownHosts.imported", { count: parsed.length }),
      };
    });
  };

  const deleteKnownHost = async (id: string) => {
    const deleted = await runReplacement((snapshot) => ({
      knownHosts: snapshot.knownHosts.filter((knownHost) => knownHost.id !== id),
      notice: t("knownHosts.removed"),
    }));
    if (deleted) setDeleteTargetId(null);
  };

  const convertKnownHost = async (knownHost: SavedKnownHost) => {
    if (!onConvertToHost || disabled || mutationLock.current) return;
    if (!nativeRuntimeAvailable) {
      setNotice(t("knownHosts.desktopOnly"));
      return;
    }
    mutationLock.current = true;
    loadSequence.current += 1;
    setMutationPending(true);
    setError(null);
    setNotice(null);
    try {
      const hostId = await onConvertToHost(knownHost);

      // SavedHost creation mutates the complete Vault graph and therefore
      // advances the inventory revision. Re-list after creation instead of
      // reusing the page snapshot; retry once if another writer wins between
      // that fresh read and the marker replacement.
      let convertedCatalog: KnownHostsCatalog | null = null;
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const latest = await knownHostsApi.list();
        const targetIndex = latest.knownHosts.findIndex((candidate) => (
          candidate.id === knownHost.id
          || (
            candidate.hostname.trim().toLocaleLowerCase()
              === knownHost.hostname.trim().toLocaleLowerCase()
            && candidate.port === knownHost.port
            && candidate.keyType === knownHost.keyType
          )
        ));
        if (targetIndex < 0) throw new Error("KNOWN_HOST_NOT_FOUND");
        const nextKnownHosts = [...latest.knownHosts];
        nextKnownHosts[targetIndex] = {
          ...nextKnownHosts[targetIndex],
          convertedToHostId: hostId,
        };
        try {
          convertedCatalog = await knownHostsApi.replace({
            expectedInventoryRevision: latest.inventoryRevision,
            knownHosts: nextKnownHosts,
          });
          break;
        } catch (reason) {
          if (attempt === 0 && classifyKnownHostsError(reason, t).refreshCatalog) continue;
          throw reason;
        }
      }
      if (!convertedCatalog) throw new Error("KNOWN_HOSTS_INVENTORY_CHANGED");
      if (!mounted.current) return;
      applyCatalog(convertedCatalog);
      setNotice(t("knownHosts.addedToHosts", { host: knownHost.hostname }));
      setContextMenu(null);
    } catch (reason) {
      const issue = classifyKnownHostsError(reason, t);
      if (issue.refreshCatalog) await refreshCatalog(true);
      if (mounted.current) setError(issue.message);
    } finally {
      mutationLock.current = false;
      if (mounted.current) setMutationPending(false);
    }
  };

  const reorder = async (
    sourceId: string,
    targetId: string,
    position: "before" | "after",
  ) => {
    setSortMode("manual");
    await runReplacement((snapshot) => ({
      knownHosts: reorderKnownHosts(snapshot.knownHosts, sourceId, targetId, position),
    }));
  };

  const handleDrop = (event: DragEvent<HTMLElement>, targetId: string) => {
    event.preventDefault();
    const sourceId = event.dataTransfer.getData("application/x-netcatty-known-host");
    const bounds = event.currentTarget.getBoundingClientRect();
    const position = viewMode === "list"
      ? (event.clientY >= bounds.top + bounds.height / 2 ? "after" : "before")
      : (event.clientX >= bounds.left + bounds.width / 2 ? "after" : "before");
    if (sourceId) void reorder(sourceId, targetId, position);
  };

  const renderActions = (knownHost: SavedKnownHost) => {
    const converted = isConverted(knownHost);
    return (
      <div className="known-hosts-item-actions">
        {!converted ? (
          <button
            type="button"
            onClick={(event) => {
              event.stopPropagation();
              void convertKnownHost(knownHost);
            }}
            disabled={disabled || mutationPending || !onConvertToHost}
            aria-label={t("knownHosts.convertNamed", { host: knownHost.hostname })}
            title={t("knownHosts.convert")}
          >
            <KnownHostsGlyph name="arrow" />
          </button>
        ) : null}
        <button
          type="button"
          className="danger"
          onClick={(event) => {
            event.stopPropagation();
            setDeleteTargetId(knownHost.id);
          }}
          disabled={disabled || mutationPending}
          aria-label={t("knownHosts.removeNamed", { host: knownHost.hostname })}
          title={t("knownHosts.remove")}
        >
          <KnownHostsGlyph name="trash" />
        </button>
      </div>
    );
  };

  return (
    <section className="known-hosts-workspace" aria-label={t("knownHosts.workspace")}>
      <header className="known-hosts-header">
        <label className="known-hosts-search">
          <KnownHostsGlyph name="search" />
          <input
            type="search"
            value={query}
            onChange={(event) => setQuery(event.currentTarget.value)}
            placeholder={t("knownHosts.searchPlaceholder")}
            aria-label={t("knownHosts.search")}
          />
        </label>

        <div className="known-hosts-header-controls">
          <details className="known-hosts-menu">
            <summary aria-label={t("knownHosts.changeView")} title={t("knownHosts.changeView")}>
              <KnownHostsGlyph name={viewMode === "grid" ? "grid" : "list"} />
              <KnownHostsGlyph name="chevron" />
            </summary>
            <div className="known-hosts-menu-popover" role="menu">
              {(["grid", "list"] as const).map((mode) => (
                <button
                  type="button"
                  className={viewMode === mode ? "active" : ""}
                  onClick={(event) => {
                    setViewMode(mode);
                    closeOwnerDetails(event.currentTarget);
                  }}
                  key={mode}
                  role="menuitem"
                >
                  <KnownHostsGlyph name={mode} />{mode === "grid" ? t("knownHosts.grid") : t("knownHosts.list")}
                </button>
              ))}
            </div>
          </details>

          <details className="known-hosts-menu">
            <summary aria-label={t("knownHosts.sort")} title={t("knownHosts.sort")}>
              <KnownHostsGlyph name="sort" />
              <KnownHostsGlyph name="chevron" />
            </summary>
            <div className="known-hosts-menu-popover known-hosts-sort-menu" role="menu">
              {([
                ["manual", t("knownHosts.sortManual")],
                ["az", "A–Z"],
                ["za", "Z–A"],
                ["newest", t("knownHosts.sortNewest")],
                ["oldest", t("knownHosts.sortOldest")],
              ] as const).map(([mode, label]) => (
                <button
                  type="button"
                  className={sortMode === mode ? "active" : ""}
                  onClick={(event) => {
                    setSortMode(mode);
                    closeOwnerDetails(event.currentTarget);
                  }}
                  key={mode}
                  role="menuitem"
                >{label}</button>
              ))}
            </div>
          </details>

          <span className="known-hosts-header-divider" aria-hidden="true" />
          <button
            type="button"
            className="known-hosts-secondary-button"
            onClick={() => void scanSystem()}
            disabled={disabled || loading || mutationPending}
          >
            <KnownHostsGlyph name="refresh" />{t("knownHosts.scanSystem")}
          </button>
          <input
            ref={fileInput}
            type="file"
            accept=".txt,known_hosts"
            hidden
            onChange={(event) => {
              const file = event.currentTarget.files?.[0];
              if (file) void importFile(file);
              event.currentTarget.value = "";
            }}
          />
          <button
            type="button"
            className="known-hosts-secondary-button"
            onClick={() => fileInput.current?.click()}
            disabled={disabled || loading || mutationPending}
          >
            <KnownHostsGlyph name="import" />{t("knownHosts.importFile")}
          </button>
        </div>
      </header>

      {error ? <div className="known-hosts-message error" role="alert">{error}</div> : null}
      {notice ? <div className="known-hosts-message notice" role="status">{notice}</div> : null}

      <div className="known-hosts-scroll-region">
        <div className={`known-hosts-items ${viewMode}`}>
          {loading && !catalog ? (
            <div className="known-hosts-loading">{t("knownHosts.loading")}</div>
          ) : displayedHosts.length === 0 ? (
            <div className="known-hosts-empty-state">
              <span className="known-hosts-empty-icon"><KnownHostsGlyph name="shield" /></span>
              <h2>{t("knownHosts.empty")}</h2>
              <p>{t("knownHosts.emptyDescription")}</p>
              <div>
                <button
                  type="button"
                  className="known-hosts-secondary-button"
                  onClick={() => void scanSystem()}
                  disabled={disabled || loading || mutationPending}
                ><KnownHostsGlyph name="refresh" />{t("knownHosts.scanSystem")}</button>
                <button
                  type="button"
                  className="known-hosts-outline-button"
                  onClick={() => fileInput.current?.click()}
                  disabled={disabled || loading || mutationPending}
                ><KnownHostsGlyph name="folder" />{t("knownHosts.browseFile")}</button>
              </div>
            </div>
          ) : (
            <>
              {displayedHosts.map((knownHost) => (
                <article
                  className={`known-hosts-item${isConverted(knownHost) ? " converted" : ""}`}
                  draggable={!disabled && !mutationPending && !deferredQuery.trim()}
                  onDragStart={(event) => {
                    event.dataTransfer.effectAllowed = "move";
                    event.dataTransfer.setData("application/x-netcatty-known-host", knownHost.id);
                  }}
                  onDragOver={(event) => event.preventDefault()}
                  onDrop={(event) => handleDrop(event, knownHost.id)}
                  onContextMenu={(event) => {
                    event.preventDefault();
                    setContextMenu({ id: knownHost.id, x: event.clientX, y: event.clientY });
                  }}
                  data-known-host-id={knownHost.id}
                  key={knownHost.id}
                >
                  <span className="known-hosts-item-icon"><KnownHostsGlyph name="server" /></span>
                  <strong title={knownHost.hostname}>{knownHost.hostname}</strong>
                  {renderActions(knownHost)}
                </article>
              ))}
              {visibleHosts.length > RENDER_LIMIT ? (
                <p className="known-hosts-limit">
                  {t("knownHosts.renderLimit", { shown: RENDER_LIMIT, total: visibleHosts.length })}
                </p>
              ) : null}
            </>
          )}
        </div>
      </div>

      {contextMenu && contextTarget ? (
        <div
          className="known-hosts-context-menu"
          role="menu"
          style={{ "--known-hosts-menu-x": `${contextMenu.x}px`, "--known-hosts-menu-y": `${contextMenu.y}px` } as CSSProperties}
          onPointerDown={(event) => event.stopPropagation()}
        >
          {!isConverted(contextTarget) ? (
            <button type="button" role="menuitem" onClick={() => void convertKnownHost(contextTarget)}>
              <KnownHostsGlyph name="arrow" />{t("knownHosts.convert")}
            </button>
          ) : null}
          <button
            type="button"
            className="danger"
            role="menuitem"
            onClick={() => {
              setDeleteTargetId(contextTarget.id);
              setContextMenu(null);
            }}
          ><KnownHostsGlyph name="trash" />{t("knownHosts.remove")}</button>
        </div>
      ) : null}

      {deleteTarget ? (
        <div className="known-hosts-dialog-backdrop" role="presentation">
          <section className="known-hosts-dialog" role="dialog" aria-modal="true" aria-labelledby="known-host-delete-title">
            <h2 id="known-host-delete-title">{t("knownHosts.deleteTitle", { host: deleteTarget.hostname })}</h2>
            <p>{t("knownHosts.deleteDescription")}</p>
            <div>
              <button type="button" onClick={() => setDeleteTargetId(null)} disabled={mutationPending}>{t("knownHosts.cancel")}</button>
              <button type="button" className="danger" onClick={() => void deleteKnownHost(deleteTarget.id)} disabled={mutationPending}>
                {mutationPending ? t("knownHosts.deleting") : t("knownHosts.delete")}
              </button>
            </div>
          </section>
        </div>
      ) : null}
    </section>
  );
};
