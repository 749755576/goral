import { useEffect, useMemo, useRef, useState } from "react";
import type { KeyboardEvent as ReactKeyboardEvent, ReactNode } from "react";

import type { SftpEntry } from "./backend";
import { createTranslator, type Locale } from "./i18n";
import {
  SftpTransferQueue,
  type SftpTransferGlyphName,
} from "./SftpTransferQueue";
import type {
  SftpSessionOwner,
  SftpTransferControlAction,
  SftpTransferSnapshot,
} from "./sftpSessionController";
import {
  MAX_SFTP_FILE_FILTER_LENGTH,
  createSftpFilterDirectoryScopeKey,
  createSftpFilterSessionScopeKey,
  filterSftpEntries,
  limitSftpFileFilter,
  normalizeSftpFileFilter,
  resolveSftpFilterEscapeAction,
  sftpFilterMemory,
  shouldFocusSftpFileFilter,
} from "./sftpFileFilter.ts";

export type SftpBrowserGlyphName =
  | "up"
  | "upload"
  | "folder"
  | "refresh"
  | "search"
  | "close"
  | "download"
  | "file"
  | "edit"
  | "trash"
  | SftpTransferGlyphName;

export type SftpBreadcrumb = Readonly<{
  path: string;
  label: string;
}>;

export type SftpBrowserPanelProps = Readonly<{
  active: boolean;
  locale?: Locale;
  path: string;
  parentPath: string;
  breadcrumbs: readonly SftpBreadcrumb[];
  loading: boolean;
  error: string | null;
  entries: readonly SftpEntry[];
  visibleEntries: readonly SftpEntry[];
  showHiddenFiles: boolean;
  transfers: readonly SftpTransferSnapshot[];
  activeOwner: SftpSessionOwner | null;
  canControlTransfer: (owner: SftpSessionOwner, transferId: string) => boolean;
  onLoadPath: (path: string) => void | Promise<void>;
  onChooseUpload: (kind: "file" | "directory") => void | Promise<void>;
  onCreateFolder: () => void | Promise<void>;
  onDownloadEntry: (entry: SftpEntry) => void | Promise<void>;
  onDownloadDirectory: (entry: SftpEntry) => void | Promise<void>;
  onRenameEntry: (entry: SftpEntry) => void | Promise<void>;
  /** Opens a text file in the remote editor. Files only; the editor refuses
   * anything that is not UTF-8 text. */
  onEditEntry: (entry: SftpEntry) => void;
  onDeleteEntry: (entry: SftpEntry) => void | Promise<void>;
  onControlTransfer: (
    transfer: SftpTransferSnapshot,
    action: SftpTransferControlAction,
  ) => void | Promise<void>;
  onRetryTransfer: (transfer: SftpTransferSnapshot) => void | Promise<void>;
  formatBytes: (bytes: number) => string;
  glyph: (name: SftpBrowserGlyphName) => ReactNode;
}>;

const activateEntry = (
  event: ReactKeyboardEvent<HTMLDivElement>,
  entry: SftpEntry,
  onLoadPath: SftpBrowserPanelProps["onLoadPath"],
  onDownloadEntry: SftpBrowserPanelProps["onDownloadEntry"],
): void => {
  if (event.key !== "Enter") return;
  if (entry.metadata.kind === "directory") void onLoadPath(entry.path);
  if (entry.metadata.kind === "file") void onDownloadEntry(entry);
};

/**
 * SFTP browser presentation and transfer queue.
 *
 * Native paths, transfer IDs, and session authority remain callback-owned by
 * TerminalWorkspace. This component only renders the already-authorized
 * snapshot and forwards user intent.
 */
export function SftpBrowserPanel({
  active,
  locale = "zh-CN",
  path,
  parentPath,
  breadcrumbs,
  loading,
  error,
  entries,
  visibleEntries,
  showHiddenFiles,
  transfers,
  activeOwner,
  canControlTransfer,
  onLoadPath,
  onChooseUpload,
  onCreateFolder,
  onDownloadEntry,
  onDownloadDirectory,
  onRenameEntry,
  onEditEntry,
  onDeleteEntry,
  onControlTransfer,
  onRetryTransfer,
  formatBytes,
  glyph,
}: SftpBrowserPanelProps) {
  const t = createTranslator(locale);
  const panelRef = useRef<HTMLElement>(null);
  const filterInputRef = useRef<HTMLInputElement>(null);
  const compositionScopeRef = useRef<string | null>(null);
  const sessionScopeKey = createSftpFilterSessionScopeKey(activeOwner);
  const directoryScopeKey = createSftpFilterDirectoryScopeKey(activeOwner, path);
  const rememberedFilter = sftpFilterMemory.read(directoryScopeKey);
  const [filterState, setFilterState] = useState(() => ({
    sessionScopeKey,
    directoryScopeKey,
    open: rememberedFilter?.open ?? false,
    value: rememberedFilter?.value ?? "",
  }));
  const defaultScopedFilterState = {
    sessionScopeKey,
    directoryScopeKey,
    open: false,
    value: "",
  };
  const scopedFilterState = filterState.sessionScopeKey !== sessionScopeKey
    ? rememberedFilter
      ? { ...defaultScopedFilterState, ...rememberedFilter }
      : defaultScopedFilterState
    : filterState.directoryScopeKey !== directoryScopeKey
      ? rememberedFilter
        ? { ...defaultScopedFilterState, ...rememberedFilter }
        : {
            ...defaultScopedFilterState,
            open: filterState.open,
          }
      : filterState;
  const filteredEntries = useMemo(
    () => filterSftpEntries(visibleEntries, scopedFilterState.value),
    [scopedFilterState.value, visibleEntries],
  );
  const hasEffectiveFilter = normalizeSftpFileFilter(scopedFilterState.value).length > 0;

  useEffect(() => {
    compositionScopeRef.current = null;
    setFilterState((current) => {
      if (
        current.sessionScopeKey === sessionScopeKey
        && current.directoryScopeKey === directoryScopeKey
      ) return current;
      return rememberedFilter
        ? {
            sessionScopeKey,
            directoryScopeKey,
            ...rememberedFilter,
          }
        : current.sessionScopeKey === sessionScopeKey
          ? {
              sessionScopeKey,
              directoryScopeKey,
              open: current.open,
              value: "",
            }
          : {
              sessionScopeKey,
              directoryScopeKey,
              open: false,
              value: "",
            };
    });
  }, [directoryScopeKey, rememberedFilter, sessionScopeKey]);

  // Persist only the UI affordance, keyed by the exact session+directory
  // scope. This lets an unmounted panel restore its filter after a tab switch
  // while keeping filters isolated across retries and terminal sessions.
  useEffect(() => {
    sftpFilterMemory.write(directoryScopeKey, {
      open: scopedFilterState.open,
      value: scopedFilterState.value,
    });
  }, [directoryScopeKey, scopedFilterState.open, scopedFilterState.value]);

  const setCurrentFilterState = (
    update: (current: typeof scopedFilterState) => typeof scopedFilterState,
  ): void => {
    setFilterState((current) => {
      const scoped = current.sessionScopeKey !== sessionScopeKey
        ? { sessionScopeKey, directoryScopeKey, open: false, value: "" }
        : current.directoryScopeKey !== directoryScopeKey
          ? { sessionScopeKey, directoryScopeKey, open: current.open, value: "" }
          : current;
      return update(scoped);
    });
  };
  const focusFilterInput = (): void => {
    window.setTimeout(() => filterInputRef.current?.focus(), 0);
  };
  const openFilter = (): void => {
    setCurrentFilterState((current) => ({ ...current, open: true }));
    focusFilterInput();
  };
  const clearFilter = (): void => {
    compositionScopeRef.current = null;
    setCurrentFilterState((current) => ({ ...current, value: "" }));
  };
  const closeFilter = (): void => {
    compositionScopeRef.current = null;
    setCurrentFilterState((current) => ({ ...current, open: false, value: "" }));
  };

  useEffect(() => {
    if (!active) return;
    const handleSearchShortcut = (event: globalThis.KeyboardEvent): void => {
      if (!shouldFocusSftpFileFilter(event, true, filterInputRef.current)) return;
      event.preventDefault();
      event.stopPropagation();
      setFilterState((current) => {
        const scoped = current.sessionScopeKey !== sessionScopeKey
          ? { sessionScopeKey, directoryScopeKey, open: false, value: "" }
          : current.directoryScopeKey !== directoryScopeKey
            ? { sessionScopeKey, directoryScopeKey, open: current.open, value: "" }
            : current;
        return { ...scoped, open: true };
      });
      window.setTimeout(() => filterInputRef.current?.focus(), 0);
    };
    window.addEventListener("keydown", handleSearchShortcut, true);
    return () => window.removeEventListener("keydown", handleSearchShortcut, true);
  }, [active, directoryScopeKey, sessionScopeKey]);

  return (
    <section
      ref={panelRef}
      className="sftp-panel"
      aria-label={t("sftp.browser")}
      tabIndex={-1}
    >
      <div className="sftp-toolbar">
        <div className="sftp-path-row">
          <button
            type="button"
            className="sftp-icon-button"
            disabled={loading || path === "/"}
            onClick={() => void onLoadPath(parentPath)}
            aria-label={t("sftp.parentDirectory")}
            title={t("sftp.parentDirectory")}
          >
            {glyph("up")}
          </button>
          <nav className="sftp-breadcrumbs" aria-label={t("sftp.remotePath")}>
            {breadcrumbs.map((breadcrumb, index) => (
              <span key={breadcrumb.path}>
                {index > 0 && <i aria-hidden="true">/</i>}
                <button
                  type="button"
                  disabled={loading || breadcrumb.path === path}
                  onClick={() => void onLoadPath(breadcrumb.path)}
                  title={breadcrumb.path}
                >
                  {breadcrumb.label}
                </button>
              </span>
            ))}
          </nav>
        </div>
        <div className="sftp-action-row">
          <button
            type="button"
            className="sftp-icon-button"
            disabled={loading}
            onClick={() => void onChooseUpload("file")}
            aria-label={t("sftp.uploadFile")}
            title={t("sftp.uploadFile")}
          >
            {glyph("upload")}
          </button>
          <button
            type="button"
            className="sftp-icon-button sftp-upload-folder-button"
            disabled={loading}
            onClick={() => void onChooseUpload("directory")}
            aria-label={t("sftp.uploadFolder")}
            title={t("sftp.uploadFolder")}
          >
            {glyph("folder")}
            <span aria-hidden="true">↑</span>
          </button>
          <button
            type="button"
            className="sftp-icon-button"
            disabled={loading}
            onClick={() => void onCreateFolder()}
            aria-label={t("sftp.newFolder")}
            title={t("sftp.newFolder")}
          >
            {glyph("folder")}
            <span aria-hidden="true">+</span>
          </button>
          <button
            type="button"
            className={`sftp-icon-button${scopedFilterState.open || hasEffectiveFilter ? " active" : ""}`}
            onClick={() => {
              if (scopedFilterState.open) closeFilter();
              else openFilter();
            }}
            aria-label={t("sftp.filterInput")}
            aria-pressed={scopedFilterState.open}
            title={t("sftp.filterInput")}
          >
            {glyph("search")}
          </button>
          <span className="sftp-action-spacer" />
          <button
            type="button"
            className="sftp-icon-button"
            disabled={loading}
            onClick={() => void onLoadPath(path)}
            aria-label={loading ? t("sftp.refreshingDirectory") : t("sftp.refreshDirectory")}
            title={t("sftp.refreshDirectory")}
          >
            {glyph("refresh")}
          </button>
        </div>
        {scopedFilterState.open && (
          <div className="sftp-filter-row" data-sftp-filter-bar="true">
            <div className="sftp-filter-field">
              {glyph("search")}
              <input
                ref={filterInputRef}
                data-sftp-filter-input="true"
                type="search"
                value={scopedFilterState.value}
                maxLength={MAX_SFTP_FILE_FILTER_LENGTH}
                placeholder={t("sftp.filterPlaceholder")}
                aria-label={t("sftp.filterInput")}
                autoComplete="off"
                spellCheck={false}
                onChange={(event) => {
                  if (
                    compositionScopeRef.current !== null
                    && compositionScopeRef.current !== directoryScopeKey
                  ) return;
                  const value = limitSftpFileFilter(event.currentTarget.value);
                  setCurrentFilterState((current) => ({ ...current, value }));
                }}
                onCompositionStart={() => {
                  compositionScopeRef.current = directoryScopeKey;
                }}
                onCompositionEnd={(event) => {
                  if (compositionScopeRef.current !== directoryScopeKey) return;
                  compositionScopeRef.current = null;
                  const value = limitSftpFileFilter(event.currentTarget.value);
                  setCurrentFilterState((current) => ({ ...current, value }));
                }}
                onKeyDown={(event) => {
                  if (event.key !== "Escape" || event.nativeEvent.isComposing) return;
                  event.preventDefault();
                  event.stopPropagation();
                  if (resolveSftpFilterEscapeAction(scopedFilterState.value) === "clear") {
                    clearFilter();
                  } else {
                    closeFilter();
                    panelRef.current?.focus();
                  }
                }}
              />
              {scopedFilterState.value && (
                <button
                  type="button"
                  className="sftp-filter-clear"
                  onClick={() => {
                    clearFilter();
                    focusFilterInput();
                  }}
                  aria-label={t("sftp.clearFilter")}
                  title={t("sftp.clearFilter")}
                >
                  {glyph("close")}
                </button>
              )}
            </div>
            <button
              type="button"
              className="sftp-filter-close"
              onClick={closeFilter}
              aria-label={t("sftp.closeFilter")}
              title={t("sftp.closeFilter")}
            >
              {glyph("close")}
            </button>
          </div>
        )}
      </div>
      <div className="sftp-list-header" role="row" aria-hidden="true">
        <span />
        <span>{t("sftp.name")}</span>
        <span>{t("sftp.size")}</span>
        <span />
      </div>
      <div className="sftp-list-stage">
        {loading && (
          <div className="sftp-loading" role="status" aria-live="polite">
            <span className="sftp-spinner" aria-hidden="true" />
            <span>{t("sftp.loadingDirectory")}</span>
          </div>
        )}
        {error ? (
          <div className="sftp-state sftp-error" role="alert">
            {glyph("folder")}
            <strong>{t("sftp.openDirectoryFailed")}</strong>
            <span>{error}</span>
            <button type="button" onClick={() => void onLoadPath(path)}>
              {glyph("refresh")} {t("sftp.retry")}
            </button>
          </div>
        ) : (
          <div className="sftp-list" role="table" aria-label={path}>
            {filteredEntries.length === 0 && !loading && (
              hasEffectiveFilter && visibleEntries.length > 0 ? (
                <div className="sftp-state sftp-filter-empty">
                  {glyph("search")}
                  <strong>{t("sftp.noFilterMatches")}</strong>
                  <span>{t("sftp.noFilterMatchesHint")}</span>
                  <button type="button" onClick={() => {
                    clearFilter();
                    focusFilterInput();
                  }}>
                    {glyph("close")} {t("sftp.clearFilter")}
                  </button>
                </div>
              ) : (
                <div className="sftp-state sftp-empty">
                  {glyph("folder")}
                  <strong>{t("sftp.emptyDirectory")}</strong>
                  <span>{t("sftp.emptyDirectoryHint")}</span>
                  <button type="button" onClick={() => void onChooseUpload("file")}>
                    {glyph("upload")} {t("sftp.uploadFile")}
                  </button>
                </div>
              )
            )}
            {filteredEntries.map((entry) => (
              <div
                className={`sftp-entry${entry.metadata.kind === "directory" ? " directory-entry" : ""}`}
                role="row"
                key={entry.path}
                tabIndex={entry.metadata.kind === "directory" || entry.metadata.kind === "file" ? 0 : -1}
                onDoubleClick={() => {
                  if (entry.metadata.kind === "directory") void onLoadPath(entry.path);
                  if (entry.metadata.kind === "file") void onDownloadEntry(entry);
                }}
                onKeyDown={(event) => activateEntry(event, entry, onLoadPath, onDownloadEntry)}
              >
                <span className={`sftp-entry-kind kind-${entry.metadata.kind}`} aria-hidden="true">
                  {glyph(entry.metadata.kind === "directory" ? "folder" : "file")}
                </span>
                <span title={entry.name}>{entry.name}</span>
                <small>{entry.metadata.kind === "directory" ? "—" : formatBytes(entry.metadata.size)}</small>
                <span className="sftp-entry-actions">
                  {entry.metadata.kind === "file" ? (
                    <button
                      type="button"
                      title={t("editor.title")}
                      aria-label={t("editor.contentLabel", { name: entry.name })}
                      onClick={(event) => {
                        event.stopPropagation();
                        onEditEntry(entry);
                      }}
                      onDoubleClick={(event) => event.stopPropagation()}
                      onKeyDown={(event) => event.stopPropagation()}
                    >
                      {glyph("file")}
                    </button>
                  ) : null}
                  <button
                    type="button"
                    title={entry.metadata.kind === "directory" ? t("sftp.downloadFolder") : t("sftp.downloadFile")}
                    aria-label={t("sftp.downloadEntry", { entry: entry.name })}
                    onClick={(event) => {
                      event.stopPropagation();
                      if (entry.metadata.kind === "directory") void onDownloadDirectory(entry);
                      if (entry.metadata.kind === "file") void onDownloadEntry(entry);
                    }}
                    onDoubleClick={(event) => event.stopPropagation()}
                    onKeyDown={(event) => event.stopPropagation()}
                  >
                    {glyph("download")}
                  </button>
                  <button
                    type="button"
                    onClick={(event) => {
                      event.stopPropagation();
                      void onRenameEntry(entry);
                    }}
                    onDoubleClick={(event) => event.stopPropagation()}
                    title={t("sftp.rename")}
                    aria-label={t("sftp.renameEntry", { entry: entry.name })}
                  >
                    {glyph("edit")}
                  </button>
                  <button
                    type="button"
                    onClick={(event) => {
                      event.stopPropagation();
                      void onDeleteEntry(entry);
                    }}
                    onDoubleClick={(event) => event.stopPropagation()}
                    title={t("sftp.delete")}
                    aria-label={t("sftp.deleteEntry", { entry: entry.name })}
                  >
                    {glyph("trash")}
                  </button>
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
      <footer className="sftp-statusbar">
        <span>{t("sftp.itemCount", { count: filteredEntries.length })}</span>
        {!showHiddenFiles && entries.length > visibleEntries.length && (
          <span>{t("sftp.hiddenCount", { count: entries.length - visibleEntries.length })}</span>
        )}
        <code title={path}>{path}</code>
      </footer>
      <SftpTransferQueue
        locale={locale}
        transfers={transfers}
        activeOwner={activeOwner}
        canControlTransfer={canControlTransfer}
        onControlTransfer={onControlTransfer}
        onRetryTransfer={onRetryTransfer}
        formatBytes={formatBytes}
        glyph={glyph}
      />
    </section>
  );
}
