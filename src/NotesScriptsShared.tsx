import { useMemo, useState, type ReactNode } from "react";

import { useI18n, type Locale } from "./i18n";
import type { NotesScriptsHost } from "./notesSnippetsUi";

export type WorkspaceGlyphName =
  | "code"
  | "edit"
  | "folder"
  | "host"
  | "note"
  | "plus"
  | "refresh"
  | "script"
  | "search"
  | "tag"
  | "trash";

export const WorkspaceGlyph = ({ name }: { name: WorkspaceGlyphName }) => {
  const body: Record<WorkspaceGlyphName, ReactNode> = {
    code: <><path d="m8 9-3 3 3 3" /><path d="m16 9 3 3-3 3" /><path d="m14 5-4 14" /></>,
    edit: <><path d="M12 20h9" /><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L8 18l-4 1 1-4Z" /></>,
    folder: <><path d="M3 6.5h6l2 2h10v9.5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z" /><path d="M3 10h18" /></>,
    host: <><rect x="4" y="3" width="16" height="7" rx="2" /><rect x="4" y="14" width="16" height="7" rx="2" /><path d="M8 6.5h.01M8 17.5h.01M12 10v4" /></>,
    note: <><path d="M6 3h9l4 4v14H6Z" /><path d="M14 3v5h5M9 12h7M9 16h7" /></>,
    plus: <><path d="M12 5v14M5 12h14" /></>,
    refresh: <><path d="M20 7v5h-5" /><path d="M4 17v-5h5" /><path d="M6.1 9a7 7 0 0 1 11.6-2.6L20 9M4 15l2.3 2.6A7 7 0 0 0 17.9 15" /></>,
    script: <><path d="M7 3h8l4 4v14H7Z" /><path d="M14 3v5h5M10 12l-2 2 2 2M15 12l2 2-2 2" /></>,
    search: <><circle cx="11" cy="11" r="7" /><path d="m20 20-4-4" /></>,
    tag: <><path d="M20 13 13 20 4 11V4h7Z" /><circle cx="8.5" cy="8.5" r="1" /></>,
    trash: <><path d="M4 7h16M9 7V4h6v3M7 7l1 14h8l1-14M10 11v6M14 11v6" /></>,
  };

  return (
    <svg
      aria-hidden="true"
      className="notes-scripts-glyph"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      {body[name]}
    </svg>
  );
};

export const formatWorkspaceTimestamp = (
  timestamp: number,
  locale: Locale = "zh-CN",
): string => {
  if (!Number.isFinite(timestamp)) return "";
  try {
    return new Intl.DateTimeFormat(locale, {
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    }).format(new Date(timestamp));
  } catch {
    return "";
  }
};

export type HostChecklistProps = {
  locale?: Locale;
  hosts: readonly NotesScriptsHost[];
  selectedIds: readonly string[];
  disabled?: boolean;
  allHosts?: boolean;
  onAllHostsChange?: (checked: boolean) => void;
  onToggle: (hostId: string, checked: boolean) => void;
};

export const HostChecklist = ({
  locale = "zh-CN",
  hosts,
  selectedIds,
  disabled = false,
  allHosts = false,
  onAllHostsChange,
  onToggle,
}: HostChecklistProps) => {
  const { t } = useI18n(locale);
  const [query, setQuery] = useState("");
  const selected = useMemo(() => new Set(selectedIds), [selectedIds]);
  const visibleHosts = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    if (!needle) return hosts;
    return hosts.filter((host) => [
      host.label,
      host.hostname,
      host.username ?? "",
      host.group ?? "",
    ].join(" ").toLocaleLowerCase().includes(needle));
  }, [hosts, query]);

  return (
    <fieldset className="notes-scripts-host-picker" disabled={disabled}>
      <div className="notes-scripts-field-heading">
        <span><WorkspaceGlyph name="host" />{t("notesScripts.hosts.linked")}</span>
        <span>{allHosts
          ? t("notesScripts.hosts.all")
          : t("notesScripts.hosts.selected", { count: selected.size })}</span>
      </div>

      {onAllHostsChange ? (
        <label className="notes-scripts-all-hosts">
          <input
            type="checkbox"
            checked={allHosts}
            onChange={(event) => onAllHostsChange(event.currentTarget.checked)}
          />
          <span>{t("notesScripts.hosts.applyAll")}</span>
        </label>
      ) : null}

      {hosts.length > 6 ? (
        <label className="notes-scripts-host-search">
          <WorkspaceGlyph name="search" />
          <input
            value={query}
            onChange={(event) => setQuery(event.currentTarget.value)}
            placeholder={t("notesScripts.hosts.filterPlaceholder")}
            aria-label={t("notesScripts.hosts.filterAria")}
          />
        </label>
      ) : null}

      <div className="notes-scripts-host-options" aria-label={t("notesScripts.hosts.selectionAria")}>
        {hosts.length === 0 ? (
          <p className="notes-scripts-host-empty">{t("notesScripts.hosts.noneSaved")}</p>
        ) : visibleHosts.length === 0 ? (
          <p className="notes-scripts-host-empty">{t("notesScripts.hosts.noneMatching")}</p>
        ) : visibleHosts.map((host) => (
          <label
            className={`notes-scripts-host-option${selected.has(host.id) ? " selected" : ""}`}
            key={host.id}
          >
            <input
              type="checkbox"
              checked={!allHosts && selected.has(host.id)}
              disabled={disabled || allHosts}
              onChange={(event) => onToggle(host.id, event.currentTarget.checked)}
            />
            <span className="notes-scripts-host-dot" aria-hidden="true" />
            <span className="notes-scripts-host-copy">
              <strong>{host.label || host.hostname}</strong>
              <small>{host.username ? `${host.username}@` : ""}{host.hostname}</small>
            </span>
            {host.group ? <span className="notes-scripts-host-group">{host.group}</span> : null}
          </label>
        ))}
      </div>
    </fieldset>
  );
};
