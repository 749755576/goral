import { useMemo, useState } from "react";

import type {
  SessionRestoreEntry,
  SessionRestoreSnapshot,
} from "./sessionRestore";
import { useI18n, type Locale } from "./i18n";
import type { WorkspaceSessionId } from "./terminalSessionRegistry";

export type SessionRestorePromptProps = Readonly<{
  snapshot: SessionRestoreSnapshot;
  locale: Locale;
  connectingId: WorkspaceSessionId | null;
  restoringSelected?: boolean;
  disabled?: boolean;
  error?: string | null;
  onReconnect: (entry: SessionRestoreEntry) => void;
  onRestoreSelected: (workspaceSessionIds: readonly WorkspaceSessionId[]) => void;
  onDiscard: () => void;
}>;

const supportsPresentationRestore = (entry: SessionRestoreEntry): boolean => (
  entry.protocol === "ssh" || entry.protocol === "local"
);

const targetDetail = (
  entry: SessionRestoreEntry,
  savedHostLabel: string,
  localTerminalLabel: string,
  serialConnectionLabel: string,
): string => {
  if (entry.target.kind === "quick") {
    return `${entry.target.hostname}:${entry.target.port}`;
  }
  if (entry.target.kind === "saved") return savedHostLabel;
  return entry.target.kind === "serial" ? serialConnectionLabel : localTerminalLabel;
};

/** Startup-only presentation. It never owns credentials or native sessions. */
export function SessionRestorePrompt({
  snapshot,
  locale,
  connectingId,
  restoringSelected = false,
  disabled = false,
  error,
  onReconnect,
  onRestoreSelected,
  onDiscard,
}: SessionRestorePromptProps) {
  const { t } = useI18n(locale);
  const presentationEntries = useMemo(
    () => snapshot.sessions.filter(supportsPresentationRestore),
    [snapshot.sessions],
  );
  const [selectedIds, setSelectedIds] = useState<ReadonlySet<WorkspaceSessionId>>(
    () => new Set(presentationEntries.map((entry) => entry.workspaceSessionId)),
  );
  const operationPending = restoringSelected || connectingId !== null;

  const toggleSelected = (workspaceSessionId: WorkspaceSessionId) => {
    if (disabled || operationPending) return;
    setSelectedIds((current) => {
      const next = new Set(current);
      if (next.has(workspaceSessionId)) next.delete(workspaceSessionId);
      else next.add(workspaceSessionId);
      return next;
    });
  };

  const restoreSelected = () => {
    const orderedIds = presentationEntries
      .map((entry) => entry.workspaceSessionId)
      .filter((workspaceSessionId) => selectedIds.has(workspaceSessionId));
    if (orderedIds.length > 0) onRestoreSelected(orderedIds);
  };

  return (
    <div className="dialog-backdrop session-restore-backdrop" role="presentation">
      <section
        className="trust-dialog session-restore-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="session-restore-title"
      >
        <p className="eyebrow">{t("restore.eyebrow")}</p>
        <h2 id="session-restore-title">{t("restore.title")}</h2>
        <p className="security-note">
          {t("restore.description")}
        </p>
        <ul className="session-restore-list">
          {snapshot.sessions.map((entry) => {
            const connecting = connectingId === entry.workspaceSessionId;
            const presentationRestore = supportsPresentationRestore(entry);
            const targetLabel = entry.target.kind === "serial"
              ? t("workspace.serial")
              : entry.target.label;
            const details = (
              <div>
                <strong>{targetLabel}</strong>
                <span>
                  {entry.protocol.toUpperCase()} · {targetDetail(
                    entry,
                    t("restore.savedHost"),
                    t("restore.localTerminal"),
                    t("restore.serialConnection"),
                  )}
                  {snapshot.activeSessionId === entry.workspaceSessionId
                    ? ` · ${t("restore.lastActive")}`
                    : ""}
                  {!presentationRestore ? ` · ${t("restore.singleOnly")}` : ""}
                </span>
              </div>
            );
            return (
              <li key={entry.workspaceSessionId}>
                {presentationRestore ? (
                  <label className="session-restore-select">
                    <input
                      type="checkbox"
                      checked={selectedIds.has(entry.workspaceSessionId)}
                      disabled={disabled || operationPending}
                      aria-label={t("restore.selectAria", { label: targetLabel })}
                      onChange={() => toggleSelected(entry.workspaceSessionId)}
                    />
                    {details}
                  </label>
                ) : (
                  <div className="session-restore-select">{details}</div>
                )}
                {!presentationRestore && (
                  <button
                    className="primary-button"
                    type="button"
                    disabled={disabled || operationPending}
                    onClick={() => onReconnect(entry)}
                  >
                    {connecting ? t("restore.preparing") : t("restore.reconnect")}
                  </button>
                )}
              </li>
            );
          })}
        </ul>
        {error && <p className="connection-error" role="alert">{error}</p>}
        <div className="dialog-actions">
          <button type="button" disabled={operationPending} onClick={onDiscard}>
            {t("restore.discard")}
          </button>
          {presentationEntries.length > 0 && (
            <button
              className="primary-button"
              type="button"
              disabled={disabled || operationPending || selectedIds.size === 0}
              onClick={restoreSelected}
            >
              {restoringSelected
                ? t("restore.restoringSelected")
                : t("restore.restoreSelected", { count: selectedIds.size })}
            </button>
          )}
        </div>
      </section>
    </div>
  );
}
