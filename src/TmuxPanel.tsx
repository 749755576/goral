import { useCallback, useEffect, useId, useRef, useState } from "react";

import {
  createTmuxSession,
  killTmuxSession,
  listTmuxSessions,
  renameTmuxSession,
  type TmuxSession,
} from "./backend";
import type { Locale, MessageKey, Translate } from "./i18n";

const MAX_TMUX_SESSION_NAME_BYTES = 64;
const FORBIDDEN_TMUX_NAME_CHARACTERS = /[\u0000-\u001f\u007f-\u009f:]/u;

type TmuxPanelProps = Readonly<{
  sessionId: string;
  locale: Locale;
  t: Translate;
}>;

type RenameDraft = Readonly<{
  name: string;
  newName: string;
}>;

const tmuxSessionNameIsValid = (name: string): boolean =>
  name.length > 0
  && !/^\s*$/u.test(name)
  && !FORBIDDEN_TMUX_NAME_CHARACTERS.test(name)
  && new TextEncoder().encode(name).byteLength <= MAX_TMUX_SESSION_NAME_BYTES;

const formatTmuxTimestamp = (
  epochSeconds: number | null,
  locale: Locale,
  t: Translate,
): string => {
  if (epochSeconds === null || !Number.isSafeInteger(epochSeconds) || epochSeconds <= 0) {
    return t("systemManager.tmux.notAvailable");
  }
  const date = new Date(epochSeconds * 1_000);
  if (!Number.isFinite(date.getTime())) return t("systemManager.tmux.notAvailable");
  return new Intl.DateTimeFormat(locale, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
};

export default function TmuxPanel({ sessionId, locale, t }: TmuxPanelProps) {
  const createInputId = useId();
  const createHintId = useId();
  const renameInputId = useId();
  const killDialogTitleId = useId();
  const killDialogDescriptionId = useId();
  const [sessions, setSessions] = useState<readonly TmuxSession[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [createName, setCreateName] = useState("");
  const [renameDraft, setRenameDraft] = useState<RenameDraft | null>(null);
  const [pendingKill, setPendingKill] = useState<TmuxSession | null>(null);

  const sessionGenerationRef = useRef(0);
  const viewSessionIdRef = useRef(sessionId);
  const refreshGenerationRef = useRef(0);
  const actionGenerationRef = useRef(0);

  const refresh = useCallback(async () => {
    const sessionGeneration = sessionGenerationRef.current;
    const refreshGeneration = ++refreshGenerationRef.current;
    const isCurrentRefresh = (): boolean =>
      sessionGenerationRef.current === sessionGeneration
      && refreshGenerationRef.current === refreshGeneration;
    setLoading(true);
    setError(null);
    try {
      const nextSessions = await listTmuxSessions(sessionId);
      if (isCurrentRefresh()) setSessions(nextSessions);
    } catch {
      if (isCurrentRefresh()) setError(t("systemManager.tmux.listFailed"));
    } finally {
      if (isCurrentRefresh()) setLoading(false);
    }
  }, [sessionId, t]);

  useEffect(() => {
    const sessionGeneration = ++sessionGenerationRef.current;
    viewSessionIdRef.current = sessionId;
    refreshGenerationRef.current += 1;
    actionGenerationRef.current += 1;
    setSessions([]);
    setLoading(false);
    setError(null);
    setBusy(null);
    setCreateName("");
    setRenameDraft(null);
    setPendingKill(null);
    void refresh();

    return () => {
      if (sessionGenerationRef.current === sessionGeneration) {
        sessionGenerationRef.current += 1;
      }
      refreshGenerationRef.current += 1;
      actionGenerationRef.current += 1;
    };
  }, [refresh, sessionId]);

  const runMutation = useCallback(async (
    busyKey: string,
    operation: () => Promise<void>,
    failureKey: MessageKey,
    onSuccess: () => void,
  ) => {
    const sessionGeneration = sessionGenerationRef.current;
    const actionGeneration = ++actionGenerationRef.current;
    refreshGenerationRef.current += 1;
    const isCurrentAction = (): boolean =>
      sessionGenerationRef.current === sessionGeneration
      && actionGenerationRef.current === actionGeneration;
    setLoading(false);
    setBusy(busyKey);
    setError(null);
    try {
      await operation();
      if (!isCurrentAction()) return;
      onSuccess();
      await refresh();
    } catch {
      if (isCurrentAction()) setError(t(failureKey));
    } finally {
      if (isCurrentAction()) setBusy(null);
    }
  }, [refresh, t]);

  const submitCreate = useCallback(() => {
    if (!tmuxSessionNameIsValid(createName)) {
      setError(t("systemManager.tmux.nameInvalid"));
      return;
    }
    void runMutation(
      "create",
      () => createTmuxSession(sessionId, createName),
      "systemManager.tmux.createFailed",
      () => setCreateName(""),
    );
  }, [createName, runMutation, sessionId, t]);

  const submitRename = useCallback(() => {
    if (!renameDraft) return;
    if (!tmuxSessionNameIsValid(renameDraft.newName)) {
      setError(t("systemManager.tmux.nameInvalid"));
      return;
    }
    if (renameDraft.newName === renameDraft.name) {
      setError(t("systemManager.tmux.renameUnchanged"));
      return;
    }
    const target = renameDraft;
    void runMutation(
      `rename:${target.name}`,
      () => renameTmuxSession(sessionId, target.name, target.newName),
      "systemManager.tmux.renameFailed",
      () => setRenameDraft(null),
    );
  }, [renameDraft, runMutation, sessionId, t]);

  const confirmKill = useCallback(() => {
    if (!pendingKill) return;
    const target = pendingKill;
    setPendingKill(null);
    void runMutation(
      `kill:${target.name}`,
      () => killTmuxSession(sessionId, target.name),
      "systemManager.tmux.killFailed",
      () => undefined,
    );
  }, [pendingKill, runMutation, sessionId]);

  const formatWindowCount = (count: number): string => t("systemManager.tmux.windowCount", {
    count: new Intl.NumberFormat(locale).format(count),
  });

  if (viewSessionIdRef.current !== sessionId) {
    return (
      <section className="system-manager-tmux" aria-label={t("systemManager.tmux.title")}>
        <div className="system-manager-empty" role="status">
          <p>{t("systemManager.refreshing")}</p>
        </div>
      </section>
    );
  }

  return (
    <section className="system-manager-tmux" aria-label={t("systemManager.tmux.title")}>
      <div className="system-manager-subheader">
        <span>{t("systemManager.rowCount", {
          count: new Intl.NumberFormat(locale).format(sessions.length),
        })}</span>
        <button
          type="button"
          className="system-manager-refresh"
          onClick={() => void refresh()}
          disabled={loading || busy !== null}
        >
          {loading ? t("systemManager.refreshing") : t("systemManager.refresh")}
        </button>
      </div>

      <form
        className="system-manager-tmux-create"
        onSubmit={(event) => {
          event.preventDefault();
          submitCreate();
        }}
      >
        <label htmlFor={createInputId}>{t("systemManager.tmux.createName")}</label>
        <div className="system-manager-tmux-input-row">
          <input
            id={createInputId}
            value={createName}
            maxLength={MAX_TMUX_SESSION_NAME_BYTES}
            autoComplete="off"
            spellCheck={false}
            aria-describedby={createHintId}
            placeholder={t("systemManager.tmux.namePlaceholder")}
            onChange={(event) => setCreateName(event.currentTarget.value)}
          />
          <button type="submit" disabled={busy !== null}>
            {busy === "create"
              ? t("systemManager.tmux.creating")
              : t("systemManager.tmux.create")}
          </button>
        </div>
        <small id={createHintId}>{t("systemManager.tmux.nameHint")}</small>
      </form>

      {error ? (
        <div className="system-manager-notice" role="status">
          <span>{error}</span>
        </div>
      ) : null}

      {sessions.length === 0 && !loading && !error ? (
        <div className="system-manager-empty">
          <h3>{t("systemManager.tmux.emptyTitle")}</h3>
          <p>{t("systemManager.tmux.emptyBody")}</p>
        </div>
      ) : null}

      <ul className="system-manager-list">
        {sessions.map((session) => {
          const isRenaming = renameDraft?.name === session.name;
          const sessionBusy = busy === `rename:${session.name}` || busy === `kill:${session.name}`;
          return (
            <li key={session.name} className="system-manager-card">
              <div className="system-manager-card-head">
                <span
                  className={`system-manager-state state-${session.attached ? "running" : "stopped"}`}
                  aria-hidden="true"
                />
                <strong title={session.name}>{session.name}</strong>
                <span className="system-manager-status">
                  {t(session.attached
                    ? "systemManager.tmux.attached"
                    : "systemManager.tmux.detached")}
                </span>
              </div>
              <div className="system-manager-meta">
                <span>{formatWindowCount(session.windows)}</span>
                <span>
                  {t("systemManager.tmux.created", {
                    value: formatTmuxTimestamp(session.created, locale, t),
                  })}
                </span>
                <span>
                  {t("systemManager.tmux.lastActivity", {
                    value: formatTmuxTimestamp(session.lastActivity, locale, t),
                  })}
                </span>
              </div>

              {isRenaming && renameDraft ? (
                <form
                  className="system-manager-tmux-rename"
                  onSubmit={(event) => {
                    event.preventDefault();
                    submitRename();
                  }}
                >
                  <label htmlFor={renameInputId}>{t("systemManager.tmux.newName")}</label>
                  <div className="system-manager-tmux-input-row">
                    <input
                      id={renameInputId}
                      value={renameDraft.newName}
                      maxLength={MAX_TMUX_SESSION_NAME_BYTES}
                      autoComplete="off"
                      spellCheck={false}
                      autoFocus
                      onChange={(event) => setRenameDraft({
                        name: renameDraft.name,
                        newName: event.currentTarget.value,
                      })}
                    />
                    <button type="button" onClick={() => setRenameDraft(null)}>
                      {t("connectionPrompt.common.cancel")}
                    </button>
                    <button type="submit" disabled={sessionBusy}>
                      {sessionBusy
                        ? t("systemManager.tmux.renaming")
                        : t("systemManager.tmux.saveRename")}
                    </button>
                  </div>
                </form>
              ) : (
                <div className="system-manager-actions">
                  <button
                    type="button"
                    disabled={busy !== null}
                    onClick={() => setRenameDraft({ name: session.name, newName: session.name })}
                  >
                    {t("systemManager.tmux.rename")}
                  </button>
                  <button
                    type="button"
                    className="is-destructive"
                    disabled={busy !== null}
                    onClick={() => setPendingKill(session)}
                  >
                    {t("systemManager.tmux.kill")}
                  </button>
                </div>
              )}
            </li>
          );
        })}
      </ul>

      {pendingKill ? (
        <div
          className="system-manager-confirm"
          role="alertdialog"
          aria-modal="true"
          aria-labelledby={killDialogTitleId}
          aria-describedby={killDialogDescriptionId}
        >
          <div className="system-manager-confirm-card">
            <h3 id={killDialogTitleId}>{t("systemManager.tmux.confirmKillTitle")}</h3>
            <p id={killDialogDescriptionId}>
              {t("systemManager.tmux.confirmKillBody", { name: pendingKill.name })}
            </p>
            <div className="system-manager-confirm-actions">
              <button type="button" onClick={() => setPendingKill(null)}>
                {t("connectionPrompt.common.cancel")}
              </button>
              <button type="button" className="is-destructive" onClick={confirmKill}>
                {t("systemManager.tmux.kill")}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}
