import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { readSftpFile, replaceSftpFileIfUnchanged } from "./backend";
import type { Translate } from "./i18n";
import {
  closeAfterSuccessfulRemoteEditorSave,
  encodeRemoteEditorText,
  hasUtf8Bom,
  persistRemoteEditorDraft,
  type RemoteEditorSaveResult,
} from "./remoteEditorSave";
import "./remoteEditor.css";

/**
 * A remote text editor over the session's existing SFTP channel.
 *
 * Scoped deliberately narrowly: open one file, edit it, save it back. It is
 * for the edit a person actually does over SSH — a config line, a unit file,
 * a compose file — not a replacement for their editor.
 *
 * Three properties matter more than features here, because every one of them
 * corresponds to a way this kind of tool loses someone's work:
 *
 *  - A file that is not text is refused rather than opened. Loading a binary
 *    into a textarea and saving it back would silently corrupt it, because
 *    the round trip through UTF-8 is lossy.
 *  - Saving writes what was loaded plus what was typed, and the editor never
 *    re-reads underneath the user. If the remote file changed since it was
 *    opened, the save is refused rather than silently overwriting.
 *  - Closing with unsaved changes asks first.
 */

type RemoteEditorProps = Readonly<{
  sessionId: string;
  path: string;
  t: Translate;
  onClose: () => void;
}>;

/** Files above this are refused: a textarea is not a viable editor for them. */
const MAX_EDITABLE_BYTES = 2 * 1024 * 1024;

/**
 * Whether a byte range is plausibly UTF-8 text.
 *
 * A NUL byte is the reliable tell for binary content — no valid UTF-8 text
 * file contains one — and a failed strict decode catches the rest. Guessing
 * by file extension would be worse: the files people edit over SSH routinely
 * have no extension at all.
 */
const looksLikeText = (bytes: Uint8Array): boolean => {
  if (bytes.includes(0)) return false;
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return true;
  } catch {
    return false;
  }
};

type LoadState =
  | { kind: "loading" }
  | {
      kind: "ready";
      original: string;
      originalBytes: Uint8Array;
      preserveUtf8Bom: boolean;
    }
  | { kind: "refused"; reason: string }
  | { kind: "failed"; reason: string };

// SFTP/server prose is backend-controlled and can expose untranslated or
// host-specific details. The renderer owns the user-facing failure message.
const readableError = (_error: unknown, fallback: string): string => fallback;

export default function RemoteEditor({ sessionId, path, t, onClose }: RemoteEditorProps) {
  const [state, setState] = useState<LoadState>({ kind: "loading" });
  const [draft, setDraft] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [confirmingClose, setConfirmingClose] = useState(false);

  // A reply for a file the user has already navigated away from must not
  // replace what is on screen.
  const generationRef = useRef(0);
  // React state updates are not synchronous. The ref closes the double-click
  // window in which two saves could otherwise both start.
  const savingRef = useRef(false);

  useEffect(() => {
    const generation = ++generationRef.current;
    setState({ kind: "loading" });
    setSaveError(null);
    setConfirmingClose(false);

    void (async () => {
      try {
        const bytes = await readSftpFile(sessionId, path);
        if (generationRef.current !== generation) return;

        if (bytes.length > MAX_EDITABLE_BYTES) {
          setState({ kind: "refused", reason: t("editor.tooLarge") });
          return;
        }
        if (!looksLikeText(bytes)) {
          // Refusing is the whole point: opening this and saving it back
          // would corrupt the file without ever showing an error.
          setState({ kind: "refused", reason: t("editor.notText") });
          return;
        }

        const text = new TextDecoder("utf-8").decode(bytes);
        setState({
          kind: "ready",
          original: text,
          originalBytes: bytes,
          preserveUtf8Bom: hasUtf8Bom(bytes),
        });
        setDraft(text);
      } catch (cause) {
        if (generationRef.current !== generation) return;
        setState({ kind: "failed", reason: readableError(cause, t("editor.openFailed")) });
      }
    })();
  }, [path, sessionId, t]);

  const dirty = state.kind === "ready" && draft !== state.original;

  const save = useCallback(async (): Promise<RemoteEditorSaveResult> => {
    if (state.kind !== "ready") return { kind: "stale" };
    if (savingRef.current) return { kind: "busy" };
    savingRef.current = true;
    setSaving(true);
    setSaveError(null);
    const generation = generationRef.current;
    const originalBytes = state.originalBytes;
    const preserveUtf8Bom = state.preserveUtf8Bom;
    const nextDraft = draft;
    const nextBytes = encodeRemoteEditorText(nextDraft, preserveUtf8Bom);
    try {
      // Native code performs the exact before/after conflict checks and
      // publishes from a recoverable staging path; this call never truncates
      // the destination in place.
      const result = await persistRemoteEditorDraft(() => replaceSftpFileIfUnchanged(
        sessionId,
        path,
        originalBytes,
        nextBytes,
      ));
      if (generationRef.current !== generation) return { kind: "stale" };

      if (result.kind === "conflict") {
        setSaveError(t("editor.changedOnDisk"));
      } else if (result.kind === "failed") {
        setSaveError(t("editor.saveFailed"));
      } else if (result.kind === "saved") {
        setState({
          kind: "ready",
          original: nextDraft,
          originalBytes: nextBytes,
          preserveUtf8Bom,
        });
      }
      return result;
    } finally {
      savingRef.current = false;
      if (generationRef.current === generation) setSaving(false);
    }
  }, [draft, path, sessionId, state, t]);

  const requestClose = useCallback(() => {
    if (savingRef.current) return;
    if (dirty) {
      setConfirmingClose(true);
      return;
    }
    onClose();
  }, [dirty, onClose]);

  // Ctrl/Cmd+S is the reflex for anyone who has ever used an editor; not
  // honouring it here would cost someone their work.
  const onKeyDown = useCallback(
    (event: React.KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s") {
        event.preventDefault();
        void save();
      }
    },
    [save],
  );

  const fileName = useMemo(() => path.split("/").filter(Boolean).pop() ?? path, [path]);

  return (
    <div className="remote-editor" onKeyDown={onKeyDown}>
      <header className="remote-editor-header">
        <div className="remote-editor-identity">
          <strong title={path}>
            {fileName}
            {dirty ? <span className="remote-editor-dirty" aria-hidden="true"> •</span> : null}
          </strong>
          <small title={path}>{path}</small>
        </div>
        <div className="remote-editor-actions">
          <button type="button" onClick={() => void save()} disabled={!dirty || saving}>
            {saving ? t("editor.saving") : t("editor.save")}
          </button>
          <button type="button" onClick={requestClose} disabled={saving}>
            {t("editor.close")}
          </button>
        </div>
      </header>

      {saveError ? (
        <div className="remote-editor-notice" role="status">
          <span>{saveError}</span>
        </div>
      ) : null}

      {state.kind === "loading" ? (
        <div className="remote-editor-empty">
          <p>{t("editor.loading")}</p>
        </div>
      ) : null}

      {state.kind === "refused" || state.kind === "failed" ? (
        <div className="remote-editor-empty">
          <h3>{t("editor.cannotEdit")}</h3>
          <p>{state.reason}</p>
        </div>
      ) : null}

      {state.kind === "ready" ? (
        <textarea
          className="remote-editor-input"
          value={draft}
          spellCheck={false}
          autoCorrect="off"
          autoCapitalize="off"
          aria-label={t("editor.contentLabel", { name: fileName })}
          onChange={(event) => setDraft(event.target.value)}
        />
      ) : null}

      {confirmingClose ? (
        <div className="remote-editor-confirm" role="alertdialog" aria-modal="true">
          <div className="remote-editor-confirm-card">
            <h3>{t("editor.confirmCloseTitle")}</h3>
            <p>{t("editor.confirmCloseBody", { name: fileName })}</p>
            <div className="remote-editor-confirm-actions">
              <button
                type="button"
                disabled={saving}
                onClick={() => setConfirmingClose(false)}
              >
                {t("connectionPrompt.common.cancel")}
              </button>
              <button
                type="button"
                disabled={saving}
                onClick={() => {
                  void closeAfterSuccessfulRemoteEditorSave(save, () => {
                    setConfirmingClose(false);
                    onClose();
                  });
                }}
              >
                {saving ? t("editor.saving") : t("editor.saveAndClose")}
              </button>
              <button
                type="button"
                className="is-destructive"
                disabled={saving}
                onClick={() => {
                  if (savingRef.current) return;
                  setConfirmingClose(false);
                  onClose();
                }}
              >
                {t("editor.discard")}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
