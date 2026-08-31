import { open } from "@tauri-apps/plugin-dialog";
import { type FormEvent, useCallback, useEffect, useId, useMemo, useRef, useState } from "react";

import {
  listLocalShells,
  type DiscoveredLocalShell,
} from "./backend";
import { useI18n, type Locale, type Translate } from "./i18n";
import "./localTerminal.css";

export type LocalTerminalSubmission = {
  shellId: string;
  cwd?: string;
  shell: DiscoveredLocalShell;
};

type LocalTerminalPanelProps = {
  locale?: Locale;
  disabled?: boolean;
  initialCwd?: string;
  shellSource?: () => Promise<DiscoveredLocalShell[]>;
  onCancel: () => void;
  onConnect: (submission: LocalTerminalSubmission) => void | Promise<void>;
};

const fixedFailure = (
  t: Translate,
  operation: "read" | "chooseDirectory" | "open",
): string => t(operation === "read"
  ? "localTerminal.readShellsFailed"
  : operation === "chooseDirectory"
    ? "localTerminal.chooseDirectoryFailed"
    : "localTerminal.openFailed");

const TerminalGlyph = () => (
  <svg
    aria-hidden="true"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <rect x="3" y="4" width="18" height="16" rx="2" />
    <path d="m7 9 3 3-3 3m5 0h5" />
  </svg>
);

export function LocalTerminalPanel({
  locale = "zh-CN",
  disabled = false,
  initialCwd = "",
  shellSource = listLocalShells,
  onCancel,
  onConnect,
}: LocalTerminalPanelProps) {
  const { t } = useI18n(locale);
  const id = useId().replaceAll(":", "");
  const mounted = useRef(true);
  const requestSequence = useRef(0);
  const [shells, setShells] = useState<DiscoveredLocalShell[]>([]);
  const [shellId, setShellId] = useState("");
  const [cwd, setCwd] = useState(initialCwd);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const sequence = ++requestSequence.current;
    setLoading(true);
    setError(null);
    try {
      const result = await shellSource();
      if (!mounted.current || sequence !== requestSequence.current) return;
      setShells(result);
      setShellId((current) => {
        if (result.some((shell) => shell.id === current)) return current;
        return result.find((shell) => shell.isDefault)?.id ?? result[0]?.id ?? "";
      });
      if (result.length === 0) setError(t("localTerminal.noShells"));
    } catch {
      if (mounted.current && sequence === requestSequence.current) {
        setError(fixedFailure(t, "read"));
      }
    } finally {
      if (mounted.current && sequence === requestSequence.current) setLoading(false);
    }
  }, [shellSource, t]);

  useEffect(() => {
    mounted.current = true;
    void refresh();
    return () => {
      mounted.current = false;
      requestSequence.current += 1;
    };
  }, [refresh]);

  const selectedShell = useMemo(
    () => shells.find((shell) => shell.id === shellId) ?? null,
    [shellId, shells],
  );

  const chooseDirectory = async () => {
    if (disabled || submitting) return;
    setError(null);
    try {
      const selected = await open({
        directory: true,
        multiple: false,
        title: t("localTerminal.chooseDirectory"),
      });
      if (typeof selected === "string") setCwd(selected);
    } catch {
      setError(fixedFailure(t, "chooseDirectory"));
    }
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedShell || disabled || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      const normalizedCwd = cwd.trim();
      await onConnect({
        shellId: selectedShell.id,
        shell: selectedShell,
        ...(normalizedCwd ? { cwd: normalizedCwd } : {}),
      });
    } catch {
      if (mounted.current) setError(fixedFailure(t, "open"));
    } finally {
      if (mounted.current) setSubmitting(false);
    }
  };

  const formDisabled = disabled || submitting;

  return (
    <section className="local-terminal-panel" aria-labelledby={`${id}-title`}>
      <header className="local-terminal-header">
        <span className="local-terminal-icon"><TerminalGlyph /></span>
        <span>
          <strong id={`${id}-title`}>{t("localTerminal.title")}</strong>
          <small>{t("localTerminal.description")}</small>
        </span>
        <button
          type="button"
          className="local-terminal-close"
          aria-label={t("localTerminal.closePanel")}
          disabled={submitting}
          onClick={onCancel}
        >
          ×
        </button>
      </header>

      {error && <div className="local-terminal-message" role="alert">{error}</div>}

      <form className="local-terminal-form" onSubmit={submit}>
        <div className="local-terminal-scroll">
          <label htmlFor={`${id}-shell`}>
            <span>{t("localTerminal.shellLabel")}</span>
            <select
              id={`${id}-shell`}
              value={shellId}
              disabled={formDisabled || loading || shells.length === 0}
              onChange={(event) => setShellId(event.target.value)}
            >
              {loading && <option value="">{t("localTerminal.discovering")}</option>}
              {!loading && shells.length === 0 && <option value="">{t("localTerminal.noShellOption")}</option>}
              {shells.map((shell) => (
                <option key={shell.id} value={shell.id}>
                  {shell.name}{shell.isDefault ? t("localTerminal.defaultSuffix") : ""}
                </option>
              ))}
            </select>
          </label>

          {selectedShell && (
            <div className="local-shell-preview" aria-label={t("localTerminal.shellDetails")}>
              <span className="local-shell-preview-icon"><TerminalGlyph /></span>
              <span>
                <strong>{selectedShell.name}</strong>
                <small title={[selectedShell.command, ...selectedShell.args].join(" ")}>
                  {[selectedShell.command, ...selectedShell.args].join(" ")}
                </small>
              </span>
            </div>
          )}

          <label htmlFor={`${id}-cwd`}>
            <span>{t("localTerminal.startDirectory")}</span>
            <small>{t("localTerminal.startDirectoryHint")}</small>
            <span className="local-cwd-row">
              <input
                id={`${id}-cwd`}
                value={cwd}
                disabled={formDisabled}
                placeholder={t("localTerminal.homeDirectory")}
                spellCheck={false}
                onChange={(event) => setCwd(event.target.value)}
              />
              <button type="button" disabled={formDisabled} onClick={() => void chooseDirectory()}>
                {t("localTerminal.browse")}
              </button>
            </span>
          </label>

          <button
            type="button"
            className="local-shell-refresh"
            disabled={formDisabled || loading}
            onClick={() => void refresh()}
          >
            {loading ? t("localTerminal.refreshing") : t("localTerminal.rediscover")}
          </button>
        </div>

        <footer>
          <button type="button" disabled={submitting} onClick={onCancel}>{t("localTerminal.cancel")}</button>
          <button
            type="submit"
            className="local-terminal-primary"
            disabled={formDisabled || loading || !selectedShell}
          >
            <TerminalGlyph />
            {submitting ? t("localTerminal.starting") : t("localTerminal.open")}
          </button>
        </footer>
      </form>
    </section>
  );
}

export default LocalTerminalPanel;
