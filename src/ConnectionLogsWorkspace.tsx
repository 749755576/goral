import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import type { WebglAddon } from "@xterm/addon-webgl";
import { isTauri } from "@tauri-apps/api/core";
import "@xterm/xterm/css/xterm.css";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type MouseEvent,
} from "react";

import {
  classifyConnectionLogReplayError,
  classifyConnectionLogsError,
  exportConnectionLog,
  listConnectionLogs,
  readConnectionLogReplay,
  replaceConnectionLogs,
  type ConnectionLogsCatalog,
  type SavedConnectionLog,
  type SavedConnectionLogIconColorId,
  type SavedConnectionLogIconId,
} from "./connectionLogsApi";
import { createTranslator, useI18n, type Locale, type Translate } from "./i18n";
import { SETTINGS_ADAPTER } from "./settingsApi";
import { createDefaultRendererSafeSettings } from "./settingsUi";
import {
  applyResolvedTerminalAppearance,
  installPreferredWebglAddon,
  resolveTerminalAppearance,
  shouldAttemptWebgl,
  type TerminalSettings,
} from "./terminalAppearance";
import "./connectionLogs.css";

export type ConnectionLogsWorkspaceApi = {
  exportLog: typeof exportConnectionLog;
  list: typeof listConnectionLogs;
  readReplay: typeof readConnectionLogReplay;
  replace: typeof replaceConnectionLogs;
};

export type ConnectionLogsWorkspaceProps = {
  disabled?: boolean;
  refreshKey?: string | number;
  api?: ConnectionLogsWorkspaceApi;
  locale?: Locale;
  onCatalogChange?: (catalog: ConnectionLogsCatalog) => void;
};

type ConnectionLogGlyphName =
  | SavedConnectionLogIconId
  | "bookmark"
  | "chevron-down"
  | "close"
  | "download"
  | "history"
  | "refresh"
  | "trash"
  | "usb"
  | "user";

type CatalogMutation = (logs: readonly SavedConnectionLog[]) => SavedConnectionLog[];
type ReplayViewState =
  | { logId: string; status: "loading" }
  | { logId: string; status: "ready"; terminalData: string }
  | { logId: string; status: "error"; message: string };

const EMPTY_CATALOG: ConnectionLogsCatalog = {
  inventoryRevision: null,
  logs: [],
};

const DEFAULT_API: ConnectionLogsWorkspaceApi = {
  exportLog: exportConnectionLog,
  list: listConnectionLogs,
  readReplay: readConnectionLogReplay,
  replace: replaceConnectionLogs,
};

export const CONNECTION_LOGS_PAGE_SIZE = 30;
export const CONNECTION_LOG_REPLAY_MAX_BYTES = 1_000_000;

const GLYPH_PATHS: Record<ConnectionLogGlyphName, string[]> = {
  activity: ["M4 13h4l2-7 4 12 2-5h4"],
  bookmark: ["M6 4h12v17l-6-4-6 4z"],
  box: ["m4 7 8-4 8 4-8 4zM4 7v10l8 4 8-4V7M12 11v10"],
  "chevron-down": ["m7 10 5 5 5-5"],
  close: ["M6 6l12 12M18 6 6 18"],
  cloud: ["M7 18h11a4 4 0 0 0 .5-8 7 7 0 0 0-13.4 2A3 3 0 0 0 7 18Z"],
  code: ["m9 18-6-6 6-6M15 6l6 6-6 6"],
  container: ["M4 7h16v11H4zM4 11h16M8 7v11M12 7v11M16 7v11"],
  cpu: ["M8 8h8v8H8zM9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"],
  database: ["M4 6c0-2 3.6-3 8-3s8 1 8 3-3.6 3-8 3-8-1-8-3ZM4 6v6c0 2 3.6 3 8 3s8-1 8-3V6M4 12v6c0 2 3.6 3 8 3s8-1 8-3v-6"],
  download: ["M12 3v12M7 10l5 5 5-5M4 20h16"],
  globe: ["M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18ZM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"],
  "hard-drive": ["M4 5h16l2 6v7H2v-7zM2 11h20M17 15h.01M13 15h.01"],
  history: ["M4 12a8 8 0 1 0 2.3-5.7M4 4v8h8M12 8v5l3 2"],
  key: ["M15 8a5 5 0 1 1-2 4l-8 8H2v-3l7-7M6 16l2 2"],
  lock: ["M6 10h12v11H6zM8 10V7a4 4 0 0 1 8 0v3"],
  monitor: ["M3 4h18v13H3zM8 21h8M12 17v4"],
  network: ["M12 4v5M5 20v-5h14v5M5 15v-3h14v3M2 20h6M9 4h6M16 20h6"],
  refresh: ["M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7"],
  router: ["M4 12h16v7H4zM8 16h.01M12 16h.01M9 8a4 4 0 0 1 6 0M6 5a8 8 0 0 1 12 0"],
  server: ["M4 4h16v7H4zM4 14h16v6H4zM8 7h.01M8 17h.01M12 7h5M12 17h5"],
  "server-cog": ["M3 4h14v7H3zM3 14h9v6H3zM7 7h.01M7 17h.01M18 14v2M18 20v2M14 18h2M20 18h2M15.2 15.2l1.4 1.4M19.4 19.4l1.4 1.4M20.8 15.2l-1.4 1.4M16.6 19.4l-1.4 1.4"],
  shield: ["M12 3 4.5 6v5.5c0 4.8 3.1 8.2 7.5 9.5 4.4-1.3 7.5-4.7 7.5-9.5V6zM9 12l2 2 4-5"],
  terminal: ["M4 5h16v14H4zM7 9l3 3-3 3M12 15h5"],
  trash: ["M4 7h16M9 7V4h6v3M7 7l1 14h8l1-14M10 11v6M14 11v6"],
  usb: ["M12 3v13M9 6l3-3 3 3M12 12l-4-4M8 8H5v3M12 15l4-4M16 11h3v3M12 16a3 3 0 1 1-3 3"],
  user: ["M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8ZM4 21a8 8 0 0 1 16 0"],
  wifi: ["M3 9a14 14 0 0 1 18 0M6 13a9 9 0 0 1 12 0M9.5 17a4 4 0 0 1 5 0M12 21h.01"],
  zap: ["m13 2-9 12h8l-1 8 9-12h-8z"],
};

const HOST_ICON_COLORS: Record<SavedConnectionLogIconColorId, string> = {
  amber: "#b45309",
  blue: "#2563eb",
  cyan: "#0891b2",
  green: "#16a34a",
  indigo: "#4f46e5",
  lime: "#65a30d",
  orange: "#ea580c",
  pink: "#db2777",
  purple: "#9333ea",
  red: "#dc2626",
  rose: "#e11d48",
  sky: "#0284c7",
  slate: "#475569",
  teal: "#0d9488",
  violet: "#7c3aed",
  zinc: "#52525b",
};

const HOST_ICON_DEFAULT_COLORS: Record<SavedConnectionLogIconId, SavedConnectionLogIconColorId> = {
  activity: "red",
  box: "amber",
  cloud: "sky",
  code: "violet",
  container: "teal",
  cpu: "indigo",
  database: "cyan",
  globe: "teal",
  "hard-drive": "zinc",
  key: "amber",
  lock: "rose",
  monitor: "sky",
  network: "lime",
  router: "orange",
  server: "blue",
  "server-cog": "slate",
  shield: "green",
  terminal: "slate",
  wifi: "purple",
  zap: "orange",
};

const ConnectionLogGlyph = ({ name }: { name: ConnectionLogGlyphName }) => (
  <svg
    aria-hidden="true"
    className="connection-log-glyph"
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

const sameLogReferences = (
  left: readonly SavedConnectionLog[],
  right: readonly SavedConnectionLog[],
): boolean => left.length === right.length && left.every((log, index) => log === right[index]);

export const sortConnectionLogsNewestFirst = (
  logs: readonly SavedConnectionLog[],
): SavedConnectionLog[] => [...logs].sort((left, right) => {
  if (left.startTime !== right.startTime) return right.startTime > left.startTime ? 1 : -1;
  return left.id.localeCompare(right.id);
});

const validDate = (timestamp: number): Date | null => {
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? null : date;
};

export const formatConnectionLogDate = (
  timestamp: number,
  locale: Locale = "zh-CN",
  t: Translate = createTranslator(locale),
): string => {
  const date = validDate(timestamp);
  return date
    ? date.toLocaleDateString(locale, { year: "numeric", month: "short", day: "numeric" })
    : t("connectionLogs.unknownDate");
};

export const formatConnectionLogTimeRange = (
  startTime: number,
  endTime?: number,
  locale: Locale = "zh-CN",
  t: Translate = createTranslator(locale),
): string => {
  const start = validDate(startTime);
  if (!start) return t("connectionLogs.unknownTime");
  const format = (date: Date) => date.toLocaleTimeString(locale, {
    hour: "2-digit",
    minute: "2-digit",
  });
  const end = endTime === undefined ? null : validDate(endTime);
  return `${format(start)} - ${end ? format(end) : t("connectionLogs.ongoing")}`;
};

const safeMetadataText = (value: string): string =>
  value.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ").slice(0, 4_096);

const validateReplayPayload = (value: unknown, expectedLogId: string): string | null => {
  if (!value || typeof value !== "object") return null;
  const candidate = value as { logId?: unknown; terminalData?: unknown };
  if (candidate.logId !== expectedLogId || typeof candidate.terminalData !== "string") return null;
  if (candidate.terminalData.length > CONNECTION_LOG_REPLAY_MAX_BYTES) return null;
  if (new TextEncoder().encode(candidate.terminalData).byteLength > CONNECTION_LOG_REPLAY_MAX_BYTES) {
    return null;
  }
  return candidate.terminalData;
};

const resolveSnapshotColor = (log: SavedConnectionLog): string => {
  if (
    log.hostIconColorMode !== "auto"
    && log.hostIconColorCustom
    && /^#[0-9a-f]{6}$/i.test(log.hostIconColorCustom)
  ) {
    return log.hostIconColorCustom;
  }
  if (log.hostIconColorMode !== "auto" && log.hostIconColor) {
    return HOST_ICON_COLORS[log.hostIconColor];
  }
  return HOST_ICON_COLORS[HOST_ICON_DEFAULT_COLORS[log.hostIconId ?? "server"]];
};

const ConnectionTargetIcon = ({ log }: { log: SavedConnectionLog }) => {
  const local = log.protocol === "local" || log.hostname.toLowerCase() === "localhost";
  if (local) {
    return <span className="connection-log-target-icon local"><ConnectionLogGlyph name="terminal" /></span>;
  }
  if (log.protocol === "serial") {
    return <span className="connection-log-target-icon serial"><ConnectionLogGlyph name="usb" /></span>;
  }
  if (log.hostIconMode === "custom" && log.hostIconId) {
    return (
      <span
        className="connection-log-target-icon host snapshot"
        data-icon-id={log.hostIconId}
        style={{ "--connection-log-icon-color": resolveSnapshotColor(log) } as CSSProperties}
      >
        <ConnectionLogGlyph name={log.hostIconId} />
      </span>
    );
  }
  if (log.hostDistro) {
    return (
      <span
        className="connection-log-target-icon host distro"
        data-host-distro={log.hostDistro}
        title={log.hostDistro}
      >
        {safeMetadataText(log.hostDistro).slice(0, 2).toUpperCase()}
      </span>
    );
  }
  return <span className="connection-log-target-icon host"><ConnectionLogGlyph name="server" /></span>;
};

const ReplayWorkspace = ({
  appColorMode,
  disabled,
  exporting,
  locale,
  log,
  mutationPending,
  onClose,
  onExport,
  onFontSizeChange,
  onRetry,
  replay,
  terminalSettings,
}: {
  appColorMode: "light" | "dark";
  disabled: boolean;
  exporting: boolean;
  locale: Locale;
  log: SavedConnectionLog;
  mutationPending: boolean;
  onClose: () => void;
  onExport: () => void;
  onFontSizeChange: (fontSize: number | undefined) => void;
  onRetry: () => void;
  replay: ReplayViewState;
  terminalSettings: TerminalSettings;
}) => {
  const { t } = useI18n(locale);
  const terminalElement = useRef<HTMLDivElement | null>(null);
  const terminal = useRef<Terminal | null>(null);
  const fitAddon = useRef<FitAddon | null>(null);
  const webglAddon = useRef<WebglAddon | null>(null);
  const webglLoadGeneration = useRef(0);
  const appearance = useMemo(
    () => resolveTerminalAppearance(terminalSettings, {
      appColorMode,
      themeId: log.themeId,
      fontSize: log.fontSize,
    }),
    [appColorMode, log.fontSize, log.themeId, terminalSettings],
  );
  const appearanceRef = useRef(appearance);
  appearanceRef.current = appearance;
  const fontSize = appearance.xtermOptions.fontSize;
  const formattedDate = useMemo(
    () => validDate(log.startTime)?.toLocaleString(locale) ?? t("connectionLogs.unknownDate"),
    [locale, log.startTime, t],
  );
  const replayData = replay.status === "ready" ? replay.terminalData : null;

  const fit = useCallback(() => {
    try {
      fitAddon.current?.fit();
    } catch {
      // A hidden or zero-sized panel cannot be fitted yet.
    }
  }, []);

  useEffect(() => {
    const element = terminalElement.current;
    if (!element || replayData === null) return;
    const initialAppearance = appearanceRef.current;
    const instance = new Terminal({
      convertEol: false,
      disableStdin: true,
      ...initialAppearance.xtermOptions,
      cursorBlink: false,
    });
    const fitter = new FitAddon();
    instance.loadAddon(fitter);
    instance.open(element);
    terminal.current = instance;
    fitAddon.current = fitter;

    if (replayData.length > 0) {
      instance.write(replayData);
    } else {
      instance.writeln(`\x1b[2m${t("connectionLogs.replay.emptyTerminal")}\x1b[0m`);
      instance.writeln("");
      instance.writeln(`\x1b[36m${t("connectionLogs.replay.hostPrefix")}\x1b[0m${safeMetadataText(log.hostname)}`);
      instance.writeln(`\x1b[36m${t("connectionLogs.replay.userPrefix")}\x1b[0m${safeMetadataText(log.username)}`);
      instance.writeln(`\x1b[36m${t("connectionLogs.replay.protocolPrefix")}\x1b[0m${log.protocol}`);
      instance.writeln(`\x1b[36m${t("connectionLogs.replay.timePrefix")}\x1b[0m${safeMetadataText(formattedDate)}`);
      if (log.endTime !== undefined) {
        const seconds = Math.max(0, Math.round((log.endTime - log.startTime) / 1_000));
        instance.writeln(
          `\x1b[36m${t("connectionLogs.replay.durationPrefix")}\x1b[0m${t("connectionLogs.replay.durationValue", {
            minutes: Math.floor(seconds / 60),
            seconds: seconds % 60,
          })}`,
        );
      }
    }

    const fitTimer = window.setTimeout(fit, 0);
    const observer = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(fit);
    observer?.observe(element);
    return () => {
      window.clearTimeout(fitTimer);
      observer?.disconnect();
      webglLoadGeneration.current += 1;
      instance.dispose();
      terminal.current = null;
      fitAddon.current = null;
      webglAddon.current = null;
    };
  }, [fit, formattedDate, log.endTime, log.hostname, log.id, log.protocol, log.startTime, log.username, replayData, t]);

  useEffect(() => {
    const instance = terminal.current;
    if (!instance) return;
    const generation = ++webglLoadGeneration.current;
    applyResolvedTerminalAppearance(instance, appearance);
    instance.options.cursorBlink = false;
    if (shouldAttemptWebgl(appearance.renderer)) {
      if (!webglAddon.current) {
        void installPreferredWebglAddon(
          instance,
          appearance.renderer,
          () => terminal.current === instance && webglLoadGeneration.current === generation,
        ).then((addon) => {
          if (!addon) return;
          if (terminal.current === instance && webglLoadGeneration.current === generation) {
            webglAddon.current = addon as WebglAddon;
          } else {
            addon.dispose();
          }
        });
      }
    } else if (webglAddon.current) {
      webglAddon.current.dispose();
      webglAddon.current = null;
    }
    const fitTimer = window.setTimeout(fit, 0);
    return () => window.clearTimeout(fitTimer);
  }, [appearance, fit]);

  const local = log.protocol === "local" || log.hostname.toLowerCase() === "localhost";
  return (
    <section
      className="connection-log-replay"
      aria-label={t("connectionLogs.replay.workspace")}
      data-terminal-theme={appearance.themeId}
      style={{ backgroundColor: appearance.background }}
    >
      <header className="connection-log-replay-header">
        <div className="connection-log-replay-title">
          <span><ConnectionLogGlyph name="history" /></span>
          <div>
            <strong>{local ? t("connectionLogs.localTerminal") : log.hostname}</strong>
            <small>{formattedDate} · {log.localUsername}@{log.localHostname}</small>
          </div>
        </div>
        <div className="connection-log-replay-actions" role="toolbar" aria-label={t("connectionLogs.replay.controls")}>
          {replay.status === "ready" && replay.terminalData.length > 0 ? (
            <button
              type="button"
              className="connection-log-replay-export"
              aria-label={t("connectionLogs.replay.exportAria")}
              title={t("connectionLogs.replay.export")}
              disabled={disabled || exporting}
              onClick={onExport}
            >
              <ConnectionLogGlyph name="download" />
              {t("connectionLogs.replay.export")}
            </button>
          ) : null}
          <button
            type="button"
            aria-label={t("connectionLogs.replay.decreaseFont")}
            title={t("connectionLogs.replay.decreaseFont")}
            disabled={disabled || mutationPending || fontSize <= 4}
            onClick={() => onFontSizeChange(fontSize - 1)}
          >A−</button>
          <button
            type="button"
            aria-label={t("connectionLogs.replay.resetFont")}
            title={t("connectionLogs.replay.resetFont")}
            disabled={disabled || mutationPending || log.fontSize === undefined}
            onClick={() => onFontSizeChange(undefined)}
          >{fontSize}px</button>
          <button
            type="button"
            aria-label={t("connectionLogs.replay.increaseFont")}
            title={t("connectionLogs.replay.increaseFont")}
            disabled={disabled || mutationPending || fontSize >= 256}
            onClick={() => onFontSizeChange(fontSize + 1)}
          >A+</button>
          <span>{t("connectionLogs.replay.readOnly")}</span>
          <button
            type="button"
            aria-label={t("connectionLogs.replay.close")}
            title={t("connectionLogs.replay.close")}
            onClick={onClose}
          >
            <ConnectionLogGlyph name="close" />
          </button>
        </div>
      </header>
      {replay.status === "loading" ? (
        <div className="connection-log-replay-state" role="status">
          <span className="connection-log-replay-spinner" aria-hidden="true" />
          <strong>{t("connectionLogs.replay.loading")}</strong>
        </div>
      ) : replay.status === "error" ? (
        <div className="connection-log-replay-state error" role="alert">
          <span><ConnectionLogGlyph name="history" /></span>
          <strong>{t("connectionLogs.replay.openFailed")}</strong>
          <p>{replay.message}</p>
          <button type="button" onClick={onRetry}>{t("connectionLogs.replay.tryAgain")}</button>
        </div>
      ) : (
        <>
          {replay.terminalData.length === 0 ? (
            <p className="connection-log-replay-notice" role="note">
              {t("connectionLogs.replay.emptyNotice")}
            </p>
          ) : null}
          <div className="connection-log-replay-terminal" style={{ backgroundColor: appearance.background }}>
            <div ref={terminalElement} />
          </div>
        </>
      )}
    </section>
  );
};

const actionClick = (event: MouseEvent<HTMLButtonElement>) => event.stopPropagation();

export const ConnectionLogsWorkspace = ({
  api,
  disabled = false,
  locale = "zh-CN",
  onCatalogChange,
  refreshKey,
}: ConnectionLogsWorkspaceProps) => {
  const { t } = useI18n(locale);
  const adapter = useMemo(() => api ?? DEFAULT_API, [api]);
  const nativeRuntimeAvailable = api !== undefined || isTauri();
  const [catalog, setCatalog] = useState<ConnectionLogsCatalog | null>(null);
  const [loading, setLoading] = useState(true);
  const [mutationPending, setMutationPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [renderLimit, setRenderLimit] = useState(CONNECTION_LOGS_PAGE_SIZE);
  const [openLogId, setOpenLogId] = useState<string | null>(null);
  const [replayState, setReplayState] = useState<ReplayViewState | null>(null);
  const [exportingLogId, setExportingLogId] = useState<string | null>(null);
  const [clearConfirmationOpen, setClearConfirmationOpen] = useState(false);
  const [rendererSettings, setRendererSettings] = useState(
    () => createDefaultRendererSafeSettings(),
  );
  const mounted = useRef(true);
  const loadSequence = useRef(0);
  const replaySequence = useRef(0);
  const exportLock = useRef(false);
  const mutationLock = useRef(false);
  const catalogRef = useRef<ConnectionLogsCatalog | null>(null);
  const onCatalogChangeRef = useRef(onCatalogChange);

  useEffect(() => {
    onCatalogChangeRef.current = onCatalogChange;
  }, [onCatalogChange]);

  useEffect(() => {
    let active = true;
    const refreshTerminalSettings = () => {
      void SETTINGS_ADAPTER.load().then((snapshot) => {
        if (active) setRendererSettings(snapshot.settings);
      }).catch(() => {
        // Replay remains usable with validated defaults when settings are unavailable.
      });
    };
    refreshTerminalSettings();
    window.addEventListener("focus", refreshTerminalSettings);
    return () => {
      active = false;
      window.removeEventListener("focus", refreshTerminalSettings);
    };
  }, []);

  const applyCatalog = useCallback((next: ConnectionLogsCatalog) => {
    catalogRef.current = next;
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
      const next = await adapter.list();
      if (!mounted.current || sequence !== loadSequence.current) return false;
      applyCatalog(next);
      return true;
    } catch (reason) {
      if (mounted.current && sequence === loadSequence.current) {
        setError(classifyConnectionLogsError(reason, t).message);
      }
      return false;
    } finally {
      if (mounted.current && sequence === loadSequence.current) setLoading(false);
    }
  }, [adapter, applyCatalog, nativeRuntimeAvailable, t]);

  useEffect(() => {
    mounted.current = true;
    void refreshCatalog();
    return () => {
      mounted.current = false;
      loadSequence.current += 1;
    };
  }, [refreshCatalog, refreshKey]);

  useEffect(() => () => {
    replaySequence.current += 1;
  }, []);

  const openReplay = useCallback(async (logId: string): Promise<void> => {
    const sequence = ++replaySequence.current;
    setOpenLogId(logId);
    setReplayState({ logId, status: "loading" });
    if (!nativeRuntimeAvailable) {
      if (mounted.current && sequence === replaySequence.current) {
        setReplayState({ logId, status: "ready", terminalData: "" });
      }
      return;
    }
    try {
      const response = await adapter.readReplay(logId);
      const terminalData = validateReplayPayload(response, logId);
      if (terminalData === null) throw new Error("CONNECTION_LOG_REPLAY_INVALID_RESPONSE");
      if (!mounted.current || sequence !== replaySequence.current) return;
      setReplayState({ logId, status: "ready", terminalData });
    } catch (reason) {
      if (!mounted.current || sequence !== replaySequence.current) return;
      const failure = classifyConnectionLogReplayError(reason, t);
      setReplayState(failure.unavailable
        ? { logId, status: "ready", terminalData: "" }
        : { logId, status: "error", message: failure.message });
    }
  }, [adapter, nativeRuntimeAvailable, t]);

  const exportReplay = useCallback(async (logId: string): Promise<void> => {
    if (disabled || !nativeRuntimeAvailable || exportLock.current) return;
    if (
      replayState?.logId !== logId
      || replayState.status !== "ready"
      || replayState.terminalData.length === 0
    ) return;

    exportLock.current = true;
    setExportingLogId(logId);
    try {
      const response = await adapter.exportLog(logId, locale);
      if (!response.success && !response.canceled) {
        console.error("Connection log export failed.");
      }
    } catch {
      console.error("Connection log export failed.");
    } finally {
      exportLock.current = false;
      if (mounted.current) setExportingLogId(null);
    }
  }, [adapter, disabled, locale, nativeRuntimeAvailable, replayState]);

  const closeReplay = useCallback(() => {
    replaySequence.current += 1;
    setOpenLogId(null);
    setReplayState(null);
  }, []);

  const mutateCatalog = useCallback(async (
    mutate: CatalogMutation,
    successNotice: string,
  ): Promise<boolean> => {
    if (disabled || mutationLock.current || !nativeRuntimeAvailable) return false;
    mutationLock.current = true;
    setMutationPending(true);
    setError(null);
    setNotice(null);
    try {
      let base = catalogRef.current ?? await adapter.list();
      if (!catalogRef.current) applyCatalog(base);
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const logs = mutate(base.logs);
        if (sameLogReferences(base.logs, logs)) {
          applyCatalog(base);
          return true;
        }
        try {
          const committed = await adapter.replace({
            expectedInventoryRevision: base.inventoryRevision,
            logs,
          });
          if (!mounted.current) return false;
          applyCatalog(committed);
          setNotice(successNotice);
          return true;
        } catch (reason) {
          const failure = classifyConnectionLogsError(reason, t);
          if (!failure.inventoryChanged || attempt > 0) throw reason;
          base = await adapter.list();
          if (!mounted.current) return false;
          applyCatalog(base);
        }
      }
      return false;
    } catch (reason) {
      if (mounted.current) setError(classifyConnectionLogsError(reason, t).message);
      return false;
    } finally {
      mutationLock.current = false;
      if (mounted.current) setMutationPending(false);
    }
  }, [adapter, applyCatalog, disabled, nativeRuntimeAvailable, t]);

  const toggleSaved = useCallback((id: string) => mutateCatalog(
    (logs) => logs.map((log) => log.id === id ? { ...log, saved: !log.saved } : log),
    t("connectionLogs.notice.bookmark"),
  ), [mutateCatalog, t]);

  const deleteLog = useCallback((id: string) => mutateCatalog(
    (logs) => logs.filter((log) => log.id !== id),
    t("connectionLogs.notice.deleted"),
  ), [mutateCatalog, t]);

  const clearUnsaved = useCallback(async () => {
    const changed = await mutateCatalog(
      (logs) => logs.filter((log) => log.saved),
      t("connectionLogs.notice.cleared"),
    );
    if (changed && mounted.current) setClearConfirmationOpen(false);
  }, [mutateCatalog, t]);

  const updateFontSize = useCallback((id: string, fontSize: number | undefined) => mutateCatalog(
    (logs) => logs.map((log) => {
      if (log.id !== id || log.fontSize === fontSize) return log;
      if (fontSize === undefined) {
        const { fontSize: _currentFontSize, ...rest } = log;
        return rest;
      }
      return { ...log, fontSize };
    }),
    t("connectionLogs.notice.appearance"),
  ), [mutateCatalog, t]);

  const sortedLogs = useMemo(
    () => sortConnectionLogsNewestFirst(catalog?.logs ?? []),
    [catalog?.logs],
  );
  const displayedLogs = useMemo(
    () => sortedLogs.slice(0, renderLimit),
    [renderLimit, sortedLogs],
  );
  const selectedLog = openLogId
    ? sortedLogs.find((log) => log.id === openLogId)
    : undefined;
  const unsavedCount = useMemo(
    () => sortedLogs.reduce((count, log) => count + (log.saved ? 0 : 1), 0),
    [sortedLogs],
  );

  useEffect(() => {
    if (openLogId && catalog && !catalog.logs.some((log) => log.id === openLogId)) {
      closeReplay();
    }
  }, [catalog, closeReplay, openLogId]);

  if (selectedLog) {
    const selectedReplay = replayState?.logId === selectedLog.id
      ? replayState
      : { logId: selectedLog.id, status: "loading" as const };
    return (
      <section className="connection-logs-workspace">
        <ReplayWorkspace
          disabled={disabled}
          exporting={exportingLogId !== null}
          locale={locale}
          log={selectedLog}
          mutationPending={mutationPending}
          onClose={closeReplay}
          onExport={() => void exportReplay(selectedLog.id)}
          onFontSizeChange={(fontSize) => void updateFontSize(selectedLog.id, fontSize)}
          onRetry={() => void openReplay(selectedLog.id)}
          replay={selectedReplay}
          terminalSettings={rendererSettings.terminal}
          appColorMode={rendererSettings.appearance.colorMode === "system"
            ? (window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light")
            : rendererSettings.appearance.colorMode}
        />
        {error ? <div className="connection-logs-message error replay-message" role="alert">{error}</div> : null}
      </section>
    );
  }

  return (
    <section className="connection-logs-workspace" aria-label={t("connectionLogs.title")}>
      <header className="connection-logs-toolbar">
        <div>
          <span className="connection-logs-toolbar-icon"><ConnectionLogGlyph name="history" /></span>
          <span>
            <strong>{t("connectionLogs.title")}</strong>
            <small>{t(
              sortedLogs.length === 1
                ? "connectionLogs.sessionCountOne"
                : "connectionLogs.sessionCount",
              { count: sortedLogs.length },
            )}</small>
          </span>
        </div>
        <div>
          <button
            type="button"
            className="connection-logs-refresh-button"
            aria-label={t("connectionLogs.refreshAria")}
            title={t("connectionLogs.refresh")}
            disabled={disabled || loading || mutationPending || !nativeRuntimeAvailable}
            onClick={() => void refreshCatalog()}
          ><ConnectionLogGlyph name="refresh" /></button>
          <button
            type="button"
            className="connection-logs-clear-button"
            disabled={disabled || mutationPending || unsavedCount === 0 || !nativeRuntimeAvailable}
            onClick={() => setClearConfirmationOpen(true)}
          ><ConnectionLogGlyph name="trash" />{t("connectionLogs.clearUnsaved")}</button>
        </div>
      </header>

      {error ? <div className="connection-logs-message error" role="alert">{error}</div> : null}
      {notice ? <div className="connection-logs-message notice" role="status">{notice}</div> : null}

      {displayedLogs.length > 0 ? (
        <div className="connection-logs-table-header" role="row">
          <span>{t("connectionLogs.date")} <ConnectionLogGlyph name="chevron-down" /></span>
          <span>{t("connectionLogs.user")}</span>
          <span>{t("connectionLogs.host")}</span>
          <span>{t("connectionLogs.saved")} <ConnectionLogGlyph name="bookmark" /></span>
        </div>
      ) : null}

      <div className="connection-logs-scroll-region">
        {loading && !catalog ? (
          <div className="connection-logs-loading">{t("connectionLogs.loading")}</div>
        ) : displayedLogs.length === 0 ? (
          <div className="connection-logs-empty-state">
            <span><ConnectionLogGlyph name="terminal" /></span>
            <h2>{t("connectionLogs.empty")}</h2>
            <p>{t("connectionLogs.emptyDescription")}</p>
          </div>
        ) : (
          <div className="connection-logs-table" role="table" aria-label={t("connectionLogs.history")}>
            {displayedLogs.map((log) => {
              const local = log.protocol === "local" || log.hostname.toLowerCase() === "localhost";
              const serial = log.protocol === "serial";
              const targetSubtitle = local
                ? t("connectionLogs.protocol.local")
                : t("connectionLogs.protocol.detail", {
                    protocol: serial ? t("connectionLogs.protocol.serial") : log.protocol,
                    target: serial ? log.hostname : log.username,
                  });
              return (
                <article
                  className="connection-log-row"
                  data-connection-log-id={log.id}
                  key={log.id}
                  role="row"
                  tabIndex={0}
                  onClick={() => void openReplay(log.id)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      void openReplay(log.id);
                    }
                  }}
                >
                  <div className="connection-log-date" role="cell">
                    <strong>{formatConnectionLogDate(log.startTime, locale, t)}</strong>
                    <small>{formatConnectionLogTimeRange(log.startTime, log.endTime, locale, t)}</small>
                  </div>
                  <div className="connection-log-user" role="cell">
                    <span><ConnectionLogGlyph name="user" /></span>
                    <p><strong title={log.localUsername}>{log.localUsername}</strong><small title={log.localHostname}>{log.localHostname}</small></p>
                  </div>
                  <div className="connection-log-host" role="cell">
                    <ConnectionTargetIcon log={log} />
                    <p>
                      <strong title={local ? t("connectionLogs.localTerminal") : log.hostLabel}>
                        {local ? t("connectionLogs.localTerminal") : log.hostLabel}
                      </strong>
                      <small title={targetSubtitle}>
                        {targetSubtitle}
                      </small>
                    </p>
                  </div>
                  <div className="connection-log-actions" role="cell">
                    <button
                      type="button"
                      className={log.saved ? "saved" : ""}
                      aria-label={t(
                        log.saved ? "connectionLogs.unsaveNamed" : "connectionLogs.saveNamed",
                        { host: log.hostLabel },
                      )}
                      title={t(log.saved ? "connectionLogs.unsave" : "connectionLogs.save")}
                      disabled={disabled || mutationPending || !nativeRuntimeAvailable}
                      onClick={(event) => {
                        actionClick(event);
                        void toggleSaved(log.id);
                      }}
                    ><ConnectionLogGlyph name="bookmark" /></button>
                    <button
                      type="button"
                      className="delete"
                      aria-label={t("connectionLogs.deleteNamed", { host: log.hostLabel })}
                      title={t("connectionLogs.delete")}
                      disabled={disabled || mutationPending || !nativeRuntimeAvailable}
                      onClick={(event) => {
                        actionClick(event);
                        void deleteLog(log.id);
                      }}
                    ><ConnectionLogGlyph name="trash" /></button>
                  </div>
                </article>
              );
            })}
            {sortedLogs.length > renderLimit ? (
              <button
                type="button"
                className="connection-logs-load-more"
                onClick={() => setRenderLimit((limit) => limit + CONNECTION_LOGS_PAGE_SIZE)}
              >{t("connectionLogs.loadMore", {
                count: Math.min(CONNECTION_LOGS_PAGE_SIZE, sortedLogs.length - renderLimit),
              })}</button>
            ) : null}
          </div>
        )}
      </div>

      {clearConfirmationOpen ? (
        <div className="connection-logs-dialog-backdrop" role="presentation">
          <section className="connection-logs-dialog" role="dialog" aria-modal="true" aria-labelledby="clear-connection-logs-title">
            <h2 id="clear-connection-logs-title">{t("connectionLogs.clearTitle")}</h2>
            <p>{t(
              unsavedCount === 1
                ? "connectionLogs.clearDescriptionOne"
                : "connectionLogs.clearDescription",
              { count: unsavedCount },
            )}</p>
            <div>
              <button type="button" disabled={mutationPending} onClick={() => setClearConfirmationOpen(false)}>
                {t("connectionLogs.cancel")}
              </button>
              <button type="button" className="danger" disabled={mutationPending} onClick={() => void clearUnsaved()}>
                {mutationPending ? t("connectionLogs.clearing") : t("connectionLogs.clearUnsaved")}
              </button>
            </div>
          </section>
        </div>
      ) : null}
    </section>
  );
};
