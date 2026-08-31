import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  type DockerContainer,
  type DockerContainerAction,
  type DockerContainerInspect,
  type DockerImage,
  type DockerStat,
  type SystemOverview,
  getSystemOverview,
  getDockerStats,
  inspectDockerContainer,
  listDockerContainers,
  listDockerImages,
  runDockerContainerAction,
} from "./backend";
import type { Locale, MessageKey, Translate } from "./i18n";
import SystemInventory, { type InventoryTab } from "./SystemInventory";
import TmuxPanel from "./TmuxPanel";
import "./systemManager.css";

/**
 * Docker container management for the active session.
 *
 * Read-only by default. The three lifecycle actions that are reversible run
 * on a single click; removal is destructive and asks first, because a
 * container removed by a stray click is not recoverable from here.
 *
 * Stats are fetched separately from the listing: `docker stats` is markedly
 * slower than `docker ps`, so the table appears immediately and the CPU and
 * memory columns fill in when they arrive.
 */

type DockerPanelProps = Readonly<{
  sessionId: string;
  connected: boolean;
  locale: Locale;
  t: Translate;
}>;

/** Actions offered inline, in the order a running container needs them. */
const RUNNING_ACTIONS: readonly DockerContainerAction[] = ["stop", "restart"];
const STOPPED_ACTIONS: readonly DockerContainerAction[] = ["start"];

const ACTION_LABEL: Record<DockerContainerAction, MessageKey> = {
  start: "systemManager.docker.start",
  stop: "systemManager.docker.stop",
  restart: "systemManager.docker.restart",
  pause: "systemManager.docker.pause",
  unpause: "systemManager.docker.unpause",
  remove: "systemManager.docker.remove",
};

const isRunning = (container: DockerContainer): boolean =>
  container.state.toLowerCase() === "running";

const formatInspectDetails = (details: DockerContainerInspect): string =>
  JSON.stringify(details, null, 2);

type SystemTab = "overview" | "containers" | "images" | "tmux" | InventoryTab;

type PendingContainerAction = Readonly<{
  action: DockerContainerAction;
  token: symbol;
}>;

const TAB_ORDER: readonly SystemTab[] = [
  "overview",
  "containers",
  "images",
  "processes",
  "ports",
  "services",
  "gpu",
  "tmux",
];

const TAB_LABEL: Record<SystemTab, MessageKey> = {
  overview: "systemManager.overview.title",
  containers: "systemManager.docker.title",
  images: "systemManager.docker.imagesTitle",
  processes: "systemManager.processes.title",
  ports: "systemManager.ports.title",
  services: "systemManager.services.title",
  tmux: "systemManager.tmux.title",
  gpu: "systemManager.gpu.title",
};

const formatOverviewBytes = (value: number | null, t: Translate): string => {
  if (value === null || !Number.isFinite(value) || value < 0) {
    return t("systemManager.overview.notAvailable");
  }
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"] as const;
  let scaled = value;
  let unit = 0;
  while (scaled >= 1024 && unit < units.length - 1) {
    scaled /= 1024;
    unit += 1;
  }
  const digits = scaled >= 100 || unit === 0 ? 0 : scaled >= 10 ? 1 : 2;
  return `${scaled.toFixed(digits)} ${units[unit]}`;
};

const formatUptime = (seconds: number | null, t: Translate): string => {
  if (seconds === null || !Number.isFinite(seconds) || seconds < 0) {
    return t("systemManager.overview.notAvailable");
  }
  const wholeMinutes = Math.floor(seconds / 60);
  const days = Math.floor(wholeMinutes / (24 * 60));
  const hours = Math.floor((wholeMinutes % (24 * 60)) / 60);
  const minutes = wholeMinutes % 60;
  return t("systemManager.overview.uptimeValue", {
    days: String(days),
    hours: String(hours),
    minutes: String(minutes),
  });
};

type OverviewFieldProps = Readonly<{
  label: string;
  value: string;
}>;

function OverviewField({ label, value }: OverviewFieldProps) {
  return (
    <div className="system-manager-overview-field">
      <dt>{label}</dt>
      <dd title={value}>{value}</dd>
    </div>
  );
}

export default function DockerPanel({ sessionId, connected, locale, t }: DockerPanelProps) {
  const [tab, setTab] = useState<SystemTab>("overview");
  const [overview, setOverview] = useState<SystemOverview | null>(null);
  const [overviewLoading, setOverviewLoading] = useState(false);
  const [overviewError, setOverviewError] = useState<string | null>(null);
  const [containers, setContainers] = useState<readonly DockerContainer[]>([]);
  const [stats, setStats] = useState<ReadonlyMap<string, DockerStat>>(new Map());
  const [images, setImages] = useState<readonly DockerImage[]>([]);
  const [loading, setLoading] = useState(false);
  const [imagesLoading, setImagesLoading] = useState(false);
  const [containerListError, setContainerListError] = useState<string | null>(null);
  const [containerActionError, setContainerActionError] = useState<string | null>(null);
  const [imagesError, setImagesError] = useState<string | null>(null);
  const [busyIds, setBusyIds] = useState<ReadonlySet<string>>(() => new Set());
  const [pendingRemoval, setPendingRemoval] = useState<DockerContainer | null>(null);
  const [inspectedContainer, setInspectedContainer] = useState<DockerContainer | null>(null);
  const [inspectDetails, setInspectDetails] = useState<DockerContainerInspect | null>(null);
  const [inspectLoading, setInspectLoading] = useState(false);
  const [inspectError, setInspectError] = useState<string | null>(null);

  // Session ownership, refresh ownership and per-target mutation ownership
  // are separate. Cross-row mutations may overlap, but a target keeps one
  // exact action token until its mutation and reconciliation refresh finish.
  const sessionGenerationRef = useRef(0);
  const viewSessionIdRef = useRef(sessionId);
  const refreshGenerationRef = useRef(0);
  const pendingActionsRef = useRef(new Map<string, PendingContainerAction>());
  const imageGenerationRef = useRef(0);
  const inspectGenerationRef = useRef(0);
  const overviewGenerationRef = useRef(0);

  const refreshOverview = useCallback(async () => {
    if (!connected) {
      setOverviewLoading(false);
      return;
    }
    const sessionGeneration = sessionGenerationRef.current;
    const overviewGeneration = ++overviewGenerationRef.current;
    const isCurrentOverviewRequest = (): boolean =>
      sessionGenerationRef.current === sessionGeneration
      && overviewGenerationRef.current === overviewGeneration;
    setOverviewLoading(true);
    setOverviewError(null);
    try {
      const next = await getSystemOverview(sessionId);
      if (!isCurrentOverviewRequest()) return;
      setOverview(next);
    } catch {
      if (!isCurrentOverviewRequest()) return;
      setOverviewError(t("systemManager.overview.listFailed"));
    } finally {
      if (isCurrentOverviewRequest()) setOverviewLoading(false);
    }
  }, [connected, sessionId, t]);

  const refresh = useCallback(async () => {
    if (!connected) {
      setLoading(false);
      return;
    }
    const sessionGeneration = sessionGenerationRef.current;
    const refreshGeneration = ++refreshGenerationRef.current;
    const isCurrentRefresh = (): boolean =>
      sessionGenerationRef.current === sessionGeneration
      && refreshGenerationRef.current === refreshGeneration;
    setLoading(true);
    setContainerListError(null);
    try {
      const next = await listDockerContainers(sessionId);
      if (!isCurrentRefresh()) return;
      setContainers(next);

      const runningIds = next.filter(isRunning).map((container) => container.id);
      if (runningIds.length === 0) {
        setStats(new Map());
        return;
      }
      // Stats are best-effort: a failure here leaves the listing intact
      // rather than replacing it with an error.
      try {
        const rows = await getDockerStats(sessionId, runningIds);
        if (!isCurrentRefresh()) return;
        setStats(new Map(rows.map((row) => [row.id, row])));
      } catch {
        if (isCurrentRefresh()) setStats(new Map());
      }
    } catch {
      if (!isCurrentRefresh()) return;
      setContainerListError(t("systemManager.docker.listFailed"));
      setContainers([]);
      setStats(new Map());
    } finally {
      if (isCurrentRefresh()) setLoading(false);
    }
  }, [connected, sessionId, t]);

  const refreshImages = useCallback(async () => {
    if (!connected) {
      setImagesLoading(false);
      return;
    }
    const sessionGeneration = sessionGenerationRef.current;
    const imageGeneration = ++imageGenerationRef.current;
    const isCurrentImageRequest = (): boolean =>
      sessionGenerationRef.current === sessionGeneration
      && imageGenerationRef.current === imageGeneration;
    setImagesLoading(true);
    setImagesError(null);
    try {
      const next = await listDockerImages(sessionId);
      if (!isCurrentImageRequest()) return;
      setImages(next);
    } catch {
      if (!isCurrentImageRequest()) return;
      setImagesError(t("systemManager.docker.imagesListFailed"));
    } finally {
      if (isCurrentImageRequest()) setImagesLoading(false);
    }
  }, [connected, sessionId, t]);

  const closeInspect = useCallback(() => {
    inspectGenerationRef.current += 1;
    setInspectedContainer(null);
    setInspectDetails(null);
    setInspectLoading(false);
    setInspectError(null);
  }, []);

  const openInspect = useCallback(async (container: DockerContainer) => {
    const sessionGeneration = sessionGenerationRef.current;
    const inspectGeneration = ++inspectGenerationRef.current;
    const isCurrentInspect = (): boolean =>
      sessionGenerationRef.current === sessionGeneration
      && inspectGenerationRef.current === inspectGeneration;
    setInspectedContainer(container);
    setInspectDetails(null);
    setInspectLoading(true);
    setInspectError(null);
    try {
      const details = await inspectDockerContainer(sessionId, container.id);
      if (!isCurrentInspect()) return;
      setInspectDetails(details);
    } catch {
      if (!isCurrentInspect()) return;
      setInspectError(t("systemManager.docker.inspectFailed"));
    } finally {
      if (isCurrentInspect()) setInspectLoading(false);
    }
  }, [sessionId, t]);

  // Establish the new session generation before starting its first refresh.
  // The previous ordering started the request and then immediately made it
  // stale, which left the refresh button permanently loading.
  useEffect(() => {
    const sessionGeneration = ++sessionGenerationRef.current;
    viewSessionIdRef.current = sessionId;
    refreshGenerationRef.current += 1;
    pendingActionsRef.current.clear();
    imageGenerationRef.current += 1;
    inspectGenerationRef.current += 1;
    overviewGenerationRef.current += 1;
    setOverview(null);
    setOverviewLoading(false);
    setOverviewError(null);
    setContainers([]);
    setStats(new Map());
    setImages([]);
    setLoading(false);
    setImagesLoading(false);
    setContainerListError(null);
    setContainerActionError(null);
    setImagesError(null);
    setBusyIds(new Set());
    setPendingRemoval(null);
    setInspectedContainer(null);
    setInspectDetails(null);
    setInspectLoading(false);
    setInspectError(null);
    if (connected) void refresh();

    return () => {
      if (sessionGenerationRef.current === sessionGeneration) {
        sessionGenerationRef.current += 1;
      }
      refreshGenerationRef.current += 1;
      pendingActionsRef.current.clear();
      imageGenerationRef.current += 1;
      inspectGenerationRef.current += 1;
      overviewGenerationRef.current += 1;
    };
  }, [connected, refresh, sessionId]);

  useEffect(() => {
    if (tab === "overview" && connected) void refreshOverview();
    return () => {
      overviewGenerationRef.current += 1;
    };
  }, [connected, refreshOverview, tab]);

  useEffect(() => {
    if (tab === "images" && connected) void refreshImages();
  }, [connected, refreshImages, tab]);

  const runAction = useCallback(
    async (container: DockerContainer, action: DockerContainerAction) => {
      if (pendingActionsRef.current.has(container.id)) return;

      const sessionGeneration = sessionGenerationRef.current;
      const startsActionBatch = pendingActionsRef.current.size === 0;
      const actionToken = Symbol(action);
      pendingActionsRef.current.set(container.id, { action, token: actionToken });
      const isCurrentAction = (): boolean =>
        sessionGenerationRef.current === sessionGeneration
        && pendingActionsRef.current.get(container.id)?.action === action
        && pendingActionsRef.current.get(container.id)?.token === actionToken;
      setBusyIds((current) => new Set(current).add(container.id));
      if (startsActionBatch) setContainerActionError(null);
      try {
        await runDockerContainerAction(sessionId, container.id, action);
      } catch {
        if (isCurrentAction()) {
          setContainerActionError(t("systemManager.docker.actionFailed"));
        }
      } finally {
        if (isCurrentAction()) {
          // Reconcile even after a reported failure: the remote operation may
          // have completed before its transport failed. Refresh does not clear
          // the independently owned action error.
          await refresh();
        }
        if (isCurrentAction()) {
          pendingActionsRef.current.delete(container.id);
          setBusyIds((current) => {
            const next = new Set(current);
            next.delete(container.id);
            return next;
          });
        }
      }
    },
    [refresh, sessionId, t],
  );

  const containerError = containerActionError ?? containerListError;

  const summary = useMemo(() => {
    const running = containers.filter(isRunning).length;
    return { running, total: containers.length };
  }, [containers]);

  const tabSummary = (() => {
    switch (tab) {
      case "overview":
        return t("systemManager.overview.summary");
      case "containers":
        return t("systemManager.docker.summary", {
          running: String(summary.running),
          total: String(summary.total),
        });
      case "images":
        return t("systemManager.rowCount", { count: String(images.length) });
      case "processes":
        return t("systemManager.processes.summary");
      case "ports":
        return t("systemManager.ports.summary");
      case "services":
        return t("systemManager.services.summary");
      case "gpu":
        return t("systemManager.gpu.summary");
      case "tmux":
        return t("systemManager.tmux.summary");
    }
  })();

  // Passive effects run after paint. Hide the previous host synchronously
  // during that one render so its targets can never be clicked with the new
  // session id before the reset effect retires them.
  if (viewSessionIdRef.current !== sessionId) {
    return (
      <div className="system-manager-panel">
        <div className="system-manager-empty" role="status">
          <p>{t("systemManager.refreshing")}</p>
        </div>
      </div>
    );
  }

  if (!connected) {
    return (
      <div className="system-manager-panel">
        <div className="system-manager-empty">
          <p>{t("systemManager.notConnected")}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="system-manager-panel">
      <header className="system-manager-header">
        <div>
          <h2>{t("systemManager.title")}</h2>
          <p>{tabSummary}</p>
        </div>
      </header>

      <div className="system-manager-tabs" role="tablist" aria-label={t("systemManager.title")}>
        {TAB_ORDER.map((id) => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={tab === id}
            className={tab === id ? "active" : undefined}
            onClick={() => setTab(id)}
          >
            {t(TAB_LABEL[id])}
          </button>
        ))}
      </div>

      {tab === "overview" ? (
        <>
          <div className="system-manager-subheader">
            <span>{t("systemManager.overview.snapshot")}</span>
            <button
              type="button"
              className="system-manager-refresh"
              onClick={() => void refreshOverview()}
              disabled={overviewLoading}
            >
              {overviewLoading ? t("systemManager.refreshing") : t("systemManager.refresh")}
            </button>
          </div>

          {overviewError ? (
            <div className="system-manager-notice" role="status">
              <span>{overviewError}</span>
            </div>
          ) : null}

          {!overview && overviewLoading ? (
            <div className="system-manager-empty" role="status">
              <p>{t("systemManager.refreshing")}</p>
            </div>
          ) : null}

          {overview ? (
            <div className="system-manager-overview">
              <dl className="system-manager-overview-grid">
                <OverviewField
                  label={t("systemManager.overview.hostname")}
                  value={overview.hostname ?? t("systemManager.overview.notAvailable")}
                />
                <OverviewField
                  label={t("systemManager.overview.os")}
                  value={overview.osName ?? t("systemManager.overview.notAvailable")}
                />
                <OverviewField
                  label={t("systemManager.overview.kernel")}
                  value={overview.kernelRelease ?? t("systemManager.overview.notAvailable")}
                />
                <OverviewField
                  label={t("systemManager.overview.uptime")}
                  value={formatUptime(overview.uptimeSeconds, t)}
                />
                <OverviewField
                  label={t("systemManager.overview.loadAverage")}
                  value={overview.loadAverage
                    ? overview.loadAverage.map((value) => value.toFixed(2)).join(" / ")
                    : t("systemManager.overview.notAvailable")}
                />
                <OverviewField
                  label={t("systemManager.overview.cpuCount")}
                  value={overview.cpuCount === null
                    ? t("systemManager.overview.notAvailable")
                    : t("systemManager.overview.cpuCountValue", {
                        count: String(overview.cpuCount),
                      })}
                />
                <OverviewField
                  label={t("systemManager.overview.memory")}
                  value={t("systemManager.overview.usageValue", {
                    used: formatOverviewBytes(overview.memoryUsedBytes, t),
                    total: formatOverviewBytes(overview.memoryTotalBytes, t),
                  })}
                />
                <OverviewField
                  label={t("systemManager.overview.rootDisk")}
                  value={t("systemManager.overview.usageValue", {
                    used: formatOverviewBytes(overview.rootDiskUsedBytes, t),
                    total: formatOverviewBytes(overview.rootDiskTotalBytes, t),
                  })}
                />
              </dl>
            </div>
          ) : null}
        </>
      ) : null}

      {tab === "processes" || tab === "ports" || tab === "services" || tab === "gpu" ? (
        <SystemInventory tab={tab} sessionId={sessionId} t={t} />
      ) : null}

      {tab === "tmux" ? (
        <TmuxPanel sessionId={sessionId} locale={locale} t={t} />
      ) : null}

      {tab === "containers" ? (
        <div className="system-manager-subheader">
          <span>{t("systemManager.rowCount", { count: String(summary.total) })}</span>
          <button
            type="button"
            className="system-manager-refresh"
            onClick={() => void refresh()}
            disabled={loading}
          >
            {loading ? t("systemManager.refreshing") : t("systemManager.refresh")}
          </button>
        </div>
      ) : null}

      {tab === "containers" && containerError ? (
        <div className="system-manager-notice" role="status">
          <span>{containerError}</span>
        </div>
      ) : null}

      {tab === "containers" && containers.length === 0 && !loading && !containerError ? (
        <div className="system-manager-empty">
          <h3>{t("systemManager.docker.emptyTitle")}</h3>
          <p>{t("systemManager.docker.emptyBody")}</p>
        </div>
      ) : null}

      {tab === "containers" ? (
      <ul className="system-manager-list">
        {containers.map((container) => {
          const stat = stats.get(container.id);
          const running = isRunning(container);
          const actions = running ? RUNNING_ACTIONS : STOPPED_ACTIONS;
          const busy = busyIds.has(container.id);
          return (
            <li key={container.id} className="system-manager-card">
              <div className="system-manager-card-head">
                <span
                  className={`system-manager-state state-${running ? "running" : "stopped"}`}
                  aria-hidden="true"
                />
                <strong title={container.names}>{container.names || container.id}</strong>
                <span className="system-manager-status">{container.status}</span>
              </div>

              <div className="system-manager-meta">
                <span title={container.image}>{container.image}</span>
                {container.ports ? <span title={container.ports}>{container.ports}</span> : null}
              </div>

              {stat ? (
                <div className="system-manager-stats">
                  <span>{t("systemManager.docker.cpu", { value: stat.cpuPercent })}</span>
                  <span>{t("systemManager.docker.memory", { value: stat.memoryUsage })}</span>
                </div>
              ) : null}

              <div className="system-manager-actions">
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => void openInspect(container)}
                >
                  {t("systemManager.docker.inspect")}
                </button>
                {actions.map((action) => (
                  <button
                    key={action}
                    type="button"
                    disabled={busy}
                    onClick={() => void runAction(container, action)}
                  >
                    {t(ACTION_LABEL[action])}
                  </button>
                ))}
                <button
                  type="button"
                  className="is-destructive"
                  disabled={busy}
                  onClick={() => setPendingRemoval(container)}
                >
                  {t(ACTION_LABEL.remove)}
                </button>
              </div>
            </li>
          );
        })}
      </ul>
      ) : null}

      {tab === "images" ? (
        <div className="system-manager-subheader">
          <span>{t("systemManager.rowCount", { count: String(images.length) })}</span>
          <button
            type="button"
            className="system-manager-refresh"
            onClick={() => void refreshImages()}
            disabled={imagesLoading}
          >
            {imagesLoading ? t("systemManager.refreshing") : t("systemManager.refresh")}
          </button>
        </div>
      ) : null}

      {tab === "images" && imagesError ? (
        <div className="system-manager-notice" role="status">
          <span>{imagesError}</span>
        </div>
      ) : null}

      {tab === "images" && images.length === 0 && imagesLoading ? (
        <div className="system-manager-empty" role="status">
          <p>{t("systemManager.refreshing")}</p>
        </div>
      ) : null}

      {tab === "images" && images.length === 0 && !imagesLoading && !imagesError ? (
        <div className="system-manager-empty">
          <h3>{t("systemManager.docker.imagesEmptyTitle")}</h3>
          <p>{t("systemManager.docker.imagesEmptyBody")}</p>
        </div>
      ) : null}

      {tab === "images" && images.length > 0 ? (
        <ul className="system-manager-list">
          {images.map((dockerImage) => (
            <li
              key={`${dockerImage.id}:${dockerImage.repository}:${dockerImage.tag}`}
              className="system-manager-card"
            >
              <div className="system-manager-card-head">
                <strong title={`${t("systemManager.docker.imageRepository")}: ${dockerImage.repository}`}>
                  {dockerImage.repository}
                </strong>
                <span
                  className="system-manager-status"
                  title={`${t("systemManager.docker.imageTag")}: ${dockerImage.tag}`}
                >
                  {dockerImage.tag}
                </span>
              </div>
              <div className="system-manager-meta system-manager-image-meta">
                <span title={dockerImage.id}>
                  <b>{t("systemManager.docker.imageId")}</b>
                  {dockerImage.id}
                </span>
                <span title={dockerImage.createdSince}>
                  <b>{t("systemManager.docker.imageCreated")}</b>
                  {dockerImage.createdSince}
                </span>
                <span title={dockerImage.size}>
                  <b>{t("systemManager.docker.imageSize")}</b>
                  {dockerImage.size}
                </span>
              </div>
            </li>
          ))}
        </ul>
      ) : null}

      {inspectedContainer ? (
        <div
          className="system-manager-confirm"
          role="dialog"
          aria-modal="true"
          aria-labelledby="system-manager-inspect-title"
        >
          <div className="system-manager-confirm-card system-manager-inspect-card">
            <h3 id="system-manager-inspect-title">
              {t("systemManager.docker.inspectTitle", {
                name: inspectedContainer.names || inspectedContainer.id,
              })}
            </h3>
            <div className="system-manager-inspect-body">
              {inspectLoading ? (
                <p role="status">{t("systemManager.docker.inspectLoading")}</p>
              ) : null}
              {!inspectLoading && inspectError ? (
                <div className="system-manager-notice" role="status">
                  <span>{inspectError}</span>
                </div>
              ) : null}
              {!inspectLoading && !inspectError && !inspectDetails ? (
                <p>{t("systemManager.docker.inspectEmpty")}</p>
              ) : null}
              {!inspectLoading && !inspectError && inspectDetails ? (
                <pre
                  tabIndex={0}
                  aria-label={t("systemManager.docker.inspectContentLabel", {
                    name: inspectedContainer.names || inspectedContainer.id,
                  })}
                >
                  {formatInspectDetails(inspectDetails)}
                </pre>
              ) : null}
            </div>
            <div className="system-manager-confirm-actions">
              <button type="button" onClick={closeInspect}>
                {t("systemManager.docker.inspectClose")}
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {pendingRemoval ? (
        <div className="system-manager-confirm" role="alertdialog" aria-modal="true">
          <div className="system-manager-confirm-card">
            <h3>{t("systemManager.docker.confirmRemoveTitle")}</h3>
            <p>
              {t("systemManager.docker.confirmRemoveBody", {
                name: pendingRemoval.names || pendingRemoval.id,
              })}
            </p>
            <div className="system-manager-confirm-actions">
              <button type="button" onClick={() => setPendingRemoval(null)}>
                {t("connectionPrompt.common.cancel")}
              </button>
              <button
                type="button"
                className="is-destructive"
                onClick={() => {
                  const target = pendingRemoval;
                  setPendingRemoval(null);
                  void runAction(target, "remove");
                }}
              >
                {t(ACTION_LABEL.remove)}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
