import { useCallback, useEffect, useRef, useState } from "react";

import {
  type ListeningPort,
  type NvidiaGpu,
  type ProcessSignal,
  type RemoteProcess,
  type ServiceAction,
  type SystemService,
  listListeningPorts,
  listNvidiaGpus,
  listRemoteProcesses,
  listSystemServices,
  runSystemServiceAction,
  signalRemoteProcess,
} from "./backend";
import type { MessageKey, Translate } from "./i18n";

/**
 * Process, port and service inventory for the active session.
 *
 * Each listing is built from a tool-fallback chain that ends in `|| true`,
 * so a host without `ss` or without systemd returns an empty list rather
 * than an error. An empty tab therefore means "nothing to show here", which
 * is why each one carries its own explanatory empty state instead of a bare
 * blank area.
 */

export type InventoryTab = "processes" | "ports" | "services" | "gpu";

type InventoryProps = Readonly<{
  tab: InventoryTab;
  sessionId: string;
  t: Translate;
}>;

const SIGNAL_LABEL: Record<ProcessSignal, MessageKey> = {
  term: "systemManager.process.signalTerm",
  hup: "systemManager.process.signalHup",
  kill: "systemManager.process.signalKill",
};

const SERVICE_LABEL: Record<ServiceAction, MessageKey> = {
  start: "systemManager.docker.start",
  stop: "systemManager.docker.stop",
  restart: "systemManager.docker.restart",
  enable: "systemManager.service.enable",
  disable: "systemManager.service.disable",
};

/** Resident memory reads better as MiB than as a six-digit KiB figure. */
const formatResident = (kib: number): string =>
  kib >= 1024 ? `${Math.round(kib / 1024)} MiB` : `${kib} KiB`;

const formatGpuMetric = (value: number): string =>
  Number.isInteger(value) ? String(value) : value.toFixed(1);

type PendingInventoryAction = Readonly<{
  action: ProcessSignal | ServiceAction;
  token: symbol;
}>;

const processTargetKey = (pid: number): string => `process:${pid}`;
const serviceTargetKey = (unit: string): string => `service:${unit}`;

export default function SystemInventory({ tab, sessionId, t }: InventoryProps) {
  const [processes, setProcesses] = useState<readonly RemoteProcess[]>([]);
  const [ports, setPorts] = useState<readonly ListeningPort[]>([]);
  const [services, setServices] = useState<readonly SystemService[]>([]);
  const [gpus, setGpus] = useState<readonly NvidiaGpu[]>([]);
  const [loading, setLoading] = useState(false);
  const [listError, setListError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busyTargets, setBusyTargets] = useState<ReadonlySet<string>>(() => new Set());
  const [pendingKill, setPendingKill] = useState<RemoteProcess | null>(null);

  // Session/tab ownership, refresh ownership and per-target mutation
  // ownership are independent. Cross-row mutations may overlap, while an
  // exact target/action token prevents duplicate or conflicting row actions.
  const sessionGenerationRef = useRef(0);
  const refreshGenerationRef = useRef(0);
  const pendingActionsRef = useRef(new Map<string, PendingInventoryAction>());

  const refresh = useCallback(async () => {
    const sessionGeneration = sessionGenerationRef.current;
    const refreshGeneration = ++refreshGenerationRef.current;
    const isCurrentRefresh = (): boolean =>
      sessionGenerationRef.current === sessionGeneration
      && refreshGenerationRef.current === refreshGeneration;
    setLoading(true);
    setListError(null);
    try {
      if (tab === "processes") {
        const rows = await listRemoteProcesses(sessionId);
        if (isCurrentRefresh()) setProcesses(rows);
      } else if (tab === "ports") {
        const rows = await listListeningPorts(sessionId);
        if (isCurrentRefresh()) setPorts(rows);
      } else if (tab === "services") {
        const rows = await listSystemServices(sessionId);
        if (isCurrentRefresh()) setServices(rows);
      } else {
        const rows = await listNvidiaGpus(sessionId);
        if (isCurrentRefresh()) setGpus(rows);
      }
    } catch {
      if (!isCurrentRefresh()) return;
      setListError(tab === "gpu"
        ? t("systemManager.gpu.listFailed")
        : t("systemManager.listFailed"));
    } finally {
      if (isCurrentRefresh()) setLoading(false);
    }
  }, [sessionId, t, tab]);

  // Establish ownership before the first request. Starting refresh first and
  // incrementing afterward would make that request stale immediately.
  useEffect(() => {
    const sessionGeneration = ++sessionGenerationRef.current;
    refreshGenerationRef.current += 1;
    pendingActionsRef.current.clear();
    setProcesses([]);
    setPorts([]);
    setServices([]);
    setGpus([]);
    setLoading(false);
    setListError(null);
    setActionError(null);
    setBusyTargets(new Set());
    setPendingKill(null);
    void refresh();

    return () => {
      if (sessionGenerationRef.current === sessionGeneration) {
        sessionGenerationRef.current += 1;
      }
      refreshGenerationRef.current += 1;
      pendingActionsRef.current.clear();
    };
  }, [refresh, sessionId, tab]);

  const sendSignal = useCallback(
    async (process: RemoteProcess, signal: ProcessSignal) => {
      const targetKey = processTargetKey(process.pid);
      if (pendingActionsRef.current.has(targetKey)) return;

      const sessionGeneration = sessionGenerationRef.current;
      const startsActionBatch = pendingActionsRef.current.size === 0;
      const actionToken = Symbol(signal);
      pendingActionsRef.current.set(targetKey, { action: signal, token: actionToken });
      const isCurrentAction = (): boolean =>
        sessionGenerationRef.current === sessionGeneration
        && pendingActionsRef.current.get(targetKey)?.action === signal
        && pendingActionsRef.current.get(targetKey)?.token === actionToken;
      setBusyTargets((current) => new Set(current).add(targetKey));
      if (startsActionBatch) setActionError(null);
      try {
        await signalRemoteProcess(sessionId, process.pid, process.startTimeToken, signal);
      } catch {
        if (isCurrentAction()) setActionError(t("systemManager.process.signalFailed"));
      } finally {
        if (isCurrentAction()) await refresh();
        if (isCurrentAction()) {
          pendingActionsRef.current.delete(targetKey);
          setBusyTargets((current) => {
            const next = new Set(current);
            next.delete(targetKey);
            return next;
          });
        }
      }
    },
    [refresh, sessionId, t],
  );

  const runService = useCallback(
    async (service: SystemService, action: ServiceAction) => {
      const targetKey = serviceTargetKey(service.unit);
      if (pendingActionsRef.current.has(targetKey)) return;

      const sessionGeneration = sessionGenerationRef.current;
      const startsActionBatch = pendingActionsRef.current.size === 0;
      const actionToken = Symbol(action);
      pendingActionsRef.current.set(targetKey, { action, token: actionToken });
      const isCurrentAction = (): boolean =>
        sessionGenerationRef.current === sessionGeneration
        && pendingActionsRef.current.get(targetKey)?.action === action
        && pendingActionsRef.current.get(targetKey)?.token === actionToken;
      setBusyTargets((current) => new Set(current).add(targetKey));
      if (startsActionBatch) setActionError(null);
      try {
        await runSystemServiceAction(sessionId, service.unit, action);
      } catch {
        if (isCurrentAction()) setActionError(t("systemManager.service.actionFailed"));
      } finally {
        if (isCurrentAction()) await refresh();
        if (isCurrentAction()) {
          pendingActionsRef.current.delete(targetKey);
          setBusyTargets((current) => {
            const next = new Set(current);
            next.delete(targetKey);
            return next;
          });
        }
      }
    },
    [refresh, sessionId, t],
  );

  const error = actionError ?? listError;

  const rowCount = tab === "processes"
    ? processes.length
    : tab === "ports"
      ? ports.length
      : tab === "services"
        ? services.length
        : gpus.length;

  return (
    <>
      <div className="system-manager-subheader">
        <span>{t("systemManager.rowCount", { count: String(rowCount) })}</span>
        <button
          type="button"
          className="system-manager-refresh"
          onClick={() => void refresh()}
          disabled={loading}
        >
          {loading ? t("systemManager.refreshing") : t("systemManager.refresh")}
        </button>
      </div>

      {error ? (
        <div className="system-manager-notice" role="status">
          <span>{error}</span>
        </div>
      ) : null}

      {rowCount === 0 && !loading && !error ? (
        <div className="system-manager-empty">
          <h3>{t(`systemManager.${tab}.emptyTitle` as MessageKey)}</h3>
          <p>{t(`systemManager.${tab}.emptyBody` as MessageKey)}</p>
        </div>
      ) : null}

      {tab === "processes" ? (
        <ul className="system-manager-list">
          {processes.map((process) => (
            <li key={process.pid} className="system-manager-card">
              <div className="system-manager-card-head">
                <strong title={process.command}>{process.command}</strong>
                <span className="system-manager-status">{process.user}</span>
              </div>
              <div className="system-manager-meta">
                <span>PID {process.pid}</span>
                <span>CPU {process.cpuPercent}%</span>
                <span>{formatResident(process.residentKib)}</span>
                <span>{process.elapsed}</span>
              </div>
              <div className="system-manager-actions">
                <button
                  type="button"
                  disabled={busyTargets.has(processTargetKey(process.pid))}
                  onClick={() => void sendSignal(process, "term")}
                >
                  {t(SIGNAL_LABEL.term)}
                </button>
                <button
                  type="button"
                  className="is-destructive"
                  disabled={busyTargets.has(processTargetKey(process.pid))}
                  onClick={() => setPendingKill(process)}
                >
                  {t(SIGNAL_LABEL.kill)}
                </button>
              </div>
            </li>
          ))}
        </ul>
      ) : null}

      {tab === "ports" ? (
        <ul className="system-manager-list">
          {ports.map((entry) => (
            <li key={`${entry.protocol}-${entry.localAddress}-${entry.port}`} className="system-manager-card">
              <div className="system-manager-card-head">
                <strong>
                  {entry.port} · {entry.protocol}
                </strong>
                <span className="system-manager-status">{entry.process || "—"}</span>
              </div>
              <div className="system-manager-meta">
                <span title={entry.localAddress}>{entry.localAddress}</span>
              </div>
            </li>
          ))}
        </ul>
      ) : null}

      {tab === "services" ? (
        <ul className="system-manager-list">
          {services.map((service) => {
            const running = service.subState === "running";
            return (
              <li key={service.unit} className="system-manager-card">
                <div className="system-manager-card-head">
                  <span
                    className={`system-manager-state state-${running ? "running" : "stopped"}`}
                    aria-hidden="true"
                  />
                  <strong title={service.description || service.unit}>{service.unit}</strong>
                  <span className="system-manager-status">{service.subState}</span>
                </div>
                {service.description ? (
                  <div className="system-manager-meta">
                    <span title={service.description}>{service.description}</span>
                  </div>
                ) : null}
                <div className="system-manager-actions">
                  <button
                    type="button"
                    disabled={busyTargets.has(serviceTargetKey(service.unit))}
                    onClick={() => void runService(service, running ? "stop" : "start")}
                  >
                    {t(running ? SERVICE_LABEL.stop : SERVICE_LABEL.start)}
                  </button>
                  <button
                    type="button"
                    disabled={busyTargets.has(serviceTargetKey(service.unit))}
                    onClick={() => void runService(service, "restart")}
                  >
                    {t(SERVICE_LABEL.restart)}
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      ) : null}

      {tab === "gpu" ? (
        <ul className="system-manager-list">
          {gpus.map((gpu) => {
            const metrics: string[] = [];
            if (gpu.utilizationPercent !== null) {
              metrics.push(t("systemManager.gpu.utilization", {
                value: formatGpuMetric(gpu.utilizationPercent),
              }));
            }
            if (gpu.memoryUsedMib !== null && gpu.memoryTotalMib !== null) {
              metrics.push(t("systemManager.gpu.memory", {
                used: formatGpuMetric(gpu.memoryUsedMib),
                total: formatGpuMetric(gpu.memoryTotalMib),
              }));
            }
            if (gpu.temperatureC !== null) {
              metrics.push(t("systemManager.gpu.temperature", {
                value: formatGpuMetric(gpu.temperatureC),
              }));
            }
            if (gpu.powerDrawW !== null) {
              metrics.push(gpu.powerLimitW === null
                ? t("systemManager.gpu.powerDraw", {
                    value: formatGpuMetric(gpu.powerDrawW),
                  })
                : t("systemManager.gpu.power", {
                    draw: formatGpuMetric(gpu.powerDrawW),
                    limit: formatGpuMetric(gpu.powerLimitW),
                  }));
            }
            if (gpu.fanPercent !== null) {
              metrics.push(t("systemManager.gpu.fan", {
                value: formatGpuMetric(gpu.fanPercent),
              }));
            }

            return (
              <li key={gpu.uuid} className="system-manager-card">
                <div className="system-manager-card-head">
                  <span className="system-manager-state state-running" aria-hidden="true" />
                  <strong title={gpu.name}>{gpu.name}</strong>
                  <span className="system-manager-status">
                    {t("systemManager.gpu.index", { index: String(gpu.index) })}
                  </span>
                </div>
                <div className="system-manager-meta">
                  <span title={gpu.uuid}>
                    {t("systemManager.gpu.uuid", { value: gpu.uuid })}
                  </span>
                  {gpu.driverVersion ? (
                    <span>
                      {t("systemManager.gpu.driver", { version: gpu.driverVersion })}
                    </span>
                  ) : null}
                </div>
                {metrics.length > 0 ? (
                  <div className="system-manager-stats">
                    {metrics.map((metric) => <span key={metric}>{metric}</span>)}
                  </div>
                ) : null}
              </li>
            );
          })}
        </ul>
      ) : null}

      {pendingKill ? (
        <div className="system-manager-confirm" role="alertdialog" aria-modal="true">
          <div className="system-manager-confirm-card">
            <h3>{t("systemManager.process.confirmKillTitle")}</h3>
            <p>
              {t("systemManager.process.confirmKillBody", {
                pid: String(pendingKill.pid),
                command: pendingKill.command,
              })}
            </p>
            <div className="system-manager-confirm-actions">
              <button type="button" onClick={() => setPendingKill(null)}>
                {t("connectionPrompt.common.cancel")}
              </button>
              <button
                type="button"
                className="is-destructive"
                onClick={() => {
                  const target = pendingKill;
                  setPendingKill(null);
                  void sendSignal(target, "kill");
                }}
              >
                {t(SIGNAL_LABEL.kill)}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </>
  );
}
