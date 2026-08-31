import type {
  PortForwardCatalog,
  PortForwardRule,
  PortForwardRuleMetadata,
  PortForwardRuntime,
  PortForwardType,
  StartPortForwardRequest,
  StartPortForwardResult,
  StopPortForwardRequest,
} from "./backend";
import { createTranslator, type MessageKey, type Translate } from "./i18n.ts";

const DEFAULT_TRANSLATOR = createTranslator("zh-CN");

export type PortForwardDraft = {
  label: string;
  type: PortForwardType;
  localPort: string;
  bindAddress: string;
  remoteHost: string;
  remotePort: string;
  hostId: string;
  autoStart: boolean;
  order?: number;
};

export type PortForwardIssueKind =
  | "invalid"
  | "notFound"
  | "stale"
  | "publication"
  | "alreadyRunning"
  | "notRunning"
  | "connection"
  | "failed";

export type PortForwardIssue = {
  kind: PortForwardIssueKind;
  message: string;
  refreshCatalog: boolean;
};

const byteLength = (value: string): number => new TextEncoder().encode(value).length;

const parsePort = (value: string): number | null => {
  if (!/^\d+$/.test(value.trim())) return null;
  const port = Number(value);
  return Number.isSafeInteger(port) && port >= 1 && port <= 65_535 ? port : null;
};

const normalizeAddress = (value: string): string | null => {
  const address = value.trim();
  if (!address || byteLength(address) > 253 || /[\0\r\n\t ]/.test(address)) return null;
  return address;
};

export const defaultPortForwardLabel = (
  type: PortForwardType,
  localPort: number,
  remoteHost?: string,
  remotePort?: number,
): string => {
  if (type === "dynamic") return `SOCKS:${localPort}`;
  const prefix = type === "local" ? "Local" : "Remote";
  return `${prefix}:${localPort} → ${remoteHost}:${remotePort}`;
};

export const normalizePortForwardDraft = (
  draft: PortForwardDraft,
): PortForwardRuleMetadata | null => {
  const localPort = parsePort(draft.localPort);
  const bindAddress = normalizeAddress(draft.bindAddress);
  const hostId = draft.hostId.trim();
  if (localPort === null || bindAddress === null || !hostId || byteLength(hostId) > 512) {
    return null;
  }

  let remoteHost: string | undefined;
  let remotePort: number | undefined;
  if (draft.type !== "dynamic") {
    remoteHost = normalizeAddress(draft.remoteHost) ?? undefined;
    remotePort = parsePort(draft.remotePort) ?? undefined;
    if (!remoteHost || !remotePort) return null;
  }

  const suppliedLabel = draft.label.trim();
  const label = suppliedLabel || defaultPortForwardLabel(
    draft.type,
    localPort,
    remoteHost,
    remotePort,
  );
  if (byteLength(label) > 256 || /[\0\r\n]/.test(label)) return null;

  return {
    label,
    type: draft.type,
    localPort,
    bindAddress,
    ...(remoteHost ? { remoteHost, remotePort } : {}),
    hostId,
    autoStart: draft.autoStart,
    ...(draft.order === undefined ? {} : { order: draft.order }),
  };
};

export const portForwardRuleSummary = (rule: PortForwardRule): string => {
  if (rule.type === "dynamic") {
    return `SOCKS5 · ${rule.bindAddress}:${rule.localPort}`;
  }
  return `${rule.bindAddress}:${rule.localPort} → ${rule.remoteHost}:${rule.remotePort}`;
};

const errorText = (reason: unknown): string => {
  if (reason instanceof Error) return reason.message;
  return String(reason);
};

const PORT_FORWARD_ISSUE_CONFIG = {
  invalid: { messageKey: "portForward.error.invalid", refreshCatalog: false },
  notFound: { messageKey: "portForward.error.notFound", refreshCatalog: true },
  stale: { messageKey: "portForward.error.stale", refreshCatalog: true },
  publication: { messageKey: "portForward.error.publication", refreshCatalog: true },
  alreadyRunning: { messageKey: "portForward.error.alreadyRunning", refreshCatalog: true },
  notRunning: { messageKey: "portForward.error.notRunning", refreshCatalog: true },
  connection: { messageKey: "portForward.error.connection", refreshCatalog: true },
  failed: { messageKey: "portForward.error.failed", refreshCatalog: false },
} as const satisfies Record<PortForwardIssueKind, {
  messageKey: MessageKey;
  refreshCatalog: boolean;
}>;

const classifyPortForwardIssueKind = (reason: unknown): PortForwardIssueKind => {
  const raw = errorText(reason);
  const has = (code: string) => raw.split("; ").some((part) => part.startsWith(code));
  if (has("PORT_FORWARD_INVALID")) return "invalid";
  if (has("PORT_FORWARD_NOT_FOUND")) return "notFound";
  if (has("PORT_FORWARD_INVENTORY_CHANGED")) return "stale";
  if (has("PORT_FORWARD_PUBLICATION_FAILED")) return "publication";
  if (has("PORT_FORWARD_ALREADY_RUNNING")) return "alreadyRunning";
  if (has("PORT_FORWARD_NOT_RUNNING")) return "notRunning";
  if (has("PORT_FORWARD_CONNECTION_FAILED")) return "connection";
  return "failed";
};

export const portForwardIssueFromKind = (
  kind: PortForwardIssueKind,
  t: Translate = DEFAULT_TRANSLATOR,
): PortForwardIssue => {
  const config = PORT_FORWARD_ISSUE_CONFIG[kind];
  return {
    kind,
    message: t(config.messageKey),
    refreshCatalog: config.refreshCatalog,
  };
};

export const classifyPortForwardError = (
  reason: unknown,
  t: Translate = DEFAULT_TRANSLATOR,
): PortForwardIssue => portForwardIssueFromKind(classifyPortForwardIssueKind(reason), t);

export type PortForwardBulkAction = "start" | "stop";

export type PortForwardBulkIssue = Readonly<Pick<
  PortForwardIssue,
  "kind" | "refreshCatalog"
>>;

export type PortForwardBulkFailure = {
  ruleId: string;
  label: string;
  issue: PortForwardBulkIssue;
};

export type PortForwardBulkResult = {
  action: PortForwardBulkAction;
  attempted: number;
  succeeded: number;
  skipped: number;
  failures: PortForwardBulkFailure[];
  catalog: PortForwardCatalog;
  refreshIssue?: PortForwardBulkIssue;
};

export type PortForwardBulkPresentation = Readonly<{
  error: string | null;
  notice: string | null;
  failureItems: readonly Readonly<{ ruleId: string; text: string }>[];
}>;

type PortForwardBulkDependencies = {
  start: (request: StartPortForwardRequest) => Promise<StartPortForwardResult>;
  stop: (request: StopPortForwardRequest) => Promise<PortForwardCatalog>;
  refresh: () => Promise<PortForwardCatalog>;
};

const runtimeForRule = (
  catalog: PortForwardCatalog,
  ruleId: string,
): PortForwardRuntime | undefined => catalog.runtime.find((runtime) => runtime.ruleId === ruleId);

/**
 * An error runtime may be replaced by a new start attempt. Active and
 * connecting runtimes have already reached (or are reaching) the start goal.
 */
export const isPortForwardStartTarget = (
  runtime: PortForwardRuntime | undefined,
): boolean => runtime === undefined || runtime.phase === "error";

/** Every process-owned runtime, including an error entry, needs stop cleanup. */
export const isPortForwardStopTarget = (
  runtime: PortForwardRuntime | undefined,
): boolean => runtime !== undefined;

export const selectPortForwardBulkTargetIds = (
  catalog: PortForwardCatalog,
  action: PortForwardBulkAction,
): string[] => {
  if (action === "start") {
    return catalog.rules
      .filter((rule) => isPortForwardStartTarget(runtimeForRule(catalog, rule.id)))
      .map((rule) => rule.id);
  }

  const runtimeIds = new Set(catalog.runtime.map((runtime) => runtime.ruleId));
  const orderedRuleIds = catalog.rules
    .filter((rule) => runtimeIds.delete(rule.id))
    .map((rule) => rule.id);
  return [...orderedRuleIds, ...runtimeIds];
};

/**
 * Sequentially composes the existing single-rule commands. Every successful
 * response becomes the authority for the next request, which is required
 * because starting a rule publishes `lastUsedAt` and advances inventory CAS.
 * Failures never abort the queue. A reconciliation is attempted after each
 * failure, and a final authoritative refresh is always attempted.
 */
export const runPortForwardBulkAction = async (
  action: PortForwardBulkAction,
  initialCatalog: PortForwardCatalog,
  dependencies: PortForwardBulkDependencies,
): Promise<PortForwardBulkResult> => {
  const queuedIds = selectPortForwardBulkTargetIds(initialCatalog, action);
  const queuedIdSet = new Set(queuedIds);
  const queuedLabels = new Map(initialCatalog.rules.map((rule) => [rule.id, rule.label]));
  let workingCatalog = initialCatalog;
  let attempted = 0;
  let succeeded = 0;
  let skipped = initialCatalog.rules.reduce(
    (count, rule) => count + (queuedIdSet.has(rule.id) ? 0 : 1),
    0,
  );
  const failures: PortForwardBulkFailure[] = [];

  const reconcileAfterFailure = async (): Promise<void> => {
    try {
      workingCatalog = await dependencies.refresh();
    } catch {
      // The mandatory final refresh below gets a fresh chance and owns the
      // user-visible refresh result. Keep processing independent rule IDs.
    }
  };

  for (const ruleId of queuedIds) {
    const rule = workingCatalog.rules.find((candidate) => candidate.id === ruleId);
    const runtime = runtimeForRule(workingCatalog, ruleId);
    if (
      (action === "start" && (!rule || !isPortForwardStartTarget(runtime)))
      || (action === "stop" && !isPortForwardStopTarget(runtime))
    ) {
      skipped += 1;
      continue;
    }

    attempted += 1;
    try {
      if (action === "start") {
        const started = await dependencies.start({
          id: rule!.id,
          expectedInventoryRevision: workingCatalog.inventoryRevision,
        });
        workingCatalog = started.catalog;
      } else {
        workingCatalog = await dependencies.stop({ id: ruleId });
      }
      succeeded += 1;
    } catch (reason) {
      const kind = classifyPortForwardIssueKind(reason);
      const issue: PortForwardBulkIssue = {
        kind,
        refreshCatalog: PORT_FORWARD_ISSUE_CONFIG[kind].refreshCatalog,
      };
      const reachedTarget = (action === "start" && issue.kind === "alreadyRunning")
        || (action === "stop" && issue.kind === "notRunning");
      if (reachedTarget) {
        skipped += 1;
      } else {
        failures.push({
          ruleId,
          label: rule?.label ?? queuedLabels.get(ruleId) ?? ruleId,
          issue,
        });
      }
      await reconcileAfterFailure();
    }
  }

  let refreshIssue: PortForwardBulkIssue | undefined;
  try {
    workingCatalog = await dependencies.refresh();
  } catch (reason) {
    const kind = classifyPortForwardIssueKind(reason);
    refreshIssue = {
      kind,
      refreshCatalog: PORT_FORWARD_ISSUE_CONFIG[kind].refreshCatalog,
    };
  }

  return {
    action,
    attempted,
    succeeded,
    skipped,
    failures,
    catalog: workingCatalog,
    ...(refreshIssue ? { refreshIssue } : {}),
  };
};

/** Localizes stable bulk result codes only at the current render boundary. */
export const createPortForwardBulkPresentation = (
  result: PortForwardBulkResult,
  t: Translate = DEFAULT_TRANSLATOR,
): PortForwardBulkPresentation => {
  const failed = result.failures.length;
  let error: string | null = null;
  let notice: string | null = null;

  if (result.refreshIssue) {
    error = t("portForward.bulkRefreshFailed");
  } else if (failed > 0) {
    const key = result.action === "start"
      ? (result.succeeded > 0
        ? "portForward.bulkStartPartial"
        : "portForward.bulkStartFailed")
      : (result.succeeded > 0
        ? "portForward.bulkStopPartial"
        : "portForward.bulkStopFailed");
    error = t(key, { succeeded: result.succeeded, failed });
  } else if (result.succeeded > 0) {
    notice = t(
      result.action === "start" ? "portForward.bulkStarted" : "portForward.bulkStopped",
      { count: result.succeeded },
    );
  } else {
    notice = t("portForward.bulkNoChanges");
  }

  return {
    error,
    notice,
    failureItems: result.failures.map((failure) => ({
      ruleId: failure.ruleId,
      text: t("portForward.bulkFailureItem", {
        rule: failure.label,
        message: portForwardIssueFromKind(failure.issue.kind, t).message,
      }),
    })),
  };
};
