import {
  type FormEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  createPortForwardRule,
  deletePortForwardRule,
  listPortForwardRules,
  startPortForward,
  stopPortForward,
  updatePortForwardRule,
  type PortForwardCatalog as PortForwardCatalogSnapshot,
  type PortForwardRule,
  type PortForwardRuntime,
  type PortForwardType,
  type SavedHost,
} from "./backend";
import {
  classifyPortForwardError,
  createPortForwardBulkPresentation,
  normalizePortForwardDraft,
  portForwardRuleSummary,
  runPortForwardBulkAction,
  selectPortForwardBulkTargetIds,
  type PortForwardBulkAction,
  type PortForwardBulkResult,
  type PortForwardDraft,
} from "./portForwardingUi";
import { useI18n, type Locale, type Translate } from "./i18n";
import { WorkspaceGlyph } from "./NotesScriptsShared";
import { WindowControlGlyph } from "./WindowControlGlyph";

type PortForwardEditor = PortForwardDraft & {
  mode: "create" | "update";
  id?: string;
  expectedInventoryRevision: unknown;
};

type DeletePrompt = {
  id: string;
  label: string;
};

export type PortForwardingCatalogProps = {
  locale?: Locale;
  hosts: SavedHost[];
  disabled?: boolean;
  nativeRuntimeAvailable?: boolean;
};

const EMPTY_PREVIEW_CATALOG: PortForwardCatalogSnapshot = {
  inventoryRevision: null,
  rules: [],
  runtime: [],
};

const typeLabel = (type: PortForwardType, t: Translate): string => {
  if (type === "local") return t("portForward.type.local");
  if (type === "remote") return t("portForward.type.remote");
  return t("portForward.type.dynamic");
};

const typeDescription = (type: PortForwardType, t: Translate): string => {
  if (type === "local") return t("portForward.type.localDescription");
  if (type === "remote") return t("portForward.type.remoteDescription");
  return t("portForward.type.dynamicDescription");
};

const emptyDraft = (
  expectedInventoryRevision: unknown,
  type: PortForwardType = "local",
): PortForwardEditor => ({
  mode: "create",
  expectedInventoryRevision,
  label: "",
  type,
  localPort: type === "dynamic" ? "1080" : "8080",
  bindAddress: "127.0.0.1",
  remoteHost: "",
  remotePort: "",
  hostId: "",
  autoStart: false,
});

const draftFromRule = (
  rule: PortForwardRule,
  expectedInventoryRevision: unknown,
): PortForwardEditor => ({
  mode: "update",
  id: rule.id,
  expectedInventoryRevision,
  label: rule.label,
  type: rule.type,
  localPort: String(rule.localPort),
  bindAddress: rule.bindAddress,
  remoteHost: rule.remoteHost ?? "",
  remotePort: rule.remotePort === undefined ? "" : String(rule.remotePort),
  hostId: rule.hostId,
  autoStart: rule.autoStart,
  order: rule.order,
});

const replaceRuntime = (
  runtimes: PortForwardRuntime[],
  next: PortForwardRuntime,
): PortForwardRuntime[] => [
  ...runtimes.filter((runtime) => runtime.ruleId !== next.ruleId),
  next,
];

const ForwardGlyph = () => (
  <svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <path d="M8 3v5M16 3v5M6 8h12v2a6 6 0 0 1-6 6v5M9 21h6" />
  </svg>
);

export const PortForwardingCatalog = ({
  locale = "zh-CN",
  hosts,
  disabled = false,
  nativeRuntimeAvailable = true,
}: PortForwardingCatalogProps) => {
  const { t } = useI18n(locale);
  const [catalog, setCatalog] = useState<PortForwardCatalogSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [mutationPending, setMutationPending] = useState(false);
  const [pendingRuleIds, setPendingRuleIds] = useState<Set<string>>(new Set());
  const [bulkAction, setBulkAction] = useState<PortForwardBulkAction | null>(null);
  const [bulkReport, setBulkReport] = useState<PortForwardBulkResult | null>(null);
  const [editor, setEditor] = useState<PortForwardEditor | null>(null);
  const [deletePrompt, setDeletePrompt] = useState<DeletePrompt | null>(null);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<"all" | PortForwardType>("all");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const mounted = useRef(true);
  const loadSequence = useRef(0);
  const mutationLock = useRef(false);
  const runtimeActionLocks = useRef(new Set<string>());
  const bulkActionLock = useRef(false);
  const bulkSequence = useRef(0);

  const applyCatalog = useCallback((next: PortForwardCatalogSnapshot) => {
    loadSequence.current += 1;
    if (!mounted.current) return;
    setCatalog(next);
    setEditor(null);
    setDeletePrompt(null);
  }, []);

  const refreshCatalog = useCallback(async (preserveMessage = false): Promise<boolean> => {
    if (bulkActionLock.current) return false;
    if (!nativeRuntimeAvailable) {
      if (mounted.current) {
        setCatalog(EMPTY_PREVIEW_CATALOG);
        setLoading(false);
      }
      return true;
    }
    const sequence = ++loadSequence.current;
    setLoading(true);
    if (!preserveMessage) {
      setError(null);
      setNotice(null);
      setBulkReport(null);
    }
    try {
      const next = await listPortForwardRules();
      if (!mounted.current || sequence !== loadSequence.current) return false;
      setCatalog(next);
      return true;
    } catch (reason) {
      if (mounted.current && sequence === loadSequence.current) {
        setError(classifyPortForwardError(reason, t).message);
      }
      return false;
    } finally {
      if (mounted.current && sequence === loadSequence.current) setLoading(false);
    }
  }, [nativeRuntimeAvailable, t]);

  useEffect(() => {
    mounted.current = true;
    void refreshCatalog();
    return () => {
      mounted.current = false;
      loadSequence.current += 1;
    };
  }, [refreshCatalog]);

  const handleFailure = useCallback(async (reason: unknown, ruleId?: string) => {
    const issue = classifyPortForwardError(reason, t);
    if (issue.refreshCatalog) await refreshCatalog(true);
    if (!mounted.current) return;
    setError(issue.message);
    setNotice(null);
    if (
      ruleId
      && (issue.kind === "connection"
        || issue.kind === "failed"
        || issue.kind === "invalid"
        || issue.kind === "publication")
    ) {
      setCatalog((current) => current ? {
        ...current,
        runtime: replaceRuntime(current.runtime, {
          ruleId,
          phase: "error",
          error: issue.message,
        }),
      } : current);
    }
  }, [refreshCatalog, t]);

  const openCreate = (type: PortForwardType = "local") => {
    if (
      !catalog
      || disabled
      || mutationPending
      || bulkActionLock.current
      || runtimeActionLocks.current.size > 0
      || !nativeRuntimeAvailable
    ) return;
    setError(null);
    setNotice(null);
    setBulkReport(null);
    setEditor(emptyDraft(catalog.inventoryRevision, type));
  };

  const openUpdate = (rule: PortForwardRule) => {
    if (
      !catalog
      || disabled
      || mutationPending
      || bulkActionLock.current
      || runtimeActionLocks.current.size > 0
    ) return;
    setError(null);
    setNotice(null);
    setBulkReport(null);
    setEditor(draftFromRule(rule, catalog.inventoryRevision));
  };

  const submitEditor = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const snapshot = editor;
    if (
      !snapshot
      || disabled
      || mutationLock.current
      || bulkActionLock.current
      || runtimeActionLocks.current.size > 0
      || !nativeRuntimeAvailable
    ) return;
    const metadata = normalizePortForwardDraft(snapshot);
    if (!metadata) {
      setError(t("portForward.validation"));
      return;
    }

    mutationLock.current = true;
    loadSequence.current += 1;
    setMutationPending(true);
    setError(null);
    setNotice(null);
    try {
      const next = snapshot.mode === "create"
        ? await createPortForwardRule({
          expectedInventoryRevision: snapshot.expectedInventoryRevision,
          metadata,
        })
        : await updatePortForwardRule({
          id: snapshot.id!,
          expectedInventoryRevision: snapshot.expectedInventoryRevision,
          metadata,
        });
      applyCatalog(next);
      setNotice(snapshot.mode === "create" ? t("portForward.created") : t("portForward.updated"));
    } catch (reason) {
      await handleFailure(reason);
    } finally {
      mutationLock.current = false;
      if (mounted.current) setMutationPending(false);
    }
  };

  const beginRule = async (rule: PortForwardRule) => {
    const snapshot = catalog;
    if (
      !snapshot
      || disabled
      || mutationLock.current
      || bulkActionLock.current
      || runtimeActionLocks.current.size > 0
      || !nativeRuntimeAvailable
    ) return;
    runtimeActionLocks.current.add(rule.id);
    setPendingRuleIds((current) => new Set(current).add(rule.id));
    setError(null);
    setNotice(null);
    setBulkReport(null);
    setCatalog((current) => current ? {
      ...current,
      runtime: replaceRuntime(current.runtime, { ruleId: rule.id, phase: "connecting" }),
    } : current);
    try {
      const result = await startPortForward({
        id: rule.id,
        expectedInventoryRevision: snapshot.inventoryRevision,
      });
      applyCatalog(result.catalog);
      setNotice(t("portForward.started", { rule: rule.label, address: result.address, port: result.port }));
    } catch (reason) {
      await handleFailure(reason, rule.id);
    } finally {
      runtimeActionLocks.current.delete(rule.id);
      if (mounted.current) {
        setPendingRuleIds((current) => {
          const next = new Set(current);
          next.delete(rule.id);
          return next;
        });
      }
    }
  };

  const stopRule = async (rule: PortForwardRule) => {
    if (
      disabled
      || mutationLock.current
      || bulkActionLock.current
      || runtimeActionLocks.current.size > 0
      || !nativeRuntimeAvailable
    ) return;
    runtimeActionLocks.current.add(rule.id);
    setPendingRuleIds((current) => new Set(current).add(rule.id));
    setError(null);
    setNotice(null);
    setBulkReport(null);
    try {
      const next = await stopPortForward({ id: rule.id });
      applyCatalog(next);
      setNotice(t("portForward.stopped", { rule: rule.label }));
    } catch (reason) {
      await handleFailure(reason, rule.id);
    } finally {
      runtimeActionLocks.current.delete(rule.id);
      if (mounted.current) {
        setPendingRuleIds((current) => {
          const next = new Set(current);
          next.delete(rule.id);
          return next;
        });
      }
    }
  };

  const confirmDelete = async () => {
    const prompt = deletePrompt;
    let workingCatalog = catalog;
    if (
      !prompt
      || !workingCatalog
      || disabled
      || mutationLock.current
      || bulkActionLock.current
      || runtimeActionLocks.current.size > 0
      || !nativeRuntimeAvailable
    ) return;
    mutationLock.current = true;
    loadSequence.current += 1;
    setMutationPending(true);
    setError(null);
    setNotice(null);
    try {
      const runtime = workingCatalog.runtime.find((item) => item.ruleId === prompt.id);
      if (runtime?.phase === "active" || runtime?.phase === "connecting") {
        workingCatalog = await stopPortForward({ id: prompt.id });
        if (mounted.current) setCatalog(workingCatalog);
      }
      const next = await deletePortForwardRule({
        id: prompt.id,
        expectedInventoryRevision: workingCatalog.inventoryRevision,
      });
      applyCatalog(next);
      setNotice(t("portForward.deleted", { rule: prompt.label }));
    } catch (reason) {
      await handleFailure(reason);
    } finally {
      mutationLock.current = false;
      if (mounted.current) setMutationPending(false);
    }
  };

  const runtimeByRule = useMemo(() => new Map(
    (catalog?.runtime ?? []).map((runtime) => [runtime.ruleId, runtime]),
  ), [catalog?.runtime]);
  const hostById = useMemo(() => new Map(hosts.map((host) => [host.id, host])), [hosts]);
  const rules = useMemo(() => {
    const query = search.trim().toLocaleLowerCase();
    return (catalog?.rules ?? [])
      .filter((rule) => typeFilter === "all" || rule.type === typeFilter)
      .filter((rule) => {
        if (!query) return true;
        const host = hostById.get(rule.hostId);
        return [rule.label, rule.bindAddress, rule.remoteHost ?? "", host?.label ?? "", host?.hostname ?? ""]
          .some((value) => value.toLocaleLowerCase().includes(query));
      })
      .sort((left, right) => (left.order ?? Number.MAX_SAFE_INTEGER) - (right.order ?? Number.MAX_SAFE_INTEGER));
  }, [catalog?.rules, hostById, search, typeFilter]);

  const startAllTargetIds = useMemo(
    () => catalog ? selectPortForwardBulkTargetIds(catalog, "start") : [],
    [catalog],
  );
  const stopAllTargetIds = useMemo(
    () => catalog ? selectPortForwardBulkTargetIds(catalog, "stop") : [],
    [catalog],
  );

  const handleBulkAction = useCallback(async (action: PortForwardBulkAction) => {
    const snapshot = catalog;
    if (
      !snapshot
      || disabled
      || loading
      || mutationLock.current
      || bulkActionLock.current
      || runtimeActionLocks.current.size > 0
      || !nativeRuntimeAvailable
    ) return;
    const targetIds = selectPortForwardBulkTargetIds(snapshot, action);
    if (targetIds.length === 0) return;

    const sequence = ++bulkSequence.current;
    bulkActionLock.current = true;
    loadSequence.current += 1;
    setBulkAction(action);
    setBulkReport(null);
    setError(null);
    setNotice(null);
    setPendingRuleIds((current) => {
      const next = new Set(current);
      for (const ruleId of targetIds) next.add(ruleId);
      return next;
    });

    try {
      const result = await runPortForwardBulkAction(action, snapshot, {
        start: startPortForward,
        stop: stopPortForward,
        refresh: listPortForwardRules,
      });
      if (!mounted.current || sequence !== bulkSequence.current) return;

      loadSequence.current += 1;
      setCatalog(result.catalog);
      setBulkReport(result);
    } finally {
      if (sequence === bulkSequence.current) {
        bulkActionLock.current = false;
        if (mounted.current) {
          setBulkAction(null);
          setPendingRuleIds((current) => {
            const next = new Set(current);
            for (const ruleId of targetIds) next.delete(ruleId);
            return next;
          });
        }
      }
    }
  }, [catalog, disabled, loading, nativeRuntimeAvailable]);

  const actionsDisabled = disabled
    || mutationPending
    || loading
    || bulkAction !== null
    || pendingRuleIds.size > 0;
  const bulkActionsDisabled = actionsDisabled
    || pendingRuleIds.size > 0
    || !catalog
    || !nativeRuntimeAvailable;
  const bulkPresentation = useMemo(
    () => bulkReport ? createPortForwardBulkPresentation(bulkReport, t) : null,
    [bulkReport, t],
  );
  const displayedError = error ?? bulkPresentation?.error ?? null;
  const displayedNotice = notice ?? bulkPresentation?.notice ?? null;

  return (
    <section className="port-forward-catalog" aria-busy={loading || mutationPending || bulkAction !== null}>
      <header className="port-forward-page-heading">
        <div className="port-forward-new-menu">
          <button
            className="primary-button"
            type="button"
            disabled={actionsDisabled || !catalog || !nativeRuntimeAvailable}
            onClick={() => openCreate("local")}
            title={nativeRuntimeAvailable ? t("portForward.new") : t("portForward.desktopCreateOnly")}
          >
            <ForwardGlyph /> {t("portForward.new")}
          </button>
          <div className="port-forward-quick-types" aria-label={t("portForward.quickCreate")}>
            <button type="button" disabled={actionsDisabled || !nativeRuntimeAvailable} onClick={() => openCreate("local")}>{typeLabel("local", t)}</button>
            <button type="button" disabled={actionsDisabled || !nativeRuntimeAvailable} onClick={() => openCreate("remote")}>{typeLabel("remote", t)}</button>
            <button type="button" disabled={actionsDisabled || !nativeRuntimeAvailable} onClick={() => openCreate("dynamic")}>{typeLabel("dynamic", t)}</button>
          </div>
        </div>
        <label className="port-forward-search">
          <WorkspaceGlyph name="search" />
          <input
            type="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder={t("portForward.searchPlaceholder")}
            aria-label={t("portForward.search")}
          />
        </label>
        <button
          className="port-forward-refresh"
          type="button"
          disabled={actionsDisabled || !nativeRuntimeAvailable}
          onClick={() => void refreshCatalog()}
        >
          {loading ? t("portForward.refreshing") : t("portForward.refresh")}
        </button>
      </header>

      <div className="port-forward-filter-bar" role="toolbar" aria-label={t("portForward.filter")}>
        {(["all", "local", "remote", "dynamic"] as const).map((type) => (
          <button
            type="button"
            className={typeFilter === type ? "active" : ""}
            aria-pressed={typeFilter === type}
            onClick={() => setTypeFilter(type)}
            key={type}
          >
            {type === "all" ? t("portForward.all") : typeLabel(type, t)}
          </button>
        ))}
        <button
          type="button"
          className="port-forward-bulk-start"
          disabled={bulkActionsDisabled || startAllTargetIds.length === 0}
          aria-busy={bulkAction === "start"}
          onClick={() => void handleBulkAction("start")}
        >
          {bulkAction === "start" ? t("portForward.startingAll") : t("portForward.startAll")}
        </button>
        <button
          type="button"
          className="port-forward-bulk-stop"
          disabled={bulkActionsDisabled || stopAllTargetIds.length === 0}
          aria-busy={bulkAction === "stop"}
          onClick={() => void handleBulkAction("stop")}
        >
          {bulkAction === "stop" ? t("portForward.stoppingAll") : t("portForward.stopAll")}
        </button>
        <span>{t("portForward.ruleCount", { count: rules.length })}</span>
      </div>

      {displayedError && <p className="connection-error port-forward-message" role="alert">{displayedError}</p>}
      {displayedNotice && <p className="saved-host-success port-forward-message" role="status">{displayedNotice}</p>}
      {bulkPresentation && bulkPresentation.failureItems.length > 0 && (
        <div className="connection-error port-forward-message" role="alert">
          <ul>
            {bulkPresentation.failureItems.map((failure) => (
              <li key={failure.ruleId}>{failure.text}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="port-forward-rule-list" aria-live="polite">
        {loading && !catalog && (
          <div className="vault-loading-state" role="status">
            <span /><span /><span /><p>{t("portForward.loading")}</p>
          </div>
        )}
        {!loading && catalog && catalog.rules.length === 0 && (
          <div className="vault-empty-state port-forward-empty">
            <span className="vault-empty-icon"><ForwardGlyph /></span>
            <h3>{t("portForward.empty")}</h3>
            <p>{t("portForward.emptyDescription")}</p>
            <div className="vault-empty-actions">
              <button
                className="primary-button"
                type="button"
                disabled={!nativeRuntimeAvailable}
                onClick={() => openCreate("local")}
              >
                <ForwardGlyph /> {t("portForward.new")}
              </button>
            </div>
          </div>
        )}
        {!loading && catalog && catalog.rules.length > 0 && rules.length === 0 && (
          <div className="vault-empty-state port-forward-empty">
            <span className="vault-empty-icon"><ForwardGlyph /></span>
            <h3>{t("portForward.noMatch")}</h3>
            <p>{t("portForward.noMatchDescription")}</p>
            <button type="button" onClick={() => { setSearch(""); setTypeFilter("all"); }}>{t("portForward.clearFilters")}</button>
          </div>
        )}
        {rules.map((rule) => {
          const runtime = runtimeByRule.get(rule.id);
          const phase = runtime?.phase ?? "inactive";
          const pending = pendingRuleIds.has(rule.id);
          const host = hostById.get(rule.hostId);
          const running = phase === "active" || phase === "connecting";
          const runtimeError = runtime?.error
            ? classifyPortForwardError(new Error(runtime.error), t).message
            : undefined;
          return (
            <article className={`port-forward-rule-card type-${rule.type} phase-${phase}`} key={rule.id}>
              <span className="port-forward-type-icon" aria-hidden="true">
                {rule.type === "dynamic" ? "S" : rule.type[0].toUpperCase()}
              </span>
              <div className="port-forward-rule-summary">
                <div>
                  <strong>{rule.label}</strong>
                  <i className="port-forward-status-dot" aria-hidden="true" />
                  <span className="port-forward-status-label">
                    {phase === "active"
                      ? t("portForward.status.active")
                      : phase === "connecting"
                        ? t("portForward.status.connecting")
                        : phase === "error"
                          ? t("portForward.status.error")
                          : t("portForward.status.inactive")}
                  </span>
                </div>
                <small>{portForwardRuleSummary(rule)}</small>
                <span title={host ? `${host.username}@${host.hostname}:${host.port}` : rule.hostId}>
                  {t("portForward.relay")} · {host?.label ?? t("portForward.missingHost")}{rule.autoStart ? ` · ${t("portForward.autoStart")}` : ""}
                </span>
                {phase === "error" && runtimeError && <em title={runtimeError}>{runtimeError}</em>}
              </div>
              <div className="port-forward-rule-actions">
                {pending ? (
                  <button type="button" disabled aria-label={t("portForward.operationPending")} title={t("portForward.operationPending")}>…</button>
                ) : running ? (
                  <button type="button" className="port-forward-stop" disabled={actionsDisabled} onClick={() => void stopRule(rule)}>{t("portForward.stop")}</button>
                ) : (
                  <button type="button" className="port-forward-start" disabled={actionsDisabled || !host} onClick={() => void beginRule(rule)}>{t("portForward.start")}</button>
                )}
                <button type="button" disabled={actionsDisabled || running} onClick={() => openUpdate(rule)}>{t("portForward.edit")}</button>
                <button
                  type="button"
                  className="saved-host-delete"
                  disabled={actionsDisabled}
                  onClick={() => {
                    if (bulkActionLock.current || runtimeActionLocks.current.size > 0) return;
                    setError(null);
                    setNotice(null);
                    setBulkReport(null);
                    setDeletePrompt({ id: rule.id, label: rule.label });
                  }}
                >
                  {t("portForward.delete")}
                </button>
              </div>
            </article>
          );
        })}
      </div>

      {editor && (
        <div className="dialog-backdrop saved-host-editor-backdrop" role="presentation">
          <form
            className="trust-dialog saved-host-dialog saved-host-details-panel port-forward-details-panel"
            role="dialog"
            aria-modal="true"
            aria-labelledby="port-forward-editor-title"
            onSubmit={(event) => void submitEditor(event)}
          >
            <header className="saved-host-details-header">
              <div>
                <span className="saved-host-details-kicker">{t("portForward.kicker")}</span>
                <h2 id="port-forward-editor-title">{editor.mode === "create" ? t("portForward.new") : t("portForward.editTitle")}</h2>
              </div>
              <div className="saved-host-details-header-actions">
                <button
                  className="saved-host-header-close"
                  type="button"
                  disabled={mutationPending}
                  aria-label={t("portForward.cancel")}
                  title={t("portForward.cancel")}
                  onClick={() => { setEditor(null); setError(null); }}
                ><WindowControlGlyph name="close" /></button>
                <button
                  className="saved-host-header-save"
                  type="submit"
                  disabled={actionsDisabled}
                  aria-label={t("portForward.save")}
                  title={t("portForward.save")}
                >{mutationPending ? "…" : "✓"}</button>
              </div>
            </header>
            <div className="saved-host-details-scroll">
              <div className="port-forward-traffic" aria-hidden="true">
                <span>{t("portForward.thisDevice")}</span><b>→</b><span>{t("portForward.sshRelay")}</span><b>→</b><span>{editor.type === "dynamic" ? t("portForward.internet") : t("portForward.destination")}</span>
              </div>
              <div className="saved-host-fields">
                <p className="host-editor-section-title">{t("portForward.forwardingType")}</p>
                <div className="port-forward-type-picker">
                  {(["local", "remote", "dynamic"] as const).map((type) => (
                    <button
                      type="button"
                      className={editor.type === type ? "active" : ""}
                      disabled={mutationPending}
                      onClick={() => setEditor((current) => current ? {
                        ...current,
                        type,
                        localPort: current.localPort || (type === "dynamic" ? "1080" : "8080"),
                      } : current)}
                      key={type}
                    >
                      <strong>{typeLabel(type, t)}</strong>
                      <small>{type === "dynamic" ? "SOCKS5" : "TCP"}</small>
                    </button>
                  ))}
                </div>
                <p className="port-forward-type-description">{typeDescription(editor.type, t)}</p>

                <p className="host-editor-section-title">{t("portForward.rule")}</p>
                <label>
                  {t("portForward.label")} <small className="host-editor-field-hint">{t("portForward.labelOptional")}</small>
                  <input autoFocus value={editor.label} maxLength={256} disabled={mutationPending} onChange={(event) => setEditor((current) => current ? { ...current, label: event.target.value } : current)} />
                </label>
                <div className="field-row">
                  <label>
                    {editor.type === "remote" ? t("portForward.remoteBindAddress") : t("portForward.bindAddress")}
                    <input value={editor.bindAddress} maxLength={253} spellCheck={false} disabled={mutationPending} onChange={(event) => setEditor((current) => current ? { ...current, bindAddress: event.target.value } : current)} />
                  </label>
                  <label>
                    {editor.type === "remote" ? t("portForward.remotePort") : editor.type === "dynamic" ? t("portForward.socksPort") : t("portForward.localPort")}
                    <input type="number" min="1" max="65535" value={editor.localPort} disabled={mutationPending} onChange={(event) => setEditor((current) => current ? { ...current, localPort: event.target.value } : current)} />
                  </label>
                </div>

                {editor.type !== "dynamic" && (
                  <>
                    <p className="host-editor-section-title">{t("portForward.destination")}</p>
                    <div className="field-row">
                      <label>
                        {t("portForward.destinationHost")}
                        <input value={editor.remoteHost} maxLength={253} spellCheck={false} disabled={mutationPending} placeholder="127.0.0.1" onChange={(event) => setEditor((current) => current ? { ...current, remoteHost: event.target.value } : current)} />
                      </label>
                      <label>
                        {t("portForward.destinationPort")}
                        <input type="number" min="1" max="65535" value={editor.remotePort} disabled={mutationPending} placeholder="3306" onChange={(event) => setEditor((current) => current ? { ...current, remotePort: event.target.value } : current)} />
                      </label>
                    </div>
                  </>
                )}

                <p className="host-editor-section-title">{t("portForward.sshRelay")}</p>
                <label>
                  {t("portForward.savedHost")}
                  <select value={editor.hostId} required disabled={mutationPending || hosts.length === 0} onChange={(event) => setEditor((current) => current ? { ...current, hostId: event.target.value } : current)}>
                    <option value="">{t("portForward.selectHost")}</option>
                    {hosts.map((host) => <option value={host.id} key={host.id}>{host.label} · {host.username}@{host.hostname}:{host.port}</option>)}
                  </select>
                </label>
                {hosts.length === 0 && <p className="connection-error">{t("portForward.createSshHostFirst")}</p>}
                <label className="remove-credential-option port-forward-auto-start">
                  <input type="checkbox" checked={editor.autoStart} disabled={mutationPending} onChange={(event) => setEditor((current) => current ? { ...current, autoStart: event.target.checked } : current)} />
                  <span><strong>{t("portForward.autoStart")}</strong><small>{t("portForward.autoStartDescription")}</small></span>
                </label>
              </div>
              {error && <p className="connection-error" role="alert">{error}</p>}
            </div>
            <div className="dialog-actions">
              <button type="button" disabled={mutationPending} onClick={() => { setEditor(null); setError(null); }}>{t("portForward.cancel")}</button>
              <button className="primary-button" type="submit" disabled={actionsDisabled || hosts.length === 0}>{mutationPending ? t("portForward.saving") : t("portForward.save")}</button>
            </div>
          </form>
        </div>
      )}

      {deletePrompt && (
        <div className="dialog-backdrop" role="presentation">
          <div className="trust-dialog saved-host-dialog password-identity-dialog" role="dialog" aria-modal="true" aria-labelledby="port-forward-delete-title">
            <p className="eyebrow">{t("portForward.deleteKicker")}</p>
            <h2 id="port-forward-delete-title">{t("portForward.deleteTitle")}</h2>
            <p>{t("portForward.deleteDescription", { rule: deletePrompt.label })}</p>
            {error && <p className="connection-error" role="alert">{error}</p>}
            <div className="dialog-actions">
              <button type="button" disabled={mutationPending} onClick={() => { setDeletePrompt(null); setError(null); }}>{t("portForward.cancel")}</button>
              <button className="danger-button" type="button" disabled={actionsDisabled} onClick={() => void confirmDelete()}>{mutationPending ? t("portForward.deleting") : t("portForward.confirmDelete")}</button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
};

export default PortForwardingCatalog;
