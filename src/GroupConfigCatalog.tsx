import {
  createContext,
  type FormEvent,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  createGroupConfig,
  deleteGroupConfig,
  listGroupConfigs,
  stageGroupProxyPassword,
  stageGroupSshPassword,
  stageGroupTelnetPassword,
  updateGroupConfig,
  type GroupConfig,
  type GroupConfigCatalog as GroupConfigCatalogSnapshot,
  type GroupConfigCredentialMutation,
  type GroupConfigDefaultsRequest,
  type GroupConfigOverride,
  type GroupConfigProxyOverride,
  type ManagedSshKey,
  type PasswordIdentity,
  type ProxyProfile,
  type SavedHost,
} from "./backend";
import { buildGroupTree, groupPathSegments, type GroupTreeNode } from "./groupTree";
import {
  classifyGroupConfigError,
  editableGroupDefaults,
  normalizeGroupConfigPath,
  resolveEffectiveGroupDefaults,
} from "./groupConfigUi";
import { createTranslator, type Locale, type Translate, useI18n } from "./i18n";
import { WindowControlGlyph } from "./WindowControlGlyph";

type CredentialAction = "keep" | "remove" | "replace";
type ProxyCommandAction = "keep" | "replace";
type EditableProxyOverride = NonNullable<GroupConfigDefaultsRequest["proxy"]>;
type EditableInlineProxy = Extract<EditableProxyOverride, { state: "inline" }>;
type EditableNetworkProxy = Exclude<EditableInlineProxy["value"], { type: "command" }>;

type GroupEditor = {
  mode: "create" | "update";
  id?: string;
  expectedRevision?: number;
  expectedInventoryRevision: unknown;
  original?: GroupConfig;
  path: string;
  defaults: GroupConfigDefaultsRequest;
  sshCredentialAction: CredentialAction;
  sshPassword: string;
  telnetCredentialAction: CredentialAction;
  telnetPassword: string;
  proxyCredentialAction: CredentialAction;
  proxyPassword: string;
  proxyCommandAction: ProxyCommandAction;
  proxyCommand: string;
  canKeepProxyCommand: boolean;
  sshPasswordStored: boolean;
  telnetPasswordStored: boolean;
  proxyPasswordStored: boolean;
};

type DeletePrompt = {
  id: string;
  label: string;
  expectedRevision: number;
  expectedInventoryRevision: unknown;
};

export type GroupConfigCatalogProps = {
  open: boolean;
  onClose: () => void;
  locale?: Locale;
  hosts: SavedHost[];
  managedKeys: ManagedSshKey[];
  passwordIdentities: PasswordIdentity[];
  proxyProfiles: ProxyProfile[];
  disabled?: boolean;
  nativeRuntimeAvailable?: boolean;
  refreshKey?: string | number;
  initialPath?: string | null;
  onCatalogChange?: (catalog: GroupConfigCatalogSnapshot) => void;
};

const EMPTY_CATALOG: GroupConfigCatalogSnapshot = {
  inventoryRevision: null,
  customGroups: [],
  groups: [],
};

const GroupConfigTranslationContext = createContext<Translate>(createTranslator("zh-CN"));

const GroupGlyph = () => (
  <svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <path d="M3 6h7l2 2h9v11H3z" />
  </svg>
);

type OverrideFrameProps = {
  label: string;
  state: "inherit" | "clear" | "set";
  onStateChange: (state: "inherit" | "clear" | "set") => void;
  disabled: boolean;
  hint?: string;
  children?: ReactNode;
};

const OverrideFrame = ({
  label,
  state,
  onStateChange,
  disabled,
  hint,
  children,
}: OverrideFrameProps) => {
  const t = useContext(GroupConfigTranslationContext);
  return (
    <div className={`group-override-field state-${state}`}>
      <label>
        <span>{label}{hint && <small>{hint}</small>}</span>
        <select value={state} disabled={disabled} onChange={(event) => onStateChange(event.target.value as OverrideFrameProps["state"])}>
          <option value="inherit">{t("groupConfig.override.inherit")}</option>
          <option value="clear">{t("groupConfig.override.clear")}</option>
          <option value="set">{t("groupConfig.override.set")}</option>
        </select>
      </label>
      {state === "set" && children}
    </div>
  );
};

type TextOverrideProps = {
  label: string;
  override: GroupConfigOverride<string>;
  onChange: (value: GroupConfigOverride<string>) => void;
  disabled: boolean;
  fallback?: string;
  placeholder?: string;
  multiline?: boolean;
};

const TextOverride = ({ label, override, onChange, disabled, fallback = "", placeholder, multiline = false }: TextOverrideProps) => (
  <OverrideFrame
    label={label}
    state={override.state}
    disabled={disabled}
    onStateChange={(state) => onChange(state === "set" ? { state, value: override.state === "set" ? override.value : fallback } : { state })}
  >
    {multiline ? (
      <textarea value={override.state === "set" ? override.value : fallback} rows={3} maxLength={32 * 1024} placeholder={placeholder} disabled={disabled} onChange={(event) => onChange({ state: "set", value: event.target.value })} />
    ) : (
      <input value={override.state === "set" ? override.value : fallback} maxLength={32 * 1024} placeholder={placeholder} disabled={disabled} onChange={(event) => onChange({ state: "set", value: event.target.value })} />
    )}
  </OverrideFrame>
);

type NumberOverrideProps = {
  label: string;
  override: GroupConfigOverride<number>;
  onChange: (value: GroupConfigOverride<number>) => void;
  disabled: boolean;
  fallback: number;
  min?: number;
  max?: number;
};

const NumberOverride = ({ label, override, onChange, disabled, fallback, min, max }: NumberOverrideProps) => (
  <OverrideFrame
    label={label}
    state={override.state}
    disabled={disabled}
    onStateChange={(state) => onChange(state === "set" ? { state, value: override.state === "set" ? override.value : fallback } : { state })}
  >
    <input type="number" value={override.state === "set" ? override.value : fallback} min={min} max={max} disabled={disabled} onChange={(event) => onChange({ state: "set", value: Number(event.target.value) })} />
  </OverrideFrame>
);

type BooleanOverrideProps = {
  label: string;
  override: GroupConfigOverride<boolean>;
  onChange: (value: GroupConfigOverride<boolean>) => void;
  disabled: boolean;
  fallback?: boolean;
};

const BooleanOverride = ({ label, override, onChange, disabled, fallback = true }: BooleanOverrideProps) => {
  const t = useContext(GroupConfigTranslationContext);
  return (
    <OverrideFrame
      label={label}
      state={override.state}
      disabled={disabled}
      onStateChange={(state) => onChange(state === "set" ? { state, value: override.state === "set" ? override.value : fallback } : { state })}
    >
      <select value={override.state === "set" ? String(override.value) : String(fallback)} disabled={disabled} onChange={(event) => onChange({ state: "set", value: event.target.value === "true" })}>
        <option value="true">{t("groupConfig.enabled")}</option>
        <option value="false">{t("groupConfig.disabled")}</option>
      </select>
    </OverrideFrame>
  );
};

type SelectOverrideProps<T extends string> = {
  label: string;
  override: GroupConfigOverride<T>;
  onChange: (value: GroupConfigOverride<T>) => void;
  disabled: boolean;
  options: Array<{ value: T; label: string }>;
};

const SelectOverride = <T extends string>({ label, override, onChange, disabled, options }: SelectOverrideProps<T>) => {
  const fallback = options[0]?.value ?? "" as T;
  return (
    <OverrideFrame
      label={label}
      state={override.state}
      disabled={disabled}
      onStateChange={(state) => onChange(state === "set" ? { state, value: override.state === "set" ? override.value : fallback } : { state })}
    >
      <select value={override.state === "set" ? override.value : fallback} disabled={disabled || options.length === 0} onChange={(event) => onChange({ state: "set", value: event.target.value as T })}>
        {options.map((option) => <option value={option.value} key={option.value}>{option.label}</option>)}
      </select>
    </OverrideFrame>
  );
};

const credentialMutation = (
  action: CredentialAction,
  stagedCredentialReference?: string,
): GroupConfigCredentialMutation => {
  if (action === "remove") return { action: "remove" };
  if (action === "replace" && stagedCredentialReference) {
    return { action: "replace", stagedCredentialReference };
  }
  return { action: "keep" };
};

const directOverrideCount = (group: GroupConfig): number => Object.entries(group.defaults)
  .filter(([key, value]) => {
    if (key === "password" || key === "telnetPassword") return value !== "inherit";
    return typeof value === "object" && value !== null && "state" in value && value.state !== "inherit";
  }).length;

const effectiveSummary = (
  path: string,
  groups: GroupConfig[],
  t: Translate,
): Array<[string, string]> => {
  const effective = resolveEffectiveGroupDefaults(path, groups);
  const result: Array<[string, string]> = [];
  if (effective.protocol) result.push([t("groupConfig.summary.protocol"), String(effective.protocol).toUpperCase()]);
  if (effective.username) result.push([t("groupConfig.summary.sshUser"), String(effective.username)]);
  if (effective.port) result.push([t("groupConfig.summary.sshPort"), String(effective.port)]);
  if (effective.telnetPort) result.push([t("groupConfig.summary.telnetPort"), String(effective.telnetPort)]);
  if (effective.password === "storedHint") result.push([t("groupConfig.summary.sshPassword"), t("groupConfig.securelySaved")]);
  if (effective.telnetPassword === "storedHint") result.push([t("groupConfig.summary.telnetPassword"), t("groupConfig.securelySaved")]);
  if (effective.proxy && typeof effective.proxy === "object" && "state" in effective.proxy) {
    const proxy = effective.proxy as GroupConfigProxyOverride;
    result.push([
      t("groupConfig.summary.proxy"),
      proxy.state === "profile"
        ? t("groupConfig.proxy.profile")
        : proxy.state === "inline" ? proxy.value.type.toUpperCase() : t("groupConfig.none"),
    ]);
  }
  return result;
};

export const GroupConfigCatalog = ({
  open,
  onClose,
  locale = "zh-CN",
  hosts,
  managedKeys,
  passwordIdentities,
  proxyProfiles,
  disabled = false,
  nativeRuntimeAvailable = true,
  refreshKey,
  initialPath,
  onCatalogChange,
}: GroupConfigCatalogProps) => {
  const { t } = useI18n(locale);
  const [catalog, setCatalog] = useState<GroupConfigCatalogSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [mutationPending, setMutationPending] = useState(false);
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [editor, setEditor] = useState<GroupEditor | null>(null);
  const [deletePrompt, setDeletePrompt] = useState<DeletePrompt | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const mounted = useRef(true);
  const loadSequence = useRef(0);
  const mutationLock = useRef(false);
  const onCatalogChangeRef = useRef(onCatalogChange);
  const observedRefreshKey = useRef(refreshKey);

  useEffect(() => {
    onCatalogChangeRef.current = onCatalogChange;
  }, [onCatalogChange]);

  const applyCatalog = useCallback((next: GroupConfigCatalogSnapshot) => {
    loadSequence.current += 1;
    if (!mounted.current) return;
    setCatalog(next);
    onCatalogChangeRef.current?.(next);
    setEditor(null);
    setDeletePrompt(null);
  }, []);

  const refreshCatalog = useCallback(async (preserveMessage = false): Promise<boolean> => {
    if (!nativeRuntimeAvailable) {
      if (mounted.current) {
        setCatalog(EMPTY_CATALOG);
        setLoading(false);
        onCatalogChangeRef.current?.(EMPTY_CATALOG);
      }
      return true;
    }
    const sequence = ++loadSequence.current;
    setLoading(true);
    if (!preserveMessage) {
      setError(null);
      setNotice(null);
    }
    try {
      const next = await listGroupConfigs();
      if (!mounted.current || sequence !== loadSequence.current) return false;
      setCatalog(next);
      onCatalogChangeRef.current?.(next);
      return true;
    } catch (reason) {
      if (mounted.current && sequence === loadSequence.current) {
        setError(t(classifyGroupConfigError(reason).messageKey));
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

  useEffect(() => {
    if (Object.is(observedRefreshKey.current, refreshKey)) return;
    observedRefreshKey.current = refreshKey;
    void refreshCatalog();
  }, [refreshCatalog, refreshKey]);

  useEffect(() => {
    if (!open) return;
    if (initialPath) setSelectedPath(initialPath);
    else if (!selectedPath && catalog?.groups[0]) setSelectedPath(catalog.groups[0].path);
  }, [catalog?.groups, initialPath, open, selectedPath]);

  const handleFailure = useCallback(async (reason: unknown) => {
    const issue = classifyGroupConfigError(reason);
    if (issue.refreshCatalog) await refreshCatalog(true);
    if (mounted.current) {
      setError(t(issue.messageKey));
      setNotice(null);
    }
  }, [refreshCatalog, t]);

  const clearEditorSecrets = () => {
    setEditor((current) => current ? {
      ...current,
      sshPassword: "",
      telnetPassword: "",
      proxyPassword: "",
      proxyCommand: "",
    } : current);
  };

  const openCreate = (path = "") => {
    if (!catalog || disabled || mutationPending || !nativeRuntimeAvailable) return;
    const editable = editableGroupDefaults();
    setError(null);
    setNotice(null);
    setEditor({
      mode: "create",
      expectedInventoryRevision: catalog.inventoryRevision,
      path,
      defaults: editable.defaults,
      sshCredentialAction: "keep",
      sshPassword: "",
      telnetCredentialAction: "keep",
      telnetPassword: "",
      proxyCredentialAction: "keep",
      proxyPassword: "",
      proxyCommandAction: "replace",
      proxyCommand: "",
      canKeepProxyCommand: false,
      sshPasswordStored: false,
      telnetPasswordStored: false,
      proxyPasswordStored: false,
    });
  };

  const openUpdate = (group: GroupConfig) => {
    if (!catalog || disabled || mutationPending) return;
    const editable = editableGroupDefaults(group);
    setError(null);
    setNotice(null);
    setEditor({
      mode: "update",
      id: group.id,
      expectedRevision: group.revision,
      expectedInventoryRevision: catalog.inventoryRevision,
      original: group,
      path: group.path,
      defaults: editable.defaults,
      sshCredentialAction: "keep",
      sshPassword: "",
      telnetCredentialAction: "keep",
      telnetPassword: "",
      proxyCredentialAction: "keep",
      proxyPassword: "",
      proxyCommandAction: editable.proxyCommandStored ? "keep" : "replace",
      proxyCommand: "",
      canKeepProxyCommand: editable.proxyCommandStored,
      sshPasswordStored: editable.sshPasswordStored,
      telnetPasswordStored: editable.telnetPasswordStored,
      proxyPasswordStored: editable.proxyPasswordStored,
    });
  };

  const updateDefaults = (patch: Partial<GroupConfigDefaultsRequest>) => {
    setEditor((current) => current ? { ...current, defaults: { ...current.defaults, ...patch } } : current);
  };

  const validateEditor = (snapshot: GroupEditor): string | null => {
    const path = normalizeGroupConfigPath(snapshot.path);
    if (!path) return t("groupConfig.validation.path");
    if (snapshot.mode === "create" && catalog?.groups.some((group) => group.path === path)) {
      return t("groupConfig.validation.duplicate");
    }
    if (snapshot.defaults.port?.state === "set" && (!Number.isInteger(snapshot.defaults.port.value) || snapshot.defaults.port.value < 1 || snapshot.defaults.port.value > 65_535)) return t("groupConfig.validation.sshPort");
    if (snapshot.defaults.telnetPort?.state === "set" && (!Number.isInteger(snapshot.defaults.telnetPort.value) || snapshot.defaults.telnetPort.value < 1 || snapshot.defaults.telnetPort.value > 65_535)) return t("groupConfig.validation.telnetPort");
    if (snapshot.defaults.etPort?.state === "set" && (!Number.isInteger(snapshot.defaults.etPort.value) || snapshot.defaults.etPort.value < 1 || snapshot.defaults.etPort.value > 65_535)) return t("groupConfig.validation.etPort");
    if (
      snapshot.defaults.moshEnabled?.state === "set"
      && snapshot.defaults.moshEnabled.value
      && snapshot.defaults.etEnabled?.state === "set"
      && snapshot.defaults.etEnabled.value
    ) return t("groupConfig.validation.transportConflict");
    const identitySelected = snapshot.defaults.identityId?.state === "set";
    if (identitySelected && snapshot.sshCredentialAction === "replace") return t("groupConfig.validation.sshIdentityPassword");
    if (identitySelected && snapshot.sshPasswordStored && snapshot.sshCredentialAction === "keep") return t("groupConfig.validation.sshIdentityRemove");
    const telnetIdentitySelected = snapshot.defaults.telnetIdentityId?.state === "set";
    if (telnetIdentitySelected && snapshot.telnetCredentialAction === "replace") return t("groupConfig.validation.telnetIdentityPassword");
    if (telnetIdentitySelected && snapshot.telnetPasswordStored && snapshot.telnetCredentialAction === "keep") return t("groupConfig.validation.telnetIdentityRemove");
    if (snapshot.sshCredentialAction === "replace" && !snapshot.sshPassword) return t("groupConfig.validation.sshPassword");
    if (snapshot.telnetCredentialAction === "replace" && !snapshot.telnetPassword) return t("groupConfig.validation.telnetPassword");

    const proxy = snapshot.defaults.proxy;
    const manualNetworkProxy = proxy?.state === "inline"
      && proxy.value.type !== "command"
      && !proxy.value.identityId;
    if (snapshot.proxyCredentialAction === "replace" && (!manualNetworkProxy || !snapshot.proxyPassword)) {
      return t("groupConfig.validation.proxyPassword");
    }
    if (snapshot.proxyPasswordStored && snapshot.proxyCredentialAction === "keep" && !manualNetworkProxy) {
      return t("groupConfig.validation.proxyRemove");
    }
    if (proxy?.state === "inline" && proxy.value.type !== "command") {
      if (!proxy.value.host.trim() || proxy.value.port < 1 || proxy.value.port > 65_535) return t("groupConfig.validation.proxyAddress");
    }
    if (proxy?.state === "inline" && proxy.value.type === "command") {
      if (snapshot.proxyCommandAction === "keep" && !snapshot.canKeepProxyCommand) return t("groupConfig.validation.proxyCommand");
      if (snapshot.proxyCommandAction === "replace" && !snapshot.proxyCommand.trim()) return t("groupConfig.validation.proxyCommand");
    }
    return null;
  };

  const submitEditor = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const snapshot = editor;
    if (!snapshot || disabled || mutationLock.current || !nativeRuntimeAvailable) return;
    const validationError = validateEditor(snapshot);
    if (validationError) {
      setError(validationError);
      return;
    }
    const path = normalizeGroupConfigPath(snapshot.path)!;
    const defaults = JSON.parse(JSON.stringify(snapshot.defaults)) as GroupConfigDefaultsRequest;
    const proxyCommandMutation = defaults.proxy?.state === "inline" && defaults.proxy.value.type === "command"
      ? snapshot.proxyCommandAction === "keep"
        ? { action: "keep" as const }
        : { action: "replace" as const, command: snapshot.proxyCommand.trim() }
      : undefined;

    mutationLock.current = true;
    loadSequence.current += 1;
    setMutationPending(true);
    setError(null);
    setNotice(null);
    let sshSecret = snapshot.sshPassword;
    let telnetSecret = snapshot.telnetPassword;
    let proxySecret = snapshot.proxyPassword;
    try {
      clearEditorSecrets();
      const sshReference = snapshot.sshCredentialAction === "replace"
        ? await stageGroupSshPassword(sshSecret)
        : undefined;
      sshSecret = "";
      const telnetReference = snapshot.telnetCredentialAction === "replace"
        ? await stageGroupTelnetPassword(telnetSecret)
        : undefined;
      telnetSecret = "";
      const proxyReference = snapshot.proxyCredentialAction === "replace"
        ? await stageGroupProxyPassword(proxySecret)
        : undefined;
      proxySecret = "";

      const credentialMutations = {
        sshPassword: credentialMutation(snapshot.sshCredentialAction, sshReference),
        telnetPassword: credentialMutation(snapshot.telnetCredentialAction, telnetReference),
        proxyPassword: credentialMutation(snapshot.proxyCredentialAction, proxyReference),
      };
      const metadata = { path, defaults, ...(proxyCommandMutation ? { proxyCommandMutation } : {}) };
      const next = snapshot.mode === "create"
        ? await createGroupConfig({
          expectedInventoryRevision: snapshot.expectedInventoryRevision,
          metadata,
          credentialMutations,
        })
        : await updateGroupConfig({
          id: snapshot.id!,
          expectedRevision: snapshot.expectedRevision!,
          expectedInventoryRevision: snapshot.expectedInventoryRevision,
          metadata,
          credentialMutations,
        });
      applyCatalog(next);
      setSelectedPath(path);
      setNotice(t(snapshot.mode === "create"
        ? "groupConfig.notice.created"
        : "groupConfig.notice.updated"));
    } catch (reason) {
      await handleFailure(reason);
    } finally {
      sshSecret = "";
      telnetSecret = "";
      proxySecret = "";
      mutationLock.current = false;
      if (mounted.current) {
        setMutationPending(false);
        clearEditorSecrets();
      }
    }
  };

  const confirmDelete = async () => {
    const prompt = deletePrompt;
    if (!prompt || disabled || mutationLock.current || !nativeRuntimeAvailable) return;
    mutationLock.current = true;
    loadSequence.current += 1;
    setMutationPending(true);
    setError(null);
    setNotice(null);
    try {
      const next = await deleteGroupConfig({
        id: prompt.id,
        expectedRevision: prompt.expectedRevision,
        expectedInventoryRevision: prompt.expectedInventoryRevision,
      });
      applyCatalog(next);
      setSelectedPath(null);
      setNotice(t("groupConfig.notice.deleted", { group: prompt.label }));
    } catch (reason) {
      await handleFailure(reason);
    } finally {
      mutationLock.current = false;
      if (mounted.current) setMutationPending(false);
    }
  };

  const groups = catalog?.groups ?? [];
  const customGroups = catalog?.customGroups ?? [];
  const customGroupPaths = useMemo(() => new Set(customGroups), [customGroups]);
  const groupByPath = useMemo(() => new Map(groups.map((group) => [group.path, group])), [groups]);
  const tree = useMemo(() => buildGroupTree({
    explicitGroups: [...customGroups, ...groups.map((group) => group.path)],
    groupConfigs: groups.map((group) => ({
      path: group.path,
      order: group.defaults.order.state === "set" ? group.defaults.order.value : undefined,
    })),
    hosts,
  }), [customGroups, groups, hosts]);
  const flattenedGroups = useMemo(() => {
    const rows: Array<{ node: GroupTreeNode<SavedHost>; depth: number }> = [];
    const walk = (node: GroupTreeNode<SavedHost>, depth: number) => {
      rows.push({ node, depth });
      node.children.forEach((child) => walk(child, depth + 1));
    };
    tree.roots.forEach((node) => walk(node, 0));
    return rows;
  }, [tree.roots]);
  const selectedGroup = selectedPath ? groupByPath.get(selectedPath) : undefined;
  const selectedSummary = selectedPath ? effectiveSummary(selectedPath, groups, t) : [];
  const actionsDisabled = disabled || mutationPending || loading;
  const editorProxy = editor?.defaults.proxy;
  const editorInlineProxy = editorProxy?.state === "inline" ? editorProxy : undefined;
  const editorNetworkProxy = editorInlineProxy?.value.type !== "command"
    ? editorInlineProxy?.value as EditableNetworkProxy | undefined
    : undefined;

  const renderCredentialEditor = (
    kind: "ssh" | "telnet" | "proxy",
    action: CredentialAction,
    stored: boolean,
    password: string,
  ) => {
    const setAction = (next: CredentialAction) => setEditor((current) => current ? {
      ...current,
      [`${kind}CredentialAction`]: next,
      [`${kind}Password`]: "",
    } as GroupEditor : current);
    const setPassword = (value: string) => setEditor((current) => current ? {
      ...current,
      [`${kind}Password`]: value,
    } as GroupEditor : current);
    return (
      <div className="group-credential-editor">
        <label>
          <span>
            {t(kind === "ssh"
              ? "groupConfig.credential.sshPassword"
              : kind === "telnet"
                ? "groupConfig.credential.telnetPassword"
                : "groupConfig.credential.proxyPassword")}
            <small>{t(stored
              ? "groupConfig.credential.stored"
              : "groupConfig.credential.notStored")}</small>
          </span>
          <select value={action} disabled={mutationPending} onChange={(event) => setAction(event.target.value as CredentialAction)}>
            <option value="keep">{t("groupConfig.credential.keep")}</option>
            <option value="remove">{t("groupConfig.credential.remove")}</option>
            <option value="replace">{t("groupConfig.credential.replace")}</option>
          </select>
        </label>
        {action === "replace" && (
          <input
            type="password"
            value={password}
            autoComplete="new-password"
            placeholder={t("groupConfig.credential.passwordPlaceholder")}
            disabled={mutationPending}
            onChange={(event) => setPassword(event.target.value)}
          />
        )}
      </div>
    );
  };

  if (!open) return null;

  return (
    <GroupConfigTranslationContext.Provider value={t}>
    <div className="dialog-backdrop group-config-backdrop" role="presentation">
      <section className="group-config-manager" role="dialog" aria-modal="true" aria-labelledby="group-config-title" aria-busy={loading || mutationPending}>
        <header className="group-config-manager-header">
          <div>
            <span className="saved-host-details-kicker">{t("groupConfig.kicker")}</span>
            <h2 id="group-config-title">{t("groupConfig.title")}</h2>
          </div>
          <div>
            <button type="button" disabled={actionsDisabled || !nativeRuntimeAvailable} onClick={() => void refreshCatalog()}>
              {t(loading ? "groupConfig.refreshing" : "groupConfig.refresh")}
            </button>
            <button className="primary-button" type="button" disabled={actionsDisabled || !catalog || !nativeRuntimeAvailable} onClick={() => openCreate()}>
              {t("groupConfig.newGroup")}
            </button>
            <button type="button" aria-label={t("groupConfig.close")} disabled={mutationPending} onClick={onClose}>
              <WindowControlGlyph name="close" />
            </button>
          </div>
        </header>

        <div className="group-config-manager-body">
          <aside className="group-config-tree-panel">
            <div className="group-config-tree-heading">
              <strong>{t("groupConfig.groups")}</strong><span>{flattenedGroups.length}</span>
            </div>
            {loading && !catalog && <p className="saved-host-empty">{t("groupConfig.loading")}</p>}
            {!loading && flattenedGroups.length === 0 && (
              <div className="group-config-empty-list">
                <span><GroupGlyph /></span>
                <p>{t("groupConfig.emptyList")}</p>
              </div>
            )}
            <div className="group-config-tree-list">
              {flattenedGroups.map(({ node, depth }) => {
                const configured = groupByPath.has(node.path);
                const savedCustomGroup = customGroupPaths.has(node.path);
                return (
                  <button
                    type="button"
                    className={selectedPath === node.path ? "active" : ""}
                    style={{ paddingLeft: `${12 + depth * 17}px` }}
                    onClick={() => { setSelectedPath(node.path); setEditor(null); setError(null); }}
                    key={node.path}
                  >
                    <GroupGlyph />
                    <span>
                      <strong>{node.name}</strong>
                      <small>{configured
                        ? t("groupConfig.tree.directDefaults", {
                          count: directOverrideCount(groupByPath.get(node.path)!),
                        })
                        : t(savedCustomGroup
                          ? "groupConfig.tree.savedGroup"
                          : "groupConfig.tree.inheritedOnly")}</small>
                    </span>
                    <i>{node.totalHostCount}</i>
                  </button>
                );
              })}
            </div>
          </aside>

          <main className="group-config-content">
            {error && <p className="connection-error group-config-message" role="alert">{error}</p>}
            {notice && <p className="saved-host-success group-config-message" role="status">{notice}</p>}

            {editor ? (
              <form className="group-config-editor" onSubmit={(event) => void submitEditor(event)}>
                <header>
                  <div>
                    <span>{t(editor.mode === "create"
                      ? "groupConfig.editor.newKicker"
                      : "groupConfig.editor.editKicker")}</span>
                    <h3>{editor.mode === "create" ? t("groupConfig.editor.createTitle") : editor.path}</h3>
                  </div>
                  <button type="button" disabled={mutationPending} onClick={() => { clearEditorSecrets(); setEditor(null); setError(null); }}>
                    {t("groupConfig.cancel")}
                  </button>
                </header>
                <div className="group-config-editor-scroll">
                  <label className="group-config-path-field">
                    {t("groupConfig.editor.path")}
                    <input value={editor.path} autoFocus={editor.mode === "create"} disabled={mutationPending || editor.mode === "update"} placeholder={t("groupConfig.editor.pathPlaceholder")} onChange={(event) => setEditor((current) => current ? { ...current, path: event.target.value } : current)} />
                    <small>{t("groupConfig.editor.pathHint")}</small>
                  </label>

                  <details open>
                    <summary>{t("groupConfig.section.general")}</summary>
                    <div className="group-config-section-grid">
                      <NumberOverride label={t("groupConfig.field.order")} override={editor.defaults.order!} fallback={1000} disabled={mutationPending} onChange={(order) => updateDefaults({ order })} />
                      <SelectOverride label={t("groupConfig.field.protocol")} override={editor.defaults.protocol!} disabled={mutationPending} options={[{ value: "ssh", label: "SSH" }, { value: "telnet", label: "Telnet" }]} onChange={(protocol) => updateDefaults({ protocol })} />
                      <SelectOverride label={t("groupConfig.field.deviceType")} override={editor.defaults.deviceType!} disabled={mutationPending} options={[{ value: "general", label: t("groupConfig.option.general") }, { value: "network", label: t("groupConfig.option.networkDevice") }]} onChange={(deviceType) => updateDefaults({ deviceType })} />
                      <NumberOverride label={t("groupConfig.field.defaultPort")} override={editor.defaults.port!} fallback={22} min={1} max={65535} disabled={mutationPending} onChange={(port) => updateDefaults({ port })} />
                      <TextOverride label={t("groupConfig.field.charset")} override={editor.defaults.charset!} fallback="utf-8" disabled={mutationPending} onChange={(charset) => updateDefaults({ charset })} />
                    </div>
                  </details>

                  <details open>
                    <summary>{t("groupConfig.section.ssh")}</summary>
                    <div className="group-config-section-grid">
                      <TextOverride label={t("groupConfig.field.username")} override={editor.defaults.username!} placeholder="root" disabled={mutationPending} onChange={(username) => updateDefaults({ username })} />
                      <SelectOverride label={t("groupConfig.field.authMethod")} override={editor.defaults.authMethod!} disabled={mutationPending} options={[{ value: "auto", label: t("groupConfig.auth.auto") }, { value: "password", label: t("groupConfig.auth.password") }, { value: "key", label: t("groupConfig.auth.privateKey") }, { value: "certificate", label: t("groupConfig.auth.certificate") }]} onChange={(authMethod) => updateDefaults({ authMethod })} />
                      <BooleanOverride label={t("groupConfig.field.savePassword")} override={editor.defaults.savePassword!} disabled={mutationPending} onChange={(savePassword) => updateDefaults({ savePassword })} />
                      <BooleanOverride label={t("groupConfig.field.agentForwarding")} override={editor.defaults.agentForwarding!} disabled={mutationPending} onChange={(agentForwarding) => updateDefaults({ agentForwarding })} />
                    </div>
                    <div className="group-config-reference-row">
                      <OverrideFrame label={t("groupConfig.field.passwordIdentity")} state={editor.defaults.identityId!.state} disabled={mutationPending} onStateChange={(state) => {
                        const current = editor.defaults.identityId!;
                        const identityId = state === "set" ? { state, value: current.state === "set" ? current.value : { type: "password" as const, id: passwordIdentities[0]?.id ?? "" } } : { state };
                        updateDefaults({ identityId, ...(state === "set" ? { identityFileId: { state: "inherit" } } : {}) });
                        if (state === "set" && editor.sshPasswordStored) setEditor((value) => value ? { ...value, sshCredentialAction: "remove" } : value);
                      }}>
                        <select value={editor.defaults.identityId!.state === "set" ? editor.defaults.identityId!.value.id : ""} disabled={mutationPending || passwordIdentities.length === 0} onChange={(event) => updateDefaults({ identityId: { state: "set", value: { type: "password", id: event.target.value } } })}>
                          {editor.defaults.identityId!.state === "set" && editor.defaults.identityId!.value.type === "key" && <option value={editor.defaults.identityId!.value.id}>{t("groupConfig.existingKeyIdentity")} · {editor.defaults.identityId!.value.id}</option>}
                          {passwordIdentities.map((identity) => <option value={identity.id} key={identity.id}>{identity.label}{identity.username ? ` · ${identity.username}` : ""}</option>)}
                        </select>
                      </OverrideFrame>
                      <OverrideFrame label={t("groupConfig.field.managedKey")} state={editor.defaults.identityFileId!.state} disabled={mutationPending} onStateChange={(state) => {
                        const current = editor.defaults.identityFileId!;
                        const identityFileId = state === "set" ? { state, value: current.state === "set" ? current.value : managedKeys[0]?.id ?? "" } : { state };
                        updateDefaults({ identityFileId, ...(state === "set" ? { identityId: { state: "inherit" } } : {}) });
                      }}>
                        <select value={editor.defaults.identityFileId!.state === "set" ? editor.defaults.identityFileId!.value : ""} disabled={mutationPending || managedKeys.length === 0} onChange={(event) => updateDefaults({ identityFileId: { state: "set", value: event.target.value } })}>
                          {managedKeys.map((key) => <option value={key.id} key={key.id}>{key.label} · {t(key.category === "key" ? "groupConfig.managedKey.key" : "groupConfig.managedKey.certificate")}</option>)}
                        </select>
                      </OverrideFrame>
                    </div>
                    <div className="group-credential-state-row">
                      <label><span>{t("groupConfig.afterPasswordRemoval")}</span><select value={editor.defaults.password ?? "inherit"} disabled={mutationPending} onChange={(event) => updateDefaults({ password: event.target.value as "inherit" | "clear" })}><option value="inherit">{t("groupConfig.inheritParent")}</option><option value="clear">{t("groupConfig.clearParentPassword")}</option></select></label>
                      {renderCredentialEditor("ssh", editor.sshCredentialAction, editor.sshPasswordStored, editor.sshPassword)}
                    </div>
                  </details>

                  <details>
                    <summary>{t("groupConfig.section.jumpStartup")}</summary>
                    <OverrideFrame label={t("groupConfig.field.hostChain")} state={editor.defaults.hostChain!.state} disabled={mutationPending} onStateChange={(state) => updateDefaults({ hostChain: state === "set" ? { state, value: editor.defaults.hostChain!.state === "set" ? editor.defaults.hostChain!.value : [] } : { state } })}>
                      <div className="group-host-chain-picker">
                        {hosts.map((host) => {
                          const selected = editor.defaults.hostChain!.state === "set" && editor.defaults.hostChain!.value.includes(host.id);
                          return <label key={host.id}><input type="checkbox" checked={selected} disabled={mutationPending} onChange={(event) => {
                            const current = editor.defaults.hostChain!.state === "set" ? editor.defaults.hostChain!.value : [];
                            updateDefaults({ hostChain: { state: "set", value: event.target.checked ? [...current, host.id] : current.filter((id) => id !== host.id) } });
                          }} /><span>{host.label}<small>{host.username}@{host.hostname}:{host.port}</small></span></label>;
                        })}
                        {hosts.length === 0 && <p>{t("groupConfig.noSavedHosts")}</p>}
                      </div>
                    </OverrideFrame>
                    <div className="group-config-section-grid">
                      <TextOverride label={t("groupConfig.field.startupCommand")} override={editor.defaults.startupCommand!} multiline disabled={mutationPending} onChange={(startupCommand) => updateDefaults({ startupCommand })} />
                      <SelectOverride label={t("groupConfig.field.startupRunMode")} override={editor.defaults.startupCommandRunMode!} disabled={mutationPending} options={[{ value: "lineDelay", label: t("groupConfig.runMode.lineDelay") }, { value: "paste", label: t("groupConfig.runMode.paste") }]} onChange={(startupCommandRunMode) => updateDefaults({ startupCommandRunMode })} />
                      <BooleanOverride label={t("groupConfig.field.legacyAlgorithms")} override={editor.defaults.legacyAlgorithms!} disabled={mutationPending} onChange={(legacyAlgorithms) => updateDefaults({ legacyAlgorithms })} />
                      <BooleanOverride label={t("groupConfig.field.skipEcdsa")} override={editor.defaults.skipEcdsaHostKey!} disabled={mutationPending} onChange={(skipEcdsaHostKey) => updateDefaults({ skipEcdsaHostKey })} />
                      <BooleanOverride label="Mosh" override={editor.defaults.moshEnabled!} disabled={mutationPending} onChange={(moshEnabled) => updateDefaults({
                        moshEnabled,
                        ...(moshEnabled.state === "set" && moshEnabled.value
                          ? { etEnabled: { state: "set", value: false } }
                          : {}),
                      })} />
                      <TextOverride label={t("groupConfig.field.moshServerPath")} override={editor.defaults.moshServerPath!} disabled={mutationPending} onChange={(moshServerPath) => updateDefaults({ moshServerPath })} />
                      <BooleanOverride label="Eternal Terminal" override={editor.defaults.etEnabled!} disabled={mutationPending} onChange={(etEnabled) => updateDefaults({
                        etEnabled,
                        ...(etEnabled.state === "set" && etEnabled.value
                          ? { moshEnabled: { state: "set", value: false } }
                          : {}),
                      })} />
                      <NumberOverride label={t("groupConfig.field.etPort")} override={editor.defaults.etPort!} fallback={2022} min={1} max={65535} disabled={mutationPending} onChange={(etPort) => updateDefaults({ etPort })} />
                    </div>
                  </details>

                  <details open>
                    <summary>{t("groupConfig.section.telnet")}</summary>
                    <div className="group-config-section-grid">
                      <BooleanOverride label={t("groupConfig.field.telnetEnabled")} override={editor.defaults.telnetEnabled!} disabled={mutationPending} onChange={(telnetEnabled) => updateDefaults({ telnetEnabled })} />
                      <NumberOverride label={t("groupConfig.field.telnetPort")} override={editor.defaults.telnetPort!} fallback={23} min={1} max={65535} disabled={mutationPending} onChange={(telnetPort) => updateDefaults({ telnetPort })} />
                      <TextOverride label={t("groupConfig.field.telnetUsername")} override={editor.defaults.telnetUsername!} disabled={mutationPending} onChange={(telnetUsername) => updateDefaults({ telnetUsername })} />
                      <OverrideFrame label={t("groupConfig.field.telnetIdentity")} state={editor.defaults.telnetIdentityId!.state} disabled={mutationPending} onStateChange={(state) => {
                        const current = editor.defaults.telnetIdentityId!;
                        updateDefaults({ telnetIdentityId: state === "set" ? { state, value: current.state === "set" ? current.value : passwordIdentities[0]?.id ?? "" } : { state } });
                        if (state === "set" && editor.telnetPasswordStored) setEditor((value) => value ? { ...value, telnetCredentialAction: "remove" } : value);
                      }}>
                        <select value={editor.defaults.telnetIdentityId!.state === "set" ? editor.defaults.telnetIdentityId!.value : ""} disabled={mutationPending || passwordIdentities.length === 0} onChange={(event) => updateDefaults({ telnetIdentityId: { state: "set", value: event.target.value } })}>
                          {passwordIdentities.map((identity) => <option value={identity.id} key={identity.id}>{identity.label}{identity.username ? ` · ${identity.username}` : ""}</option>)}
                        </select>
                      </OverrideFrame>
                    </div>
                    <div className="group-credential-state-row">
                      <label><span>{t("groupConfig.afterPasswordRemoval")}</span><select value={editor.defaults.telnetPassword ?? "inherit"} disabled={mutationPending} onChange={(event) => updateDefaults({ telnetPassword: event.target.value as "inherit" | "clear" })}><option value="inherit">{t("groupConfig.inheritParent")}</option><option value="clear">{t("groupConfig.clearParentPassword")}</option></select></label>
                      {renderCredentialEditor("telnet", editor.telnetCredentialAction, editor.telnetPasswordStored, editor.telnetPassword)}
                    </div>
                  </details>

                  <details open>
                    <summary>{t("groupConfig.section.proxy")}</summary>
                    <div className="group-proxy-state-row">
                      <label><span>{t("groupConfig.proxy.state")}</span><select value={editor.defaults.proxy?.state ?? "inherit"} disabled={mutationPending} onChange={(event) => {
                        const state = event.target.value as EditableProxyOverride["state"];
                        let proxy: EditableProxyOverride;
                        if (state === "profile") proxy = { state, value: proxyProfiles[0]?.id ?? "" };
                        else if (state === "inline") proxy = { state, value: { type: "http", host: "", port: 8080, username: "", hasSavedCredential: false } };
                        else proxy = { state };
                        updateDefaults({ proxy });
                        if (editor.proxyPasswordStored && state !== "inline") setEditor((value) => value ? { ...value, proxyCredentialAction: "remove" } : value);
                      }}><option value="inherit">{t("groupConfig.override.inherit")}</option><option value="clear">{t("groupConfig.override.clear")}</option><option value="profile">{t("groupConfig.proxy.profile")}</option><option value="inline">{t("groupConfig.proxy.inline")}</option></select></label>
                      {editor.defaults.proxy?.state === "profile" && <label><span>{t("groupConfig.proxy.profile")}</span><select value={editor.defaults.proxy.value} disabled={mutationPending || proxyProfiles.length === 0} onChange={(event) => updateDefaults({ proxy: { state: "profile", value: event.target.value } })}>{proxyProfiles.map((profile) => <option value={profile.id} key={profile.id}>{profile.label} · {profile.config.type.toUpperCase()}</option>)}</select></label>}
                    </div>
                    {editorInlineProxy && (
                      <div className="group-inline-proxy-editor">
                        <label><span>{t("groupConfig.proxy.type")}</span><select value={editorInlineProxy.value.type} disabled={mutationPending} onChange={(event) => {
                          const type = event.target.value as "http" | "socks5" | "command";
                          const proxy = type === "command" ? { state: "inline" as const, value: { type } } : { state: "inline" as const, value: { type, host: "", port: 8080, username: "", hasSavedCredential: false as const } };
                          updateDefaults({ proxy });
                          setEditor((current) => current ? { ...current, proxyPassword: "", proxyCommand: "", proxyCommandAction: type === "command" && current.canKeepProxyCommand ? "keep" : "replace", ...(current.proxyPasswordStored && type === "command" ? { proxyCredentialAction: "remove" as const } : {}) } : current);
                        }}><option value="http">HTTP</option><option value="socks5">SOCKS5</option><option value="command">{t("groupConfig.proxy.command")}</option></select></label>
                        {editorInlineProxy.value.type === "command" ? (
                          <>
                            <label><span>{t("groupConfig.proxy.commandAction")}</span><select value={editor.proxyCommandAction} disabled={mutationPending} onChange={(event) => setEditor((current) => current ? { ...current, proxyCommandAction: event.target.value as ProxyCommandAction, proxyCommand: "" } : current)}>{editor.canKeepProxyCommand && <option value="keep">{t("groupConfig.proxy.keepExisting")}</option>}<option value="replace">{t("groupConfig.credential.replace")}</option></select></label>
                            {editor.proxyCommandAction === "replace" && <label className="wide"><span>{t("groupConfig.proxy.command")}</span><textarea value={editor.proxyCommand} rows={3} disabled={mutationPending} onChange={(event) => setEditor((current) => current ? { ...current, proxyCommand: event.target.value } : current)} /></label>}
                          </>
                        ) : (
                          <>
                            <label><span>{t("groupConfig.proxy.host")}</span><input value={editorNetworkProxy!.host} disabled={mutationPending} onChange={(event) => updateDefaults({ proxy: { state: "inline", value: { ...editorNetworkProxy!, host: event.target.value } } })} /></label>
                            <label><span>{t("groupConfig.proxy.port")}</span><input type="number" min="1" max="65535" value={editorNetworkProxy!.port} disabled={mutationPending} onChange={(event) => updateDefaults({ proxy: { state: "inline", value: { ...editorNetworkProxy!, port: Number(event.target.value) } } })} /></label>
                            <label><span>{t("groupConfig.proxy.auth")}</span><select value={editorNetworkProxy!.identityId ? "identity" : "manual"} disabled={mutationPending} onChange={(event) => {
                              const current = editorNetworkProxy!;
                              const value = event.target.value === "identity" ? { ...current, identityId: passwordIdentities[0]?.id ?? "", username: "", hasSavedCredential: false as const } : { ...current, identityId: undefined, username: "", hasSavedCredential: false as const };
                              updateDefaults({ proxy: { state: "inline", value } });
                              if (editor.proxyPasswordStored && event.target.value === "identity") setEditor((state) => state ? { ...state, proxyCredentialAction: "remove" } : state);
                            }}><option value="manual">{t("groupConfig.proxy.manual")}</option><option value="identity">{t("groupConfig.field.passwordIdentity")}</option></select></label>
                            {editorNetworkProxy!.identityId ? <label><span>{t("groupConfig.proxy.identity")}</span><select value={editorNetworkProxy!.identityId} disabled={mutationPending || passwordIdentities.length === 0} onChange={(event) => updateDefaults({ proxy: { state: "inline", value: { ...editorNetworkProxy!, identityId: event.target.value } } })}>{passwordIdentities.map((identity) => <option value={identity.id} key={identity.id}>{identity.label}</option>)}</select></label> : <label><span>{t("groupConfig.field.username")}</span><input value={editorNetworkProxy!.username} disabled={mutationPending} onChange={(event) => updateDefaults({ proxy: { state: "inline", value: { ...editorNetworkProxy!, username: event.target.value } } })} /></label>}
                          </>
                        )}
                      </div>
                    )}
                    {renderCredentialEditor("proxy", editor.proxyCredentialAction, editor.proxyPasswordStored, editor.proxyPassword)}
                  </details>

                  <details>
                    <summary>{t("groupConfig.section.appearance")}</summary>
                    <div className="group-config-section-grid">
                      <TextOverride label={t("groupConfig.appearance.theme")} override={editor.defaults.theme!} disabled={mutationPending} onChange={(theme) => updateDefaults({ theme })} />
                      <BooleanOverride label={t("groupConfig.appearance.themeOverride")} override={editor.defaults.themeOverride!} disabled={mutationPending} onChange={(themeOverride) => updateDefaults({ themeOverride })} />
                      <TextOverride label={t("groupConfig.appearance.fontFamily")} override={editor.defaults.fontFamily!} disabled={mutationPending} onChange={(fontFamily) => updateDefaults({ fontFamily })} />
                      <BooleanOverride label={t("groupConfig.appearance.fontOverride")} override={editor.defaults.fontFamilyOverride!} disabled={mutationPending} onChange={(fontFamilyOverride) => updateDefaults({ fontFamilyOverride })} />
                      <NumberOverride label={t("groupConfig.appearance.fontSize")} override={editor.defaults.fontSize!} fallback={14} min={6} max={96} disabled={mutationPending} onChange={(fontSize) => updateDefaults({ fontSize })} />
                      <NumberOverride label={t("groupConfig.appearance.fontWeight")} override={editor.defaults.fontWeight!} fallback={400} min={100} max={900} disabled={mutationPending} onChange={(fontWeight) => updateDefaults({ fontWeight })} />
                    </div>
                  </details>

                  <p className="security-note group-config-security-note">{t("groupConfig.securityNote")}</p>
                </div>
                <footer><button type="button" disabled={mutationPending} onClick={() => { clearEditorSecrets(); setEditor(null); setError(null); }}>{t("groupConfig.cancel")}</button><button className="primary-button" type="submit" disabled={actionsDisabled}>{t(mutationPending ? "groupConfig.saving" : "groupConfig.save")}</button></footer>
              </form>
            ) : selectedPath ? (
              <section className="group-config-overview">
                <header>
                  <div><span>{t("groupConfig.overview.pathKicker")}</span><h3>{selectedPath}</h3><p>{groupPathSegments(selectedPath).join(" › ")}</p></div>
                  <div>{selectedGroup ? <><button type="button" disabled={actionsDisabled} onClick={() => openUpdate(selectedGroup)}>{t("groupConfig.overview.edit")}</button><button className="saved-host-delete" type="button" disabled={actionsDisabled} onClick={() => catalog && setDeletePrompt({ id: selectedGroup.id, label: selectedGroup.path, expectedRevision: selectedGroup.revision, expectedInventoryRevision: catalog.inventoryRevision })}>{t("groupConfig.overview.delete")}</button></> : <button className="primary-button" type="button" disabled={actionsDisabled || !nativeRuntimeAvailable} onClick={() => openCreate(selectedPath)}>{t("groupConfig.overview.add")}</button>}</div>
                </header>
                <div className="group-inheritance-flow"><span>{t("groupConfig.root")}</span>{groupPathSegments(selectedPath).map((segment, index, segments) => <span className={index === segments.length - 1 ? "active" : ""} key={`${index}-${segment}`}>→ {segment}</span>)}</div>
                <div className="group-effective-defaults"><h4>{t("groupConfig.overview.effective")}</h4>{selectedSummary.length ? <dl>{selectedSummary.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl> : <p>{t("groupConfig.overview.noEffective")}</p>}</div>
                <div className="group-direct-defaults"><h4>{t("groupConfig.overview.direct")}</h4><p>{selectedGroup ? t("groupConfig.overview.directCount", { count: directOverrideCount(selectedGroup) }) : customGroupPaths.has(selectedPath) ? t("groupConfig.overview.savedCustom") : t("groupConfig.overview.implicit")}</p></div>
              </section>
            ) : (
              <div className="group-config-empty-content"><span><GroupGlyph /></span><h3>{t("groupConfig.selectGroup")}</h3><p>{t("groupConfig.selectGroupDescription")}</p></div>
            )}
          </main>
        </div>
      </section>

      {deletePrompt && (
        <div className="dialog-backdrop group-config-delete-backdrop" role="presentation">
          <div className="trust-dialog saved-host-dialog password-identity-dialog" role="dialog" aria-modal="true" aria-labelledby="group-config-delete-title">
            <p className="eyebrow">{t("groupConfig.delete.kicker")}</p>
            <h2 id="group-config-delete-title">{t("groupConfig.delete.title")}</h2>
            <p>{t("groupConfig.delete.description", { group: deletePrompt.label })}</p>
            {error && <p className="connection-error" role="alert">{error}</p>}
            <div className="dialog-actions"><button type="button" disabled={mutationPending} onClick={() => { setDeletePrompt(null); setError(null); }}>{t("groupConfig.cancel")}</button><button className="danger-button" type="button" disabled={actionsDisabled} onClick={() => void confirmDelete()}>{t(mutationPending ? "groupConfig.delete.deleting" : "groupConfig.delete.confirm")}</button></div>
          </div>
        </div>
      )}
    </div>
    </GroupConfigTranslationContext.Provider>
  );
};

export default GroupConfigCatalog;
