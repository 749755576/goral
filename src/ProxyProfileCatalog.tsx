import {
  type FormEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import {
  createProxyProfile,
  deleteProxyProfile,
  listProxyProfiles,
  stageSshPassword,
  updateProxyProfile,
  type PasswordIdentity,
  type ProxyNetworkAuthRequest,
  type ProxyProfile,
  type ProxyProfileCatalog as ProxyProfileCatalogSnapshot,
  type ProxyProfileConfigRequest,
  type ProxyProfileCredentialMutation,
} from "./backend";
import {
  classifyProxyProfileError,
  normalizeProxyCommandMutation,
  normalizeProxyNetworkConfig,
  normalizeProxyProfileMetadata,
  PROXY_PROFILE_COMMAND_MAX_BYTES,
} from "./proxyProfileUi";
import { useI18n, type Locale, type Translate } from "./i18n";

type ProxyType = "http" | "socks5" | "command";
type CredentialAction = "keep" | "remove" | "replace";
type CommandAction = "keep" | "replace";

type ProxyProfileEditor = {
  mode: "create" | "update";
  id?: string;
  expectedRevision?: number;
  expectedInventoryRevision: unknown;
  label: string;
  type: ProxyType;
  host: string;
  port: string;
  authMode: "manual" | "identity";
  username: string;
  identityId: string;
  credentialAction: CredentialAction;
  password: string;
  canKeepCommand: boolean;
  commandAction: CommandAction;
  command: string;
};

type ProxyProfileDeletePrompt = {
  id: string;
  label: string;
  expectedRevision: number;
  expectedInventoryRevision: unknown;
};

export type ProxyProfileCatalogProps = {
  disabled?: boolean;
  locale?: Locale;
  refreshKey?: string | number;
  identities: PasswordIdentity[];
  onCatalogChange?: (catalog: ProxyProfileCatalogSnapshot) => void;
};

const credentialMutation = (
  action: CredentialAction,
  stagedCredentialReference?: string,
): ProxyProfileCredentialMutation => {
  if (action === "remove") {
    return { action: "remove" };
  }
  if (action === "replace" && stagedCredentialReference) {
    return { action: "replace", stagedCredentialReference };
  }
  return { action: "keep" };
};

const buildNetworkAuth = (
  editor: ProxyProfileEditor,
  stagedCredentialReference?: string,
): ProxyNetworkAuthRequest => {
  if (editor.authMode === "identity") {
    // This branch intentionally cannot carry a manual credential mutation.
    return { mode: "identity", identityId: editor.identityId };
  }
  return {
    mode: "manual",
    username: editor.username,
    credentialMutation: credentialMutation(
      editor.credentialAction,
      stagedCredentialReference,
    ),
  };
};

const buildConfig = (
  editor: ProxyProfileEditor,
  stagedCredentialReference?: string,
): ProxyProfileConfigRequest | null => {
  if (editor.type === "command") {
    const commandMutation = normalizeProxyCommandMutation(
      editor.commandAction,
      editor.command,
    );
    return commandMutation ? { type: "command", commandMutation } : null;
  }
  return normalizeProxyNetworkConfig(
    editor.type,
    editor.host,
    editor.port,
    buildNetworkAuth(editor, stagedCredentialReference),
  );
};

const typeLabel = (type: ProxyType, t: Translate): string => {
  if (type === "http") return "HTTP";
  if (type === "socks5") return "SOCKS5";
  return t("proxyProfile.typeCommand");
};

export const ProxyProfileCatalog = ({
  disabled = false,
  locale = "zh-CN",
  refreshKey,
  identities,
  onCatalogChange,
}: ProxyProfileCatalogProps) => {
  const { t } = useI18n(locale);
  const [catalog, setCatalog] = useState<ProxyProfileCatalogSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [mutationPending, setMutationPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [editor, setEditor] = useState<ProxyProfileEditor | null>(null);
  const [deletePrompt, setDeletePrompt] = useState<ProxyProfileDeletePrompt | null>(null);
  const mounted = useRef(true);
  const loadSequence = useRef(0);
  const mutationLock = useRef(false);
  const onCatalogChangeRef = useRef(onCatalogChange);
  const observedRefreshKey = useRef(refreshKey);

  useEffect(() => {
    onCatalogChangeRef.current = onCatalogChange;
  }, [onCatalogChange]);

  const refreshCatalog = useCallback(async (preserveError = false): Promise<boolean> => {
    const sequence = ++loadSequence.current;
    setLoading(true);
    if (!preserveError) {
      setError(null);
    }
    try {
      const next = await listProxyProfiles();
      if (!mounted.current || sequence !== loadSequence.current) {
        return false;
      }
      setCatalog(next);
      onCatalogChangeRef.current?.(next);
      return true;
    } catch (reason) {
      if (mounted.current && sequence === loadSequence.current) {
        setError(classifyProxyProfileError(reason, t).message);
      }
      return false;
    } finally {
      if (mounted.current && sequence === loadSequence.current) {
        setLoading(false);
      }
    }
  }, [t]);

  useEffect(() => {
    mounted.current = true;
    void refreshCatalog();
    return () => {
      mounted.current = false;
      loadSequence.current += 1;
    };
  }, [refreshCatalog]);

  useEffect(() => {
    if (Object.is(observedRefreshKey.current, refreshKey)) {
      return;
    }
    observedRefreshKey.current = refreshKey;
    void refreshCatalog();
  }, [refreshCatalog, refreshKey]);

  const clearEditorSecrets = () => {
    setEditor((current) => current ? { ...current, password: "", command: "" } : current);
  };

  const applyMutationResult = (next: ProxyProfileCatalogSnapshot) => {
    loadSequence.current += 1;
    if (mounted.current) {
      setCatalog(next);
      onCatalogChangeRef.current?.(next);
      setEditor(null);
      setDeletePrompt(null);
      setError(null);
    }
  };

  const handleMutationFailure = async (reason: unknown) => {
    const issue = classifyProxyProfileError(reason, t);
    clearEditorSecrets();
    if (issue.refreshCatalog) {
      setEditor(null);
      setDeletePrompt(null);
      await refreshCatalog(true);
    }
    if (mounted.current) {
      setError(issue.message);
    }
  };

  const openCreateEditor = () => {
    if (!catalog || disabled || mutationPending) {
      return;
    }
    setError(null);
    setEditor({
      mode: "create",
      expectedInventoryRevision: catalog.inventoryRevision,
      label: "",
      type: "http",
      host: "",
      port: "8080",
      authMode: "manual",
      username: "",
      identityId: "",
      credentialAction: "keep",
      password: "",
      canKeepCommand: false,
      commandAction: "replace",
      command: "",
    });
  };

  const openUpdateEditor = (profile: ProxyProfile) => {
    if (!catalog || disabled || mutationPending) {
      return;
    }
    const networkConfig = profile.config.type === "command" ? null : profile.config;
    setError(null);
    setEditor({
      mode: "update",
      id: profile.id,
      expectedRevision: profile.revision,
      expectedInventoryRevision: catalog.inventoryRevision,
      label: profile.label,
      type: profile.config.type,
      host: networkConfig?.host ?? "",
      port: networkConfig ? String(networkConfig.port) : "8080",
      authMode: networkConfig?.auth.mode ?? "manual",
      username: networkConfig?.auth.mode === "manual" ? networkConfig.auth.username : "",
      identityId: networkConfig?.auth.mode === "identity" ? networkConfig.auth.identityId : "",
      credentialAction: "keep",
      password: "",
      canKeepCommand: profile.config.type === "command",
      commandAction: profile.config.type === "command" ? "keep" : "replace",
      command: "",
    });
  };

  const submitEditor = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const snapshot = editor;
    if (!snapshot || disabled || mutationLock.current) {
      return;
    }
    if (snapshot.mode === "create" && snapshot.type === "command" && snapshot.commandAction !== "replace") {
      setError(t("proxyProfile.validation.createCommandRequired"));
      clearEditorSecrets();
      return;
    }
    if (snapshot.type === "command" && snapshot.commandAction === "keep" && !snapshot.canKeepCommand) {
      setError(t("proxyProfile.validation.switchCommandRequired"));
      clearEditorSecrets();
      return;
    }
    if (
      snapshot.type !== "command"
      && snapshot.authMode === "manual"
      && snapshot.credentialAction === "replace"
      && !snapshot.password
    ) {
      setError(t("proxyProfile.validation.passwordRequired"));
      clearEditorSecrets();
      return;
    }

    // Validate all non-secret fields before consuming a staged password.
    const previewConfig = buildConfig(
      snapshot,
      snapshot.credentialAction === "replace" ? "pending-staged-reference" : undefined,
    );
    if (!previewConfig || !normalizeProxyProfileMetadata(snapshot.label, previewConfig)) {
      setError(t("proxyProfile.validation.invalid"));
      clearEditorSecrets();
      return;
    }

    mutationLock.current = true;
    loadSequence.current += 1;
    setMutationPending(true);
    setError(null);
    let secretToStage = snapshot.password;
    try {
      let stagedCredentialReference: string | undefined;
      if (
        snapshot.type !== "command"
        && snapshot.authMode === "manual"
        && snapshot.credentialAction === "replace"
      ) {
        // React state is cleared before raw staging. Only the opaque reference
        // is allowed into the ordinary create/update request below.
        clearEditorSecrets();
        stagedCredentialReference = await stageSshPassword(secretToStage);
        secretToStage = "";
      } else if (snapshot.type === "command" && snapshot.commandAction === "replace") {
        clearEditorSecrets();
      }

      const config = buildConfig(snapshot, stagedCredentialReference);
      const metadata = config
        ? normalizeProxyProfileMetadata(snapshot.label, config)
        : null;
      if (!metadata) {
        throw new Error("PROXY_PROFILE_INVALID");
      }

      const next = snapshot.mode === "create"
        ? await createProxyProfile({
          expectedInventoryRevision: snapshot.expectedInventoryRevision,
          metadata,
        })
        : await updateProxyProfile({
          id: snapshot.id!,
          expectedRevision: snapshot.expectedRevision!,
          expectedInventoryRevision: snapshot.expectedInventoryRevision,
          metadata,
        });
      applyMutationResult(next);
    } catch (reason) {
      await handleMutationFailure(reason);
    } finally {
      secretToStage = "";
      mutationLock.current = false;
      if (mounted.current) {
        setMutationPending(false);
        clearEditorSecrets();
      }
    }
  };

  const confirmDelete = async () => {
    const prompt = deletePrompt;
    if (!prompt || disabled || mutationLock.current) {
      return;
    }
    mutationLock.current = true;
    loadSequence.current += 1;
    setMutationPending(true);
    setError(null);
    try {
      const next = await deleteProxyProfile({
        id: prompt.id,
        expectedRevision: prompt.expectedRevision,
        expectedInventoryRevision: prompt.expectedInventoryRevision,
      });
      applyMutationResult(next);
    } catch (reason) {
      await handleMutationFailure(reason);
    } finally {
      mutationLock.current = false;
      if (mounted.current) {
        setMutationPending(false);
      }
    }
  };

  const profiles = catalog?.profiles ?? [];
  const passwordIdentityLabel = (identityId: string): string => (
    identities.find((identity) => identity.id === identityId)?.label
      ?? t("proxyProfile.identityBoundFallback")
  );

  return (
    <section className="password-identity-catalog proxy-profile-catalog" aria-busy={loading || mutationPending}>
      <header className="password-identity-heading">
        <div>
          <p className="eyebrow">{t("proxyProfile.catalogEyebrow")}</p>
          <h2>{t("proxyProfile.title")}</h2>
        </div>
        <div className="password-identity-toolbar">
          <button
            type="button"
            onClick={() => void refreshCatalog()}
            disabled={disabled || loading || mutationPending}
          >
            {loading ? t("proxyProfile.refreshing") : t("proxyProfile.refresh")}
          </button>
          <button
            type="button"
            className="primary-button"
            onClick={openCreateEditor}
            disabled={disabled || !catalog || loading || mutationPending}
          >
            {t("proxyProfile.create")}
          </button>
        </div>
      </header>

      <p className="password-identity-description">
        {t("proxyProfile.description")}
      </p>

      {error && <p className="connection-error" role="alert">{error}</p>}

      <div className="password-identity-list" aria-live="polite">
        {loading && !catalog && (
          <p className="saved-host-empty">{t("proxyProfile.loading")}</p>
        )}
        {!loading && catalog && profiles.length === 0 && (
          <div className="proxy-profile-empty-state" role="status">
            <span className="proxy-profile-empty-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none">
                <circle cx="6" cy="12" r="2.5" />
                <circle cx="18" cy="7" r="2.5" />
                <circle cx="18" cy="17" r="2.5" />
                <path d="M8.5 11.2 15.5 8M8.5 12.8l7 3.2" />
              </svg>
            </span>
            <div className="proxy-profile-empty-copy">
              <h3>{t("proxyProfile.empty")}</h3>
              <p>{t("proxyProfile.emptyDescription")}</p>
            </div>
            <button
              type="button"
              className="primary-button"
              onClick={openCreateEditor}
              disabled={disabled || loading || mutationPending}
            >
              {t("proxyProfile.create")}
            </button>
          </div>
        )}
        {profiles.map((profile) => (
          <article className="password-identity-card proxy-profile-card" key={profile.id}>
            <div className="saved-host-summary">
              <strong>{profile.label}</strong>
              <small>{typeLabel(profile.config.type, t)}</small>
              {profile.config.type === "command" ? (
                <span className="credential-saved">{t("proxyProfile.commandConfigured")}</span>
              ) : (
                <>
                  <small>{profile.config.host}:{profile.config.port}</small>
                  <span className={
                    profile.config.auth.mode === "identity"
                      || profile.config.auth.hasSavedCredential
                      ? "credential-saved"
                      : "credential-missing"
                  }>
                    {profile.config.auth.mode === "identity"
                      ? t("proxyProfile.identityStatus", {
                        identity: passwordIdentityLabel(profile.config.auth.identityId),
                      })
                      : profile.config.auth.hasSavedCredential
                        ? profile.config.auth.username
                          ? t("proxyProfile.manualStatusSavedWithUsername", {
                            username: profile.config.auth.username,
                          })
                          : t("proxyProfile.manualStatusSaved")
                        : profile.config.auth.username
                          ? t("proxyProfile.manualStatusMissingWithUsername", {
                            username: profile.config.auth.username,
                          })
                          : t("proxyProfile.manualStatusMissing")}
                  </span>
                </>
              )}
            </div>
            <div className="password-identity-actions">
              <button
                type="button"
                onClick={() => openUpdateEditor(profile)}
                disabled={disabled || mutationPending}
              >
                {t("proxyProfile.edit")}
              </button>
              <button
                type="button"
                className="saved-host-delete"
                onClick={() => {
                  if (!catalog || disabled || mutationPending) return;
                  setError(null);
                  setDeletePrompt({
                    id: profile.id,
                    label: profile.label,
                    expectedRevision: profile.revision,
                    expectedInventoryRevision: catalog.inventoryRevision,
                  });
                }}
                disabled={disabled || mutationPending}
              >
                {t("proxyProfile.delete")}
              </button>
            </div>
          </article>
        ))}
      </div>

      {editor && (
        <div className="dialog-backdrop" role="presentation">
          <form
            className="trust-dialog saved-host-dialog password-identity-dialog proxy-profile-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="proxy-profile-editor-title"
            onSubmit={(event) => void submitEditor(event)}
          >
            <p className="eyebrow">{t("proxyProfile.editorEyebrow")}</p>
            <h2 id="proxy-profile-editor-title">
              {editor.mode === "create"
                ? t("proxyProfile.createTitle")
                : t("proxyProfile.editTitle")}
            </h2>
            <div className="saved-host-fields">
              <label>
                {t("proxyProfile.label")}
                <input
                  autoFocus
                  value={editor.label}
                  maxLength={256}
                  disabled={disabled || mutationPending}
                  onChange={(event) => setEditor((current) => current ? {
                    ...current,
                    label: event.target.value,
                  } : current)}
                />
              </label>
              <label>
                {t("proxyProfile.type")}
                <select
                  value={editor.type}
                  disabled={disabled || mutationPending}
                  onChange={(event) => {
                    const type = event.target.value as ProxyType;
                    setEditor((current) => current ? {
                      ...current,
                      type,
                      password: "",
                      command: "",
                    } : current);
                  }}
                >
                  <option value="http">HTTP</option>
                  <option value="socks5">SOCKS5</option>
                  <option value="command">{t("proxyProfile.typeCommand")}</option>
                </select>
              </label>

              {editor.type === "command" ? (
                <>
                  {editor.mode === "update" && (
                    <label>
                      {t("proxyProfile.commandAction")}
                      <select
                        value={editor.commandAction}
                        disabled={disabled || mutationPending}
                        onChange={(event) => setEditor((current) => current ? {
                          ...current,
                          commandAction: event.target.value as CommandAction,
                          command: "",
                        } : current)}
                      >
                        {editor.canKeepCommand && (
                          <option value="keep">{t("proxyProfile.commandKeep")}</option>
                        )}
                        <option value="replace">{t("proxyProfile.commandReplace")}</option>
                      </select>
                    </label>
                  )}
                  {editor.commandAction === "replace" && (
                    <label>
                      {t("proxyProfile.command")}
                      <textarea
                        value={editor.command}
                        maxLength={PROXY_PROFILE_COMMAND_MAX_BYTES}
                        rows={5}
                        spellCheck={false}
                        disabled={disabled || mutationPending}
                        onChange={(event) => setEditor((current) => current ? {
                          ...current,
                          command: event.target.value,
                        } : current)}
                      />
                    </label>
                  )}
                  {editor.mode === "update" && editor.commandAction === "keep" && (
                    <p className="security-note">{t("proxyProfile.commandKeepNote")}</p>
                  )}
                </>
              ) : (
                <>
                  <label>
                    {t("proxyProfile.host")}
                    <input
                      value={editor.host}
                      maxLength={253}
                      disabled={disabled || mutationPending}
                      onChange={(event) => setEditor((current) => current ? {
                        ...current,
                        host: event.target.value,
                      } : current)}
                    />
                  </label>
                  <label>
                    {t("proxyProfile.port")}
                    <input
                      type="number"
                      min="1"
                      max="65535"
                      value={editor.port}
                      disabled={disabled || mutationPending}
                      onChange={(event) => setEditor((current) => current ? {
                        ...current,
                        port: event.target.value,
                      } : current)}
                    />
                  </label>
                  <label>
                    {t("proxyProfile.authMethod")}
                    <select
                      value={editor.authMode}
                      disabled={disabled || mutationPending}
                      onChange={(event) => {
                        const authMode = event.target.value as "manual" | "identity";
                        setEditor((current) => current ? {
                          ...current,
                          authMode,
                          password: "",
                          credentialAction: "keep",
                        } : current);
                      }}
                    >
                      <option value="manual">{t("proxyProfile.authManual")}</option>
                      <option value="identity">{t("proxyProfile.authIdentity")}</option>
                    </select>
                  </label>
                  {editor.authMode === "identity" ? (
                    <label>
                      {t("proxyProfile.passwordIdentity")}
                      <select
                        value={editor.identityId}
                        disabled={disabled || mutationPending}
                        onChange={(event) => setEditor((current) => current ? {
                          ...current,
                          identityId: event.target.value,
                          password: "",
                        } : current)}
                      >
                        <option value="">{t("proxyProfile.selectPasswordIdentity")}</option>
                        {identities.map((identity) => (
                          <option value={identity.id} key={identity.id}>
                            {identity.label}{identity.username ? ` · ${identity.username}` : ""}
                          </option>
                        ))}
                      </select>
                    </label>
                  ) : (
                    <>
                      <label>
                        {t("proxyProfile.usernameOptional")}
                        <input
                          value={editor.username}
                          maxLength={255}
                          autoComplete="username"
                          disabled={disabled || mutationPending}
                          onChange={(event) => setEditor((current) => current ? {
                            ...current,
                            username: event.target.value,
                          } : current)}
                        />
                      </label>
                      <label>
                        {t("proxyProfile.passwordAction")}
                        <select
                          value={editor.credentialAction}
                          disabled={disabled || mutationPending}
                          onChange={(event) => setEditor((current) => current ? {
                            ...current,
                            credentialAction: event.target.value as CredentialAction,
                            password: "",
                          } : current)}
                        >
                          <option value="keep">
                            {editor.mode === "create"
                              ? t("proxyProfile.passwordCreateKeep")
                              : t("proxyProfile.passwordUpdateKeep")}
                          </option>
                          <option value="replace">
                            {editor.mode === "create"
                              ? t("proxyProfile.passwordCreateReplace")
                              : t("proxyProfile.passwordUpdateReplace")}
                          </option>
                          {editor.mode === "update" && (
                            <option value="remove">{t("proxyProfile.passwordRemove")}</option>
                          )}
                        </select>
                      </label>
                      {editor.credentialAction === "replace" && (
                        <label>
                          {t("proxyProfile.password")}
                          <input
                            type="password"
                            value={editor.password}
                            autoComplete="new-password"
                            disabled={disabled || mutationPending}
                            onChange={(event) => setEditor((current) => current ? {
                              ...current,
                              password: event.target.value,
                            } : current)}
                          />
                        </label>
                      )}
                    </>
                  )}
                </>
              )}
            </div>
            <p className="security-note">
              {t("proxyProfile.securityNote")}
            </p>
            {error && <p className="connection-error" role="alert">{error}</p>}
            <div className="dialog-actions">
              <button
                type="button"
                disabled={mutationPending}
                onClick={() => {
                  clearEditorSecrets();
                  setEditor(null);
                  setError(null);
                }}
              >
                {t("proxyProfile.cancel")}
              </button>
              <button
                type="submit"
                className="primary-button"
                disabled={disabled || mutationPending}
              >
                {mutationPending ? t("proxyProfile.saving") : t("proxyProfile.save")}
              </button>
            </div>
          </form>
        </div>
      )}

      {deletePrompt && (
        <div className="dialog-backdrop" role="presentation">
          <div
            className="trust-dialog saved-host-dialog password-identity-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="proxy-profile-delete-title"
          >
            <p className="eyebrow">{t("proxyProfile.deleteEyebrow")}</p>
            <h2 id="proxy-profile-delete-title">{t("proxyProfile.deleteTitle")}</h2>
            <p>{t("proxyProfile.deleteDescription", { label: deletePrompt.label })}</p>
            {error && <p className="connection-error" role="alert">{error}</p>}
            <div className="dialog-actions">
              <button
                type="button"
                disabled={mutationPending}
                onClick={() => {
                  setDeletePrompt(null);
                  setError(null);
                }}
              >
                {t("proxyProfile.cancel")}
              </button>
              <button
                type="button"
                className="danger-button"
                disabled={disabled || mutationPending}
                onClick={() => void confirmDelete()}
              >
                {mutationPending ? t("proxyProfile.deleting") : t("proxyProfile.confirmDelete")}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
};

export default ProxyProfileCatalog;
