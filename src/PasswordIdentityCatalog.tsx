import {
  type FormEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import {
  createPasswordIdentity,
  deletePasswordIdentity,
  listPasswordIdentities,
  stageSshPassword,
  updatePasswordIdentity,
  type PasswordIdentity,
  type PasswordIdentityCatalog as PasswordIdentityCatalogSnapshot,
  type PasswordIdentityCredentialMutation,
} from "./backend";
import {
  classifyPasswordIdentityError,
  normalizePasswordIdentityMetadata,
} from "./passwordIdentityUi";
import { useI18n, type Locale } from "./i18n";

type EditorCredentialAction = "keep" | "remove" | "replace";

type PasswordIdentityEditor = {
  mode: "create" | "update";
  id?: string;
  expectedRevision?: number;
  expectedInventoryRevision: unknown;
  label: string;
  username: string;
  credentialAction: EditorCredentialAction;
  password: string;
};

type PasswordIdentityDeletePrompt = {
  id: string;
  label: string;
  expectedRevision: number;
  expectedInventoryRevision: unknown;
};

export type PasswordIdentityCatalogProps = {
  disabled?: boolean;
  locale?: Locale;
  refreshKey?: string | number;
  onCatalogChange?: (catalog: PasswordIdentityCatalogSnapshot) => void;
};

const updateCredentialMutation = (
  action: EditorCredentialAction,
  stagedCredentialReference?: string,
): PasswordIdentityCredentialMutation => {
  if (action === "remove") {
    return { action: "remove" };
  }
  if (action === "replace" && stagedCredentialReference) {
    return { action: "replace", stagedCredentialReference };
  }
  return { action: "keep" };
};

export const PasswordIdentityCatalog = ({
  disabled = false,
  locale = "zh-CN",
  refreshKey,
  onCatalogChange,
}: PasswordIdentityCatalogProps) => {
  const { t } = useI18n(locale);
  const [catalog, setCatalog] = useState<PasswordIdentityCatalogSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [mutationPending, setMutationPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [editor, setEditor] = useState<PasswordIdentityEditor | null>(null);
  const [deletePrompt, setDeletePrompt] = useState<PasswordIdentityDeletePrompt | null>(null);
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
      const next = await listPasswordIdentities();
      if (!mounted.current || sequence !== loadSequence.current) {
        return false;
      }
      setCatalog(next);
      onCatalogChangeRef.current?.(next);
      return true;
    } catch (reason) {
      if (mounted.current && sequence === loadSequence.current) {
        setError(classifyPasswordIdentityError(reason, t).message);
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

  const applyMutationResult = (next: PasswordIdentityCatalogSnapshot) => {
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
    const issue = classifyPasswordIdentityError(reason, t);
    if (issue.refreshCatalog) {
      setEditor(null);
      setDeletePrompt(null);
      await refreshCatalog(true);
    }
    if (mounted.current) {
      setError(issue.message);
      setEditor((current) => current ? { ...current, password: "" } : current);
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
      username: "",
      credentialAction: "keep",
      password: "",
    });
  };

  const openUpdateEditor = (identity: PasswordIdentity) => {
    if (!catalog || disabled || mutationPending) {
      return;
    }
    setError(null);
    setEditor({
      mode: "update",
      id: identity.id,
      expectedRevision: identity.revision,
      expectedInventoryRevision: catalog.inventoryRevision,
      label: identity.label,
      username: identity.username,
      credentialAction: "keep",
      password: "",
    });
  };

  const submitEditor = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const snapshot = editor;
    if (!snapshot || disabled || mutationLock.current) {
      return;
    }
    const metadata = normalizePasswordIdentityMetadata(snapshot.label, snapshot.username);
    if (!metadata) {
      setError(t("passwordIdentity.validation.labelRequired"));
      setEditor((current) => current ? { ...current, password: "" } : current);
      return;
    }
    if (snapshot.credentialAction === "replace" && !snapshot.password) {
      setError(t("passwordIdentity.validation.passwordRequired"));
      setEditor((current) => current ? { ...current, password: "" } : current);
      return;
    }

    mutationLock.current = true;
    loadSequence.current += 1;
    setMutationPending(true);
    setError(null);
    let secretToStage = snapshot.password;
    try {
      let stagedCredentialReference: string | undefined;
      if (snapshot.credentialAction === "replace") {
        // Clear React state before the raw staging call. stageSshPassword owns
        // and zeroes the encoded byte buffer; only its opaque reference is
        // allowed into the ordinary mutation request below.
        setEditor((current) => current ? { ...current, password: "" } : current);
        stagedCredentialReference = await stageSshPassword(secretToStage);
        secretToStage = "";
      }

      const next = snapshot.mode === "create"
        ? await createPasswordIdentity({
          expectedInventoryRevision: snapshot.expectedInventoryRevision,
          metadata,
          ...(stagedCredentialReference ? { stagedCredentialReference } : {}),
        })
        : await updatePasswordIdentity({
          id: snapshot.id!,
          expectedRevision: snapshot.expectedRevision!,
          expectedInventoryRevision: snapshot.expectedInventoryRevision,
          metadata,
          credentialMutation: updateCredentialMutation(
            snapshot.credentialAction,
            stagedCredentialReference,
          ),
        });
      applyMutationResult(next);
    } catch (reason) {
      await handleMutationFailure(reason);
    } finally {
      secretToStage = "";
      mutationLock.current = false;
      if (mounted.current) {
        setMutationPending(false);
        setEditor((current) => current ? { ...current, password: "" } : current);
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
      const next = await deletePasswordIdentity({
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

  const identities = catalog?.identities ?? [];

  return (
    <section className="password-identity-catalog" aria-busy={loading || mutationPending}>
      <header className="password-identity-heading">
        <div>
          <p className="eyebrow">{t("passwordIdentity.catalogEyebrow")}</p>
          <h2>{t("passwordIdentity.title")}</h2>
        </div>
        <div className="password-identity-toolbar">
          <button
            type="button"
            onClick={() => void refreshCatalog()}
            disabled={disabled || loading || mutationPending}
          >
            {loading ? t("passwordIdentity.refreshing") : t("passwordIdentity.refresh")}
          </button>
          <button
            type="button"
            className="primary-button"
            onClick={openCreateEditor}
            disabled={disabled || !catalog || loading || mutationPending}
          >
            {t("passwordIdentity.create")}
          </button>
        </div>
      </header>

      <p className="password-identity-description">
        {t("passwordIdentity.description")}
      </p>

      {error && <p className="connection-error" role="alert">{error}</p>}

      <div className="password-identity-list" aria-live="polite">
        {loading && !catalog && (
          <p className="saved-host-empty">{t("passwordIdentity.loading")}</p>
        )}
        {!loading && catalog && identities.length === 0 && (
          <p className="saved-host-empty">{t("passwordIdentity.empty")}</p>
        )}
        {identities.map((identity) => (
          <article className="password-identity-card" key={identity.id}>
            <div className="saved-host-summary">
              <strong>{identity.label}</strong>
              <small>{identity.username || t("passwordIdentity.hostUsername")}</small>
              <span className={identity.hasSavedCredential ? "credential-saved" : "credential-missing"}>
                {identity.hasSavedCredential
                  ? t("passwordIdentity.credentialSaved")
                  : t("passwordIdentity.credentialNeeded")}
              </span>
            </div>
            <div className="password-identity-actions">
              <button
                type="button"
                onClick={() => openUpdateEditor(identity)}
                disabled={disabled || mutationPending}
              >
                {t("passwordIdentity.edit")}
              </button>
              <button
                type="button"
                className="saved-host-delete"
                onClick={() => {
                  if (!catalog || disabled || mutationPending) {
                    return;
                  }
                  setError(null);
                  setDeletePrompt({
                    id: identity.id,
                    label: identity.label,
                    expectedRevision: identity.revision,
                    expectedInventoryRevision: catalog.inventoryRevision,
                  });
                }}
                disabled={disabled || mutationPending}
              >
                {t("passwordIdentity.delete")}
              </button>
            </div>
          </article>
        ))}
      </div>

      {editor && (
        <div className="dialog-backdrop" role="presentation">
          <form
            className="trust-dialog saved-host-dialog password-identity-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="password-identity-editor-title"
            onSubmit={(event) => void submitEditor(event)}
          >
            <p className="eyebrow">{t("passwordIdentity.editorEyebrow")}</p>
            <h2 id="password-identity-editor-title">
              {editor.mode === "create"
                ? t("passwordIdentity.createTitle")
                : t("passwordIdentity.editTitle")}
            </h2>
            <div className="saved-host-fields">
              <label>
                {t("passwordIdentity.label")}
                <input
                  autoFocus
                  value={editor.label}
                  maxLength={256}
                  disabled={disabled || mutationPending}
                  onChange={(event) => setEditor((current) => (
                    current ? { ...current, label: event.target.value } : current
                  ))}
                />
              </label>
              <label>
                {t("passwordIdentity.usernameOptional")}
                <input
                  value={editor.username}
                  maxLength={256}
                  autoComplete="username"
                  disabled={disabled || mutationPending}
                  onChange={(event) => setEditor((current) => (
                    current ? { ...current, username: event.target.value } : current
                  ))}
                />
              </label>
              <label>
                {t("passwordIdentity.passwordAction")}
                <select
                  value={editor.credentialAction}
                  disabled={disabled || mutationPending}
                  onChange={(event) => {
                    const credentialAction = event.target.value as EditorCredentialAction;
                    setEditor((current) => current ? {
                      ...current,
                      credentialAction,
                      password: "",
                    } : current);
                  }}
                >
                  <option value="keep">
                    {editor.mode === "create"
                      ? t("passwordIdentity.passwordCreateKeep")
                      : t("passwordIdentity.passwordUpdateKeep")}
                  </option>
                  <option value="replace">
                    {editor.mode === "create"
                      ? t("passwordIdentity.passwordCreateReplace")
                      : t("passwordIdentity.passwordUpdateReplace")}
                  </option>
                  {editor.mode === "update" && (
                    <option value="remove">{t("passwordIdentity.passwordRemove")}</option>
                  )}
                </select>
              </label>
              {editor.credentialAction === "replace" && (
                <label>
                  {t("passwordIdentity.password")}
                  <input
                    type="password"
                    value={editor.password}
                    autoComplete="new-password"
                    disabled={disabled || mutationPending}
                    onChange={(event) => setEditor((current) => (
                      current ? { ...current, password: event.target.value } : current
                    ))}
                  />
                </label>
              )}
            </div>
            <p className="security-note">
              {t("passwordIdentity.securityNote")}
            </p>
            {error && <p className="connection-error" role="alert">{error}</p>}
            <div className="dialog-actions">
              <button
                type="button"
                disabled={mutationPending}
                onClick={() => {
                  setEditor(null);
                  setError(null);
                }}
              >
                {t("passwordIdentity.cancel")}
              </button>
              <button
                type="submit"
                className="primary-button"
                disabled={disabled || mutationPending}
              >
                {mutationPending
                  ? t("passwordIdentity.saving")
                  : t("passwordIdentity.save")}
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
            aria-labelledby="password-identity-delete-title"
          >
            <p className="eyebrow">{t("passwordIdentity.deleteEyebrow")}</p>
            <h2 id="password-identity-delete-title">{t("passwordIdentity.deleteTitle")}</h2>
            <p>
              {t("passwordIdentity.deleteDescription", { label: deletePrompt.label })}
            </p>
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
                {t("passwordIdentity.cancel")}
              </button>
              <button
                type="button"
                className="danger-button"
                disabled={disabled || mutationPending}
                onClick={() => void confirmDelete()}
              >
                {mutationPending
                  ? t("passwordIdentity.deleting")
                  : t("passwordIdentity.confirmDelete")}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
};

export default PasswordIdentityCatalog;
