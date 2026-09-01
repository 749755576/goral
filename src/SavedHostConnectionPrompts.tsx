import type { FormEventHandler } from "react";

import { useI18n, type Locale } from "./i18n";

type ConnectionPromptCommonProps = Readonly<{
  locale: Locale;
  targetLabel: string;
  targetAddress: string;
  busy: boolean;
  connecting: boolean;
  closing: boolean;
  error?: string | null;
  onSubmit: FormEventHandler<HTMLFormElement>;
  onCancel: () => void;
}>;

export type SavedHostPasswordPromptDialogProps = ConnectionPromptCommonProps & Readonly<{
  password: string;
  showManualLogin: boolean;
  onPasswordChange: (password: string) => void;
  onManualLogin: () => void;
}>;

/** Controlled one-time login-password presentation with no session authority. */
export function SavedHostPasswordPromptDialog({
  locale,
  targetLabel,
  targetAddress,
  busy,
  connecting,
  closing,
  error,
  password,
  showManualLogin,
  onPasswordChange,
  onManualLogin,
  onSubmit,
  onCancel,
}: SavedHostPasswordPromptDialogProps) {
  const { t } = useI18n(locale);

  return (
    <div className="dialog-backdrop connection-prompt-backdrop" role="presentation">
      <form
        className="trust-dialog saved-host-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="saved-host-password-title"
        onSubmit={onSubmit}
      >
        <p className="eyebrow">{t("connectionPrompt.password.eyebrow")}</p>
        <h2 id="saved-host-password-title">{t("connectionPrompt.password.title")}</h2>
        <p>
          {targetLabel}<br />
          <code>{targetAddress}</code>
        </p>
        <div className="saved-host-fields">
          <label>
            {t("connectionPrompt.password.label")}
            <input
              autoFocus
              type="password"
              value={password}
              onChange={(event) => onPasswordChange(event.target.value)}
              disabled={busy}
              autoComplete="current-password"
              required
            />
          </label>
        </div>
        {error && (
          <p className="connection-error" role="alert">
            {t("connectionPrompt.common.connectionFailedPrefix")}{error}
          </p>
        )}
        <p className="security-note">{t("connectionPrompt.password.securityNote")}</p>
        <div className="dialog-actions">
          <button type="button" disabled={closing} onClick={onCancel}>
            {busy
              ? t("connectionPrompt.common.cancelConnection")
              : t("connectionPrompt.common.cancel")}
          </button>
          {showManualLogin && (
            <button type="button" disabled={busy} onClick={onManualLogin}>
              {t("connectionPrompt.common.manualLogin")}
            </button>
          )}
          <button
            className="primary-button"
            type="submit"
            disabled={busy || password.length === 0}
          >
            {connecting
              ? t("connectionPrompt.common.connecting")
              : t("connectionPrompt.common.connect")}
          </button>
        </div>
      </form>
    </div>
  );
}

export type SavedHostProxyPasswordPromptDialogProps = ConnectionPromptCommonProps & Readonly<{
  requireSshPassword: boolean;
  showKeyPassphrase: boolean;
  sshPassword: string;
  keyPassphrase: string;
  proxyPassword: string;
  onSshPasswordChange: (password: string) => void;
  onKeyPassphraseChange: (passphrase: string) => void;
  onProxyPasswordChange: (password: string) => void;
}>;

/** Controlled one-time proxy credentials; staging remains in the workspace. */
export function SavedHostProxyPasswordPromptDialog({
  locale,
  targetLabel,
  targetAddress,
  busy,
  connecting,
  closing,
  error,
  requireSshPassword,
  showKeyPassphrase,
  sshPassword,
  keyPassphrase,
  proxyPassword,
  onSshPasswordChange,
  onKeyPassphraseChange,
  onProxyPasswordChange,
  onSubmit,
  onCancel,
}: SavedHostProxyPasswordPromptDialogProps) {
  const { t } = useI18n(locale);

  return (
    <div className="dialog-backdrop connection-prompt-backdrop" role="presentation">
      <form
        className="trust-dialog saved-host-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="saved-host-proxy-password-title"
        onSubmit={onSubmit}
      >
        <p className="eyebrow">{t("connectionPrompt.proxy.eyebrow")}</p>
        <h2 id="saved-host-proxy-password-title">{t("connectionPrompt.proxy.title")}</h2>
        <p>
          {targetLabel}<br />
          <code>{targetAddress}</code>
        </p>
        <div className="saved-host-fields">
          {requireSshPassword && (
            <label>
              {t("connectionPrompt.proxy.sshPasswordLabel")}
              <input
                type="password"
                value={sshPassword}
                onChange={(event) => onSshPasswordChange(event.target.value)}
                disabled={busy}
                autoComplete="current-password"
                required
              />
            </label>
          )}
          {showKeyPassphrase && (
            <label>
              {t("connectionPrompt.proxy.keyPassphraseLabel")}
              <input
                type="password"
                value={keyPassphrase}
                onChange={(event) => onKeyPassphraseChange(event.target.value)}
                disabled={busy}
                autoComplete="new-password"
              />
            </label>
          )}
          <label>
            {t("connectionPrompt.proxy.proxyPasswordLabel")}
            <input
              autoFocus
              type="password"
              value={proxyPassword}
              onChange={(event) => onProxyPasswordChange(event.target.value)}
              disabled={busy}
              autoComplete="new-password"
              required
            />
          </label>
        </div>
        {error && (
          <p className="connection-error" role="alert">
            {t("connectionPrompt.common.connectionFailedPrefix")}{error}
          </p>
        )}
        <p className="security-note">{t("connectionPrompt.proxy.securityNote")}</p>
        <div className="dialog-actions">
          <button type="button" disabled={closing} onClick={onCancel}>
            {busy
              ? t("connectionPrompt.common.cancelConnection")
              : t("connectionPrompt.common.cancel")}
          </button>
          <button
            className="primary-button"
            type="submit"
            disabled={
              busy
              || proxyPassword.length === 0
              || (requireSshPassword && sshPassword.length === 0)
            }
          >
            {connecting
              ? t("connectionPrompt.common.connecting")
              : t("connectionPrompt.common.connect")}
          </button>
        </div>
      </form>
    </div>
  );
}

export type SavedHostKeyPassphrasePromptDialogProps = ConnectionPromptCommonProps & Readonly<{
  passphrase: string;
  hasSavedPassphrase: boolean;
  onPassphraseChange: (passphrase: string) => void;
}>;

/** Controlled one-time managed-key passphrase presentation. */
export function SavedHostKeyPassphrasePromptDialog({
  locale,
  targetLabel,
  targetAddress,
  busy,
  connecting,
  closing,
  error,
  passphrase,
  hasSavedPassphrase,
  onPassphraseChange,
  onSubmit,
  onCancel,
}: SavedHostKeyPassphrasePromptDialogProps) {
  const { t } = useI18n(locale);

  return (
    <div className="dialog-backdrop connection-prompt-backdrop" role="presentation">
      <form
        className="trust-dialog saved-host-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="saved-host-key-passphrase-title"
        onSubmit={onSubmit}
      >
        <p className="eyebrow">{t("connectionPrompt.keyPassphrase.eyebrow")}</p>
        <h2 id="saved-host-key-passphrase-title">
          {t("connectionPrompt.keyPassphrase.title")}
        </h2>
        <p>
          {targetLabel}<br />
          <code>{targetAddress}</code>
        </p>
        <div className="saved-host-fields">
          <label>
            {t("connectionPrompt.keyPassphrase.label")}
            <input
              autoFocus
              type="password"
              value={passphrase}
              onChange={(event) => onPassphraseChange(event.target.value)}
              placeholder={hasSavedPassphrase
                ? t("connectionPrompt.keyPassphrase.savedPlaceholder")
                : t("connectionPrompt.keyPassphrase.unsavedPlaceholder")}
              disabled={busy}
              autoComplete="off"
              spellCheck={false}
            />
          </label>
        </div>
        {error && (
          <p className="connection-error" role="alert">
            {t("connectionPrompt.common.connectionFailedPrefix")}{error}
          </p>
        )}
        <p className="security-note">
          {hasSavedPassphrase
            ? t("connectionPrompt.keyPassphrase.savedDescription")
            : t("connectionPrompt.keyPassphrase.unsavedDescription")}{" "}
          {t("connectionPrompt.keyPassphrase.securityNote")}
        </p>
        <div className="dialog-actions">
          <button type="button" disabled={closing} onClick={onCancel}>
            {busy
              ? t("connectionPrompt.common.cancelConnection")
              : t("connectionPrompt.common.cancel")}
          </button>
          <button className="primary-button" type="submit" disabled={busy}>
            {connecting
              ? t("connectionPrompt.common.connecting")
              : t("connectionPrompt.common.connect")}
          </button>
        </div>
      </form>
    </div>
  );
}
