import type { ReactNode } from "react";

import type {
  PasswordIdentity,
  ProxyProfile,
} from "./backend";
import { createTranslator, type Locale } from "./i18n";
import type { SavedHostEditor } from "./SavedHostChainEditor";
import { PROXY_PROFILE_COMMAND_MAX_BYTES } from "./proxyProfileUi";

export type SavedHostProxyFieldsProps = Readonly<{
  editor: SavedHostEditor;
  locale: Locale;
  submitting: boolean;
  proxyProfiles: readonly ProxyProfile[];
  passwordIdentities: readonly PasswordIdentity[];
  onChange: (update: (current: SavedHostEditor) => SavedHostEditor) => void;
  glyph: (name: "proxy") => ReactNode;
}>;

/**
 * Saved-host proxy controls. Draft state, credential staging, persistence,
 * permissions, and session ownership remain with the workspace; this
 * component can only request edits to the parent-owned draft snapshot.
 */
export function SavedHostProxyFields({
  editor,
  locale,
  submitting,
  proxyProfiles,
  passwordIdentities,
  onChange,
  glyph,
}: SavedHostProxyFieldsProps) {
  const t = createTranslator(locale);
  return (
    <>
      <div className="host-editor-section-title">
        {glyph("proxy")}
        <span>{t("savedHost.editor.proxy.section")}</span>
      </div>
      <label>
        {t("savedHost.editor.proxy.profile")}
        <select
          value={editor.proxyProfileId}
          onChange={(event) => onChange((current) => ({
            ...current,
            proxyProfileId: event.target.value,
          }))}
          disabled={submitting}
        >
          <option value="">{t("savedHost.editor.proxy.profileNone")}</option>
          {proxyProfiles.map((profile) => (
            <option key={profile.id} value={profile.id}>
              {profile.label} · {profile.config.type.toUpperCase()}
            </option>
          ))}
          {editor.proxyProfileId
            && !proxyProfiles.some((profile) => profile.id === editor.proxyProfileId) && (
            <option value={editor.proxyProfileId}>
              {t("savedHost.editor.proxy.currentProfileRefreshing")}
            </option>
          )}
        </select>
      </label>
      <label className="remove-credential-option">
        <input
          type="checkbox"
          checked={editor.inlineProxyEnabled}
          onChange={(event) => onChange((current) => ({
            ...current,
            inlineProxyEnabled: event.target.checked,
            inlineProxyPassword: "",
            inlineProxyCommand: "",
          }))}
          disabled={submitting}
        />
        {t("savedHost.editor.proxy.inlineEnabled")}
      </label>
      {editor.inlineProxyEnabled && (
        <>
          <label>
            {t("savedHost.editor.proxy.inlineType")}
            <select
              value={editor.inlineProxyType}
              onChange={(event) => {
                const inlineProxyType = event.target.value as "http" | "socks5" | "command";
                onChange((current) => ({
                  ...current,
                  inlineProxyType,
                  inlineProxyPassword: "",
                  inlineProxyCommand: "",
                  inlineProxyCommandAction: inlineProxyType === "command"
                    && current.canKeepInlineProxyCommand
                    ? current.inlineProxyCommandAction
                    : "replace",
                }));
              }}
              disabled={submitting}
            >
              <option value="http">{t("savedHost.editor.proxy.typeHttp")}</option>
              <option value="socks5">{t("savedHost.editor.proxy.typeSocks5")}</option>
              <option value="command">{t("savedHost.editor.proxy.typeCommand")}</option>
            </select>
          </label>
          {editor.inlineProxyType === "command" ? (
            <>
              {editor.mode === "edit" && (
                <label>
                  {t("savedHost.editor.proxy.commandHandling")}
                  <select
                    value={editor.inlineProxyCommandAction}
                    onChange={(event) => onChange((current) => ({
                      ...current,
                      inlineProxyCommandAction: event.target.value as "keep" | "replace",
                      inlineProxyCommand: "",
                    }))}
                    disabled={submitting}
                  >
                    {editor.canKeepInlineProxyCommand && (
                      <option value="keep">{t("savedHost.editor.proxy.commandKeep")}</option>
                    )}
                    <option value="replace">{t("savedHost.editor.proxy.commandReplace")}</option>
                  </select>
                </label>
              )}
              {editor.inlineProxyCommandAction === "replace" ? (
                <label>
                  {t("savedHost.editor.proxy.command")}
                  <textarea
                    value={editor.inlineProxyCommand}
                    maxLength={PROXY_PROFILE_COMMAND_MAX_BYTES}
                    rows={4}
                    spellCheck={false}
                    onChange={(event) => onChange((current) => ({
                      ...current,
                      inlineProxyCommand: event.target.value,
                    }))}
                    disabled={submitting}
                  />
                </label>
              ) : (
                <p className="security-note">
                  {t("savedHost.editor.proxy.commandKeepNote")}
                </p>
              )}
            </>
          ) : (
            <>
              <label>
                {t("savedHost.editor.proxy.host")}
                <input
                  value={editor.inlineProxyHost}
                  maxLength={253}
                  onChange={(event) => onChange((current) => ({
                    ...current,
                    inlineProxyHost: event.target.value,
                  }))}
                  disabled={submitting}
                />
              </label>
              <label>
                {t("savedHost.editor.proxy.port")}
                <input
                  type="number"
                  min="1"
                  max="65535"
                  value={editor.inlineProxyPort}
                  onChange={(event) => onChange((current) => ({
                    ...current,
                    inlineProxyPort: event.target.value,
                  }))}
                  disabled={submitting}
                />
              </label>
              <label>
                {t("savedHost.editor.proxy.authMethod")}
                <select
                  value={editor.inlineProxyAuthMode}
                  onChange={(event) => onChange((current) => ({
                    ...current,
                    inlineProxyAuthMode: event.target.value as "manual" | "identity",
                    inlineProxyCredentialAction: "keep",
                    inlineProxyPassword: "",
                  }))}
                  disabled={submitting}
                >
                  <option value="manual">{t("savedHost.editor.proxy.authManual")}</option>
                  <option value="identity">{t("savedHost.editor.proxy.authIdentity")}</option>
                </select>
              </label>
              {editor.inlineProxyAuthMode === "identity" ? (
                <label>
                  {t("savedHost.editor.proxy.passwordIdentity")}
                  <select
                    value={editor.inlineProxyIdentityId}
                    onChange={(event) => onChange((current) => ({
                      ...current,
                      inlineProxyIdentityId: event.target.value,
                      inlineProxyPassword: "",
                    }))}
                    disabled={submitting}
                  >
                    <option value="">{t("savedHost.editor.proxy.selectPasswordIdentity")}</option>
                    {passwordIdentities.map((identity) => (
                      <option key={identity.id} value={identity.id}>
                        {identity.label}{identity.username ? ` · ${identity.username}` : ""}
                      </option>
                    ))}
                  </select>
                </label>
              ) : (
                <>
                  <label>
                    {t("savedHost.editor.proxy.username")}
                    <input
                      value={editor.inlineProxyUsername}
                      maxLength={255}
                      autoComplete="username"
                      onChange={(event) => onChange((current) => ({
                        ...current,
                        inlineProxyUsername: event.target.value,
                      }))}
                      disabled={submitting}
                    />
                  </label>
                  <label>
                    {t("savedHost.editor.proxy.passwordHandling")}
                    <select
                      value={editor.inlineProxyCredentialAction}
                      onChange={(event) => onChange((current) => ({
                        ...current,
                        inlineProxyCredentialAction: event.target.value as "keep" | "remove" | "replace",
                        inlineProxyPassword: "",
                      }))}
                      disabled={submitting}
                    >
                      <option value="keep">
                        {editor.mode === "create"
                          ? t("savedHost.editor.proxy.passwordKeepCreate")
                          : t("savedHost.editor.proxy.passwordKeepEdit")}
                      </option>
                      <option value="replace">
                        {editor.mode === "create"
                          ? t("savedHost.editor.proxy.passwordReplaceCreate")
                          : t("savedHost.editor.proxy.passwordReplaceEdit")}
                      </option>
                      {editor.mode === "edit" && (
                        <option value="remove">{t("savedHost.editor.proxy.passwordRemove")}</option>
                      )}
                    </select>
                  </label>
                  {editor.inlineProxyCredentialAction === "replace" && (
                    <label>
                      {t("savedHost.editor.proxy.password")}
                      <input
                        type="password"
                        value={editor.inlineProxyPassword}
                        autoComplete="new-password"
                        onChange={(event) => onChange((current) => ({
                          ...current,
                          inlineProxyPassword: event.target.value,
                        }))}
                        disabled={submitting}
                      />
                    </label>
                  )}
                </>
              )}
            </>
          )}
        </>
      )}
    </>
  );
}
