import type { ReactNode } from "react";

import type {
  ManagedSshKey,
  PasswordIdentity,
} from "./backend";
import { createTranslator, type Locale } from "./i18n";
import type {
  SavedHostEditor,
  SavedHostNetworkProtocol,
} from "./SavedHostChainEditor";
import { hasSavedHostOwnedCredential } from "./savedHostAuth";
import { resolveQuickConnectProtocolPort } from "./telnetLocalEcho";

export type SavedHostCredentialFieldsProps = Readonly<{
  editor: SavedHostEditor;
  locale: Locale;
  savedHostSubmitting: boolean;
  managedSshKeysLoading: boolean;
  managedKeys: readonly ManagedSshKey[];
  passwordIdentities: readonly PasswordIdentity[];
  onChange: (update: (current: SavedHostEditor) => SavedHostEditor) => void;
  glyph: (name: "key") => ReactNode;
}>;

/**
 * Saved-host authentication controls. The workspace retains form ownership and
 * persistence; this component only edits the parent-owned draft snapshot.
 */
export function SavedHostCredentialFields({
  editor,
  locale,
  savedHostSubmitting,
  managedSshKeysLoading,
  managedKeys,
  passwordIdentities,
  onChange,
  glyph,
}: SavedHostCredentialFieldsProps) {
  const t = createTranslator(locale);
  return (
    <>
      <div className="host-editor-section-title">
        {glyph("key")}
        <span>{t("savedHost.editor.credentials.section")}</span>
      </div>
      <label>
        {t("savedHost.editor.credentials.protocol")}
        <select
          value={editor.protocol}
          onChange={(event) => {
            const protocol = event.target.value as SavedHostNetworkProtocol;
            onChange((current) => ({
              ...current,
              port: resolveQuickConnectProtocolPort(current.port, current.protocol, protocol),
              protocol,
              transportOverride: "inherit",
              etPort: "",
              authMethod: "password",
              managedSshKeyId: "",
              passwordIdentityId: "",
              hostChainIds: protocol === "telnet" ? [] : current.hostChainIds,
              hostChainCandidateId: "",
              proxyProfileId: protocol === "telnet" ? "" : current.proxyProfileId,
              inlineProxyEnabled: protocol === "telnet" ? false : current.inlineProxyEnabled,
              password: "",
              removeCredential: false,
            }));
          }}
          disabled={savedHostSubmitting}
        >
          <option value="ssh">{t("savedHost.editor.credentials.protocolSsh")}</option>
          <option value="telnet">{t("savedHost.editor.credentials.protocolTelnet")}</option>
        </select>
      </label>
      {editor.protocol === "ssh" && (
        <>
          <label>
            {t("savedHost.editor.credentials.transport")}
            <select
              value={editor.transportOverride}
              onChange={(event) => onChange((current) => ({
                ...current,
                transportOverride: event.target.value as SavedHostEditor["transportOverride"],
              }))}
              disabled={savedHostSubmitting}
            >
              <option value="inherit">{t("savedHost.editor.credentials.transportInherit")}</option>
              <option value="ssh">{t("savedHost.editor.credentials.transportSsh")}</option>
              <option value="mosh">{t("savedHost.editor.credentials.transportMosh")}</option>
              <option value="et">{t("savedHost.editor.credentials.transportEt")}</option>
            </select>
          </label>
          <label>
            {t("savedHost.editor.credentials.etPort")}
            <input
              type="number"
              min="1"
              max="65535"
              value={editor.etPort}
              onChange={(event) => onChange((current) => ({
                ...current,
                etPort: event.target.value,
              }))}
              placeholder={t("savedHost.editor.credentials.etPortPlaceholder")}
              disabled={savedHostSubmitting}
            />
          </label>
        </>
      )}
      <label>
        {t("savedHost.editor.credentials.authMethod")}
        <select
          value={editor.authMethod}
          onChange={(event) => onChange((current) => ({
            ...current,
            authMethod: event.target.value as "password" | "key" | "certificate",
            managedSshKeyId: "",
            passwordIdentityId: "",
            password: "",
            removeCredential: false,
          }))}
          disabled={savedHostSubmitting || editor.protocol === "telnet"}
        >
          <option value="password">{t("savedHost.editor.credentials.authPassword")}</option>
          <option value="key">{t("savedHost.editor.credentials.authKey")}</option>
          <option value="certificate">{t("savedHost.editor.credentials.authCertificate")}</option>
        </select>
      </label>
      {editor.authMethod === "password" && (
        <label>
          {t("savedHost.editor.credentials.passwordIdentity")}
          <select
            value={editor.passwordIdentityId}
            onChange={(event) => onChange((current) => ({
              ...current,
              passwordIdentityId: event.target.value,
            }))}
            disabled={savedHostSubmitting}
          >
            <option value="">{t("savedHost.editor.credentials.passwordIdentityNone")}</option>
            {passwordIdentities.map((identity) => (
              <option key={identity.id} value={identity.id}>
                {identity.label}
                {identity.username
                  ? ` · ${identity.username}`
                  : t("savedHost.editor.credentials.usesHostUsernameSuffix")}
              </option>
            ))}
            {editor.passwordIdentityId
              && !passwordIdentities.some((identity) => identity.id === editor.passwordIdentityId)
              && editor.host?.passwordIdentity && (
              <option value={editor.host.passwordIdentity.id}>
                {editor.host.passwordIdentity.label}
                {t("savedHost.editor.credentials.refreshingSuffix")}
              </option>
            )}
          </select>
        </label>
      )}
      {editor.authMethod === "password" && (
        <label>
          {editor.mode === "create"
            ? t("savedHost.editor.credentials.passwordCreate")
            : t("savedHost.editor.credentials.passwordEdit")}
          <input
            type="password"
            value={editor.password}
            onChange={(event) => onChange((current) => ({
              ...current,
              password: event.target.value,
              removeCredential: false,
            }))}
            placeholder={editor.mode === "edit"
              ? t("savedHost.editor.credentials.passwordEditPlaceholder")
              : t("savedHost.editor.credentials.passwordCreatePlaceholder")}
            disabled={savedHostSubmitting || editor.removeCredential}
            autoComplete="new-password"
          />
        </label>
      )}
      {editor.protocol === "ssh" && editor.authMethod !== "password" && (
        <label>
          {editor.authMethod === "certificate"
            ? t("savedHost.editor.credentials.sshCertificate")
            : t("savedHost.editor.credentials.sshPrivateKey")}
          <select
            value={editor.managedSshKeyId}
            onChange={(event) => onChange((current) => ({
              ...current,
              managedSshKeyId: event.target.value,
            }))}
            disabled={savedHostSubmitting || managedSshKeysLoading}
            required
          >
            <option value="">
              {managedSshKeysLoading
                ? t("savedHost.editor.credentials.keychainLoading")
                : editor.authMethod === "certificate"
                  ? t("savedHost.editor.credentials.selectCertificate")
                  : t("savedHost.editor.credentials.selectPrivateKey")}
            </option>
            {managedKeys
              .filter((key) => key.category === editor.authMethod)
              .map((key) => (
                <option value={key.id} key={key.id}>
                  {key.label}
                  {key.hasSavedPassphrase
                    ? t("savedHost.editor.credentials.savedPassphraseSuffix")
                    : ""}
                </option>
              ))}
            {editor.managedSshKeyId
              && !managedKeys.some((key) => key.id === editor.managedSshKeyId) && (
              <option value={editor.managedSshKeyId}>
                {t("savedHost.editor.credentials.currentManagedRefreshing")}
              </option>
            )}
          </select>
          {!managedSshKeysLoading
            && !managedKeys.some((key) => key.category === editor.authMethod) && (
            <small className="host-editor-field-hint">
              {t("savedHost.editor.credentials.noManagedCredentials")}
            </small>
          )}
        </label>
      )}
      {editor.mode === "edit"
        && editor.host
        && editor.authMethod === "password"
        && hasSavedHostOwnedCredential(editor.host) && (
        <label className="remove-credential-option">
          <input
            type="checkbox"
            checked={editor.removeCredential}
            onChange={(event) => onChange((current) => ({
              ...current,
              removeCredential: event.target.checked,
              password: "",
            }))}
            disabled={savedHostSubmitting}
          />
          {t("savedHost.editor.credentials.removeHostPassword")}
        </label>
      )}
    </>
  );
}
