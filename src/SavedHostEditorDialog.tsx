import type { FormEventHandler, ReactNode } from "react";

import type {
  ManagedSshKey,
  PasswordIdentity,
  ProxyProfile,
  SavedHost,
} from "./backend";
import { createTranslator, type Locale } from "./i18n";
import {
  SavedHostChainEditor,
  type SavedHostEditor,
} from "./SavedHostChainEditor";
import { SavedHostCredentialFields } from "./SavedHostCredentialFields";
import { SavedHostGeneralFields } from "./SavedHostGeneralFields";
import { SavedHostProxyFields } from "./SavedHostProxyFields";

type SavedHostEditorGlyph = "check" | "hosts" | "key" | "proxy" | "settings" | "tree";

export type SavedHostEditorDialogProps = Readonly<{
  editor: SavedHostEditor;
  locale?: Locale;
  submitting: boolean;
  busy: boolean;
  nativeRuntimeAvailable: boolean;
  error: string | null;
  groups: readonly string[];
  savedHosts: readonly SavedHost[];
  managedSshKeysLoading: boolean;
  managedKeys: readonly ManagedSshKey[];
  passwordIdentities: readonly PasswordIdentity[];
  proxyProfiles: readonly ProxyProfile[];
  onChange: (update: (current: SavedHostEditor) => SavedHostEditor) => void;
  onSubmit: FormEventHandler<HTMLFormElement>;
  onClose: () => void;
  glyph: (name: SavedHostEditorGlyph) => ReactNode;
}>;

/**
 * Controlled SavedHost editor shell. Drafts (including transient credential
 * input), mutation authority, permissions, and native session ownership stay
 * in the workspace; this component owns presentation only.
 */
export function SavedHostEditorDialog({
  editor,
  locale = "zh-CN",
  submitting,
  busy,
  nativeRuntimeAvailable,
  error,
  groups,
  savedHosts,
  managedSshKeysLoading,
  managedKeys,
  passwordIdentities,
  proxyProfiles,
  onChange,
  onSubmit,
  onClose,
  glyph,
}: SavedHostEditorDialogProps) {
  const t = createTranslator(locale);
  const nativeUnavailableMessage = nativeRuntimeAvailable
    ? null
    : t("savedHost.editor.dialog.desktopOnly");
  const saveDisabled = submitting || busy || !nativeRuntimeAvailable;
  const saveButtonTitle = nativeUnavailableMessage ?? t("savedHost.editor.dialog.save");

  return (
    <div className="dialog-backdrop saved-host-editor-backdrop" role="presentation">
      <form
        className="trust-dialog saved-host-dialog saved-host-details-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="saved-host-editor-title"
        onSubmit={onSubmit}
      >
        <header className="saved-host-details-header">
          <div>
            <span className="saved-host-details-kicker">
              {t("savedHost.editor.dialog.kicker", {
                protocol: editor.protocol.toUpperCase(),
              })}
            </span>
            <h2 id="saved-host-editor-title">
              {editor.mode === "create"
                ? t("savedHost.editor.dialog.titleCreate")
                : t("savedHost.editor.dialog.titleEdit")}
            </h2>
          </div>
          <div className="saved-host-details-header-actions">
            <button
              className="saved-host-header-save"
              type="submit"
              disabled={saveDisabled}
              aria-label={nativeUnavailableMessage ?? t("savedHost.editor.dialog.saveAria")}
              title={saveButtonTitle}
            >
              {glyph("check")}
            </button>
            <button
              className="saved-host-header-close"
              type="button"
              disabled={submitting}
              onClick={onClose}
              aria-label={t("savedHost.editor.dialog.closeAria")}
              title={t("savedHost.editor.dialog.close")}
            >
              ×
            </button>
          </div>
        </header>
        <div className="saved-host-details-scroll">
          {nativeUnavailableMessage && (
            <p
              className="saved-host-native-notice"
              role={error === nativeUnavailableMessage ? "alert" : "status"}
            >
              {nativeUnavailableMessage}
            </p>
          )}
          <div className="saved-host-fields">
            <SavedHostGeneralFields
              editor={editor}
              locale={locale}
              submitting={submitting}
              groups={groups}
              onChange={onChange}
              glyph={(name) => glyph(name)}
            />
            <SavedHostCredentialFields
              editor={editor}
              locale={locale}
              savedHostSubmitting={submitting}
              managedSshKeysLoading={managedSshKeysLoading}
              managedKeys={managedKeys}
              passwordIdentities={passwordIdentities}
              onChange={onChange}
              glyph={(name) => glyph(name)}
            />
            {editor.protocol === "ssh" && (
              <>
                <SavedHostProxyFields
                  editor={editor}
                  locale={locale}
                  submitting={submitting}
                  proxyProfiles={proxyProfiles}
                  passwordIdentities={passwordIdentities}
                  onChange={onChange}
                  glyph={(name) => glyph(name)}
                />
                <SavedHostChainEditor
                  editor={editor}
                  locale={locale}
                  savedHosts={savedHosts}
                  submitting={submitting}
                  onChange={onChange}
                  glyph={(name) => glyph(name)}
                />
              </>
            )}
          </div>
          {error && error !== nativeUnavailableMessage && (
            <p className="connection-error" role="alert">{error}</p>
          )}
          {editor.protocol === "ssh" && editor.authMethod !== "password" ? (
            <p className="security-note">
              {editor.authMethod === "certificate"
                ? t("savedHost.editor.dialog.certificateSecurityNote")
                : t("savedHost.editor.dialog.privateKeySecurityNote")}
            </p>
          ) : (
            <p className="security-note">
              {t("savedHost.editor.dialog.passwordSecurityNote")}
            </p>
          )}
        </div>
        <div className="dialog-actions">
          <button type="button" disabled={submitting} onClick={onClose}>
            {t("savedHost.editor.dialog.cancel")}
          </button>
          <button
            className="primary-button"
            type="submit"
            disabled={saveDisabled}
            title={saveButtonTitle}
          >
            {submitting
              ? t("savedHost.editor.dialog.saving")
              : t("savedHost.editor.dialog.save")}
          </button>
        </div>
      </form>
    </div>
  );
}
