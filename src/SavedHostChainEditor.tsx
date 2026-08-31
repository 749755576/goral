import type { ReactNode } from "react";

import type { SavedHost } from "./backend";
import { createTranslator, type Locale } from "./i18n";
import { savedHostEffectiveUsername } from "./savedHostAuth";

export type SavedHostNetworkProtocol = "ssh" | "telnet";

export type SavedHostEditor = {
  mode: "create" | "edit";
  host?: SavedHost;
  label: string;
  group: string;
  tags: string;
  hostname: string;
  port: string;
  username: string;
  protocol: SavedHostNetworkProtocol;
  transportOverride: "inherit" | "ssh" | "mosh" | "et";
  etPort: string;
  authMethod: "password" | "key" | "certificate";
  managedSshKeyId: string;
  hostChainIds: string[];
  hostChainCandidateId: string;
  passwordIdentityId: string;
  password: string;
  removeCredential: boolean;
  proxyProfileId: string;
  inlineProxyEnabled: boolean;
  inlineProxyType: "http" | "socks5" | "command";
  inlineProxyHost: string;
  inlineProxyPort: string;
  inlineProxyAuthMode: "manual" | "identity";
  inlineProxyUsername: string;
  inlineProxyIdentityId: string;
  inlineProxyCredentialAction: "keep" | "remove" | "replace";
  inlineProxyPassword: string;
  inlineProxyCommandAction: "keep" | "replace";
  inlineProxyCommand: string;
  canKeepInlineProxyCommand: boolean;
};

export type SavedHostChainEditorProps = Readonly<{
  editor: SavedHostEditor;
  locale: Locale;
  savedHosts: readonly SavedHost[];
  submitting: boolean;
  onChange: (update: (current: SavedHostEditor) => SavedHostEditor) => void;
  glyph: (name: "tree") => ReactNode;
}>;

/**
 * Ordered jump-host editor. It owns no connection authority; the parent still
 * validates and persists the resulting ordered IDs through the Rust boundary.
 */
export function SavedHostChainEditor({
  editor,
  locale,
  savedHosts,
  submitting,
  onChange,
  glyph,
}: SavedHostChainEditorProps) {
  const t = createTranslator(locale);
  return (
    <>
      <div className="host-editor-section-title">
        {glyph("tree")}
        <span>{t("savedHost.editor.chain.section")}</span>
      </div>
      <div className="host-chain-editor">
        {editor.hostChainIds.length === 0 ? (
          <p className="host-chain-empty">{t("savedHost.editor.chain.direct")}</p>
        ) : (
          <ol className="host-chain-list">
            {editor.hostChainIds.map((hostId, index) => {
              const jumpHost = savedHosts.find((host) => host.id === hostId);
              return (
                <li key={`${hostId}:${index}`}>
                  <span className="host-chain-order">{index + 1}</span>
                  <span className="host-chain-summary">
                    <strong>{jumpHost?.label ?? t("savedHost.editor.chain.missingHost")}</strong>
                    <small>
                      {jumpHost
                        ? `${savedHostEffectiveUsername(jumpHost)}@${jumpHost.hostname}:${jumpHost.port}`
                        : t("savedHost.editor.chain.invalidReference")}
                    </small>
                  </span>
                  <span className="host-chain-actions">
                    <button
                      type="button"
                      disabled={submitting || index === 0}
                      aria-label={t("savedHost.editor.chain.moveUp", {
                        target: jumpHost?.label ?? index + 1,
                      })}
                      onClick={() => onChange((current) => {
                        if (index === 0) return current;
                        const hostChainIds = [...current.hostChainIds];
                        [hostChainIds[index - 1], hostChainIds[index]] = [
                          hostChainIds[index],
                          hostChainIds[index - 1],
                        ];
                        return { ...current, hostChainIds };
                      })}
                    >↑</button>
                    <button
                      type="button"
                      disabled={submitting || index === editor.hostChainIds.length - 1}
                      aria-label={t("savedHost.editor.chain.moveDown", {
                        target: jumpHost?.label ?? index + 1,
                      })}
                      onClick={() => onChange((current) => {
                        if (index >= current.hostChainIds.length - 1) return current;
                        const hostChainIds = [...current.hostChainIds];
                        [hostChainIds[index], hostChainIds[index + 1]] = [
                          hostChainIds[index + 1],
                          hostChainIds[index],
                        ];
                        return { ...current, hostChainIds };
                      })}
                    >↓</button>
                    <button
                      type="button"
                      disabled={submitting}
                      aria-label={t("savedHost.editor.chain.remove", {
                        target: jumpHost?.label ?? index + 1,
                      })}
                      onClick={() => onChange((current) => ({
                        ...current,
                        hostChainIds: current.hostChainIds.filter((_, itemIndex) => (
                          itemIndex !== index
                        )),
                      }))}
                    >×</button>
                  </span>
                </li>
              );
            })}
          </ol>
        )}
        <div className="host-chain-add-row">
          <select
            aria-label={t("savedHost.editor.chain.selectLabel")}
            value={editor.hostChainCandidateId}
            onChange={(event) => onChange((current) => ({
              ...current,
              hostChainCandidateId: event.target.value,
            }))}
            disabled={submitting}
          >
            <option value="">{t("savedHost.editor.chain.selectPlaceholder")}</option>
            {savedHosts
              .filter((host) => (
                host.id !== editor.host?.id
                && host.protocol.toLowerCase() !== "telnet"
                && !editor.hostChainIds.includes(host.id)
              ))
              .map((host) => (
                <option value={host.id} key={host.id}>
                  {host.label} · {savedHostEffectiveUsername(host)}@{host.hostname}
                </option>
              ))}
          </select>
          <button
            type="button"
            disabled={submitting || !editor.hostChainCandidateId}
            onClick={() => onChange((current) => ({
              ...current,
              hostChainIds: current.hostChainCandidateId
                ? [...current.hostChainIds, current.hostChainCandidateId]
                : current.hostChainIds,
              hostChainCandidateId: "",
            }))}
          >{t("savedHost.editor.chain.add")}</button>
        </div>
      </div>
    </>
  );
}
