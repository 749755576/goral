import type { KeyboardEvent } from "react";

import type { SavedHost } from "./backend";
import { HostAvatar, type HostAvatarSize } from "./HostAvatar";
import { createTranslator, type Locale, type Translate } from "./i18n";
import {
  isSavedKeyHost,
  isSavedManagedKeyHost,
  isSavedReferenceKeyHost,
  isSavedUnsupportedKeyHost,
  savedHostPasswordIdentityBinding,
} from "./savedHostAuth";

type SavedHostCatalogCardProps = {
  locale?: Locale;
  host: SavedHost;
  disabled: boolean;
  avatarSize: HostAvatarSize;
  displayAddress: string;
  transportLabel: string;
  proxyProfileLabel: string | null;
  active?: boolean;
  onConnect: (host: SavedHost) => void;
  onEdit: (host: SavedHost) => void;
  onRemove: (host: SavedHost) => void;
};

const isSavedTelnetHost = (host: SavedHost): boolean =>
  host.protocol.toLowerCase() === "telnet";

const isSavedSerialHost = (host: SavedHost): boolean =>
  host.protocol.toLowerCase() === "serial";

const credentialClassName = (host: SavedHost): string => {
  if (isSavedSerialHost(host) || isSavedKeyHost(host) || host.hasSavedCredential) {
    return "credential-saved";
  }
  return "credential-missing";
};

const credentialLabel = (host: SavedHost, t: Translate): string => {
  if (isSavedSerialHost(host)) return t("savedHost.card.serialSaved");
  if (isSavedTelnetHost(host)) {
    return host.hasSavedCredential
      ? t("savedHost.card.telnetPasswordSaved")
      : t("savedHost.card.telnetPasswordPrompt");
  }
  if (isSavedManagedKeyHost(host)) {
    return host.hasSavedKeyPassphrase
      ? t("savedHost.card.managedKeyPassphraseSaved")
      : t("savedHost.card.managedKeySaved");
  }
  if (isSavedReferenceKeyHost(host)) return t("savedHost.card.selectReferenceKey");
  if (isSavedUnsupportedKeyHost(host)) return t("savedHost.card.keyNeedsRepair");
  return host.hasSavedCredential
    ? t("savedHost.card.passwordSaved")
    : t("savedHost.card.passwordPrompt");
};

export function SavedHostCatalogCard({
  locale = "zh-CN",
  host,
  disabled,
  avatarSize,
  displayAddress,
  transportLabel,
  proxyProfileLabel,
  active = false,
  onConnect,
  onEdit,
  onRemove,
}: SavedHostCatalogCardProps) {
  const t = createTranslator(locale);
  const passwordIdentity = savedHostPasswordIdentityBinding(host);

  const handleKeyDown = (event: KeyboardEvent<HTMLElement>) => {
    if ((event.target as HTMLElement).closest("button")) return;
    if (disabled || (event.key !== "Enter" && event.key !== " ")) return;
    event.preventDefault();
    onConnect(host);
  };

  return (
    <article
      className={`saved-host-card${active ? " active" : ""}`}
      data-host-protocol={host.protocol.toLowerCase()}
      data-credential-state={credentialClassName(host)}
      role="button"
      tabIndex={disabled ? -1 : 0}
      aria-disabled={disabled}
      aria-current={active ? "page" : undefined}
      aria-label={t("savedHost.card.connect", { host: host.label })}
      onClick={() => {
        if (!disabled) onConnect(host);
      }}
      onKeyDown={handleKeyDown}
    >
      <HostAvatar
        host={{ protocol: host.protocol, ...host.visual }}
        size={avatarSize}
        className="saved-host-avatar"
      />
      <div className="saved-host-summary">
        <strong title={host.label}>{host.label}</strong>
        <small className="saved-host-address" title={displayAddress}>
          {displayAddress} · {transportLabel}
        </small>
        {passwordIdentity && (
          <small className="saved-host-secondary-meta" title={passwordIdentity.id}>
            {t("savedHost.card.boundIdentity", { identity: passwordIdentity.label })}
            {passwordIdentity.username
              ? t("savedHost.card.identityUsername", { username: passwordIdentity.username })
              : t("savedHost.card.hostUsername")}
          </small>
        )}
        {host.proxy?.inlineProxy ? (
          <small className="saved-host-secondary-meta">
            {host.proxy.inlineProxy.type === "command"
              ? t("savedHost.card.inlineCommandProxy")
              : t("savedHost.card.inlineProxy", {
                type: host.proxy.inlineProxy.type.toUpperCase(),
                address: `${host.proxy.inlineProxy.host}:${host.proxy.inlineProxy.port}`,
              })}
          </small>
        ) : host.proxy?.proxyProfileId && proxyProfileLabel ? (
          <small className="saved-host-secondary-meta" title={host.proxy.proxyProfileId}>
            {t("savedHost.card.proxyProfile", { profile: proxyProfileLabel })}
          </small>
        ) : null}
        <span className={`saved-host-credential-state ${credentialClassName(host)}`}>
          {credentialLabel(host, t)}
        </span>
      </div>
      <span className="saved-host-connect-indicator" aria-hidden="true">↗</span>
      <div className="saved-host-actions">
        <button
          type="button"
          disabled={disabled}
          onClick={(event) => {
            event.stopPropagation();
            onEdit(host);
          }}
        >
          {t("savedHost.card.edit")}
        </button>
        <button
          className="saved-host-delete"
          type="button"
          disabled={disabled}
          onClick={(event) => {
            event.stopPropagation();
            onRemove(host);
          }}
        >
          {t("savedHost.card.delete")}
        </button>
      </div>
    </article>
  );
}
