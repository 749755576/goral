import type {
  ProxyCommandMutation,
  ProxyNetworkAuthRequest,
  ProxyProfileConfigRequest,
  ProxyProfileMetadata,
} from "./backend";
import { errorText, hasErrorCode } from "./errorCode.ts";
import { createTranslator, type Translate } from "./i18n.ts";

const defaultTranslate = createTranslator("zh-CN");

export const PROXY_PROFILE_LABEL_MAX_BYTES = 256;
export const PROXY_PROFILE_HOST_MAX_BYTES = 253;
export const PROXY_PROFILE_USERNAME_MAX_BYTES = 255;
export const PROXY_PROFILE_COMMAND_MAX_BYTES = 32 * 1024;

export type ProxyProfileUiError = {
  kind: "stale" | "repair" | "notFound" | "invalid" | "failed";
  message: string;
  refreshCatalog: boolean;
};

const byteLength = (value: string): number => new TextEncoder().encode(value).byteLength;

const containsControlCharacter = (value: string): boolean => (
  Array.from(value).some((character) => /[\u0000-\u001f\u007f-\u009f]/u.test(character))
);

const normalizeText = (
  value: string,
  maximumBytes: number,
  required: boolean,
  rejectWhitespace: boolean,
): string | null => {
  if (containsControlCharacter(value)) {
    return null;
  }
  const normalized = value.trim();
  if ((required && !normalized) || byteLength(normalized) > maximumBytes) {
    return null;
  }
  if (rejectWhitespace && /\s/u.test(normalized)) {
    return null;
  }
  return normalized;
};

export const normalizeProxyCommandMutation = (
  action: "keep" | "replace",
  command: string,
): ProxyCommandMutation | null => {
  if (action === "keep") {
    return { action: "keep" };
  }
  if (command.includes("\0")) {
    return null;
  }
  const normalized = command.trim();
  if (!normalized || byteLength(normalized) > PROXY_PROFILE_COMMAND_MAX_BYTES) {
    return null;
  }
  return { action: "replace", command: normalized };
};

export const normalizeProxyNetworkConfig = (
  type: "http" | "socks5",
  host: string,
  port: string,
  auth: ProxyNetworkAuthRequest,
): ProxyProfileConfigRequest | null => {
  const normalizedHost = normalizeText(
    host,
    PROXY_PROFILE_HOST_MAX_BYTES,
    true,
    true,
  );
  const normalizedPort = Number(port);
  if (
    normalizedHost === null
    || !Number.isInteger(normalizedPort)
    || normalizedPort < 1
    || normalizedPort > 65535
  ) {
    return null;
  }

  let normalizedAuth: ProxyNetworkAuthRequest;
  if (auth.mode === "identity") {
    const identityId = auth.identityId.trim();
    if (!identityId) {
      return null;
    }
    normalizedAuth = { mode: "identity", identityId };
  } else {
    const username = normalizeText(
      auth.username,
      PROXY_PROFILE_USERNAME_MAX_BYTES,
      false,
      false,
    );
    if (username === null) {
      return null;
    }
    normalizedAuth = {
      mode: "manual",
      username,
      credentialMutation: auth.credentialMutation,
    };
  }

  return type === "http"
    ? { type: "http", host: normalizedHost, port: normalizedPort, auth: normalizedAuth }
    : { type: "socks5", host: normalizedHost, port: normalizedPort, auth: normalizedAuth };
};

export const normalizeProxyProfileMetadata = (
  label: string,
  config: ProxyProfileConfigRequest,
): ProxyProfileMetadata | null => {
  const normalizedLabel = normalizeText(
    label,
    PROXY_PROFILE_LABEL_MAX_BYTES,
    true,
    false,
  );
  if (normalizedLabel === null) {
    return null;
  }
  return { label: normalizedLabel, config };
};

export const classifyProxyProfileError = (
  error: unknown,
  t: Translate = defaultTranslate,
): ProxyProfileUiError => {
  const rendered = errorText(error);
  if (
    hasErrorCode(rendered, "PROXY_PROFILE_INVENTORY_CHANGED")
    || hasErrorCode(rendered, "PROXY_PROFILE_CHANGED")
  ) {
    return {
      kind: "stale",
      message: t("proxyProfile.error.stale"),
      refreshCatalog: true,
    };
  }
  if (hasErrorCode(rendered, "PROXY_PROFILE_NOT_FOUND")) {
    return {
      kind: "notFound",
      message: t("proxyProfile.error.notFound"),
      refreshCatalog: true,
    };
  }
  if (hasErrorCode(rendered, "PROXY_PROFILE_REPAIR_REQUIRED")) {
    return {
      kind: "repair",
      message: t("proxyProfile.error.repair"),
      refreshCatalog: false,
    };
  }
  if (hasErrorCode(rendered, "PROXY_PROFILE_INVALID")) {
    return {
      kind: "invalid",
      message: t("proxyProfile.error.invalid"),
      refreshCatalog: false,
    };
  }
  if (hasErrorCode(rendered, "PROXY_PROFILE_PUBLICATION_FAILED")) {
    return {
      kind: "failed",
      message: t("proxyProfile.error.publicationFailed"),
      refreshCatalog: true,
    };
  }
  return {
    kind: "failed",
    message: t("proxyProfile.error.failed"),
    refreshCatalog: false,
  };
};
