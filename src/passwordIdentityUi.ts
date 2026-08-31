import type { PasswordIdentityMetadata } from "./backend";
import { errorText, hasErrorCode } from "./errorCode.ts";
import { createTranslator, type Translate } from "./i18n.ts";

const defaultTranslate = createTranslator("zh-CN");

export type PasswordIdentityUiError = {
  kind: "stale" | "inUse" | "repair" | "notFound" | "invalid" | "failed";
  message: string;
  refreshCatalog: boolean;
};

export const normalizePasswordIdentityMetadata = (
  label: string,
  username: string,
): PasswordIdentityMetadata | null => {
  const normalizedLabel = label.trim();
  if (!normalizedLabel) {
    return null;
  }
  return {
    label: normalizedLabel,
    username: username.trim(),
  };
};

export const classifyPasswordIdentityError = (
  error: unknown,
  t: Translate = defaultTranslate,
): PasswordIdentityUiError => {
  const rendered = errorText(error);
  if (
    hasErrorCode(rendered, "PASSWORD_IDENTITY_INVENTORY_CHANGED")
    || hasErrorCode(rendered, "PASSWORD_IDENTITY_CHANGED")
  ) {
    return {
      kind: "stale",
      message: t("passwordIdentity.error.stale"),
      refreshCatalog: true,
    };
  }
  if (hasErrorCode(rendered, "PASSWORD_IDENTITY_IN_USE")) {
    return {
      kind: "inUse",
      message: t("passwordIdentity.error.inUse"),
      refreshCatalog: false,
    };
  }
  if (hasErrorCode(rendered, "PASSWORD_IDENTITY_REPAIR_REQUIRED")) {
    return {
      kind: "repair",
      message: t("passwordIdentity.error.repair"),
      refreshCatalog: false,
    };
  }
  if (hasErrorCode(rendered, "PASSWORD_IDENTITY_NOT_FOUND")) {
    return {
      kind: "notFound",
      message: t("passwordIdentity.error.notFound"),
      refreshCatalog: true,
    };
  }
  if (hasErrorCode(rendered, "PASSWORD_IDENTITY_INVALID")) {
    return {
      kind: "invalid",
      message: t("passwordIdentity.error.invalid"),
      refreshCatalog: false,
    };
  }
  if (hasErrorCode(rendered, "PASSWORD_IDENTITY_PUBLICATION_FAILED")) {
    return {
      kind: "failed",
      message: t("passwordIdentity.error.publicationFailed"),
      refreshCatalog: true,
    };
  }
  return {
    kind: "failed",
    message: t("passwordIdentity.error.failed"),
    refreshCatalog: false,
  };
};
