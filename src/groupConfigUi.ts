import type {
  GroupConfig,
  GroupConfigDefaults,
  GroupConfigDefaultsRequest,
  GroupConfigOverride,
  GroupConfigProxyOverride,
} from "./backend";

export type GroupConfigIssue = {
  kind: "invalid" | "notFound" | "changed" | "stale" | "publication" | "repair" | "failed";
  messageKey:
    | "groupConfig.error.invalid"
    | "groupConfig.error.notFound"
    | "groupConfig.error.changed"
    | "groupConfig.error.stale"
    | "groupConfig.error.publication"
    | "groupConfig.error.repair"
    | "groupConfig.error.failed";
  refreshCatalog: boolean;
};

const inherit = <T>(): GroupConfigOverride<T> => ({ state: "inherit" });

export const newGroupDefaultsRequest = (): GroupConfigDefaultsRequest => ({
  order: inherit<number>(),
  username: inherit<string>(),
  password: "inherit",
  savePassword: inherit<boolean>(),
  authMethod: inherit<"auto" | "password" | "key" | "certificate">(),
  identityId: inherit(),
  identityFileId: inherit<string>(),
  identityFilePaths: inherit<string[]>(),
  port: inherit<number>(),
  protocol: inherit<"ssh" | "telnet">(),
  deviceType: inherit<"general" | "network">(),
  agentForwarding: inherit<boolean>(),
  proxy: { state: "inherit" },
  hostChain: inherit<string[]>(),
  startupCommand: inherit<string>(),
  startupCommandRunMode: inherit<"lineDelay" | "paste">(),
  loginScriptId: inherit<string>(),
  legacyAlgorithms: inherit<boolean>(),
  skipEcdsaHostKey: inherit<boolean>(),
  algorithms: inherit(),
  environmentVariables: inherit(),
  charset: inherit<string>(),
  moshEnabled: inherit<boolean>(),
  moshServerPath: inherit<string>(),
  etEnabled: inherit<boolean>(),
  etPort: inherit<number>(),
  telnetEnabled: inherit<boolean>(),
  telnetPort: inherit<number>(),
  telnetIdentityId: inherit<string>(),
  telnetUsername: inherit<string>(),
  telnetPassword: "inherit",
  theme: inherit<string>(),
  themeOverride: inherit<boolean>(),
  fontFamily: inherit<string>(),
  fontFamilyOverride: inherit<boolean>(),
  fontSize: inherit<number>(),
  fontSizeOverride: inherit<boolean>(),
  fontWeight: inherit<number>(),
  fontWeightOverride: inherit<boolean>(),
  backspaceBehavior: inherit<"ctrl-h">(),
});

export type EditableGroupDefaults = {
  defaults: GroupConfigDefaultsRequest;
  sshPasswordStored: boolean;
  telnetPasswordStored: boolean;
  proxyPasswordStored: boolean;
  proxyCommandStored: boolean;
};

/** Converts a renderer-safe backend view back into a hint-free mutation draft. */
export const editableGroupDefaults = (group?: GroupConfig): EditableGroupDefaults => {
  if (!group) {
    return {
      defaults: newGroupDefaultsRequest(),
      sshPasswordStored: false,
      telnetPasswordStored: false,
      proxyPasswordStored: false,
      proxyCommandStored: false,
    };
  }
  const defaults = JSON.parse(JSON.stringify(group.defaults)) as GroupConfigDefaultsRequest;
  const sshPasswordStored = group.defaults.password === "storedHint";
  const telnetPasswordStored = group.defaults.telnetPassword === "storedHint";
  defaults.password = group.defaults.password === "clear" ? "clear" : "inherit";
  defaults.telnetPassword = group.defaults.telnetPassword === "clear" ? "clear" : "inherit";

  let proxyPasswordStored = false;
  let proxyCommandStored = false;
  if (defaults.proxy?.state === "inline") {
    if (defaults.proxy.value.type === "command") {
      proxyCommandStored = true;
    } else {
      proxyPasswordStored = group.defaults.proxy.state === "inline"
        && group.defaults.proxy.value.type !== "command"
        && group.defaults.proxy.value.hasSavedCredential;
      defaults.proxy.value.hasSavedCredential = false;
    }
  }
  return {
    defaults,
    sshPasswordStored,
    telnetPasswordStored,
    proxyPasswordStored,
    proxyCommandStored,
  };
};

/** Mirrors SavedGroupPath: only slash is structural and empty slash parts collapse. */
export const normalizeGroupConfigPath = (value: string): string | null => {
  const normalized = value.split("/").filter((segment) => segment.length > 0).join("/");
  return normalized && new TextEncoder().encode(normalized).length <= 32 * 1024
    ? normalized
    : null;
};

const pathAncestors = (value: string): string[] => {
  const segments = value.split("/").filter((segment) => segment.length > 0);
  return segments.map((_, index) => segments.slice(0, index + 1).join("/"));
};

export type EffectiveGroupDefaults = Partial<Record<keyof GroupConfigDefaults, unknown>>;

/** Root-to-leaf preview using the same inherit / clear / set behavior as Rust. */
export const resolveEffectiveGroupDefaults = (
  path: string,
  groups: readonly GroupConfig[],
): EffectiveGroupDefaults => {
  const byPath = new Map(groups.map((group) => [group.path, group.defaults]));
  const effective: EffectiveGroupDefaults = {};
  for (const ancestor of pathAncestors(path)) {
    const defaults = byPath.get(ancestor);
    if (!defaults) continue;
    for (const [key, override] of Object.entries(defaults) as Array<[
      keyof GroupConfigDefaults,
      GroupConfigDefaults[keyof GroupConfigDefaults],
    ]>) {
      if (key === "password" || key === "telnetPassword") {
        if (override === "inherit") continue;
        if (override === "clear") delete effective[key];
        else effective[key] = "storedHint";
        continue;
      }
      if (key === "proxy") {
        const proxy = override as GroupConfigProxyOverride;
        if (proxy.state === "inherit") continue;
        if (proxy.state === "clear") delete effective.proxy;
        else effective.proxy = proxy;
        continue;
      }
      const scalar = override as GroupConfigOverride<unknown>;
      if (scalar.state === "inherit") continue;
      if (scalar.state === "clear") delete effective[key];
      else effective[key] = scalar.value;
    }
  }
  return effective;
};

const rawError = (reason: unknown): string => reason instanceof Error ? reason.message : String(reason);

export const classifyGroupConfigError = (reason: unknown): GroupConfigIssue => {
  const raw = rawError(reason);
  const has = (code: string) => raw.split("; ").some((part) => part.startsWith(code));
  if (has("GROUP_CONFIG_INVALID")) {
    return { kind: "invalid", messageKey: "groupConfig.error.invalid", refreshCatalog: false };
  }
  if (has("GROUP_CONFIG_NOT_FOUND")) {
    return { kind: "notFound", messageKey: "groupConfig.error.notFound", refreshCatalog: true };
  }
  if (has("GROUP_CONFIG_CHANGED")) {
    return { kind: "changed", messageKey: "groupConfig.error.changed", refreshCatalog: true };
  }
  if (has("GROUP_CONFIG_INVENTORY_CHANGED")) {
    return { kind: "stale", messageKey: "groupConfig.error.stale", refreshCatalog: true };
  }
  if (has("GROUP_CONFIG_PUBLICATION_FAILED")) {
    return { kind: "publication", messageKey: "groupConfig.error.publication", refreshCatalog: true };
  }
  if (has("GROUP_CONFIG_REPAIR_REQUIRED")) {
    return { kind: "repair", messageKey: "groupConfig.error.repair", refreshCatalog: false };
  }
  return { kind: "failed", messageKey: "groupConfig.error.failed", refreshCatalog: false };
};
