import type { SavedKnownHost } from "./knownHostsApi";
import { createTranslator, type Translate } from "./i18n.ts";

const DEFAULT_TRANSLATOR = createTranslator("zh-CN");

export type KnownHostsSortMode = "manual" | "az" | "za" | "newest" | "oldest";
export type KnownHostsViewMode = "grid" | "list";

export type KnownHostsIssue = {
  message: string;
  refreshCatalog: boolean;
};

export type ParseKnownHostsOptions = {
  now?: () => number;
  idFactory?: (index: number, discoveredAt: number) => string;
};

export const KNOWN_HOSTS_IMPORT_MAX_BYTES = 8 * 1024 * 1024;
export const KNOWN_HOSTS_IMPORT_MAX_ENTRIES = 10_000;
export const KNOWN_HOSTS_IMPORT_MAX_LINE_BYTES = 20 * 1024;
const MAX_HOSTNAME_BYTES = 1_024;
const MAX_KEY_TYPE_BYTES = 128;
const MAX_PUBLIC_KEY_BYTES = 16 * 1024;
const textEncoder = new TextEncoder();

const PUBLIC_SERVICE_HOSTNAMES = new Set([
  "github.com",
  "gitlab.com",
  "bitbucket.org",
  "ssh.dev.azure.com",
  "vs-ssh.visualstudio.com",
]);

const normalizeHostname = (hostname: string): string => hostname.trim().toLocaleLowerCase();
const knownHostSelectorKey = (knownHost: Pick<SavedKnownHost, "hostname" | "port" | "keyType">): string =>
  `${normalizeHostname(knownHost.hostname)}\u0000${knownHost.port}\u0000${knownHost.keyType}`;

export const isPublicServiceKnownHost = (hostname: string): boolean =>
  PUBLIC_SERVICE_HOSTNAMES.has(normalizeHostname(hostname));

export const sameKnownHostSelector = (
  left: SavedKnownHost,
  right: SavedKnownHost,
): boolean => normalizeHostname(left.hostname) === normalizeHostname(right.hostname)
  && left.port === right.port
  && left.keyType === right.keyType;

/** Mirrors the legacy domain upsert: exact ID wins, then host/port/key type. */
export const upsertKnownHost = (
  knownHosts: readonly SavedKnownHost[],
  incoming: SavedKnownHost,
): SavedKnownHost[] => {
  const idIndex = knownHosts.findIndex((existing) => existing.id === incoming.id);
  const index = idIndex >= 0
    ? idIndex
    : knownHosts.findIndex((existing) => sameKnownHostSelector(existing, incoming));
  if (index < 0) return [...knownHosts, incoming];

  const existing = knownHosts[index];
  const updated: SavedKnownHost = {
    ...existing,
    ...incoming,
    id: existing.id,
    discoveredAt: existing.discoveredAt,
    convertedToHostId: existing.convertedToHostId ?? incoming.convertedToHostId,
    lastSeen: incoming.lastSeen ?? incoming.discoveredAt,
  };
  return [
    ...knownHosts.slice(0, index),
    updated,
    ...knownHosts.slice(index + 1),
  ];
};

export const mergeKnownHosts = (
  current: readonly SavedKnownHost[],
  incoming: readonly SavedKnownHost[],
): SavedKnownHost[] => {
  if (current.length > KNOWN_HOSTS_IMPORT_MAX_ENTRIES) {
    throw new Error("KNOWN_HOSTS_CATALOG_TOO_LARGE");
  }
  const merged = [...current];
  const firstIndexById = new Map<string, number>();
  const firstIndexBySelector = new Map<string, number>();
  merged.forEach((knownHost, index) => {
    if (!firstIndexById.has(knownHost.id)) firstIndexById.set(knownHost.id, index);
    const selector = knownHostSelectorKey(knownHost);
    if (!firstIndexBySelector.has(selector)) firstIndexBySelector.set(selector, index);
  });

  for (const knownHost of incoming) {
    const selector = knownHostSelectorKey(knownHost);
    const index = firstIndexById.get(knownHost.id) ?? firstIndexBySelector.get(selector);
    if (index === undefined) {
      if (merged.length >= KNOWN_HOSTS_IMPORT_MAX_ENTRIES) {
        throw new Error("KNOWN_HOSTS_CATALOG_TOO_LARGE");
      }
      const appendedIndex = merged.length;
      merged.push(knownHost);
      if (!firstIndexById.has(knownHost.id)) firstIndexById.set(knownHost.id, appendedIndex);
      if (!firstIndexBySelector.has(selector)) firstIndexBySelector.set(selector, appendedIndex);
      continue;
    }

    const existing = merged[index];
    const previousSelector = knownHostSelectorKey(existing);
    const updated: SavedKnownHost = {
      ...existing,
      ...knownHost,
      id: existing.id,
      discoveredAt: existing.discoveredAt,
      convertedToHostId: existing.convertedToHostId ?? knownHost.convertedToHostId,
      lastSeen: knownHost.lastSeen ?? knownHost.discoveredAt,
    };
    merged[index] = updated;

    const updatedSelector = knownHostSelectorKey(updated);
    if (previousSelector !== updatedSelector && firstIndexBySelector.get(previousSelector) === index) {
      firstIndexBySelector.delete(previousSelector);
      const nextPreviousIndex = merged.findIndex((candidate, candidateIndex) =>
        candidateIndex !== index && knownHostSelectorKey(candidate) === previousSelector);
      if (nextPreviousIndex >= 0) firstIndexBySelector.set(previousSelector, nextPreviousIndex);
    }
    const currentUpdatedIndex = firstIndexBySelector.get(updatedSelector);
    if (currentUpdatedIndex === undefined || index < currentUpdatedIndex) {
      firstIndexBySelector.set(updatedSelector, index);
    }
  }
  return merged;
};

const compareOptionalOrder = (left: SavedKnownHost, right: SavedKnownHost): number => {
  if (typeof left.order === "number" && typeof right.order === "number") {
    return left.order - right.order;
  }
  if (typeof left.order === "number") return -1;
  if (typeof right.order === "number") return 1;
  return 0;
};

export const sortKnownHosts = (
  knownHosts: readonly SavedKnownHost[],
  mode: KnownHostsSortMode,
): SavedKnownHost[] => [...knownHosts].sort((left, right) => {
  if (mode === "manual") return compareOptionalOrder(left, right);
  if (mode === "az") return left.hostname.localeCompare(right.hostname);
  if (mode === "za") return right.hostname.localeCompare(left.hostname);
  if (mode === "newest") return right.discoveredAt - left.discoveredAt;
  return left.discoveredAt - right.discoveredAt;
});

/** The legacy page displays only the newest record for each hostname. */
export const dedupeKnownHostsForDisplay = (
  knownHosts: readonly SavedKnownHost[],
): SavedKnownHost[] => {
  const byHostname = new Map<string, SavedKnownHost>();
  for (const knownHost of knownHosts) {
    const key = normalizeHostname(knownHost.hostname);
    const current = byHostname.get(key);
    if (!current || knownHost.discoveredAt > current.discoveredAt) {
      byHostname.set(key, knownHost);
    }
  }
  return Array.from(byHostname.values());
};

export const matchesKnownHostSearch = (
  knownHost: SavedKnownHost,
  query: string,
): boolean => {
  const needle = query.trim().toLocaleLowerCase();
  if (!needle) return true;
  return knownHost.hostname.toLocaleLowerCase().includes(needle)
    || knownHost.keyType.toLocaleLowerCase().includes(needle);
};

export const reorderKnownHosts = (
  knownHosts: readonly SavedKnownHost[],
  sourceId: string,
  targetId: string,
  position: "before" | "after" = "before",
): SavedKnownHost[] => {
  const ordered = sortKnownHosts(knownHosts, "manual");
  const sourceIndex = ordered.findIndex((knownHost) => knownHost.id === sourceId);
  const targetIndex = ordered.findIndex((knownHost) => knownHost.id === targetId);
  if (sourceIndex < 0 || targetIndex < 0 || sourceIndex === targetIndex) return ordered;
  const [source] = ordered.splice(sourceIndex, 1);
  const remainingTargetIndex = ordered.findIndex((knownHost) => knownHost.id === targetId);
  ordered.splice(remainingTargetIndex + (position === "after" ? 1 : 0), 0, source);
  return ordered.map((knownHost, order) => ({ ...knownHost, order }));
};

const decodeBase64 = (value: string): Uint8Array | null => {
  try {
    const decoded = globalThis.atob(value);
    return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
};

const bytesToBase64 = (bytes: Uint8Array): string => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return globalThis.btoa(binary).replace(/=+$/g, "");
};

export const fingerprintFromPublicKey = async (
  publicKey: string,
): Promise<string | undefined> => {
  const encoded = publicKey.trim().split(/\s+/)[1];
  if (!encoded || !globalThis.crypto?.subtle) return undefined;
  const raw = decodeBase64(encoded);
  if (!raw) return undefined;
  try {
    const digestInput = new Uint8Array(raw.byteLength);
    digestInput.set(raw);
    const digest = await globalThis.crypto.subtle.digest("SHA-256", digestInput.buffer);
    return bytesToBase64(new Uint8Array(digest));
  } catch {
    return undefined;
  }
};

const defaultKnownHostId = (index: number, discoveredAt: number): string => {
  const suffix = globalThis.crypto?.randomUUID?.()
    ?? `${Math.random().toString(36).slice(2, 11)}-${index}`;
  return `kh-${discoveredAt}-${suffix}`;
};

/** Parses the same ordinary OpenSSH lines accepted by the legacy file import. */
export const parseKnownHostsFile = async (
  content: string,
  options: ParseKnownHostsOptions = {},
): Promise<SavedKnownHost[]> => {
  if (textEncoder.encode(content).byteLength > KNOWN_HOSTS_IMPORT_MAX_BYTES) {
    throw new Error("KNOWN_HOSTS_FILE_TOO_LARGE");
  }
  const now = options.now ?? Date.now;
  const idFactory = options.idFactory ?? defaultKnownHostId;
  const entries: SavedKnownHost[] = [];
  const lines = content.split(/\r?\n/).filter((line) => line.trim() && !line.trimStart().startsWith("#"));

  for (let index = 0; index < lines.length; index += 1) {
    if (textEncoder.encode(lines[index]).byteLength > KNOWN_HOSTS_IMPORT_MAX_LINE_BYTES) {
      throw new Error("KNOWN_HOSTS_LINE_TOO_LARGE");
    }
    const parts = lines[index].trim().split(/\s+/);
    if (parts.length < 3) continue;
    // Marker lines carry revocation or certificate-authority semantics and
    // must never be flattened into ordinary trusted-host records.
    if (parts[0].startsWith("@")) continue;
    const [hostPattern, keyType, encodedKey] = parts;
    let hostname = hostPattern;
    let port = 22;
    const bracketed = hostPattern.match(/^\[([^\]]+)\]:(\d+)$/);
    if (bracketed) {
      hostname = bracketed[1];
      port = Number(bracketed[2]);
    } else if (hostPattern.includes(",")) {
      hostname = hostPattern.split(",")[0];
    }
    if (hostname.startsWith("|1|")) hostname = "(hashed)";
    if (!hostname || !keyType || !encodedKey || !Number.isInteger(port) || port < 1 || port > 65535) {
      continue;
    }
    const discoveredAt = Math.max(1, Math.trunc(now()));
    const publicKey = `${keyType} ${encodedKey}`;
    if (
      textEncoder.encode(hostname).byteLength > MAX_HOSTNAME_BYTES
      || textEncoder.encode(keyType).byteLength > MAX_KEY_TYPE_BYTES
      || textEncoder.encode(publicKey).byteLength > MAX_PUBLIC_KEY_BYTES
    ) {
      continue;
    }
    if (entries.length >= KNOWN_HOSTS_IMPORT_MAX_ENTRIES) {
      throw new Error("KNOWN_HOSTS_CATALOG_TOO_LARGE");
    }
    const fingerprint = await fingerprintFromPublicKey(publicKey);
    entries.push({
      id: idFactory(index, discoveredAt),
      hostname,
      port,
      keyType,
      publicKey,
      ...(fingerprint ? { fingerprint } : {}),
      discoveredAt,
    });
  }
  return entries;
};

export const withoutPublicServiceKnownHosts = (
  knownHosts: readonly SavedKnownHost[],
): SavedKnownHost[] => knownHosts.filter(
  (knownHost) => !isPublicServiceKnownHost(knownHost.hostname),
);

const safeErrorText = (reason: unknown): string => {
  if (reason instanceof Error) return reason.message.toUpperCase();
  return typeof reason === "string" ? reason.toUpperCase() : "";
};

export const classifyKnownHostsError = (
  reason: unknown,
  t: Translate = DEFAULT_TRANSLATOR,
): KnownHostsIssue => {
  const text = safeErrorText(reason);
  if (text.includes("KNOWN_HOSTS_INVENTORY_CHANGED") || text.includes("INVENTORY_CHANGED")) {
    return {
      message: t("knownHosts.error.stale"),
      refreshCatalog: true,
    };
  }
  if (text.includes("INVALID") || text.includes("VALIDATION") || text.includes("TOO_LARGE")) {
    return {
      message: t("knownHosts.error.invalid"),
      refreshCatalog: false,
    };
  }
  return {
    message: t("knownHosts.error.failed"),
    refreshCatalog: false,
  };
};
