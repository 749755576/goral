import type { HostKeyPrompt } from "./backend";
import type { SavedKnownHost } from "./knownHostsApi";

export type HostKeyTrustOptions = {
  now?: () => number;
  idFactory?: (discoveredAt: number) => string;
};

const defaultIdFactory = (discoveredAt: number): string => {
  const suffix = globalThis.crypto?.randomUUID?.()
    ?? Math.random().toString(36).slice(2, 11);
  return `kh-${discoveredAt}-${suffix}`;
};

const sameSelector = (
  knownHost: SavedKnownHost,
  prompt: HostKeyPrompt,
): boolean => knownHost.hostname.trim().toLocaleLowerCase()
  === prompt.hostname.trim().toLocaleLowerCase()
  && knownHost.port === prompt.port
  && knownHost.keyType === prompt.keyType;

/**
 * Converts one accepted live SSH key into the durable legacy KnownHost shape.
 * A changed key keeps its original record identity and discovery timestamp.
 */
export const buildKnownHostsAfterTrust = (
  knownHosts: readonly SavedKnownHost[],
  prompt: HostKeyPrompt,
  options: HostKeyTrustOptions = {},
): SavedKnownHost[] => {
  const observedAt = Math.max(1, Math.trunc((options.now ?? Date.now)()));
  const existing = knownHosts.find((knownHost) =>
    knownHost.id === prompt.knownHostId
      || sameSelector(knownHost, prompt));

  const incoming: SavedKnownHost = {
    id: prompt.knownHostId
      ?? existing?.id
      ?? (options.idFactory ?? defaultIdFactory)(observedAt),
    hostname: prompt.hostname,
    port: prompt.port,
    keyType: prompt.keyType,
    publicKey: prompt.publicKey,
    fingerprint: prompt.fingerprint,
    discoveredAt: existing?.discoveredAt ?? observedAt,
    ...(existing ? { lastSeen: observedAt } : {}),
    ...(existing?.convertedToHostId
      ? { convertedToHostId: existing.convertedToHostId }
      : {}),
    ...(typeof existing?.order === "number" ? { order: existing.order } : {}),
  };

  const existingIndex = knownHosts.findIndex((knownHost) => knownHost === existing);
  if (existingIndex < 0) return [...knownHosts, incoming];
  return [
    ...knownHosts.slice(0, existingIndex),
    incoming,
    ...knownHosts.slice(existingIndex + 1),
  ];
};
