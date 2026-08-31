import { invoke } from "@tauri-apps/api/core";

/**
 * Renderer-safe projection of the legacy KnownHost record persisted by Vault
 * v9. Runtime host-key prompts and verifier state must never be added here.
 */
export type SavedKnownHost = {
  id: string;
  hostname: string;
  port: number;
  keyType: string;
  publicKey: string;
  fingerprint?: string;
  discoveredAt: number;
  lastSeen?: number;
  convertedToHostId?: string;
  order?: number;
};

export type KnownHostsCatalog = {
  inventoryRevision: unknown;
  knownHosts: SavedKnownHost[];
};

export type ReplaceKnownHostsRequest = {
  expectedInventoryRevision: unknown;
  knownHosts: SavedKnownHost[];
};

export type SystemKnownHostsScan = {
  sourceCount: number;
  knownHosts: SavedKnownHost[];
  omittedCount: number;
};

export const KNOWN_HOSTS_COMMANDS = {
  list: "list_known_hosts",
  replace: "replace_known_hosts",
  scanSystem: "scan_system_known_hosts",
} as const;

export const listKnownHosts = (): Promise<KnownHostsCatalog> =>
  invoke<KnownHostsCatalog>(KNOWN_HOSTS_COMMANDS.list);

export const replaceKnownHosts = (
  request: ReplaceKnownHostsRequest,
): Promise<KnownHostsCatalog> =>
  invoke<KnownHostsCatalog>(KNOWN_HOSTS_COMMANDS.replace, { request });

export const scanSystemKnownHosts = (): Promise<SystemKnownHostsScan> =>
  invoke<SystemKnownHostsScan>(KNOWN_HOSTS_COMMANDS.scanSystem);
