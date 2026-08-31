import type { SavedHost } from "./backend";

export type SearchableSavedHost = Pick<
  SavedHost,
  "label" | "hostname" | "username" | "group" | "passwordIdentity"
>;

export function savedHostMatchesSearch(
  host: SearchableSavedHost,
  query: string,
): boolean {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) return true;

  return [
    host.label,
    host.hostname,
    host.username,
    host.passwordIdentity?.username,
    host.group,
  ].some((value) => value?.toLowerCase().includes(normalizedQuery));
}

export function filterSavedHosts<T extends SearchableSavedHost>(
  hosts: readonly T[],
  query: string,
): T[] {
  if (!query.trim()) return [...hosts];
  return hosts.filter((host) => savedHostMatchesSearch(host, query));
}
