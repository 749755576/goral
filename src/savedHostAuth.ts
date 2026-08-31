import type { SavedHost, SavedHostPasswordIdentity } from "./backend";

export type SavedHostCredentialState = Readonly<{
  hostOwned: boolean;
  identityOwned: boolean;
  effective: boolean;
}>;

export const savedHostPasswordIdentityBinding = (
  host: SavedHost,
): SavedHostPasswordIdentity | null => host.passwordIdentity ?? null;

export const isSavedPasswordIdentityBound = (host: SavedHost): boolean =>
  savedHostPasswordIdentityBinding(host) !== null;

export const savedHostEffectiveUsername = (host: SavedHost): string => {
  const identityUsername = savedHostPasswordIdentityBinding(host)?.username;
  return identityUsername !== undefined && identityUsername.length > 0
    ? identityUsername
    : host.username;
};

/**
 * Separates the host-owned password account from a shared identity account.
 * Host edit/remove flows must use `hostOwned`, never `effective`.
 */
export const savedHostCredentialState = (host: SavedHost): SavedHostCredentialState => ({
  hostOwned: host.hasSavedHostCredential,
  identityOwned: savedHostPasswordIdentityBinding(host)?.hasSavedCredential === true,
  effective: host.hasSavedCredential,
});

export const hasSavedHostOwnedCredential = (host: SavedHost): boolean =>
  savedHostCredentialState(host).hostOwned;

export const hasEffectiveSavedHostCredential = (host: SavedHost): boolean =>
  savedHostCredentialState(host).effective;

export const isSavedKeyHost = (host: SavedHost): boolean =>
  ["key", "certificate"].includes(host.authMethod.toLowerCase());

export const isSavedReferenceKeyHost = (host: SavedHost): boolean =>
  host.authMethod.toLowerCase() === "key" && host.keySource === "reference";

export const isSavedManagedKeyHost = (host: SavedHost): boolean =>
  isSavedKeyHost(host) && host.keySource === "managed";

/**
 * Reference certificates need both a certificate and its private key. The
 * current native picker contract supplies only one private-key path, so every
 * non-managed certificate (and every otherwise unresolved key relationship)
 * is rejected before opening a picker or staging a secret.
 */
export const isSavedUnsupportedKeyHost = (host: SavedHost): boolean =>
  isSavedKeyHost(host)
  && !isSavedManagedKeyHost(host)
  && !isSavedReferenceKeyHost(host);
