import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  hasEffectiveSavedHostCredential,
  hasSavedHostOwnedCredential,
  isSavedKeyHost,
  isSavedManagedKeyHost,
  isSavedPasswordIdentityBound,
  isSavedReferenceKeyHost,
  isSavedUnsupportedKeyHost,
  savedHostCredentialState,
  savedHostEffectiveUsername,
  savedHostPasswordIdentityBinding,
} from "../../src/savedHostAuth.ts";
import type { SavedHost } from "../../src/backend.ts";

const backendSourceUrl = new URL("../../src/backend.ts", import.meta.url);

const host = (
  authMethod: string,
  keySource: "none" | "reference" | "managed",
  overrides: Partial<SavedHost> = {},
): SavedHost => ({
  id: "saved-host",
  revision: 1,
  label: "Saved host",
  hostname: "host.example.test",
  port: 22,
  username: "host-user",
  protocol: "ssh",
  authMethod,
  keySource,
  hasSavedCredential: false,
  hasSavedHostCredential: false,
  passwordIdentity: null,
  hasSavedKeyPassphrase: false,
  createdAt: 1,
  updatedAt: 1,
  ...overrides,
});

test("managed certificates use the managed-key connection flow", () => {
  const certificate = host("certificate", "managed");
  assert.equal(isSavedKeyHost(certificate), true);
  assert.equal(isSavedManagedKeyHost(certificate), true);
  assert.equal(isSavedReferenceKeyHost(certificate), false);
  assert.equal(isSavedUnsupportedKeyHost(certificate), false);
});

test("reference certificates fail before the one-file native picker flow", () => {
  const certificate = host("CERTIFICATE", "reference");
  assert.equal(isSavedKeyHost(certificate), true);
  assert.equal(isSavedReferenceKeyHost(certificate), false);
  assert.equal(isSavedManagedKeyHost(certificate), false);
  assert.equal(isSavedUnsupportedKeyHost(certificate), true);
});

test("password hosts never enter either key flow", () => {
  const password = host("password", "none");
  assert.equal(isSavedKeyHost(password), false);
  assert.equal(isSavedReferenceKeyHost(password), false);
  assert.equal(isSavedManagedKeyHost(password), false);
  assert.equal(isSavedUnsupportedKeyHost(password), false);
});

test("saved-host password identity DTOs mirror the Rust camel-case boundary", async () => {
  const source = await readFile(backendSourceUrl, "utf8");
  const savedHost = source.slice(
    source.indexOf("export type SavedHost ="),
    source.indexOf("export type SavedHostPasswordIdentity"),
  );
  assert.match(savedHost, /hasSavedCredential: boolean;/);
  assert.match(savedHost, /hasSavedHostCredential: boolean;/);
  assert.match(savedHost, /passwordIdentity: SavedHostPasswordIdentity \| null;/);
  assert.doesNotMatch(savedHost, /passwordIdentity\?:/);

  const identity = source.slice(
    source.indexOf("export type SavedHostPasswordIdentity"),
    source.indexOf("export type SavedHostDraft"),
  );
  for (const field of ["id", "label", "username"]) {
    assert.match(identity, new RegExp(`${field}: string;`));
  }
  assert.match(identity, /hasSavedCredential: boolean;/);
  assert.doesNotMatch(identity, /\b(?:password|credentialReference|backendLocator|keyringAccount)\??\s*:/);

  const draft = source.slice(
    source.indexOf("export type SavedHostDraft"),
    source.indexOf("export type SavedHostCredentialMutation"),
  );
  assert.match(draft, /passwordIdentityId\?: string;/);
});

test("a non-empty identity username overrides the host username", () => {
  const bound = host("password", "none", {
    username: "host-user",
    passwordIdentity: {
      id: "shared-login",
      label: "Shared login",
      username: "identity-user",
      hasSavedCredential: false,
    },
  });
  assert.equal(savedHostEffectiveUsername(bound), "identity-user");
  assert.equal(isSavedPasswordIdentityBound(bound), true);
  assert.equal(savedHostPasswordIdentityBinding(bound)?.id, "shared-login");

  const emptyOverride = host("password", "none", {
    username: "host-user",
    passwordIdentity: {
      id: "shared-login",
      label: "Shared login",
      username: "",
      hasSavedCredential: false,
    },
  });
  assert.equal(savedHostEffectiveUsername(emptyOverride), "host-user");
  assert.equal(savedHostEffectiveUsername(host("password", "none")), "host-user");
  assert.equal(isSavedPasswordIdentityBound(host("password", "none")), false);
});

test("host editing never mistakes an identity password for a host-owned password", () => {
  const identityOnly = host("password", "none", {
    hasSavedCredential: true,
    hasSavedHostCredential: false,
    passwordIdentity: {
      id: "shared-login",
      label: "Shared login",
      username: "identity-user",
      hasSavedCredential: true,
    },
  });
  assert.deepEqual(savedHostCredentialState(identityOnly), {
    hostOwned: false,
    identityOwned: true,
    effective: true,
  });
  assert.equal(hasSavedHostOwnedCredential(identityOnly), false);
  assert.equal(hasEffectiveSavedHostCredential(identityOnly), true);

  const hostOnly = host("password", "none", {
    hasSavedCredential: true,
    hasSavedHostCredential: true,
  });
  assert.deepEqual(savedHostCredentialState(hostOnly), {
    hostOwned: true,
    identityOwned: false,
    effective: true,
  });
  assert.equal(hasSavedHostOwnedCredential(hostOnly), true);
  assert.equal(hasEffectiveSavedHostCredential(hostOnly), true);
});

test("credential state preserves distinct host and identity ownership when both exist", () => {
  const both = host("password", "none", {
    hasSavedCredential: true,
    hasSavedHostCredential: true,
    passwordIdentity: {
      id: "shared-login",
      label: "Shared login",
      username: "identity-user",
      hasSavedCredential: true,
    },
  });
  assert.deepEqual(savedHostCredentialState(both), {
    hostOwned: true,
    identityOwned: true,
    effective: true,
  });

  const neither = host("password", "none");
  assert.deepEqual(savedHostCredentialState(neither), {
    hostOwned: false,
    identityOwned: false,
    effective: false,
  });
  assert.equal(hasEffectiveSavedHostCredential(neither), false);
});

test("effective credential availability follows the backend aggregate hint", () => {
  const staleIdentityHint = host("password", "none", {
    hasSavedCredential: false,
    hasSavedHostCredential: false,
    passwordIdentity: {
      id: "shared-login",
      label: "Shared login",
      username: "identity-user",
      hasSavedCredential: true,
    },
  });
  assert.deepEqual(savedHostCredentialState(staleIdentityHint), {
    hostOwned: false,
    identityOwned: true,
    effective: false,
  });
  assert.equal(hasEffectiveSavedHostCredential(staleIdentityHint), false);
});
