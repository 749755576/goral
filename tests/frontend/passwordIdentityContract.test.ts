import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const backendSourceUrl = new URL("../../src/backend.ts", import.meta.url);

test("password identity backend calls use the exact Rust command boundary", async () => {
  const source = await readFile(backendSourceUrl, "utf8");

  assert.match(
    source,
    /invoke<PasswordIdentityCatalog>\("list_password_identities"\)/,
  );
  for (const command of [
    "create_password_identity",
    "update_password_identity",
    "delete_password_identity",
  ]) {
    assert.match(
      source,
      new RegExp(
        `invoke<PasswordIdentityCatalog>\\("${command}", \\{ request \\}\\)`,
      ),
    );
  }
});

test("ordinary password identity requests carry only metadata, CAS, and staging references", async () => {
  const source = await readFile(backendSourceUrl, "utf8");
  const metadata = source.slice(
    source.indexOf("export type PasswordIdentityMetadata"),
    source.indexOf("export type PasswordIdentityCredentialMutation"),
  );
  assert.match(metadata, /label: string;/);
  assert.match(metadata, /username: string;/);
  assert.doesNotMatch(metadata, /\b(?:password|credential|hasSavedCredential)\??\s*:/);

  const requests = source.slice(
    source.indexOf("export type PasswordIdentityCredentialMutation"),
    source.indexOf("export type ManagedSshMasterKeyRotationResult"),
  );
  assert.match(requests, /\| \{ action: "keep" \}/);
  assert.match(requests, /\| \{ action: "remove" \}/);
  assert.match(
    requests,
    /\| \{ action: "replace"; stagedCredentialReference: string \}/,
  );
  assert.match(requests, /expectedInventoryRevision: unknown;/);
  assert.match(requests, /expectedRevision: number;/);
  assert.match(requests, /stagedCredentialReference\?: string;/);
  assert.doesNotMatch(
    requests,
    /\b(?:password|credentialReference|hasSavedCredential|backendLocator|keyringAccount)\??\s*:/,
  );
});

test("legacy import result types include every Rust password identity counter", async () => {
  const source = await readFile(backendSourceUrl, "utf8");
  const inspection = source.slice(
    source.indexOf("export type LegacyVaultInspection"),
    source.indexOf("export type InspectLegacyVaultRequest"),
  );
  for (const field of [
    "sourcePasswordIdentityCount",
    "importablePasswordIdentityCount",
    "duplicatePasswordIdentityCount",
    "conflictPasswordIdentityCount",
    "recoverablePasswordIdentityCredentialCount",
    "passwordIdentityCredentialReentryRequiredCount",
  ]) {
    assert.match(inspection, new RegExp(`${field}: number;`));
  }

  const result = source.slice(
    source.indexOf("export type LegacyVaultImportResult"),
    source.indexOf("export type SftpEntryKind"),
  );
  for (const field of [
    "passwordIdentitiesImportedCount",
    "passwordIdentityCredentialsStoredCount",
    "passwordIdentityCredentialReentryRequiredCount",
  ]) {
    assert.match(result, new RegExp(`${field}: number;`));
  }
});
