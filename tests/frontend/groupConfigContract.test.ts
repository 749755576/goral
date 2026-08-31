import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const backendSourceUrl = new URL("../../src/backend.ts", import.meta.url);

test("group config backend calls use the exact Rust command boundary", async () => {
  const source = await readFile(backendSourceUrl, "utf8");

  assert.match(source, /invoke<GroupConfigCatalog>\("list_group_configs"\)/);
  for (const command of [
    "create_group_config",
    "update_group_config",
    "delete_group_config",
  ]) {
    assert.match(
      source,
      new RegExp(`invoke<GroupConfigCatalog>\\("${command}", \\{ request \\}\\)`),
    );
  }

  for (const command of [
    "stage_group_ssh_password",
    "stage_group_telnet_password",
    "stage_group_proxy_password",
  ]) {
    assert.match(source, new RegExp(`stageRawGroupPassword\\("${command}", password\\)`));
  }
  assert.match(source, /return await invoke<string>\(command, payload\);/);
  assert.match(source, /finally \{\s*payload\.fill\(0\);\s*\}/);
});

test("group config JSON requests cannot forge backend credential hints", async () => {
  const source = await readFile(backendSourceUrl, "utf8");
  const requests = source.slice(
    source.indexOf("export type GroupConfigDefaultsRequest"),
    source.indexOf("export type LegacyVaultSourceKind"),
  );

  assert.match(requests, /Exclude<GroupConfigCredentialOverride, "storedHint">/);
  assert.match(requests, /hasSavedCredential\?: false;/);
  assert.match(requests, /sshPassword\?: "useMetadata" \| "keep";/);
  assert.match(requests, /telnetPassword\?: "useMetadata" \| "keep";/);
  assert.match(requests, /proxyPassword\?: "useMetadata" \| "keep";/);
  assert.match(requests, /proxyCommandMutation\?: GroupConfigProxyCommandMutation;/);
  assert.match(requests, /\| \{ action: "replace"; command: string \};/);
  assert.match(requests, /\| \{ action: "replace"; stagedCredentialReference: string \};/);
  assert.match(requests, /credentialMutations\?: GroupConfigCredentialMutations;/);
  assert.equal(
    [...requests.matchAll(/stagedCredentialReference\??\s*:/g)].length,
    1,
  );
  assert.doesNotMatch(
    requests,
    /\b(?:passwordBody|telnetPasswordBody|proxyPasswordBody|secret|credentialReference|backendLocator|keyringAccount)\??\s*:/,
  );
});

test("group config catalog exposes presence state but no password body field", async () => {
  const source = await readFile(backendSourceUrl, "utf8");
  const catalog = source.slice(
    source.indexOf("export type GroupConfigCredentialOverride"),
    source.indexOf("export type GroupConfigDefaultsRequest"),
  );

  assert.match(catalog, /"inherit" \| "clear" \| "storedHint"/);
  assert.match(catalog, /customGroups: string\[\];/);
  assert.match(catalog, /\| \{ type: "command" \};/);
  assert.doesNotMatch(
    catalog,
    /\b(?:command|passwordBody|telnetPasswordBody|proxyPassword|ciphertext|backendLocator|keyringAccount)\??\s*:/,
  );
});
