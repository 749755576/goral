import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const backendSourceUrl = new URL("../../src/backend.ts", import.meta.url);

test("proxy profile backend calls use the exact Rust command boundary", async () => {
  const source = await readFile(backendSourceUrl, "utf8");

  assert.match(source, /invoke<ProxyProfileCatalog>\("list_proxy_profiles"\)/);
  for (const command of [
    "create_proxy_profile",
    "update_proxy_profile",
    "delete_proxy_profile",
  ]) {
    assert.match(
      source,
      new RegExp(`invoke<ProxyProfileCatalog>\\("${command}", \\{ request \\}\\)`),
    );
  }
});

test("renderer-safe proxy views omit command bodies and secret material", async () => {
  const source = await readFile(backendSourceUrl, "utf8");
  const views = source.slice(
    source.indexOf("export type ProxyNetworkAuth ="),
    source.indexOf("export type ProxyProfileCredentialMutation ="),
  );

  assert.match(views, /\| \{ type: "command" \};/);
  assert.doesNotMatch(views, /\bcommand\??\s*:/);
  assert.doesNotMatch(
    views,
    /\b(?:password|credentialReference|stagedCredentialReference|backendLocator|keyringAccount)\??\s*:/,
  );
});

test("proxy mutation requests use typed command and credential mutations", async () => {
  const source = await readFile(backendSourceUrl, "utf8");
  const requests = source.slice(
    source.indexOf("export type ProxyProfileCredentialMutation ="),
    source.indexOf("export type GroupConfigOverride"),
  );

  assert.match(requests, /export type ProxyCommandMutation =/);
  assert.match(requests, /\| \{ action: "keep" \}/);
  assert.match(requests, /\| \{ action: "replace"; command: string \}/);
  assert.match(
    requests,
    /\| \{ type: "command"; commandMutation: ProxyCommandMutation \};/,
  );
  assert.match(requests, /credentialMutation: ProxyProfileCredentialMutation;/);
  assert.match(requests, /\| \{ mode: "identity"; identityId: string \};/);
  assert.doesNotMatch(requests, /\bpassword\??\s*:/);
});
