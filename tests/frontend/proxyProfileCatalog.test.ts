import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  classifyProxyProfileError,
  normalizeProxyCommandMutation,
  normalizeProxyNetworkConfig,
  normalizeProxyProfileMetadata,
  PROXY_PROFILE_COMMAND_MAX_BYTES,
} from "../../src/proxyProfileUi.ts";
import { createTranslator } from "../../src/i18n.ts";

test("proxy profile helpers normalize valid inputs and enforce byte limits", () => {
  const auth = {
    mode: "manual" as const,
    username: " proxy-user ",
    credentialMutation: { action: "keep" as const },
  };
  const config = normalizeProxyNetworkConfig("http", " proxy.example.test ", "8080", auth);
  assert.deepEqual(config, {
    type: "http",
    host: "proxy.example.test",
    port: 8080,
    auth: {
      mode: "manual",
      username: "proxy-user",
      credentialMutation: { action: "keep" },
    },
  });
  assert.deepEqual(normalizeProxyProfileMetadata(" Office proxy ", config!), {
    label: "Office proxy",
    config,
  });
  assert.equal(normalizeProxyNetworkConfig("http", "bad host", "80", auth), null);
  assert.equal(normalizeProxyNetworkConfig("socks5", "proxy", "0", auth), null);
  assert.equal(normalizeProxyNetworkConfig("socks5", "proxy", "65536", auth), null);
  assert.equal(
    normalizeProxyNetworkConfig("http", "proxy", "80", {
      mode: "manual",
      username: "é".repeat(128),
      credentialMutation: { action: "keep" },
    }),
    null,
  );

  assert.deepEqual(normalizeProxyCommandMutation("keep", ""), { action: "keep" });
  assert.deepEqual(normalizeProxyCommandMutation("replace", "  connect %h %p  "), {
    action: "replace",
    command: "connect %h %p",
  });
  assert.equal(normalizeProxyCommandMutation("replace", "  "), null);
  assert.equal(normalizeProxyCommandMutation("replace", "bad\0command"), null);
  assert.equal(
    normalizeProxyCommandMutation("replace", "x".repeat(PROXY_PROFILE_COMMAND_MAX_BYTES + 1)),
    null,
  );
});

test("proxy profile fixed errors map to safe bilingual recovery messages", () => {
  const cases = [
    ["PROXY_PROFILE_INVENTORY_CHANGED: fixed", "stale", true],
    ["PROXY_PROFILE_CHANGED: fixed", "stale", true],
    ["PROXY_PROFILE_NOT_FOUND: fixed", "notFound", true],
    ["PROXY_PROFILE_REPAIR_REQUIRED: fixed", "repair", false],
    ["PROXY_PROFILE_INVALID: fixed", "invalid", false],
    ["PROXY_PROFILE_PUBLICATION_FAILED: fixed", "failed", true],
  ] as const;
  for (const [error, kind, refreshCatalog] of cases) {
    for (const locale of ["zh-CN", "en-US"] as const) {
      const classified = classifyProxyProfileError(error, createTranslator(locale));
      assert.equal(classified.kind, kind);
      assert.equal(classified.refreshCatalog, refreshCatalog);
      assert.ok(classified.message.length > 0);
      assert.equal(classified.message.includes(error), false);
      if (locale === "zh-CN") {
        assert.match(classified.message, /\p{Script=Han}/u);
      } else {
        assert.doesNotMatch(classified.message, /\p{Script=Han}/u);
      }
    }
  }

  const attackerMarker = "raw-proxy-error-must-not-reach-the-ui";
  for (const locale of ["zh-CN", "en-US"] as const) {
    const fallback = classifyProxyProfileError(
      new Error(attackerMarker),
      createTranslator(locale),
    );
    assert.equal(fallback.kind, "failed");
    assert.equal(fallback.refreshCatalog, false);
    assert.equal(fallback.message.includes(attackerMarker), false);
  }
});

test("component stages manual passwords before CRUD and sends only opaque references", async () => {
  const source = await readFile(
    new URL("../../src/ProxyProfileCatalog.tsx", import.meta.url),
    "utf8",
  );
  const staging = source.indexOf("await stageSshPassword(secretToStage)");
  const create = source.indexOf("await createProxyProfile({");
  const update = source.indexOf("await updateProxyProfile({");
  assert.ok(staging > 0 && create > staging && update > create);

  const createRequest = source.slice(create, update);
  const updateRequest = source.slice(update, source.indexOf("applyMutationResult(next)", update));
  for (const ordinaryRequest of [createRequest, updateRequest]) {
    assert.doesNotMatch(ordinaryRequest, /\bpassword\s*:/);
    assert.doesNotMatch(ordinaryRequest, /secretToStage/);
    assert.match(ordinaryRequest, /metadata/);
  }
  assert.match(source, /stagedCredentialReference = await stageSshPassword\(secretToStage\)/);
  assert.match(source, /finally \{\s*secretToStage = "";/);
  assert.match(source, /\{ \.\.\.current, password: "", command: "" \}/);
  assert.match(source, /locale\?: Locale;/);
  assert.match(source, /const \{ t \} = useI18n\(locale\);/);
  assert.doesNotMatch(source, /\p{Script=Han}/u);
});

test("identity auth and command editing remain mutually safe", async () => {
  const source = await readFile(
    new URL("../../src/ProxyProfileCatalog.tsx", import.meta.url),
    "utf8",
  );
  const identityBranch = source.slice(
    source.indexOf("if (editor.authMode === \"identity\")"),
    source.indexOf("return {", source.indexOf("if (editor.authMode === \"identity\")") + 10),
  );
  assert.doesNotMatch(identityBranch, /credentialMutation|password|stagedCredentialReference/);
  assert.match(source, /return \{ mode: "identity", identityId: editor\.identityId \};/);

  const updateInitializer = source.slice(
    source.indexOf("const openUpdateEditor"),
    source.indexOf("const submitEditor"),
  );
  assert.match(
    updateInitializer,
    /commandAction: profile\.config\.type === "command" \? "keep" : "replace"/,
  );
  assert.match(updateInitializer, /command: ""/);
  assert.match(source, /commandMutation \? \{ type: "command", commandMutation \} : null/);
  assert.match(source, /t\("proxyProfile\.commandConfigured"\)/);
  assert.doesNotMatch(source, /profile\.config\.command/);
});

test("empty proxy catalog exposes a localized primary onboarding action", async () => {
  const source = await readFile(
    new URL("../../src/ProxyProfileCatalog.tsx", import.meta.url),
    "utf8",
  );

  assert.match(source, /className="proxy-profile-empty-state" role="status"/);
  assert.match(source, /className="proxy-profile-empty-icon" aria-hidden="true"/);
  assert.match(source, /t\("proxyProfile\.empty"\)/);
  assert.match(source, /t\("proxyProfile\.emptyDescription"\)/);
  assert.match(
    source,
    /className="primary-button"[\s\S]*?onClick=\{openCreateEditor\}[\s\S]*?t\("proxyProfile\.create"\)/,
  );

  for (const locale of ["zh-CN", "en-US"] as const) {
    const t = createTranslator(locale);
    assert.notEqual(t("proxyProfile.emptyDescription"), "proxyProfile.emptyDescription");
  }
});
