import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  classifyPasswordIdentityError,
  normalizePasswordIdentityMetadata,
} from "../../src/passwordIdentityUi.ts";
import { createTranslator } from "../../src/i18n.ts";

test("password identity metadata normalization rejects blank labels and trims safe fields", () => {
  assert.equal(normalizePasswordIdentityMetadata("   ", "user"), null);
  assert.deepEqual(
    normalizePasswordIdentityMetadata("  Shared production login  ", "  deploy-user  "),
    { label: "Shared production login", username: "deploy-user" },
  );
  assert.deepEqual(
    normalizePasswordIdentityMetadata("Login", "   "),
    { label: "Login", username: "" },
  );
});

test("password identity fixed errors map to safe bilingual recovery actions", () => {
  const cases = [
    ["PASSWORD_IDENTITY_INVENTORY_CHANGED: fixed", "stale", true],
    ["PASSWORD_IDENTITY_CHANGED: fixed", "stale", true],
    ["PASSWORD_IDENTITY_IN_USE: fixed", "inUse", false],
    ["PASSWORD_IDENTITY_REPAIR_REQUIRED: fixed", "repair", false],
    ["PASSWORD_IDENTITY_NOT_FOUND: fixed", "notFound", true],
    ["PASSWORD_IDENTITY_INVALID: fixed", "invalid", false],
    ["PASSWORD_IDENTITY_PUBLICATION_FAILED: fixed", "failed", true],
  ] as const;
  for (const [error, kind, refreshCatalog] of cases) {
    for (const locale of ["zh-CN", "en-US"] as const) {
      const classified = classifyPasswordIdentityError(error, createTranslator(locale));
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

  const attackerMarker = "raw-error-must-not-reach-the-ui";
  for (const locale of ["zh-CN", "en-US"] as const) {
    const fallback = classifyPasswordIdentityError(
      new Error(attackerMarker),
      createTranslator(locale),
    );
    assert.equal(fallback.kind, "failed");
    assert.equal(fallback.refreshCatalog, false);
    assert.equal(fallback.message.includes(attackerMarker), false);
  }
});

test("component stages passwords before CRUD and ordinary requests carry references only", async () => {
  const source = await readFile(
    new URL("../../src/PasswordIdentityCatalog.tsx", import.meta.url),
    "utf8",
  );
  const staging = source.indexOf("await stageSshPassword(secretToStage)");
  const create = source.indexOf("await createPasswordIdentity({");
  const update = source.indexOf("await updatePasswordIdentity({");
  assert.ok(staging > 0 && create > staging && update > create);

  const createRequest = source.slice(create, update);
  const updateRequest = source.slice(
    update,
    source.indexOf("applyMutationResult(next)", update),
  );
  for (const ordinaryRequest of [createRequest, updateRequest]) {
    assert.doesNotMatch(ordinaryRequest, /\bpassword\s*:/);
    assert.doesNotMatch(ordinaryRequest, /secretToStage/);
    assert.match(ordinaryRequest, /stagedCredentialReference|credentialMutation/);
  }
  assert.match(source, /setEditor\(\(current\) => current \? \{ \.\.\.current, password: "" \}/);
  assert.match(source, /finally \{\s*secretToStage = "";/);
  assert.match(source, /expectedInventoryRevision: snapshot\.expectedInventoryRevision/);
  assert.match(source, /expectedRevision: snapshot\.expectedRevision!/);
  assert.match(source, /expectedInventoryRevision: prompt\.expectedInventoryRevision/);
  assert.match(source, /expectedRevision: prompt\.expectedRevision/);
  assert.match(source, /disabled\?: boolean;/);
  assert.match(source, /locale\?: Locale;/);
  assert.match(source, /const \{ t \} = useI18n\(locale\);/);
  assert.doesNotMatch(source, /\p{Script=Han}/u);
  assert.match(source, /refreshKey\?: string \| number;/);
  assert.match(
    source,
    /onCatalogChange\?: \(catalog: PasswordIdentityCatalogSnapshot\) => void;/,
  );
  assert.match(source, /onCatalogChangeRef\.current\?\.\(next\)/);
  assert.match(source, /observedRefreshKey\.current, refreshKey/);
});
