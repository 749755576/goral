import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);
const credentialFieldsUrl = new URL("../../src/SavedHostCredentialFields.tsx", import.meta.url);
const catalogCardUrl = new URL("../../src/SavedHostCatalogCard.tsx", import.meta.url);

test("saved-host editor round-trips and clears the password identity binding", async () => {
  const [source, editorType, credentialFields] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(new URL("../../src/SavedHostChainEditor.tsx", import.meta.url), "utf8"),
    readFile(credentialFieldsUrl, "utf8"),
  ]);
  assert.match(editorType, /passwordIdentityId: string;/);
  assert.match(source, /passwordIdentityId: savedHostPasswordIdentityBinding\(host\)\?\.id \?\? ""/);
  assert.match(
    source,
    /editor\.authMethod === "password" && editor\.passwordIdentityId[\s\S]*?\{ passwordIdentityId: editor\.passwordIdentityId \}/,
  );
  assert.match(credentialFields, /value=\{editor\.passwordIdentityId\}/);
  assert.match(credentialFields, /t\("savedHost\.editor\.credentials\.passwordIdentityNone"\)/);
});

test("host-owned credential cleanup never keys off an identity credential", async () => {
  const [source, credentialFields] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(credentialFieldsUrl, "utf8"),
  ]);
  assert.match(credentialFields, /hasSavedHostOwnedCredential\(editor\.host\)/);
  assert.doesNotMatch(credentialFields, /editor\.host\?\.hasSavedCredential/);
  assert.match(source, /removeCredential: hasSavedHostOwnedCredential\(latest\) && current\.removeCredential/);
  assert.match(source, /t\("savedHost\.delete\.confirmWithIdentity", \{/);
  assert.match(source, /identity: identity\.label/);
});

test("saved-host list and connection target use identity-overridden usernames", async () => {
  const [source, catalogCard] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(catalogCardUrl, "utf8"),
  ]);
  assert.match(
    source,
    /username: protocol === "serial" \? "" : savedHostEffectiveUsername\(host\)/,
  );
  assert.match(catalogCard, /passwordIdentity = savedHostPasswordIdentityBinding\(host\)/);
  assert.match(
    catalogCard,
    /t\("savedHost\.card\.boundIdentity", \{ identity: passwordIdentity\.label \}\)/,
  );
  assert.ok(
    (source.match(/savedHostEffectiveUsername\(host\)/g)?.length ?? 0) >= 3,
    "effective username must drive both connection chrome and saved-host list output",
  );
});

test("full-Vault catalog tokens converge after every graph mutation", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  assert.match(source, /onCatalogChange=\{handlePasswordIdentityCatalogChange\}/);
  assert.match(
    source,
    /<PasswordIdentityCatalog[\s\S]*?locale=\{rendererLocale\}[\s\S]*?onCatalogChange=\{handlePasswordIdentityCatalogChange\}/,
  );

  const identityHandler = source.slice(
    source.indexOf("const handlePasswordIdentityCatalogChange"),
    source.indexOf("useEffect(() =>", source.indexOf("const handlePasswordIdentityCatalogChange")),
  );
  assert.match(identityHandler, /refreshSavedHosts\(false, true\)/);
  assert.match(identityHandler, /refreshManagedSshKeys\(\)/);

  const hostSubmit = source.slice(
    source.indexOf("const submitSavedHost"),
    source.indexOf("const removeSavedHost"),
  );
  const hostDelete = source.slice(
    source.indexOf("const removeSavedHost"),
    source.indexOf("const clearManagedSshKeyInputs"),
  );
  for (const mutation of [hostSubmit, hostDelete]) {
    assert.match(mutation, /setPasswordIdentityRefreshKey/);
    assert.match(mutation, /refreshManagedSshKeys/);
    assert.match(mutation, /refreshSavedHosts/);
  }

  const managedMutationApplications = source.match(
    /observeManagedInventoryRevision\(nextCatalog\.inventoryRevision\)/g,
  );
  assert.equal(managedMutationApplications?.length, 2);

  const legacyCommit = source.slice(
    source.indexOf("const commitLegacyVaultPreview"),
    source.indexOf("const submitSavedHost"),
  );
  assert.match(legacyCommit, /setPasswordIdentityRefreshKey/);
  assert.match(legacyCommit, /refreshSavedHosts/);
  assert.match(legacyCommit, /refreshManagedSshKeys/);
});
