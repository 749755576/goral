import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const backendUrl = new URL("../../src/backend.ts", import.meta.url);
const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);
const catalogCardUrl = new URL("../../src/SavedHostCatalogCard.tsx", import.meta.url);
const proxyFieldsUrl = new URL("../../src/SavedHostProxyFields.tsx", import.meta.url);
const editorDialogUrl = new URL("../../src/SavedHostEditorDialog.tsx", import.meta.url);
const connectionPromptsUrl = new URL("../../src/SavedHostConnectionPrompts.tsx", import.meta.url);

test("saved-host proxy DTOs reuse renderer-safe profile config contracts", async () => {
  const source = await readFile(backendUrl, "utf8");
  const savedHost = source.slice(
    source.indexOf("export type SavedHost ="),
    source.indexOf("export type SavedHostPasswordIdentity"),
  );
  assert.match(savedHost, /proxy: SavedHostProxy \| null;/);
  assert.match(savedHost, /proxyProfileId: string \| null;/);
  assert.match(savedHost, /inlineProxy: ProxyProfileConfig \| null;/);
  assert.match(
    savedHost,
    /\| \{ action: "replace"; config: ProxyProfileConfigRequest \};/,
  );
  assert.match(
    savedHost,
    /\| \{ action: "replace"; profileId: string \};/,
  );
  assert.match(savedHost, /inlineProxy: SavedHostInlineProxyMutation;/);
  assert.match(savedHost, /profile: SavedHostProxyProfileMutation;/);

  const draft = source.slice(
    source.indexOf("export type SavedHostDraft ="),
    source.indexOf("export type SavedHostCredentialMutation"),
  );
  assert.match(draft, /proxy\?: SavedHostProxyMutation;/);

  const session = source.slice(
    source.indexOf("export type StartSavedHostSessionRequest ="),
    source.indexOf("export const getBackendStatus"),
  );
  assert.match(session, /proxyCredentialReference\?: string;/);
});

test("saved-host inline proxy passwords use raw staging before ordinary CRUD", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  const submit = source.slice(
    source.indexOf("const submitSavedHost ="),
    source.indexOf("const removeSavedHost"),
  );
  const stage = submit.indexOf("await stageEditorProxyPassword(proxySecretToStage)");
  const create = submit.indexOf("await createSavedHost({ draft, stagedCredentialReference })");
  const update = submit.indexOf("await updateSavedHost({");
  assert.ok(stage > 0 && create > stage && update > create);
  assert.match(submit, /stagedInlineProxyCredentialReference/);
  assert.match(submit, /buildSavedHostProxyMutation\(editor, inlineConfig\)/);
  assert.doesNotMatch(
    submit.slice(create, submit.indexOf("setSavedHostEditor(null)")),
    /inlineProxyPassword\s*:/,
  );
  assert.match(submit, /inlineProxyPassword: ""/);
  assert.match(submit, /inlineProxyCommand: ""/);
});

test("saved-host editor supports profile plus priority inline proxy without command disclosure", async () => {
  const [source, catalogCard, proxyFields] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(catalogCardUrl, "utf8"),
    readFile(proxyFieldsUrl, "utf8"),
  ]);
  const editor = source.slice(
    source.indexOf("const openCreateSavedHost"),
    source.indexOf("const inspectLegacyVaultFile"),
  );
  assert.match(editor, /proxyProfileId: host\.proxy\?\.proxyProfileId \?\? ""/);
  assert.match(editor, /inlineProxyEnabled: inlineProxy !== null/);
  assert.match(editor, /inlineProxyCommandAction: inlineProxy\?\.type === "command" \? "keep" : "replace"/);
  assert.match(editor, /inlineProxyCommand: ""/);
  assert.doesNotMatch(editor, /inlineProxy\.command/);

  assert.match(proxyFields, /t\("savedHost\.editor\.proxy\.inlineEnabled"\)/);
  assert.match(proxyFields, /t\("savedHost\.editor\.proxy\.commandKeepNote"\)/);
  assert.match(catalogCard, /t\("savedHost\.card\.inlineCommandProxy"\)/);
  assert.match(proxyFields, /editor\.inlineProxyAuthMode === "identity"/);
  assert.match(source, /\{ mode: "identity", identityId: editor\.inlineProxyIdentityId \}/);
});

test("SavedHostProxyFields is callback-only and leaves proxy authority in TerminalWorkspace", async () => {
  const [workspace, dialog, proxyFields] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(editorDialogUrl, "utf8"),
    readFile(proxyFieldsUrl, "utf8"),
  ]);

  assert.match(dialog, /import \{ SavedHostProxyFields \} from "\.\/SavedHostProxyFields";/);
  assert.match(dialog, /<SavedHostProxyFields[\s\S]*?editor=\{editor\}/);
  assert.match(dialog, /<SavedHostProxyFields[\s\S]*?locale=\{locale\}/);
  assert.match(dialog, /proxyProfiles=\{proxyProfiles\}/);
  assert.match(dialog, /passwordIdentities=\{passwordIdentities\}/);
  assert.match(workspace, /<SavedHostEditorDialog[\s\S]*?editor=\{savedHostEditor\}/);
  assert.match(workspace, /proxyProfiles=\{proxyProfileCatalog\?\.profiles \?\? \[\]\}/);
  assert.match(workspace, /passwordIdentities=\{passwordIdentityCatalog\?\.identities \?\? \[\]\}/);
  assert.match(proxyFields, /onChange: \(update: \(current: SavedHostEditor\) => SavedHostEditor\) => void;/);
  assert.match(proxyFields, /proxyProfiles: readonly ProxyProfile\[\];/);
  assert.match(proxyFields, /passwordIdentities: readonly PasswordIdentity\[\];/);
  assert.match(proxyFields, /locale: Locale;/);
  assert.match(proxyFields, /createTranslator\(locale\)/);
  assert.match(proxyFields, /onChange\(\(current\) =>/);
  assert.doesNotMatch(
    proxyFields,
    /useState|useEffect|useRef|stageEditorProxyPassword|stageSshPassword|createSavedHost|updateSavedHost|startSavedHostSession/,
  );

  const submit = workspace.slice(
    workspace.indexOf("const submitSavedHost ="),
    workspace.indexOf("const removeSavedHost"),
  );
  assert.match(submit, /await stageEditorProxyPassword\(proxySecretToStage\)/);
  assert.match(submit, /await createSavedHost\(\{ draft, stagedCredentialReference \}\)/);
  assert.match(submit, /await updateSavedHost\(\{/);
});

test("saved-host connection keeps SSH and proxy one-shot credentials distinct", async () => {
  const [source, prompt] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(connectionPromptsUrl, "utf8"),
  ]);
  const connect = source.slice(
    source.indexOf("const connectSavedHost"),
    source.indexOf("const beginSavedHostConnection"),
  );
  assert.match(connect, /oneTimeProxyPassword\?: string/);
  assert.match(connect, /proxyCredentialReference/);
  assert.match(connect, /\{ proxyCredentialReference \}/);
  assert.match(connect, /isSavedProxyCredentialNotFound\(failure\)/);
  assert.match(connect, /setSavedHostProxyPasswordPrompt/);

  assert.match(prompt, /connectionPrompt\.proxy\.sshPasswordLabel/);
  assert.match(prompt, /connectionPrompt\.proxy\.proxyPasswordLabel/);
  assert.match(prompt, /connectionPrompt\.proxy\.securityNote/);
  assert.match(prompt, /value=\{proxyPassword\}/);
  assert.match(prompt, /value=\{sshPassword\}/);
  assert.match(source, /proxyPassword: ""/);
  assert.match(source, /sshPassword: ""/);
});
