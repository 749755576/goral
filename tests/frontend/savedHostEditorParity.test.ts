import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const backendUrl = new URL("../../src/backend.ts", import.meta.url);
const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);
const dialogUrl = new URL("../../src/SavedHostEditorDialog.tsx", import.meta.url);
const generalFieldsUrl = new URL("../../src/SavedHostGeneralFields.tsx", import.meta.url);
const credentialFieldsUrl = new URL("../../src/SavedHostCredentialFields.tsx", import.meta.url);
const proxyFieldsUrl = new URL("../../src/SavedHostProxyFields.tsx", import.meta.url);
const stylesUrl = new URL("../../src/styles.css", import.meta.url);

test("SavedHost CRUD exposes the original grouping, tags, authentication, and jump-chain shape", async () => {
  const backend = await readFile(backendUrl, "utf8");
  const savedHost = backend.slice(
    backend.indexOf("export type SavedHost ="),
    backend.indexOf("export type SavedHostProxy ="),
  );
  const draft = backend.slice(
    backend.indexOf("export type SavedHostDraft ="),
    backend.indexOf("export type SavedHostCredentialMutation"),
  );

  assert.match(savedHost, /tags: string\[\];/);
  assert.match(savedHost, /hostChain: \{ hostIds: string\[\] \} \| null;/);
  assert.match(savedHost, /managedSshKeyId: string \| null;/);
  assert.match(draft, /authMethod\?: "password" \| "key" \| "certificate";/);
  assert.match(draft, /managedSshKeyId\?: string;/);
  assert.match(draft, /hostChain\?: \{ hostIds: string\[\] \};/);
});

test("New Host uses the original right-side Host Details workflow", async () => {
  const [workspace, dialog, chainEditor, generalFields, credentialFields, proxyFields, styles] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(dialogUrl, "utf8"),
    readFile(new URL("../../src/SavedHostChainEditor.tsx", import.meta.url), "utf8"),
    readFile(generalFieldsUrl, "utf8"),
    readFile(credentialFieldsUrl, "utf8"),
    readFile(proxyFieldsUrl, "utf8"),
    readFile(stylesUrl, "utf8"),
  ]);

  assert.match(workspace, /<SavedHostEditorDialog[\s\S]*?editor=\{savedHostEditor\}/);
  assert.match(dialog, /saved-host-dialog saved-host-details-panel/);
  assert.match(dialog, /t\("savedHost\.editor\.dialog\.titleCreate"\)/);
  assert.match(dialog, /t\("savedHost\.editor\.dialog\.titleEdit"\)/);
  assert.match(generalFields, /t\("savedHost\.editor\.general\.section"\)/);
  assert.match(generalFields, /t\("savedHost\.editor\.general\.addressSection"\)/);
  assert.match(credentialFields, /t\("savedHost\.editor\.credentials\.section"\)/);
  assert.match(proxyFields, /t\("savedHost\.editor\.proxy\.section"\)/);
  assert.match(chainEditor, /t\("savedHost\.editor\.chain\.section"\)/);
  assert.match(styles, /\.saved-host-editor-backdrop[\s\S]*?justify-content: flex-end/);
  assert.match(styles, /\.saved-host-details-panel[\s\S]*?width: min\(420px/);
});

test("SavedHostGeneralFields is callback-only and leaves persistence in the workspace", async () => {
  const [workspace, dialog, generalFields] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(dialogUrl, "utf8"),
    readFile(generalFieldsUrl, "utf8"),
  ]);

  assert.match(workspace, /import \{ SavedHostEditorDialog \} from "\.\/SavedHostEditorDialog";/);
  assert.match(workspace, /<SavedHostEditorDialog[\s\S]*?editor=\{savedHostEditor\}/);
  assert.match(workspace, /<SavedHostEditorDialog[\s\S]*?locale=\{rendererLocale\}/);
  assert.match(workspace, /groups=\{savedHostGroups\}/);
  assert.match(dialog, /import \{ SavedHostGeneralFields \} from "\.\/SavedHostGeneralFields";/);
  assert.match(dialog, /<SavedHostGeneralFields[\s\S]*?editor=\{editor\}/);
  assert.match(dialog, /<SavedHostGeneralFields[\s\S]*?locale=\{locale\}/);
  assert.match(dialog, /groups=\{groups\}/);
  assert.match(generalFields, /locale: Locale;/);
  assert.match(generalFields, /createTranslator\(locale\)/);
  assert.match(generalFields, /onChange: \(update: \(current: SavedHostEditor\) => SavedHostEditor\) => void;/);
  assert.match(generalFields, /required=\{editor\.protocol === "ssh"\}/);
  assert.doesNotMatch(
    generalFields,
    /useState|useEffect|useRef|createSavedHost|updateSavedHost|stageSshPassword|startSavedHostSession/,
  );
});

test("extracted SavedHost editor fields receive the renderer locale and contain no fixed Chinese copy", async () => {
  const componentUrls = [
    generalFieldsUrl,
    credentialFieldsUrl,
    proxyFieldsUrl,
    new URL("../../src/SavedHostChainEditor.tsx", import.meta.url),
  ];
  const [workspace, dialog, ...components] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(dialogUrl, "utf8"),
    ...componentUrls.map((url) => readFile(url, "utf8")),
  ]);

  for (const component of components) {
    assert.match(component, /locale: Locale;/);
    assert.match(component, /createTranslator\(locale\)/);
    assert.doesNotMatch(component, /\p{Script=Han}/u);
  }
  assert.match(dialog, /locale = "zh-CN"/);
  assert.match(dialog, /createTranslator\(locale\)/);
  assert.doesNotMatch(dialog, /\p{Script=Han}/u);
  const editorMount = dialog.slice(
    dialog.indexOf("<SavedHostGeneralFields"),
    dialog.indexOf("{error &&"),
  );
  assert.equal(editorMount.match(/locale=\{locale\}/g)?.length, 4);
});

test("SavedHostEditorDialog is controlled presentation and leaves all mutation authority in TerminalWorkspace", async () => {
  const [workspace, dialog] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(dialogUrl, "utf8"),
  ]);

  assert.match(dialog, /onChange: \(update: \(current: SavedHostEditor\) => SavedHostEditor\) => void;/);
  assert.match(dialog, /onSubmit: FormEventHandler<HTMLFormElement>;/);
  assert.match(dialog, /onClose: \(\) => void;/);
  assert.match(dialog, /<SavedHostCredentialFields/);
  assert.match(dialog, /<SavedHostProxyFields/);
  assert.match(dialog, /<SavedHostChainEditor/);
  assert.match(dialog, /t\("savedHost\.editor\.dialog\.passwordSecurityNote"\)/);
  assert.doesNotMatch(
    dialog,
    /useState|useEffect|useRef|stageSshPassword|stageEditorProxyPassword|createSavedHost|updateSavedHost|startSavedHostSession/,
  );
  assert.match(workspace, /onChange=\{\(update\) => setSavedHostEditor/);
  assert.match(workspace, /onSubmit=\{\(event\) => void submitSavedHost\(event\)\}/);
  assert.match(workspace, /onClose=\{closeSavedHostEditor\}/);
});

test("browser preview makes native Vault persistence visibly unavailable", async () => {
  const [workspace, dialog] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(dialogUrl, "utf8"),
  ]);

  assert.match(dialog, /nativeRuntimeAvailable: boolean;/);
  assert.match(dialog, /const saveDisabled = submitting \|\| busy \|\| !nativeRuntimeAvailable;/);
  assert.match(dialog, /t\("savedHost\.editor\.dialog\.desktopOnly"\)/);
  assert.match(dialog, /nativeUnavailableMessage && \([\s\S]*?role=\{error === nativeUnavailableMessage \? "alert" : "status"\}/);
  assert.ok(
    dialog.indexOf("{nativeUnavailableMessage && (")
      < dialog.indexOf('<div className="saved-host-fields">'),
  );
  assert.match(dialog, /error && error !== nativeUnavailableMessage && \([\s\S]*?role="alert"/);
  assert.match(workspace, /nativeRuntimeAvailable=\{NATIVE_DESKTOP_RUNTIME_AVAILABLE\}/);

  const submit = workspace.slice(
    workspace.indexOf("const submitSavedHost"),
    workspace.indexOf("const removeSavedHost"),
  );
  assert.match(
    submit,
    /if \(!NATIVE_DESKTOP_RUNTIME_AVAILABLE\) \{\s*setSavedHostsError\(t\("savedHost\.editor\.dialog\.desktopOnly"\)\);\s*return;/,
  );
  assert.ok(
    submit.indexOf("if (!NATIVE_DESKTOP_RUNTIME_AVAILABLE)")
      < submit.indexOf("savedHostMutation.current = mutationToken"),
  );
});

test("Host editor persists managed authentication and ordered jump hosts", async () => {
  const [workspace, chainEditor, credentialFields] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(new URL("../../src/SavedHostChainEditor.tsx", import.meta.url), "utf8"),
    readFile(credentialFieldsUrl, "utf8"),
  ]);

  assert.match(credentialFields, /t\("savedHost\.editor\.credentials\.authPassword"\)/);
  assert.match(credentialFields, /t\("savedHost\.editor\.credentials\.authKey"\)/);
  assert.match(credentialFields, /t\("savedHost\.editor\.credentials\.authCertificate"\)/);
  assert.match(credentialFields, /key\.category === editor\.authMethod/);
  assert.match(workspace, /hostChain: \{ hostIds: editor\.hostChainIds \}/);
  assert.match(workspace, /hostChainIds: host\.hostChain\?\.hostIds \?\? \[\]/);
  assert.match(chainEditor, /\[hostChainIds\[index - 1\], hostChainIds\[index\]\]/);
});

test("SavedHost mutations use typed bilingual copy and never expose backend error text", async () => {
  const workspace = await readFile(workspaceUrl, "utf8");
  const mutation = workspace.slice(
    workspace.indexOf("const submitSavedHost"),
    workspace.indexOf("const clearManagedSshKeyInputs"),
  );

  for (const key of [
    "savedHost.validation.port",
    "savedHost.validation.etPort",
    "savedHost.validation.managedCertificate",
    "savedHost.validation.managedKey",
    "savedHost.validation.inlineCommand",
    "savedHost.validation.inlinePassword",
    "savedHost.validation.inlineProxy",
    "savedHost.delete.confirm",
    "savedHost.delete.confirmWithIdentity",
  ]) {
    assert.match(mutation, new RegExp(`t\\("${key.replaceAll(".", "\\.")}"`));
  }
  assert.match(mutation, /savedHostMutationErrorMessage\(reason, "save", t\)/);
  assert.match(mutation, /savedHostMutationErrorMessage\(reason, "delete", t\)/);
  assert.doesNotMatch(mutation, /\p{Script=Han}/u);
  assert.doesNotMatch(mutation, /setSavedHostsError\([^)]*messageOf\(reason\)/u);

  const errorMapper = workspace.slice(
    workspace.indexOf("const isSavedHostRevisionConflict"),
    workspace.indexOf("const isManagedSshKeyInventoryConflict"),
  );
  assert.match(errorMapper, /SAVED_HOST_REVISION_CONFLICT/);
  assert.match(errorMapper, /SAVED_HOST_PROXY_REPAIR_REQUIRED/);
  assert.match(errorMapper, /savedHost\.error\.saveFailed/);
  assert.match(errorMapper, /savedHost\.error\.deleteFailed/);
  assert.doesNotMatch(errorMapper, /return message/);
});
