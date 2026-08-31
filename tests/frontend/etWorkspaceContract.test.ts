import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const backendUrl = new URL("../../src/backend.ts", import.meta.url);
const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);
const credentialFieldsUrl = new URL("../../src/SavedHostCredentialFields.tsx", import.meta.url);

const sliceBetween = (source: string, start: string, end: string): string => {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex + start.length);
  assert.ok(startIndex >= 0, `missing start marker: ${start}`);
  assert.ok(endIndex > startIndex, `missing end marker after ${start}: ${end}`);
  return source.slice(startIndex, endIndex);
};

test("ET renderer start request contains only an opaque saved target and dimensions", async () => {
  const backend = await readFile(backendUrl, "utf8");
  const request = sliceBetween(
    backend,
    "export type StartEtSessionRequest",
    "export const getBackendStatus",
  );

  assert.match(request, /hostId: string/);
  assert.match(request, /columns: number/);
  assert.match(request, /rows: number/);
  assert.doesNotMatch(request, /hostname|username|password|credential|path|command|argv|environment/);
  assert.match(backend, /startSessionWithChannels\("start_et_session", request, callbacks\)/);
});

test("SavedHost exposes ET only as an effective SSH transport mutually exclusive with Mosh", async () => {
  const [backend, workspace, editorSource, credentialFields] = await Promise.all([
    readFile(backendUrl, "utf8"),
    readFile(workspaceUrl, "utf8"),
    readFile(new URL("../../src/SavedHostChainEditor.tsx", import.meta.url), "utf8"),
    readFile(credentialFieldsUrl, "utf8"),
  ]);
  const savedHost = sliceBetween(backend, "export type SavedHost =", "export type SavedHostDraft");
  const etSelector = sliceBetween(
    workspace,
    "const isSavedSshHost",
    "const savedHostTransportLabel",
  );

  assert.match(savedHost, /effectiveEtEnabled\?: boolean/);
  assert.match(etSelector, /host\.protocol\.toLowerCase\(\) === "ssh"/);
  assert.match(etSelector, /host\.effectiveEtEnabled === true/);
  assert.match(etSelector, /host\.effectiveMoshEnabled !== true/);
  assert.match(workspace, /isSavedEtHost\(host\)[\s\S]*?\? "et"/);
  assert.match(workspace, /if \(isSavedEtHost\(host\)\)[\s\S]*?connectSavedHost\(host\)/);
});

test("SavedHost editor round-trips host transport overrides without freezing inherited values", async () => {
  const [backend, workspace, editorSource, credentialFields] = await Promise.all([
    readFile(backendUrl, "utf8"),
    readFile(workspaceUrl, "utf8"),
    readFile(new URL("../../src/SavedHostChainEditor.tsx", import.meta.url), "utf8"),
    readFile(credentialFieldsUrl, "utf8"),
  ]);
  const savedHost = sliceBetween(backend, "export type SavedHost =", "export type SavedHostDraft");
  const draft = sliceBetween(backend, "export type SavedHostDraft =", "export type SavedHostCredentialMutation");
  const openEdit = sliceBetween(workspace, "const openEditSavedHost", "const closeSavedHostEditor");
  const submit = sliceBetween(workspace, "const submitSavedHost", "const removeSavedHost");

  assert.match(savedHost, /moshEnabled\?: boolean \| null/);
  assert.match(savedHost, /etEnabled\?: boolean \| null/);
  assert.match(savedHost, /etPort\?: number \| null/);
  assert.match(draft, /moshEnabled\?: boolean/);
  assert.match(draft, /etEnabled\?: boolean/);
  assert.match(draft, /etPort\?: number/);
  assert.match(editorSource, /transportOverride: "inherit" \| "ssh" \| "mosh" \| "et"/);
  assert.match(openEdit, /transportOverride: host\.moshEnabled === true/);
  assert.match(openEdit, /host\.etEnabled === true/);
  assert.match(openEdit, /host\.moshEnabled === false && host\.etEnabled === false/);
  assert.doesNotMatch(openEdit, /effectiveMoshEnabled|effectiveEtEnabled/);
  assert.match(submit, /transportOverride === "ssh"[\s\S]*?moshEnabled: false, etEnabled: false/);
  assert.match(submit, /transportOverride === "mosh"[\s\S]*?moshEnabled: true, etEnabled: false/);
  assert.match(submit, /transportOverride === "et"[\s\S]*?moshEnabled: false, etEnabled: true/);
  assert.match(submit, /numericEtPort < 1 \|\| numericEtPort > 65535/);
  assert.match(submit, /editor\.protocol === "ssh" && numericEtPort !== undefined[\s\S]*?etPort: numericEtPort/);
  assert.match(credentialFields, /t\("savedHost\.editor\.credentials\.transportInherit"\)/);
  assert.match(credentialFields, /t\("savedHost\.editor\.credentials\.transportMosh"\)/);
  assert.match(credentialFields, /t\("savedHost\.editor\.credentials\.transportEt"\)/);
});

test("SavedHost ET start and retry keep exact native authority and terminal ownership", async () => {
  const workspace = await readFile(workspaceUrl, "utf8");
  const start = sliceBetween(
    workspace,
    'if (protocol === "et")',
    "let passwordToStage = oneTimePassword",
  );
  const retry = sliceBetween(
    workspace,
    "const retryEtConnection",
    "const retrySerialConnection",
  );

  for (const source of [start, retry]) {
    assert.match(
      source,
      /startEtSession\(\{\s*hostId: [^,]+,\s*columns: size\.columns,\s*rows: size\.rows,?\s*\}, callbacks\)/,
    );
    assert.doesNotMatch(source, /credentialReference|selectedIdentityFilePaths|hostname:|username:|path:|argv|environment:/);
    assert.match(source, /return \{ \.\.\.active, protocol: "et" \}/);
  }
  assert.match(retry, /\{ preserveScrollback: true \}/);
  assert.match(workspace, /operation\.protocol === "et"/);
  assert.match(workspace, /target\.protocol === "et"/);
  assert.match(workspace, /connectionTarget\?\.protocol === "et"[\s\S]*?retryEtConnection\(\)/);
});

test("ET uses exact-session raw input, resize, close, and cancel boundaries", async () => {
  const [backend, workspace] = await Promise.all([
    readFile(backendUrl, "utf8"),
    readFile(workspaceUrl, "utf8"),
  ]);
  const input = sliceBetween(workspace, "const dispatchInput", "const observer = new ResizeObserver");
  const close = sliceBetween(workspace, "const closeTerminalSession", "const cancelTerminalSession");
  const cancel = sliceBetween(workspace, "const cancelTerminalSession", "const isSavedCredentialNotFound");
  const legacyActivation = sliceBetween(workspace, "const activateSession = useCallback", "const connect = async");
  const savedConnection = sliceBetween(
    workspace,
    "const beginSavedHostConnection",
    "const openCreateSavedHost",
  );

  assert.match(backend, /sendRawSessionInput\("et_session_input_raw", sessionId, data\)/);
  assert.match(backend, /invoke\("resize_et_session", \{ sessionId, size \}\)/);
  assert.match(backend, /invoke\("close_et_session", \{ sessionId \}\)/);
  assert.match(backend, /invoke\("cancel_et_session", \{ sessionId \}\)/);
  assert.match(input, /active\.protocol === "et"[\s\S]*?sendChunks\(prepared\.chunks, sendEtInput\)/);
  assert.match(workspace, /active\.protocol === "et"[\s\S]*?resizeEtSession\(sessionId, size\)/);
  assert.match(close, /active\.protocol === "et"[\s\S]*?closeEtSession\(active\.sessionId\)/);
  assert.match(cancel, /active\.protocol === "et"[\s\S]*?cancelEtSession\(active\.sessionId\)/);
  assert.match(
    workspace,
    /sftpAvailable = activeSshSession !== null \|\| connectionTarget\?\.protocol === "ssh"/,
  );
  assert.match(
    legacyActivation,
    /terminalSessionCatalog\.snapshot\.order\.length > 0/,
  );
  assert.match(savedConnection, /!host\.effectiveMoshEnabled[\s\S]*?&& !isSavedEtHost\(host\)/);
  assert.match(
    savedConnection,
    /!usesSharedSshRuntime && terminalSessionCatalog\.snapshot\.order\.length > 0/,
  );
});
