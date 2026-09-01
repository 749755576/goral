import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);
const controllerUrl = new URL("../../src/sftpSessionController.ts", import.meta.url);

// Source files may be checked out with CRLF on Windows. Contract markers are
// written in LF form so the structural assertions remain platform-neutral.
const readSource = (url: URL): Promise<string> => readFile(url, "utf8")
  .then((source) => source.replace(/\r\n/g, "\n"));

const sliceBetween = (source: string, start: string, end: string): string => {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex + start.length);
  assert.ok(startIndex >= 0, `missing start marker: ${start}`);
  assert.ok(endIndex > startIndex, `missing end marker: ${end}`);
  return source.slice(startIndex, endIndex);
};

test("late SFTP listings require the exact workspace owner and latest request token", async () => {
  const [workspace, controller] = await Promise.all([
    readSource(workspaceUrl),
    readSource(controllerUrl),
  ]);
  const adapter = sliceBetween(workspace, "const loadSftpPath", "const updateTransfer");
  const listing = sliceBetween(controller, "async load(\n", "/** Alias for callers");

  assert.match(adapter, /expectedOwner \?\? captureCurrentSftpOwner\(\)/);
  assert.match(adapter, /!owner \|\| !isCurrentSftpOwner\(owner\)/);
  assert.match(adapter, /sftpController\.load\(owner\.workspaceId, path, owner\)/);

  assert.match(listing, /const owner = expectedOwner \?\? session\.owner/);
  assert.match(listing, /if \(!ownersEqual\(session\.owner, owner\)\) return false/);
  assert.match(listing, /requestToken = session\.latestListingToken \+ 1/);
  assert.match(listing, /readDirectory\(owner\.backendSessionId, path\)/);
  const exactCompletionGuard = /session\.latestListingToken !== requestToken[\s\S]*?!ownersEqual\(session\.owner, owner\)/g;
  assert.equal(
    [...listing.matchAll(exactCompletionGuard)].length,
    2,
    "both successful and failed late listings recheck token plus the complete owner",
  );
  assert.match(listing, /session\.path = path;[\s\S]*session\.entries = Object\.freeze\(copied\)/);
  assert.match(listing, /session\.error = this\.#safeError\(reason\)/);
});

test("activation, retry, and close project only one exact workspace SFTP snapshot", async () => {
  const [workspace, controller] = await Promise.all([
    readSource(workspaceUrl),
    readSource(controllerUrl),
  ]);
  const projection = sliceBetween(workspace, "const projectActiveSftpSnapshot", "const bindSftpWorkspace");
  const binding = sliceBetween(workspace, "const bindSftpWorkspace", "useEffect(() => sftpController.subscribe");
  const lifecycle = sliceBetween(
    workspace,
    "useEffect(() => {\n    const liveSshIds",
    "const getTerminalSidePanelContainerWidth",
  );
  const reset = sliceBetween(controller, "resetSession(", "/** Remove one workspace");
  const remove = sliceBetween(controller, "removeSession(", "/** Load a directory");

  assert.match(workspace, /useLayoutEffect\(\(\) => \{[\s\S]*?activeSftpWorkspaceIdRef\.current = activeSshSession\?\.id \?\? null/);
  assert.match(projection, /if \(!snapshot\) \{[\s\S]*?setActiveSftpProjection\(null\)/);
  assert.match(projection, /sftpController\.getOwner\(snapshot\.workspaceId\)/);
  assert.match(projection, /!owner \|\| !sftpController\.isExactOwner\(owner\)/);
  assert.match(projection, /setActiveSftpProjection\(createActiveSftpProjection\(owner, snapshot\)\)/);
  assert.match(
    workspace,
    /resolveActiveSftpProjection\([\s\S]*?activeSshSession\?\.id \?\? null,[\s\S]*?activeSftpProjection,[\s\S]*?sftpController\.isExactOwner/,
  );
  assert.match(
    workspace,
    /projectionOwnsSftpMutation\([\s\S]*?activeSftpProjection,[\s\S]*?activeSftpWorkspaceIdRef\.current,[\s\S]*?owner,[\s\S]*?sftpController\.isExactOwner/,
  );
  assert.match(
    workspace,
    /sftpTabVisible && terminalSidePanelTab === "sftp" && activeSftpRender && \(/,
  );
  assert.doesNotMatch(
    projection,
    /setSftpPath|setSftpEntries|setSftpError|setTransfers|setSftpLoading/,
  );
  assert.match(binding, /sshTerminals\.backendSessionIdFor\(workspaceId\)/);
  assert.match(binding, /sshTerminals\.operationGenerationFor\(workspaceId\)/);
  assert.match(binding, /sftpController\.isSuspended\(workspaceId\)/);
  assert.match(binding, /sftpController\.bindSession\(\{[\s\S]*workspaceId,[\s\S]*operationGeneration,[\s\S]*backendSessionId/);
  assert.match(binding, /sharedTerminalRegistry\.activeSessionId === workspaceId[\s\S]*sftpController\.activate\(workspaceId\)/);

  assert.match(lifecycle, /sharedTerminalRegistry\.sessions\[id\]\?\.protocol === "ssh" && sshTerminals\.owns\(id\)/);
  assert.match(lifecycle, /sftpController\.removeSession\(workspaceId\)/);
  assert.match(lifecycle, /snapshot\?\.state === "connected"[\s\S]*sshTerminals\.backendSessionIdFor\(workspaceId\)[\s\S]*bindSftpWorkspace\(workspaceId\)/);
  assert.match(lifecycle, /else if \(sftpController\.getOwner\(workspaceId\)\)[\s\S]*sftpController\.resetSession\(workspaceId\)/);
  assert.match(binding, /suspendSftpWorkspaceForStop\(workspaceId\)[\s\S]*sshTerminals\.disconnect\(workspaceId\)/);
  assert.match(binding, /sftpController\.resumeSession\(suspension\)/);
  assert.match(binding, /sftpController\.finalizeSuspension\(suspension, pending\.remove\)/);
  assert.match(binding, /pendingSftpStops\.current\.get\(workspaceId\)[\s\S]*return existing\.promise/);
  assert.match(binding, /const closeSshWorkspace[\s\S]*stopSshWorkspace\(workspaceId, true\)/);

  assert.match(reset, /expectedOwner && !ownersEqual\(session\.owner, expectedOwner\)/);
  assert.match(reset, /session\.owner = null/);
  assert.match(controller, /#nextOwnerGeneration = 0/);
  assert.match(controller, /#allocateOwnerGeneration\(\): number/);
  assert.match(controller, /sftpGeneration: this\.#allocateOwnerGeneration\(\)/);
  assert.match(reset, /this\.#clearState\(session\)/);
  assert.match(remove, /expectedOwner && !ownersEqual\(session\.owner, expectedOwner\)/);
  assert.match(remove, /this\.#clearControls\(session\)/);
  assert.match(remove, /this\.#sessions\.delete\(workspaceId\)/);
});

test("transfer backend IDs stay out of React snapshots and controls cannot cross workspaces", async () => {
  const [workspace, controller] = await Promise.all([
    readSource(workspaceUrl),
    readSource(controllerUrl),
  ]);
  const snapshotType = sliceBetween(controller, "export type SftpTransferSnapshot =", "/** Minimal input");
  const privateState = sliceBetween(controller, "type MutableSftpSession =", "const emptySnapshot");
  const registration = sliceBetween(controller, "registerTransferControl(", "updateTransfer(");
  const control = sliceBetween(controller, "async controlTransfer(", "/** Alias used by control-button adapters");
  const uiControl = sliceBetween(workspace, "const controlOwnedSftpTransfer", "useEffect(() => {");

  assert.match(workspace, /type VisibleTransfer = SftpTransferSnapshot/);
  assert.doesNotMatch(snapshotType, /backendTransferId|transferId|pause\?:|resume\?:|cancel\?:|retention|dispose/);
  assert.match(privateState, /controls: Map<string, MutableTransferControl>/);
  assert.match(privateState, /pendingControlOwners: Map<string, SftpSessionOwner>/);
  assert.match(controller, /readonly #backendTransferOwners = new Map/);
  assert.match(registration, /const exactOwner = this\.isExactOwner\(owner\)/);
  assert.match(registration, /session\.pendingControlOwners\.get\(transferId\)/);
  assert.match(registration, /if \(!exactOwner && !retainedPendingOwner\) return false/);
  assert.match(registration, /retainedPendingOwner && session\.controls\.has\(transferId\)/);
  assert.match(registration, /const transfer = session\.transfers\.get\(transferId\)/);
  assert.match(registration, /if \(!transfer \|\| isTerminalTransferStatus\(transfer\.status\)\) return false/);
  assert.match(registration, /if \(!this\.#bindControl\(session, transferId, control\)\) return false/);
  assert.match(registration, /session\.pendingControlOwners\.delete\(transferId\)/);
  assert.match(registration, /retainedPendingOwner && retainedRoute/);

  const ownerGuard = control.indexOf("if (!this.isExactOwner(owner)) return false");
  const privateLookup = control.indexOf("session.controls.get(transferId)");
  const nativeCall = control.indexOf("await localAction()");
  assert.ok(ownerGuard >= 0 && ownerGuard < privateLookup, "owner is checked before private authority lookup");
  assert.ok(privateLookup >= 0 && privateLookup < nativeCall, "native control uses the private authority");
  assert.match(control, /return this\.isExactOwner\(owner\)/);

  assert.match(uiControl, /captureCurrentSftpOwner\(\)/);
  assert.match(uiControl, /!owner \|\| !isCurrentSftpOwner\(owner\)/);
  assert.match(uiControl, /sftpController\.controlTransfer\(owner, transfer\.id, action\)/);
  assert.doesNotMatch(uiControl, /pauseSftpTransfer|resumeSftpTransfer|cancelSftpTransfer|backendTransferId/);
});

test("drag/drop and SFTP mutations remain owner-bound and path-safe", async () => {
  const [workspace, controller] = await Promise.all([
    readSource(workspaceUrl),
    readSource(controllerUrl),
  ]);
  const dragDrop = sliceBetween(
    workspace,
    "if (!sftpOpen || activeSshSession?.state !== \"connected\") return;",
    "useEffect(() => {\n    if (activeSurface !== \"terminal\") return;",
  );
  const mutations = sliceBetween(workspace, "const createRemoteFolder", "const retryTransfer");

  assert.match(dragDrop, /const owner = captureCurrentSftpOwner\(\)/);
  assert.match(dragDrop, /event\.payload\.type === "drop" && isCurrentSftpOwner\(owner\)/);
  assert.match(dragDrop, /uploadLocalPath\(path, owner\)/);
  assert.match(dragDrop, /if \(disposed\) dispose\(\);[\s\S]*else unlisten = dispose/);
  assert.match(dragDrop, /return \(\) => \{[\s\S]*disposed = true;[\s\S]*unlisten\?\.\(\)/);

  assert.match(mutations, /createSftpDirectory\(owner\.backendSessionId, childPath\)/);
  assert.match(mutations, /renameSftpPath\(owner\.backendSessionId, entry\.path, renamedPath\)/);
  assert.match(mutations, /removeSftp(?:Directory|File)\(owner\.backendSessionId, entry\.path\)/);
  assert.match(mutations, /if \(isCurrentSftpOwner\(owner\)\) setOwnedSftpError\(owner, SFTP_OPERATION_ERROR\)/);
  assert.doesNotMatch(mutations, /setSftpError\(messageOf\(|error: event\.message/);
  assert.match(controller, /#safeError\(reason: unknown\)/);
  assert.match(controller, /boundedText\(error, "sftp_error", MAX_ERROR_BYTES, true\)/);
});
