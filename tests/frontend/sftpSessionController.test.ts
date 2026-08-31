import assert from "node:assert/strict";
import test from "node:test";

import type { SftpEntry } from "../../src/backend.ts";
import {
  SftpSessionController,
  type SftpSessionOwner,
  type SftpTransferControlRequest,
} from "../../src/sftpSessionController.ts";
import {
  workspaceSessionIdFrom,
  type WorkspaceSessionId,
} from "../../src/terminalSessionRegistry.ts";

const workspaceId = (suffix: number): WorkspaceSessionId => workspaceSessionIdFrom(
  `ws-00000000-0000-4000-8000-${String(suffix).padStart(12, "0")}`,
);

const entry = (
  name: string,
  kind: SftpEntry["metadata"]["kind"] = "file",
): SftpEntry => ({
  name,
  path: `/${name}`,
  metadata: { kind, size: kind === "directory" ? 0 : name.length },
});

const deferred = <Value>() => {
  let resolve!: (value: Value) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<Value>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
};

const tick = async () => {
  await Promise.resolve();
  await Promise.resolve();
};

test("A/B directory path, entries, loading, and errors remain isolated", async () => {
  const calls: Array<{ backendSessionId: string; path: string }> = [];
  const controller = new SftpSessionController({
    async readDirectory(backendSessionId, path) {
      calls.push({ backendSessionId, path });
      if (backendSessionId === "backend-a") return [entry("z.txt"), entry("folder", "directory")];
      throw new Error("B directory unavailable");
    },
    formatError: () => "directory unavailable",
  });
  const a = workspaceId(1);
  const b = workspaceId(2);
  const ownerA = controller.bindSession(a, 1, "backend-a");
  const ownerB = controller.bindSession(b, 1, "backend-b");

  assert.equal(await controller.load(a, "/alpha", ownerA), true);
  assert.equal(await controller.load(b, "/beta", ownerB), false);

  assert.equal(controller.getSnapshot(a)?.path, "/alpha");
  assert.deepEqual(controller.getSnapshot(a)?.entries.map((value) => value.name), [
    "folder",
    "z.txt",
  ]);
  assert.equal(controller.getSnapshot(a)?.error, null);
  assert.equal(controller.getSnapshot(b)?.path, "/");
  assert.deepEqual(controller.getSnapshot(b)?.entries, []);
  assert.equal(controller.getSnapshot(b)?.error, "directory unavailable");
  assert.deepEqual(calls, [
    { backendSessionId: "backend-a", path: "/alpha" },
    { backendSessionId: "backend-b", path: "/beta" },
  ]);
});

test("a late listing cannot overwrite a newer request or another workspace", async () => {
  const oldListing = deferred<readonly SftpEntry[]>();
  const newListing = deferred<readonly SftpEntry[]>();
  const controller = new SftpSessionController({
    readDirectory(_backendSessionId, path) {
      return path === "/old" ? oldListing.promise : newListing.promise;
    },
  });
  const a = workspaceId(1);
  const b = workspaceId(2);
  const ownerA = controller.bindSession(a, 1, "backend-a");
  controller.bindSession(b, 1, "backend-b");

  const oldRequest = controller.load(a, "/old", ownerA);
  const newRequest = controller.load(a, "/new", ownerA);
  newListing.resolve([entry("new.txt")]);
  assert.equal(await newRequest, true);
  oldListing.resolve([entry("old.txt")]);
  assert.equal(await oldRequest, false);

  assert.equal(controller.getSnapshot(a)?.path, "/new");
  assert.deepEqual(controller.getSnapshot(a)?.entries.map((value) => value.name), ["new.txt"]);
  assert.equal(controller.getSnapshot(a)?.loading, false);
  assert.equal(controller.getSnapshot(b)?.path, "/");
  assert.deepEqual(controller.getSnapshot(b)?.entries, []);
});

test("SSH retry generation invalidates old listings and transfer events", async () => {
  const oldListing = deferred<readonly SftpEntry[]>();
  const controller = new SftpSessionController({
    readDirectory: () => oldListing.promise,
  });
  const a = workspaceId(1);
  const oldOwner = controller.bindSession(a, 1, "backend-a-1");
  assert.equal(controller.addTransfer(oldOwner, {
    id: "transfer-a",
    direction: "download",
    status: "running",
  }), true);
  const pendingListing = controller.load(a, "/old", oldOwner);
  await tick();

  const newOwner = controller.bindSession(a, 2, "backend-a-2");
  assert.ok(newOwner.sftpGeneration > oldOwner.sftpGeneration);
  assert.equal(controller.isExactOwner(oldOwner), false);
  assert.equal(controller.handleTransferEvent(oldOwner, "transfer-a", {
    type: "progress",
    bytesTransferred: 99,
    totalBytes: 100,
  }), false);
  oldListing.resolve([entry("stale.txt")]);
  assert.equal(await pendingListing, false);

  assert.equal(controller.getSnapshot(a)?.path, "/");
  assert.deepEqual(controller.getSnapshot(a)?.entries, []);
  assert.deepEqual(controller.getSnapshot(a)?.transfers, []);
  assert.throws(
    () => controller.bindSession(a, 1, "backend-a-1"),
    /SFTP_OPERATION_GENERATION_STALE/,
  );
});

test("background A transfer progress updates only A while B stays active", () => {
  const controller = new SftpSessionController({ readDirectory: async () => [] });
  const a = workspaceId(1);
  const b = workspaceId(2);
  const ownerA = controller.bindSession(a, 1, "backend-a");
  const ownerB = controller.bindSession(b, 1, "backend-b");
  controller.activate(b);
  controller.addTransfer(ownerA, { id: "same-id", direction: "upload" });
  controller.addTransfer(ownerB, { id: "same-id", direction: "download" });

  assert.equal(controller.handleTransferEvent(ownerA, "same-id", {
    type: "progress",
    bytesTransferred: 40,
    totalBytes: 100,
  }), true);

  assert.equal(controller.activeWorkspaceId, b);
  assert.equal(controller.activeSnapshot?.workspaceId, b);
  assert.equal(controller.getSnapshot(a)?.transfers[0]?.bytesTransferred, 40);
  assert.equal(controller.getSnapshot(a)?.transfers[0]?.status, "running");
  assert.equal(controller.getSnapshot(b)?.transfers[0]?.bytesTransferred, 0);
  assert.equal(controller.getSnapshot(b)?.transfers[0]?.status, "queued");
});

test("removing A releases only A and leaves B state and authority intact", async () => {
  const controls: SftpTransferControlRequest[] = [];
  const controller = new SftpSessionController({
    readDirectory: async (_backendSessionId, path) => [entry(path.slice(1))],
    transferControl: async (request) => { controls.push(request); },
  });
  const a = workspaceId(1);
  const b = workspaceId(2);
  const ownerA = controller.bindSession(a, 1, "backend-a");
  const ownerB = controller.bindSession(b, 1, "backend-b");
  controller.addTransfer(ownerA, { id: "a-transfer" }, {
    backendTransferId: "native-a-transfer",
  });
  controller.addTransfer(ownerB, { id: "b-transfer" }, {
    backendTransferId: "native-b-transfer",
  });
  await controller.load(b, "/beta", ownerB);

  assert.equal(controller.removeSession(a, ownerA), true);
  assert.equal(controller.getSnapshot(a), undefined);
  assert.equal(controller.isExactOwner(ownerB), true);
  assert.equal(controller.getSnapshot(b)?.path, "/beta");
  assert.equal(await controller.controlTransfer(ownerB, "b-transfer", "pause"), true);
  assert.equal(controls[0]?.backendTransferId, "native-b-transfer");
  assert.equal(controls[0]?.owner.backendSessionId, "backend-b");
});

test("forged backend IDs and duplicate native ownership are rejected", async () => {
  let listingCalls = 0;
  let controlCalls = 0;
  const controller = new SftpSessionController({
    readDirectory: async () => {
      listingCalls += 1;
      return [];
    },
    transferControl: async () => { controlCalls += 1; },
  });
  const a = workspaceId(1);
  const b = workspaceId(2);
  const ownerA = controller.bindSession(a, 1, "backend-a");
  const forged: SftpSessionOwner = {
    ...ownerA,
    backendSessionId: "backend-forged",
  };
  controller.addTransfer(ownerA, { id: "transfer-a" }, {
    backendTransferId: "native-transfer-a",
  });

  assert.equal(await controller.load(a, "/forged", forged), false);
  assert.equal(controller.updateTransfer(forged, "transfer-a", { status: "failed" }), false);
  assert.equal(controller.handleTransferEvent(forged, "transfer-a", { type: "started" }), false);
  assert.equal(await controller.controlTransfer(forged, "transfer-a", "cancel"), false);
  assert.equal(listingCalls, 0);
  assert.equal(controlCalls, 0);
  assert.throws(
    () => controller.bindSession(b, 1, "backend-a"),
    /SFTP_BACKEND_SESSION_ID_DUPLICATE/,
  );
});

test("snapshots are immutable, transfer authority stays private, and history is capped at 20", () => {
  const controller = new SftpSessionController({ readDirectory: async () => [] });
  const a = workspaceId(1);
  const owner = controller.bindSession(a, 1, "backend-a");
  const observed: string[] = [];
  controller.subscribe(a, (snapshot) => {
    observed.push(snapshot.transfers.at(-1)?.id ?? "none");
    throw new Error("observer cannot break authority");
  });

  for (let index = 1; index <= 21; index += 1) {
    assert.equal(controller.addTransfer(owner, { id: `transfer-${index}` }, {
      backendTransferId: `native-${index}`,
      retention: { secretMarker: `private-${index}` },
    }), true);
  }

  const snapshot = controller.getSnapshot(a)!;
  assert.equal(snapshot.transfers.length, 20);
  assert.equal(snapshot.transfers.some((transfer) => transfer.id === "transfer-1"), false);
  assert.equal(snapshot.transfers.some((transfer) => transfer.id === "transfer-21"), true);
  assert.ok(Object.isFrozen(snapshot));
  assert.ok(Object.isFrozen(snapshot.transfers));
  assert.doesNotMatch(JSON.stringify(snapshot), /native-|private-|secretMarker|retention/);
  assert.equal(observed.length, 21);
});

test("setError and canControlTransfer require the exact current workspace owner", () => {
  const controller = new SftpSessionController({ readDirectory: async () => [] });
  const a = workspaceId(1);
  const owner = controller.bindSession(a, 1, "backend-a");
  const forged: SftpSessionOwner = { ...owner, backendSessionId: "backend-forged" };

  assert.equal(controller.setError(owner, "safe directory error"), true);
  assert.equal(controller.getSnapshot(a)?.error, "safe directory error");
  assert.equal(controller.setError(forged, "forged error"), false);
  assert.equal(controller.getSnapshot(a)?.error, "safe directory error");

  controller.addTransfer(owner, { id: "transfer-a" }, {
    backendTransferId: "native-transfer-a",
  });
  assert.equal(controller.canControlTransfer(owner, "transfer-a"), true);
  assert.equal(controller.canControlTransfer(forged, "transfer-a"), false);
  assert.equal(controller.setError(owner, null), true);
  assert.equal(controller.getSnapshot(a)?.error, null);
});

test("a terminal event received before the native starter returns cannot regain control authority", () => {
  const controller = new SftpSessionController({ readDirectory: async () => [] });
  const a = workspaceId(1);
  const owner = controller.bindSession(a, 1, "backend-a");
  controller.addTransfer(owner, {
    id: "fast-transfer",
    direction: "download",
    status: "queued",
  });

  assert.equal(controller.handleTransferEvent(owner, "fast-transfer", {
    type: "completed",
    checkpoint: {
      direction: "download",
      remotePath: "/fast.txt",
      bytesTransferred: 4,
      totalBytes: 4,
    },
    replacedExisting: false,
  }), true);
  assert.equal(controller.getSnapshot(a)?.transfers[0]?.status, "completed");
  assert.equal(controller.registerTransferControl(owner, "fast-transfer", {
    backendTransferId: "native-fast-transfer",
  }), false);
  assert.equal(controller.canControlTransfer(owner, "fast-transfer"), false);
});

test("removing and rebinding an identical native session never revives the retired owner", () => {
  const controller = new SftpSessionController({ readDirectory: async () => [] });
  const a = workspaceId(1);
  const retiredOwner = controller.bindSession(a, 1, "backend-a");

  assert.equal(controller.removeSession(a, retiredOwner), true);
  const replacementOwner = controller.bindSession(a, 1, "backend-a");

  assert.notEqual(replacementOwner.sftpGeneration, retiredOwner.sftpGeneration);
  assert.equal(controller.isExactOwner(retiredOwner), false);
  assert.equal(controller.isExactOwner(replacementOwner), true);
  assert.equal(controller.addTransfer(retiredOwner, { id: "revived-transfer" }), false);
});

test("failed-stop suspension rotates authority while preserving live transfer control", async () => {
  const controls: SftpTransferControlRequest[] = [];
  const controller = new SftpSessionController({
    readDirectory: async (_backendSessionId, path) => [entry(path.slice(1))],
    transferControl: async (request) => { controls.push(request); },
  });
  const a = workspaceId(1);
  const retiredOwner = controller.bindSession(a, 1, "backend-a");
  await controller.load(a, "/alpha", retiredOwner);
  controller.addTransfer(retiredOwner, {
    id: "live-transfer",
    status: "running",
    bytesTransferred: 10,
    totalBytes: 100,
  }, {
    backendTransferId: "native-live-transfer",
  });

  const suspension = controller.suspendSession(a, retiredOwner);
  assert.ok(suspension);
  assert.equal(controller.isSuspended(a), true);
  assert.equal(controller.getOwner(a), undefined);
  assert.equal(controller.isExactOwner(retiredOwner), false);
  assert.equal(await controller.controlTransfer(retiredOwner, "live-transfer", "pause"), false);
  assert.equal(controller.setError(retiredOwner, "stale action"), false);
  assert.equal(controller.registerTransferControl(retiredOwner, "live-transfer", {
    backendTransferId: "forged-replacement-control",
  }), false);

  assert.equal(controller.handleTransferEvent(retiredOwner, "live-transfer", {
    type: "progress",
    bytesTransferred: 25,
    totalBytes: 100,
  }), true);

  const resumedOwner = controller.resumeSession(suspension);
  assert.ok(resumedOwner);
  assert.equal(controller.isSuspended(a), false);
  assert.notEqual(resumedOwner.sftpGeneration, retiredOwner.sftpGeneration);
  assert.equal(controller.isExactOwner(retiredOwner), false);
  assert.equal(controller.isExactOwner(resumedOwner), true);
  assert.equal(controller.getSnapshot(a)?.path, "/alpha");
  assert.equal(controller.getSnapshot(a)?.transfers[0]?.bytesTransferred, 25);
  assert.equal(controller.canControlTransfer(resumedOwner, "live-transfer"), true);
  assert.equal(await controller.controlTransfer(resumedOwner, "live-transfer", "pause"), true);
  assert.equal(controls[0]?.owner.sftpGeneration, resumedOwner.sftpGeneration);

  assert.equal(controller.handleTransferEvent(retiredOwner, "live-transfer", {
    type: "progress",
    bytesTransferred: 50,
    totalBytes: 100,
  }), true);
  assert.equal(controller.getSnapshot(a)?.transfers[0]?.bytesTransferred, 50);
  assert.equal(controller.resumeSession(suspension), null);
});

test("a pending native starter can publish its exact control across failed-stop rollback", async () => {
  const controls: SftpTransferControlRequest[] = [];
  const controller = new SftpSessionController({
    readDirectory: async () => [],
    transferControl: async (request) => { controls.push(request); },
  });
  const a = workspaceId(1);
  const starterOwner = controller.bindSession(a, 1, "backend-a");
  controller.addTransfer(starterOwner, {
    id: "pending-transfer",
    status: "queued",
  });

  const suspension = controller.suspendSession(a, starterOwner);
  assert.ok(suspension);
  assert.equal(controller.handleTransferEvent(starterOwner, "pending-transfer", {
    type: "started",
  }), true);
  const resumedOwner = controller.resumeSession(suspension);
  assert.ok(resumedOwner);

  assert.equal(controller.registerTransferControl(starterOwner, "pending-transfer", {
    backendTransferId: "native-pending-transfer",
  }, {
    plan: {
      localPath: "C:\\pending.txt",
      remotePath: "/pending.txt",
      localSize: 100,
      localModifiedUnixSeconds: 1,
      remoteSize: 0,
      remoteModifiedUnixSeconds: null,
      action: "fresh",
    },
  }), true);
  assert.equal(controller.registerTransferControl(starterOwner, "pending-transfer", {
    backendTransferId: "native-second-control",
  }), false);
  assert.equal(controller.canControlTransfer(starterOwner, "pending-transfer"), false);
  assert.equal(controller.canControlTransfer(resumedOwner, "pending-transfer"), true);
  assert.equal(controller.getSnapshot(a)?.transfers[0]?.plan?.remotePath, "/pending.txt");
  assert.equal(controller.handleTransferEvent(starterOwner, "pending-transfer", {
    type: "progress",
    bytesTransferred: 70,
    totalBytes: 100,
  }), true);
  assert.equal(controller.getSnapshot(a)?.transfers[0]?.bytesTransferred, 70);
  assert.equal(await controller.controlTransfer(resumedOwner, "pending-transfer", "cancel"), true);
  assert.equal(controls[0]?.backendTransferId, "native-pending-transfer");
  assert.equal(controls[0]?.owner.sftpGeneration, resumedOwner.sftpGeneration);
});

test("a completed pending transfer cannot publish late control after suspension", () => {
  const controller = new SftpSessionController({ readDirectory: async () => [] });
  const a = workspaceId(1);
  const starterOwner = controller.bindSession(a, 1, "backend-a");
  controller.addTransfer(starterOwner, {
    id: "pending-transfer",
    status: "queued",
  });
  const suspension = controller.suspendSession(a, starterOwner);
  assert.ok(suspension);
  assert.equal(controller.handleTransferEvent(starterOwner, "pending-transfer", {
    type: "completed",
    checkpoint: {
      direction: "upload",
      remotePath: "/done.txt",
      bytesTransferred: 4,
      totalBytes: 4,
    },
    replacedExisting: false,
  }), true);
  const resumedOwner = controller.resumeSession(suspension);
  assert.ok(resumedOwner);
  assert.equal(controller.registerTransferControl(starterOwner, "pending-transfer", {
    backendTransferId: "native-pending-transfer",
  }), false);
  assert.equal(controller.canControlTransfer(resumedOwner, "pending-transfer"), false);
});

test("a pending starter failure settles only its retained exact transfer", () => {
  const controller = new SftpSessionController({
    readDirectory: async () => [],
    formatError: () => "safe starter failure",
  });
  const a = workspaceId(1);
  const b = workspaceId(2);
  const starterOwner = controller.bindSession(a, 1, "backend-a");
  const ownerB = controller.bindSession(b, 1, "backend-b");
  controller.addTransfer(starterOwner, { id: "pending-transfer", status: "queued" });
  const suspension = controller.suspendSession(a, starterOwner);
  assert.ok(suspension);
  const resumedOwner = controller.resumeSession(suspension);
  assert.ok(resumedOwner);

  assert.equal(controller.failTransferStart(starterOwner, "pending-transfer", new Error("raw")), true);
  assert.equal(controller.getSnapshot(a)?.transfers[0]?.status, "failed");
  assert.equal(controller.getSnapshot(a)?.transfers[0]?.error, "safe starter failure");
  assert.equal(controller.failTransferStart(ownerB, "pending-transfer", new Error("forged")), false);
  assert.equal(controller.updateTransfer(starterOwner, "pending-transfer", {
    status: "running",
  }), false);
});

test("fresh control replacement retires an old rollback event route", () => {
  const controller = new SftpSessionController({ readDirectory: async () => [] });
  const a = workspaceId(1);
  const retiredOwner = controller.bindSession(a, 1, "backend-a");
  controller.addTransfer(retiredOwner, {
    id: "live-transfer",
    status: "running",
  }, {
    backendTransferId: "native-old-transfer",
  });
  const suspension = controller.suspendSession(a, retiredOwner);
  assert.ok(suspension);
  const resumedOwner = controller.resumeSession(suspension);
  assert.ok(resumedOwner);
  assert.equal(controller.handleTransferEvent(retiredOwner, "live-transfer", {
    type: "progress",
    bytesTransferred: 20,
    totalBytes: 100,
  }), true);

  assert.equal(controller.registerTransferControl(resumedOwner, "live-transfer", {
    backendTransferId: "native-new-transfer",
  }), true);
  assert.equal(controller.handleTransferEvent(retiredOwner, "live-transfer", {
    type: "progress",
    bytesTransferred: 90,
    totalBytes: 100,
  }), false);
  assert.equal(controller.getSnapshot(a)?.transfers[0]?.bytesTransferred, 20);
});

test("successful-stop finalization clears a suspended workspace exactly once", () => {
  const controller = new SftpSessionController({ readDirectory: async () => [] });
  const a = workspaceId(1);
  const owner = controller.bindSession(a, 1, "backend-a");
  controller.addTransfer(owner, { id: "live-transfer" }, {
    backendTransferId: "native-live-transfer",
  });
  const suspension = controller.suspendSession(a, owner);
  assert.ok(suspension);

  assert.equal(controller.finalizeSuspension(suspension, true), true);
  assert.equal(controller.getSnapshot(a), undefined);
  assert.equal(controller.finalizeSuspension(suspension, true), false);
});
