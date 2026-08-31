import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  createTerminalResizeCoordinator,
  type TerminalResizeFrameScheduler,
} from "../../src/terminalResizeCoordinator.ts";

const size = (columns: number, rows = 24) => ({
  columns,
  rows,
  pixelWidth: 0,
  pixelHeight: 0,
});

const deferred = () => {
  let resolve!: () => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<void>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
};

const testScheduler = () => {
  let nextId = 0;
  const callbacks = new Map<number, () => void>();
  const scheduler: TerminalResizeFrameScheduler = {
    request(callback) {
      const id = ++nextId;
      callbacks.set(id, callback);
      return id;
    },
    cancel(frameId) {
      callbacks.delete(frameId);
    },
  };
  return {
    scheduler,
    flush() {
      const queued = [...callbacks.values()];
      callbacks.clear();
      for (const callback of queued) callback();
    },
    get pendingFrames() {
      return callbacks.size;
    },
  };
};

test("terminal resize bursts publish only the newest dimensions in one frame", async () => {
  const frames = testScheduler();
  const sent: Array<[string, number, number]> = [];
  const coordinator = createTerminalResizeCoordinator(async (sessionId, request) => {
    sent.push([sessionId, request.columns, request.rows]);
  }, frames.scheduler);

  coordinator.request("session-a", size(80));
  coordinator.request("session-a", size(100));
  coordinator.request("session-a", size(120, 40));
  assert.equal(frames.pendingFrames, 1);
  assert.deepEqual(sent, []);

  frames.flush();
  await Promise.resolve();
  assert.deepEqual(sent, [["session-a", 120, 40]]);
});

test("native resize commands stay serialized and coalesce while one is in flight", async () => {
  const frames = testScheduler();
  const first = deferred();
  const sent: number[] = [];
  const coordinator = createTerminalResizeCoordinator((_sessionId, request) => {
    sent.push(request.columns);
    return sent.length === 1 ? first.promise : Promise.resolve();
  }, frames.scheduler);

  coordinator.request("session-a", size(80));
  frames.flush();
  coordinator.request("session-a", size(90));
  coordinator.request("session-a", size(110));
  assert.deepEqual(sent, [80]);
  assert.equal(frames.pendingFrames, 0);

  first.resolve();
  await first.promise;
  await new Promise<void>((resolve) => queueMicrotask(resolve));
  assert.equal(frames.pendingFrames, 1);
  frames.flush();
  await Promise.resolve();
  assert.deepEqual(sent, [80, 110]);
});

test("completed dimensions are deduplicated until the session changes", async () => {
  const frames = testScheduler();
  const sent: string[] = [];
  const coordinator = createTerminalResizeCoordinator(async (sessionId) => {
    sent.push(sessionId);
  }, frames.scheduler);

  coordinator.request("session-a", size(80));
  frames.flush();
  await new Promise<void>((resolve) => queueMicrotask(resolve));
  coordinator.request("session-a", size(80));
  assert.equal(frames.pendingFrames, 0);

  coordinator.request("session-b", size(80));
  frames.flush();
  await Promise.resolve();
  assert.deepEqual(sent, ["session-a", "session-b"]);
});

test("switching sessions drops a queued old resize and waits for an old in-flight call", async () => {
  const frames = testScheduler();
  const first = deferred();
  const sent: string[] = [];
  const coordinator = createTerminalResizeCoordinator((sessionId) => {
    sent.push(sessionId);
    return sent.length === 1 ? first.promise : Promise.resolve();
  }, frames.scheduler);

  coordinator.request("session-a", size(80));
  frames.flush();
  coordinator.request("session-a", size(90));
  coordinator.request("session-b", size(100));
  assert.equal(frames.pendingFrames, 0);

  first.resolve();
  await first.promise;
  await new Promise<void>((resolve) => queueMicrotask(resolve));
  frames.flush();
  await Promise.resolve();
  assert.deepEqual(sent, ["session-a", "session-b"]);
});

test("reset and dispose cancel queued native resizes", () => {
  const frames = testScheduler();
  const sent: number[] = [];
  const coordinator = createTerminalResizeCoordinator(async (_sessionId, request) => {
    sent.push(request.columns);
  }, frames.scheduler);

  coordinator.request("session-a", size(80));
  coordinator.reset();
  assert.equal(frames.pendingFrames, 0);
  frames.flush();
  assert.deepEqual(sent, []);

  coordinator.request("session-a", size(90));
  coordinator.dispose();
  assert.equal(frames.pendingFrames, 0);
  coordinator.request("session-a", size(100));
  frames.flush();
  assert.deepEqual(sent, []);
});

test("legacy sessions keep the workspace coordinator while each Local tab owns an exact coordinator", async () => {
  const [workspace, localSessions, localController] = await Promise.all([
    readFile(new URL("../../src/TerminalWorkspace.tsx", import.meta.url), "utf8"),
    readFile(new URL("../../src/LocalTerminalSessions.tsx", import.meta.url), "utf8"),
    readFile(new URL("../../src/localTerminalSessionController.ts", import.meta.url), "utf8"),
  ]);

  assert.match(workspace, /createTerminalResizeCoordinator\(\(sessionId, size\) =>/);
  assert.match(workspace, /active\.protocol === "telnet"[\s\S]*?resizeTelnetSession/);
  assert.match(workspace, /active\.protocol === "serial"[\s\S]*?resizeSerialSession/);
  assert.match(workspace, /active\.protocol === "mosh"[\s\S]*?resizeMoshSession/);
  assert.match(workspace, /active\.protocol === "et"[\s\S]*?resizeEtSession/);
  assert.match(workspace, /resizeSshSession\(sessionId, size\)/);
  assert.match(workspace, /terminalResizeCoordinator\.current\?\.request\(active\.sessionId/);
  assert.match(workspace, /terminalResizeCoordinator\.current\?\.reset\(\)/);
  assert.doesNotMatch(workspace, /void resizeSshSession\(/);
  assert.doesNotMatch(workspace, /resizeLocalPtySession\s*\(/);

  assert.match(localSessions, /createResizeCoordinator: \(transport\) => createTerminalResizeCoordinator\(transport\)/);
  assert.match(localSessions, /resize: resizeLocalPtySession/);
  assert.match(localController, /resizeCoordinator: LocalTerminalResizeCoordinator/);
  assert.match(localController, /#dependencies\.createResizeCoordinator\([\s\S]*?getByBackendSessionId\(backendSessionId\) !== runtime/);
  assert.match(localController, /#dependencies\.backend\.resize\(backendSessionId, size\)/);
  assert.match(localController, /runtime\.resizeCoordinator\.request\(backendSessionId/);
});
