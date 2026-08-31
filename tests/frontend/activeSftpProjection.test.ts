import assert from "node:assert/strict";
import test from "node:test";

import type { SftpEntry } from "../../src/backend.ts";
import {
  createActiveSftpProjection,
  projectionOwnsSftpMutation,
  resolveActiveSftpProjection,
} from "../../src/activeSftpProjection.ts";
import { SftpSessionController } from "../../src/sftpSessionController.ts";
import {
  workspaceSessionIdFrom,
  type WorkspaceSessionId,
} from "../../src/terminalSessionRegistry.ts";

const workspaceId = (suffix: number): WorkspaceSessionId => workspaceSessionIdFrom(
  `ws-00000000-0000-4000-8000-${String(suffix).padStart(12, "0")}`,
);

const entry = (name: string): SftpEntry => ({
  name,
  path: `/${name}`,
  metadata: { kind: "file", size: name.length },
});

test("switching A to B never pairs A entries with B authority", async () => {
  const controller = new SftpSessionController({
    async readDirectory(backendSessionId) {
      return backendSessionId === "backend-a" ? [entry("a.txt")] : [entry("b.txt")];
    },
  });
  const a = workspaceId(1);
  const b = workspaceId(2);
  const ownerA = controller.bindSession(a, 1, "backend-a");
  const ownerB = controller.bindSession(b, 1, "backend-b");

  assert.equal(await controller.load(a, "/alpha", ownerA), true);
  const projectionA = createActiveSftpProjection(ownerA, controller.getSnapshot(a)!);
  assert.deepEqual(
    resolveActiveSftpProjection(a, projectionA, (owner) => controller.isExactOwner(owner))
      ?.snapshot.entries.map((value) => value.name),
    ["a.txt"],
  );

  // This is the render window that previously mixed the retained A snapshot
  // with the newly active B owner: both owners remain valid while the tab flips.
  controller.activate(b);
  assert.equal(controller.isExactOwner(ownerA), true);
  assert.equal(controller.isExactOwner(ownerB), true);
  assert.equal(
    resolveActiveSftpProjection(b, projectionA, (owner) => controller.isExactOwner(owner)),
    null,
  );
  assert.equal(
    projectionOwnsSftpMutation(
      projectionA,
      b,
      ownerA,
      (owner) => controller.isExactOwner(owner),
    ),
    false,
  );
  assert.equal(
    projectionOwnsSftpMutation(
      projectionA,
      b,
      ownerB,
      (owner) => controller.isExactOwner(owner),
    ),
    false,
  );

  assert.equal(await controller.load(b, "/beta", ownerB), true);
  const projectionB = createActiveSftpProjection(ownerB, controller.getSnapshot(b)!);
  assert.deepEqual(
    resolveActiveSftpProjection(b, projectionB, (owner) => controller.isExactOwner(owner))
      ?.snapshot.entries.map((value) => value.name),
    ["b.txt"],
  );
  assert.equal(
    projectionOwnsSftpMutation(
      projectionB,
      b,
      ownerB,
      (owner) => controller.isExactOwner(owner),
    ),
    true,
  );
});

test("an owner and snapshot from different workspaces cannot form a projection", () => {
  const controller = new SftpSessionController({ readDirectory: async () => [] });
  const a = workspaceId(1);
  const b = workspaceId(2);
  const ownerA = controller.bindSession(a, 1, "backend-a");
  controller.bindSession(b, 1, "backend-b");

  assert.throws(
    () => createActiveSftpProjection(ownerA, controller.getSnapshot(b)!),
    /SFTP_ACTIVE_PROJECTION_WORKSPACE_MISMATCH/,
  );
});
