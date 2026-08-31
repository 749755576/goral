import assert from "node:assert/strict";
import test from "node:test";

import type {
  HostKeyPrompt,
  InteractivePrompt,
} from "../../src/backend.ts";
import { SshPromptQueue } from "../../src/sshPromptQueue.ts";
import {
  workspaceSessionIdFrom,
  type WorkspaceSessionId,
} from "../../src/terminalSessionRegistry.ts";

const id = (suffix: number): WorkspaceSessionId => workspaceSessionIdFrom(
  `ws-30000000-0000-4000-8000-${String(suffix).padStart(12, "0")}`,
);

const hostPrompt = (
  requestId: string,
  clientAttemptId: string,
): HostKeyPrompt => ({
  requestId,
  ownerId: "main",
  sessionId: "pending",
  clientAttemptId,
  hostname: "host.example.test",
  port: 22,
  status: "unknown",
  keyType: "ssh-ed25519",
  fingerprint: "fingerprint",
  publicKey: "ssh-ed25519 AAAATEST",
});

const interactivePrompt = (
  requestId: string,
  clientAttemptId: string,
): InteractivePrompt => ({
  requestId,
  ownerId: "main",
  sessionId: "pending",
  clientAttemptId,
  name: "MFA",
  instructions: "Enter the code",
  prompts: [{ text: "Code", echo: false }],
});

const createHarness = (limit?: number) => {
  const routes = new Map<string, WorkspaceSessionId>();
  const rejectedHostKeys: string[] = [];
  const canceledInteractive: string[] = [];
  const queue = new SshPromptQueue({
    resolveAttempt: (attemptId) => routes.get(attemptId) ?? null,
    isInternalAttempt: (attemptId) => attemptId.startsWith("internal:"),
    rejectHostKey: async (requestId) => {
      rejectedHostKeys.push(requestId);
    },
    cancelInteractive: async (requestId) => {
      canceledInteractive.push(requestId);
    },
    ...(limit === undefined ? {} : { limit }),
  });
  return { canceledInteractive, queue, rejectedHostKeys, routes };
};

test("A/B host-key and interactive prompts retain FIFO order instead of overwriting", () => {
  const harness = createHarness();
  harness.routes.set("attempt-a", id(1));
  harness.routes.set("attempt-b", id(2));

  assert.equal(harness.queue.enqueueInteractive(interactivePrompt("interactive-b", "attempt-b")), true);
  assert.equal(harness.queue.enqueueHostKey(hostPrompt("host-a", "attempt-a")), true);
  assert.equal(harness.queue.snapshot.current?.key, "interactive:interactive-b");
  assert.deepEqual(
    harness.queue.snapshot.prompts.map((prompt) => [prompt.key, prompt.workspaceSessionId]),
    [
      ["interactive:interactive-b", id(2)],
      ["hostKey:host-a", id(1)],
    ],
  );

  assert.equal(harness.queue.complete("interactive", "interactive-b"), true);
  assert.equal(harness.queue.snapshot.current?.key, "hostKey:host-a");
  assert.equal(harness.queue.complete("hostKey", "host-a"), true);
  assert.equal(harness.queue.snapshot.current, null);
});

test("unknown attempts and bounded overflow are rejected at their exact native broker", async () => {
  const harness = createHarness(1);
  harness.routes.set("attempt-a", id(1));
  harness.routes.set("attempt-b", id(2));

  assert.equal(harness.queue.enqueueHostKey(hostPrompt("unknown", "forged")), false);
  assert.equal(harness.queue.enqueueHostKey(hostPrompt("accepted", "attempt-a")), true);
  assert.equal(
    harness.queue.enqueueInteractive(interactivePrompt("overflow", "attempt-b")),
    false,
  );
  await Promise.resolve();
  assert.deepEqual(harness.rejectedHostKeys, ["unknown"]);
  assert.deepEqual(harness.canceledInteractive, ["overflow"]);
  assert.deepEqual(harness.queue.snapshot.prompts.map((prompt) => prompt.key), [
    "hostKey:accepted",
  ]);
});

test("duplicate broadcast delivery never creates or answers a second prompt", () => {
  const harness = createHarness();
  harness.routes.set("attempt-a", id(1));
  const prompt = hostPrompt("same-request", "attempt-a");
  assert.equal(harness.queue.enqueueHostKey(prompt), true);
  assert.equal(harness.queue.enqueueHostKey(prompt), false);
  assert.equal(harness.queue.snapshot.prompts.length, 1);
  assert.deepEqual(harness.rejectedHostKeys, []);
});

test("prune rejects retired A while preserving exact B and internal operations", async () => {
  const harness = createHarness();
  harness.routes.set("attempt-a", id(1));
  harness.routes.set("attempt-b", id(2));
  harness.queue.enqueueHostKey(hostPrompt("host-a", "attempt-a"));
  harness.queue.enqueueInteractive(interactivePrompt("interactive-b", "attempt-b"));
  harness.queue.enqueueHostKey(hostPrompt("port-forward", "internal:port-forward"));

  harness.routes.delete("attempt-a");
  assert.equal(harness.queue.prune(), 1);
  await Promise.resolve();
  assert.deepEqual(harness.rejectedHostKeys, ["host-a"]);
  assert.deepEqual(harness.queue.snapshot.prompts.map((prompt) => prompt.key), [
    "interactive:interactive-b",
    "hostKey:port-forward",
  ]);
});

test("interactive snapshots contain prompts but never renderer answers or secret fields", () => {
  const harness = createHarness();
  harness.routes.set("attempt-a", id(1));
  harness.queue.enqueueInteractive(interactivePrompt("interactive-a", "attempt-a"));
  const serialized = JSON.stringify(harness.queue.snapshot);
  assert.match(serialized, /Code/);
  assert.doesNotMatch(serialized, /123456|answers|password/);
});

test("dispose rejects every queued exact request and clears observers", async () => {
  const harness = createHarness();
  harness.routes.set("attempt-a", id(1));
  harness.queue.enqueueHostKey(hostPrompt("host-a", "attempt-a"));
  harness.queue.enqueueInteractive(interactivePrompt("interactive-a", "attempt-a"));
  harness.queue.dispose();
  await Promise.resolve();
  assert.deepEqual(harness.rejectedHostKeys, ["host-a"]);
  assert.deepEqual(harness.canceledInteractive, ["interactive-a"]);
  assert.equal(harness.queue.snapshot.current, null);
  assert.throws(() => harness.queue.subscribe(() => undefined), /SSH_PROMPT_QUEUE_DISPOSED/);
});
