import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import type { HostKeyPrompt } from "../../src/backend.ts";
import { buildKnownHostsAfterTrust } from "../../src/hostKeyTrust.ts";
import type { SavedKnownHost } from "../../src/knownHostsApi.ts";

const prompt = (overrides: Partial<HostKeyPrompt> = {}): HostKeyPrompt => ({
  requestId: "request-1",
  ownerId: "main",
  sessionId: "session-1",
  clientAttemptId: "attempt-host-key-1",
  hostname: "switch.example.test",
  port: 22,
  status: "unknown",
  keyType: "ssh-ed25519",
  fingerprint: "new-fingerprint",
  publicKey: "ssh-ed25519 bmV3LWtleQ==",
  ...overrides,
});

const existing = (overrides: Partial<SavedKnownHost> = {}): SavedKnownHost => ({
  id: "kh-existing",
  hostname: "switch.example.test",
  port: 22,
  keyType: "ssh-ed25519",
  publicKey: "ssh-ed25519 b2xkLWtleQ==",
  fingerprint: "old-fingerprint",
  discoveredAt: 10,
  convertedToHostId: "host-7",
  order: 4,
  ...overrides,
});

test("trusting an unknown host appends the exact live public key", () => {
  const result = buildKnownHostsAfterTrust([], prompt(), {
    now: () => 50,
    idFactory: () => "kh-new",
  });

  assert.deepEqual(result, [{
    id: "kh-new",
    hostname: "switch.example.test",
    port: 22,
    keyType: "ssh-ed25519",
    publicKey: "ssh-ed25519 bmV3LWtleQ==",
    fingerprint: "new-fingerprint",
    discoveredAt: 50,
  }]);
});

test("trusting a changed key updates its known id without losing catalog metadata", () => {
  const result = buildKnownHostsAfterTrust(
    [existing()],
    prompt({ status: "changed", knownHostId: "kh-existing", knownFingerprint: "old-fingerprint" }),
    { now: () => 75, idFactory: () => "must-not-be-used" },
  );

  assert.deepEqual(result, [{
    id: "kh-existing",
    hostname: "switch.example.test",
    port: 22,
    keyType: "ssh-ed25519",
    publicKey: "ssh-ed25519 bmV3LWtleQ==",
    fingerprint: "new-fingerprint",
    discoveredAt: 10,
    lastSeen: 75,
    convertedToHostId: "host-7",
    order: 4,
  }]);
});

test("trusting the same selector reuses the durable record even without a known id", () => {
  const result = buildKnownHostsAfterTrust(
    [existing({ hostname: "SWITCH.EXAMPLE.TEST" })],
    prompt(),
    { now: () => 90, idFactory: () => "must-not-be-used" },
  );

  assert.equal(result.length, 1);
  assert.equal(result[0].id, "kh-existing");
  assert.equal(result[0].discoveredAt, 10);
  assert.equal(result[0].lastSeen, 90);
  assert.equal(result[0].fingerprint, "new-fingerprint");
});

test("the SSH prompt persists the live key before allowing the connection", async () => {
  const workspace = await readFile(
    new URL("../../src/TerminalWorkspace.tsx", import.meta.url),
    "utf8",
  );
  assert.match(workspace, /listKnownHosts/);
  assert.match(workspace, /buildKnownHostsAfterTrust\(knownHostsCatalog\.knownHosts, prompt\)/);
  assert.match(workspace, /await replaceKnownHosts\(\{[\s\S]*?expectedInventoryRevision:[\s\S]*?knownHosts,[\s\S]*?\}\)/);
  assert.match(workspace, /await persistHostKey\(prompt\);[\s\S]*?await respondToHostKey\(prompt\.requestId, accept\)/);
  assert.match(workspace, /answerHostKey\(true, true\)/);
  assert.match(workspace, /"hostKey\.updateContinue"/);
  assert.match(workspace, /"hostKey\.saveContinue"/);

  const hostKeyAnswer = workspace.slice(
    workspace.indexOf("const answerHostKey"),
    workspace.indexOf("const answerInteractive"),
  );
  assert.match(hostKeyAnswer, /t\("hostKey\.error\.respondFailed"\)/);
  assert.doesNotMatch(hostKeyAnswer, /setError\([^)]*messageOf/);

  const interactiveAnswer = workspace.slice(
    workspace.indexOf("const answerInteractive"),
    workspace.indexOf("const legacyBusy"),
  );
  assert.match(interactiveAnswer, /t\("interactiveAuth\.error\.respondFailed"\)/);
  assert.match(interactiveAnswer, /t\("interactiveAuth\.error\.cancelFailed"\)/);
  assert.doesNotMatch(interactiveAnswer, /setError\([^)]*messageOf/);
});
