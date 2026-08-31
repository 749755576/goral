import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import type {
  HostKeyPrompt,
  InteractivePrompt,
  StartSavedHostSessionRequest,
  StartSshSessionRequest,
} from "../../src/backend.ts";

const clientAttemptId = "attempt-123e4567-e89b-42d3-a456-426614174000";

const quickRequest: StartSshSessionRequest = {
  clientAttemptId,
  config: { hostname: "quick.example.test", username: "alice" },
  credentialReference: "credential-reference",
};

const savedRequest: StartSavedHostSessionRequest = {
  clientAttemptId,
  hostId: "saved-host-id",
  expectedRevision: 7,
};

const hostKeyPrompt: HostKeyPrompt = {
  requestId: "hostkey-request",
  ownerId: "main",
  sessionId: "pending",
  clientAttemptId,
  hostname: "quick.example.test",
  port: 22,
  status: "unknown",
  keyType: "ssh-ed25519",
  fingerprint: "SHA256:test",
  publicKey: "ssh-ed25519 AAAATEST",
};

const interactivePrompt: InteractivePrompt = {
  requestId: "interactive-request",
  ownerId: "main",
  sessionId: "pending",
  clientAttemptId,
  name: "Authentication",
  instructions: "",
  prompts: [{ text: "Verification code: ", echo: false }],
};

test("SSH start and prompt DTOs require the same client attempt route", async () => {
  assert.equal(quickRequest.clientAttemptId, clientAttemptId);
  assert.equal(savedRequest.clientAttemptId, clientAttemptId);
  assert.equal(hostKeyPrompt.clientAttemptId, clientAttemptId);
  assert.equal(interactivePrompt.clientAttemptId, clientAttemptId);

  const source = await readFile(new URL("../../src/backend.ts", import.meta.url), "utf8");
  for (const [name, nextName] of [
    ["HostKeyPrompt", "InteractivePrompt"],
    ["InteractivePrompt", "SshSessionCallbacks"],
    ["StartSshSessionRequest", "StartSavedHostSessionRequest"],
    ["StartSavedHostSessionRequest", "StartSavedTelnetSessionRequest"],
  ] as const) {
    const start = source.indexOf(`export type ${name} =`);
    const end = source.indexOf(`export type ${nextName} =`, start + 1);
    assert.ok(start >= 0 && end > start, `${name} DTO must remain declared`);
    const declaration = source.slice(start, end);
    assert.match(declaration, /clientAttemptId: string;/);
    assert.doesNotMatch(declaration, /clientAttemptId\?:/);
  }
});
