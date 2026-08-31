import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  MANAGED_SSH_KEY_BUNDLE_HEADER_BYTES,
  MANAGED_SSH_KEY_BUNDLE_MAGIC,
  MANAGED_SSH_KEY_BUNDLE_VERSION,
  encodeManagedSshKeyBundleEnvelope,
  withZeroizedManagedSshKeyBundle,
} from "../../src/managedSshKeyBundle.ts";

test("managed SSH key raw envelope has a fixed versioned big-endian contract", () => {
  const privateKey = Uint8Array.from([0x11, 0x12]);
  const publicKey = Uint8Array.from([0x21]);
  const certificate = Uint8Array.from([0x31, 0x32, 0x33]);
  const passphrase = Uint8Array.from([0x41, 0x42]);
  const envelope = encodeManagedSshKeyBundleEnvelope({
    privateKey,
    publicKey,
    certificate,
    passphrase,
  });
  const view = new DataView(envelope.buffer, envelope.byteOffset, envelope.byteLength);

  assert.equal(
    new TextDecoder().decode(envelope.subarray(0, 8)),
    MANAGED_SSH_KEY_BUNDLE_MAGIC,
  );
  assert.equal(envelope[8], MANAGED_SSH_KEY_BUNDLE_VERSION);
  assert.equal(envelope[9], 0b111);
  assert.deepEqual([...envelope.subarray(10, 12)], [0, 0]);
  assert.equal(view.getUint32(12), privateKey.length);
  assert.equal(view.getUint32(16), publicKey.length);
  assert.equal(view.getUint32(20), certificate.length);
  assert.equal(view.getUint32(24), passphrase.length);
  assert.deepEqual(
    [...envelope.subarray(MANAGED_SSH_KEY_BUNDLE_HEADER_BYTES)],
    [...privateKey, ...publicKey, ...certificate, ...passphrase],
  );
});

test("absent optional bundle fields have zero flags and zero lengths", () => {
  const envelope = encodeManagedSshKeyBundleEnvelope({
    privateKey: Uint8Array.from([0x51]),
  });
  const view = new DataView(envelope.buffer, envelope.byteOffset, envelope.byteLength);
  assert.equal(envelope[9], 0);
  assert.equal(view.getUint32(12), 1);
  assert.deepEqual(
    [view.getUint32(16), view.getUint32(20), view.getUint32(24)],
    [0, 0, 0],
  );
  assert.deepEqual([...envelope.subarray(MANAGED_SSH_KEY_BUNDLE_HEADER_BYTES)], [0x51]);
});

test("successful staging clears the raw envelope and every caller-owned secret buffer", async () => {
  const privateKey = Uint8Array.from([1, 2, 3]);
  const publicKey = Uint8Array.from([4]);
  const certificate = Uint8Array.from([5]);
  const passphrase = Uint8Array.from([6, 7]);
  let stagedCopy: Uint8Array | undefined;
  let rawEnvelope: Uint8Array | undefined;

  const reference = await withZeroizedManagedSshKeyBundle(
    { privateKey, publicKey, certificate, passphrase },
    async (envelope) => {
      rawEnvelope = envelope;
      stagedCopy = envelope.slice();
      return "opaque-reference";
    },
  );

  assert.equal(reference, "opaque-reference");
  assert.equal(stagedCopy?.[MANAGED_SSH_KEY_BUNDLE_HEADER_BYTES], 1);
  for (const bytes of [privateKey, publicKey, certificate, passphrase, rawEnvelope!]) {
    assert.ok(bytes.every((byte) => byte === 0));
  }
});

test("failed staging and preflight rejection still clear caller-owned secret buffers", async () => {
  const privateKey = Uint8Array.from([9, 8, 7]);
  const passphrase = Uint8Array.from([6]);
  await assert.rejects(
    withZeroizedManagedSshKeyBundle(
      { privateKey, passphrase },
      async () => { throw new Error("fixed failure"); },
    ),
    /fixed failure/,
  );
  assert.ok(privateKey.every((byte) => byte === 0));
  assert.ok(passphrase.every((byte) => byte === 0));

  const emptyPrivateKey = new Uint8Array(0);
  const rejectedPassphrase = Uint8Array.from([5, 4, 3]);
  await assert.rejects(
    withZeroizedManagedSshKeyBundle(
      { privateKey: emptyPrivateKey, passphrase: rejectedPassphrase },
      async () => "unreachable",
    ),
    /MANAGED_SSH_KEY_BUNDLE_INVALID/,
  );
  assert.ok(rejectedPassphrase.every((byte) => byte === 0));
});

test("backend contract keeps secret material on the single raw staging call", async () => {
  const backendSource = await readFile(new URL("../../src/backend.ts", import.meta.url), "utf8");
  const workspaceSource = await readFile(
    new URL("../../src/TerminalWorkspace.tsx", import.meta.url),
    "utf8",
  );
  assert.match(
    backendSource,
    /invoke<string>\("stage_managed_ssh_key_bundle", envelope\)/,
  );
  assert.match(backendSource, /invoke<ManagedSshKeyCatalog>\("create_managed_ssh_key", \{ request \}\)/);
  assert.match(backendSource, /invoke<ManagedSshKeyCatalog>\("update_managed_ssh_key", \{ request \}\)/);
  assert.match(backendSource, /invoke<ManagedSshKeyCatalog>\("delete_managed_ssh_key", \{ request \}\)/);
  assert.match(
    backendSource,
    /invoke<ManagedSshMasterKeyRotationResult>\("rotate_managed_ssh_master_key"\)/,
  );

  const ordinaryRequests = backendSource.slice(
    backendSource.indexOf("export type CreateManagedSshKeyRequest"),
    backendSource.indexOf("export type PasswordIdentity ="),
  );
  for (const forbidden of ["privateKey", "publicKey", "certificate", "passphrase", "backendLocator", "custodyRevision"]) {
    assert.equal(
      ordinaryRequests.includes(forbidden),
      false,
      `${forbidden} crossed the ordinary managed-key mutation contract`,
    );
  }

  const editorState = workspaceSource.slice(
    workspaceSource.indexOf("type ManagedSshKeyEditor"),
    workspaceSource.indexOf("type ConnectionOperation"),
  );
  assert.doesNotMatch(
    editorState,
    /\b(?:privateKey|publicKey|certificate|passphrase)\??\s*:/,
    "managed-key secret material must not be stored in React editor state",
  );
  assert.match(
    workspaceSource,
    /expectedInventoryRevision: managedSshKeyCatalog\.inventoryRevision/,
    "opening an editor must freeze the observed catalog revision",
  );
  assert.equal(
    workspaceSource.match(/expectedInventoryRevision: editor\.expectedInventoryRevision/g)?.length,
    2,
    "create and update must use the editor's frozen catalog revision",
  );
  assert.match(
    workspaceSource,
    /expectedInventoryRevision: prompt\.expectedInventoryRevision/,
    "delete confirmation must use its frozen catalog revision",
  );
  assert.doesNotMatch(
    workspaceSource,
    /expectedInventoryRevision: catalog\.inventoryRevision/,
    "a refreshed revision must never be paired with a stale editor or delete confirmation",
  );
  assert.match(workspaceSource, /t\("managedKey\.rotate\.title"\)/);
  assert.match(workspaceSource, /t\("managedKey\.rotate\.warning"\)/);
  assert.doesNotMatch(workspaceSource, /轮换托管密钥的主密钥/);
});
