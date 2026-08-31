import assert from "node:assert/strict";
import test from "node:test";

import {
  AI_IMAGE_MAX_BYTES,
  detectAiImageMimeType,
  encodeCanonicalBase64,
  prepareAiDraftImages,
  revokeAiDraftImages,
  validateAiImageBytes,
} from "../../src/ai/aiImageAttachments.ts";

test("AI image attachment helpers detect PNG, JPEG, and WebP signatures", () => {
  assert.equal(detectAiImageMimeType(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])), "image/png");
  assert.equal(detectAiImageMimeType(new Uint8Array([0xff, 0xd8, 0xff, 0xe0])), "image/jpeg");
  assert.equal(detectAiImageMimeType(new Uint8Array([
    0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x57, 0x45, 0x42, 0x50,
  ])), "image/webp");
  assert.equal(detectAiImageMimeType(new Uint8Array([0x47, 0x49, 0x46])), null);
});

test("AI image attachment helpers reject MIME spoofing and enforce the native size bound", () => {
  const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  assert.equal(validateAiImageBytes("", png), "image/png");
  assert.equal(validateAiImageBytes("image/png", png), "image/png");
  assert.throws(() => validateAiImageBytes("image/jpeg", png), /AI_IMAGE_MIME_MISMATCH/u);
  assert.throws(() => validateAiImageBytes("image/gif", new Uint8Array([0x47, 0x49, 0x46])), /AI_IMAGE_TYPE_UNSUPPORTED/u);
  assert.throws(() => validateAiImageBytes("image/png", new Uint8Array(AI_IMAGE_MAX_BYTES + 1)), /AI_IMAGE_TOO_LARGE/u);
});

test("AI image attachment Base64 is canonical and does not add a data URL prefix", () => {
  const encoded = encodeCanonicalBase64(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  assert.equal(encoded, "iVBORw0KGgo=");
  assert.doesNotMatch(encoded, /^data:/u);
});

test("AI image files become path-free bounded drafts with revocable previews", async () => {
  const file = new File(
    [new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])],
    "screen.png",
    { type: "image/png" },
  );
  const images = await prepareAiDraftImages([file], []);
  assert.equal(images.length, 1);
  assert.equal(images[0]?.name, "screen.png");
  assert.equal(images[0]?.mimeType, "image/png");
  assert.equal(images[0]?.data, "iVBORw0KGgo=");
  assert.match(images[0]?.previewUrl ?? "", /^blob:/u);
  assert.equal("path" in (images[0] ?? {}), false);
  revokeAiDraftImages(images);
});
