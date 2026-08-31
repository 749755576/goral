import type { NativeAiChatContentPart } from "../aiApi";

export const AI_IMAGE_MAX_COUNT = 4;
export const AI_IMAGE_MAX_BYTES = 5 * 1024 * 1024;
export const AI_IMAGE_MAX_TOTAL_BYTES = 10 * 1024 * 1024;
export const AI_IMAGE_ACCEPT = "image/png,image/jpeg,image/webp";

// 120 Unicode scalars stay below the conversation metadata's 512-byte bound.
const AI_IMAGE_NAME_MAX_LENGTH = 120;
const BASE64_CHUNK_BYTES = 0x8000;

export type AiImageMimeType = NativeAiChatContentPart["mimeType"];

export type AiDraftImage = Readonly<{
  id: string;
  name: string;
  mimeType: AiImageMimeType;
  size: number;
  data: string;
  previewUrl: string;
}>;

export type AiImageAttachmentMetadata = Readonly<{
  id: string;
  name: string;
  mimeType: AiImageMimeType;
  size: number;
}>;

const safeImageName = (value: string): string => {
  const normalized = value
    .normalize("NFKC")
    .replace(/[\p{Cc}\p{Cf}\p{Cs}]/gu, "")
    .trim();
  return [...(normalized || "image")].slice(0, AI_IMAGE_NAME_MAX_LENGTH).join("");
};

export const detectAiImageMimeType = (bytes: Uint8Array): AiImageMimeType | null => {
  if (
    bytes.length >= 8
    && bytes[0] === 0x89
    && bytes[1] === 0x50
    && bytes[2] === 0x4e
    && bytes[3] === 0x47
    && bytes[4] === 0x0d
    && bytes[5] === 0x0a
    && bytes[6] === 0x1a
    && bytes[7] === 0x0a
  ) return "image/png";
  if (
    bytes.length >= 3
    && bytes[0] === 0xff
    && bytes[1] === 0xd8
    && bytes[2] === 0xff
  ) return "image/jpeg";
  if (
    bytes.length >= 12
    && bytes[0] === 0x52
    && bytes[1] === 0x49
    && bytes[2] === 0x46
    && bytes[3] === 0x46
    && bytes[8] === 0x57
    && bytes[9] === 0x45
    && bytes[10] === 0x42
    && bytes[11] === 0x50
  ) return "image/webp";
  return null;
};

export const encodeCanonicalBase64 = (bytes: Uint8Array): string => {
  const chunks: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += BASE64_CHUNK_BYTES) {
    const end = Math.min(offset + BASE64_CHUNK_BYTES, bytes.length);
    let binary = "";
    for (let index = offset; index < end; index += 1) {
      binary += String.fromCharCode(bytes[index] ?? 0);
    }
    chunks.push(binary);
  }
  return btoa(chunks.join(""));
};

export const validateAiImageBytes = (
  declaredMimeType: string,
  bytes: Uint8Array,
): AiImageMimeType => {
  if (bytes.length === 0) throw new Error("AI_IMAGE_INPUT_INVALID");
  if (bytes.length > AI_IMAGE_MAX_BYTES) throw new Error("AI_IMAGE_TOO_LARGE");
  const detectedMimeType = detectAiImageMimeType(bytes);
  if (!detectedMimeType) throw new Error("AI_IMAGE_TYPE_UNSUPPORTED");
  if (declaredMimeType && declaredMimeType !== detectedMimeType) {
    throw new Error("AI_IMAGE_MIME_MISMATCH");
  }
  return detectedMimeType;
};

export const prepareAiDraftImages = async (
  files: readonly File[],
  existing: readonly AiDraftImage[],
): Promise<readonly AiDraftImage[]> => {
  if (files.length === 0) return Object.freeze([]);
  if (existing.length + files.length > AI_IMAGE_MAX_COUNT) {
    throw new Error("AI_IMAGE_COUNT_LIMIT");
  }
  let totalBytes = existing.reduce((total, image) => total + image.size, 0);
  const prepared: AiDraftImage[] = [];
  try {
    for (const file of files) {
      if (file.size === 0) throw new Error("AI_IMAGE_INPUT_INVALID");
      if (file.size > AI_IMAGE_MAX_BYTES) throw new Error("AI_IMAGE_TOO_LARGE");
      totalBytes += file.size;
      if (totalBytes > AI_IMAGE_MAX_TOTAL_BYTES) {
        throw new Error("AI_IMAGE_TOTAL_TOO_LARGE");
      }
      const bytes = new Uint8Array(await file.arrayBuffer());
      const mimeType = validateAiImageBytes(file.type, bytes);
      const previewUrl = URL.createObjectURL(file);
      prepared.push(Object.freeze({
        id: crypto.randomUUID(),
        name: safeImageName(file.name),
        mimeType,
        size: bytes.length,
        data: encodeCanonicalBase64(bytes),
        previewUrl,
      }));
    }
    return Object.freeze(prepared);
  } catch (reason) {
    prepared.forEach((image) => URL.revokeObjectURL(image.previewUrl));
    throw reason;
  }
};

export const aiImageContentParts = (
  images: readonly AiDraftImage[],
): readonly NativeAiChatContentPart[] => Object.freeze(images.map((image) => Object.freeze({
  type: "image" as const,
  mimeType: image.mimeType,
  data: image.data,
})));

export const aiImageAttachmentMetadata = (
  images: readonly AiDraftImage[],
): readonly AiImageAttachmentMetadata[] => Object.freeze(images.map((image) => Object.freeze({
  id: image.id,
  name: image.name,
  mimeType: image.mimeType,
  size: image.size,
})));

export const revokeAiDraftImages = (images: readonly AiDraftImage[]): void => {
  images.forEach((image) => URL.revokeObjectURL(image.previewUrl));
};
