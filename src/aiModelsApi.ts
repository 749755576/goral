import { invoke, isTauri } from "@tauri-apps/api/core";

import type {
  RendererSafeSettingsAdapter,
  RendererSafeSettingsSnapshot,
} from "./settingsUi";

export const AI_MODELS_COMMAND = "list_ai_models";
export const AI_MODELS_RESPONSE_INVALID = "AI_MODELS_RESPONSE_INVALID";

const MAX_PROVIDER_PROFILE_ID_BYTES = 128;
const MAX_MODEL_ID_BYTES = 256;
const MAX_MODELS = 512;
const PROFILE_ID_PATTERN = /^[a-z0-9][a-z0-9._-]*$/u;
const UTF8 = new TextEncoder();

export type AiModelsInvoker = <T>(
  command: string,
  args?: Record<string, unknown>,
) => Promise<T>;

const invalidModelsResponse = (): Error => new Error(AI_MODELS_RESPONSE_INVALID);

const safeProviderProfileId = (providerProfileId: string): string => {
  if (
    typeof providerProfileId !== "string"
    || !PROFILE_ID_PATTERN.test(providerProfileId)
    || UTF8.encode(providerProfileId).byteLength > MAX_PROVIDER_PROFILE_ID_BYTES
  ) {
    throw new Error("AI_PROVIDER_INVALID");
  }
  return providerProfileId;
};

const containsControlOrUnpairedSurrogate = (value: string): boolean => {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (
      codePoint === undefined
      || (codePoint >= 0x00 && codePoint <= 0x1f)
      || (codePoint >= 0x7f && codePoint <= 0x9f)
      || (codePoint >= 0xd800 && codePoint <= 0xdfff)
    ) {
      return true;
    }
  }
  return false;
};

const compareUtf8 = (left: Uint8Array, right: Uint8Array): number => {
  const sharedLength = Math.min(left.byteLength, right.byteLength);
  for (let index = 0; index < sharedLength; index += 1) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return left.byteLength - right.byteLength;
};

const validateModelsResponse = (response: unknown): readonly string[] => {
  if (!Array.isArray(response) || response.length > MAX_MODELS) {
    throw invalidModelsResponse();
  }

  let previous: Uint8Array | null = null;
  for (const modelId of response) {
    if (
      typeof modelId !== "string"
      || modelId.trim().length === 0
      || containsControlOrUnpairedSurrogate(modelId)
    ) {
      throw invalidModelsResponse();
    }
    const encoded = UTF8.encode(modelId);
    if (
      encoded.byteLength > MAX_MODEL_ID_BYTES
      || (previous !== null && compareUtf8(previous, encoded) >= 0)
    ) {
      throw invalidModelsResponse();
    }
    previous = encoded;
  }
  return response;
};

const safeModelId = (modelId: string): string => {
  if (
    typeof modelId !== "string"
    || modelId.trim().length === 0
    || containsControlOrUnpairedSurrogate(modelId)
    || UTF8.encode(modelId).byteLength > MAX_MODEL_ID_BYTES
  ) {
    throw new Error("AI_MODEL_INVALID");
  }
  return modelId;
};

export const listAiModels = async (
  providerProfileId: string,
  commandInvoker: AiModelsInvoker = invoke,
): Promise<readonly string[]> => {
  const safeProfileId = safeProviderProfileId(providerProfileId);
  if (!isTauri() && commandInvoker === invoke) return [];
  const response = await commandInvoker<unknown>(AI_MODELS_COMMAND, {
    providerProfileId: safeProfileId,
  });
  return validateModelsResponse(response);
};

/**
 * Persist only one profile's model using the native Settings inventory CAS.
 * The current active profile and every unrelated setting are round-tripped
 * unchanged from the freshly loaded native snapshot.
 */
export const persistAiProviderModel = async (
  adapter: RendererSafeSettingsAdapter,
  providerProfileId: string,
  modelId: string,
): Promise<RendererSafeSettingsSnapshot> => {
  const safeProfileId = safeProviderProfileId(providerProfileId);
  const safeModel = safeModelId(modelId);
  const current = await adapter.load();
  const profileIndex = current.settings.ai.providers.findIndex(({ id }) => id === safeProfileId);
  if (profileIndex < 0) throw new Error("AI_PROVIDER_INVALID");
  if (current.settings.ai.providers[profileIndex]?.model === safeModel) return current;

  const nextSettings = structuredClone(current.settings);
  const profile = nextSettings.ai.providers[profileIndex];
  if (!profile) throw new Error("AI_PROVIDER_INVALID");
  profile.model = safeModel;
  return adapter.replace({
    settings: nextSettings,
    expectedInventoryRevision: current.inventoryRevision,
  });
};

export const supportsAiReasoningEffort = (
  protocol: "openAiChatCompletions" | "anthropicMessages",
  modelId: string,
): boolean => {
  if (protocol !== "openAiChatCompletions") return false;
  const model = modelId.normalize("NFKC").trim().toLocaleLowerCase();
  if (/gpt-5(?:\.\d+)?-chat/u.test(model)) return false;
  return /(?:^|[^a-z0-9])o[1-4](?:$|[^a-z0-9])/u.test(model)
    || /(?:^|[\/:._-])gpt-5(?:\.\d+)?(?:$|[\/:._-])/u.test(model)
    || /(?:^|[\/:._-])gpt-oss(?:$|[\/:._-])/u.test(model)
    || /reason(?:er|ing)/u.test(model)
    || /deepseek-r1/u.test(model)
    || /grok-4(?:$|[\/:._-])/u.test(model);
};
