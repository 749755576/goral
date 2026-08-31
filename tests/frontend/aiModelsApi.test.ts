import assert from "node:assert/strict";
import test from "node:test";

import {
  AI_MODELS_COMMAND,
  AI_MODELS_RESPONSE_INVALID,
  listAiModels,
  persistAiProviderModel,
  supportsAiReasoningEffort,
} from "../../src/aiModelsApi.ts";
import { createDefaultRendererSafeSettings } from "../../src/settingsUi.ts";

test("model discovery invokes only the profile-bound native command", async () => {
  const calls: Array<Readonly<{
    command: string;
    args?: Record<string, unknown>;
  }>> = [];
  const expected = ["alpha", "model-z", "中文模型"];
  const result = await listAiModels("deepseek.work-1", async <T>(
    command: string,
    args?: Record<string, unknown>,
  ): Promise<T> => {
    calls.push({ command, args });
    return expected as T;
  });

  assert.deepEqual(result, expected);
  assert.deepEqual(calls, [{
    command: AI_MODELS_COMMAND,
    args: { providerProfileId: "deepseek.work-1" },
  }]);
  assert.deepEqual(Object.keys(calls[0]?.args ?? {}), ["providerProfileId"]);
});

test("model discovery rejects invalid provider profile IDs before invocation", async () => {
  let invoked = false;
  const invoker = async <T>(): Promise<T> => {
    invoked = true;
    return [] as T;
  };
  const invalidProfiles = [
    "",
    "Uppercase",
    "-leading-dash",
    "profile/slash",
    "profile space",
    "x".repeat(129),
    "中文",
    "line\nbreak",
  ];

  for (const profileId of invalidProfiles) {
    await assert.rejects(
      () => listAiModels(profileId, invoker),
      { message: "AI_PROVIDER_INVALID" },
    );
  }
  assert.equal(invoked, false);
});

test("model discovery rejects malicious or non-canonical native responses", async () => {
  const invalidResponses: unknown[] = [
    null,
    {},
    "not-an-array",
    Array.from({ length: 513 }, (_, index) => `model-${index.toString().padStart(3, "0")}`),
    ["valid", 7],
    [""],
    ["   "],
    ["line\nbreak"],
    ["control\u0085character"],
    ["x".repeat(257)],
    ["duplicate", "duplicate"],
    ["zeta", "alpha"],
    ["unpaired-\ud800"],
  ];

  for (const response of invalidResponses) {
    await assert.rejects(
      () => listAiModels("openai", async <T>(): Promise<T> => response as T),
      { message: AI_MODELS_RESPONSE_INVALID },
    );
  }
});

test("ordinary browser preview returns an empty model catalog without invoking Tauri", async () => {
  assert.deepEqual(await listAiModels("openai"), []);
});

test("model selection updates only the requested profile through Settings inventory CAS", async () => {
  const settings = createDefaultRendererSafeSettings("windows");
  settings.ai.providers.push({
    id: "deepseek.work",
    providerId: "deepseek",
    name: "DeepSeek Work",
    protocol: "openAiChatCompletions",
    baseUrl: "https://api.deepseek.com/v1",
    model: "deepseek-chat",
    enabled: true,
  });
  settings.ai.activeProviderId = "openai-compatible";
  let snapshot = {
    settings: structuredClone(settings),
    inventoryRevision: { generation: 0, checksum: "before" },
  };
  const adapter = {
    async load() { return structuredClone(snapshot); },
    async replace(request: { settings: typeof settings; expectedInventoryRevision: unknown }) {
      assert.deepEqual(request.expectedInventoryRevision, snapshot.inventoryRevision);
      snapshot = {
        settings: structuredClone(request.settings),
        inventoryRevision: { generation: 1, checksum: "after" },
      };
      return structuredClone(snapshot);
    },
  };
  const before = await adapter.load();

  const saved = await persistAiProviderModel(adapter, "deepseek.work", "deepseek-reasoner");

  assert.equal(saved.settings.ai.activeProviderId, before.settings.ai.activeProviderId);
  assert.equal(saved.settings.ai.providers[0]?.model, before.settings.ai.providers[0]?.model);
  assert.equal(
    saved.settings.ai.providers.find(({ id }) => id === "deepseek.work")?.model,
    "deepseek-reasoner",
  );
  assert.notDeepEqual(saved.inventoryRevision, before.inventoryRevision);
});

test("model persistence rejects invalid targets without clearing the stored profile", async () => {
  const settings = createDefaultRendererSafeSettings("windows");
  const snapshot = {
    settings: structuredClone(settings),
    inventoryRevision: { generation: 0, checksum: "unchanged" },
  };
  const adapter = {
    async load() { return structuredClone(snapshot); },
    async replace() { throw new Error("replace must not be called"); },
  };
  const before = await adapter.load();
  await assert.rejects(
    persistAiProviderModel(adapter, "openai-compatible", "line\nbreak"),
    /AI_MODEL_INVALID/u,
  );
  await assert.rejects(
    persistAiProviderModel(adapter, "missing-profile", "gpt-5"),
    /AI_PROVIDER_INVALID/u,
  );
  assert.deepEqual(await adapter.load(), before);
});

test("reasoning effort is limited to recognized OpenAI-compatible reasoning models", () => {
  for (const model of [
    "o1",
    "openai/o2-preview",
    "openai/o3-mini",
    "o4-mini",
    "gpt-5",
    "gpt-5.1-codex",
    "openai/gpt-oss-120b",
    "deepseek-reasoner",
    "deepseek-r1",
    "x-ai/grok-4-fast",
    "custom-reasoning-model",
  ]) {
    assert.equal(supportsAiReasoningEffort("openAiChatCompletions", model), true, model);
  }
  for (const model of [
    "gpt-4o",
    "gpt-50",
    "gpt-5-chat-latest",
    "gpt-5.1-chat-latest",
    "claude-sonnet-4-5",
    "ordinary-chat",
  ]) {
    assert.equal(supportsAiReasoningEffort("openAiChatCompletions", model), false, model);
  }
  assert.equal(supportsAiReasoningEffort("anthropicMessages", "claude-reasoning"), false);
});
