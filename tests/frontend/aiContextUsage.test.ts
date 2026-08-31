import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  createAiContextUsage,
  estimateAiChatTextTokens,
  estimateAiTextTokens,
  formatAiTokenCount,
  inferAiContextWindowTokens,
} from "../../src/ai/aiContextUsage.ts";
import { createTranslator } from "../../src/i18n.ts";

const composerUrl = new URL("../../src/ai/AiComposer.tsx", import.meta.url);
const ringUrl = new URL("../../src/ai/AiContextUsageRing.tsx", import.meta.url);
const workspaceUrl = new URL("../../src/aiWorkspace.tsx", import.meta.url);

test("AI text context estimate is deterministic and explicitly tokenizer-independent", () => {
  assert.equal(estimateAiTextTokens(""), 0);
  assert.equal(estimateAiTextTokens("abcd"), 1);
  assert.equal(estimateAiTextTokens("中文测试"), 4);
  assert.equal(estimateAiTextTokens("abcd中文"), 3);
  assert.equal(estimateAiTextTokens("🙂"), 2);
  assert.equal(
    estimateAiChatTextTokens([{ content: "abcd" }, { content: "中文" }]),
    13,
  );
});

test("AI context windows use explicit or recognized model names and never invent an unknown default", () => {
  assert.equal(inferAiContextWindowTokens("moonshot-v1-8k"), 8_000);
  assert.equal(inferAiContextWindowTokens("doubao-1-5-pro-32k-250115"), 32_000);
  assert.equal(inferAiContextWindowTokens("openai/gpt-4o-mini"), 128_000);
  assert.equal(inferAiContextWindowTokens("anthropic/claude-sonnet-4-5"), 200_000);
  assert.equal(inferAiContextWindowTokens("gpt-4.1-mini"), 1_000_000);
  assert.equal(inferAiContextWindowTokens("local/custom-model"), null);
  assert.equal(inferAiContextWindowTokens(""), null);
});

test("AI context usage reports a bounded percentage only when the model limit is known", () => {
  const known = createAiContextUsage([{ content: "x".repeat(64_000) }], "gpt-4o-mini", false);
  assert.equal(known.contextWindowTokens, 128_000);
  assert.ok(known.estimatedTextTokens > 0);
  assert.ok(known.percent !== null && known.percent > 0 && known.percent < 100);

  const unknown = createAiContextUsage([{ content: "hello" }], "private-model", true);
  assert.equal(unknown.contextWindowTokens, null);
  assert.equal(unknown.percent, null);
  assert.equal(unknown.containsImages, true);
  assert.equal(formatAiTokenCount(128_000), "128K");
});

test("context usage ring follows the actual projected request and exposes honest tooltip and aria copy", () => {
  const composer = readFileSync(composerUrl, "utf8");
  const ring = readFileSync(ringUrl, "utf8");
  const workspace = readFileSync(workspaceUrl, "utf8");
  const en = createTranslator("en-US");
  const zh = createTranslator("zh-CN");

  assert.match(workspace, /const projectedMessages = buildAiMessages\([\s\S]*?createAiContextUsage\(\s*projectedMessages/u);
  assert.match(workspace, /contextUsage=\{composerContextUsage\}/u);
  assert.match(composer, /<AiProviderMenu[\s\S]*?<AiContextUsageRing usage=\{contextUsage\} t=\{t\}/u);
  assert.match(ring, /compactValue[\s\S]*?usage\.percent === null[\s\S]*?≈\$\{used\}[\s\S]*?ai-context-usage-label/u);
  assert.match(ring, /usage\.percent === null \? null : \([\s\S]*?<svg/u);
  assert.match(ring, /title=\{label\}/u);
  assert.match(ring, /role: "progressbar"/u);
  assert.match(ring, /"aria-valuetext": label/u);
  assert.match(ring, /role: "img"/u);
  assert.match(en("ai.contextUsage.known", { used: "1K", max: "128K", percent: 1, model: "gpt-4o" }), /Estimated.+not provider-reported exact usage/u);
  assert.match(en("ai.contextUsage.unknown", { used: "1K", model: "private" }), /limit.+unknown/u);
  assert.match(zh("ai.contextUsage.known", { used: "1K", max: "128K", percent: 1, model: "gpt-4o" }), /估算.+并非服务商返回的精确用量/u);
  assert.match(zh("ai.contextUsage.unknown", { used: "1K", model: "私有模型" }), /上限未知/u);
  assert.match(zh("ai.contextUsage.imagesExcluded"), /未计入/u);
});
