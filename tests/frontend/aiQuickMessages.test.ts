import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  AI_COMPOSER_MAX_LENGTH,
  builtInAiQuickMessages,
  expandAiQuickMessage,
  filterAiQuickMessages,
  findAiQuickMessageTrigger,
  resolveAiQuickMessageIndex,
} from "../../src/ai/aiQuickMessages.ts";
import { createTranslator } from "../../src/i18n.ts";

const composerUrl = new URL("../../src/ai/AiComposer.tsx", import.meta.url);
const pickerUrl = new URL("../../src/ai/AiQuickMessagePicker.tsx", import.meta.url);

test("slash opens the complete localized built-in quick-message catalog", () => {
  const trigger = findAiQuickMessageTrigger("/", 1);
  const messages = filterAiQuickMessages(builtInAiQuickMessages(createTranslator("en-US")), trigger?.query ?? "missing");

  assert.deepEqual(trigger, { start: 0, end: 1, query: "" });
  assert.deepEqual(messages.map(({ slug }) => slug), ["status", "diagnose", "explain"]);
});

test("slash filtering accepts localized Unicode names as well as English slugs and labels", () => {
  const zhMessages = builtInAiQuickMessages(createTranslator("zh-CN"));
  const zhTrigger = findAiQuickMessageTrigger("/查询", "/查询".length);
  const enMessages = builtInAiQuickMessages(createTranslator("en-US"));

  assert.equal(zhTrigger?.query, "查询");
  assert.deepEqual(filterAiQuickMessages(zhMessages, zhTrigger?.query ?? "").map(({ slug }) => slug), ["status"]);
  assert.deepEqual(filterAiQuickMessages(enMessages, "diag").map(({ slug }) => slug), ["diagnose"]);
  assert.deepEqual(filterAiQuickMessages(enMessages, "terminal").map(({ slug }) => slug), ["status", "explain"]);
});

test("quick-message expansion replaces only the active slash token with ordinary text", () => {
  const value = "Before /查询 after";
  const caret = "Before /查询".length;
  const trigger = findAiQuickMessageTrigger(value, caret);
  assert.ok(trigger);

  const expanded = expandAiQuickMessage(value, trigger, "Summarize safely.");
  assert.ok(expanded);
  assert.deepEqual(expanded, {
    value: "Before Summarize safely. after",
    caret: "Before Summarize safely.".length,
  });
});

test("quick-message keyboard navigation wraps and supports Home and End", () => {
  assert.equal(resolveAiQuickMessageIndex("ArrowDown", 2, 3), 0);
  assert.equal(resolveAiQuickMessageIndex("ArrowUp", 0, 3), 2);
  assert.equal(resolveAiQuickMessageIndex("Home", 2, 3), 0);
  assert.equal(resolveAiQuickMessageIndex("End", 0, 3), 2);
  assert.equal(resolveAiQuickMessageIndex("ArrowDown", 0, 0), null);
});

test("programmatic quick-message expansion cannot bypass the Composer length bound", () => {
  const value = `${"x".repeat(AI_COMPOSER_MAX_LENGTH - 2)} /`;
  const trigger = findAiQuickMessageTrigger(value, value.length);
  assert.ok(trigger);
  assert.equal(expandAiQuickMessage(value, trigger, "This cannot fit."), null);
});

test("picker selection changes composer text without request, submit, credential, or terminal authority", async () => {
  const [composer, picker] = await Promise.all([
    readFile(composerUrl, "utf8"),
    readFile(pickerUrl, "utf8"),
  ]);

  assert.match(picker, /const select = useCallback[\s\S]*?expandAiQuickMessage[\s\S]*?onValueChange\(expanded\.value\);[\s\S]*?setState\(null\)/u);
  assert.doesNotMatch(picker, /onSubmit|terminal_execute|nativeAiAgentTransport|openAiCompatibleAgent|apiKey|baseUrl|invoke\(/u);
  assert.match(picker, /expectedControlledValueRef\.current === value[\s\S]*?setState\(null\)/u);
  assert.match(picker, /event\.key === "Tab"[\s\S]*?close\(\);[\s\S]*?return false/u);
  assert.match(composer, /if \(quickMessagePicker\.onKeyDown\(event\)\) return;[\s\S]*?event\.key === "Enter"[\s\S]*?onSubmit\(\)/u);
  assert.match(composer, /quickMessagePicker\.sync\(event\.target\.value,[\s\S]*?onValueChange\(event\.target\.value\)/u);
  assert.match(composer, /onBlur=\{quickMessagePicker\.close\}/u);
});
