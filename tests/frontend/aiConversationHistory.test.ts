import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const componentUrl = new URL(
  "../../src/AiConversationHistory.tsx",
  import.meta.url,
);

test("AI conversation history exposes a renderer-safe caller-owned contract", async () => {
  const source = await readFile(componentUrl, "utf8");

  assert.match(source, /id: string;\s+title: string;\s+messageCount: number;\s+active: boolean;/);
  assert.match(source, /items: ReadonlyArray<AiConversationHistoryItem>;/);
  assert.match(source, /onNew: \(\) => void;/);
  assert.match(source, /onSelect: \(id: string\) => void;/);
  assert.match(source, /onDelete: \(id: string\) => void;/);
  assert.doesNotMatch(
    source,
    /from "\.\/(?:aiWorkspace|backend|i18n)"|invoke\(|localStorage|sessionStorage|useState|useEffect/,
  );
});

test("AI conversation history delegates new, selection, and isolated deletion actions", async () => {
  const source = await readFile(componentUrl, "utf8");

  assert.match(source, /<button type="button" disabled=\{disabled\} onClick=\{onNew\}>/);
  assert.match(source, /onClick=\{\(\) => onSelect\(item\.id\)\}/);
  assert.match(
    source,
    /onClick=\{\(event\) => \{\s+event\.stopPropagation\(\);\s+onDelete\(item\.id\);\s+\}\}/,
  );
});

test("AI conversation history keeps copy external and exposes list semantics", async () => {
  const source = await readFile(componentUrl, "utf8");

  for (const label of [
    "regionLabel",
    "title",
    "newConversation",
    "empty",
    "messageCount",
    "selectConversation",
    "deleteConversation",
    "delete",
  ]) {
    assert.match(source, new RegExp(`labels\\.${label}`));
  }

  assert.match(source, /<section[^>]+aria-label=\{labels\.regionLabel\}/);
  assert.match(source, /<ul className="ai-conversation-history-list">/);
  assert.match(source, /aria-current=\{item\.active \? "true" : undefined\}/);
  assert.match(source, /aria-label=\{formatItemLabel\(labels\.selectConversation, item\)\}/);
  assert.match(source, /aria-label=\{formatItemLabel\(labels\.deleteConversation, item\)\}/);
  assert.match(source, /id="ai-conversation-history"/);
  assert.match(source, /title=\{item\.title\}/);
  assert.match(source, /role="status"/);
  assert.doesNotMatch(source, /[\u3400-\u9fff]/u);
});
