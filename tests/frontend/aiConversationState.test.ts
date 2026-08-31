import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  AI_NO_TERMINAL_SCOPE_KEY,
  MAX_AI_CONVERSATIONS_PER_SCOPE,
  MAX_AI_CONVERSATION_SCOPES,
  MAX_AI_CONVERSATION_IMAGE_PARTS,
  MAX_AI_CONVERSATION_TITLE_BYTES,
  MAX_AI_CONVERSATION_TOTAL_TEXT_BYTES,
  MAX_AI_MESSAGES_PER_CONVERSATION,
  MAX_AI_MESSAGE_BYTES,
  activateAiConversationScope,
  aiConversationScopeKey,
  appendAiConversationMessage,
  captureActiveAiConversation,
  createAiConversation,
  createAiConversationState,
  deleteAiConversation,
  deleteAiConversationMessage,
  deriveAiConversationTitle,
  getAiConversation,
  getAiConversationScope,
  switchAiConversation,
  updateAiConversationMessage,
  type AiConversationState,
  type AiConversationTarget,
} from "../../src/aiConversationState.ts";

const utf8 = new TextEncoder();

const activate = (
  state: AiConversationState,
  routeId: string | null,
  generation: number,
  conversationId: string,
) => activateAiConversationScope(
  state,
  routeId === null ? null : { routeId, generation },
  { conversationId },
);

const append = (
  state: AiConversationState,
  target: AiConversationTarget,
  id: string,
  content: string,
  role: "user" | "assistant" = "user",
) => appendAiConversationMessage(state, target, { id, role, content });

test("terminal scopes use the exact routeId:generation key and no-terminal has its own scope", () => {
  assert.equal(aiConversationScopeKey({ routeId: "ssh:tab-A", generation: 17 }), "ssh:tab-A:17");
  assert.equal(aiConversationScopeKey(null), AI_NO_TERMINAL_SCOPE_KEY);
  assert.equal(aiConversationScopeKey(undefined), AI_NO_TERMINAL_SCOPE_KEY);
  assert.notEqual(aiConversationScopeKey({ routeId: "no-terminal", generation: 0 }), AI_NO_TERMINAL_SCOPE_KEY);
});

test("conversation state supports create, switch, and delete without mutating an older snapshot", () => {
  const empty = createAiConversationState();
  const activated = activate(empty, "route-a", 1, "conversation-a");
  const withSecond = createAiConversation(activated, "route-a:1", {
    conversationId: "conversation-b",
  });
  const switched = switchAiConversation(withSecond, {
    scopeKey: "route-a:1",
    conversationId: "conversation-a",
  });
  const deleted = deleteAiConversation(switched, {
    scopeKey: "route-a:1",
    conversationId: "conversation-a",
  });

  assert.equal(empty.scopes.length, 0);
  assert.equal(getAiConversationScope(activated, "route-a:1")?.conversations.length, 1);
  assert.equal(captureActiveAiConversation(withSecond)?.conversationId, "conversation-b");
  assert.equal(captureActiveAiConversation(switched)?.conversationId, "conversation-a");
  assert.equal(captureActiveAiConversation(deleted)?.conversationId, "conversation-b");
  assert.deepEqual(
    getAiConversationScope(deleted, "route-a:1")?.conversations.map(({ id }) => id),
    ["conversation-b"],
  );
  assert.equal(Object.isFrozen(deleted), true);
  assert.equal(Object.isFrozen(deleted.scopes), true);
  assert.equal(Object.isFrozen(deleted.scopes[0]?.conversations), true);
});

test("the first user message creates a short title without hidden controls or markup", () => {
  let state = activate(createAiConversationState(), null, 0, "untitled");
  const target = captureActiveAiConversation(state);
  assert.ok(target);
  state = append(
    state,
    target,
    "message-1",
    `  <script>部署生产环境\u202Ehidden</script>  ${"界".repeat(100)}`,
  );
  const firstTitle = getAiConversation(state, target)?.title ?? "";
  assert.ok(firstTitle.length > 0);
  assert.ok(utf8.encode(firstTitle).byteLength <= MAX_AI_CONVERSATION_TITLE_BYTES);
  assert.doesNotMatch(firstTitle, /[<>\p{Cc}\p{Cf}\p{Cs}]/u);

  state = append(state, target, "message-2", "这条消息不能重命名会话");
  assert.equal(getAiConversation(state, target)?.title, firstTitle);
  assert.equal(deriveAiConversationTitle("\u0000\u202E<>"), "");
});

test("conversation title stays fixed after the first user message is evicted", () => {
  let state = activate(createAiConversationState(), null, 0, "stable-title");
  const target = captureActiveAiConversation(state);
  assert.ok(target);
  state = append(state, target, "first-user", "First title");
  for (let index = 0; index < MAX_AI_MESSAGES_PER_CONVERSATION + 2; index += 1) {
    state = append(state, target, `assistant-${index}`, `reply ${index}`, "assistant");
  }
  assert.equal(getAiConversation(state, target)?.messages.some(({ id }) => id === "first-user"), false);
  state = append(state, target, "second-user", "Second title");
  assert.equal(getAiConversation(state, target)?.title, "First title");
});

test("late replies append only to their captured scope and conversation", () => {
  let state = activate(createAiConversationState(), "ssh-original", 4, "original-chat");
  const captured = captureActiveAiConversation(state);
  assert.ok(captured);
  state = activate(state, "ssh-current", 5, "current-chat");
  const current = captureActiveAiConversation(state);
  assert.ok(current);

  state = append(state, captured, "late-answer", "original response", "assistant");
  assert.equal(getAiConversation(state, captured)?.messages.at(-1)?.content, "original response");
  assert.equal(getAiConversation(state, current)?.messages.length, 0);
  assert.deepEqual(captureActiveAiConversation(state), current);

  const staleState = deleteAiConversation(state, captured);
  assert.strictEqual(
    append(staleState, captured, "later-answer", "must be discarded", "assistant"),
    staleState,
  );
  assert.equal(getAiConversation(staleState, current)?.messages.length, 0);
});

test("streaming updates one captured assistant message and cannot cross conversation targets", () => {
  let state = activate(createAiConversationState(), "stream-route", 8, "stream-chat");
  const streamingTarget = captureActiveAiConversation(state);
  assert.ok(streamingTarget);
  state = append(state, streamingTarget, "assistant-stream", "", "assistant");

  state = activate(state, "other-route", 9, "other-chat");
  const otherTarget = captureActiveAiConversation(state);
  assert.ok(otherTarget);
  const beforeUpdate = state;
  state = updateAiConversationMessage(
    state,
    streamingTarget,
    "assistant-stream",
    { content: "浣?" },
  );
  state = updateAiConversationMessage(
    state,
    streamingTarget,
    "assistant-stream",
    { content: "浣犲ソ" },
  );

  const streamedMessages = getAiConversation(state, streamingTarget)?.messages ?? [];
  assert.equal(streamedMessages.length, 1);
  assert.deepEqual(streamedMessages[0], {
    id: "assistant-stream",
    role: "assistant",
    content: "浣犲ソ",
    createdOrder: streamedMessages[0]?.createdOrder,
  });
  assert.equal(getAiConversation(state, otherTarget)?.messages.length, 0);
  assert.deepEqual(captureActiveAiConversation(state), otherTarget);
  assert.notStrictEqual(state, beforeUpdate);

  const unknownMessage = updateAiConversationMessage(
    state,
    streamingTarget,
    "late-unknown-message",
    { content: "must be ignored" },
  );
  assert.strictEqual(unknownMessage, state);
  const withoutPlaceholder = deleteAiConversationMessage(
    state,
    streamingTarget,
    "assistant-stream",
  );
  assert.equal(getAiConversation(withoutPlaceholder, streamingTarget)?.messages.length, 0);
  assert.equal(getAiConversation(withoutPlaceholder, otherTarget)?.messages.length, 0);
});

test("message content and message count are hard bounded using UTF-8 boundaries", () => {
  let state = activate(createAiConversationState(), null, 0, "bounded-chat");
  const target = captureActiveAiConversation(state);
  assert.ok(target);
  state = append(state, target, "oversized", "界".repeat(MAX_AI_MESSAGE_BYTES), "assistant");
  const bounded = getAiConversation(state, target)?.messages[0]?.content ?? "";
  assert.ok(utf8.encode(bounded).byteLength <= MAX_AI_MESSAGE_BYTES);
  assert.doesNotMatch(bounded, /\uFFFD/u);

  for (let index = 0; index < MAX_AI_MESSAGES_PER_CONVERSATION + 3; index += 1) {
    state = append(state, target, `small-${index}`, `message ${index}`, "assistant");
  }
  const messages = getAiConversation(state, target)?.messages ?? [];
  assert.equal(messages.length, MAX_AI_MESSAGES_PER_CONVERSATION);
  assert.equal(messages.at(-1)?.id, `small-${MAX_AI_MESSAGES_PER_CONVERSATION + 2}`);
  assert.equal(messages.some(({ id }) => id === "oversized"), false);
});

test("conversation and scope catalogs evict the oldest non-active histories", () => {
  let state = activate(createAiConversationState(), "first-route", 1, "chat-0");
  for (let index = 1; index <= MAX_AI_CONVERSATIONS_PER_SCOPE; index += 1) {
    state = createAiConversation(state, "first-route:1", { conversationId: `chat-${index}` });
  }
  const firstScope = getAiConversationScope(state, "first-route:1");
  assert.equal(firstScope?.conversations.length, MAX_AI_CONVERSATIONS_PER_SCOPE);
  assert.equal(firstScope?.conversations.some(({ id }) => id === "chat-0"), false);
  assert.equal(firstScope?.activeConversationId, `chat-${MAX_AI_CONVERSATIONS_PER_SCOPE}`);

  for (let index = 0; index <= MAX_AI_CONVERSATION_SCOPES; index += 1) {
    state = activate(state, `route-${index}`, index, `route-chat-${index}`);
  }
  assert.equal(state.scopes.length, MAX_AI_CONVERSATION_SCOPES);
  assert.equal(state.scopes.some(({ key }) => key === "first-route:1"), false);
  assert.equal(state.activeScopeKey, `route-${MAX_AI_CONVERSATION_SCOPES}:${MAX_AI_CONVERSATION_SCOPES}`);
});

test("scope eviction never drops a protected in-flight conversation target", () => {
  let state = activate(createAiConversationState(), "request-route", 1, "request-chat");
  const requestTarget = captureActiveAiConversation(state);
  assert.ok(requestTarget);
  state = append(state, requestTarget, "request-message", "still in flight");

  for (let index = 0; index < MAX_AI_CONVERSATION_SCOPES; index += 1) {
    state = activateAiConversationScope(
      state,
      { routeId: `new-route-${index}`, generation: index },
      {
        conversationId: `new-chat-${index}`,
        protectedTargets: [requestTarget],
      },
    );
  }

  assert.equal(state.scopes.length, MAX_AI_CONVERSATION_SCOPES);
  assert.equal(getAiConversation(state, requestTarget)?.messages[0]?.content, "still in flight");
  state = append(state, requestTarget, "late-reply", "accepted", "assistant");
  assert.equal(getAiConversation(state, requestTarget)?.messages.at(-1)?.content, "accepted");
});

test("the global text budget drops inactive history before trimming oldest active messages", () => {
  let state = activate(createAiConversationState(), "old-route", 1, "old-history");
  const oldTarget = captureActiveAiConversation(state);
  assert.ok(oldTarget);
  state = append(state, oldTarget, "old-large", "o".repeat(MAX_AI_MESSAGE_BYTES), "assistant");

  state = activate(state, "active-route", 2, "active-history");
  const activeTarget = captureActiveAiConversation(state);
  assert.ok(activeTarget);
  const appendedIds: string[] = [];
  for (let index = 0; index < 20; index += 1) {
    const id = `active-large-${index}`;
    appendedIds.push(id);
    state = append(state, activeTarget, id, "a".repeat(MAX_AI_MESSAGE_BYTES), "assistant");
  }

  assert.ok(state.totalTextBytes <= MAX_AI_CONVERSATION_TOTAL_TEXT_BYTES);
  assert.equal(getAiConversation(state, oldTarget), null);
  const activeMessages = getAiConversation(state, activeTarget)?.messages ?? [];
  assert.ok(activeMessages.length < appendedIds.length);
  assert.equal(activeMessages.some(({ id }) => id === appendedIds[0]), false);
  assert.equal(activeMessages.at(-1)?.id, appendedIds.at(-1));
});

test("conversation image bodies stay bounded while safe attachment metadata remains visible", () => {
  let state = activate(createAiConversationState(), "vision-route", 3, "vision-chat");
  const target = captureActiveAiConversation(state);
  assert.ok(target);
  for (let index = 0; index < MAX_AI_CONVERSATION_IMAGE_PARTS + 2; index += 1) {
    state = appendAiConversationMessage(state, target, {
      id: `vision-message-${index}`,
      role: "user",
      content: `image ${index}`,
      attachments: [{
        id: `vision-image-${index}`,
        name: `screen-${index}.png`,
        mimeType: "image/png",
        size: 8,
        data: "iVBORw0KGgo=",
      }],
    });
  }

  const messages = getAiConversation(state, target)?.messages ?? [];
  const attachments = messages.flatMap((message) => message.attachments ?? []);
  assert.equal(attachments.length, MAX_AI_CONVERSATION_IMAGE_PARTS + 2);
  assert.equal(attachments.filter((attachment) => attachment.data).length, MAX_AI_CONVERSATION_IMAGE_PARTS);
  assert.equal(attachments[0]?.data, undefined);
  assert.equal(attachments.at(-1)?.data, "iVBORw0KGgo=");
  assert.equal("path" in (attachments.at(-1) ?? {}), false);
  assert.equal("previewUrl" in (attachments.at(-1) ?? {}), false);
});

test("the state module is memory-only and has no credential or persistence surface", async () => {
  const source = await readFile(new URL("../../src/aiConversationState.ts", import.meta.url), "utf8");
  assert.doesNotMatch(source, /localStorage|sessionStorage|indexedDB|StorageEvent/u);
  assert.doesNotMatch(source, /api[_-]?key|authorization|bearer/iu);

  const state = activate(createAiConversationState(), null, 0, "memory-only");
  assert.deepEqual(Object.keys(state).sort(), ["activeScopeKey", "revision", "scopes", "totalTextBytes"]);
});
