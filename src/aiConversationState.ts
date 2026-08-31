/**
 * Bounded, renderer-memory-only AI conversation state.
 *
 * This module deliberately has no storage adapter and contains no provider
 * configuration. In particular, credentials must remain outside this state.
 */

export const AI_NO_TERMINAL_SCOPE_KEY = "no-terminal";
export const MAX_AI_CONVERSATION_SCOPES = 12;
export const MAX_AI_CONVERSATIONS_PER_SCOPE = 8;
// The native request adds one system message and accepts at most 64 entries.
export const MAX_AI_MESSAGES_PER_CONVERSATION = 63;
export const MAX_AI_MESSAGE_BYTES = 128 * 1024;
export const MAX_AI_CONVERSATION_TITLE_BYTES = 96;
export const MAX_AI_IMAGE_ATTACHMENTS_PER_MESSAGE = 4;
export const MAX_AI_IMAGE_ATTACHMENT_BYTES = 5 * 1024 * 1024;
export const MAX_AI_TOOL_COMMAND_BYTES = 32 * 1024 - 1;
export const MAX_AI_CONVERSATION_IMAGE_PARTS = 4;
export const MAX_AI_CONVERSATION_IMAGE_BYTES = 10 * 1024 * 1024;
// Leave headroom below the native 512 KiB request-text limit for the system
// safety prompt and two explicitly attached 16 KiB terminal context blocks.
export const MAX_AI_CONVERSATION_TOTAL_TEXT_BYTES = 384 * 1024;

const MAX_AI_SCOPE_KEY_BYTES = 2 * 1024;
const MAX_AI_OPAQUE_ID_BYTES = 256;
const MAX_AI_ATTACHMENT_NAME_BYTES = 512;
// Empty titles are localized by the presentation layer. Keeping locale copy
// out of this state prevents an English workspace inheriting a Chinese title.
const DEFAULT_CONVERSATION_TITLE = "";
const utf8 = new TextEncoder();

export type AiConversationMessageRole = "user" | "assistant" | "system" | "error";

export type AiConversationTerminalScope = Readonly<{
  routeId: string;
  generation: number;
}>;

export type AiConversationToolActivityStatus =
  | "running"
  | "completed"
  | "timedOut"
  | "failed"
  | "rejected"
  | "cancelled";

export type AiConversationToolActivity = Readonly<{
  id: string;
  name: "terminal_execute";
  command: string;
  status: AiConversationToolActivityStatus;
  errorCode?: string;
}>;

export type AiConversationMessage = Readonly<{
  id: string;
  role: AiConversationMessageRole;
  content: string;
  attachments?: readonly AiConversationImageAttachment[];
  toolActivity?: AiConversationToolActivity;
  createdOrder: number;
}>;

export type AiConversationImageAttachment = Readonly<{
  id: string;
  name: string;
  mimeType: "image/png" | "image/jpeg" | "image/webp";
  size: number;
  /** In-memory only. Old image bodies are discarded before their metadata. */
  data?: string;
}>;

export type AiConversationImageAttachmentInput = Readonly<{
  id: string;
  name: string;
  mimeType: "image/png" | "image/jpeg" | "image/webp";
  size: number;
  data: string;
}>;

export type AiConversation = Readonly<{
  id: string;
  title: string;
  titleInitialized: boolean;
  messages: readonly AiConversationMessage[];
  createdOrder: number;
  updatedOrder: number;
}>;

export type AiConversationScopeState = Readonly<{
  key: string;
  activeConversationId: string;
  conversations: readonly AiConversation[];
  createdOrder: number;
  updatedOrder: number;
}>;

export type AiConversationState = Readonly<{
  activeScopeKey: string;
  scopes: readonly AiConversationScopeState[];
  revision: number;
  totalTextBytes: number;
}>;

export type AiConversationTarget = Readonly<{
  scopeKey: string;
  conversationId: string;
}>;

export type AiConversationMessageInput = Readonly<{
  id: string;
  role: AiConversationMessageRole;
  content: string;
  attachments?: readonly AiConversationImageAttachmentInput[];
  toolActivity?: AiConversationToolActivity;
}>;

export type AiConversationMessageUpdate = Readonly<{
  role?: AiConversationMessageRole;
  content?: string;
  toolActivity?: AiConversationToolActivity;
}>;

export type AiConversationCreationOptions = Readonly<{
  conversationId?: string;
}>;

export type AiConversationActivationOptions = Readonly<{
  conversationId?: string;
  /** Keep an in-flight request target alive while another scope is activated. */
  protectedTargets?: readonly AiConversationTarget[];
}>;

type MutableMessage = {
  id: string;
  role: AiConversationMessageRole;
  content: string;
  attachments?: Array<{
    id: string;
    name: string;
    mimeType: "image/png" | "image/jpeg" | "image/webp";
    size: number;
    data?: string;
  }>;
  toolActivity?: {
    id: string;
    name: "terminal_execute";
    command: string;
    status: AiConversationToolActivityStatus;
    errorCode?: string;
  };
  createdOrder: number;
};

type MutableConversation = {
  id: string;
  title: string;
  titleInitialized: boolean;
  messages: MutableMessage[];
  createdOrder: number;
  updatedOrder: number;
};

type MutableScope = {
  key: string;
  activeConversationId: string;
  conversations: MutableConversation[];
  createdOrder: number;
  updatedOrder: number;
};

type MutableState = {
  activeScopeKey: string;
  scopes: MutableScope[];
  revision: number;
};

const byteLength = (value: string): number => utf8.encode(value).byteLength;

const takeUtf8Prefix = (value: string, maxBytes: number): string => {
  if (byteLength(value) <= maxBytes) return value;
  let result = "";
  let used = 0;
  for (const character of value) {
    const size = byteLength(character);
    if (used + size > maxBytes) break;
    result += character;
    used += size;
  }
  return result;
};

const assertBoundedOpaqueText = (value: string, name: string, maxBytes: number): string => {
  if (!value || byteLength(value) > maxBytes || /[\p{Cc}\p{Cf}\p{Cs}]/u.test(value)) {
    throw new Error(`AI_CONVERSATION_${name}_INVALID`);
  }
  return value;
};

const assertScopeKey = (scopeKey: string): string => (
  assertBoundedOpaqueText(scopeKey, "SCOPE_KEY", MAX_AI_SCOPE_KEY_BYTES)
);

const assertOpaqueId = (id: string): string => (
  assertBoundedOpaqueText(id, "ID", MAX_AI_OPAQUE_ID_BYTES)
);

const makeConversationId = (): string => `ai-conversation-${crypto.randomUUID()}`;

const newConversation = (id: string, order: number): MutableConversation => ({
  id: assertOpaqueId(id),
  title: DEFAULT_CONVERSATION_TITLE,
  titleInitialized: false,
  messages: [],
  createdOrder: order,
  updatedOrder: order,
});

const toMutable = (state: AiConversationState): MutableState => ({
  activeScopeKey: state.activeScopeKey,
  revision: state.revision,
  scopes: state.scopes.map((scope) => ({
    key: scope.key,
    activeConversationId: scope.activeConversationId,
    createdOrder: scope.createdOrder,
    updatedOrder: scope.updatedOrder,
    conversations: scope.conversations.map((conversation) => ({
      id: conversation.id,
      title: conversation.title,
      titleInitialized: conversation.titleInitialized,
      createdOrder: conversation.createdOrder,
      updatedOrder: conversation.updatedOrder,
      messages: conversation.messages.map((message) => ({
        id: message.id,
        role: message.role,
        content: message.content,
        createdOrder: message.createdOrder,
        ...(message.attachments ? {
          attachments: message.attachments.map((attachment) => ({ ...attachment })),
        } : {}),
        ...(message.toolActivity ? { toolActivity: { ...message.toolActivity } } : {}),
      })),
    })),
  })),
});

const textBytes = (scopes: readonly MutableScope[]): number => scopes.reduce(
  (scopeTotal, scope) => scopeTotal + scope.conversations.reduce(
    (conversationTotal, conversation) => conversationTotal
      + byteLength(conversation.title)
      + conversation.messages.reduce((messageTotal, message) => (
        messageTotal
          + byteLength(message.content)
          + byteLength(message.toolActivity?.command ?? "")
      ), 0),
    0,
  ),
  0,
);

const retainedImageContent = (scopes: readonly MutableScope[]) => scopes
  .flatMap((scope) => scope.conversations)
  .flatMap((conversation) => conversation.messages)
  .flatMap((message) => (message.attachments ?? [])
    .filter((attachment) => Boolean(attachment.data))
    .map((attachment) => ({ message, attachment })));

const imageBytes = (scopes: readonly MutableScope[]): number => retainedImageContent(scopes)
  .reduce((total, { attachment }) => total + attachment.size, 0);

const freezeState = (state: MutableState): AiConversationState => {
  const scopes = Object.freeze(state.scopes.map((scope) => Object.freeze({
    key: scope.key,
    activeConversationId: scope.activeConversationId,
    createdOrder: scope.createdOrder,
    updatedOrder: scope.updatedOrder,
    conversations: Object.freeze(scope.conversations.map((conversation) => Object.freeze({
      id: conversation.id,
      title: conversation.title,
      titleInitialized: conversation.titleInitialized,
      createdOrder: conversation.createdOrder,
      updatedOrder: conversation.updatedOrder,
      messages: Object.freeze(conversation.messages.map((message) => Object.freeze({
        ...message,
        ...(message.attachments ? {
          attachments: Object.freeze(message.attachments.map((attachment) => Object.freeze({ ...attachment }))),
        } : {}),
        ...(message.toolActivity ? {
          toolActivity: Object.freeze({ ...message.toolActivity }),
        } : {}),
      }))),
    }))),
  })));
  return Object.freeze({
    activeScopeKey: state.activeScopeKey,
    scopes,
    revision: state.revision,
    totalTextBytes: textBytes(state.scopes),
  });
};

const targetKey = (scopeKey: string, conversationId: string): string => (
  `${scopeKey}\u0000${conversationId}`
);

const protectedTargetKeys = (
  targets: readonly AiConversationTarget[] | undefined,
): ReadonlySet<string> => new Set((targets ?? []).map((target) => targetKey(
  assertScopeKey(target.scopeKey),
  assertOpaqueId(target.conversationId),
)));

const activeTargetKey = (state: MutableState): string | null => {
  const scope = state.scopes.find(({ key }) => key === state.activeScopeKey);
  return scope ? targetKey(scope.key, scope.activeConversationId) : null;
};

const removeConversation = (
  state: MutableState,
  scope: MutableScope,
  conversationId: string,
): void => {
  scope.conversations = scope.conversations.filter(({ id }) => id !== conversationId);
  if (scope.conversations.length === 0) {
    state.scopes = state.scopes.filter(({ key }) => key !== scope.key);
    return;
  }
  if (scope.activeConversationId === conversationId) {
    scope.activeConversationId = [...scope.conversations]
      .sort((left, right) => right.updatedOrder - left.updatedOrder)[0].id;
  }
};

const oldestRemovableConversation = (
  state: MutableState,
  protectedTargets: ReadonlySet<string>,
): { scope: MutableScope; conversation: MutableConversation } | null => {
  const globallyActive = activeTargetKey(state);
  const candidates = state.scopes.flatMap((scope) => scope.conversations
    .filter((conversation) => {
      const key = targetKey(scope.key, conversation.id);
      return key !== globallyActive && !protectedTargets.has(key);
    })
    .map((conversation) => ({ scope, conversation })));
  candidates.sort((left, right) => (
    left.conversation.updatedOrder - right.conversation.updatedOrder
    || left.conversation.createdOrder - right.conversation.createdOrder
  ));
  return candidates[0] ?? null;
};

const normalizeToolActivity = (
  activity: AiConversationToolActivity,
): MutableMessage["toolActivity"] => {
  const id = assertOpaqueId(activity.id);
  if (
    activity.name !== "terminal_execute"
    || !activity.command.trim()
    || byteLength(activity.command) > MAX_AI_TOOL_COMMAND_BYTES
    || activity.command.includes("\0")
    || [...activity.command].some((character) => (
      /\p{Cc}/u.test(character) && character !== "\n" && character !== "\t"
    ))
    || !["running", "completed", "timedOut", "failed", "rejected", "cancelled"].includes(activity.status)
    || (activity.errorCode !== undefined && (
      !activity.errorCode
      || byteLength(activity.errorCode) > 128
      || !/^[A-Z0-9_]+$/u.test(activity.errorCode)
    ))
  ) {
    throw new Error("AI_CONVERSATION_TOOL_ACTIVITY_INVALID");
  }
  return {
    id,
    name: "terminal_execute",
    command: activity.command,
    status: activity.status,
    ...(activity.errorCode ? { errorCode: activity.errorCode } : {}),
  };
};

const enforceBounds = (state: MutableState, protectedTargets: ReadonlySet<string>): void => {
  for (const scope of state.scopes) {
    for (const conversation of scope.conversations) {
      if (conversation.messages.length > MAX_AI_MESSAGES_PER_CONVERSATION) {
        conversation.messages.splice(
          0,
          conversation.messages.length - MAX_AI_MESSAGES_PER_CONVERSATION,
        );
      }
    }
    while (scope.conversations.length > MAX_AI_CONVERSATIONS_PER_SCOPE) {
      const removable = [...scope.conversations]
        .filter((conversation) => (
          conversation.id !== scope.activeConversationId
          && !protectedTargets.has(targetKey(scope.key, conversation.id))
        ))
        .sort((left, right) => (
          left.updatedOrder - right.updatedOrder || left.createdOrder - right.createdOrder
        ))[0];
      if (!removable) {
        throw new Error("AI_CONVERSATION_BOUND_INVARIANT");
      }
      removeConversation(state, scope, removable.id);
    }
  }

  while (state.scopes.length > MAX_AI_CONVERSATION_SCOPES) {
    const removable = [...state.scopes]
      .filter((scope) => (
        scope.key !== state.activeScopeKey
        && ![...protectedTargets].some((key) => key.startsWith(`${scope.key}\u0000`))
      ))
      .sort((left, right) => (
        left.updatedOrder - right.updatedOrder || left.createdOrder - right.createdOrder
      ))[0];
    if (!removable) {
      throw new Error("AI_CONVERSATION_BOUND_INVARIANT");
    }
    state.scopes = state.scopes.filter(({ key }) => key !== removable.key);
  }

  // Whole inactive histories are cheaper and less surprising to evict than
  // cutting a currently visible exchange in half.
  while (textBytes(state.scopes) > MAX_AI_CONVERSATION_TOTAL_TEXT_BYTES) {
    const removable = oldestRemovableConversation(state, protectedTargets);
    if (!removable) break;
    removeConversation(state, removable.scope, removable.conversation.id);
  }

  // If active/protected histories alone fill the budget, remove the globally
  // oldest messages. A newly appended response has the newest order, so it is
  // retained ahead of earlier context whenever possible.
  while (textBytes(state.scopes) > MAX_AI_CONVERSATION_TOTAL_TEXT_BYTES) {
    const oldest = state.scopes.flatMap((scope) => scope.conversations.flatMap((conversation) => (
      conversation.messages.length > 0
        ? [{ conversation, message: conversation.messages[0] }]
        : []
    ))).sort((left, right) => left.message.createdOrder - right.message.createdOrder)[0];
    if (!oldest) break;
    oldest.conversation.messages.shift();
  }

  if (textBytes(state.scopes) > MAX_AI_CONVERSATION_TOTAL_TEXT_BYTES) {
    throw new Error("AI_CONVERSATION_BOUND_INVARIANT");
  }

  // Chat Completions is stateless, so retain recent image bodies for follow-up
  // questions. The native contract accepts at most four parts / 10 MiB total;
  // discard the oldest bodies first while keeping safe message metadata visible.
  let retainedImages = retainedImageContent(state.scopes);
  while (
    retainedImages.length > MAX_AI_CONVERSATION_IMAGE_PARTS
    || imageBytes(state.scopes) > MAX_AI_CONVERSATION_IMAGE_BYTES
  ) {
    retainedImages.sort((left, right) => left.message.createdOrder - right.message.createdOrder);
    const oldest = retainedImages.shift();
    if (!oldest) break;
    delete oldest.attachment.data;
    retainedImages = retainedImageContent(state.scopes);
  }
};

const finish = (state: MutableState, protectedTargets: ReadonlySet<string> = new Set()): AiConversationState => {
  enforceBounds(state, protectedTargets);
  return freezeState(state);
};

export const aiConversationScopeKey = (
  scope: AiConversationTerminalScope | null | undefined,
): string => {
  if (!scope) return AI_NO_TERMINAL_SCOPE_KEY;
  assertBoundedOpaqueText(scope.routeId, "ROUTE_ID", MAX_AI_SCOPE_KEY_BYTES);
  if (!Number.isSafeInteger(scope.generation) || scope.generation < 0) {
    throw new Error("AI_CONVERSATION_GENERATION_INVALID");
  }
  const key = `${scope.routeId}:${scope.generation}`;
  return assertScopeKey(key);
};

export const deriveAiConversationTitle = (firstUserMessage: string): string => {
  const normalized = firstUserMessage
    .normalize("NFKC")
    .replace(/[\p{Cc}\p{Cf}\p{Cs}<> &]/gu, (character) => (
      /[\s<> &]/u.test(character) ? " " : ""
    ))
    .replace(/\s+/gu, " ")
    .trim();
  if (!normalized) return DEFAULT_CONVERSATION_TITLE;
  if (byteLength(normalized) <= MAX_AI_CONVERSATION_TITLE_BYTES) return normalized;
  const ellipsis = "…";
  return `${takeUtf8Prefix(
    normalized,
    MAX_AI_CONVERSATION_TITLE_BYTES - byteLength(ellipsis),
  ).trimEnd()}${ellipsis}`;
};

export const createAiConversationState = (): AiConversationState => freezeState({
  activeScopeKey: AI_NO_TERMINAL_SCOPE_KEY,
  scopes: [],
  revision: 0,
});

export const activateAiConversationScope = (
  state: AiConversationState,
  terminalScope: AiConversationTerminalScope | null | undefined,
  options: AiConversationActivationOptions = {},
): AiConversationState => {
  const scopeKey = aiConversationScopeKey(terminalScope);
  const existing = state.scopes.find(({ key }) => key === scopeKey);
  if (existing && state.activeScopeKey === scopeKey) return state;

  const draft = toMutable(state);
  const order = ++draft.revision;
  draft.activeScopeKey = scopeKey;
  const mutableExisting = draft.scopes.find(({ key }) => key === scopeKey);
  if (mutableExisting) {
    mutableExisting.updatedOrder = order;
  } else {
    const conversation = newConversation(options.conversationId ?? makeConversationId(), order);
    draft.scopes.push({
      key: scopeKey,
      activeConversationId: conversation.id,
      conversations: [conversation],
      createdOrder: order,
      updatedOrder: order,
    });
  }
  return finish(draft, protectedTargetKeys(options.protectedTargets));
};

export const createAiConversation = (
  state: AiConversationState,
  scopeKey: string = state.activeScopeKey,
  options: AiConversationCreationOptions = {},
): AiConversationState => {
  assertScopeKey(scopeKey);
  const conversationId = assertOpaqueId(options.conversationId ?? makeConversationId());
  const draft = toMutable(state);
  const existingScope = draft.scopes.find(({ key }) => key === scopeKey);
  if (existingScope?.conversations.some(({ id }) => id === conversationId)) {
    throw new Error("AI_CONVERSATION_ID_DUPLICATE");
  }

  const order = ++draft.revision;
  const conversation = newConversation(conversationId, order);
  draft.activeScopeKey = scopeKey;
  if (existingScope) {
    existingScope.conversations.push(conversation);
    existingScope.activeConversationId = conversationId;
    existingScope.updatedOrder = order;
  } else {
    draft.scopes.push({
      key: scopeKey,
      activeConversationId: conversationId,
      conversations: [conversation],
      createdOrder: order,
      updatedOrder: order,
    });
  }
  return finish(draft, new Set([targetKey(scopeKey, conversationId)]));
};

export const switchAiConversation = (
  state: AiConversationState,
  target: AiConversationTarget,
): AiConversationState => {
  assertScopeKey(target.scopeKey);
  assertOpaqueId(target.conversationId);
  const scope = state.scopes.find(({ key }) => key === target.scopeKey);
  if (!scope?.conversations.some(({ id }) => id === target.conversationId)) return state;
  if (
    state.activeScopeKey === target.scopeKey
    && scope.activeConversationId === target.conversationId
  ) return state;

  const draft = toMutable(state);
  const order = ++draft.revision;
  const mutableScope = draft.scopes.find(({ key }) => key === target.scopeKey);
  if (!mutableScope) return state;
  draft.activeScopeKey = target.scopeKey;
  mutableScope.activeConversationId = target.conversationId;
  mutableScope.updatedOrder = order;
  const conversation = mutableScope.conversations.find(({ id }) => id === target.conversationId);
  if (conversation) conversation.updatedOrder = order;
  return finish(draft, new Set([targetKey(target.scopeKey, target.conversationId)]));
};

export const deleteAiConversation = (
  state: AiConversationState,
  target: AiConversationTarget,
  options: AiConversationCreationOptions = {},
): AiConversationState => {
  assertScopeKey(target.scopeKey);
  assertOpaqueId(target.conversationId);
  const sourceScope = state.scopes.find(({ key }) => key === target.scopeKey);
  if (!sourceScope?.conversations.some(({ id }) => id === target.conversationId)) return state;

  const draft = toMutable(state);
  const order = ++draft.revision;
  const scope = draft.scopes.find(({ key }) => key === target.scopeKey);
  if (!scope) return state;
  scope.conversations = scope.conversations.filter(({ id }) => id !== target.conversationId);

  if (scope.conversations.length === 0) {
    if (draft.activeScopeKey !== target.scopeKey) {
      draft.scopes = draft.scopes.filter(({ key }) => key !== target.scopeKey);
      return finish(draft);
    }
    const replacement = newConversation(options.conversationId ?? makeConversationId(), order);
    scope.conversations = [replacement];
    scope.activeConversationId = replacement.id;
  } else if (scope.activeConversationId === target.conversationId) {
    scope.activeConversationId = [...scope.conversations]
      .sort((left, right) => right.updatedOrder - left.updatedOrder)[0].id;
  }
  scope.updatedOrder = order;
  return finish(draft, new Set([targetKey(scope.key, scope.activeConversationId)]));
};

export const captureActiveAiConversation = (
  state: AiConversationState,
): AiConversationTarget | null => {
  const scope = state.scopes.find(({ key }) => key === state.activeScopeKey);
  if (!scope?.conversations.some(({ id }) => id === scope.activeConversationId)) return null;
  return Object.freeze({
    scopeKey: scope.key,
    conversationId: scope.activeConversationId,
  });
};

export const appendAiConversationMessage = (
  state: AiConversationState,
  capturedTarget: AiConversationTarget,
  input: AiConversationMessageInput,
): AiConversationState => {
  assertScopeKey(capturedTarget.scopeKey);
  assertOpaqueId(capturedTarget.conversationId);
  const sourceScope = state.scopes.find(({ key }) => key === capturedTarget.scopeKey);
  const sourceConversation = sourceScope?.conversations.find(
    ({ id }) => id === capturedTarget.conversationId,
  );
  if (!sourceConversation || sourceConversation.messages.some(({ id }) => id === input.id)) {
    return state;
  }
  assertOpaqueId(input.id);
  if (!["user", "assistant", "system", "error"].includes(input.role)) {
    throw new Error("AI_CONVERSATION_ROLE_INVALID");
  }
  const attachments = input.attachments ?? [];
  if (attachments.length > MAX_AI_IMAGE_ATTACHMENTS_PER_MESSAGE) {
    throw new Error("AI_CONVERSATION_ATTACHMENTS_INVALID");
  }
  if (attachments.length > 0 && input.role !== "user") {
    throw new Error("AI_CONVERSATION_ATTACHMENTS_INVALID");
  }
  if (input.toolActivity && input.role !== "assistant") {
    throw new Error("AI_CONVERSATION_TOOL_ACTIVITY_INVALID");
  }
  const toolActivity = input.toolActivity
    ? normalizeToolActivity(input.toolActivity)
    : undefined;
  const normalizedAttachments = attachments.map((attachment) => {
    const id = assertOpaqueId(attachment.id);
    const name = assertBoundedOpaqueText(
      attachment.name,
      "ATTACHMENT_NAME",
      MAX_AI_ATTACHMENT_NAME_BYTES,
    );
    if (
      !["image/png", "image/jpeg", "image/webp"].includes(attachment.mimeType)
      || !Number.isSafeInteger(attachment.size)
      || attachment.size <= 0
      || attachment.size > MAX_AI_IMAGE_ATTACHMENT_BYTES
      || !attachment.data
      || attachment.data.length !== Math.ceil(attachment.size / 3) * 4
      || !/^[A-Za-z0-9+/]+={0,2}$/u.test(attachment.data)
    ) {
      throw new Error("AI_CONVERSATION_ATTACHMENTS_INVALID");
    }
    return {
      id,
      name,
      mimeType: attachment.mimeType,
      size: attachment.size,
      data: attachment.data,
    };
  });

  const draft = toMutable(state);
  const order = ++draft.revision;
  const scope = draft.scopes.find(({ key }) => key === capturedTarget.scopeKey);
  const conversation = scope?.conversations.find(({ id }) => id === capturedTarget.conversationId);
  if (!scope || !conversation) return state;
  const content = takeUtf8Prefix(input.content, MAX_AI_MESSAGE_BYTES);
  conversation.messages.push({
    id: input.id,
    role: input.role,
    content,
    ...(normalizedAttachments.length > 0 ? { attachments: normalizedAttachments } : {}),
    ...(toolActivity ? { toolActivity } : {}),
    createdOrder: order,
  });
  if (input.role === "user" && !conversation.titleInitialized) {
    conversation.title = deriveAiConversationTitle(content);
    conversation.titleInitialized = true;
  }
  conversation.updatedOrder = order;
  scope.updatedOrder = order;
  return finish(
    draft,
    new Set([targetKey(capturedTarget.scopeKey, capturedTarget.conversationId)]),
  );
};

/** Replace one already-published message without changing its identity/order.
 * Streaming callers use this for every delta and for the authoritative final
 * body, so one assistant turn never expands into one message per chunk. */
export const updateAiConversationMessage = (
  state: AiConversationState,
  capturedTarget: AiConversationTarget,
  messageId: string,
  input: AiConversationMessageUpdate,
): AiConversationState => {
  assertScopeKey(capturedTarget.scopeKey);
  assertOpaqueId(capturedTarget.conversationId);
  assertOpaqueId(messageId);
  const sourceScope = state.scopes.find(({ key }) => key === capturedTarget.scopeKey);
  const sourceConversation = sourceScope?.conversations.find(
    ({ id }) => id === capturedTarget.conversationId,
  );
  const sourceMessage = sourceConversation?.messages.find(({ id }) => id === messageId);
  if (!sourceMessage) return state;
  const role = input.role ?? sourceMessage.role;
  if (!["user", "assistant", "system", "error"].includes(role)) {
    throw new Error("AI_CONVERSATION_ROLE_INVALID");
  }
  const content = takeUtf8Prefix(input.content ?? sourceMessage.content, MAX_AI_MESSAGE_BYTES);
  const toolActivity = input.toolActivity
    ? normalizeToolActivity(input.toolActivity)
    : sourceMessage.toolActivity;
  if (toolActivity && role !== "assistant") {
    throw new Error("AI_CONVERSATION_TOOL_ACTIVITY_INVALID");
  }
  if (
    sourceMessage.role === role
    && sourceMessage.content === content
    && JSON.stringify(sourceMessage.toolActivity) === JSON.stringify(toolActivity)
  ) return state;

  const draft = toMutable(state);
  const order = ++draft.revision;
  const scope = draft.scopes.find(({ key }) => key === capturedTarget.scopeKey);
  const conversation = scope?.conversations.find(({ id }) => id === capturedTarget.conversationId);
  const message = conversation?.messages.find(({ id }) => id === messageId);
  if (!scope || !conversation || !message) return state;
  message.role = role;
  message.content = content;
  if (toolActivity) {
    message.toolActivity = { ...toolActivity };
  } else {
    delete message.toolActivity;
  }
  conversation.updatedOrder = order;
  scope.updatedOrder = order;
  return finish(
    draft,
    new Set([targetKey(capturedTarget.scopeKey, capturedTarget.conversationId)]),
  );
};

/** Remove an unfilled streaming placeholder after an explicit cancellation. */
export const deleteAiConversationMessage = (
  state: AiConversationState,
  capturedTarget: AiConversationTarget,
  messageId: string,
): AiConversationState => {
  assertScopeKey(capturedTarget.scopeKey);
  assertOpaqueId(capturedTarget.conversationId);
  assertOpaqueId(messageId);
  const sourceScope = state.scopes.find(({ key }) => key === capturedTarget.scopeKey);
  const sourceConversation = sourceScope?.conversations.find(
    ({ id }) => id === capturedTarget.conversationId,
  );
  if (!sourceConversation?.messages.some(({ id }) => id === messageId)) return state;

  const draft = toMutable(state);
  const order = ++draft.revision;
  const scope = draft.scopes.find(({ key }) => key === capturedTarget.scopeKey);
  const conversation = scope?.conversations.find(({ id }) => id === capturedTarget.conversationId);
  if (!scope || !conversation) return state;
  conversation.messages = conversation.messages.filter(({ id }) => id !== messageId);
  conversation.updatedOrder = order;
  scope.updatedOrder = order;
  return finish(
    draft,
    new Set([targetKey(capturedTarget.scopeKey, capturedTarget.conversationId)]),
  );
};

export const getAiConversationScope = (
  state: AiConversationState,
  scopeKey: string = state.activeScopeKey,
): AiConversationScopeState | null => state.scopes.find(({ key }) => key === scopeKey) ?? null;

export const getAiConversation = (
  state: AiConversationState,
  target: AiConversationTarget | null = captureActiveAiConversation(state),
): AiConversation | null => {
  if (!target) return null;
  return state.scopes.find(({ key }) => key === target.scopeKey)
    ?.conversations.find(({ id }) => id === target.conversationId) ?? null;
};
