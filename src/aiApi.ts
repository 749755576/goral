import { Channel, invoke, isTauri } from "@tauri-apps/api/core";

export const AI_COMMANDS = Object.freeze({
  startTurn: "start_ai_agent_turn",
  authorizeTool: "authorize_ai_agent_tool",
  continueTurn: "continue_ai_agent_turn",
  cancelTurn: "cancel_ai_agent_turn",
  stream: "stream_ai_chat",
  complete: "complete_ai_chat",
  cancel: "cancel_ai_chat",
  hasSavedKey: "has_saved_ai_api_key",
  saveKey: "save_ai_api_key",
  deleteKey: "delete_ai_api_key",
  runLocalAgent: "run_local_ai_agent",
  cancelLocalAgent: "cancel_local_ai_agent",
} as const);

export type NativeAiChatRole = "system" | "user" | "assistant";

export type NativeAiChatContentPart = Readonly<{
  type: "image";
  mimeType: "image/png" | "image/jpeg" | "image/webp";
  /** Canonical standard Base64 only. Native paths, URLs, and data-URL prefixes are not accepted. */
  data: string;
}>;

export type NativeAiChatMessage = Readonly<{
  role: NativeAiChatRole;
  content: string;
  contentParts?: ReadonlyArray<NativeAiChatContentPart>;
}>;

export type NativeLocalAiAgentId = "codex" | "claude" | "opencode";

export type NativeAiChatRequest = Readonly<{
  providerProfileId: string;
  messages: ReadonlyArray<NativeAiChatMessage>;
  /** Omitted when extended reasoning is disabled or unsupported. */
  reasoningEffort?: NativeAiReasoningEffort;
}>;

export type NativeAiTerminalScope = Readonly<{
  routeId: string;
  generation: number;
  protocol: string;
}>;

export type NativeAiTerminalToolCall = Readonly<{
  id: string;
  command: string;
  scope: NativeAiTerminalScope;
}>;

export type NativeAiAgentTurnStep = Readonly<{
  kind: "completed";
  content: string;
}> | Readonly<{
  kind: "toolCall";
  turnId: string;
  call: NativeAiTerminalToolCall;
  approvalRequired: boolean;
  /** Optional bounded assistant text emitted alongside the native tool call. */
  content?: string;
}>;

export type NativeAiReasoningEffort = "low" | "medium" | "high";

export type NativeAiAgentStartRequest = NativeAiChatRequest & Readonly<{
  terminalScope: NativeAiTerminalScope | null;
  /** Omitted when extended reasoning is disabled. */
  reasoningEffort?: NativeAiReasoningEffort;
}>;

export type NativeAiTerminalToolResult = Readonly<{
  output: string;
  timedOut: boolean;
  errorCode?: string;
}>;

type NativeAiChatResponse = Readonly<{ content: string }>;

export type NativeAiChatStreamEvent = Readonly<{
  kind: "delta";
  content: string;
}> | Readonly<{
  kind: "done";
}>;

export type AiChatDeltaHandler = (delta: string) => void;

export type AiChatEventChannel = {
  onmessage: (event: NativeAiChatStreamEvent) => void;
};

export type AiCommandInvoker = <T>(
  command: string,
  args?: Record<string, unknown>,
) => Promise<T>;

const requestId = (): string => `ai-${crypto.randomUUID()}`;

const createAiChatEventChannel = (): AiChatEventChannel => (
  isTauri()
    ? new Channel<NativeAiChatStreamEvent>()
    : { onmessage: () => undefined }
);

/**
 * Invoke the native bounded provider transport and bind AbortSignal to its
 * exact request ID. Neither the request nor its API key is persisted here.
 */
export const createNativeAiChatTransport = (
  invokeCommand: AiCommandInvoker = invoke,
  createEventChannel: () => AiChatEventChannel = createAiChatEventChannel,
) => async (
  request: NativeAiChatRequest,
  signal: AbortSignal,
  onDelta?: AiChatDeltaHandler,
): Promise<string> => {
  if (signal.aborted) throw new DOMException("AI request aborted", "AbortError");
  const id = requestId();
  let settled = false;
  let cancelSent = false;
  let acceptingEvents = true;
  let sawDone = false;
  let streamedContent = "";
  let streamError: Error | null = null;
  const onEvent = createEventChannel();
  const cancel = () => {
    acceptingEvents = false;
    onEvent.onmessage = () => undefined;
    if (settled || cancelSent) return;
    cancelSent = true;
    void invokeCommand<boolean>(AI_COMMANDS.cancel, { requestId: id }).catch(() => undefined);
  };
  onEvent.onmessage = (event) => {
    if (!acceptingEvents || signal.aborted || sawDone || streamError) return;
    if (event?.kind === "done") {
      sawDone = true;
      return;
    }
    if (event?.kind !== "delta" || typeof event.content !== "string") {
      streamError = new Error("AI_STREAM_EVENT_INVALID");
      cancel();
      return;
    }
    if (!event.content) return;
    streamedContent += event.content;
    onDelta?.(event.content);
  };
  signal.addEventListener("abort", cancel, { once: true });
  try {
    const response = await invokeCommand<NativeAiChatResponse>(AI_COMMANDS.stream, {
      request: {
        requestId: id,
        providerProfileId: request.providerProfileId,
        messages: request.messages,
        ...(request.reasoningEffort ? { reasoningEffort: request.reasoningEffort } : {}),
      },
      onEvent,
    });
    if (streamError) throw streamError;
    if (signal.aborted) throw new DOMException("AI request aborted", "AbortError");
    if (!response || typeof response.content !== "string") {
      throw new Error("AI_STREAM_RESPONSE_INVALID");
    }
    // The native final body is authoritative and repairs a missed/out-of-sync
    // renderer delta. A non-empty streamed body is still a safe fallback for
    // older native builds that returned an empty final body.
    return response.content || streamedContent;
  } finally {
    settled = true;
    acceptingEvents = false;
    onEvent.onmessage = () => undefined;
    signal.removeEventListener("abort", cancel);
  }
};

export const completeNativeAiChat = createNativeAiChatTransport();

/**
 * Run one locally installed AI agent without a provider profile or API key.
 * The request ID owns both its stream and cancellation command, and the
 * channel is detached before the promise settles so late native events cannot
 * mutate a later renderer conversation.
 */
export const createNativeLocalAiAgentTransport = (
  invokeCommand: AiCommandInvoker = invoke,
  createEventChannel: () => AiChatEventChannel = createAiChatEventChannel,
) => async (
  agentId: NativeLocalAiAgentId,
  messages: ReadonlyArray<NativeAiChatMessage>,
  signal: AbortSignal,
  onDelta?: AiChatDeltaHandler,
): Promise<string> => {
  if (!isTauri() && invokeCommand === invoke) throw new Error("AI_CLIENT_UNAVAILABLE");
  if (signal.aborted) throw new DOMException("AI request aborted", "AbortError");
  const id = requestId();
  let settled = false;
  let cancelSent = false;
  let acceptingEvents = true;
  let sawDone = false;
  let streamedContent = "";
  let streamError: Error | null = null;
  const onEvent = createEventChannel();
  const cancel = () => {
    acceptingEvents = false;
    onEvent.onmessage = () => undefined;
    if (settled || cancelSent) return;
    cancelSent = true;
    void invokeCommand<boolean>(AI_COMMANDS.cancelLocalAgent, { requestId: id }).catch(() => undefined);
  };
  onEvent.onmessage = (event) => {
    if (!acceptingEvents || signal.aborted || sawDone || streamError) return;
    if (event?.kind === "done") {
      sawDone = true;
      return;
    }
    if (event?.kind !== "delta" || typeof event.content !== "string") {
      streamError = new Error("AI_STREAM_EVENT_INVALID");
      cancel();
      return;
    }
    if (!event.content) return;
    streamedContent += event.content;
    onDelta?.(event.content);
  };
  signal.addEventListener("abort", cancel, { once: true });
  try {
    const response = await invokeCommand<NativeAiChatResponse>(AI_COMMANDS.runLocalAgent, {
      request: {
        requestId: id,
        agentId,
        messages,
      },
      onEvent,
    });
    if (streamError) throw streamError;
    if (signal.aborted) throw new DOMException("AI request aborted", "AbortError");
    if (!response || typeof response.content !== "string") {
      throw new Error("AI_STREAM_RESPONSE_INVALID");
    }
    return response.content || streamedContent;
  } finally {
    settled = true;
    acceptingEvents = false;
    onEvent.onmessage = () => undefined;
    signal.removeEventListener("abort", cancel);
  }
};

export const runNativeLocalAiAgent = createNativeLocalAiAgentTransport();

const invokeCancelableAgentStep = async (
  turnId: string,
  command: typeof AI_COMMANDS.startTurn | typeof AI_COMMANDS.continueTurn,
  args: Record<string, unknown>,
  signal: AbortSignal,
  invokeCommand: AiCommandInvoker,
): Promise<NativeAiAgentTurnStep> => {
  if (signal.aborted) throw new DOMException("AI turn aborted", "AbortError");
  let settled = false;
  const cancel = () => {
    if (settled) return;
    void invokeCommand<boolean>(AI_COMMANDS.cancelTurn, { turnId }).catch(() => undefined);
  };
  signal.addEventListener("abort", cancel, { once: true });
  try {
    const step = await invokeCommand<NativeAiAgentTurnStep>(command, args);
    if (signal.aborted) throw new DOMException("AI turn aborted", "AbortError");
    return step;
  } finally {
    settled = true;
    signal.removeEventListener("abort", cancel);
  }
};

export const createNativeAiAgentTransport = (
  invokeCommand: AiCommandInvoker = invoke,
) => ({
  start: async (
    request: NativeAiAgentStartRequest,
    signal: AbortSignal,
  ): Promise<NativeAiAgentTurnStep> => {
    const turnId = requestId();
    return invokeCancelableAgentStep(turnId, AI_COMMANDS.startTurn, {
      request: {
        turnId,
        providerProfileId: request.providerProfileId,
        messages: request.messages,
        terminalScope: request.terminalScope,
        ...(request.reasoningEffort ? { reasoningEffort: request.reasoningEffort } : {}),
      },
    }, signal, invokeCommand);
  },
  continue: async (
    turnId: string,
    toolCallId: string,
    terminalScope: NativeAiTerminalScope,
    result: NativeAiTerminalToolResult,
    signal: AbortSignal,
  ): Promise<NativeAiAgentTurnStep> => invokeCancelableAgentStep(
    turnId,
    AI_COMMANDS.continueTurn,
    {
      request: { turnId, toolCallId, terminalScope, result },
    },
    signal,
    invokeCommand,
  ),
  authorize: async (
    turnId: string,
    toolCallId: string,
    terminalScope: NativeAiTerminalScope,
    userApproved: boolean,
    signal: AbortSignal,
  ): Promise<boolean> => {
    if (signal.aborted) throw new DOMException("AI turn aborted", "AbortError");
    const authorized = await invokeCommand<boolean>(AI_COMMANDS.authorizeTool, {
      request: { turnId, toolCallId, terminalScope, userApproved },
    });
    if (signal.aborted) throw new DOMException("AI turn aborted", "AbortError");
    return authorized;
  },
  cancel: async (turnId: string): Promise<boolean> => invokeCommand<boolean>(
    AI_COMMANDS.cancelTurn,
    { turnId },
  ),
});

export const nativeAiAgentTransport = createNativeAiAgentTransport();

const safeProviderProfileId = (providerProfileId: string): string => {
  if (!/^[a-z0-9][a-z0-9._-]*$/u.test(providerProfileId) || new TextEncoder().encode(providerProfileId).byteLength > 128) {
    throw new Error("AI_PROVIDER_INVALID");
  }
  return providerProfileId;
};

/** Only a boolean presence hint crosses back to the renderer; the key never does. */
export const hasSavedAiApiKey = async (
  providerProfileId: string,
  invokeCommand: AiCommandInvoker = invoke,
): Promise<boolean> => {
  if (!isTauri() && invokeCommand === invoke) return false;
  return invokeCommand<boolean>(AI_COMMANDS.hasSavedKey, {
    providerProfileId: safeProviderProfileId(providerProfileId),
  });
};

/** Called only after an explicit user action. The native side writes the keyring. */
export const saveAiApiKey = async (
  providerProfileId: string,
  apiKey: string,
  invokeCommand: AiCommandInvoker = invoke,
): Promise<boolean> => invokeCommand<boolean>(AI_COMMANDS.saveKey, {
  request: { providerProfileId: safeProviderProfileId(providerProfileId), apiKey: apiKey.trim() },
});

export const deleteSavedAiApiKey = async (
  providerProfileId: string,
  invokeCommand: AiCommandInvoker = invoke,
): Promise<boolean> => invokeCommand<boolean>(AI_COMMANDS.deleteKey, {
  providerProfileId: safeProviderProfileId(providerProfileId),
});
