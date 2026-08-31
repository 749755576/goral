import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  allowsMissingAiApiKey,
  buildAiMessages,
  createLocalAiAgentCompletion,
  createOpenAiCompatibleCompletion,
  normalizeAiEndpoint,
} from "../../src/aiCompletion.ts";
import {
  AI_COMMANDS,
  createNativeAiAgentTransport,
  createNativeAiChatTransport,
  createNativeLocalAiAgentTransport,
  deleteSavedAiApiKey,
  hasSavedAiApiKey,
  saveAiApiKey,
  type NativeAiChatMessage,
} from "../../src/aiApi.ts";
import { createTranslator, localizeAiError } from "../../src/i18n.ts";

const workspaceUrl = new URL("../../src/aiWorkspace.tsx", import.meta.url);
const composerUrl = new URL("../../src/ai/AiComposer.tsx", import.meta.url);
const markdownUrl = new URL("../../src/AiMarkdown.tsx", import.meta.url);

test("AI endpoint normalization keeps only HTTP(S) chat-completions URLs", () => {
  assert.equal(
    normalizeAiEndpoint("https://api.example.test/v1/"),
    "https://api.example.test/v1/chat/completions",
  );
  assert.equal(
    normalizeAiEndpoint("http://localhost:8080/v1/chat/completions"),
    "http://localhost:8080/v1/chat/completions",
  );
  assert.throws(() => normalizeAiEndpoint("file:///secret"), /AI_URL_PROTOCOL/);
  assert.throws(() => normalizeAiEndpoint("https://user:pass@example.test/v1"), /AI_URL_CREDENTIALS/);
  assert.equal(
    normalizeAiEndpoint("http://api.example.test/v1"),
    "http://api.example.test/v1/chat/completions",
  );
  assert.equal(allowsMissingAiApiKey(normalizeAiEndpoint("http://api.example.test/v1")), false);
  assert.equal(allowsMissingAiApiKey(normalizeAiEndpoint("http://127.0.0.1:11434/v1")), true);
  assert.equal(allowsMissingAiApiKey(normalizeAiEndpoint("http://[::1]:11434/v1")), true);
  assert.equal(allowsMissingAiApiKey(normalizeAiEndpoint("https://localhost/v1")), false);
});

test("AI completion forwards only the selected provider profile and bounded messages", async () => {
  const forwarded: Array<{
    providerProfileId: string;
    messages: ReadonlyArray<{ role: "user" | "assistant" | "system"; content: string }>;
    reasoningEffort?: "low" | "medium" | "high";
  }> = [];
  const receivedDeltas: string[] = [];
  const complete = createOpenAiCompatibleCompletion(async (request, _signal, onDelta) => {
    forwarded.push(request);
    onDelta?.("local ");
    onDelta?.("answer");
    return "local answer";
  });
  const signal = new AbortController().signal;
  const request = {
    providerProfileId: "local-profile",
    assistantMode: "terminal" as const,
    commandPermissionMode: "confirm" as const,
    locale: "zh-CN" as const,
    context: {},
    messages: [{ role: "user" as const, content: "hello" }],
    reasoningEffort: "high" as const,
  };

  assert.equal(await complete(request, signal, (delta) => receivedDeltas.push(delta)), "local answer");
  assert.deepEqual(receivedDeltas, ["local ", "answer"]);
  assert.equal(forwarded[0]?.providerProfileId, "local-profile");
  assert.equal(forwarded[0]?.reasoningEffort, "high");
  assert.deepEqual(forwarded[0]?.messages.map(({ role, content }) => ({ role, content })), [
    { role: "system", content: forwarded[0]?.messages[0]?.content ?? "" },
    { role: "user", content: "hello" },
  ]);
  assert.equal("baseUrl" in (forwarded[0] ?? {}), false);
  assert.equal("apiKey" in (forwarded[0] ?? {}), false);
  assert.equal("model" in (forwarded[0] ?? {}), false);
  assert.equal("useStoredKey" in (forwarded[0] ?? {}), false);
});

test("AI completion preserves bounded image content parts only on user messages", async () => {
  let forwarded: Readonly<{
    providerProfileId: string;
    messages: ReadonlyArray<NativeAiChatMessage>;
  }> | undefined;
  const complete = createOpenAiCompatibleCompletion(async (request) => {
    forwarded = request;
    return "vision answer";
  });
  await complete({
    providerProfileId: "vision-profile",
    assistantMode: "explain",
    commandPermissionMode: "observer",
    locale: "zh-CN",
    context: {},
    messages: [{
      role: "user",
      content: "请分析图片",
      contentParts: [{
        type: "image",
        mimeType: "image/png",
        data: "iVBORw0KGgo=",
      }],
    }],
  }, new AbortController().signal);

  const userMessage = forwarded?.messages.find(({ role }) => role === "user");
  assert.deepEqual(userMessage?.contentParts, [{
    type: "image",
    mimeType: "image/png",
    data: "iVBORw0KGgo=",
  }]);
  assert.equal(forwarded?.messages[0]?.contentParts, undefined);
});

test("AI messages bound terminal context and drop unsupported renderer-only roles", () => {
  const messages = buildAiMessages({
    providerProfileId: "openai-compatible",
    assistantMode: "terminal",
    commandPermissionMode: "confirm",
    locale: "zh-CN",
    context: { selectedText: "selected", recentOutput: "recent" },
    messages: [
      { role: "user", content: "hello" },
      { role: "error", content: "must not be sent" },
      { role: "assistant", content: "answer" },
    ],
  });
  assert.equal(messages.length, 4);
  assert.doesNotMatch(messages[0].content, /selected|recent/u);
  assert.match(messages[0].content, /不可信数据/u);
  assert.equal(messages[1].role, "user");
  assert.match(messages[1].content, /selected/u);
  assert.match(messages[1].content, /recent/u);
  assert.deepEqual(messages.slice(2), [
    { role: "user", content: "hello" },
    { role: "assistant", content: "answer" },
  ]);
  assert.doesNotMatch(JSON.stringify(messages), /secret/u);
});

test("AI messages always identify the captured terminal without attaching output implicitly", () => {
  const messages = buildAiMessages({
    providerProfileId: "openai-compatible",
    assistantMode: "terminal",
    commandPermissionMode: "observer",
    locale: "en-US",
    context: { terminalLabel: "production-shell", terminalProtocol: "ssh" },
    messages: [{ role: "user", content: "What shell is this?" }],
  });

  assert.doesNotMatch(messages[0].content, /production-shell/u);
  assert.match(messages[0].content, /separate user-role message/u);
  assert.equal(messages[1].role, "user");
  assert.match(messages[1].content, /Current terminal target: production-shell \(ssh\)/u);
  assert.doesNotMatch(messages[1].content, /Terminal selection explicitly attached/u);
  assert.doesNotMatch(messages[1].content, /Recent terminal output explicitly attached/u);
});

test("assistant modes are explicit and each mode is embedded in the system prompt", () => {
  const build = (assistantMode: "terminal" | "diagnose" | "explain") => buildAiMessages({
    providerProfileId: "openai-compatible",
    assistantMode,
    commandPermissionMode: "confirm",
    locale: "en-US",
    context: {},
    terminalScope: {
      routeId: "terminal-1",
      generation: 7,
      protocol: "ssh",
      label: "production-shell",
      connected: true,
      commandExecutionSupported: true,
    },
    messages: [{ role: "user", content: "help" }],
  });

  const terminal = build("terminal");
  const diagnose = build("diagnose");
  const explain = build("explain");
  assert.match(terminal[0].content, /Terminal-agent mode is active/u);
  assert.match(terminal[0].content, /call terminal_execute/u);
  assert.match(diagnose[0].content, /Diagnostic mode is active/u);
  assert.match(diagnose[0].content, /call terminal_execute/u);
  assert.match(explain[0].content, /Explanation mode is active/u);
  assert.match(explain[0].content, /do not call terminal_execute/u);
  assert.match(explain[0].content, /No executable terminal tool target is available/u);
});

test("AI completion uses the native command and binds cancellation to one opaque request ID", async () => {
  const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
  let rejectCompletion: ((reason: Error) => void) | undefined;
  const transport = createNativeAiChatTransport(async <T>(command: string, args?: Record<string, unknown>) => {
    calls.push({ command, args });
    if (command === AI_COMMANDS.cancel) return true as T;
    return await new Promise<T>((_resolve, reject) => {
      rejectCompletion = reject;
    });
  });
  const controller = new AbortController();
  const pending = transport({
    providerProfileId: "primary-profile",
    messages: [{ role: "user", content: "hello" }],
    reasoningEffort: "medium",
  }, controller.signal);

  await Promise.resolve();
  controller.abort();
  rejectCompletion?.(new Error("AI_REQUEST_CANCELED"));
  await assert.rejects(pending, /AI_REQUEST_CANCELED/);
  assert.equal(calls[0]?.command, AI_COMMANDS.stream);
  assert.equal(calls[1]?.command, AI_COMMANDS.cancel);
  const completeRequest = calls[0]?.args?.request as { requestId?: string; reasoningEffort?: string };
  assert.match(completeRequest.requestId ?? "", /^ai-[0-9a-f-]{36}$/u);
  assert.equal(completeRequest.reasoningEffort, "medium");
  assert.deepEqual(Object.keys(completeRequest).sort(), [
    "messages",
    "providerProfileId",
    "reasoningEffort",
    "requestId",
  ]);
  assert.equal(typeof (calls[0]?.args?.onEvent as { onmessage?: unknown })?.onmessage, "function");
  assert.deepEqual(calls[1]?.args, { requestId: completeRequest.requestId });
});

test("native AI streaming forwards ordered deltas and keeps the final response authoritative", async () => {
  const deltas: string[] = [];
  const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
  const transport = createNativeAiChatTransport(async <T>(command: string, args?: Record<string, unknown>) => {
    calls.push({ command, args });
    const channel = args?.onEvent as {
      onmessage: (event: { kind: "delta"; content: string } | { kind: "done" }) => void;
    };
    channel.onmessage({ kind: "delta", content: "draft " });
    channel.onmessage({ kind: "delta", content: "body" });
    channel.onmessage({ kind: "done" });
    channel.onmessage({ kind: "delta", content: " ignored" });
    return { content: "authoritative final" } as T;
  });

  const content = await transport({
    providerProfileId: "primary-profile",
    messages: [{ role: "user", content: "hello" }],
  }, new AbortController().signal, (delta) => deltas.push(delta));

  assert.equal(content, "authoritative final");
  assert.deepEqual(deltas, ["draft ", "body"]);
  assert.equal(calls[0]?.command, AI_COMMANDS.stream);
  assert.deepEqual(Object.keys(calls[0]?.args ?? {}).sort(), ["onEvent", "request"]);
});

test("native AI streaming falls back to accumulated deltas when an older final body is empty", async () => {
  const transport = createNativeAiChatTransport(async <T>(_command: string, args?: Record<string, unknown>) => {
    const channel = args?.onEvent as {
      onmessage: (event: { kind: "delta"; content: string } | { kind: "done" }) => void;
    };
    channel.onmessage({ kind: "delta", content: "fallback" });
    channel.onmessage({ kind: "done" });
    return { content: "" } as T;
  });

  assert.equal(await transport({
    providerProfileId: "primary-profile",
    messages: [{ role: "user", content: "hello" }],
  }, new AbortController().signal), "fallback");
});

test("local Codex transport streams without provider or API-key fields and rejects late events", async () => {
  const deltas: string[] = [];
  const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
  let channel: { onmessage: (event: { kind: "delta"; content: string } | { kind: "done" }) => void } | null = null;
  const transport = createNativeLocalAiAgentTransport(async <T>(command: string, args?: Record<string, unknown>) => {
    calls.push({ command, args });
    channel = args?.onEvent as typeof channel;
    channel?.onmessage({ kind: "delta", content: "本机" });
    channel?.onmessage({ kind: "delta", content: "回答" });
    channel?.onmessage({ kind: "done" });
    return { content: "本机回答" } as T;
  });

  assert.equal(await transport(
    "codex",
    [{ role: "user", content: "你好" }],
    new AbortController().signal,
    (delta) => deltas.push(delta),
  ), "本机回答");
  channel?.onmessage({ kind: "delta", content: "迟到" });

  assert.deepEqual(deltas, ["本机", "回答"]);
  assert.equal(calls[0]?.command, AI_COMMANDS.runLocalAgent);
  const request = calls[0]?.args?.request as Record<string, unknown>;
  assert.deepEqual(Object.keys(request).sort(), ["agentId", "messages", "requestId"]);
  assert.equal(request.agentId, "codex");
  assert.equal("providerProfileId" in request, false);
  assert.equal("apiKey" in request, false);
});

test("local Codex cancellation uses the exact request ID and detaches the stream", async () => {
  const deltas: string[] = [];
  const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
  let resolveRun: ((value: { content: string }) => void) | null = null;
  let channel: { onmessage: (event: { kind: "delta"; content: string } | { kind: "done" }) => void } | null = null;
  const transport = createNativeLocalAiAgentTransport(async <T>(command: string, args?: Record<string, unknown>) => {
    calls.push({ command, args });
    if (command === AI_COMMANDS.cancelLocalAgent) return true as T;
    channel = args?.onEvent as typeof channel;
    return new Promise<{ content: string }>((resolve) => {
      resolveRun = resolve;
    }) as Promise<T>;
  });
  const controller = new AbortController();
  const pending = transport(
    "codex",
    [{ role: "user", content: "hello" }],
    controller.signal,
    (delta) => deltas.push(delta),
  );

  await Promise.resolve();
  const requestId = (calls[0]?.args?.request as { requestId: string }).requestId;
  controller.abort();
  channel?.onmessage({ kind: "delta", content: "late" });
  resolveRun?.({ content: "late final" });
  await assert.rejects(pending, /aborted/u);
  assert.deepEqual(deltas, []);
  assert.equal(calls[1]?.command, AI_COMMANDS.cancelLocalAgent);
  assert.deepEqual(calls[1]?.args, { requestId });
});

test("local Codex completion always builds an observer-only bounded prompt", async () => {
  const forwarded: Array<ReadonlyArray<{ role: "system" | "user" | "assistant"; content: string }>> = [];
  const complete = createLocalAiAgentCompletion(async (_agentId, messages) => {
    forwarded.push(messages);
    return "完成";
  });
  const answer = await complete("codex", {
    providerProfileId: "must-not-be-forwarded",
    assistantMode: "terminal",
    commandPermissionMode: "auto",
    locale: "zh-CN",
    messages: [{ role: "user", content: "看看这个问题" }],
    context: {},
  }, new AbortController().signal);

  assert.equal(answer, "完成");
  assert.match(forwarded[0]?.[0]?.content ?? "", /observer 模式/u);
  assert.doesNotMatch(JSON.stringify(forwarded), /must-not-be-forwarded/u);
});

test("native agent transport preserves one turn across tool result continuation", async () => {
  const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
  const invoke = async <T>(command: string, args?: Record<string, unknown>): Promise<T> => {
    calls.push({ command, args });
    if (command === AI_COMMANDS.startTurn) {
      const request = args?.request as { turnId: string };
      return {
        kind: "toolCall",
        turnId: request.turnId,
        call: {
          id: "call-1",
          command: "pwd",
          scope: { routeId: "terminal-1", generation: 7, protocol: "ssh" },
        },
        approvalRequired: false,
        content: "I will inspect the active directory first.",
      } as T;
    }
    if (command === AI_COMMANDS.continueTurn) {
      return { kind: "completed", content: "done" } as T;
    }
    return true as T;
  };
  const transport = createNativeAiAgentTransport(invoke);
  const signal = new AbortController().signal;
  const first = await transport.start({
    providerProfileId: "local-profile",
    messages: [{ role: "user", content: "where am I" }],
    terminalScope: { routeId: "terminal-1", generation: 7, protocol: "ssh" },
    reasoningEffort: "high",
  }, signal);
  assert.equal(first.kind, "toolCall");
  if (first.kind !== "toolCall") return;
  assert.equal(first.content, "I will inspect the active directory first.");
  assert.equal(await transport.authorize(
    first.turnId,
    first.call.id,
    first.call.scope,
    false,
    signal,
  ), true);
  const final = await transport.continue(
    first.turnId,
    first.call.id,
    first.call.scope,
    { output: "/srv/project", timedOut: false },
    signal,
  );
  assert.deepEqual(final, { kind: "completed", content: "done" });
  assert.deepEqual(calls.map(({ command }) => command), [
    AI_COMMANDS.startTurn,
    AI_COMMANDS.authorizeTool,
    AI_COMMANDS.continueTurn,
  ]);
  assert.equal("permissionMode" in ((calls[0]?.args?.request ?? {}) as object), false);
  assert.equal(
    (calls[0]?.args?.request as { reasoningEffort?: string }).reasoningEffort,
    "high",
  );
  assert.deepEqual(calls[1]?.args?.request, {
    turnId: first.turnId,
    toolCallId: first.call.id,
    terminalScope: first.call.scope,
    userApproved: false,
  });
  assert.equal((calls[2]?.args?.request as { turnId: string }).turnId, first.turnId);
});

test("AI command permissions keep observer, confirm, and auto as distinct policies", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  assert.match(source, /extractAiCommandProposals\(message\.content\)/u);
  assert.match(source, /const approval = stageAiCommandApproval\(proposal, terminalScope\)/u);
  assert.match(source, /effectivePermissionMode === "observer"/u);
  assert.match(source, /effectivePermissionMode === "auto"[\s\S]*?dispatchCommand\(approval\)/u);
  assert.match(source, /else \{\s*setPendingCommand\(approval\)/u);
  assert.match(source, /const dispatchCommand[\s\S]*?confirmAiCommandApproval\(approval, sendApprovedCommand\)/u);
  assert.match(source, /role="dialog"[\s\S]*?pendingCommand\.proposal\.command/u);
  assert.match(source, /onClick=\{\(\) => void approveCommand\(\)\}/u);
  assert.match(source, /toolStep\.approvalRequired[\s\S]*?setPendingAgentApproval/u);
  assert.match(source, /expiresAt: Date\.now\(\) \+ AI_AGENT_APPROVAL_TTL_MS/u);
  assert.match(source, /window\.setTimeout\([\s\S]*?cancelActiveAgentTurn\(\);[\s\S]*?pending\.controller\.abort\(\);[\s\S]*?setBusyTarget\(null\)/u);
  assert.match(source, /nativeAiAgentTransport\.authorize\([\s\S]*?executeAndCaptureAiTerminalTool/u);
  assert.match(source, /toolStep\.call\.scope,\s*false,\s*controller\.signal/u);
  assert.match(source, /pending\.step\.call\.scope,\s*true,\s*pending\.controller\.signal/u);
  assert.match(source, /executeAndCaptureAiTerminalTool\([\s\S]*?nativeAiAgentTransport\.continue/u);
  assert.match(source, /data-ai-tool-call="terminal_execute"/u);
  assert.match(createTranslator("en-US")("ai.stopped"), /already sent may still be running/u);
  assert.match(createTranslator("zh-CN")("ai.stopped"), /已经发送的终端命令可能仍在运行/u);
});

test("AI permission changes serialize persistence, roll back failures, and lock conflicting controls", async () => {
  const [source, composer] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(composerUrl, "utf8"),
  ]);
  assert.match(source, /const \[selectedPermissionMode, setSelectedPermissionMode\] = useState\(commandPermissionMode\)/u);
  assert.match(source, /const \[permissionSaving, setPermissionSaving\] = useState\(false\)/u);
  assert.match(source, /permissionSaveInFlightRef = useRef<Promise<boolean> \| null>\(null\)/u);
  assert.match(source, /if \(permissionSaveInFlightRef\.current\) return permissionSaveInFlightRef\.current/u);
  assert.match(source, /const previousMode = persistedPermissionModeRef\.current[\s\S]*?setSelectedPermissionMode\(mode\)[\s\S]*?onCommandPermissionModeChange\(mode\)/u);
  assert.match(source, /\.catch\(\(\) => \{[\s\S]*?setSelectedPermissionMode\(previousMode\)[\s\S]*?ai\.settingsApplyFailed/u);
  assert.match(source, /if \([\s\S]{0,220}?permissionSaveInFlightRef\.current[\s\S]{0,120}?pendingProviderSelectionRef\.current[\s\S]{0,120}?abortRef\.current[\s\S]{0,40}?\) return/u);
  assert.match(source, /changeAllowed: Boolean\([\s\S]*?!hasCurrentImageContent[\s\S]*?onCommandPermissionModeChange[\s\S]*?selectedProviderSupportsTools/u);
  assert.match(composer, /<AiPermissionMenu[\s\S]*?disabled=\{busy \|\| permissionSaving \|\| !engine\.permission\.changeAllowed\}/u);
  assert.match(composer, /<AiProviderMenu[\s\S]*?profiles=\{engine\.provider\.profiles\}[\s\S]*?disabled=\{busy \|\| permissionSaving\}/u);
  assert.match(composer, /disabled=\{busy \|\| permissionSaving \|\| !ready\}/u);
  assert.match(source, /if \(await savePermissionMode\("auto"\)\) \{\s*await resolveAgentApproval\(true\)/u);
  assert.match(source, /disabled=\{agentApprovalRunning \|\| permissionSaving\}/u);
});

test("AI provider selection follows persisted startup authority and serializes rapid choices", async () => {
  const source = await readFile(workspaceUrl, "utf8");

  assert.match(source, /previousActiveProviderProfileIdRef = useRef\(activeProviderProfileId\)/u);
  assert.match(source, /const activeProviderChanged = previousActiveProviderProfileIdRef\.current !== activeProviderProfileId/u);
  assert.match(
    source,
    /const pending = pendingProviderSelectionRef\.current;[\s\S]*?return pending\.providerProfileId;[\s\S]*?if \(activeProviderChanged\) \{[\s\S]*?enabledProviderProfileId\(providers, activeProviderProfileId\)/u,
  );
  assert.match(source, /providerSelectionQueueRef = useRef<Promise<void>>\(Promise\.resolve\(\)\)/u);
  assert.match(source, /const sequence = \+\+providerSelectionSequenceRef\.current;[\s\S]*?pendingProviderSelectionRef\.current = \{ sequence, providerProfileId \}/u);
  assert.match(source, /const queued = providerSelectionQueueRef\.current\.then\(persistSelection\);[\s\S]*?providerSelectionQueueRef\.current = queued/u);
  assert.match(source, /pendingProviderSelectionRef\.current\?\.sequence !== sequence\) return;[\s\S]*?renderedProvidersRef\.current,[\s\S]*?renderedActiveProviderProfileIdRef\.current/u);
  assert.match(source, /pendingProviderSelectionRef\.current[\s\S]{0,120}?abortRef\.current/u);
});

test("AI model catalogs are cached, stale-safe, retryable, and persist through serialized Settings CAS", async () => {
  const source = await readFile(workspaceUrl, "utf8");

  assert.match(source, /modelCatalogSource = listAiModels/u);
  assert.match(source, /modelCatalogCacheRef = useRef\(new Map<string, readonly string\[\]>\(\)\)/u);
  assert.match(source, /const sequence = \+\+modelCatalogLoadSequenceRef\.current[\s\S]*?await modelCatalogSource\(profileId\)/u);
  assert.match(source, /sequence !== modelCatalogLoadSequenceRef\.current[\s\S]*?renderedSelectedProviderProfileIdRef\.current !== profileId/u);
  assert.match(source, /status: "error",[\s\S]*?models: cached \?\? Object\.freeze\(\[\]\)/u);
  assert.match(source, /void loadProviderModels\(selectedProvider\.id\)/u);
  assert.match(source, /retryProviderModels[\s\S]*?loadProviderModels\(profileId, true\)/u);

  assert.match(source, /modelSelectionQueueRef = useRef<Promise<void>>\(Promise\.resolve\(\)\)/u);
  assert.match(source, /const previousModel = modelOverridesRef\.current\[profileId\] \?\? provider\.model/u);
  assert.match(source, /setModelOverrides\(optimisticModels\)[\s\S]*?await providerQueueAtSelection[\s\S]*?persistAiProviderModel\(settingsAdapter, profileId, modelId\)/u);
  assert.match(source, /modelSelectionSequenceRef\.current\.get\(profileId\) !== sequence[\s\S]*?previousModel[\s\S]*?ai\.settingsApplyFailed/u);
  assert.match(source, /modelQueueAtSelection[\s\S]*?await modelQueueAtSelection[\s\S]*?onSelectProvider\(providerProfileId\)/u);
  assert.match(source, /new Set\(\[selectedProviderModel, \.\.\.\(selectedCatalog\?\.models \?\? \[\]\)\]\)/u);
  assert.match(source, /modelValue: selectedProviderModel[\s\S]*?models: composerModels[\s\S]*?onSelectModel: selectProviderModel[\s\S]*?onRetryModels: retryProviderModels/u);
});

test("reasoning effort appears only for supported models and off is omitted from native starts", async () => {
  const [workspace, completion] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(new URL("../../src/aiCompletion.ts", import.meta.url), "utf8"),
  ]);

  assert.match(workspace, /useState<AiThinkingEffort>\("off"\)/u);
  assert.match(workspace, /supportsAiReasoningEffort\(selectedProvider\.protocol, selectedProviderModel\)/u);
  assert.match(workspace, /!selectedProviderSupportsThinking && thinkingEffort !== "off"[\s\S]*?setThinkingEffort\("off"\)/u);
  assert.match(workspace, /thinkingEffort !== "off"[\s\S]*?\{ reasoningEffort: thinkingEffort \}/u);
  assert.match(workspace, /thinking=\{selectedProviderSupportsThinking \? \{[\s\S]*?onSelect: selectThinkingEffort/u);
  assert.match(completion, /request\.reasoningEffort \? \{ reasoningEffort: request\.reasoningEffort \} : \{\}/u);
});

test("AI workspace submits the selected provider profile, binds scope metadata, and clears busy feedback", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  assert.match(source, /if \(!requestUsesLocalAgent && !selectedProvider\) \{[\s\S]*?setNotice\(t\("ai\.noProviderConfigured"\)\)/u);
  assert.match(source, /const requestProviderProfileId = requestUsesLocalAgent[\s\S]*?`local-agent:\$\{requestLocalAgent!\.id\}`[\s\S]*?: selectedProvider\?\.id/u);
  assert.match(source, /const completionRequest: AiCompletionRequest = \{[\s\S]*?providerProfileId: requestProviderProfileId/u);
  assert.doesNotMatch(source, /normalizeAiEndpoint|allowsMissingAiApiKey|requestApiKey|useStoredKey/u);
  assert.match(
    source,
    /const requestContext: AiWorkspaceContext = Object\.freeze\([\s\S]*?terminalLabel: requestScope\.label,[\s\S]*?terminalProtocol: requestScope\.protocol/u,
  );
  assert.match(source, /setNotice\(t\("ai\.generating"\)\);[\s\S]*?setBusyTarget\(capturedConversation\)/u);
  assert.match(source, /currentConversationBusy && !streamingAssistantMessageId \? \([\s\S]*?<article className="ai-message ai-message-assistant ai-message-pending" aria-label=\{t\("ai\.generating"\)\}/u);
  assert.match(
    source,
    /if \(!pausedForApproval && abortRef\.current === controller\) \{[\s\S]*?setBusyTarget\(null\);[\s\S]*?setNotice\(null\);/u,
  );
  assert.match(source, /const stop[\s\S]*?setBusyTarget\(null\);[\s\S]*?usingLocalAgent \? t\("ai\.localAgent\.stopped"\) : t\("ai\.stopped"\)/u);

  assert.equal(createTranslator("zh-CN")("ai.generating"), "正在生成…");
  assert.equal(createTranslator("en-US")("ai.generating"), "Generating…");
});

test("AI workspace can send explicitly attached terminal context without typed text", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  const composer = await readFile(composerUrl, "utf8");

  assert.match(source, /const hasSendableContext = Boolean\([\s\S]*?aiConversationScopeKey\(contextScope\) === currentScopeKey[\s\S]*?selectedText[\s\S]*?recentOutput/u);
  assert.match(source, /const content = input\.trim\(\) \|\| \(requestImages\.length > 0[\s\S]*?ai\.image\.contextOnlyPrompt[\s\S]*?ai\.image\.onlyPrompt[\s\S]*?ai\.contextOnlyPrompt/u);
  assert.match(source, /contextSummary=\{contextSummary\}[\s\S]*?hasSendableContext=\{hasSendableContext\}/u);
  assert.match(composer, /!value\.trim\(\) && !hasSendableContext && images\.length === 0/u);
});

test("AI workspace offers terminal, diagnose, and explain modes with explain routed tool-free", async () => {
  const [source, composer] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(composerUrl, "utf8"),
  ]);
  assert.match(source, /export type AiAssistantMode = AiComposerMode/u);
  assert.match(composer, /export type AiComposerMode = "terminal" \| "explain" \| "diagnose"/u);
  assert.match(source, /useState<AiAssistantMode>\("terminal"\)/u);
  assert.match(composer, /value=\{mode\}[\s\S]*?<option value="terminal">[\s\S]*?<option value="diagnose">[\s\S]*?<option value="explain">/u);
  assert.match(source, /const completionRequest: AiCompletionRequest = \{[\s\S]*?assistantMode,/u);
  assert.match(source, /const requestAgent = !requestUsesLocalAgent[\s\S]*?selectedProviderSupportsTools[\s\S]*?assistantMode !== "explain"[\s\S]*?requestScope\?\.connected[\s\S]*?requestScope\.commandExecutionSupported[\s\S]*?\? agent[\s\S]*?: null/u);
  assert.match(source, /requestAgent = !requestUsesLocalAgent[\s\S]*?selectedPermissionMode !== "observer"/u);
  assert.match(source, /if \(requestAgent\) \{[\s\S]*?await requestAgent\(completionRequest,[\s\S]*?\} else \{[\s\S]*?requestUsesLocalAgent[\s\S]*?localAgentComplete![\s\S]*?: await complete\(completionRequest,/u);
});

test("AI Composer is a controlled callback-only presentation boundary", async () => {
  const [source, composer] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(composerUrl, "utf8"),
  ]);

  assert.doesNotMatch(source, /className="ai-workspace-composer"/u);
  assert.match(source, /<AiComposer[\s\S]*?value=\{input\}[\s\S]*?contextSummary=\{contextSummary\}[\s\S]*?mode=\{assistantMode\}[\s\S]*?ready=\{assistantReady\}[\s\S]*?busy=\{busy\}[\s\S]*?permissionSaving=\{permissionSaving\}[\s\S]*?engine=\{composerEngine\}/u);
  assert.match(source, /onValueChange=\{setInput\}[\s\S]*?onSubmit=\{\(\) => void submit\(\)\}[\s\S]*?onStop=\{stop\}[\s\S]*?onClearContext=\{clearContext\}[\s\S]*?onReadContext=\{readContext\}/u);

  assert.match(composer, /<form className="ai-workspace-composer" onSubmit=\{submit\} onDragOver=\{handleDragOver\} onDrop=\{handleDrop\}>/u);
  assert.match(composer, /event\.preventDefault\(\);\s*onSubmit\(\)/u);
  assert.match(composer, /event\.key === "Enter" && !event\.shiftKey && !event\.nativeEvent\.isComposing/u);
  assert.match(composer, /Math\.min\(Math\.max\(textarea\.scrollHeight, 52\), 180\)/u);
  assert.match(composer, /value=\{value\}[\s\S]*?onChange=\{\(event\) => \{[\s\S]*?quickMessagePicker\.sync\(event\.target\.value,[\s\S]*?onValueChange\(event\.target\.value\);[\s\S]*?\}\}/u);
  assert.match(composer, /maxLength=\{AI_COMPOSER_MAX_LENGTH\}[\s\S]*?spellCheck=\{false\}[\s\S]*?autoCorrect="off"[\s\S]*?autoCapitalize="off"[\s\S]*?autoComplete="off"/u);
  assert.match(composer, /<AiContextMenu[\s\S]*?onReadContext=\{onReadContext\}/u);
  assert.match(composer, /busy \? \([\s\S]*?onClick=\{onStop\}[\s\S]*?: \([\s\S]*?type="submit"/u);
  assert.doesNotMatch(composer, /useState|nativeAiAgentTransport|openAiCompatibleAgent|terminal_execute|invoke\(|apiKey|baseUrl|AiConversation/u);
});

test("AI image drafts are scoped, callback-only, and bypass terminal tools", async () => {
  const [source, composer] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(composerUrl, "utf8"),
  ]);

  assert.match(source, /useState<ScopedValue<readonly AiDraftImage\[\]>>/u);
  assert.match(source, /scopedImages\.scopeKey === currentScopeKey \? scopedImages\.value : \[\]/u);
  assert.match(source, /prepareAiDraftImages\(files, draftImages\)/u);
  assert.match(source, /const requestHasImageContent = requestConversation\.messages\.some\([\s\S]*?attachment\.data/u);
  assert.match(source, /!requestHasImageContent[\s\S]*?selectedProviderSupportsTools/u);
  assert.match(source, /commandPermissionMode: requestHasImageContent[\s\S]*?\? "observer"/u);
  assert.match(source, /images=\{draftImages\}[\s\S]*?onAddImageFiles=\{addDraftImageFiles\}[\s\S]*?onRemoveImage=\{removeDraftImage\}/u);
  assert.match(composer, /type="file"[\s\S]*?accept=\{AI_IMAGE_ACCEPT\}[\s\S]*?multiple/u);
  assert.match(composer, /onPaste=\{handlePaste\}/u);
  assert.match(composer, /onDragOver=\{handleDragOver\} onDrop=\{handleDrop\}/u);
  assert.match(composer, /images\.map\(\(image\) =>[\s\S]*?onRemoveImage\(image\.id\)/u);
  assert.doesNotMatch(composer, /FileReader|contentParts|completeNativeAiChat|nativeAiAgentTransport/u);
});

test("retained image bodies block unsupported engines and keep the whole request observer-only", async () => {
  const source = await readFile(workspaceUrl, "utf8");

  assert.match(
    source,
    /const hasRetainedImageContent = messages\.some\([\s\S]*?message\.attachments\?\.some\([\s\S]*?attachment\.data/u,
  );
  assert.match(source, /const hasCurrentImageContent = hasDraftImages \|\| hasRetainedImageContent/u);
  assert.match(
    source,
    /const imageInputEnabled = !usingLocalAgent[\s\S]*?selectedProvider\?\.protocol === "openAiChatCompletions"/u,
  );
  assert.match(
    source,
    /const requestHasImageContent = requestConversation\.messages\.some\([\s\S]*?attachment\.data[\s\S]*?if \(requestHasImageContent && !imageInputEnabled\) \{[\s\S]*?setNotice\(imageInputDisabledReason\);[\s\S]*?return;/u,
  );
  assert.match(
    source,
    /const requestAgent = !requestUsesLocalAgent\s*&& !requestHasImageContent[\s\S]*?commandPermissionMode: requestHasImageContent \|\| requestUsesLocalAgent/u,
  );
  assert.match(
    source,
    /value: hasCurrentImageContent \? "observer" : effectivePermissionMode[\s\S]*?!hasCurrentImageContent[\s\S]*?ai\.permission\.imageObserverOnly/u,
  );
});

test("AI image draft lifetime survives the StrictMode effect cleanup and setup probe", async () => {
  const source = await readFile(workspaceUrl, "utf8");

  assert.match(
    source,
    /useEffect\(\(\) => \{\s*mountedRef\.current = true;\s*return \(\) => \{\s*mountedRef\.current = false;/u,
  );
  assert.match(source, /if \(!mountedRef\.current \|\| renderedScopeKeyRef\.current !== requestedScopeKey\)/u);
});

test("AI workspace enables every discovered runtime-supported local agent in tool-free observer mode", async () => {
  const [source, composer] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(composerUrl, "utf8"),
  ]);
  const header = source.slice(source.indexOf('<header className="ai-workspace-header">'), source.indexOf("</header>"));

  assert.match(header, /<AiAgentMenu[\s\S]*?value=\{selectedAssistantEngine\}[\s\S]*?agents=\{localAgents\}[\s\S]*?localRuntimeAvailable=\{localAgentComplete !== null\}/u);
  assert.match(header, /onSelect=\{\(agentId\) => selectAssistantEngine\(agentId as "builtin" \| NativeLocalAiAgentId\)\}/u);
  assert.doesNotMatch(header, /value=\{assistantMode\}/u);
  assert.match(source, /const composerEngine: AiComposerEngine = usingLocalAgent[\s\S]*?kind: "local",[\s\S]*?label: selectedLocalAgentLabel/u);
  assert.match(source, /<AiComposer[\s\S]*?mode=\{assistantMode\}[\s\S]*?engine=\{composerEngine\}/u);
  assert.match(composer, /value=\{mode\}[\s\S]*?<option value="terminal">[\s\S]*?<option value="diagnose">[\s\S]*?<option value="explain">/u);
  assert.match(source, /commandPermissionMode: requestHasImageContent \|\| requestUsesLocalAgent \|\| !selectedProviderSupportsTools[\s\S]*?\? "observer"[\s\S]*?: selectedPermissionMode/u);
  assert.match(source, /requestUsesLocalAgent[\s\S]*?localAgentComplete!\(requestLocalAgent!\.id/u);
  assert.match(source, /usingLocalAgent \|\| effectivePermissionMode === "observer"[\s\S]*?ai\.localAgent\.commandDisabled/u);
  assert.match(composer, /engine\.kind === "local" \? \([\s\S]*?ai\.localAgent\.runtimeLabel[\s\S]*?engine\.kind === "local" \? \([\s\S]*?ai\.localAgent\.readOnly/u);
  assert.doesNotMatch(source, /candidate\.id\s*[!=]==?\s*"codex"|requestLocalAgent\.id\s*[!=]==?\s*"codex"|engineId\s*[!=]==?\s*"codex"/u);
  assert.equal(createTranslator("zh-CN")("ai.localAgent.readOnly"), "无工具观察");
  assert.equal(createTranslator("zh-CN")("ai.localAgent.commandDisabled"), "本机智能体处于无工具观察模式，不能向终端发送命令。");
  assert.equal(createTranslator("en-US")("ai.localAgent.commandDisabled"), "The local agent has no tools and cannot send commands to the terminal.");
  assert.equal(createTranslator("en-US")("ai.localAgent.readOnlyDescription"), "Runs without tools and cannot execute or modify terminal commands.");
});

test("AI streaming reuses one assistant placeholder and binds every delta to its captured generation", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  assert.match(source, /const requestScopeKey = aiConversationScopeKey\(requestScope\);[\s\S]*?capturedConversation\.scopeKey !== requestScopeKey/u);
  assert.match(
    source,
    /const assistantMessageId = requestAgent \? null : makeId\(\);[\s\S]*?\{ id: assistantMessageId, role: "assistant", content: "" \}/u,
  );
  assert.match(
    source,
    /const publishDelta = \(delta: string\) => \{[\s\S]*?abortRef\.current !== controller[\s\S]*?sameConversationTarget\(active\.target, capturedConversation\)[\s\S]*?updateAiConversationMessage\([\s\S]*?assistantMessageId,[\s\S]*?\{ content: nextContent \}/u,
  );
  assert.match(
    source,
    /const finalContent = answer \|\| active\.content \|\| t\("ai\.emptyResponse"\);[\s\S]*?updateAiConversationMessage\([\s\S]*?assistantMessageId,[\s\S]*?\{ content: finalContent \}/u,
  );
  assert.match(source, /streamingAssistant && !streamingAssistant\.content[\s\S]*?deleteAiConversationMessage/u);
  assert.match(source, /isStreamingAssistant && !message\.content[\s\S]*?ai-thinking-dots/u);

  const deltaCallback = source.slice(
    source.indexOf("const publishDelta ="),
    source.indexOf("if (controller.signal.aborted || abortRef.current !== controller) return;"),
  );
  assert.doesNotMatch(deltaCallback, /appendAiConversationMessage/u);
});

test("saved AI keys expose only presence and explicit save/delete commands", async () => {
  const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
  const mock = async <T>(command: string, args?: Record<string, unknown>): Promise<T> => {
    calls.push({ command, args });
    return true as T;
  };

  const providerProfileId = "openai-work";
  assert.equal(await hasSavedAiApiKey(providerProfileId, mock), true);
  assert.equal(await saveAiApiKey(providerProfileId, "  secret-marker  ", mock), true);
  assert.equal(await deleteSavedAiApiKey(providerProfileId, mock), true);
  assert.deepEqual(calls.map(({ command }) => command), [
    AI_COMMANDS.hasSavedKey,
    AI_COMMANDS.saveKey,
    AI_COMMANDS.deleteKey,
  ]);
  assert.deepEqual(calls[0]?.args, { providerProfileId });
  assert.deepEqual(calls[1]?.args, {
    request: { providerProfileId, apiKey: "secret-marker" },
  });
  assert.deepEqual(calls[2]?.args, { providerProfileId });
  assert.doesNotMatch(JSON.stringify(calls[0]), /secret-marker/u);
  await assert.rejects(hasSavedAiApiKey("Invalid Provider", mock), /AI_PROVIDER_INVALID/u);
});

test("right-side AI workspace is profile-only and exposes model, permission, Settings, and Markdown copy controls", async () => {
  const [source, composer, markdown] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(composerUrl, "utf8"),
    readFile(markdownUrl, "utf8"),
  ]);
  assert.match(source, /providers\?: ReadonlyArray<AiProviderOption>/u);
  assert.match(source, /activeProviderProfileId\?: string/u);
  assert.match(source, /provider: \{[\s\S]*?value: selectedProvider\?\.id \?\? "",[\s\S]*?profiles: composerProviders,[\s\S]*?onSelect: selectProvider,[\s\S]*?modelValue: selectedProviderModel,[\s\S]*?onSelectModel: selectProviderModel,[\s\S]*?onOpenSettings/u);
  assert.match(source, /permission: \{[\s\S]*?value: hasCurrentImageContent \? "observer" : effectivePermissionMode,[\s\S]*?onSelect: selectPermissionMode/u);
  assert.match(composer, /<AiProviderMenu[\s\S]*?value=\{engine\.provider\.value\}[\s\S]*?onOpenSettings=\{engine\.provider\.onOpenSettings\}/u);
  assert.match(composer, /<AiPermissionMenu[\s\S]*?value=\{engine\.permission\.value\}[\s\S]*?onSelect=\{engine\.permission\.onSelect\}/u);
  assert.match(source, /<AiAgentMenu[\s\S]*?onOpenSettings=\{onOpenSettings\}/u);
  assert.match(source, /onClose\?: \(\) => void/u);
  assert.match(source, /aria-label=\{t\("ai\.closePanel"\)\}[\s\S]*?onClick=\{onClose\}/u);
  assert.match(source, /<AiMarkdown[\s\S]*?labels=\{\{ copyCode: t\("ai\.copyCode"\), copiedCode: t\("ai\.copiedCode"\) \}\}/u);
  assert.match(markdown, /navigator\.clipboard\.writeText\(value\)/u);
  assert.match(markdown, /onClick=\{\(\) => void copy\(segment\.content, index\)\}/u);
  assert.doesNotMatch(source, /type="password"|apiKeyDraft|hasSavedAiApiKey|saveAiApiKey|deleteSavedAiApiKey/u);
  assert.doesNotMatch(source, /\bbaseUrl\b|\bapiKey\b|\buseStoredKey\b/u);
});

test("non-OpenAI provider protocols stay text-only without overwriting the saved permission", async () => {
  const [source, composer] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(composerUrl, "utf8"),
  ]);
  assert.match(source, /protocol: AiProviderProtocol/u);
  assert.match(source, /selectedProviderSupportsTools = selectedProvider\?\.protocol === "openAiChatCompletions"/u);
  assert.match(source, /effectivePermissionMode: AiCommandPermissionMode = selectedProviderSupportsTools[\s\S]*?selectedPermissionMode[\s\S]*?: "observer"/u);
  assert.match(source, /const requestAgent = !requestUsesLocalAgent[\s\S]*?!requestHasImageContent[\s\S]*?selectedProviderSupportsTools/u);
  assert.match(source, /commandPermissionMode: requestHasImageContent \|\| requestUsesLocalAgent \|\| !selectedProviderSupportsTools[\s\S]*?\? "observer"/u);
  assert.match(source, /value: hasCurrentImageContent \? "observer" : effectivePermissionMode,[\s\S]*?changeAllowed: Boolean\([\s\S]*?!hasCurrentImageContent[\s\S]*?selectedProviderSupportsTools[\s\S]*?ai\.permission\.protocolToolUnsupported/u);
  assert.match(composer, /value=\{engine\.permission\.value\}[\s\S]*?disabledReason=\{engine\.permission\.disabledReason\}/u);
  assert.doesNotMatch(source, /setSelectedPermissionMode\("observer"\)/u);
  assert.equal(
    createTranslator("en-US")("ai.permission.protocolToolUnsupported"),
    "This provider protocol does not support terminal tools yet. Observer mode is used.",
  );
  assert.equal(
    createTranslator("zh-CN")("ai.permission.protocolToolUnsupported"),
    "此服务商接口协议暂不支持终端工具，已使用观察模式。",
  );
});

test("AI workspace isolates history, drafts, and late replies by exact terminal generation", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  assert.match(source, /const currentScopeKey = aiConversationScopeKey\(terminalScope\)/u);
  assert.match(source, /scopedInput\.scopeKey === currentScopeKey \? scopedInput\.value : ""/u);
  assert.match(source, /getAiConversationScope\(conversationState, currentScopeKey\)/u);
  assert.match(source, /const capturedConversation = currentConversationTarget/u);
  assert.match(
    source,
    /requestConversation\.messages\.map\(\(\{ role, content: body, attachments \}\) => \(\{[\s\S]*?contentParts:[\s\S]*?mimeType: attachment\.mimeType,[\s\S]*?data: attachment\.data/u,
  );
  assert.match(
    source,
    /setConversationState\(\(current\) => appendAiConversationMessage\([\s\S]*?current,[\s\S]*?capturedConversation/u,
  );
  assert.match(source, /<AiConversationHistory[\s\S]*?onSelect=\{selectConversation\}[\s\S]*?onDelete=\{deleteConversation\}/u);
  assert.match(source, /scopedContext\.scopeKey === currentScopeKey/u);
  assert.match(source, /scopedPendingCommand\.scopeKey === currentScopeKey/u);
  assert.match(source, /scopedNotice\.scopeKey === currentScopeKey/u);
  assert.match(source, /renderedScopeKeyRef\.current !== requestedScopeKey/u);
  assert.match(source, /protectedTargets: busyTarget \? \[busyTarget\] : \[\]/u);
  assert.match(source, /if \([\s\S]{0,220}?permissionSaveInFlightRef\.current[\s\S]{0,120}?pendingProviderSelectionRef\.current[\s\S]{0,120}?abortRef\.current[\s\S]{0,40}?\) return/u);
  assert.match(
    source,
    /const withoutTarget = deleteAiConversation\(current, target\);[\s\S]*?createAiConversation\(withoutTarget, target\.scopeKey\)/u,
  );
  assert.doesNotMatch(source, /\[messages, setMessages\]/u);
});

test("AI workspace owns no credential fields and unknown errors cannot expose request secrets", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  assert.doesNotMatch(source, /apiKeyDraft|setApiKey|type="password"|autoComplete="off"/u);
  assert.doesNotMatch(source, /localStorage|sessionStorage|indexedDB/u);

  const translated = localizeAiError(
    new Error("provider echoed fake-api-key and private terminal output"),
    createTranslator("zh-CN"),
  );
  assert.doesNotMatch(translated, /fake-api-key|private terminal output/u);
  assert.equal(translated, createTranslator("zh-CN")("ai.requestFailed"));

  const t = createTranslator("zh-CN");
  assert.equal(localizeAiError(new Error("AI_STORED_KEY_NOT_FOUND"), t), t("ai.error.storedKeyMissing"));
  assert.equal(localizeAiError(new Error("AI_CREDENTIAL_STORE_FAILED"), t), t("ai.error.credentialStore"));
  assert.equal(localizeAiError(new Error("AI_PROVIDER_INVALID"), t), t("ai.error.providerInvalid"));
  assert.equal(localizeAiError(new Error("AI_KEY_SOURCE_INVALID"), t), t("ai.error.keySource"));
  assert.equal(localizeAiError(new Error("AI_LOCAL_AGENT_UNAVAILABLE"), t), t("ai.error.localAgentUnavailable"));
  assert.equal(localizeAiError(new Error("AI_LOCAL_AGENT_START_FAILED"), t), t("ai.error.localAgentStartFailed"));
  assert.equal(localizeAiError(new Error("AI_LOCAL_AGENT_TIMEOUT"), t), t("ai.error.localAgentTimeout"));
  assert.equal(localizeAiError(new Error("AI_TOOL_OBSERVER_DENIED"), t), t("ai.error.permissionChanged"));
  assert.equal(localizeAiError(new Error("AI_TOOL_APPROVAL_REQUIRED"), t), t("ai.error.permissionChanged"));
});
