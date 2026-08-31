import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  confirmAiCommandApproval,
  extractAiCommandProposals,
  stageAiCommandApproval,
  type AiCommandApproval,
  type AiCommandProposal,
} from "./aiCommandProposal";
import {
  nativeAiAgentTransport,
  type NativeAiReasoningEffort,
  type NativeAiAgentTurnStep,
  type NativeAiChatContentPart,
  type NativeLocalAiAgentId,
} from "./aiApi";
import type { DiscoveredAiAgent } from "./aiAgentDiscoveryApi";
import AiMarkdown from "./AiMarkdown";
import AiConversationHistory from "./AiConversationHistory";
import AiComposer, { type AiComposerEngine, type AiComposerMode } from "./ai/AiComposer";
import AiAgentMenu from "./ai/AiAgentMenu";
import AiGlyph from "./ai/AiGlyph";
import type { AiThinkingEffort } from "./ai/AiThinkingMenu";
import {
  prepareAiDraftImages,
  revokeAiDraftImages,
  type AiDraftImage,
} from "./ai/aiImageAttachments";
import { createAiContextUsage } from "./ai/aiContextUsage";
import {
  activateAiConversationScope,
  aiConversationScopeKey,
  appendAiConversationMessage,
  createAiConversation,
  createAiConversationState,
  deleteAiConversation,
  deleteAiConversationMessage,
  getAiConversation,
  getAiConversationScope,
  switchAiConversation,
  type AiConversationImageAttachment,
  type AiConversationToolActivity,
  type AiConversationTarget,
  updateAiConversationMessage,
} from "./aiConversationState";
import { buildAiMessages, openAiCompatibleAgent } from "./aiCompletion";
import {
  listAiModels,
  persistAiProviderModel,
  supportsAiReasoningEffort,
} from "./aiModelsApi";
import { executeAndCaptureAiTerminalTool } from "./aiTerminalTool";
import { localizeAiError, useI18n, type Locale } from "./i18n";
import { SETTINGS_ADAPTER } from "./settingsApi";
import {
  type AiCommandPermissionMode,
  type AiProviderProtocol,
  type RendererSafeSettingsAdapter,
} from "./settingsUi";

export type AiMessageRole = "user" | "assistant" | "system" | "error";

export type AiTerminalScope = Readonly<{
  /** Renderer-owned route; never included in provider messages. */
  routeId: string;
  /** Exact runtime generation captured before context/request/approval. */
  generation: number;
  protocol: string;
  label: string;
  connected: boolean;
  commandExecutionSupported: boolean;
}>;

export type AiMessage = Readonly<{
  id: string;
  role: AiMessageRole;
  content: string;
  attachments?: readonly AiConversationImageAttachment[];
  toolActivity?: AiConversationToolActivity;
  terminalScope?: AiTerminalScope;
}>;

export type AiWorkspaceContext = Readonly<{
  selectedText?: string;
  recentOutput?: string;
  terminalLabel?: string;
  terminalProtocol?: string;
}>;

export type AiAssistantMode = AiComposerMode;

export type AiCompletionRequest = Readonly<{
  providerProfileId: string;
  assistantMode: AiAssistantMode;
  commandPermissionMode: AiCommandPermissionMode;
  locale: Locale;
  messages: ReadonlyArray<Readonly<{
    role: AiMessageRole;
    content: string;
    contentParts?: readonly NativeAiChatContentPart[];
  }>>;
  context: AiWorkspaceContext;
  terminalScope?: AiTerminalScope;
  reasoningEffort?: NativeAiReasoningEffort;
}>;

export type AiCompletion = (
  request: AiCompletionRequest,
  signal: AbortSignal,
  onDelta?: (delta: string) => void,
) => Promise<string>;

export type AiLocalAgentCompletion = (
  agentId: NativeLocalAiAgentId,
  request: AiCompletionRequest,
  signal: AbortSignal,
  onDelta?: (delta: string) => void,
) => Promise<string>;

export type AiAgent = (
  request: AiCompletionRequest,
  signal: AbortSignal,
) => Promise<NativeAiAgentTurnStep>;

export type AiProviderOption = Readonly<{
  id: string;
  providerId: string;
  name: string;
  model: string;
  protocol: AiProviderProtocol;
  enabled: boolean;
}>;

export type AiWorkspaceProps = Readonly<{
  locale?: Locale;
  providers?: ReadonlyArray<AiProviderOption>;
  activeProviderProfileId?: string;
  commandPermissionMode?: AiCommandPermissionMode;
  initialContext?: AiWorkspaceContext;
  terminalScope?: AiTerminalScope | null;
  getSelectedTerminalText?: (scope: AiTerminalScope) => string | Promise<string | undefined> | undefined;
  getRecentTerminalOutput?: (scope: AiTerminalScope) => string | Promise<string | undefined> | undefined;
  sendApprovedCommand?: (scope: AiTerminalScope, command: string) => Promise<void>;
  complete?: AiCompletion;
  localAgents?: ReadonlyArray<DiscoveredAiAgent>;
  localAgentComplete?: AiLocalAgentCompletion | null;
  agent?: AiAgent | null;
  modelCatalogSource?: typeof listAiModels;
  settingsAdapter?: RendererSafeSettingsAdapter;
  onSelectProvider?: (providerProfileId: string) => void | Promise<void>;
  onCommandPermissionModeChange?: (mode: AiCommandPermissionMode) => void | Promise<void>;
  onOpenSettings?: () => void;
  onClose?: () => void;
}>;

type PendingCommand = AiCommandApproval<AiTerminalScope>;

type PendingAgentApproval = Readonly<{
  step: Extract<NativeAiAgentTurnStep, { kind: "toolCall" }>;
  scope: AiTerminalScope;
  target: AiConversationTarget;
  controller: AbortController;
  activityMessageId: string;
  expiresAt: number;
}>;

type ScopedValue<T> = Readonly<{
  scopeKey: string;
  value: T;
}>;

type ActiveStreamingAssistant = {
  controller: AbortController;
  target: AiConversationTarget;
  messageId: string;
  content: string;
};

type PendingProviderSelection = Readonly<{
  sequence: number;
  providerProfileId: string;
}>;

type AiModelCatalogState = Readonly<{
  profileId: string;
  status: "idle" | "loading" | "ready" | "error";
  models: readonly string[];
}>;

const DEFAULT_PROVIDER: AiProviderOption = Object.freeze({
  id: "openai-compatible",
  providerId: "openai-compatible",
  name: "OpenAI",
  model: "gpt-4o-mini",
  protocol: "openAiChatCompletions",
  enabled: true,
});
const DEFAULT_PROVIDERS: ReadonlyArray<AiProviderOption> = Object.freeze([DEFAULT_PROVIDER]);
const AI_AGENT_APPROVAL_TTL_MS = 5 * 60 * 1_000;

const terminalToolActivity = (
  step: Extract<NativeAiAgentTurnStep, { kind: "toolCall" }>,
  status: AiConversationToolActivity["status"],
  errorCode?: string,
): AiConversationToolActivity => Object.freeze({
  id: step.call.id,
  name: "terminal_execute",
  command: step.call.command,
  status,
  ...(errorCode ? { errorCode } : {}),
});

const enabledProviderProfileId = (
  providers: ReadonlyArray<AiProviderOption>,
  preferredProfileId: string,
): string => providers.some((provider) => provider.id === preferredProfileId && provider.enabled)
  ? preferredProfileId
  : providers.find((provider) => provider.enabled)?.id ?? "";

const makeId = (): string => `ai-message-${crypto.randomUUID()}`;

const sameToolScope = (
  left: Pick<AiTerminalScope, "routeId" | "generation" | "protocol">,
  right: Pick<AiTerminalScope, "routeId" | "generation" | "protocol">,
): boolean => left.routeId === right.routeId
  && left.generation === right.generation
  && left.protocol === right.protocol;

const sameConversationTarget = (
  left: AiConversationTarget,
  right: AiConversationTarget,
): boolean => left.scopeKey === right.scopeKey
  && left.conversationId === right.conversationId;

const terminalToolErrorCode = (reason: unknown): string => {
  const candidate = reason instanceof Error ? reason.message : String(reason);
  return /^[A-Z0-9_]{1,128}$/u.test(candidate)
    ? candidate
    : "TERMINAL_SEND_FAILED";
};

export const createPlaceholderAiCompletion: AiCompletion = async () => {
  throw new Error("AI_CLIENT_UNAVAILABLE");
};

export function AiWorkspace({
  locale = "zh-CN",
  providers = DEFAULT_PROVIDERS,
  activeProviderProfileId = providers[0]?.id ?? "",
  commandPermissionMode = "confirm",
  initialContext,
  terminalScope = null,
  getSelectedTerminalText,
  getRecentTerminalOutput,
  sendApprovedCommand,
  complete = createPlaceholderAiCompletion,
  localAgents = [],
  localAgentComplete = null,
  agent = openAiCompatibleAgent,
  modelCatalogSource = listAiModels,
  settingsAdapter = SETTINGS_ADAPTER,
  onSelectProvider,
  onCommandPermissionModeChange,
  onOpenSettings,
  onClose,
}: AiWorkspaceProps) {
  const { t } = useI18n(locale);
  const [assistantMode, setAssistantMode] = useState<AiAssistantMode>("terminal");
  const [selectedAssistantEngine, setSelectedAssistantEngine] = useState<"builtin" | NativeLocalAiAgentId>("builtin");
  const [selectedProviderProfileId, setSelectedProviderProfileId] = useState(activeProviderProfileId);
  const [selectedPermissionMode, setSelectedPermissionMode] = useState(commandPermissionMode);
  const [thinkingEffort, setThinkingEffort] = useState<AiThinkingEffort>("off");
  const [permissionSaving, setPermissionSaving] = useState(false);
  const persistedPermissionModeRef = useRef(commandPermissionMode);
  const permissionSaveInFlightRef = useRef<Promise<boolean> | null>(null);
  const providerSelectionSequenceRef = useRef(0);
  const providerSelectionQueueRef = useRef<Promise<void>>(Promise.resolve());
  const pendingProviderSelectionRef = useRef<PendingProviderSelection | null>(null);
  const previousActiveProviderProfileIdRef = useRef(activeProviderProfileId);
  const renderedActiveProviderProfileIdRef = useRef(activeProviderProfileId);
  const renderedProvidersRef = useRef(providers);
  const [modelOverrides, setModelOverrides] = useState<Readonly<Record<string, string>>>({});
  const modelOverridesRef = useRef(modelOverrides);
  const modelCatalogCacheRef = useRef(new Map<string, readonly string[]>());
  const modelCatalogLoadSequenceRef = useRef(0);
  const modelSelectionSequenceRef = useRef(new Map<string, number>());
  const modelSelectionQueueRef = useRef<Promise<void>>(Promise.resolve());
  const [modelCatalog, setModelCatalog] = useState<AiModelCatalogState>({
    profileId: "",
    status: "idle",
    models: Object.freeze([]),
  });
  renderedActiveProviderProfileIdRef.current = activeProviderProfileId;
  renderedProvidersRef.current = providers;
  modelOverridesRef.current = modelOverrides;
  const selectedProvider = providers.find((provider) => provider.id === selectedProviderProfileId && provider.enabled)
    ?? providers.find((provider) => provider.id === activeProviderProfileId && provider.enabled)
    ?? providers.find((provider) => provider.enabled)
    ?? null;
  const selectedProviderModel = selectedProvider
    ? modelOverrides[selectedProvider.id] ?? selectedProvider.model
    : "";
  const renderedSelectedProviderProfileIdRef = useRef(selectedProvider?.id ?? "");
  renderedSelectedProviderProfileIdRef.current = selectedProvider?.id ?? "";
  const composerProviders = useMemo(() => providers.map((provider) => {
    const model = modelOverrides[provider.id];
    return model === undefined ? provider : { ...provider, model };
  }), [modelOverrides, providers]);
  const selectedProviderSupportsTools = selectedProvider?.protocol === "openAiChatCompletions";
  const effectivePermissionMode: AiCommandPermissionMode = selectedProviderSupportsTools
    ? selectedPermissionMode
    : "observer";
  const selectedLocalAgent = selectedAssistantEngine === "builtin"
    ? null
    : localAgents.find((candidate) => candidate.id === selectedAssistantEngine) ?? null;
  const usingLocalAgent = selectedAssistantEngine !== "builtin";
  const selectedProviderSupportsThinking = !usingLocalAgent
    && selectedProvider !== null
    && supportsAiReasoningEffort(selectedProvider.protocol, selectedProviderModel);
  const imageInputEnabled = !usingLocalAgent
    && selectedProvider?.protocol === "openAiChatCompletions";
  const imageInputDisabledReason = usingLocalAgent
    ? t("ai.image.error.localAgentUnsupported")
    : t("ai.image.error.providerUnsupported");
  const localAgentReady = selectedLocalAgent?.runtimeSupported === true
    && selectedLocalAgent?.available === true
    && localAgentComplete !== null;
  const assistantReady = usingLocalAgent ? localAgentReady : selectedProvider !== null;
  const messageEndRef = useRef<HTMLDivElement>(null);
  const currentScopeKey = aiConversationScopeKey(terminalScope);
  const [scopedInput, setScopedInput] = useState(() => ({
    scopeKey: currentScopeKey,
    value: "",
  }));
  const input = scopedInput.scopeKey === currentScopeKey ? scopedInput.value : "";
  const setInput = useCallback((value: string) => {
    setScopedInput({ scopeKey: currentScopeKey, value });
  }, [currentScopeKey]);
  const [scopedImages, setScopedImages] = useState<ScopedValue<readonly AiDraftImage[]>>(() => ({
    scopeKey: currentScopeKey,
    value: Object.freeze([]),
  }));
  const draftImages = scopedImages.scopeKey === currentScopeKey ? scopedImages.value : [];
  const draftImagesCleanupRef = useRef(scopedImages.value);
  const imageAddInFlightRef = useRef(false);
  const mountedRef = useRef(true);
  draftImagesCleanupRef.current = scopedImages.value;
  const [scopedContext, setScopedContext] = useState<ScopedValue<Readonly<{
    context: AiWorkspaceContext;
    terminalScope: AiTerminalScope | null;
  }>>>(() => ({
    scopeKey: currentScopeKey,
    value: { context: initialContext ?? {}, terminalScope },
  }));
  const [conversationState, setConversationState] = useState(() => (
    activateAiConversationScope(createAiConversationState(), terminalScope)
  ));
  const [showHistory, setShowHistory] = useState(false);
  const [busyTarget, setBusyTarget] = useState<AiConversationTarget | null>(null);
  const [scopedNotice, setScopedNotice] = useState<ScopedValue<string | null>>(() => ({
    scopeKey: currentScopeKey,
    value: null,
  }));
  const [scopedPendingCommand, setScopedPendingCommand] = useState<ScopedValue<PendingCommand | null>>(() => ({
    scopeKey: currentScopeKey,
    value: null,
  }));
  const [runningCommandId, setRunningCommandId] = useState<string | null>(null);
  const runningCommandRef = useRef<PendingCommand | null>(null);
  const [pendingAgentApproval, setPendingAgentApproval] = useState<PendingAgentApproval | null>(null);
  const pendingAgentApprovalRef = useRef<PendingAgentApproval | null>(null);
  pendingAgentApprovalRef.current = pendingAgentApproval;
  const [agentApprovalRunning, setAgentApprovalRunning] = useState(false);
  const runningAgentToolRef = useRef(false);
  const activeAgentTurnIdRef = useRef<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const activeStreamingAssistantRef = useRef<ActiveStreamingAssistant | null>(null);
  const [streamingAssistantMessageId, setStreamingAssistantMessageId] = useState<string | null>(null);
  const renderedScopeKeyRef = useRef(currentScopeKey);
  renderedScopeKeyRef.current = currentScopeKey;
  const context = scopedContext.scopeKey === currentScopeKey
    ? scopedContext.value.context
    : {};
  const contextScope = scopedContext.scopeKey === currentScopeKey
    ? scopedContext.value.terminalScope
    : null;
  const hasSendableContext = Boolean(
    contextScope
    && aiConversationScopeKey(contextScope) === currentScopeKey
    && (context.selectedText?.trim() || context.recentOutput?.trim()),
  );
  const hasDraftImages = draftImages.length > 0;
  const notice = scopedNotice.scopeKey === currentScopeKey ? scopedNotice.value : null;
  const pendingCommand = scopedPendingCommand.scopeKey === currentScopeKey
    ? scopedPendingCommand.value
    : null;
  const setNotice = useCallback((value: string | null) => {
    setScopedNotice((current) => (
      renderedScopeKeyRef.current === currentScopeKey
        ? { scopeKey: currentScopeKey, value }
        : current
    ));
  }, [currentScopeKey]);
  const clearDraftImages = useCallback(() => {
    setScopedImages((current) => {
      if (current.scopeKey !== currentScopeKey || current.value.length === 0) return current;
      revokeAiDraftImages(current.value);
      return { scopeKey: currentScopeKey, value: Object.freeze([]) };
    });
  }, [currentScopeKey]);
  const removeDraftImage = useCallback((imageId: string) => {
    setScopedImages((current) => {
      if (current.scopeKey !== currentScopeKey) return current;
      const removed = current.value.find((image) => image.id === imageId);
      if (!removed) return current;
      URL.revokeObjectURL(removed.previewUrl);
      return {
        scopeKey: currentScopeKey,
        value: Object.freeze(current.value.filter((image) => image.id !== imageId)),
      };
    });
  }, [currentScopeKey]);
  const addDraftImageFiles = useCallback(async (files: readonly File[]) => {
    if (imageAddInFlightRef.current || files.length === 0) return;
    imageAddInFlightRef.current = true;
    const requestedScopeKey = currentScopeKey;
    try {
      const prepared = await prepareAiDraftImages(files, draftImages);
      if (!mountedRef.current || renderedScopeKeyRef.current !== requestedScopeKey) {
        revokeAiDraftImages(prepared);
        return;
      }
      setScopedImages((current) => {
        if (current.scopeKey !== requestedScopeKey) {
          revokeAiDraftImages(prepared);
          return current;
        }
        return {
          scopeKey: requestedScopeKey,
          value: Object.freeze([...current.value, ...prepared]),
        };
      });
      setNotice(t("ai.image.added", { count: prepared.length }));
    } catch (reason) {
      if (!mountedRef.current || renderedScopeKeyRef.current !== requestedScopeKey) return;
      const code = reason instanceof Error ? reason.message : String(reason);
      const message = code.startsWith("AI_IMAGE_COUNT_LIMIT")
        ? t("ai.image.error.count")
        : code.startsWith("AI_IMAGE_TOO_LARGE")
          ? t("ai.image.error.tooLarge")
          : code.startsWith("AI_IMAGE_TOTAL_TOO_LARGE")
            ? t("ai.image.error.totalTooLarge")
            : code.startsWith("AI_IMAGE_TYPE_UNSUPPORTED")
              ? t("ai.image.error.type")
              : code.startsWith("AI_IMAGE_MIME_MISMATCH")
                ? t("ai.image.error.mimeMismatch")
                : code.startsWith("AI_IMAGE_INPUT_INVALID")
                  ? t("ai.image.error.invalid")
                  : t("ai.image.error.readFailed");
      setNotice(message);
    } finally {
      imageAddInFlightRef.current = false;
    }
  }, [currentScopeKey, draftImages, setNotice, t]);
  const setPendingCommand = useCallback((value: PendingCommand | null) => {
    setScopedPendingCommand((current) => (
      renderedScopeKeyRef.current === currentScopeKey
        ? { scopeKey: currentScopeKey, value }
        : current
    ));
  }, [currentScopeKey]);
  const clearContext = useCallback(() => {
    setScopedContext({
      scopeKey: currentScopeKey,
      value: { context: {}, terminalScope: null },
    });
  }, [currentScopeKey]);
  const currentConversationScope = getAiConversationScope(conversationState, currentScopeKey);
  const currentConversationTarget = currentConversationScope
    ? Object.freeze({
        scopeKey: currentScopeKey,
        conversationId: currentConversationScope.activeConversationId,
      })
    : null;
  const currentConversation = getAiConversation(conversationState, currentConversationTarget);
  const messages = currentConversation?.messages ?? [];
  const hasRetainedImageContent = messages.some((message) => (
    message.attachments?.some((attachment) => Boolean(attachment.data))
  ));
  const hasCurrentImageContent = hasDraftImages || hasRetainedImageContent;
  const busy = busyTarget !== null;
  const currentConversationBusy = currentConversationTarget !== null
    && busyTarget?.scopeKey === currentConversationTarget.scopeKey
    && busyTarget.conversationId === currentConversationTarget.conversationId;
  const localAgentOptionLabel = useCallback((candidate: DiscoveredAiAgent): string => {
    if (candidate.runtimeSupported && candidate.available) {
      return candidate.version
        ? `${candidate.name} · ${candidate.version}`
        : `${candidate.name} · ${t("ai.localAgent.detected")}`;
    }
    if (candidate.runtimeSupported) {
      return `${candidate.name} · ${candidate.installed
        ? t("ai.localAgent.installedUnavailable")
        : t("ai.localAgent.notDetected")}`;
    }
    return `${candidate.name} · ${candidate.installed
      ? t("ai.localAgent.detectedUnsupported")
      : t("ai.localAgent.notDetectedUnsupported")}`;
  }, [t]);
  const selectedLocalAgentLabel = selectedLocalAgent
    ? localAgentOptionLabel(selectedLocalAgent)
    : t("ai.localAgent.notAvailable");

  const cancelActiveAgentTurn = useCallback(() => {
    const turnId = activeAgentTurnIdRef.current;
    activeAgentTurnIdRef.current = null;
    if (turnId) void nativeAiAgentTransport.cancel(turnId).catch(() => undefined);
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      modelCatalogLoadSequenceRef.current += 1;
      cancelActiveAgentTurn();
      const controller = abortRef.current;
      abortRef.current = null;
      controller?.abort();
      activeStreamingAssistantRef.current = null;
      revokeAiDraftImages(draftImagesCleanupRef.current);
    };
  }, [cancelActiveAgentTurn]);

  useEffect(() => {
    setModelOverrides((current) => {
      const next = { ...current };
      let changed = false;
      for (const [profileId, model] of Object.entries(current)) {
        const persisted = providers.find((provider) => provider.id === profileId)?.model;
        if (persisted === undefined || persisted === model) {
          delete next[profileId];
          changed = true;
        }
      }
      if (changed) modelOverridesRef.current = next;
      return changed ? next : current;
    });
  }, [providers]);

  useEffect(() => {
    if (!selectedProviderSupportsThinking && thinkingEffort !== "off") {
      setThinkingEffort("off");
    }
  }, [selectedProviderSupportsThinking, thinkingEffort]);

  const loadProviderModels = useCallback(async (profileId: string, force = false) => {
    if (!profileId) return;
    const cached = modelCatalogCacheRef.current.get(profileId);
    if (cached && !force) {
      setModelCatalog({ profileId, status: "ready", models: cached });
      return;
    }

    const sequence = ++modelCatalogLoadSequenceRef.current;
    setModelCatalog({
      profileId,
      status: "loading",
      models: cached ?? Object.freeze([]),
    });
    try {
      const discovered = await modelCatalogSource(profileId);
      if (discovered.length === 0) throw new Error("AI_MODELS_EMPTY");
      const models = Object.freeze([...discovered]);
      if (
        !mountedRef.current
        || sequence !== modelCatalogLoadSequenceRef.current
        || renderedSelectedProviderProfileIdRef.current !== profileId
      ) return;
      modelCatalogCacheRef.current.set(profileId, models);
      setModelCatalog({ profileId, status: "ready", models });
    } catch {
      if (
        !mountedRef.current
        || sequence !== modelCatalogLoadSequenceRef.current
        || renderedSelectedProviderProfileIdRef.current !== profileId
      ) return;
      setModelCatalog({
        profileId,
        status: "error",
        models: cached ?? Object.freeze([]),
      });
    }
  }, [modelCatalogSource]);

  useEffect(() => {
    if (usingLocalAgent || !selectedProvider) return;
    void loadProviderModels(selectedProvider.id);
  }, [loadProviderModels, selectedProvider?.id, usingLocalAgent]);

  useEffect(() => {
    const pending = pendingAgentApproval;
    if (!pending) return;
    const timeout = window.setTimeout(() => {
      if (pendingAgentApprovalRef.current !== pending || runningAgentToolRef.current) return;
      pendingAgentApprovalRef.current = null;
      cancelActiveAgentTurn();
      pending.controller.abort();
      setPendingAgentApproval(null);
      setAgentApprovalRunning(false);
      if (abortRef.current === pending.controller) {
        abortRef.current = null;
        setBusyTarget(null);
      }
      const expired = t("ai.error.agentTurnNotFound");
      setConversationState((current) => appendAiConversationMessage(
        current,
        pending.target,
        { id: makeId(), role: "error", content: expired },
      ));
      setScopedNotice({ scopeKey: pending.target.scopeKey, value: expired });
    }, Math.max(0, pending.expiresAt - Date.now()));
    return () => window.clearTimeout(timeout);
  }, [cancelActiveAgentTurn, pendingAgentApproval, t]);

  useEffect(() => {
    const activeProviderChanged = previousActiveProviderProfileIdRef.current !== activeProviderProfileId;
    previousActiveProviderProfileIdRef.current = activeProviderProfileId;
    setSelectedProviderProfileId((current) => {
      const pending = pendingProviderSelectionRef.current;
      if (pending && providers.some((provider) => (
        provider.id === pending.providerProfileId && provider.enabled
      ))) {
        return pending.providerProfileId;
      }
      if (activeProviderChanged) {
        return enabledProviderProfileId(providers, activeProviderProfileId);
      }
      return providers.some((provider) => provider.id === current && provider.enabled)
        ? current
        : enabledProviderProfileId(providers, activeProviderProfileId);
    });
  }, [activeProviderProfileId, providers]);

  useEffect(() => {
    if (selectedAssistantEngine === "builtin" || busy) return;
    const remainsRunnable = localAgents.some((candidate) => (
      candidate.id === selectedAssistantEngine
      && candidate.runtimeSupported
      && candidate.available
    ))
      && localAgentComplete !== null;
    if (!remainsRunnable) setSelectedAssistantEngine("builtin");
  }, [busy, localAgentComplete, localAgents, selectedAssistantEngine]);

  useEffect(() => {
    persistedPermissionModeRef.current = commandPermissionMode;
    if (!permissionSaveInFlightRef.current) {
      setSelectedPermissionMode(commandPermissionMode);
    }
  }, [commandPermissionMode]);

  useEffect(() => {
    messageEndRef.current?.scrollIntoView({ block: "end" });
  }, [currentConversationBusy, messages]);

  useEffect(() => {
    setConversationState((current) => activateAiConversationScope(current, terminalScope, {
      protectedTargets: busyTarget ? [busyTarget] : [],
    }));
  }, [busyTarget, currentScopeKey, terminalScope]);

  useEffect(() => {
    setScopedInput((current) => (
      current.scopeKey === currentScopeKey
        ? current
        : { scopeKey: currentScopeKey, value: "" }
    ));
    setScopedImages((current) => {
      if (current.scopeKey === currentScopeKey) return current;
      revokeAiDraftImages(current.value);
      return { scopeKey: currentScopeKey, value: Object.freeze([]) };
    });
    setShowHistory(false);
    setPendingCommand(null);
    setNotice(null);
  }, [currentScopeKey]);

  useEffect(() => {
    if (usingLocalAgent || effectivePermissionMode !== "confirm") setPendingCommand(null);
  }, [effectivePermissionMode, setPendingCommand, usingLocalAgent]);

  const contextSummary = useMemo(() => {
    const selected = context.selectedText?.trim();
    const recent = context.recentOutput?.trim();
    if (selected && recent) return t("ai.contextSummary", { selected: selected.length, recent: recent.length });
    if (selected) return t("ai.contextSelectedSummary", { count: selected.length });
    if (recent) return t("ai.contextRecentSummary", { count: recent.length });
    return "";
  }, [context, t]);

  const messageLabel: Record<AiMessageRole, string> = {
    user: t("ai.role.user"),
    assistant: t("ai.role.assistant"),
    system: t("ai.role.system"),
    error: t("ai.role.error"),
  };
  const toolStatusLabel: Record<AiConversationToolActivity["status"], string> = {
    running: t("ai.tool.running"),
    completed: t("ai.tool.completed"),
    timedOut: t("ai.tool.timedOut"),
    failed: t("ai.tool.failed"),
    rejected: t("ai.tool.rejected"),
    cancelled: t("ai.tool.cancelled"),
  };

  const readContext = useCallback(async (kind: "selectedText" | "recentOutput") => {
    const scope = terminalScope;
    const getter = kind === "selectedText" ? getSelectedTerminalText : getRecentTerminalOutput;
    if (!scope || !scope.connected || !getter) {
      setNotice(t("ai.noConnectedTerminal"));
      return;
    }
    const requestedScopeKey = aiConversationScopeKey(scope);
    try {
      const value = await getter(scope);
      if (renderedScopeKeyRef.current !== requestedScopeKey) return;
      if (typeof value === "string" && value.trim()) {
        setScopedContext((current) => ({
          scopeKey: requestedScopeKey,
          value: {
            context: {
              ...(current.scopeKey === requestedScopeKey ? current.value.context : {}),
              [kind]: value,
              terminalLabel: scope.label,
              terminalProtocol: scope.protocol,
            },
            terminalScope: scope,
          },
        }));
        setNotice(kind === "selectedText" ? t("ai.selectionAdded") : t("ai.outputAdded"));
      } else {
        setNotice(kind === "selectedText" ? t("ai.noSelection") : t("ai.noRecentOutput"));
      }
    } catch {
      if (renderedScopeKeyRef.current !== requestedScopeKey) return;
      setNotice(t("ai.contextReadFailed"));
    }
  }, [getRecentTerminalOutput, getSelectedTerminalText, setNotice, t, terminalScope]);

  const processAgentStep = useCallback(async (
    initialStep: NativeAiAgentTurnStep,
    target: AiConversationTarget,
    scope: AiTerminalScope | undefined,
    controller: AbortController,
  ): Promise<boolean> => {
    let step = initialStep;
    while (!controller.signal.aborted) {
      if (step.kind === "completed") {
        activeAgentTurnIdRef.current = null;
        const content = step.content || t("ai.emptyResponse");
        setConversationState((current) => appendAiConversationMessage(
          current,
          target,
          {
            id: makeId(),
            role: "assistant",
            content,
          },
        ));
        return false;
      }

      // Retain the discriminated tool-call branch across the async callbacks
      // below. `step` is reassigned after `continue`, so TypeScript cannot
      // safely keep its narrowing inside state-updater closures.
      const toolStep = step;
      activeAgentTurnIdRef.current = toolStep.turnId;
      if (!scope || !sameToolScope(scope, toolStep.call.scope)) {
        cancelActiveAgentTurn();
        throw new Error("AI_TERMINAL_SCOPE_INVALID");
      }
      const activityMessageId = makeId();
      const activity = terminalToolActivity(toolStep, "running");
      setConversationState((current) => appendAiConversationMessage(
        current,
        target,
        {
          id: activityMessageId,
          role: "assistant",
          content: toolStep.content?.trim() ?? "",
          toolActivity: activity,
        },
      ));
      if (toolStep.approvalRequired) {
        setPendingAgentApproval(Object.freeze({
          step: toolStep,
          scope,
          target,
          controller,
          activityMessageId,
          expiresAt: Date.now() + AI_AGENT_APPROVAL_TTL_MS,
        }));
        setNotice(null);
        return true;
      }

      try {
        await nativeAiAgentTransport.authorize(
          toolStep.turnId,
          toolStep.call.id,
          toolStep.call.scope,
          false,
          controller.signal,
        );
      } catch (reason) {
        setConversationState((current) => updateAiConversationMessage(
          current,
          target,
          activityMessageId,
          { toolActivity: terminalToolActivity(toolStep, controller.signal.aborted ? "cancelled" : "failed", "AI_TOOL_AUTHORIZATION_FAILED") },
        ));
        throw reason;
      }

      let result: Readonly<{ output: string; timedOut: boolean; errorCode?: string }>;
      if (!sendApprovedCommand) {
        result = { output: "", timedOut: false, errorCode: "TERMINAL_SEND_PROTOCOL_UNSUPPORTED" };
      } else {
        try {
          result = await executeAndCaptureAiTerminalTool(
            scope,
            toolStep.call.command,
            sendApprovedCommand,
            getRecentTerminalOutput,
            controller.signal,
          );
        } catch (reason) {
          if (controller.signal.aborted) {
            setConversationState((current) => updateAiConversationMessage(
              current,
              target,
              activityMessageId,
              { toolActivity: terminalToolActivity(toolStep, "cancelled") },
            ));
            throw reason;
          }
          result = {
            output: "",
            timedOut: false,
            errorCode: terminalToolErrorCode(reason),
          };
        }
      }
      setConversationState((current) => updateAiConversationMessage(
        current,
        target,
        activityMessageId,
        {
          toolActivity: terminalToolActivity(
            toolStep,
            result.timedOut ? "timedOut" : result.errorCode ? "failed" : "completed",
            result.errorCode,
          ),
        },
      ));
      step = await nativeAiAgentTransport.continue(
        toolStep.turnId,
        toolStep.call.id,
        toolStep.call.scope,
        result,
        controller.signal,
      );
    }
    throw new DOMException("AI turn aborted", "AbortError");
  }, [cancelActiveAgentTurn, getRecentTerminalOutput, sendApprovedCommand, setNotice, t]);

  const stop = useCallback(() => {
    if (!busy) return;
    const streamingAssistant = activeStreamingAssistantRef.current;
    cancelActiveAgentTurn();
    abortRef.current?.abort();
    abortRef.current = null;
    activeStreamingAssistantRef.current = null;
    setStreamingAssistantMessageId(null);
    if (streamingAssistant && !streamingAssistant.content) {
      setConversationState((current) => deleteAiConversationMessage(
        current,
        streamingAssistant.target,
        streamingAssistant.messageId,
      ));
    }
    setPendingAgentApproval(null);
    setBusyTarget(null);
    setNotice(usingLocalAgent ? t("ai.localAgent.stopped") : t("ai.stopped"));
  }, [busy, cancelActiveAgentTurn, setNotice, t, usingLocalAgent]);

  const clear = useCallback(() => {
    if (busy && !currentConversationBusy) return;
    const target = currentConversationTarget;
    if (target && currentConversationBusy) {
      cancelActiveAgentTurn();
      abortRef.current?.abort();
      abortRef.current = null;
      activeStreamingAssistantRef.current = null;
      setStreamingAssistantMessageId(null);
      setPendingAgentApproval(null);
      setBusyTarget(null);
    }
    if (target) {
      setConversationState((current) => {
        if (!getAiConversation(current, target)) return current;
        const scope = getAiConversationScope(current, target.scopeKey);
        const withoutTarget = deleteAiConversation(current, target);
        return (scope?.conversations.length ?? 0) <= 1
          ? withoutTarget
          : createAiConversation(withoutTarget, target.scopeKey);
      });
    }
    setInput("");
    clearDraftImages();
    setPendingCommand(null);
    setShowHistory(false);
    setNotice(null);
  }, [busy, cancelActiveAgentTurn, clearDraftImages, currentConversationBusy, currentConversationTarget, setInput, setNotice, setPendingCommand]);

  const newConversation = useCallback(() => {
    if (busy) return;
    setConversationState((current) => createAiConversation(current, currentScopeKey));
    setInput("");
    clearDraftImages();
    setPendingCommand(null);
    setShowHistory(false);
    setNotice(null);
  }, [busy, clearDraftImages, currentScopeKey, setInput]);

  const selectConversation = useCallback((conversationId: string) => {
    if (busy) return;
    setConversationState((current) => switchAiConversation(current, {
      scopeKey: currentScopeKey,
      conversationId,
    }));
    setInput("");
    clearDraftImages();
    setPendingCommand(null);
    setShowHistory(false);
    setNotice(null);
  }, [busy, clearDraftImages, currentScopeKey, setInput]);

  const deleteConversation = useCallback((conversationId: string) => {
    if (busy) return;
    const deletingCurrent = conversationId === currentConversationTarget?.conversationId;
    setConversationState((current) => deleteAiConversation(current, {
      scopeKey: currentScopeKey,
      conversationId,
    }));
    if (deletingCurrent) {
      setInput("");
      clearDraftImages();
      setPendingCommand(null);
      setNotice(null);
    }
  }, [busy, clearDraftImages, currentConversationTarget, currentScopeKey, setInput, setNotice, setPendingCommand]);

  const submit = useCallback(async () => {
    const requestImages = draftImages;
    const content = input.trim() || (requestImages.length > 0
      ? hasSendableContext
        ? t("ai.image.contextOnlyPrompt")
        : t("ai.image.onlyPrompt")
      : hasSendableContext ? t("ai.contextOnlyPrompt") : "");
    // React state updates after the event returns; the ref closes the same-frame
    // double-submit gap before `busy` can re-render the composer.
    if (
      !content
      || busy
      || permissionSaving
      || permissionSaveInFlightRef.current
      || pendingProviderSelectionRef.current
      || abortRef.current
    ) return;
    const capturedConversation = currentConversationTarget;
    if (!capturedConversation) {
      setConversationState((current) => activateAiConversationScope(current, terminalScope));
      return;
    }
    const requestLocalAgent = selectedAssistantEngine === "builtin"
      ? null
      : localAgents.find((candidate) => candidate.id === selectedAssistantEngine) ?? null;
    const requestUsesLocalAgent = selectedAssistantEngine !== "builtin";
    if (!requestUsesLocalAgent && !selectedProvider) {
      setNotice(t("ai.noProviderConfigured"));
      return;
    }
    if (requestImages.length > 0 && !imageInputEnabled) {
      setNotice(imageInputDisabledReason);
      return;
    }
    if (
      requestUsesLocalAgent
      && (!requestLocalAgent || !requestLocalAgent.runtimeSupported || !requestLocalAgent.available || !localAgentComplete)
    ) {
      setNotice(t("ai.localAgent.notAvailable"));
      return;
    }
    const requestProviderProfileId = requestUsesLocalAgent
      ? `local-agent:${requestLocalAgent!.id}`
      : selectedProvider?.id ?? "";
    const requestScope = terminalScope ? Object.freeze({ ...terminalScope }) : undefined;
    const requestScopeKey = aiConversationScopeKey(requestScope);
    if (capturedConversation.scopeKey !== requestScopeKey) return;
    const userMessage = Object.freeze({
      id: makeId(),
      role: "user",
      content,
      ...(requestImages.length > 0 ? {
        attachments: Object.freeze(requestImages.map((image) => Object.freeze({
          id: image.id,
          name: image.name,
          mimeType: image.mimeType,
          size: image.size,
          data: image.data,
        }))),
      } : {}),
    });
    const nextConversationState = appendAiConversationMessage(
      switchAiConversation(conversationState, capturedConversation),
      capturedConversation,
      userMessage,
    );
    const requestConversation = getAiConversation(nextConversationState, capturedConversation);
    if (!requestConversation) return;
    const requestHasImageContent = requestConversation.messages.some((message) => (
      message.attachments?.some((attachment) => Boolean(attachment.data))
    ));
    if (requestHasImageContent && !imageInputEnabled) {
      setNotice(imageInputDisabledReason);
      return;
    }
    const requestAgent = !requestUsesLocalAgent
      && !requestHasImageContent
      && selectedProviderSupportsTools
      && assistantMode !== "explain"
      && selectedPermissionMode !== "observer"
      && requestScope?.connected
      && requestScope.commandExecutionSupported
      ? agent
      : null;
    const assistantMessageId = requestAgent ? null : makeId();
    const publishedConversationState = assistantMessageId
      ? appendAiConversationMessage(
          nextConversationState,
          capturedConversation,
          { id: assistantMessageId, role: "assistant", content: "" },
        )
      : nextConversationState;
    const attachedContext = contextScope
      && aiConversationScopeKey(contextScope) === aiConversationScopeKey(requestScope)
      ? context
      : {};
    const requestContext: AiWorkspaceContext = Object.freeze({
      ...attachedContext,
      ...(requestScope ? {
        terminalLabel: requestScope.label,
        terminalProtocol: requestScope.protocol,
      } : {}),
    });
    setConversationState(publishedConversationState);
    setInput("");
    clearDraftImages();
    setShowHistory(false);
    setNotice(t("ai.generating"));
    setBusyTarget(capturedConversation);
    const controller = new AbortController();
    abortRef.current = controller;
    if (assistantMessageId) {
      activeStreamingAssistantRef.current = {
        controller,
        target: capturedConversation,
        messageId: assistantMessageId,
        content: "",
      };
      setStreamingAssistantMessageId(assistantMessageId);
    }
    let pausedForApproval = false;
    try {
      const completionRequest: AiCompletionRequest = {
        providerProfileId: requestProviderProfileId,
        assistantMode,
        commandPermissionMode: requestHasImageContent || requestUsesLocalAgent || !selectedProviderSupportsTools
          ? "observer"
          : selectedPermissionMode,
        locale,
        messages: requestConversation.messages.map(({ role, content: body, attachments }) => ({
          role,
          content: body,
          ...(attachments?.some((attachment) => attachment.data) ? {
            contentParts: attachments.flatMap((attachment) => attachment.data ? [{
              type: "image" as const,
              mimeType: attachment.mimeType,
              data: attachment.data,
            }] : []),
          } : {}),
        })),
        context: requestContext,
        terminalScope: requestScope,
        ...(!requestUsesLocalAgent
          && selectedProviderSupportsThinking
          && thinkingEffort !== "off"
          ? { reasoningEffort: thinkingEffort }
          : {}),
      };
      if (requestAgent) {
        const step = await requestAgent(completionRequest, controller.signal);
        pausedForApproval = await processAgentStep(
          step,
          capturedConversation,
          requestScope,
          controller,
        );
      } else {
        if (!assistantMessageId) throw new Error("AI_STREAM_TARGET_INVALID");
        const publishDelta = (delta: string) => {
          const active = activeStreamingAssistantRef.current;
          if (
            !delta
            || controller.signal.aborted
            || abortRef.current !== controller
            || !active
            || active.controller !== controller
            || active.messageId !== assistantMessageId
            || !sameConversationTarget(active.target, capturedConversation)
            || capturedConversation.scopeKey !== requestScopeKey
          ) return;
          active.content += delta;
          const nextContent = active.content;
          setConversationState((current) => updateAiConversationMessage(
            current,
            capturedConversation,
            assistantMessageId,
            { content: nextContent },
          ));
        };
        const answer = requestUsesLocalAgent
          ? await localAgentComplete!(requestLocalAgent!.id, completionRequest, controller.signal, publishDelta)
          : await complete(completionRequest, controller.signal, publishDelta);
        if (controller.signal.aborted || abortRef.current !== controller) return;
        const active = activeStreamingAssistantRef.current;
        if (
          !active
          || active.controller !== controller
          || active.messageId !== assistantMessageId
          || !sameConversationTarget(active.target, capturedConversation)
        ) return;
        const finalContent = answer || active.content || t("ai.emptyResponse");
        active.content = finalContent;
        setConversationState((current) => updateAiConversationMessage(
          current,
          capturedConversation,
          assistantMessageId,
          { content: finalContent },
        ));
      }
    } catch (reason) {
      if (!controller.signal.aborted) {
        cancelActiveAgentTurn();
        const error = localizeAiError(reason, t);
        setConversationState((current) => assistantMessageId
          ? updateAiConversationMessage(
              current,
              capturedConversation,
              assistantMessageId,
              { role: "error", content: error },
            )
          : appendAiConversationMessage(
              current,
              capturedConversation,
              { id: makeId(), role: "error", content: error },
            ));
      }
    } finally {
      const active = activeStreamingAssistantRef.current;
      if (active?.controller === controller) {
        activeStreamingAssistantRef.current = null;
        setStreamingAssistantMessageId((current) => (
          current === active.messageId ? null : current
        ));
      }
      if (!pausedForApproval && abortRef.current === controller) {
        abortRef.current = null;
        setBusyTarget(null);
        setNotice(null);
      }
    }
  }, [agent, assistantMode, busy, cancelActiveAgentTurn, clearDraftImages, complete, context, contextScope, conversationState, currentConversationTarget, draftImages, hasSendableContext, imageInputDisabledReason, imageInputEnabled, input, localAgentComplete, localAgents, locale, permissionSaving, processAgentStep, selectedAssistantEngine, selectedPermissionMode, selectedProvider, selectedProviderSupportsThinking, selectedProviderSupportsTools, setInput, setNotice, t, terminalScope, thinkingEffort]);

  const resolveAgentApproval = useCallback(async (approved: boolean) => {
    const pending = pendingAgentApproval;
    if (!pending || runningAgentToolRef.current) return;
    runningAgentToolRef.current = true;
    setAgentApprovalRunning(true);
    setPendingAgentApproval(null);
    let pausedAgain = false;
    try {
      let result: Readonly<{ output: string; timedOut: boolean; errorCode?: string }>;
      if (!approved) {
        result = { output: "", timedOut: false, errorCode: "AI_TOOL_APPROVAL_REJECTED" };
        setConversationState((current) => updateAiConversationMessage(
          current,
          pending.target,
          pending.activityMessageId,
          { toolActivity: terminalToolActivity(pending.step, "rejected", result.errorCode) },
        ));
      } else {
        try {
          await nativeAiAgentTransport.authorize(
            pending.step.turnId,
            pending.step.call.id,
            pending.step.call.scope,
            true,
            pending.controller.signal,
          );
        } catch (reason) {
          setConversationState((current) => updateAiConversationMessage(
            current,
            pending.target,
            pending.activityMessageId,
            {
              toolActivity: terminalToolActivity(
                pending.step,
                pending.controller.signal.aborted ? "cancelled" : "failed",
                "AI_TOOL_AUTHORIZATION_FAILED",
              ),
            },
          ));
          throw reason;
        }
        if (!sendApprovedCommand) {
          result = { output: "", timedOut: false, errorCode: "TERMINAL_SEND_PROTOCOL_UNSUPPORTED" };
        } else {
          try {
            result = await executeAndCaptureAiTerminalTool(
              pending.scope,
              pending.step.call.command,
              sendApprovedCommand,
              getRecentTerminalOutput,
              pending.controller.signal,
            );
          } catch (reason) {
            if (pending.controller.signal.aborted) {
              setConversationState((current) => updateAiConversationMessage(
                current,
                pending.target,
                pending.activityMessageId,
                { toolActivity: terminalToolActivity(pending.step, "cancelled") },
              ));
              throw reason;
            }
            result = {
              output: "",
              timedOut: false,
              errorCode: terminalToolErrorCode(reason),
            };
          }
        }
        setConversationState((current) => updateAiConversationMessage(
          current,
          pending.target,
          pending.activityMessageId,
          {
            toolActivity: terminalToolActivity(
              pending.step,
              result.timedOut ? "timedOut" : result.errorCode ? "failed" : "completed",
              result.errorCode,
            ),
          },
        ));
      }
      const step = await nativeAiAgentTransport.continue(
        pending.step.turnId,
        pending.step.call.id,
        pending.step.call.scope,
        result,
        pending.controller.signal,
      );
      pausedAgain = await processAgentStep(
        step,
        pending.target,
        pending.scope,
        pending.controller,
      );
    } catch (reason) {
      if (!pending.controller.signal.aborted) {
        cancelActiveAgentTurn();
        setConversationState((current) => appendAiConversationMessage(
          current,
          pending.target,
          {
            id: makeId(),
            role: "error",
            content: localizeAiError(reason, t),
          },
        ));
      }
    } finally {
      runningAgentToolRef.current = false;
      setAgentApprovalRunning(false);
      if (!pausedAgain && abortRef.current === pending.controller) {
        abortRef.current = null;
        setBusyTarget(null);
        setNotice(null);
      }
    }
  }, [cancelActiveAgentTurn, getRecentTerminalOutput, pendingAgentApproval, processAgentStep, sendApprovedCommand, setNotice, t]);

  const dispatchCommand = useCallback(async (approval: PendingCommand) => {
    if (!sendApprovedCommand || runningCommandRef.current) return;
    runningCommandRef.current = approval;
    setRunningCommandId(approval.proposal.id);
    try {
      const sent = await confirmAiCommandApproval(approval, sendApprovedCommand);
      if (!sent) return;
      setPendingCommand(null);
      setNotice(t("ai.commandSent", { target: approval.scope.label }));
    } catch (reason) {
      const code = reason instanceof Error ? reason.message : String(reason);
      if (code.includes("STALE") || code.includes("NOT_FOUND")) {
        setNotice(t("ai.commandTargetChanged"));
      } else if (code.includes("NOT_CONNECTED") || code.includes("CLOSING")) {
        setNotice(t("ai.commandTargetDisconnected"));
      } else {
        setNotice(t("ai.commandFailed"));
      }
    } finally {
      if (runningCommandRef.current === approval) {
        runningCommandRef.current = null;
        setRunningCommandId(null);
      }
    }
  }, [sendApprovedCommand, setNotice, setPendingCommand, t]);

  const runCommandProposal = useCallback((proposal: AiCommandProposal) => {
    if (
      usingLocalAgent
      ||
      effectivePermissionMode === "observer"
      || !terminalScope?.connected
      || !terminalScope.commandExecutionSupported
      || !sendApprovedCommand
      || runningCommandRef.current
    ) return;
    const approval = stageAiCommandApproval(proposal, terminalScope);
    if (effectivePermissionMode === "auto") {
      void dispatchCommand(approval);
    } else {
      setPendingCommand(approval);
    }
  }, [dispatchCommand, effectivePermissionMode, sendApprovedCommand, setPendingCommand, terminalScope, usingLocalAgent]);

  const approveCommand = useCallback(() => {
    if (pendingCommand) void dispatchCommand(pendingCommand);
  }, [dispatchCommand, pendingCommand]);

  const selectAssistantEngine = useCallback((engineId: "builtin" | NativeLocalAiAgentId) => {
    if (busy || permissionSaving || permissionSaveInFlightRef.current) return;
    if (engineId !== "builtin") {
      const candidate = localAgents.find((item) => item.id === engineId);
      if (!candidate?.runtimeSupported || !candidate.available || !localAgentComplete) return;
    }
    setSelectedAssistantEngine(engineId);
    setPendingCommand(null);
    setNotice(null);
  }, [busy, localAgentComplete, localAgents, permissionSaving, setNotice, setPendingCommand]);

  const selectProvider = useCallback((providerProfileId: string) => {
    if (busy || permissionSaving || permissionSaveInFlightRef.current || !providers.some((provider) => provider.id === providerProfileId && provider.enabled)) return;
    setSelectedProviderProfileId(providerProfileId);
    if (!onSelectProvider) return;

    const sequence = ++providerSelectionSequenceRef.current;
    pendingProviderSelectionRef.current = { sequence, providerProfileId };
    const modelQueueAtSelection = modelSelectionQueueRef.current;
    const persistSelection = async () => {
      await modelQueueAtSelection;
      try {
        await onSelectProvider(providerProfileId);
        if (pendingProviderSelectionRef.current?.sequence === sequence) {
          pendingProviderSelectionRef.current = null;
        }
      } catch {
        if (pendingProviderSelectionRef.current?.sequence !== sequence) return;
        pendingProviderSelectionRef.current = null;
        setSelectedProviderProfileId(enabledProviderProfileId(
          renderedProvidersRef.current,
          renderedActiveProviderProfileIdRef.current,
        ));
        setNotice(t("ai.settingsApplyFailed"));
      }
    };
    const queued = providerSelectionQueueRef.current.then(persistSelection);
    providerSelectionQueueRef.current = queued;
  }, [busy, onSelectProvider, permissionSaving, providers, setNotice, t]);

  const selectProviderModel = useCallback((modelId: string) => {
    if (busy || permissionSaving) return;
    const profileId = renderedSelectedProviderProfileIdRef.current;
    const provider = renderedProvidersRef.current.find((candidate) => (
      candidate.id === profileId && candidate.enabled
    ));
    if (!provider) return;
    const catalog = modelCatalogCacheRef.current.get(profileId);
    if (!catalog?.includes(modelId) && modelId !== provider.model) return;

    const previousModel = modelOverridesRef.current[profileId] ?? provider.model;
    if (previousModel === modelId) return;
    const sequence = (modelSelectionSequenceRef.current.get(profileId) ?? 0) + 1;
    modelSelectionSequenceRef.current.set(profileId, sequence);
    const optimisticModels = { ...modelOverridesRef.current, [profileId]: modelId };
    modelOverridesRef.current = optimisticModels;
    setModelOverrides(optimisticModels);
    const providerQueueAtSelection = providerSelectionQueueRef.current;

    const persistSelection = async () => {
      await providerQueueAtSelection;
      try {
        await persistAiProviderModel(settingsAdapter, profileId, modelId);
      } catch {
        if (modelSelectionSequenceRef.current.get(profileId) !== sequence) return;
        setModelOverrides((current) => {
          const next = { ...current };
          const persistedModel = renderedProvidersRef.current.find(({ id }) => id === profileId)?.model;
          if (persistedModel === previousModel) delete next[profileId];
          else next[profileId] = previousModel;
          modelOverridesRef.current = next;
          return next;
        });
        setNotice(t("ai.settingsApplyFailed"));
      }
    };
    const queued = modelSelectionQueueRef.current.then(persistSelection);
    modelSelectionQueueRef.current = queued;
  }, [busy, permissionSaving, setNotice, settingsAdapter, t]);

  const retryProviderModels = useCallback(() => {
    const profileId = renderedSelectedProviderProfileIdRef.current;
    if (profileId) void loadProviderModels(profileId, true);
  }, [loadProviderModels]);

  const selectThinkingEffort = useCallback((value: AiThinkingEffort) => {
    if (busy || permissionSaving || !selectedProviderSupportsThinking) return;
    setThinkingEffort(value);
  }, [busy, permissionSaving, selectedProviderSupportsThinking]);

  const savePermissionMode = useCallback((mode: AiCommandPermissionMode): Promise<boolean> => {
    if (!onCommandPermissionModeChange) return Promise.resolve(false);
    if (mode === selectedPermissionMode && !permissionSaveInFlightRef.current) {
      return Promise.resolve(true);
    }
    if (permissionSaveInFlightRef.current) return permissionSaveInFlightRef.current;

    const previousMode = persistedPermissionModeRef.current;
    setSelectedPermissionMode(mode);
    setPermissionSaving(true);
    const operation = Promise.resolve()
      .then(() => onCommandPermissionModeChange(mode))
      .then(() => {
        persistedPermissionModeRef.current = mode;
        setSelectedPermissionMode(mode);
        return true;
      })
      .catch(() => {
        setSelectedPermissionMode(previousMode);
        setNotice(t("ai.settingsApplyFailed"));
        return false;
      })
      .finally(() => {
        if (permissionSaveInFlightRef.current === operation) {
          permissionSaveInFlightRef.current = null;
          setPermissionSaving(false);
        }
      });
    permissionSaveInFlightRef.current = operation;
    return operation;
  }, [onCommandPermissionModeChange, selectedPermissionMode, setNotice, t]);

  const selectPermissionMode = useCallback((mode: AiCommandPermissionMode) => {
    if (busy || permissionSaving || permissionSaveInFlightRef.current) return;
    void savePermissionMode(mode);
  }, [busy, permissionSaving, savePermissionMode]);

  const approveAgentAlways = useCallback(async () => {
    if (permissionSaving || runningAgentToolRef.current) return;
    if (await savePermissionMode("auto")) {
      await resolveAgentApproval(true);
    }
  }, [permissionSaving, resolveAgentApproval, savePermissionMode]);

  const historyItems = useMemo(() => (
    [...(currentConversationScope?.conversations ?? [])]
      .sort((left, right) => right.updatedOrder - left.updatedOrder)
      .map((conversation) => ({
        id: conversation.id,
        title: conversation.title || t("ai.untitledConversation"),
        messageCount: conversation.messages.length,
        active: conversation.id === currentConversationScope?.activeConversationId,
      }))
  ), [currentConversationScope, t]);

  const selectedCatalog = selectedProvider && modelCatalog.profileId === selectedProvider.id
    ? modelCatalog
    : null;
  const composerModelIds = selectedProvider
    ? [...new Set([selectedProviderModel, ...(selectedCatalog?.models ?? [])])].filter(Boolean)
    : [];
  const composerModels = composerModelIds.map((id) => ({ id }));
  const composerContextUsage = useMemo(() => {
    if (!assistantReady) return undefined;
    const draftContent = input.trim() || (draftImages.length > 0
      ? hasSendableContext
        ? t("ai.image.contextOnlyPrompt")
        : t("ai.image.onlyPrompt")
      : hasSendableContext ? t("ai.contextOnlyPrompt") : "");
    const previewMessages: AiCompletionRequest["messages"] = [
      ...messages.map(({ role, content }) => ({ role, content })),
      ...(draftContent ? [{ role: "user" as const, content: draftContent }] : []),
    ];
    const attachedContext = contextScope
      && aiConversationScopeKey(contextScope) === currentScopeKey
      ? context
      : {};
    const requestContext: AiWorkspaceContext = {
      ...attachedContext,
      ...(terminalScope ? {
        terminalLabel: terminalScope.label,
        terminalProtocol: terminalScope.protocol,
      } : {}),
    };
    const projectedMessages = buildAiMessages({
      providerProfileId: usingLocalAgent ? "local-agent" : selectedProvider?.id ?? "",
      assistantMode,
      commandPermissionMode: hasCurrentImageContent || usingLocalAgent || !selectedProviderSupportsTools
        ? "observer"
        : selectedPermissionMode,
      locale,
      messages: previewMessages,
      context: requestContext,
      ...(terminalScope ? { terminalScope } : {}),
    });
    return createAiContextUsage(
      projectedMessages,
      usingLocalAgent ? "" : selectedProviderModel,
      hasCurrentImageContent,
    );
  }, [
    assistantMode,
    assistantReady,
    context,
    contextScope,
    currentScopeKey,
    draftImages.length,
    hasCurrentImageContent,
    hasSendableContext,
    input,
    locale,
    messages,
    selectedPermissionMode,
    selectedProvider?.id,
    selectedProviderModel,
    selectedProviderSupportsTools,
    t,
    terminalScope,
    usingLocalAgent,
  ]);

  const composerEngine: AiComposerEngine = usingLocalAgent
    ? {
        kind: "local",
        label: selectedLocalAgentLabel,
      }
    : {
        kind: "builtin",
        provider: {
          value: selectedProvider?.id ?? "",
          profiles: composerProviders,
          onSelect: selectProvider,
          ...(selectedProvider ? {
            modelValue: selectedProviderModel,
            models: composerModels,
            modelsLoading: selectedCatalog === null || selectedCatalog.status === "loading",
            ...(selectedCatalog?.status === "error"
              ? { modelsError: t("ai.settings.modelsFailed") }
              : {}),
            onSelectModel: selectProviderModel,
            onRetryModels: retryProviderModels,
          } : {}),
          ...(onOpenSettings ? { onOpenSettings } : {}),
        },
        permission: {
          value: hasCurrentImageContent ? "observer" : effectivePermissionMode,
          changeAllowed: Boolean(
            !hasCurrentImageContent
            && onCommandPermissionModeChange
            && selectedProviderSupportsTools
          ),
          onSelect: selectPermissionMode,
          ...(hasCurrentImageContent
            ? { disabledReason: t("ai.permission.imageObserverOnly") }
            : selectedProvider && !selectedProviderSupportsTools
            ? { disabledReason: t("ai.permission.protocolToolUnsupported") }
            : {}),
        },
      };

  return (
    <section className="ai-workspace" aria-label={t("ai.title")} data-testid="ai-workspace">
      <header className="ai-workspace-header">
        <div className="ai-agent-identity">
          <AiAgentMenu
            value={selectedAssistantEngine}
            agents={localAgents}
            localRuntimeAvailable={localAgentComplete !== null}
            disabled={busy || permissionSaving}
            builtinSubtitle={terminalScope?.connected ? t("ai.agentConnected") : t("ai.agentChatOnly")}
            t={t}
            onSelect={(agentId) => selectAssistantEngine(agentId as "builtin" | NativeLocalAiAgentId)}
            onOpenSettings={onOpenSettings}
          />
        </div>
        <div className="ai-workspace-actions">
          <button
            type="button"
            className={showHistory ? "is-active" : undefined}
            aria-controls="ai-conversation-history"
            aria-expanded={showHistory}
            aria-label={showHistory ? t("ai.hideConversationHistory") : t("ai.conversationHistory")}
            title={showHistory ? t("ai.hideConversationHistory") : t("ai.conversationHistory")}
            onClick={() => setShowHistory((current) => !current)}
          >
            <AiGlyph name="history" />
          </button>
          <button type="button" className="is-new" disabled={busy} aria-label={t("ai.newConversation")} title={t("ai.newConversation")} onClick={newConversation}>
            <AiGlyph name="new" />
          </button>
          <button
            type="button"
            aria-label={t("ai.clear")}
            title={t("ai.clear")}
            onClick={clear}
            disabled={(busy && !currentConversationBusy) || (messages.length === 0 && !currentConversationBusy)}
          >
            <AiGlyph name="clear" />
          </button>
          {onClose ? (
            <button type="button" aria-label={t("ai.closePanel")} title={t("ai.closePanel")} onClick={onClose}>
              <AiGlyph name="close" />
            </button>
          ) : null}
        </div>
      </header>

      {showHistory ? (
        <AiConversationHistory
          items={historyItems}
          disabled={busy}
          labels={{
            regionLabel: t("ai.conversationHistory"),
            title: t("ai.conversationHistory"),
            newConversation: t("ai.newConversation"),
            empty: t("ai.conversationHistoryEmpty"),
            messageCount: t("ai.conversationMessageCount"),
            selectConversation: t("ai.selectConversation"),
            deleteConversation: t("ai.deleteConversation"),
            delete: t("ai.delete"),
          }}
          onNew={newConversation}
          onSelect={selectConversation}
          onDelete={deleteConversation}
        />
      ) : (
        <div className="ai-workspace-messages" role="log" aria-live="polite" data-testid="ai-messages">
          {messages.length === 0 ? (
            <div className="ai-workspace-empty">
              <div className="ai-empty-intro">
                <span className="ai-empty-mark"><AiGlyph name="spark" /></span>
                <div>
                  <h3>{t("ai.emptyTitle")}</h3>
                  <p>{assistantReady
                    ? t("ai.emptyDescription")
                    : usingLocalAgent ? t("ai.localAgent.notAvailable") : t("ai.noProviderConfigured")}</p>
                </div>
              </div>
              {assistantReady ? (
                <div className="ai-empty-suggestions" aria-label={t("ai.suggestions")}>
                  <button type="button" aria-label={t("ai.suggestion.explain")} title={t("ai.suggestion.explainPrompt")} onClick={() => setInput(t("ai.suggestion.explainPrompt"))}>
                    <span className="ai-suggestion-icon" aria-hidden="true"><AiGlyph name="context" /></span>
                    <span className="ai-suggestion-copy">
                      <strong>{t("ai.suggestion.explain")}</strong>
                      <small>{t("ai.suggestion.explainPrompt")}</small>
                    </span>
                  </button>
                  <button type="button" aria-label={t("ai.suggestion.diagnose")} title={t("ai.suggestion.diagnosePrompt")} onClick={() => setInput(t("ai.suggestion.diagnosePrompt"))}>
                    <span className="ai-suggestion-icon" aria-hidden="true"><AiGlyph name="spark" /></span>
                    <span className="ai-suggestion-copy">
                      <strong>{t("ai.suggestion.diagnose")}</strong>
                      <small>{t("ai.suggestion.diagnosePrompt")}</small>
                    </span>
                  </button>
                  <button type="button" aria-label={t("ai.suggestion.command")} title={t("ai.suggestion.commandPrompt")} onClick={() => setInput(t("ai.suggestion.commandPrompt"))}>
                    <span className="ai-suggestion-icon" aria-hidden="true"><AiGlyph name="terminal" /></span>
                    <span className="ai-suggestion-copy">
                      <strong>{t("ai.suggestion.command")}</strong>
                      <small>{t("ai.suggestion.commandPrompt")}</small>
                    </span>
                  </button>
                </div>
              ) : onOpenSettings && !usingLocalAgent ? (
                <button type="button" className="ai-primary-action" onClick={onOpenSettings}>{t("ai.openSettings")}</button>
              ) : null}
            </div>
          ) : null}
          {messages.map((message) => {
            const proposals = message.role === "assistant"
              ? extractAiCommandProposals(message.content)
              : [];
            const isStreamingAssistant = currentConversationBusy
              && message.id === streamingAssistantMessageId;
            return (
              <article key={message.id} className={`ai-message ai-message-${message.role}`}>
                <span className="ai-message-avatar" aria-hidden="true">
                  {message.role === "user" ? t("ai.userInitial") : <AiGlyph name="spark" />}
                </span>
                <div className="ai-message-body">
                  <strong>{messageLabel[message.role]}</strong>
                  {isStreamingAssistant && !message.content ? (
                    <span className="ai-thinking-dots" aria-hidden="true"><i /><i /><i /></span>
                  ) : message.content ? (
                    <AiMarkdown
                      content={message.content}
                      labels={{ copyCode: t("ai.copyCode"), copiedCode: t("ai.copiedCode") }}
                    />
                  ) : null}
                  {message.toolActivity ? (
                    <section
                      className="ai-tool-activity"
                      data-status={message.toolActivity.status}
                      aria-label={`${t("ai.tool.terminalExecute")} · ${toolStatusLabel[message.toolActivity.status]}`}
                    >
                      <span className="ai-tool-activity-icon" aria-hidden="true"><AiGlyph name="terminal" /></span>
                      <code title={message.toolActivity.command}>{message.toolActivity.command}</code>
                      <span className="ai-tool-activity-status">
                        <b aria-hidden="true">{message.toolActivity.status === "completed" ? "✓" : message.toolActivity.status === "running" ? "…" : "!"}</b>
                        {toolStatusLabel[message.toolActivity.status]}
                      </span>
                    </section>
                  ) : null}
                  {message.attachments?.length ? (
                    <div className="ai-message-attachments" aria-label={t("ai.image.messageList")}>
                      {message.attachments.map((attachment) => (
                        <span className="ai-message-attachment" key={attachment.id} title={attachment.name}>
                          <AiGlyph name="image" />
                          <b>{attachment.name}</b>
                          <small>{t("ai.image.sizeKib", { count: Math.max(1, Math.ceil(attachment.size / 1024)) })}</small>
                        </span>
                      ))}
                    </div>
                  ) : null}
                  {proposals.map((proposal) => (
                    <section className="ai-command-proposal" key={proposal.id}>
                      <span><AiGlyph name="terminal" /> {terminalScope?.label ?? t("ai.noCommandTarget")}</span>
                      {usingLocalAgent || effectivePermissionMode === "observer" ? (
                        <small>{usingLocalAgent
                          ? t("ai.localAgent.commandDisabled")
                          : t("ai.commandExecutionDenied")}</small>
                      ) : (
                        <button
                          type="button"
                          disabled={permissionSaving || !terminalScope?.connected || !terminalScope.commandExecutionSupported || !sendApprovedCommand || runningCommandId !== null}
                          onClick={() => runCommandProposal(proposal)}
                        >
                          {effectivePermissionMode === "auto" ? t("ai.runCommandNow") : t("ai.runCommand")}
                        </button>
                      )}
                    </section>
                  ))}
                </div>
              </article>
            );
          })}
          {currentConversationBusy && !streamingAssistantMessageId ? (
            <article className="ai-message ai-message-assistant ai-message-pending" aria-label={t("ai.generating")}>
              <span className="ai-message-avatar"><AiGlyph name="spark" /></span>
              <div className="ai-message-body">
                <strong>{t("ai.role.assistant")}</strong>
                <span className="ai-thinking-dots" aria-hidden="true"><i /><i /><i /></span>
              </div>
            </article>
          ) : null}
          <div ref={messageEndRef} aria-hidden="true" />
        </div>
      )}

      {notice ? (
        <div className="ai-workspace-notice" role="status">
          <span>{notice}</span>
          {onOpenSettings && !usingLocalAgent ? <button type="button" onClick={onOpenSettings}>{t("ai.openSettings")}</button> : null}
        </div>
      ) : null}
      <AiComposer
        t={t}
        value={input}
        terminal={terminalScope ? {
          label: terminalScope.label,
          protocol: terminalScope.protocol,
          connected: terminalScope.connected,
        } : null}
        contextSummary={contextSummary}
        hasSendableContext={hasSendableContext}
        contextUsage={composerContextUsage}
        images={draftImages}
        imageInputEnabled={imageInputEnabled}
        imageInputDisabledReason={imageInputDisabledReason}
        mode={assistantMode}
        ready={assistantReady}
        busy={busy}
        permissionSaving={permissionSaving}
        engine={composerEngine}
        thinking={selectedProviderSupportsThinking ? {
          value: thinkingEffort,
          onSelect: selectThinkingEffort,
        } : undefined}
        onValueChange={setInput}
        onSubmit={() => void submit()}
        onStop={stop}
        onModeChange={setAssistantMode}
        onClearContext={clearContext}
        onReadContext={readContext}
        onAddImageFiles={addDraftImageFiles}
        onRemoveImage={removeDraftImage}
      />

      {pendingAgentApproval
        && terminalScope
        && sameToolScope(terminalScope, pendingAgentApproval.scope) && (
        <div className="ai-command-confirm-backdrop" role="presentation">
          <section className="ai-command-confirm" role="dialog" aria-modal="true" aria-label={t("ai.confirmCommandTitle")} data-ai-tool-call="terminal_execute">
            <h3>{t("ai.confirmCommandTitle")}</h3>
            <p>{t("ai.confirmCommandDescription", { target: pendingAgentApproval.scope.label })}</p>
            <pre><code>{pendingAgentApproval.step.call.command}</code></pre>
            <div>
              <button type="button" disabled={agentApprovalRunning || permissionSaving} onClick={() => void resolveAgentApproval(false)}>{t("ai.rejectCommand")}</button>
              {onCommandPermissionModeChange ? (
                <button type="button" disabled={agentApprovalRunning || permissionSaving} onClick={() => void approveAgentAlways()}>{t("ai.alwaysAllowCommand")}</button>
              ) : null}
              <button type="button" className="is-primary" disabled={agentApprovalRunning || permissionSaving} onClick={() => void resolveAgentApproval(true)}>{agentApprovalRunning ? t("ai.runningCommand") : t("ai.allowCommandOnce")}</button>
            </div>
          </section>
        </div>
      )}

      {pendingCommand && (
        <div className="ai-command-confirm-backdrop" role="presentation">
          <section className="ai-command-confirm" role="dialog" aria-modal="true" aria-label={t("ai.confirmCommandTitle")}>
            <h3>{t("ai.confirmCommandTitle")}</h3>
            <p>{t("ai.confirmCommandDescription", { target: pendingCommand.scope.label })}</p>
            <pre><code>{pendingCommand.proposal.command}</code></pre>
            <div>
              <button type="button" disabled={runningCommandId !== null} onClick={() => setPendingCommand(null)}>{t("ai.cancelCommand")}</button>
              <button type="button" disabled={runningCommandId !== null} onClick={() => void approveCommand()}>{runningCommandId ? t("ai.runningCommand") : t("ai.confirmCommand")}</button>
            </div>
          </section>
        </div>
      )}
    </section>
  );
}

export default AiWorkspace;
