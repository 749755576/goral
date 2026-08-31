import {
  type ClipboardEvent,
  type DragEvent,
  type FormEvent,
  type KeyboardEvent,
  useEffect,
  useRef,
} from "react";

import type { Translate } from "../i18n";
import type { AiCommandPermissionMode } from "../settingsUi";
import AiContextUsageRing from "./AiContextUsageRing";
import AiContextMenu from "./AiContextMenu";
import AiGlyph from "./AiGlyph";
import AiPermissionMenu from "./AiPermissionMenu";
import AiProviderMenu, {
  type AiProviderMenuModel,
  type AiProviderMenuProfile,
} from "./AiProviderMenu";
import AiQuickMessagePicker, { useAiQuickMessagePicker } from "./AiQuickMessagePicker";
import type { AiThinkingEffort } from "./AiThinkingMenu";
import { AI_IMAGE_ACCEPT, type AiDraftImage } from "./aiImageAttachments";
import type { AiContextUsage } from "./aiContextUsage";
import { AI_COMPOSER_MAX_LENGTH } from "./aiQuickMessages";

export type AiComposerMode = "terminal" | "explain" | "diagnose";

export type AiComposerTerminal = Readonly<{
  label: string;
  protocol: string;
  connected: boolean;
}>;

export type AiComposerEngine =
  | Readonly<{
      kind: "local";
      label: string;
    }>
  | Readonly<{
      kind: "builtin";
      provider: Readonly<{
        value: string;
        profiles: ReadonlyArray<AiProviderMenuProfile>;
        modelValue?: string;
        models?: ReadonlyArray<AiProviderMenuModel>;
        modelsLoading?: boolean;
        modelsError?: string;
        onSelect: (profileId: string) => void;
        onSelectModel?: (modelId: string) => void;
        onRetryModels?: () => void;
        onOpenSettings?: () => void;
      }>;
      permission: Readonly<{
        value: AiCommandPermissionMode;
        changeAllowed: boolean;
        disabledReason?: string;
        onSelect: (mode: AiCommandPermissionMode) => void;
      }>;
    }>;

export type AiComposerProps = Readonly<{
  t: Translate;
  value: string;
  terminal: AiComposerTerminal | null;
  contextSummary: string;
  hasSendableContext: boolean;
  contextUsage?: AiContextUsage;
  images: readonly AiDraftImage[];
  imageInputEnabled: boolean;
  imageInputDisabledReason?: string;
  mode: AiComposerMode;
  ready: boolean;
  busy: boolean;
  permissionSaving: boolean;
  engine: AiComposerEngine;
  thinking?: Readonly<{
    value: AiThinkingEffort;
    onSelect: (value: AiThinkingEffort) => void;
  }>;
  onValueChange: (value: string) => void;
  onSubmit: () => void;
  onStop: () => void;
  onModeChange: (mode: AiComposerMode) => void;
  onClearContext: () => void;
  onReadContext: (kind: "selectedText" | "recentOutput") => void | Promise<void>;
  onAddImageFiles: (files: readonly File[]) => void | Promise<void>;
  onRemoveImage: (imageId: string) => void;
}>;

export default function AiComposer({
  t,
  value,
  terminal,
  contextSummary,
  hasSendableContext,
  contextUsage,
  images,
  imageInputEnabled,
  imageInputDisabledReason,
  mode,
  ready,
  busy,
  permissionSaving,
  engine,
  thinking,
  onValueChange,
  onSubmit,
  onStop,
  onModeChange,
  onClearContext,
  onReadContext,
  onAddImageFiles,
  onRemoveImage,
}: AiComposerProps) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const imageInputRef = useRef<HTMLInputElement>(null);
  const quickMessagePicker = useAiQuickMessagePicker({
    t,
    value,
    disabled: busy || permissionSaving || !ready,
    textareaRef,
    onValueChange,
  });

  useEffect(() => {
    const textarea = textareaRef.current;
    if (!textarea) return;
    textarea.style.height = "0";
    textarea.style.height = `${Math.min(Math.max(textarea.scrollHeight, 52), 180)}px`;
  }, [value]);

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    onSubmit();
  };

  const handleInputKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (quickMessagePicker.onKeyDown(event)) return;
    if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) {
      event.preventDefault();
      onSubmit();
    }
  };

  const imageActionsDisabled = busy || permissionSaving || !ready || !imageInputEnabled;
  const addImageFiles = (files: FileList | readonly File[] | null) => {
    if (!files || files.length === 0 || imageActionsDisabled) return;
    void onAddImageFiles(Array.from(files));
  };
  const handlePaste = (event: ClipboardEvent<HTMLTextAreaElement>) => {
    const files = Array.from(event.clipboardData.files);
    if (files.length === 0 || imageActionsDisabled) return;
    event.preventDefault();
    addImageFiles(files);
  };
  const handleDragOver = (event: DragEvent<HTMLFormElement>) => {
    if (imageActionsDisabled || !event.dataTransfer.types.includes("Files")) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = "copy";
  };
  const handleDrop = (event: DragEvent<HTMLFormElement>) => {
    if (imageActionsDisabled || event.dataTransfer.files.length === 0) return;
    event.preventDefault();
    addImageFiles(event.dataTransfer.files);
  };

  const openQuickMessages = () => {
    const textarea = textareaRef.current;
    const selectionStart = textarea?.selectionStart ?? value.length;
    const selectionEnd = textarea?.selectionEnd ?? selectionStart;
    const before = value.slice(0, selectionStart);
    const after = value.slice(selectionEnd);
    const slash = before && !/\s$/u.test(before) ? " /" : "/";
    const nextValue = `${before}${slash}${after}`;
    if (nextValue.length > AI_COMPOSER_MAX_LENGTH) return;
    const caret = before.length + slash.length;
    quickMessagePicker.sync(nextValue, caret);
    onValueChange(nextValue);
    requestAnimationFrame(() => {
      textareaRef.current?.focus();
      textareaRef.current?.setSelectionRange(caret, caret);
    });
  };

  return (
    <form className="ai-workspace-composer" onSubmit={submit} onDragOver={handleDragOver} onDrop={handleDrop}>
      <div className="ai-composer-context" aria-label={t("ai.context")}>
        {terminal ? (
          <span
            className="ai-context-chip ai-terminal-context-chip"
            data-connected={terminal.connected}
            title={`${terminal.label} · ${terminal.protocol.toUpperCase()} · ${terminal.connected
              ? t("ai.composer.terminalConnected")
              : t("ai.composer.terminalDisconnected")}`}
          >
            <AiGlyph name="terminal" />
            <span className="ai-terminal-status-dot" aria-hidden="true" />
            <span className="ai-context-chip-label">
              {terminal.label} · {terminal.protocol.toUpperCase()}
            </span>
          </span>
        ) : null}
        {contextSummary ? (
          <button type="button" className="ai-context-chip is-attached" onClick={onClearContext} title={t("ai.removeContext")}>
            <AiGlyph name="context" />
            <span className="ai-context-chip-label" title={contextSummary}>{contextSummary}</span>
            <AiGlyph name="close" />
          </button>
        ) : null}
      </div>
      {images.length > 0 ? (
        <div className="ai-image-drafts" aria-label={t("ai.image.attachedList")}>
          {images.map((image) => (
            <figure className="ai-image-draft" key={image.id}>
              <img src={image.previewUrl} alt={image.name} />
              <figcaption>
                <span title={image.name}>{image.name}</span>
                <small>{t("ai.image.sizeKib", { count: Math.max(1, Math.ceil(image.size / 1024)) })}</small>
              </figcaption>
              <button
                type="button"
                disabled={busy || permissionSaving}
                aria-label={t("ai.image.remove", { name: image.name })}
                title={t("ai.image.remove", { name: image.name })}
                onClick={() => onRemoveImage(image.id)}
              >
                <AiGlyph name="close" />
              </button>
            </figure>
          ))}
        </div>
      ) : null}
      <textarea
        ref={textareaRef}
        value={value}
        onChange={(event) => {
          quickMessagePicker.sync(event.target.value, event.target.selectionStart ?? event.target.value.length);
          onValueChange(event.target.value);
        }}
        onKeyDown={handleInputKeyDown}
        onPaste={handlePaste}
        onBlur={quickMessagePicker.close}
        placeholder={ready ? t("ai.inputPlaceholder") : engine.kind === "local"
          ? t("ai.localAgent.notAvailable")
          : t("ai.noProviderInputPlaceholder")}
        rows={1}
        maxLength={AI_COMPOSER_MAX_LENGTH}
        spellCheck={false}
        autoCorrect="off"
        autoCapitalize="off"
        autoComplete="off"
        disabled={busy || permissionSaving || !ready}
        aria-label={t("ai.inputPlaceholder")}
        aria-haspopup="menu"
        aria-expanded={quickMessagePicker.open}
        aria-controls={quickMessagePicker.open ? quickMessagePicker.menuId : undefined}
        aria-activedescendant={quickMessagePicker.activeOptionId}
      />
      {quickMessagePicker.open ? (
        <AiQuickMessagePicker
          t={t}
          menuId={quickMessagePicker.menuId}
          query={quickMessagePicker.query}
          messages={quickMessagePicker.messages}
          activeIndex={quickMessagePicker.activeIndex}
          onActiveIndexChange={quickMessagePicker.setActiveIndex}
          onSelect={quickMessagePicker.select}
        />
      ) : null}
      <footer>
        <div className="ai-composer-controls">
          <div className="ai-composer-main-controls">
            <AiContextMenu
              disabled={busy || permissionSaving || !ready}
              terminalContextAvailable={Boolean(terminal?.connected)}
              imageInputAvailable={imageInputEnabled}
              t={t}
              onReadContext={onReadContext}
              onAddImage={() => imageInputRef.current?.click()}
              onOpenQuickMessages={openQuickMessages}
            />
            {engine.kind === "local" ? (
              <span className="ai-composer-runtime" title={t("ai.localAgent.runtimeLabel")}>{engine.label}</span>
            ) : (
              <AiProviderMenu
                value={engine.provider.value}
                profiles={engine.provider.profiles}
                modelValue={engine.provider.modelValue}
                models={engine.provider.models}
                modelsLoading={engine.provider.modelsLoading}
                modelsError={engine.provider.modelsError}
                thinking={thinking}
                disabled={busy || permissionSaving}
                t={t}
                onSelect={engine.provider.onSelect}
                onSelectModel={engine.provider.onSelectModel}
                onRetryModels={engine.provider.onRetryModels}
                onOpenSettings={engine.provider.onOpenSettings}
              />
            )}
          </div>
          <input
            ref={imageInputRef}
            className="ai-image-file-input"
            type="file"
            accept={AI_IMAGE_ACCEPT}
            multiple
            tabIndex={-1}
            aria-hidden="true"
            disabled={imageActionsDisabled}
            title={imageInputDisabledReason}
            onChange={(event) => {
              addImageFiles(event.target.files);
              event.target.value = "";
            }}
          />
          <div className="ai-composer-routing-controls">
            <select
              className="ai-composer-mode-select"
              value={mode}
              disabled={busy || permissionSaving}
              aria-label={t("ai.selectMode")}
              title={t("ai.selectMode")}
              onChange={(event) => onModeChange(event.target.value as AiComposerMode)}
            >
              <option value="terminal">{t("ai.agent.terminalShort")}</option>
              <option value="diagnose">{t("ai.agent.diagnoseShort")}</option>
              <option value="explain">{t("ai.agent.explainShort")}</option>
            </select>
            {engine.kind === "local" ? (
              <span className="ai-composer-read-only" title={t("ai.localAgent.readOnlyDescription")}>{t("ai.localAgent.readOnly")}</span>
            ) : (
              <AiPermissionMenu
                value={engine.permission.value}
                disabled={busy || permissionSaving || !engine.permission.changeAllowed}
                disabledReason={engine.permission.disabledReason}
                t={t}
                onSelect={engine.permission.onSelect}
              />
            )}
            {contextUsage ? <AiContextUsageRing usage={contextUsage} t={t} /> : null}
          </div>
        </div>
        {busy ? (
          <button type="button" className="ai-send-button is-stop" onClick={onStop} aria-label={t("ai.stop")} title={t("ai.stop")}>
            <AiGlyph name="stop" />
          </button>
        ) : (
          <button type="submit" className="ai-send-button" disabled={permissionSaving || (!value.trim() && !hasSendableContext && images.length === 0) || (images.length > 0 && !imageInputEnabled) || !ready} aria-label={t("ai.send")} title={t("ai.send")}>
            <AiGlyph name="send" />
          </button>
        )}
      </footer>
    </form>
  );
}
