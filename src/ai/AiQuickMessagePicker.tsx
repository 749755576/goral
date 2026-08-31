import {
  type KeyboardEvent,
  type RefObject,
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";

import type { Translate } from "../i18n";
import {
  builtInAiQuickMessages,
  expandAiQuickMessage,
  filterAiQuickMessages,
  findAiQuickMessageTrigger,
  resolveAiQuickMessageIndex,
  type AiQuickMessage,
  type AiQuickMessageNavigationKey,
  type AiQuickMessageTrigger,
} from "./aiQuickMessages";

type PickerState = Readonly<{ trigger: AiQuickMessageTrigger; activeIndex: number }>;

export function useAiQuickMessagePicker({
  t,
  value,
  disabled,
  textareaRef,
  onValueChange,
}: Readonly<{
  t: Translate;
  value: string;
  disabled: boolean;
  textareaRef: RefObject<HTMLTextAreaElement | null>;
  onValueChange: (value: string) => void;
}>) {
  const menuId = useId();
  const messages = useMemo(() => builtInAiQuickMessages(t), [t]);
  const [state, setState] = useState<PickerState | null>(null);
  const expectedControlledValueRef = useRef<string | null>(null);
  const visibleMessages = useMemo(() => (
    state ? filterAiQuickMessages(messages, state.trigger.query) : []
  ), [messages, state]);

  const sync = useCallback((nextValue: string, caret: number) => {
    if (disabled) {
      expectedControlledValueRef.current = null;
      setState(null);
      return;
    }
    expectedControlledValueRef.current = nextValue;
    const trigger = findAiQuickMessageTrigger(nextValue, caret);
    setState((current) => trigger ? {
      trigger,
      activeIndex: current?.trigger.query === trigger.query ? current.activeIndex : 0,
    } : null);
  }, [disabled]);

  useEffect(() => {
    if (disabled) setState(null);
  }, [disabled]);

  useEffect(() => {
    if (expectedControlledValueRef.current === value) {
      expectedControlledValueRef.current = null;
      return;
    }
    expectedControlledValueRef.current = null;
    setState(null);
  }, [value]);

  const close = useCallback(() => setState(null), []);

  const select = useCallback((message: AiQuickMessage) => {
    if (!state) return;
    const expanded = expandAiQuickMessage(value, state.trigger, message.content);
    if (!expanded) {
      setState(null);
      return;
    }
    onValueChange(expanded.value);
    setState(null);
    requestAnimationFrame(() => {
      textareaRef.current?.focus();
      textareaRef.current?.setSelectionRange(expanded.caret, expanded.caret);
    });
  }, [onValueChange, state, textareaRef, value]);

  const onKeyDown = useCallback((event: KeyboardEvent<HTMLTextAreaElement>): boolean => {
    if (!state || event.nativeEvent.isComposing) return false;
    if (event.key === "Tab") {
      close();
      return false;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      close();
      return true;
    }
    if (["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key) && visibleMessages.length > 0) {
      event.preventDefault();
      setState((current) => current ? {
        ...current,
        activeIndex: resolveAiQuickMessageIndex(
          event.key as AiQuickMessageNavigationKey,
          current.activeIndex,
          visibleMessages.length,
        ) ?? 0,
      } : current);
      return true;
    }
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      const message = visibleMessages[Math.min(state.activeIndex, visibleMessages.length - 1)];
      if (message) select(message);
      return true;
    }
    return false;
  }, [close, select, state, visibleMessages]);

  const activeIndex = visibleMessages.length === 0
    ? 0
    : Math.min(state?.activeIndex ?? 0, visibleMessages.length - 1);

  return {
    open: state !== null,
    menuId,
    activeOptionId: state && visibleMessages[activeIndex]
      ? `${menuId}-${visibleMessages[activeIndex].id}`
      : undefined,
    query: state?.trigger.query ?? "",
    messages: visibleMessages,
    activeIndex,
    sync,
    select,
    close,
    setActiveIndex: (index: number) => setState((current) => current ? { ...current, activeIndex: index } : current),
    onKeyDown,
  } as const;
}

export default function AiQuickMessagePicker({
  t,
  menuId,
  query,
  messages,
  activeIndex,
  onActiveIndexChange,
  onSelect,
}: Readonly<{
  t: Translate;
  menuId: string;
  query: string;
  messages: readonly AiQuickMessage[];
  activeIndex: number;
  onActiveIndexChange: (index: number) => void;
  onSelect: (message: AiQuickMessage) => void;
}>) {
  return (
    <div id={menuId} role="menu" aria-label={t("ai.quickMessage.menuLabel")} className="ai-popup-menu ai-popup-menu-top-start">
      {messages.length > 0 ? (
        <div className="ai-popup-group" role="group" aria-label={t("ai.quickMessage.builtInGroup")}>
          <span className="ai-popup-group-label">{t("ai.quickMessage.builtInGroup")}</span>
          {messages.map((message, index) => (
            <button
              key={message.id}
              id={`${menuId}-${message.id}`}
              type="button"
              role="menuitemradio"
              aria-checked={index === activeIndex}
              tabIndex={-1}
              onMouseDown={(event) => event.preventDefault()}
              onMouseEnter={() => onActiveIndexChange(index)}
              onClick={() => onSelect(message)}
            >
              <span className="ai-popup-item-copy">
                <strong>{message.name}</strong>
                <small>{message.description}</small>
              </span>
              <span className="ai-popup-status">/{message.slug}</span>
            </button>
          ))}
        </div>
      ) : (
        <p className="ai-popup-empty" role="status">
          {t("ai.quickMessage.noResults", { query: `/${query}` })}
        </p>
      )}
    </div>
  );
}
