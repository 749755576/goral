import {
  prepareTerminalTextInput,
  type PreparedTerminalTextInput,
  type TerminalTextInputSource,
} from "./terminalPerCharacterInput.ts";

/** Minimal DOM-key shape kept independent from xterm and React. */
export type ImeTextInputKeyEvent = Readonly<{
  type?: string;
  key: string;
  code?: string;
  keyCode?: number;
  altKey?: boolean;
  ctrlKey?: boolean;
  metaKey?: boolean;
  isComposing?: boolean;
}>;

export type ImeTextInputEvent = Readonly<{
  data: string | null;
  inputType: string;
}>;

/** Printable ASCII punctuation commonly remapped to full-width CJK glyphs. */
const ASCII_PUNCTUATION_RE = /^[\x21-\x2f\x3a-\x40\x5b-\x60\x7b-\x7e]$/;

/**
 * Windows can deliver xterm's committed Process/229 text on a later task.
 * Keep the marker briefly, while ordinary keyboard/paste/blur events cancel it.
 */
export const PROCESS_IME_DATA_GRACE_MS = 250;

export const isAsciiPunctuationKey = (key: string): boolean =>
  ASCII_PUNCTUATION_RE.test(key);

export const shouldDeferKeyDownForImeTextInput = (
  event: ImeTextInputKeyEvent,
): boolean => {
  if (event.type !== undefined && event.type !== "keydown") return false;
  if (event.isComposing === true || event.keyCode === 229) return false;
  if (event.altKey || event.ctrlKey || event.metaKey) return false;
  return isAsciiPunctuationKey(event.key);
};

const MODIFIER_ONLY_KEY_RE =
  /^(Shift|Control|Alt|Meta|CapsLock|NumLock|ScrollLock|Hyper|Super|Fn|FnLock|Symbol|SymbolLock)$/;

export const isModifierOnlyKey = (key: string): boolean =>
  MODIFIER_ONLY_KEY_RE.test(key);

/** DOM key identities used when an IME consumes the physical key release. */
const IME_SENTINEL_KEYS = new Set(["Dead", "Process", "Unidentified", "Compose"]);

export const isImeSentinelKeyUp = (event: ImeTextInputKeyEvent): boolean => {
  if (event.type !== undefined && event.type !== "keyup") return false;
  return event.keyCode === 229 || IME_SENTINEL_KEYS.has(event.key);
};

export const shouldFlushDeferredImeTextInputOnKeyUp = (
  deferredKey: string | null | undefined,
  event: ImeTextInputKeyEvent,
): boolean => {
  if (!deferredKey) return false;
  if (event.type !== undefined && event.type !== "keyup") return false;
  if (event.isComposing === true) return false;
  if (event.altKey || event.ctrlKey || event.metaKey) return false;
  return !isModifierOnlyKey(event.key);
};

export const shouldFlushStaleDeferredImeTextInput = (
  deferredKey: string | null | undefined,
  event: ImeTextInputKeyEvent,
): boolean => {
  if (!deferredKey) return false;
  if (event.type !== undefined && event.type !== "keydown") return false;
  if (event.isComposing === true || event.keyCode === 229) return false;
  if (event.altKey || event.ctrlKey || event.metaKey) return false;
  if (isModifierOnlyKey(event.key)) return false;
  return event.key !== deferredKey;
};

export const shouldDiscardStaleDeferredImeTextInput = (
  deferredKey: string | null | undefined,
  event: ImeTextInputKeyEvent,
): boolean => {
  if (!deferredKey) return false;
  if (event.type !== undefined && event.type !== "keydown") return false;
  if (event.isComposing === true || event.keyCode === 229) return false;
  return Boolean(event.altKey || event.ctrlKey || event.metaKey);
};

export const shouldBlockKeyPressForImeTextInput = (
  deferredKey: string | null | undefined,
  event: ImeTextInputKeyEvent,
  deferredKeyCode?: number | null,
): boolean => {
  if (!deferredKey || event.type !== "keypress") return false;
  if (event.isComposing === true || event.keyCode === 229) return true;
  return event.key === deferredKey
    || (deferredKeyCode != null && event.keyCode === deferredKeyCode);
};

export const shouldCommitDeferredImeTextInput = (
  deferredKey: string | null | undefined,
  event: ImeTextInputEvent,
): event is ImeTextInputEvent & { data: string } => (
  Boolean(deferredKey)
  && event.inputType === "insertText"
  && typeof event.data === "string"
  && event.data.length > 0
);

export type TerminalImeKeyResult = Readonly<{
  allowXterm: boolean;
  commitText: string | null;
}>;

/**
 * Pure state machine for xterm's key/input/composition events. It delays an
 * ASCII punctuation key long enough for a CJK IME to replace it with `，`,
 * `。`, `、`, etc., while stale or modified key paths can never wedge input.
 */
export class TerminalImeTextInputState {
  #compositionPending = false;
  #deferredKey: string | null = null;
  #suppressedPunctuationKey: Readonly<{
    key: string;
    code: string | null;
    keyCode: number | null;
  }> | null = null;

  get deferredKey(): string | null {
    return this.#deferredKey;
  }

  handleKeyEvent(event: ImeTextInputKeyEvent): TerminalImeKeyResult {
    if (event.type === "keyup") {
      const matchesSuppressed = this.#matchesSuppressedPunctuationKey(event);
      if (this.#deferredKey === null) {
        if (matchesSuppressed) {
          this.#suppressedPunctuationKey = null;
          return { allowXterm: false, commitText: null };
        }
        return { allowXterm: true, commitText: null };
      }
      if (!shouldFlushDeferredImeTextInputOnKeyUp(this.#deferredKey, event)) {
        return { allowXterm: true, commitText: null };
      }

      const commitText = this.#takeDeferredKey();
      this.#suppressedPunctuationKey = null;
      // A real unrelated release retains its own xterm identity. Exact and
      // IME-sentinel releases belong to the suppressed punctuation lifecycle.
      return {
        allowXterm: !matchesSuppressed && !isImeSentinelKeyUp(event),
        commitText,
      };
    }

    if (
      event.type === "keypress"
      && this.#matchesSuppressedPunctuationKey(event)
    ) {
      return { allowXterm: false, commitText: null };
    }

    if (event.type !== "keydown") {
      return { allowXterm: true, commitText: null };
    }

    if (event.isComposing === true || event.keyCode === 229) {
      this.#compositionPending = true;
    }

    let commitText: string | null = null;
    if (shouldFlushStaleDeferredImeTextInput(this.#deferredKey, event)) {
      commitText = this.#takeDeferredKey();
    } else if (shouldDiscardStaleDeferredImeTextInput(this.#deferredKey, event)) {
      this.#clearDeferredKey();
    }

    if (shouldDeferKeyDownForImeTextInput(event)) {
      this.#deferredKey = event.key;
      this.#suppressedPunctuationKey = Object.freeze({
        key: event.key,
        code: event.code ?? null,
        keyCode: event.keyCode ?? null,
      });
      return { allowXterm: false, commitText };
    }
    return { allowXterm: true, commitText };
  }

  handleInputEvent(event: ImeTextInputEvent): string | null {
    if (shouldCommitDeferredImeTextInput(this.#deferredKey, event)) {
      this.#clearDeferredKey();
      this.#compositionPending = false;
      return event.data;
    }
    if (
      event.inputType === "insertText"
      && typeof event.data === "string"
      && event.data.length > 0
    ) {
      this.#compositionPending = true;
    }
    return null;
  }

  markCompositionPending(): void {
    this.#compositionPending = true;
  }

  clearCompositionPending(): void {
    this.#compositionPending = false;
  }

  consumeDataSource(data: string): TerminalTextInputSource {
    if (this.#compositionPending && !data.startsWith("\x1b")) {
      this.#compositionPending = false;
      return "ime";
    }
    return "raw";
  }

  flushDeferredKey(): string | null {
    return this.#takeDeferredKey();
  }

  reset(): void {
    this.#clearDeferredKey();
    this.#suppressedPunctuationKey = null;
    this.#compositionPending = false;
  }

  #matchesSuppressedPunctuationKey(event: ImeTextInputKeyEvent): boolean {
    const suppressed = this.#suppressedPunctuationKey;
    if (!suppressed) return false;

    // Some Windows IMEs replace the actual punctuation identity with a
    // Process/229 release. It belongs to the deferred key only while that
    // fallback is still waiting to be committed.
    if (isImeSentinelKeyUp(event)) {
      return true;
    }

    return event.key === suppressed.key
      || (
        suppressed.code !== null
        && event.code !== undefined
        && event.code === suppressed.code
      )
      || (
        suppressed.keyCode !== null
        && event.keyCode !== undefined
        && event.keyCode === suppressed.keyCode
      );
  }

  #takeDeferredKey(): string | null {
    const key = this.#deferredKey;
    this.#clearDeferredKey();
    return key;
  }

  #clearDeferredKey(): void {
    this.#deferredKey = null;
  }
}

export type TerminalImeInputSurface = Readonly<{
  attachCustomKeyEventHandler?: (
    handler: (event: KeyboardEvent) => boolean,
  ) => void;
  readonly element?: HTMLElement;
  readonly textarea?: HTMLTextAreaElement;
}>;

export type TerminalInputBinding = Readonly<{
  /** Route xterm onData through sanitize -> source decision -> wire chunks. */
  handleData: (data: string) => void;
  /** Attach capture/input/composition listeners after Terminal.open(). */
  bindDom: () => void;
  /** Drop transient input state without writing it into a replacement session. */
  reset: () => void;
  dispose: () => void;
}>;

/**
 * Binds the pure IME state machine to an xterm-like surface. The capture-phase
 * input listener commits full-width punctuation before xterm can discard it.
 */
export const createTerminalInputBinding = (
  surface: TerminalImeInputSurface,
  onInput: (input: PreparedTerminalTextInput) => void,
): TerminalInputBinding => {
  const state = new TerminalImeTextInputState();
  let disposed = false;
  let pendingClearTimer: ReturnType<typeof setTimeout> | null = null;
  let removeDomListeners: (() => void) | null = null;

  const clearPendingTimer = (): void => {
    if (pendingClearTimer === null) return;
    clearTimeout(pendingClearTimer);
    pendingClearTimer = null;
  };
  const scheduleCompositionClear = (delayMs = 0): void => {
    clearPendingTimer();
    pendingClearTimer = setTimeout(() => {
      pendingClearTimer = null;
      state.clearCompositionPending();
    }, delayMs);
  };
  const emit = (data: string, source: TerminalTextInputSource): void => {
    if (disposed) return;
    const prepared = prepareTerminalTextInput(data, source);
    if (prepared) onInput(prepared);
  };

  surface.attachCustomKeyEventHandler?.((event) => {
    if (disposed) return true;
    if (
      event.type === "keydown"
      && event.keyCode === 229
      && event.isComposing !== true
    ) {
      // Some Windows IMEs expose only Process/229 before xterm emits the
      // committed text on a later task. A bounded grace period bridges that
      // task boundary; ordinary input below cancels a stale marker.
      scheduleCompositionClear(PROCESS_IME_DATA_GRACE_MS);
    } else if (
      event.type === "keydown"
      && event.isComposing !== true
    ) {
      clearPendingTimer();
      state.clearCompositionPending();
    }
    const result = state.handleKeyEvent(event);
    if (result.commitText) emit(result.commitText, "ime");
    return result.allowXterm;
  });

  const bindDom = (): void => {
    removeDomListeners?.();
    removeDomListeners = null;
    if (disposed) return;

    const root = surface.element ?? surface.textarea;
    const textarea = surface.textarea;
    if (!root) return;

    const handleInput = (rawEvent: Event): void => {
      const event = rawEvent as Event & ImeTextInputEvent;
      const committed = state.handleInputEvent({
        data: typeof event.data === "string" ? event.data : null,
        inputType: typeof event.inputType === "string" ? event.inputType : "",
      });
      if (committed) {
        clearPendingTimer();
        emit(committed, "ime");
        try {
          if (textarea) textarea.value = "";
        } catch {
          // A detached WebView textarea cannot retain the deferred commit.
        }
      } else if (event.inputType === "insertText") {
        scheduleCompositionClear();
      }
    };
    const handleCompositionStart = (): void => {
      clearPendingTimer();
      state.markCompositionPending();
    };
    const handleCompositionEnd = (): void => {
      state.markCompositionPending();
      scheduleCompositionClear();
    };
    const handlePaste = (): void => {
      clearPendingTimer();
      state.clearCompositionPending();
    };
    const handleBlur = (): void => {
      clearPendingTimer();
      const fallback = state.flushDeferredKey();
      state.reset();
      if (fallback) emit(fallback, "ime");
    };

    root.addEventListener("input", handleInput, true);
    root.addEventListener("paste", handlePaste, true);
    textarea?.addEventListener("compositionstart", handleCompositionStart);
    textarea?.addEventListener("compositionend", handleCompositionEnd);
    textarea?.addEventListener("blur", handleBlur);
    removeDomListeners = () => {
      root.removeEventListener("input", handleInput, true);
      root.removeEventListener("paste", handlePaste, true);
      textarea?.removeEventListener("compositionstart", handleCompositionStart);
      textarea?.removeEventListener("compositionend", handleCompositionEnd);
      textarea?.removeEventListener("blur", handleBlur);
    };
  };

  return Object.freeze({
    handleData(data: string): void {
      if (disposed) return;
      const source = state.consumeDataSource(data);
      if (source === "ime") clearPendingTimer();
      emit(data, source);
    },
    bindDom,
    reset(): void {
      clearPendingTimer();
      state.reset();
    },
    dispose(): void {
      if (disposed) return;
      disposed = true;
      clearPendingTimer();
      removeDomListeners?.();
      removeDomListeners = null;
      state.reset();
    },
  });
};
