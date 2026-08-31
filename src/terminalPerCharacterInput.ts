import { sanitizeTerminalInput } from "./terminalInputSanitize.ts";

/** Short raw pastes are sent as keystrokes; larger pastes retain one write. */
export const MAX_RAW_PASTE_PER_CHARACTER_LENGTH = 32;

const ESC = "\x1b";

export type TerminalTextInputSource = "ime" | "raw";

export type PreparedTerminalTextInput = Readonly<{
  /** Sanitized text used by local echo and other once-per-input bookkeeping. */
  text: string;
  /** Exact ordered native writes. ANSI/escape payloads always have one chunk. */
  chunks: readonly string[];
  source: TerminalTextInputSource;
}>;

/** True only when the payload cannot contain an ANSI or terminal escape sequence. */
export const isPlainTerminalInputText = (data: string): boolean => !data.includes(ESC);

/** One write per Unicode code point, keeping UTF-16 surrogate pairs together. */
export const splitTextIntoCodePointWrites = (data: string): string[] => Array.from(data);

/** A multi-code-point IME commit must reproduce physical per-character typing. */
export const shouldSplitImeTextInputForWire = (text: string): boolean =>
  isPlainTerminalInputText(text) && Array.from(text).length > 1;

/** A short, unbracketed, plain-text paste is sent as individual keystrokes. */
export const shouldSplitRawPasteInputForWire = (data: string): boolean => {
  if (!isPlainTerminalInputText(data)) return false;

  let codePointCount = 0;
  for (let index = 0; index < data.length;) {
    index += (data.codePointAt(index) ?? 0) > 0xffff ? 2 : 1;
    codePointCount += 1;
    if (codePointCount > MAX_RAW_PASTE_PER_CHARACTER_LENGTH) return false;
  }
  return codePointCount > 1;
};

/** Escape payloads remain atomic even if a caller incorrectly requests splitting. */
export const getTextInputWireChunks = (
  data: string,
  perCharacterWrites: boolean,
): readonly string[] => (
  perCharacterWrites && isPlainTerminalInputText(data)
    ? splitTextIntoCodePointWrites(data)
    : [data]
);

/**
 * Sanitize first, then decide whether the resulting payload is an IME commit
 * or a short raw paste. This order matters when zero-width characters would
 * otherwise push a qualifying paste above the 32-code-point limit.
 */
export const prepareTerminalTextInput = (
  data: string,
  source: TerminalTextInputSource,
): PreparedTerminalTextInput | null => {
  const text = sanitizeTerminalInput(data);
  if (!text) return null;
  const split = source === "ime"
    ? shouldSplitImeTextInputForWire(text)
    : shouldSplitRawPasteInputForWire(text);
  return Object.freeze({
    text,
    chunks: Object.freeze([...getTextInputWireChunks(text, split)]),
    source,
  });
};

/**
 * Serializes every native write from one xterm runtime. Separate input events
 * cannot interleave while an earlier multi-character IME commit is in flight.
 */
export class TerminalInputWriteQueue {
  #generation = 0;
  #tail: Promise<void> = Promise.resolve();

  enqueue<Chunk>(
    chunks: readonly Chunk[],
    write: (chunk: Chunk) => Promise<void>,
    isCurrent: () => boolean = () => true,
  ): Promise<boolean> {
    const generation = this.#generation;
    const task = this.#tail.then(async () => {
      for (const chunk of chunks) {
        if (generation !== this.#generation || !isCurrent()) return false;
        await write(chunk);
      }
      return true;
    });
    this.#tail = task.then(() => undefined, () => undefined);
    return task;
  }

  /** Prevent every queued-but-not-started chunk from reaching a retired session. */
  invalidate(): void {
    this.#generation += 1;
    // A replacement native session must not wait behind an unresolved write
    // owned by the retired session. The old task still observes the bumped
    // generation after its in-flight write settles and drops its remaining
    // chunks, while new input starts on an independent tail immediately.
    this.#tail = Promise.resolve();
  }
}
