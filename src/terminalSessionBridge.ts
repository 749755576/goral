/**
 * Renderer-only terminal context and input bounds shared by protocol session
 * controllers. This module never persists, logs, or otherwise retains text.
 */

export const TERMINAL_CONTEXT_MAX_BYTES = 16 * 1024;
export const TERMINAL_CONTEXT_MAX_LINES = 200;
export const TERMINAL_SEND_TEXT_MAX_BYTES = 32 * 1024;

export type TerminalBufferLineSource = Readonly<{
  translateToString: (trimRight?: boolean) => string;
}>;

export type TerminalContextSource = Readonly<{
  getSelection?: () => string;
  readonly buffer?: Readonly<{
    readonly active: Readonly<{
      readonly baseY: number;
      readonly cursorY: number;
      readonly length: number;
      getLine: (index: number) => TerminalBufferLineSource | undefined;
    }>;
  }>;
}>;

export type TerminalContextSnapshot = Readonly<{
  selectedText: string;
  recentOutput: string;
}>;

export type TerminalSendTextErrorCode =
  | "TERMINAL_SEND_TEXT_INVALID"
  | "TERMINAL_SEND_TEXT_EMPTY"
  | "TERMINAL_SEND_TEXT_CONTAINS_NUL"
  | "TERMINAL_SEND_TEXT_TOO_LARGE"
  | "TERMINAL_SEND_SESSION_NOT_FOUND"
  | "TERMINAL_SEND_SESSION_NOT_CONNECTED"
  | "TERMINAL_SEND_SESSION_CLOSING"
  | "TERMINAL_SEND_ROUTE_STALE"
  | "TERMINAL_SEND_FAILED";

export type PreparedTerminalText = Readonly<{
  bytes: Uint8Array | null;
  error: TerminalSendTextErrorCode | null;
}>;

const utf8 = new TextEncoder();
const utf8Decoder = new TextDecoder();

const isContinuationByte = (value: number | undefined): boolean => (
  value !== undefined && (value & 0xc0) === 0x80
);

/** Keep the beginning of a string without splitting a UTF-8 code point. */
export const takeUtf8Prefix = (value: string, maximumBytes: number): string => {
  if (maximumBytes <= 0 || value.length === 0) return "";
  let candidateEnd = Math.min(value.length, maximumBytes);
  if (
    candidateEnd < value.length
    && candidateEnd > 0
    && value.charCodeAt(candidateEnd - 1) >= 0xd800
    && value.charCodeAt(candidateEnd - 1) <= 0xdbff
    && value.charCodeAt(candidateEnd) >= 0xdc00
    && value.charCodeAt(candidateEnd) <= 0xdfff
  ) {
    candidateEnd -= 1;
  }
  const candidate = value.slice(0, candidateEnd);
  const bytes = utf8.encode(candidate);
  if (bytes.byteLength <= maximumBytes) return candidate;

  let byteEnd = maximumBytes;
  while (byteEnd > 0 && isContinuationByte(bytes[byteEnd])) byteEnd -= 1;
  return utf8Decoder.decode(bytes.subarray(0, byteEnd));
};

/** Keep the end of a string without splitting a UTF-8 code point. */
export const takeUtf8Suffix = (value: string, maximumBytes: number): string => {
  if (maximumBytes <= 0 || value.length === 0) return "";
  let candidateStart = Math.max(0, value.length - maximumBytes);
  if (
    candidateStart > 0
    && value.charCodeAt(candidateStart) >= 0xdc00
    && value.charCodeAt(candidateStart) <= 0xdfff
    && value.charCodeAt(candidateStart - 1) >= 0xd800
    && value.charCodeAt(candidateStart - 1) <= 0xdbff
  ) {
    candidateStart -= 1;
  }
  const candidate = value.slice(candidateStart);
  const bytes = utf8.encode(candidate);
  if (bytes.byteLength <= maximumBytes) return candidate;

  let byteStart = bytes.byteLength - maximumBytes;
  while (byteStart < bytes.byteLength && isContinuationByte(bytes[byteStart])) {
    byteStart += 1;
  }
  return utf8Decoder.decode(bytes.subarray(byteStart));
};

export const readTerminalSelectedText = (
  terminal: TerminalContextSource | null | undefined,
): string => {
  try {
    const selection = terminal?.getSelection?.();
    return typeof selection === "string"
      ? takeUtf8Prefix(selection, TERMINAL_CONTEXT_MAX_BYTES)
      : "";
  } catch {
    return "";
  }
};

export const readTerminalRecentOutput = (
  terminal: TerminalContextSource | null | undefined,
): string => {
  try {
    const buffer = terminal?.buffer?.active;
    if (!buffer || !Number.isSafeInteger(buffer.length) || buffer.length < 1) return "";
    if (!Number.isFinite(buffer.baseY) || !Number.isFinite(buffer.cursorY)) return "";

    const cursorLine = Math.floor(buffer.baseY) + Math.floor(buffer.cursorY);
    const end = Math.min(buffer.length - 1, Math.max(0, cursorLine));
    const start = Math.max(0, end - TERMINAL_CONTEXT_MAX_LINES + 1);
    const lines: string[] = [];
    for (let index = start; index <= end; index += 1) {
      const line = buffer.getLine(index);
      if (!line) continue;
      const text = line.translateToString(true);
      if (typeof text === "string") lines.push(text);
    }
    return takeUtf8Suffix(lines.join("\n"), TERMINAL_CONTEXT_MAX_BYTES);
  } catch {
    return "";
  }
};

export const readTerminalContext = (
  terminal: TerminalContextSource | null | undefined,
): TerminalContextSnapshot => Object.freeze({
  selectedText: readTerminalSelectedText(terminal),
  recentOutput: readTerminalRecentOutput(terminal),
});

/**
 * Validate and encode one explicit renderer input request. Whitespace and
 * control sequences are retained exactly; no newline or carriage return is
 * appended. The returned bytes are short-lived call data only.
 */
export const prepareTerminalText = (value: unknown): PreparedTerminalText => {
  if (typeof value !== "string") {
    return { bytes: null, error: "TERMINAL_SEND_TEXT_INVALID" };
  }
  if (value.length === 0) {
    return { bytes: null, error: "TERMINAL_SEND_TEXT_EMPTY" };
  }
  if (value.includes("\0")) {
    return { bytes: null, error: "TERMINAL_SEND_TEXT_CONTAINS_NUL" };
  }
  // Every UTF-16 code unit contributes at least one UTF-8 byte. Rejecting an
  // oversized code-unit count first prevents an untrusted caller from forcing
  // an unbounded temporary encoding allocation merely to learn it is too big.
  if (value.length > TERMINAL_SEND_TEXT_MAX_BYTES) {
    return { bytes: null, error: "TERMINAL_SEND_TEXT_TOO_LARGE" };
  }
  const bytes = utf8.encode(value);
  if (bytes.byteLength > TERMINAL_SEND_TEXT_MAX_BYTES) {
    return { bytes: null, error: "TERMINAL_SEND_TEXT_TOO_LARGE" };
  }
  return { bytes, error: null };
};
