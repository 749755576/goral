/**
 * Removes invisible formatting characters that can make a command look
 * different from the bytes sent to a PTY. ZWNJ and ZWJ remain valid input:
 * they carry meaning in Persian text and emoji sequences.
 */
const INVISIBLE_TERMINAL_INPUT =
  /[\u00ad\u061c\u200b\u200e-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/gu;

export const sanitizeTerminalInput = (data: string): string =>
  data ? data.replace(INVISIBLE_TERMINAL_INPUT, "") : data;
