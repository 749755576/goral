import assert from "node:assert/strict";
import test from "node:test";

import {
  prepareTerminalText,
  readTerminalContext,
  readTerminalRecentOutput,
  readTerminalSelectedText,
  takeUtf8Prefix,
  takeUtf8Suffix,
  TERMINAL_CONTEXT_MAX_BYTES,
  TERMINAL_CONTEXT_MAX_LINES,
  TERMINAL_SEND_TEXT_MAX_BYTES,
  type TerminalContextSource,
} from "../../src/terminalSessionBridge.ts";

const utf8 = new TextEncoder();

const terminalWith = (
  selection: string,
  lines: readonly string[],
  cursorLine = lines.length - 1,
): TerminalContextSource => ({
  getSelection: () => selection,
  buffer: {
    active: {
      baseY: Math.max(0, cursorLine),
      cursorY: 0,
      length: lines.length,
      getLine: (index) => lines[index] === undefined
        ? undefined
        : { translateToString: () => lines[index]! },
    },
  },
});

test("UTF-8 context bounds never split a code point", () => {
  const prefixInput = `${"a".repeat(TERMINAL_CONTEXT_MAX_BYTES - 1)}界tail`;
  const suffixInput = `head界${"z".repeat(TERMINAL_CONTEXT_MAX_BYTES - 1)}`;
  const prefix = takeUtf8Prefix(prefixInput, TERMINAL_CONTEXT_MAX_BYTES);
  const suffix = takeUtf8Suffix(suffixInput, TERMINAL_CONTEXT_MAX_BYTES);

  assert.equal(prefix, "a".repeat(TERMINAL_CONTEXT_MAX_BYTES - 1));
  assert.equal(suffix, "z".repeat(TERMINAL_CONTEXT_MAX_BYTES - 1));
  assert.ok(utf8.encode(prefix).byteLength <= TERMINAL_CONTEXT_MAX_BYTES);
  assert.ok(utf8.encode(suffix).byteLength <= TERMINAL_CONTEXT_MAX_BYTES);
  assert.doesNotMatch(prefix + suffix, /\ufffd/);
});

test("terminal context reads one exact source with at most 200 recent lines and 16 KiB", () => {
  const lines = Array.from({ length: 250 }, (_, index) => `line-${index}`);
  const source = terminalWith("selected text", lines);
  const context = readTerminalContext(source);
  const outputLines = context.recentOutput.split("\n");

  assert.equal(context.selectedText, "selected text");
  assert.equal(outputLines.length, TERMINAL_CONTEXT_MAX_LINES);
  assert.equal(outputLines[0], "line-50");
  assert.equal(outputLines.at(-1), "line-249");
  assert.ok(utf8.encode(context.recentOutput).byteLength <= TERMINAL_CONTEXT_MAX_BYTES);

  const large = terminalWith("界".repeat(20_000), ["old", "新".repeat(20_000)]);
  assert.ok(utf8.encode(readTerminalSelectedText(large)).byteLength <= TERMINAL_CONTEXT_MAX_BYTES);
  const recent = readTerminalRecentOutput(large);
  assert.ok(utf8.encode(recent).byteLength <= TERMINAL_CONTEXT_MAX_BYTES);
  assert.ok(recent.endsWith("新"));
  assert.doesNotMatch(recent, /\ufffd/);
});

test("terminal context failures are isolated and return no stale text", () => {
  const broken: TerminalContextSource = {
    getSelection: () => {
      throw new Error("selection contains a secret failure detail");
    },
    buffer: {
      active: {
        baseY: 0,
        cursorY: 0,
        length: 1,
        getLine: () => ({
          translateToString: () => {
            throw new Error("buffer contains a secret failure detail");
          },
        }),
      },
    },
  };

  assert.equal(readTerminalSelectedText(broken), "");
  assert.equal(readTerminalRecentOutput(broken), "");
  assert.deepEqual(readTerminalContext(undefined), {
    selectedText: "",
    recentOutput: "",
  });
});

test("explicit terminal text validation preserves bytes and never adds Enter", () => {
  const exact = "  printf 'ok'\u001b[D";
  const prepared = prepareTerminalText(exact);
  assert.equal(prepared.error, null);
  assert.equal(new TextDecoder().decode(prepared.bytes!), exact);
  assert.equal(new TextDecoder().decode(prepared.bytes!).endsWith("\r"), false);
  assert.equal(prepareTerminalText(42).error, "TERMINAL_SEND_TEXT_INVALID");
  assert.equal(prepareTerminalText("").error, "TERMINAL_SEND_TEXT_EMPTY");
  assert.equal(
    prepareTerminalText("echo\0hidden").error,
    "TERMINAL_SEND_TEXT_CONTAINS_NUL",
  );
  assert.equal(prepareTerminalText("a".repeat(TERMINAL_SEND_TEXT_MAX_BYTES)).error, null);
  assert.equal(
    prepareTerminalText("界".repeat(TERMINAL_SEND_TEXT_MAX_BYTES)).error,
    "TERMINAL_SEND_TEXT_TOO_LARGE",
  );
});
