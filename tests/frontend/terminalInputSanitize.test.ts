import assert from "node:assert/strict";
import test from "node:test";

import { sanitizeTerminalInput } from "../../src/terminalInputSanitize.ts";

test("terminal input removes invisible command characters", () => {
  const dangerousBidiControls = [
    "\u061c",
    "\u200e",
    "\u200f",
    ...Array.from({ length: 5 }, (_, index) => String.fromCodePoint(0x202a + index)),
    ...Array.from({ length: 4 }, (_, index) => String.fromCodePoint(0x2066 + index)),
  ];
  assert.equal(
    sanitizeTerminalInput(
      `\u00ad\u200bls${dangerousBidiControls.join("")}\u2060\u2061\u2062\u2063\u2064\ufeff -la`,
    ),
    "ls -la",
  );
  for (const control of dangerousBidiControls) {
    assert.equal(sanitizeTerminalInput(`echo safe${control}suffix`), "echo safesuffix");
  }
  assert.equal(sanitizeTerminalInput("\u200b\ufeff\u2060"), "");
});

test("terminal input preserves meaningful joiners, text and control input", () => {
  assert.equal(sanitizeTerminalInput("a\u200cb"), "a\u200cb");
  assert.equal(sanitizeTerminalInput("a\u200db"), "a\u200db");
  assert.equal(sanitizeTerminalInput("你好 👨‍💻\r\u0003\u007f"), "你好 👨‍💻\r\u0003\u007f");
});

test("terminal input sanitization is stable", () => {
  const once = sanitizeTerminalInput("ls\u200b\r");
  assert.equal(once, "ls\r");
  assert.equal(sanitizeTerminalInput(once), once);
});
