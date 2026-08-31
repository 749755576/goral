import assert from "node:assert/strict";
import test from "node:test";

import {
  mapTerminalBackspaceInput,
  prepareSerialConfigForSavedHost,
  resolveSerialBackspaceFormValue,
  resolveSerialBackspaceOverrideOnSave,
} from "../../src/serialBackspace.ts";
import { handleSerialLineModeInput } from "../../src/serialLineInput.ts";
import { formatSerialLocalEcho } from "../../src/serialLocalEcho.ts";

test("Serial local echo preserves legacy printable, newline, and editing output", () => {
  assert.equal(formatSerialLocalEcho("show version"), "show version");
  assert.equal(formatSerialLocalEcho("one\ntwo"), "one\r\ntwo");
  assert.equal(formatSerialLocalEcho("\r\n"), "\r\n");
  assert.equal(formatSerialLocalEcho("\x7f"), "\b \b");
  assert.equal(formatSerialLocalEcho("\b"), "\b \b");
  assert.equal(formatSerialLocalEcho("\x03"), "^C");
  assert.equal(formatSerialLocalEcho("\x15"), "");
});

test("Serial line mode sends every completed pasted line and retains the tail", () => {
  const writes: string[] = [];
  const echoes: string[] = [];
  const bufferRef = { current: "" };
  handleSerialLineModeInput("show version\rshow clock\nlast", {
    bufferRef,
    localEcho: true,
    writeToSession: (data) => writes.push(data),
    writeToTerminal: (data) => echoes.push(data),
  });
  assert.deepEqual(writes, ["show version\r", "show clock\r"]);
  assert.equal(bufferRef.current, "last");
  assert.deepEqual(echoes, ["show version", "\r\n", "show clock", "\r\n", "last"]);
});

test("Serial line editing handles Backspace, Ctrl+U, and Ctrl+C", () => {
  const writes: string[] = [];
  const echoes: string[] = [];
  const bufferRef = { current: "abc" };
  const options = {
    bufferRef,
    localEcho: true,
    writeToSession: (data: string) => writes.push(data),
    writeToTerminal: (data: string) => echoes.push(data),
  };
  handleSerialLineModeInput("\x7f", options);
  assert.equal(bufferRef.current, "ab");
  handleSerialLineModeInput("\x15", options);
  assert.equal(bufferRef.current, "");
  bufferRef.current = "pending";
  handleSerialLineModeInput("\x03", options);
  assert.equal(bufferRef.current, "");
  assert.deepEqual(writes, ["\x03"]);
  assert.deepEqual(echoes, ["\b \b", "\b \b\b \b", "^C\r\n"]);
});

test("Ctrl-H mapping affects only xterm DEL in explicit ctrl-h mode", () => {
  assert.equal(mapTerminalBackspaceInput("\x7f", "ctrl-h"), "\x08");
  assert.equal(mapTerminalBackspaceInput("\x7f", "default"), "\x7f");
  assert.equal(mapTerminalBackspaceInput("x", "ctrl-h"), "x");
});

test("saved Serial backspace keeps explicit overrides and preserves inheritance", () => {
  assert.deepEqual(prepareSerialConfigForSavedHost({
    path: "COM3",
    baudRate: 115200,
    backspaceBehavior: "default" as const,
  }), { path: "COM3", baudRate: 115200 });
  assert.deepEqual(prepareSerialConfigForSavedHost({
    path: "COM3",
    baudRate: 115200,
    backspaceBehavior: "ctrl-h" as const,
  }), { path: "COM3", baudRate: 115200, backspaceBehavior: "ctrl-h" });

  const inherited = { serialConfig: { backspaceBehavior: undefined } };
  assert.equal(
    resolveSerialBackspaceFormValue(inherited, { backspaceBehavior: "ctrl-h" }),
    "ctrl-h",
  );
  assert.equal(resolveSerialBackspaceOverrideOnSave({
    initialHost: inherited,
    selectedBehavior: "ctrl-h",
    behaviorChanged: false,
  }), undefined);
  assert.equal(resolveSerialBackspaceOverrideOnSave({
    initialHost: inherited,
    selectedBehavior: "default",
    behaviorChanged: true,
  }), "default");
});
