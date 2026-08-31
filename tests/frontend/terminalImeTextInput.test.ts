import assert from "node:assert/strict";
import test from "node:test";

import {
  prepareTerminalTextInput,
  type PreparedTerminalTextInput,
} from "../../src/terminalPerCharacterInput.ts";
import {
  PROCESS_IME_DATA_GRACE_MS,
  TerminalImeTextInputState,
  createTerminalInputBinding,
  shouldBlockKeyPressForImeTextInput,
} from "../../src/terminalImeTextInput.ts";

test("full-width IME punctuation owns its matching press and release", () => {
  const state = new TerminalImeTextInputState();
  const commits: string[] = [];

  assert.deepEqual(state.handleKeyEvent({ type: "keydown", key: ",", code: "Comma" }), {
    allowXterm: false,
    commitText: null,
  });
  assert.equal(state.deferredKey, ",");
  const inputCommit = state.handleInputEvent({ inputType: "insertText", data: "，" });
  if (inputCommit) commits.push(inputCommit);
  assert.equal(state.deferredKey, null);
  assert.deepEqual(state.handleKeyEvent({
    type: "keypress",
    key: ",",
    code: "Comma",
    keyCode: 44,
  }), {
    allowXterm: false,
    commitText: null,
  });
  const release = state.handleKeyEvent({
    type: "keyup",
    key: ",",
    code: "Comma",
    keyCode: 44,
  });
  if (release.commitText) commits.push(release.commitText);
  assert.deepEqual(release, { allowXterm: false, commitText: null });
  assert.deepEqual(commits, ["，"]);
});

test("plain punctuation is committed once and its complete key lifecycle is suppressed", () => {
  const state = new TerminalImeTextInputState();
  const commits: string[] = [];

  assert.deepEqual(state.handleKeyEvent({
    type: "keydown",
    key: ",",
    code: "Comma",
    keyCode: 188,
  }), { allowXterm: false, commitText: null });
  assert.deepEqual(state.handleKeyEvent({
    type: "keypress",
    key: ",",
    code: "Comma",
    keyCode: 44,
  }), { allowXterm: false, commitText: null });
  const release = state.handleKeyEvent({
    type: "keyup",
    key: ",",
    code: "Comma",
    keyCode: 188,
  });
  if (release.commitText) commits.push(release.commitText);

  assert.deepEqual(release, { allowXterm: false, commitText: "," });
  assert.deepEqual(commits, [","]);
});

test("composition and Process/229 commits are identified as IME text", () => {
  const state = new TerminalImeTextInputState();
  state.handleKeyEvent({
    type: "keydown",
    key: "Process",
    keyCode: 229,
    isComposing: true,
  });

  const source = state.consumeDataSource("中国");
  assert.equal(source, "ime");
  assert.deepEqual(prepareTerminalTextInput("中国", source)?.chunks, ["中", "国"]);
  assert.equal(state.consumeDataSource("x"), "raw");
});

test("Process/229 keyup releases a deferred punctuation key instead of wedging input", () => {
  const state = new TerminalImeTextInputState();
  state.handleKeyEvent({ type: "keydown", key: ".", code: "Period" });

  assert.deepEqual(state.handleKeyEvent({
    type: "keyup",
    key: "Process",
    keyCode: 229,
  }), {
    allowXterm: false,
    commitText: ".",
  });
  assert.equal(state.deferredKey, null);
});

test("an unrelated real keyup flushes stale punctuation without stealing its identity", () => {
  const state = new TerminalImeTextInputState();
  state.handleKeyEvent({ type: "keydown", key: ",", code: "Comma", keyCode: 188 });

  assert.deepEqual(state.handleKeyEvent({
    type: "keyup",
    key: "x",
    code: "KeyX",
    keyCode: 88,
  }), {
    allowXterm: true,
    commitText: ",",
  });
  assert.equal(state.deferredKey, null);
  assert.deepEqual(state.handleKeyEvent({ type: "keydown", key: "a", code: "KeyA" }), {
    allowXterm: true,
    commitText: null,
  });
});

test("every Windows IME sentinel keyup releases deferred punctuation once", () => {
  for (const key of ["Dead", "Compose", "Unidentified"] as const) {
    const state = new TerminalImeTextInputState();
    state.handleKeyEvent({ type: "keydown", key: "/", code: "Slash", keyCode: 191 });
    assert.deepEqual(state.handleKeyEvent({ type: "keyup", key }), {
      allowXterm: false,
      commitText: "/",
    });
    assert.equal(state.deferredKey, null);
    assert.deepEqual(state.handleKeyEvent({ type: "keydown", key: "x", code: "KeyX" }), {
      allowXterm: true,
      commitText: null,
    });
  }
});

test("modifier and composing keyups do not prematurely flush deferred punctuation", () => {
  const state = new TerminalImeTextInputState();
  state.handleKeyEvent({ type: "keydown", key: ";", code: "Semicolon" });
  assert.deepEqual(state.handleKeyEvent({ type: "keyup", key: "Shift" }), {
    allowXterm: true,
    commitText: null,
  });
  assert.equal(state.deferredKey, ";");
  assert.deepEqual(state.handleKeyEvent({
    type: "keyup",
    key: ";",
    code: "Semicolon",
    isComposing: true,
  }), {
    allowXterm: true,
    commitText: null,
  });
  assert.equal(state.deferredKey, ";");
});

test("a later ordinary key flushes stale punctuation and remains usable", () => {
  const state = new TerminalImeTextInputState();
  state.handleKeyEvent({ type: "keydown", key: ";", code: "Semicolon" });

  assert.deepEqual(state.handleKeyEvent({ type: "keydown", key: "a", code: "KeyA" }), {
    allowXterm: true,
    commitText: ";",
  });
  assert.deepEqual(state.handleKeyEvent({ type: "keyup", key: "a", code: "KeyA" }), {
    allowXterm: true,
    commitText: null,
  });
});

test("modified shortcuts discard stale punctuation instead of injecting it before Ctrl+C", () => {
  const state = new TerminalImeTextInputState();
  state.handleKeyEvent({ type: "keydown", key: ",", code: "Comma" });

  assert.deepEqual(state.handleKeyEvent({
    type: "keydown",
    key: "c",
    code: "KeyC",
    ctrlKey: true,
  }), {
    allowXterm: true,
    commitText: null,
  });
  assert.equal(state.deferredKey, null);
});

test("only the matching deferred keypress is blocked", () => {
  assert.equal(shouldBlockKeyPressForImeTextInput(",", {
    type: "keypress",
    key: ",",
    keyCode: 44,
  }, 44), true);
  assert.equal(shouldBlockKeyPressForImeTextInput(",", {
    type: "keypress",
    key: "x",
    keyCode: 120,
  }, 44), false);
});

test("Process/229 survives a zero-delay task before a long IME commit", async () => {
  let keyHandler: ((event: KeyboardEvent) => boolean) | null = null;
  const inputs: PreparedTerminalTextInput[] = [];
  const binding = createTerminalInputBinding({
    attachCustomKeyEventHandler(handler) {
      keyHandler = handler;
    },
  }, (input) => {
    inputs.push(input);
  });
  const longImeCommit = "中文".repeat(17);
  const longRawPaste = "原子".repeat(17);

  assert.equal(PROCESS_IME_DATA_GRACE_MS > 0, true);
  assert.ok(keyHandler);
  keyHandler({
    type: "keydown",
    key: "Process",
    keyCode: 229,
    isComposing: false,
  } as KeyboardEvent);
  await Promise.resolve();
  await new Promise<void>((resolve) => setTimeout(resolve, 0));

  binding.handleData(longImeCommit);
  binding.handleData(longRawPaste);
  binding.dispose();

  assert.equal(inputs[0]?.source, "ime");
  assert.deepEqual(inputs[0]?.chunks, Array.from(longImeCommit));
  assert.equal(inputs[1]?.source, "raw");
  assert.deepEqual(inputs[1]?.chunks, [longRawPaste]);
});
