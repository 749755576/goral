import assert from "node:assert/strict";
import test from "node:test";

import {
  MAX_RAW_PASTE_PER_CHARACTER_LENGTH,
  TerminalInputWriteQueue,
  getTextInputWireChunks,
  prepareTerminalTextInput,
  shouldSplitImeTextInputForWire,
  shouldSplitRawPasteInputForWire,
  splitTextIntoCodePointWrites,
} from "../../src/terminalPerCharacterInput.ts";

const deferred = () => {
  let resolve!: () => void;
  const promise = new Promise<void>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
};

test("IME commits and short plain pastes split by Unicode code point", () => {
  assert.equal(shouldSplitImeTextInputForWire("中国"), true);
  assert.deepEqual(splitTextIntoCodePointWrites("中😀国"), ["中", "😀", "国"]);
  assert.deepEqual(prepareTerminalTextInput("中国", "ime")?.chunks, ["中", "国"]);
  assert.deepEqual(prepareTerminalTextInput("A😀中", "raw")?.chunks, ["A", "😀", "中"]);
});

test("raw paste splitting uses the sanitized payload and the exact 32-code-point bound", () => {
  const atLimit = "甲".repeat(MAX_RAW_PASTE_PER_CHARACTER_LENGTH);
  const aboveLimit = `${atLimit}乙`;

  assert.equal(shouldSplitRawPasteInputForWire(atLimit), true);
  assert.equal(prepareTerminalTextInput(atLimit, "raw")?.chunks.length, 32);
  assert.equal(shouldSplitRawPasteInputForWire(aboveLimit), false);
  assert.deepEqual(prepareTerminalTextInput(aboveLimit, "raw")?.chunks, [aboveLimit]);

  const invisibleInflated = `${atLimit}\u200b`;
  const prepared = prepareTerminalTextInput(invisibleInflated, "raw");
  assert.equal(prepared?.text, atLimit);
  assert.equal(prepared?.chunks.length, 32);
  assert.equal(prepareTerminalTextInput("\u200b", "raw"), null);
});

test("ANSI and bracketed-paste payloads always remain one atomic write", () => {
  for (const payload of [
    "\x1b[A",
    "\x1b[200~echo safe\x1b[201~",
    "plain\x1bsequence",
  ]) {
    assert.equal(shouldSplitImeTextInputForWire(payload), false);
    assert.equal(shouldSplitRawPasteInputForWire(payload), false);
    assert.deepEqual(getTextInputWireChunks(payload, true), [payload]);
    assert.deepEqual(prepareTerminalTextInput(payload, "ime")?.chunks, [payload]);
    assert.deepEqual(prepareTerminalTextInput(payload, "raw")?.chunks, [payload]);
  }
});

test("write queue preserves strict character and event order", async () => {
  const queue = new TerminalInputWriteQueue();
  const gate = deferred();
  const writes: string[] = [];

  const first = queue.enqueue(["中", "国"], async (chunk) => {
    writes.push(chunk);
    if (chunk === "中") await gate.promise;
  });
  const second = queue.enqueue(["!"], async (chunk) => {
    writes.push(chunk);
  });

  await Promise.resolve();
  assert.deepEqual(writes, ["中"]);
  gate.resolve();
  await Promise.all([first, second]);
  assert.deepEqual(writes, ["中", "国", "!"]);
});

test("invalidating a queue drops retired chunks without blocking a replacement session", async () => {
  const queue = new TerminalInputWriteQueue();
  const oldWriteGate = deferred();
  const writes: string[] = [];

  const retired = queue.enqueue(["旧", "队"], async (chunk) => {
    writes.push(chunk);
    if (chunk === "旧") await oldWriteGate.promise;
  });
  await Promise.resolve();
  assert.deepEqual(writes, ["旧"]);

  queue.invalidate();
  const replacement = queue.enqueue(["新"], async (chunk) => {
    writes.push(chunk);
  });
  await replacement;
  assert.deepEqual(writes, ["旧", "新"]);

  oldWriteGate.resolve();
  await retired;
  assert.deepEqual(writes, ["旧", "新"]);
});
