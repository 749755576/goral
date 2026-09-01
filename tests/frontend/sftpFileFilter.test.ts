import assert from "node:assert/strict";
import test from "node:test";

import {
  MAX_SFTP_FILE_FILTER_LENGTH,
  createSftpFilterDirectoryScopeKey,
  createSftpFilterSessionScopeKey,
  createSftpFilterMemory,
  filterSftpEntries,
  isEditableSftpFilterShortcutTarget,
  limitSftpFileFilter,
  resolveSftpFilterEscapeAction,
  shouldFocusSftpFileFilter,
  type SftpFilterShortcutEvent,
} from "../../src/sftpFileFilter.ts";

const entries = Object.freeze([
  Object.freeze({ name: "Alpha.txt", id: 1 }),
  Object.freeze({ name: "beta.log", id: 2 }),
  Object.freeze({ name: "资料", id: 3 }),
]);

const target = (
  tagName: string,
  options: Readonly<{
    contentEditable?: boolean;
    closest?: unknown;
  }> = {},
): EventTarget => ({
  tagName,
  isContentEditable: options.contentEditable ?? false,
  closest: () => options.closest ?? null,
}) as unknown as EventTarget;

const shortcut = (
  overrides: Partial<SftpFilterShortcutEvent> = {},
): SftpFilterShortcutEvent => ({
  key: "f",
  ctrlKey: true,
  target: target("BUTTON"),
  ...overrides,
});

test("file filtering is case-insensitive, ordered, immutable, and current-list only", () => {
  const alpha = filterSftpEntries(entries, "  ALPHA  ");
  assert.deepEqual(alpha, [entries[0]]);
  assert.deepEqual(filterSftpEntries(entries, "资料"), [entries[2]]);
  assert.deepEqual(filterSftpEntries(entries.slice(1), "alpha"), []);
  assert.deepEqual(entries.map((entry) => entry.id), [1, 2, 3]);
});

test("clearing the filter restores the exact complete directory snapshot", () => {
  assert.equal(filterSftpEntries(entries, ""), entries);
  assert.equal(filterSftpEntries(entries, "   "), entries);
  assert.deepEqual(filterSftpEntries(entries, "log"), [entries[1]]);
  assert.equal(resolveSftpFilterEscapeAction("log"), "clear");
  assert.equal(resolveSftpFilterEscapeAction(""), "close");
});

test("filter memory restores exact directory scopes and stays bounded", () => {
  const memory = createSftpFilterMemory(2);
  memory.write("session-a:/home", { open: true, value: "  report  " });
  memory.write("session-b:/home", { open: false, value: "秘密" });

  assert.deepEqual(memory.read("session-a:/home"), {
    open: true,
    value: "  report  ",
  });
  assert.deepEqual(memory.read("session-b:/home"), {
    open: false,
    value: "秘密",
  });

  // Touch A, then add C: B is the least recently used scope and is evicted.
  assert.ok(memory.read("session-a:/home"));
  memory.write("session-c:/home", { open: true, value: "c" });
  assert.equal(memory.read("session-b:/home"), undefined);
  assert.deepEqual(memory.read("session-a:/home"), { open: true, value: "  report  " });
  assert.deepEqual(memory.read("session-c:/home"), { open: true, value: "c" });

  memory.write("session-c:/home", { open: false, value: `${"x".repeat(MAX_SFTP_FILE_FILTER_LENGTH)}tail` });
  assert.equal(memory.read("session-c:/home")?.value.length, MAX_SFTP_FILE_FILTER_LENGTH);
  memory.clear();
  assert.equal(memory.read("session-a:/home"), undefined);
});

test("filter input is bounded by Unicode code point without splitting emoji", () => {
  const value = `${"a".repeat(MAX_SFTP_FILE_FILTER_LENGTH - 1)}😀tail`;
  const limited = limitSftpFileFilter(value);
  assert.equal(Array.from(limited).length, MAX_SFTP_FILE_FILTER_LENGTH);
  assert.equal(limited.endsWith("😀"), true);
});

test("scope keys change for directory, workspace, SSH retry, and SFTP generation", () => {
  const owner = {
    workspaceId: "ws-a",
    operationGeneration: 1,
    backendSessionId: "native-a",
    sftpGeneration: 1,
  };
  const session = createSftpFilterSessionScopeKey(owner);
  const directory = createSftpFilterDirectoryScopeKey(owner, "/home/a");

  assert.notEqual(directory, createSftpFilterDirectoryScopeKey(owner, "/home/b"));
  assert.notEqual(session, createSftpFilterSessionScopeKey({ ...owner, workspaceId: "ws-b" }));
  assert.notEqual(session, createSftpFilterSessionScopeKey({ ...owner, operationGeneration: 2 }));
  assert.notEqual(session, createSftpFilterSessionScopeKey({ ...owner, sftpGeneration: 2 }));
  assert.notEqual(session, createSftpFilterSessionScopeKey({ ...owner, backendSessionId: "native-b" }));
});

test("Ctrl/Cmd+F is claimed only by an active SFTP surface", () => {
  assert.equal(shouldFocusSftpFileFilter(shortcut(), true), true);
  assert.equal(shouldFocusSftpFileFilter(shortcut({ ctrlKey: false, metaKey: true }), true), true);
  assert.equal(shouldFocusSftpFileFilter(shortcut(), false), false);
  assert.equal(shouldFocusSftpFileFilter(shortcut({ key: "g" }), true), false);
  assert.equal(shouldFocusSftpFileFilter(shortcut({ shiftKey: true }), true), false);
  assert.equal(shouldFocusSftpFileFilter(shortcut({ altKey: true }), true), false);
  assert.equal(shouldFocusSftpFileFilter(shortcut({ defaultPrevented: true }), true), false);
  assert.equal(shouldFocusSftpFileFilter(shortcut({ isComposing: true }), true), false);
});

test("ordinary editors, terminal search, and AI input retain their search shortcut", () => {
  const input = target("INPUT");
  const textarea = target("TEXTAREA");
  const select = target("SELECT");
  const editable = target("DIV", { contentEditable: true });
  const nestedTextbox = target("SPAN", { closest: { role: "textbox" } });

  for (const editableTarget of [input, textarea, select, editable, nestedTextbox]) {
    assert.equal(isEditableSftpFilterShortcutTarget(editableTarget), true);
    assert.equal(
      shouldFocusSftpFileFilter(shortcut({ target: editableTarget }), true),
      false,
    );
  }

  assert.equal(
    shouldFocusSftpFileFilter(shortcut({ target: input }), true, input),
    true,
    "repeating Ctrl/Cmd+F in the SFTP filter keeps that exact filter focused",
  );
});
