import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { createTranslator } from "../../src/i18n.ts";
import {
  closeAfterSuccessfulRemoteEditorSave,
  encodeRemoteEditorText,
  hasUtf8Bom,
  persistRemoteEditorDraft,
} from "../../src/remoteEditorSave.ts";

const deferred = <T>() => {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
};

test("save-and-close waits for a successful native save before closing", async () => {
  const pending = deferred<void>();
  let closeCount = 0;
  const operation = closeAfterSuccessfulRemoteEditorSave(
    () => persistRemoteEditorDraft(() => pending.promise),
    () => { closeCount += 1; },
  );

  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(closeCount, 0, "an in-flight save must keep the draft mounted");

  pending.resolve();
  assert.deepEqual(await operation, { kind: "saved" });
  assert.equal(closeCount, 1);
});

test("conflict and disconnected-session failures never close the editor", async () => {
  for (const failure of [
    new Error("SFTP_EDITOR_DESTINATION_CHANGED: remote contents differ"),
    new Error("SSH session is not connected"),
  ]) {
    let closeCount = 0;
    const result = await closeAfterSuccessfulRemoteEditorSave(
      () => persistRemoteEditorDraft(async () => { throw failure; }),
      () => { closeCount += 1; },
    );

    assert.equal(closeCount, 0);
    assert.equal(
      result.kind,
      failure.message.startsWith("SFTP_EDITOR_DESTINATION_CHANGED") ? "conflict" : "failed",
    );
  }
});

test("busy and stale saves cannot close or discard the current draft", async () => {
  for (const kind of ["busy", "stale"] as const) {
    let closeCount = 0;
    const result = await closeAfterSuccessfulRemoteEditorSave(
      async () => ({ kind }),
      () => { closeCount += 1; },
    );
    assert.deepEqual(result, { kind });
    assert.equal(closeCount, 0);
  }
});

test("conditional saves retain the exact original bytes and preserve an existing UTF-8 BOM", () => {
  const original = Uint8Array.of(0xef, 0xbb, 0xbf, 0x61);
  assert.equal(hasUtf8Bom(original), true);
  assert.deepEqual(
    [...encodeRemoteEditorText("b", hasUtf8Bom(original))],
    [0xef, 0xbb, 0xbf, 0x62],
  );
  assert.deepEqual([...encodeRemoteEditorText("b", false)], [0x62]);
});

test("RemoteEditor uses the conditional-write gate and disables closing while saving", async () => {
  const [editor, backend] = await Promise.all([
    readFile(new URL("../../src/RemoteEditor.tsx", import.meta.url), "utf8"),
    readFile(new URL("../../src/backend.ts", import.meta.url), "utf8"),
  ]);

  assert.match(editor, /closeAfterSuccessfulRemoteEditorSave\(save,/u);
  assert.match(editor, /originalBytes,/u);
  assert.doesNotMatch(editor, /save\(\)\.then\(\(\) => onClose\(\)\)/u);
  assert.match(editor, /onClick=\{requestClose\} disabled=\{saving\}/u);
  assert.match(editor, /className="is-destructive"[\s\S]*?disabled=\{saving\}/u);
  assert.doesNotMatch(editor, /\.message|String\(error\)|String\(cause\)/u);
  assert.match(backend, /invoke\("sftp_replace_file_if_unchanged_raw", envelope\)/u);
  assert.doesNotMatch(backend, /invoke\("sftp_write_file_raw"/u);
});

test("remote editor filename interpolation is complete in both locales", () => {
  for (const locale of ["zh-CN", "en-US"] as const) {
    const t = createTranslator(locale);
    for (const key of ["editor.contentLabel", "editor.confirmCloseBody"] as const) {
      const rendered = t(key, { name: "sshd_config" });
      assert.match(rendered, /sshd_config/u);
      assert.doesNotMatch(rendered, /\{\{?name\}?\}/u);
    }
  }
});
