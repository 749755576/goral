import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);
const dialogUrl = new URL("../../src/WorkspacePromptDialog.tsx", import.meta.url);

test("SFTP and saved-host mutations use the localized in-app dialog boundary", async () => {
  const [workspace, dialog] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(dialogUrl, "utf8"),
  ]);

  assert.doesNotMatch(workspace, /window\.(?:prompt|confirm)\(/);
  assert.match(workspace, /requestWorkspaceText\(/);
  assert.match(workspace, /requestWorkspaceConfirmation\(/);
  assert.match(workspace, /<WorkspacePromptDialog/);
  assert.match(dialog, /role="dialog"/);
  assert.match(dialog, /aria-labelledby=\{titleId\}/);
  assert.match(dialog, /request\.cancelLabel/);
  assert.match(dialog, /request\.confirmLabel/);
});
