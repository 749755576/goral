import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const backendUrl = new URL("../../src/backend.ts", import.meta.url);

function sourceBetween(source: string, start: string, end: string): string {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex + start.length);
  assert.ok(startIndex >= 0, `missing source marker: ${start}`);
  assert.ok(endIndex > startIndex, `missing source marker after ${start}: ${end}`);
  return source.slice(startIndex, endIndex);
}

test("renderer SSH clone request carries only exact source authority and optional shell options", async () => {
  const source = await readFile(backendUrl, "utf8");
  const request = sourceBetween(
    source,
    "export type CloneSshSessionRequest",
    "export type StartSavedTelnetSessionRequest",
  );
  const adapter = sourceBetween(
    source,
    "export const cloneSshSession",
    "export const startSavedHostSession",
  );

  assert.match(request, /sourceSessionId:\s*string/);
  assert.match(request, /shell\?:\s*StartSshSessionRequest\["shell"\]/);
  assert.doesNotMatch(
    request,
    /credential|password|hostname|username|hostId|expectedRevision|clientAttemptId/i,
  );
  assert.match(
    adapter,
    /startSessionWithChannels\("clone_ssh_session",\s*request,\s*callbacks\)/,
  );
});
