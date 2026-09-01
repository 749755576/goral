import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const readSource = (relativePath: string): string => (
  readFileSync(new URL(relativePath, import.meta.url), "utf8")
);

test("SSH xterm owns strict remote cwd notifications per view", () => {
  const source = readSource("../../src/SshTerminalSessions.tsx");
  assert.match(source, /parseRemoteTerminalOsc7Cwd/);
  assert.match(source, /registerOscHandler\(7/);
  assert.match(source, /registerOscHandler\(9/);
  assert.match(source, /cwdOperationGeneration/);
  assert.match(source, /cwdFor: \(id: WorkspaceSessionId\) => string \| undefined/);
  assert.match(source, /snapshot\.state !== "connected"/);
});

test("TerminalWorkspace follows only the exact active SSH attempt", () => {
  const source = readSource("../../src/TerminalWorkspace.tsx");
  assert.match(source, /const activeSshTerminalCwd = activeSshSession/);
  assert.match(source, /rendererSettings\.sftp\.followTerminalCwd/);
  assert.match(source, /const followKey = `\$\{workspaceId\}:\$\{operationGeneration\}:\$\{cwd\}`/);
  assert.match(source, /owner\.workspaceId !== workspaceId/);
  assert.match(source, /void loadSftpPath\(cwd, owner\)/);
});

