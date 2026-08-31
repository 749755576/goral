import assert from "node:assert/strict";
import test from "node:test";

import {
  normalizeTrustedLocalCwd,
  parseTrustedLocalOsc7Cwd,
  parseTrustedLocalOsc9Cwd,
} from "../../src/localTerminalCwd.ts";

test("OSC 7 accepts encoded local absolute paths without granting URI authority", () => {
  assert.equal(
    parseTrustedLocalOsc7Cwd("file://DESKTOP/C:/Users/me/My%20Project", "windows"),
    "C:\\Users\\me\\My Project",
  );
  assert.equal(
    parseTrustedLocalOsc7Cwd("file://remote-host/var/lib/app", "posix"),
    "/var/lib/app",
  );
});

test("OSC cwd parsing rejects relative, UNC, device, traversal, and malformed metadata", () => {
  const rejectedWindows = [
    "file://server/share",
    "file:////server/share",
    "file://host/C:/work/../secret",
    "file://user:password@host/C:/work",
    "file://host/C:/work?next=D:/other",
    "file://host/C:/work%00hidden",
    "https://host/C:/work",
    "/C:/raw-path-is-not-osc7",
  ];
  for (const payload of rejectedWindows) {
    assert.equal(parseTrustedLocalOsc7Cwd(payload, "windows"), null, payload);
  }
  assert.equal(normalizeTrustedLocalCwd("relative\\path", "windows"), null);
  assert.equal(normalizeTrustedLocalCwd("\\\\?\\C:\\work", "windows"), null);
  assert.equal(normalizeTrustedLocalCwd("//network/share", "posix"), null);
  assert.equal(normalizeTrustedLocalCwd("/srv/../secret", "posix"), null);
});

test("OSC 9;9 compatibility accepts only a strict native absolute path", () => {
  assert.equal(parseTrustedLocalOsc9Cwd("9;c:/work/tree", "windows"), "C:\\work\\tree");
  assert.equal(parseTrustedLocalOsc9Cwd("9;/srv/app", "posix"), "/srv/app");
  assert.equal(parseTrustedLocalOsc9Cwd("4;progress", "windows"), null);
  assert.equal(parseTrustedLocalOsc9Cwd("9;\\\\server\\share", "windows"), null);
  assert.equal(parseTrustedLocalOsc9Cwd("9;C:\\bad?name", "windows"), null);
});
