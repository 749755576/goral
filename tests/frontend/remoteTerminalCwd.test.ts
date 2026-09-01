import test from "node:test";
import assert from "node:assert/strict";

import {
  normalizeRemoteTerminalCwd,
  parseRemoteTerminalOsc7Cwd,
  parseRemoteTerminalOsc9Cwd,
} from "../../src/remoteTerminalCwd.ts";

test("remote OSC 7 paths are decoded and descriptive hosts are ignored", () => {
  assert.equal(
    parseRemoteTerminalOsc7Cwd("file://server.example/srv/app%20one"),
    "/srv/app one",
  );
  assert.equal(parseRemoteTerminalOsc7Cwd("file:///srv/app"), "/srv/app");
});

test("remote cwd parsing rejects authority credentials and traversal", () => {
  assert.equal(parseRemoteTerminalOsc7Cwd("file://user:pass@host/srv/app"), null);
  assert.equal(parseRemoteTerminalOsc7Cwd("file://host/srv/%2e%2e/secrets"), null);
  assert.equal(parseRemoteTerminalOsc7Cwd("file://host/srv/app?secret=1"), null);
  assert.equal(parseRemoteTerminalOsc9Cwd("9;/srv/../etc"), null);
});

test("remote cwd normalization keeps absolute paths and rejects local namespaces", () => {
  assert.equal(normalizeRemoteTerminalCwd("/var/lib/goral"), "/var/lib/goral");
  assert.equal(normalizeRemoteTerminalCwd("C:\\work\\project"), "C:/work/project");
  assert.equal(normalizeRemoteTerminalCwd("//server/share"), null);
  assert.equal(normalizeRemoteTerminalCwd("\\\\server\\share"), null);
  assert.equal(normalizeRemoteTerminalCwd("relative/path"), null);
  assert.equal(normalizeRemoteTerminalCwd("/tmp/./work"), null);
});

test("OSC 9;9 payloads are accepted only with the explicit marker", () => {
  assert.equal(parseRemoteTerminalOsc9Cwd("9;/srv/project"), "/srv/project");
  assert.equal(parseRemoteTerminalOsc9Cwd("/srv/project"), null);
});

