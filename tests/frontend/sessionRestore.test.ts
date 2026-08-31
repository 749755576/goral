import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  MAX_SESSION_RESTORE_BYTES,
  MAX_SESSION_RESTORE_ENTRIES,
  MAX_SESSION_RESTORE_PANE_DEPTH,
  MAX_SESSION_RESTORE_PANE_NODES,
  SESSION_RESTORE_STORAGE_KEY,
  SESSION_RESTORE_VERSION,
  createSessionRestoreSnapshot,
  createSessionRestoreSnapshotFromRegistry,
  createSessionRestoreStore,
  decodeSessionRestoreSnapshot,
  encodeSessionRestoreSnapshot,
  validateSessionRestoreSnapshot,
  type SessionRestoreEntry,
  type SessionRestorePaneLayout,
} from "../../src/sessionRestore.ts";
import {
  addTerminalSessionSnapshot,
  createTerminalSessionRegistrySnapshot,
  workspaceSessionIdFrom,
} from "../../src/terminalSessionRegistry.ts";

const id = (sequence: number) => workspaceSessionIdFrom(
  `ws-00000000-0000-4000-8000-${String(sequence).padStart(12, "0")}`,
);

const saved = (sequence: number): SessionRestoreEntry => ({
  workspaceSessionId: id(sequence),
  protocol: "ssh",
  target: {
    kind: "saved",
    savedHostId: `host-${sequence}`,
    label: `生产主机 ${sequence}`,
  },
});

test("restore snapshots retain only bounded protocol and target presentation data", () => {
  const snapshot = createSessionRestoreSnapshot([saved(1)], id(1));
  const encoded = encodeSessionRestoreSnapshot(snapshot);
  const roundTrip = decodeSessionRestoreSnapshot(encoded);

  assert.deepEqual(roundTrip, snapshot);
  assert.ok(Object.isFrozen(roundTrip));
  assert.ok(Object.isFrozen(roundTrip.sessions));
  assert.ok(Object.isFrozen(roundTrip.sessions[0]));
  assert.ok(Object.isFrozen(roundTrip.sessions[0].target));
  assert.doesNotMatch(encoded, /password|credential|secret|passphrase|path|cwd|handle|command|args/i);
  assert.doesNotMatch(encoded, /connected|connecting|runtime|native/i);
});

test("quick, local, and serial targets are protocol-bound and never accept extra fields", () => {
  const quick = createSessionRestoreSnapshot([{
    workspaceSessionId: id(2),
    protocol: "telnet",
    target: { kind: "quick", label: "测试 Telnet", hostname: "example.test", port: 23 },
  }], id(2));
  assert.equal(decodeSessionRestoreSnapshot(encodeSessionRestoreSnapshot(quick)).sessions[0].target.kind, "quick");

  const local = createSessionRestoreSnapshot([{
    workspaceSessionId: id(3),
    protocol: "local",
    target: { kind: "local", label: "PowerShell", shellId: "pwsh" },
  }], id(3));
  assert.deepEqual(local.sessions[0].target, {
    kind: "local",
    label: "PowerShell",
    shellId: "pwsh",
  });

  const serial = createSessionRestoreSnapshot([{
    workspaceSessionId: id(4),
    protocol: "serial",
    target: { kind: "serial", label: "Serial" },
  }], id(4));
  assert.equal(serial.sessions[0].target.kind, "serial");

  assert.throws(
    () => validateSessionRestoreSnapshot({
      version: SESSION_RESTORE_VERSION,
      activeSessionId: null,
      sessions: [{
        ...saved(4),
        target: { kind: "saved", savedHostId: "host-4", label: "host", password: "leak" },
      }],
    }),
    /SESSION_RESTORE_TARGET_INVALID/,
  );
  assert.throws(
    () => validateSessionRestoreSnapshot({
      version: SESSION_RESTORE_VERSION,
      activeSessionId: null,
      sessions: [{
        workspaceSessionId: id(5),
        protocol: "local",
        target: { kind: "local", label: "shell", shellId: "pwsh", cwd: "C:\\private" },
      }],
    }),
    /SESSION_RESTORE_TARGET_PROTOCOL_INVALID|SESSION_RESTORE_TARGET_INVALID/,
  );
  assert.throws(
    () => validateSessionRestoreSnapshot({
      version: SESSION_RESTORE_VERSION,
      activeSessionId: null,
      sessions: [{
        workspaceSessionId: id(6),
        protocol: "serial",
        target: { kind: "serial", label: "Serial", portPath: "COM7" },
      }],
    }),
    /SESSION_RESTORE_TARGET_INVALID|SESSION_RESTORE_TARGET_PROTOCOL_INVALID/,
  );

  for (const forbiddenField of ["cwd", "command", "args", "path", "secret", "username"]) {
    assert.throws(
      () => validateSessionRestoreSnapshot({
        version: SESSION_RESTORE_VERSION,
        activeSessionId: null,
        sessions: [{
          workspaceSessionId: id(7),
          protocol: "local",
          target: {
            kind: "local",
            label: "shell",
            shellId: "pwsh",
            [forbiddenField]: forbiddenField === "args" ? ["--login"] : "private-value",
          },
        }],
      }),
      /SESSION_RESTORE_TARGET_INVALID/,
    );
  }
  for (const shellId of ["C:\\Windows\\pwsh.exe", "/bin/zsh", "file://shell", "../pwsh", "pwsh secret", "PowerShell"]) {
    assert.throws(
      () => createSessionRestoreSnapshot([{
        workspaceSessionId: id(8),
        protocol: "local",
        target: { kind: "local", label: "shell", shellId },
      }]),
      /SESSION_RESTORE_SHELL_ID_INVALID/,
    );
  }
});

test("restore input is bounded, unique, and active selection must refer to a retained entry", () => {
  assert.throws(
    () => createSessionRestoreSnapshot([saved(1), saved(1)]),
    /SESSION_RESTORE_DUPLICATE/,
  );
  assert.throws(
    () => createSessionRestoreSnapshot([saved(1)], id(2)),
    /SESSION_RESTORE_ACTIVE_SESSION_INVALID/,
  );
  assert.throws(
    () => decodeSessionRestoreSnapshot(JSON.stringify({ version: SESSION_RESTORE_VERSION, activeSessionId: null, sessions: [] }) + "x".repeat(MAX_SESSION_RESTORE_BYTES)),
    /SESSION_RESTORE_SIZE_LIMIT|SESSION_RESTORE_JSON_INVALID/,
  );

  const tooMany = Array.from({ length: MAX_SESSION_RESTORE_ENTRIES + 1 }, (_, index) => ({
    ...saved(index + 1),
    workspaceSessionId: id(index + 1),
  }));
  assert.throws(
    () => createSessionRestoreSnapshot(tooMany),
    /SESSION_RESTORE_LIMIT_REACHED/,
  );
});

test("storage adapter saves under one stable key and ignores corrupt persisted hints", () => {
  const values = new Map<string, string>();
  const storage = {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value); },
    removeItem: (key: string) => { values.delete(key); },
  };
  const store = createSessionRestoreStore(storage);
  const snapshot = createSessionRestoreSnapshot([saved(6)], id(6));

  assert.equal(store.load(), null);
  store.save(snapshot);
  assert.equal(values.size, 1);
  assert.equal(values.has(SESSION_RESTORE_STORAGE_KEY), true);
  assert.deepEqual(store.load(), snapshot);
  values.set(SESSION_RESTORE_STORAGE_KEY, "{\"version\":2}");
  assert.equal(store.load(), null);
  store.clear();
  assert.equal(values.size, 0);
});

test("storage adapter safely promotes the valid LumenDock v2 hint to the Goral key", () => {
  const snapshot = createSessionRestoreSnapshot([saved(7)], id(7));
  const legacyKey = "lumendock.session-restore.v2";
  const values = new Map<string, string>([[legacyKey, encodeSessionRestoreSnapshot(snapshot)]]);
  const writes: string[] = [];
  const removals: string[] = [];
  const store = createSessionRestoreStore({
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => {
      writes.push(key);
      values.set(key, value);
    },
    removeItem: (key) => {
      removals.push(key);
      values.delete(key);
    },
  });

  assert.deepEqual(store.load(), snapshot);
  assert.deepEqual(writes, [SESSION_RESTORE_STORAGE_KEY]);
  assert.deepEqual(removals, [legacyKey]);
  assert.equal(values.has(legacyKey), false);
  assert.deepEqual(
    decodeSessionRestoreSnapshot(values.get(SESSION_RESTORE_STORAGE_KEY) ?? ""),
    snapshot,
  );
});

test("denied key promotion still returns the valid legacy hint without deleting it", () => {
  const snapshot = createSessionRestoreSnapshot([saved(8)], id(8));
  const legacyKey = "lumendock.session-restore.v2";
  const encoded = encodeSessionRestoreSnapshot(snapshot);
  const removals: string[] = [];
  const store = createSessionRestoreStore({
    getItem: (key) => key === legacyKey ? encoded : null,
    setItem: () => { throw new Error("denied"); },
    removeItem: (key) => { removals.push(key); },
  });

  assert.deepEqual(store.load(), snapshot);
  assert.deepEqual(removals, []);
});

test("v2 deliberately discards the separate v1 hint without weakening exact-key validation", () => {
  assert.equal(SESSION_RESTORE_VERSION, 2);
  assert.equal(SESSION_RESTORE_STORAGE_KEY, "goral.session-restore.v2");
  assert.throws(
    () => decodeSessionRestoreSnapshot(JSON.stringify({
      version: 1,
      activeSessionId: null,
      sessions: [],
    })),
    /SESSION_RESTORE_SNAPSHOT_INVALID/,
  );
  assert.throws(
    () => validateSessionRestoreSnapshot({
      version: SESSION_RESTORE_VERSION,
      activeSessionId: null,
      sessions: [],
      legacySessions: [],
    }),
    /SESSION_RESTORE_SNAPSHOT_INVALID/,
  );

  const reads: string[] = [];
  const values = new Map([["lumendock.session-restore.v1", JSON.stringify({
    version: 1,
    activeSessionId: null,
    sessions: [],
  })]]);
  const store = createSessionRestoreStore({
    getItem: (key) => {
      reads.push(key);
      return values.get(key) ?? null;
    },
    setItem: (key, value) => { values.set(key, value); },
    removeItem: (key) => { values.delete(key); },
  });
  assert.equal(store.load(), null);
  assert.deepEqual(reads, [SESSION_RESTORE_STORAGE_KEY, "lumendock.session-restore.v2"]);
});

test("live catalogs project only targets explicitly approved by the presentation resolver", () => {
  let registry = createTerminalSessionRegistrySnapshot();
  registry = addTerminalSessionSnapshot(registry, {
    id: id(8), protocol: "ssh", title: "prod", state: "connected",
  });
  registry = addTerminalSessionSnapshot(registry, {
    id: id(9), protocol: "local", title: "PowerShell", state: "connected",
  });

  const snapshot = createSessionRestoreSnapshotFromRegistry(registry, (workspaceId, session) => (
    workspaceId === id(8)
      ? { kind: "saved", savedHostId: "host-prod", label: session.title }
      : null
  ));

  assert.equal(snapshot.sessions.length, 1);
  assert.equal(snapshot.sessions[0].workspaceSessionId, id(8));
  assert.equal(snapshot.activeSessionId, null, "an omitted active runtime cannot remain selected");
  assert.doesNotMatch(encodeSessionRestoreSnapshot(snapshot), /connected|PowerShell/);
});

test("registry projection safely omits pre-v2 Local hints without inferring shell authority", () => {
  let registry = createTerminalSessionRegistrySnapshot();
  registry = addTerminalSessionSnapshot(registry, {
    id: id(10), protocol: "local", title: "PowerShell", state: "connected",
  });
  const snapshot = createSessionRestoreSnapshotFromRegistry(
    registry,
    () => ({ kind: "local", label: "PowerShell" }),
  );
  assert.deepEqual(snapshot.sessions, []);
  assert.equal(snapshot.activeSessionId, null);
});

test("pane layout round-trips frozen strict nodes and prunes omitted sessions", () => {
  const layout: SessionRestorePaneLayout = {
    root: {
      id: "split-root",
      type: "split",
      direction: "vertical",
      ratio: 0.4,
      first: { id: "pane-one", type: "pane", sessionId: id(1) },
      second: {
        id: "split-nested",
        type: "split",
        direction: "horizontal",
        ratio: 0.6,
        first: { id: "pane-two", type: "pane", sessionId: id(2) },
        second: { id: "pane-omitted", type: "pane", sessionId: id(3) },
      },
    },
    focusedSessionId: id(3),
  };
  const snapshot = createSessionRestoreSnapshot([saved(1), saved(2)], id(2), layout);
  assert.deepEqual(snapshot.paneLayout, {
    root: {
      id: "split-root",
      type: "split",
      direction: "vertical",
      ratio: 0.4,
      first: { id: "pane-one", type: "pane", sessionId: id(1) },
      second: { id: "pane-two", type: "pane", sessionId: id(2) },
    },
    focusedSessionId: id(1),
  });
  const roundTrip = decodeSessionRestoreSnapshot(encodeSessionRestoreSnapshot(snapshot));
  assert.deepEqual(roundTrip, snapshot);
  assert.ok(Object.isFrozen(roundTrip.paneLayout));
  assert.ok(Object.isFrozen(roundTrip.paneLayout?.root));
  assert.ok(Object.isFrozen(
    roundTrip.paneLayout?.root.type === "split" ? roundTrip.paneLayout.root.first : null,
  ));
});

test("registry projection prunes layout leaves to retained session targets", () => {
  let registry = createTerminalSessionRegistrySnapshot();
  registry = addTerminalSessionSnapshot(registry, {
    id: id(20), protocol: "ssh", title: "kept", state: "connected",
  });
  registry = addTerminalSessionSnapshot(registry, {
    id: id(21), protocol: "local", title: "omitted", state: "connected",
  });
  const layout: SessionRestorePaneLayout = {
    root: {
      id: "split-projected",
      type: "split",
      direction: "horizontal",
      ratio: 0.5,
      first: { id: "pane-kept", type: "pane", sessionId: id(20) },
      second: { id: "pane-dropped", type: "pane", sessionId: id(21) },
    },
    focusedSessionId: id(21),
  };
  const snapshot = createSessionRestoreSnapshotFromRegistry(
    registry,
    (workspaceId, session) => workspaceId === id(20)
      ? { kind: "saved", savedHostId: "kept-host", label: session.title }
      : { kind: "local", label: session.title },
    layout,
  );
  assert.equal(snapshot.sessions.length, 1);
  assert.deepEqual(snapshot.paneLayout, {
    root: { id: "pane-kept", type: "pane", sessionId: id(20) },
    focusedSessionId: id(20),
  });
});

test("untrusted pane layouts enforce exact keys, ownership, uniqueness, ratios, and focus", () => {
  const base = {
    version: SESSION_RESTORE_VERSION,
    activeSessionId: id(1),
    sessions: [saved(1), saved(2)],
  };
  const leaf = (sequence: number, nodeId = `pane-${sequence}`) => ({
    id: nodeId,
    type: "pane",
    sessionId: id(sequence),
  });
  const split = (first: unknown, second: unknown) => ({
    id: "split-one",
    type: "split",
    direction: "vertical",
    ratio: 0.5,
    first,
    second,
  });

  for (const [paneLayout, error] of [
    [{ root: { ...leaf(1), path: "private" }, focusedSessionId: id(1) }, /PANE_NODE_INVALID/],
    [{ root: split(leaf(1, "same"), leaf(2, "same")), focusedSessionId: id(1) }, /PANE_NODE_DUPLICATE/],
    [{ root: split(leaf(1), leaf(1, "other")), focusedSessionId: id(1) }, /PANE_SESSION_DUPLICATE/],
    [{ root: leaf(3), focusedSessionId: id(3) }, /PANE_SESSION_INVALID/],
    [{ root: leaf(1), focusedSessionId: id(2) }, /PANE_FOCUS_INVALID/],
    [{ root: { ...split(leaf(1), leaf(2)), direction: "diagonal" }, focusedSessionId: id(1) }, /PANE_DIRECTION_INVALID/],
    [{ root: { ...split(leaf(1), leaf(2)), ratio: 1 }, focusedSessionId: id(1) }, /PANE_RATIO_INVALID/],
    [{ root: leaf(1, "C:\\private"), focusedSessionId: id(1) }, /PANE_NODE_ID_INVALID/],
  ] as const) {
    assert.throws(
      () => validateSessionRestoreSnapshot({ ...base, paneLayout }),
      error,
    );
  }
});

test("pane tree depth and node count remain bounded by the 64-session model", () => {
  assert.equal(MAX_SESSION_RESTORE_PANE_DEPTH, MAX_SESSION_RESTORE_ENTRIES);
  assert.equal(MAX_SESSION_RESTORE_PANE_NODES, (MAX_SESSION_RESTORE_ENTRIES * 2) - 1);
  const sessions = Array.from({ length: MAX_SESSION_RESTORE_ENTRIES }, (_, index) => saved(index + 1));
  let tooDeep: unknown = { id: "deep-final", type: "pane", sessionId: id(1) };
  for (let depth = 0; depth < MAX_SESSION_RESTORE_PANE_DEPTH; depth += 1) {
    tooDeep = {
      id: `deep-split-${depth}`,
      type: "split",
      direction: "vertical",
      ratio: 0.5,
      first: tooDeep,
      second: { id: `deep-side-${depth}`, type: "pane", sessionId: id((depth % 63) + 2) },
    };
  }
  assert.throws(
    () => validateSessionRestoreSnapshot({
      version: SESSION_RESTORE_VERSION,
      activeSessionId: id(1),
      sessions,
      paneLayout: { root: tooDeep, focusedSessionId: id(1) },
    }),
    /SESSION_RESTORE_PANE_DEPTH_LIMIT|SESSION_RESTORE_PANE_NODE_LIMIT/,
  );
});

test("storage denial is treated as an unavailable optional hint", () => {
  const store = createSessionRestoreStore({
    getItem: () => { throw new Error("denied"); },
    setItem: () => { throw new Error("denied"); },
    removeItem: () => { throw new Error("denied"); },
  });
  assert.equal(store.load(), null);
  assert.doesNotThrow(() => store.save(createSessionRestoreSnapshot([])));
  assert.doesNotThrow(() => store.clear());
});

test("best-effort storage cannot let an aggregate size limit disrupt live sessions", () => {
  const values = new Map<string, string>();
  const store = createSessionRestoreStore({
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => { values.set(key, value); },
    removeItem: (key) => { values.delete(key); },
  });
  const snapshot = createSessionRestoreSnapshot(Array.from(
    { length: MAX_SESSION_RESTORE_ENTRIES },
    (_, index) => ({
      workspaceSessionId: id(index + 100),
      protocol: "ssh" as const,
      target: {
        kind: "quick" as const,
        label: "l".repeat(512),
        hostname: "h".repeat(512),
        port: 22,
      },
    }),
  ));
  assert.throws(() => encodeSessionRestoreSnapshot(snapshot), /SESSION_RESTORE_SIZE_LIMIT/);
  assert.doesNotThrow(() => store.save(snapshot));
  assert.equal(values.size, 0);
});

test("startup restore UI remains a callback-only explicit reconnect boundary", async () => {
  const [promptSource, workspaceSource] = await Promise.all([
    readFile(new URL("../../src/SessionRestorePrompt.tsx", import.meta.url), "utf8"),
    readFile(new URL("../../src/TerminalWorkspace.tsx", import.meta.url), "utf8"),
  ]);
  assert.match(promptSource, /aria-labelledby="session-restore-title"/);
  assert.match(promptSource, /locale: Locale/);
  assert.match(promptSource, /useI18n\(locale\)/);
  assert.match(promptSource, /onReconnect: \(entry: SessionRestoreEntry\) => void/);
  assert.match(promptSource, /onRestoreSelected: \(workspaceSessionIds: readonly WorkspaceSessionId\[\]\) => void/);
  assert.match(promptSource, /type="checkbox"/);
  assert.match(promptSource, /supportsPresentationRestore/);
  assert.match(
    promptSource,
    /const targetLabel = entry\.target\.kind === "serial"[\s\S]*?t\("workspace\.serial"\)[\s\S]*?: entry\.target\.label/,
  );
  assert.match(promptSource, /<strong>\{targetLabel\}<\/strong>/);
  assert.match(promptSource, /t\("restore\.selectAria", \{ label: targetLabel \}\)/);
  assert.doesNotMatch(promptSource, /\.\/backend|stageSsh|startSsh|credentialReference|type="password"/);
  assert.match(workspaceSource, /rendererSettings\.system\.restorePreviousSession/);
  assert.match(workspaceSource, /createSessionRestoreSnapshotFromRegistry/);
  assert.match(workspaceSource, /setPassword\(""\)/);
  assert.match(workspaceSource, /settleSessionRestore\(\);\s*await beginSavedHostConnection\(host\)/);
  assert.match(workspaceSource, /connectionTarget\.protocol === "serial"[\s\S]*?\{ kind: "serial", label: t\("workspace\.serial"\) \}/);
  assert.match(workspaceSource, /entry\.target\.kind === "serial"[\s\S]*?setSerialPanel\(\{ mode: "quick" \}\)/);
  const selectedRestore = workspaceSource.slice(
    workspaceSource.indexOf("const restoreSelectedSessionPresentations"),
    workspaceSource.indexOf("const reconnectRestoredSession"),
  );
  assert.match(selectedRestore, /sshTerminals\.restoreDisconnected/);
  assert.match(selectedRestore, /localTerminals\.restoreDisconnected/);
  assert.match(selectedRestore, /pruneTerminalPaneLayout\(snapshot\.paneLayout, restoredIds\)/);
  assert.match(selectedRestore, /\{ activate: false \}/);
  assert.doesNotMatch(
    selectedRestore,
    /beginSavedHostConnection|connectSavedHost|startSshSession|startSavedHostSession|stageSshPassword|stageSshKeyPassphrase/,
  );
  assert.match(workspaceSource, /shellId: target\.shell\.id/);
  assert.match(
    workspaceSource,
    /terminalPaneWorkspaceVisible \? terminalPaneLayout : null/,
  );
  assert.match(
    workspaceSource,
    /setUsername\(""\)[\s\S]*?setPassword\(""\)[\s\S]*?setError\(t\("restore\.quickCredentialsRequired"\)\)/,
  );
  const startupEffect = workspaceSource.slice(
    workspaceSource.indexOf("if (!rendererSettingsReady) return;"),
    workspaceSource.indexOf("if (!rendererSettingsReady || !sessionRestoreSettled)"),
  );
  assert.doesNotMatch(startupEffect, /beginSavedHostConnection|connectSavedHost|startSshSession|localTerminals\.open/);
  assert.ok(
    startupEffect.indexOf("if (!rendererSettings.system.restorePreviousSession)")
      < startupEffect.indexOf("if (sessionRestoreChecked.current) return"),
    "disabling restore after startup must dismiss a pending prompt before the one-shot guard",
  );
  assert.match(startupEffect, /setSessionRestoreSnapshot\(null\)/);
});

test("oversized display labels fail before persistence", () => {
  assert.throws(() => createSessionRestoreSnapshot([{
    ...saved(7),
    target: { kind: "saved", savedHostId: "host-7", label: "x".repeat(65_000) },
  }]), /SESSION_RESTORE_TARGET_LABEL_INVALID/);
  assert.ok(MAX_SESSION_RESTORE_BYTES > 0);
});
