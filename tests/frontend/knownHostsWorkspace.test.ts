import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import type { SavedKnownHost } from "../../src/knownHostsApi.ts";
import {
  classifyKnownHostsError,
  dedupeKnownHostsForDisplay,
  matchesKnownHostSearch,
  mergeKnownHosts,
  parseKnownHostsFile,
  reorderKnownHosts,
  sortKnownHosts,
  upsertKnownHost,
  withoutPublicServiceKnownHosts,
  KNOWN_HOSTS_IMPORT_MAX_BYTES,
  KNOWN_HOSTS_IMPORT_MAX_ENTRIES,
  KNOWN_HOSTS_IMPORT_MAX_LINE_BYTES,
} from "../../src/knownHostsUi.ts";

const apiUrl = new URL("../../src/knownHostsApi.ts", import.meta.url);
const uiUrl = new URL("../../src/knownHostsUi.ts", import.meta.url);
const componentUrl = new URL("../../src/KnownHostsWorkspace.tsx", import.meta.url);
const stylesUrl = new URL("../../src/knownHosts.css", import.meta.url);
const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);
const backendUrl = new URL("../../src/backend.ts", import.meta.url);
const mainUrl = new URL("../../src/main.tsx", import.meta.url);

const knownHost = (overrides: Partial<SavedKnownHost> = {}): SavedKnownHost => ({
  id: "kh-existing",
  hostname: "server.example.com",
  port: 22,
  keyType: "ssh-ed25519",
  publicKey: "ssh-ed25519 AAAA",
  fingerprint: "old-fingerprint",
  discoveredAt: 100,
  ...overrides,
});

test("Known Hosts DTO and wrappers match the Vault v9 three-command boundary", async () => {
  const [api, backend] = await Promise.all([
    readFile(apiUrl, "utf8"),
    readFile(backendUrl, "utf8"),
  ]);
  const record = api.slice(
    api.indexOf("export type SavedKnownHost ="),
    api.indexOf("export type KnownHostsCatalog"),
  );
  for (const field of [
    "id: string;",
    "hostname: string;",
    "port: number;",
    "keyType: string;",
    "publicKey: string;",
    "fingerprint?: string;",
    "discoveredAt: number;",
    "lastSeen?: number;",
    "convertedToHostId?: string;",
    "order?: number;",
  ]) {
    assert.match(record, new RegExp(field.replace(/[?]/g, "\\?")));
  }
  assert.doesNotMatch(record, /status|trusted|runtime|session|error/i);

  for (const command of ["list_known_hosts", "replace_known_hosts", "scan_system_known_hosts"]) {
    assert.match(api, new RegExp(`"${command}"`));
  }
  assert.match(api, /expectedInventoryRevision: unknown;/);
  assert.match(api, /invoke<KnownHostsCatalog>\(KNOWN_HOSTS_COMMANDS\.replace, \{ request \}\)/);
  assert.match(backend, /type SavedKnownHost/);
  assert.match(backend, /scanSystemKnownHosts/);
});

test("scan merging mirrors legacy ID-first and selector-second upsert semantics", () => {
  const existing = knownHost({ convertedToHostId: "host-1", order: 4 });
  const refreshed = knownHost({
    id: "scan-random-id",
    hostname: " SERVER.example.com ",
    publicKey: "ssh-ed25519 NEW",
    fingerprint: "new-fingerprint",
    discoveredAt: 900,
  });
  assert.deepEqual(upsertKnownHost([existing], refreshed), [{
    ...existing,
    hostname: refreshed.hostname,
    publicKey: refreshed.publicKey,
    fingerprint: refreshed.fingerprint,
    lastSeen: 900,
  }]);

  const sameIdDifferentSelector = knownHost({
    id: existing.id,
    hostname: "moved.example.com",
    keyType: "ssh-rsa",
    discoveredAt: 901,
  });
  const byId = upsertKnownHost([existing], sameIdDifferentSelector);
  assert.equal(byId.length, 1);
  assert.equal(byId[0].id, existing.id);
  assert.equal(byId[0].hostname, "moved.example.com");

  const otherKeyType = knownHost({ id: "kh-rsa", keyType: "ssh-rsa" });
  assert.equal(mergeKnownHosts([existing], [otherKeyType]).length, 2);
});

test("large system scans merge in bounded time without changing legacy selector precedence", () => {
  const incoming = Array.from({ length: 10_000 }, (_, index) => knownHost({
    id: `scan-${index}`,
    hostname: `host-${index}.example.test`,
    discoveredAt: index + 1,
  }));
  const startedAt = performance.now();
  const merged = mergeKnownHosts([], incoming);
  const elapsed = performance.now() - startedAt;

  assert.equal(merged.length, 10_000);
  assert.equal(merged[9_999].hostname, "host-9999.example.test");
  assert.ok(elapsed < 1_000, `expected a linear bounded merge, took ${elapsed.toFixed(1)} ms`);
});

test("file parser handles ordinary OpenSSH selectors and rejects every marker line", async () => {
  const raw = Buffer.from("trusted imported host key");
  const encoded = raw.toString("base64");
  const content = [
    "# comment",
    `server.example.com ssh-ed25519 ${encoded}`,
    `[port.example.com]:2222 ssh-ed25519 ${encoded}`,
    `alias.example.com,10.0.0.8 ssh-rsa ${encoded}`,
    `|1|hash|salt ssh-ed25519 ${encoded}`,
    `@revoked revoked.example.com ssh-ed25519 ${encoded}`,
    `@cert-authority *.example.net ssh-ed25519 ${encoded}`,
    `@future-marker ignored.example.net ssh-ed25519 ${encoded}`,
  ].join("\n");
  const parsed = await parseKnownHostsFile(content, {
    now: () => 1234,
    idFactory: (index) => `kh-${index}`,
  });

  assert.deepEqual(parsed.map((entry) => [entry.hostname, entry.port, entry.keyType]), [
    ["server.example.com", 22, "ssh-ed25519"],
    ["port.example.com", 2222, "ssh-ed25519"],
    ["alias.example.com", 22, "ssh-rsa"],
    ["(hashed)", 22, "ssh-ed25519"],
  ]);
  const expectedFingerprint = crypto.createHash("sha256").update(raw).digest("base64").replace(/=+$/g, "");
  assert.equal(parsed[0].fingerprint, expectedFingerprint);
  assert.equal(parsed.some((entry) => entry.hostname.includes("revoked")), false);
});

test("file parser and merge enforce renderer and Vault catalog bounds", async () => {
  await assert.rejects(
    parseKnownHostsFile("x".repeat(KNOWN_HOSTS_IMPORT_MAX_BYTES + 1)),
    /KNOWN_HOSTS_FILE_TOO_LARGE/,
  );
  await assert.rejects(
    parseKnownHostsFile(`host ssh-ed25519 ${"A".repeat(KNOWN_HOSTS_IMPORT_MAX_LINE_BYTES)}`),
    /KNOWN_HOSTS_LINE_TOO_LARGE/,
  );

  const lines = Array.from(
    { length: KNOWN_HOSTS_IMPORT_MAX_ENTRIES + 1 },
    (_, index) => `host-${index} ssh-ed25519 !`,
  ).join("\n");
  await assert.rejects(
    parseKnownHostsFile(lines, {
      now: () => 1,
      idFactory: (index) => `kh-${index}`,
    }),
    /KNOWN_HOSTS_CATALOG_TOO_LARGE/,
  );

  const fullCatalog = Array.from(
    { length: KNOWN_HOSTS_IMPORT_MAX_ENTRIES },
    (_, index) => knownHost({ id: `kh-${index}`, hostname: `host-${index}` }),
  );
  assert.throws(
    () => mergeKnownHosts(fullCatalog, [knownHost({ id: "overflow", hostname: "overflow" })]),
    /KNOWN_HOSTS_CATALOG_TOO_LARGE/,
  );
});

test("public services, search, display dedupe, sorting, and manual reorder retain legacy behavior", () => {
  assert.deepEqual(withoutPublicServiceKnownHosts([
    knownHost({ id: "public", hostname: "github.com" }),
    knownHost({ id: "private", hostname: "internal.example" }),
  ]).map((entry) => entry.id), ["private"]);

  const old = knownHost({ id: "old", discoveredAt: 10, order: 2 });
  const latest = knownHost({ id: "latest", discoveredAt: 20, order: 1 });
  assert.deepEqual(dedupeKnownHostsForDisplay([old, latest]).map((entry) => entry.id), ["latest"]);
  assert.equal(matchesKnownHostSearch(latest, "ED25519"), true);
  assert.equal(matchesKnownHostSearch(latest, "missing"), false);

  const alpha = knownHost({ id: "alpha", hostname: "alpha", order: 0 });
  const beta = knownHost({ id: "beta", hostname: "beta", order: 1 });
  const gamma = knownHost({ id: "gamma", hostname: "gamma", order: 2 });
  assert.deepEqual(sortKnownHosts([gamma, alpha, beta], "manual").map((entry) => entry.id), ["alpha", "beta", "gamma"]);
  assert.deepEqual(reorderKnownHosts([alpha, beta, gamma], "alpha", "gamma", "after").map((entry) => entry.id), ["beta", "gamma", "alpha"]);
});

test("Known Hosts errors are fixed and never echo backend-controlled content", () => {
  const stale = classifyKnownHostsError(new Error("KNOWN_HOSTS_INVENTORY_CHANGED raw-marker"));
  assert.equal(stale.refreshCatalog, true);
  assert.equal(stale.message.includes("raw-marker"), false);
  assert.match(stale.message, /已在其他窗口中更新/);

  const fallback = classifyKnownHostsError(new Error("secret public key raw-marker"));
  assert.equal(fallback.refreshCatalog, false);
  assert.equal(fallback.message.includes("raw-marker"), false);
});

test("workspace exposes the complete legacy page and browser-safe runtime guard", async () => {
  const [component, ui, styles] = await Promise.all([
    readFile(componentUrl, "utf8"),
    readFile(uiUrl, "utf8"),
    readFile(stylesUrl, "utf8"),
  ]);

  assert.match(component, /api !== undefined \|\| isTauri\(\)/);
  assert.match(component, /if \(!nativeRuntimeAvailable\)[\s\S]*?applyCatalog\(EMPTY_CATALOG\)/);
  assert.match(component, /t\("knownHosts\.searchPlaceholder"\)/);
  assert.match(component, /t\("knownHosts\.scanSystem"\)/);
  assert.match(component, /t\("knownHosts\.importFile"\)/);
  assert.match(component, /t\("knownHosts\.empty"\)/);
  assert.match(component, /t\("knownHosts\.convert"\)/);
  assert.match(component, /role="menu"/);
  assert.match(component, /role="dialog"/);
  assert.match(component, /onDragStart/);
  assert.match(component, /parseKnownHostsFile/);
  assert.match(component, /file\.size > KNOWN_HOSTS_IMPORT_MAX_BYTES/);
  assert.match(component, /onConvertToHost/);
  const convertFlow = component.slice(
    component.indexOf("const convertKnownHost = async"),
    component.indexOf("const reorder = async"),
  );
  assert.ok(convertFlow.indexOf("await onConvertToHost(knownHost)") < convertFlow.indexOf("await knownHostsApi.list()"));
  assert.ok(convertFlow.indexOf("await knownHostsApi.list()") < convertFlow.indexOf("knownHostsApi.replace({"));
  assert.match(convertFlow, /expectedInventoryRevision: latest\.inventoryRevision/);
  assert.doesNotMatch(convertFlow, /expectedInventoryRevision: snapshot\.inventoryRevision/);
  assert.match(ui, /parts\[0\]\.startsWith\("@"\)/);
  assert.match(styles, /\.known-hosts-header\s*\{[\s\S]*?56px/);
  assert.match(styles, /\.known-hosts-item\s*\{[\s\S]*?height: 68px/);
  assert.match(styles, /grid-template-columns: repeat\(3, minmax\(0, 1fr\)\)/);
});

test("TerminalWorkspace enables Known Hosts without disturbing adjacent modules", async () => {
  const [workspace, main] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(mainUrl, "utf8"),
  ]);
  assert.match(workspace, /import \{ KnownHostsWorkspace \} from "\.\/KnownHostsWorkspace"/);
  assert.match(workspace, /type SidebarView =[^;]+\| "known"[^;]+\| "logs";/s);
  assert.match(workspace, /className=\{sidebarView === "known" \? "active" : ""\}/);
  assert.match(workspace, /onClick=\{\(\) => showVaultView\("known"\)\}/);
  assert.doesNotMatch(workspace, /Known Hosts 正在迁移/);
  assert.match(workspace, /sidebarView === "known" && \([\s\S]*?<KnownHostsWorkspace[\s\S]*?hosts=\{savedHosts\}/);
  assert.match(workspace, /onConvertToHost=\{convertKnownHostToSavedHost\}/);
  assert.match(workspace, /createSavedHost\(\{[\s\S]*?label: knownHost\.hostname,[\s\S]*?hostname: knownHost\.hostname/);
  assert.match(workspace, /sidebarView !== "scripts" && sidebarView !== "notes" && sidebarView !== "known"/);
  assert.match(workspace, /<PortForwardingCatalog/);
  assert.match(workspace, /<GroupConfigCatalog/);
  assert.match(main, /import "\.\/knownHosts\.css";/);
});
