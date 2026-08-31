import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  filterSavedHosts,
  savedHostMatchesSearch,
  type SearchableSavedHost,
} from "../../src/savedHostSearch.ts";

const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);
const stylesUrl = new URL("../../src/styles.css", import.meta.url);

const hosts: SearchableSavedHost[] = [
  {
    label: "Production API",
    hostname: "api.example.test",
    username: "deploy",
    group: "Cloud/Production",
    passwordIdentity: null,
  },
  {
    label: "Database",
    hostname: "10.20.30.40",
    username: "postgres",
    group: "Data/Primary",
    passwordIdentity: {
      id: "identity-1",
      label: "Shared DBA",
      username: "dba-admin",
      hasSavedCredential: true,
    },
  },
];

test("saved-host search matches label, hostname, username, and group", () => {
  assert.equal(savedHostMatchesSearch(hosts[0], "production api"), true);
  assert.equal(savedHostMatchesSearch(hosts[0], "EXAMPLE.TEST"), true);
  assert.equal(savedHostMatchesSearch(hosts[0], "deploy"), true);
  assert.equal(savedHostMatchesSearch(hosts[0], "cloud/prod"), true);
  assert.equal(savedHostMatchesSearch(hosts[0], "missing"), false);
});

test("saved-host search includes the effective identity username and trims queries", () => {
  assert.deepEqual(filterSavedHosts(hosts, "  DBA-ADMIN  "), [hosts[1]]);
  assert.deepEqual(filterSavedHosts(hosts, "   "), hosts);
});

test("TerminalWorkspace filters before preserving SavedHostGroupTree host actions", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  assert.match(source, /filterSavedHosts\(savedHosts, savedHostSearch\)/);
  assert.match(source, /aria-label=\{t\("workspace\.searchSavedHosts"\)\}/);
  assert.match(source, /hosts=\{filteredSavedHosts\}/);
  assert.match(source, /beginSavedHostConnection\(host\)/);
  assert.match(source, /openEditSavedHost\(host\)/);
  assert.match(source, /removeSavedHost\(host\)/);
});

test("saved-host controls stay in a compact rail toolbar", async () => {
  const [source, styles] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(stylesUrl, "utf8"),
  ]);
  assert.match(source, /className="saved-hosts-toolbar" role="toolbar"/);
  assert.match(source, /aria-label=\{t\("workspace\.createHost"\)\}/);
  assert.match(source, /aria-label=\{t\("workspace\.importLegacyVault"\)\}/);
  assert.match(source, /aria-label=\{t\("workspace\.refreshHosts"\)\}/);
  assert.match(styles, /\.saved-hosts-toolbar\s*\{[\s\S]*?flex:\s*0 0 36px/);
  assert.match(styles, /\.saved-hosts-toolbar \.saved-host-toolbar-action\s*\{[\s\S]*?width:\s*27px/);
});
