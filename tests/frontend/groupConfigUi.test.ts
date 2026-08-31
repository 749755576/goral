import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import type { GroupConfig, GroupConfigDefaults } from "../../src/backend.ts";
import {
  classifyGroupConfigError,
  editableGroupDefaults,
  newGroupDefaultsRequest,
  normalizeGroupConfigPath,
  resolveEffectiveGroupDefaults,
} from "../../src/groupConfigUi.ts";
import { createTranslator } from "../../src/i18n.ts";

const componentUrl = new URL("../../src/GroupConfigCatalog.tsx", import.meta.url);
const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);

const group = (path: string, patch: Partial<GroupConfigDefaults>, id = path): GroupConfig => ({
  id,
  revision: 1,
  path,
  defaults: { ...newGroupDefaultsRequest(), ...patch } as GroupConfigDefaults,
  createdAt: 1,
  updatedAt: 1,
});

test("group paths mirror legacy slash-only normalization without trimming segments", () => {
  assert.equal(normalizeGroupConfigPath("//Ops\\DB/ Team /./..//"), "Ops\\DB/ Team /./..");
  assert.equal(normalizeGroupConfigPath("///"), null);
  assert.equal(normalizeGroupConfigPath("x".repeat(32 * 1024)), "x".repeat(32 * 1024));
  assert.equal(normalizeGroupConfigPath("x".repeat(32 * 1024 + 1)), null);
});

test("root-to-leaf preview applies inherit, clear, and set in ancestor order", () => {
  const groups = [
    group("A", {
      username: { state: "set", value: "root-user" },
      port: { state: "set", value: 22 },
      protocol: { state: "set", value: "ssh" },
      proxy: { state: "profile", value: "proxy-1" },
      password: "storedHint",
    }),
    group("A/B", {
      username: { state: "clear" },
      port: { state: "inherit" },
      proxy: { state: "clear" },
      password: "clear",
    }),
    group("A/B/C", {
      username: { state: "set", value: "leaf-user" },
      port: { state: "set", value: 2202 },
    }),
  ];
  assert.deepEqual(resolveEffectiveGroupDefaults("A/B/C", groups), {
    username: "leaf-user",
    port: 2202,
    protocol: "ssh",
  });
});

test("renderer stored hints become hint-free mutation metadata", () => {
  const current = group("Production", {
    password: "storedHint",
    telnetPassword: "storedHint",
    proxy: {
      state: "inline",
      value: {
        type: "http",
        host: "proxy.internal",
        port: 8080,
        username: "proxy-user",
        hasSavedCredential: true,
      },
    },
  });
  const editable = editableGroupDefaults(current);
  assert.equal(editable.sshPasswordStored, true);
  assert.equal(editable.telnetPasswordStored, true);
  assert.equal(editable.proxyPasswordStored, true);
  assert.equal(editable.defaults.password, "inherit");
  assert.equal(editable.defaults.telnetPassword, "inherit");
  assert.deepEqual(editable.defaults.proxy, {
    state: "inline",
    value: {
      type: "http",
      host: "proxy.internal",
      port: 8080,
      username: "proxy-user",
      hasSavedCredential: false,
    },
  });
});

test("fixed group errors map to safe recovery messages", () => {
  const cases = [
    ["GROUP_CONFIG_INVALID: fixed", "invalid", "groupConfig.error.invalid", false],
    ["GROUP_CONFIG_NOT_FOUND: fixed", "notFound", "groupConfig.error.notFound", true],
    ["GROUP_CONFIG_CHANGED: fixed", "changed", "groupConfig.error.changed", true],
    ["GROUP_CONFIG_INVENTORY_CHANGED: fixed", "stale", "groupConfig.error.stale", true],
    ["GROUP_CONFIG_PUBLICATION_FAILED: fixed", "publication", "groupConfig.error.publication", true],
    ["GROUP_CONFIG_REPAIR_REQUIRED: fixed", "repair", "groupConfig.error.repair", false],
  ] as const;
  for (const [raw, kind, messageKey, refreshCatalog] of cases) {
    const issue = classifyGroupConfigError(new Error(raw));
    assert.equal(issue.kind, kind);
    assert.equal(issue.messageKey, messageKey);
    assert.equal(issue.refreshCatalog, refreshCatalog);
    assert.equal(createTranslator("en-US")(issue.messageKey).includes(raw), false);
    assert.equal(createTranslator("zh-CN")(issue.messageKey).includes(raw), false);
  }
  const marker = "raw-group-error-must-not-reach-ui";
  const fallback = classifyGroupConfigError(new Error(marker));
  assert.equal(fallback.messageKey, "groupConfig.error.failed");
  assert.equal(createTranslator("en-US")(fallback.messageKey).includes(marker), false);
});

test("Group Defaults editor stages three credentials before safe JSON CRUD", async () => {
  const source = await readFile(componentUrl, "utf8");
  const sshStage = source.indexOf("await stageGroupSshPassword(sshSecret)");
  const telnetStage = source.indexOf("await stageGroupTelnetPassword(telnetSecret)");
  const proxyStage = source.indexOf("await stageGroupProxyPassword(proxySecret)");
  const create = source.indexOf("await createGroupConfig({");
  const update = source.indexOf("await updateGroupConfig({");
  assert.ok(sshStage > 0 && telnetStage > sshStage && proxyStage > telnetStage);
  assert.ok(create > proxyStage && update > create);
  const requests = source.slice(create, source.indexOf("applyCatalog(next)", update));
  assert.doesNotMatch(requests, /sshSecret|telnetSecret|proxySecret/);
  assert.doesNotMatch(requests, /\b(?:password|telnetPassword|proxyPassword)\s*:/);
  assert.match(requests, /credentialMutations/);
  assert.match(source, /sshPassword: ""/);
  assert.match(source, /telnetPassword: ""/);
  assert.match(source, /proxyPassword: ""/);
  assert.match(source, /finally \{[\s\S]*?sshSecret = "";[\s\S]*?telnetSecret = "";[\s\S]*?proxySecret = "";/);
});

test("Group Defaults UI exposes legacy inheritance and SSH, Telnet, Proxy references", async () => {
  const [component, workspace] = await Promise.all([
    readFile(componentUrl, "utf8"),
    readFile(workspaceUrl, "utf8"),
  ]);
  assert.match(component, /t\("groupConfig\.override\.inherit"\)/);
  assert.match(component, /t\("groupConfig\.override\.clear"\)/);
  assert.match(component, /t\("groupConfig\.override\.set"\)/);
  assert.match(component, /t\("groupConfig\.section\.ssh"\)/);
  assert.match(component, /t\("groupConfig\.section\.telnet"\)/);
  assert.match(component, /t\("groupConfig\.section\.proxy"\)/);
  assert.match(component, /passwordIdentities\.map/);
  assert.match(component, /proxyProfiles\.map/);
  assert.match(component, /managedKeys\.map/);
  assert.match(component, /customGroups = catalog\?\.customGroups \?\? \[\]/);
  assert.match(component, /explicitGroups: \[\.\.\.customGroups, \.\.\.groups\.map/);
  assert.match(component, /resolveEffectiveGroupDefaults/);
  assert.match(component, /groupConfig\.credential\.keep[\s\S]*groupConfig\.credential\.remove[\s\S]*groupConfig\.credential\.replace/);
  assert.match(component, /label="Mosh"[\s\S]*?etEnabled: \{ state: "set", value: false \}/);
  assert.match(component, /label="Eternal Terminal"[\s\S]*?moshEnabled: \{ state: "set", value: false \}/);
  assert.match(component, /groupConfig\.validation\.transportConflict/);
  assert.match(component, /locale\?: Locale/);
  assert.doesNotMatch(component, /[\p{Script=Han}]/u);
  assert.match(workspace, /aria-label=\{t\("workspace\.manageGroups"\)\}/);
  assert.match(workspace, /<GroupConfigCatalog/);
  assert.match(workspace, /<GroupConfigCatalog[\s\S]*?locale=\{rendererLocale\}/);
  assert.match(workspace, /onCatalogChange=\{handleGroupConfigCatalogChange\}/);
});
