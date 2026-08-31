import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { createTranslator, type MessageKey } from "../../src/i18n.ts";

const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);
const frameStylesUrl = new URL("../../src/mainWorkspaceFrame.css", import.meta.url);

type HeadingPair = readonly [
  eyebrow: MessageKey,
  title: MessageKey,
  params?: Readonly<Record<string, string>>,
];

const headingPairs: readonly HeadingPair[] = [
  ["groupConfig.kicker", "groupConfig.title"],
  ["groupConfig.editor.newKicker", "groupConfig.editor.createTitle"],
  ["groupConfig.delete.kicker", "groupConfig.delete.title"],
  ["notes.newEyebrow", "notes.createTitle"],
  ["notes.editEyebrow", "notes.editTitle"],
  ["portForward.kicker", "portForward.new"],
  ["portForward.kicker", "portForward.editTitle"],
  ["portForward.deleteKicker", "portForward.deleteTitle"],
  ["passwordIdentity.catalogEyebrow", "passwordIdentity.title"],
  ["passwordIdentity.editorEyebrow", "passwordIdentity.createTitle"],
  ["passwordIdentity.editorEyebrow", "passwordIdentity.editTitle"],
  ["passwordIdentity.deleteEyebrow", "passwordIdentity.deleteTitle"],
  ["proxyProfile.catalogEyebrow", "proxyProfile.title"],
  ["proxyProfile.editorEyebrow", "proxyProfile.createTitle"],
  ["proxyProfile.editorEyebrow", "proxyProfile.editTitle"],
  ["proxyProfile.deleteEyebrow", "proxyProfile.deleteTitle"],
  ["connectionPrompt.password.eyebrow", "connectionPrompt.password.title"],
  ["connectionPrompt.proxy.eyebrow", "connectionPrompt.proxy.title"],
  ["connectionPrompt.keyPassphrase.eyebrow", "connectionPrompt.keyPassphrase.title"],
  ["scripts.newEyebrow", "scripts.createTitle"],
  ["scripts.editEyebrow", "scripts.editTitle"],
  ["restore.eyebrow", "restore.title"],
  [
    "savedHost.editor.dialog.kicker",
    "savedHost.editor.dialog.titleCreate",
    { protocol: "SSH" },
  ],
  [
    "savedHost.editor.dialog.kicker",
    "savedHost.editor.dialog.titleEdit",
    { protocol: "SSH" },
  ],
  ["workspace.quickConnectEyebrow", "workspace.connectionTitle", { protocol: "SSH" }],
  ["brand.subtitle", "workspace.noSavedHosts"],
  ["workspace.managedKeysEyebrow", "workspace.managedKeysTitle"],
  ["managedKey.editor.kicker", "managedKey.editor.createTitle"],
  ["managedKey.editor.kicker", "managedKey.editor.editTitle"],
  ["managedKey.delete.kicker", "managedKey.delete.title"],
  ["managedKey.rotate.kicker", "managedKey.rotate.title"],
  ["legacyImport.kicker", "legacyImport.title"],
  ["hostKey.kicker", "hostKey.changedTitle"],
  ["hostKey.kicker", "hostKey.unknownTitle"],
  ["interactiveAuth.kicker", "interactiveAuth.title"],
];

test("eyebrows provide hierarchy instead of repeating their adjacent title", () => {
  for (const locale of ["en-US", "zh-CN"] as const) {
    const t = createTranslator(locale);
    for (const [eyebrowKey, titleKey, params] of headingPairs) {
      const eyebrow = t(eyebrowKey, params).trim().toLocaleLowerCase(locale);
      const title = t(titleKey, params).trim().toLocaleLowerCase(locale);
      assert.notEqual(
        eyebrow,
        title,
        `${locale} repeats ${eyebrowKey} directly above ${titleKey}`,
      );
    }
  }
});

test("password and proxy catalogs identify their Vault parent", () => {
  const en = createTranslator("en-US");
  const zh = createTranslator("zh-CN");
  assert.equal(en("passwordIdentity.catalogEyebrow"), "VAULT");
  assert.equal(en("proxyProfile.catalogEyebrow"), "VAULT");
  assert.equal(zh("passwordIdentity.catalogEyebrow"), "保险库");
  assert.equal(zh("proxyProfile.catalogEyebrow"), "保险库");
});

test("empty Saved Hosts uses one central message and omits the duplicate toolbar", async () => {
  const workspace = await readFile(workspaceUrl, "utf8");
  assert.equal(
    workspace.split('t("workspace.noSavedHosts")').length - 1,
    1,
    "the empty-state title must render only once",
  );
  assert.equal(
    workspace.split('t("workspace.noSavedHostsDescription")').length - 1,
    1,
    "the empty-state description must render only once",
  );
  assert.match(
    workspace,
    /&& !\(sidebarView === "saved" && savedHostsHaveSnapshot && savedHosts\.length === 0\) && \(\s*<header className="vault-toolbar">/u,
  );
});

test("primary onboarding card has the same explicit icon-title-description anatomy", async () => {
  const [workspace, styles] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(frameStylesUrl, "utf8"),
  ]);
  const start = workspace.indexOf(
    '<button type="button" className="primary-button" data-onboarding-path="primary"',
  );
  const end = workspace.indexOf("</button>", start);
  assert.ok(start >= 0 && end > start);
  const primaryCard = workspace.slice(start, end);

  assert.match(primaryCard, /<span><VaultGlyph name="plus" \/><\/span>/u);
  assert.match(primaryCard, /<strong>\{t\("workspace\.newHost"\)\}<\/strong>/u);
  assert.match(primaryCard, /<small>\{t\("workspace\.credentialsCustody"\)\}<\/small>/u);
  assert.ok(primaryCard.indexOf("<span>") < primaryCard.indexOf("<strong>"));
  assert.ok(primaryCard.indexOf("<strong>") < primaryCard.indexOf("<small>"));
  assert.match(workspace, /type VaultGlyphName =[\s\S]*?\| "plus"/u);
  assert.match(workspace, /plus: \["M12 5v14M5 12h14"\]/u);

  assert.match(
    styles,
    /\.primary-button\[data-onboarding-path="primary"\] > span > \.vault-glyph/u,
  );
  assert.doesNotMatch(
    styles,
    /\.primary-button\[data-onboarding-path="primary"\] > \.vault-glyph/u,
  );
  assert.doesNotMatch(
    styles,
    /\.primary-button\[data-onboarding-path="primary"\]::(?:before|after)/u,
  );
});
