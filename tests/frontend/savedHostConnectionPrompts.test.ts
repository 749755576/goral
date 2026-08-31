import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const promptsUrl = new URL("../../src/SavedHostConnectionPrompts.tsx", import.meta.url);
const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);

test("saved-host connection prompts are controlled callback-only presentation", async () => {
  const source = await readFile(promptsUrl, "utf8");

  assert.match(source, /export function SavedHostPasswordPromptDialog/);
  assert.match(source, /export function SavedHostProxyPasswordPromptDialog/);
  assert.match(source, /export function SavedHostKeyPassphrasePromptDialog/);
  assert.match(source, /locale: Locale;/);
  assert.equal(source.match(/useI18n\(locale\)/g)?.length, 3);
  assert.equal(source.match(/className="trust-dialog saved-host-dialog"/g)?.length, 3);
  assert.equal(source.match(/role="dialog"/g)?.length, 3);
  assert.equal(source.match(/aria-modal="true"/g)?.length, 3);
  assert.equal(source.match(/className="saved-host-fields"/g)?.length, 3);
  assert.equal(source.match(/role="alert"/g)?.length, 3);

  assert.doesNotMatch(
    source,
    /\.\/backend|SavedHost[;,}]|useState|useEffect|useRef|stageSsh|startSavedHostSession|connectSavedHost|invoke\(/,
  );
  assert.doesNotMatch(source, /\p{Script=Han}/u);
});

test("saved-host connection prompts use the complete typed translation contract", async () => {
  const source = await readFile(promptsUrl, "utf8");
  const keys = [
    "connectionPrompt.common.connectionFailedPrefix",
    "connectionPrompt.common.cancel",
    "connectionPrompt.common.cancelConnection",
    "connectionPrompt.common.manualLogin",
    "connectionPrompt.common.connect",
    "connectionPrompt.common.connecting",
    "connectionPrompt.password.eyebrow",
    "connectionPrompt.password.title",
    "connectionPrompt.password.label",
    "connectionPrompt.password.securityNote",
    "connectionPrompt.proxy.eyebrow",
    "connectionPrompt.proxy.title",
    "connectionPrompt.proxy.sshPasswordLabel",
    "connectionPrompt.proxy.keyPassphraseLabel",
    "connectionPrompt.proxy.proxyPasswordLabel",
    "connectionPrompt.proxy.securityNote",
    "connectionPrompt.keyPassphrase.eyebrow",
    "connectionPrompt.keyPassphrase.title",
    "connectionPrompt.keyPassphrase.label",
    "connectionPrompt.keyPassphrase.savedPlaceholder",
    "connectionPrompt.keyPassphrase.unsavedPlaceholder",
    "connectionPrompt.keyPassphrase.savedDescription",
    "connectionPrompt.keyPassphrase.unsavedDescription",
    "connectionPrompt.keyPassphrase.securityNote",
  ] as const;

  for (const key of keys) assert.match(source, new RegExp(`t\\("${key.replaceAll(".", "\\.")}\"\\)`));
});

test("secret fields remain parent-controlled and preserve the existing prompt behavior", async () => {
  const source = await readFile(promptsUrl, "utf8");

  for (const value of ["password", "sshPassword", "keyPassphrase", "proxyPassword", "passphrase"]) {
    assert.match(source, new RegExp(`value=\\{${value}\\}`));
  }
  assert.match(source, /onPasswordChange\(event\.target\.value\)/);
  assert.match(source, /onSshPasswordChange\(event\.target\.value\)/);
  assert.match(source, /onKeyPassphraseChange\(event\.target\.value\)/);
  assert.match(source, /onProxyPasswordChange\(event\.target\.value\)/);
  assert.match(source, /onPassphraseChange\(event\.target\.value\)/);
  assert.match(source, /requireSshPassword && sshPassword\.length === 0/);
  assert.match(source, /showKeyPassphrase &&/);
  assert.match(source, /showManualLogin &&/);
  assert.match(source, /hasSavedPassphrase[\s\S]*?savedPlaceholder[\s\S]*?unsavedPlaceholder/);
});

test("TerminalWorkspace retains secret staging, exact retry, and cancel authority", async () => {
  const workspace = await readFile(workspaceUrl, "utf8");

  assert.match(workspace, /import \{[\s\S]*?SavedHostPasswordPromptDialog[\s\S]*?SavedHostProxyPasswordPromptDialog[\s\S]*?\} from "\.\/SavedHostConnectionPrompts";/);
  assert.match(workspace, /savedHostPasswordPrompt \? \([\s\S]*?: savedHostProxyPasswordPrompt \? \([\s\S]*?: savedHostKeyPassphrasePrompt \? \(/);
  assert.match(workspace, /sshTerminals\.open\([\s\S]*?start, notifyWorkspaceSessionCreated\)/);
  assert.match(workspace, /notifyWorkspaceSessionCreated[\s\S]*?workspaceSessionId[\s\S]*?setSavedHostPasswordPrompt[\s\S]*?setSavedHostProxyPasswordPrompt[\s\S]*?setSavedHostKeyPassphrasePrompt/);
  assert.match(workspace, /stopSavedHostPromptConnection[\s\S]*?disconnectSshWorkspace\(workspaceSessionId\)/);
  assert.match(workspace, /savedHostPromptSshState === "connecting"[\s\S]*?savedHostPromptSshState === "closing"/);
  assert.match(workspace, /setSavedHostKeyPassphrasePrompt\(null\);[\s\S]*?connectionPrompt\.error\.proxyPasswordRequired/);
  assert.match(workspace, /const \{ host, workspaceSessionId \} = savedHostPasswordPrompt;[\s\S]*?connectSavedHost\(host\)/);
  assert.doesNotMatch(workspace, /ONE-TIME (?:PASSWORD|PROXY PASSWORD|KEY PASSPHRASE)/);
});
