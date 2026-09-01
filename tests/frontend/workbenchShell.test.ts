import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const appUrl = new URL("../../src/App.tsx", import.meta.url);
const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);
const stylesUrl = new URL("../../src/styles.css", import.meta.url);
const frameStylesUrl = new URL("../../src/mainWorkspaceFrame.css", import.meta.url);
const indexUrl = new URL("../../index.html", import.meta.url);
const tauriConfigUrl = new URL("../../src-tauri/tauri.conf.json", import.meta.url);

test("App renders the workbench directly without the old branding banner", async () => {
  const source = await readFile(appUrl, "utf8");
  assert.match(source, /<main className="shell">[\s\S]*?<TerminalWorkspace \/>/);
  assert.doesNotMatch(source, /className="topbar"/);
  assert.doesNotMatch(source, /Electron Free|Rust Edition/);
});

test("desktop product branding uses the independent Goral identity", async () => {
  const [workspace, index, tauriConfig] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(indexUrl, "utf8"),
    readFile(tauriConfigUrl, "utf8"),
  ]);
  assert.doesNotMatch(workspace, /Netcatty Rust Terminal/);
  assert.match(index, /<title>Goral · 斑羚<\/title>/);
  const config = JSON.parse(tauriConfig);
  assert.equal(config.productName, "Goral");
  assert.equal(config.identifier, "io.github.749755576.goral");
  assert.equal(config.app.windows[0].title, "Goral · 斑羚");
  assert.equal(config.bundle.publisher, "Goral contributors");
  assert.match(config.bundle.copyright, /2026 749755576 and contributors/);
  assert.match(config.bundle.shortDescription, /Rust\/Tauri terminal workspace/);
  assert.match(config.bundle.longDescription, /^Goral is an Electron-free/);
  assert.deepEqual(config.bundle.icon, [
    "icons/32x32.png",
    "icons/128x128.png",
    "icons/128x128@2x.png",
    "icons/icon.icns",
    "icons/icon.ico",
  ]);
  const iconAssets = await Promise.all(config.bundle.icon.map((iconPath: string) => (
    readFile(new URL(`../../src-tauri/${iconPath}`, import.meta.url))
  )));
  assert.equal(iconAssets.every((asset) => asset.byteLength > 512), true);
});

test("workbench shell exposes Vault plus globally ordered terminal and Workspace tabs", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  assert.match(source, /className=\{`workspace workbench-shell surface-\$\{activeSurface\}`\}/);
  assert.match(source, /type WorkspaceSurface = "vault" \| "terminal"/);
  assert.match(source, /useState<WorkspaceSurface>\("vault"\)/);
  assert.match(source, /className="surface-tabs"/);
  assert.match(source, /\{t\("workspace\.vaults"\)\}/);
  assert.match(source, /setActiveSurface\("terminal"\)/);
  assert.match(source, /setActiveSurface\("vault"\)/);
  assert.match(source, /className="workspace-navigation"/);
  assert.match(source, /aria-label=\{t\("workspace\.hosts"\)\}/);
  assert.match(source, /aria-label=\{t\("workspace\.keychain"\)\}/);
  assert.match(source, /aria-label=\{t\("workspace\.proxies"\)\}/);
  assert.match(source, /className="vault-section-switcher"/);
  assert.match(source, /\{t\("workspace\.passwordIdentities"\)\}/);
  assert.match(source, /className=\{`surface-tab session-surface-tab/);
  assert.match(source, /terminalSessionCatalogRef\.current = createTerminalSessionCatalog\(\)/);
  assert.match(source, /useLocalTerminalSessions\([\s\S]*?terminalSessionCatalog,[\s\S]*?\)/);
  assert.match(source, /useSshTerminalSessions\([\s\S]*?terminalSessionCatalog,[\s\S]*?resolveSshTerminalAppearance/);
  assert.match(source, /const sharedTerminalRegistry = localTerminals\.registry/);
  assert.match(source, /createTerminalWorkspaceTabs\([\s\S]*?sharedTerminalRegistry\.order,[\s\S]*?hasTerminalPaneWorkspace \? terminalPaneSessionIds : \[\]/);
  assert.match(source, /terminalWorkspaceTabs\.map\(\(tab\) => \{/);
  assert.match(source, /if \(tab\.type === "workspace"\) \{[\s\S]*?<span>\{t\("workspace\.splitWorkspace"\)\}<\/span>/);
  assert.match(source, /const id = tab\.sessionId/);
  assert.match(source, /terminalSession = sharedTerminalRegistry\.sessions\[id\]/);
  assert.match(source, /key=\{id\}[\s\S]*?className=\{`local-session-tab/);
  const sharedActivation = source.slice(
    source.indexOf("const activateSharedTerminalSession"),
    source.indexOf("const commitTerminalPaneClone"),
  );
  assert.match(sharedActivation, /snapshot = terminalSessionCatalog\.snapshot\.sessions\[workspaceSessionId\]/);
  assert.match(sharedActivation, /if \(snapshot\.protocol === "local"\) \{[\s\S]*?localTerminals\.activate\(workspaceSessionId\)/);
  assert.match(sharedActivation, /else if \(snapshot\.protocol === "ssh" && sshTerminals\.owns\(workspaceSessionId\)\) \{[\s\S]*?sshTerminals\.activate\(workspaceSessionId\)/);
  assert.match(sharedActivation, /else \{[\s\S]*?return false/);
  assert.match(source, /activateSharedTerminalSession\(id, false\)/);
  assert.match(source, /if \(terminalSession\.protocol === "local"\) void localTerminals\.close\(id\);[\s\S]*?else void closeSshWorkspace\(id\)/);
  assert.match(source, /<LocalTerminalSessionViewports[\s\S]*?registry=\{sharedTerminalRegistry\}/);
  assert.match(source, /<SshTerminalSessionViewports[\s\S]*?registry=\{sharedTerminalRegistry\}[\s\S]*?owns=\{sshTerminals\.owns\}/);
  assert.match(source, /className="terminal-session-summary"/);
  assert.doesNotMatch(source, /className="terminal-tab-strip"|className="new-terminal-tab"/);
  assert.doesNotMatch(source, /className="catty-agent-panel"|>Catty Agent<|className="catty-agent-composer"/);
  assert.match(source, /hidden=\{activeSurface !== "terminal"[\s\S]*?\|\| \(connectionTarget === null && activeSharedSession === null\)\}/);
  assert.doesNotMatch(source, /user@127\.0\.0\.1/);
  assert.doesNotMatch(source, /Netcatty Terminal/);

  const styles = await readFile(stylesUrl, "utf8");
  assert.match(styles, /\.surface-vault\s*\{[\s\S]*?background:\s*var\(--ld-surface-muted\)/);
  assert.match(styles, /\.surface-vault \.connection-panel\s*\{[\s\S]*?grid-template-columns:\s*208px minmax\(0, 1fr\)/);
  assert.match(styles, /\.surface-terminal\s*\{[\s\S]*?grid-template-columns:\s*258px minmax\(360px, 1fr\) minmax\(300px, 356px\)/);
  assert.match(styles, /\.surface-terminal \.terminal-panel\s*\{[\s\S]*?grid-column:\s*2/);
  assert.match(styles, /\.terminal-side-panel\s*\{[\s\S]*?grid-column:\s*3/);
  assert.match(styles, /\.workspace-chrome\s*\{/);
});

test("Vault keeps the original single-level navigation while identity, key, and proxy catalogs remain reachable", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  const tabs = source.slice(
    source.indexOf('<div className="connection-tabs">'),
    source.indexOf('\n          <div className="vault-navigation-footer"'),
  );
  assert.match(tabs, /aria-label=\{t\("workspace\.keychain"\)\}/);
  assert.match(tabs, /aria-label=\{t\("workspace\.proxies"\)\}/);
  assert.match(tabs, /showVaultView\("keys"\)/);
  assert.match(tabs, /showVaultView\("proxies"\)/);
  assert.doesNotMatch(tabs, /Password Identities/);

  const sectionSwitcher = source.slice(
    source.indexOf('<div className="vault-section-switcher"'),
    source.indexOf('\n            ) : (', source.indexOf('<div className="vault-section-switcher"')),
  );
  assert.match(sectionSwitcher, /t\("workspace\.passwordIdentities"\)/);
  assert.match(sectionSwitcher, /showVaultView\("identities"\)/);

  const styles = await readFile(stylesUrl, "utf8");
  assert.match(styles, /\.surface-vault \.password-identity-catalog/);
  assert.match(styles, /\.surface-vault \.proxy-profile-catalog/);
  assert.match(styles, /\[hidden\]\s*\{[\s\S]*?display:\s*none !important/);
});

test("Vault keeps the legacy product navigation visible and enables completed modules", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  const navigation = source.slice(
    source.indexOf('<nav className="workspace-navigation"'),
    source.indexOf("\n        </nav>"),
  );

  for (const key of [
    "workspace.hosts",
    "workspace.keychain",
    "workspace.proxies",
    "workspace.portForwarding",
    "workspace.scripts",
    "workspace.notes",
    "workspace.knownHosts",
    "workspace.logs",
    "workspace.settings",
  ]) {
    assert.equal(navigation.includes(`t("${key}")`), true);
  }
  assert.doesNotMatch(navigation, />Quick Connect</);
  assert.doesNotMatch(navigation, />Soon</);
  assert.match(navigation, /aria-label=\{t\("workspace\.portForwarding"\)\}/);
  assert.match(navigation, /showVaultView\("port"\)/);
  assert.doesNotMatch(navigation, /Port Forwarding 正在迁移/);
  assert.match(navigation, /aria-label=\{t\("workspace\.scripts"\)\}/);
  assert.match(navigation, /showVaultView\("scripts"\)/);
  assert.match(navigation, /aria-label=\{t\("workspace\.notes"\)\}/);
  assert.match(navigation, /showVaultView\("notes"\)/);
  assert.doesNotMatch(navigation, /Scripts 正在迁移|Notes 正在迁移/);
  assert.match(navigation, /aria-label=\{t\("workspace\.knownHosts"\)\}/);
  assert.match(navigation, /showVaultView\("known"\)/);
  assert.doesNotMatch(navigation, /Known Hosts 正在迁移/);
  assert.match(navigation, /aria-label=\{t\("workspace\.logs"\)\}/);
  assert.match(navigation, /showVaultView\("logs"\)/);
  assert.doesNotMatch(navigation, /Connection Logs 正在迁移/);
  assert.match(navigation, /openSettingsWindow\(rendererLocale\)/);
  assert.doesNotMatch(navigation, /Settings 正在迁移/);
});

test("Vault header and empty state retain the original Hosts workflow", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  assert.match(source, /placeholder=\{t\("workspace\.searchHostsPlaceholder"\)\}/);
  assert.match(source, /className="vault-view-controls"/);
  assert.match(source, /setHostViewMode\(mode\)/);
  assert.match(source, /className="vault-new-host-split"/);
  assert.match(source, /<VaultGlyph name="terminal" \/> \{t\("workspace\.localTerminal"\)\}/);
  assert.match(source, /onClick=\{openQuickSerialPanel\}[\s\S]*?<VaultGlyph name="serial" \/> \{t\("workspace\.serial"\)\}/);
  assert.doesNotMatch(source, /disabled title="Serial 会话正在迁移"/);
  assert.match(source, /className="vault-empty-state"/);
  assert.match(source, /<h3>\{t\("workspace\.noSavedHosts"\)\}<\/h3>/);
  assert.match(source, /className="primary-button"[\s\S]*?<span><VaultGlyph name="plus" \/><\/span>[\s\S]*?<strong>\{t\("workspace\.newHost"\)\}<\/strong>/);
  assert.match(source, /className="vault-empty-actions"[\s\S]*?<VaultGlyph name="download" \/> \{t\("workspace\.importVault"\)\}/);
});

test("plain-browser visual previews fall back to an empty Vault without invoke errors", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  assert.match(source, /import \{ isTauri \} from "@tauri-apps\/api\/core"/);
  assert.match(source, /const NATIVE_DESKTOP_RUNTIME_AVAILABLE = isTauri\(\)/);
  assert.match(source, /if \(!NATIVE_DESKTOP_RUNTIME_AVAILABLE\) \{[\s\S]*?setSavedHosts\(\[\]\);[\s\S]*?setSavedHostsError\(null\);[\s\S]*?setSavedHostsLoading\(false\);/);
  assert.match(source, /if \(!NATIVE_DESKTOP_RUNTIME_AVAILABLE\) return;[\s\S]*?subscribeHostKeyPrompts/);
  assert.match(source, /className="runtime-preview-placeholder"/);
});

test("browser-sized workbench releases the native guard width and stacks onboarding actions", async () => {
  const styles = await readFile(frameStylesUrl, "utf8");
  assert.match(styles, /@media \(max-width: 979px\)[\s\S]*?body\s*\{[\s\S]*?min-width:\s*0/);
  assert.match(styles, /@media \(max-width: 700px\)[\s\S]*?\.surface-vault \.vault-onboarding-paths\s*\{[\s\S]*?grid-template-columns:\s*1fr/);
  assert.match(styles, /\.surface-vault \.vault-onboarding-path,\s*\.surface-vault \.vault-onboarding-paths > \.primary-button\[data-onboarding-path="primary"\][\s\S]*?min-height:\s*132px/);
});

test("SSH prompt subscriptions and queue authority are retired on a real window unmount", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  assert.match(source, /pendingSshPromptQueueDisposalRef\.current = token[\s\S]*?queueMicrotask\(\(\) => \{[\s\S]*?sshPromptQueue\.dispose\(\)/);
  assert.equal(
    [...source.matchAll(/if \(promptChannel\) promptChannel\.onmessage = \(\) => \{\}/g)].length,
    2,
    "both native prompt channel callbacks are detached during cleanup",
  );
});

test("Vault uses a light card surface while sessions use the resolved terminal theme", async () => {
  const styles = await readFile(stylesUrl, "utf8");
  const dualSurface = styles.slice(styles.indexOf("/* Netcatty dual-surface desktop shell"));
  assert.match(dualSurface, /\.surface-vault[\s\S]*?background:\s*var\(--ld-surface-muted\)/);
  assert.match(dualSurface, /\.surface-vault \.saved-host-card\s*\{[\s\S]*?border:\s*1px solid/);
  assert.match(
    dualSurface,
    /\.surface-terminal[\s\S]*?background:\s*var\(--terminal-resolved-bg, var\(--ld-accent-soft\)\)/,
  );
  assert.match(dualSurface, /\.surface-terminal \.terminal-container\s*\{[\s\S]*?background:\s*var\(--terminal-resolved-bg, #0d1117\)/);
});
