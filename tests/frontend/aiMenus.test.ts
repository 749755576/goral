import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { resolveAiMenuFocusIndex } from "../../src/ai/aiMenuKeyboard.ts";
import { createTranslator } from "../../src/i18n.ts";

const popupUrl = new URL("../../src/ai/AiPopupMenu.tsx", import.meta.url);
const agentUrl = new URL("../../src/ai/AiAgentMenu.tsx", import.meta.url);
const providerUrl = new URL("../../src/ai/AiProviderMenu.tsx", import.meta.url);
const permissionUrl = new URL("../../src/ai/AiPermissionMenu.tsx", import.meta.url);
const contextMenuUrl = new URL("../../src/ai/AiContextMenu.tsx", import.meta.url);
const thinkingMenuUrl = new URL("../../src/ai/AiThinkingMenu.tsx", import.meta.url);
const composerUrl = new URL("../../src/ai/AiComposer.tsx", import.meta.url);
const workspaceUrl = new URL("../../src/aiWorkspace.tsx", import.meta.url);
const stylesUrl = new URL("../../src/styles.css", import.meta.url);

test("AI popup keyboard navigation wraps and supports Home and End", () => {
  assert.equal(resolveAiMenuFocusIndex("ArrowDown", -1, 3), 0);
  assert.equal(resolveAiMenuFocusIndex("ArrowDown", 2, 3), 0);
  assert.equal(resolveAiMenuFocusIndex("ArrowUp", -1, 3), 2);
  assert.equal(resolveAiMenuFocusIndex("ArrowUp", 0, 3), 2);
  assert.equal(resolveAiMenuFocusIndex("Home", 2, 3), 0);
  assert.equal(resolveAiMenuFocusIndex("End", 0, 3), 2);
  assert.equal(resolveAiMenuFocusIndex("ArrowDown", 0, 0), null);
  assert.equal(resolveAiMenuFocusIndex("ArrowDown", 0, Number.NaN), null);
});

test("AI popup owns complete menu-button focus and dismissal semantics", async () => {
  const source = await readFile(popupUrl, "utf8");
  assert.match(source, /type="button"[\s\S]*?aria-haspopup="menu"[\s\S]*?aria-expanded=\{open\}[\s\S]*?aria-controls=\{open \? menuId/u);
  assert.match(source, /role="menu"[\s\S]*?aria-labelledby=\{triggerId\}/u);
  assert.match(source, /event\.key === "ArrowDown" \|\| event\.key === "ArrowUp"/u);
  assert.match(source, /menuitemradio[^\r\n]*:not\(\[aria-disabled=/u);
  assert.match(source, /\[role="searchbox"\]:not\(:disabled\)/u);
  assert.match(source, /\["ArrowDown", "ArrowUp", "Home", "End"\]/u);
  assert.match(source, /event\.key === "Escape"[\s\S]*?preventDefault\(\)[\s\S]*?stopPropagation\(\)[\s\S]*?close\(\)/u);
  assert.match(source, /event\.key === "Tab"[\s\S]*?close\(false\)/u);
  assert.match(source, /item\.tabIndex = item === target \? 0 : -1/u);
  assert.match(source, /scrollIntoView\(\{ block: "nearest" \}\)/u);
  assert.match(source, /document\.addEventListener\("pointerdown", onPointerDown, true\)[\s\S]*?removeEventListener\("pointerdown", onPointerDown, true\)/u);
});

test("Agent, provider, and permission menus expose grouped radio choices without moving configuration into chat", async () => {
  const [agent, provider, permission, composer, workspace] = await Promise.all([
    readFile(agentUrl, "utf8"),
    readFile(providerUrl, "utf8"),
    readFile(permissionUrl, "utf8"),
    readFile(composerUrl, "utf8"),
    readFile(workspaceUrl, "utf8"),
  ]);

  assert.match(agent, /role="group"[\s\S]*?ai\.menu\.agent\.builtinGroup/u);
  assert.match(agent, /ai\.menu\.agent\.availableGroup/u);
  assert.match(agent, /agents\.filter\(\(agent\) => agent\.runtimeSupported && agent\.available && localRuntimeAvailable\)/u);
  assert.doesNotMatch(agent, /ai\.menu\.agent\.unavailableGroup|aria-disabled="true"/u);
  assert.match(agent, /role="menuitemradio"[\s\S]*?aria-checked/u);

  assert.match(provider, /profiles: ReadonlyArray<AiProviderMenuProfile>/u);
  assert.match(provider, /profile\.name[\s\S]*?profile\.model/u);
  assert.match(provider, /ai\.menu\.provider\.current[\s\S]*?ai\.menu\.provider\.enabled[\s\S]*?ai\.menu\.provider\.disabled/u);
  assert.match(provider, /role="menuitem"[\s\S]*?onOpenSettings\(\)/u);
  assert.doesNotMatch(provider, /apiKey|baseUrl|type="password"/u);

  assert.match(permission, /mode: "observer"[\s\S]*?mode: "confirm"[\s\S]*?mode: "auto"/u);
  assert.match(permission, /observerDescription[\s\S]*?confirmDescription[\s\S]*?autoDescription/u);
  assert.match(permission, /role="menuitemradio"[\s\S]*?aria-checked=\{value === choice\.mode\}/u);

  assert.match(workspace, /<AiAgentMenu/u);
  assert.match(workspace, /<AiComposer/u);
  assert.match(composer, /<AiProviderMenu[\s\S]*?<AiPermissionMenu/u);
  assert.doesNotMatch(workspace, /<select[^>]*value=\{selectedAssistantEngine\}/u);
  assert.doesNotMatch(composer, /<select[^>]*value=\{engine\.provider\.value/u);
  assert.doesNotMatch(composer, /<select[^>]*value=\{engine\.permission\.value/u);
});

test("Composer exposes real context, model, mode, thinking, and permission controls in its footer", async () => {
  const [composer, contextMenu, thinkingMenu, provider] = await Promise.all([
    readFile(composerUrl, "utf8"),
    readFile(contextMenuUrl, "utf8"),
    readFile(thinkingMenuUrl, "utf8"),
    readFile(providerUrl, "utf8"),
  ]);

  assert.match(composer, /<footer>[\s\S]*?<AiContextMenu[\s\S]*?<AiProviderMenu[\s\S]*?ai-composer-mode-select[\s\S]*?<AiPermissionMenu/u);
  assert.doesNotMatch(composer, /<details|ai-composer-advanced|ai-send-inline/u);
  assert.match(contextMenu, /terminalContextAvailable \? \([\s\S]*?selectedText[\s\S]*?recentOutput/u);
  assert.match(contextMenu, /imageInputAvailable \? \([\s\S]*?ai\.composer\.image/u);
  assert.match(contextMenu, /ai\.composer\.quickMessage[\s\S]*?onOpenQuickMessages/u);
  assert.match(thinkingMenu, /"off" \| "low" \| "medium" \| "high"/u);
  assert.match(thinkingMenu, /role="menuitemradio"[\s\S]*?aria-checked=\{value === choice\.value\}/u);
  assert.match(provider, /modelValue\?: string[\s\S]*?models\?: ReadonlyArray<AiProviderMenuModel>/u);
  assert.match(provider, /thinking\?: Readonly<[\s\S]*?AiThinkingEffort[\s\S]*?ai-provider-thinking-options/u);
  assert.match(provider, /type="search"[\s\S]*?role="searchbox"[\s\S]*?searchModels/u);
  assert.match(provider, /onSelectModel\?\.\(modelId\)[\s\S]*?role="menuitemradio"/u);
});

test("AI menu copy is complete in Simplified Chinese and English", () => {
  const en = createTranslator("en-US");
  const zh = createTranslator("zh-CN");
  assert.equal(en("ai.menu.agent.availableGroup"), "Available on this computer");
  assert.equal(zh("ai.menu.agent.availableGroup"), "本机可用");
  assert.equal(en("ai.menu.provider.manage"), "Manage providers and API keys in Settings");
  assert.equal(zh("ai.menu.provider.manage"), "前往设置管理服务商和 API 密钥");
  assert.match(en("ai.permission.confirmDescription"), /recommended/u);
  assert.match(zh("ai.permission.confirmDescription"), /推荐/u);
  assert.match(en("ai.permission.autoDescription"), /safety/u);
  assert.match(zh("ai.permission.autoDescription"), /安全/u);
  assert.match(en("ai.permission.protocolToolUnsupported"), /Observer/u);
  assert.match(zh("ai.permission.protocolToolUnsupported"), /观察/u);
  for (const key of [
    "ai.composer.addMenuLabel",
    "ai.composer.quickMessageDescription",
    "ai.menu.provider.searchModels",
    "ai.thinking.highDescription",
  ] as const) {
    assert.notEqual(en(key), key);
    assert.notEqual(zh(key), key);
  }
});

test("truncated AI menu values keep complete localized hover text", async () => {
  const [agent, provider, permission, popup] = await Promise.all([
    readFile(agentUrl, "utf8"),
    readFile(providerUrl, "utf8"),
    readFile(permissionUrl, "utf8"),
    readFile(popupUrl, "utf8"),
  ]);

  assert.match(agent, /const selectedTitle = `\$\{selectedName\} · \$\{selectedSubtitle\}`;/u);
  assert.match(agent, /triggerTitle=\{selectedTitle\}/u);
  assert.match(agent, /title=\{`\$\{agent\.name\} · \$\{localDetail\(agent\)\}`\}/u);
  assert.match(provider, /triggerTitle=\{selected[\s\S]*?selected\.name[\s\S]*?selectedModel/u);
  assert.match(provider, /<strong>\{selectedModel \|\| selected\?\.name \|\| t\("ai\.noProvider"\)\}<\/strong>/u);
  assert.doesNotMatch(provider, /ai-popup-trigger-copy[\s\S]{0,180}<small>/u);
  assert.match(provider, /title=\{`\$\{profile\.name\} · \$\{profile\.model\} ·/u);
  assert.match(permission, /triggerTitle=\{`\$\{selected\.title\} · \$\{disabledReason \?\? selected\.description\}`\}/u);
  assert.match(permission, /title=\{`\$\{choice\.title\} · \$\{choice\.description\}`\}/u);
  assert.match(popup, /className=\{`ai-popup-root[\s\S]*?title=\{triggerTitle\}/u);
  assert.match(popup, /className=\{`ai-popup-trigger[\s\S]*?title=\{triggerTitle\}/u);
});

test("AI popup geometry stays inside the compact 319px workspace and scrolls long catalogs", async () => {
  const styles = await readFile(stylesUrl, "utf8");
  assert.match(styles, /\.ai-popup-menu\s*\{[\s\S]*?width:\s*min\(286px, calc\(100cqi - 16px\)\);[\s\S]*?max-height:[\s\S]*?overflow-y:\s*auto;/u);
  assert.match(styles, /\.ai-composer-controls\s*\{[\s\S]*?overflow:\s*visible;/u);
  assert.match(styles, /\.ai-composer-controls \.ai-popup-root\s*\{[\s\S]*?position:\s*static;/u);
  assert.match(styles, /\.ai-composer-controls \.ai-popup-menu\s*\{[\s\S]*?left:\s*8px;[\s\S]*?width:\s*min\(300px, calc\(100% - 16px\)\);/u);
  const compact = styles.slice(styles.indexOf("@container ai-workspace (max-width: 319px)"));
  assert.match(compact, /\.ai-agent-menu \.ai-popup-menu\s*\{[\s\S]*?width:\s*calc\(100cqi - 16px\);/u);
  assert.match(compact, /\.ai-composer-controls \.ai-popup-menu\s*\{[\s\S]*?right:\s*8px;[\s\S]*?left:\s*8px;[\s\S]*?width:\s*auto;/u);
});
