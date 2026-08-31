import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import test from "node:test";

import {
  LOCALES,
  createTranslator,
  localizeAiError,
  normalizeLocale,
} from "../../src/i18n.ts";
import { createDefaultRendererSafeSettings } from "../../src/settingsUi.ts";

const rendererSourceRoot = new URL("../../src/", import.meta.url);

test("supported locale catalogs have identical typed keys", () => {
  assert.deepEqual(
    Object.keys(LOCALES["zh-CN"]).sort(),
    Object.keys(LOCALES["en-US"]).sort(),
  );
});

test("translation catalogs use the supported double-brace placeholder syntax", () => {
  const unsupportedPlaceholder = /(^|[^\{])\{[A-Za-z][A-Za-z0-9_]*\}(?!\})/u;
  for (const [locale, catalog] of Object.entries(LOCALES)) {
    const violations = Object.entries(catalog)
      .filter(([, value]) => unsupportedPlaceholder.test(value))
      .map(([key]) => key);
    assert.deepEqual(
      violations,
      [],
      `${locale} contains unsupported single-brace placeholders: ${violations.join(", ")}`,
    );
  }
});

test("system manager placeholders are rendered instead of leaking braces into the UI", () => {
  const zh = createTranslator("zh-CN");
  const en = createTranslator("en-US");

  assert.equal(en("systemManager.rowCount", { count: 7 }), "7 entries");
  assert.equal(
    en("systemManager.process.confirmKillBody", { pid: 42, command: "worker" }),
    "PID 42 (worker) will be terminated immediately, without a chance to shut down cleanly.",
  );
  assert.equal(zh("systemManager.docker.summary", { running: 2, total: 5 }), "共 5 个，运行中 2 个");
  assert.equal(zh("systemManager.docker.memory", { value: "128 MiB" }), "内存 128 MiB");
  assert.equal(zh("systemManager.docker.imagesTitle"), "镜像");
  assert.equal(en("systemManager.docker.imagesEmptyTitle"), "No images");
  assert.equal(
    zh("systemManager.docker.inspectTitle", { name: "web-1" }),
    "容器详情：web-1",
  );
  assert.equal(
    en("systemManager.docker.inspectContentLabel", { name: "web-1" }),
    "Read-only details for web-1",
  );
});

test("React presentation files keep Chinese copy in the typed catalog", async () => {
  const entries = await readdir(rendererSourceRoot, { withFileTypes: true });
  const violations: string[] = [];
  await Promise.all(entries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".tsx"))
    .map(async (entry) => {
      const source = await readFile(new URL(entry.name, rendererSourceRoot), "utf8");
      if (/\p{Script=Han}/u.test(source)) violations.push(entry.name);
    }));
  assert.deepEqual(
    violations.sort(),
    [],
    `Move user-visible Chinese text into i18n.ts: ${violations.join(", ")}`,
  );
});

test("React presentation keeps natural-language JSX copy in the typed catalog", async () => {
  const technicalUiLiterals = new Set([
    "127.0.0.1",
    "3306",
    "A+",
    "A−",
    "enc:v1:",
    "HTTP",
    "JavaScript",
    "Goral",
    "Mosh",
    "N",
    "Python",
    "root",
    "server.example.com",
    "SFTP",
    "SOCKS5",
    "SSH",
    "Telnet",
    "UTF-8",
  ]);
  const entries = await readdir(rendererSourceRoot, { withFileTypes: true });
  const violations: string[] = [];
  await Promise.all(entries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".tsx"))
    .map(async (entry) => {
      const source = await readFile(new URL(entry.name, rendererSourceRoot), "utf8");
      const candidates = [
        />\s*([A-Za-z][^<>{}\r\n]*?)\s*<\/[A-Za-z]/gu,
        /\b(?:title|aria-label|aria-description|placeholder|alt)\s*=\s*["']([^"']+)["']/gu,
      ];
      for (const pattern of candidates) {
        for (const match of source.matchAll(pattern)) {
          const literal = match[1]?.trim() ?? "";
          if (!literal || technicalUiLiterals.has(literal)) continue;
          const line = source.slice(0, match.index).split(/\r?\n/u).length;
          violations.push(`${entry.name}:${line}: ${literal}`);
        }
      }
    }));
  assert.deepEqual(
    violations.sort(),
    [],
    `Move user-visible natural language into i18n.ts (technical tokens are allowlisted):\n${violations.join("\n")}`,
  );
});

test("SavedHost session failures do not expose unknown native prose", async () => {
  const source = await readFile(new URL("TerminalWorkspace.tsx", rendererSourceRoot), "utf8");
  const boundary = source.slice(
    source.indexOf("const savedHostSessionErrorMessage"),
    source.indexOf("const isSavedHostRevisionConflict"),
  );
  assert.match(boundary, /SAVED_PROXY_CREDENTIAL_NOT_FOUND/u);
  assert.match(boundary, /t\("terminal\.runtime\.connectionFailed"\)/u);
  assert.doesNotMatch(boundary, /return message;/u);
});

test("system language follows English systems while malformed values fall back to Simplified Chinese", () => {
  assert.equal(normalizeLocale("system", "zh-CN"), "zh-CN");
  assert.equal(normalizeLocale("system", "en-GB"), "en-US");
  assert.equal(normalizeLocale("system", "invalid"), "zh-CN");
  assert.equal(normalizeLocale("fr-FR"), "zh-CN");
  assert.equal(normalizeLocale("en-US"), "en-US");
  assert.equal(createDefaultRendererSafeSettings().appearance.uiLanguage, "zh-CN");
});

test("translation interpolation preserves unknown placeholders and renders locale text", () => {
  const translate = createTranslator("en-US");
  assert.equal(
    translate("ai.contextSummary", { selected: 4, recent: 12 }),
    "Selected 4 chars · recent output 12 chars",
  );
  assert.equal(translate("ai.contextSummary"), "Selected {{selected}} chars · recent output {{recent}} chars");
});

test("SavedHost editor catalogs preserve Chinese defaults and provide natural English", () => {
  const zh = createTranslator("zh-CN");
  const en = createTranslator("en-US");

  assert.equal(zh("savedHost.editor.dialog.titleCreate"), "新建主机");
  assert.equal(zh("savedHost.editor.dialog.save"), "保存");
  assert.equal(
    zh("savedHost.editor.dialog.desktopOnly"),
    "浏览器预览无法访问原生保险库，请在 Goral 桌面应用中保存主机。",
  );
  assert.equal(zh("savedHost.editor.dialog.kicker", { protocol: "TELNET" }), "保险库 · TELNET");
  assert.equal(zh("savedHost.editor.general.name"), "名称");
  assert.equal(zh("savedHost.editor.credentials.authKey"), "托管 SSH 私钥");
  assert.equal(zh("savedHost.editor.proxy.inlineEnabled"), "使用内联代理（启用时优先于上方代理配置）");
  assert.equal(zh("savedHost.editor.chain.direct"), "直接连接 · 不经过跳板主机");

  assert.equal(en("savedHost.editor.dialog.titleCreate"), "New Host");
  assert.equal(en("savedHost.editor.dialog.save"), "Save");
  assert.equal(
    en("savedHost.editor.dialog.desktopOnly"),
    "Saving Hosts requires Goral desktop because the native Vault is unavailable in browser preview.",
  );
  assert.equal(en("savedHost.editor.dialog.kicker", { protocol: "SERIAL" }), "VAULT · SERIAL");
  assert.equal(en("savedHost.editor.general.name"), "Name");
  assert.equal(en("savedHost.editor.credentials.authKey"), "Managed SSH private key");
  assert.equal(en("savedHost.editor.proxy.inlineEnabled"), "Use an inline proxy (takes priority over the profile above)");
  assert.equal(en("savedHost.editor.chain.direct"), "Direct connection · No jump host");
  assert.equal(zh("savedHost.validation.port"), "端口必须是 1 到 65535 之间的整数。");
  assert.equal(en("savedHost.error.saveFailed"), "The Host could not be saved safely. Refresh the catalog and try again.");
  assert.equal(
    zh("savedHost.delete.confirmWithIdentity", {
      host: "生产库",
      credentialNote: "主机密码也会删除。",
      identity: "DBA",
    }),
    "确定删除已保存主机“生产库”吗？主机密码也会删除。共享密码身份“DBA”及其密码不会被删除。",
  );
  assert.equal(
    en("savedHost.editor.chain.moveUp", { target: "bastion.example" }),
    "Move jump host bastion.example up",
  );
});

test("safe multi-session restore is bilingual and remains explicit", () => {
  const zh = createTranslator("zh-CN");
  const en = createTranslator("en-US");

  assert.equal(zh("restore.restoreSelected", { count: 3 }), "恢复所选标签（3）");
  assert.equal(zh("restore.restoringSelected"), "正在恢复标签…");
  assert.equal(en("restore.restoreSelected", { count: 2 }), "Restore selected tabs (2)");
  assert.match(en("restore.description"), /never reconnects automatically/);
});

test("Connection Logs and Local Terminal surfaces follow the selected locale", () => {
  const zh = createTranslator("zh-CN");
  const en = createTranslator("en-US");

  assert.equal(zh("connectionLogs.title"), "连接日志");
  assert.equal(zh("connectionLogs.replay.readOnly"), "只读");
  assert.equal(zh("connectionLogs.replay.hostPrefix"), "主机：");
  assert.equal(en("connectionLogs.replay.hostPrefix"), "Host: ");
  assert.equal(zh("connectionLogs.protocol.local"), "本地");
  assert.equal(
    zh("connectionLogs.protocol.detail", { protocol: zh("connectionLogs.protocol.serial"), target: "COM3" }),
    "串口，COM3",
  );
  assert.equal(
    zh("connectionLogs.replay.durationValue", { minutes: 2, seconds: 7 }),
    "2 分 7 秒",
  );
  assert.equal(en("connectionLogs.title"), "Connection Logs");
  assert.equal(en("connectionLogs.replay.readOnly"), "Read-only");
  assert.equal(en("localTerminal.chooseDirectoryFailed"), "Could not open the folder picker. Try again.");
  assert.match(zh("localTerminal.openFailed"), /无法打开本地终端/);
  assert.equal(en("terminal.local.opening", { target: "PowerShell" }), "Opening PowerShell…");
  assert.equal(zh("terminal.local.closed"), "本地终端已关闭");
});

test("AI terminal tool settings and agent failures describe the active safety model", () => {
  const zh = createTranslator("zh-CN");
  const en = createTranslator("en-US");

  assert.equal(en("settings.anchor.ai-terminal-execute"), "Terminal execution tool");
  assert.equal(zh("settings.anchor.ai-terminal-execute"), "终端执行工具");
  assert.equal(en("settings.anchor.ai-safety-command-timeout"), "Command output capture timeout");
  assert.equal(zh("settings.anchor.ai-safety-command-timeout"), "命令输出捕获超时");
  assert.equal(en("settings.anchor.ai-safety-response-timeout"), "Provider response timeout");
  assert.equal(zh("settings.anchor.ai-safety-response-timeout"), "服务商响应等待时间");
  assert.match(en("ai.settings.safety.responseTimeoutDescription"), /response data.*Streaming output/u);
  assert.match(zh("ai.settings.safety.responseTimeoutDescription"), /服务商.*流式输出/u);
  assert.equal(en("ai.settings.safety.responseTimeoutUnit"), "s");
  assert.equal(zh("ai.settings.safety.responseTimeoutUnit"), "秒");
  assert.match(en("ai.settings.permissionDescription"), /terminal_execute/);
  assert.equal(en("ai.settings.permissionAsk"), "Confirm before every tool call (recommended)");
  assert.equal(en("ai.settings.permissionAuto"), "Automatically run allowed tool calls");
  assert.equal(en("ai.settings.permissionDeny"), "Observer (execution disabled)");
  assert.equal(zh("ai.settings.permissionAsk"), "每次工具调用前确认（推荐）");
  assert.equal(zh("ai.settings.permissionDeny"), "观察者（禁止执行）");
  assert.equal(en("ai.settings.builtinAgentActive"), "Active");
  assert.equal(zh("ai.settings.terminalToolAvailable"), "可用");
  assert.equal(en("ai.settings.safety.timeoutValue"), "5 seconds");
  assert.equal(zh("ai.settings.safety.grantsValue"), "仅限当前终端");
  assert.match(en("ai.settings.safety.limitsDescription"), /4 iterations.*32 KiB/);

  const errorCases = [
    ["AI_IMAGE_INPUT_INVALID", "ai.error.imageInputInvalid"],
    ["AI_IMAGE_INPUT_UNSUPPORTED", "ai.error.imageInputUnsupported"],
    ["AI_REASONING_PROTOCOL_UNSUPPORTED", "ai.error.reasoningProtocolUnsupported"],
    ["AI_AGENT_ITERATION_LIMIT", "ai.error.agentIterationLimit"],
    ["AI_AGENT_TURN_NOT_FOUND", "ai.error.agentTurnNotFound"],
    ["AI_TERMINAL_SCOPE_INVALID", "ai.error.terminalScopeInvalid"],
    ["AI_TOOL_CALL_INVALID", "ai.error.toolCallInvalid"],
    ["AI_TOOL_COMMAND_INVALID", "ai.error.toolCommandInvalid"],
    ["AI_TOOL_RESULT_INVALID", "ai.error.toolResultInvalid"],
  ] as const;
  for (const [code, key] of errorCases) {
    assert.equal(localizeAiError(new Error(`${code}: private detail`), en), en(key));
    assert.equal(localizeAiError(new Error(`${code}: 私密详情`), zh), zh(key));
  }
  assert.match(en("ai.error.reasoningProtocolUnsupported"), /protocol does not support reasoning effort/u);
  assert.match(zh("ai.error.reasoningProtocolUnsupported"), /接口协议不支持思考强度/u);
  assert.match(zh("ai.error.agentTurnNotFound"), /5 分钟后过期/);
});

test("brand, SFTP, and serial-transfer status text never mixes locales", () => {
  const zh = createTranslator("zh-CN");
  const en = createTranslator("en-US");

  assert.equal(zh("brand.subtitle"), "斑羚");
  assert.equal(en("brand.subtitle"), "Terminal workspace");
  assert.equal(zh("sftp.action.newFolderPrompt"), "请输入新文件夹名称");
  assert.equal(en("sftp.action.newFolderPrompt"), "New folder name");
  assert.equal(zh("transfer.zmodem.selectionCanceled"), "已取消 ZMODEM 文件选择。");
  assert.equal(en("transfer.zmodem.selectionCanceled"), "ZMODEM file selection canceled.");
  assert.equal(
    en("transfer.zmodem.sent", { count: "2", size: "1 MiB" }),
    "ZMODEM send complete: 2 files (1 MiB)",
  );
});

test("one-time connection prompts are complete, safe, and bilingual", () => {
  const zh = createTranslator("zh-CN");
  const en = createTranslator("en-US");

  assert.equal(zh("connectionPrompt.common.connectionFailedPrefix"), "连接失败：");
  assert.equal(zh("connectionPrompt.common.cancelConnection"), "取消连接");
  assert.equal(zh("connectionPrompt.common.manualLogin"), "手动登录");
  assert.equal(zh("connectionPrompt.common.connecting"), "正在连接…");
  assert.equal(zh("connectionPrompt.password.title"), "输入一次性密码");
  assert.equal(zh("connectionPrompt.proxy.sshPasswordLabel"), "SSH 登录密码");
  assert.equal(zh("connectionPrompt.keyPassphrase.savedPlaceholder"), "留空则使用已安全保存的口令");
  assert.match(zh("connectionPrompt.keyPassphrase.securityNote"), /不会写入主机记录、日志或页面存储/);

  assert.equal(en("connectionPrompt.common.connectionFailedPrefix"), "Connection failed: ");
  assert.equal(en("connectionPrompt.common.cancel"), "Cancel");
  assert.equal(en("connectionPrompt.common.connect"), "Connect");
  assert.equal(en("connectionPrompt.password.label"), "Password");
  assert.equal(en("connectionPrompt.proxy.proxyPasswordLabel"), "Proxy password");
  assert.equal(
    en("connectionPrompt.keyPassphrase.unsavedPlaceholder"),
    "Enter only if the private key requires a passphrase",
  );
  assert.match(en("connectionPrompt.proxy.securityNote"), /never saved/);
  assert.match(en("connectionPrompt.keyPassphrase.savedDescription"), /connection only/);
});

test("connection prompt transitions expose stable bilingual recovery messages", () => {
  const zh = createTranslator("zh-CN");
  const en = createTranslator("en-US");

  assert.equal(
    zh("connectionPrompt.error.keyFileConfirmationRequired"),
    "连接前必须重新选择 SSH 私钥文件。",
  );
  assert.equal(
    zh("connectionPrompt.error.keyFileSelectionInvalid"),
    "所选 SSH 私钥文件无效，请重新选择。",
  );
  assert.equal(
    zh("connectionPrompt.error.proxyPasswordRequired"),
    "代理需要一次性密码。该密码与 SSH 登录密码相互独立。",
  );
  assert.equal(
    zh("connectionPrompt.error.sshAndProxyPasswordsRequired"),
    "SSH 登录也需要一次性密码，请分别重新输入 SSH 密码和代理密码。",
  );
  assert.equal(
    zh("connectionPrompt.error.savedCredentialMissing"),
    "系统中已找不到这台主机或绑定身份的有效密码，请输入一次性密码。",
  );

  assert.match(en("connectionPrompt.error.keyFileConfirmationRequired"), /private key file again/);
  assert.match(en("connectionPrompt.error.keyFileSelectionInvalid"), /private key file is invalid/);
  assert.match(en("connectionPrompt.error.proxyPasswordRequired"), /separate from the SSH login password/);
  assert.match(en("connectionPrompt.error.sshAndProxyPasswordsRequired"), /Re-enter the SSH and proxy passwords/);
  assert.match(en("connectionPrompt.error.savedCredentialMissing"), /system credential store/);
});

test("managed keys, legacy import, Host key, and SSH verification dialogs are bilingual", () => {
  const zh = createTranslator("zh-CN");
  const en = createTranslator("en-US");

  assert.equal(zh("managedKey.rotate.title"), "轮换托管密钥的主密钥？");
  assert.equal(en("managedKey.rotate.confirm"), "Rotate");
  assert.equal(zh("legacyImport.summary.importableHosts"), "待导入主机");
  assert.equal(en("legacyImport.summary.recoverableTelnetPasswords"), "Recoverable Telnet passwords");
  assert.equal(zh("hostKey.changedTitle"), "服务器主机密钥已变化");
  assert.equal(en("hostKey.trustOnce"), "Trust Once");
  assert.match(en("hostKey.error.respondFailed"), /connection remains blocked/);
  assert.equal(zh("interactiveAuth.title"), "需要进一步验证");
  assert.equal(en("interactiveAuth.prompt", { index: 2 }), "Verification response 2");
  assert.match(zh("interactiveAuth.error.respondFailed"), /无法发送验证结果/);
  assert.equal(zh("localTerminal.openDialog"), "打开本地终端");
});
