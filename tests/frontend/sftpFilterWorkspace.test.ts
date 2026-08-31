import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { createTranslator } from "../../src/i18n.ts";

const panelUrl = new URL("../../src/SftpBrowserPanel.tsx", import.meta.url);
const filterUrl = new URL("../../src/sftpFileFilter.ts", import.meta.url);
const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);
const stylesUrl = new URL("../../src/styles.css", import.meta.url);

test("SFTP filter stays renderer-local to the exact session and current directory", async () => {
  const [panel, filter, workspace] = await Promise.all([
    readFile(panelUrl, "utf8"),
    readFile(filterUrl, "utf8"),
    readFile(workspaceUrl, "utf8"),
  ]);

  assert.match(panel, /createSftpFilterSessionScopeKey\(activeOwner\)/);
  assert.match(panel, /createSftpFilterDirectoryScopeKey\(activeOwner, path\)/);
  assert.match(panel, /filterSftpEntries\(visibleEntries, scopedFilterState\.value\)/);
  assert.match(panel, /filteredEntries\.map\(\(entry\) =>/);
  assert.match(panel, /clearFilter[\s\S]*?value: ""/);
  assert.match(workspace, /active=\{sftpOpen && editorTarget === null\}/);
  assert.doesNotMatch(
    filter,
    /\binvoke\s*\(|\breadSftpDirectory\s*\(|\bsendSftp[A-Za-z]*\s*\(/,
  );
});

test("SFTP search shortcut is capture-safe and never claims ordinary editors", async () => {
  const [panel, filter] = await Promise.all([
    readFile(panelUrl, "utf8"),
    readFile(filterUrl, "utf8"),
  ]);

  assert.match(panel, /shouldFocusSftpFileFilter\(event, true, filterInputRef\.current\)/);
  assert.match(panel, /window\.addEventListener\("keydown", handleSearchShortcut, true\)/);
  assert.match(panel, /event\.preventDefault\(\)[\s\S]*?event\.stopPropagation\(\)/);
  assert.match(filter, /tagName === "INPUT" \|\| tagName === "TEXTAREA" \|\| tagName === "SELECT"/);
  assert.match(filter, /element\.isContentEditable === true/);
  assert.match(filter, /event\.target === filterInputTarget/);
  assert.match(filter, /event\.defaultPrevented !== true/);
});

test("filter UI exposes complete bilingual labels, clearing, and Escape exit", async () => {
  const [panel, styles] = await Promise.all([
    readFile(panelUrl, "utf8"),
    readFile(stylesUrl, "utf8"),
  ]);
  const en = createTranslator("en-US");
  const zh = createTranslator("zh-CN");

  assert.equal(en("sftp.filterPlaceholder"), "Filter files in this directory");
  assert.equal(en("sftp.filterInput"), "SFTP file filter");
  assert.equal(zh("sftp.filterPlaceholder"), "筛选当前目录中的文件");
  assert.equal(zh("sftp.filterInput"), "SFTP 文件筛选");
  assert.equal(zh("sftp.clearFilter"), "清空文件筛选");
  assert.equal(zh("sftp.closeFilter"), "关闭文件筛选");

  assert.match(panel, /placeholder=\{t\("sftp\.filterPlaceholder"\)\}/);
  assert.match(panel, /aria-label=\{t\("sftp\.filterInput"\)\}/);
  assert.match(panel, /aria-label=\{t\("sftp\.clearFilter"\)\}/);
  assert.match(panel, /aria-label=\{t\("sftp\.closeFilter"\)\}/);
  assert.match(panel, /resolveSftpFilterEscapeAction\(scopedFilterState\.value\)/);
  assert.match(panel, /hasEffectiveFilter && visibleEntries\.length > 0/);
  assert.match(styles, /\.sftp-filter-row\s*\{/);
  assert.match(styles, /\.sftp-filter-field\s*\{/);
});
