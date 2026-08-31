import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);
const backendUrl = new URL("../../src/backend.ts", import.meta.url);

test("legacy import refreshes every catalog which can receive imported data", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  const commit = source.slice(
    source.indexOf("const commitLegacyVaultPreview"),
    source.indexOf("const submitSavedHost"),
  );

  assert.match(source, /const \[notesSnippetsRefreshKey, setNotesSnippetsRefreshKey\] = useState\(0\);/);
  assert.match(commit, /setProxyProfileRefreshKey\(\(current\) => current \+ 1\)/);
  assert.match(commit, /setGroupConfigRefreshKey\(\(current\) => current \+ 1\)/);
  assert.match(commit, /setNotesSnippetsRefreshKey\(\(current\) => current \+ 1\)/);
  assert.match(
    source,
    /<ScriptsWorkspace[\s\S]*?refreshKey=\{notesSnippetsRefreshKey\}/,
  );
  assert.match(
    source,
    /<NotesWorkspace[\s\S]*?refreshKey=\{notesSnippetsRefreshKey\}/,
  );
});

test("legacy import preview and completion disclose every imported catalog without source bodies", async () => {
  const [workspace, backend] = await Promise.all([
    readFile(workspaceUrl, "utf8"),
    readFile(backendUrl, "utf8"),
  ]);
  const inspection = backend.slice(
    backend.indexOf("export type LegacyVaultInspection"),
    backend.indexOf("export type InspectLegacyVaultRequest"),
  );
  const result = backend.slice(
    backend.indexOf("export type LegacyVaultImportResult"),
    backend.indexOf("export type SftpEntryKind"),
  );
  const preview = workspace.slice(
    workspace.indexOf("const legacyVaultImportableEntityCount"),
    workspace.indexOf("const hasLegacyVaultErrorCode"),
  );
  const summaryRows = workspace.slice(
    workspace.indexOf("const LEGACY_VAULT_SUMMARY_ROWS"),
    workspace.indexOf("const legacyVaultImportableEntityCount"),
  );
  const commit = workspace.slice(
    workspace.indexOf("const commitLegacyVaultPreview"),
    workspace.indexOf("const submitSavedHost"),
  );
  const dialog = workspace.slice(
    workspace.indexOf('{legacyVaultPreview && ('),
    workspace.indexOf("{savedHostEditor && ("),
  );

  for (const field of [
    "recoverableTelnetCredentialCount", "telnetCredentialReentryRequiredCount",
    "sourceProxyProfileCount", "sourceInlineProxyHostCount", "importableProxyProfileCount",
    "duplicateProxyProfileCount", "conflictProxyProfileCount",
    "recoverableProxyProfileCredentialCount", "recoverableInlineProxyCredentialCount",
    "proxyProfileCredentialReentryRequiredCount", "inlineProxyCredentialReentryRequiredCount",
    "unsupportedProxyProfileCount",
    "sourceCustomGroupCount", "importableCustomGroupCount", "duplicateCustomGroupCount", "conflictCustomGroupCount",
    "sourceGroupConfigCount", "importableGroupConfigCount", "duplicateGroupConfigCount", "conflictGroupConfigCount",
    "sourceSnippetCount", "importableSnippetCount", "duplicateSnippetCount", "conflictSnippetCount",
    "sourceSnippetPackageCount", "importableSnippetPackageCount", "duplicateSnippetPackageCount",
    "sourceNoteCount", "importableNoteCount", "duplicateNoteCount", "conflictNoteCount",
    "sourceNoteGroupCount", "importableNoteGroupCount", "duplicateNoteGroupCount",
    "catalogScopeChangeCount",
    "remappedSnippetIdCount", "remappedNoteIdCount", "remappedHostScriptEdgeCount", "remappedGroupScriptEdgeCount",
  ]) {
    assert.match(inspection, new RegExp(`${field}: number;`));
    assert.match(
      summaryRows,
      new RegExp(`\\["${field}", "legacyImport\\.summary\\.[^"]+", (?:true|false)\\]`),
    );
  }
  assert.match(dialog, /LEGACY_VAULT_SUMMARY_ROWS\.map/);
  assert.match(dialog, /legacyVaultPreview\.inspection\[field\]/);
  assert.match(dialog, /<dt>\{t\(labelKey\)\}<\/dt>/);

  for (const field of [
    "importableProxyProfileCount",
    "importableCustomGroupCount",
    "importableGroupConfigCount",
    "importableSnippetCount",
    "importableSnippetPackageCount",
    "importableNoteCount",
    "importableNoteGroupCount",
  ]) {
    assert.match(preview, new RegExp(`inspection\\.${field}`));
  }

  for (const field of [
    "telnetCredentialsStoredCount",
    "telnetCredentialReentryRequiredCount",
    "proxyProfilesImportedCount",
    "proxyProfileCredentialsStoredCount",
    "inlineProxyCredentialsStoredCount",
    "proxyCredentialReentryRequiredCount",
    "customGroupsImportedCount",
    "groupConfigsImportedCount",
    "snippetsImportedCount",
    "snippetPackagesImportedCount",
    "notesImportedCount",
    "noteGroupsImportedCount",
  ]) {
    assert.match(result, new RegExp(`${field}: number;`));
    assert.match(commit, new RegExp(`result\\.${field}`));
  }

  assert.match(preview, /inspection\.catalogScopeChangeCount > 0/);
  assert.match(
    summaryRows,
    /"recoverableTelnetCredentialCount", "legacyImport\.summary\.recoverableTelnetPasswords"/,
  );
  assert.match(
    summaryRows,
    /"telnetCredentialReentryRequiredCount", "legacyImport\.summary\.telnetPasswordsNeedReentry"/,
  );
  assert.match(
    summaryRows,
    /"recoverableCredentialCount", "legacyImport\.summary\.recoverableCredentials"/,
  );
  assert.match(commit, /t\("legacyImport\.notice\.complete", \{/);
  assert.match(commit, /storedTelnet: result\.telnetCredentialsStoredCount/);
  assert.match(commit, /reentryTelnet: result\.telnetCredentialReentryRequiredCount/);

  const inspectHandler = workspace.slice(
    workspace.indexOf("const inspectLegacyVaultFile"),
    workspace.indexOf("const commitLegacyVaultPreview"),
  );
  assert.match(inspectHandler, /inspectLegacyVault\(\{ path: selectedPath \}\)/);
  assert.doesNotMatch(inspectHandler, /(?:arrayBuffer|FileReader|readAsText|\.text\(\))/);
});
