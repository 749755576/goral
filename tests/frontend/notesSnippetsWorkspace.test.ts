import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { createTranslator } from "../../src/i18n.ts";
import {
  classifyNotesSnippetsError,
  createEmptySavedSnippetDraft,
  createEmptyVaultNoteDraft,
  matchesSavedSnippetSearch,
  matchesVaultNoteSearch,
  nextCatalogOrder,
  savedSnippetToDraft,
  sortSavedSnippets,
  sortVaultNotes,
  splitListInput,
  vaultNoteToDraft,
} from "../../src/notesSnippetsUi.ts";

const apiUrl = new URL("../../src/notesSnippetsApi.ts", import.meta.url);
const notesWorkspaceUrl = new URL("../../src/NotesWorkspace.tsx", import.meta.url);
const scriptsWorkspaceUrl = new URL("../../src/ScriptsWorkspace.tsx", import.meta.url);
const sharedWorkspaceUrl = new URL("../../src/NotesScriptsShared.tsx", import.meta.url);
const stylesUrl = new URL("../../src/notesScripts.css", import.meta.url);
const terminalWorkspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);
const mainUrl = new URL("../../src/main.tsx", import.meta.url);

test("Notes and Snippets DTOs mirror the Rust persistent fields without runtime state", async () => {
  const source = await readFile(apiUrl, "utf8");
  const note = source.slice(
    source.indexOf("export type SavedVaultNote ="),
    source.indexOf("export type SavedVaultNoteDraft"),
  );
  for (const field of [
    "id: string;",
    "title: string;",
    "content: string;",
    "group?: string;",
    "tags?: string[];",
    "linkedHostIds?: string[];",
    "createdAt: number;",
    "updatedAt: number;",
    "order?: number;",
  ]) {
    assert.match(note, new RegExp(field.replace(/[?\[\]]/g, "\\$&")));
  }

  const snippet = source.slice(
    source.indexOf("export type SavedSnippet ="),
    source.indexOf("export type SavedSnippetDraft"),
  );
  for (const field of [
    "id: string;",
    "label: string;",
    "command: string;",
    "tags?: string[];",
    "package?: string;",
    "targets?: string[];",
    "targetGroups?: string[];",
    "targetsAllHosts?: boolean;",
    "shortkey?: string;",
    "noAutoRun?: boolean;",
    "multiLineRunMode?: SavedSnippetMultiLineRunMode;",
    "order?: number;",
    "kind?: SavedSnippetKind;",
    "language?: SavedScriptLanguage;",
    "description?: string;",
    "trigger?: SavedScriptTrigger;",
    "triggerPattern?: string;",
  ]) {
    assert.match(snippet, new RegExp(field.replace(/[?\[\]]/g, "\\$&")));
  }

  for (const forbidden of [
    "revision",
    "running",
    "active",
    "status",
    "lastError",
    "output",
    "runId",
    "sessionId",
  ]) {
    assert.doesNotMatch(note, new RegExp(`\\b${forbidden}\\b`, "i"));
    assert.doesNotMatch(snippet, new RegExp(`\\b${forbidden}\\b`, "i"));
  }
});

test("CRUD commands use the confirmed eight-command Tauri boundary and inventory CAS", async () => {
  const source = await readFile(apiUrl, "utf8");
  for (const command of [
    "list_vault_notes",
    "create_vault_note",
    "update_vault_note",
    "delete_vault_note",
    "list_saved_snippets",
    "create_saved_snippet",
    "update_saved_snippet",
    "delete_saved_snippet",
  ]) {
    assert.match(source, new RegExp(`"${command}"`));
  }

  const requests = source.slice(
    source.indexOf("export type CreateVaultNoteRequest"),
    source.indexOf("export const NOTES_SNIPPETS_COMMANDS"),
  );
  assert.equal((requests.match(/expectedInventoryRevision: unknown;/g) ?? []).length, 6);
  assert.doesNotMatch(requests, /expectedRevision/);
  assert.match(requests, /SavedVaultNoteDraft/);
  assert.match(requests, /SavedSnippetDraft/);
  assert.match(source, /SavedVaultNote,[\s\S]*?"id" \| "createdAt" \| "updatedAt"/);
  assert.match(source, /SavedSnippet, "id"/);

  for (const operation of [
    "createNote",
    "updateNote",
    "deleteNote",
    "createSnippet",
    "updateSnippet",
    "deleteSnippet",
  ]) {
    assert.match(
      source,
      new RegExp(`invoke<NotesSnippetsCatalog>\\(NOTES_SNIPPETS_COMMANDS\\.${operation}, \\{ request \\}\\)`),
    );
  }
});

test("renderer drafts cannot submit Rust-owned IDs or note timestamps", () => {
  const noteDraft = vaultNoteToDraft({
    id: "note-1",
    title: "Runbook",
    content: "Restart safely",
    group: "Ops/Runbooks",
    tags: ["ops"],
    linkedHostIds: ["host-1"],
    createdAt: 100,
    updatedAt: 200,
    order: 3,
  });
  assert.deepEqual(noteDraft, {
    title: "Runbook",
    content: "Restart safely",
    group: "Ops/Runbooks",
    tags: ["ops"],
    linkedHostIds: ["host-1"],
    order: 3,
  });
  assert.equal("id" in noteDraft, false);
  assert.equal("createdAt" in noteDraft, false);
  assert.equal("updatedAt" in noteDraft, false);

  const snippetDraft = savedSnippetToDraft({
    id: "script-1",
    label: "Inspect",
    command: "nct.terminal.write('whoami')",
    kind: "script",
    language: "javascript",
    trigger: "manual",
    targets: ["host-1"],
  });
  assert.deepEqual(snippetDraft, {
    label: "Inspect",
    command: "nct.terminal.write('whoami')",
    kind: "script",
    language: "javascript",
    trigger: "manual",
    targets: ["host-1"],
  });
  assert.equal("id" in snippetDraft, false);

  assert.deepEqual(createEmptyVaultNoteDraft(4), { title: "", content: "", order: 4 });
  assert.deepEqual(createEmptySavedSnippetDraft(5), {
    label: "",
    command: "",
    kind: "script",
    language: "javascript",
    trigger: "manual",
    order: 5,
  });
});

test("search covers bodies, catalog metadata, and linked host display fields", () => {
  const hosts = [{
    id: "host-prod",
    label: "Production API",
    hostname: "api.internal",
    username: "deploy",
    group: "Production/Linux",
  }];
  const note = {
    id: "note-1",
    title: "Release checklist",
    content: "Check the canary before rollout",
    group: "Operations",
    tags: ["deploy"],
    linkedHostIds: ["host-prod"],
    createdAt: 10,
    updatedAt: 20,
  };
  assert.equal(matchesVaultNoteSearch(note, "canary", hosts), true);
  assert.equal(matchesVaultNoteSearch(note, "api.internal", hosts), true);
  assert.equal(matchesVaultNoteSearch(note, "missing-value", hosts), false);

  const snippet = {
    id: "script-1",
    label: "Inspect service",
    command: "systemctl status app",
    kind: "script" as const,
    language: "python" as const,
    description: "Read-only production check",
    tags: ["diagnostics"],
    package: "ops/linux",
    targets: ["host-prod"],
    targetGroups: ["Staging/Linux"],
    trigger: "onOutput" as const,
    triggerPattern: "FAILED",
  };
  for (const query of ["systemctl", "diagnostics", "ops/linux", "staging", "FAILED", "Production API"]) {
    assert.equal(matchesSavedSnippetSearch(snippet, query, hosts), true);
  }
  assert.equal(matchesSavedSnippetSearch(snippet, "unrelated", hosts), false);
});

test("sorting and list normalization retain legacy scope distinctions", () => {
  assert.deepEqual(splitListInput(" linux, ops\nlinux ,, deploy "), ["linux", "ops", "deploy"]);
  assert.equal(splitListInput(" , \n "), undefined);
  assert.equal(nextCatalogOrder([{ order: 9 }, {}, { order: 2 }]), 10);

  const notes = sortVaultNotes([
    { id: "b", title: "B", content: "", createdAt: 1, updatedAt: 2, order: 4 },
    { id: "a", title: "A", content: "", createdAt: 1, updatedAt: 9, order: 1 },
  ]);
  assert.deepEqual(notes.map((note) => note.id), ["a", "b"]);

  const snippets = sortSavedSnippets([
    { id: "b", label: "B", command: "", targetGroups: [], order: 4 },
    { id: "a", label: "A", command: "", order: 1 },
  ]);
  assert.deepEqual(snippets.map((snippet) => snippet.id), ["a", "b"]);
  assert.deepEqual(savedSnippetToDraft(snippets[1]).targetGroups, []);
  assert.equal(savedSnippetToDraft(snippets[0]).targetGroups, undefined);
});

test("fixed error messages do not echo backend content", () => {
  const stale = classifyNotesSnippetsError(
    new Error("NOTES_SNIPPETS_INVENTORY_CHANGED: raw-attacker-marker"),
    "备注",
    createTranslator("zh-CN"),
  );
  assert.equal(stale.refreshCatalog, true);
  assert.equal(stale.message.includes("raw-attacker-marker"), false);

  const fallback = classifyNotesSnippetsError(
    new Error("secret script body raw-attacker-marker"),
    "脚本",
    createTranslator("zh-CN"),
  );
  assert.equal(fallback.refreshCatalog, false);
  assert.equal(fallback.message.includes("raw-attacker-marker"), false);
});

test("Notes and Scripts presentation catalogs are complete in Chinese and English", () => {
  const zh = createTranslator("zh-CN");
  const en = createTranslator("en-US");

  assert.equal(zh("notes.title"), "备注");
  assert.equal(en("notes.title"), "Notes");
  assert.equal(zh("scripts.searchAria"), "搜索脚本");
  assert.equal(en("scripts.searchAria"), "Search scripts");
  assert.equal(zh("notesScripts.hosts.selected", { count: 3 }), "已选择 3 台");
  assert.equal(en("notesScripts.hosts.selected", { count: 3 }), "3 selected");
  assert.equal(
    en("notesScripts.error.catalogChanged", { entity: en("notes.entity") }),
    "The note catalog changed in another window and was reloaded.",
  );
});

test("browser Notes and Scripts previews keep native mutations disabled with a localized notice", async () => {
  const [notes, scripts] = await Promise.all([
    readFile(notesWorkspaceUrl, "utf8"),
    readFile(scriptsWorkspaceUrl, "utf8"),
  ]);
  const zh = createTranslator("zh-CN");
  const en = createTranslator("en-US");

  assert.match(notes, /const nativeUnavailableMessage = nativeRuntimeAvailable/);
  assert.match(scripts, /const nativeUnavailableMessage = nativeRuntimeAvailable/);
  for (const source of [notes, scripts]) {
    assert.match(source, /t\("notesScripts\.desktopOnly"\)/);
    assert.match(source, /disabled=\{!catalog \|\| disabled \|\| !nativeRuntimeAvailable \|\| mutationPending\}/);
    assert.match(source, /className="notes-scripts-native-notice" role="status"/);
    assert.match(source, /if \(!nativeRuntimeAvailable\) \{[\s\S]*?setError\(nativeUnavailableMessage/);
  }
  assert.match(zh("notesScripts.desktopOnly"), /Goral/);
  assert.match(en("notesScripts.desktopOnly"), /Goral/);
});

test("standalone workspaces expose list, search, empty, editor, delete, body, and host selection surfaces", async () => {
  const [notes, scripts, shared, styles] = await Promise.all([
    readFile(notesWorkspaceUrl, "utf8"),
    readFile(scriptsWorkspaceUrl, "utf8"),
    readFile(sharedWorkspaceUrl, "utf8"),
    readFile(stylesUrl, "utf8"),
  ]);

  assert.doesNotMatch(notes, /import "\.\/notesScripts\.css"/);
  assert.doesNotMatch(scripts, /import "\.\/notesScripts\.css"/);
  assert.match(notes, /listVaultNotes/);
  assert.match(notes, /createVaultNote/);
  assert.match(notes, /updateVaultNote/);
  assert.match(notes, /deleteVaultNote/);
  assert.match(notes, /locale\?: Locale/);
  assert.match(notes, /const \{ t \} = useI18n\(locale\)/);
  assert.match(notes, /aria-label=\{t\("notes\.searchAria"\)\}/);
  assert.match(notes, /t\("notes\.emptyListTitle"\)/);
  assert.match(notes, /t\("notes\.bodyLabel"\)/);
  assert.match(notes, /<HostChecklist/);
  assert.match(notes, /locale=\{locale\}/);
  assert.match(notes, /linkedHostIds/);
  assert.match(notes, /refreshKey\?: string \| number/);
  assert.match(notes, /observedRefreshKey/);
  assert.equal((notes.match(/expectedInventoryRevision: snapshot\.expectedInventoryRevision/g) ?? []).length, 2);
  assert.match(notes, /expectedInventoryRevision: prompt\.expectedInventoryRevision/);
  assert.doesNotMatch(notes, /expectedInventoryRevision: catalogSnapshot\.inventoryRevision/);

  assert.match(scripts, /listSavedSnippets/);
  assert.match(scripts, /createSavedSnippet/);
  assert.match(scripts, /updateSavedSnippet/);
  assert.match(scripts, /deleteSavedSnippet/);
  assert.match(scripts, /locale\?: Locale/);
  assert.match(scripts, /const \{ t \} = useI18n\(locale\)/);
  assert.match(scripts, /aria-label=\{t\("scripts\.searchAria"\)\}/);
  assert.match(scripts, /t\("scripts\.emptyListTitle"\)/);
  assert.match(scripts, /t\("scripts\.bodyLabel"\)/);
  assert.match(scripts, /<HostChecklist/);
  assert.match(scripts, /locale=\{locale\}/);
  assert.match(scripts, /targetsAllHosts/);
  assert.match(scripts, /targetGroupsExplicit/);
  assert.match(scripts, /refreshKey\?: string \| number/);
  assert.match(scripts, /observedRefreshKey/);
  assert.equal((scripts.match(/expectedInventoryRevision: snapshot\.expectedInventoryRevision/g) ?? []).length, 2);
  assert.match(scripts, /expectedInventoryRevision: prompt\.expectedInventoryRevision/);
  assert.doesNotMatch(scripts, /expectedInventoryRevision: catalogSnapshot\.inventoryRevision/);

  assert.match(shared, /locale\?: Locale/);
  assert.match(shared, /useI18n\(locale\)/);
  assert.match(shared, /aria-label=\{t\("notesScripts\.hosts\.selectionAria"\)\}/);
  assert.match(shared, /t\("notesScripts\.hosts\.applyAll"\)/);
  assert.match(shared, /new Intl\.DateTimeFormat\(locale/);
  assert.doesNotMatch(scripts, /<option value="onConnect">/);
  assert.doesNotMatch(scripts, /<option value="onOutput">/);
  assert.doesNotMatch(scripts, /<b>Trigger<\/b>/);
  assert.match(styles, /\.notes-scripts-workspace\s*\{/);
  // The workspace must draw from the app palette, not a private one. It
  // previously hardcoded a beige/teal scheme with no dark variant, so it
  // rendered light-theme colours inside a dark application.
  assert.ok(styles.includes("--ns-canvas: var(--ld-bg)"));
  assert.ok(styles.includes("--ns-ink: var(--ld-text)"));
  assert.match(styles, /\.notes-scripts-layout\s*\{[\s\S]*?grid-template-columns/);
  assert.match(styles, /\.notes-scripts-empty-state\s*\{/);
  assert.match(styles, /\.notes-scripts-code-block\s*\{/);
});

test("TerminalWorkspace enables and mounts the two catalog workspaces without disturbing adjacent modules", async () => {
  const [workspace, main, styles] = await Promise.all([
    readFile(terminalWorkspaceUrl, "utf8"),
    readFile(mainUrl, "utf8"),
    readFile(stylesUrl, "utf8"),
  ]);

  assert.match(workspace, /import \{ NotesWorkspace \} from "\.\/NotesWorkspace"/);
  assert.match(workspace, /import \{ ScriptsWorkspace \} from "\.\/ScriptsWorkspace"/);
  assert.match(workspace, /type SidebarView =[^;]+\| "scripts"[^;]+\| "notes"[^;]+\| "known"[^;]+\| "logs";/s);
  assert.match(workspace, /useState<SidebarView>\("saved"\)/);
  assert.match(workspace, /className=\{sidebarView === "scripts" \? "active" : ""\}/);
  assert.match(workspace, /onClick=\{\(\) => showVaultView\("scripts"\)\}/);
  assert.match(workspace, /className=\{sidebarView === "notes" \? "active" : ""\}/);
  assert.match(workspace, /onClick=\{\(\) => showVaultView\("notes"\)\}/);
  assert.doesNotMatch(workspace, /title="(?:Scripts|Notes) 正在迁移"/);
  assert.match(workspace, /sidebarView === "scripts" && \([\s\S]*?<ScriptsWorkspace[\s\S]*?hosts=\{savedHosts\}/);
  assert.match(workspace, /sidebarView === "notes" && \([\s\S]*?<NotesWorkspace[\s\S]*?hosts=\{savedHosts\}/);
  assert.match(workspace, /<ScriptsWorkspace[\s\S]*?locale=\{rendererLocale\}/);
  assert.match(workspace, /<NotesWorkspace[\s\S]*?locale=\{rendererLocale\}/);
  assert.match(workspace, /sidebarView !== "scripts" && sidebarView !== "notes"/);

  // Existing management surfaces remain independently mounted.
  assert.match(workspace, /<PortForwardingCatalog/);
  assert.match(workspace, /<GroupConfigCatalog/);

  assert.match(main, /import "\.\/styles\.css";\s*import "\.\/notesScripts\.css";/);
  assert.match(styles, /\.surface-vault \.connection-panel > \.notes-scripts-view\s*\{[\s\S]*?grid-row:\s*1 \/ -1/);
});
