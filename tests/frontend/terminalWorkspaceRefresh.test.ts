import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);

// Keep source-structure checks stable when Git checks out TSX with CRLF.
const readSource = (url: URL): Promise<string> => readFile(url, "utf8")
  .then((source) => source.replace(/\r\n/g, "\n"));

const functionBlock = (
  source: string,
  startMarker: string,
  endMarker: string,
): string => {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.ok(start >= 0, `missing ${startMarker}`);
  assert.ok(end > start, `missing boundary ${endMarker}`);
  return source.slice(start, end);
};

test("initial catalog hydration does not fan out refreshes to the Hosts surface", async () => {
  const workspace = await readSource(workspaceUrl);
  const callbacks = [
    ["const observeManagedInventoryRevision", "const refreshManagedSshKeys"],
    ["const handlePasswordIdentityCatalogChange", "const handleProxyProfileCatalogChange"],
    ["const handleProxyProfileCatalogChange", "const handleGroupConfigCatalogChange"],
    ["const handleGroupConfigCatalogChange", "useEffect(() => {\n    void refreshSavedHosts();"],
  ] as const;

  for (const [start, end] of callbacks) {
    const block = functionBlock(workspace, start, end);
    assert.match(
      block,
      /if \(\s*previous\.seen\s*&&/,
      `${start} must treat its first snapshot as hydration`,
    );
  }
});

test("opening Connection Logs does not refresh unrelated Vault catalogs", async () => {
  const workspace = await readSource(workspaceUrl);
  const logsPanel = functionBlock(
    workspace,
    '{sidebarView === "logs" && (',
    "<GroupConfigCatalog",
  );

  assert.match(logsPanel, /<ConnectionLogsWorkspace/);
  assert.doesNotMatch(logsPanel, /onCatalogChange=/);
  assert.doesNotMatch(logsPanel, /refreshCatalogsAfterKnownHostsMutation/);
});

test("real host-key mutations still refresh Known Hosts and dependent catalogs", async () => {
  const workspace = await readSource(workspaceUrl);
  const refresh = functionBlock(
    workspace,
    "const refreshCatalogsAfterKnownHostsMutation",
    "const persistHostKey",
  );
  const persist = functionBlock(workspace, "const persistHostKey", "const answerHostKey");

  assert.match(refresh, /setKnownHostsRefreshKey/);
  assert.match(refresh, /refreshDependentCatalogsAfterKnownHostsMutation\(\)/);
  assert.match(persist, /await replaceKnownHosts/);
  assert.match(persist, /refreshCatalogsAfterKnownHostsMutation\(\)/);
});
