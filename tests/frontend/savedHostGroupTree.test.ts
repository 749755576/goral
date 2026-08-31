import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const componentUrl = new URL("../../src/SavedHostGroupTree.tsx", import.meta.url);
const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);
const backendUrl = new URL("../../src/backend.ts", import.meta.url);

test("SavedHostGroupTree projects groups while preserving caller-owned host actions", async () => {
  const source = await readFile(componentUrl, "utf8");
  assert.match(source, /buildGroupTree\(\{ explicitGroups, groupConfigs, hosts \}\)/);
  assert.match(source, /aria-expanded=\{expanded\}/);
  assert.match(source, /togglePath\(node\.path\)/);
  assert.match(source, /node\.hosts\.map\(\(host\) => renderHost\(host\)\)/);
  assert.match(source, /tree\.ungroupedHosts\.map\(\(host\) => renderHost\(host\)\)/);
  assert.match(source, /ungroupedLabel \?\? t\("savedHost\.group\.ungrouped"\)/);
});

test("TerminalWorkspace projects native explicit groups and saved order into the reusable tree", async () => {
  const source = await readFile(workspaceUrl, "utf8");
  assert.match(source, /import \{ SavedHostGroupTree \} from "\.\/SavedHostGroupTree";/);
  assert.match(source, /<SavedHostGroupTree[\s\S]*?hosts=\{filteredSavedHosts\}/);
  assert.match(source, /explicitGroups=\{savedHostGroups\}/);
  assert.match(source, /groupConfigs=\{groupTreeOrderConfigs\}/);
  assert.match(source, /groupConfigCatalog\?\.customGroups \?\? \[\]/);
  assert.match(source, /groupConfigCatalog\?\.groups\.map\(\(group\) => group\.path\)/);
  assert.match(source, /renderHost=\{\(host\) => \(/);

  const treeStart = source.indexOf("<SavedHostGroupTree");
  const treeEndMarker = "\n              />";
  const treeProjection = source.slice(
    treeStart,
    source.indexOf(treeEndMarker, treeStart) + treeEndMarker.length,
  );
  for (const action of [
    "beginSavedHostConnection(host)",
    "openEditSavedHost(host)",
    "removeSavedHost(host)",
  ]) {
    assert.match(treeProjection, new RegExp(action.replace(/[()]/g, "\\$&")));
  }
});

test("SavedHost group remains an optional renderer field until the Rust API lands", async () => {
  const source = await readFile(backendUrl, "utf8");
  const savedHost = source.slice(
    source.indexOf("export type SavedHost ="),
    source.indexOf("export type SavedHostProxy ="),
  );
  assert.match(savedHost, /group\?: string;/);
});
