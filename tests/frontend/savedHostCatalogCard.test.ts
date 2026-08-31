import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const componentUrl = new URL("../../src/SavedHostCatalogCard.tsx", import.meta.url);
const workspaceUrl = new URL("../../src/TerminalWorkspace.tsx", import.meta.url);

test("SavedHostCatalogCard is a presentation boundary with caller-owned actions", async () => {
  const [component, workspace] = await Promise.all([
    readFile(componentUrl, "utf8"),
    readFile(workspaceUrl, "utf8"),
  ]);

  assert.match(workspace, /import \{ SavedHostCatalogCard \} from "\.\/SavedHostCatalogCard";/);
  assert.match(workspace, /<SavedHostCatalogCard[\s\S]*?host=\{host\}/);
  assert.match(workspace, /onConnect=\{\(host\) => void beginSavedHostConnection\(host\)\}/);
  assert.match(workspace, /onEdit=\{\(host\) => openEditSavedHost\(host\)\}/);
  assert.match(workspace, /onRemove=\{\(host\) => void removeSavedHost\(host\)\}/);

  assert.match(component, /onConnect: \(host: SavedHost\) => void;/);
  assert.match(component, /onEdit: \(host: SavedHost\) => void;/);
  assert.match(component, /onRemove: \(host: SavedHost\) => void;/);
  assert.match(component, /event\.stopPropagation\(\);[\s\S]*?onEdit\(host\)/);
  assert.match(component, /event\.stopPropagation\(\);[\s\S]*?onRemove\(host\)/);
  assert.doesNotMatch(component, /useState|useEffect|useRef|startSavedHostSession|deleteSavedHost|updateSavedHost/);
});
