import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("TerminalWorkspace mounts and synchronizes the proxy profile catalog", async () => {
  const source = await readFile(
    new URL("../../src/TerminalWorkspace.tsx", import.meta.url),
    "utf8",
  );

  assert.match(source, /import \{ ProxyProfileCatalog \} from "\.\/ProxyProfileCatalog";/);
  assert.match(source, /type SidebarView =[\s\S]*?\| "identities"[\s\S]*?\| "proxies"/);
  assert.match(
    source,
    /t\("workspace\.proxyCount", \{ count: proxyProfileCatalog\?\.profiles\.length \?\? 0 \}\)/,
  );
  assert.match(source, /hidden=\{sidebarView !== "proxies"\}/);
  assert.match(source, /identities=\{passwordIdentityCatalog\?\.identities \?\? \[\]\}/);
  assert.match(source, /<ProxyProfileCatalog[\s\S]*?locale=\{rendererLocale\}/);
  assert.match(source, /refreshKey=\{proxyProfileRefreshKey\}/);
  assert.match(source, /onCatalogChange=\{handleProxyProfileCatalogChange\}/);
  assert.match(source, /setProxyProfileRefreshKey\(\(current\) => current \+ 1\)/);
  assert.match(source, /setPasswordIdentityRefreshKey\(\(current\) => current \+ 1\)/);
  assert.match(source, /proxyProfileInventoryRevision\.current/);
});
