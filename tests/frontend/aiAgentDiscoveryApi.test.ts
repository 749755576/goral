import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  AI_AGENT_DISCOVERY_COMMAND,
  discoverAiAgents,
  type DiscoveredAiAgent,
} from "../../src/aiAgentDiscoveryApi.ts";

test("AI Agent discovery calls the one typed native command without renderer paths", async () => {
  const expected: DiscoveredAiAgent[] = [
    {
      id: "codex",
      name: "Codex CLI",
      installed: true,
      available: true,
      runtimeSupported: true,
      version: "1.2.3",
    },
  ];
  const calls: string[] = [];
  const result = await discoverAiAgents(async <T>(command: string): Promise<T> => {
    calls.push(command);
    return expected as T;
  });

  assert.deepEqual(calls, [AI_AGENT_DISCOVERY_COMMAND]);
  assert.deepEqual(result, expected);
  assert.deepEqual(Object.keys(result[0] ?? {}).sort(), [
    "available",
    "id",
    "installed",
    "name",
    "runtimeSupported",
    "version",
  ]);
});

test("native discovery is registered and its DTO excludes executable and auth data", async () => {
  const rust = await readFile(
    new URL("../../src-tauri/src/ai_agent_discovery.rs", import.meta.url),
    "utf8",
  );
  const desktop = await readFile(
    new URL("../../src-tauri/src/lib.rs", import.meta.url),
    "utf8",
  );

  assert.match(rust, /pub\(crate\) async fn discover_ai_agents\(\)/u);
  assert.match(desktop, /ai_agent_discovery::discover_ai_agents/u);
  const dto = rust.slice(
    rust.indexOf("pub(crate) struct DiscoveredAiAgent"),
    rust.indexOf("struct AgentSpec"),
  );
  assert.doesNotMatch(dto, /path|executable|environment|auth|secret|credential|key/u);
});

test("browser preview discovery stays local and returns the built-in-only fallback", async () => {
  assert.deepEqual(await discoverAiAgents(), []);
});

test("TerminalWorkspace discovers agents only for an open native AI panel", async () => {
  const workspace = await readFile(
    new URL("../../src/TerminalWorkspace.tsx", import.meta.url),
    "utf8",
  );
  assert.match(workspace, /const \[discoveredAiAgents, setDiscoveredAiAgents\] = useState/u);
  assert.match(
    workspace,
    /useEffect\(\(\) => \{\s*if \(!aiOpen \|\| !NATIVE_DESKTOP_RUNTIME_AVAILABLE\) return;[\s\S]*?discoverAiAgents\(\)[\s\S]*?setDiscoveredAiAgents/u,
  );
  assert.match(workspace, /localAgents=\{discoveredAiAgents\}/u);
  assert.match(workspace, /localAgentComplete=\{openLocalAiAgentCompletion\}/u);
});
