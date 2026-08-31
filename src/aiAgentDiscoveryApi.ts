import { invoke, isTauri } from "@tauri-apps/api/core";

export type AiAgentId = "codex" | "claude" | "opencode";

export type DiscoveredAiAgent = Readonly<{
  id: AiAgentId;
  name: string;
  installed: boolean;
  available: boolean;
  runtimeSupported: boolean;
  version: string | null;
}>;

export const AI_AGENT_DISCOVERY_COMMAND = "discover_ai_agents";

export type AiAgentDiscoveryInvoker = <T>(command: string) => Promise<T>;

export function discoverAiAgents(
  commandInvoker?: AiAgentDiscoveryInvoker,
): Promise<DiscoveredAiAgent[]> {
  if (!commandInvoker && !isTauri()) return Promise.resolve([]);
  return (commandInvoker ?? invoke)<DiscoveredAiAgent[]>(AI_AGENT_DISCOVERY_COMMAND);
}
