import { TERMINAL_SEND_TEXT_MAX_BYTES } from "./terminalSessionBridge.ts";

export const MAX_AI_COMMAND_PROPOSALS = 8;
// Approved commands are sent with one trailing carriage return. Reserve that
// byte so every accepted proposal still fits the terminal bridge boundary.
export const MAX_AI_COMMAND_BYTES = TERMINAL_SEND_TEXT_MAX_BYTES - 1;

export const AI_COMMAND_LANGUAGES = Object.freeze([
  "bash",
  "sh",
  "zsh",
  "fish",
  "powershell",
  "pwsh",
  "cmd",
  "bat",
  "shell",
  "console",
] as const);

export type AiCommandLanguage = (typeof AI_COMMAND_LANGUAGES)[number];

export type AiCommandProposal = Readonly<{
  id: string;
  language: AiCommandLanguage;
  command: string;
}>;

/**
 * Immutable command-and-route snapshot created by the user's Run/Review
 * action. Merely staging an approval cannot execute anything; the caller's
 * configured permission policy decides whether confirmation is immediate or
 * requires a second explicit action.
 */
export type AiCommandApproval<TScope extends object> = Readonly<{
  proposal: AiCommandProposal;
  scope: Readonly<TScope>;
}>;

type OpenFence = Readonly<{
  marker: "`" | "~";
  markerLength: number;
  language: AiCommandLanguage | null;
  lines: string[];
}>;

const utf8 = new TextEncoder();
const languageSet: ReadonlySet<string> = new Set(AI_COMMAND_LANGUAGES);
const claimedApprovals = new WeakSet<object>();
const unsafeCommandControl = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]|\p{Cf}/u;

function commandLanguage(value: string): AiCommandLanguage | null {
  const normalized = value.trim().toLowerCase();
  return languageSet.has(normalized) ? normalized as AiCommandLanguage : null;
}

function openingFence(line: string): OpenFence | null {
  const match = line.match(/^( {0,3})(`{3,}|~{3,})([^`]*)$/u);
  if (!match) return null;
  const markerRun = match[2] ?? "";
  const info = (match[3] ?? "").trim();
  return {
    marker: markerRun[0] as "`" | "~",
    markerLength: markerRun.length,
    language: commandLanguage(info),
    lines: [],
  };
}

function closesFence(line: string, fence: OpenFence): boolean {
  const match = line.match(/^( {0,3})(`{3,}|~{3,})\s*$/u);
  if (!match) return false;
  const markerRun = match[2] ?? "";
  return markerRun[0] === fence.marker && markerRun.length >= fence.markerLength;
}

function proposalFingerprint(language: AiCommandLanguage, command: string): string {
  // FNV-1a produces a deterministic renderer identifier without retaining the
  // command itself in DOM attributes or introducing random/time-based IDs.
  let hash = 0x811c9dc5;
  for (const byte of utf8.encode(`${language}\0${command}`)) {
    hash ^= byte;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

/**
 * Extract explicitly shell-labelled Markdown fences from an AI response.
 *
 * Unknown and unlabelled fences are consumed as ordinary Markdown rather than
 * guessed to be commands. Commands containing invisible terminal/Unicode
 * formatting controls, no non-whitespace content, or more than the bounded
 * UTF-8 limit are rejected whole and are never truncated. Tab and line-feed
 * remain allowed so reviewed multi-line shell commands keep their semantics.
 * This module only describes proposals; it has no session or execution access.
 */
export function extractAiCommandProposals(
  assistantContent: string,
): readonly AiCommandProposal[] {
  const lines = assistantContent.replace(/\r\n?/gu, "\n").split("\n");
  const proposals: AiCommandProposal[] = [];
  const fingerprintOccurrences = new Map<string, number>();
  let fence: OpenFence | null = null;

  for (const line of lines) {
    if (fence === null) {
      fence = openingFence(line);
      continue;
    }

    if (!closesFence(line, fence)) {
      fence.lines.push(line);
      continue;
    }

    if (fence.language !== null) {
      const command = fence.lines.join("\n");
      if (
        command.trim().length > 0
        && !unsafeCommandControl.test(command)
        && utf8.encode(command).byteLength <= MAX_AI_COMMAND_BYTES
      ) {
        const fingerprint = proposalFingerprint(fence.language, command);
        const occurrence = (fingerprintOccurrences.get(fingerprint) ?? 0) + 1;
        fingerprintOccurrences.set(fingerprint, occurrence);
        proposals.push(Object.freeze({
          id: `ai-command-${fingerprint}-${occurrence}`,
          language: fence.language,
          command,
        }));
        if (proposals.length >= MAX_AI_COMMAND_PROPOSALS) break;
      }
    }
    fence = null;
  }

  return Object.freeze(proposals);
}

/** Capture the exact renderer route and runtime generation for later review. */
export function stageAiCommandApproval<TScope extends object>(
  proposal: AiCommandProposal,
  scope: TScope,
): AiCommandApproval<TScope> {
  return Object.freeze({
    proposal,
    scope: Object.freeze({ ...scope }),
  });
}

/**
 * Execute one explicitly confirmed approval at most once. A failed send releases
 * the claim so the still-visible confirmation dialog may be retried afterwards.
 */
export async function confirmAiCommandApproval<TScope extends object>(
  approval: AiCommandApproval<TScope>,
  send: (scope: Readonly<TScope>, command: string) => Promise<void>,
): Promise<boolean> {
  if (claimedApprovals.has(approval)) return false;
  claimedApprovals.add(approval);
  try {
    await send(approval.scope, approval.proposal.command);
    return true;
  } catch (reason) {
    claimedApprovals.delete(approval);
    throw reason;
  }
}
