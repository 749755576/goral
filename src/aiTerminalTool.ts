import { takeUtf8Suffix } from "./terminalSessionBridge.ts";
import type { AiTerminalScope } from "./aiWorkspace.tsx";

export const AI_TERMINAL_TOOL_CAPTURE_TIMEOUT_MS = 5_000;
export const AI_TERMINAL_TOOL_OUTPUT_MAX_BYTES = 32 * 1024;

const DEFAULT_POLL_MS = 125;
const DEFAULT_SETTLE_MS = 375;

export type AiTerminalToolCapture = Readonly<{
  output: string;
  timedOut: boolean;
}>;

type CaptureOptions = Readonly<{
  timeoutMs?: number;
  pollMs?: number;
  settleMs?: number;
  now?: () => number;
  wait?: (milliseconds: number, signal: AbortSignal) => Promise<void>;
}>;

const abortError = (): DOMException => new DOMException("AI terminal tool aborted", "AbortError");

const waitFor = (milliseconds: number, signal: AbortSignal): Promise<void> => new Promise((resolve, reject) => {
  if (signal.aborted) {
    reject(abortError());
    return;
  }
  const timeout = window.setTimeout(() => {
    signal.removeEventListener("abort", abort);
    resolve();
  }, milliseconds);
  const abort = () => {
    window.clearTimeout(timeout);
    reject(abortError());
  };
  signal.addEventListener("abort", abort, { once: true });
});

const outputDelta = (before: string, after: string): string => {
  if (!before) return after;
  if (after.startsWith(before)) return after.slice(before.length).replace(/^\r?\n/u, "");
  // Terminal context is a rolling tail. If its old prefix was evicted, return
  // the current bounded tail rather than guessing an unsafe string splice.
  return after === before ? "" : after;
};

/**
 * Send once through the renderer's exact generation-bound controller, then
 * capture a bounded, settling tail for the model. The timeout bounds capture,
 * not the remote shell process: once bytes are accepted by a terminal they
 * cannot be recalled by canceling the AI turn. This interactive-tail adapter
 * has no process-scoped stdout/stderr or exit status, so concurrent terminal
 * output can be included; callers must treat it as bounded observational data.
 */
export async function executeAndCaptureAiTerminalTool(
  scope: AiTerminalScope,
  command: string,
  send: (scope: AiTerminalScope, command: string) => Promise<void>,
  readRecentOutput: ((scope: AiTerminalScope) => string | Promise<string | undefined> | undefined) | undefined,
  signal: AbortSignal,
  options: CaptureOptions = {},
): Promise<AiTerminalToolCapture> {
  if (signal.aborted) throw abortError();
  const timeoutMs = Math.max(1, Math.min(options.timeoutMs ?? AI_TERMINAL_TOOL_CAPTURE_TIMEOUT_MS, AI_TERMINAL_TOOL_CAPTURE_TIMEOUT_MS));
  const pollMs = Math.max(1, options.pollMs ?? DEFAULT_POLL_MS);
  const settleMs = Math.max(pollMs, options.settleMs ?? DEFAULT_SETTLE_MS);
  const now = options.now ?? Date.now;
  const wait = options.wait ?? waitFor;
  const before = readRecentOutput ? await readRecentOutput(scope) ?? "" : "";
  if (signal.aborted) throw abortError();
  await send(scope, command);
  if (signal.aborted) throw abortError();
  if (!readRecentOutput) return { output: "", timedOut: false };

  const deadline = now() + timeoutMs;
  let latest = "";
  let lastChangedAt = now();
  while (now() < deadline) {
    await wait(Math.min(pollMs, Math.max(1, deadline - now())), signal);
    const after = await readRecentOutput(scope) ?? "";
    if (signal.aborted) throw abortError();
    const next = outputDelta(before, after);
    if (next !== latest) {
      latest = next;
      lastChangedAt = now();
    } else if (latest && now() - lastChangedAt >= settleMs) {
      return {
        output: takeUtf8Suffix(latest, AI_TERMINAL_TOOL_OUTPUT_MAX_BYTES),
        timedOut: false,
      };
    }
  }
  return {
    output: takeUtf8Suffix(latest, AI_TERMINAL_TOOL_OUTPUT_MAX_BYTES),
    timedOut: true,
  };
}
