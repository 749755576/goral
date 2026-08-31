import assert from "node:assert/strict";
import test from "node:test";

import {
  AI_TERMINAL_TOOL_OUTPUT_MAX_BYTES,
  executeAndCaptureAiTerminalTool,
} from "../../src/aiTerminalTool.ts";
import type { AiTerminalScope } from "../../src/aiWorkspace.tsx";

const scope: AiTerminalScope = Object.freeze({
  routeId: "terminal-1",
  generation: 7,
  protocol: "ssh",
  label: "production",
  connected: true,
  commandExecutionSupported: true,
});

test("terminal tool sends once to the frozen generation and captures a settling delta", async () => {
  let now = 0;
  let reads = 0;
  const sends: Array<{ scope: AiTerminalScope; command: string }> = [];
  const result = await executeAndCaptureAiTerminalTool(
    scope,
    "pwd",
    async (captured, command) => { sends.push({ scope: captured, command }); },
    () => {
      reads += 1;
      return reads === 1 ? "$ " : "$ \r\n/srv/project\r\n$ ";
    },
    new AbortController().signal,
    {
      timeoutMs: 1_000,
      pollMs: 100,
      settleMs: 200,
      now: () => now,
      wait: async (milliseconds) => { now += milliseconds; },
    },
  );

  assert.deepEqual(sends, [{ scope, command: "pwd" }]);
  assert.equal(result.timedOut, false);
  assert.match(result.output, /\/srv\/project/u);
});

test("terminal tool cancellation before dispatch never writes", async () => {
  const controller = new AbortController();
  controller.abort();
  let sends = 0;
  await assert.rejects(
    executeAndCaptureAiTerminalTool(
      scope,
      "pwd",
      async () => { sends += 1; },
      () => "",
      controller.signal,
    ),
    /aborted/u,
  );
  assert.equal(sends, 0);
});

test("terminal capture timeout and output size are bounded", async () => {
  let now = 0;
  const oversized = "x".repeat(AI_TERMINAL_TOOL_OUTPUT_MAX_BYTES + 2_000);
  let reads = 0;
  const result = await executeAndCaptureAiTerminalTool(
    scope,
    "long-running-command",
    async () => undefined,
    () => {
      reads += 1;
      return reads === 1 ? "" : `${oversized}${reads}`;
    },
    new AbortController().signal,
    {
      timeoutMs: 500,
      pollMs: 100,
      settleMs: 400,
      now: () => now,
      wait: async (milliseconds) => { now += milliseconds; },
    },
  );
  assert.equal(result.timedOut, true);
  assert.ok(new TextEncoder().encode(result.output).byteLength <= AI_TERMINAL_TOOL_OUTPUT_MAX_BYTES);
});
