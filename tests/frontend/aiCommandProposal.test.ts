import assert from "node:assert/strict";
import test from "node:test";

import {
  AI_COMMAND_LANGUAGES,
  confirmAiCommandApproval,
  extractAiCommandProposals,
  MAX_AI_COMMAND_BYTES,
  MAX_AI_COMMAND_PROPOSALS,
  stageAiCommandApproval,
} from "../../src/aiCommandProposal.ts";
import { TERMINAL_SEND_TEXT_MAX_BYTES } from "../../src/terminalSessionBridge.ts";

test("AI command proposals accept every explicit supported shell language", () => {
  const markdown = AI_COMMAND_LANGUAGES.map((language, index) => [
    `\`\`\`${language}`,
    `echo ${index}`,
    "```",
  ].join("\r\n")).join("\r\n");

  const proposals = extractAiCommandProposals(markdown);
  assert.equal(proposals.length, MAX_AI_COMMAND_PROPOSALS);
  assert.deepEqual(
    proposals.map(({ language, command }) => ({ language, command })),
    AI_COMMAND_LANGUAGES.slice(0, MAX_AI_COMMAND_PROPOSALS).map((language, index) => ({
      language,
      command: `echo ${index}`,
    })),
  );
});

test("AI command proposals ignore prose, unlabelled fences, and unknown languages", () => {
  const proposals = extractAiCommandProposals([
    "Run `echo inline` if needed.",
    "```",
    "echo unlabelled",
    "```",
    "```python",
    "print('not a terminal command')",
    "```",
    "```markdown",
    "```bash",
    "echo nested-looking-text",
    "```",
    "```BASH",
    "echo accepted",
    "```",
  ].join("\n"));

  assert.deepEqual(
    proposals.map(({ language, command }) => ({ language, command })),
    [{ language: "bash", command: "echo accepted" }],
  );
});

test("AI command proposals handle CRLF, multiple blocks, and Markdown fence lengths", () => {
  const proposals = extractAiCommandProposals([
    "````powershell",
    "$items = Get-ChildItem",
    "```",
    "$items | Measure-Object",
    "````",
    "~~~cmd",
    "echo ready",
    "~~~~",
  ].join("\r\n"));

  assert.deepEqual(
    proposals.map(({ language, command }) => ({ language, command })),
    [
      {
        language: "powershell",
        command: "$items = Get-ChildItem\n```\n$items | Measure-Object",
      },
      { language: "cmd", command: "echo ready" },
    ],
  );
});

test("AI command proposals reject empty, invisible controls, and UTF-8 oversized blocks without truncation", () => {
  const exactLimit = "x".repeat(MAX_AI_COMMAND_BYTES);
  const oneByteOversized = "x".repeat(MAX_AI_COMMAND_BYTES + 1);
  const multibyteOversized = "界".repeat(Math.floor(MAX_AI_COMMAND_BYTES / 3) + 1);
  const proposals = extractAiCommandProposals([
    "```sh",
    "   ",
    "```",
    "```bash",
    "echo before\0after",
    "```",
    "```bash",
    "echo safe\u0015\u001b[A",
    "```",
    "```powershell",
    "Write-Output safe\u202Ehidden",
    "```",
    "```zsh",
    multibyteOversized,
    "```",
    "```cmd",
    oneByteOversized,
    "```",
    "```shell",
    exactLimit,
    "```",
  ].join("\n"));

  assert.equal(proposals.length, 1);
  assert.equal(proposals[0]?.command, exactLimit);
  assert.equal(new TextEncoder().encode(proposals[0]?.command).byteLength, MAX_AI_COMMAND_BYTES);
  assert.equal(
    new TextEncoder().encode(`${proposals[0]?.command}\r`).byteLength,
    TERMINAL_SEND_TEXT_MAX_BYTES,
  );
});

test("AI command proposals preserve visible multi-line commands and tabs", () => {
  const proposals = extractAiCommandProposals(
    "```sh\nprintf 'first\\n'\n\tprintf 'second\\n'\n```",
  );
  assert.equal(proposals.length, 1);
  assert.equal(proposals[0]?.command, "printf 'first\\n'\n\tprintf 'second\\n'");
});

test("AI command proposals are capped, immutable, uniquely identified, and deterministic", () => {
  const markdown = Array.from(
    { length: MAX_AI_COMMAND_PROPOSALS + 3 },
    () => "```console\necho duplicate\n```",
  ).join("\n");
  const first = extractAiCommandProposals(markdown);
  const second = extractAiCommandProposals(markdown);

  assert.equal(first.length, MAX_AI_COMMAND_PROPOSALS);
  assert.equal(new Set(first.map(({ id }) => id)).size, first.length);
  assert.deepEqual(first.map(({ id }) => id), second.map(({ id }) => id));
  assert.equal(Object.isFrozen(first), true);
  assert.equal(first.every(Object.isFrozen), true);
});

test("AI command proposals ignore an unterminated supported fence", () => {
  assert.deepEqual(
    extractAiCommandProposals("```fish\necho never-approved"),
    [],
  );
});

test("AI command approval is two-stage and remains bound to its captured terminal scope", async () => {
  const proposal = extractAiCommandProposals("```bash\nprintf ready\n```")[0];
  assert.ok(proposal);
  const mutableScope = {
    routeId: "ssh-tab-original",
    generation: 7,
    protocol: "ssh",
    label: "Production",
    connected: true,
    commandExecutionSupported: true,
  };
  const pending = stageAiCommandApproval(proposal, mutableScope);
  const sends: Array<{ routeId: string; generation: number; command: string }> = [];

  // The first action only opens review; it has no sender and cannot execute.
  assert.equal(sends.length, 0);
  mutableScope.routeId = "ssh-tab-current";
  mutableScope.generation = 8;
  assert.equal(pending.scope.routeId, "ssh-tab-original");
  assert.equal(pending.scope.generation, 7);
  assert.equal(Object.isFrozen(pending), true);
  assert.equal(Object.isFrozen(pending.scope), true);

  let finishSend: (() => void) | undefined;
  const sender = async (scope: Readonly<typeof mutableScope>, command: string) => {
    sends.push({ routeId: scope.routeId, generation: scope.generation, command });
    await new Promise<void>((resolve) => {
      finishSend = resolve;
    });
  };
  const confirmed = confirmAiCommandApproval(pending, sender);
  await Promise.resolve();
  assert.deepEqual(sends, [{
    routeId: "ssh-tab-original",
    generation: 7,
    command: "printf ready",
  }]);

  // A double-click cannot dispatch the same approval while its first send runs.
  assert.equal(await confirmAiCommandApproval(pending, sender), false);
  assert.equal(sends.length, 1);
  finishSend?.();
  assert.equal(await confirmed, true);
  assert.equal(await confirmAiCommandApproval(pending, sender), false);
  assert.equal(sends.length, 1);
});

test("a failed confirmed command can be reviewed and retried without changing its scope", async () => {
  const proposal = extractAiCommandProposals("```pwsh\nGet-Location\n```")[0];
  assert.ok(proposal);
  const pending = stageAiCommandApproval(proposal, {
    routeId: "local-tab-1",
    generation: 3,
  });
  let attempts = 0;
  const sender = async (scope: Readonly<{ routeId: string; generation: number }>, command: string) => {
    attempts += 1;
    assert.deepEqual(scope, { routeId: "local-tab-1", generation: 3 });
    assert.equal(command, "Get-Location");
    if (attempts === 1) throw new Error("TERMINAL_SEND_ROUTE_STALE");
  };

  await assert.rejects(confirmAiCommandApproval(pending, sender), /TERMINAL_SEND_ROUTE_STALE/u);
  assert.equal(await confirmAiCommandApproval(pending, sender), true);
  assert.equal(attempts, 2);
});
