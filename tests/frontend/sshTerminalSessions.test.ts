import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const adapterUrl = new URL("../../src/SshTerminalSessions.tsx", import.meta.url);
const controllerUrl = new URL(
  "../../src/sshTerminalSessionController.ts",
  import.meta.url,
);

test("SSH adapter injects and observes the one shared terminal catalog", async () => {
  const source = await readFile(adapterUrl, "utf8");

  assert.match(
    source,
    /export function useSshTerminalSessions\(\s*catalog: TerminalSessionCatalog,/,
  );
  assert.match(
    source,
    /new SshTerminalSessionController<Terminal>\(\{\s*catalog,/,
  );
  assert.match(source, /catalog\.subscribe\(\(snapshot\) => \{/);
  assert.match(source, /throw new Error\("TERMINAL_SESSION_CATALOG_CHANGED"\)/);
  assert.doesNotMatch(source, /createTerminalSessionCatalog/);
});

test("every open and retry gets an exact renderer-generated SSH attempt route", async () => {
  const [adapter, controller] = await Promise.all([
    readFile(adapterUrl, "utf8"),
    readFile(controllerUrl, "utf8"),
  ]);

  assert.match(adapter, /const clientAttemptId = createSshClientAttemptId\(\);/);
  assert.equal(
    adapter.match(/const clientAttemptId = createSshClientAttemptId\(\);/g)?.length,
    2,
  );
  assert.match(
    adapter,
    /controller\.open\([\s\S]*?target,[\s\S]*?\{ clientAttemptId, start \},[\s\S]*?\{ onSessionCreated \},[\s\S]*?\)/,
  );
  assert.match(adapter, /onSessionCreated\?: SshTerminalSessionCreated/);
  assert.match(adapter, /controller\.retry\(id, \{ clientAttemptId, start \}\)/);
  assert.match(adapter, /workspaceSessionIdForAttempt/);
  assert.match(adapter, /isExactAttemptRoute/);

  assert.match(controller, /`attempt-\$\{randomUuid\(\)\}`/);
  assert.match(controller, /5 \* 60 \* 1_000/);
  assert.match(controller, /CLIENT_ATTEMPT_GUARD_LIMIT = 4_096/);
  assert.match(
    controller,
    /#attemptToWorkspace\.size \+ this\.#retiredAttemptIds\.size[\s\S]*?>= CLIENT_ATTEMPT_GUARD_LIMIT/,
  );
  assert.doesNotMatch(controller, /#usedAttemptIds/);
});

test("SSH open notification exposes only the renderer workspace ID and isolates observers", async () => {
  const controller = await readFile(controllerUrl, "utf8");

  assert.match(
    controller,
    /export type SshTerminalSessionCreated = \(id: WorkspaceSessionId\) => void/,
  );
  assert.match(
    controller,
    /this\.#dependencies\.catalog\.add\([\s\S]*?state: "connecting",[\s\S]*?\}\);[\s\S]*?options\.onSessionCreated\?\.\(id\);[\s\S]*?await this\.#startRuntime/,
  );
  assert.match(controller, /An observer exception[\s\S]*?must not abort, leak/);
});

test("SSH xterms stay mounted per owned tab and resolve appearance per target", async () => {
  const source = await readFile(adapterUrl, "utf8");

  assert.match(source, /resolveAppearanceRef\.current\(target\)/);
  assert.match(source, /resolveAppearanceRef\.current\(runtime\.target\)/);
  assert.match(source, /view\.appearance = nextAppearance/);
  assert.match(source, /Keep the last successfully applied/);
  assert.match(
    source,
    /registry\.sessions\[id\]\?\.protocol === "ssh" && owns\(id\)/,
  );
  assert.match(source, /hidden=\{!placement\}/);
  assert.match(
    source,
    /className="terminal-container local-terminal-viewports ssh-terminal-viewports terminal-pane-layer"/,
  );
  assert.match(source, /StrictMode remounts reuse the xterm DOM and accumulated scrollback/);
});

test("only the globally active owned SSH runtime may retain WebGL", async () => {
  const source = await readFile(adapterUrl, "utf8");

  assert.match(source, /for \(const \[candidateId, candidateView\] of viewsRef\.current\)/);
  assert.match(source, /if \(candidateId !== id\) releaseWebgl\(candidateView\)/);
  assert.match(source, /catalog\.snapshot\.activeSessionId !== id/);
  assert.match(source, /controller\.getRuntime\(id\) === runtime/g);
  assert.match(source, /viewsRef\.current\.get\(id\) === view/g);
  assert.match(source, /view\.webglGeneration === generation/g);
  assert.match(
    source,
    /configureActiveRenderer\(snapshot\.activeSessionId\)/,
  );
});

test("StrictMode cleanup is deferred and destroys only SSH-owned resources", async () => {
  const source = await readFile(adapterUrl, "utf8");

  assert.match(source, /pendingDisposalRef\.current = null/);
  assert.match(source, /queueMicrotask\(\(\) => \{/);
  assert.match(source, /if \(pendingDisposalRef\.current !== token\) return/);
  assert.match(source, /controller\.dispose\(\)/);
  assert.match(source, /sendInput: sendSshInput/);
  assert.match(source, /resize: resizeSshSession/);
  assert.match(source, /close: closeSshSession/);
  assert.match(source, /cancel: cancelSshSession/);
  assert.doesNotMatch(source, /sendLocalPtyInput|resizeLocalPtySession|closeLocalPtySession/);
});
