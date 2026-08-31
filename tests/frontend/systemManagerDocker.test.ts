import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const panelUrl = new URL("../../src/DockerPanel.tsx", import.meta.url);
const backendUrl = new URL("../../src/backend.ts", import.meta.url);
const commandsUrl = new URL("../../src-tauri/src/system_manager_commands.rs", import.meta.url);
const dockerCrateUrl = new URL("../../crates/netcatty-sysmanager/src/docker.rs", import.meta.url);

/**
 * Strips comments so prose describing a command cannot be mistaken for code
 * that builds one.
 */
const code = (source: string): string =>
  source.replace(new RegExp("\\/\\*[\\s\\S]*?\\*\\/", "g"), "").replace(new RegExp("^\\s*\\/\\/.*$", "gm"), "");

test("Docker commands are built and escalated natively, never in the renderer", async () => {
  const [panel, backend] = await Promise.all([
    readFile(panelUrl, "utf8"),
    readFile(backendUrl, "utf8"),
  ]);

  // The renderer names an operation and a target. If it ever assembles a
  // command string, a renderer compromise becomes remote code execution.
  assert.doesNotMatch(code(panel), /docker\s+(ps|images|stats|inspect|rm|start|stop)/u);
  assert.doesNotMatch(code(panel), /sudo/u);
  assert.doesNotMatch(code(backend), /docker\s+(ps|images|stats|inspect)/u);
  assert.doesNotMatch(code(backend), /sudo/u);

  // It also must not invent its own IPC surface.
  for (const command of [
    "list_docker_containers",
    "list_docker_images",
    "get_docker_stats",
    "inspect_docker_container",
    "run_docker_container_action",
  ]) {
    assert.ok(backend.includes(`invoke("${command}"`), `backend must expose ${command}`);
  }
});

test("container targets are validated before they can reach a remote shell", async () => {
  const crate = await readFile(dockerCrateUrl, "utf8");

  // Refusing to build the command is stronger than quoting: there is no path
  // where a crafted id reaches a shell.
  assert.match(crate, /pub fn is_safe_container_id/u);
  assert.match(crate, /is_safe_container_id\(container_id\)\.then/u);
  assert.match(crate, /is_safe_container_id\(id\)/u);

  const commands = await readFile(commandsUrl, "utf8");
  assert.match(commands, /SYSTEM_MANAGER_INVALID_TARGET/u);
  // Every command that takes a caller-named target must refuse an unusable
  // one rather than pass it through. Counting occurrences would only break
  // when a new manager is added, which is exactly when it should not.
  const bodies = commands.split("pub(super) async fn ").slice(1);
  const withNamedTarget = bodies.filter(
    (body) => body.includes("container_id: String") || body.includes("unit: String"),
  );
  assert.ok(withNamedTarget.length >= 3, "expected the target-taking commands to be found");
  for (const body of withNamedTarget) {
    assert.ok(
      body.includes("SYSTEM_MANAGER_INVALID_TARGET"),
      `a command taking a caller-named target must refuse an unusable one: ${body.slice(0, 40)}`,
    );
  }
});

test("privilege route is selected by a read-only probe before one Docker operation", async () => {
  const [crate, commands] = await Promise.all([
    readFile(dockerCrateUrl, "utf8"),
    readFile(commandsUrl, "utf8"),
  ]);

  // Two rungs only, and the ladder terminates. A password rung would be a
  // credential path and is deliberately absent until it can be given proper
  // custody rather than passed through the renderer.
  assert.match(crate, /pub enum Escalation\s*\{\s*[\s\S]*?None,[\s\S]*?PasswordlessSudo,\s*\}/u);
  assert.doesNotMatch(crate, /sudo -S/u, "no password-on-stdin rung yet");
  assert.match(crate, /Self::PasswordlessSudo => None/u, "the ladder must terminate");

  // Route selection uses a fixed read-only daemon probe and never interprets
  // localized stderr from a failed mutation.
  assert.match(crate, /pub const ACCESS_PROBE_ARGS: &str = "version --format/u);
  assert.doesNotMatch(crate, /should_escalate|is_socket_permission_error/u);

  const runnerStart = commands.indexOf("async fn run_docker(");
  const runnerEnd = commands.indexOf("#[tauri::command]", runnerStart);
  const runner = commands.slice(runnerStart, runnerEnd);
  const probe = runner.indexOf(
    "run_docker_attempt(state, session_id, docker::ACCESS_PROBE_ARGS, route)",
  );
  const operation = runner.indexOf("run_docker_attempt(state, session_id, args, selected)");
  assert.ok(runnerStart >= 0 && runnerEnd > runnerStart, "native Docker runner must exist");
  assert.ok(probe >= 0 && operation > probe, "the read-only probe must select a route first");
  assert.equal(
    runner.match(/run_docker_attempt\(state, session_id, args, selected\)/gu)?.length,
    1,
    "the requested operation must have exactly one execution site",
  );
  assert.doesNotMatch(runner, /stderr|should_escalate|is_socket_permission_error/u);
});

test("the panel confirms destructive removal and isolates late replies", async () => {
  const panel = await readFile(panelUrl, "utf8");

  // Removal is not recoverable from this panel, so it asks first.
  assert.match(panel, /pendingRemoval/u);
  assert.match(panel, /systemManager\.docker\.confirmRemoveTitle/u);
  assert.match(panel, /role="alertdialog"/u);

  // Refreshes and per-target actions have independent ownership inside one
  // exact session. One row must not make another row's completion stale.
  assert.match(panel, /sessionGenerationRef/u);
  assert.match(panel, /viewSessionIdRef/u);
  assert.match(panel, /refreshGenerationRef/u);
  assert.match(panel, /pendingActionsRef/u);
  assert.doesNotMatch(panel, /actionGenerationRef/u);
  assert.match(panel, /imageGenerationRef/u);
  assert.match(panel, /inspectGenerationRef/u);
  assert.match(panel, /isCurrentRefresh/u);
  assert.match(panel, /isCurrentAction/u);

  // Switching sessions clears state rather than showing one host's containers
  // under another host's name.
  assert.match(
    panel,
    /pendingActionsRef\.current\.clear\(\);[\s\S]*?setContainers\(\[\]\);[\s\S]*?setImages\(\[\]\);[\s\S]*?setLoading\(false\);[\s\S]*?setBusyIds\(new Set\(\)\);/u,
  );
});

test("Docker images have a complete lazy tab with independent request ownership", async () => {
  const panel = await readFile(panelUrl, "utf8");

  assert.match(panel, /type DockerImage/u);
  assert.match(panel, /type SystemTab = "overview" \| "containers" \| "images" \| "tmux" \| InventoryTab/u);
  assert.match(panel, /images: "systemManager\.docker\.imagesTitle"/u);
  assert.match(panel, /await listDockerImages\(sessionId\)/u);
  assert.match(panel, /tab === "images" && connected/u);
  assert.match(panel, /systemManager\.docker\.imagesEmptyTitle/u);
  assert.match(panel, /systemManager\.docker\.imagesEmptyBody/u);
  assert.match(panel, /systemManager\.docker\.imagesListFailed/u);
  for (const field of ["id", "repository", "tag", "createdSince", "size"]) {
    assert.ok(panel.includes(`dockerImage.${field}`), `image list must render ${field}`);
  }

  const imageRequest = panel.indexOf("const refreshImages = useCallback(");
  const sessionCapture = panel.indexOf(
    "const sessionGeneration = sessionGenerationRef.current;",
    imageRequest,
  );
  const requestGeneration = panel.indexOf(
    "const imageGeneration = ++imageGenerationRef.current;",
    sessionCapture,
  );
  const nativeRequest = panel.indexOf("await listDockerImages(sessionId);", requestGeneration);
  const staleGuard = panel.indexOf("if (!isCurrentImageRequest()) return;", nativeRequest);
  assert.ok(imageRequest >= 0 && sessionCapture > imageRequest, "image requests bind the current session");
  assert.ok(
    requestGeneration > sessionCapture && nativeRequest > requestGeneration && staleGuard > nativeRequest,
    "only the newest image request may publish rows",
  );

  // The images tab is not an inventory fallback. This protects the typed
  // SystemInventory boundary as more tabs are added.
  assert.doesNotMatch(panel, /tab !== "containers"[\s\S]*?<SystemInventory/u);
  assert.match(panel, /tab === "processes" \|\| tab === "ports" \|\| tab === "services" \|\| tab === "gpu"/u);
});

test("container inspect is read-only, formatted, closeable and stale-safe", async () => {
  const [panel, backend, commands, crate] = await Promise.all([
    readFile(panelUrl, "utf8"),
    readFile(backendUrl, "utf8"),
    readFile(commandsUrl, "utf8"),
    readFile(dockerCrateUrl, "utf8"),
  ]);

  assert.match(panel, /await inspectDockerContainer\(sessionId, container\.id\)/u);
  assert.match(panel, /type DockerContainerInspect/u);
  assert.match(panel, /useState<DockerContainerInspect \| null>\(null\)/u);
  assert.match(panel, /JSON\.stringify\(details, null, 2\)/u);
  assert.doesNotMatch(panel, /JSON\.parse/u, "the renderer must never parse raw inspect output");
  assert.match(backend, /Promise<DockerContainerInspect>/u);
  assert.doesNotMatch(
    backend,
    /inspectDockerContainer[\s\S]{0,160}Promise<string>/u,
    "inspect must not expose raw stdout as a string",
  );
  assert.match(commands, /Result<DockerContainerInspect, String>/u);
  assert.match(commands, /docker::parse_container_inspect\(&stdout\)/u);
  assert.match(crate, /pub struct DockerContainerInspect/u);
  assert.match(crate, /Unknown keys are ignored by construction/u);
  const dtoStart = backend.indexOf("export type DockerInspectState");
  const dtoEnd = backend.indexOf("export type DockerContainerAction", dtoStart);
  const dtoContract = code(backend.slice(dtoStart, dtoEnd));
  assert.ok(dtoStart >= 0 && dtoEnd > dtoStart, "safe inspect DTO block must exist");
  for (const forbidden of ["env", "cmd", "args", "labels", "source", "raw", "registryAuth"]) {
    assert.doesNotMatch(
      dtoContract,
      new RegExp(`\\b${forbidden}\\b`, "iu"),
      `renderer inspect DTO must not expose ${forbidden}`,
    );
  }
  assert.match(panel, /role="dialog"/u);
  assert.match(panel, /aria-modal="true"/u);
  for (const key of [
    "systemManager.docker.inspect",
    "systemManager.docker.inspectTitle",
    "systemManager.docker.inspectLoading",
    "systemManager.docker.inspectFailed",
    "systemManager.docker.inspectEmpty",
    "systemManager.docker.inspectClose",
    "systemManager.docker.inspectContentLabel",
  ]) {
    assert.ok(panel.includes(key), `inspect UI must use ${key}`);
  }

  const inspectRequest = panel.indexOf("const openInspect = useCallback(");
  const sessionCapture = panel.indexOf(
    "const sessionGeneration = sessionGenerationRef.current;",
    inspectRequest,
  );
  const requestGeneration = panel.indexOf(
    "const inspectGeneration = ++inspectGenerationRef.current;",
    sessionCapture,
  );
  const nativeRequest = panel.indexOf(
    "await inspectDockerContainer(sessionId, container.id);",
    requestGeneration,
  );
  const staleGuard = panel.indexOf("if (!isCurrentInspect()) return;", nativeRequest);
  assert.ok(
    inspectRequest >= 0
      && sessionCapture > inspectRequest
      && requestGeneration > sessionCapture
      && nativeRequest > requestGeneration
      && staleGuard > nativeRequest,
    "inspect replies must retain exact session and request ownership",
  );

  const close = panel.indexOf("const closeInspect = useCallback(");
  const invalidate = panel.indexOf("inspectGenerationRef.current += 1;", close);
  const clear = panel.indexOf("setInspectedContainer(null);", invalidate);
  assert.ok(close >= 0 && invalidate > close && clear > invalidate, "closing must retire the pending request");
});

test("Docker failures expose only renderer-owned localized messages", async () => {
  const panel = await readFile(panelUrl, "utf8");

  assert.doesNotMatch(panel, /readableError/u);
  assert.doesNotMatch(panel, /\.message/u);
  assert.doesNotMatch(panel, /SYSTEM_MANAGER_[A-Z_]+/u);
  assert.match(panel, /setContainerListError\(t\("systemManager\.docker\.listFailed"\)\)/u);
  assert.match(panel, /setContainerActionError\(t\("systemManager\.docker\.actionFailed"\)\)/u);
  assert.match(panel, /setImagesError\(t\("systemManager\.docker\.imagesListFailed"\)\)/u);
  assert.match(panel, /setInspectError\(t\("systemManager\.docker\.inspectFailed"\)\)/u);
  assert.match(panel, /const containerError = containerActionError \?\? containerListError/u);
});

test("container mutations are target-owned, duplicate-safe and always reconciled", async () => {
  const panel = await readFile(panelUrl, "utf8");

  const sessionEffect = panel.indexOf(
    "const sessionGeneration = ++sessionGenerationRef.current;",
  );
  const bindView = panel.indexOf("viewSessionIdRef.current = sessionId;", sessionEffect);
  const resetLoading = panel.indexOf("setLoading(false);", sessionEffect);
  const firstRefresh = panel.indexOf("if (connected) void refresh();", sessionEffect);
  assert.ok(sessionEffect >= 0, "the session effect must establish ownership");
  assert.ok(bindView > sessionEffect, "the reset effect must bind its exact session view");
  assert.ok(resetLoading > sessionEffect, "a switched session must retire stale loading state");
  assert.ok(
    firstRefresh > resetLoading,
    "the first request must start only after the session generation and reset are established",
  );
  assert.match(
    panel,
    /if \(viewSessionIdRef\.current !== sessionId\)[\s\S]*?systemManager\.refreshing/u,
    "the old host must be hidden during the render before passive reset effects run",
  );

  const actionStart = panel.indexOf("const runAction = useCallback(");
  const actionEnd = panel.indexOf("  const containerError", actionStart);
  const actionBody = panel.slice(actionStart, actionEnd);
  const duplicateGuard = actionBody.indexOf(
    "if (pendingActionsRef.current.has(container.id)) return;",
  );
  const tokenRegistration = actionBody.indexOf(
    "pendingActionsRef.current.set(container.id, { action, token: actionToken });",
  );
  const nativeAction = actionBody.indexOf("await runDockerContainerAction(");
  const guardedError = actionBody.indexOf(
    "setContainerActionError(t(\"systemManager.docker.actionFailed\"));",
    nativeAction,
  );
  const finallyBlock = actionBody.indexOf("} finally {", guardedError);
  const actionRefresh = actionBody.indexOf("await refresh();", finallyBlock);
  const guardedCleanup = actionBody.indexOf(
    "pendingActionsRef.current.delete(container.id);",
    actionRefresh,
  );
  assert.ok(actionStart >= 0 && actionEnd > actionStart, "the action path must be found");
  assert.ok(
    duplicateGuard >= 0 && tokenRegistration > duplicateGuard && nativeAction > tokenRegistration,
    "the exact target must be synchronously claimed before the native mutation",
  );
  assert.ok(
    guardedError > nativeAction
      && finallyBlock > guardedError
      && actionRefresh > finallyBlock
      && guardedCleanup > actionRefresh,
    "success and failure must both reconcile before releasing the exact target",
  );
  assert.match(
    actionBody,
    /sessionGenerationRef\.current === sessionGeneration[\s\S]*?\.action === action[\s\S]*?\.token === actionToken/u,
    "session, target, action and token must all retain ownership",
  );
  assert.match(actionBody, /const startsActionBatch = pendingActionsRef\.current\.size === 0/u);
  assert.match(actionBody, /if \(startsActionBatch\) setContainerActionError\(null\)/u);
  assert.match(actionBody, /setBusyIds\(\(current\) => new Set\(current\)\.add\(container\.id\)\)/u);
  assert.match(panel, /const busy = busyIds\.has\(container\.id\)/u);

  const refreshStart = panel.indexOf("const refresh = useCallback(");
  const refreshEnd = panel.indexOf("const refreshImages = useCallback(", refreshStart);
  assert.doesNotMatch(
    panel.slice(refreshStart, refreshEnd),
    /setContainerActionError/u,
    "a reconciliation refresh must preserve mutation failures",
  );
});

test("the panel is localized and uses no literal user-facing strings", async () => {
  const panel = await readFile(panelUrl, "utf8");

  for (const key of [
    "systemManager.docker.title",
    "systemManager.docker.imagesTitle",
    "systemManager.docker.imagesEmptyTitle",
    "systemManager.docker.inspectTitle",
    "systemManager.docker.emptyTitle",
    "systemManager.notConnected",
    "systemManager.refresh",
  ]) {
    assert.ok(panel.includes(key), `panel must use ${key}`);
  }

  // Action labels resolve through the typed key map, so a missing translation
  // is a compile error rather than a blank button.
  assert.match(panel, /Record<DockerContainerAction, MessageKey>/u);
});
