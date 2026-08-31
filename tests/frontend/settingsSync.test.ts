import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { createSettingsReloadCoordinator } from "../../src/settingsSync.ts";

const deferred = <T>() => {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
};

test("a late Settings load cannot overwrite the newest cross-window reload", async () => {
  const first = deferred<string>();
  const second = deferred<string>();
  const loads = [first.promise, second.promise];
  const applied: string[] = [];
  const coordinator = createSettingsReloadCoordinator({
    load: async () => {
      const next = loads.shift();
      assert.ok(next);
      return next;
    },
    apply: (snapshot) => applied.push(snapshot),
  });

  const staleReload = coordinator.reload();
  const newestReload = coordinator.reload();
  second.resolve("revision-2");
  assert.equal(await newestReload, true);
  first.resolve("revision-1");
  assert.equal(await staleReload, false);
  assert.deepEqual(applied, ["revision-2"]);
});

test("disposing Settings synchronization rejects an in-flight renderer update", async () => {
  const pending = deferred<string>();
  const applied: string[] = [];
  const coordinator = createSettingsReloadCoordinator({
    load: () => pending.promise,
    apply: (snapshot) => applied.push(snapshot),
  });

  const reload = coordinator.reload();
  coordinator.dispose();
  pending.resolve("after-unmount");
  assert.equal(await reload, false);
  assert.deepEqual(applied, []);
});

test("native Settings commits emit a revision-only event and the main window cleans up its listener", async () => {
  const [command, api, workspace] = await Promise.all([
    readFile(new URL("../../src-tauri/src/settings_commands.rs", import.meta.url), "utf8"),
    readFile(new URL("../../src/settingsApi.ts", import.meta.url), "utf8"),
    readFile(new URL("../../src/TerminalWorkspace.tsx", import.meta.url), "utf8"),
  ]);

  assert.match(command, /SETTINGS_CHANGED_EVENT:\s*&str\s*=\s*"goral:settings-changed"/u);
  assert.match(api, /SETTINGS_CHANGED_EVENT\s*=\s*"goral:settings-changed"/u);
  const commitIndex = command.indexOf("commit(state.settings.clone(), request).await?");
  const emitIndex = command.indexOf("app.emit(", commitIndex);
  assert.ok(commitIndex >= 0 && emitIndex > commitIndex, "the event must follow a successful durable commit");
  const payload = command.slice(
    command.indexOf("struct SettingsChangedNotification"),
    command.indexOf("fn settings_changed_notification"),
  );
  assert.match(payload, /inventory_revision/u);
  assert.doesNotMatch(payload, /settings\s*:/u);
  assert.doesNotMatch(payload, /key|password|secret/iu);

  assert.match(api, /if \(!isTauri\(\)\) return null/u);
  assert.match(api, /listen<unknown>\(SETTINGS_CHANGED_EVENT/u);
  assert.match(api, /isSettingsChangedNotification\(event\.payload\)/u);
  assert.match(workspace, /subscribeSettingsChanges\(\(\) => refreshTerminalSettings\(\)\)/u);
  assert.match(workspace, /setRendererSettings\(snapshot\.settings\)/u);
  assert.match(workspace, /stopListening\?\.\(\)/u);
  assert.match(workspace, /unlisten\?\.\(\)/u);
  assert.match(workspace, /coordinator\.dispose\(\)/u);
  assert.match(workspace, /await settingsReloadCoordinatorRef\.current\?\.reload\(\)/u);
});
