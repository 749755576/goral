import assert from "node:assert/strict";
import test from "node:test";

import {
  createCoalescedRefresh,
  shouldShowSavedHostsBackgroundRefresh,
  shouldShowSavedHostsInitialLoader,
} from "../../src/savedHostsRefresh.ts";

const deferred = <T>() => {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
};

test("saved-host loading presentation reserves the large loader for the first snapshot", () => {
  assert.equal(shouldShowSavedHostsInitialLoader(true, false), true);
  assert.equal(shouldShowSavedHostsBackgroundRefresh(true, false), false);

  assert.equal(shouldShowSavedHostsInitialLoader(true, true), false);
  assert.equal(shouldShowSavedHostsBackgroundRefresh(true, true), true);

  assert.equal(shouldShowSavedHostsInitialLoader(false, false), false);
  assert.equal(shouldShowSavedHostsBackgroundRefresh(false, true), false);
});

test("ten concurrent saved-host refresh requests share exactly one operation", async () => {
  const pending = deferred<number>();
  let calls = 0;
  const refresh = createCoalescedRefresh(async () => {
    calls += 1;
    return pending.promise;
  });

  const requests = Array.from({ length: 10 }, () => refresh.request(undefined));
  assert.equal(calls, 1);
  assert.equal(refresh.isRunning(), true);

  pending.resolve(42);
  assert.deepEqual(await Promise.all(requests), Array(10).fill(42));
  assert.equal(calls, 1);
  assert.equal(refresh.isRunning(), false);
});

test("changed data can queue one trailing refresh without parallel or repeated work", async () => {
  const attempts = [deferred<number>(), deferred<number>()];
  let calls = 0;
  const refresh = createCoalescedRefresh(async () => {
    const attempt = attempts[calls];
    calls += 1;
    return attempt.promise;
  });

  const first = refresh.request(undefined);
  const queued = Array.from({ length: 8 }, () => refresh.request(undefined, {
    queueFollowUp: true,
  }));
  assert.equal(calls, 1);

  attempts[0].resolve(1);
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(calls, 2);

  const duringFollowUp = refresh.request(undefined, { queueFollowUp: true });
  assert.equal(calls, 2);
  attempts[1].resolve(2);

  assert.equal(await first, 2);
  assert.deepEqual(await Promise.all(queued), Array(8).fill(2));
  assert.equal(await duringFollowUp, 2);
  assert.equal(calls, 2);
  assert.equal(refresh.isRunning(), false);
});
