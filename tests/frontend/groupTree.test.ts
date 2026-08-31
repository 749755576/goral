import assert from "node:assert/strict";
import test from "node:test";

import {
  buildGroupTree,
  planGroupCreation,
  planGroupMove,
  planGroupRename,
  validateGroupLeafName,
} from "../../src/groupTree.ts";

type Host = {
  id: string;
  group?: string | null;
};

const host = (id: string, group?: string | null): Host => ({ id, group });

test("group tree keeps explicit empty leaves distinct from implicit ancestors", () => {
  const tree = buildGroupTree<Host>({
    explicitGroups: ["Empty/Leaf"],
    hosts: [],
  });

  assert.equal(tree.roots.length, 1);
  assert.deepEqual(tree.roots[0], {
    name: "Empty",
    path: "Empty",
    explicit: false,
    hosts: [],
    totalHostCount: 0,
    children: [{
      name: "Leaf",
      path: "Empty/Leaf",
      explicit: true,
      hosts: [],
      children: [],
      totalHostCount: 0,
    }],
  });
});

test("group tree includes host-only paths and implicit ancestors", () => {
  const grouped = host("host-1", "Host only/Child");
  const tree = buildGroupTree({
    explicitGroups: [],
    hosts: [grouped, host("root"), host("slash-only", "///")],
  });

  assert.equal(tree.roots[0]?.path, "Host only");
  assert.equal(tree.roots[0]?.explicit, false);
  assert.equal(tree.roots[0]?.children[0]?.path, "Host only/Child");
  assert.deepEqual(tree.roots[0]?.children[0]?.hosts, [grouped]);
  assert.equal(tree.roots[0]?.totalHostCount, 1);
  assert.deepEqual(tree.ungroupedHosts.map(({ id }) => id), ["root", "slash-only"]);
});

test("group hierarchy treats only slash as a separator and preserves segment contents", () => {
  const tree = buildGroupTree<Host>({
    explicitGroups: [String.raw`Ops\DB/ Team /./..`],
    hosts: [],
  });

  const root = tree.roots[0];
  assert.equal(root?.name, String.raw`Ops\DB`);
  assert.equal(root?.path, String.raw`Ops\DB`);
  assert.equal(root?.children[0]?.name, " Team ");
  assert.equal(root?.children[0]?.children[0]?.name, ".");
  assert.equal(root?.children[0]?.children[0]?.children[0]?.name, "..");
  assert.equal(
    root?.children[0]?.children[0]?.children[0]?.path,
    String.raw`Ops\DB/ Team /./..`,
  );
});

test("siblings sort by finite saved order and then by stable name", () => {
  const tree = buildGroupTree({
    explicitGroups: ["Root/Zulu", "Root/Alpha", "Root/Beta", "Root/Gamma"],
    groupConfigs: [
      { path: "Root/Zulu", order: 2000 },
      { path: "Root/Beta", order: 1000 },
      { path: "Root/Gamma", order: 2000 },
      { path: "Root/Delta", order: 500 },
      { path: "Root/Alpha", order: Number.NaN },
    ],
    hosts: [host("host-only", "Root/Delta")],
  });

  assert.deepEqual(
    tree.roots[0]?.children.map(({ name }) => name),
    ["Delta", "Beta", "Gamma", "Zulu", "Alpha"],
  );
});

test("leaf validation trims new names, rejects separators, and keeps logical dot names", () => {
  assert.deepEqual(validateGroupLeafName("  Production  "), {
    ok: true,
    name: "Production",
  });
  assert.deepEqual(validateGroupLeafName("   "), { ok: false, error: "required" });
  assert.deepEqual(validateGroupLeafName("A/B"), {
    ok: false,
    error: "invalidSeparator",
  });
  assert.deepEqual(validateGroupLeafName(String.raw`A\B`), {
    ok: false,
    error: "invalidSeparator",
  });
  assert.deepEqual(validateGroupLeafName("."), { ok: true, name: "." });
  assert.deepEqual(validateGroupLeafName(".."), { ok: true, name: ".." });
});

test("group creation validates the leaf and rejects an occupied target", () => {
  assert.deepEqual(planGroupCreation("Root", " New ", ["Root/Other"]), {
    ok: true,
    nextPath: "Root/New",
  });
  assert.deepEqual(planGroupCreation("Root", "Other", ["Root/Other"]), {
    ok: false,
    error: "collision",
  });
});

test("group rename detects collisions across the complete moved subtree", () => {
  const existing = ["A", "A/Child", "B/Child"];
  assert.deepEqual(planGroupRename("A", "B", existing), {
    ok: false,
    error: "collision",
  });
  assert.deepEqual(planGroupRename("A", " C ", existing), {
    ok: true,
    nextPath: "C",
  });
  assert.deepEqual(planGroupRename("A", "A", existing), {
    ok: false,
    error: "unchanged",
  });
});

test("group move rejects descendants, unchanged moves, and subtree collisions", () => {
  const existing = ["A", "A/Child", "Target", "Target/A/Child"];
  assert.deepEqual(planGroupMove("A", "A/Child", existing), {
    ok: false,
    error: "descendant",
  });
  assert.deepEqual(planGroupMove("A/Child", "A", existing), {
    ok: false,
    error: "unchanged",
  });
  assert.deepEqual(planGroupMove("A", "Target", existing), {
    ok: false,
    error: "collision",
  });
  assert.deepEqual(planGroupMove("A", null, ["A", "A/Child"]), {
    ok: false,
    error: "unchanged",
  });
  assert.deepEqual(planGroupMove("A", "Elsewhere", ["A", "A/Child", "Elsewhere"]), {
    ok: true,
    nextPath: "Elsewhere/A",
  });
});
