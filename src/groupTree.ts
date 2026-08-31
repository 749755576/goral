export type GroupOrderConfig = Readonly<{
  path: string;
  order?: number;
}>;

export type GroupTreeHost = Readonly<{
  group?: string | null;
}>;

export type GroupTreeNode<THost extends GroupTreeHost> = {
  name: string;
  path: string;
  explicit: boolean;
  hosts: THost[];
  children: GroupTreeNode<THost>[];
  totalHostCount: number;
};

export type GroupTree<THost extends GroupTreeHost> = {
  roots: GroupTreeNode<THost>[];
  ungroupedHosts: THost[];
};

type MutableGroupTreeNode<THost extends GroupTreeHost> = {
  name: string;
  path: string;
  explicit: boolean;
  hosts: THost[];
  children: Map<string, MutableGroupTreeNode<THost>>;
};

export type GroupLeafNameError = "required" | "invalidSeparator";

export type GroupLeafNameResult =
  | { ok: true; name: string }
  | { ok: false; error: GroupLeafNameError };

export type GroupPathChangeError =
  | GroupLeafNameError
  | "sourceRequired"
  | "descendant"
  | "collision"
  | "unchanged";

export type GroupPathChangeResult =
  | { ok: true; nextPath: string }
  | { ok: false; error: GroupPathChangeError };

export type BuildGroupTreeInput<THost extends GroupTreeHost> = {
  explicitGroups: readonly string[];
  groupConfigs?: readonly GroupOrderConfig[];
  hosts: readonly THost[];
};

/**
 * Projects a stored group path into its hierarchy segments.
 *
 * Group identity uses `/` as its only separator. Segment contents are never
 * trimmed or interpreted, so backslashes, whitespace, `.` and `..` remain
 * ordinary group-name characters. Empty slash components are omitted to
 * match the legacy tree projection.
 */
export const groupPathSegments = (path: string): string[] =>
  path.split("/").filter((segment) => segment.length > 0);

export const projectedGroupPath = (path: string): string =>
  groupPathSegments(path).join("/");

const parentGroupPath = (path: string): string => {
  const segments = groupPathSegments(path);
  return segments.slice(0, -1).join("/");
};

const groupPathLeaf = (path: string): string | null => {
  const segments = groupPathSegments(path);
  return segments.at(-1) ?? null;
};

const isPathAtOrBelow = (path: string, root: string): boolean =>
  path === root || path.startsWith(`${root}/`);

const compareNames = (left: string, right: string): number => {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
};

const validOrder = (value: number | undefined): value is number =>
  typeof value === "number" && Number.isFinite(value);

export function buildGroupTree<THost extends GroupTreeHost>({
  explicitGroups,
  groupConfigs = [],
  hosts,
}: BuildGroupTreeInput<THost>): GroupTree<THost> {
  const roots = new Map<string, MutableGroupTreeNode<THost>>();

  const insertPath = (rawPath: string, explicit: boolean, host?: THost): boolean => {
    const segments = groupPathSegments(rawPath);
    if (segments.length === 0) return false;

    let children = roots;
    let currentPath = "";
    let leaf: MutableGroupTreeNode<THost> | undefined;
    segments.forEach((segment) => {
      currentPath = currentPath ? `${currentPath}/${segment}` : segment;
      let node = children.get(segment);
      if (!node) {
        node = {
          name: segment,
          path: currentPath,
          explicit: false,
          hosts: [],
          children: new Map(),
        };
        children.set(segment, node);
      }
      leaf = node;
      children = node.children;
    });

    if (!leaf) return false;
    if (explicit) leaf.explicit = true;
    if (host !== undefined) leaf.hosts.push(host);
    return true;
  };

  explicitGroups.forEach((path) => insertPath(path, true));

  const ungroupedHosts: THost[] = [];
  hosts.forEach((host) => {
    if (typeof host.group !== "string" || !insertPath(host.group, false, host)) {
      ungroupedHosts.push(host);
    }
  });

  const orderByPath = new Map<string, number>();
  groupConfigs.forEach((config) => {
    const path = projectedGroupPath(config.path);
    if (path && validOrder(config.order)) orderByPath.set(path, config.order);
  });

  const finalize = (
    nodes: Iterable<MutableGroupTreeNode<THost>>,
  ): GroupTreeNode<THost>[] => Array.from(nodes, (node) => {
    const children = finalize(node.children.values());
    const totalHostCount = children.reduce(
      (count, child) => count + child.totalHostCount,
      node.hosts.length,
    );
    return {
      name: node.name,
      path: node.path,
      explicit: node.explicit,
      hosts: node.hosts,
      children,
      totalHostCount,
    };
  }).sort((left, right) => {
    const leftOrder = orderByPath.get(left.path);
    const rightOrder = orderByPath.get(right.path);
    if (validOrder(leftOrder) && validOrder(rightOrder)) {
      if (leftOrder !== rightOrder) return leftOrder - rightOrder;
      return compareNames(left.name, right.name);
    }
    if (validOrder(leftOrder)) return -1;
    if (validOrder(rightOrder)) return 1;
    return compareNames(left.name, right.name);
  });

  return {
    roots: finalize(roots.values()),
    ungroupedHosts,
  };
}

export const validateGroupLeafName = (rawName: string): GroupLeafNameResult => {
  const name = rawName.trim();
  if (!name) return { ok: false, error: "required" };
  if (name.includes("/") || name.includes("\\")) {
    return { ok: false, error: "invalidSeparator" };
  }
  return { ok: true, name };
};

const collisionAfterPathChange = (
  sourcePath: string,
  nextPath: string,
  existingPaths: Iterable<string>,
): boolean => {
  const paths = Array.from(existingPaths, projectedGroupPath).filter(Boolean);
  const outsideSource = new Set(paths.filter((path) => !isPathAtOrBelow(path, sourcePath)));
  return paths
    .filter((path) => isPathAtOrBelow(path, sourcePath))
    .map((path) => nextPath + path.slice(sourcePath.length))
    .some((path) => outsideSource.has(path));
};

export const planGroupCreation = (
  parentPath: string | null,
  rawLeafName: string,
  existingPaths: Iterable<string>,
): GroupPathChangeResult => {
  const leaf = validateGroupLeafName(rawLeafName);
  if (!leaf.ok) return leaf;
  const parent = parentPath ? projectedGroupPath(parentPath) : "";
  const nextPath = parent ? `${parent}/${leaf.name}` : leaf.name;
  const occupied = new Set(Array.from(existingPaths, projectedGroupPath).filter(Boolean));
  return occupied.has(nextPath)
    ? { ok: false, error: "collision" }
    : { ok: true, nextPath };
};

export const planGroupRename = (
  sourceValue: string,
  rawLeafName: string,
  existingPaths: Iterable<string>,
): GroupPathChangeResult => {
  const sourcePath = projectedGroupPath(sourceValue);
  if (!sourcePath) return { ok: false, error: "sourceRequired" };
  const leaf = validateGroupLeafName(rawLeafName);
  if (!leaf.ok) return leaf;
  const parent = parentGroupPath(sourcePath);
  const nextPath = parent ? `${parent}/${leaf.name}` : leaf.name;
  if (nextPath === sourcePath) return { ok: false, error: "unchanged" };
  if (collisionAfterPathChange(sourcePath, nextPath, existingPaths)) {
    return { ok: false, error: "collision" };
  }
  return { ok: true, nextPath };
};

export const planGroupMove = (
  sourceValue: string,
  targetParentValue: string | null,
  existingPaths: Iterable<string>,
): GroupPathChangeResult => {
  const sourcePath = projectedGroupPath(sourceValue);
  const leaf = groupPathLeaf(sourcePath);
  if (!sourcePath || !leaf) return { ok: false, error: "sourceRequired" };
  const targetParent = targetParentValue ? projectedGroupPath(targetParentValue) : "";
  if (targetParent && isPathAtOrBelow(targetParent, sourcePath)) {
    return { ok: false, error: "descendant" };
  }
  const nextPath = targetParent ? `${targetParent}/${leaf}` : leaf;
  if (nextPath === sourcePath) return { ok: false, error: "unchanged" };
  if (collisionAfterPathChange(sourcePath, nextPath, existingPaths)) {
    return { ok: false, error: "collision" };
  }
  return { ok: true, nextPath };
};
