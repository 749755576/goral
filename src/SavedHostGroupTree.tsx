import { useState, type ReactNode } from "react";

import type { SavedHost } from "./backend";
import { createTranslator, type Locale } from "./i18n";
import {
  buildGroupTree,
  type GroupOrderConfig,
  type GroupTreeNode,
} from "./groupTree";

export type SavedHostGroupTreeProps = {
  hosts: readonly SavedHost[];
  explicitGroups?: readonly string[];
  groupConfigs?: readonly GroupOrderConfig[];
  renderHost: (host: SavedHost) => ReactNode;
  locale?: Locale;
  ungroupedLabel?: string;
};

export function SavedHostGroupTree({
  hosts,
  explicitGroups = [],
  groupConfigs = [],
  renderHost,
  locale = "zh-CN",
  ungroupedLabel,
}: SavedHostGroupTreeProps) {
  const t = createTranslator(locale);
  const resolvedUngroupedLabel = ungroupedLabel ?? t("savedHost.group.ungrouped");
  const [collapsedPaths, setCollapsedPaths] = useState<ReadonlySet<string>>(
    () => new Set(),
  );
  const tree = buildGroupTree({ explicitGroups, groupConfigs, hosts });

  const togglePath = (path: string) => {
    setCollapsedPaths((current) => {
      const next = new Set(current);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  };

  const renderNode = (node: GroupTreeNode<SavedHost>, depth: number): ReactNode => {
    const expanded = !collapsedPaths.has(node.path);
    return (
      <section className="saved-host-group" data-group-path={node.path} key={node.path}>
        <button
          type="button"
          className="saved-host-group-toggle"
          aria-expanded={expanded}
          onClick={() => togglePath(node.path)}
          style={{ paddingLeft: `${8 + depth * 12}px` }}
        >
          <span className="saved-host-group-chevron" aria-hidden="true">
            {expanded ? "−" : "+"}
          </span>
          <span className="saved-host-group-name" title={node.name}>{node.name}</span>
          <span className="saved-host-group-count">{node.totalHostCount}</span>
        </button>
        {expanded && (
          <div className="saved-host-group-contents">
            {node.hosts.map((host) => renderHost(host))}
            {node.children.map((child) => renderNode(child, depth + 1))}
          </div>
        )}
      </section>
    );
  };

  return (
    <div className="saved-host-group-tree">
      {tree.roots.map((node) => renderNode(node, 0))}
      {tree.ungroupedHosts.length > 0 && (
        <section className="saved-host-group saved-host-ungrouped" data-group-path="">
          <div className="saved-host-group-label">
            <span className="saved-host-group-name">{resolvedUngroupedLabel}</span>
            <span className="saved-host-group-count">{tree.ungroupedHosts.length}</span>
          </div>
          <div className="saved-host-group-contents">
            {tree.ungroupedHosts.map((host) => renderHost(host))}
          </div>
        </section>
      )}
    </div>
  );
}

export default SavedHostGroupTree;
