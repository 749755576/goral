import type { DiscoveredAiAgent } from "../aiAgentDiscoveryApi";
import type { Translate } from "../i18n";
import AiPopupMenu from "./AiPopupMenu";

export type AiAgentMenuProps = Readonly<{
  value: string;
  agents: ReadonlyArray<DiscoveredAiAgent>;
  localRuntimeAvailable: boolean;
  disabled?: boolean;
  builtinSubtitle: string;
  t: Translate;
  onSelect: (agentId: string) => void;
  onOpenSettings?: () => void;
}>;

const AgentMark = ({ name, builtin = false }: Readonly<{ name: string; builtin?: boolean }>) => (
  <span className={`ai-agent-menu-mark ${builtin ? "is-builtin" : ""}`} aria-hidden="true">
    {builtin ? (
      <svg viewBox="0 0 24 24"><path d="m12 3 1.6 5.1L19 10l-5.4 1.9L12 17l-1.6-5.1L5 10l5.4-1.9L12 3Z" /></svg>
    ) : name.trim().slice(0, 1).toLocaleUpperCase()}
  </span>
);

const Chevron = () => (
  <svg className="ai-popup-chevron" viewBox="0 0 16 16" aria-hidden="true"><path d="m4 6 4 4 4-4" /></svg>
);

export default function AiAgentMenu({
  value,
  agents,
  localRuntimeAvailable,
  disabled = false,
  builtinSubtitle,
  t,
  onSelect,
  onOpenSettings,
}: AiAgentMenuProps) {
  const runnable = agents.filter((agent) => agent.runtimeSupported && agent.available && localRuntimeAvailable);
  const selectedLocal = value === "builtin"
    ? null
    : runnable.find((agent) => agent.id === value) ?? null;
  const selectedName = selectedLocal?.name ?? t("ai.agent.builtin");
  const selectedSubtitle = selectedLocal ? t("ai.localAgent.readOnly") : builtinSubtitle;
  const selectedTitle = `${selectedName} · ${selectedSubtitle}`;

  const select = (agentId: string, close: () => void) => {
    onSelect(agentId);
    close();
  };

  const localDetail = (agent: DiscoveredAiAgent): string => {
    const status = t("ai.menu.agent.ready");
    return agent.version ? `${agent.version} · ${status}` : status;
  };

  return (
    <AiPopupMenu
      label={t("ai.selectAgent")}
      disabled={disabled}
      rootClassName="ai-agent-menu"
      triggerClassName="ai-agent-menu-trigger"
      triggerTitle={selectedTitle}
      trigger={(
        <>
          <AgentMark name={selectedName} builtin={!selectedLocal} />
          <span className="ai-popup-trigger-copy">
            <strong>{selectedName}</strong>
            <small>{selectedSubtitle}</small>
          </span>
          <Chevron />
        </>
      )}
    >
      {(close) => (
        <>
          <div className="ai-popup-group" role="group" aria-label={t("ai.menu.agent.builtinGroup")}>
            <span className="ai-popup-group-label">{t("ai.menu.agent.builtinGroup")}</span>
            <button
              type="button"
              role="menuitemradio"
              aria-checked={value === "builtin"}
              tabIndex={-1}
              title={`${t("ai.agent.builtin")} · ${t("ai.menu.agent.builtinDescription")}`}
              onClick={() => select("builtin", close)}
            >
              <AgentMark name={t("ai.agent.builtin")} builtin />
              <span className="ai-popup-item-copy">
                <strong>{t("ai.agent.builtin")}</strong>
                <small>{t("ai.menu.agent.builtinDescription")}</small>
              </span>
              {value === "builtin" ? <span className="ai-popup-check" aria-hidden="true">✓</span> : null}
            </button>
          </div>

          {runnable.length > 0 ? (
            <div className="ai-popup-group" role="group" aria-label={t("ai.menu.agent.availableGroup")}>
              <span className="ai-popup-group-label">{t("ai.menu.agent.availableGroup")}</span>
              {runnable.map((agent) => (
                <button
                  key={agent.id}
                  type="button"
                  role="menuitemradio"
                  aria-checked={value === agent.id}
                  tabIndex={-1}
                  title={`${agent.name} · ${localDetail(agent)}`}
                  onClick={() => select(agent.id, close)}
                >
                  <AgentMark name={agent.name} />
                  <span className="ai-popup-item-copy">
                    <strong>{agent.name}</strong>
                    <small>{localDetail(agent)}</small>
                  </span>
                  {value === agent.id ? <span className="ai-popup-check" aria-hidden="true">✓</span> : null}
                </button>
              ))}
            </div>
          ) : null}

          {onOpenSettings ? (
            <div className="ai-popup-footer">
              <button type="button" role="menuitem" tabIndex={-1} onClick={() => { close(false); onOpenSettings(); }}>
                <span className="ai-popup-settings-icon" aria-hidden="true">⚙</span>
                <span>{t("ai.menu.agent.manage")}</span>
              </button>
            </div>
          ) : null}
        </>
      )}
    </AiPopupMenu>
  );
}
