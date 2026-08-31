import type { Translate } from "../i18n";
import AiPopupMenu from "./AiPopupMenu";

export type AiThinkingEffort = "off" | "low" | "medium" | "high";

export type AiThinkingMenuProps = Readonly<{
  value: AiThinkingEffort;
  disabled?: boolean;
  t: Translate;
  onSelect: (value: AiThinkingEffort) => void;
}>;

const Chevron = () => (
  <svg className="ai-popup-chevron" viewBox="0 0 16 16" aria-hidden="true"><path d="m4 6 4 4 4-4" /></svg>
);

export default function AiThinkingMenu({
  value,
  disabled = false,
  t,
  onSelect,
}: AiThinkingMenuProps) {
  const choices: ReadonlyArray<Readonly<{
    value: AiThinkingEffort;
    label: string;
    description: string;
  }>> = [
    { value: "off", label: t("ai.thinking.off"), description: t("ai.thinking.offDescription") },
    { value: "low", label: t("ai.thinking.low"), description: t("ai.thinking.lowDescription") },
    { value: "medium", label: t("ai.thinking.medium"), description: t("ai.thinking.mediumDescription") },
    { value: "high", label: t("ai.thinking.high"), description: t("ai.thinking.highDescription") },
  ];
  const selected = choices.find((choice) => choice.value === value) ?? choices[0];

  return (
    <AiPopupMenu
      label={t("ai.thinking.menuLabel")}
      disabled={disabled}
      placement="top-start"
      rootClassName="ai-thinking-menu"
      triggerClassName="ai-thinking-menu-trigger"
      triggerTitle={`${t("ai.thinking.menuLabel")} · ${selected.label} · ${selected.description}`}
      trigger={(
        <>
          <span className={`ai-thinking-mark is-${selected.value}`} aria-hidden="true" />
          <span className="ai-thinking-trigger-title">{selected.label}</span>
          <Chevron />
        </>
      )}
    >
      {(close) => (
        <div className="ai-popup-group" role="group" aria-label={t("ai.thinking.menuLabel")}>
          <span className="ai-popup-group-label">{t("ai.thinking.menuLabel")}</span>
          {choices.map((choice) => (
            <button
              key={choice.value}
              type="button"
              role="menuitemradio"
              aria-checked={value === choice.value}
              tabIndex={-1}
              title={`${choice.label} · ${choice.description}`}
              onClick={() => {
                onSelect(choice.value);
                close();
              }}
            >
              <span className={`ai-thinking-mark is-${choice.value}`} aria-hidden="true" />
              <span className="ai-popup-item-copy">
                <strong>{choice.label}</strong>
                <small>{choice.description}</small>
              </span>
              {value === choice.value ? <span className="ai-popup-check" aria-hidden="true">✓</span> : null}
            </button>
          ))}
        </div>
      )}
    </AiPopupMenu>
  );
}
