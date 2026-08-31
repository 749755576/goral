import type { Translate } from "../i18n";
import type { AiCommandPermissionMode } from "../settingsUi";
import AiPopupMenu from "./AiPopupMenu";

export type AiPermissionMenuProps = Readonly<{
  value: AiCommandPermissionMode;
  disabled?: boolean;
  disabledReason?: string;
  t: Translate;
  onSelect: (mode: AiCommandPermissionMode) => void;
}>;

const PermissionIcon = ({ mode }: Readonly<{ mode: AiCommandPermissionMode }>) => {
  if (mode === "observer") {
    return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 12s3.4-5 9-5 9 5 9 5-3.4 5-9 5-9-5-9-5Z" /><circle cx="12" cy="12" r="2.4" /></svg>;
  }
  if (mode === "confirm") {
    return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 5.5 6v5.2c0 4.2 2.7 7.8 6.5 9.3 3.8-1.5 6.5-5.1 6.5-9.3V6L12 3Z" /><path d="m9 12 2 2 4-4" /></svg>;
  }
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m13 2-7 12h6l-1 8 7-12h-6l1-8Z" /></svg>;
};

const Chevron = () => (
  <svg className="ai-popup-chevron" viewBox="0 0 16 16" aria-hidden="true"><path d="m4 6 4 4 4-4" /></svg>
);

export default function AiPermissionMenu({
  value,
  disabled = false,
  disabledReason,
  t,
  onSelect,
}: AiPermissionMenuProps) {
  const choices: ReadonlyArray<Readonly<{
    mode: AiCommandPermissionMode;
    title: string;
    description: string;
  }>> = [
    { mode: "observer", title: t("ai.permission.observer"), description: t("ai.permission.observerDescription") },
    { mode: "confirm", title: t("ai.permission.confirm"), description: t("ai.permission.confirmDescription") },
    { mode: "auto", title: t("ai.permission.auto"), description: t("ai.permission.autoDescription") },
  ];
  const selected = choices.find((choice) => choice.mode === value) ?? choices[1];

  return (
    <AiPopupMenu
      label={t("ai.permission.menuLabel")}
      disabled={disabled}
      triggerTitle={`${selected.title} · ${disabledReason ?? selected.description}`}
      placement="top-end"
      rootClassName="ai-permission-menu"
      triggerClassName="ai-permission-menu-trigger"
      trigger={(
        <>
          <span className={`ai-permission-icon is-${selected.mode}`}><PermissionIcon mode={selected.mode} /></span>
          <span className="ai-permission-trigger-title">{selected.title}</span>
          <Chevron />
        </>
      )}
    >
      {(close) => (
        <div className="ai-popup-group" role="group" aria-label={t("ai.permission.menuLabel")}>
          <span className="ai-popup-group-label">{t("ai.permission.menuLabel")}</span>
          {choices.map((choice) => (
            <button
              key={choice.mode}
              type="button"
              role="menuitemradio"
              aria-checked={value === choice.mode}
              tabIndex={-1}
              title={`${choice.title} · ${choice.description}`}
              onClick={() => { onSelect(choice.mode); close(); }}
            >
              <span className={`ai-permission-icon is-${choice.mode}`}><PermissionIcon mode={choice.mode} /></span>
              <span className="ai-popup-item-copy">
                <strong>{choice.title}</strong>
                <small>{choice.description}</small>
              </span>
              {value === choice.mode ? <span className="ai-popup-check" aria-hidden="true">✓</span> : null}
            </button>
          ))}
        </div>
      )}
    </AiPopupMenu>
  );
}
