import type { Translate } from "../i18n";
import AiGlyph from "./AiGlyph";
import AiPopupMenu from "./AiPopupMenu";

export type AiContextMenuProps = Readonly<{
  disabled?: boolean;
  terminalContextAvailable: boolean;
  imageInputAvailable: boolean;
  t: Translate;
  onReadContext: (kind: "selectedText" | "recentOutput") => void | Promise<void>;
  onAddImage: () => void;
  onOpenQuickMessages: () => void;
}>;

type ContextActionProps = Readonly<{
  icon: "context" | "terminal" | "image" | "spark";
  title: string;
  description: string;
  onSelect: () => void;
  close: (restoreFocus?: boolean) => void;
}>;

function ContextAction({
  icon,
  title,
  description,
  onSelect,
  close,
}: ContextActionProps) {
  return (
    <button
      type="button"
      role="menuitem"
      tabIndex={-1}
      title={`${title} · ${description}`}
      onClick={() => {
        close(false);
        onSelect();
      }}
    >
      <span className="ai-context-menu-icon" aria-hidden="true"><AiGlyph name={icon} /></span>
      <span className="ai-popup-item-copy">
        <strong>{title}</strong>
        <small>{description}</small>
      </span>
    </button>
  );
}

export default function AiContextMenu({
  disabled = false,
  terminalContextAvailable,
  imageInputAvailable,
  t,
  onReadContext,
  onAddImage,
  onOpenQuickMessages,
}: AiContextMenuProps) {
  return (
    <AiPopupMenu
      label={t("ai.composer.addMenuLabel")}
      disabled={disabled}
      placement="top-start"
      rootClassName="ai-context-menu"
      triggerClassName="ai-context-menu-trigger"
      triggerTitle={t("ai.composer.addMenuLabel")}
      trigger={<span className="ai-context-menu-plus" aria-hidden="true">+</span>}
    >
      {(close) => (
        <div className="ai-popup-group" role="group" aria-label={t("ai.composer.addMenuGroup")}>
          <span className="ai-popup-group-label">{t("ai.composer.addMenuGroup")}</span>
          {terminalContextAvailable ? (
            <>
              <ContextAction
                icon="context"
                title={t("ai.composer.selectedText")}
                description={t("ai.composer.selectedTextDescription")}
                onSelect={() => void onReadContext("selectedText")}
                close={close}
              />
              <ContextAction
                icon="terminal"
                title={t("ai.composer.recentOutput")}
                description={t("ai.composer.recentOutputDescription")}
                onSelect={() => void onReadContext("recentOutput")}
                close={close}
              />
            </>
          ) : null}
          {imageInputAvailable ? (
            <ContextAction
              icon="image"
              title={t("ai.composer.image")}
              description={t("ai.composer.imageDescription")}
              onSelect={onAddImage}
              close={close}
            />
          ) : null}
          <ContextAction
            icon="spark"
            title={t("ai.composer.quickMessage")}
            description={t("ai.composer.quickMessageDescription")}
            onSelect={onOpenQuickMessages}
            close={close}
          />
        </div>
      )}
    </AiPopupMenu>
  );
}
