import {
  type KeyboardEvent,
  type ReactNode,
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
} from "react";

import { resolveAiMenuFocusIndex, type AiMenuNavigationKey } from "./aiMenuKeyboard";

export type AiPopupMenuPlacement = "bottom-start" | "top-start" | "top-end";

export type AiPopupMenuProps = Readonly<{
  label: string;
  disabled?: boolean;
  placement?: AiPopupMenuPlacement;
  rootClassName?: string;
  triggerClassName?: string;
  triggerTitle?: string;
  trigger: ReactNode;
  children: (close: (restoreFocus?: boolean) => void) => ReactNode;
}>;

const focusableMenuItems = (menu: HTMLDivElement | null): HTMLElement[] => (
  menu
    ? Array.from(menu.querySelectorAll<HTMLElement>(
      '[role="searchbox"]:not(:disabled), [role="menuitem"]:not([aria-disabled="true"]), [role="menuitemradio"]:not([aria-disabled="true"])',
    ))
    : []
);

const focusMenuItem = (items: readonly HTMLElement[], target: HTMLElement | undefined) => {
  if (!target) return;
  for (const item of items) item.tabIndex = item === target ? 0 : -1;
  target.focus();
  target.scrollIntoView({ block: "nearest" });
};

export default function AiPopupMenu({
  label,
  disabled = false,
  placement = "bottom-start",
  rootClassName = "",
  triggerClassName = "",
  triggerTitle,
  trigger,
  children,
}: AiPopupMenuProps) {
  const menuId = useId();
  const triggerId = `${menuId}-trigger`;
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const focusIntentRef = useRef<"first" | "last" | "selected">("selected");
  const [open, setOpen] = useState(false);

  const close = useCallback((restoreFocus = true) => {
    setOpen(false);
    if (restoreFocus) requestAnimationFrame(() => triggerRef.current?.focus());
  }, []);

  const openWithFocus = useCallback((intent: "first" | "last" | "selected") => {
    if (disabled) return;
    focusIntentRef.current = intent;
    setOpen(true);
  }, [disabled]);

  useEffect(() => {
    if (!disabled) return;
    setOpen(false);
  }, [disabled]);

  useEffect(() => {
    if (!open) return undefined;
    const frame = requestAnimationFrame(() => {
      const items = focusableMenuItems(menuRef.current);
      if (items.length === 0) return;
      const selected = items.find((item) => item.getAttribute("aria-checked") === "true");
      const target = focusIntentRef.current === "first"
        ? items[0]
        : focusIntentRef.current === "last"
          ? items.at(-1)
          : selected ?? items[0];
      focusMenuItem(items, target);
    });
    const onPointerDown = (event: PointerEvent) => {
      if (event.target instanceof Node && !rootRef.current?.contains(event.target)) close(false);
    };
    document.addEventListener("pointerdown", onPointerDown, true);
    return () => {
      cancelAnimationFrame(frame);
      document.removeEventListener("pointerdown", onPointerDown, true);
    };
  }, [close, open]);

  const onTriggerKeyDown = (event: KeyboardEvent<HTMLButtonElement>) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      openWithFocus(event.key === "ArrowDown" ? "first" : "last");
    } else if (event.key === "Escape" && open) {
      event.preventDefault();
      close();
    }
  };

  const onMenuKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      close();
      return;
    }
    if (event.key === "Tab") {
      close(false);
      return;
    }
    if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) return;
    const items = focusableMenuItems(menuRef.current);
    const currentIndex = items.indexOf(document.activeElement as HTMLElement);
    const nextIndex = resolveAiMenuFocusIndex(
      event.key as AiMenuNavigationKey,
      currentIndex,
      items.length,
    );
    if (nextIndex === null) return;
    event.preventDefault();
    focusMenuItem(items, items[nextIndex]);
  };

  return (
    <div ref={rootRef} className={`ai-popup-root ${rootClassName}`.trim()} title={triggerTitle}>
      <button
        ref={triggerRef}
        id={triggerId}
        type="button"
        className={`ai-popup-trigger ${triggerClassName}`.trim()}
        disabled={disabled}
        title={triggerTitle}
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => (open ? close() : openWithFocus("selected"))}
        onKeyDown={onTriggerKeyDown}
      >
        {trigger}
      </button>
      {open ? (
        <div
          ref={menuRef}
          id={menuId}
          role="menu"
          aria-labelledby={triggerId}
          className={`ai-popup-menu ai-popup-menu-${placement}`}
          onKeyDown={onMenuKeyDown}
        >
          {children(close)}
        </div>
      ) : null}
    </div>
  );
}
