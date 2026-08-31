import { useEffect } from "react";

/**
 * Interface font selection.
 *
 * This setting has always been persisted and validated, but nothing ever
 * applied it to the document, so choosing a font in Settings did nothing.
 * The hook below closes that gap by writing the resolved stack onto the
 * `--ld-font-ui` custom property that every stylesheet now reads from.
 *
 * Terminal font selection is deliberately NOT handled here. That remains
 * owned by `terminalAppearance.ts`, which sets it on the xterm instance
 * directly so per-host and per-session overrides keep winning.
 */

export const DEFAULT_UI_FONT_FAMILY_ID = "inter";

/**
 * Each stack ends in the platform Han face rather than in Inter, so Latin
 * and CJK keep their own vertical metrics instead of one being synthesised
 * from the other.
 */
const CJK_TAIL = '"PingFang SC", "Microsoft YaHei UI", "Microsoft YaHei"';

const UI_FONT_STACKS: Record<string, string> = {
  inter: `"Inter Variable", "Inter", -apple-system, BlinkMacSystemFont, "SF Pro Text", ${CJK_TAIL}, "Segoe UI", system-ui, sans-serif`,
  system: `-apple-system, BlinkMacSystemFont, "Segoe UI Variable Text", "Segoe UI", ${CJK_TAIL}, system-ui, sans-serif`,
  menlo: `"Cascadia Code", "Cascadia Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, ${CJK_TAIL}, monospace`,
};

/**
 * Resolves a stored id to a font stack.
 *
 * Unknown ids fall back to the default rather than being written through.
 * That is what retires the legacy `"mona-sans"` value: Mona Sans is no
 * longer bundled, so a profile still holding that id resolves to Inter
 * instead of to a family the app cannot load.
 */
export function resolveUiFontStack(fontFamilyId: string): string {
  return UI_FONT_STACKS[fontFamilyId] ?? UI_FONT_STACKS[DEFAULT_UI_FONT_FAMILY_ID];
}

export function isKnownUiFontFamilyId(fontFamilyId: string): boolean {
  return Object.hasOwn(UI_FONT_STACKS, fontFamilyId);
}

/** Keeps `--ld-font-ui` on the document root in sync with the setting. */
export function useUiFontFamily(fontFamilyId: string): void {
  useEffect(() => {
    document.documentElement.style.setProperty(
      "--ld-font-ui",
      resolveUiFontStack(fontFamilyId),
    );
  }, [fontFamilyId]);
}
