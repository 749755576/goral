import type { ITerminalAddon, ITheme, Terminal } from "@xterm/xterm";

import type { RendererSafeSettings } from "./settingsUi";

export type TerminalRendererPreference = RendererSafeSettings["terminal"]["renderer"];
export type TerminalSettings = RendererSafeSettings["terminal"];

export type TerminalTheme = {
  id: "netcatty-dark" | "netcatty-light";
  name: string;
  type: "dark" | "light";
  theme: Readonly<ITheme>;
};

const NETCATTY_DARK: TerminalTheme = {
  id: "netcatty-dark",
  name: "Goral Dark",
  type: "dark",
  theme: Object.freeze({
    background: "#0d1117",
    foreground: "#c9d1d9",
    cursor: "#58a6ff",
    selectionBackground: "#264f78",
    black: "#0d1117",
    red: "#ff7b72",
    green: "#3fb950",
    yellow: "#d29922",
    blue: "#58a6ff",
    magenta: "#bc8cff",
    cyan: "#39c5cf",
    white: "#b1bac4",
    brightBlack: "#6e7681",
    brightRed: "#ffa198",
    brightGreen: "#56d364",
    brightYellow: "#e3b341",
    brightBlue: "#79c0ff",
    brightMagenta: "#d2a8ff",
    brightCyan: "#56d4dd",
    brightWhite: "#f0f6fc",
    scrollbarSliderBackground: "#c9d1d933",
    scrollbarSliderHoverBackground: "#c9d1d966",
    scrollbarSliderActiveBackground: "#c9d1d980",
  }),
};

const NETCATTY_LIGHT: TerminalTheme = {
  id: "netcatty-light",
  name: "Goral Light",
  type: "light",
  theme: Object.freeze({
    background: "#f6f8fa",
    foreground: "#24292f",
    cursor: "#0969da",
    selectionBackground: "#add6ff",
    black: "#24292f",
    red: "#cf222e",
    green: "#116329",
    yellow: "#9a6700",
    blue: "#0969da",
    magenta: "#8250df",
    cyan: "#0e7574",
    white: "#6e7781",
    brightBlack: "#57606a",
    brightRed: "#a40e26",
    brightGreen: "#1a7f37",
    brightYellow: "#7d4e00",
    brightBlue: "#218bff",
    brightMagenta: "#a475f9",
    brightCyan: "#0c7875",
    brightWhite: "#8c959f",
    scrollbarSliderBackground: "#24292f33",
    scrollbarSliderHoverBackground: "#24292f66",
    scrollbarSliderActiveBackground: "#24292f80",
  }),
};

export const TERMINAL_THEMES: readonly TerminalTheme[] = Object.freeze([
  NETCATTY_DARK,
  NETCATTY_LIGHT,
]);

const TERMINAL_THEME_BY_ID = new Map(TERMINAL_THEMES.map((theme) => [theme.id, theme]));

export type ResolvedTerminalAppearance = {
  themeId: TerminalTheme["id"];
  themeType: TerminalTheme["type"];
  background: string;
  foreground: string;
  renderer: TerminalRendererPreference;
  xtermOptions: {
    allowProposedApi: true;
    cursorBlink: boolean;
    cursorStyle: TerminalSettings["cursorStyle"];
    fontFamily: string;
    fontSize: number;
    fontWeight: number;
    fontWeightBold: number;
    lineHeight: number;
    minimumContrastRatio: number;
    scrollback: number;
    theme: ITheme;
  };
};

export type TerminalAppearanceOverride = {
  themeId?: string;
  fontFamily?: string;
  fontSize?: number;
  fontWeight?: number;
  appColorMode?: "light" | "dark";
  /** Host/GroupConfig themes yield to Follow App Theme; replay themes do not. */
  isHostAppearance?: boolean;
};

export function getTerminalTheme(themeId: string | undefined): TerminalTheme | undefined {
  return themeId === undefined
    ? undefined
    : TERMINAL_THEME_BY_ID.get(themeId as TerminalTheme["id"]);
}

function quoteFontFamily(font: string): string {
  const trimmed = font.trim();
  if (!trimmed) return "";
  return /[\s,]/.test(trimmed) && !/^(["']).*\1$/.test(trimmed)
    ? `"${trimmed.replaceAll('"', '\\"')}"`
    : trimmed;
}

export function resolveTerminalFontFamily(fontFamilyId: string, fallbackFont: string): string {
  const primary = fontFamilyId === "consolas"
    ? "Consolas"
    : fontFamilyId === "monospace"
      ? ""
      : fontFamilyId === "menlo"
        ? "Menlo"
        : quoteFontFamily(fontFamilyId);
  const fallback = quoteFontFamily(fallbackFont);
  return [primary, fallback, '"Cascadia Mono"', "Consolas", "monospace"]
    .filter((font, index, fonts) => font.length > 0 && fonts.indexOf(font) === index)
    .join(", ");
}

function finiteInRange(value: number | undefined, fallback: number, min: number, max: number): number {
  return typeof value === "number" && Number.isFinite(value)
    ? Math.min(max, Math.max(min, value))
    : fallback;
}

/** Shared live/replay resolver. Unknown imported theme IDs fail closed to the known global theme. */
export function resolveTerminalAppearance(
  settings: TerminalSettings,
  override: TerminalAppearanceOverride = {},
): ResolvedTerminalAppearance {
  const followedTheme = settings.followAppTheme && override.appColorMode !== undefined
    ? (override.appColorMode === "light" ? NETCATTY_LIGHT : NETCATTY_DARK)
    : undefined;
  const globalTheme = followedTheme ?? getTerminalTheme(settings.themeId) ?? NETCATTY_DARK;
  const selectedTheme = settings.followAppTheme && override.isHostAppearance
    ? globalTheme
    : getTerminalTheme(override.themeId) ?? globalTheme;
  const fontFamilyId = typeof override.fontFamily === "string" && override.fontFamily.trim().length > 0
    ? override.fontFamily
    : settings.fontFamilyId;
  const fontSize = finiteInRange(override.fontSize, settings.fontSize, 4, 256);
  const fontWeight = finiteInRange(override.fontWeight, settings.fontWeight, 100, 900);
  return {
    themeId: selectedTheme.id,
    themeType: selectedTheme.type,
    background: selectedTheme.theme.background ?? NETCATTY_DARK.theme.background!,
    foreground: selectedTheme.theme.foreground ?? NETCATTY_DARK.theme.foreground!,
    renderer: settings.renderer,
    xtermOptions: {
      allowProposedApi: true,
      cursorBlink: settings.cursorBlink,
      cursorStyle: settings.cursorStyle,
      fontFamily: resolveTerminalFontFamily(fontFamilyId, settings.fallbackFont),
      fontSize,
      fontWeight,
      fontWeightBold: settings.boldFontWeight,
      lineHeight: 1 + (settings.linePadding / 10),
      minimumContrastRatio: settings.minimumContrastRatio,
      scrollback: settings.scrollbackRows,
      theme: { ...selectedTheme.theme },
    },
  };
}

export function shouldAttemptWebgl(renderer: TerminalRendererPreference): boolean {
  return renderer === "auto" || renderer === "webgl";
}

export type DisposableXtermAddon = ITerminalAddon;

/** Loads WebGL opportunistically; xterm's built-in renderer remains active on every failure. */
export function tryInstallWebglAddon<T extends DisposableXtermAddon>(
  terminal: Pick<Terminal, "loadAddon">,
  renderer: TerminalRendererPreference,
  createAddon: () => T,
): T | null {
  if (!shouldAttemptWebgl(renderer)) return null;
  let addon: T | null = null;
  try {
    addon = createAddon();
    terminal.loadAddon(addon);
    return addon;
  } catch {
    try {
      addon?.dispose();
    } catch {
      // The built-in renderer is already the safe fallback.
    }
    return null;
  }
}

/** Keeps the sizeable WebGL renderer out of the startup bundle and rechecks ownership after loading. */
export async function installPreferredWebglAddon(
  terminal: Pick<Terminal, "loadAddon">,
  renderer: TerminalRendererPreference,
  isCurrent: () => boolean = () => true,
): Promise<DisposableXtermAddon | null> {
  if (!shouldAttemptWebgl(renderer)) return null;
  try {
    const { WebglAddon } = await import("@xterm/addon-webgl");
    if (!isCurrent()) return null;
    return tryInstallWebglAddon(terminal, renderer, () => new WebglAddon());
  } catch {
    return null;
  }
}

export function applyResolvedTerminalAppearance(
  terminal: Terminal,
  appearance: ResolvedTerminalAppearance,
): void {
  const options = appearance.xtermOptions;
  terminal.options.cursorBlink = options.cursorBlink;
  terminal.options.cursorStyle = options.cursorStyle;
  terminal.options.fontFamily = options.fontFamily;
  terminal.options.fontSize = options.fontSize;
  terminal.options.fontWeight = options.fontWeight as typeof terminal.options.fontWeight;
  terminal.options.fontWeightBold = options.fontWeightBold as typeof terminal.options.fontWeightBold;
  terminal.options.lineHeight = options.lineHeight;
  terminal.options.minimumContrastRatio = options.minimumContrastRatio;
  terminal.options.scrollback = options.scrollback;
  terminal.options.theme = options.theme;
}
