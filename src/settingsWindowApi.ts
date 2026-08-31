import { invoke } from "@tauri-apps/api/core";
import type { Locale } from "./i18n.ts";

export const SETTINGS_WINDOW_COMMANDS = {
  open: "open_settings_window",
  hide: "hide_settings_window",
} as const;

export const SETTINGS_WINDOW_FOCUS_EVENT = "goral:settings-focus";

export type SettingsWindowTarget = "ai-providers";

export function isSettingsWindowTarget(value: unknown): value is SettingsWindowTarget {
  return value === "ai-providers";
}

export function readInitialSettingsWindowTarget(): SettingsWindowTarget | null {
  const nativeMarker = globalThis as typeof globalThis & {
    __GORAL_SETTINGS_TARGET__?: unknown;
  };
  return isSettingsWindowTarget(nativeMarker.__GORAL_SETTINGS_TARGET__)
    ? nativeMarker.__GORAL_SETTINGS_TARGET__
    : null;
}

export function openSettingsWindow(locale: Locale, target?: SettingsWindowTarget): Promise<void> {
  return invoke<void>(SETTINGS_WINDOW_COMMANDS.open, target ? { locale, target } : { locale });
}

export function hideSettingsWindow(): Promise<void> {
  return invoke<void>(SETTINGS_WINDOW_COMMANDS.hide);
}

export function isSettingsWindowLocation(locationLike: Pick<Location, "search"> = window.location): boolean {
  const nativeMarker = globalThis as typeof globalThis & {
    __GORAL_SETTINGS_WINDOW__?: boolean;
  };
  return nativeMarker.__GORAL_SETTINGS_WINDOW__ === true
    || new URLSearchParams(locationLike.search).get("window") === "settings";
}
