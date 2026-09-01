import { invoke, isTauri } from "@tauri-apps/api/core";
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
  if (isSettingsWindowTarget(nativeMarker.__GORAL_SETTINGS_TARGET__)) {
    return nativeMarker.__GORAL_SETTINGS_TARGET__;
  }

  // The browser preview has no native initialization script.  Preserve the
  // deep-link target in the URL so opening AI settings from the preview lands
  // on the same page as the desktop window instead of silently losing the
  // requested anchor.
  if (typeof window !== "undefined") {
    const target = new URLSearchParams(window.location.search).get("target");
    return isSettingsWindowTarget(target) ? target : null;
  }
  return null;
}

export function openSettingsWindow(locale: Locale, target?: SettingsWindowTarget): Promise<void> {
  if (!isTauri()) {
    const url = new URL(window.location.href);
    url.searchParams.set("window", "settings");
    if (target) url.searchParams.set("target", target);
    else url.searchParams.delete("target");
    // A full navigation intentionally remounts the route, matching the
    // separate native Settings WebView while remaining usable in previews.
    window.location.assign(url.toString());
    return Promise.resolve();
  }
  return invoke<void>(SETTINGS_WINDOW_COMMANDS.open, target ? { locale, target } : { locale });
}

export function hideSettingsWindow(): Promise<void> {
  if (!isTauri()) {
    const url = new URL(window.location.href);
    url.searchParams.delete("window");
    url.searchParams.delete("target");
    window.location.assign(url.toString());
    return Promise.resolve();
  }
  return invoke<void>(SETTINGS_WINDOW_COMMANDS.hide);
}

export function isSettingsWindowLocation(locationLike: Pick<Location, "search"> = window.location): boolean {
  const nativeMarker = globalThis as typeof globalThis & {
    __GORAL_SETTINGS_WINDOW__?: boolean;
  };
  return nativeMarker.__GORAL_SETTINGS_WINDOW__ === true
    || new URLSearchParams(locationLike.search).get("window") === "settings";
}
