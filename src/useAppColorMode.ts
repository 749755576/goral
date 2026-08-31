import { useEffect } from "react";

export type AppColorMode = "light" | "dark" | "system";

const SYSTEM_DARK_QUERY = "(prefers-color-scheme: dark)";

const resolveColorMode = (
  mode: AppColorMode,
  media: MediaQueryList,
): Exclude<AppColorMode, "system"> => (
  mode === "system" ? (media.matches ? "dark" : "light") : mode
);

/**
 * Keeps the renderer-safe appearance setting reflected on the document root.
 * The CSS skin consumes this attribute; terminal theme resolution remains
 * independent so per-host and per-session terminal themes continue to win.
 */
export function useAppColorMode(mode: AppColorMode): void {
  useEffect(() => {
    const media = window.matchMedia(SYSTEM_DARK_QUERY);
    const apply = () => {
      document.documentElement.dataset.goralMode = resolveColorMode(mode, media);
    };

    apply();
    if (mode !== "system") return undefined;

    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [mode]);
}
