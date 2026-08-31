export type LocalTerminalCwdPlatform = "windows" | "posix";

const MAX_CWD_BYTES = 4_096;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/;
const WINDOWS_DRIVE_PATH = /^[A-Za-z]:[\\/]/;
const WINDOWS_FILE_URL_PATH = /^\/[A-Za-z]:\//;
const WINDOWS_INVALID_CHARACTER = /[<>"|?*]/;

const hasBoundedText = (value: string): boolean => (
  value.length > 0
  && !CONTROL_CHARACTER.test(value)
  && new TextEncoder().encode(value).length <= MAX_CWD_BYTES
);

const hasTraversalSegment = (value: string): boolean => (
  value.split(/[\\/]/).some((segment) => segment === "." || segment === "..")
);

/**
 * Accepts only an absolute path in the host OS namespace. In particular, a
 * terminal escape cannot select a UNC share or a Windows device namespace.
 */
export const normalizeTrustedLocalCwd = (
  value: string,
  platform: LocalTerminalCwdPlatform,
): string | null => {
  if (!hasBoundedText(value) || hasTraversalSegment(value)) return null;
  if (platform === "windows") {
    if (
      !WINDOWS_DRIVE_PATH.test(value)
      || value.startsWith("\\\\")
      || WINDOWS_INVALID_CHARACTER.test(value.slice(2))
    ) return null;
    return `${value[0]!.toUpperCase()}:${value.slice(2).replaceAll("/", "\\")}`;
  }
  if (!value.startsWith("/") || value.startsWith("//") || value.includes("\\")) {
    return null;
  }
  return value;
};

/**
 * Parses xterm's payload for OSC 7 (`file://host/path`). The URI authority is
 * deliberately discarded: it is descriptive shell metadata, never authority
 * to turn a local split into a UNC/network launch.
 */
export const parseTrustedLocalOsc7Cwd = (
  payload: string,
  platform: LocalTerminalCwdPlatform,
): string | null => {
  if (!hasBoundedText(payload) || !/^file:\/\//i.test(payload)) return null;
  try {
    // URL canonicalization removes dot segments, so reject them before URL
    // parsing (including percent-encoded spellings) instead of blessing the
    // canonicalized escape target.
    if (hasTraversalSegment(decodeURIComponent(payload))) return null;
    const url = new URL(payload);
    if (
      url.protocol !== "file:"
      || url.username
      || url.password
      || url.port
      || url.search
      || url.hash
    ) return null;
    let path = decodeURIComponent(url.pathname);
    if (platform === "windows") {
      if (!WINDOWS_FILE_URL_PATH.test(path)) return null;
      path = path.slice(1);
    }
    return normalizeTrustedLocalCwd(path, platform);
  } catch {
    return null;
  }
};

/** Windows Terminal/ConEmu current-directory extension: OSC 9;9;<path>. */
export const parseTrustedLocalOsc9Cwd = (
  payload: string,
  platform: LocalTerminalCwdPlatform,
): string | null => {
  if (!payload.startsWith("9;")) return null;
  return normalizeTrustedLocalCwd(payload.slice(2), platform);
};
