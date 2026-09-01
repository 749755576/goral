/**
 * Parse the descriptive working-directory notifications emitted by remote
 * shells.  The value is used only as an SFTP navigation target; it is never
 * treated as a local filesystem path or as command authority.
 */

const MAX_REMOTE_CWD_BYTES = 4_096;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/u;

const hasBoundedText = (value: string): boolean => (
  typeof value === "string"
  && value.length > 0
  && !CONTROL_CHARACTER.test(value)
  && new TextEncoder().encode(value).byteLength <= MAX_REMOTE_CWD_BYTES
);

const hasTraversalSegment = (value: string): boolean => (
  value.split(/[\\/]/u).some((segment) => segment === "." || segment === "..")
);

/**
 * Remote SFTP paths are absolute POSIX-style paths in the normal case.  A
 * drive-qualified absolute path is also accepted for SFTP servers backed by
 * Windows, but UNC/device namespaces and traversal segments are rejected.
 */
export const normalizeRemoteTerminalCwd = (value: string): string | null => {
  if (!hasBoundedText(value) || hasTraversalSegment(value)) return null;
  if (/^[A-Za-z]:[\\/]/u.test(value)) {
    if (value.startsWith("\\\\") || /[<>"|?*]/u.test(value.slice(2))) return null;
    return `${value[0]!.toUpperCase()}:${value.slice(2).replaceAll("\\", "/")}`;
  }
  if (!value.startsWith("/") || value.startsWith("//") || value.includes("\\")) return null;
  return value;
};

/** Parse an OSC 7 payload (`file://host/path`) without trusting its authority. */
export const parseRemoteTerminalOsc7Cwd = (payload: string): string | null => {
  if (!hasBoundedText(payload) || !/^file:\/\//iu.test(payload)) return null;
  try {
    // Reject dot segments before URL canonicalization can erase them.
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
    return normalizeRemoteTerminalCwd(decodeURIComponent(url.pathname));
  } catch {
    return null;
  }
};

/** Parse an OSC 9;9 payload used by a few remote shell integrations. */
export const parseRemoteTerminalOsc9Cwd = (payload: string): string | null => {
  if (!hasBoundedText(payload) || !payload.startsWith("9;")) return null;
  return normalizeRemoteTerminalCwd(payload.slice(2));
};

