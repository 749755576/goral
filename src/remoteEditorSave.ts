import { hasErrorCode } from "./errorCode.ts";

export const SFTP_EDITOR_DESTINATION_CHANGED = "SFTP_EDITOR_DESTINATION_CHANGED";

export type RemoteEditorSaveResult =
  | Readonly<{ kind: "saved" }>
  | Readonly<{ kind: "conflict" }>
  | Readonly<{ kind: "failed"; cause: unknown }>
  | Readonly<{ kind: "busy" }>
  | Readonly<{ kind: "stale" }>;

const UTF8_BOM = Uint8Array.of(0xef, 0xbb, 0xbf);

export const hasUtf8Bom = (bytes: Uint8Array): boolean =>
  bytes.length >= UTF8_BOM.length
  && bytes[0] === UTF8_BOM[0]
  && bytes[1] === UTF8_BOM[1]
  && bytes[2] === UTF8_BOM[2];

/** Preserve an existing UTF-8 BOM instead of silently changing file format. */
export const encodeRemoteEditorText = (text: string, preserveBom: boolean): Uint8Array => {
  const encoded = new TextEncoder().encode(text);
  if (!preserveBom) return encoded;
  const result = new Uint8Array(UTF8_BOM.length + encoded.length);
  result.set(UTF8_BOM, 0);
  result.set(encoded, UTF8_BOM.length);
  return result;
};

/**
 * Converts the native conditional-write contract into renderer-owned states.
 * Provider/transport wording never decides whether a conflict is recognized;
 * only the stable native code does.
 */
export async function persistRemoteEditorDraft(
  write: () => Promise<void>,
): Promise<RemoteEditorSaveResult> {
  try {
    await write();
    return { kind: "saved" };
  } catch (cause) {
    if (hasErrorCode(cause, SFTP_EDITOR_DESTINATION_CHANGED)) {
      return { kind: "conflict" };
    }
    return { kind: "failed", cause };
  }
}

/**
 * The sole save-and-close gate. A rejected write, a conflict, a disconnected
 * session, a stale editor generation, or an already-running save all leave
 * the editor mounted with its draft intact.
 */
export async function closeAfterSuccessfulRemoteEditorSave(
  save: () => Promise<RemoteEditorSaveResult>,
  onClose: () => void,
): Promise<RemoteEditorSaveResult> {
  const result = await save();
  if (result.kind === "saved") onClose();
  return result;
}
