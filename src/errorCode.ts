/**
 * Backend commands currently expose a stable error code followed by an
 * optional human-readable detail (`CODE: detail`).  Keep parsing in one place
 * so a wording change cannot silently bypass a renderer recovery path.
 */
export function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function hasErrorCode(error: unknown, code: string): boolean {
  const rendered = errorText(error).trim();
  if (!rendered || !code) return false;
  if (rendered === code || rendered.startsWith(`${code}:`)) return true;
  // Some older adapters joined multiple coded errors with `;` or a newline.
  return rendered.split(/[;\n]/u).some((part) => {
    const candidate = part.trim();
    return candidate === code || candidate.startsWith(`${code}:`);
  });
}
