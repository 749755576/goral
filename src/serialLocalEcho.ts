function normalizeSerialLocalEchoLineEndings(data: string): string {
  let output = "";
  for (let index = 0; index < data.length; index += 1) {
    const character = data[index];
    if (character === "\r") {
      output += "\r\n";
      if (data[index + 1] === "\n") index += 1;
    } else if (character === "\n") {
      output += "\r\n";
    } else {
      output += character;
    }
  }
  return output;
}

/** Mirrors the legacy Serial local-echo rendering rules. */
export function formatSerialLocalEcho(data: string): string {
  if (!data) return "";
  if (data === "\x7f" || data === "\b") return "\b \b";
  if (data === "\x03") return "^C";
  if (data === "\r" || data === "\n" || data.charCodeAt(0) >= 32 || data.length > 1) {
    return normalizeSerialLocalEchoLineEndings(data);
  }
  return "";
}
