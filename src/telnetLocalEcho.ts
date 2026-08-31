export type QuickConnectProtocol = "ssh" | "telnet" | "mosh" | "et";

/**
 * Changes the conventional port only while the user has left the previous
 * protocol's default untouched. Custom ports belong to the user.
 */
export function resolveQuickConnectProtocolPort(
  currentPort: string,
  previousProtocol: QuickConnectProtocol,
  nextProtocol: QuickConnectProtocol,
): string {
  if (previousProtocol === nextProtocol) return currentPort;
  const previousDefault = previousProtocol === "telnet" ? "23" : "22";
  if (currentPort !== previousDefault) return currentPort;
  return nextProtocol === "telnet" ? "23" : "22";
}

/** Formats client-side Telnet echo without rendering terminal control keys. */
export function formatTelnetLocalEcho(data: string): string {
  let output = "";
  for (let index = 0; index < data.length; index += 1) {
    const character = data[index];
    if (character === "\r") {
      output += "\r\n";
      if (data[index + 1] === "\n") index += 1;
    } else if (character === "\n") {
      output += "\r\n";
    } else if (character === "\x1b") {
      if (data[index + 1] === "[" || data[index + 1] === "O") {
        index += 1;
        while (index + 1 < data.length) {
          index += 1;
          const code = data.charCodeAt(index);
          if (code >= 0x40 && code <= 0x7e) break;
        }
      } else if (index + 1 < data.length) {
        index += 1;
      }
    } else if (character === "\x7f" || character === "\b") {
      output += "\b \b";
    } else if (character === "\x03") {
      output += "^C";
    } else if (character >= " ") {
      output += character;
    }
  }
  return output;
}
