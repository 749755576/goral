export type SerialLineBufferRef = {
  current: string;
};

export type SerialLineModeInputOptions = {
  bufferRef: SerialLineBufferRef;
  localEcho?: boolean;
  writeToSession: (data: string) => void;
  writeToTerminal: (data: string) => void;
};

function submitLine(options: SerialLineModeInputOptions): void {
  options.writeToSession(`${options.bufferRef.current}\r`);
  options.bufferRef.current = "";
  if (options.localEcho) options.writeToTerminal("\r\n");
}

function appendText(text: string, options: SerialLineModeInputOptions): void {
  if (!text) return;
  options.bufferRef.current += text;
  if (options.localEcho) options.writeToTerminal(text);
}

function clearLine(options: SerialLineModeInputOptions): void {
  if (options.localEcho && options.bufferRef.current.length > 0) {
    options.writeToTerminal("\b \b".repeat(options.bufferRef.current.length));
  }
  options.bufferRef.current = "";
}

/** Buffers Serial input until Enter while preserving legacy editing behavior. */
export function handleSerialLineModeInput(
  data: string,
  options: SerialLineModeInputOptions,
): void {
  if (data === "\r" || data === "\n") {
    submitLine(options);
    return;
  }

  if (data === "\x7f" || data === "\b") {
    if (options.bufferRef.current.length > 0) {
      options.bufferRef.current = options.bufferRef.current.slice(0, -1);
      if (options.localEcho) options.writeToTerminal("\b \b");
    }
    return;
  }

  if (data === "\x03") {
    options.bufferRef.current = "";
    options.writeToSession(data);
    if (options.localEcho) options.writeToTerminal("^C\r\n");
    return;
  }

  if (data === "\x15") {
    clearLine(options);
    return;
  }

  const normalizedData = data.replace(/\r\n/g, "\r").replace(/\n/g, "\r");
  if (normalizedData.includes("\r")) {
    const parts = normalizedData.split("\r");
    parts.forEach((part, index) => {
      appendText(part, options);
      if (index < parts.length - 1) submitLine(options);
    });
    return;
  }

  if (data.charCodeAt(0) >= 32 || data.length > 1) appendText(data, options);
}
