export type SerialBackspaceBehavior = "default" | "ctrl-h";

export type SerialConfigBackspaceLike = {
  backspaceBehavior?: SerialBackspaceBehavior;
};

export type SerialHostBackspaceLike = {
  serialConfig?: SerialConfigBackspaceLike;
  backspaceBehavior?: SerialBackspaceBehavior;
};

export function mapTerminalBackspaceInput(
  data: string,
  behavior: SerialBackspaceBehavior | undefined,
): string {
  return data === "\x7f" && behavior === "ctrl-h" ? "\x08" : data;
}

export function prepareSerialConfigForSavedHost<T extends SerialConfigBackspaceLike>(config: T): T {
  if (config.backspaceBehavior === "ctrl-h") return { ...config };
  const { backspaceBehavior: _omitted, ...rest } = config;
  return rest as T;
}

export function resolveSerialBackspaceFormValue(
  host: SerialHostBackspaceLike,
  groupDefaults?: { backspaceBehavior?: SerialBackspaceBehavior },
): SerialBackspaceBehavior {
  return (
    host.serialConfig?.backspaceBehavior
    ?? (host.backspaceBehavior === "ctrl-h" ? "ctrl-h" : undefined)
    ?? (groupDefaults?.backspaceBehavior === "ctrl-h" ? "ctrl-h" : "default")
  );
}

export function resolveSerialBackspaceOverrideOnSave({
  initialHost,
  selectedBehavior,
  behaviorChanged,
}: {
  initialHost: SerialHostBackspaceLike;
  selectedBehavior: SerialBackspaceBehavior;
  behaviorChanged: boolean;
}): SerialBackspaceBehavior | undefined {
  const hasExplicitBehavior = initialHost.serialConfig?.backspaceBehavior !== undefined
    || initialHost.backspaceBehavior === "ctrl-h";
  return hasExplicitBehavior || behaviorChanged ? selectedBehavior : undefined;
}
