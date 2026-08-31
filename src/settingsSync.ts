export type SettingsReloadCoordinator<T> = Readonly<{
  reload: () => Promise<boolean>;
  dispose: () => void;
}>;

export type SettingsReloadCoordinatorOptions<T> = Readonly<{
  load: () => Promise<T>;
  apply: (snapshot: T) => void;
  onLatestError?: () => void;
}>;

/**
 * Serial numbers, rather than request completion order, decide which load may
 * update the renderer. A slow pre-notification load therefore cannot replace a
 * newer snapshot after a second window commits Settings.
 */
export const createSettingsReloadCoordinator = <T>({
  load,
  apply,
  onLatestError,
}: SettingsReloadCoordinatorOptions<T>): SettingsReloadCoordinator<T> => {
  let requestGeneration = 0;
  let disposed = false;

  return Object.freeze({
    async reload(): Promise<boolean> {
      const generation = ++requestGeneration;
      try {
        const snapshot = await load();
        if (disposed || generation !== requestGeneration) return false;
        apply(snapshot);
        return true;
      } catch {
        if (!disposed && generation === requestGeneration) onLatestError?.();
        return false;
      }
    },
    dispose(): void {
      disposed = true;
      requestGeneration += 1;
    },
  });
};
