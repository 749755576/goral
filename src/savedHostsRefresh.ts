export type CoalescedRefreshOptions = Readonly<{
  queueFollowUp?: boolean;
}>;

export type CoalescedRefresh<TInput, TOutput> = Readonly<{
  isRunning: () => boolean;
  request: (
    input: TInput,
    options?: CoalescedRefreshOptions,
  ) => Promise<TOutput>;
}>;

/**
 * Shares one refresh with every concurrent caller. A caller that knows the
 * underlying data changed while that refresh was running may request one
 * trailing pass. Further requests, including requests made during that
 * trailing pass, share the same flight instead of creating a refresh storm.
 */
export const createCoalescedRefresh = <TInput, TOutput>(
  operation: (input: TInput) => Promise<TOutput>,
): CoalescedRefresh<TInput, TOutput> => {
  let activeFlight: Promise<TOutput> | null = null;
  let followUpRequested = false;
  let followUpStarted = false;
  let followUpInput: TInput | undefined;

  const request = (
    input: TInput,
    options: CoalescedRefreshOptions = {},
  ): Promise<TOutput> => {
    if (activeFlight) {
      if (options.queueFollowUp && !followUpStarted) {
        followUpRequested = true;
        followUpInput = input;
      }
      return activeFlight;
    }

    followUpRequested = false;
    followUpStarted = false;
    followUpInput = undefined;

    const execute = async (): Promise<TOutput> => {
      let firstResult: TOutput | undefined;
      let firstFailure: unknown;
      let firstFailed = false;
      try {
        firstResult = await operation(input);
      } catch (reason) {
        firstFailed = true;
        firstFailure = reason;
      }

      if (followUpRequested) {
        followUpStarted = true;
        return operation(followUpInput as TInput);
      }
      if (firstFailed) {
        throw firstFailure;
      }
      return firstResult as TOutput;
    };

    const flight = execute();
    const settledFlight = flight.finally(() => {
      if (activeFlight === settledFlight) {
        activeFlight = null;
        followUpRequested = false;
        followUpStarted = false;
        followUpInput = undefined;
      }
    });
    activeFlight = settledFlight;
    return settledFlight;
  };

  return Object.freeze({
    isRunning: () => activeFlight !== null,
    request,
  });
};

export const shouldShowSavedHostsInitialLoader = (
  loading: boolean,
  hasSnapshot: boolean,
): boolean => loading && !hasSnapshot;

export const shouldShowSavedHostsBackgroundRefresh = (
  loading: boolean,
  hasSnapshot: boolean,
): boolean => loading && hasSnapshot;
