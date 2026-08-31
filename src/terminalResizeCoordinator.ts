import type { TerminalSize } from "./backend";

export type TerminalResizeTransport = (
  sessionId: string,
  size: TerminalSize,
) => Promise<void>;

export type TerminalResizeFrameScheduler = Readonly<{
  request: (callback: () => void) => number;
  cancel: (frameId: number) => void;
}>;

export type TerminalResizeCoordinator = Readonly<{
  request: (sessionId: string, size: TerminalSize) => void;
  reset: () => void;
  dispose: () => void;
}>;

type PendingResize = Readonly<{
  sessionId: string;
  size: TerminalSize;
}>;

const sameResize = (
  left: PendingResize | null,
  right: PendingResize,
): boolean => left !== null
  && left.sessionId === right.sessionId
  && left.size.columns === right.size.columns
  && left.size.rows === right.size.rows
  && left.size.pixelWidth === right.size.pixelWidth
  && left.size.pixelHeight === right.size.pixelHeight;

const copyResize = (sessionId: string, size: TerminalSize): PendingResize => ({
  sessionId,
  size: {
    columns: size.columns,
    rows: size.rows,
    pixelWidth: size.pixelWidth,
    pixelHeight: size.pixelHeight,
  },
});

/**
 * Coalesces xterm ResizeObserver bursts to one request per animation frame and
 * keeps native resize commands strictly ordered. A new session invalidates all
 * queued and completed dimensions from the previous owner.
 */
export function createTerminalResizeCoordinator(
  transport: TerminalResizeTransport,
  scheduler: TerminalResizeFrameScheduler = {
    request: (callback) => window.requestAnimationFrame(callback),
    cancel: (frameId) => window.cancelAnimationFrame(frameId),
  },
): TerminalResizeCoordinator {
  let disposed = false;
  let generation = 0;
  let ownerSessionId: string | null = null;
  let scheduledFrame: number | null = null;
  let pending: PendingResize | null = null;
  let inFlight: PendingResize | null = null;
  let lastCompleted: PendingResize | null = null;

  const cancelScheduledFrame = () => {
    if (scheduledFrame === null) return;
    scheduler.cancel(scheduledFrame);
    scheduledFrame = null;
  };

  const schedule = () => {
    if (disposed || scheduledFrame !== null || inFlight !== null || pending === null) return;
    const scheduledGeneration = generation;
    scheduledFrame = scheduler.request(() => {
      scheduledFrame = null;
      if (disposed || generation !== scheduledGeneration || inFlight !== null) return;
      const next = pending;
      pending = null;
      if (!next || sameResize(lastCompleted, next)) {
        schedule();
        return;
      }

      inFlight = next;
      void transport(next.sessionId, next.size).then(
        () => {
          if (!disposed && generation === scheduledGeneration) lastCompleted = next;
        },
        () => undefined,
      ).finally(() => {
        if (inFlight === next) inFlight = null;
        schedule();
      });
    });
  };

  const reset = () => {
    generation += 1;
    ownerSessionId = null;
    pending = null;
    lastCompleted = null;
    cancelScheduledFrame();
  };

  return {
    request(sessionId, size) {
      if (disposed || sessionId.length === 0) return;
      const next = copyResize(sessionId, size);
      if (ownerSessionId !== sessionId) {
        generation += 1;
        ownerSessionId = sessionId;
        pending = null;
        lastCompleted = null;
        cancelScheduledFrame();
      }
      if (
        sameResize(pending, next)
        || (pending === null && sameResize(inFlight, next))
        || (pending === null && inFlight === null && sameResize(lastCompleted, next))
      ) return;
      pending = next;
      schedule();
    },
    reset,
    dispose() {
      if (disposed) return;
      reset();
      disposed = true;
    },
  };
}
