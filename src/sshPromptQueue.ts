import type {
  HostKeyPrompt,
  InteractivePrompt,
} from "./backend.ts";
import type { WorkspaceSessionId } from "./terminalSessionRegistry.ts";

export const MAX_PENDING_SSH_PROMPTS = 64;

export type QueuedHostKeyPrompt = Readonly<{
  kind: "hostKey";
  key: string;
  workspaceSessionId: WorkspaceSessionId | null;
  prompt: Readonly<HostKeyPrompt>;
}>;

export type FrozenInteractivePrompt = Readonly<
  Omit<InteractivePrompt, "prompts">
  & {
    prompts: readonly Readonly<InteractivePrompt["prompts"][number]>[];
  }
>;

export type QueuedInteractivePrompt = Readonly<{
  kind: "interactive";
  key: string;
  workspaceSessionId: WorkspaceSessionId | null;
  prompt: FrozenInteractivePrompt;
}>;

export type QueuedSshPrompt = QueuedHostKeyPrompt | QueuedInteractivePrompt;

export type SshPromptQueueSnapshot = Readonly<{
  prompts: readonly QueuedSshPrompt[];
  current: QueuedSshPrompt | null;
}>;

export type SshPromptQueueDependencies = Readonly<{
  resolveAttempt: (clientAttemptId: string) => WorkspaceSessionId | null;
  isInternalAttempt?: (clientAttemptId: string) => boolean;
  rejectHostKey: (requestId: string) => Promise<void>;
  cancelInteractive: (requestId: string) => Promise<void>;
  limit?: number;
}>;

export type SshPromptQueueListener = (snapshot: SshPromptQueueSnapshot) => void;

const emptySnapshot = (): SshPromptQueueSnapshot => Object.freeze({
  prompts: Object.freeze([]),
  current: null,
});

const freezeHostKeyPrompt = (prompt: HostKeyPrompt): Readonly<HostKeyPrompt> => Object.freeze({
  ...prompt,
});

const freezeInteractivePrompt = (
  prompt: InteractivePrompt,
): FrozenInteractivePrompt => Object.freeze({
  ...prompt,
  prompts: Object.freeze(prompt.prompts.map((item) => Object.freeze({ ...item }))),
});

const freezeSnapshot = (prompts: readonly QueuedSshPrompt[]): SshPromptQueueSnapshot => {
  const frozenPrompts = Object.freeze([...prompts]);
  return Object.freeze({
    prompts: frozenPrompts,
    current: frozenPrompts[0] ?? null,
  });
};

const promptKey = (kind: QueuedSshPrompt["kind"], requestId: string): string => (
  `${kind}:${requestId}`
);

/**
 * Window-wide FIFO for SSH host-key and interactive prompts.
 *
 * Prompts are routed by the renderer-generated clientAttemptId. Unknown or
 * retired attempts are rejected at the native broker instead of falling
 * through to whichever terminal tab happens to be active.
 */
export class SshPromptQueue {
  readonly #dependencies: SshPromptQueueDependencies;
  readonly #limit: number;
  readonly #listeners = new Set<SshPromptQueueListener>();
  #snapshot = emptySnapshot();
  #disposed = false;

  constructor(dependencies: SshPromptQueueDependencies) {
    const limit = dependencies.limit ?? MAX_PENDING_SSH_PROMPTS;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_PENDING_SSH_PROMPTS) {
      throw new Error("SSH_PROMPT_QUEUE_LIMIT_INVALID");
    }
    this.#dependencies = dependencies;
    this.#limit = limit;
  }

  get snapshot(): SshPromptQueueSnapshot {
    return this.#snapshot;
  }

  subscribe(listener: SshPromptQueueListener): () => void {
    if (this.#disposed) throw new Error("SSH_PROMPT_QUEUE_DISPOSED");
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  #commit(prompts: readonly QueuedSshPrompt[]): void {
    this.#snapshot = freezeSnapshot(prompts);
    for (const listener of [...this.#listeners]) {
      try {
        listener(this.#snapshot);
      } catch {
        // Presentation observers cannot retain or redirect broker authority.
      }
    }
  }

  #reject(prompt: QueuedSshPrompt): void {
    try {
      const rejection = prompt.kind === "hostKey"
        ? this.#dependencies.rejectHostKey(prompt.prompt.requestId)
        : this.#dependencies.cancelInteractive(prompt.prompt.requestId);
      void rejection.catch(() => undefined);
    } catch {
      // The native broker/window shutdown path will reject remaining requests.
    }
  }

  #route(clientAttemptId: string): WorkspaceSessionId | null | undefined {
    try {
      const workspaceSessionId = this.#dependencies.resolveAttempt(clientAttemptId);
      if (workspaceSessionId) return workspaceSessionId;
      if (this.#dependencies.isInternalAttempt?.(clientAttemptId) === true) return null;
      return undefined;
    } catch {
      return undefined;
    }
  }

  #enqueue(prompt: QueuedSshPrompt): boolean {
    if (this.#disposed) {
      this.#reject(prompt);
      return false;
    }
    if (this.#snapshot.prompts.some((queued) => queued.key === prompt.key)) {
      // Broadcast redelivery of the same request must not create two dialogs
      // or answer the native one-shot twice.
      return false;
    }
    if (this.#snapshot.prompts.length >= this.#limit) {
      this.#reject(prompt);
      return false;
    }
    this.#commit([...this.#snapshot.prompts, prompt]);
    return true;
  }

  enqueueHostKey(prompt: HostKeyPrompt): boolean {
    const workspaceSessionId = this.#route(prompt.clientAttemptId);
    const queued: QueuedHostKeyPrompt = Object.freeze({
      kind: "hostKey",
      key: promptKey("hostKey", prompt.requestId),
      workspaceSessionId: workspaceSessionId ?? null,
      prompt: freezeHostKeyPrompt(prompt),
    });
    if (workspaceSessionId === undefined) {
      this.#reject(queued);
      return false;
    }
    return this.#enqueue(queued);
  }

  enqueueInteractive(prompt: InteractivePrompt): boolean {
    const workspaceSessionId = this.#route(prompt.clientAttemptId);
    const queued: QueuedInteractivePrompt = Object.freeze({
      kind: "interactive",
      key: promptKey("interactive", prompt.requestId),
      workspaceSessionId: workspaceSessionId ?? null,
      prompt: freezeInteractivePrompt(prompt),
    });
    if (workspaceSessionId === undefined) {
      this.#reject(queued);
      return false;
    }
    return this.#enqueue(queued);
  }

  complete(kind: QueuedSshPrompt["kind"], requestId: string): boolean {
    const key = promptKey(kind, requestId);
    const next = this.#snapshot.prompts.filter((prompt) => prompt.key !== key);
    if (next.length === this.#snapshot.prompts.length) return false;
    this.#commit(next);
    return true;
  }

  /** Rejects queued prompts whose exact attempt/runtime has been retired. */
  prune(): number {
    const retained: QueuedSshPrompt[] = [];
    const rejected: QueuedSshPrompt[] = [];
    for (const queued of this.#snapshot.prompts) {
      if (queued.workspaceSessionId === null) {
        retained.push(queued);
        continue;
      }
      const currentOwner = this.#dependencies.resolveAttempt(
        queued.prompt.clientAttemptId,
      );
      if (currentOwner === queued.workspaceSessionId) retained.push(queued);
      else rejected.push(queued);
    }
    if (rejected.length === 0) return 0;
    this.#commit(retained);
    for (const prompt of rejected) this.#reject(prompt);
    return rejected.length;
  }

  dispose(): void {
    if (this.#disposed) return;
    const pending = this.#snapshot.prompts;
    this.#disposed = true;
    this.#listeners.clear();
    this.#snapshot = emptySnapshot();
    for (const prompt of pending) this.#reject(prompt);
  }
}
