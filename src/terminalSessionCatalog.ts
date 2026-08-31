import {
  activateTerminalSessionSnapshot,
  addTerminalSessionSnapshot,
  createTerminalSessionRegistrySnapshot,
  MAX_WORKSPACE_SESSIONS,
  removeTerminalSessionSnapshot,
  updateTerminalSessionSnapshot,
  type CreateTerminalSessionSnapshot,
  type TerminalSessionRegistrySnapshot,
  type TerminalSessionSnapshotUpdate,
  type WorkspaceSessionId,
} from "./terminalSessionRegistry.ts";

export type TerminalSessionCatalogListener = (
  snapshot: TerminalSessionRegistrySnapshot,
  previous: TerminalSessionRegistrySnapshot,
) => void;

/**
 * The single renderer authority for terminal tab order and activation.
 *
 * Protocol controllers keep their own non-serializable runtimes, but share
 * this catalog so the global session limit, active tab, and removal-neighbour
 * behavior cannot diverge between controllers.
 */
export interface TerminalSessionCatalog {
  readonly snapshot: TerminalSessionRegistrySnapshot;
  add: (
    input: CreateTerminalSessionSnapshot,
    options?: Readonly<{ activate?: boolean }>,
  ) => TerminalSessionRegistrySnapshot;
  activate: (id: WorkspaceSessionId) => TerminalSessionRegistrySnapshot;
  update: (
    id: WorkspaceSessionId,
    update: TerminalSessionSnapshotUpdate,
  ) => TerminalSessionRegistrySnapshot;
  remove: (id: WorkspaceSessionId) => TerminalSessionRegistrySnapshot;
  subscribe: (listener: TerminalSessionCatalogListener) => () => void;
}

class InMemoryTerminalSessionCatalog implements TerminalSessionCatalog {
  readonly #limit: number;
  readonly #listeners = new Set<TerminalSessionCatalogListener>();
  #snapshot = createTerminalSessionRegistrySnapshot();

  constructor(limit: number) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_WORKSPACE_SESSIONS) {
      throw new Error("WORKSPACE_SESSION_LIMIT_INVALID");
    }
    this.#limit = limit;
  }

  get snapshot(): TerminalSessionRegistrySnapshot {
    return this.#snapshot;
  }

  #commit(next: TerminalSessionRegistrySnapshot): TerminalSessionRegistrySnapshot {
    if (next === this.#snapshot) return this.#snapshot;
    const previous = this.#snapshot;
    this.#snapshot = next;
    for (const listener of [...this.#listeners]) {
      try {
        listener(next, previous);
      } catch {
        // A presentation observer cannot roll back or block catalog authority.
      }
    }
    return next;
  }

  add(
    input: CreateTerminalSessionSnapshot,
    options: Readonly<{ activate?: boolean }> = {},
  ): TerminalSessionRegistrySnapshot {
    return this.#commit(addTerminalSessionSnapshot(this.#snapshot, input, {
      ...options,
      limit: this.#limit,
    }));
  }

  activate(id: WorkspaceSessionId): TerminalSessionRegistrySnapshot {
    return this.#commit(activateTerminalSessionSnapshot(this.#snapshot, id));
  }

  update(
    id: WorkspaceSessionId,
    update: TerminalSessionSnapshotUpdate,
  ): TerminalSessionRegistrySnapshot {
    return this.#commit(updateTerminalSessionSnapshot(this.#snapshot, id, update));
  }

  remove(id: WorkspaceSessionId): TerminalSessionRegistrySnapshot {
    return this.#commit(removeTerminalSessionSnapshot(this.#snapshot, id));
  }

  subscribe(listener: TerminalSessionCatalogListener): () => void {
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }
}

export const createTerminalSessionCatalog = (
  options: Readonly<{ limit?: number }> = {},
): TerminalSessionCatalog => new InMemoryTerminalSessionCatalog(
  options.limit ?? MAX_WORKSPACE_SESSIONS,
);
