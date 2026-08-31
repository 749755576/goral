import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  cancelSshSession,
  closeSshSession,
  resizeSshSession,
  sendSshInput,
} from "./backend";
import {
  createSshClientAttemptId,
  SshTerminalSessionController,
  type SshClientAttemptId,
  type SshTerminalOpenResult,
  type SshTerminalRestoreOptions,
  type SshTerminalSessionCreated,
  type SshTerminalStart,
  type SshTerminalTarget,
} from "./sshTerminalSessionController";
import type { TerminalSessionCatalog } from "./terminalSessionCatalog";
import {
  type TerminalSessionRegistrySnapshot,
  type TerminalSessionSnapshot,
  type WorkspaceSessionId,
} from "./terminalSessionRegistry";
import type { TerminalPanePlacement } from "./terminalPaneLayout";
import {
  applyResolvedTerminalAppearance,
  installPreferredWebglAddon,
  shouldAttemptWebgl,
  type DisposableXtermAddon,
  type ResolvedTerminalAppearance,
} from "./terminalAppearance";
import { createTerminalResizeCoordinator } from "./terminalResizeCoordinator";
import type { TerminalSendTextErrorCode } from "./terminalSessionBridge";
import type { Translate } from "./i18n";

export type {
  SshClientAttemptId,
  SshTerminalOpenResult,
  SshTerminalRestoreOptions,
  SshTerminalSessionCreated,
  SshTerminalStart,
  SshTerminalTarget,
  TerminalSendTextErrorCode,
};

export type SshTerminalAppearanceResolver = (
  target: SshTerminalTarget,
) => ResolvedTerminalAppearance;

type SshTerminalViewRuntime = {
  viewport: HTMLElement | null;
  viewportObserver: ResizeObserver | null;
  opened: boolean;
  webglAddon: DisposableXtermAddon | null;
  webglGeneration: number;
  appearance: ResolvedTerminalAppearance;
};

export type UseSshTerminalSessionsResult = Readonly<{
  registry: TerminalSessionRegistrySnapshot;
  activeSession: TerminalSessionSnapshot | null;
  owns: (id: WorkspaceSessionId) => boolean;
  targetFor: (id: WorkspaceSessionId) => SshTerminalTarget | undefined;
  backendSessionIdFor: (id: WorkspaceSessionId) => string | undefined;
  operationGenerationFor: (id: WorkspaceSessionId) => number | undefined;
  appearanceFor: (id: WorkspaceSessionId) => ResolvedTerminalAppearance | undefined;
  open: (
    target: SshTerminalTarget,
    start: SshTerminalStart,
    onSessionCreated?: SshTerminalSessionCreated,
  ) => Promise<SshTerminalOpenResult>;
  restoreDisconnected: (
    id: WorkspaceSessionId,
    target: SshTerminalTarget,
    options?: SshTerminalRestoreOptions,
  ) => Promise<SshTerminalOpenResult>;
  activate: (id: WorkspaceSessionId) => void;
  retry: (id: WorkspaceSessionId, start: SshTerminalStart) => Promise<string | null>;
  disconnect: (id: WorkspaceSessionId) => Promise<string | null>;
  close: (id: WorkspaceSessionId) => Promise<string | null>;
  readSelectedText: (id: WorkspaceSessionId) => string;
  readRecentOutput: (id: WorkspaceSessionId) => string;
  sendText: (
    id: WorkspaceSessionId,
    data: string,
    expectedGeneration?: number,
  ) => Promise<TerminalSendTextErrorCode | null>;
  hasSessions: () => boolean;
  fit: (id: WorkspaceSessionId) => void;
  fitActive: () => void;
  mountViewport: (id: WorkspaceSessionId, element: HTMLElement) => void;
  unmountViewport: (id: WorkspaceSessionId, element: HTMLElement) => void;
  workspaceSessionIdForAttempt: (
    clientAttemptId: string,
  ) => WorkspaceSessionId | undefined;
  isExactAttemptRoute: (
    clientAttemptId: string,
    workspaceSessionId: WorkspaceSessionId,
  ) => boolean;
}>;

const makeViewRuntime = (
  appearance: ResolvedTerminalAppearance,
): SshTerminalViewRuntime => ({
  viewport: null,
  viewportObserver: null,
  opened: false,
  webglAddon: null,
  webglGeneration: 0,
  appearance,
});

/**
 * Owns only this hook's SSH runtimes while observing one shared, global tab catalog.
 * The caller supplies a target-aware appearance resolver so SavedHost/GroupConfig
 * projection remains outside the terminal runtime authority.
 */
export function useSshTerminalSessions(
  catalog: TerminalSessionCatalog,
  resolveAppearance: SshTerminalAppearanceResolver,
  translate: Translate,
): UseSshTerminalSessionsResult {
  const catalogRef = useRef<TerminalSessionCatalog | null>(null);
  if (!catalogRef.current) {
    catalogRef.current = catalog;
  } else if (catalogRef.current !== catalog) {
    throw new Error("TERMINAL_SESSION_CATALOG_CHANGED");
  }

  const [registry, setRegistry] = useState<TerminalSessionRegistrySnapshot>(
    () => catalog.snapshot,
  );
  const resolveAppearanceRef = useRef(resolveAppearance);
  const translateRef = useRef(translate);
  const viewsRef = useRef(new Map<WorkspaceSessionId, SshTerminalViewRuntime>());
  const controllerRef = useRef<SshTerminalSessionController<Terminal> | null>(null);
  const pendingDisposalRef = useRef<object | null>(null);
  resolveAppearanceRef.current = resolveAppearance;
  translateRef.current = translate;

  if (!controllerRef.current) {
    controllerRef.current = new SshTerminalSessionController<Terminal>({
      catalog,
      backend: {
        sendInput: sendSshInput,
        resize: resizeSshSession,
        close: closeSshSession,
        cancel: cancelSshSession,
      },
      createXterm(id, target) {
        const appearance = resolveAppearanceRef.current(target);
        const terminal = new Terminal({
          convertEol: false,
          ...appearance.xtermOptions,
        });
        const fitAddon = new FitAddon();
        terminal.loadAddon(fitAddon);
        viewsRef.current.set(id, makeViewRuntime(appearance));
        return {
          terminal,
          fit: {
            fit() {
              const viewport = viewsRef.current.get(id)?.viewport;
              if (
                !viewport
                || viewport.clientWidth < 1
                || viewport.clientHeight < 1
              ) return false;
              fitAddon.fit();
              return true;
            },
          },
        };
      },
      createResizeCoordinator: (transport) => createTerminalResizeCoordinator(transport),
      scheduler: {
        request: (callback) => window.requestAnimationFrame(callback),
        cancel: (frameId) => window.cancelAnimationFrame(frameId),
      },
      translate: (key, variables) => translateRef.current(key, variables),
      onRuntimeDestroyed(runtime) {
        const view = viewsRef.current.get(runtime.id);
        if (!view) return;
        view.viewportObserver?.disconnect();
        view.viewportObserver = null;
        view.webglGeneration += 1;
        view.webglAddon?.dispose();
        view.webglAddon = null;
        view.viewport = null;
        viewsRef.current.delete(runtime.id);
      },
    });
  }
  const controller = controllerRef.current;

  const releaseWebgl = useCallback((view: SshTerminalViewRuntime) => {
    view.webglGeneration += 1;
    view.webglAddon?.dispose();
    view.webglAddon = null;
  }, []);

  const refreshAppearance = useCallback((id: WorkspaceSessionId) => {
    const runtime = controller.getRuntime(id);
    const view = viewsRef.current.get(id);
    if (!runtime || !view) return undefined;
    try {
      const nextAppearance = resolveAppearanceRef.current(runtime.target);
      applyResolvedTerminalAppearance(runtime.terminal, nextAppearance);
      view.appearance = nextAppearance;
    } catch {
      // A transient settings/resolver failure must not corrupt a live terminal.
      // Keep the last successfully applied, renderer-safe appearance.
    }
    return view.appearance;
  }, [controller]);

  const configureActiveRenderer = useCallback((id: WorkspaceSessionId | null) => {
    for (const [candidateId, candidateView] of viewsRef.current) {
      if (candidateId !== id) releaseWebgl(candidateView);
    }
    if (id === null) return;
    const runtime = controller.getRuntime(id);
    const view = viewsRef.current.get(id);
    if (!runtime || !view || catalog.snapshot.activeSessionId !== id) return;
    const selectedAppearance = refreshAppearance(id);
    if (!selectedAppearance) return;
    if (!shouldAttemptWebgl(selectedAppearance.renderer)) {
      releaseWebgl(view);
      return;
    }
    if (view.webglAddon) return;
    const generation = ++view.webglGeneration;
    void installPreferredWebglAddon(
      runtime.terminal,
      selectedAppearance.renderer,
      () => controller.getRuntime(id) === runtime
        && catalog.snapshot.activeSessionId === id
        && viewsRef.current.get(id) === view
        && view.webglGeneration === generation,
    ).then((addon) => {
      if (!addon) return;
      if (
        controller.getRuntime(id) === runtime
        && catalog.snapshot.activeSessionId === id
        && viewsRef.current.get(id) === view
        && view.webglGeneration === generation
      ) {
        view.webglAddon = addon;
      } else {
        addon.dispose();
      }
    });
  }, [catalog, controller, refreshAppearance, releaseWebgl]);

  useEffect(() => {
    setRegistry(catalog.snapshot);
    configureActiveRenderer(catalog.snapshot.activeSessionId);
    return catalog.subscribe((snapshot) => {
      setRegistry(snapshot);
      // A Local (or future protocol) activation must immediately retire every
      // SSH WebGL addon; hidden xterms and their scrollback remain mounted.
      configureActiveRenderer(snapshot.activeSessionId);
    });
  }, [catalog, configureActiveRenderer]);

  const open = useCallback((
    target: SshTerminalTarget,
    start: SshTerminalStart,
    onSessionCreated?: SshTerminalSessionCreated,
  ) => {
    const clientAttemptId = createSshClientAttemptId();
    return controller.open(
      target,
      { clientAttemptId, start },
      { onSessionCreated },
    );
  }, [controller]);

  const restoreDisconnected = useCallback((
    id: WorkspaceSessionId,
    target: SshTerminalTarget,
    options?: SshTerminalRestoreOptions,
  ) => controller.restoreDisconnected(id, target, options), [controller]);

  const activate = useCallback((id: WorkspaceSessionId) => {
    controller.activate(id);
    configureActiveRenderer(id);
  }, [configureActiveRenderer, controller]);

  const retry = useCallback((id: WorkspaceSessionId, start: SshTerminalStart) => {
    const clientAttemptId = createSshClientAttemptId();
    return controller.retry(id, { clientAttemptId, start });
  }, [controller]);

  const disconnect = useCallback((id: WorkspaceSessionId) => (
    controller.disconnect(id)
  ), [controller]);

  const close = useCallback((id: WorkspaceSessionId) => (
    controller.close(id)
  ), [controller]);

  const readSelectedText = useCallback((id: WorkspaceSessionId) => (
    controller.readSelectedText(id)
  ), [controller]);
  const readRecentOutput = useCallback((id: WorkspaceSessionId) => (
    controller.readRecentOutput(id)
  ), [controller]);
  const sendText = useCallback((id: WorkspaceSessionId, data: string, expectedGeneration?: number) => (
    controller.sendText(id, data, expectedGeneration)
  ), [controller]);

  const owns = useCallback((id: WorkspaceSessionId) => controller.owns(id), [controller]);
  const targetFor = useCallback((id: WorkspaceSessionId) => (
    controller.getRuntime(id)?.target
  ), [controller]);
  const backendSessionIdFor = useCallback((id: WorkspaceSessionId) => (
    controller.backendSessionIdFor(id)
  ), [controller]);
  const operationGenerationFor = useCallback((id: WorkspaceSessionId) => (
    controller.getRuntime(id)?.operationGeneration
  ), [controller]);
  const appearanceFor = useCallback((id: WorkspaceSessionId) => (
    viewsRef.current.get(id)?.appearance
  ), []);
  const hasSessions = useCallback(() => controller.hasSessions(), [controller]);
  const fit = useCallback((id: WorkspaceSessionId) => controller.fit(id), [controller]);
  const fitActive = useCallback(() => controller.fitActive(), [controller]);
  const workspaceSessionIdForAttempt = useCallback((clientAttemptId: string) => (
    controller.workspaceSessionIdForAttempt(clientAttemptId)
  ), [controller]);
  const isExactAttemptRoute = useCallback((
    clientAttemptId: string,
    workspaceSessionId: WorkspaceSessionId,
  ) => controller.isExactAttemptRoute(clientAttemptId, workspaceSessionId), [controller]);

  const mountViewport = useCallback((id: WorkspaceSessionId, element: HTMLElement) => {
    const runtime = controller.getRuntime(id);
    const view = viewsRef.current.get(id);
    if (!runtime || !view) return;
    view.viewportObserver?.disconnect();
    view.viewport = element;
    if (!view.opened) {
      runtime.terminal.open(element);
      view.opened = true;
    } else if (
      runtime.terminal.element
      && runtime.terminal.element.parentElement !== element
    ) {
      // React StrictMode remounts reuse the xterm DOM and accumulated scrollback.
      element.appendChild(runtime.terminal.element);
    }
    view.viewportObserver = new ResizeObserver(() => controller.fit(id));
    view.viewportObserver.observe(element);
    controller.markViewportReady(id);
    if (catalog.snapshot.activeSessionId === id) configureActiveRenderer(id);
  }, [catalog, configureActiveRenderer, controller]);

  const unmountViewport = useCallback((id: WorkspaceSessionId, element: HTMLElement) => {
    const view = viewsRef.current.get(id);
    if (!view || view.viewport !== element) return;
    view.viewportObserver?.disconnect();
    view.viewportObserver = null;
    view.viewport = null;
  }, []);

  useEffect(() => {
    for (const id of catalog.snapshot.order) {
      if (controller.owns(id)) refreshAppearance(id);
    }
    configureActiveRenderer(catalog.snapshot.activeSessionId);
    window.requestAnimationFrame(() => controller.fitActive());
  }, [catalog, configureActiveRenderer, controller, refreshAppearance, registry, resolveAppearance]);

  useEffect(() => {
    // React StrictMode performs a synchronous cleanup/setup probe. Deferring
    // destruction by one microtask retains the controller during that probe;
    // a real unmount still retires only this controller's exact SSH sessions.
    pendingDisposalRef.current = null;
    return () => {
      const token = {};
      pendingDisposalRef.current = token;
      queueMicrotask(() => {
        if (pendingDisposalRef.current !== token) return;
        controller.dispose();
        pendingDisposalRef.current = null;
      });
    };
  }, [controller]);

  const activeSession = useMemo(() => controller.activeSession, [controller, registry]);

  return {
    registry,
    activeSession,
    owns,
    targetFor,
    backendSessionIdFor,
    operationGenerationFor,
    appearanceFor,
    open,
    restoreDisconnected,
    activate,
    retry,
    disconnect,
    close,
    readSelectedText,
    readRecentOutput,
    sendText,
    hasSessions,
    fit,
    fitActive,
    mountViewport,
    unmountViewport,
    workspaceSessionIdForAttempt,
    isExactAttemptRoute,
  };
}

type SshTerminalViewportProps = Readonly<{
  id: WorkspaceSessionId;
  placement: TerminalPanePlacement | null;
  background: string;
  onActivate?: (id: WorkspaceSessionId) => void;
  mountViewport: (id: WorkspaceSessionId, element: HTMLElement) => void;
  unmountViewport: (id: WorkspaceSessionId, element: HTMLElement) => void;
}>;

function SshTerminalViewport({
  id,
  placement,
  background,
  onActivate,
  mountViewport,
  unmountViewport,
}: SshTerminalViewportProps) {
  const elementRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const element = elementRef.current;
    if (!element) return;
    mountViewport(id, element);
    return () => unmountViewport(id, element);
  }, [id, mountViewport, unmountViewport]);

  return (
    <div
      ref={elementRef}
      className={`local-terminal-viewport ssh-terminal-viewport terminal-pane-viewport${
        placement?.focused ? " focused" : ""
      }`}
      data-workspace-session-id={id}
      data-terminal-pane-focused={placement?.focused ? "true" : "false"}
      hidden={!placement}
      style={placement ? {
        left: `${placement.rect.x * 100}%`,
        top: `${placement.rect.y * 100}%`,
        width: `${placement.rect.width * 100}%`,
        height: `${placement.rect.height * 100}%`,
        backgroundColor: background,
      } : undefined}
      onPointerDownCapture={() => {
        if (placement && !placement.focused) onActivate?.(id);
      }}
    />
  );
}

export type SshTerminalSessionViewportsProps = Readonly<{
  registry: TerminalSessionRegistrySnapshot;
  background: string;
  backgroundFor?: (id: WorkspaceSessionId) => string | undefined;
  placements?: Readonly<Record<string, TerminalPanePlacement>>;
  onActivate?: (id: WorkspaceSessionId) => void;
  owns: (id: WorkspaceSessionId) => boolean;
  mountViewport: (id: WorkspaceSessionId, element: HTMLElement) => void;
  unmountViewport: (id: WorkspaceSessionId, element: HTMLElement) => void;
}>;

const FULL_TERMINAL_PLACEMENT: TerminalPanePlacement = Object.freeze({
  rect: Object.freeze({ x: 0, y: 0, width: 1, height: 1 }),
  focused: true,
});

export function SshTerminalSessionViewports({
  registry,
  background,
  backgroundFor,
  placements,
  onActivate,
  owns,
  mountViewport,
  unmountViewport,
}: SshTerminalSessionViewportsProps) {
  const placementFor = (id: WorkspaceSessionId): TerminalPanePlacement | null => (
    placements?.[id]
    ?? (registry.activeSessionId === id ? FULL_TERMINAL_PLACEMENT : null)
  );
  const hasVisibleOwnedSsh = registry.order.some((id) => (
    registry.sessions[id]?.protocol === "ssh"
    && owns(id)
    && placementFor(id) !== null
  ));
  return (
    <div
      className="terminal-container local-terminal-viewports ssh-terminal-viewports terminal-pane-layer"
      hidden={!hasVisibleOwnedSsh}
      style={{ backgroundColor: background }}
    >
      {registry.order.map((id) => (
        registry.sessions[id]?.protocol === "ssh" && owns(id)
          ? (
              <SshTerminalViewport
                key={id}
                id={id}
                placement={placementFor(id)}
                background={backgroundFor?.(id) ?? background}
                onActivate={onActivate}
                mountViewport={mountViewport}
                unmountViewport={unmountViewport}
              />
            )
          : null
      ))}
    </div>
  );
}
