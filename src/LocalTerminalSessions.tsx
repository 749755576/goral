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
  cancelLocalPtySession,
  closeLocalPtySession,
  listLocalShells,
  resizeLocalPtySession,
  sendLocalPtyInput,
  startLocalPtySession,
} from "./backend";
import {
  LocalTerminalSessionController,
  type LocalTerminalOpenResult,
  type LocalTerminalRestoreOptions,
  type LocalTerminalRestoreRequest,
  type LocalTerminalTarget,
} from "./localTerminalSessionController";
import {
  createTerminalSessionCatalog,
  type TerminalSessionCatalog,
} from "./terminalSessionCatalog";
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
  LocalTerminalOpenResult,
  LocalTerminalRestoreOptions,
  LocalTerminalRestoreRequest,
  LocalTerminalTarget,
  TerminalSendTextErrorCode,
};

type LocalTerminalViewRuntime = {
  viewport: HTMLElement | null;
  viewportObserver: ResizeObserver | null;
  opened: boolean;
  webglAddon: DisposableXtermAddon | null;
  webglGeneration: number;
};

export type UseLocalTerminalSessionsResult = Readonly<{
  registry: TerminalSessionRegistrySnapshot;
  activeSession: TerminalSessionSnapshot | null;
  targetFor: (id: WorkspaceSessionId) => LocalTerminalTarget | undefined;
  open: (target: LocalTerminalTarget) => Promise<LocalTerminalOpenResult>;
  restoreDisconnected: (
    request: LocalTerminalRestoreRequest,
    options?: LocalTerminalRestoreOptions,
  ) => Promise<LocalTerminalOpenResult>;
  activate: (id: WorkspaceSessionId) => void;
  retry: (id: WorkspaceSessionId) => Promise<string | null>;
  disconnect: (id: WorkspaceSessionId) => Promise<string | null>;
  close: (id: WorkspaceSessionId) => Promise<string | null>;
  operationGenerationFor: (id: WorkspaceSessionId) => number | undefined;
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
}>;

const makeViewRuntime = (): LocalTerminalViewRuntime => ({
  viewport: null,
  viewportObserver: null,
  opened: false,
  webglAddon: null,
  webglGeneration: 0,
});

export function useLocalTerminalSessions(
  appearance: ResolvedTerminalAppearance,
  sharedCatalog: TerminalSessionCatalog | undefined,
  translate: Translate,
): UseLocalTerminalSessionsResult {
  const catalogRef = useRef<TerminalSessionCatalog | null>(null);
  if (!catalogRef.current) {
    catalogRef.current = sharedCatalog ?? createTerminalSessionCatalog();
  } else if (sharedCatalog && catalogRef.current !== sharedCatalog) {
    throw new Error("TERMINAL_SESSION_CATALOG_CHANGED");
  }
  const catalog = catalogRef.current;
  const [registry, setRegistry] = useState<TerminalSessionRegistrySnapshot>(
    () => catalog.snapshot,
  );
  const appearanceRef = useRef(appearance);
  const translateRef = useRef(translate);
  const viewsRef = useRef(new Map<WorkspaceSessionId, LocalTerminalViewRuntime>());
  const controllerRef = useRef<LocalTerminalSessionController<Terminal> | null>(null);
  const pendingDisposalRef = useRef<object | null>(null);
  appearanceRef.current = appearance;
  translateRef.current = translate;

  if (!controllerRef.current) {
    controllerRef.current = new LocalTerminalSessionController<Terminal>({
      catalog,
      backend: {
        listShells: listLocalShells,
        start: startLocalPtySession,
        sendInput: sendLocalPtyInput,
        resize: resizeLocalPtySession,
        close: closeLocalPtySession,
        cancel: cancelLocalPtySession,
      },
      createXterm(id) {
        const terminal = new Terminal({
          convertEol: false,
          ...appearanceRef.current.xtermOptions,
        });
        const fitAddon = new FitAddon();
        terminal.loadAddon(fitAddon);
        viewsRef.current.set(id, makeViewRuntime());
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
      cwdPlatform: navigator.userAgent.includes("Windows") ? "windows" : "posix",
      translate: (key, variables) => translateRef.current(key, variables),
      onRegistryChange: setRegistry,
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

  const configureActiveRenderer = useCallback((id: WorkspaceSessionId) => {
    for (const candidateId of controller.registry.order) {
      if (candidateId === id) continue;
      const candidateView = viewsRef.current.get(candidateId);
      if (!candidateView?.webglAddon) continue;
      candidateView.webglGeneration += 1;
      candidateView.webglAddon.dispose();
      candidateView.webglAddon = null;
    }
    const runtime = controller.getRuntime(id);
    if (!runtime) return;
    const selectedAppearance = appearanceRef.current;
    applyResolvedTerminalAppearance(runtime.terminal, selectedAppearance);
    const view = viewsRef.current.get(id);
    if (!view) return;
    if (!shouldAttemptWebgl(selectedAppearance.renderer)) {
      view.webglGeneration += 1;
      view.webglAddon?.dispose();
      view.webglAddon = null;
      return;
    }
    if (view.webglAddon) return;
    const generation = ++view.webglGeneration;
    void installPreferredWebglAddon(
      runtime.terminal,
      selectedAppearance.renderer,
      () => controller.getRuntime(id) === runtime
        && controller.registry.activeSessionId === id
        && viewsRef.current.get(id) === view
        && view.webglGeneration === generation,
    ).then((addon) => {
      if (!addon) return;
      if (
        controller.getRuntime(id) === runtime
        && controller.registry.activeSessionId === id
        && viewsRef.current.get(id) === view
        && view.webglGeneration === generation
      ) {
        view.webglAddon = addon;
      } else {
        addon.dispose();
      }
    });
  }, [controller]);

  const open = useCallback((target: LocalTerminalTarget) => (
    controller.open(target)
  ), [controller]);

  const restoreDisconnected = useCallback((
    request: LocalTerminalRestoreRequest,
    options?: LocalTerminalRestoreOptions,
  ) => controller.restoreDisconnected(request, options), [controller]);

  const targetFor = useCallback((id: WorkspaceSessionId) => (
    controller.targetFor(id)
  ), [controller]);

  const activate = useCallback((id: WorkspaceSessionId) => {
    controller.activate(id);
  }, [controller]);

  const retry = useCallback((id: WorkspaceSessionId) => (
    controller.retry(id)
  ), [controller]);

  const disconnect = useCallback((id: WorkspaceSessionId) => (
    controller.disconnect(id)
  ), [controller]);

  const close = useCallback((id: WorkspaceSessionId) => (
    controller.close(id)
  ), [controller]);
  const operationGenerationFor = useCallback((id: WorkspaceSessionId) => (
    controller.getRuntime(id)?.operationGeneration
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

  const hasSessions = useCallback(() => controller.hasSessions(), [controller]);
  const fit = useCallback((id: WorkspaceSessionId) => controller.fit(id), [controller]);
  const fitActive = useCallback(() => controller.fitActive(), [controller]);

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
      // StrictMode remounts reuse the xterm DOM and its accumulated scrollback.
      element.appendChild(runtime.terminal.element);
    }
    view.viewportObserver = new ResizeObserver(() => controller.fit(id));
    view.viewportObserver.observe(element);
    controller.markViewportReady(id);
    if (controller.registry.activeSessionId === id) configureActiveRenderer(id);
  }, [configureActiveRenderer, controller]);

  const unmountViewport = useCallback((id: WorkspaceSessionId, element: HTMLElement) => {
    const view = viewsRef.current.get(id);
    if (!view || view.viewport !== element) return;
    view.viewportObserver?.disconnect();
    view.viewportObserver = null;
    view.viewport = null;
  }, []);

  useEffect(() => {
    for (const id of controller.registry.order) {
      const runtime = controller.getRuntime(id);
      if (runtime) applyResolvedTerminalAppearance(runtime.terminal, appearance);
    }
    const activeId = controller.registry.activeSessionId;
    if (activeId) {
      configureActiveRenderer(activeId);
      window.requestAnimationFrame(() => controller.fitActive());
    }
  }, [appearance, configureActiveRenderer, controller, registry]);

  useEffect(() => {
    // React StrictMode performs a synchronous cleanup/setup probe. Deferring
    // destruction by one microtask lets that probe retain the same controller,
    // while a real unmount still retires every exact native session.
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
    targetFor,
    open,
    restoreDisconnected,
    activate,
    retry,
    disconnect,
    close,
    operationGenerationFor,
    readSelectedText,
    readRecentOutput,
    sendText,
    hasSessions,
    fit,
    fitActive,
    mountViewport,
    unmountViewport,
  };
}

type LocalTerminalViewportProps = Readonly<{
  id: WorkspaceSessionId;
  placement: TerminalPanePlacement | null;
  background: string;
  onActivate?: (id: WorkspaceSessionId) => void;
  mountViewport: (id: WorkspaceSessionId, element: HTMLElement) => void;
  unmountViewport: (id: WorkspaceSessionId, element: HTMLElement) => void;
}>;

function LocalTerminalViewport({
  id,
  placement,
  background,
  onActivate,
  mountViewport,
  unmountViewport,
}: LocalTerminalViewportProps) {
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
      className={`local-terminal-viewport terminal-pane-viewport${
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

type LocalTerminalSessionViewportsProps = Readonly<{
  registry: TerminalSessionRegistrySnapshot;
  background: string;
  placements?: Readonly<Record<string, TerminalPanePlacement>>;
  onActivate?: (id: WorkspaceSessionId) => void;
  mountViewport: (id: WorkspaceSessionId, element: HTMLElement) => void;
  unmountViewport: (id: WorkspaceSessionId, element: HTMLElement) => void;
}>;

const FULL_TERMINAL_PLACEMENT: TerminalPanePlacement = Object.freeze({
  rect: Object.freeze({ x: 0, y: 0, width: 1, height: 1 }),
  focused: true,
});

export function LocalTerminalSessionViewports({
  registry,
  background,
  placements,
  onActivate,
  mountViewport,
  unmountViewport,
}: LocalTerminalSessionViewportsProps) {
  const placementFor = (id: WorkspaceSessionId): TerminalPanePlacement | null => (
    placements?.[id]
    ?? (registry.activeSessionId === id ? FULL_TERMINAL_PLACEMENT : null)
  );
  const hasVisibleLocal = registry.order.some((id) => (
    registry.sessions[id]?.protocol === "local" && placementFor(id) !== null
  ));
  return (
    <div
      className="terminal-container local-terminal-viewports terminal-pane-layer"
      hidden={!hasVisibleLocal}
      style={{ backgroundColor: background }}
    >
      {registry.order.map((id) => (
        registry.sessions[id]?.protocol === "local"
          ? (
              <LocalTerminalViewport
                key={id}
                id={id}
                placement={placementFor(id)}
                background={background}
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
