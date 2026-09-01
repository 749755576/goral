import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import type { WebglAddon } from "@xterm/addon-webgl";
import { isTauri } from "@tauri-apps/api/core";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open, save } from "@tauri-apps/plugin-dialog";
import "@xterm/xterm/css/xterm.css";
import {
  FormEvent,
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { createTerminalInputBinding } from "./terminalImeTextInput.ts";
import {
  TerminalInputWriteQueue,
  type PreparedTerminalTextInput,
} from "./terminalPerCharacterInput.ts";

import {
  cancelInteractiveAuth,
  cancelEtSession,
  cancelMoshSession,
  cancelSerialSession,
  cancelSerialYmodem,
  cancelSerialZmodem,
  cancelSshSession,
  cancelTelnetSession,
  cancelSftpTransfer,
  classifyLocalTransferSource,
  cloneSshSession,
  closeEtSession,
  closeMoshSession,
  closeSerialSession,
  closeSshSession,
  closeTelnetSession,
  commitLegacyVaultImport,
  createManagedSshKey,
  createSavedHost,
  createSftpDirectory,
  deleteSavedHost,
  deleteManagedSshKey,
  inspectLegacyVault,
  listKnownHosts,
  listSavedHosts,
  listManagedSshKeys,
  pauseSftpTransfer,
  readSftpDirectory,
  receiveSerialYmodem,
  removeSftpDirectory,
  removeSftpFile,
  renameSftpPath,
  resumeSftpTransfer,
  resizeEtSession,
  resizeSerialSession,
  resizeMoshSession,
  resizeSshSession,
  resizeTelnetSession,
  respondToHostKey,
  respondToInteractiveAuth,
  replaceKnownHosts,
  rotateManagedSshMasterKey,
  sendSerialInput,
  sendSerialYmodem,
  sendEtInput,
  sendMoshInput,
  sendSshInput,
  sendTelnetInput,
  stageSshKeyPassphrase,
  stageManagedSshKeyBundle,
  stageSshPassword,
  stageTelnetPassword,
  startSftpDownload,
  startSftpDownloadDirectory,
  startSftpUpload,
  startSftpUploadDirectory,
  startSavedHostSession,
  startSavedMoshSession,
  startSavedSerialSession,
  startSavedTelnetSession,
  startEtSession,
  startMoshSession,
  startSerialSession,
  startSerialZmodem,
  startSshSession,
  startTelnetSession,
  subscribeHostKeyPrompts,
  subscribeInteractivePrompts,
  updateSavedHost,
  updateManagedSshKey,
  type HostKeyPrompt,
  type GroupConfigCatalog as GroupConfigCatalogSnapshot,
  type InteractivePrompt,
  type LegacyVaultInspection,
  type LegacyVaultImportIssueCode,
  type LegacyVaultSourceKind,
  type ManagedSshKey,
  type ManagedSshKeyCatalog,
  type ManagedSshKeyCategory,
  type PasswordIdentityCatalog as PasswordIdentityCatalogSnapshot,
  type ProxyProfileConfigRequest,
  type ProxyProfileCredentialMutation,
  type ProxyProfileCatalog as ProxyProfileCatalogSnapshot,
  type SshSessionHandle,
  type SavedHost,
  type SavedHostEffectiveAppearance,
  type SavedKnownHost,
  type SavedHostCredentialMutation,
  type SavedHostDraft,
  type SavedHostInlineProxyMutation,
  type SavedHostProxyMutation,
  type SavedHostProxyProfileMutation,
  type SerialConfig,
  type SerialYmodemDirection,
  type SerialYmodemProgressEvent,
  type SerialZmodemDirection,
  type SerialZmodemProgressEvent,
  type SshSessionCallbacks,
  type SftpEntry,
  type SftpTransferEvent,
} from "./backend";
import {
  LocalTerminalPanel,
  type LocalTerminalSubmission,
} from "./LocalTerminalPanel";
import {
  LocalTerminalSessionViewports,
  useLocalTerminalSessions,
} from "./LocalTerminalSessions";
import {
  SshTerminalSessionViewports,
  useSshTerminalSessions,
  type SshTerminalStart,
  type SshTerminalTarget,
} from "./SshTerminalSessions";
import {
  createTerminalSessionCatalog,
  type TerminalSessionCatalog,
} from "./terminalSessionCatalog";
import { SshPromptQueue, type SshPromptQueueSnapshot } from "./sshPromptQueue";
import {
  createActiveSftpProjection,
  projectionOwnsSftpMutation,
  resolveActiveSftpProjection,
  type ActiveSftpProjection,
} from "./activeSftpProjection";
import {
  SftpSessionController,
  type SftpSessionOwner as WorkspaceSftpSessionOwner,
  type SftpSessionSuspension,
  type SftpSessionSnapshot,
  type SftpTransferSnapshot,
} from "./sftpSessionController";
import {
  SftpBrowserPanel,
} from "./SftpBrowserPanel";
import {
  MAX_WORKSPACE_SESSIONS,
  createWorkspaceSessionId,
  type WorkspaceSessionId,
} from "./terminalSessionRegistry";
import {
  clampTerminalPaneRatio,
  collectTerminalPaneSessionIds,
  computeTerminalPaneGeometry,
  createTerminalPaneLayout,
  createTerminalPanePlacements,
  findNextTerminalPaneFocusSessionId,
  focusTerminalPane,
  MAX_TERMINAL_PANES,
  pruneTerminalPaneLayout,
  removeTerminalPane,
  resizeTerminalPaneSplit,
  shouldDissolveTerminalPaneLayout,
  splitTerminalPane,
  splitTerminalPaneAtPosition,
  terminalPaneLayoutContains,
  type TerminalPaneLayoutSnapshot,
  type TerminalPaneFocusDirection,
  type TerminalPaneRect,
  type TerminalPaneSplitDirection,
} from "./terminalPaneLayout";
import {
  resolveTerminalPaneDropHint,
  type TerminalPaneDropHint,
} from "./terminalPaneDrag";
import { createTerminalWorkspaceTabs } from "./terminalWorkspaceTabs";
import {
  createSessionRestoreSnapshot,
  createSessionRestoreSnapshotFromRegistry,
  createSessionRestoreStore,
  type SessionRestoreEntry,
  type SessionRestoreSnapshot,
} from "./sessionRestore";
import { SessionRestorePrompt } from "./SessionRestorePrompt";
import {
  WorkspacePromptDialog,
  type WorkspacePromptDialogRequest,
} from "./WorkspacePromptDialog";
import {
  MANAGED_SSH_KEY_CERTIFICATE_MAX_BYTES,
  MANAGED_SSH_KEY_PASSPHRASE_MAX_BYTES,
  MANAGED_SSH_KEY_PRIVATE_KEY_MAX_BYTES,
  MANAGED_SSH_KEY_PUBLIC_KEY_MAX_BYTES,
} from "./managedSshKeyBundle";
import { PasswordIdentityCatalog } from "./PasswordIdentityCatalog";
import { PortForwardingCatalog } from "./PortForwardingCatalog";
import { ProxyProfileCatalog } from "./ProxyProfileCatalog";
import { GroupConfigCatalog } from "./GroupConfigCatalog";
import { KnownHostsWorkspace } from "./KnownHostsWorkspace";
import { ConnectionLogsWorkspace } from "./ConnectionLogsWorkspace";
import { buildKnownHostsAfterTrust } from "./hostKeyTrust";
import { NotesWorkspace } from "./NotesWorkspace";
import { ScriptsWorkspace } from "./ScriptsWorkspace";
import { SavedHostGroupTree } from "./SavedHostGroupTree";
import type { SavedHostEditor } from "./SavedHostChainEditor";
import { SavedHostEditorDialog } from "./SavedHostEditorDialog";
import { SavedHostCatalogCard } from "./SavedHostCatalogCard";
import {
  createCoalescedRefresh,
  shouldShowSavedHostsBackgroundRefresh,
  shouldShowSavedHostsInitialLoader,
  type CoalescedRefresh,
} from "./savedHostsRefresh";
import {
  SavedHostKeyPassphrasePromptDialog,
  SavedHostPasswordPromptDialog,
  SavedHostProxyPasswordPromptDialog,
} from "./SavedHostConnectionPrompts";
import {
  SerialConnectPanel,
  type QuickSerialConnectSubmission,
  type SavedSerialCreateSubmission,
  type SavedSerialEditSubmission,
} from "./SerialConnectPanel";
import { openSettingsWindow } from "./settingsWindowApi";
import { SETTINGS_ADAPTER, subscribeSettingsChanges } from "./settingsApi";
import {
  createSettingsReloadCoordinator,
  type SettingsReloadCoordinator,
} from "./settingsSync";
import { createDefaultRendererSafeSettings } from "./settingsUi";
import { normalizeLocale, useI18n, type MessageKey, type Translate } from "./i18n";
import {
  applyResolvedTerminalAppearance,
  installPreferredWebglAddon,
  resolveTerminalAppearance,
  shouldAttemptWebgl,
} from "./terminalAppearance";
import {
  createTerminalResizeCoordinator,
  type TerminalResizeCoordinator,
} from "./terminalResizeCoordinator";
import {
  getTerminalSidePanelWidthBounds,
  resizeTerminalSidePanelWidth,
  type TerminalSidePanelId,
} from "./terminalSidePanel";
import {
  normalizeProxyCommandMutation,
  normalizeProxyNetworkConfig,
} from "./proxyProfileUi";
import {
  hasSavedHostOwnedCredential,
  isSavedKeyHost,
  isSavedManagedKeyHost,
  isSavedReferenceKeyHost,
  isSavedUnsupportedKeyHost,
  savedHostEffectiveUsername,
  savedHostPasswordIdentityBinding,
} from "./savedHostAuth";
import { filterSavedHosts } from "./savedHostSearch";
import {
  formatTelnetLocalEcho,
  resolveQuickConnectProtocolPort,
} from "./telnetLocalEcho";
import { mapTerminalBackspaceInput } from "./serialBackspace";
import { handleSerialLineModeInput } from "./serialLineInput";
import { formatSerialLocalEcho } from "./serialLocalEcho";
import { hasErrorCode } from "./errorCode";
import {
  prepareTerminalText,
  readTerminalRecentOutput,
  readTerminalSelectedText,
} from "./terminalSessionBridge";
import AiWorkspace, { type AiTerminalScope } from "./aiWorkspace";
import { discoverAiAgents, type DiscoveredAiAgent } from "./aiAgentDiscoveryApi";
import { openAiCompatibleCompletion, openLocalAiAgentCompletion } from "./aiCompletion";
import DockerPanel from "./DockerPanel";
import RemoteEditor from "./RemoteEditor";
import { WindowControlGlyph } from "./WindowControlGlyph";
import { useAppColorMode } from "./useAppColorMode";
import { useUiFontFamily } from "./useUiFontFamily";

type ConnectionState = "disconnected" | "connecting" | "connected" | "closing";
type ConnectionProtocol = "ssh" | "telnet" | "mosh" | "et" | "serial";
type NetworkConnectionProtocol = Exclude<ConnectionProtocol, "serial">;
type WorkspaceSurface = "vault" | "terminal";
type ConnectionTarget = {
  protocol: ConnectionProtocol;
  hostname: string;
  port: number;
  username: string;
  serialConfig?: SerialConfig;
  charset?: string;
  effectiveAppearance?: SavedHostEffectiveAppearance;
  savedHost?: SavedHost;
};
type ActiveTerminalSession = SshSessionHandle & { protocol: ConnectionProtocol };
type TerminalSidePanelResize = {
  pointerId: number;
  startX: number;
  startWidth: number;
};
// The AI composer has a denser, multi-control footer than SFTP/Docker. Keep
// its own floor so a user cannot resize the panel into an unreadable strip;
// the shared side-panel floor remains 280px for the other tools.
const AI_SIDE_PANEL_MIN_WIDTH = 420;
type TerminalPaneResize = {
  pointerId: number;
  splitId: string;
  direction: TerminalPaneSplitDirection;
  splitRect: TerminalPaneRect;
  startClientX: number;
  startClientY: number;
  startRatio: number;
};
type WindowCommand = "minimize" | "maximize" | "close";
type SessionRestorePresentation = Readonly<
  | {
      kind: "ssh";
      entry: SessionRestoreEntry;
      target: SshTerminalTarget;
    }
  | {
      kind: "local";
      entry: SessionRestoreEntry;
      shellId: string;
    }
>;

const terminalPaneRectEquals = (
  left: TerminalPaneRect | undefined,
  right: TerminalPaneRect | undefined,
): boolean => Boolean(
  left
  && right
  && left.x === right.x
  && left.y === right.y
  && left.width === right.width
  && left.height === right.height,
);

const changedTerminalPaneSessionIds = (
  previous: TerminalPaneLayoutSnapshot,
  next: TerminalPaneLayoutSnapshot,
): readonly WorkspaceSessionId[] => {
  const previousPanes = computeTerminalPaneGeometry(previous).panes;
  const nextPanes = computeTerminalPaneGeometry(next).panes;
  return collectTerminalPaneSessionIds(next.root).filter((sessionId) => (
    !terminalPaneRectEquals(previousPanes[sessionId], nextPanes[sessionId])
  ));
};

const connectionStateLabel = (state: ConnectionState, t: Translate): string => {
  if (state === "connecting") return t("workspace.connectionState.connecting");
  if (state === "connected") return t("workspace.connectionState.connected");
  if (state === "closing") return t("workspace.connectionState.closing");
  return t("workspace.connectionState.disconnected");
};
type HostViewMode = "grid" | "list" | "tree";
type SidebarView =
  | "quick"
  | "saved"
  | "keys"
  | "identities"
  | "proxies"
  | "port"
  | "scripts"
  | "notes"
  | "known"
  | "logs";
type VaultGlyphName =
  | "hosts"
  | "key"
  | "identity"
  | "proxy"
  | "port"
  | "scripts"
  | "notes"
  | "known"
  | "logs"
  | "ai"
  | "settings"
  | "search"
  | "list"
  | "tree"
  | "tag"
  | "sort"
  | "check"
  | "plus"
  | "download"
  | "upload"
  | "refresh"
  | "file"
  | "edit"
  | "trash"
  | "pause"
  | "play"
  | "close"
  | "up"
  | "disconnect"
  | "terminal"
  | "serial"
  | "folder"
  | "workspace"
  | "focus"
  | "splitHorizontal"
  | "splitVertical"
  | "chevron";

const NATIVE_DESKTOP_RUNTIME_AVAILABLE = isTauri();
const BROWSER_SERIAL_PORT_SOURCE = async () => [];
const BROWSER_LOCAL_SHELL_SOURCE = async () => [];
const BROWSER_VISUAL_PREVIEW = import.meta.env.DEV && !NATIVE_DESKTOP_RUNTIME_AVAILABLE
  ? new URLSearchParams(window.location.search).get("preview")
  : null;
const makeBrowserPreviewHost = (
  id: string,
  label: string,
  hostname: string,
  group: string,
): SavedHost => ({
  id,
  revision: 1,
  label,
  group,
  tags: [],
  hostChain: null,
  hostname,
  port: 22,
  username: "root",
  protocol: "ssh",
  visual: {
    os: "linux",
    distro: "linux",
    distroMode: "auto",
    manualDistro: null,
    iconMode: "auto",
    iconId: null,
    iconColorMode: "auto",
    iconColor: null,
    iconColorCustom: null,
  },
  serialConfig: null,
  effectiveSerialConfig: null,
  hasExplicitSerialBackspaceBehavior: false,
  charset: null,
  hasExplicitCharset: false,
  authMethod: "password",
  keySource: "none",
  managedSshKeyId: null,
  hasSavedCredential: true,
  hasSavedHostCredential: true,
  passwordIdentity: null,
  hasSavedKeyPassphrase: false,
  proxy: null,
  effectiveAppearance: {
    themeId: null,
    fontFamily: null,
    fontSize: null,
    fontWeight: null,
  },
  createdAt: 0,
  updatedAt: 0,
});
const BROWSER_VISUAL_PREVIEW_HOSTS: SavedHost[] = BROWSER_VISUAL_PREVIEW
  ? [
      makeBrowserPreviewHost("preview-web-1", "Web Production", "web-01.example.invalid", "Production"),
      makeBrowserPreviewHost("preview-db-1", "Database Primary", "db-01.example.invalid", "Production"),
      makeBrowserPreviewHost("preview-cache-1", "Redis Cache", "cache-01.example.invalid", "Production"),
      makeBrowserPreviewHost("preview-staging-1", "Staging API", "api-staging.example.invalid", "Development"),
      makeBrowserPreviewHost("preview-ci-1", "CI Runner", "ci.example.invalid", "Development"),
      makeBrowserPreviewHost("preview-router-1", "Edge Router", "router.example.invalid", "Network"),
    ]
  : [];
const SFTP_DIRECTORY_ERROR: MessageKey = "sftp.error.directory";
const SFTP_OPERATION_ERROR: MessageKey = "sftp.error.operation";
const SFTP_TRANSFER_ERROR: MessageKey = "sftp.error.transfer";
const SFTP_TRANSFER_CONTROL_ERROR: MessageKey = "sftp.error.transferControl";
const SFTP_LOCAL_SOURCE_ERROR: MessageKey = "sftp.error.localSource";
const SFTP_PICKER_ERROR: MessageKey = "sftp.error.picker";
const SFTP_VALIDATION_ERROR: MessageKey = "sftp.error.invalidName";
const SSH_SESSION_STOP_ERROR: MessageKey = "terminal.runtime.disconnectFailed";

const localizeSftpError = (message: string, t: Translate): string => {
  switch (message) {
    case SFTP_DIRECTORY_ERROR:
    case SFTP_OPERATION_ERROR:
    case SFTP_TRANSFER_ERROR:
    case SFTP_TRANSFER_CONTROL_ERROR:
    case SFTP_LOCAL_SOURCE_ERROR:
    case SFTP_PICKER_ERROR:
    case SFTP_VALIDATION_ERROR:
      return t(message);
    default:
      return t(SFTP_TRANSFER_ERROR);
  }
};

const VAULT_GLYPH_PATHS: Record<VaultGlyphName, string[]> = {
  hosts: ["M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z"],
  key: ["M14.5 7.5a4.5 4.5 0 1 1-2.1 3.8L20 3.7M17 6.7l2.3 2.3"],
  identity: ["M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8ZM4.5 21a7.5 7.5 0 0 1 15 0"],
  proxy: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM3.5 9h17M3.5 15h17M12 3c2.2 2.4 3.3 5.4 3.3 9S14.2 18.6 12 21M12 3c-2.2 2.4-3.3 5.4-3.3 9S9.8 18.6 12 21"],
  port: ["M8 3v5M16 3v5M6 8h12v2a6 6 0 0 1-6 6v5M9 21h6"],
  scripts: ["M6 3h8l4 4v14H6zM14 3v5h5M10 12l-2 2 2 2M14 12l2 2-2 2"],
  notes: ["M6 3h12v18H6zM9 3v18M12 8h3M12 12h3M12 16h3"],
  known: ["M5 4h12a2 2 0 0 1 2 2v14H7a2 2 0 0 1-2-2zM8 4v6l2-1.5L12 10V4"],
  logs: ["M3 13h4l2-7 4 14 3-9 2 2h3"],
  ai: ["M12 2.8 13.7 8l5.5 1.7-5.5 1.7-1.7 5.5-1.7-5.5-5.5-1.7L10.3 8 12 2.8ZM18.5 15l.8 2.4 2.4.8-2.4.8-.8 2.4-.8-2.4-2.4-.8 2.4-.8.8-2.4Z"],
  settings: ["M12 15.2a3.2 3.2 0 1 0 0-6.4 3.2 3.2 0 0 0 0 6.4ZM12 2v3M12 19v3M4.9 4.9 7 7M17 17l2.1 2.1M2 12h3M19 12h3M4.9 19.1 7 17M17 7l2.1-2.1"],
  search: ["M10.8 18.3a7.5 7.5 0 1 1 0-15 7.5 7.5 0 0 1 0 15ZM16.2 16.2 21 21"],
  list: ["M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"],
  tree: ["M6 4v12M6 8h6M6 16h6M12 8v8M12 12h6M18 12v6M15 18h6"],
  tag: ["M3 4h8l10 10-7 7L4 11zM8 8h.01"],
  sort: ["M8 6h12M8 12h8M8 18h4M4 4v16M2 18l2 2 2-2"],
  check: ["M4 4h16v16H4zM8 12l3 3 6-7"],
  plus: ["M12 5v14M5 12h14"],
  download: ["M12 3v12M7 10l5 5 5-5M4 20h16"],
  upload: ["M12 21V9M7 14l5-5 5 5M4 4h16"],
  refresh: ["M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7"],
  file: ["M6 3h8l4 4v14H6zM14 3v5h5"],
  edit: ["M4 20h4L19 9l-4-4L4 16v4ZM13.5 6.5l4 4"],
  trash: ["M4 7h16M9 7V4h6v3M7 7l1 14h8l1-14M10 11v6M14 11v6"],
  pause: ["M9 5v14M15 5v14"],
  play: ["M8 5v14l11-7z"],
  close: ["M6 6l12 12M18 6 6 18"],
  up: ["M12 19V5M6 11l6-6 6 6"],
  disconnect: ["M12 3v9M5.6 6.6a8 8 0 1 0 12.8 0"],
  terminal: ["M4 5h16v14H4zM7 9l3 3-3 3M12 15h5"],
  serial: ["M8 3v5M16 3v5M6 8h12v2a6 6 0 0 1-6 6v5M9 21h6"],
  folder: ["M3 6h7l2 2h9v11H3z"],
  workspace: ["M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z"],
  focus: ["M4 9V4h5M15 4h5v5M20 15v5h-5M9 20H4v-5"],
  splitHorizontal: ["M4 4h16v16H4zM4 12h16"],
  splitVertical: ["M4 4h16v16H4zM12 4v16"],
  chevron: ["M8 10l4 4 4-4"],
};

const VaultGlyph = ({ name }: { name: VaultGlyphName }) => (
  <svg
    aria-hidden="true"
    className="vault-glyph"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    {VAULT_GLYPH_PATHS[name].map((path) => <path d={path} key={path} />)}
  </svg>
);

const BrandWordmark = ({ t }: { t: Translate }) => (
  <div className="vault-wordmark" role="img" aria-label={t("brand.wordmarkAlt")}>
    <strong>Goral</strong>
    <small>{t("brand.subtitle")}</small>
  </div>
);

type VisibleTransfer = SftpTransferSnapshot;

type SerialPanelState =
  | { mode: "quick" }
  | { mode: "create" }
  | { mode: "saved"; hostId: string };

type SavedHostPasswordPrompt = {
  host: SavedHost;
  workspaceSessionId?: WorkspaceSessionId;
  password: string;
  error?: string;
};

type SavedHostProxyPasswordPrompt = {
  host: SavedHost;
  workspaceSessionId?: WorkspaceSessionId;
  proxyPassword: string;
  sshPassword: string;
  selectedIdentityFilePaths?: string[];
  keyPassphrase: string;
  error?: string;
};

type SavedHostKeyPassphrasePrompt = {
  host: SavedHost;
  workspaceSessionId?: WorkspaceSessionId;
  passphrase: string;
  error?: string;
};

type LegacyVaultImportPreview = {
  path: string;
  inspection: LegacyVaultInspection;
  error?: string;
};

type ManagedSshKeyEditor = {
  mode: "create" | "edit";
  key?: ManagedSshKey;
  expectedInventoryRevision: unknown;
  label: string;
  category: ManagedSshKeyCategory;
  replaceSecret: boolean;
  passphrasePresent: boolean;
  savePassphrase: boolean;
};

type ManagedSshKeyDeletePrompt = {
  key: ManagedSshKey;
  expectedInventoryRevision: unknown;
};

type ConnectionOperation = {
  token: number;
  protocol: ConnectionProtocol;
  target: ConnectionTarget;
  sftpGeneration: number;
  handle: ActiveTerminalSession | null;
  connected: boolean;
  cancelRequested: boolean;
  closed: boolean;
  pendingSerialZmodemDetection: {
    sessionId: string;
    transferId: string;
    direction: SerialZmodemDirection;
  } | null;
};

type SerialYmodemTransferOwner = {
  token: number;
  sessionId: string;
  transferId: string | null;
  direction: SerialYmodemDirection;
  transferStarted: boolean;
  cancelRequested: boolean;
};

type SerialYmodemTransferState = {
  token: number;
  sessionId: string;
  transferId: string | null;
  direction: SerialYmodemDirection;
  phase: "selecting" | "transferring" | "canceling";
  progress: SerialYmodemProgressEvent | null;
};

type SerialZmodemTransferOwner = {
  token: number;
  sessionId: string;
  transferId: string;
  direction: SerialZmodemDirection;
  operation: ConnectionOperation;
  resumePhase: Exclude<SerialZmodemTransferState["phase"], "canceling">;
  cancelRequested: boolean;
};

type SerialZmodemTransferState = {
  token: number;
  sessionId: string;
  transferId: string;
  direction: SerialZmodemDirection;
  phase: "selecting" | "transferring" | "finalizing" | "canceling";
  progress: SerialZmodemProgressEvent | null;
};

type ObservedInventoryRevision = {
  seen: boolean;
  value: unknown;
};

const SAVED_CREDENTIAL_NOT_FOUND = "SAVED_CREDENTIAL_NOT_FOUND";
// The native boundary currently uses one public code for both Host and proxy
// credential prompts. Classify its bounded detail once, then keep only stable
// renderer-owned sentinels inside the session controllers. Native prose must
// never become presentation text.
const SAVED_PROXY_CREDENTIAL_NOT_FOUND = "SAVED_PROXY_CREDENTIAL_NOT_FOUND";
const SAVED_HOST_KEY_FILE_CONFIRMATION_REQUIRED = "SAVED_HOST_KEY_FILE_CONFIRMATION_REQUIRED";
const SAVED_HOST_KEY_FILE_SELECTION_INVALID = "SAVED_HOST_KEY_FILE_SELECTION_INVALID";
const MANAGED_SSH_KEY_INVENTORY_CHANGED = "MANAGED_SSH_KEY_INVENTORY_CHANGED";
const MANAGED_SSH_KEY_IN_USE = "MANAGED_SSH_KEY_IN_USE";

const isSavedTelnetHost = (host: SavedHost): boolean =>
  host.protocol.toLowerCase() === "telnet";

const isSavedSerialHost = (host: SavedHost): boolean =>
  host.protocol.toLowerCase() === "serial";

const isSavedSshHost = (host: SavedHost): boolean =>
  host.protocol.toLowerCase() === "ssh";

const isSavedEtHost = (host: SavedHost): boolean =>
  isSavedSshHost(host)
  && host.effectiveEtEnabled === true
  && host.effectiveMoshEnabled !== true;

const savedHostTransportLabel = (host: SavedHost): string => {
  if (isSavedSerialHost(host)) return "SERIAL";
  if (isSavedTelnetHost(host)) return "TELNET";
  if (host.effectiveMoshEnabled) return "MOSH";
  if (isSavedEtHost(host)) return "ET";
  return "SSH";
};

const savedHostDisplayAddress = (host: SavedHost): string => {
  if (isSavedSerialHost(host)) {
    const config = host.effectiveSerialConfig ?? host.serialConfig;
    return config ? `${config.path} · ${config.baudRate} baud` : host.hostname;
  }
  const username = isSavedTelnetHost(host) ? host.username : savedHostEffectiveUsername(host);
  return `${username ? `${username}@` : ""}${host.hostname}:${host.port}`;
};

const messageOf = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);

const closeTerminalSession = (active: ActiveTerminalSession): Promise<void> =>
  active.protocol === "telnet"
    ? closeTelnetSession(active.sessionId)
    : active.protocol === "serial"
      ? closeSerialSession(active.sessionId)
      : active.protocol === "mosh"
        ? closeMoshSession(active.sessionId)
        : active.protocol === "et"
          ? closeEtSession(active.sessionId)
          : closeSshSession(active.sessionId);

const cancelTerminalSession = (active: ActiveTerminalSession): Promise<void> =>
  active.protocol === "telnet"
    ? cancelTelnetSession(active.sessionId)
    : active.protocol === "serial"
      ? cancelSerialSession(active.sessionId)
      : active.protocol === "mosh"
        ? cancelMoshSession(active.sessionId)
        : active.protocol === "et"
          ? cancelEtSession(active.sessionId)
          : cancelSshSession(active.sessionId);

const isSavedCredentialNotFound = (message: string): boolean =>
  message === SAVED_CREDENTIAL_NOT_FOUND
  || message === SAVED_PROXY_CREDENTIAL_NOT_FOUND;

const isSavedProxyCredentialNotFound = (message: string): boolean => (
  message === SAVED_PROXY_CREDENTIAL_NOT_FOUND
);

const savedHostInlineProxyCredentialMutation = (
  action: SavedHostEditor["inlineProxyCredentialAction"],
  stagedCredentialReference?: string,
): ProxyProfileCredentialMutation => {
  if (action === "remove") return { action: "remove" };
  if (action === "replace" && stagedCredentialReference) {
    return { action: "replace", stagedCredentialReference };
  }
  return { action: "keep" };
};

const buildSavedHostInlineProxyConfig = (
  editor: SavedHostEditor,
  stagedCredentialReference?: string,
): ProxyProfileConfigRequest | null => {
  if (editor.inlineProxyType === "command") {
    const commandMutation = normalizeProxyCommandMutation(
      editor.inlineProxyCommandAction,
      editor.inlineProxyCommand,
    );
    return commandMutation ? { type: "command", commandMutation } : null;
  }
  return normalizeProxyNetworkConfig(
    editor.inlineProxyType,
    editor.inlineProxyHost,
    editor.inlineProxyPort,
    editor.inlineProxyAuthMode === "identity"
      ? { mode: "identity", identityId: editor.inlineProxyIdentityId }
      : {
        mode: "manual",
        username: editor.inlineProxyUsername,
        credentialMutation: savedHostInlineProxyCredentialMutation(
          editor.inlineProxyCredentialAction,
          stagedCredentialReference,
        ),
      },
  );
};

const savedHostProxyProfileMutation = (
  editor: SavedHostEditor,
): SavedHostProxyProfileMutation => {
  const currentProfileId = editor.host?.proxy?.proxyProfileId ?? "";
  if (editor.proxyProfileId === currentProfileId) return { action: "keep" };
  return editor.proxyProfileId
    ? { action: "replace", profileId: editor.proxyProfileId }
    : { action: "remove" };
};

const buildSavedHostProxyMutation = (
  editor: SavedHostEditor,
  inlineConfig: ProxyProfileConfigRequest | null,
): SavedHostProxyMutation | undefined => {
  const currentInlineProxy = editor.host?.proxy?.inlineProxy ?? null;
  if (
    editor.mode === "create"
    && !editor.inlineProxyEnabled
    && !editor.proxyProfileId
  ) {
    return undefined;
  }
  let inlineProxy: SavedHostInlineProxyMutation;
  if (editor.inlineProxyEnabled && inlineConfig) {
    inlineProxy = { action: "replace", config: inlineConfig };
  } else if (currentInlineProxy) {
    inlineProxy = { action: "remove" };
  } else {
    inlineProxy = { action: "keep" };
  }
  return {
    inlineProxy,
    profile: savedHostProxyProfileMutation(editor),
  };
};

const savedHostSessionErrorMessage = (reason: unknown, t: Translate): string => {
  const message = messageOf(reason);
  if (hasErrorCode(message, SAVED_CREDENTIAL_NOT_FOUND)) {
    return /proxy needs a one-time password/i.test(message)
      ? SAVED_PROXY_CREDENTIAL_NOT_FOUND
      : SAVED_CREDENTIAL_NOT_FOUND;
  }
  if (hasErrorCode(message, SAVED_HOST_KEY_FILE_CONFIRMATION_REQUIRED)) {
    return t("connectionPrompt.error.keyFileConfirmationRequired");
  }
  if (hasErrorCode(message, SAVED_HOST_KEY_FILE_SELECTION_INVALID)) {
    return t("connectionPrompt.error.keyFileSelectionInvalid");
  }
  if (hasErrorCode(message, "SAVED_HOST_NOT_FOUND")) {
    return t("savedHost.error.notFound");
  }
  if (
    hasErrorCode(message, "SAVED_HOST_REPAIR_REQUIRED")
    || hasErrorCode(message, "SAVED_HOST_PROXY_REPAIR_REQUIRED")
  ) {
    return t("savedHost.error.repairRequired");
  }
  if (hasErrorCode(message, "SAVED_HOST_MANAGED_KEY_UNAVAILABLE")) {
    return t("savedHost.error.managedKeyUnavailable");
  }
  return t("terminal.runtime.connectionFailed");
};

const isSavedHostRevisionConflict = (message: string): boolean =>
  hasErrorCode(message, "SAVED_HOST_REVISION_CONFLICT")
  || /changed by another window|revision/i.test(message);

const savedHostMutationErrorMessage = (
  reason: unknown,
  action: "save" | "delete",
  t: Translate,
): string => {
  const message = messageOf(reason);
  if (isSavedHostRevisionConflict(message)) {
    return t("savedHost.error.revisionConflict");
  }
  if (hasErrorCode(message, "SAVED_HOST_NOT_FOUND")) {
    return t("savedHost.error.notFound");
  }
  if (
    hasErrorCode(message, "SAVED_HOST_REPAIR_REQUIRED")
    || hasErrorCode(message, "SAVED_HOST_PROXY_REPAIR_REQUIRED")
  ) {
    return t("savedHost.error.repairRequired");
  }
  if (hasErrorCode(message, "SAVED_HOST_MANAGED_KEY_UNAVAILABLE")) {
    return t("savedHost.error.managedKeyUnavailable");
  }
  if ([
    "SAVED_HOST_CREDENTIAL_MUTATION_INVALID",
    "SAVED_HOST_PROXY_INVALID",
    "SAVED_HOST_AUTH_RELATIONSHIP_INVALID",
    "SAVED_HOST_AUTH_METHOD_UNSUPPORTED",
    "SAVED_HOST_REFERENCE_CERTIFICATE_UNSUPPORTED",
    "SAVED_HOST_CHAIN_INVALID",
    "SAVED_HOST_CHAIN_CREDENTIAL_REQUIRED",
  ].some((code) => hasErrorCode(message, code))) {
    return t("savedHost.error.invalid");
  }
  return action === "delete"
    ? t("savedHost.error.deleteFailed")
    : t("savedHost.error.saveFailed");
};

const isManagedSshKeyInventoryConflict = (message: string): boolean =>
  message.includes(MANAGED_SSH_KEY_INVENTORY_CHANGED)
  || /inventory.*revision/i.test(message);

const sameInventoryRevision = (left: unknown, right: unknown): boolean => {
  if (Object.is(left, right)) return true;
  try {
    return JSON.stringify(left) === JSON.stringify(right);
  } catch {
    return false;
  }
};

const managedSshKeyErrorMessage = (
  reason: unknown,
  action: "list" | "stage" | "create" | "update" | "delete" | "rotate",
  t: Translate,
): string => {
  const message = messageOf(reason);
  if (isManagedSshKeyInventoryConflict(message)) {
    return t("managedKey.error.inventoryChanged");
  }
  if (message.includes(MANAGED_SSH_KEY_IN_USE)) {
    return t("managedKey.error.inUse");
  }
  if (action === "list") return t("managedKey.error.list");
  if (action === "stage") return t("managedKey.error.stage");
  if (action === "delete") return t("managedKey.error.delete");
  if (action === "rotate") return t("managedKey.error.rotate");
  return action === "create"
    ? t("managedKey.error.create")
    : t("managedKey.error.update");
};

const readBoundedManagedSshKeyFile = async (
  file: File,
  maximumBytes: number,
): Promise<Uint8Array> => {
  if (file.size <= 0 || file.size > maximumBytes) {
    throw new Error("MANAGED_SSH_KEY_BUNDLE_INVALID");
  }
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes.byteLength <= 0 || bytes.byteLength > maximumBytes) {
    bytes.fill(0);
    throw new Error("MANAGED_SSH_KEY_BUNDLE_INVALID");
  }
  return bytes;
};

const legacyVaultSourceLabelKeys: Record<LegacyVaultSourceKind, MessageKey> = {
  bareHostArray: "legacyImport.source.hostList",
  unversionedVaultExport: "legacyImport.source.vaultExport",
  backupPlainJsonV1: "legacyImport.source.plainBackup",
  backupSafeStorageV1RequiresRecovery: "legacyImport.source.encryptedBackup",
};

const legacyVaultIssueMessageKeys: Record<
  LegacyVaultImportIssueCode | "LEGACY_PASSWORD_IDENTITY_RESIDUAL_KEY_REFERENCE_IGNORED",
  MessageKey
> = {
  LEGACY_SOURCE_RECOVERY_REQUIRED: "legacyImport.issue.sourceRecovery",
  LEGACY_HOST_REJECTED: "legacyImport.issue.hostRejected",
  LEGACY_HOST_UNSUPPORTED: "legacyImport.issue.hostUnsupported",
  LEGACY_DUPLICATE_HOST_ID: "legacyImport.issue.duplicateHost",
  LEGACY_SECRET_MATERIAL_STRIPPED: "legacyImport.issue.secretStripped",
  LEGACY_ENCRYPTED_CREDENTIAL_REENTRY_REQUIRED: "legacyImport.issue.encryptedCredential",
  LEGACY_OVERSIZED_CREDENTIAL_REENTRY_REQUIRED: "legacyImport.issue.oversizedCredential",
  LEGACY_INVALID_CREDENTIAL_REENTRY_REQUIRED: "legacyImport.issue.invalidCredential",
  LEGACY_MISSING_CREDENTIAL_REENTRY_REQUIRED: "legacyImport.issue.missingCredential",
  LEGACY_ADDITIONAL_CREDENTIAL_REENTRY_REQUIRED: "legacyImport.issue.additionalCredential",
  LEGACY_PASSWORD_NOT_SAVED_BY_POLICY: "legacyImport.issue.passwordPolicy",
  LEGACY_NON_SSH_PASSWORD_REENTRY_REQUIRED: "legacyImport.issue.nonSshPassword",
  LEGACY_SSH_KEY_REJECTED: "legacyImport.issue.keyRejected",
  LEGACY_SSH_KEY_UNSUPPORTED: "legacyImport.issue.keyUnsupported",
  LEGACY_DUPLICATE_SSH_KEY_ID: "legacyImport.issue.duplicateKey",
  LEGACY_SSH_KEY_CREDENTIAL_RECOVERY_REQUIRED: "legacyImport.issue.keyRecovery",
  LEGACY_SSH_CERTIFICATE_UNSUPPORTED: "legacyImport.issue.certificateUnsupported",
  LEGACY_IDENTITY_REJECTED: "legacyImport.issue.identityRejected",
  LEGACY_IDENTITY_UNSUPPORTED: "legacyImport.issue.identityUnsupported",
  LEGACY_DUPLICATE_IDENTITY_ID: "legacyImport.issue.duplicateIdentity",
  LEGACY_IDENTITY_CREDENTIAL_REENTRY_REQUIRED: "legacyImport.issue.identityCredential",
  LEGACY_PASSWORD_IDENTITY_RESIDUAL_KEY_REFERENCE_IGNORED: "legacyImport.issue.residualKeyReference",
  LEGACY_MISSING_SSH_KEY_REFERENCE: "legacyImport.issue.missingKeyReference",
  LEGACY_MISSING_IDENTITY_REFERENCE: "legacyImport.issue.missingIdentityReference",
  LEGACY_INVALID_IDENTITY_FILE_PATHS: "legacyImport.issue.invalidIdentityPaths",
};

const legacyVaultRecordKindLabelKeys: Record<string, MessageKey> = {
  source: "legacyImport.record.source",
  host: "legacyImport.record.host",
  sshKey: "legacyImport.record.sshKey",
  identity: "legacyImport.record.identity",
} as const;

const LEGACY_VAULT_SUMMARY_ROWS = [
  ["sourceCount", "legacyImport.summary.sourceHosts", false],
  ["importableCount", "legacyImport.summary.importableHosts", true],
  ["duplicateCount", "legacyImport.summary.duplicateHosts", false],
  ["conflictCount", "legacyImport.summary.conflictingHosts", false],
  ["unsupportedCount", "legacyImport.summary.unsupportedHosts", false],
  ["sourceSshKeyCount", "legacyImport.summary.sourceSshKeys", false],
  ["importableSshKeyReferenceCount", "legacyImport.summary.importableKeyReferences", true],
  ["duplicateSshKeyReferenceCount", "legacyImport.summary.duplicateKeyReferences", false],
  ["conflictSshKeyReferenceCount", "legacyImport.summary.conflictingKeyReferences", false],
  ["sourceManagedSshKeyCount", "legacyImport.summary.sourceManagedKeys", false],
  ["importableManagedSshKeyCount", "legacyImport.summary.importableManagedKeys", true],
  ["duplicateManagedSshKeyCount", "legacyImport.summary.duplicateManagedKeys", false],
  ["conflictManagedSshKeyCount", "legacyImport.summary.conflictingManagedKeys", false],
  ["managedSshKeyRecoveryRequiredCount", "legacyImport.summary.managedKeysNeedRecovery", false],
  ["managedPassphrasesDiscardedByPolicyCount", "legacyImport.summary.passphrasesNotSaved", false],
  ["unsupportedSshKeyCount", "legacyImport.summary.unsupportedKeys", false],
  ["sourceIdentityCount", "legacyImport.summary.sourceIdentities", false],
  ["importableIdentityReferenceCount", "legacyImport.summary.importableIdentities", true],
  ["duplicateIdentityReferenceCount", "legacyImport.summary.duplicateIdentities", false],
  ["conflictIdentityReferenceCount", "legacyImport.summary.conflictingIdentities", false],
  ["sourcePasswordIdentityCount", "legacyImport.summary.sourcePasswordIdentities", false],
  ["importablePasswordIdentityCount", "legacyImport.summary.importablePasswordIdentities", true],
  ["duplicatePasswordIdentityCount", "legacyImport.summary.duplicatePasswordIdentities", false],
  ["conflictPasswordIdentityCount", "legacyImport.summary.conflictingPasswordIdentities", false],
  ["recoverablePasswordIdentityCredentialCount", "legacyImport.summary.recoverableIdentityPasswords", false],
  ["passwordIdentityCredentialReentryRequiredCount", "legacyImport.summary.identityPasswordsNeedReentry", false],
  ["recoverableTelnetCredentialCount", "legacyImport.summary.recoverableTelnetPasswords", false],
  ["telnetCredentialReentryRequiredCount", "legacyImport.summary.telnetPasswordsNeedReentry", false],
  ["unsupportedIdentityCount", "legacyImport.summary.unsupportedIdentities", false],
  ["sourceProxyProfileCount", "legacyImport.summary.sourceProxyProfiles", false],
  ["sourceInlineProxyHostCount", "legacyImport.summary.hostsWithInlineProxy", false],
  ["importableProxyProfileCount", "legacyImport.summary.importableProxyProfiles", true],
  ["duplicateProxyProfileCount", "legacyImport.summary.duplicateProxyProfiles", false],
  ["conflictProxyProfileCount", "legacyImport.summary.conflictingProxyProfiles", false],
  ["recoverableProxyProfileCredentialCount", "legacyImport.summary.recoverableProxyPasswords", false],
  ["recoverableInlineProxyCredentialCount", "legacyImport.summary.recoverableInlineProxyPasswords", false],
  ["proxyProfileCredentialReentryRequiredCount", "legacyImport.summary.proxyPasswordsNeedReentry", false],
  ["inlineProxyCredentialReentryRequiredCount", "legacyImport.summary.inlineProxyPasswordsNeedReentry", false],
  ["unsupportedProxyProfileCount", "legacyImport.summary.unsupportedProxyProfiles", false],
  ["sourceCustomGroupCount", "legacyImport.summary.sourceCustomGroups", false],
  ["importableCustomGroupCount", "legacyImport.summary.importableCustomGroups", true],
  ["duplicateCustomGroupCount", "legacyImport.summary.duplicateCustomGroups", false],
  ["conflictCustomGroupCount", "legacyImport.summary.conflictingCustomGroups", false],
  ["sourceGroupConfigCount", "legacyImport.summary.sourceGroupConfigs", false],
  ["importableGroupConfigCount", "legacyImport.summary.importableGroupConfigs", true],
  ["duplicateGroupConfigCount", "legacyImport.summary.duplicateGroupConfigs", false],
  ["conflictGroupConfigCount", "legacyImport.summary.conflictingGroupConfigs", false],
  ["sourceSnippetCount", "legacyImport.summary.sourceScripts", false],
  ["importableSnippetCount", "legacyImport.summary.importableScripts", true],
  ["duplicateSnippetCount", "legacyImport.summary.duplicateScripts", false],
  ["conflictSnippetCount", "legacyImport.summary.conflictingScripts", false],
  ["sourceSnippetPackageCount", "legacyImport.summary.sourceScriptPackages", false],
  ["importableSnippetPackageCount", "legacyImport.summary.importableScriptPackages", true],
  ["duplicateSnippetPackageCount", "legacyImport.summary.duplicateScriptPackages", false],
  ["sourceNoteCount", "legacyImport.summary.sourceNotes", false],
  ["importableNoteCount", "legacyImport.summary.importableNotes", true],
  ["duplicateNoteCount", "legacyImport.summary.duplicateNotes", false],
  ["conflictNoteCount", "legacyImport.summary.conflictingNotes", false],
  ["sourceNoteGroupCount", "legacyImport.summary.sourceNoteGroups", false],
  ["importableNoteGroupCount", "legacyImport.summary.importableNoteGroups", true],
  ["duplicateNoteGroupCount", "legacyImport.summary.duplicateNoteGroups", false],
  ["catalogScopeChangeCount", "legacyImport.summary.emptyCatalogChanges", true],
  ["remappedSnippetIdCount", "legacyImport.summary.remappedScriptIds", false],
  ["remappedNoteIdCount", "legacyImport.summary.remappedNoteIds", false],
  ["remappedHostScriptEdgeCount", "legacyImport.summary.remappedHostScriptLinks", false],
  ["remappedGroupScriptEdgeCount", "legacyImport.summary.remappedGroupScriptLinks", false],
  ["remappedEntityCount", "legacyImport.summary.safelyRemapped", false],
  ["recoverableCredentialCount", "legacyImport.summary.recoverableCredentials", false],
  ["requiresCredentialReentryCount", "legacyImport.summary.passwordsNeedReentry", false],
] as const satisfies ReadonlyArray<readonly [keyof LegacyVaultInspection, MessageKey, boolean]>;

const legacyVaultImportableEntityCount = (inspection: LegacyVaultInspection): number =>
  inspection.importableCount
  + inspection.importableSshKeyReferenceCount
  + inspection.importableManagedSshKeyCount
  + inspection.importableIdentityReferenceCount
  + inspection.importablePasswordIdentityCount
  + inspection.importableProxyProfileCount
  + inspection.importableCustomGroupCount
  + inspection.importableGroupConfigCount
  + inspection.importableSnippetCount
  + inspection.importableSnippetPackageCount
  + inspection.importableNoteCount
  + inspection.importableNoteGroupCount;

const legacyVaultInspectionHasChanges = (inspection: LegacyVaultInspection): boolean =>
  legacyVaultImportableEntityCount(inspection) > 0
  || inspection.catalogScopeChangeCount > 0;

const legacyVaultErrorMessage = (
  reason: unknown,
  action: "inspect" | "commit",
  t: Translate,
): string => {
  const error = messageOf(reason);
  if (hasErrorCode(error, "LEGACY_VAULT_IMPORT_REPAIR_REQUIRED")) {
    return t("legacyImport.error.repairRequired");
  }
  if (hasErrorCode(error, "LEGACY_VAULT_CREDENTIAL_REPAIR_FAILED")) {
    return t("legacyImport.error.credentialRepair");
  }
  if (hasErrorCode(error, "LEGACY_VAULT_SOURCE_UNAVAILABLE")) {
    return t("legacyImport.error.sourceUnavailable");
  }
  if (hasErrorCode(error, "LEGACY_VAULT_SOURCE_NOT_REGULAR")) {
    return t("legacyImport.error.sourceNotRegular");
  }
  if (hasErrorCode(error, "LEGACY_VAULT_SOURCE_TOO_LARGE")) {
    return t("legacyImport.error.sourceTooLarge");
  }
  if (hasErrorCode(error, "LEGACY_VAULT_SOURCE_CHANGED")) {
    return t("legacyImport.error.sourceChanged");
  }
  if (hasErrorCode(error, "LEGACY_VAULT_RECOVERY_REQUIRED")) {
    return t("legacyImport.error.recoveryRequired");
  }
  if (hasErrorCode(error, "LEGACY_VAULT_INVENTORY_CHANGED")) {
    return t("legacyImport.error.inventoryChanged");
  }
  if (hasErrorCode(error, "LEGACY_VAULT_SOURCE_INVALID")) {
    return t("legacyImport.error.sourceInvalid");
  }
  if (hasErrorCode(error, "LEGACY_VAULT_ASSESSMENT_FAILED")) {
    return t("legacyImport.error.assessmentFailed");
  }
  if (hasErrorCode(error, "LEGACY_VAULT_CREDENTIAL_FAILED")) {
    return t("legacyImport.error.credentialFailed");
  }
  if (hasErrorCode(error, "LEGACY_VAULT_IMPORT_FAILED")) {
    return t("legacyImport.error.importFailed");
  }
  return action === "inspect"
    ? t("legacyImport.error.inspectFailed")
    : t("legacyImport.error.commitFailed");
};

const joinLocalChildPath = (parent: string, child: string): string => {
  const separator = parent.includes("\\") ? "\\" : "/";
  return `${parent}${/[\\/]$/.test(parent) ? "" : separator}${child}`;
};

const formatByteCount = (bytes: number, locale: string): string => {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / (1024 ** exponent);
  return `${value.toLocaleString(locale, {
    maximumFractionDigits: exponent === 0 ? 0 : 1,
  })} ${units[exponent]}`;
};

export function TerminalWorkspace() {
  const workbenchElement = useRef<HTMLElement>(null);
  const terminalElement = useRef<HTMLDivElement>(null);
  const terminalPaneStageElement = useRef<HTMLDivElement>(null);
  const terminal = useRef<Terminal | null>(null);
  const fitAddon = useRef<FitAddon | null>(null);
  const webglAddon = useRef<WebglAddon | null>(null);
  const webglLoadGeneration = useRef(0);
  const session = useRef<ActiveTerminalSession | null>(null);
  const telnetLocalEcho = useRef(false);
  const serialInputConfig = useRef<SerialConfig | null>(null);
  const serialLineBuffer = useRef("");
  const serialYmodemTransferOwner = useRef<SerialYmodemTransferOwner | null>(null);
  const nextSerialYmodemTransferToken = useRef(0);
  const serialZmodemTransferOwner = useRef<SerialZmodemTransferOwner | null>(null);
  const nextSerialZmodemTransferToken = useRef(0);
  const handleSessionControlRef = useRef<((
    operation: ConnectionOperation,
    control: Parameters<SshSessionCallbacks["onControl"]>[0],
  ) => void) | null>(null);
  const terminalResizeCoordinator = useRef<TerminalResizeCoordinator | null>(null);
  const legacySftpGeneration = useRef(0);
  const sftpControllerRef = useRef<SftpSessionController | null>(null);
  if (!sftpControllerRef.current) {
    sftpControllerRef.current = new SftpSessionController({
      readDirectory: async (sessionId, path) => {
        try {
          return await readSftpDirectory(sessionId, path);
        } catch {
          throw new Error(SFTP_DIRECTORY_ERROR);
        }
      },
      formatError: (reason) => messageOf(reason) === SFTP_DIRECTORY_ERROR
        ? SFTP_DIRECTORY_ERROR
        : SFTP_TRANSFER_ERROR,
    });
  }
  const sftpController = sftpControllerRef.current;
  const knownSftpWorkspaceIds = useRef(new Set<WorkspaceSessionId>());
  const activeSftpWorkspaceIdRef = useRef<WorkspaceSessionId | null>(null);
  const pendingSftpStops = useRef(new Map<WorkspaceSessionId, {
    remove: boolean;
    promise: Promise<string | null>;
  }>());
  const connectionOperation = useRef<ConnectionOperation | null>(null);
  const nextConnectionToken = useRef(0);
  const savedHostMutation = useRef<number | null>(null);
  const nextSavedHostMutationToken = useRef(0);
  const nextSavedHostsRefreshToken = useRef(0);
  const savedHostsRefreshCoordinator = useRef<CoalescedRefresh<
    boolean,
    SavedHost[] | null
  > | null>(null);
  const nextManagedSshKeysRefreshToken = useRef(0);
  const managedInventoryRevision = useRef<ObservedInventoryRevision>({
    seen: false,
    value: undefined,
  });
  const passwordIdentityInventoryRevision = useRef<ObservedInventoryRevision>({
    seen: false,
    value: undefined,
  });
  const proxyProfileInventoryRevision = useRef<ObservedInventoryRevision>({
    seen: false,
    value: undefined,
  });
  const groupConfigInventoryRevision = useRef<ObservedInventoryRevision>({
    seen: false,
    value: undefined,
  });
  const managedPrivateKeyInput = useRef<HTMLInputElement>(null);
  const managedPublicKeyInput = useRef<HTMLInputElement>(null);
  const managedCertificateInput = useRef<HTMLInputElement>(null);
  const managedPassphraseInput = useRef<HTMLInputElement>(null);
  const [hostname, setHostname] = useState("");
  const [quickProtocol, setQuickProtocol] = useState<NetworkConnectionProtocol>("ssh");
  const [rendererSettings, setRendererSettings] = useState(
    () => createDefaultRendererSafeSettings(),
  );
  useAppColorMode(rendererSettings.appearance.colorMode);
  useUiFontFamily(rendererSettings.appearance.uiFontFamilyId);
  const rendererLocale = normalizeLocale(rendererSettings.appearance.uiLanguage);
  const { t } = useI18n(rendererLocale);
  const translateRef = useRef<Translate>(t);
  translateRef.current = t;
  useEffect(() => {
    document.documentElement.lang = rendererLocale;
    const title = t("app.mainWindowTitle");
    document.title = title;
    if (NATIVE_DESKTOP_RUNTIME_AVAILABLE) {
      void import("@tauri-apps/api/window")
        .then(({ getCurrentWindow }) => getCurrentWindow().setTitle(title))
        .catch(() => undefined);
    }
  }, [rendererLocale, t]);
  const formatBytes = useCallback(
    (bytes: number): string => formatByteCount(bytes, rendererLocale),
    [rendererLocale],
  );
  const formatCount = useCallback(
    (count: number): string => count.toLocaleString(rendererLocale),
    [rendererLocale],
  );
  const [rendererSettingsReady, setRendererSettingsReady] = useState(false);
  const settingsReloadCoordinatorRef = useRef<SettingsReloadCoordinator<
    Awaited<ReturnType<typeof SETTINGS_ADAPTER.load>>
  > | null>(null);
  const [sessionRestoreSnapshot, setSessionRestoreSnapshot] = useState<SessionRestoreSnapshot | null>(null);
  const [sessionRestoreSettled, setSessionRestoreSettled] = useState(false);
  const [sessionRestoreConnectingId, setSessionRestoreConnectingId] = useState<WorkspaceSessionId | null>(null);
  const [sessionRestoreRestoring, setSessionRestoreRestoring] = useState(false);
  const [sessionRestoreError, setSessionRestoreError] = useState<string | null>(null);
  const sessionRestoreChecked = useRef(false);
  const restoredQuickSshSessionIds = useRef(new Set<WorkspaceSessionId>());
  const [legacyRestoreSessionId] = useState<WorkspaceSessionId>(() => createWorkspaceSessionId());
  const sessionRestoreStoreRef = useRef<ReturnType<typeof createSessionRestoreStore> | null>(null);
  if (!sessionRestoreStoreRef.current) {
    sessionRestoreStoreRef.current = createSessionRestoreStore({
      getItem: (key) => window.localStorage.getItem(key),
      setItem: (key, value) => window.localStorage.setItem(key, value),
      removeItem: (key) => window.localStorage.removeItem(key),
    });
  }
  const [port, setPort] = useState("22");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [connectionState, setConnectionState] = useState<ConnectionState>("disconnected");
  const [connectionTarget, setConnectionTarget] = useState<ConnectionTarget | null>(null);
  const [serialYmodemTransfer, setSerialYmodemTransfer] = useState<SerialYmodemTransferState | null>(null);
  const [serialZmodemTransfer, setSerialZmodemTransfer] = useState<SerialZmodemTransferState | null>(null);
  const [activeSurface, setActiveSurface] = useState<WorkspaceSurface>("vault");
  const [error, setError] = useState<string | null>(null);
  const [workspacePrompt, setWorkspacePrompt] = useState<WorkspacePromptDialogRequest | null>(null);
  const nextWorkspacePromptId = useRef(0);
  const workspacePromptResolver = useRef<{
    id: number;
    resolve: (result: string | boolean | null) => void;
  } | null>(null);
  const requestWorkspaceText = useCallback((
    request: Omit<WorkspacePromptDialogRequest, "id" | "kind">,
  ): Promise<string | null> => new Promise((resolve) => {
    workspacePromptResolver.current?.resolve(null);
    const id = ++nextWorkspacePromptId.current;
    workspacePromptResolver.current = {
      id,
      resolve: (result) => resolve(typeof result === "string" ? result : null),
    };
    setWorkspacePrompt({ ...request, id, kind: "text" });
  }), []);
  const requestWorkspaceConfirmation = useCallback((
    request: Omit<WorkspacePromptDialogRequest, "id" | "kind" | "initialValue">,
  ): Promise<boolean> => new Promise((resolve) => {
    workspacePromptResolver.current?.resolve(null);
    const id = ++nextWorkspacePromptId.current;
    workspacePromptResolver.current = {
      id,
      resolve: (result) => resolve(result === true),
    };
    setWorkspacePrompt({ ...request, id, kind: "confirm" });
  }), []);
  const settleWorkspacePrompt = useCallback((
    id: number,
    result: string | boolean | null,
  ) => {
    const pending = workspacePromptResolver.current;
    if (!pending || pending.id !== id) return;
    workspacePromptResolver.current = null;
    setWorkspacePrompt((current) => current?.id === id ? null : current);
    pending.resolve(result);
  }, []);
  useEffect(() => () => {
    workspacePromptResolver.current?.resolve(null);
    workspacePromptResolver.current = null;
  }, []);
  const [hostKeySaving, setHostKeySaving] = useState(false);
  const [interactiveAnswers, setInteractiveAnswers] = useState<string[]>([]);
  const [terminalSidePanelTab, setTerminalSidePanelTab] = useState<TerminalSidePanelId>("sftp");
  const [terminalSidePanelOpen, setTerminalSidePanelOpen] = useState(false);
  const [discoveredAiAgents, setDiscoveredAiAgents] = useState<ReadonlyArray<DiscoveredAiAgent>>([]);
  const [terminalSidePanelWidth, setTerminalSidePanelWidth] = useState(372);
  const [terminalSidePanelResize, setTerminalSidePanelResize] = useState<TerminalSidePanelResize | null>(null);
  const [terminalPaneLayout, setTerminalPaneLayout] = useState<TerminalPaneLayoutSnapshot | null>(null);
  const [terminalPaneWorkspaceVisible, setTerminalPaneWorkspaceVisible] = useState(false);
  const [terminalPaneZoomedSessionId, setTerminalPaneZoomedSessionId] = useState<WorkspaceSessionId | null>(null);
  const [terminalPaneResize, setTerminalPaneResize] = useState<TerminalPaneResize | null>(null);
  const [draggedTerminalSessionId, setDraggedTerminalSessionId] = useState<WorkspaceSessionId | null>(null);
  const [terminalPaneDropHint, setTerminalPaneDropHint] = useState<TerminalPaneDropHint | null>(null);
  const [activeSftpProjection, setActiveSftpProjection] = useState<ActiveSftpProjection | null>(null);
  const [sidebarView, setSidebarView] = useState<SidebarView>("saved");
  const [hostViewMode, setHostViewMode] = useState<HostViewMode>("grid");
  const [savedHosts, setSavedHosts] = useState<SavedHost[]>([]);
  const [savedHostsHaveSnapshot, setSavedHostsHaveSnapshot] = useState(false);
  const [savedHostSearch, setSavedHostSearch] = useState("");
  const [selectedVaultGroup, setSelectedVaultGroup] = useState<string | null>(null);
  const [groupConfigCatalog, setGroupConfigCatalog] = useState<GroupConfigCatalogSnapshot | null>(null);
  const [groupConfigRefreshKey, setGroupConfigRefreshKey] = useState(0);
  const [notesSnippetsRefreshKey, setNotesSnippetsRefreshKey] = useState(0);
  const [knownHostsRefreshKey, setKnownHostsRefreshKey] = useState(0);
  const [groupConfigManagerOpen, setGroupConfigManagerOpen] = useState(false);
  const [groupConfigInitialPath, setGroupConfigInitialPath] = useState<string | null>(null);
  const filteredSavedHosts = useMemo(() => {
    const matches = filterSavedHosts(savedHosts, savedHostSearch);
    if (!selectedVaultGroup) return matches;
    return matches.filter((host) => (
      host.group === selectedVaultGroup
      || host.group?.startsWith(`${selectedVaultGroup}/`) === true
    ));
  }, [savedHostSearch, savedHosts, selectedVaultGroup]);
  const savedHostGroups = useMemo(() => Array.from(new Set([
    ...savedHosts.map((host) => host.group ?? ""),
    ...(groupConfigCatalog?.customGroups ?? []),
    ...(groupConfigCatalog?.groups.map((group) => group.path) ?? []),
  ].filter((group) => group.split("/").some((segment) => segment.length > 0))))
    .sort((left, right) => left.localeCompare(right)), [
    groupConfigCatalog?.customGroups,
    groupConfigCatalog?.groups,
    savedHosts,
  ]);
  const savedHostTags = useMemo(() => Array.from(new Set(
    savedHosts.flatMap((host) => host.tags),
  )).sort((left, right) => left.localeCompare(right)), [savedHosts]);
  const groupTreeOrderConfigs = useMemo(() => (groupConfigCatalog?.groups ?? []).map((group) => ({
    path: group.path,
    order: group.defaults.order.state === "set" ? group.defaults.order.value : undefined,
  })), [groupConfigCatalog?.groups]);
  const savedHostGroupCards = useMemo(() => {
    const counts = new Map<string, { label: string; count: number }>();
    const immediateChild = (rawGroup: string): { path: string; label: string } | null => {
      const group = rawGroup.split("/").filter((segment) => segment.length > 0).join("/");
      if (!group) return null;
      let remainder = group;
      if (selectedVaultGroup) {
        const prefix = `${selectedVaultGroup}/`;
        if (!group.startsWith(prefix)) return null;
        remainder = group.slice(prefix.length);
      }
      const label = remainder.split("/")[0];
      if (!label) return null;
      return { path: selectedVaultGroup ? `${selectedVaultGroup}/${label}` : label, label };
    };
    for (const group of savedHostGroups) {
      const child = immediateChild(group);
      if (child && !counts.has(child.path)) counts.set(child.path, { label: child.label, count: 0 });
    }
    for (const host of savedHosts) {
      const group = host.group;
      if (!group) continue;
      const child = immediateChild(group);
      if (!child) continue;
      const current = counts.get(child.path);
      counts.set(child.path, { label: child.label, count: (current?.count ?? 0) + 1 });
    }
    return Array.from(counts, ([path, value]) => ({ path, ...value }))
      .sort((left, right) => {
        const leftOrder = groupTreeOrderConfigs.find((group) => group.path === left.path)?.order;
        const rightOrder = groupTreeOrderConfigs.find((group) => group.path === right.path)?.order;
        if (leftOrder !== undefined && rightOrder !== undefined && leftOrder !== rightOrder) return leftOrder - rightOrder;
        if (leftOrder !== undefined) return -1;
        if (rightOrder !== undefined) return 1;
        return left.label.localeCompare(right.label);
      });
  }, [groupTreeOrderConfigs, savedHostGroups, savedHosts, selectedVaultGroup]);
  const [savedHostsLoading, setSavedHostsLoading] = useState(true);
  const [savedHostsError, setSavedHostsError] = useState<string | null>(null);
  const [savedHostsNotice, setSavedHostsNotice] = useState<string | null>(null);
  const [savedHostEditor, setSavedHostEditor] = useState<SavedHostEditor | null>(null);
  const [serialPanel, setSerialPanel] = useState<SerialPanelState | null>(null);
  const [localTerminalPanelOpen, setLocalTerminalPanelOpen] = useState(false);
  const [savedHostSubmitting, setSavedHostSubmitting] = useState(false);
  const [savedHostPasswordPrompt, setSavedHostPasswordPrompt] = useState<SavedHostPasswordPrompt | null>(null);
  const [savedHostProxyPasswordPrompt, setSavedHostProxyPasswordPrompt] = useState<SavedHostProxyPasswordPrompt | null>(null);
  const [savedHostKeyPassphrasePrompt, setSavedHostKeyPassphrasePrompt] = useState<SavedHostKeyPassphrasePrompt | null>(null);
  const [legacyVaultPreview, setLegacyVaultPreview] = useState<LegacyVaultImportPreview | null>(null);
  const [managedSshKeyCatalog, setManagedSshKeyCatalog] = useState<ManagedSshKeyCatalog | null>(null);
  const [managedSshKeysLoading, setManagedSshKeysLoading] = useState(true);
  const [managedSshKeysError, setManagedSshKeysError] = useState<string | null>(null);
  const [managedSshKeysNotice, setManagedSshKeysNotice] = useState<string | null>(null);
  const [managedSshKeyEditor, setManagedSshKeyEditor] = useState<ManagedSshKeyEditor | null>(null);
  const [managedSshKeyDelete, setManagedSshKeyDelete] = useState<ManagedSshKeyDeletePrompt | null>(null);
  const [managedMasterKeyRotationOpen, setManagedMasterKeyRotationOpen] = useState(false);
  const [passwordIdentityCatalog, setPasswordIdentityCatalog] = useState<PasswordIdentityCatalogSnapshot | null>(null);
  const [passwordIdentityRefreshKey, setPasswordIdentityRefreshKey] = useState(0);
  const [proxyProfileCatalog, setProxyProfileCatalog] = useState<ProxyProfileCatalogSnapshot | null>(null);
  const [proxyProfileRefreshKey, setProxyProfileRefreshKey] = useState(0);
  const appTerminalColorMode = rendererSettings.appearance.colorMode === "system"
    ? (window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light")
    : rendererSettings.appearance.colorMode;
  const localTerminalAppearance = useMemo(
    () => resolveTerminalAppearance(rendererSettings.terminal, {
      appColorMode: appTerminalColorMode,
    }),
    [appTerminalColorMode, rendererSettings.terminal],
  );
  const liveTerminalAppearance = useMemo(
    () => resolveTerminalAppearance(rendererSettings.terminal, {
      appColorMode: appTerminalColorMode,
      ...(connectionTarget?.effectiveAppearance ? {
        themeId: connectionTarget.effectiveAppearance.themeId ?? undefined,
        fontFamily: connectionTarget.effectiveAppearance.fontFamily ?? undefined,
        fontSize: connectionTarget.effectiveAppearance.fontSize ?? undefined,
        fontWeight: connectionTarget.effectiveAppearance.fontWeight ?? undefined,
        isHostAppearance: true,
      } : {}),
    }),
    [appTerminalColorMode, connectionTarget?.effectiveAppearance, rendererSettings.terminal],
  );
  const liveTerminalAppearanceRef = useRef(liveTerminalAppearance);
  liveTerminalAppearanceRef.current = liveTerminalAppearance;
  const terminalSessionCatalogRef = useRef<TerminalSessionCatalog | null>(null);
  if (!terminalSessionCatalogRef.current) {
    terminalSessionCatalogRef.current = createTerminalSessionCatalog();
  }
  const terminalSessionCatalog = terminalSessionCatalogRef.current;
  const localTerminals = useLocalTerminalSessions(
    localTerminalAppearance,
    terminalSessionCatalog,
    t,
  );
  const resolveSshTerminalAppearance = useCallback((target: SshTerminalTarget) => (
    resolveTerminalAppearance(rendererSettings.terminal, {
      appColorMode: appTerminalColorMode,
      ...(target.appearanceOverride ?? {}),
      isHostAppearance: target.kind === "saved",
    })
  ), [appTerminalColorMode, rendererSettings.terminal]);
  const sshTerminals = useSshTerminalSessions(
    terminalSessionCatalog,
    resolveSshTerminalAppearance,
    t,
  );
  const localTerminalTargetFor = localTerminals.targetFor;
  const sshTerminalTargetFor = sshTerminals.targetFor;
  const sharedTerminalRegistry = localTerminals.registry;
  const sshTerminalsRef = useRef(sshTerminals);
  sshTerminalsRef.current = sshTerminals;
  const sshPromptQueueRef = useRef<SshPromptQueue | null>(null);
  if (!sshPromptQueueRef.current) {
    sshPromptQueueRef.current = new SshPromptQueue({
      resolveAttempt: (clientAttemptId) => (
        sshTerminalsRef.current.workspaceSessionIdForAttempt(clientAttemptId) ?? null
      ),
      isInternalAttempt: (clientAttemptId) => clientAttemptId.startsWith("internal-"),
      rejectHostKey: (requestId) => respondToHostKey(requestId, false),
      cancelInteractive: cancelInteractiveAuth,
    });
  }
  const sshPromptQueue = sshPromptQueueRef.current;
  const pendingSshPromptQueueDisposalRef = useRef<object | null>(null);
  const [sshPromptSnapshot, setSshPromptSnapshot] = useState<SshPromptQueueSnapshot>(
    () => sshPromptQueue.snapshot,
  );
  const currentSshPrompt = sshPromptSnapshot.current;
  const hostKeyPrompt = currentSshPrompt?.kind === "hostKey"
    ? currentSshPrompt.prompt
    : null;
  const interactivePrompt = currentSshPrompt?.kind === "interactive"
    ? currentSshPrompt.prompt
    : null;
  const previousSharedSessionCount = useRef(0);

  useEffect(() => {
    for (const workspaceSessionId of restoredQuickSshSessionIds.current) {
      if (!sharedTerminalRegistry.sessions[workspaceSessionId]) {
        restoredQuickSshSessionIds.current.delete(workspaceSessionId);
      }
    }
  }, [sharedTerminalRegistry]);

  useEffect(() => {
    const sessionCount = sharedTerminalRegistry.order.length;
    if (
      previousSharedSessionCount.current > 0
      && sessionCount === 0
      && connectionTarget === null
      && activeSurface === "terminal"
    ) {
      setActiveSurface("vault");
    }
    previousSharedSessionCount.current = sessionCount;
  }, [activeSurface, connectionTarget, sharedTerminalRegistry.order.length]);

  useEffect(() => {
    setSshPromptSnapshot(sshPromptQueue.snapshot);
    return sshPromptQueue.subscribe(setSshPromptSnapshot);
  }, [sshPromptQueue]);

  useEffect(() => {
    // React StrictMode performs a synchronous cleanup/setup probe. A deferred
    // disposal survives that probe but still rejects every native prompt on a
    // real window unmount.
    pendingSshPromptQueueDisposalRef.current = null;
    return () => {
      const token = {};
      pendingSshPromptQueueDisposalRef.current = token;
      queueMicrotask(() => {
        if (pendingSshPromptQueueDisposalRef.current !== token) return;
        sshPromptQueue.dispose();
        pendingSshPromptQueueDisposalRef.current = null;
      });
    };
  }, [sshPromptQueue]);

  useEffect(() => {
    sshPromptQueue.prune();
  }, [sharedTerminalRegistry, sshPromptQueue]);

  useEffect(() => {
    if (!interactivePrompt) {
      setInteractiveAnswers([]);
      return;
    }
    setInteractiveAnswers(interactivePrompt.prompts.map(() => ""));
  }, [interactivePrompt?.requestId]);

  const activeLocalSession = localTerminals.activeSession;
  const activeSshSession = sshTerminals.activeSession;
  const activeSshTerminalCwd = activeSshSession
    ? sshTerminals.cwdFor(activeSshSession.id) ?? null
    : null;
  const activeSharedSession = activeLocalSession ?? activeSshSession;
  const activeSshTarget = activeSshSession
    ? sshTerminals.targetFor(activeSshSession.id)
    : undefined;
  const hasSharedTerminalSessions = sharedTerminalRegistry.order.length > 0;
  const activeTerminalAppearance = activeSshSession
    ? sshTerminals.appearanceFor(activeSshSession.id) ?? localTerminalAppearance
    : activeLocalSession
      ? localTerminalAppearance
      : liveTerminalAppearance;
  const terminalPaneSessionIds = useMemo(
    () => terminalPaneLayout
      ? collectTerminalPaneSessionIds(terminalPaneLayout.root)
      : [],
    [terminalPaneLayout],
  );
  const terminalPaneGeometry = useMemo(
    () => terminalPaneLayout
      ? computeTerminalPaneGeometry(terminalPaneLayout)
      : null,
    [terminalPaneLayout],
  );
  const terminalViewportPlacements = useMemo(() => {
    if (!terminalPaneWorkspaceVisible || !terminalPaneLayout) return undefined;
    const focusedSessionId = activeSharedSession
      && terminalPaneLayoutContains(terminalPaneLayout, activeSharedSession.id)
      ? activeSharedSession.id
      : terminalPaneLayout.focusedSessionId;
    if (
      terminalPaneZoomedSessionId
      && terminalPaneLayoutContains(terminalPaneLayout, terminalPaneZoomedSessionId)
    ) {
      return Object.freeze({
        [terminalPaneZoomedSessionId]: Object.freeze({
          rect: Object.freeze({ x: 0, y: 0, width: 1, height: 1 }),
          focused: terminalPaneZoomedSessionId === focusedSessionId,
        }),
      });
    }
    return createTerminalPanePlacements(terminalPaneLayout, focusedSessionId);
  }, [
    activeSharedSession,
    terminalPaneLayout,
    terminalPaneWorkspaceVisible,
    terminalPaneZoomedSessionId,
  ]);
  const hasTerminalPaneWorkspace = terminalPaneSessionIds.length > 1;
  const terminalWorkspaceTabs = useMemo(
    () => createTerminalWorkspaceTabs(
      sharedTerminalRegistry.order,
      hasTerminalPaneWorkspace ? terminalPaneSessionIds : [],
    ),
    [hasTerminalPaneWorkspace, sharedTerminalRegistry.order, terminalPaneSessionIds],
  );
  const fitSharedTerminalSessionsOnNextFrame = useCallback((
    workspaceSessionIds: readonly WorkspaceSessionId[],
  ): void => {
    const exactSessionIds = [...new Set(workspaceSessionIds)];
    window.requestAnimationFrame(() => {
      for (const workspaceSessionId of exactSessionIds) {
        const snapshot = terminalSessionCatalog.snapshot.sessions[workspaceSessionId];
        if (snapshot?.protocol === "local") {
          localTerminals.fit(workspaceSessionId);
        } else if (snapshot?.protocol === "ssh" && sshTerminals.owns(workspaceSessionId)) {
          sshTerminals.fit(workspaceSessionId);
        }
      }
    });
  }, [localTerminals, sshTerminals, terminalSessionCatalog]);
  const sftpAvailable = activeSshSession !== null || connectionTarget?.protocol === "ssh";
  const sftpTabVisible = sftpAvailable && rendererSettings.appearance.showSftpTab;
  const sftpOpen = sftpTabVisible && terminalSidePanelOpen && terminalSidePanelTab === "sftp";
  const aiOpen = terminalSidePanelOpen && terminalSidePanelTab === "ai";
  const dockerOpen = terminalSidePanelOpen && terminalSidePanelTab === "docker";
  const [editorTarget, setEditorTarget] = useState<{ sessionId: string; path: string } | null>(null);
  const dockerSessionId = activeSshSession
    ? sshTerminals.backendSessionIdFor(activeSshSession.id)
    : undefined;
  const terminalSidePanelVisible = sftpOpen || aiOpen || dockerOpen;
  useEffect(() => {
    if (!aiOpen || !NATIVE_DESKTOP_RUNTIME_AVAILABLE) return;
    let acceptsResult = true;
    void discoverAiAgents()
      .then((agents) => {
        if (acceptsResult) setDiscoveredAiAgents(agents);
      })
      .catch(() => {
        if (acceptsResult) setDiscoveredAiAgents([]);
      });
    return () => {
      acceptsResult = false;
    };
  }, [aiOpen]);
  const activeSftpRender = resolveActiveSftpProjection(
    activeSshSession?.id ?? null,
    activeSftpProjection,
    (owner) => sftpController.isExactOwner(owner),
  );
  const sftpPath = activeSftpRender?.snapshot.path ?? "/";
  const sftpEntries = activeSftpRender?.snapshot.entries ?? [];
  const sftpLoading = activeSftpRender?.snapshot.loading ?? false;
  const rawSftpError = activeSftpRender?.snapshot.error ?? null;
  const sftpError = rawSftpError ? localizeSftpError(rawSftpError, t) : null;
  const rawTransfers = activeSftpRender?.snapshot.transfers ?? [];
  const transfers = useMemo(() => rawTransfers.map((transfer) => (
    transfer.error
      ? { ...transfer, error: localizeSftpError(transfer.error, t) }
      : transfer
  )), [rawTransfers, t]);
  const visibleSftpEntries = useMemo(
    () => rendererSettings.sftp.showHiddenFiles
      ? sftpEntries
      : sftpEntries.filter((entry) => !entry.name.startsWith(".")),
    [rendererSettings.sftp.showHiddenFiles, sftpEntries],
  );
  const sftpPathRef = useRef(sftpPath);
  sftpPathRef.current = sftpPath;

  useLayoutEffect(() => {
    activeSftpWorkspaceIdRef.current = activeSshSession?.id ?? null;
  }, [activeSshSession?.id]);

  const projectActiveSftpSnapshot = useCallback((snapshot: SftpSessionSnapshot | null) => {
    if (!snapshot) {
      setActiveSftpProjection(null);
      return;
    }
    const owner = sftpController.getOwner(snapshot.workspaceId);
    if (!owner || !sftpController.isExactOwner(owner)) {
      setActiveSftpProjection(null);
      return;
    }
    setActiveSftpProjection(createActiveSftpProjection(owner, snapshot));
  }, [sftpController]);

  const bindSftpWorkspace = useCallback((workspaceId: WorkspaceSessionId) => {
    if (sftpController.isSuspended(workspaceId)) return null;
    if (terminalSessionCatalog.snapshot.sessions[workspaceId]?.state !== "connected") return null;
    const backendSessionId = sshTerminals.backendSessionIdFor(workspaceId);
    const operationGeneration = sshTerminals.operationGenerationFor(workspaceId);
    if (!backendSessionId || operationGeneration === undefined) return null;
    const owner = sftpController.bindSession({
      workspaceId,
      operationGeneration,
      backendSessionId,
    });
    knownSftpWorkspaceIds.current.add(workspaceId);
    if (sharedTerminalRegistry.activeSessionId === workspaceId) {
      sftpController.activate(workspaceId);
      projectActiveSftpSnapshot(sftpController.getSnapshot(workspaceId) ?? null);
    }
    return owner;
  }, [
    projectActiveSftpSnapshot,
    sftpController,
    sharedTerminalRegistry.activeSessionId,
    sshTerminals.backendSessionIdFor,
    sshTerminals.operationGenerationFor,
    terminalSessionCatalog,
  ]);

  const suspendSftpWorkspaceForStop = useCallback((
    workspaceId: WorkspaceSessionId,
  ): SftpSessionSuspension | null => {
    const owner = sftpController.getOwner(workspaceId);
    const suspension = owner
      ? sftpController.suspendSession(workspaceId, owner)
      : null;
    if (activeSftpWorkspaceIdRef.current === workspaceId) {
      projectActiveSftpSnapshot(null);
    }
    return suspension;
  }, [projectActiveSftpSnapshot, sftpController]);

  const stopSshWorkspace = useCallback((
    workspaceId: WorkspaceSessionId,
    remove: boolean,
  ): Promise<string | null> => {
    const existing = pendingSftpStops.current.get(workspaceId);
    if (existing) {
      if (remove && !existing.remove) {
        existing.remove = true;
        void sshTerminals.close(workspaceId);
      }
      return existing.promise;
    }

    const pending = {
      remove,
      promise: Promise.resolve<string | null>(null),
    };
    const suspension = suspendSftpWorkspaceForStop(workspaceId);
    const operation = (async () => {
      const recoverSftpAfterFailure = () => {
        const state = terminalSessionCatalog.snapshot.sessions[workspaceId]?.state;
        const runtimeCanResume = state === "connected" || state === "connecting";
        const resumedOwner = runtimeCanResume && suspension
          ? sftpController.resumeSession(suspension)
          : null;
        if (runtimeCanResume && !resumedOwner) bindSftpWorkspace(workspaceId);
        if (resumedOwner) {
          const resumedPath = sftpController.getSnapshot(workspaceId)?.path ?? "/";
          void sftpController.load(workspaceId, resumedPath, resumedOwner);
        }
        if (!runtimeCanResume && suspension) {
          sftpController.finalizeSuspension(suspension, pending.remove);
          if (pending.remove) knownSftpWorkspaceIds.current.delete(workspaceId);
        }
        if (activeSftpWorkspaceIdRef.current === workspaceId) {
          projectActiveSftpSnapshot(sftpController.getSnapshot(workspaceId) ?? null);
        }
      };

      let failure: string | null;
      try {
        failure = await (pending.remove
          ? sshTerminals.close(workspaceId)
          : sshTerminals.disconnect(workspaceId));
      } catch {
        recoverSftpAfterFailure();
        return t(SSH_SESSION_STOP_ERROR);
      }
      if (failure) {
        recoverSftpAfterFailure();
        return failure;
      }

      const finalized = suspension
        ? sftpController.finalizeSuspension(suspension, pending.remove)
        : false;
      if (!finalized) {
        if (pending.remove) sftpController.removeSession(workspaceId);
        else sftpController.resetSession(workspaceId);
      }
      if (pending.remove) knownSftpWorkspaceIds.current.delete(workspaceId);
      return null;
    })().finally(() => {
      if (pendingSftpStops.current.get(workspaceId) === pending) {
        pendingSftpStops.current.delete(workspaceId);
      }
    });
    pending.promise = operation;
    pendingSftpStops.current.set(workspaceId, pending);
    return operation;
  }, [
    bindSftpWorkspace,
    projectActiveSftpSnapshot,
    sftpController,
    sshTerminals,
    suspendSftpWorkspaceForStop,
    terminalSessionCatalog,
    t,
  ]);

  const disconnectSshWorkspace = useCallback((workspaceId: WorkspaceSessionId) => (
    stopSshWorkspace(workspaceId, false)
  ), [stopSshWorkspace]);

  const closeSshWorkspace = useCallback((workspaceId: WorkspaceSessionId) => (
    stopSshWorkspace(workspaceId, true)
  ), [stopSshWorkspace]);

  useEffect(() => sftpController.subscribe((snapshot) => {
    if (activeSftpWorkspaceIdRef.current === snapshot.workspaceId) {
      projectActiveSftpSnapshot(snapshot);
    }
  }), [projectActiveSftpSnapshot, sftpController]);

  useEffect(() => {
    const activeWorkspaceId = activeSshSession?.id ?? null;
    if (!activeWorkspaceId) {
      projectActiveSftpSnapshot(null);
      return;
    }
    bindSftpWorkspace(activeWorkspaceId);
    sftpController.activate(activeWorkspaceId);
    projectActiveSftpSnapshot(sftpController.getSnapshot(activeWorkspaceId) ?? null);
  }, [activeSshSession?.id, bindSftpWorkspace, projectActiveSftpSnapshot, sftpController]);

  useEffect(() => {
    if (
      activeSshSession?.state === "connected"
      && rendererSettings.appearance.showSftpTab
      && rendererSettings.sftp.autoOpenSidebar
    ) {
      setTerminalSidePanelTab("sftp");
      setTerminalSidePanelOpen(true);
    }
  }, [
    activeSshSession?.id,
    activeSshSession?.state,
    rendererSettings.appearance.showSftpTab,
    rendererSettings.sftp.autoOpenSidebar,
  ]);

  useEffect(() => {
    const liveSshIds = new Set(sharedTerminalRegistry.order.filter((id) => (
      sharedTerminalRegistry.sessions[id]?.protocol === "ssh" && sshTerminals.owns(id)
    )));
    for (const workspaceId of [...knownSftpWorkspaceIds.current]) {
      if (liveSshIds.has(workspaceId)) continue;
      sftpController.removeSession(workspaceId);
      knownSftpWorkspaceIds.current.delete(workspaceId);
    }
    for (const workspaceId of liveSshIds) {
      const snapshot = sharedTerminalRegistry.sessions[workspaceId];
      if (
        snapshot?.state === "connected"
        && sshTerminals.backendSessionIdFor(workspaceId)
      ) {
        bindSftpWorkspace(workspaceId);
      } else if (sftpController.getOwner(workspaceId)) {
        sftpController.resetSession(workspaceId);
      }
    }
  }, [
    bindSftpWorkspace,
    sftpController,
    sharedTerminalRegistry,
    sshTerminals.backendSessionIdFor,
    sshTerminals.owns,
  ]);

  const getTerminalSidePanelContainerWidth = useCallback((): number => {
    const shell = workbenchElement.current;
    const shellWidth = shell?.getBoundingClientRect().width ?? window.innerWidth;
    const connectionWidth = shell
      ?.querySelector<HTMLElement>(".connection-panel")
      ?.getBoundingClientRect().width ?? 0;
    return Math.max(0, shellWidth - connectionWidth);
  }, []);

  /**
   * Resolve the resize bounds for the currently selected side-panel tool.
   * SFTP and Docker intentionally retain the legacy 280px floor; the AI
   * composer gets a wider floor because its footer contains several readable
   * controls that cannot be compressed into a narrow strip.
   */
  const getActiveTerminalSidePanelWidthBounds = useCallback((
    containerWidth: number,
  ) => {
    const legacyBounds = getTerminalSidePanelWidthBounds(containerWidth);
    const min = aiOpen ? AI_SIDE_PANEL_MIN_WIDTH : legacyBounds.min;
    return {
      min,
      // A very small window cannot satisfy both the terminal and panel
      // minimums. Preserve the AI floor and let the responsive overlay cap
      // the visible panel to the available viewport width.
      max: Math.max(min, legacyBounds.max),
    };
  }, [aiOpen]);

  const clampActiveTerminalSidePanelWidth = useCallback((
    requestedWidth: number,
    containerWidth: number,
  ): number => {
    const bounds = getActiveTerminalSidePanelWidthBounds(containerWidth);
    const safeRequestedWidth = Number.isFinite(requestedWidth)
      ? requestedWidth
      : bounds.min;
    return Math.min(bounds.max, Math.max(bounds.min, safeRequestedWidth));
  }, [getActiveTerminalSidePanelWidthBounds]);

  useEffect(() => {
    if (BROWSER_VISUAL_PREVIEW !== "terminal" && BROWSER_VISUAL_PREVIEW !== "sftp") return;
    setConnectionState("connected");
    setConnectionTarget({
      protocol: "ssh",
      hostname: "dev.goral.local",
      port: 22,
      username: "goral",
    });
    setSidebarView("saved");
    setActiveSurface("terminal");
    setTerminalSidePanelTab("sftp");
    setTerminalSidePanelOpen(BROWSER_VISUAL_PREVIEW === "sftp");
  }, []);

  useEffect(() => {
    if (!terminalPaneLayout) return;
    const liveSessionIds = new Set(sharedTerminalRegistry.order);
    const pruned = pruneTerminalPaneLayout(terminalPaneLayout, liveSessionIds);
    if (!pruned || shouldDissolveTerminalPaneLayout(pruned)) {
      const remainingSessionId = pruned?.focusedSessionId;
      setTerminalPaneLayout(null);
      setTerminalPaneWorkspaceVisible(false);
      setTerminalPaneZoomedSessionId(null);
      setTerminalPaneResize(null);
      setTerminalPaneDropHint(null);
      if (remainingSessionId) fitSharedTerminalSessionsOnNextFrame([remainingSessionId]);
      return;
    }
    if (pruned !== terminalPaneLayout) {
      setTerminalPaneLayout(pruned);
      setTerminalPaneDropHint(null);
      const zoomedSessionId = terminalPaneZoomedSessionId
        && terminalPaneLayoutContains(pruned, terminalPaneZoomedSessionId)
        ? terminalPaneZoomedSessionId
        : null;
      if (!zoomedSessionId) setTerminalPaneZoomedSessionId(null);
      fitSharedTerminalSessionsOnNextFrame(
        zoomedSessionId
          ? [zoomedSessionId]
          : terminalPaneZoomedSessionId
            ? collectTerminalPaneSessionIds(pruned.root)
            : changedTerminalPaneSessionIds(terminalPaneLayout, pruned),
      );
    }
  }, [
    fitSharedTerminalSessionsOnNextFrame,
    sharedTerminalRegistry.order,
    terminalPaneLayout,
    terminalPaneZoomedSessionId,
  ]);

  useEffect(() => {
    if (!terminalPaneWorkspaceVisible || !terminalPaneLayout || !activeSharedSession) return;
    if (!terminalPaneLayoutContains(terminalPaneLayout, activeSharedSession.id)) {
      setTerminalPaneWorkspaceVisible(false);
      setTerminalPaneZoomedSessionId(null);
      setTerminalPaneResize(null);
      setTerminalPaneDropHint(null);
      return;
    }
    if (terminalPaneLayout.focusedSessionId !== activeSharedSession.id) {
      setTerminalPaneLayout(focusTerminalPane(terminalPaneLayout, activeSharedSession.id));
    }
  }, [activeSharedSession, terminalPaneLayout, terminalPaneWorkspaceVisible]);

  useEffect(() => {
    if (!terminalPaneResize) return;
    const handlePointerMove = (event: PointerEvent) => {
      if (event.pointerId !== terminalPaneResize.pointerId) return;
      const stageBounds = terminalPaneStageElement.current?.getBoundingClientRect();
      if (!stageBounds) return;
      const splitSizePixels = terminalPaneResize.direction === "vertical"
        ? stageBounds.width * terminalPaneResize.splitRect.width
        : stageBounds.height * terminalPaneResize.splitRect.height;
      if (splitSizePixels <= 0) return;
      const pointerDelta = terminalPaneResize.direction === "vertical"
        ? event.clientX - terminalPaneResize.startClientX
        : event.clientY - terminalPaneResize.startClientY;
      const ratio = clampTerminalPaneRatio(
        terminalPaneResize.startRatio + pointerDelta / splitSizePixels,
        splitSizePixels,
      );
      setTerminalPaneLayout((current) => {
        if (!current) return current;
        try {
          return resizeTerminalPaneSplit(current, terminalPaneResize.splitId, ratio);
        } catch {
          return current;
        }
      });
    };
    const finishResize = (event: PointerEvent) => {
      if (event.pointerId === terminalPaneResize.pointerId) setTerminalPaneResize(null);
    };
    const clearResize = () => setTerminalPaneResize(null);
    window.addEventListener("pointermove", handlePointerMove);
    window.addEventListener("pointerup", finishResize);
    window.addEventListener("pointercancel", finishResize);
    window.addEventListener("blur", clearResize);
    return () => {
      window.removeEventListener("pointermove", handlePointerMove);
      window.removeEventListener("pointerup", finishResize);
      window.removeEventListener("pointercancel", finishResize);
      window.removeEventListener("blur", clearResize);
    };
  }, [terminalPaneResize]);

  useEffect(() => {
    if (!terminalSidePanelResize) return;
    const handlePointerMove = (event: PointerEvent) => {
      if (event.pointerId !== terminalSidePanelResize.pointerId) return;
      const containerWidth = getTerminalSidePanelContainerWidth();
      setTerminalSidePanelWidth(clampActiveTerminalSidePanelWidth(
        resizeTerminalSidePanelWidth(
          terminalSidePanelResize.startWidth,
          terminalSidePanelResize.startX,
          event.clientX,
          containerWidth,
        ),
        containerWidth,
      ));
    };
    const finishResize = (event: PointerEvent) => {
      if (event.pointerId === terminalSidePanelResize.pointerId) {
        setTerminalSidePanelResize(null);
      }
    };
    const clearResize = () => setTerminalSidePanelResize(null);
    window.addEventListener("pointermove", handlePointerMove);
    window.addEventListener("pointerup", finishResize);
    window.addEventListener("pointercancel", finishResize);
    window.addEventListener("blur", clearResize);
    return () => {
      window.removeEventListener("pointermove", handlePointerMove);
      window.removeEventListener("pointerup", finishResize);
      window.removeEventListener("pointercancel", finishResize);
      window.removeEventListener("blur", clearResize);
    };
  }, [clampActiveTerminalSidePanelWidth, getTerminalSidePanelContainerWidth, terminalSidePanelResize]);

  // Switching from SFTP/Docker to AI can carry over a previously narrow
  // width. Raise it immediately so the first rendered frame and the resize
  // separator's aria value agree with the AI panel's minimum.
  useEffect(() => {
    if (!aiOpen) return;
    const containerWidth = getTerminalSidePanelContainerWidth();
    setTerminalSidePanelWidth((current) => clampActiveTerminalSidePanelWidth(
      current,
      containerWidth,
    ));
  }, [aiOpen, clampActiveTerminalSidePanelWidth, getTerminalSidePanelContainerWidth]);

  useEffect(() => {
    const handleWindowResize = () => {
      const containerWidth = getTerminalSidePanelContainerWidth();
      setTerminalSidePanelWidth((current) => clampActiveTerminalSidePanelWidth(
        current,
        containerWidth,
      ));
    };
    window.addEventListener("resize", handleWindowResize);
    return () => window.removeEventListener("resize", handleWindowResize);
  }, [clampActiveTerminalSidePanelWidth, getTerminalSidePanelContainerWidth]);

  useEffect(() => {
    const coordinator = createTerminalResizeCoordinator((sessionId, size) => {
      const active = session.current;
      if (!active || active.sessionId !== sessionId) return Promise.resolve();
      return active.protocol === "telnet"
        ? resizeTelnetSession(sessionId, size)
        : active.protocol === "serial"
          ? resizeSerialSession(sessionId, size)
          : active.protocol === "mosh"
            ? resizeMoshSession(sessionId, size)
            : active.protocol === "et"
              ? resizeEtSession(sessionId, size)
              : resizeSshSession(sessionId, size);
    });
    terminalResizeCoordinator.current = coordinator;
    return () => {
      if (terminalResizeCoordinator.current === coordinator) {
        terminalResizeCoordinator.current = null;
      }
      coordinator.dispose();
    };
  }, []);

  const fit = useCallback(() => {
    fitAddon.current?.fit();
    const active = session.current;
    const instance = terminal.current;
    if (active && instance) {
      terminalResizeCoordinator.current?.request(active.sessionId, {
        columns: instance.cols,
        rows: instance.rows,
        pixelWidth: 0,
        pixelHeight: 0,
      });
    }
  }, []);

  const runSavedHostsRefresh = useCallback(async (
    preserveCurrentError = false,
  ): Promise<SavedHost[] | null> => {
    if (!NATIVE_DESKTOP_RUNTIME_AVAILABLE) {
      if (BROWSER_VISUAL_PREVIEW) {
        setSavedHosts(BROWSER_VISUAL_PREVIEW_HOSTS);
        setSavedHostsHaveSnapshot(true);
        setSavedHostsError(null);
        return BROWSER_VISUAL_PREVIEW_HOSTS;
      }
      setSavedHosts([]);
      setSavedHostsHaveSnapshot(true);
      setSavedHostsError(null);
      return [];
    }
    if (!preserveCurrentError) setSavedHostsError(null);
    try {
      const hosts = await listSavedHosts();
      setSavedHosts(hosts);
      setSavedHostsHaveSnapshot(true);
      return hosts;
    } catch (reason) {
      const refreshError = translateRef.current("workspace.error.loadSavedHosts");
      setSavedHostsError((current) => (
        preserveCurrentError && current ? `${current} ${refreshError}` : refreshError
      ));
      return null;
    }
  }, []);

  if (!savedHostsRefreshCoordinator.current) {
    savedHostsRefreshCoordinator.current = createCoalescedRefresh(runSavedHostsRefresh);
  }

  const refreshSavedHosts = useCallback((
    preserveCurrentError = false,
    queueFollowUp = false,
  ): Promise<SavedHost[] | null> => {
    const coordinator = savedHostsRefreshCoordinator.current!;
    const startsFlight = !coordinator.isRunning();
    const refreshToken = startsFlight
      ? ++nextSavedHostsRefreshToken.current
      : nextSavedHostsRefreshToken.current;
    if (startsFlight) setSavedHostsLoading(true);
    const result = coordinator.request(preserveCurrentError, { queueFollowUp });
    if (!startsFlight) return result;
    return result.finally(() => {
      if (nextSavedHostsRefreshToken.current === refreshToken) {
        setSavedHostsLoading(false);
      }
    });
  }, []);

  const observeManagedInventoryRevision = useCallback((inventoryRevision: unknown) => {
    const previous = managedInventoryRevision.current;
    managedInventoryRevision.current = { seen: true, value: inventoryRevision };
    const managedGraphChanged = previous.seen
      && !sameInventoryRevision(previous.value, inventoryRevision);
    const passwordIdentityCatalogIsStale = passwordIdentityInventoryRevision.current.seen
      && !sameInventoryRevision(
        passwordIdentityInventoryRevision.current.value,
        inventoryRevision,
      );
    const proxyProfileCatalogIsStale = proxyProfileInventoryRevision.current.seen
      && !sameInventoryRevision(
        proxyProfileInventoryRevision.current.value,
        inventoryRevision,
      );
    const groupConfigCatalogIsStale = groupConfigInventoryRevision.current.seen
      && !sameInventoryRevision(groupConfigInventoryRevision.current.value, inventoryRevision);
    // A catalog's first snapshot is hydration, not a mutation. During the
    // initial parallel loads the other catalogs may still expose a different
    // point-in-time revision; fanning out refresh keys here makes the Hosts
    // surface alternate between its full loader and background refresh. Only
    // reconcile dependents after this source has already been hydrated once.
    if (
      previous.seen
      && (managedGraphChanged || passwordIdentityCatalogIsStale || proxyProfileCatalogIsStale || groupConfigCatalogIsStale)
    ) {
      setPasswordIdentityRefreshKey((current) => current + 1);
      setProxyProfileRefreshKey((current) => current + 1);
      setGroupConfigRefreshKey((current) => current + 1);
      void refreshSavedHosts(false, true);
    }
  }, [refreshSavedHosts]);

  const refreshManagedSshKeys = useCallback(async (
    preserveCurrentError = false,
  ): Promise<ManagedSshKeyCatalog | null> => {
    const refreshToken = ++nextManagedSshKeysRefreshToken.current;
    if (!NATIVE_DESKTOP_RUNTIME_AVAILABLE) {
      const catalog: ManagedSshKeyCatalog = { inventoryRevision: null, keys: [] };
      setManagedSshKeyCatalog(catalog);
      setManagedSshKeysError(null);
      setManagedSshKeysLoading(false);
      return catalog;
    }
    setManagedSshKeysLoading(true);
    if (!preserveCurrentError) setManagedSshKeysError(null);
    try {
      const catalog = await listManagedSshKeys();
      if (nextManagedSshKeysRefreshToken.current === refreshToken) {
        observeManagedInventoryRevision(catalog.inventoryRevision);
        setManagedSshKeyCatalog(catalog);
        return catalog;
      }
      return null;
    } catch (reason) {
      if (nextManagedSshKeysRefreshToken.current === refreshToken) {
        const refreshError = managedSshKeyErrorMessage(reason, "list", t);
        setManagedSshKeysError((current) => (
          preserveCurrentError && current ? `${current} ${refreshError}` : refreshError
        ));
      }
      return null;
    } finally {
      if (nextManagedSshKeysRefreshToken.current === refreshToken) {
        setManagedSshKeysLoading(false);
      }
    }
  }, [observeManagedInventoryRevision, t]);

  const handlePasswordIdentityCatalogChange = useCallback((
    catalog: PasswordIdentityCatalogSnapshot,
  ) => {
    const previous = passwordIdentityInventoryRevision.current;
    passwordIdentityInventoryRevision.current = {
      seen: true,
      value: catalog.inventoryRevision,
    };
    setPasswordIdentityCatalog(catalog);

    const passwordIdentityGraphChanged = previous.seen
      && !sameInventoryRevision(previous.value, catalog.inventoryRevision);
    const managedCatalogIsStale = managedInventoryRevision.current.seen
      && !sameInventoryRevision(
        managedInventoryRevision.current.value,
        catalog.inventoryRevision,
      );
    const proxyProfileCatalogIsStale = proxyProfileInventoryRevision.current.seen
      && !sameInventoryRevision(
        proxyProfileInventoryRevision.current.value,
        catalog.inventoryRevision,
      );
    const groupConfigCatalogIsStale = groupConfigInventoryRevision.current.seen
      && !sameInventoryRevision(groupConfigInventoryRevision.current.value, catalog.inventoryRevision);
    if (
      previous.seen
      && (passwordIdentityGraphChanged || managedCatalogIsStale || proxyProfileCatalogIsStale || groupConfigCatalogIsStale)
    ) {
      setProxyProfileRefreshKey((current) => current + 1);
      setGroupConfigRefreshKey((current) => current + 1);
      void Promise.all([
        refreshSavedHosts(false, true),
        refreshManagedSshKeys(),
      ]);
    }
  }, [refreshManagedSshKeys, refreshSavedHosts]);

  const handleProxyProfileCatalogChange = useCallback((
    catalog: ProxyProfileCatalogSnapshot,
  ) => {
    const previous = proxyProfileInventoryRevision.current;
    proxyProfileInventoryRevision.current = {
      seen: true,
      value: catalog.inventoryRevision,
    };
    setProxyProfileCatalog(catalog);

    const proxyProfileGraphChanged = previous.seen
      && !sameInventoryRevision(previous.value, catalog.inventoryRevision);
    const managedCatalogIsStale = managedInventoryRevision.current.seen
      && !sameInventoryRevision(
        managedInventoryRevision.current.value,
        catalog.inventoryRevision,
      );
    const passwordIdentityCatalogIsStale = passwordIdentityInventoryRevision.current.seen
      && !sameInventoryRevision(
        passwordIdentityInventoryRevision.current.value,
        catalog.inventoryRevision,
      );
    const groupConfigCatalogIsStale = groupConfigInventoryRevision.current.seen
      && !sameInventoryRevision(groupConfigInventoryRevision.current.value, catalog.inventoryRevision);
    if (
      previous.seen
      && (
        proxyProfileGraphChanged
        || managedCatalogIsStale
        || passwordIdentityCatalogIsStale
        || groupConfigCatalogIsStale
      )
    ) {
      setPasswordIdentityRefreshKey((current) => current + 1);
      setGroupConfigRefreshKey((current) => current + 1);
      void Promise.all([
        refreshSavedHosts(false, true),
        refreshManagedSshKeys(),
      ]);
    }
  }, [refreshManagedSshKeys, refreshSavedHosts]);

  const handleGroupConfigCatalogChange = useCallback((
    catalog: GroupConfigCatalogSnapshot,
  ) => {
    const previous = groupConfigInventoryRevision.current;
    groupConfigInventoryRevision.current = {
      seen: true,
      value: catalog.inventoryRevision,
    };
    setGroupConfigCatalog(catalog);

    const groupGraphChanged = previous.seen
      && !sameInventoryRevision(previous.value, catalog.inventoryRevision);
    const managedCatalogIsStale = managedInventoryRevision.current.seen
      && !sameInventoryRevision(managedInventoryRevision.current.value, catalog.inventoryRevision);
    const identityCatalogIsStale = passwordIdentityInventoryRevision.current.seen
      && !sameInventoryRevision(passwordIdentityInventoryRevision.current.value, catalog.inventoryRevision);
    const proxyCatalogIsStale = proxyProfileInventoryRevision.current.seen
      && !sameInventoryRevision(proxyProfileInventoryRevision.current.value, catalog.inventoryRevision);
    if (
      previous.seen
      && (groupGraphChanged || managedCatalogIsStale || identityCatalogIsStale || proxyCatalogIsStale)
    ) {
      setPasswordIdentityRefreshKey((current) => current + 1);
      setProxyProfileRefreshKey((current) => current + 1);
      void Promise.all([refreshSavedHosts(false, true), refreshManagedSshKeys()]);
    }
  }, [refreshManagedSshKeys, refreshSavedHosts]);

  useEffect(() => {
    void refreshSavedHosts();
  }, [refreshSavedHosts]);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | null = null;
    const coordinator = createSettingsReloadCoordinator({
      load: () => SETTINGS_ADAPTER.load(),
      apply: (snapshot) => {
        setRendererSettings(snapshot.settings);
        setRendererSettingsReady(true);
      },
      // Keep the validated defaults if native settings are temporarily unavailable.
      onLatestError: () => setRendererSettingsReady(true),
    });
    settingsReloadCoordinatorRef.current = coordinator;
    const refreshTerminalSettings = () => {
      void coordinator.reload();
    };
    refreshTerminalSettings();
    window.addEventListener("focus", refreshTerminalSettings);
    void subscribeSettingsChanges(() => refreshTerminalSettings())
      .then((stopListening) => {
        if (disposed) {
          stopListening?.();
          return;
        }
        unlisten = stopListening;
        // Close the gap between the first load and native listener registration.
        if (stopListening) refreshTerminalSettings();
      })
      .catch(() => undefined);
    return () => {
      disposed = true;
      window.removeEventListener("focus", refreshTerminalSettings);
      unlisten?.();
      coordinator.dispose();
      if (settingsReloadCoordinatorRef.current === coordinator) {
        settingsReloadCoordinatorRef.current = null;
      }
    };
  }, []);

  const updateAiPreferences = useCallback(async (change: Readonly<{
    activeProviderId?: string;
    commandPermissionMode?: "observer" | "confirm" | "auto";
  }>) => {
    const current = await SETTINGS_ADAPTER.load();
    const next = structuredClone(current.settings);
    if (change.activeProviderId !== undefined) {
      if (!next.ai.providers.some((provider) => provider.id === change.activeProviderId)) {
        throw new Error("AI_PROVIDER_INVALID");
      }
      next.ai.activeProviderId = change.activeProviderId;
    }
    if (change.commandPermissionMode !== undefined) {
      next.ai.commandPermissionMode = change.commandPermissionMode;
    }
    await SETTINGS_ADAPTER.replace({
      settings: next,
      expectedInventoryRevision: current.inventoryRevision,
    });
    // Re-read the current Rust authority instead of applying a replace response
    // that may already be older than a commit from the Settings window.
    await settingsReloadCoordinatorRef.current?.reload();
  }, []);

  useEffect(() => {
    if (!rendererSettingsReady) return;
    const store = sessionRestoreStoreRef.current;
    if (!rendererSettings.system.restorePreviousSession) {
      sessionRestoreChecked.current = true;
      store?.clear();
      setSessionRestoreSnapshot(null);
      setSessionRestoreError(null);
      setSessionRestoreConnectingId(null);
      setSessionRestoreRestoring(false);
      setSessionRestoreSettled(true);
      return;
    }
    if (sessionRestoreChecked.current) return;
    sessionRestoreChecked.current = true;
    const snapshot = store?.load() ?? null;
    if (snapshot && snapshot.sessions.length > 0) {
      setSessionRestoreSnapshot(snapshot);
      return;
    }
    setSessionRestoreSettled(true);
  }, [rendererSettings.system.restorePreviousSession, rendererSettingsReady]);

  useEffect(() => {
    if (!rendererSettingsReady || !sessionRestoreSettled) return;
    const store = sessionRestoreStoreRef.current;
    if (!rendererSettings.system.restorePreviousSession) {
      store?.clear();
      return;
    }
    const sharedSnapshot = createSessionRestoreSnapshotFromRegistry(
      sharedTerminalRegistry,
      (workspaceId, terminalSession) => {
        if (terminalSession.protocol === "local") {
          const target = localTerminalTargetFor(workspaceId);
          return target
            ? {
                kind: "local",
                label: target.shell.name || terminalSession.title,
                shellId: target.shell.id,
              }
            : null;
        }
        if (terminalSession.protocol !== "ssh") return null;
        const target = sshTerminalTargetFor(workspaceId);
        if (!target) return null;
        return target.kind === "saved" && target.savedHostId
          ? { kind: "saved", savedHostId: target.savedHostId, label: target.title }
          : {
              kind: "quick",
              label: target.title,
              hostname: target.hostname,
              port: target.port,
            };
      },
      terminalPaneWorkspaceVisible ? terminalPaneLayout : null,
    );
    let snapshot = sharedSnapshot;
    if (connectionTarget && sharedSnapshot.sessions.length < MAX_WORKSPACE_SESSIONS) {
      const workspaceSessionId = legacyRestoreSessionId;
      const target: SessionRestoreEntry["target"] = connectionTarget.savedHost
        ? {
            kind: "saved",
            savedHostId: connectionTarget.savedHost.id,
            label: connectionTarget.savedHost.label,
          }
        : connectionTarget.protocol === "serial"
          ? { kind: "serial", label: t("workspace.serial") }
          : {
              kind: "quick",
              label: `${connectionTarget.hostname}:${connectionTarget.port}`,
              hostname: connectionTarget.hostname,
              port: connectionTarget.port,
            };
      snapshot = createSessionRestoreSnapshot([
        ...sharedSnapshot.sessions,
        {
          workspaceSessionId,
          protocol: connectionTarget.protocol,
          target,
        },
      ], workspaceSessionId, sharedSnapshot.paneLayout ?? null);
    }
    if (snapshot.sessions.length > 0) store?.save(snapshot);
    else store?.clear();
  }, [
    connectionTarget,
    legacyRestoreSessionId,
    localTerminalTargetFor,
    rendererSettings.system.restorePreviousSession,
    rendererSettingsReady,
    sessionRestoreSettled,
    sharedTerminalRegistry,
    sshTerminalTargetFor,
    t,
    terminalPaneLayout,
    terminalPaneWorkspaceVisible,
  ]);

  useEffect(() => {
    void refreshManagedSshKeys();
  }, [refreshManagedSshKeys]);

  const advanceSftpSessionGeneration = useCallback((): number => {
    projectActiveSftpSnapshot(null);
    return ++legacySftpGeneration.current;
  }, [projectActiveSftpSnapshot]);

  const bindSftpSessionOwner = useCallback((
    _sessionId: string,
    _generation: number,
  ): boolean => {
    // Quick/Saved SSH now binds through bindSftpWorkspace. The legacy
    // singleton no longer starts SSH and therefore owns no SFTP authority.
    return false;
  }, []);

  const isCurrentSftpOwner = useCallback((owner: WorkspaceSftpSessionOwner): boolean => (
    projectionOwnsSftpMutation(
      activeSftpProjection,
      activeSftpWorkspaceIdRef.current,
      owner,
      (candidate) => sftpController.isExactOwner(candidate),
    )
  ), [activeSftpProjection, sftpController]);

  const captureCurrentSftpOwner = useCallback((): WorkspaceSftpSessionOwner | null => {
    const projection = resolveActiveSftpProjection(
      activeSftpWorkspaceIdRef.current,
      activeSftpProjection,
      (owner) => sftpController.isExactOwner(owner),
    );
    return projection ? { ...projection.owner } : null;
  }, [activeSftpProjection, sftpController]);

  const loadSftpPath = useCallback(async (
    path: string,
    expectedOwner?: WorkspaceSftpSessionOwner,
  ) => {
    const owner = expectedOwner ?? captureCurrentSftpOwner();
    if (!owner || !isCurrentSftpOwner(owner)) return;
    await sftpController.load(owner.workspaceId, path, owner);
  }, [captureCurrentSftpOwner, isCurrentSftpOwner, sftpController]);

  // Keep the SFTP browser aligned with the active remote shell when the
  // persisted setting is enabled.  The key includes the exact workspace,
  // SSH attempt generation, and cwd so a late OSC notification can never
  // navigate a newer tab or re-capture a directory the user browsed to.
  const followedTerminalCwdRef = useRef<string | null>(null);
  useEffect(() => {
    const workspaceId = activeSshSession?.id ?? null;
    const operationGeneration = workspaceId
      ? sshTerminals.operationGenerationFor(workspaceId)
      : undefined;
    const cwd = activeSshTerminalCwd;
    if (
      !rendererSettings.sftp.followTerminalCwd
      || !sftpOpen
      || !workspaceId
      || operationGeneration === undefined
      || !cwd
      || activeSshSession?.state !== "connected"
    ) {
      if (!workspaceId || !rendererSettings.sftp.followTerminalCwd) {
        followedTerminalCwdRef.current = null;
      }
      return;
    }
    const owner = captureCurrentSftpOwner();
    if (!owner || owner.workspaceId !== workspaceId) return;
    const followKey = `${workspaceId}:${operationGeneration}:${cwd}`;
    if (followedTerminalCwdRef.current === followKey) return;
    followedTerminalCwdRef.current = followKey;
    if (sftpPath === cwd) return;
    void loadSftpPath(cwd, owner);
  }, [
    activeSshSession?.id,
    activeSshSession?.state,
    activeSshTerminalCwd,
    captureCurrentSftpOwner,
    loadSftpPath,
    rendererSettings.sftp.followTerminalCwd,
    sftpOpen,
    sftpPath,
    sshTerminals,
  ]);

  const updateTransfer = useCallback((
    id: string,
    owner: WorkspaceSftpSessionOwner,
    update: Partial<VisibleTransfer>,
  ) => {
    sftpController.updateTransfer(owner, id, update);
  }, [sftpController]);

  const setOwnedSftpError = useCallback((
    owner: WorkspaceSftpSessionOwner,
    message: string | null,
  ) => {
    sftpController.setError(owner, message);
  }, [sftpController]);

  const addOwnedTransfer = useCallback((
    owner: WorkspaceSftpSessionOwner,
    transfer: VisibleTransfer,
  ) => sftpController.addTransfer(owner, transfer), [sftpController]);

  const registerStartedSftpTransfer = useCallback((
    owner: WorkspaceSftpSessionOwner,
    transferId: string,
    handle: {
      transferId: string;
      eventChannel: { onmessage: (event: SftpTransferEvent) => void };
    },
    starterPatch: Parameters<SftpSessionController["registerTransferControl"]>[3] = {},
  ): boolean => {
    const releaseEventChannel = () => {
      handle.eventChannel.onmessage = () => undefined;
    };
    const registered = sftpController.registerTransferControl(owner, transferId, {
      backendTransferId: handle.transferId,
      pause: () => pauseSftpTransfer(handle.transferId),
      resume: () => resumeSftpTransfer(handle.transferId),
      cancel: () => cancelSftpTransfer(handle.transferId),
      retention: handle.eventChannel,
      dispose: releaseEventChannel,
    }, starterPatch);
    if (!registered) {
      releaseEventChannel();
    }
    return registered;
  }, [sftpController]);

  const handleTransferEvent = useCallback((
    id: string,
    owner: WorkspaceSftpSessionOwner,
    direction: "upload" | "download",
    _isDirectory: boolean,
    event: SftpTransferEvent,
  ) => {
    if (!sftpController.handleTransferEvent(owner, id, event)) return;
    if (
      direction === "upload"
      && (event.type === "completed" || event.type === "directoryCompleted")
    ) {
      const currentOwner = sftpController.getOwner(owner.workspaceId);
      if (currentOwner) void loadSftpPath(sftpPathRef.current, currentOwner);
    }
  }, [loadSftpPath, sftpController]);

  const uploadLocalPath = useCallback(async (
    localPath: string,
    expectedOwner?: WorkspaceSftpSessionOwner,
  ) => {
    const owner = expectedOwner ?? captureCurrentSftpOwner();
    if (!owner || !isCurrentSftpOwner(owner)) return;
    const label = localPath.split(/[\\/]/).filter(Boolean).at(-1) ?? t("sftp.action.uploadFallback");
    const separator = sftpPath.endsWith("/") ? "" : "/";
    const remotePath = `${sftpPath}${separator}${label}`;
    let sourceKind: "file" | "directory";
    try {
      sourceKind = await classifyLocalTransferSource(localPath);
    } catch {
      if (isCurrentSftpOwner(owner)) setOwnedSftpError(owner, SFTP_LOCAL_SOURCE_ERROR);
      return;
    }
    if (!isCurrentSftpOwner(owner)) return;
    const isDirectory = sourceKind === "directory";
    const id = `pending-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const visibleTransfer: VisibleTransfer = {
      id,
      direction: "upload",
      isDirectory,
      localPath,
      remotePath,
      label,
      status: "queued",
      bytesTransferred: 0,
      totalBytes: 0,
      filesCompleted: 0,
      totalFiles: 0,
      skippedEntries: 0,
      failedFiles: 0,
    };
    addOwnedTransfer(owner, visibleTransfer);
    try {
      if (isDirectory) {
        const handle = await startSftpUploadDirectory(
          owner.backendSessionId,
          localPath,
          remotePath,
          undefined,
          undefined,
          (event) => handleTransferEvent(id, owner, "upload", true, event),
        );
        registerStartedSftpTransfer(owner, id, handle);
      } else {
        const handle = await startSftpUpload(
          owner.backendSessionId,
          localPath,
          remotePath,
          (event) => handleTransferEvent(id, owner, "upload", false, event),
        );
        registerStartedSftpTransfer(owner, id, handle, { plan: handle.plan });
      }
    } catch {
      sftpController.failTransferStart(owner, id, SFTP_TRANSFER_ERROR);
    }
  }, [
    addOwnedTransfer,
    captureCurrentSftpOwner,
    handleTransferEvent,
    isCurrentSftpOwner,
    registerStartedSftpTransfer,
    setOwnedSftpError,
    sftpController,
    sftpPath,
    t,
  ]);

  const chooseSftpUpload = useCallback(async (sourceKind: "file" | "directory") => {
    const owner = captureCurrentSftpOwner();
    if (!owner) return;
    let selection: string | string[] | null;
    try {
      selection = await open({
        title: t(sourceKind === "directory"
          ? "sftp.action.chooseUploadFolder"
          : "sftp.action.chooseUploadFile"),
        directory: sourceKind === "directory",
        multiple: sourceKind === "file",
      });
    } catch {
      if (isCurrentSftpOwner(owner)) setOwnedSftpError(owner, SFTP_PICKER_ERROR);
      return;
    }
    if (!isCurrentSftpOwner(owner)) return;
    const paths = typeof selection === "string" ? [selection] : selection ?? [];
    for (const localPath of paths) {
      if (!isCurrentSftpOwner(owner)) return;
      await uploadLocalPath(localPath, owner);
    }
  }, [captureCurrentSftpOwner, isCurrentSftpOwner, setOwnedSftpError, t, uploadLocalPath]);

  const remoteChildPath = useCallback((name: string) => {
    const separator = sftpPath.endsWith("/") ? "" : "/";
    return `${sftpPath}${separator}${name}`;
  }, [sftpPath]);

  const createRemoteFolder = useCallback(async () => {
    const owner = captureCurrentSftpOwner();
    if (!owner) return;
    const name = (await requestWorkspaceText({
      title: t("sftp.action.newFolderTitle"),
      message: t("sftp.action.newFolderPrompt"),
      initialValue: "",
      confirmLabel: t("sftp.action.createFolder"),
      cancelLabel: t("workspace.dialog.cancel"),
    }))?.trim();
    if (!name) return;
    if (name === "." || name === ".." || /[\\/]/.test(name)) {
      setOwnedSftpError(owner, SFTP_VALIDATION_ERROR);
      return;
    }
    const currentPath = sftpPath;
    const childPath = remoteChildPath(name);
    try {
      await createSftpDirectory(owner.backendSessionId, childPath);
      await loadSftpPath(currentPath, owner);
    } catch {
      if (isCurrentSftpOwner(owner)) setOwnedSftpError(owner, SFTP_OPERATION_ERROR);
    }
  }, [captureCurrentSftpOwner, isCurrentSftpOwner, loadSftpPath, remoteChildPath, requestWorkspaceText, setOwnedSftpError, sftpPath, t]);

  const renameRemoteEntry = useCallback(async (entry: SftpEntry) => {
    const owner = captureCurrentSftpOwner();
    if (!owner) return;
    const name = (await requestWorkspaceText({
      title: t("sftp.action.renameTitle", { entry: entry.name }),
      message: t("sftp.action.renamePrompt"),
      initialValue: entry.name,
      confirmLabel: t("sftp.action.rename"),
      cancelLabel: t("workspace.dialog.cancel"),
    }))?.trim();
    if (!name || name === entry.name) return;
    if (name === "." || name === ".." || /[\\/]/.test(name)) {
      setOwnedSftpError(owner, SFTP_VALIDATION_ERROR);
      return;
    }
    const currentPath = sftpPath;
    const renamedPath = remoteChildPath(name);
    try {
      await renameSftpPath(owner.backendSessionId, entry.path, renamedPath);
      await loadSftpPath(currentPath, owner);
    } catch {
      if (isCurrentSftpOwner(owner)) setOwnedSftpError(owner, SFTP_OPERATION_ERROR);
    }
  }, [captureCurrentSftpOwner, isCurrentSftpOwner, loadSftpPath, remoteChildPath, requestWorkspaceText, setOwnedSftpError, sftpPath, t]);

  const deleteRemoteEntry = useCallback(async (entry: SftpEntry) => {
    const owner = captureCurrentSftpOwner();
    if (!owner || !await requestWorkspaceConfirmation({
      title: t("sftp.action.deleteTitle", { entry: entry.name }),
      message: t("sftp.action.deleteConfirm", { entry: entry.name }),
      confirmLabel: t("workspace.delete"),
      cancelLabel: t("workspace.dialog.cancel"),
      danger: true,
    })) return;
    const currentPath = sftpPath;
    try {
      if (entry.metadata.kind === "directory") {
        await removeSftpDirectory(owner.backendSessionId, entry.path);
      } else {
        await removeSftpFile(owner.backendSessionId, entry.path);
      }
      await loadSftpPath(currentPath, owner);
    } catch {
      if (isCurrentSftpOwner(owner)) setOwnedSftpError(owner, SFTP_OPERATION_ERROR);
    }
  }, [captureCurrentSftpOwner, isCurrentSftpOwner, loadSftpPath, requestWorkspaceConfirmation, setOwnedSftpError, sftpPath, t]);

  const downloadRemoteEntry = useCallback(async (entry: SftpEntry) => {
    const owner = captureCurrentSftpOwner();
    if (!owner || entry.metadata.kind !== "file") return;
    let localPath: string | null;
    try {
      localPath = await save({
        title: t("sftp.action.saveFile", { entry: entry.name }),
        defaultPath: entry.name,
      });
    } catch {
      if (isCurrentSftpOwner(owner)) setOwnedSftpError(owner, SFTP_PICKER_ERROR);
      return;
    }
    if (!localPath || !isCurrentSftpOwner(owner)) return;
    const id = `pending-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const visibleTransfer: VisibleTransfer = {
      id,
      direction: "download",
      isDirectory: false,
      localPath,
      remotePath: entry.path,
      label: entry.name,
      status: "queued",
      bytesTransferred: 0,
      totalBytes: entry.metadata.size,
      filesCompleted: 0,
      totalFiles: 0,
      skippedEntries: 0,
      failedFiles: 0,
    };
    addOwnedTransfer(owner, visibleTransfer);
    try {
      const handle = await startSftpDownload(
        owner.backendSessionId,
        entry.path,
        localPath,
        (event) => handleTransferEvent(id, owner, "download", false, event),
      );
      registerStartedSftpTransfer(owner, id, handle, {
        downloadPlan: handle.plan,
      });
    } catch {
      sftpController.failTransferStart(owner, id, SFTP_TRANSFER_ERROR);
    }
  }, [
    addOwnedTransfer,
    captureCurrentSftpOwner,
    handleTransferEvent,
    isCurrentSftpOwner,
    registerStartedSftpTransfer,
    setOwnedSftpError,
    sftpController,
    t,
  ]);

  const downloadRemoteDirectory = useCallback(async (entry: SftpEntry) => {
    const owner = captureCurrentSftpOwner();
    if (!owner || entry.metadata.kind !== "directory") return;
    let localParent: string | string[] | null;
    try {
      localParent = await open({
        title: t("sftp.action.chooseDownloadFolder", { entry: entry.name }),
        directory: true,
        multiple: false,
      });
    } catch {
      if (isCurrentSftpOwner(owner)) setOwnedSftpError(owner, SFTP_PICKER_ERROR);
      return;
    }
    if (typeof localParent !== "string" || !isCurrentSftpOwner(owner)) return;
    const localRoot = joinLocalChildPath(localParent, entry.name);
    const id = `pending-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const visibleTransfer: VisibleTransfer = {
      id,
      direction: "download",
      isDirectory: true,
      localPath: localRoot,
      remotePath: entry.path,
      label: entry.name,
      status: "queued",
      bytesTransferred: 0,
      totalBytes: 0,
      filesCompleted: 0,
      totalFiles: 0,
      skippedEntries: 0,
      failedFiles: 0,
    };
    addOwnedTransfer(owner, visibleTransfer);
    try {
      const handle = await startSftpDownloadDirectory(
        owner.backendSessionId,
        entry.path,
        localRoot,
        undefined,
        undefined,
        (event) => handleTransferEvent(id, owner, "download", true, event),
      );
      registerStartedSftpTransfer(owner, id, handle);
    } catch {
      sftpController.failTransferStart(owner, id, SFTP_TRANSFER_ERROR);
    }
  }, [
    addOwnedTransfer,
    captureCurrentSftpOwner,
    handleTransferEvent,
    isCurrentSftpOwner,
    registerStartedSftpTransfer,
    setOwnedSftpError,
    sftpController,
    t,
  ]);

  const retryTransfer = useCallback(async (transfer: VisibleTransfer) => {
    const owner = captureCurrentSftpOwner();
    if (!owner || !isCurrentSftpOwner(owner)) return;
    if (typeof transfer.localPath !== "string" || typeof transfer.remotePath !== "string") return;
    if (transfer.isDirectory && !transfer.directoryCheckpoint) return;
    if (!transfer.isDirectory && !transfer.checkpoint) return;
    if (!transfer.isDirectory && transfer.direction === "upload" && !transfer.plan) return;
    if (!transfer.isDirectory && transfer.direction === "download" && !transfer.downloadPlan) return;
    updateTransfer(transfer.id, owner, {
      status: "queued",
      error: undefined,
      failedFiles: 0,
      skippedEntries: 0,
      currentPath: undefined,
    });
    try {
      if (transfer.isDirectory && transfer.direction === "upload") {
        const handle = await startSftpUploadDirectory(
          owner.backendSessionId,
          transfer.localPath,
          transfer.remotePath,
          undefined,
          transfer.directoryCheckpoint,
          (event) => handleTransferEvent(transfer.id, owner, "upload", true, event),
        );
        registerStartedSftpTransfer(owner, transfer.id, handle);
      } else if (transfer.isDirectory) {
        const handle = await startSftpDownloadDirectory(
          owner.backendSessionId,
          transfer.remotePath,
          transfer.localPath,
          undefined,
          transfer.directoryCheckpoint,
          (event) => handleTransferEvent(transfer.id, owner, "download", true, event),
        );
        registerStartedSftpTransfer(owner, transfer.id, handle);
      } else if (transfer.direction === "upload") {
        const handle = await startSftpUpload(
          owner.backendSessionId,
          transfer.localPath,
          transfer.remotePath,
          (event) => handleTransferEvent(transfer.id, owner, "upload", false, event),
          { plan: transfer.plan!, checkpoint: transfer.checkpoint! },
        );
        registerStartedSftpTransfer(owner, transfer.id, handle, { plan: handle.plan });
      } else {
        const handle = await startSftpDownload(
          owner.backendSessionId,
          transfer.remotePath,
          transfer.localPath,
          (event) => handleTransferEvent(transfer.id, owner, "download", false, event),
          { plan: transfer.downloadPlan!, checkpoint: transfer.checkpoint! },
        );
        registerStartedSftpTransfer(owner, transfer.id, handle, {
          downloadPlan: handle.plan,
        });
      }
    } catch {
      sftpController.failTransferStart(owner, transfer.id, SFTP_TRANSFER_ERROR);
    }
  }, [
    captureCurrentSftpOwner,
    handleTransferEvent,
    isCurrentSftpOwner,
    registerStartedSftpTransfer,
    sftpController,
    updateTransfer,
  ]);

  const controlOwnedSftpTransfer = useCallback(async (
    transfer: VisibleTransfer,
    action: "pause" | "resume" | "cancel",
  ) => {
    const owner = captureCurrentSftpOwner();
    if (!owner || !isCurrentSftpOwner(owner)) return;
    const controlled = await sftpController.controlTransfer(owner, transfer.id, action);
    if (!controlled && isCurrentSftpOwner(owner)) {
      updateTransfer(transfer.id, owner, { error: SFTP_TRANSFER_CONTROL_ERROR });
    }
  }, [captureCurrentSftpOwner, isCurrentSftpOwner, sftpController, updateTransfer]);

  useEffect(() => {
    if (!sftpOpen || activeSshSession?.state !== "connected") return;
    const owner = captureCurrentSftpOwner();
    if (!owner) return;
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void getCurrentWebview().onDragDropEvent((event) => {
      if (event.payload.type === "drop" && isCurrentSftpOwner(owner)) {
        for (const path of event.payload.paths) void uploadLocalPath(path, owner);
      }
    }).then((dispose) => {
      if (disposed) dispose();
      else unlisten = dispose;
    }).catch(() => {
      if (isCurrentSftpOwner(owner)) setOwnedSftpError(owner, SFTP_OPERATION_ERROR);
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [
    captureCurrentSftpOwner,
    activeSshSession?.state,
    isCurrentSftpOwner,
    setOwnedSftpError,
    sftpOpen,
    uploadLocalPath,
  ]);

  useEffect(() => {
    if (activeSurface !== "terminal") return;
    const timer = window.setTimeout(() => {
      if (activeLocalSession) localTerminals.fitActive();
      else if (activeSshSession) sshTerminals.fitActive();
      else fit();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [
    activeSurface,
    activeLocalSession,
    activeSshSession,
    fit,
    localTerminals.fitActive,
    sshTerminals.fitActive,
    // Opening or resizing the right-hand tool panel changes the xterm's
    // actual cell width even when the window itself stays the same size.
    // Schedule a fit for that transition as well; otherwise a freshly opened
    // AI/SFTP panel can leave the remote shell at its old column count and
    // wrap ordinary output one character at a time.
    terminalSidePanelVisible,
    terminalSidePanelTab,
    terminalSidePanelWidth,
    sftpOpen,
  ]);

  useEffect(() => {
    const element = terminalElement.current;
    if (!element) return;
    const appearance = liveTerminalAppearanceRef.current;
    const instance = new Terminal({
      convertEol: false,
      ...appearance.xtermOptions,
    });
    const fitter = new FitAddon();
    instance.loadAddon(fitter);
    instance.open(element);
    if (BROWSER_VISUAL_PREVIEW) {
      instance.writeln("\x1b[32mgoral@dev\x1b[0m:\x1b[34m~/projects\x1b[0m$ cargo test --workspace");
      instance.writeln("   Compiling goral-core v0.1.0");
      instance.writeln("   Compiling goral-ssh v0.1.0");
      instance.writeln("    Finished test profile in 2.31s");
      instance.write("\x1b[32mgoral@dev\x1b[0m:\x1b[34m~/projects\x1b[0m$ ");
    }
    terminal.current = instance;
    fitAddon.current = fitter;
    fitter.fit();
    const inputWriteQueue = new TerminalInputWriteQueue();
    const textEncoder = new TextEncoder();
    let inputOperation: unknown = null;
    let inputSessionId: string | null = null;
    const dispatchInput = (prepared: PreparedTerminalTextInput) => {
      const active = session.current;
      if (!active) return;
      const operation = connectionOperation.current;
      if (operation !== inputOperation || active.sessionId !== inputSessionId) {
        inputWriteQueue.invalidate();
        inputOperation = operation;
        inputSessionId = active.sessionId;
      }
      const isCurrent = () => (
        session.current === active
        && connectionOperation.current === operation
        && operation?.handle === active
        && operation.closed !== true
        && operation.cancelRequested !== true
      );
      const sendChunks = (
        chunks: readonly string[],
        send: (sessionId: string, data: Uint8Array) => Promise<void>,
      ) => {
        void inputWriteQueue.enqueue(
          chunks,
          (chunk) => send(active.sessionId, textEncoder.encode(chunk)),
          isCurrent,
        ).catch(() => undefined);
      };

      if (active.protocol === "telnet") {
        if (telnetLocalEcho.current) {
          const localEcho = formatTelnetLocalEcho(prepared.text);
          if (localEcho) instance.write(localEcho);
        }
        sendChunks(prepared.chunks, sendTelnetInput);
      } else if (active.protocol === "serial") {
        const zmodemOwner = serialZmodemTransferOwner.current;
        if (zmodemOwner?.sessionId === active.sessionId) {
          if (prepared.text.includes("\x03") && !zmodemOwner.cancelRequested) {
            zmodemOwner.cancelRequested = true;
            setSerialZmodemTransfer((current) => current?.token === zmodemOwner.token
              ? { ...current, phase: "canceling" }
              : current);
            void cancelSerialZmodem(active.sessionId, zmodemOwner.transferId).catch(() => {
              if (serialZmodemTransferOwner.current === zmodemOwner) {
                zmodemOwner.cancelRequested = false;
                setSerialZmodemTransfer((current) => current?.token === zmodemOwner.token
                  ? {
                    ...current,
                    phase: zmodemOwner.resumePhase,
                  }
                  : current);
                setError(translateRef.current("transfer.zmodem.cancelFailed"));
              }
            });
          }
          return;
        }
        const transferOwner = serialYmodemTransferOwner.current;
        if (transferOwner?.sessionId === active.sessionId) {
          if (
            prepared.text.includes("\x03")
            && transferOwner.transferStarted
            && transferOwner.transferId !== null
            && !transferOwner.cancelRequested
          ) {
            transferOwner.cancelRequested = true;
            setSerialYmodemTransfer((current) => (
              current?.token === transferOwner.token
                ? { ...current, phase: "canceling" }
                : current
            ));
            void cancelSerialYmodem(active.sessionId, transferOwner.transferId).catch(() => {
              if (serialYmodemTransferOwner.current === transferOwner) {
                transferOwner.cancelRequested = false;
                setSerialYmodemTransfer((current) => (
                  current?.token === transferOwner.token
                    ? { ...current, phase: "transferring" }
                    : current
                ));
                setError(translateRef.current("transfer.ymodem.cancelFailed"));
              }
            });
          }
          return;
        }
        const config = serialInputConfig.current;
        const mapped = mapTerminalBackspaceInput(prepared.text, config?.backspaceBehavior);
        const writeToSession = (value: string) => {
          sendChunks([value], sendSerialInput);
        };
        if (config?.lineMode) {
          handleSerialLineModeInput(mapped, {
            bufferRef: serialLineBuffer,
            localEcho: config.localEcho,
            writeToSession,
            writeToTerminal: (value) => instance.write(value),
          });
        } else {
          if (config?.localEcho) {
            const localEcho = formatSerialLocalEcho(mapped);
            if (localEcho) instance.write(localEcho);
          }
          sendChunks(
            prepared.chunks.length === 1 && prepared.chunks[0] === prepared.text
              ? [mapped]
              : Array.from(mapped),
            sendSerialInput,
          );
        }
      } else if (active.protocol === "mosh") {
        sendChunks(prepared.chunks, sendMoshInput);
      } else if (active.protocol === "et") {
        sendChunks(prepared.chunks, sendEtInput);
      } else {
        sendChunks(prepared.chunks, sendSshInput);
      }
    };
    const inputBinding = createTerminalInputBinding(instance, dispatchInput);
    const input = instance.onData(inputBinding.handleData);
    inputBinding.bindDom();
    const observer = new ResizeObserver(fit);
    observer.observe(element);
    return () => {
      observer.disconnect();
      input.dispose();
      inputWriteQueue.invalidate();
      inputBinding.dispose();
      webglLoadGeneration.current += 1;
      instance.dispose();
      terminal.current = null;
      fitAddon.current = null;
      webglAddon.current = null;
    };
  }, [fit]);

  useEffect(() => {
    const instance = terminal.current;
    if (!instance) return;
    const generation = ++webglLoadGeneration.current;
    applyResolvedTerminalAppearance(instance, liveTerminalAppearance);
    if (shouldAttemptWebgl(liveTerminalAppearance.renderer)) {
      if (!webglAddon.current) {
        void installPreferredWebglAddon(
          instance,
          liveTerminalAppearance.renderer,
          () => terminal.current === instance && webglLoadGeneration.current === generation,
        ).then((addon) => {
          if (!addon) return;
          if (terminal.current === instance && webglLoadGeneration.current === generation) {
            webglAddon.current = addon as WebglAddon;
          } else {
            addon.dispose();
          }
        });
      }
    } else if (webglAddon.current) {
      webglAddon.current.dispose();
      webglAddon.current = null;
    }
    const timer = window.setTimeout(fit, 0);
    return () => window.clearTimeout(timer);
  }, [fit, liveTerminalAppearance]);

  useEffect(() => {
    if (!NATIVE_DESKTOP_RUNTIME_AVAILABLE) return;
    let mounted = true;
    let promptChannel: Awaited<ReturnType<typeof subscribeHostKeyPrompts>> | null = null;
    void subscribeHostKeyPrompts((prompt) => {
      if (mounted) sshPromptQueue.enqueueHostKey(prompt);
    }).then((channel) => {
      promptChannel = channel;
      if (!mounted) promptChannel.onmessage = () => {};
    }).catch(() => {
      if (mounted) setError(translateRef.current("hostKey.error.subscribeFailed"));
    });
    return () => {
      mounted = false;
      if (promptChannel) promptChannel.onmessage = () => {};
    };
  }, [sshPromptQueue]);

  useEffect(() => {
    if (!NATIVE_DESKTOP_RUNTIME_AVAILABLE) return;
    let mounted = true;
    let promptChannel: Awaited<ReturnType<typeof subscribeInteractivePrompts>> | null = null;
    void subscribeInteractivePrompts((prompt) => {
      if (mounted) sshPromptQueue.enqueueInteractive(prompt);
    }).then((channel) => {
      promptChannel = channel;
      if (!mounted) promptChannel.onmessage = () => {};
    }).catch(() => {
      if (mounted) setError(translateRef.current("interactiveAuth.error.subscribeFailed"));
    });
    return () => {
      mounted = false;
      if (promptChannel) promptChannel.onmessage = () => {};
    };
  }, [sshPromptQueue]);

  const handleSessionControl = useCallback((
    operation: ConnectionOperation,
    control: Parameters<SshSessionCallbacks["onControl"]>[0],
  ) => {
    if (connectionOperation.current !== operation) return;
    switch (control.type) {
      case "connecting":
        if (!operation.cancelRequested) setConnectionState("connecting");
        break;
      case "connected":
        operation.connected = true;
        if (!operation.cancelRequested) {
          setConnectionState("connected");
          if (
            operation.protocol === "ssh"
            && rendererSettings.appearance.showSftpTab
            && rendererSettings.sftp.autoOpenSidebar
          ) {
            setTerminalSidePanelTab("sftp");
            setTerminalSidePanelOpen(true);
          }
        }
        break;
      case "ready":
        // Mosh emits an explicit ready barrier after its trusted native
        // client owns the PTY. Connection state is already established.
        break;
      case "serialZmodemDetected": {
        if (operation.protocol !== "serial" || operation.cancelRequested) {
          break;
        }
        if (!operation.handle) {
          operation.pendingSerialZmodemDetection ??= {
            sessionId: control.sessionId,
            transferId: control.transferId,
            direction: control.direction,
          };
          break;
        }
        if (operation.handle.sessionId !== control.sessionId) break;
        const existing = serialZmodemTransferOwner.current;
        if (
          existing?.sessionId === control.sessionId
          && existing.transferId === control.transferId
        ) break;
        if (existing || serialYmodemTransferOwner.current) break;
        const owner: SerialZmodemTransferOwner = {
          token: ++nextSerialZmodemTransferToken.current,
          sessionId: control.sessionId,
          transferId: control.transferId,
          direction: control.direction,
          operation,
          resumePhase: "selecting",
          cancelRequested: false,
        };
        serialZmodemTransferOwner.current = owner;
        setSerialZmodemTransfer({
          token: owner.token,
          sessionId: owner.sessionId,
          transferId: owner.transferId,
          direction: owner.direction,
          phase: "selecting",
          progress: null,
        });
        terminal.current?.writeln(
          `\r\n\x1b[90m${t(control.direction === "send"
            ? "transfer.zmodem.detectedReceiver"
            : "transfer.zmodem.detectedSender")}\x1b[0m`,
        );
        void startSerialZmodem(
          owner.sessionId,
          owner.transferId,
          owner.direction,
          rendererLocale,
          (event) => handleSessionControlRef.current?.(operation, event),
        ).then((response) => {
          if (serialZmodemTransferOwner.current !== owner) return;
          if (response.canceled) {
            terminal.current?.writeln(
              `\r\n\x1b[90m${t("transfer.zmodem.selectionCanceled")}\x1b[0m`,
            );
          } else {
            const message = t(
              owner.direction === "send" ? "transfer.zmodem.sent" : "transfer.zmodem.received",
              {
                count: formatCount(response.fileCount),
                size: formatBytes(response.transferredBytes),
              },
            );
            terminal.current?.writeln(
              `\r\n\x1b[32m${message}\x1b[0m`,
            );
          }
          serialZmodemTransferOwner.current = null;
          setSerialZmodemTransfer((current) => current?.token === owner.token ? null : current);
        }).catch(() => {
          if (serialZmodemTransferOwner.current !== owner) return;
          const message = owner.cancelRequested
            ? t("transfer.zmodem.canceled")
            : t("transfer.zmodem.failed");
          if (!owner.cancelRequested) setError(message);
          terminal.current?.writeln(`\r\n\x1b[${owner.cancelRequested ? "90" : "31"}m${message}\x1b[0m`);
          serialZmodemTransferOwner.current = null;
          setSerialZmodemTransfer((current) => current?.token === owner.token ? null : current);
        });
        break;
      }
      case "serialZmodemProgress": {
        const owner = serialZmodemTransferOwner.current;
        if (
          !owner
          || owner.operation !== operation
          || owner.sessionId !== control.sessionId
          || owner.transferId !== control.transferId
          || owner.direction !== control.direction
        ) break;
        const progress: SerialZmodemProgressEvent = {
          stage: control.stage,
          transferredBytes: control.transferredBytes,
          totalBytes: control.totalBytes,
          ...(control.fileName ? { fileName: control.fileName } : {}),
          fileIndex: control.fileIndex,
          fileCount: control.fileCount,
        };
        owner.resumePhase = control.stage === "finalizing" ? "finalizing" : "transferring";
        setSerialZmodemTransfer((current) => current?.token === owner.token ? {
          ...current,
          phase: owner.cancelRequested ? "canceling" : owner.resumePhase,
          progress,
        } : current);
        break;
      }
      case "serialZmodemCompleted": {
        const owner = serialZmodemTransferOwner.current;
        if (
          !owner
          || owner.operation !== operation
          || owner.sessionId !== control.sessionId
          || owner.transferId !== control.transferId
          || owner.direction !== control.direction
        ) break;
        const message = t(
          control.direction === "send" ? "transfer.zmodem.sent" : "transfer.zmodem.received",
          {
            count: formatCount(control.fileCount),
            size: formatBytes(control.transferredBytes),
          },
        );
        terminal.current?.writeln(`\r\n\x1b[32m${message}\x1b[0m`);
        serialZmodemTransferOwner.current = null;
        setSerialZmodemTransfer((current) => current?.token === owner.token ? null : current);
        break;
      }
      case "serialZmodemCanceled": {
        const owner = serialZmodemTransferOwner.current;
        if (
          !owner
          || owner.operation !== operation
          || owner.sessionId !== control.sessionId
          || owner.transferId !== control.transferId
          || owner.direction !== control.direction
        ) break;
        terminal.current?.writeln(
          `\r\n\x1b[90m${t("transfer.zmodem.canceled")}\x1b[0m`,
        );
        serialZmodemTransferOwner.current = null;
        setSerialZmodemTransfer((current) => current?.token === owner.token ? null : current);
        break;
      }
      case "serialZmodemError": {
        const owner = serialZmodemTransferOwner.current;
        if (
          !owner
          || owner.operation !== operation
          || owner.sessionId !== control.sessionId
          || owner.transferId !== control.transferId
          || owner.direction !== control.direction
        ) break;
        if (!owner.cancelRequested) {
          const message = t("transfer.zmodem.failed");
          setError(message);
          terminal.current?.writeln(`\r\n\x1b[31m${message}\x1b[0m`);
        }
        serialZmodemTransferOwner.current = null;
        setSerialZmodemTransfer((current) => current?.token === owner.token ? null : current);
        break;
      }
      case "error":
        if (!operation.cancelRequested) {
          const message = t("terminal.runtime.connectionFailed");
          setError(message);
          terminal.current?.writeln(`\r\n\x1b[31m${message}\x1b[0m`);
        }
        break;
      case "closed":
        operation.closed = true;
        connectionOperation.current = null;
        serialYmodemTransferOwner.current = null;
        setSerialYmodemTransfer(null);
        serialZmodemTransferOwner.current = null;
        setSerialZmodemTransfer(null);
        telnetLocalEcho.current = false;
        serialInputConfig.current = null;
        serialLineBuffer.current = "";
        terminalResizeCoordinator.current?.reset();
        advanceSftpSessionGeneration();
        operation.handle?.dispose();
        if (!operation.handle || session.current?.sessionId === operation.handle.sessionId) {
          session.current = null;
        }
        operation.handle = null;
        setConnectionState("disconnected");
        if (
          operation.protocol === "telnet"
          || operation.protocol === "serial"
          || operation.protocol === "et"
        ) {
          setConnectionTarget(operation.target);
          setActiveSurface("terminal");
        } else {
          setConnectionTarget(null);
          setActiveSurface("vault");
        }
        setTerminalSidePanelTab("sftp");
        setTerminalSidePanelOpen(false);
        terminal.current?.writeln(`\r\n\x1b[90m${t("terminal.runtime.connectionClosed")}\x1b[0m`);
        break;
      case "exitStatus":
        terminal.current?.writeln(`\r\n\x1b[90m${t("terminal.runtime.remoteExited", { status: control.status })}\x1b[0m`);
        break;
      case "eof":
        break;
      case "telnetEchoMode":
        if (operation.protocol === "telnet") telnetLocalEcho.current = control.localEcho;
        break;
    }
  }, [advanceSftpSessionGeneration, formatBytes, formatCount, rendererSettings, t]);
  handleSessionControlRef.current = handleSessionControl;

  const handleSessionData = useCallback((operation: ConnectionOperation, frame: Uint8Array) => {
    if (connectionOperation.current !== operation || operation.cancelRequested) return;
    const offset = frame[0] === 1 ? 5 : 1;
    terminal.current?.write(frame.subarray(offset));
  }, []);

  const buildShellRequest = useCallback(() => ({
    terminal: "xterm-256color",
    size: {
      columns: terminal.current?.cols ?? 80,
      rows: terminal.current?.rows ?? 24,
      pixelWidth: 0,
      pixelHeight: 0,
    },
    environment: [] as Array<[string, string]>,
  }), []);

  const activateSession = useCallback(async (
    target: ConnectionTarget,
    start: (callbacks: SshSessionCallbacks) => Promise<ActiveTerminalSession>,
    options: { preserveScrollback?: boolean } = {},
  ): Promise<string | null> => {
    if (
      connectionOperation.current
      || session.current
      || terminalSessionCatalog.snapshot.order.length > 0
    ) {
      return t("terminal.runtime.connectionBusy");
    }
    terminalResizeCoordinator.current?.reset();
    const sftpGeneration = advanceSftpSessionGeneration();
    const operation: ConnectionOperation = {
      token: ++nextConnectionToken.current,
      protocol: target.protocol,
      target,
      sftpGeneration,
      handle: null,
      connected: false,
      cancelRequested: false,
      closed: false,
      pendingSerialZmodemDetection: null,
    };
    connectionOperation.current = operation;
    serialYmodemTransferOwner.current = null;
    setSerialYmodemTransfer(null);
    serialZmodemTransferOwner.current = null;
    setSerialZmodemTransfer(null);
    telnetLocalEcho.current = false;
    serialInputConfig.current = target.protocol === "serial"
      ? target.serialConfig ?? null
      : null;
    serialLineBuffer.current = "";
    setError(null);
    setConnectionState("connecting");
    setTerminalSidePanelTab("sftp");
    setTerminalSidePanelOpen(false);
    setConnectionTarget(target);
    setSidebarView("saved");
    setActiveSurface("terminal");
    if (!options.preserveScrollback) terminal.current?.clear();
    const targetLabel = target.protocol === "serial"
      ? `${target.hostname} · ${target.port} baud`
      : `${target.hostname}:${target.port}`;
    terminal.current?.writeln(`\x1b[90m${t("terminal.runtime.connecting", { target: targetLabel })}\x1b[0m`);
    try {
      const active = await start({
        onControl: (control) => handleSessionControl(operation, control),
        onData: (frame) => handleSessionData(operation, frame),
      });
      operation.handle = active;
      if (
        connectionOperation.current !== operation
        || operation.closed
        || operation.cancelRequested
      ) {
        let stopFailure: unknown = null;
        try {
          await cancelTerminalSession(active);
        } catch {
          try {
            await closeTerminalSession(active);
          } catch (reason) {
            stopFailure = reason;
          }
        }
        if (
          stopFailure
          && connectionOperation.current === operation
          && !operation.closed
        ) {
          operation.cancelRequested = false;
          session.current = active;
          if (active.protocol === "ssh") {
            bindSftpSessionOwner(active.sessionId, operation.sftpGeneration);
          }
          setConnectionState(operation.connected ? "connected" : "connecting");
          const message = t("terminal.runtime.cancelFailed");
          setError(message);
          return message;
        }
        active.dispose();
        if (connectionOperation.current === operation) {
          connectionOperation.current = null;
          setConnectionState("disconnected");
          if (
            target.protocol === "telnet"
            || target.protocol === "serial"
            || target.protocol === "et"
          ) {
            setConnectionTarget(target);
            setActiveSurface("terminal");
          } else {
            setConnectionTarget(null);
            setActiveSurface("vault");
          }
        }
        return null;
      }
      session.current = active;
      const pendingSerialZmodemDetection = operation.pendingSerialZmodemDetection;
      operation.pendingSerialZmodemDetection = null;
      if (
        active.protocol === "serial"
        && pendingSerialZmodemDetection?.sessionId === active.sessionId
      ) {
        handleSessionControlRef.current?.(operation, {
          type: "serialZmodemDetected",
          sessionId: pendingSerialZmodemDetection.sessionId,
          transferId: pendingSerialZmodemDetection.transferId,
          direction: pendingSerialZmodemDetection.direction,
        });
      }
      if (active.protocol === "ssh") {
        bindSftpSessionOwner(active.sessionId, operation.sftpGeneration);
      }
      fit();
      return null;
    } catch (reason) {
      const message = messageOf(reason);
      if (connectionOperation.current !== operation || operation.closed) return null;
      connectionOperation.current = null;
      operation.handle?.dispose();
      if (!operation.handle || session.current?.sessionId === operation.handle.sessionId) {
        session.current = null;
      }
      operation.handle = null;
      telnetLocalEcho.current = false;
      serialInputConfig.current = null;
      serialLineBuffer.current = "";
      terminalResizeCoordinator.current?.reset();
      advanceSftpSessionGeneration();
      setConnectionState("disconnected");
      if (
        target.protocol === "telnet"
        || target.protocol === "serial"
        || target.protocol === "et"
      ) {
        setConnectionTarget(target);
        setActiveSurface("terminal");
      } else {
        setConnectionTarget(null);
        setActiveSurface("vault");
      }
      if (operation.cancelRequested) {
        terminal.current?.writeln(`\r\n\x1b[90m${t("terminal.runtime.connectionCanceled")}\x1b[0m`);
        return null;
      }
      const safeMessage = t("terminal.runtime.connectionFailed");
      setError(safeMessage);
      terminal.current?.writeln(`\r\n\x1b[31m${safeMessage}\x1b[0m`);
      return message;
    }
  }, [
    advanceSftpSessionGeneration,
    bindSftpSessionOwner,
    fit,
    handleSessionControl,
    handleSessionData,
    t,
    terminalSessionCatalog,
  ]);

  const activateSharedTerminalSession = useCallback((
    workspaceSessionId: WorkspaceSessionId,
    keepPaneWorkspaceVisible: boolean,
  ): boolean => {
    const snapshot = terminalSessionCatalog.snapshot.sessions[workspaceSessionId];
    if (!snapshot) return false;
    if (snapshot.protocol === "local") {
      localTerminals.activate(workspaceSessionId);
    } else if (snapshot.protocol === "ssh" && sshTerminals.owns(workspaceSessionId)) {
      sshTerminals.activate(workspaceSessionId);
    } else {
      return false;
    }
    if (
      keepPaneWorkspaceVisible
      && terminalPaneLayout
      && terminalPaneLayoutContains(terminalPaneLayout, workspaceSessionId)
    ) {
      setTerminalPaneLayout(focusTerminalPane(terminalPaneLayout, workspaceSessionId));
      setTerminalPaneWorkspaceVisible(true);
    } else {
      setTerminalPaneWorkspaceVisible(false);
      setTerminalPaneZoomedSessionId(null);
      setTerminalPaneResize(null);
    }
    setSidebarView("saved");
    setActiveSurface("terminal");
    return true;
  }, [localTerminals, sshTerminals, terminalPaneLayout, terminalSessionCatalog]);

  const commitTerminalPaneClone = useCallback((
    sourceSessionId: WorkspaceSessionId,
    clonedSessionId: WorkspaceSessionId,
    direction: TerminalPaneSplitDirection,
  ): void => {
    if (sourceSessionId === clonedSessionId) return;
    setTerminalPaneLayout((current) => {
      const base = current
        && terminalPaneWorkspaceVisible
        && terminalPaneLayoutContains(current, sourceSessionId)
        ? current
        : createTerminalPaneLayout(sourceSessionId);
      return splitTerminalPane(base, sourceSessionId, clonedSessionId, direction);
    });
    setTerminalPaneWorkspaceVisible(true);
    setTerminalPaneZoomedSessionId(null);
    setTerminalPaneResize(null);
    const source = terminalSessionCatalog.snapshot.sessions[sourceSessionId];
    if (source?.protocol === "local") localTerminals.activate(sourceSessionId);
    if (source?.protocol === "ssh" && sshTerminals.owns(sourceSessionId)) {
      sshTerminals.activate(sourceSessionId);
    }
    setSidebarView("saved");
    setActiveSurface("terminal");
    fitSharedTerminalSessionsOnNextFrame([sourceSessionId, clonedSessionId]);
  }, [
    fitSharedTerminalSessionsOnNextFrame,
    localTerminals,
    sshTerminals,
    terminalPaneWorkspaceVisible,
    terminalSessionCatalog,
  ]);

  const connect = async (event: FormEvent) => {
    event.preventDefault();
    const numericPort = Number(port);
    const quickTarget = { hostname, port: numericPort, username };
    if (quickProtocol === "mosh") {
      await activateSession(
        { protocol: "mosh", ...quickTarget },
        async (callbacks) => {
          let passwordToStage = password;
          setPassword("");
          try {
            const credentialReference = await stageSshPassword(passwordToStage);
            passwordToStage = "";
            const active = await startMoshSession({
              config: {
                hostname,
                port: numericPort,
                username,
                auth: { method: "password", hasPassword: true },
              },
              credentialReference,
              verifyHostKeys: true,
              size: buildShellRequest().size,
            }, callbacks);
            return { ...active, protocol: "mosh" };
          } finally {
            passwordToStage = "";
          }
        },
      );
      return;
    }
    if (quickProtocol === "telnet") {
      await activateSession(
        { protocol: "telnet", ...quickTarget },
        async (callbacks) => {
          let passwordToStage = password;
          setPassword("");
          try {
            const credentialReference = passwordToStage.length > 0
              ? await stageTelnetPassword(passwordToStage)
              : undefined;
            passwordToStage = "";
            const shell = buildShellRequest();
            const active = await startTelnetSession({
              hostname,
              port: numericPort,
              ...((username.length > 0 || credentialReference) ? { username } : {}),
              ...(credentialReference ? { credentialReference } : {}),
              terminal: shell.terminal,
              size: shell.size,
              charset: "utf-8",
            }, callbacks);
            return { ...active, protocol: "telnet" };
          } finally {
            passwordToStage = "";
          }
        },
      );
      return;
    }
    if (connectionOperation.current || session.current) return;
    let passwordToStage = password;
    setPassword("");
    const start: SshTerminalStart = async (callbacks, initialSize, clientAttemptId) => {
      try {
        const credentialReference = await stageSshPassword(passwordToStage);
        passwordToStage = "";
        return await startSshSession({
          clientAttemptId,
          config: {
            hostname,
            port: numericPort,
            username,
            auth: { method: "password", hasPassword: true },
          },
          credentialReference,
          verifyHostKeys: true,
          shell: {
            terminal: "xterm-256color",
            size: initialSize,
            environment: [],
          },
        }, callbacks);
      } finally {
        passwordToStage = "";
      }
    };
    setError(null);
    setConnectionTarget(null);
    setTerminalSidePanelOpen(false);
    setSidebarView("saved");
    setActiveSurface("terminal");
    const activeSshSession = sshTerminals.activeSession;
    const activeSshTarget = activeSshSession
      ? sshTerminals.targetFor(activeSshSession.id)
      : undefined;
    const canRetryActiveQuick = activeSshSession?.state === "disconnected"
      && activeSshTarget?.kind === "quick"
      && activeSshTarget.hostname === hostname
      && activeSshTarget.port === numericPort
      && (
        activeSshTarget.username === username
        || restoredQuickSshSessionIds.current.has(activeSshSession.id)
      );
    try {
      const result = canRetryActiveQuick
        ? {
            id: activeSshSession.id,
            error: await sshTerminals.retry(activeSshSession.id, start),
          }
        : await sshTerminals.open({
            kind: "quick",
            title: hostname || "SSH",
            hostname,
            port: numericPort,
            username,
          }, start);
      bindSftpWorkspace(result.id);
      if (result.error) setError(t("terminal.runtime.sshFailed"));
    } catch {
      setError(t("terminal.runtime.sshFailed"));
    } finally {
      passwordToStage = "";
    }
  };

  const retryTelnetConnection = async () => {
    const target = connectionTarget;
    if (
      !target
      || target.protocol !== "telnet"
      || connectionState !== "disconnected"
      || connectionOperation.current
      || session.current
    ) return;
    if (target.savedHost && !target.savedHost.hasSavedCredential) {
      setSavedHostPasswordPrompt({ host: target.savedHost, password: "" });
      return;
    }
    await activateSession(
      target,
      async (callbacks) => {
        const shell = buildShellRequest();
        const active = target.savedHost
          ? await startSavedTelnetSession({
            hostId: target.savedHost.id,
            expectedRevision: target.savedHost.revision,
            terminal: shell.terminal,
            size: shell.size,
          }, callbacks)
          : await startTelnetSession({
            hostname: target.hostname,
            port: target.port,
            ...(target.username.length > 0 ? { username: target.username } : {}),
            terminal: shell.terminal,
            size: shell.size,
            charset: "utf-8",
          }, callbacks);
        return { ...active, protocol: "telnet" };
      },
      { preserveScrollback: true },
    );
  };

  const retryEtConnection = async () => {
    const target = connectionTarget;
    if (
      !target
      || target.protocol !== "et"
      || !target.savedHost
      || connectionState !== "disconnected"
      || connectionOperation.current
      || session.current
    ) return;
    await activateSession(
      target,
      async (callbacks) => {
        const size = buildShellRequest().size;
        const active = await startEtSession({
          hostId: target.savedHost!.id,
          columns: size.columns,
          rows: size.rows,
        }, callbacks);
        return { ...active, protocol: "et" };
      },
      { preserveScrollback: true },
    );
  };

  const retrySerialConnection = async () => {
    const target = connectionTarget;
    if (
      !target
      || target.protocol !== "serial"
      || !target.serialConfig
      || connectionState !== "disconnected"
      || connectionOperation.current
      || session.current
    ) return;
    await activateSession(
      target,
      async (callbacks) => {
        const size = buildShellRequest().size;
        const active = target.savedHost
          ? await startSavedSerialSession({
            hostId: target.savedHost.id,
            expectedRevision: target.savedHost.revision,
            size,
          }, callbacks)
          : await startSerialSession({
            config: target.serialConfig!,
            size,
            ...(target.charset ? { charset: target.charset } : {}),
          }, callbacks);
        return { ...active, protocol: "serial" };
      },
      { preserveScrollback: true },
    );
  };

  const retryLocalTerminalConnection = async () => {
    const active = localTerminals.activeSession;
    if (!active || active.state !== "disconnected") return;
    await localTerminals.retry(active.id);
  };

  const openLocalTerminalPanel = () => {
    if (connectionOperation.current || session.current) return;
    if (terminalSessionCatalog.snapshot.order.length >= MAX_WORKSPACE_SESSIONS) {
      setError(t("terminal.local.tabLimit"));
      return;
    }
    setError(null);
    setLocalTerminalPanelOpen(true);
  };

  const handleLocalTerminalConnect = async (
    submission: LocalTerminalSubmission,
  ): Promise<void> => {
    if (connectionOperation.current || session.current) {
      throw new Error(t("terminal.runtime.connectionBusy"));
    }
    setError(null);
    setConnectionTarget(null);
    setTerminalSidePanelOpen(false);
    setActiveSurface("terminal");
    const result = await localTerminals.open({
      shell: submission.shell,
      ...(submission.cwd ? { cwd: submission.cwd } : {}),
    });
    setLocalTerminalPanelOpen(false);
    if (result.error) setError(t("terminal.local.startFailed"));
  };

  const openQuickSerialPanel = () => {
    if (
      connectionOperation.current
      || session.current
      || terminalSessionCatalog.snapshot.order.length > 0
    ) return;
    setError(null);
    setSerialPanel({ mode: "quick" });
  };

  const openCreateSerialPanel = () => {
    if (connectionOperation.current || savedHostMutation.current !== null) return;
    setSavedHostsError(null);
    setSavedHostEditor(null);
    setSerialPanel({ mode: "create" });
  };

  const openSavedSerialPanel = (host: SavedHost) => {
    if (connectionOperation.current || savedHostMutation.current !== null) return;
    setSavedHostsError(null);
    setSavedHostEditor(null);
    setSerialPanel({ mode: "saved", hostId: host.id });
  };

  const handleQuickSerialConnect = async (
    submission: QuickSerialConnectSubmission,
  ): Promise<void> => {
    const failure = await activateSession(
      {
        protocol: "serial",
        hostname: submission.config.path,
        port: submission.config.baudRate,
        username: "",
        serialConfig: submission.config,
        charset: submission.charset,
      },
      async (callbacks) => {
        const active = await startSerialSession({
          config: submission.config,
          charset: submission.charset,
          size: buildShellRequest().size,
        }, callbacks);
        return { ...active, protocol: "serial" };
      },
    );
    if (failure) throw new Error(failure);
    setSerialPanel(null);
  };

  const handleCreateSavedSerial = async (
    submission: SavedSerialCreateSubmission,
  ): Promise<void> => {
    if (savedHostMutation.current !== null || connectionOperation.current) {
      throw new Error(t("serial.error.operationBusy"));
    }
    const mutationToken = ++nextSavedHostMutationToken.current;
    savedHostMutation.current = mutationToken;
    setSavedHostSubmitting(true);
    setSavedHostsError(null);
    try {
      await createSavedHost({ draft: submission.draft });
      setGroupConfigRefreshKey((current) => current + 1);
      await refreshSavedHosts(false, true);
      if (savedHostMutation.current === mutationToken) {
        setSavedHostsNotice(t("serial.notice.hostSaved"));
        setSerialPanel(null);
      }
    } catch {
      if (savedHostMutation.current === mutationToken) {
        setSavedHostsError(t("serial.error.createFailed"));
      }
      throw new Error(t("serial.error.createFailed"));
    } finally {
      if (savedHostMutation.current === mutationToken) {
        savedHostMutation.current = null;
        setSavedHostSubmitting(false);
      }
    }
  };

  const handleUpdateSavedSerial = async (
    submission: SavedSerialEditSubmission,
  ): Promise<void> => {
    if (savedHostMutation.current !== null || connectionOperation.current) {
      throw new Error(t("serial.error.operationBusy"));
    }
    const mutationToken = ++nextSavedHostMutationToken.current;
    savedHostMutation.current = mutationToken;
    setSavedHostSubmitting(true);
    setSavedHostsError(null);
    try {
      await updateSavedHost({
        id: submission.id,
        expectedRevision: submission.expectedRevision,
        draft: submission.draft,
        credentialMutation: { action: "keep" },
      });
      setGroupConfigRefreshKey((current) => current + 1);
      await refreshSavedHosts(false, true);
      if (savedHostMutation.current === mutationToken) {
        setSavedHostsNotice(t("serial.notice.hostUpdated"));
        setSerialPanel(null);
      }
    } catch {
      if (savedHostMutation.current === mutationToken) {
        setSavedHostsError(t("serial.error.updateFailed"));
        setGroupConfigRefreshKey((current) => current + 1);
        await refreshSavedHosts(true, true);
      }
      throw new Error(t("serial.error.updateFailed"));
    } finally {
      if (savedHostMutation.current === mutationToken) {
        savedHostMutation.current = null;
        setSavedHostSubmitting(false);
      }
    }
  };

  const connectSavedHost = useCallback(async (
    host: SavedHost,
    oneTimePassword?: string,
    selectedIdentityFilePaths?: string[],
    oneTimeKeyPassphrase?: string,
    oneTimeProxyPassword?: string,
    retryWorkspaceSessionId?: WorkspaceSessionId,
    onWorkspaceSessionOpened?: (id: WorkspaceSessionId) => void,
  ): Promise<string | null> => {
    const protocol: ConnectionProtocol = isSavedSerialHost(host)
      ? "serial"
      : isSavedTelnetHost(host)
        ? "telnet"
        : host.effectiveMoshEnabled
          ? "mosh"
          : isSavedEtHost(host)
            ? "et"
            : "ssh";
    const effectiveSerialConfig = protocol === "serial"
      ? host.effectiveSerialConfig ?? host.serialConfig
      : null;
    if (protocol === "serial" && !effectiveSerialConfig) {
      const message = t("serial.error.configIncomplete");
      setError(message);
      return message;
    }
    let sshWorkspaceSessionId = retryWorkspaceSessionId;
    let failure: string | null;
    if (protocol === "ssh") {
      if (connectionOperation.current || session.current) {
        return t("terminal.runtime.connectionBusy");
      }
      let passwordToStage = oneTimePassword;
      let proxyPasswordToStage = oneTimeProxyPassword;
      let keyPassphraseToStage = isSavedManagedKeyHost(host)
        ? oneTimeKeyPassphrase
        : undefined;
      if (passwordToStage !== undefined) {
        setSavedHostPasswordPrompt((current) => (
          current?.host.id === host.id ? { ...current, password: "" } : current
        ));
      }
      if (proxyPasswordToStage !== undefined) {
        setSavedHostProxyPasswordPrompt((current) => (
          current?.host.id === host.id ? { ...current, proxyPassword: "" } : current
        ));
      }
      const start: SshTerminalStart = async (callbacks, initialSize, clientAttemptId) => {
        try {
          const credentialReference = passwordToStage === undefined
            ? undefined
            : await stageSshPassword(passwordToStage);
          passwordToStage = undefined;
          const proxyCredentialReference = proxyPasswordToStage === undefined
            ? undefined
            : await stageSshPassword(proxyPasswordToStage);
          proxyPasswordToStage = undefined;
          const keyPassphraseReference = keyPassphraseToStage === undefined
            ? undefined
            : await stageSshKeyPassphrase(keyPassphraseToStage);
          keyPassphraseToStage = undefined;
          return await startSavedHostSession({
            hostId: host.id,
            expectedRevision: host.revision,
            clientAttemptId,
            ...(credentialReference ? { credentialReference } : {}),
            ...(proxyCredentialReference ? { proxyCredentialReference } : {}),
            ...(keyPassphraseReference ? { keyPassphraseReference } : {}),
            ...(selectedIdentityFilePaths ? { selectedIdentityFilePaths } : {}),
            verifyHostKeys: true,
            shell: {
              terminal: "xterm-256color",
              size: initialSize,
              environment: [],
            },
          }, callbacks);
        } catch (reason) {
          throw new Error(savedHostSessionErrorMessage(reason, t));
        } finally {
          passwordToStage = undefined;
          proxyPasswordToStage = undefined;
          keyPassphraseToStage = undefined;
        }
      };
      setError(null);
      setConnectionTarget(null);
      setTerminalSidePanelOpen(false);
      setSidebarView("saved");
      setActiveSurface("terminal");
      let notifiedWorkspaceSessionId: WorkspaceSessionId | undefined;
      const notifyWorkspaceSessionCreated = (workspaceSessionId: WorkspaceSessionId) => {
        sshWorkspaceSessionId = workspaceSessionId;
        if (notifiedWorkspaceSessionId === workspaceSessionId) return;
        setSavedHostPasswordPrompt((current) => current?.host.id === host.id
          ? { ...current, workspaceSessionId }
          : current);
        setSavedHostProxyPasswordPrompt((current) => current?.host.id === host.id
          ? { ...current, workspaceSessionId }
          : current);
        setSavedHostKeyPassphrasePrompt((current) => current?.host.id === host.id
          ? { ...current, workspaceSessionId }
          : current);
        notifiedWorkspaceSessionId = workspaceSessionId;
        try {
          onWorkspaceSessionOpened?.(workspaceSessionId);
        } catch {
          // Presentation observers cannot revoke the prompt's exact cancel ID.
        }
      };
      try {
        if (sshWorkspaceSessionId) {
          sshTerminals.activate(sshWorkspaceSessionId);
          failure = await sshTerminals.retry(sshWorkspaceSessionId, start);
        } else {
          const opened = await sshTerminals.open({
            kind: "saved",
            title: host.label,
            hostname: host.hostname,
            port: host.port,
            username: savedHostEffectiveUsername(host),
            savedHostId: host.id,
            appearanceOverride: {
              themeId: host.effectiveAppearance.themeId ?? undefined,
              fontFamily: host.effectiveAppearance.fontFamily ?? undefined,
              fontSize: host.effectiveAppearance.fontSize ?? undefined,
              fontWeight: host.effectiveAppearance.fontWeight ?? undefined,
            },
          }, start, notifyWorkspaceSessionCreated);
          sshWorkspaceSessionId = opened.id;
          failure = opened.error;
        }
      } catch (reason) {
        failure = savedHostSessionErrorMessage(reason, t);
      } finally {
        passwordToStage = undefined;
        proxyPasswordToStage = undefined;
        keyPassphraseToStage = undefined;
      }
      if (sshWorkspaceSessionId) {
        notifyWorkspaceSessionCreated(sshWorkspaceSessionId);
        bindSftpWorkspace(sshWorkspaceSessionId);
      }
      if (failure) setError(t("terminal.runtime.connectionFailed"));
    } else {
      failure = await activateSession(
      {
        protocol,
        hostname: effectiveSerialConfig?.path ?? host.hostname,
        port: effectiveSerialConfig?.baudRate ?? host.port,
        username: protocol === "serial" ? "" : savedHostEffectiveUsername(host),
        ...(effectiveSerialConfig ? { serialConfig: effectiveSerialConfig } : {}),
        ...(host.charset ? { charset: host.charset } : {}),
        effectiveAppearance: host.effectiveAppearance,
        ...(protocol === "telnet" || protocol === "serial" || protocol === "et"
          ? { savedHost: host }
          : {}),
      },
      async (callbacks) => {
        if (protocol === "serial") {
          try {
            const active = await startSavedSerialSession({
              hostId: host.id,
              expectedRevision: host.revision,
              size: buildShellRequest().size,
            }, callbacks);
            return { ...active, protocol: "serial" };
          } catch (reason) {
            throw new Error(savedHostSessionErrorMessage(reason, t));
          }
        }
        if (protocol === "telnet") {
          let passwordToStage = oneTimePassword;
          if (passwordToStage !== undefined) {
            setSavedHostPasswordPrompt((current) => (
              current?.host.id === host.id ? { ...current, password: "" } : current
            ));
          }
          try {
            const credentialReference = passwordToStage === undefined
              ? undefined
              : await stageTelnetPassword(passwordToStage);
            passwordToStage = undefined;
            const shell = buildShellRequest();
            const active = await startSavedTelnetSession({
              hostId: host.id,
              expectedRevision: host.revision,
              ...(credentialReference ? { credentialReference } : {}),
              terminal: shell.terminal,
              size: shell.size,
            }, callbacks);
            return { ...active, protocol: "telnet" };
          } catch (reason) {
            throw new Error(savedHostSessionErrorMessage(reason, t));
          } finally {
            passwordToStage = undefined;
          }
        }
        if (protocol === "et") {
          try {
            const size = buildShellRequest().size;
            const active = await startEtSession({
              hostId: host.id,
              columns: size.columns,
              rows: size.rows,
            }, callbacks);
            return { ...active, protocol: "et" };
          } catch (reason) {
            throw new Error(savedHostSessionErrorMessage(reason, t));
          }
        }
        let passwordToStage = oneTimePassword;
        let proxyPasswordToStage = oneTimeProxyPassword;
        let keyPassphraseToStage = isSavedManagedKeyHost(host)
          ? oneTimeKeyPassphrase
          : undefined;
        if (passwordToStage !== undefined) {
          setSavedHostPasswordPrompt((current) => (
            current?.host.id === host.id ? { ...current, password: "" } : current
          ));
        }
        if (proxyPasswordToStage !== undefined) {
          setSavedHostProxyPasswordPrompt((current) => (
            current?.host.id === host.id ? { ...current, proxyPassword: "" } : current
          ));
        }
        try {
          const credentialReference = passwordToStage === undefined
            ? undefined
            : await stageSshPassword(passwordToStage);
          passwordToStage = undefined;
          const proxyCredentialReference = proxyPasswordToStage === undefined
            ? undefined
            : await stageSshPassword(proxyPasswordToStage);
          proxyPasswordToStage = undefined;
          const keyPassphraseReference = keyPassphraseToStage === undefined
            ? undefined
            : await stageSshKeyPassphrase(keyPassphraseToStage);
          keyPassphraseToStage = undefined;
          const commonRequest = {
            hostId: host.id,
            expectedRevision: host.revision,
            ...(credentialReference ? { credentialReference } : {}),
            ...(proxyCredentialReference ? { proxyCredentialReference } : {}),
            ...(keyPassphraseReference ? { keyPassphraseReference } : {}),
            ...(selectedIdentityFilePaths ? { selectedIdentityFilePaths } : {}),
            verifyHostKeys: true,
          };
          const active = await startSavedMoshSession({
            ...commonRequest,
            size: buildShellRequest().size,
          }, callbacks);
          return { ...active, protocol: "mosh" };
        } catch (reason) {
          throw new Error(savedHostSessionErrorMessage(reason, t));
        } finally {
          passwordToStage = undefined;
          proxyPasswordToStage = undefined;
          keyPassphraseToStage = undefined;
        }
      },
      );
    }

    if (protocol === "serial" || protocol === "et") {
      return failure ? t("terminal.runtime.connectionFailed") : null;
    }

    if (
      protocol === "ssh"
      &&
      oneTimeProxyPassword === undefined
      && failure
      && isSavedProxyCredentialNotFound(failure)
    ) {
      setGroupConfigRefreshKey((current) => current + 1);
      const refreshed = await refreshSavedHosts(false, true);
      const latest = refreshed?.find((candidate) => candidate.id === host.id) ?? host;
      setProxyProfileRefreshKey((current) => current + 1);
      setError(null);
      setSavedHostPasswordPrompt(null);
      setSavedHostKeyPassphrasePrompt(null);
      setSavedHostProxyPasswordPrompt({
        host: latest,
        ...(sshWorkspaceSessionId ? { workspaceSessionId: sshWorkspaceSessionId } : {}),
        proxyPassword: "",
        sshPassword: "",
        selectedIdentityFilePaths,
        keyPassphrase: "",
        error: t("connectionPrompt.error.proxyPasswordRequired"),
      });
      return t("connectionPrompt.error.proxyPasswordRequired");
    }
    if (
      protocol === "ssh"
      &&
      oneTimeProxyPassword !== undefined
      && failure
      && isSavedCredentialNotFound(failure)
      && !isSavedProxyCredentialNotFound(failure)
    ) {
      setGroupConfigRefreshKey((current) => current + 1);
      const refreshed = await refreshSavedHosts(false, true);
      const latest = refreshed?.find((candidate) => candidate.id === host.id) ?? host;
      setError(null);
      setSavedHostPasswordPrompt(null);
      setSavedHostKeyPassphrasePrompt(null);
      setSavedHostProxyPasswordPrompt({
        host: latest,
        ...(sshWorkspaceSessionId ? { workspaceSessionId: sshWorkspaceSessionId } : {}),
        proxyPassword: "",
        sshPassword: "",
        selectedIdentityFilePaths,
        keyPassphrase: "",
        error: t("connectionPrompt.error.sshAndProxyPasswordsRequired"),
      });
      return t("connectionPrompt.error.sshAndProxyPasswordsRequired");
    }
    if (
      (protocol === "telnet" || !isSavedKeyHost(host))
      && oneTimePassword === undefined
      && failure
      && isSavedCredentialNotFound(failure)
      && !isSavedProxyCredentialNotFound(failure)
    ) {
      setGroupConfigRefreshKey((current) => current + 1);
      const refreshed = await refreshSavedHosts(false, true);
      const latest = refreshed?.find((candidate) => candidate.id === host.id) ?? {
        ...host,
        hasSavedCredential: false,
      };
      setError(null);
      setSavedHostProxyPasswordPrompt(null);
      setSavedHostKeyPassphrasePrompt(null);
      setSavedHostPasswordPrompt({
        host: latest,
        ...(protocol === "ssh" && sshWorkspaceSessionId
          ? { workspaceSessionId: sshWorkspaceSessionId }
          : {}),
        password: "",
        error: t("connectionPrompt.error.savedCredentialMissing"),
      });
      return t("connectionPrompt.error.savedCredentialMissing");
    }
    return failure ? t("terminal.runtime.connectionFailed") : null;
  }, [activateSession, bindSftpWorkspace, buildShellRequest, refreshSavedHosts, sshTerminals, t]);

  const splitActiveTerminalPane = useCallback(async (
    direction: TerminalPaneSplitDirection,
  ): Promise<void> => {
    const source = activeSharedSession;
    if (!source) return;
    if (terminalPaneLayout !== null && !terminalPaneWorkspaceVisible) {
      setError(t("terminal.pane.workspaceExists"));
      return;
    }
    const paneCount = terminalPaneWorkspaceVisible && terminalPaneLayout
      ? collectTerminalPaneSessionIds(terminalPaneLayout.root).length
      : 1;
    if (paneCount >= MAX_TERMINAL_PANES) {
      setError(t("terminal.pane.limit", { count: MAX_TERMINAL_PANES }));
      return;
    }
    if (source.state !== "connected") {
      setError(t("terminal.pane.connectionRequired"));
      return;
    }
    setError(null);

    if (source.protocol === "local") {
      const target = localTerminals.targetFor(source.id);
      if (!target) {
        setError(t("terminal.pane.localExpired"));
        return;
      }
      try {
        const cloned = await localTerminals.open(target);
        if (cloned.error) {
          await localTerminals.close(cloned.id);
          setError(t("terminal.pane.cloneFailed"));
          return;
        }
        commitTerminalPaneClone(source.id, cloned.id, direction);
      } catch {
        setError(t("terminal.pane.cloneFailed"));
      }
      return;
    }

    const target = sshTerminals.targetFor(source.id);
    if (!target) {
      setError(t("terminal.pane.sshTargetExpired"));
      return;
    }
    const sourceBackendSessionId = sshTerminals.backendSessionIdFor(source.id);
    if (!sourceBackendSessionId) {
      setError(t("terminal.pane.sshSessionExpired"));
      return;
    }

    const startClone: SshTerminalStart = async (callbacks, initialSize) => (
      cloneSshSession({
        sourceSessionId: sourceBackendSessionId,
        shell: {
          terminal: "xterm-256color",
          size: initialSize,
          environment: [],
        },
      }, callbacks)
    );
    try {
      const cloned = await sshTerminals.open(target, startClone);
      if (cloned.error) {
        await sshTerminals.close(cloned.id);
        setError(t("terminal.pane.cloneFailed"));
        return;
      }
      bindSftpWorkspace(cloned.id);
      commitTerminalPaneClone(source.id, cloned.id, direction);
    } catch {
      setError(t("terminal.pane.cloneFailed"));
    }
  }, [
    activeSharedSession,
    bindSftpWorkspace,
    commitTerminalPaneClone,
    localTerminals,
    sshTerminals,
    t,
    terminalPaneLayout,
    terminalPaneWorkspaceVisible,
  ]);

  const closeActiveTerminalPane = useCallback(async (): Promise<void> => {
    const closingSession = activeSharedSession;
    if (
      !closingSession
      || !terminalPaneWorkspaceVisible
      || !terminalPaneLayout
      || !terminalPaneLayoutContains(terminalPaneLayout, closingSession.id)
    ) return;

    const remainder = removeTerminalPane(terminalPaneLayout, closingSession.id);
    const nextSessionId = remainder?.focusedSessionId ?? null;
    setTerminalPaneZoomedSessionId(null);
    setTerminalPaneResize(null);
    setTerminalPaneDropHint(null);
    if (nextSessionId) activateSharedTerminalSession(nextSessionId, true);

    try {
      const failure = closingSession.protocol === "local"
        ? await localTerminals.close(closingSession.id)
        : await closeSshWorkspace(closingSession.id);
      if (!failure) return;
      activateSharedTerminalSession(closingSession.id, true);
      setError(t("terminal.pane.closeFailed"));
    } catch {
      activateSharedTerminalSession(closingSession.id, true);
      setError(t("terminal.pane.closeFailed"));
    }
  }, [
    activateSharedTerminalSession,
    activeSharedSession,
    closeSshWorkspace,
    localTerminals,
    t,
    terminalPaneLayout,
    terminalPaneWorkspaceVisible,
  ]);

  useEffect(() => {
    const handleTerminalPaneShortcut = (event: KeyboardEvent) => {
      if (
        activeSurface !== "terminal"
        || !activeSharedSession
        || event.repeat
        || event.metaKey
      ) return;
      const target = event.target;
      const terminalHelperTextarea = target instanceof HTMLTextAreaElement
        && target.classList.contains("xterm-helper-textarea");
      const ordinaryEditable = target instanceof HTMLInputElement
        || (target instanceof HTMLTextAreaElement && !terminalHelperTextarea)
        || target instanceof HTMLSelectElement
        || (target instanceof HTMLElement && target.isContentEditable);
      if (ordinaryEditable) return;

      const consumeShortcut = (): void => {
        event.preventDefault();
        // This listener runs during capture so xterm cannot also encode and
        // send the workspace command to the exact native session.
        event.stopPropagation();
      };

      if (
        event.ctrlKey
        && event.altKey
        && !event.shiftKey
        && terminalPaneWorkspaceVisible
        && terminalPaneLayout
      ) {
        const focusDirectionByCode: Partial<Record<string, TerminalPaneFocusDirection>> = {
          ArrowUp: "up",
          ArrowDown: "down",
          ArrowLeft: "left",
          ArrowRight: "right",
        };
        const direction = focusDirectionByCode[event.code];
        if (!direction) return;
        const currentSessionId = terminalPaneLayoutContains(
          terminalPaneLayout,
          activeSharedSession.id,
        )
          ? activeSharedSession.id
          : terminalPaneLayout.focusedSessionId;
        const nextSessionId = findNextTerminalPaneFocusSessionId(
          terminalPaneLayout,
          currentSessionId,
          direction,
        );
        if (!nextSessionId) return;
        consumeShortcut();
        if (terminalPaneZoomedSessionId) {
          setTerminalPaneZoomedSessionId(nextSessionId);
          fitSharedTerminalSessionsOnNextFrame([nextSessionId]);
        }
        activateSharedTerminalSession(nextSessionId, true);
        return;
      }

      if (!event.ctrlKey || !event.shiftKey || event.altKey) return;
      if (event.code === "KeyD") {
        consumeShortcut();
        void splitActiveTerminalPane("horizontal");
      } else if (event.code === "KeyE") {
        consumeShortcut();
        void splitActiveTerminalPane("vertical");
      } else if (event.code === "KeyW" && terminalPaneWorkspaceVisible) {
        consumeShortcut();
        if (terminalPaneZoomedSessionId === activeSharedSession.id) {
          setTerminalPaneZoomedSessionId(null);
        }
        void closeActiveTerminalPane();
      } else if (
        event.key === "Enter"
        && terminalPaneWorkspaceVisible
        && terminalPaneLayout
        && terminalPaneLayoutContains(terminalPaneLayout, activeSharedSession.id)
      ) {
        consumeShortcut();
        const nextZoomedSessionId = terminalPaneZoomedSessionId === activeSharedSession.id
          ? null
          : activeSharedSession.id;
        setTerminalPaneZoomedSessionId(nextZoomedSessionId);
        setTerminalPaneResize(null);
        fitSharedTerminalSessionsOnNextFrame(
          nextZoomedSessionId
            ? [nextZoomedSessionId]
            : collectTerminalPaneSessionIds(terminalPaneLayout.root),
        );
      }
    };
    window.addEventListener("keydown", handleTerminalPaneShortcut, true);
    return () => window.removeEventListener("keydown", handleTerminalPaneShortcut, true);
  }, [
    activateSharedTerminalSession,
    activeSharedSession,
    activeSurface,
    closeActiveTerminalPane,
    fitSharedTerminalSessionsOnNextFrame,
    splitActiveTerminalPane,
    terminalPaneLayout,
    terminalPaneWorkspaceVisible,
    terminalPaneZoomedSessionId,
  ]);

  const showTerminalPaneWorkspace = useCallback(() => {
    if (!terminalPaneLayout || terminalPaneSessionIds.length < 2) return;
    activateSharedTerminalSession(terminalPaneLayout.focusedSessionId, true);
    fitSharedTerminalSessionsOnNextFrame(
      terminalPaneZoomedSessionId
        && terminalPaneLayoutContains(terminalPaneLayout, terminalPaneZoomedSessionId)
        ? [terminalPaneZoomedSessionId]
        : terminalPaneSessionIds,
    );
  }, [
    activateSharedTerminalSession,
    fitSharedTerminalSessionsOnNextFrame,
    terminalPaneLayout,
    terminalPaneSessionIds,
    terminalPaneZoomedSessionId,
  ]);

  const dissolveTerminalPaneWorkspace = useCallback(() => {
    const focusedSessionId = terminalPaneLayout?.focusedSessionId;
    setTerminalPaneLayout(null);
    setTerminalPaneWorkspaceVisible(false);
    setTerminalPaneZoomedSessionId(null);
    setTerminalPaneResize(null);
    setTerminalPaneDropHint(null);
    if (focusedSessionId) fitSharedTerminalSessionsOnNextFrame([focusedSessionId]);
  }, [fitSharedTerminalSessionsOnNextFrame, terminalPaneLayout]);

  const detachFocusedTerminalPane = useCallback(() => {
    if (
      !terminalPaneWorkspaceVisible
      || !terminalPaneLayout
      || !activeSharedSession
      || !terminalPaneLayoutContains(terminalPaneLayout, activeSharedSession.id)
    ) return;
    const detachedSessionId = activeSharedSession.id;
    const remainder = removeTerminalPane(terminalPaneLayout, detachedSessionId);
    setTerminalPaneLayout(
      remainder && !shouldDissolveTerminalPaneLayout(remainder) ? remainder : null,
    );
    // Detach follows the legacy tab behavior: the detached runtime becomes a
    // standalone active tab, while a workspace with 2+ remaining panes stays
    // available in its original chrome slot.
    setTerminalPaneWorkspaceVisible(false);
    setTerminalPaneZoomedSessionId(null);
    setTerminalPaneResize(null);
    setTerminalPaneDropHint(null);
    fitSharedTerminalSessionsOnNextFrame([detachedSessionId]);
  }, [
    activeSharedSession,
    fitSharedTerminalSessionsOnNextFrame,
    terminalPaneLayout,
    terminalPaneWorkspaceVisible,
  ]);

  const resolveDraggedTerminalPaneHint = useCallback((
    clientX: number,
    clientY: number,
  ): TerminalPaneDropHint | null => {
    if (
      !draggedTerminalSessionId
      || terminalPaneZoomedSessionId
      || !activeSharedSession
      || activeSharedSession.state === "closing"
      || !terminalSessionCatalog.snapshot.sessions[draggedTerminalSessionId]
      || (terminalPaneLayout !== null && !terminalPaneWorkspaceVisible)
    ) return null;
    const base = terminalPaneLayout ?? createTerminalPaneLayout(activeSharedSession.id);
    if (terminalPaneLayoutContains(base, draggedTerminalSessionId)) return null;
    const bounds = terminalPaneStageElement.current?.getBoundingClientRect();
    if (!bounds || bounds.width <= 0 || bounds.height <= 0) return null;
    const hint = resolveTerminalPaneDropHint(base, {
      x: (clientX - bounds.left) / bounds.width,
      y: (clientY - bounds.top) / bounds.height,
    });
    return hint?.targetSessionId === draggedTerminalSessionId ? null : hint;
  }, [
    activeSharedSession,
    draggedTerminalSessionId,
    terminalPaneLayout,
    terminalPaneWorkspaceVisible,
    terminalPaneZoomedSessionId,
    terminalSessionCatalog,
  ]);

  const commitDraggedTerminalPane = useCallback((clientX: number, clientY: number): void => {
    const draggedSessionId = draggedTerminalSessionId;
    const hint = resolveDraggedTerminalPaneHint(clientX, clientY);
    setDraggedTerminalSessionId(null);
    setTerminalPaneDropHint(null);
    if (!draggedSessionId || !hint || !activeSharedSession) return;
    const draggedSnapshot = terminalSessionCatalog.snapshot.sessions[draggedSessionId];
    if (!draggedSnapshot || draggedSnapshot.state === "closing") return;
    const base = terminalPaneLayout ?? createTerminalPaneLayout(activeSharedSession.id);
    try {
      const next = splitTerminalPaneAtPosition(
        base,
        hint.targetSessionId,
        draggedSessionId,
        hint.direction,
        hint.position,
      );
      setTerminalPaneLayout(next);
      setTerminalPaneWorkspaceVisible(true);
      setTerminalPaneZoomedSessionId(null);
      setTerminalPaneResize(null);
      fitSharedTerminalSessionsOnNextFrame([
        hint.targetSessionId,
        draggedSessionId,
      ]);
    } catch {
      // A tab may retire between drag start and drop. Exact registry/layout
      // validation makes that a harmless no-op instead of retargeting a pane.
    }
  }, [
    activeSharedSession,
    draggedTerminalSessionId,
    fitSharedTerminalSessionsOnNextFrame,
    resolveDraggedTerminalPaneHint,
    terminalPaneLayout,
    terminalSessionCatalog,
  ]);

  const resizeTerminalPaneFromKeyboard = useCallback((
    splitId: string,
    direction: TerminalPaneSplitDirection,
    splitRect: TerminalPaneRect,
    currentRatio: number,
    delta: number,
  ) => {
    const stageBounds = terminalPaneStageElement.current?.getBoundingClientRect();
    if (!stageBounds || !terminalPaneLayout) return;
    const splitSizePixels = direction === "vertical"
      ? stageBounds.width * splitRect.width
      : stageBounds.height * splitRect.height;
    if (splitSizePixels <= 0) return;
    const ratio = clampTerminalPaneRatio(currentRatio + delta, splitSizePixels);
    const resized = resizeTerminalPaneSplit(terminalPaneLayout, splitId, ratio);
    setTerminalPaneLayout(resized);
    fitSharedTerminalSessionsOnNextFrame(
      changedTerminalPaneSessionIds(terminalPaneLayout, resized),
    );
  }, [fitSharedTerminalSessionsOnNextFrame, terminalPaneLayout]);

  const retrySshConnection = async () => {
    const active = sshTerminals.activeSession;
    if (!active || active.state !== "disconnected") return;
    const target = sshTerminals.targetFor(active.id);
    if (!target) return;
    if (target.kind === "quick") {
      setQuickProtocol("ssh");
      setHostname(target.hostname);
      setPort(String(target.port));
      setUsername("");
      setPassword("");
      setSidebarView("quick");
      setActiveSurface("vault");
      setError(t("terminal.retry.quickPassword"));
      return;
    }
    const host = savedHosts.find((candidate) => candidate.id === target.savedHostId);
    if (!host) {
      setError(t("terminal.retry.savedHostMissing"));
      return;
    }
    if (isSavedUnsupportedKeyHost(host)) {
      setError(t("terminal.retry.keyRelation"));
      return;
    }
    if (isSavedReferenceKeyHost(host)) {
      let selectedPath: string | string[] | null = null;
      try {
        selectedPath = await open({
          title: t("terminal.filePicker.privateKeyTitle"),
          directory: false,
          multiple: false,
        });
      } catch {
        setError(t("terminal.filePicker.privateKeyFailed"));
        return;
      }
      if (typeof selectedPath !== "string") return;
      await connectSavedHost(
        host,
        undefined,
        [selectedPath],
        undefined,
        undefined,
        active.id,
      );
      return;
    }
    if (isSavedManagedKeyHost(host)) {
      setSavedHostKeyPassphrasePrompt({
        host,
        workspaceSessionId: active.id,
        passphrase: "",
      });
      return;
    }
    if (!host.hasSavedCredential) {
      setSavedHostPasswordPrompt({
        host,
        workspaceSessionId: active.id,
        password: "",
      });
      return;
    }
    await connectSavedHost(
      host,
      undefined,
      undefined,
      undefined,
      undefined,
      active.id,
    );
  };

  const beginSavedHostConnection = useCallback(async (host: SavedHost) => {
    if (connectionOperation.current || savedHostMutation.current !== null) return;
    setSavedHostsError(null);
    setError(null);
    const usesSharedSshRuntime = isSavedSshHost(host)
      && !host.effectiveMoshEnabled
      && !isSavedEtHost(host);
    if (!usesSharedSshRuntime && terminalSessionCatalog.snapshot.order.length > 0) {
      setError(t("terminal.exclusiveProtocol"));
      return;
    }
    if (isSavedSerialHost(host)) {
      await connectSavedHost(host);
      return;
    }
    if (isSavedTelnetHost(host)) {
      if (!host.hasSavedCredential) {
        setSavedHostPasswordPrompt({ host, password: "" });
        return;
      }
      await connectSavedHost(host);
      return;
    }
    if (isSavedEtHost(host)) {
      await connectSavedHost(host);
      return;
    }
    if (isSavedUnsupportedKeyHost(host)) {
      setSavedHostsError(t("terminal.savedHost.keyRelationUnsupported"));
      return;
    }
    if (isSavedReferenceKeyHost(host)) {
      const mutationToken = ++nextSavedHostMutationToken.current;
      savedHostMutation.current = mutationToken;
      setSavedHostSubmitting(true);
      let selectedPath: string | string[] | null = null;
      try {
        selectedPath = await open({
          title: t("terminal.filePicker.privateKeyTitle"),
          directory: false,
          multiple: false,
        });
      } catch {
        if (savedHostMutation.current === mutationToken) {
          setSavedHostsError(t("terminal.filePicker.privateKeyFailed"));
        }
      } finally {
        if (savedHostMutation.current === mutationToken) {
          savedHostMutation.current = null;
          setSavedHostSubmitting(false);
        }
      }
      if (typeof selectedPath !== "string") return;
      if (connectionOperation.current || savedHostMutation.current !== null) return;
      await connectSavedHost(host, undefined, [selectedPath]);
      return;
    }
    if (isSavedManagedKeyHost(host)) {
      setSavedHostKeyPassphrasePrompt({ host, passphrase: "" });
      return;
    }
    if (!host.hasSavedCredential) {
      setSavedHostPasswordPrompt({ host, password: "" });
      return;
    }
    await connectSavedHost(host);
  }, [connectSavedHost, t, terminalSessionCatalog]);

  const settleSessionRestore = () => {
    sessionRestoreStoreRef.current?.clear();
    setSessionRestoreSnapshot(null);
    setSessionRestoreError(null);
    setSessionRestoreConnectingId(null);
    setSessionRestoreRestoring(false);
    setSessionRestoreSettled(true);
  };

  const restoreSelectedSessionPresentations = async (
    workspaceSessionIds: readonly WorkspaceSessionId[],
  ) => {
    const snapshot = sessionRestoreSnapshot;
    if (
      !snapshot
      || sessionRestoreRestoring
      || sessionRestoreConnectingId !== null
      || workspaceSessionIds.length === 0
    ) return;

    setSessionRestoreRestoring(true);
    setSessionRestoreError(null);
    const created: Array<Readonly<{ kind: "ssh" | "local"; id: WorkspaceSessionId }>> = [];
    let safeFailure = t("restore.restoreSelectedFailed");
    try {
      const selectedIds = new Set(workspaceSessionIds);
      const selectedEntries = snapshot.sessions.filter((entry) => (
        selectedIds.has(entry.workspaceSessionId)
      ));
      if (
        selectedIds.size !== workspaceSessionIds.length
        || selectedEntries.length !== selectedIds.size
      ) {
        safeFailure = t("restore.selectionChanged");
        throw new Error("SESSION_RESTORE_SELECTION_INVALID");
      }
      if (
        terminalSessionCatalog.snapshot.order.length + selectedEntries.length
        > MAX_WORKSPACE_SESSIONS
      ) {
        safeFailure = t("restore.limitReached");
        throw new Error("SESSION_RESTORE_LIMIT_REACHED");
      }

      const presentations: SessionRestorePresentation[] = [];
      for (const entry of selectedEntries) {
        if (entry.protocol === "local" && entry.target.kind === "local") {
          presentations.push({
            kind: "local",
            entry,
            shellId: entry.target.shellId,
          });
          continue;
        }
        if (entry.protocol !== "ssh") {
          safeFailure = t("restore.selectionChanged");
          throw new Error("SESSION_RESTORE_PROTOCOL_UNSUPPORTED");
        }
        if (entry.target.kind === "quick") {
          presentations.push({
            kind: "ssh",
            entry,
            target: {
              kind: "quick",
              title: entry.target.label,
              hostname: entry.target.hostname,
              port: entry.target.port,
              username: "",
            },
          });
          continue;
        }
        if (entry.target.kind !== "saved") {
          safeFailure = t("restore.selectionChanged");
          throw new Error("SESSION_RESTORE_TARGET_UNSUPPORTED");
        }
        if (savedHostsLoading) {
          safeFailure = t("restore.savedHostsLoading");
          throw new Error("SESSION_RESTORE_SAVED_HOSTS_LOADING");
        }
        const savedHostId = entry.target.savedHostId;
        const host = savedHosts.find((candidate) => candidate.id === savedHostId);
        if (!host) {
          safeFailure = t("restore.savedHostMissing");
          throw new Error("SESSION_RESTORE_SAVED_HOST_MISSING");
        }
        if (!isSavedSshHost(host) || host.effectiveMoshEnabled || isSavedEtHost(host)) {
          safeFailure = t("restore.savedHostChanged");
          throw new Error("SESSION_RESTORE_SAVED_HOST_CHANGED");
        }
        presentations.push({
          kind: "ssh",
          entry,
          target: {
            kind: "saved",
            title: host.label,
            hostname: host.hostname,
            port: host.port,
            username: savedHostEffectiveUsername(host),
            savedHostId: host.id,
            appearanceOverride: {
              themeId: host.effectiveAppearance.themeId ?? undefined,
              fontFamily: host.effectiveAppearance.fontFamily ?? undefined,
              fontSize: host.effectiveAppearance.fontSize ?? undefined,
              fontWeight: host.effectiveAppearance.fontWeight ?? undefined,
            },
          },
        });
      }

      for (const presentation of presentations) {
        const id = presentation.entry.workspaceSessionId;
        if (presentation.kind === "ssh") {
          await sshTerminals.restoreDisconnected(id, presentation.target, { activate: false });
          if (presentation.target.kind === "quick") {
            restoredQuickSshSessionIds.current.add(id);
          }
          created.push({ kind: "ssh", id });
        } else {
          await localTerminals.restoreDisconnected({
            workspaceSessionId: id,
            shellId: presentation.shellId,
          }, { activate: false });
          created.push({ kind: "local", id });
        }
      }

      const restoredIds = new Set(created.map(({ id }) => id));
      const restoredPaneLayout = snapshot.paneLayout
        ? pruneTerminalPaneLayout(snapshot.paneLayout, restoredIds)
        : null;
      const restoredPaneIds = restoredPaneLayout
        ? collectTerminalPaneSessionIds(restoredPaneLayout.root)
        : [];
      const showRestoredPanes = restoredPaneLayout !== null && restoredPaneIds.length > 1;
      const preferredSessionId = showRestoredPanes
        ? restoredPaneLayout.focusedSessionId
        : snapshot.activeSessionId && restoredIds.has(snapshot.activeSessionId)
          ? snapshot.activeSessionId
          : created[0]?.id ?? null;
      if (!preferredSessionId || !activateSharedTerminalSession(preferredSessionId, false)) {
        throw new Error("SESSION_RESTORE_ACTIVATION_FAILED");
      }

      setTerminalPaneLayout(showRestoredPanes ? restoredPaneLayout : null);
      setTerminalPaneWorkspaceVisible(showRestoredPanes);
      setTerminalPaneZoomedSessionId(null);
      setTerminalPaneResize(null);
      setTerminalSidePanelOpen(false);
      settleSessionRestore();
      fitSharedTerminalSessionsOnNextFrame(
        showRestoredPanes ? restoredPaneIds : [preferredSessionId],
      );
    } catch {
      for (const restored of [...created].reverse()) {
        if (restored.kind === "ssh") {
          restoredQuickSshSessionIds.current.delete(restored.id);
          await sshTerminals.close(restored.id).catch(() => undefined);
        } else {
          await localTerminals.close(restored.id).catch(() => undefined);
        }
      }
      setSessionRestoreError(safeFailure);
    } finally {
      setSessionRestoreRestoring(false);
    }
  };

  const reconnectRestoredSession = async (entry: SessionRestoreEntry) => {
    if (sessionRestoreConnectingId !== null || sessionRestoreRestoring) return;
    setSessionRestoreConnectingId(entry.workspaceSessionId);
    setSessionRestoreError(null);

    if (entry.target.kind === "saved") {
      if (savedHostsLoading) {
        setSessionRestoreError(t("restore.savedHostsLoading"));
        setSessionRestoreConnectingId(null);
        return;
      }
      const savedHostId = entry.target.savedHostId;
      const host = savedHosts.find((candidate) => candidate.id === savedHostId);
      if (!host) {
        setSessionRestoreError(t("restore.savedHostMissing"));
        setSessionRestoreConnectingId(null);
        return;
      }
      settleSessionRestore();
      await beginSavedHostConnection(host);
      return;
    }

    if (entry.target.kind === "quick") {
      if (entry.protocol !== "ssh" && entry.protocol !== "mosh" && entry.protocol !== "telnet") {
        setSessionRestoreError(t("restore.quickUnsupported"));
        setSessionRestoreConnectingId(null);
        return;
      }
      setQuickProtocol(entry.protocol);
      setHostname(entry.target.hostname);
      setPort(String(entry.target.port));
      setUsername("");
      setPassword("");
      setError(t("restore.quickCredentialsRequired"));
      settleSessionRestore();
      setSidebarView("quick");
      setActiveSurface("vault");
      return;
    }

    if (entry.target.kind === "serial") {
      settleSessionRestore();
      setError(null);
      setSidebarView("quick");
      setActiveSurface("vault");
      setSerialPanel({ mode: "quick" });
      return;
    }

    settleSessionRestore();
    openLocalTerminalPanel();
  };

  const openCreateSavedHost = () => {
    if (connectionOperation.current || savedHostMutation.current !== null) return;
    setSavedHostsError(null);
    setSerialPanel(null);
    setSavedHostEditor({
      mode: "create",
      label: "",
      group: "",
      tags: "",
      hostname: "",
      port: "22",
      username: "",
      protocol: "ssh",
      transportOverride: "inherit",
      etPort: "",
      authMethod: "password",
      managedSshKeyId: "",
      hostChainIds: [],
      hostChainCandidateId: "",
      passwordIdentityId: "",
      password: "",
      removeCredential: false,
      proxyProfileId: "",
      inlineProxyEnabled: false,
      inlineProxyType: "http",
      inlineProxyHost: "",
      inlineProxyPort: "8080",
      inlineProxyAuthMode: "manual",
      inlineProxyUsername: "",
      inlineProxyIdentityId: "",
      inlineProxyCredentialAction: "keep",
      inlineProxyPassword: "",
      inlineProxyCommandAction: "replace",
      inlineProxyCommand: "",
      canKeepInlineProxyCommand: false,
    });
  };

  const convertKnownHostToSavedHost = async (knownHost: SavedKnownHost): Promise<string> => {
    if (!NATIVE_DESKTOP_RUNTIME_AVAILABLE) throw new Error("NATIVE_RUNTIME_UNAVAILABLE");
    if (connectionOperation.current || savedHostMutation.current !== null) {
      throw new Error("SAVED_HOST_MUTATION_BUSY");
    }
    const mutationToken = ++nextSavedHostMutationToken.current;
    savedHostMutation.current = mutationToken;
    setSavedHostSubmitting(true);
    setSavedHostsError(null);
    try {
      const created = await createSavedHost({
        draft: {
          label: knownHost.hostname,
          hostname: knownHost.hostname,
          port: knownHost.port,
          username: "",
          authMethod: "password",
        },
      });
      if (savedHostMutation.current === mutationToken) {
        setSavedHosts((current) => [
          ...current.filter((host) => host.id !== created.id),
          created,
        ]);
      }
      return created.id;
    } catch {
      if (savedHostMutation.current === mutationToken) {
        setSavedHostsError(t("knownHosts.convertFailed"));
      }
      throw new Error(t("knownHosts.convertFailed"));
    } finally {
      if (savedHostMutation.current === mutationToken) {
        savedHostMutation.current = null;
        setSavedHostSubmitting(false);
      }
    }
  };

  const openEditSavedHost = (host: SavedHost) => {
    if (connectionOperation.current || savedHostMutation.current !== null) return;
    if (isSavedSerialHost(host)) {
      openSavedSerialPanel(host);
      return;
    }
    const inlineProxy = host.proxy?.inlineProxy ?? null;
    const inlineNetworkProxy = inlineProxy?.type === "http" || inlineProxy?.type === "socks5"
      ? inlineProxy
      : null;
    setSavedHostsError(null);
    setSavedHostEditor({
      mode: "edit",
      host,
      label: host.label,
      group: host.group ?? "",
      tags: host.tags?.join(", ") ?? "",
      hostname: host.hostname,
      port: String(host.port),
      username: host.username,
      protocol: host.protocol.toLowerCase() === "telnet" ? "telnet" : "ssh",
      transportOverride: host.moshEnabled === true
        ? "mosh"
        : host.etEnabled === true
          ? "et"
          : host.moshEnabled === false && host.etEnabled === false
            ? "ssh"
            : "inherit",
      etPort: host.etPort == null ? "" : String(host.etPort),
      authMethod: host.authMethod === "key" || host.authMethod === "certificate"
        ? host.authMethod
        : "password",
      managedSshKeyId: host.managedSshKeyId ?? "",
      hostChainIds: host.hostChain?.hostIds ?? [],
      hostChainCandidateId: "",
      passwordIdentityId: savedHostPasswordIdentityBinding(host)?.id ?? "",
      password: "",
      removeCredential: false,
      proxyProfileId: host.proxy?.proxyProfileId ?? "",
      inlineProxyEnabled: inlineProxy !== null,
      inlineProxyType: inlineProxy?.type ?? "http",
      inlineProxyHost: inlineNetworkProxy?.host ?? "",
      inlineProxyPort: inlineNetworkProxy ? String(inlineNetworkProxy.port) : "8080",
      inlineProxyAuthMode: inlineNetworkProxy?.auth.mode ?? "manual",
      inlineProxyUsername: inlineNetworkProxy?.auth.mode === "manual"
        ? inlineNetworkProxy.auth.username
        : "",
      inlineProxyIdentityId: inlineNetworkProxy?.auth.mode === "identity"
        ? inlineNetworkProxy.auth.identityId
        : "",
      inlineProxyCredentialAction: "keep",
      inlineProxyPassword: "",
      inlineProxyCommandAction: inlineProxy?.type === "command" ? "keep" : "replace",
      inlineProxyCommand: "",
      canKeepInlineProxyCommand: inlineProxy?.type === "command",
    });
  };

  const closeSavedHostEditor = () => {
    if (savedHostSubmitting) return;
    setSavedHostEditor((current) => current ? {
      ...current,
      password: "",
      inlineProxyPassword: "",
      inlineProxyCommand: "",
    } : current);
    setSavedHostEditor(null);
    setSavedHostsError(null);
  };

  const inspectLegacyVaultFile = async () => {
    if (connectionOperation.current || savedHostMutation.current !== null) return;
    const mutationToken = ++nextSavedHostMutationToken.current;
    savedHostMutation.current = mutationToken;
    setSavedHostSubmitting(true);
    setSavedHostsError(null);
    setSavedHostsNotice(null);
    try {
      const selectedPath: string | string[] | null = await open({
        title: t("legacyImport.fileDialogTitle"),
        directory: false,
        multiple: false,
        filters: [{ name: t("legacyImport.fileFilter"), extensions: ["json"] }],
      });
      if (savedHostMutation.current !== mutationToken || typeof selectedPath !== "string") return;
      const inspection = await inspectLegacyVault({ path: selectedPath });
      if (savedHostMutation.current !== mutationToken) return;
      setLegacyVaultPreview({ path: selectedPath, inspection });
    } catch (reason) {
      if (savedHostMutation.current === mutationToken) {
        setSavedHostsError(legacyVaultErrorMessage(reason, "inspect", t));
      }
    } finally {
      if (savedHostMutation.current === mutationToken) {
        savedHostMutation.current = null;
        setSavedHostSubmitting(false);
      }
    }
  };

  const commitLegacyVaultPreview = async () => {
    const preview = legacyVaultPreview;
    if (
      !preview
      || preview.inspection.sourceKind === "backupSafeStorageV1RequiresRecovery"
      || !legacyVaultInspectionHasChanges(preview.inspection)
      || connectionOperation.current
      || savedHostMutation.current !== null
    ) return;
    const mutationToken = ++nextSavedHostMutationToken.current;
    savedHostMutation.current = mutationToken;
    setSavedHostSubmitting(true);
    setSavedHostsError(null);
    setLegacyVaultPreview((current) => current ? { ...current, error: undefined } : current);
    try {
      const result = await commitLegacyVaultImport({
        path: preview.path,
        sourceFingerprint: preview.inspection.sourceFingerprint,
        inventoryRevision: preview.inspection.inventoryRevision,
      });
      if (savedHostMutation.current !== mutationToken) return;
      setLegacyVaultPreview(null);
      setPasswordIdentityRefreshKey((current) => current + 1);
      setProxyProfileRefreshKey((current) => current + 1);
      setGroupConfigRefreshKey((current) => current + 1);
      setNotesSnippetsRefreshKey((current) => current + 1);
      setSavedHostsNotice(
        t("legacyImport.notice.complete", {
          hosts: result.importedCount,
          keyReferences: result.sshKeyReferencesImportedCount,
          managedKeys: result.managedSshKeysImportedCount,
          secretBundles: result.managedSecretBlobsPublishedCount,
          keyIdentities: result.identityReferencesImportedCount,
          passwordIdentities: result.passwordIdentitiesImportedCount,
          proxyProfiles: result.proxyProfilesImportedCount,
          customGroups: result.customGroupsImportedCount,
          groupConfigs: result.groupConfigsImportedCount,
          scripts: result.snippetsImportedCount,
          scriptPackages: result.snippetPackagesImportedCount,
          notes: result.notesImportedCount,
          noteGroups: result.noteGroupsImportedCount,
          remapped: result.remappedEntityCount,
          duplicates: result.duplicateCount,
          conflicts: result.conflictCount,
          storedCredentials: result.credentialsStoredCount,
          storedTelnet: result.telnetCredentialsStoredCount,
          storedIdentity: result.passwordIdentityCredentialsStoredCount,
          storedProxyProfiles: result.proxyProfileCredentialsStoredCount,
          storedInlineProxies: result.inlineProxyCredentialsStoredCount,
          reentry: result.requiresCredentialReentryCount,
          reentryTelnet: result.telnetCredentialReentryRequiredCount,
          reentryIdentity: result.passwordIdentityCredentialReentryRequiredCount,
          reentryProxy: result.proxyCredentialReentryRequiredCount,
        }),
      );
      await Promise.all([
        refreshSavedHosts(false, true),
        refreshManagedSshKeys(),
      ]);
    } catch (reason) {
      if (savedHostMutation.current === mutationToken) {
        setLegacyVaultPreview((current) => (
          current?.path === preview.path
            && current.inspection.sourceFingerprint === preview.inspection.sourceFingerprint
            ? { ...current, error: legacyVaultErrorMessage(reason, "commit", t) }
            : current
        ));
      }
    } finally {
      if (savedHostMutation.current === mutationToken) {
        savedHostMutation.current = null;
        setSavedHostSubmitting(false);
      }
    }
  };

  const submitSavedHost = async (event: FormEvent) => {
    event.preventDefault();
    const editor = savedHostEditor;
    if (!editor) return;
    if (!NATIVE_DESKTOP_RUNTIME_AVAILABLE) {
      setSavedHostsError(t("savedHost.editor.dialog.desktopOnly"));
      return;
    }
    if (savedHostMutation.current !== null || connectionOperation.current) return;
    const mutationToken = ++nextSavedHostMutationToken.current;
    savedHostMutation.current = mutationToken;
    const numericPort = Number(editor.port);
    if (!Number.isInteger(numericPort) || numericPort < 1 || numericPort > 65535) {
      if (savedHostMutation.current === mutationToken) savedHostMutation.current = null;
      setSavedHostsError(t("savedHost.validation.port"));
      return;
    }
    const numericEtPort = editor.etPort.trim() === "" ? undefined : Number(editor.etPort);
    if (
      numericEtPort !== undefined
      && (!Number.isInteger(numericEtPort) || numericEtPort < 1 || numericEtPort > 65535)
    ) {
      if (savedHostMutation.current === mutationToken) savedHostMutation.current = null;
      setSavedHostsError(t("savedHost.validation.etPort"));
      return;
    }
    if (
      editor.protocol === "ssh"
      && editor.authMethod !== "password"
      && !editor.managedSshKeyId
    ) {
      if (savedHostMutation.current === mutationToken) savedHostMutation.current = null;
      setSavedHostsError(
        editor.authMethod === "certificate"
          ? t("savedHost.validation.managedCertificate")
          : t("savedHost.validation.managedKey"),
      );
      return;
    }
    if (
      editor.protocol === "ssh"
      && editor.inlineProxyEnabled
      && editor.inlineProxyType === "command"
      && editor.inlineProxyCommandAction === "keep"
      && !editor.canKeepInlineProxyCommand
    ) {
      savedHostMutation.current = null;
      setSavedHostsError(t("savedHost.validation.inlineCommand"));
      setSavedHostEditor((current) => current ? {
        ...current,
        password: "",
        inlineProxyPassword: "",
        inlineProxyCommand: "",
      } : current);
      return;
    }
    if (
      editor.protocol === "ssh"
      && editor.inlineProxyEnabled
      && editor.inlineProxyType !== "command"
      && editor.inlineProxyAuthMode === "manual"
      && editor.inlineProxyCredentialAction === "replace"
      && !editor.inlineProxyPassword
    ) {
      savedHostMutation.current = null;
      setSavedHostsError(t("savedHost.validation.inlinePassword"));
      return;
    }
    const previewInlineConfig = editor.protocol === "ssh" && editor.inlineProxyEnabled
      ? buildSavedHostInlineProxyConfig(
        editor,
        editor.inlineProxyCredentialAction === "replace"
          ? "pending-staged-reference"
          : undefined,
      )
      : null;
    if (editor.protocol === "ssh" && editor.inlineProxyEnabled && !previewInlineConfig) {
      savedHostMutation.current = null;
      setSavedHostsError(t("savedHost.validation.inlineProxy"));
      setSavedHostEditor((current) => current ? {
        ...current,
        password: "",
        inlineProxyPassword: "",
        inlineProxyCommand: "",
      } : current);
      return;
    }
    const baseDraft: SavedHostDraft = {
      ...(editor.label.trim() ? { label: editor.label.trim() } : {}),
      hostname: editor.hostname.trim(),
      port: numericPort,
      username: editor.username.trim(),
      protocol: editor.protocol,
      ...(editor.protocol === "ssh" && editor.transportOverride === "ssh"
        ? { moshEnabled: false, etEnabled: false }
        : {}),
      ...(editor.protocol === "ssh" && editor.transportOverride === "mosh"
        ? { moshEnabled: true, etEnabled: false }
        : {}),
      ...(editor.protocol === "ssh" && editor.transportOverride === "et"
        ? { moshEnabled: false, etEnabled: true }
        : {}),
      ...(editor.protocol === "ssh" && numericEtPort !== undefined
        ? { etPort: numericEtPort }
        : {}),
      ...(editor.group.trim() ? { group: editor.group.trim() } : {}),
      ...(editor.tags.trim() ? {
        tags: Array.from(new Set(
          editor.tags
            .split(",")
            .map((tag) => tag.trim())
            .filter((tag) => tag.length > 0),
        )),
      } : {}),
      ...(editor.protocol === "ssh" && editor.hostChainIds.length > 0
        ? { hostChain: { hostIds: editor.hostChainIds } }
        : {}),
      authMethod: editor.protocol === "telnet" ? "password" : editor.authMethod,
      ...(editor.authMethod === "password" && editor.passwordIdentityId
        ? { passwordIdentityId: editor.passwordIdentityId }
        : {}),
      ...(editor.protocol === "ssh" && editor.authMethod !== "password"
        ? { managedSshKeyId: editor.managedSshKeyId }
        : {}),
    };
    setSavedHostSubmitting(true);
    setSavedHostsError(null);
    let sshSecretToStage = editor.protocol === "telnet" || editor.authMethod === "password"
      ? editor.password
      : "";
    let proxySecretToStage = editor.inlineProxyPassword;
    try {
      const stageEditorSshPassword = async (passwordToStage: string): Promise<string> => {
        setSavedHostEditor((current) => current ? { ...current, password: "" } : current);
        return editor.protocol === "telnet"
          ? stageTelnetPassword(passwordToStage)
          : stageSshPassword(passwordToStage);
      };
      const stageEditorProxyPassword = async (passwordToStage: string): Promise<string> => {
        setSavedHostEditor((current) => current ? {
          ...current,
          inlineProxyPassword: "",
          inlineProxyCommand: "",
        } : current);
        return stageSshPassword(passwordToStage);
      };
      let stagedInlineProxyCredentialReference: string | undefined;
      if (
        editor.protocol === "ssh"
        && editor.inlineProxyEnabled
        && editor.inlineProxyType !== "command"
        && editor.inlineProxyAuthMode === "manual"
        && editor.inlineProxyCredentialAction === "replace"
      ) {
        stagedInlineProxyCredentialReference = await stageEditorProxyPassword(proxySecretToStage);
        proxySecretToStage = "";
      }
      if (
        editor.protocol === "ssh"
        && editor.inlineProxyEnabled
        && editor.inlineProxyType === "command"
      ) {
        setSavedHostEditor((current) => current ? {
          ...current,
          inlineProxyCommand: "",
        } : current);
      }
      const inlineConfig = editor.protocol === "ssh" && editor.inlineProxyEnabled
        ? buildSavedHostInlineProxyConfig(editor, stagedInlineProxyCredentialReference)
        : null;
      if (editor.protocol === "ssh" && editor.inlineProxyEnabled && !inlineConfig) {
        throw new Error("SAVED_HOST_PROXY_INVALID");
      }
      const proxy = editor.protocol === "ssh"
        ? buildSavedHostProxyMutation(editor, inlineConfig)
        : undefined;
      const draft: SavedHostDraft = {
        ...baseDraft,
        ...(proxy ? { proxy } : {}),
      };
      if (editor.mode === "create") {
        let stagedCredentialReference: string | undefined;
        if (sshSecretToStage.length > 0) {
          stagedCredentialReference = await stageEditorSshPassword(sshSecretToStage);
          sshSecretToStage = "";
        }
        await createSavedHost({ draft, stagedCredentialReference });
      } else if (editor.host) {
        let credentialMutation: SavedHostCredentialMutation = { action: "keep" };
        if (
          editor.protocol === "ssh"
          && editor.authMethod !== "password"
          && hasSavedHostOwnedCredential(editor.host)
        ) {
          credentialMutation = { action: "remove" };
        } else if (editor.removeCredential) {
          credentialMutation = { action: "remove" };
        } else if (sshSecretToStage.length > 0) {
          credentialMutation = {
            action: "replace",
            stagedCredentialReference: await stageEditorSshPassword(sshSecretToStage),
          };
          sshSecretToStage = "";
        }
        await updateSavedHost({
          id: editor.host.id,
          expectedRevision: editor.host.revision,
          draft,
          credentialMutation,
        });
      }
      setSavedHostEditor(null);
      setPasswordIdentityRefreshKey((current) => current + 1);
      setProxyProfileRefreshKey((current) => current + 1);
      setGroupConfigRefreshKey((current) => current + 1);
      await Promise.all([
        refreshSavedHosts(false, true),
        refreshManagedSshKeys(),
      ]);
    } catch (reason) {
      const failure = messageOf(reason);
      setSavedHostsError(savedHostMutationErrorMessage(reason, "save", t));
      setPasswordIdentityRefreshKey((current) => current + 1);
      setProxyProfileRefreshKey((current) => current + 1);
      setGroupConfigRefreshKey((current) => current + 1);
      const [refreshed] = await Promise.all([
        refreshSavedHosts(true, true),
        refreshManagedSshKeys(true),
      ]);
      if (editor.mode === "edit" && editor.host && refreshed) {
        const latest = refreshed.find((host) => host.id === editor.host?.id);
        setSavedHostEditor((current) => {
          if (current?.mode !== "edit" || current.host?.id !== editor.host?.id) return current;
          if (!latest) return null;
          if (isSavedHostRevisionConflict(failure)) {
            return {
              ...current,
              mode: "edit",
              host: latest,
              label: latest.label,
              group: latest.group ?? "",
              tags: latest.tags?.join(", ") ?? "",
              hostname: latest.hostname,
              port: String(latest.port),
              username: latest.username,
              protocol: latest.protocol.toLowerCase() === "telnet" ? "telnet" : "ssh",
              transportOverride: latest.moshEnabled === true
                ? "mosh"
                : latest.etEnabled === true
                  ? "et"
                  : latest.moshEnabled === false && latest.etEnabled === false
                    ? "ssh"
                    : "inherit",
              etPort: latest.etPort == null ? "" : String(latest.etPort),
              authMethod: latest.authMethod === "key" || latest.authMethod === "certificate"
                ? latest.authMethod
                : "password",
              managedSshKeyId: latest.managedSshKeyId ?? "",
              hostChainIds: latest.hostChain?.hostIds ?? [],
              hostChainCandidateId: "",
              passwordIdentityId: savedHostPasswordIdentityBinding(latest)?.id ?? "",
              password: "",
              removeCredential: false,
              inlineProxyPassword: "",
              inlineProxyCommand: "",
            };
          }
          return {
            ...current,
            host: latest,
            password: "",
            inlineProxyPassword: "",
            inlineProxyCommand: "",
            removeCredential: hasSavedHostOwnedCredential(latest) && current.removeCredential,
          };
        });
      }
    } finally {
      sshSecretToStage = "";
      proxySecretToStage = "";
      if (savedHostMutation.current === mutationToken) {
        savedHostMutation.current = null;
        setSavedHostSubmitting(false);
        setSavedHostEditor((current) => current ? {
          ...current,
          password: "",
          inlineProxyPassword: "",
          inlineProxyCommand: "",
        } : current);
      }
    }
  };

  const removeSavedHost = async (host: SavedHost) => {
    if (savedHostMutation.current !== null || connectionOperation.current) return;
    const mutationToken = ++nextSavedHostMutationToken.current;
    savedHostMutation.current = mutationToken;
    const identity = savedHostPasswordIdentityBinding(host);
    const credentialNote = t(hasSavedHostOwnedCredential(host)
      ? "savedHost.delete.ownedCredential"
      : "savedHost.delete.noOwnedCredential");
    const confirmation = identity
      ? t("savedHost.delete.confirmWithIdentity", {
        host: host.label,
        credentialNote,
        identity: identity.label,
      })
      : t("savedHost.delete.confirm", { host: host.label, credentialNote });
    if (!await requestWorkspaceConfirmation({
      title: t("savedHost.delete.title"),
      message: confirmation,
      confirmLabel: t("workspace.delete"),
      cancelLabel: t("workspace.dialog.cancel"),
      danger: true,
    })) {
      if (savedHostMutation.current === mutationToken) savedHostMutation.current = null;
      return;
    }
    setSavedHostSubmitting(true);
    setSavedHostsError(null);
    try {
      await deleteSavedHost({ id: host.id, expectedRevision: host.revision });
      setPasswordIdentityRefreshKey((current) => current + 1);
      setGroupConfigRefreshKey((current) => current + 1);
      await Promise.all([
        refreshSavedHosts(false, true),
        refreshManagedSshKeys(),
      ]);
    } catch (reason) {
      setSavedHostsError(savedHostMutationErrorMessage(reason, "delete", t));
      setPasswordIdentityRefreshKey((current) => current + 1);
      setGroupConfigRefreshKey((current) => current + 1);
      await Promise.all([
        refreshSavedHosts(true, true),
        refreshManagedSshKeys(true),
      ]);
    } finally {
      if (savedHostMutation.current === mutationToken) {
        savedHostMutation.current = null;
        setSavedHostSubmitting(false);
      }
    }
  };

  const clearManagedSshKeyInputs = () => {
    for (const input of [
      managedPrivateKeyInput.current,
      managedPublicKeyInput.current,
      managedCertificateInput.current,
      managedPassphraseInput.current,
    ]) {
      if (input) input.value = "";
    }
  };

  const openCreateManagedSshKey = () => {
    if (
      connectionOperation.current
      || savedHostMutation.current !== null
      || !managedSshKeyCatalog
    ) return;
    clearManagedSshKeyInputs();
    setManagedSshKeysError(null);
    setManagedSshKeysNotice(null);
    setManagedSshKeyEditor({
      mode: "create",
      expectedInventoryRevision: managedSshKeyCatalog.inventoryRevision,
      label: "",
      category: "key",
      replaceSecret: true,
      passphrasePresent: false,
      savePassphrase: false,
    });
  };

  const openEditManagedSshKey = (key: ManagedSshKey) => {
    if (
      connectionOperation.current
      || savedHostMutation.current !== null
      || !managedSshKeyCatalog
    ) return;
    clearManagedSshKeyInputs();
    setManagedSshKeysError(null);
    setManagedSshKeysNotice(null);
    setManagedSshKeyEditor({
      mode: "edit",
      key,
      expectedInventoryRevision: managedSshKeyCatalog.inventoryRevision,
      label: key.label,
      category: key.category,
      replaceSecret: false,
      passphrasePresent: false,
      savePassphrase: false,
    });
  };

  const submitManagedSshKey = async (event: FormEvent) => {
    event.preventDefault();
    const editor = managedSshKeyEditor;
    const catalog = managedSshKeyCatalog;
    if (
      !editor
      || !catalog
      || connectionOperation.current
      || savedHostMutation.current !== null
    ) return;

    const label = editor.label.trim();
    if (!label) {
      setManagedSshKeysError(t("managedKey.validation.label"));
      return;
    }

    const replaceSecret = editor.mode === "create" || editor.replaceSecret;
    const privateKeyFile = replaceSecret
      ? managedPrivateKeyInput.current?.files?.item(0)
      : undefined;
    const publicKeyFile = replaceSecret
      ? managedPublicKeyInput.current?.files?.item(0)
      : undefined;
    const certificateFile = replaceSecret
      ? managedCertificateInput.current?.files?.item(0)
      : undefined;
    if (replaceSecret) {
      if (!privateKeyFile) {
        setManagedSshKeysError(t("managedKey.validation.privateKey"));
        return;
      }
      if (editor.category === "certificate" && !certificateFile) {
        setManagedSshKeysError(t("managedKey.validation.certificate"));
        return;
      }
      if (editor.category === "key" && certificateFile) {
        setManagedSshKeysError(t("managedKey.validation.unexpectedCertificate"));
        return;
      }
    }

    const mutationToken = ++nextSavedHostMutationToken.current;
    savedHostMutation.current = mutationToken;
    setSavedHostSubmitting(true);
    setManagedSshKeysError(null);
    setManagedSshKeysNotice(null);
    let stagedBundleReference: string | undefined;
    let stagingCompleted = !replaceSecret;
    try {
      let privateKey: Uint8Array | undefined;
      let publicKey: Uint8Array | undefined;
      let certificate: Uint8Array | undefined;
      let passphrase: Uint8Array | undefined;
      try {
        if (replaceSecret) {
          privateKey = await readBoundedManagedSshKeyFile(
            privateKeyFile!,
            MANAGED_SSH_KEY_PRIVATE_KEY_MAX_BYTES,
          );
          if (publicKeyFile) {
            publicKey = await readBoundedManagedSshKeyFile(
              publicKeyFile,
              MANAGED_SSH_KEY_PUBLIC_KEY_MAX_BYTES,
            );
          }
          if (certificateFile) {
            certificate = await readBoundedManagedSshKeyFile(
              certificateFile,
              MANAGED_SSH_KEY_CERTIFICATE_MAX_BYTES,
            );
          }
          const passphraseText = managedPassphraseInput.current?.value ?? "";
          if (managedPassphraseInput.current) managedPassphraseInput.current.value = "";
          if (passphraseText.length > MANAGED_SSH_KEY_PASSPHRASE_MAX_BYTES) {
            throw new Error("MANAGED_SSH_KEY_BUNDLE_INVALID");
          }
          if (passphraseText.length > 0) {
            passphrase = new TextEncoder().encode(passphraseText);
            if (passphrase.byteLength > MANAGED_SSH_KEY_PASSPHRASE_MAX_BYTES) {
              throw new Error("MANAGED_SSH_KEY_BUNDLE_INVALID");
            }
          }
          stagedBundleReference = await stageManagedSshKeyBundle({
            privateKey,
            publicKey,
            certificate,
            passphrase,
          });
          stagingCompleted = true;
        }
      } finally {
        privateKey?.fill(0);
        publicKey?.fill(0);
        certificate?.fill(0);
        passphrase?.fill(0);
        clearManagedSshKeyInputs();
        setManagedSshKeyEditor((current) => current ? {
          ...current,
          passphrasePresent: false,
          savePassphrase: false,
        } : current);
      }

      const metadata = {
        label,
        category: editor.category,
        savePassphrase: replaceSecret ? editor.savePassphrase : editor.key?.hasSavedPassphrase ?? false,
      };
      const nextCatalog = editor.mode === "create"
        ? await createManagedSshKey({
          expectedInventoryRevision: editor.expectedInventoryRevision,
          metadata,
          stagedBundleReference: stagedBundleReference!,
        })
        : await updateManagedSshKey({
          id: editor.key!.id,
          expectedInventoryRevision: editor.expectedInventoryRevision,
          metadata,
          ...(stagedBundleReference ? { stagedBundleReference } : {}),
        });
      if (savedHostMutation.current !== mutationToken) return;
      nextManagedSshKeysRefreshToken.current += 1;
      observeManagedInventoryRevision(nextCatalog.inventoryRevision);
      setManagedSshKeyCatalog(nextCatalog);
      setManagedSshKeysLoading(false);
      setManagedSshKeyEditor(null);
      setManagedSshKeysNotice(t(editor.mode === "create"
        ? "managedKey.notice.created"
        : "managedKey.notice.updated"));
      await refreshSavedHosts();
    } catch (reason) {
      if (savedHostMutation.current === mutationToken) {
        if (!stagingCompleted) {
          setManagedSshKeysError(managedSshKeyErrorMessage(reason, "stage", t));
        } else {
          const inventoryConflict = isManagedSshKeyInventoryConflict(messageOf(reason));
          setManagedSshKeysError(managedSshKeyErrorMessage(
            reason,
            editor.mode === "create" ? "create" : "update",
            t,
          ));
          const refreshed = await refreshManagedSshKeys(true);
          if (inventoryConflict || (
            editor.mode === "edit"
            && editor.key
            && refreshed
            && !refreshed.keys.some((key) => key.id === editor.key?.id)
          )) {
            setManagedSshKeyEditor(null);
          }
        }
      }
    } finally {
      if (savedHostMutation.current === mutationToken) {
        savedHostMutation.current = null;
        setSavedHostSubmitting(false);
      }
    }
  };

  const confirmDeleteManagedSshKey = async () => {
    const prompt = managedSshKeyDelete;
    if (
      !prompt
      || connectionOperation.current
      || savedHostMutation.current !== null
    ) return;
    const mutationToken = ++nextSavedHostMutationToken.current;
    savedHostMutation.current = mutationToken;
    setSavedHostSubmitting(true);
    setManagedSshKeysError(null);
    setManagedSshKeysNotice(null);
    try {
      const nextCatalog = await deleteManagedSshKey({
        id: prompt.key.id,
        expectedInventoryRevision: prompt.expectedInventoryRevision,
      });
      if (savedHostMutation.current !== mutationToken) return;
      nextManagedSshKeysRefreshToken.current += 1;
      observeManagedInventoryRevision(nextCatalog.inventoryRevision);
      setManagedSshKeyCatalog(nextCatalog);
      setManagedSshKeysLoading(false);
      setManagedSshKeyDelete(null);
      setManagedSshKeysNotice(t("managedKey.notice.deleted"));
      await refreshSavedHosts();
    } catch (reason) {
      if (savedHostMutation.current === mutationToken) {
        const inventoryConflict = isManagedSshKeyInventoryConflict(messageOf(reason));
        setManagedSshKeysError(managedSshKeyErrorMessage(reason, "delete", t));
        const refreshed = await refreshManagedSshKeys(true);
        if (
          inventoryConflict
          || (refreshed && !refreshed.keys.some((candidate) => candidate.id === prompt.key.id))
        ) {
          setManagedSshKeyDelete(null);
        }
      }
    } finally {
      if (savedHostMutation.current === mutationToken) {
        savedHostMutation.current = null;
        setSavedHostSubmitting(false);
      }
    }
  };

  const confirmManagedMasterKeyRotation = async () => {
    if (connectionOperation.current || savedHostMutation.current !== null) return;
    const mutationToken = ++nextSavedHostMutationToken.current;
    savedHostMutation.current = mutationToken;
    setSavedHostSubmitting(true);
    setManagedSshKeysError(null);
    setManagedSshKeysNotice(null);
    try {
      const result = await rotateManagedSshMasterKey();
      if (savedHostMutation.current !== mutationToken) return;
      setManagedMasterKeyRotationOpen(false);
      if (result.status === "notInitialized") {
        setManagedSshKeysNotice(t("managedKey.notice.rotationNotInitialized"));
      } else if (result.status === "completedCleanupPending") {
        setManagedSshKeysNotice(t("managedKey.notice.rotationCleanupPending", {
          count: result.retainedSecretRevisionCount,
        }));
      } else {
        setManagedSshKeysNotice(t("managedKey.notice.rotationComplete", {
          count: result.retainedSecretRevisionCount,
        }));
      }
    } catch (reason) {
      if (savedHostMutation.current === mutationToken) {
        setManagedSshKeysError(managedSshKeyErrorMessage(reason, "rotate", t));
      }
    } finally {
      if (savedHostMutation.current === mutationToken) {
        savedHostMutation.current = null;
        setSavedHostSubmitting(false);
      }
    }
  };

  const submitSavedHostPassword = async (event: FormEvent) => {
    event.preventDefault();
    const prompt = savedHostPasswordPrompt;
    if (!prompt || !prompt.password.length) return;
    setSavedHostPasswordPrompt({ ...prompt, error: undefined });
    const failure = await connectSavedHost(
      prompt.host,
      prompt.password,
      undefined,
      undefined,
      undefined,
      prompt.workspaceSessionId,
    );
    if (failure) {
      setSavedHostPasswordPrompt((current) => current ? { ...current, error: failure } : current);
    } else {
      setSavedHostPasswordPrompt(null);
    }
  };

  const submitSavedHostProxyPassword = async (event: FormEvent) => {
    event.preventDefault();
    const prompt = savedHostProxyPasswordPrompt;
    if (!prompt || !prompt.proxyPassword.length) return;
    const needsSshPassword = !isSavedKeyHost(prompt.host)
      && !prompt.host.hasSavedCredential;
    if (needsSshPassword && !prompt.sshPassword.length) return;
    let proxyPasswordToStage: string | undefined = prompt.proxyPassword;
    let sshPasswordToStage = needsSshPassword ? prompt.sshPassword : undefined;
    let keyPassphraseToStage = prompt.keyPassphrase.length > 0
      ? prompt.keyPassphrase
      : undefined;
    setSavedHostProxyPasswordPrompt((current) => current ? {
      ...current,
      proxyPassword: "",
      sshPassword: "",
      keyPassphrase: "",
      error: undefined,
    } : current);
    let failure: string | null;
    try {
      failure = await connectSavedHost(
        prompt.host,
        sshPasswordToStage,
        prompt.selectedIdentityFilePaths,
        keyPassphraseToStage,
        proxyPasswordToStage,
        prompt.workspaceSessionId,
      );
    } finally {
      proxyPasswordToStage = undefined;
      sshPasswordToStage = undefined;
      keyPassphraseToStage = undefined;
    }
    if (failure) {
      setSavedHostProxyPasswordPrompt((current) => current ? {
        ...current,
        error: current.error ?? failure,
      } : current);
    } else {
      setSavedHostProxyPasswordPrompt(null);
    }
  };

  const submitSavedHostKeyPassphrase = async (event: FormEvent) => {
    event.preventDefault();
    const prompt = savedHostKeyPassphrasePrompt;
    if (
      !prompt
      || connectionOperation.current
      || savedHostMutation.current !== null
    ) return;
    const passphraseToStage = prompt.passphrase;
    setSavedHostKeyPassphrasePrompt((current) => (
      current?.host.id === prompt.host.id
        ? { ...current, passphrase: "", error: undefined }
        : current
    ));
    const failure = await connectSavedHost(
      prompt.host,
      undefined,
      undefined,
      passphraseToStage.length > 0 ? passphraseToStage : undefined,
      undefined,
      prompt.workspaceSessionId,
    );
    if (failure) {
      setSavedHostKeyPassphrasePrompt((current) => (
        current?.host.id === prompt.host.id
          ? { ...current, passphrase: "", error: failure }
          : current
      ));
    } else {
      setSavedHostKeyPassphrasePrompt((current) => (
        current?.host.id === prompt.host.id ? null : current
      ));
    }
  };

  const stopSavedHostPromptConnection = (workspaceSessionId?: WorkspaceSessionId) => {
    if (workspaceSessionId) {
      void disconnectSshWorkspace(workspaceSessionId).then((failure) => {
        if (failure) setError(t("terminal.runtime.disconnectFailed"));
      });
      return;
    }
    if (connectionOperation.current) void disconnect();
  };

  const cancelSavedHostPasswordPrompt = () => {
    const workspaceSessionId = savedHostPasswordPrompt?.workspaceSessionId;
    setSavedHostPasswordPrompt((current) => (
      current ? { ...current, password: "" } : current
    ));
    setSavedHostPasswordPrompt(null);
    stopSavedHostPromptConnection(workspaceSessionId);
  };

  const cancelSavedHostProxyPasswordPrompt = () => {
    const workspaceSessionId = savedHostProxyPasswordPrompt?.workspaceSessionId;
    setSavedHostProxyPasswordPrompt((current) => current ? {
      ...current,
      proxyPassword: "",
      sshPassword: "",
      keyPassphrase: "",
    } : current);
    setSavedHostProxyPasswordPrompt(null);
    stopSavedHostPromptConnection(workspaceSessionId);
  };

  const cancelSavedHostKeyPassphrasePrompt = () => {
    const workspaceSessionId = savedHostKeyPassphrasePrompt?.workspaceSessionId;
    setSavedHostKeyPassphrasePrompt((current) => (
      current ? { ...current, passphrase: "" } : current
    ));
    setSavedHostKeyPassphrasePrompt(null);
    stopSavedHostPromptConnection(workspaceSessionId);
  };

  const startSerialYmodemTransfer = async (direction: SerialYmodemDirection) => {
    const active = session.current;
    const operation = connectionOperation.current;
    if (
      !NATIVE_DESKTOP_RUNTIME_AVAILABLE
      || !active
      || active.protocol !== "serial"
      || !operation
      || !operation.connected
      || operation.cancelRequested
    ) {
      setError(t("transfer.ymodem.connectionRequired"));
      return;
    }
    if (serialYmodemTransferOwner.current) return;

    const owner: SerialYmodemTransferOwner = {
      token: ++nextSerialYmodemTransferToken.current,
      sessionId: active.sessionId,
      transferId: null,
      direction,
      transferStarted: false,
      cancelRequested: false,
    };
    serialYmodemTransferOwner.current = owner;
    setSerialYmodemTransfer({
      token: owner.token,
      sessionId: owner.sessionId,
      transferId: null,
      direction,
      phase: "selecting",
      progress: null,
    });
    setError(null);
    terminal.current?.writeln(
      direction === "send"
        ? `\r\n\x1b[90m${t("transfer.ymodem.selectSend")}\x1b[0m`
        : `\r\n\x1b[90m${t("transfer.ymodem.selectReceive")}\x1b[0m`,
    );

    const onProgress = (progress: SerialYmodemProgressEvent) => {
      if (
        serialYmodemTransferOwner.current !== owner
        || session.current?.sessionId !== owner.sessionId
        || connectionOperation.current !== operation
        || progress.direction !== owner.direction
        || (owner.transferId !== null && owner.transferId !== progress.transferId)
      ) return;
      owner.transferId = progress.transferId;
      owner.transferStarted = true;
      setSerialYmodemTransfer((current) => (
        current?.token === owner.token
          ? {
            ...current,
            transferId: owner.transferId,
            phase: owner.cancelRequested ? "canceling" : "transferring",
            progress,
          }
          : current
      ));
    };

    try {
      const response = direction === "send"
        ? await sendSerialYmodem(owner.sessionId, rendererLocale, onProgress)
        : await receiveSerialYmodem(owner.sessionId, rendererLocale, onProgress);
      if (
        serialYmodemTransferOwner.current !== owner
        || session.current?.sessionId !== owner.sessionId
        || connectionOperation.current !== operation
      ) return;
      if (response.canceled) {
        terminal.current?.writeln(`\r\n\x1b[90m${t("transfer.ymodem.selectionCanceled")}\x1b[0m`);
      } else if (direction === "send" && "fileName" in response) {
        terminal.current?.writeln(
          `\r\n\x1b[32m${t("transfer.ymodem.sent", {
            file: response.fileName ?? t("transfer.ymodem.defaultFile"),
            size: formatBytes(response.writtenBytes),
          })}\x1b[0m`,
        );
      } else if ("fileCount" in response) {
        terminal.current?.writeln(
          `\r\n\x1b[32m${t("transfer.ymodem.received", {
            count: response.fileCount,
            size: formatBytes(response.writtenBytes),
          })}\x1b[0m`,
        );
      }
    } catch {
      if (serialYmodemTransferOwner.current !== owner) return;
      if (owner.cancelRequested) {
        terminal.current?.writeln(`\r\n\x1b[90m${t("transfer.ymodem.canceled")}\x1b[0m`);
      } else {
        const message = t("transfer.ymodem.failed");
        setError(message);
        terminal.current?.writeln(`\r\n\x1b[31m${message}\x1b[0m`);
      }
    } finally {
      if (serialYmodemTransferOwner.current === owner) {
        serialYmodemTransferOwner.current = null;
        setSerialYmodemTransfer((current) => (
          current?.token === owner.token ? null : current
        ));
      }
    }
  };

  const requestSerialYmodemCancel = async () => {
    const owner = serialYmodemTransferOwner.current;
    if (!owner || !owner.transferStarted || !owner.transferId || owner.cancelRequested) return;
    owner.cancelRequested = true;
    setSerialYmodemTransfer((current) => (
      current?.token === owner.token ? { ...current, phase: "canceling" } : current
    ));
    try {
      await cancelSerialYmodem(owner.sessionId, owner.transferId);
    } catch {
      if (serialYmodemTransferOwner.current === owner) {
        owner.cancelRequested = false;
        setSerialYmodemTransfer((current) => (
          current?.token === owner.token ? { ...current, phase: "transferring" } : current
        ));
        setError(t("transfer.ymodem.cancelFailed"));
      }
    }
  };

  const requestSerialZmodemCancel = async () => {
    const owner = serialZmodemTransferOwner.current;
    if (!owner || owner.cancelRequested) return;
    owner.cancelRequested = true;
    setSerialZmodemTransfer((current) => current?.token === owner.token
      ? { ...current, phase: "canceling" }
      : current);
    try {
      await cancelSerialZmodem(owner.sessionId, owner.transferId);
    } catch {
      if (serialZmodemTransferOwner.current === owner) {
        owner.cancelRequested = false;
        setSerialZmodemTransfer((current) => current?.token === owner.token
          ? {
            ...current,
            phase: owner.resumePhase,
          }
          : current);
        setError(t("transfer.zmodem.cancelFailed"));
      }
    }
  };

  const disconnect = async () => {
    const operation = connectionOperation.current;
    if (!operation || operation.cancelRequested) return;
    operation.cancelRequested = true;
    setConnectionState("closing");
    const active = operation.handle ?? session.current;
    if (!active) {
      terminal.current?.writeln(`\r\n\x1b[90m${t("terminal.runtime.canceling")}\x1b[0m`);
      return;
    }
    try {
      const zmodemOwner = serialZmodemTransferOwner.current;
      if (zmodemOwner?.sessionId === active.sessionId && !zmodemOwner.cancelRequested) {
        zmodemOwner.cancelRequested = true;
        try {
          await cancelSerialZmodem(active.sessionId, zmodemOwner.transferId);
        } catch {
          // Closing the serial session below remains the authoritative fallback.
        }
      }
      const transferOwner = serialYmodemTransferOwner.current;
      if (
        transferOwner?.sessionId === active.sessionId
        && transferOwner.transferId
        && !transferOwner.cancelRequested
      ) {
        transferOwner.cancelRequested = true;
        try {
          await cancelSerialYmodem(active.sessionId, transferOwner.transferId);
        } catch {
          // Closing the serial session below remains the authoritative fallback.
        }
      }
      if (operation.connected) {
        await closeTerminalSession(active);
      } else {
        await cancelTerminalSession(active);
      }
    } catch {
      try {
        if (operation.connected) {
          await cancelTerminalSession(active);
        } else {
          await closeTerminalSession(active);
        }
      } catch {
        if (connectionOperation.current === operation) {
          operation.cancelRequested = false;
          operation.handle = active;
          session.current = active;
          setConnectionState(operation.connected ? "connected" : "connecting");
          setError(t("terminal.runtime.disconnectFailed"));
        }
      }
    }
  };

  const disconnectActiveTerminal = async () => {
    const activeLocal = localTerminals.activeSession;
    if (activeLocal) {
      const failure = await localTerminals.disconnect(activeLocal.id);
      if (failure) setError(t("terminal.runtime.disconnectFailed"));
      return;
    }
    const activeSsh = sshTerminals.activeSession;
    if (activeSsh) {
      const failure = await disconnectSshWorkspace(activeSsh.id);
      if (failure) setError(t("terminal.runtime.disconnectFailed"));
      return;
    }
    await disconnect();
  };

  const refreshDependentCatalogsAfterKnownHostsMutation = useCallback(() => {
    setPasswordIdentityRefreshKey((current) => current + 1);
    setProxyProfileRefreshKey((current) => current + 1);
    setGroupConfigRefreshKey((current) => current + 1);
    void refreshManagedSshKeys();
  }, [refreshManagedSshKeys]);

  const refreshCatalogsAfterKnownHostsMutation = useCallback(() => {
    setKnownHostsRefreshKey((current) => current + 1);
    refreshDependentCatalogsAfterKnownHostsMutation();
  }, [refreshDependentCatalogsAfterKnownHostsMutation]);

  const persistHostKey = async (prompt: HostKeyPrompt): Promise<void> => {
    if (!NATIVE_DESKTOP_RUNTIME_AVAILABLE) throw new Error("NATIVE_RUNTIME_UNAVAILABLE");
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const knownHostsCatalog = await listKnownHosts();
      const knownHosts = buildKnownHostsAfterTrust(knownHostsCatalog.knownHosts, prompt);
      try {
        await replaceKnownHosts({
          expectedInventoryRevision: knownHostsCatalog.inventoryRevision,
          knownHosts,
        });
        refreshCatalogsAfterKnownHostsMutation();
        return;
      } catch (reason) {
        const inventoryChanged = messageOf(reason).toUpperCase().includes("KNOWN_HOSTS_INVENTORY_CHANGED");
        if (!inventoryChanged || attempt > 0) throw reason;
      }
    }
  };

  const answerHostKey = async (accept: boolean, remember = false) => {
    const prompt = hostKeyPrompt;
    if (!prompt || hostKeySaving) return;
    if (!remember) {
      sshPromptQueue.complete("hostKey", prompt.requestId);
    } else {
      setHostKeySaving(true);
      setError(null);
    }
    let persisted = false;
    try {
      if (remember) {
        await persistHostKey(prompt);
        persisted = true;
      }
      await respondToHostKey(prompt.requestId, accept);
      if (remember) {
        sshPromptQueue.complete("hostKey", prompt.requestId);
      }
    } catch {
      if (persisted) {
        sshPromptQueue.complete("hostKey", prompt.requestId);
      }
      setError(remember && !persisted
        ? t("workspace.hostKeySaveFailed")
        : t("hostKey.error.respondFailed"));
    } finally {
      if (remember) setHostKeySaving(false);
    }
  };

  const answerInteractive = async (event: FormEvent) => {
    event.preventDefault();
    const prompt = interactivePrompt;
    if (!prompt) return;
    sshPromptQueue.complete("interactive", prompt.requestId);
    try {
      await respondToInteractiveAuth(prompt.requestId, interactiveAnswers);
      setInteractiveAnswers([]);
    } catch {
      setError(t("interactiveAuth.error.respondFailed"));
    }
  };

  const rejectInteractive = async () => {
    const prompt = interactivePrompt;
    if (!prompt) return;
    sshPromptQueue.complete("interactive", prompt.requestId);
    setInteractiveAnswers([]);
    await cancelInteractiveAuth(prompt.requestId).catch(() => {
      setError(t("interactiveAuth.error.cancelFailed"));
    });
  };

  const legacyBusy = connectionState !== "disconnected";
  // Local and SSH own independent runtimes in one catalog. The remaining
  // legacy singleton protocols stay mutually exclusive with that catalog.
  const busy = legacyBusy;
  const savedHostPromptWorkspaceSessionId = savedHostPasswordPrompt?.workspaceSessionId
    ?? savedHostProxyPasswordPrompt?.workspaceSessionId
    ?? savedHostKeyPassphrasePrompt?.workspaceSessionId;
  const savedHostPromptSshState = savedHostPromptWorkspaceSessionId
    ? sharedTerminalRegistry.sessions[savedHostPromptWorkspaceSessionId]?.state ?? null
    : null;
  const savedHostPromptBusy = busy
    || savedHostPromptSshState === "connecting"
    || savedHostPromptSshState === "connected"
    || savedHostPromptSshState === "closing";
  const savedHostPromptConnecting = connectionState === "connecting"
    || savedHostPromptSshState === "connecting";
  const savedHostPromptClosing = connectionState === "closing"
    || savedHostPromptSshState === "closing";
  const quickConnectionBlocked = legacyBusy
    || (quickProtocol !== "ssh" && hasSharedTerminalSessions);
  const savedActionsDisabled = busy || savedHostSubmitting;
  const managedActionsDisabled = savedActionsDisabled
    || managedSshKeysLoading
    || managedSshKeyCatalog === null
    || !NATIVE_DESKTOP_RUNTIME_AVAILABLE;
  const showSavedHostsInitialLoader = shouldShowSavedHostsInitialLoader(
    savedHostsLoading,
    savedHostsHaveSnapshot,
  );
  const showSavedHostsBackgroundRefresh = shouldShowSavedHostsBackgroundRefresh(
    savedHostsLoading,
    savedHostsHaveSnapshot,
  );
  const savedProxyProfileLabel = (profileId: string): string => (
    proxyProfileCatalog?.profiles.find((profile) => profile.id === profileId)?.label
    ?? t("workspace.boundProxyProfile")
  );
  const serialPanelHost = serialPanel?.mode === "saved"
    ? savedHosts.find((host) => host.id === serialPanel.hostId) ?? null
    : null;
  const toolbarTarget = connectionTarget ?? (activeSshTarget ? {
    protocol: "ssh" as const,
    hostname: activeSshTarget.hostname,
    port: activeSshTarget.port,
    username: activeSshTarget.username,
  } : {
    protocol: quickProtocol,
    hostname: hostname || "",
    port: Number(port) || 22,
    username: username || "",
  });
  const showVaultView = (
    view: SidebarView,
  ) => {
    setSidebarView(view);
    setActiveSurface("vault");
  };
  const showTerminalSurface = () => {
    if (!connectionTarget && !activeSharedSession) {
      showVaultView("quick");
      return;
    }
    setSidebarView("saved");
    setActiveSurface("terminal");
  };
  const runWindowCommand = async (command: WindowCommand) => {
    try {
      const { getCurrentWindow } = await import("@tauri-apps/api/window");
      const appWindow = getCurrentWindow();
      if (command === "minimize") await appWindow.minimize();
      if (command === "maximize") await appWindow.toggleMaximize();
      if (command === "close") await appWindow.close();
    } catch {
      // The static frontend test server has no Tauri window; chrome controls are safe no-ops there.
    }
  };
  const parentSftpPath = sftpPath === "/"
    ? "/"
    : sftpPath.replace(/[\\/]+$/, "").replace(/[\\/][^\\/]*$/, "") || "/";
  const activeSftpOwner = activeSftpRender ? { ...activeSftpRender.owner } : null;
  const sftpBreadcrumbs = [
    { label: "/", path: "/" },
    ...sftpPath
      .split(/[\\/]+/)
      .filter(Boolean)
      .map((label, index, segments) => ({
        label,
        path: `/${segments.slice(0, index + 1).join("/")}`,
      })),
  ];
  const terminalAddress = activeLocalSession?.title ?? (activeSshTarget
    ? `${activeSshTarget.username ? `${activeSshTarget.username}@` : ""}${activeSshTarget.hostname}:${activeSshTarget.port}`
    : (
    toolbarTarget.protocol === "serial"
      ? `${toolbarTarget.hostname} · ${toolbarTarget.port} baud`
      : `${toolbarTarget.username ? `${toolbarTarget.username}@` : ""}${toolbarTarget.hostname}:${toolbarTarget.port}`
  ));
  const terminalConnectionState = activeSharedSession?.state ?? connectionState;
  const terminalConnectionStateLabel = connectionStateLabel(terminalConnectionState, t);
  const terminalProtocolLabel = activeSharedSession
    ? activeSharedSession.protocol.toUpperCase()
    : connectionTarget?.protocol.toUpperCase() ?? toolbarTarget.protocol.toUpperCase();
  const activeLocalAiGeneration = activeLocalSession
    ? localTerminals.operationGenerationFor(activeLocalSession.id)
    : undefined;
  const activeSshAiGeneration = activeSshSession
    ? sshTerminals.operationGenerationFor(activeSshSession.id)
    : undefined;
  const legacyAiOperation = connectionOperation.current;
  const legacyAiSession = session.current;
  const aiTerminalScope: AiTerminalScope | null = activeLocalSession
    && activeLocalAiGeneration !== undefined
    ? Object.freeze({
        routeId: activeLocalSession.id,
        generation: activeLocalAiGeneration,
        protocol: "local",
        label: activeLocalSession.title,
        connected: activeLocalSession.state === "connected",
        commandExecutionSupported: true,
      })
    : activeSshSession && activeSshAiGeneration !== undefined
      ? Object.freeze({
          routeId: activeSshSession.id,
          generation: activeSshAiGeneration,
          protocol: "ssh",
          label: activeSshSession.title,
          connected: activeSshSession.state === "connected",
          commandExecutionSupported: true,
        })
      : legacyAiOperation
          && legacyAiSession
          && legacyAiOperation.handle === legacyAiSession
        ? Object.freeze({
            routeId: legacyAiSession.sessionId,
            generation: legacyAiOperation.token,
            protocol: legacyAiOperation.protocol,
            label: terminalAddress,
            connected: connectionState === "connected"
              && legacyAiOperation.connected
              && !legacyAiOperation.cancelRequested
              && !legacyAiOperation.closed,
            // Serial input may be line-mode transformed or owned by an active
            // transfer, so AI can inspect it but must never bypass that policy.
            commandExecutionSupported: legacyAiOperation.protocol !== "serial",
          })
        : null;
  const readAiSelectedTerminalText = useCallback((scope: AiTerminalScope) => {
    const workspaceSessionId = scope.routeId as WorkspaceSessionId;
    if (scope.protocol === "local") {
      if (
        sharedTerminalRegistry.sessions[scope.routeId]?.protocol !== "local"
        || localTerminals.operationGenerationFor(workspaceSessionId) !== scope.generation
      ) {
        return "";
      }
      return localTerminals.readSelectedText(workspaceSessionId);
    }
    if (scope.protocol === "ssh") {
      if (
        !sshTerminals.owns(workspaceSessionId)
        || sharedTerminalRegistry.sessions[scope.routeId]?.protocol !== "ssh"
        || sshTerminals.operationGenerationFor(workspaceSessionId) !== scope.generation
      ) {
        return "";
      }
      return sshTerminals.readSelectedText(workspaceSessionId);
    }

    const operation = connectionOperation.current;
    const active = session.current;
    if (
      !operation
      || !active
      || operation.handle !== active
      || operation.token !== scope.generation
      || operation.protocol !== scope.protocol
      || active.protocol !== scope.protocol
      || active.sessionId !== scope.routeId
    ) {
      return "";
    }
    return readTerminalSelectedText(terminal.current);
  }, [
    localTerminals.operationGenerationFor,
    localTerminals.readSelectedText,
    sharedTerminalRegistry.sessions,
    sshTerminals.operationGenerationFor,
    sshTerminals.owns,
    sshTerminals.readSelectedText,
  ]);
  const readAiRecentTerminalOutput = useCallback((scope: AiTerminalScope) => {
    const workspaceSessionId = scope.routeId as WorkspaceSessionId;
    if (scope.protocol === "local") {
      if (
        sharedTerminalRegistry.sessions[scope.routeId]?.protocol !== "local"
        || localTerminals.operationGenerationFor(workspaceSessionId) !== scope.generation
      ) {
        return "";
      }
      return localTerminals.readRecentOutput(workspaceSessionId);
    }
    if (scope.protocol === "ssh") {
      if (
        !sshTerminals.owns(workspaceSessionId)
        || sharedTerminalRegistry.sessions[scope.routeId]?.protocol !== "ssh"
        || sshTerminals.operationGenerationFor(workspaceSessionId) !== scope.generation
      ) {
        return "";
      }
      return sshTerminals.readRecentOutput(workspaceSessionId);
    }

    const operation = connectionOperation.current;
    const active = session.current;
    if (
      !operation
      || !active
      || operation.handle !== active
      || operation.token !== scope.generation
      || operation.protocol !== scope.protocol
      || active.protocol !== scope.protocol
      || active.sessionId !== scope.routeId
    ) {
      return "";
    }
    return readTerminalRecentOutput(terminal.current);
  }, [
    localTerminals.operationGenerationFor,
    localTerminals.readRecentOutput,
    sharedTerminalRegistry.sessions,
    sshTerminals.operationGenerationFor,
    sshTerminals.owns,
    sshTerminals.readRecentOutput,
  ]);
  const sendAiApprovedCommand = useCallback(async (
    scope: AiTerminalScope,
    command: string,
  ): Promise<void> => {
    const data = `${command}\r`;
    const workspaceSessionId = scope.routeId as WorkspaceSessionId;
    if (scope.protocol === "local") {
      const failure = await localTerminals.sendText(
        workspaceSessionId,
        data,
        scope.generation,
      );
      if (failure) throw new Error(failure);
      return;
    }
    if (scope.protocol === "ssh") {
      const failure = await sshTerminals.sendText(
        workspaceSessionId,
        data,
        scope.generation,
      );
      if (failure) throw new Error(failure);
      return;
    }

    const operation = connectionOperation.current;
    const active = session.current;
    if (
      !operation
      || !active
      || operation.handle !== active
      || operation.token !== scope.generation
      || operation.protocol !== scope.protocol
      || active.protocol !== scope.protocol
      || active.sessionId !== scope.routeId
    ) {
      throw new Error("TERMINAL_SEND_ROUTE_STALE");
    }
    if (
      operation.closed
      || operation.cancelRequested
      || connectionState === "closing"
    ) {
      throw new Error("TERMINAL_SEND_SESSION_CLOSING");
    }
    if (!operation.connected || connectionState !== "connected") {
      throw new Error("TERMINAL_SEND_SESSION_NOT_CONNECTED");
    }
    if (operation.protocol === "serial") {
      throw new Error("TERMINAL_SEND_PROTOCOL_UNSUPPORTED");
    }

    const prepared = prepareTerminalText(data);
    if (prepared.error || !prepared.bytes) {
      throw new Error(prepared.error ?? "TERMINAL_SEND_TEXT_INVALID");
    }
    try {
      if (operation.protocol === "telnet") {
        await sendTelnetInput(active.sessionId, prepared.bytes);
      } else if (operation.protocol === "mosh") {
        await sendMoshInput(active.sessionId, prepared.bytes);
      } else if (operation.protocol === "et") {
        await sendEtInput(active.sessionId, prepared.bytes);
      } else {
        await sendSshInput(active.sessionId, prepared.bytes);
      }
    } catch {
      throw new Error("TERMINAL_SEND_FAILED");
    }
  }, [connectionState, localTerminals.sendText, sshTerminals.sendText]);
  const serialYmodemProgressPercent = serialYmodemTransfer?.progress
    && serialYmodemTransfer.progress.totalBytes > 0
    ? Math.min(
        100,
        Math.round(
          (serialYmodemTransfer.progress.transferredBytes
            / serialYmodemTransfer.progress.totalBytes) * 100,
        ),
      )
    : null;
  const serialYmodemStatusLabel = serialYmodemTransfer
    ? serialYmodemTransfer.phase === "selecting"
      ? `YMODEM · ${t("workspace.selectingFile")}`
      : serialYmodemTransfer.phase === "canceling"
        ? t("workspace.cancelingTransfer", { protocol: "YMODEM" })
        : t("workspace.transferDirection", {
          protocol: "YMODEM",
          direction: serialYmodemTransfer.direction === "send"
            ? t("workspace.transferSend")
            : t("workspace.transferReceive"),
          progress: serialYmodemProgressPercent === null ? "" : ` ${serialYmodemProgressPercent}%`,
        })
    : null;
  const serialZmodemProgressPercent = serialZmodemTransfer?.progress
    && serialZmodemTransfer.progress.totalBytes > 0
    ? Math.min(
        100,
        Math.round(
          (serialZmodemTransfer.progress.transferredBytes
            / serialZmodemTransfer.progress.totalBytes) * 100,
        ),
      )
    : null;
  const serialZmodemStatusLabel = serialZmodemTransfer
    ? serialZmodemTransfer.phase === "selecting"
      ? `ZMODEM · ${t("workspace.selectingFile")}`
      : serialZmodemTransfer.phase === "canceling"
        ? t("workspace.cancelingTransfer", { protocol: "ZMODEM" })
        : t("workspace.transferDirection", {
          protocol: "ZMODEM",
          direction: serialZmodemTransfer.direction === "send"
            ? t("workspace.transferSend")
            : t("workspace.transferReceive"),
          progress: `${serialZmodemTransfer.phase === "finalizing"
            ? t("workspace.transferFinalizing")
            : ""}${serialZmodemProgressPercent === null ? "" : ` ${serialZmodemProgressPercent}%`}`,
        })
    : null;
  const terminalSidePanelContainerWidth = getTerminalSidePanelContainerWidth();
  const activeTerminalSidePanelWidthBounds = getActiveTerminalSidePanelWidthBounds(
    terminalSidePanelContainerWidth,
  );
  const activeTerminalSidePanelAriaWidth = Math.min(
    activeTerminalSidePanelWidthBounds.max,
    Math.max(activeTerminalSidePanelWidthBounds.min, terminalSidePanelWidth),
  );
  return (
    <section
      ref={workbenchElement}
      className={`workspace workbench-shell surface-${activeSurface}`}
      data-terminal-side-panel-open={terminalSidePanelVisible}
      data-ai-panel-open={aiOpen}
      data-terminal-side-panel-resizing={terminalSidePanelResize !== null}
      data-sidebar-view={sidebarView}
      data-host-view={hostViewMode}
      data-vault-empty={savedHostsHaveSnapshot && savedHosts.length === 0 ? "true" : "false"}
      style={{
        "--terminal-side-panel-width": terminalSidePanelVisible
          ? `${terminalSidePanelWidth}px`
          : "0px",
        "--terminal-side-panel-min-width": aiOpen
          ? `${AI_SIDE_PANEL_MIN_WIDTH}px`
          : "0px",
        "--terminal-resolved-bg": activeTerminalAppearance.background,
        "--terminal-resolved-fg": activeTerminalAppearance.foreground,
      } as React.CSSProperties}
    >
      <header className="workspace-chrome">
        <div className="chrome-app-menu" aria-hidden="true"><VaultGlyph name="folder" /></div>
        <div className="surface-tabs" role="tablist" aria-label={t("workspace.surfaceTabs")}>
          <button
            type="button"
            role="tab"
            aria-selected={activeSurface === "vault"}
            className={`surface-tab${activeSurface === "vault" ? " active" : ""}`}
            onClick={() => setActiveSurface("vault")}
          >
            <VaultGlyph name="folder" />
            {t("workspace.vaults")}
          </button>
          {connectionTarget && (
            <button
              type="button"
              role="tab"
              aria-selected={activeSurface === "terminal" && !terminalPaneWorkspaceVisible}
              className={`surface-tab session-surface-tab${
                activeSurface === "terminal" && !terminalPaneWorkspaceVisible ? " active" : ""
              }`}
              title={terminalAddress}
              onClick={showTerminalSurface}
            >
              <img src="/logo-goral.svg" alt="" aria-hidden="true" />
              <span>{connectionTarget.hostname}</span>
              <i className={`connection-dot state-${connectionState}`} aria-hidden="true" />
            </button>
          )}
          {terminalWorkspaceTabs.map((tab) => {
            if (tab.type === "workspace") {
              return (
                <button
                  key="terminal-pane-workspace"
                  type="button"
                  role="tab"
                  aria-selected={activeSurface === "terminal" && terminalPaneWorkspaceVisible}
                  className={`surface-tab workspace-surface-tab${
                    activeSurface === "terminal" && terminalPaneWorkspaceVisible ? " active" : ""
                  }`}
                  data-terminal-pane-count={tab.sessionIds.length}
                  title={t("workspace.splitWorkspaceTitle", { count: tab.sessionIds.length })}
                  onClick={showTerminalPaneWorkspace}
                >
                  <VaultGlyph name="workspace" />
                  <span>{t("workspace.splitWorkspace")}</span>
                </button>
              );
            }
            const id = tab.sessionId;
            const terminalSession = sharedTerminalRegistry.sessions[id];
            if (!terminalSession) return null;
            const selected = activeSurface === "terminal"
              && !terminalPaneWorkspaceVisible
              && sharedTerminalRegistry.activeSessionId === id;
            return (
              <div
                key={id}
                className={`local-session-tab${selected ? " active" : ""}${
                  draggedTerminalSessionId === id ? " dragging" : ""
                }`}
                data-workspace-session-id={id}
                draggable={terminalSession.state !== "closing"}
                onDragStart={(event) => {
                  if (terminalSession.state === "closing") {
                    event.preventDefault();
                    return;
                  }
                  event.dataTransfer.effectAllowed = "move";
                  event.dataTransfer.setData("application/x-goral-terminal-session", id);
                  event.dataTransfer.setData("text/plain", id);
                  setDraggedTerminalSessionId(id);
                  setTerminalPaneDropHint(null);
                }}
                onDragEnd={() => {
                  setDraggedTerminalSessionId(null);
                  setTerminalPaneDropHint(null);
                }}
              >
                <button
                  type="button"
                  role="tab"
                  aria-selected={selected}
                  className={`surface-tab session-surface-tab${selected ? " active" : ""}`}
                  title={terminalSession.title}
                  onClick={() => {
                    activateSharedTerminalSession(id, false);
                  }}
                >
                  <img src="/logo-goral.svg" alt="" aria-hidden="true" />
                  <span>{terminalSession.title}</span>
                  <i className={`connection-dot state-${terminalSession.state}`} aria-hidden="true" />
                </button>
                <button
                  type="button"
                  className="local-session-tab-close"
                  disabled={terminalSession.state === "closing"}
                  aria-label={t("workspace.closeTerminal", { target: terminalSession.title })}
                  title={t("workspace.closeTerminalTab")}
                  onClick={() => {
                    if (terminalSession.protocol === "local") void localTerminals.close(id);
                    else void closeSshWorkspace(id).then((failure) => {
                      if (failure) setError(t("terminal.runtime.disconnectFailed"));
                    }).catch(() => setError(t("terminal.runtime.disconnectFailed")));
                  }}
                >
                  ×
                </button>
              </div>
            );
          })}
        </div>
        <div className="chrome-drag-region" data-tauri-drag-region="" />
        <div className="window-controls" aria-label={t("workspace.windowControls")}>
          <button type="button" aria-label={t("workspace.minimizeWindow")} title={t("workspace.minimizeWindow")} onClick={() => void runWindowCommand("minimize")}>
            <WindowControlGlyph name="minimize" />
          </button>
          <button type="button" aria-label={t("workspace.maximizeWindow")} title={t("workspace.maximizeWindow")} onClick={() => void runWindowCommand("maximize")}>
            <WindowControlGlyph name="maximize" />
          </button>
          <button className="window-close" type="button" aria-label={t("workspace.closeWindow")} title={t("workspace.closeWindow")} onClick={() => void runWindowCommand("close")}>
            <WindowControlGlyph name="close" />
          </button>
        </div>
      </header>

      <aside
        className="connection-panel connection-hub"
        aria-label={activeSurface === "terminal" ? t("workspace.savedHostTree") : t("workspace.vaultAndHosts")}
      >
        <nav className="workspace-navigation" aria-label={t("workspace.vaultNavigation")}>
          <div className="vault-brand">
            <img src="/logo-goral.svg" alt="" aria-hidden="true" />
            <BrandWordmark t={t} />
          </div>
          <div className="connection-tabs">
            <button
              type="button"
              className={sidebarView === "saved" ? "active" : ""}
              aria-current={sidebarView === "saved" ? "page" : undefined}
              aria-label={t("workspace.hosts")}
              title={t("workspace.hosts")}
              onClick={() => showVaultView("saved")}
            >
              <span className="nav-icon"><VaultGlyph name="hosts" /></span>
              <span className="nav-label">{t("workspace.hosts")}</span>
            </button>
            <button
              type="button"
              className={sidebarView === "keys" ? "active" : ""}
              aria-current={sidebarView === "keys" ? "page" : undefined}
              aria-label={t("workspace.keychain")}
              title={t("workspace.keychain")}
              onClick={() => showVaultView("keys")}
            >
              <span className="nav-icon"><VaultGlyph name="key" /></span>
              <span className="nav-label">{t("workspace.keychain")}</span>
            </button>
            <button
              type="button"
              className={sidebarView === "proxies" ? "active" : ""}
              aria-current={sidebarView === "proxies" ? "page" : undefined}
              aria-label={t("workspace.proxies")}
              title={t("workspace.proxies")}
              onClick={() => showVaultView("proxies")}
            >
              <span className="nav-icon"><VaultGlyph name="proxy" /></span>
              <span className="nav-label">{t("workspace.proxies")}</span>
              <small className="nav-count">{t("workspace.proxyCount", { count: proxyProfileCatalog?.profiles.length ?? 0 })}</small>
            </button>
            <button
              type="button"
              className={sidebarView === "port" ? "active" : ""}
              aria-current={sidebarView === "port" ? "page" : undefined}
              aria-label={t("workspace.portForwarding")}
              title={t("workspace.portForwarding")}
              onClick={() => showVaultView("port")}
            >
              <span className="nav-icon"><VaultGlyph name="port" /></span>
              <span className="nav-label">{t("workspace.portForwarding")}</span>
            </button>
            <button
              type="button"
              className={sidebarView === "scripts" ? "active" : ""}
              aria-current={sidebarView === "scripts" ? "page" : undefined}
              aria-label={t("workspace.scripts")}
              title={t("workspace.scripts")}
              onClick={() => showVaultView("scripts")}
            >
              <span className="nav-icon"><VaultGlyph name="scripts" /></span>
              <span className="nav-label">{t("workspace.scripts")}</span>
            </button>
            <button
              type="button"
              className={sidebarView === "notes" ? "active" : ""}
              aria-current={sidebarView === "notes" ? "page" : undefined}
              aria-label={t("workspace.notes")}
              title={t("workspace.notes")}
              onClick={() => showVaultView("notes")}
            >
              <span className="nav-icon"><VaultGlyph name="notes" /></span>
              <span className="nav-label">{t("workspace.notes")}</span>
            </button>
            <button
              type="button"
              className={sidebarView === "known" ? "active" : ""}
              aria-current={sidebarView === "known" ? "page" : undefined}
              aria-label={t("workspace.knownHosts")}
              title={t("workspace.knownHosts")}
              onClick={() => showVaultView("known")}
            >
              <span className="nav-icon"><VaultGlyph name="known" /></span>
              <span className="nav-label">{t("workspace.knownHosts")}</span>
            </button>
            <button
              type="button"
              className={sidebarView === "logs" ? "active" : ""}
              aria-current={sidebarView === "logs" ? "page" : undefined}
              aria-label={t("workspace.logs")}
              title={t("workspace.logs")}
              onClick={() => showVaultView("logs")}
            >
              <span className="nav-icon"><VaultGlyph name="logs" /></span>
              <span className="nav-label">{t("workspace.logs")}</span>
            </button>
          </div>
          <div className="vault-navigation-footer">
            <button
              type="button"
              disabled={!NATIVE_DESKTOP_RUNTIME_AVAILABLE}
              title={NATIVE_DESKTOP_RUNTIME_AVAILABLE ? t("workspace.settings") : t("workspace.settingsDesktopOnly")}
              onClick={() => {
                void openSettingsWindow(rendererLocale).catch(() => setError(t("workspace.error.openSettings")));
              }}
            >
              <span className="nav-icon"><VaultGlyph name="settings" /></span>
              <span>{t("workspace.settings")}</span>
            </button>
          </div>
        </nav>

        {sidebarView !== "scripts" && sidebarView !== "notes" && sidebarView !== "known" && sidebarView !== "logs"
          && !(sidebarView === "saved" && savedHostsHaveSnapshot && savedHosts.length === 0) && (
        <header className="vault-toolbar">
          {sidebarView === "saved" ? (
            <label className="vault-host-search">
              <span><VaultGlyph name="search" /></span>
              <input
                type="search"
                value={savedHostSearch}
                onChange={(event) => setSavedHostSearch(event.target.value)}
                aria-label={t("workspace.searchSavedHosts")}
                placeholder={t("workspace.searchHostsPlaceholder")}
              />
            </label>
          ) : (
            sidebarView === "keys" || sidebarView === "identities" ? (
              <div className="vault-section-switcher" aria-label={t("workspace.keychainSections")}>
                <button
                  type="button"
                  className={sidebarView === "keys" ? "active" : ""}
                  onClick={() => showVaultView("keys")}
                >
                  {t("workspace.sshKeys")}
                </button>
                <button
                  type="button"
                  className={sidebarView === "identities" ? "active" : ""}
                  onClick={() => showVaultView("identities")}
                >
                  {t("workspace.passwordIdentities")}
                </button>
              </div>
            ) : (
              <div className="vault-breadcrumb">
                <span>{t("workspace.vaults")}</span>
                <b aria-hidden="true">›</b>
                <strong>{sidebarView === "quick" ? t("workspace.quickConnect") : sidebarView === "port" ? t("workspace.portForwarding") : t("workspace.proxies")}</strong>
              </div>
            )
          )}
          <div className="vault-actions" role="toolbar" aria-label={t("workspace.vaultActions")}>
            <button
              className="vault-connect-action"
              type="button"
              onClick={() => (connectionTarget || activeSharedSession)
                ? showTerminalSurface()
                : showVaultView("quick")}
            >
              {connectionTarget || activeSharedSession ? t("workspace.openSession") : t("workspace.connect")}
            </button>
            {sidebarView === "saved" && (
              <div className="vault-view-controls" aria-label={t("workspace.hostView")}>
                <details className="vault-view-menu">
                  <summary aria-label={t("workspace.switchHostView")} title={t("workspace.switchHostView")}>
                    <VaultGlyph name={hostViewMode === "grid" ? "hosts" : hostViewMode} />
                    <VaultGlyph name="chevron" />
                  </summary>
                  <div className="vault-view-menu-popover" role="menu">
                    {(["grid", "list", "tree"] as const).map((mode) => (
                      <button
                        type="button"
                        className={hostViewMode === mode ? "active" : ""}
                        aria-pressed={hostViewMode === mode}
                        onClick={(event) => {
                          setHostViewMode(mode);
                          event.currentTarget.closest("details")?.removeAttribute("open");
                        }}
                        role="menuitem"
                        key={mode}
                      >
                        <VaultGlyph name={mode === "grid" ? "hosts" : mode} />
                        {mode === "grid"
                          ? t("workspace.viewGrid")
                          : mode === "list"
                            ? t("workspace.viewList")
                            : t("workspace.viewTree")}
                      </button>
                    ))}
                  </div>
                </details>
                <button
                  type="button"
                  aria-label={t("workspace.manageGroups")}
                  title={t("workspace.manageGroupsTitle")}
                  disabled={savedActionsDisabled}
                  onClick={() => {
                    setGroupConfigInitialPath(selectedVaultGroup);
                    setGroupConfigManagerOpen(true);
                  }}
                >
                  <VaultGlyph name="folder" />
                </button>
              </div>
            )}
            {sidebarView === "saved" && (
              <div className="vault-new-host-split">
                <button className="vault-new-host" type="button" disabled={savedActionsDisabled} onClick={openCreateSavedHost}>
                  <VaultGlyph name="plus" /> {t("workspace.newHost")}
                </button>
                <button
                  className="vault-new-host-options"
                  type="button"
                  disabled={savedActionsDisabled}
                  onClick={openCreateSerialPanel}
                  aria-label={t("workspace.createSerialHost")}
                  title={t("workspace.createSerialHost")}
                >
                  <VaultGlyph name="serial" />
                </button>
                <button
                  className="vault-new-host-options"
                  type="button"
                  disabled={savedHostsLoading || savedActionsDisabled || !NATIVE_DESKTOP_RUNTIME_AVAILABLE}
                  onClick={() => void inspectLegacyVaultFile()}
                  aria-label={t("workspace.importLegacyVault")}
                  title={t("workspace.importLegacyVaultTitle")}
                >
                  <VaultGlyph name="chevron" />
                </button>
              </div>
            )}
            <button
              className="vault-session-action"
              type="button"
              disabled={legacyBusy || savedHostSubmitting
                || sharedTerminalRegistry.order.length >= MAX_WORKSPACE_SESSIONS}
              onClick={openLocalTerminalPanel}
              title={t("workspace.openLocalTerminal")}
            >
              <VaultGlyph name="terminal" /> {t("workspace.localTerminal")}
            </button>
            <button
              className="vault-session-action"
              type="button"
              disabled={legacyBusy || hasSharedTerminalSessions || savedHostSubmitting}
              onClick={openQuickSerialPanel}
              title={t("workspace.quickSerial")}
            >
              <VaultGlyph name="serial" /> {t("workspace.serial")}
            </button>
          </div>
        </header>
        )}

        {sidebarView === "quick" ? (
          <form className="quick-connect-form" onSubmit={(event) => void connect(event)}>
            <div className="panel-title">
              <div>
                <p className="eyebrow">{t("workspace.quickConnectEyebrow")}</p>
                <h2>{t("workspace.connectionTitle", { protocol: quickProtocol.toUpperCase() })}</h2>
              </div>
              <span className={`connection-dot state-${connectionState}`} />
            </div>
            <label>
              {t("workspace.protocol")}
              <select
                value={quickProtocol}
                onChange={(event) => {
                  const nextProtocol = event.target.value as NetworkConnectionProtocol;
                  setPort((currentPort) => resolveQuickConnectProtocolPort(
                    currentPort,
                    quickProtocol,
                    nextProtocol,
                  ));
                  setQuickProtocol(nextProtocol);
                  setError(null);
                }}
                disabled={busy}
              >
                <option value="ssh">SSH</option>
                <option value="mosh">Mosh</option>
                <option value="telnet">Telnet</option>
              </select>
            </label>
            <label>
              {t("workspace.host")}
              <input
                value={hostname}
                onChange={(event) => setHostname(event.target.value)}
                placeholder="server.example.com"
                disabled={quickConnectionBlocked}
                required
              />
            </label>
            <div className="field-row">
              <label>
                {t("workspace.port")}
                <input type="number" min="1" max="65535" value={port} onChange={(event) => setPort(event.target.value)} disabled={quickConnectionBlocked} required />
              </label>
              <label>
                {t("workspace.username")}
                <input value={username} onChange={(event) => setUsername(event.target.value)} disabled={quickConnectionBlocked} required={quickProtocol !== "telnet"} />
              </label>
            </div>
            <label>
              {t("workspace.password")}
              <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} disabled={quickConnectionBlocked} autoComplete="current-password" required={quickProtocol !== "telnet"} />
            </label>
            {error && <p className="connection-error">{error}</p>}
            {legacyBusy ? (
              <button className="danger-button" type="button" onClick={() => void disconnectActiveTerminal()}>
                {connectionState === "closing" ? t("workspace.disconnecting") : t("workspace.disconnect")}
              </button>
            ) : (
              <button className="primary-button" type="submit" disabled={quickConnectionBlocked}>
                {quickConnectionBlocked ? t("workspace.closeTerminalTabsFirst") : t("workspace.connect")}
              </button>
            )}
            <p className="security-note">{t("workspace.quickCredentialSecurity")}</p>
          </form>
        ) : sidebarView === "saved" ? (
          <section className="saved-hosts-view" role="tabpanel">
            <div className="saved-hosts-toolbar" role="toolbar" aria-label={t("workspace.savedHostsToolbar")}>
              <label className="saved-host-search">
                <span className="saved-host-search-icon" aria-hidden="true">⌕</span>
                <input
                  type="search"
                  value={savedHostSearch}
                  onChange={(event) => setSavedHostSearch(event.target.value)}
                  aria-label={t("workspace.searchSavedHosts")}
                  placeholder={t("workspace.searchHosts")}
              />
              </label>
              {savedHostSearch && (
                <button
                  className="saved-host-toolbar-action saved-host-search-clear"
                  type="button"
                  aria-label={t("workspace.clearHostSearch")}
                  title={t("workspace.clearSearch")}
                  onClick={() => setSavedHostSearch("")}
                >
                  ×
                </button>
              )}
              <button
                className="saved-host-toolbar-action"
                type="button"
                disabled={savedActionsDisabled}
                onClick={openCreateSavedHost}
                aria-label={t("workspace.createHost")}
                title={t("workspace.createHost")}
              >
                +
              </button>
              <button
                className="saved-host-toolbar-action"
                type="button"
                disabled={savedActionsDisabled}
                onClick={openCreateSerialPanel}
                aria-label={t("workspace.createSerialHost")}
                title={t("workspace.createSerialHost")}
              >
                <VaultGlyph name="serial" />
              </button>
              <button
                className="saved-host-toolbar-action"
                type="button"
                disabled={savedHostsLoading || savedActionsDisabled}
                onClick={() => void inspectLegacyVaultFile()}
                aria-label={t("workspace.importLegacyVault")}
                title={t("workspace.importLegacyVaultTitle")}
              >
                ⇩
              </button>
              <button
                className="saved-host-toolbar-action"
                type="button"
                disabled={savedHostsLoading || savedActionsDisabled}
                onClick={() => void refreshSavedHosts(false, true)}
                aria-label={t("workspace.refreshHosts")}
                title={t("workspace.refreshHosts")}
              >
                ↻
              </button>
            </div>
            {(savedHostsError || error) && (
              <p className="connection-error">{savedHostsError ?? error}</p>
            )}
            {savedHostsNotice && (
              <p className="saved-host-success" role="status">{savedHostsNotice}</p>
            )}
            <div className={`saved-host-list host-layout-${hostViewMode}`} aria-live="polite">
              {savedHosts.length > 0 && (
                <nav className="vault-content-breadcrumb" aria-label={t("workspace.hostGroupPath")}>
                  <button type="button" onClick={() => setSelectedVaultGroup(null)}>{t("workspace.allHosts")}</button>
                  {selectedVaultGroup?.split("/").map((segment, index, segments) => {
                    const path = segments.slice(0, index + 1).join("/");
                    const current = index === segments.length - 1;
                    return (
                      <span key={path}>
                        <b aria-hidden="true">›</b>
                        {current ? (
                          <strong>{segment}</strong>
                        ) : (
                          <button type="button" onClick={() => setSelectedVaultGroup(path)}>
                            {segment}
                          </button>
                        )}
                      </span>
                    );
                  })}
                </nav>
              )}
              {savedHostGroupCards.length > 0 && (
                <>
                  <div className="vault-section-heading">
                    <h2>{t("workspace.groups")}</h2>
                    <span>{t("workspace.groupCount", { count: savedHostGroupCards.length })}</span>
                  </div>
                  <div className="vault-group-strip">
                    {savedHostGroupCards.map((group) => (
                      <button
                        type="button"
                        className="vault-group-card"
                        onClick={() => setSelectedVaultGroup(group.path)}
                        aria-label={t("workspace.openGroup", { group: group.label })}
                        key={group.path}
                      >
                        <span className="vault-group-icon"><VaultGlyph name="folder" /></span>
                        <span>
                          <strong>{group.label}</strong>
                          <small>{t("workspace.hostCount", {
                            count: group.count,
                            unit: group.count === 1
                              ? t("workspace.hostUnitOne")
                              : t("workspace.hostUnitMany"),
                          })}</small>
                        </span>
                      </button>
                    ))}
                  </div>
                </>
              )}
              <div className="vault-section-heading hosts-heading">
                <h2>{t("workspace.hosts")}</h2>
                <span>
                  {t("workspace.entryCount", { count: filteredSavedHosts.length })}
                  {showSavedHostsBackgroundRefresh && (
                    <small
                      className="saved-host-refresh-status"
                      role="status"
                      aria-live="polite"
                      aria-atomic="true"
                    >
                      {t("hosts.refreshingInline")}
                    </small>
                  )}
                </span>
              </div>
              {showSavedHostsInitialLoader && (
                <div className="vault-loading-state" role="status">
                  <span /><span /><span />
                  <p>{t("workspace.loadingSavedHosts")}</p>
                </div>
              )}
              {savedHostsHaveSnapshot && savedHosts.length === 0 && (
                <div className="vault-empty-state" data-onboarding="true">
                  <div className="vault-onboarding">
                    <div className="vault-onboarding-intro">
                      <span className="vault-empty-icon"><VaultGlyph name="hosts" /></span>
                      <p className="eyebrow">{t("brand.subtitle")}</p>
                      <h3>{t("workspace.noSavedHosts")}</h3>
                      <p>{t("workspace.noSavedHostsDescription")}</p>
                    </div>
                    <div className="vault-onboarding-paths" aria-label={t("workspace.vaultActions")}>
                      <button type="button" className="primary-button" data-onboarding-path="primary" onClick={openCreateSavedHost}>
                        <span><VaultGlyph name="plus" /></span>
                        <strong>{t("workspace.newHost")}</strong>
                        <small>{t("workspace.credentialsCustody")}</small>
                      </button>
                      <button type="button" className="vault-onboarding-path" onClick={() => showVaultView("quick")}>
                        <span><VaultGlyph name="terminal" /></span>
                        <strong>{t("workspace.quickConnect")}</strong>
                        <small>{t("workspace.quickCredentialSecurity")}</small>
                      </button>
                      <button type="button" className="vault-onboarding-path" onClick={openLocalTerminalPanel}>
                        <span><VaultGlyph name="terminal" /></span>
                        <strong>{t("workspace.localTerminal")}</strong>
                        <small>{t("workspace.openLocalTerminal")}</small>
                      </button>
                    </div>
                    <div className="vault-empty-actions" data-onboarding-secondary="true">
                      <button type="button" onClick={openCreateSerialPanel}>
                        <VaultGlyph name="serial" /> {t("workspace.newSerial")}
                      </button>
                      <button
                        type="button"
                        disabled={!NATIVE_DESKTOP_RUNTIME_AVAILABLE}
                        onClick={() => void inspectLegacyVaultFile()}
                        title={NATIVE_DESKTOP_RUNTIME_AVAILABLE ? t("workspace.importLegacyNetcatty") : t("workspace.importDesktopOnly")}
                      >
                        <VaultGlyph name="download" /> {t("workspace.importVault")}
                      </button>
                    </div>
                  </div>
                </div>
              )}
              {savedHostsHaveSnapshot && savedHosts.length > 0 && filteredSavedHosts.length === 0 && (
                <div className="vault-empty-state vault-search-empty" role="status">
                  <span className="vault-empty-icon"><VaultGlyph name="search" /></span>
                  <h3>{t("workspace.noMatchingHosts")}</h3>
                  <p>{t("workspace.noMatchingHostsDescription")}</p>
                  <button type="button" onClick={() => setSavedHostSearch("")}>{t("workspace.clearSearch")}</button>
                </div>
              )}
              {filteredSavedHosts.length > 0 && (
                <SavedHostGroupTree
                  hosts={filteredSavedHosts}
                  locale={rendererLocale}
                  explicitGroups={savedHostGroups}
                  groupConfigs={groupTreeOrderConfigs}
                  renderHost={(host) => (
                    <SavedHostCatalogCard
                      key={host.id}
                      locale={rendererLocale}
                      host={host}
                      disabled={savedActionsDisabled}
                      avatarSize={activeSurface === "terminal" ? "tree" : "lg"}
                      displayAddress={savedHostDisplayAddress(host)}
                      transportLabel={savedHostTransportLabel(host)}
                      proxyProfileLabel={host.proxy?.proxyProfileId
                        ? savedProxyProfileLabel(host.proxy.proxyProfileId)
                        : null}
                      active={connectionTarget?.savedHost?.id === host.id
                        || (activeSshTarget?.kind === "saved" && activeSshTarget.savedHostId === host.id)}
                      onConnect={(host) => void beginSavedHostConnection(host)}
                      onEdit={(host) => openEditSavedHost(host)}
                      onRemove={(host) => void removeSavedHost(host)}
                    />
                  )}
              />
              )}
            </div>
            {busy && (
              <button className="danger-button" type="button" onClick={() => void disconnectActiveTerminal()}>
                {connectionState === "closing" ? t("workspace.disconnecting") : t("workspace.disconnectCurrent")}
              </button>
            )}
            {savedHosts.length > 0 && (
              <p className="security-note">{t("workspace.savedCredentialSecurity")}</p>
            )}
          </section>
        ) : (
          <section
            className="saved-hosts-view managed-keys-view"
            role="tabpanel"
            hidden={sidebarView !== "keys"}
          >
            <div className="panel-title saved-hosts-heading">
              <div>
                <p className="eyebrow">{t("workspace.managedKeysEyebrow")}</p>
                <h2>{t("workspace.managedKeysTitle")}</h2>
              </div>
            </div>
            <div className="managed-keys-toolbar">
              <button
                className="primary-button"
                type="button"
                disabled={managedActionsDisabled}
                onClick={openCreateManagedSshKey}
              >
                + {t("workspace.add")}
              </button>
              <button
                type="button"
                disabled={managedSshKeysLoading || savedActionsDisabled}
                onClick={() => void refreshManagedSshKeys()}
              >
                {t("workspace.refresh")}
              </button>
              <button
                type="button"
                disabled={managedActionsDisabled}
                onClick={() => {
                  setManagedSshKeysError(null);
                  setManagedSshKeysNotice(null);
                  setManagedMasterKeyRotationOpen(true);
                }}
              >
                {t("workspace.rotateMasterKey")}
              </button>
            </div>
            {managedSshKeysError && (
              <p className="connection-error" role="alert">{managedSshKeysError}</p>
            )}
            {managedSshKeysNotice && (
              <p className="saved-host-success" role="status">{managedSshKeysNotice}</p>
            )}
            <div className="saved-host-list managed-key-list" aria-live="polite">
              {managedSshKeysLoading && <p className="saved-host-empty">{t("workspace.loadingManagedKeys")}</p>}
              {!managedSshKeysLoading && (managedSshKeyCatalog?.keys.length ?? 0) === 0 && (
                <p className="saved-host-empty">
                  {t("workspace.noManagedKeys")}
                </p>
              )}
              {managedSshKeyCatalog?.keys.map((key) => (
                <article className="saved-host-card managed-key-card" key={key.id}>
                  <div className="saved-host-summary">
                    <strong title={key.label}>{key.label}</strong>
                    <small>
                      {key.category === "certificate"
                        ? t("managedKey.editor.certificateType")
                        : t("managedKey.editor.privateKeyType")}
                      {key.source === "generated" ? ` · ${t("workspace.generated")}` : ` · ${t("workspace.imported")}`}
                    </small>
                    <span className={key.hasSavedPassphrase ? "credential-saved" : "credential-missing"}>
                      {key.hasSavedPassphrase ? t("workspace.passphraseSaved") : t("workspace.passphraseNotSaved")}
                    </span>
                  </div>
                  <div className="managed-key-actions">
                    <button
                      type="button"
                      disabled={managedActionsDisabled}
                      onClick={() => openEditManagedSshKey(key)}
                    >
                      {t("workspace.edit")}
                    </button>
                    <button
                      className="saved-host-delete"
                      type="button"
                      disabled={managedActionsDisabled}
                      onClick={() => {
                        setManagedSshKeysError(null);
                        setManagedSshKeysNotice(null);
                        if (managedSshKeyCatalog) {
                          setManagedSshKeyDelete({
                            key,
                            expectedInventoryRevision: managedSshKeyCatalog.inventoryRevision,
                          });
                        }
                      }}
                    >
                      {t("workspace.delete")}
                    </button>
                  </div>
                </article>
              ))}
            </div>
            <p className="security-note">{t("workspace.managedKeySecurity")}</p>
          </section>
        )}
        <section
          className="saved-hosts-view password-identities-view"
          role="tabpanel"
          hidden={sidebarView !== "identities"}
        >
          {NATIVE_DESKTOP_RUNTIME_AVAILABLE ? (
            <PasswordIdentityCatalog
              disabled={savedActionsDisabled}
              locale={rendererLocale}
              refreshKey={passwordIdentityRefreshKey}
              onCatalogChange={handlePasswordIdentityCatalogChange}
            />
          ) : (
            <div className="runtime-preview-placeholder">
              <span><VaultGlyph name="identity" /></span>
              <h2>{t("workspace.passwordIdentities")}</h2>
              <p>{t("workspace.passwordIdentityDesktopOnly")}</p>
            </div>
          )}
        </section>
        <section
          className="saved-hosts-view proxy-profiles-view"
          role="tabpanel"
          hidden={sidebarView !== "proxies"}
        >
          {NATIVE_DESKTOP_RUNTIME_AVAILABLE ? (
            <ProxyProfileCatalog
              disabled={savedActionsDisabled}
              identities={passwordIdentityCatalog?.identities ?? []}
              locale={rendererLocale}
              refreshKey={proxyProfileRefreshKey}
              onCatalogChange={handleProxyProfileCatalogChange}
            />
          ) : (
            <div className="runtime-preview-placeholder">
              <span><VaultGlyph name="proxy" /></span>
              <h2>{t("workspace.proxies")}</h2>
              <p>{t("workspace.proxyDesktopOnly")}</p>
            </div>
          )}
        </section>
        <section
          className="saved-hosts-view port-forwarding-view"
          role="tabpanel"
          hidden={sidebarView !== "port"}
        >
          <PortForwardingCatalog
            locale={rendererLocale}
            hosts={savedHosts}
            disabled={savedActionsDisabled}
            nativeRuntimeAvailable={NATIVE_DESKTOP_RUNTIME_AVAILABLE}
          />
        </section>
        {sidebarView === "scripts" && (
          <section className="notes-scripts-view" role="tabpanel" aria-label={t("scripts.title")}>
            <ScriptsWorkspace
              locale={rendererLocale}
              hosts={savedHosts}
              disabled={savedActionsDisabled}
              refreshKey={notesSnippetsRefreshKey}
              onOpenHost={(host) => {
                setSelectedVaultGroup(null);
                setSavedHostSearch(host.hostname);
                showVaultView("saved");
              }}
            />
          </section>
        )}
        {sidebarView === "notes" && (
          <section className="notes-scripts-view" role="tabpanel" aria-label={t("notes.title")}>
            <NotesWorkspace
              locale={rendererLocale}
              hosts={savedHosts}
              disabled={savedActionsDisabled}
              refreshKey={notesSnippetsRefreshKey}
              onOpenHost={(host) => {
                setSelectedVaultGroup(null);
                setSavedHostSearch(host.hostname);
                showVaultView("saved");
              }}
            />
          </section>
        )}
        {sidebarView === "known" && (
          <section className="known-hosts-view" role="tabpanel" aria-label={t("knownHosts.workspace")}>
            <KnownHostsWorkspace
              locale={rendererLocale}
              hosts={savedHosts}
              disabled={savedActionsDisabled}
              refreshKey={knownHostsRefreshKey}
              onCatalogChange={refreshDependentCatalogsAfterKnownHostsMutation}
              onConvertToHost={convertKnownHostToSavedHost}
            />
          </section>
        )}
        {sidebarView === "logs" && (
          <section className="connection-logs-view" role="tabpanel" aria-label={t("connectionLogs.title")}>
            <ConnectionLogsWorkspace
              locale={rendererLocale}
              disabled={savedActionsDisabled}
            />
          </section>
        )}
        <GroupConfigCatalog
          open={groupConfigManagerOpen}
          onClose={() => setGroupConfigManagerOpen(false)}
          locale={rendererLocale}
          hosts={savedHosts}
          managedKeys={managedSshKeyCatalog?.keys ?? []}
          passwordIdentities={passwordIdentityCatalog?.identities ?? []}
          proxyProfiles={proxyProfileCatalog?.profiles ?? []}
          disabled={savedActionsDisabled}
          nativeRuntimeAvailable={NATIVE_DESKTOP_RUNTIME_AVAILABLE}
          refreshKey={groupConfigRefreshKey}
          initialPath={groupConfigInitialPath}
          onCatalogChange={handleGroupConfigCatalogChange}
        />
      </aside>

      <div
        className="terminal-panel"
        data-terminal-theme={activeTerminalAppearance.themeId}
        hidden={activeSurface !== "terminal"
          || (connectionTarget === null && activeSharedSession === null)}
        style={{
          "--terminal-resolved-bg": activeTerminalAppearance.background,
          "--terminal-resolved-fg": activeTerminalAppearance.foreground,
        } as React.CSSProperties}
      >
        <div className="terminal-toolbar">
          <div
            className="terminal-session-summary"
            role="status"
            aria-label={t("workspace.terminalStatusAria", {
              address: terminalAddress,
              state: terminalConnectionStateLabel,
            })}
          >
            <span className={`connection-dot state-${terminalConnectionState}`} aria-hidden="true" />
            <strong title={terminalAddress}>{terminalAddress}</strong>
            <span className="terminal-protocol-badge">{terminalProtocolLabel}</span>
            <span className={`terminal-state-label state-${terminalConnectionState}`}>{terminalConnectionStateLabel}</span>
            {serialYmodemStatusLabel && (
              <span
                className="serial-ymodem-status"
                title={serialYmodemTransfer?.progress?.fileName ?? serialYmodemStatusLabel}
              >
                {serialYmodemStatusLabel}
              </span>
            )}
            {serialZmodemStatusLabel && (
              <span
                className="serial-ymodem-status serial-zmodem-status"
                title={serialZmodemTransfer?.progress?.fileName ?? serialZmodemStatusLabel}
              >
                {serialZmodemStatusLabel}
              </span>
            )}
          </div>
          <div className="terminal-actions">
            {connectionTarget?.protocol === "telnet" && connectionState === "disconnected" && (
              <button
                type="button"
                className="terminal-tool-button"
                aria-label={t("workspace.retryTelnet")}
                title={t("workspace.retryConnection")}
                onClick={() => void retryTelnetConnection()}
              >
                <VaultGlyph name="refresh" />
              </button>
            )}
            {connectionTarget?.protocol === "et" && connectionState === "disconnected" && (
              <button
                type="button"
                className="terminal-tool-button"
                aria-label={t("workspace.retryEt")}
                title={t("workspace.retryConnection")}
                onClick={() => void retryEtConnection()}
              >
                <VaultGlyph name="refresh" />
              </button>
            )}
            {connectionTarget?.protocol === "serial" && connectionState === "disconnected" && (
              <button
                type="button"
                className="terminal-tool-button"
                aria-label={t("workspace.retrySerial")}
                title={t("workspace.retryConnection")}
                onClick={() => void retrySerialConnection()}
              >
                <VaultGlyph name="refresh" />
              </button>
            )}
            {activeLocalSession?.state === "disconnected" && (
              <button
                type="button"
                className="terminal-tool-button"
                aria-label={t("workspace.retryLocal")}
                title={t("workspace.retryLocal")}
                onClick={() => void retryLocalTerminalConnection()}
              >
                <VaultGlyph name="refresh" />
              </button>
            )}
            {activeSshSession?.state === "disconnected" && (
              <button
                type="button"
                className="terminal-tool-button"
                aria-label={t("workspace.retrySsh")}
                title={t("workspace.retryConnection")}
                onClick={() => void retrySshConnection()}
              >
                <VaultGlyph name="refresh" />
              </button>
            )}
            {connectionTarget?.protocol === "serial"
              && connectionState === "connected"
              && !serialYmodemTransfer
              && !serialZmodemTransfer && (
                <>
                  <button
                    type="button"
                    className="terminal-tool-button"
                    aria-label={t("workspace.ymodemSend")}
                    title={t("workspace.ymodemSend")}
                    onClick={() => void startSerialYmodemTransfer("send")}
                  >
                    <VaultGlyph name="upload" />
                  </button>
                  <button
                    type="button"
                    className="terminal-tool-button"
                    aria-label={t("workspace.ymodemReceive")}
                    title={t("workspace.ymodemReceive")}
                    onClick={() => void startSerialYmodemTransfer("receive")}
                  >
                    <VaultGlyph name="download" />
                  </button>
                </>
              )}
            {connectionTarget?.protocol === "serial"
              && connectionState === "connected"
              && serialYmodemTransfer && (
                <button
                  type="button"
                  className="terminal-tool-button terminal-transfer-cancel-button"
                  disabled={serialYmodemTransfer.phase !== "transferring"}
                  aria-label={t("workspace.cancelYmodem")}
                  title={serialYmodemTransfer.phase === "selecting"
                    ? t("workspace.cancelInFilePicker")
                    : t("workspace.cancelTransferShortcut", { protocol: "YMODEM" })}
                  onClick={() => void requestSerialYmodemCancel()}
                >
                  <VaultGlyph name="close" />
                </button>
              )}
            {connectionTarget?.protocol === "serial"
              && connectionState === "connected"
              && serialZmodemTransfer && (
                <button
                  type="button"
                  className="terminal-tool-button terminal-transfer-cancel-button"
                  disabled={serialZmodemTransfer.phase === "selecting"
                    || serialZmodemTransfer.phase === "canceling"}
                  aria-label={t("workspace.cancelZmodem")}
                  title={serialZmodemTransfer.phase === "selecting"
                    ? t("workspace.cancelInFilePicker")
                    : t("workspace.cancelTransferShortcut", { protocol: "ZMODEM" })}
                  onClick={() => void requestSerialZmodemCancel()}
                >
                  <VaultGlyph name="close" />
                </button>
              )}
            {activeSharedSession && (
              <>
                <button
                  type="button"
                  className="terminal-tool-button terminal-split-button"
                  disabled={activeSharedSession.state !== "connected"
                    || (terminalPaneWorkspaceVisible
                      && terminalPaneSessionIds.length >= MAX_TERMINAL_PANES)}
                  aria-label={t("workspace.splitHorizontal")}
                  title={t("workspace.splitHorizontal")}
                  onClick={() => void splitActiveTerminalPane("horizontal")}
                >
                  <VaultGlyph name="splitHorizontal" />
                </button>
                <button
                  type="button"
                  className="terminal-tool-button terminal-split-button"
                  disabled={activeSharedSession.state !== "connected"
                    || (terminalPaneWorkspaceVisible
                      && terminalPaneSessionIds.length >= MAX_TERMINAL_PANES)}
                  aria-label={t("workspace.splitVertical")}
                  title={t("workspace.splitVertical")}
                  onClick={() => void splitActiveTerminalPane("vertical")}
                >
                  <VaultGlyph name="splitVertical" />
                </button>
                {terminalPaneWorkspaceVisible && hasTerminalPaneWorkspace && (
                  <>
                    <button
                      type="button"
                      className={`terminal-tool-button${terminalPaneZoomedSessionId ? " active" : ""}`}
                      aria-label={terminalPaneZoomedSessionId ? t("workspace.restoreAllPanes") : t("workspace.zoomCurrentPane")}
                      aria-pressed={terminalPaneZoomedSessionId !== null}
                      title={terminalPaneZoomedSessionId
                        ? t("workspace.restoreAllPanesShortcut")
                        : t("workspace.zoomCurrentPaneShortcut")}
                      onClick={() => {
                        if (!terminalPaneLayout || !activeSharedSession) return;
                        const nextZoomedSessionId = terminalPaneZoomedSessionId === activeSharedSession.id
                          ? null
                          : activeSharedSession.id;
                        setTerminalPaneZoomedSessionId(nextZoomedSessionId);
                        setTerminalPaneResize(null);
                        setTerminalPaneDropHint(null);
                        fitSharedTerminalSessionsOnNextFrame(
                          nextZoomedSessionId
                            ? [nextZoomedSessionId]
                            : collectTerminalPaneSessionIds(terminalPaneLayout.root),
                        );
                      }}
                    >
                      <VaultGlyph name="focus" />
                    </button>
                    <button
                      type="button"
                      className="terminal-tool-button"
                      disabled={activeSharedSession.state === "closing"}
                      aria-label={t("workspace.closeCurrentPane")}
                      title={t("workspace.closeCurrentPaneShortcut")}
                      onClick={() => void closeActiveTerminalPane()}
                    >
                      <VaultGlyph name="close" />
                    </button>
                    <button
                      type="button"
                      className="terminal-tool-button"
                      aria-label={t("workspace.detachCurrentPane")}
                      title={t("workspace.detachCurrentPaneTitle")}
                      onClick={detachFocusedTerminalPane}
                    >
                      <VaultGlyph name="up" />
                    </button>
                    <button
                      type="button"
                      className="terminal-tool-button active"
                      aria-label={t("workspace.dissolveSplitWorkspace")}
                      title={t("workspace.dissolveSplitWorkspaceTitle")}
                      onClick={dissolveTerminalPaneWorkspace}
                    >
                      <VaultGlyph name="workspace" />
                    </button>
                  </>
                )}
              </>
            )}
            {sftpTabVisible && (
              <button
                type="button"
                className={`terminal-tool-button terminal-context-button terminal-sftp-button${
                  terminalSidePanelOpen && terminalSidePanelTab === "sftp" ? " active" : ""
                }`}
                disabled={terminalConnectionState !== "connected"}
                aria-label={sftpOpen ? t("terminal.closeSftpPanel") : t("terminal.openSftpPanel")}
                aria-pressed={terminalSidePanelOpen && terminalSidePanelTab === "sftp"}
                title="SFTP"
                onClick={() => {
                  if (terminalSidePanelOpen && terminalSidePanelTab === "sftp") {
                    setTerminalSidePanelResize(null);
                    setTerminalSidePanelOpen(false);
                    return;
                  }
                  setTerminalSidePanelTab("sftp");
                  setTerminalSidePanelOpen(true);
                  if (sftpEntries.length === 0) void loadSftpPath(sftpPath);
                }}
              >
                <VaultGlyph name="folder" />
              </button>
            )}
            {activeSshSession ? (
              <button
                type="button"
                className={`terminal-tool-button terminal-context-button${dockerOpen ? " active" : ""}`}
                disabled={activeSurface !== "terminal"}
                aria-label={dockerOpen ? t("systemManager.closePanel") : t("systemManager.openPanel")}
                aria-pressed={dockerOpen}
                title={t("systemManager.docker.title")}
                onClick={() => {
                  if (dockerOpen) {
                    setTerminalSidePanelResize(null);
                    setTerminalSidePanelOpen(false);
                    return;
                  }
                  setTerminalSidePanelTab("docker");
                  setTerminalSidePanelOpen(true);
                }}
              >
                <VaultGlyph name="workspace" />
              </button>
            ) : null}
            <button
              type="button"
              className={`terminal-tool-button terminal-context-button terminal-ai-button${aiOpen ? " active" : ""}`}
              disabled={activeSurface !== "terminal"}
              aria-label={aiOpen ? t("ai.closePanel") : t("ai.openPanel")}
              aria-pressed={aiOpen}
              title={t("ai.title")}
              onClick={() => {
                if (aiOpen) {
                  setTerminalSidePanelResize(null);
                  setTerminalSidePanelOpen(false);
                  return;
                }
                setTerminalSidePanelTab("ai");
                setTerminalSidePanelOpen(true);
              }}
            >
              <VaultGlyph name="ai" />
            </button>
            {terminalConnectionState !== "disconnected" && (
              <button
                type="button"
                className="terminal-tool-button terminal-disconnect-button"
                disabled={terminalConnectionState === "closing"}
                aria-label={terminalConnectionState === "connecting" ? t("workspace.cancelConnection") : t("workspace.disconnectCurrent")}
                title={terminalConnectionState === "connecting" ? t("workspace.cancelConnection") : t("workspace.disconnect")}
                onClick={() => void disconnectActiveTerminal()}
              >
                <VaultGlyph name="disconnect" />
              </button>
            )}
          </div>
        </div>
        <div
          ref={terminalPaneStageElement}
          className="terminal-pane-stage"
          data-terminal-pane-workspace={terminalPaneWorkspaceVisible ? "true" : "false"}
          data-terminal-pane-zoomed-session-id={terminalPaneZoomedSessionId ?? undefined}
          onDragOver={(event) => {
            const hint = resolveDraggedTerminalPaneHint(event.clientX, event.clientY);
            if (!hint) {
              setTerminalPaneDropHint(null);
              return;
            }
            event.preventDefault();
            event.dataTransfer.dropEffect = "move";
            setTerminalPaneDropHint(hint);
          }}
          onDragLeave={(event) => {
            const relatedTarget = event.relatedTarget;
            if (relatedTarget instanceof Node && event.currentTarget.contains(relatedTarget)) return;
            setTerminalPaneDropHint(null);
          }}
          onDrop={(event) => {
            event.preventDefault();
            commitDraggedTerminalPane(event.clientX, event.clientY);
          }}
        >
          <div
            className="terminal-container legacy-terminal-viewport"
            ref={terminalElement}
            hidden={activeSharedSession !== null}
            style={{ backgroundColor: liveTerminalAppearance.background }}
          />
          <LocalTerminalSessionViewports
            registry={sharedTerminalRegistry}
            background={localTerminalAppearance.background}
            placements={terminalViewportPlacements}
            onActivate={(id) => activateSharedTerminalSession(id, true)}
            mountViewport={localTerminals.mountViewport}
            unmountViewport={localTerminals.unmountViewport}
          />
          <SshTerminalSessionViewports
            registry={sharedTerminalRegistry}
            background={activeTerminalAppearance.background}
            backgroundFor={(id) => sshTerminals.appearanceFor(id)?.background}
            placements={terminalViewportPlacements}
            onActivate={(id) => activateSharedTerminalSession(id, true)}
            owns={sshTerminals.owns}
            mountViewport={sshTerminals.mountViewport}
            unmountViewport={sshTerminals.unmountViewport}
          />
          {terminalPaneDropHint && terminalPaneZoomedSessionId === null && (
            <div
              className="terminal-pane-drop-preview"
              aria-hidden="true"
              data-terminal-pane-drop-target={terminalPaneDropHint.targetSessionId}
              style={{
                left: `${terminalPaneDropHint.previewRect.x * 100}%`,
                top: `${terminalPaneDropHint.previewRect.y * 100}%`,
                width: `${terminalPaneDropHint.previewRect.width * 100}%`,
                height: `${terminalPaneDropHint.previewRect.height * 100}%`,
              }}
            />
          )}
          {terminalPaneWorkspaceVisible
            && terminalPaneZoomedSessionId === null
            && terminalPaneGeometry?.handles.map((handle) => {
            const vertical = handle.direction === "vertical";
            const dividerPosition = vertical
              ? handle.rect.x + handle.rect.width * handle.ratio
              : handle.rect.y + handle.rect.height * handle.ratio;
            return (
              <div
                key={handle.splitId}
                className={`terminal-pane-resizer ${vertical ? "vertical" : "horizontal"}`}
                data-terminal-pane-split-id={handle.splitId}
                role="separator"
                aria-label={vertical ? t("workspace.resizeLeftRightPanes") : t("workspace.resizeTopBottomPanes")}
                aria-orientation={vertical ? "vertical" : "horizontal"}
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={Math.round(handle.ratio * 100)}
                tabIndex={0}
                style={vertical ? {
                  left: `${dividerPosition * 100}%`,
                  top: `${handle.rect.y * 100}%`,
                  height: `${handle.rect.height * 100}%`,
                } : {
                  left: `${handle.rect.x * 100}%`,
                  top: `${dividerPosition * 100}%`,
                  width: `${handle.rect.width * 100}%`,
                }}
                onPointerDown={(event) => {
                  if (event.button !== 0) return;
                  event.preventDefault();
                  setTerminalPaneResize({
                    pointerId: event.pointerId,
                    splitId: handle.splitId,
                    direction: handle.direction,
                    splitRect: handle.rect,
                    startClientX: event.clientX,
                    startClientY: event.clientY,
                    startRatio: handle.ratio,
                  });
                }}
                onKeyDown={(event) => {
                  const decrease = vertical ? event.key === "ArrowLeft" : event.key === "ArrowUp";
                  const increase = vertical ? event.key === "ArrowRight" : event.key === "ArrowDown";
                  if (!decrease && !increase) return;
                  event.preventDefault();
                  resizeTerminalPaneFromKeyboard(
                    handle.splitId,
                    handle.direction,
                    handle.rect,
                    handle.ratio,
                    decrease ? -0.025 : 0.025,
                  );
                }}
              />
            );
          })}
        </div>
      </div>

      <aside
        className="terminal-side-panel"
        aria-label={t("workspace.terminalSidePanel")}
        data-ai-panel-open={aiOpen}
        hidden={activeSurface !== "terminal" || !terminalSidePanelVisible}
      >
        <div
          className="terminal-side-panel-resizer"
          role="separator"
          aria-label={t("workspace.resizeTerminalSidePanel")}
          aria-orientation="vertical"
          aria-valuemin={activeTerminalSidePanelWidthBounds.min}
          aria-valuemax={activeTerminalSidePanelWidthBounds.max}
          aria-valuenow={Math.round(activeTerminalSidePanelAriaWidth)}
          tabIndex={0}
          onPointerDown={(event) => {
            if (event.button !== 0) return;
            event.preventDefault();
            setTerminalSidePanelResize({
              pointerId: event.pointerId,
              startX: event.clientX,
              startWidth: terminalSidePanelWidth,
            });
          }}
          onKeyDown={(event) => {
            if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
            event.preventDefault();
            const containerWidth = getTerminalSidePanelContainerWidth();
            const delta = event.key === "ArrowLeft" ? 16 : -16;
            setTerminalSidePanelWidth((current) => clampActiveTerminalSidePanelWidth(
              current + delta,
              containerWidth,
            ));
          }}
        />
        {terminalSidePanelTab === "sftp" ? (
          <div className="terminal-side-panel-header">
            <div className="terminal-side-panel-title">
              <VaultGlyph name="folder" />
              <span>
                <strong>SFTP</strong>
                <small title={terminalAddress}>{terminalAddress}</small>
              </span>
            </div>
            <button
              type="button"
              className="terminal-side-panel-close"
              aria-label={t("terminal.closeSftpPanel")}
              title={t("terminal.closeSidePanel")}
              onClick={() => {
                setTerminalSidePanelResize(null);
                setTerminalSidePanelOpen(false);
              }}
            >
              <VaultGlyph name="close" />
            </button>
          </div>
        ) : null}
        <div hidden={!aiOpen} style={{ display: aiOpen ? "contents" : "none" }}>
          <AiWorkspace
            locale={rendererLocale}
            providers={rendererSettings.ai.providers}
            activeProviderProfileId={rendererSettings.ai.activeProviderId}
            commandPermissionMode={rendererSettings.ai.commandPermissionMode}
            complete={openAiCompatibleCompletion}
            localAgents={discoveredAiAgents}
            localAgentComplete={openLocalAiAgentCompletion}
            terminalScope={aiTerminalScope}
            getSelectedTerminalText={readAiSelectedTerminalText}
            getRecentTerminalOutput={readAiRecentTerminalOutput}
            sendApprovedCommand={sendAiApprovedCommand}
            initialContext={{}}
            onSelectProvider={(providerProfileId) => updateAiPreferences({ activeProviderId: providerProfileId })}
            onCommandPermissionModeChange={(mode) => updateAiPreferences({ commandPermissionMode: mode })}
            onOpenSettings={() => {
              void openSettingsWindow(rendererLocale, "ai-providers").catch(() => setError(t("workspace.error.openSettings")));
            }}
            onClose={() => {
              setTerminalSidePanelResize(null);
              setTerminalSidePanelOpen(false);
            }}
          />
        </div>
        {editorTarget ? (
          <RemoteEditor
            t={t}
            sessionId={editorTarget.sessionId}
            path={editorTarget.path}
            onClose={() => setEditorTarget(null)}
          />
        ) : null}
        {!editorTarget && dockerOpen && dockerSessionId ? (
          <DockerPanel
            t={t}
            locale={rendererLocale}
            sessionId={dockerSessionId}
            connected={terminalConnectionState === "connected"}
          />
        ) : null}
        {sftpTabVisible && terminalSidePanelTab === "sftp" && activeSftpRender && (
          <SftpBrowserPanel
            active={sftpOpen && editorTarget === null}
            locale={rendererLocale}
            path={sftpPath}
            parentPath={parentSftpPath}
            breadcrumbs={sftpBreadcrumbs}
            loading={sftpLoading}
            error={sftpError}
            entries={sftpEntries}
            visibleEntries={visibleSftpEntries}
            showHiddenFiles={rendererSettings.sftp.showHiddenFiles}
            transfers={transfers}
            activeOwner={activeSftpOwner}
            canControlTransfer={(owner, transferId) => (
              sftpController.canControlTransfer(owner, transferId)
            )}
            onLoadPath={loadSftpPath}
            onChooseUpload={chooseSftpUpload}
            onCreateFolder={createRemoteFolder}
            onDownloadEntry={downloadRemoteEntry}
            onDownloadDirectory={downloadRemoteDirectory}
            onRenameEntry={renameRemoteEntry}
            onEditEntry={(entry) => {
              const owner = activeSftpRender?.owner;
              if (owner) setEditorTarget({ sessionId: owner.backendSessionId, path: entry.path });
            }}
            onDeleteEntry={deleteRemoteEntry}
            onControlTransfer={controlOwnedSftpTransfer}
            onRetryTransfer={retryTransfer}
            formatBytes={formatBytes}
            glyph={(name) => <VaultGlyph name={name} />}
          />
        )}

      </aside>

      {managedSshKeyEditor && (
        <div className="dialog-backdrop" role="presentation">
          <form
            className="trust-dialog saved-host-dialog managed-key-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="managed-key-editor-title"
            onSubmit={(event) => void submitManagedSshKey(event)}
          >
            <p className="eyebrow">{t("managedKey.editor.kicker")}</p>
            <h2 id="managed-key-editor-title">
              {t(managedSshKeyEditor.mode === "create"
                ? "managedKey.editor.createTitle"
                : "managedKey.editor.editTitle")}
            </h2>
            <div className="saved-host-fields managed-key-fields">
              <label>
                {t("managedKey.editor.name")}
                <input
                  autoFocus
                  value={managedSshKeyEditor.label}
                  onChange={(event) => setManagedSshKeyEditor((current) => (
                    current ? { ...current, label: event.target.value } : current
                  ))}
                  disabled={savedHostSubmitting}
                  maxLength={256}
                  required
                />
              </label>
              <label>
                {t("managedKey.editor.type")}
                <select
                  value={managedSshKeyEditor.category}
                  onChange={(event) => setManagedSshKeyEditor((current) => (
                    current ? {
                      ...current,
                      category: event.target.value as ManagedSshKeyCategory,
                    } : current
                  ))}
                  disabled={
                    savedHostSubmitting
                    || (managedSshKeyEditor.mode === "edit" && !managedSshKeyEditor.replaceSecret)
                  }
                >
                  <option value="key">{t("managedKey.editor.privateKeyType")}</option>
                  <option value="certificate">{t("managedKey.editor.certificateType")}</option>
                </select>
              </label>
              {managedSshKeyEditor.mode === "edit" && (
                <label className="replace-managed-key-option">
                  <input
                    type="checkbox"
                    checked={managedSshKeyEditor.replaceSecret}
                    onChange={(event) => {
                      clearManagedSshKeyInputs();
                      setManagedSshKeyEditor((current) => current ? {
                        ...current,
                        replaceSecret: event.target.checked,
                        category: current.key?.category ?? current.category,
                        passphrasePresent: false,
                        savePassphrase: false,
                      } : current);
                    }}
                    disabled={savedHostSubmitting}
                  />
                  {t("managedKey.editor.replaceMaterials")}
                </label>
              )}
              {(managedSshKeyEditor.mode === "create" || managedSshKeyEditor.replaceSecret) && (
                <div className="managed-key-secret-fields">
                  <label>
                    {t("managedKey.editor.privateKeyFile")}
                    <input
                      ref={managedPrivateKeyInput}
                      type="file"
                      disabled={savedHostSubmitting}
                      required
                    />
                  </label>
                  <label>
                    {t("managedKey.editor.publicKeyFile")}
                    <input
                      ref={managedPublicKeyInput}
                      type="file"
                      disabled={savedHostSubmitting}
                    />
                  </label>
                  {managedSshKeyEditor.category === "certificate" && (
                    <label>
                      {t("managedKey.editor.certificateFile")}
                      <input
                        ref={managedCertificateInput}
                        type="file"
                        disabled={savedHostSubmitting}
                        required
                      />
                    </label>
                  )}
                  <label>
                    {t("managedKey.editor.passphrase")}
                    <input
                      ref={managedPassphraseInput}
                      type="password"
                      onInput={(event) => setManagedSshKeyEditor((current) => {
                        if (!current) return current;
                        const passphrasePresent = event.currentTarget.value.length > 0;
                        return {
                          ...current,
                          passphrasePresent,
                          savePassphrase: passphrasePresent ? current.savePassphrase : false,
                        };
                      })}
                      disabled={savedHostSubmitting}
                      autoComplete="off"
                      spellCheck={false}
                      maxLength={MANAGED_SSH_KEY_PASSPHRASE_MAX_BYTES}
                    />
                  </label>
                  <label className="replace-managed-key-option">
                    <input
                      type="checkbox"
                      checked={managedSshKeyEditor.savePassphrase}
                      onChange={(event) => setManagedSshKeyEditor((current) => (
                        current ? { ...current, savePassphrase: event.target.checked } : current
                      ))}
                      disabled={savedHostSubmitting || !managedSshKeyEditor.passphrasePresent}
                    />
                    {t("managedKey.editor.savePassphrase")}
                  </label>
                </div>
              )}
            </div>
            {managedSshKeysError && (
              <p className="connection-error" role="alert">{managedSshKeysError}</p>
            )}
            <p className="security-note">
              {t("managedKey.editor.security")}
            </p>
            <div className="dialog-actions">
              <button
                type="button"
                disabled={savedHostSubmitting}
                onClick={() => {
                  clearManagedSshKeyInputs();
                  setManagedSshKeyEditor(null);
                  setManagedSshKeysError(null);
                }}
              >
                {t("managedKey.cancel")}
              </button>
              <button className="primary-button" type="submit" disabled={savedHostSubmitting || busy}>
                {t(savedHostSubmitting ? "managedKey.editor.saving" : "managedKey.editor.save")}
              </button>
            </div>
          </form>
        </div>
      )}

      {managedSshKeyDelete && (
        <div className="dialog-backdrop" role="presentation">
          <div
            className="trust-dialog saved-host-dialog managed-key-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="managed-key-delete-title"
          >
            <p className="eyebrow">{t("managedKey.delete.kicker")}</p>
            <h2 id="managed-key-delete-title">{t("managedKey.delete.title")}</h2>
            <p>
              {t("managedKey.delete.description", { key: managedSshKeyDelete.key.label })}
            </p>
            <p className="warning-text">
              {t("managedKey.delete.warning")}
            </p>
            {managedSshKeysError && (
              <p className="connection-error" role="alert">{managedSshKeysError}</p>
            )}
            <div className="dialog-actions">
              <button
                type="button"
                disabled={savedHostSubmitting}
                onClick={() => {
                  setManagedSshKeyDelete(null);
                  setManagedSshKeysError(null);
                }}
              >
                {t("managedKey.cancel")}
              </button>
              <button
                className="danger-button"
                type="button"
                disabled={savedHostSubmitting || busy}
                onClick={() => void confirmDeleteManagedSshKey()}
              >
                {t(savedHostSubmitting ? "managedKey.delete.deleting" : "managedKey.delete.confirm")}
              </button>
            </div>
          </div>
        </div>
      )}

      {managedMasterKeyRotationOpen && (
        <div className="dialog-backdrop" role="presentation">
          <div
            className="trust-dialog saved-host-dialog managed-key-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="managed-master-key-rotation-title"
          >
            <p className="eyebrow">{t("managedKey.rotate.kicker")}</p>
            <h2 id="managed-master-key-rotation-title">{t("managedKey.rotate.title")}</h2>
            <p>
              {t("managedKey.rotate.description")}
            </p>
            <p className="warning-text">
              {t("managedKey.rotate.warning")}
            </p>
            {managedSshKeysError && (
              <p className="connection-error" role="alert">{managedSshKeysError}</p>
            )}
            <div className="dialog-actions">
              <button
                type="button"
                disabled={savedHostSubmitting}
                onClick={() => {
                  setManagedMasterKeyRotationOpen(false);
                  setManagedSshKeysError(null);
                }}
              >
                {t("managedKey.cancel")}
              </button>
              <button
                className="primary-button"
                type="button"
                disabled={savedHostSubmitting || busy}
                onClick={() => void confirmManagedMasterKeyRotation()}
              >
                {t(savedHostSubmitting ? "managedKey.rotate.rotating" : "managedKey.rotate.confirm")}
              </button>
            </div>
          </div>
        </div>
      )}

      {legacyVaultPreview && (
        <div className="dialog-backdrop" role="presentation">
          <div
            className="trust-dialog saved-host-dialog legacy-import-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="legacy-import-title"
          >
            <p className="eyebrow">{t("legacyImport.kicker")}</p>
            <h2 id="legacy-import-title">{t("legacyImport.title")}</h2>
            <p>
              {t("legacyImport.inspected", {
                source: t(legacyVaultSourceLabelKeys[legacyVaultPreview.inspection.sourceKind]),
              })}
            </p>
            <dl className="legacy-import-summary">
              {LEGACY_VAULT_SUMMARY_ROWS.map(([field, labelKey, positive]) => (
                <div className={positive ? "is-positive" : undefined} key={field}>
                  <dt>{t(labelKey)}</dt>
                  <dd>{legacyVaultPreview.inspection[field]}</dd>
                </div>
              ))}
            </dl>
            <ul className="legacy-import-policy">
              <li>{t("legacyImport.policy.duplicates")}</li>
              <li>{t("legacyImport.policy.remap")}</li>
              <li>{t("legacyImport.policy.referencePaths")}</li>
              <li>{t("legacyImport.policy.secureStorage")}</li>
              <li>{t("legacyImport.policy.passwordPolicy")}</li>
              <li><code>enc:v1:</code> {t("legacyImport.policy.unrecoverableSuffix")}</li>
            </ul>
            {legacyVaultPreview.inspection.sourceKind === "backupSafeStorageV1RequiresRecovery" && (
              <p className="legacy-import-blocked" role="alert">
                {t("legacyImport.blocked")}
              </p>
            )}
            {!legacyVaultInspectionHasChanges(legacyVaultPreview.inspection)
              && legacyVaultPreview.inspection.sourceKind !== "backupSafeStorageV1RequiresRecovery" && (
                 <p className="warning-text">{t("legacyImport.noChanges")}</p>
              )}
            {legacyVaultPreview.inspection.issues.length > 0 && (
              <section className="legacy-import-issues" aria-label={t("legacyImport.issues.title")}>
                <h3>{t("legacyImport.issues.title")}</h3>
                <ul>
                  {legacyVaultPreview.inspection.issues.map((issue, index) => (
                    <li key={`${issue.code}-${index}`}>
                      {t(issue.recordIndex === undefined
                        ? "legacyImport.issues.recordPrefix"
                        : "legacyImport.issues.indexedRecordPrefix", {
                        kind: t(legacyVaultRecordKindLabelKeys[issue.recordKind]),
                        index: (issue.recordIndex ?? 0) + 1,
                      })}
                      {t(legacyVaultIssueMessageKeys[issue.code] ?? "legacyImport.issue.unknown")}
                    </li>
                  ))}
                </ul>
                {legacyVaultPreview.inspection.omittedIssueCount > 0 && (
                  <p className="warning-text">
                    {t("legacyImport.issues.omitted", {
                      count: legacyVaultPreview.inspection.omittedIssueCount,
                    })}
                  </p>
                )}
              </section>
            )}
            {legacyVaultPreview.error && (
              <p className="connection-error" role="alert">{legacyVaultPreview.error}</p>
            )}
            <p className="security-note">{t("legacyImport.security")}</p>
            <div className="dialog-actions">
              <button
                type="button"
                disabled={savedHostSubmitting}
                onClick={() => setLegacyVaultPreview(null)}
              >
                {t("legacyImport.cancel")}
              </button>
              <button
                className="primary-button"
                type="button"
                disabled={
                  savedHostSubmitting
                  || busy
                  || !legacyVaultInspectionHasChanges(legacyVaultPreview.inspection)
                  || legacyVaultPreview.inspection.sourceKind === "backupSafeStorageV1RequiresRecovery"
                }
                onClick={() => void commitLegacyVaultPreview()}
              >
                {savedHostSubmitting
                  ? t("legacyImport.importing")
                  : legacyVaultPreview.inspection.sourceKind === "backupSafeStorageV1RequiresRecovery"
                    ? t("legacyImport.restoreRequired")
                    : !legacyVaultInspectionHasChanges(legacyVaultPreview.inspection)
                      ? t("legacyImport.noChanges")
                      : t("legacyImport.confirm")}
              </button>
            </div>
          </div>
        </div>
      )}

      {workspacePrompt && (
        <WorkspacePromptDialog
          request={workspacePrompt}
          onCancel={() => settleWorkspacePrompt(workspacePrompt.id, null)}
          onConfirm={(result) => settleWorkspacePrompt(workspacePrompt.id, result)}
        />
      )}

      {sessionRestoreSnapshot && (
        <SessionRestorePrompt
          snapshot={sessionRestoreSnapshot}
          locale={rendererLocale}
          connectingId={sessionRestoreConnectingId}
          restoringSelected={sessionRestoreRestoring}
          disabled={savedHostsLoading || busy || savedHostSubmitting}
          error={sessionRestoreError}
          onReconnect={(entry) => void reconnectRestoredSession(entry)}
          onRestoreSelected={(workspaceSessionIds) => (
            void restoreSelectedSessionPresentations(workspaceSessionIds)
          )}
          onDiscard={settleSessionRestore}
        />
      )}

      {localTerminalPanelOpen && (
        <div className="dialog-backdrop serial-dialog-backdrop" role="presentation">
          <div
            className="local-terminal-dialog-shell"
            role="dialog"
            aria-modal="true"
            aria-label={t("localTerminal.openDialog")}
          >
            <LocalTerminalPanel
              locale={rendererLocale}
              disabled={legacyBusy
                || sharedTerminalRegistry.order.length >= MAX_WORKSPACE_SESSIONS}
              initialCwd={rendererSettings.terminal.localStartDir}
              shellSource={NATIVE_DESKTOP_RUNTIME_AVAILABLE
                ? undefined
                : BROWSER_LOCAL_SHELL_SOURCE}
              onCancel={() => setLocalTerminalPanelOpen(false)}
              onConnect={handleLocalTerminalConnect}
            />
          </div>
        </div>
      )}

      {serialPanel && (serialPanel.mode !== "saved" || serialPanelHost) && (
        <div className="dialog-backdrop serial-dialog-backdrop" role="presentation">
          <div
            className="serial-dialog-shell"
            role="dialog"
            aria-modal="true"
            aria-label={t(serialPanel.mode === "quick"
              ? "serial.dialog.quick"
              : serialPanel.mode === "create" ? "serial.dialog.create" : "serial.dialog.edit")}
          >
            {serialPanel.mode === "quick" ? (
              <SerialConnectPanel
                mode="quick"
                locale={rendererLocale}
                layout="aside"
                disabled={busy}
                portSource={NATIVE_DESKTOP_RUNTIME_AVAILABLE
                  ? undefined
                  : BROWSER_SERIAL_PORT_SOURCE}
                onCancel={() => setSerialPanel(null)}
                onConnect={handleQuickSerialConnect}
              />
            ) : serialPanel.mode === "create" ? (
              <SerialConnectPanel
                mode="create"
                locale={rendererLocale}
                layout="aside"
                disabled={savedHostSubmitting || busy}
                portSource={NATIVE_DESKTOP_RUNTIME_AVAILABLE
                  ? undefined
                  : BROWSER_SERIAL_PORT_SOURCE}
                groups={savedHostGroups}
                availableTags={savedHostTags}
                initialGroup={selectedVaultGroup ?? undefined}
                onCancel={() => setSerialPanel(null)}
                onSave={handleCreateSavedSerial}
              />
            ) : serialPanelHost ? (
              <SerialConnectPanel
                mode="saved"
                locale={rendererLocale}
                layout="aside"
                disabled={savedHostSubmitting || busy}
                savedHost={serialPanelHost}
                portSource={NATIVE_DESKTOP_RUNTIME_AVAILABLE
                  ? undefined
                  : BROWSER_SERIAL_PORT_SOURCE}
                groups={savedHostGroups}
                availableTags={savedHostTags}
                onCancel={() => setSerialPanel(null)}
                onSave={handleUpdateSavedSerial}
              />
            ) : null}
          </div>
        </div>
      )}

      {savedHostEditor && (
        <SavedHostEditorDialog
          editor={savedHostEditor}
          locale={rendererLocale}
          submitting={savedHostSubmitting}
          busy={busy}
          nativeRuntimeAvailable={NATIVE_DESKTOP_RUNTIME_AVAILABLE}
          error={savedHostsError}
          groups={savedHostGroups}
          savedHosts={savedHosts}
          managedSshKeysLoading={managedSshKeysLoading}
          managedKeys={managedSshKeyCatalog?.keys ?? []}
          passwordIdentities={passwordIdentityCatalog?.identities ?? []}
          proxyProfiles={proxyProfileCatalog?.profiles ?? []}
          onChange={(update) => setSavedHostEditor((current) => (
            current ? update(current) : current
          ))}
          onSubmit={(event) => void submitSavedHost(event)}
          onClose={closeSavedHostEditor}
          glyph={(name) => <VaultGlyph name={name} />}
        />
      )}

      {savedHostPasswordPrompt ? (
        <SavedHostPasswordPromptDialog
          locale={rendererLocale}
          targetLabel={savedHostPasswordPrompt.host.label}
          targetAddress={savedHostDisplayAddress(savedHostPasswordPrompt.host)}
          busy={savedHostPromptBusy}
          connecting={savedHostPromptConnecting}
          closing={savedHostPromptClosing}
          error={savedHostPasswordPrompt.error}
          password={savedHostPasswordPrompt.password}
          showManualLogin={isSavedTelnetHost(savedHostPasswordPrompt.host)}
          onPasswordChange={(password) => setSavedHostPasswordPrompt((current) => (
            current ? { ...current, password, error: undefined } : current
          ))}
          onSubmit={(event) => void submitSavedHostPassword(event)}
          onCancel={cancelSavedHostPasswordPrompt}
          onManualLogin={() => {
            const { host, workspaceSessionId } = savedHostPasswordPrompt;
            // Keep the prompt mounted while Telnet falls back to manual login.
            // Unmounting it before the async attempt completes produces a
            // visible close/open flash when the fallback fails.
            setSavedHostPasswordPrompt((current) => current ? {
              ...current,
              password: "",
              error: undefined,
            } : current);
            void connectSavedHost(host).then((failure) => {
              if (failure) {
                setSavedHostPasswordPrompt((current) => current ? {
                  ...current,
                  error: failure,
                } : {
                  host,
                  ...(workspaceSessionId ? { workspaceSessionId } : {}),
                  password: "",
                  error: failure,
                });
              } else {
                setSavedHostPasswordPrompt((current) => (
                  current?.host.id === host.id ? null : current
                ));
              }
            });
          }}
        />
      ) : savedHostProxyPasswordPrompt ? (
        <SavedHostProxyPasswordPromptDialog
          locale={rendererLocale}
          targetLabel={savedHostProxyPasswordPrompt.host.label}
          targetAddress={[
            savedHostEffectiveUsername(savedHostProxyPasswordPrompt.host),
            "@",
            savedHostProxyPasswordPrompt.host.hostname,
            ":",
            savedHostProxyPasswordPrompt.host.port,
          ].join("")}
          busy={savedHostPromptBusy}
          connecting={savedHostPromptConnecting}
          closing={savedHostPromptClosing}
          error={savedHostProxyPasswordPrompt.error}
          requireSshPassword={
            !isSavedKeyHost(savedHostProxyPasswordPrompt.host)
            && !savedHostProxyPasswordPrompt.host.hasSavedCredential
          }
          showKeyPassphrase={
            isSavedManagedKeyHost(savedHostProxyPasswordPrompt.host)
            && !savedHostProxyPasswordPrompt.host.hasSavedKeyPassphrase
          }
          sshPassword={savedHostProxyPasswordPrompt.sshPassword}
          keyPassphrase={savedHostProxyPasswordPrompt.keyPassphrase}
          proxyPassword={savedHostProxyPasswordPrompt.proxyPassword}
          onSshPasswordChange={(sshPassword) => (
            setSavedHostProxyPasswordPrompt((current) => current ? {
              ...current,
              sshPassword,
              error: undefined,
            } : current)
          )}
          onKeyPassphraseChange={(keyPassphrase) => (
            setSavedHostProxyPasswordPrompt((current) => current ? {
              ...current,
              keyPassphrase,
              error: undefined,
            } : current)
          )}
          onProxyPasswordChange={(proxyPassword) => (
            setSavedHostProxyPasswordPrompt((current) => current ? {
              ...current,
              proxyPassword,
              error: undefined,
            } : current)
          )}
          onSubmit={(event) => void submitSavedHostProxyPassword(event)}
          onCancel={cancelSavedHostProxyPasswordPrompt}
        />
      ) : savedHostKeyPassphrasePrompt ? (
        <SavedHostKeyPassphrasePromptDialog
          locale={rendererLocale}
          targetLabel={savedHostKeyPassphrasePrompt.host.label}
          targetAddress={[
            savedHostKeyPassphrasePrompt.host.username,
            "@",
            savedHostKeyPassphrasePrompt.host.hostname,
            ":",
            savedHostKeyPassphrasePrompt.host.port,
          ].join("")}
          busy={savedHostPromptBusy}
          connecting={savedHostPromptConnecting}
          closing={savedHostPromptClosing}
          error={savedHostKeyPassphrasePrompt.error}
          passphrase={savedHostKeyPassphrasePrompt.passphrase}
          hasSavedPassphrase={savedHostKeyPassphrasePrompt.host.hasSavedKeyPassphrase}
          onPassphraseChange={(passphrase) => setSavedHostKeyPassphrasePrompt((current) => (
            current ? { ...current, passphrase, error: undefined } : current
          ))}
          onSubmit={(event) => void submitSavedHostKeyPassphrase(event)}
          onCancel={cancelSavedHostKeyPassphrasePrompt}
        />
      ) : null}
      {hostKeyPrompt && (
        <div className="dialog-backdrop live-terminal-dialog-backdrop" role="presentation">
          <div className="trust-dialog" role="dialog" aria-modal="true" aria-labelledby="host-key-title">
            <p className="eyebrow">{t("hostKey.kicker")}</p>
            <h2 id="host-key-title">
              {t(hostKeyPrompt.status === "changed" ? "hostKey.changedTitle" : "hostKey.unknownTitle")}
            </h2>
            <p>{hostKeyPrompt.hostname}:{hostKeyPrompt.port}</p>
            <code>{hostKeyPrompt.keyType}<br />SHA256:{hostKeyPrompt.fingerprint}</code>
            {hostKeyPrompt.status === "changed" && <p className="warning-text">{t("hostKey.changedWarning")}</p>}
            <div className="dialog-actions">
              <button type="button" disabled={hostKeySaving} onClick={() => void answerHostKey(false)}>{t("hostKey.reject")}</button>
              <button type="button" disabled={hostKeySaving} onClick={() => void answerHostKey(true)}>{t("hostKey.trustOnce")}</button>
              <button
                className="primary-button"
                type="button"
                disabled={hostKeySaving}
                onClick={() => void answerHostKey(true, true)}
              >
                {hostKeySaving
                  ? t("hostKey.saving")
                  : t(hostKeyPrompt.status === "changed" ? "hostKey.updateContinue" : "hostKey.saveContinue")}
              </button>
            </div>
          </div>
        </div>
      )}

      {interactivePrompt && (
        <div className="dialog-backdrop live-terminal-dialog-backdrop" role="presentation">
          <form className="trust-dialog" role="dialog" aria-modal="true" aria-labelledby="interactive-auth-title" onSubmit={(event) => void answerInteractive(event)}>
            <p className="eyebrow">{t("interactiveAuth.kicker")}</p>
            <h2 id="interactive-auth-title">{interactivePrompt.name || t("interactiveAuth.title")}</h2>
            {interactivePrompt.instructions && <p>{interactivePrompt.instructions}</p>}
            <div className="interactive-fields">
              {interactivePrompt.prompts.map((prompt, index) => (
                <label key={`${prompt.text}-${index}`}>
                  {prompt.text || t("interactiveAuth.prompt", { index: index + 1 })}
                  <input
                    autoFocus={index === 0}
                    type={prompt.echo ? "text" : "password"}
                    value={interactiveAnswers[index] ?? ""}
                    onChange={(event) => setInteractiveAnswers((answers) => {
                      const next = [...answers];
                      next[index] = event.target.value;
                      return next;
                    })}
                  />
                </label>
              ))}
            </div>
            <div className="dialog-actions">
              <button type="button" onClick={() => void rejectInteractive()}>{t("interactiveAuth.cancel")}</button>
              <button className="primary-button" type="submit">{t("interactiveAuth.continue")}</button>
            </div>
          </form>
        </div>
      )}
    </section>
  );
}
