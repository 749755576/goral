import { Channel, invoke } from "@tauri-apps/api/core";

import {
  withZeroizedManagedSshKeyBundle,
  type ManagedSshKeyBundleBytes,
} from "./managedSshKeyBundle";
import type { HostVisual } from "./hostVisual";
import type { Locale } from "./i18n.ts";

export type { HostVisual } from "./hostVisual";

// Known Hosts keeps its focused catalog module while remaining available from
// the canonical typed backend boundary used by the rest of the workbench.
export {
  KNOWN_HOSTS_COMMANDS,
  listKnownHosts,
  replaceKnownHosts,
  scanSystemKnownHosts,
  type KnownHostsCatalog,
  type ReplaceKnownHostsRequest,
  type SavedKnownHost,
  type SystemKnownHostsScan,
} from "./knownHostsApi";

export {
  CONNECTION_LOGS_COMMANDS,
  classifyConnectionLogsError,
  listConnectionLogs,
  replaceConnectionLogs,
  type ConnectionLogsCatalog,
  type ReplaceConnectionLogsRequest,
  type SavedConnectionLog,
  type SavedConnectionLogHostOs,
  type SavedConnectionLogIconColorId,
  type SavedConnectionLogIconColorMode,
  type SavedConnectionLogIconId,
  type SavedConnectionLogIconMode,
  type SavedConnectionLogProtocol,
} from "./connectionLogsApi";

// Notes/Snippets keeps its focused API module for the dedicated workspaces,
// while the canonical backend boundary re-exports the same typed wrappers so
// every caller observes one command and DTO contract.
export {
  NOTES_SNIPPETS_COMMANDS,
  createSavedSnippet,
  createVaultNote,
  deleteSavedSnippet,
  deleteVaultNote,
  listSavedSnippets,
  listVaultNotes,
  updateSavedSnippet,
  updateVaultNote,
  type CreateSavedSnippetRequest,
  type CreateVaultNoteRequest,
  type DeleteSavedSnippetRequest,
  type DeleteVaultNoteRequest,
  type NotesSnippetsCatalog,
  type SavedScriptLanguage,
  type SavedScriptTrigger,
  type SavedSnippet,
  type SavedSnippetDraft,
  type SavedSnippetKind,
  type SavedSnippetMultiLineRunMode,
  type SavedVaultNote,
  type SavedVaultNoteDraft,
  type UpdateSavedSnippetRequest,
  type UpdateVaultNoteRequest,
} from "./notesSnippetsApi";

export type BackendStatus = {
  appVersion: string;
  runtime: string;
  operatingSystem: string;
  architecture: string;
  processId: number;
};

export type SshAuthMethod = "auto" | "password" | "key" | "certificate";

export type SshConnectionConfig = {
  hostname: string;
  port?: number;
  username: string;
  auth?: {
    method?: SshAuthMethod;
    authPolicyVersion?: number;
    identityId?: string;
    identityAvailable?: boolean;
    hasPassword?: boolean;
    keyId?: string;
    keyAvailable?: boolean;
    hasPrivateKey?: boolean;
    hasPublicKey?: boolean;
    hasCertificate?: boolean;
    identityFilePaths?: string[];
    useSshAgent?: boolean;
    identityAgent?: string;
    identitiesOnly?: boolean;
    addKeysToAgent?: string;
    useKeychain?: boolean;
    agentForwarding?: boolean;
    requiresMfa?: boolean;
  };
  proxy?: {
    type: "http" | "socks5" | "command";
    host?: string;
    port?: number;
    command?: string;
    identityId?: string;
    username?: string;
    hasPassword?: boolean;
  };
  jumpHosts?: Array<{ hostId: string }>;
  legacyAlgorithms?: boolean;
  skipEcdsaHostKey?: boolean;
  algorithms?: {
    kex?: string[];
    cipher?: string[];
    hmac?: string[];
    serverHostKey?: string[];
    compress?: string[];
  };
  keepalive?: {
    overrideGlobal?: boolean;
    intervalSeconds?: number;
    countMax?: number;
  };
  timeouts?: {
    tcpConnectSeconds?: number;
    authReadySeconds?: number;
  };
};

export type SshValidationResult = {
  valid: boolean;
  normalized?: {
    hostname: string;
    port: number;
    username: string;
    authMethod: SshAuthMethod;
    legacyAlgorithms: boolean;
    skipEcdsaHostKey: boolean;
    timeouts: {
      tcpConnectSeconds: number;
      authReadySeconds: number;
    };
  };
  errors: Array<{ field: string; code: string; message: string }>;
  authPlan: {
    method: SshAuthMethod;
    attempts: Array<{
      kind:
        | "none"
        | "keyboardInteractive"
        | "sshAgent"
        | "selectedKey"
        | "certificate"
        | "defaultKeys"
        | "password";
      canPrompt: boolean;
    }>;
    agentForwarding: boolean;
  };
};

export type TerminalSize = {
  columns: number;
  rows: number;
  pixelWidth: number;
  pixelHeight: number;
};

export type SshControlEvent =
  | { type: "connecting" }
  | { type: "connected" }
  | { type: "ready" }
  | { type: "eof" }
  | { type: "exitStatus"; status: number }
  | { type: "telnetEchoMode"; remoteEcho: boolean; localEcho: boolean }
  | {
    type: "serialZmodemDetected";
    sessionId: string;
    transferId: string;
    direction: SerialZmodemDirection;
  }
  | ({
    type: "serialZmodemProgress";
    sessionId: string;
    transferId: string;
    direction: SerialZmodemDirection;
  }
    & SerialZmodemProgressEvent)
  | {
    type: "serialZmodemCompleted";
    sessionId: string;
    transferId: string;
    direction: SerialZmodemDirection;
    fileCount: number;
    skippedFiles: number;
    totalBytes: number;
    transferredBytes: number;
  }
  | {
    type: "serialZmodemCanceled";
    sessionId: string;
    transferId: string;
    direction: SerialZmodemDirection;
  }
  | {
    type: "serialZmodemError";
    sessionId: string;
    transferId: string;
    direction: SerialZmodemDirection;
    code: string;
    message: string;
  }
  | { type: "error"; code: string; message: string }
  | { type: "closed" };

export type HostKeyPrompt = {
  requestId: string;
  ownerId: string;
  sessionId: string;
  clientAttemptId: string;
  hostname: string;
  port: number;
  status: "trusted" | "changed" | "unknown";
  keyType: string;
  fingerprint: string;
  publicKey: string;
  knownHostId?: string;
  knownFingerprint?: string;
};

export type InteractivePrompt = {
  requestId: string;
  ownerId: string;
  sessionId: string;
  clientAttemptId: string;
  name: string;
  instructions: string;
  prompts: Array<{ text: string; echo: boolean }>;
};

export type SshSessionCallbacks = {
  onControl: (event: SshControlEvent) => void;
  onData: (frame: Uint8Array) => void;
};

export type SshSessionHandle = {
  sessionId: string;
  controlChannel: Channel<SshControlEvent>;
  dataChannel: Channel<ArrayBuffer>;
  /** Detaches renderer callbacks after this session generation is retired. */
  dispose: () => void;
};

export type SerialParity = "none" | "even" | "odd" | "mark" | "space";
export type SerialFlowControl = "none" | "xon/xoff" | "rts/cts";
export type SerialBackspaceBehavior = "default" | "ctrl-h";
export type SerialPortKind = "hardware" | "pseudo" | "custom";

export type SerialConfig = {
  path: string;
  baudRate: number;
  dataBits?: 5 | 6 | 7 | 8;
  stopBits?: 1 | 1.5 | 2;
  parity?: SerialParity;
  flowControl?: SerialFlowControl;
  localEcho?: boolean;
  lineMode?: boolean;
  backspaceBehavior?: SerialBackspaceBehavior;
};

export type SerialPortInfo = {
  path: string;
  manufacturer: string;
  serialNumber: string;
  vendorId: string;
  productId: string;
  pnpId: string;
  type: SerialPortKind;
};

export type SerialYmodemDirection = "send" | "receive";
export type SerialYmodemProgressStage = "header" | "data" | "complete";

export type SerialYmodemProgressEvent = {
  transferId: string;
  direction: SerialYmodemDirection;
  stage: SerialYmodemProgressStage;
  transferredBytes: number;
  totalBytes: number;
  fileName?: string;
  fileCount: number;
};

export type SendSerialYmodemResponse = {
  canceled: boolean;
  fileName?: string;
  totalBytes: number;
  writtenBytes: number;
  packetsSent: number;
};

export type ReceivedSerialYmodemFile = {
  fileName: string;
  totalBytes: number;
  writtenBytes: number;
};

export type ReceiveSerialYmodemResponse = {
  canceled: boolean;
  files: ReceivedSerialYmodemFile[];
  fileCount: number;
  totalBytes: number;
  writtenBytes: number;
};

export type SerialZmodemDirection = "send" | "receive";
export type SerialZmodemProgressStage = "header" | "data" | "finalizing" | "complete";

export type SerialZmodemProgressEvent = {
  stage: SerialZmodemProgressStage;
  transferredBytes: number;
  totalBytes: number;
  fileName?: string;
  fileIndex: number;
  fileCount: number;
};

export type SerialZmodemResponse = {
  canceled: boolean;
  fileCount: number;
  skippedFiles: number;
  totalBytes: number;
  transferredBytes: number;
};

export type DiscoveredLocalShell = {
  id: string;
  name: string;
  command: string;
  args: string[];
  icon: string;
  isDefault: boolean;
};

export type SavedHost = {
  id: string;
  revision: number;
  label: string;
  /** Optional until the Rust saved-host group field is exposed. */
  group?: string;
  tags: string[];
  hostChain: { hostIds: string[] } | null;
  hostname: string;
  port: number;
  username: string;
  protocol: string;
  /** Host-owned Mosh override; null inherits the GroupConfig/default value. */
  moshEnabled?: boolean | null;
  /** Host-owned Eternal Terminal override; null inherits the GroupConfig/default value. */
  etEnabled?: boolean | null;
  /** Host-owned Eternal Terminal port; null inherits the GroupConfig/default port. */
  etPort?: number | null;
  /** Effective Host + GroupConfig Mosh transport switch; valid only for SSH hosts. */
  effectiveMoshEnabled?: boolean;
  /** Effective Host + GroupConfig ET switch; false for non-SSH or Mosh-selected hosts. */
  effectiveEtEnabled?: boolean;
  /** Renderer-safe legacy OS/distro/custom-icon projection. */
  visual: HostVisual;
  /** Present only for primary Serial hosts. */
  serialConfig: SerialConfig | null;
  /** Includes effective GroupConfig Backspace inheritance for runtime/display. */
  effectiveSerialConfig: SerialConfig | null;
  /** True only when Backspace was explicitly set on the host, not inherited from its group. */
  hasExplicitSerialBackspaceBehavior: boolean;
  /** True only when charset was explicitly set on the host, not inherited from its group. */
  hasExplicitCharset: boolean;
  /** Effective host/group character set used by Telnet and Serial runtimes. */
  charset: string | null;
  authMethod: string;
  keySource: "none" | "reference" | "managed";
  /** Safe Vault entity ID for the selected managed key/certificate, if any. */
  managedSshKeyId: string | null;
  /** Effective persisted password availability: identity or host-owned. */
  hasSavedCredential: boolean;
  /** Only the host-owned password account; use this for host edit/remove UI. */
  hasSavedHostCredential: boolean;
  /** Bound reusable identity metadata; always present and `null` when unbound. */
  passwordIdentity: SavedHostPasswordIdentity | null;
  hasSavedKeyPassphrase: boolean;
  /** Renderer-safe proxy binding. Inline proxy configuration has priority. */
  proxy: SavedHostProxy | null;
  /** Effective host + root-to-leaf GroupConfig appearance; never persisted back. */
  effectiveAppearance: SavedHostEffectiveAppearance;
  createdAt: number;
  updatedAt: number;
};

export type SavedHostEffectiveAppearance = {
  /** Null means the host/group theme override is inactive. */
  themeId: string | null;
  /** Null means the global terminal font family remains active. */
  fontFamily: string | null;
  /** Null means the global terminal font size remains active. */
  fontSize: number | null;
  /** Null means the global terminal font weight remains active. */
  fontWeight: number | null;
};

export type SavedHostProxy = {
  proxyProfileId: string | null;
  inlineProxy: ProxyProfileConfig | null;
};

export type SavedHostInlineProxyMutation =
  | { action: "keep" }
  | { action: "remove" }
  | { action: "replace"; config: ProxyProfileConfigRequest };

export type SavedHostProxyProfileMutation =
  | { action: "keep" }
  | { action: "remove" }
  | { action: "replace"; profileId: string };

export type SavedHostProxyMutation = {
  inlineProxy: SavedHostInlineProxyMutation;
  profile: SavedHostProxyProfileMutation;
};

/** Renderer-safe metadata for the reusable password identity bound to a host. */
export type SavedHostPasswordIdentity = {
  id: string;
  label: string;
  username: string;
  hasSavedCredential: boolean;
};

export type SavedHostDraft = {
  label?: string;
  hostname: string;
  port: number;
  username: string;
  /** Primary saved-host protocol. Omission remains SSH-compatible. */
  protocol?: "ssh" | "telnet" | "serial";
  /** Required for Serial; ignored payloads are rejected for network hosts. */
  serialConfig?: SerialConfig;
  charset?: string;
  /** Legacy-compatible Vault group path. Omission keeps the host at root. */
  group?: string;
  tags?: string[];
  hostChain?: { hostIds: string[] };
  /** Native CRUD authentication selection; omitted payloads remain password-compatible. */
  authMethod?: "password" | "key" | "certificate";
  /** Required for managed key/certificate authentication. */
  managedSshKeyId?: string;
  /** Replaces the reusable password-identity binding; omission clears it. */
  passwordIdentityId?: string;
  /** Host-owned Mosh override. Omission clears it and restores inheritance. */
  moshEnabled?: boolean;
  /** Host-owned ET override. Omission clears it and restores inheritance. */
  etEnabled?: boolean;
  /** Host-owned ET port. Omission restores GroupConfig/default inheritance. */
  etPort?: number;
  proxy?: SavedHostProxyMutation;
};

export type SavedHostCredentialMutation =
  | { action: "keep" }
  | { action: "remove" }
  | { action: "replace"; stagedCredentialReference: string };

export type CreateSavedHostRequest = {
  draft: SavedHostDraft;
  stagedCredentialReference?: string;
};

export type UpdateSavedHostRequest = {
  id: string;
  expectedRevision: number;
  draft: SavedHostDraft;
  credentialMutation: SavedHostCredentialMutation;
};

export type DeleteSavedHostRequest = {
  id: string;
  expectedRevision: number;
};

export type ManagedSshKeyCategory = "key" | "certificate";

export type ManagedSshKeySource = "generated" | "imported";

/** Renderer-safe catalog metadata. Backend locators and custody details are omitted. */
export type ManagedSshKey = {
  id: string;
  label: string;
  category: ManagedSshKeyCategory;
  source: ManagedSshKeySource;
  hasSavedPassphrase: boolean;
  createdAt: number;
  updatedAt: number;
};

/**
 * `inventoryRevision` is an opaque, backend-issued complete-Vault CAS token.
 * The renderer may only round-trip it unchanged.
 */
export type ManagedSshKeyCatalog = {
  inventoryRevision: unknown;
  keys: ManagedSshKey[];
};

export type ManagedSshKeyMetadata = {
  label: string;
  category: ManagedSshKeyCategory;
  savePassphrase: boolean;
};

export type CreateManagedSshKeyRequest = {
  expectedInventoryRevision: unknown;
  metadata: ManagedSshKeyMetadata;
  stagedBundleReference: string;
};

export type UpdateManagedSshKeyRequest = {
  id: string;
  expectedInventoryRevision: unknown;
  metadata: ManagedSshKeyMetadata;
  stagedBundleReference?: string;
};

export type DeleteManagedSshKeyRequest = {
  id: string;
  expectedInventoryRevision: unknown;
};

/** Renderer-safe metadata for one reusable password identity. */
export type PasswordIdentity = {
  id: string;
  revision: number;
  label: string;
  username: string;
  hasSavedCredential: boolean;
  createdAt: number;
  updatedAt: number;
};

/**
 * `inventoryRevision` is the opaque complete-Vault CAS token issued by Rust.
 * It must be round-tripped unchanged with every password-identity mutation.
 */
export type PasswordIdentityCatalog = {
  inventoryRevision: unknown;
  identities: PasswordIdentity[];
};

export type PasswordIdentityMetadata = {
  label: string;
  username: string;
};

export type PasswordIdentityCredentialMutation =
  | { action: "keep" }
  | { action: "remove" }
  | { action: "replace"; stagedCredentialReference: string };

export type CreatePasswordIdentityRequest = {
  expectedInventoryRevision: unknown;
  metadata: PasswordIdentityMetadata;
  stagedCredentialReference?: string;
};

export type UpdatePasswordIdentityRequest = {
  id: string;
  expectedRevision: number;
  expectedInventoryRevision: unknown;
  metadata: PasswordIdentityMetadata;
  credentialMutation: PasswordIdentityCredentialMutation;
};

export type DeletePasswordIdentityRequest = {
  id: string;
  expectedRevision: number;
  expectedInventoryRevision: unknown;
};

/** Renderer-safe result. Epochs, keyring accounts, locators, and key bytes stay in Rust. */
export type ManagedSshMasterKeyRotationResult = {
  status: "notInitialized" | "completed" | "completedCleanupPending";
  retainedSecretRevisionCount: number;
};

export type ProxyNetworkAuth =
  | { mode: "manual"; username: string; hasSavedCredential: boolean }
  | { mode: "identity"; identityId: string };

/** Renderer-safe proxy metadata. Command bodies never cross this boundary. */
export type ProxyProfileConfig =
  | { type: "http"; host: string; port: number; auth: ProxyNetworkAuth }
  | { type: "socks5"; host: string; port: number; auth: ProxyNetworkAuth }
  | { type: "command" };

export type ProxyProfile = {
  id: string;
  revision: number;
  label: string;
  config: ProxyProfileConfig;
  createdAt: number;
  updatedAt: number;
};

export type ProxyProfileCatalog = {
  inventoryRevision: unknown;
  profiles: ProxyProfile[];
};

export type ProxyProfileCredentialMutation =
  | { action: "keep" }
  | { action: "remove" }
  | { action: "replace"; stagedCredentialReference: string };

export type ProxyCommandMutation =
  | { action: "keep" }
  | { action: "replace"; command: string };

export type ProxyNetworkAuthRequest =
  | {
    mode: "manual";
    username: string;
    credentialMutation: ProxyProfileCredentialMutation;
  }
  | { mode: "identity"; identityId: string };

export type ProxyProfileConfigRequest =
  | { type: "http"; host: string; port: number; auth: ProxyNetworkAuthRequest }
  | { type: "socks5"; host: string; port: number; auth: ProxyNetworkAuthRequest }
  | { type: "command"; commandMutation: ProxyCommandMutation };

export type ProxyProfileMetadata = {
  label: string;
  config: ProxyProfileConfigRequest;
};

export type CreateProxyProfileRequest = {
  expectedInventoryRevision: unknown;
  metadata: ProxyProfileMetadata;
};

export type UpdateProxyProfileRequest = {
  id: string;
  expectedRevision: number;
  expectedInventoryRevision: unknown;
  metadata: ProxyProfileMetadata;
};

export type DeleteProxyProfileRequest = {
  id: string;
  expectedRevision: number;
  expectedInventoryRevision: unknown;
};

export type PortForwardType = "local" | "remote" | "dynamic";

/** Durable forwarding metadata. Runtime status and errors are intentionally separate. */
export type PortForwardRule = {
  id: string;
  label: string;
  type: PortForwardType;
  localPort: number;
  bindAddress: string;
  remoteHost?: string;
  remotePort?: number;
  hostId: string;
  autoStart: boolean;
  createdAt: number;
  lastUsedAt?: number;
  order?: number;
};

export type PortForwardRuntime = {
  ruleId: string;
  phase: "connecting" | "active" | "error";
  tunnelId?: string;
  address?: string;
  port?: number;
  error?: string;
};

export type PortForwardCatalog = {
  inventoryRevision: unknown;
  rules: PortForwardRule[];
  runtime: PortForwardRuntime[];
};

export type PortForwardRuleMetadata = {
  label: string;
  type: PortForwardType;
  localPort: number;
  bindAddress: string;
  remoteHost?: string;
  remotePort?: number;
  hostId: string;
  autoStart?: boolean;
  order?: number;
};

export type CreatePortForwardRuleRequest = {
  expectedInventoryRevision: unknown;
  metadata: PortForwardRuleMetadata;
};

export type UpdatePortForwardRuleRequest = CreatePortForwardRuleRequest & {
  id: string;
};

export type DeletePortForwardRuleRequest = {
  id: string;
  expectedInventoryRevision: unknown;
};

export type StartPortForwardRequest = {
  id: string;
  expectedInventoryRevision: unknown;
  credentialReference?: string;
  proxyCredentialReference?: string;
  keyPassphraseReference?: string;
  selectedIdentityFilePaths?: string[];
  knownHosts?: StartSshSessionRequest["knownHosts"];
  verifyHostKeys?: boolean;
};

export type StartPortForwardResult = {
  ruleId: string;
  tunnelId: string;
  address: string;
  port: number;
  catalog: PortForwardCatalog;
};

export type StopPortForwardRequest = {
  id: string;
};

/** Tri-state GroupConfig field used by the legacy root-to-leaf merge rules. */
export type GroupConfigOverride<T> =
  | { state: "inherit" }
  | { state: "clear" }
  | { state: "set"; value: T };

export type GroupConfigCredentialOverride = "inherit" | "clear" | "storedHint";

export type GroupConfigIdentityReference =
  | { type: "key"; id: string }
  | { type: "password"; id: string };

export type GroupConfigProxy =
  | {
    type: "http" | "socks5";
    host: string;
    port: number;
    identityId?: string;
    username: string;
    hasSavedCredential: boolean;
  }
  | { type: "command" };

export type GroupConfigProxyOverride =
  | { state: "inherit" }
  | { state: "clear" }
  | { state: "profile"; value: string }
  | { state: "inline"; value: GroupConfigProxy };

export type GroupConfigAlgorithmOverrides = {
  kex: string[] | null;
  cipher: string[] | null;
  hmac: string[] | null;
  serverHostKey: string[] | null;
  compress: string[] | null;
};

/** Renderer-safe GroupConfig state. Credential fields contain presence only. */
export type GroupConfigDefaults = {
  order: GroupConfigOverride<number>;
  username: GroupConfigOverride<string>;
  password: GroupConfigCredentialOverride;
  savePassword: GroupConfigOverride<boolean>;
  authMethod: GroupConfigOverride<"auto" | "password" | "key" | "certificate">;
  identityId: GroupConfigOverride<GroupConfigIdentityReference>;
  identityFileId: GroupConfigOverride<string>;
  identityFilePaths: GroupConfigOverride<string[]>;
  port: GroupConfigOverride<number>;
  protocol: GroupConfigOverride<"ssh" | "telnet">;
  deviceType: GroupConfigOverride<"general" | "network">;
  agentForwarding: GroupConfigOverride<boolean>;
  proxy: GroupConfigProxyOverride;
  hostChain: GroupConfigOverride<string[]>;
  startupCommand: GroupConfigOverride<string>;
  startupCommandRunMode: GroupConfigOverride<"lineDelay" | "paste">;
  loginScriptId: GroupConfigOverride<string>;
  legacyAlgorithms: GroupConfigOverride<boolean>;
  skipEcdsaHostKey: GroupConfigOverride<boolean>;
  algorithms: GroupConfigOverride<GroupConfigAlgorithmOverrides>;
  environmentVariables: GroupConfigOverride<Array<{ name: string; value: string }>>;
  charset: GroupConfigOverride<string>;
  moshEnabled: GroupConfigOverride<boolean>;
  moshServerPath: GroupConfigOverride<string>;
  etEnabled: GroupConfigOverride<boolean>;
  etPort: GroupConfigOverride<number>;
  telnetEnabled: GroupConfigOverride<boolean>;
  telnetPort: GroupConfigOverride<number>;
  telnetIdentityId: GroupConfigOverride<string>;
  telnetUsername: GroupConfigOverride<string>;
  telnetPassword: GroupConfigCredentialOverride;
  theme: GroupConfigOverride<string>;
  themeOverride: GroupConfigOverride<boolean>;
  fontFamily: GroupConfigOverride<string>;
  fontFamilyOverride: GroupConfigOverride<boolean>;
  fontSize: GroupConfigOverride<number>;
  fontSizeOverride: GroupConfigOverride<boolean>;
  fontWeight: GroupConfigOverride<number>;
  fontWeightOverride: GroupConfigOverride<boolean>;
  backspaceBehavior: GroupConfigOverride<"ctrl-h">;
};

export type GroupConfig = {
  id: string;
  revision: number;
  path: string;
  defaults: GroupConfigDefaults;
  createdAt: number;
  updatedAt: number;
};

export type GroupConfigCatalog = {
  inventoryRevision: unknown;
  customGroups: string[];
  groups: GroupConfig[];
};

/** Ordinary JSON can clear/inherit credentials but cannot forge stored hints. */
export type GroupConfigDefaultsRequest = Omit<
  Partial<GroupConfigDefaults>,
  "password" | "telnetPassword" | "proxy"
> & {
  password?: Exclude<GroupConfigCredentialOverride, "storedHint">;
  telnetPassword?: Exclude<GroupConfigCredentialOverride, "storedHint">;
  proxy?: Exclude<GroupConfigProxyOverride, { state: "inline" }> | {
    state: "inline";
    value:
      | Omit<Extract<GroupConfigProxy, { type: "http" | "socks5" }>, "hasSavedCredential"> & {
        hasSavedCredential?: false;
      }
      | Extract<GroupConfigProxy, { type: "command" }>;
  };
};

export type GroupConfigProxyCommandMutation =
  | { action: "keep" }
  | { action: "replace"; command: string };

export type GroupConfigMetadataRequest = {
  path: string;
  defaults: GroupConfigDefaultsRequest;
  proxyCommandMutation?: GroupConfigProxyCommandMutation;
};

export type CreateGroupConfigRequest = {
  expectedInventoryRevision: unknown;
  metadata: GroupConfigMetadataRequest;
  credentialMutations?: GroupConfigCredentialMutations;
};

export type GroupConfigCredentialHintActions = {
  sshPassword?: "useMetadata" | "keep";
  telnetPassword?: "useMetadata" | "keep";
  proxyPassword?: "useMetadata" | "keep";
};

/** Password bodies are staged over raw IPC; ordinary JSON carries only the one-shot reference. */
export type GroupConfigCredentialMutation =
  | { action: "keep" }
  | { action: "remove" }
  | { action: "replace"; stagedCredentialReference: string };

export type GroupConfigCredentialMutations = {
  sshPassword?: GroupConfigCredentialMutation;
  telnetPassword?: GroupConfigCredentialMutation;
  proxyPassword?: GroupConfigCredentialMutation;
};

export type UpdateGroupConfigRequest = {
  id: string;
  expectedRevision: number;
  expectedInventoryRevision: unknown;
  metadata: GroupConfigMetadataRequest;
  credentialHints?: GroupConfigCredentialHintActions;
  credentialMutations?: GroupConfigCredentialMutations;
};

export type DeleteGroupConfigRequest = {
  id: string;
  expectedRevision: number;
  expectedInventoryRevision: unknown;
};

export type LegacyVaultSourceKind =
  | "bareHostArray"
  | "unversionedVaultExport"
  | "backupPlainJsonV1"
  | "backupSafeStorageV1RequiresRecovery";

export type LegacyVaultImportIssueCode =
  | "LEGACY_SOURCE_RECOVERY_REQUIRED"
  | "LEGACY_HOST_REJECTED"
  | "LEGACY_HOST_UNSUPPORTED"
  | "LEGACY_DUPLICATE_HOST_ID"
  | "LEGACY_SECRET_MATERIAL_STRIPPED"
  | "LEGACY_ENCRYPTED_CREDENTIAL_REENTRY_REQUIRED"
  | "LEGACY_OVERSIZED_CREDENTIAL_REENTRY_REQUIRED"
  | "LEGACY_INVALID_CREDENTIAL_REENTRY_REQUIRED"
  | "LEGACY_MISSING_CREDENTIAL_REENTRY_REQUIRED"
  | "LEGACY_ADDITIONAL_CREDENTIAL_REENTRY_REQUIRED"
  | "LEGACY_PASSWORD_NOT_SAVED_BY_POLICY"
  | "LEGACY_NON_SSH_PASSWORD_REENTRY_REQUIRED"
  | "LEGACY_SSH_KEY_REJECTED"
  | "LEGACY_SSH_KEY_UNSUPPORTED"
  | "LEGACY_DUPLICATE_SSH_KEY_ID"
  | "LEGACY_SSH_KEY_CREDENTIAL_RECOVERY_REQUIRED"
  | "LEGACY_SSH_CERTIFICATE_UNSUPPORTED"
  | "LEGACY_IDENTITY_REJECTED"
  | "LEGACY_IDENTITY_UNSUPPORTED"
  | "LEGACY_DUPLICATE_IDENTITY_ID"
  | "LEGACY_IDENTITY_CREDENTIAL_REENTRY_REQUIRED"
  | "LEGACY_MISSING_SSH_KEY_REFERENCE"
  | "LEGACY_MISSING_IDENTITY_REFERENCE"
  | "LEGACY_INVALID_IDENTITY_FILE_PATHS";

export type LegacyVaultRecordKind = "source" | "host" | "sshKey" | "identity";

export type LegacyVaultImportIssue = {
  code: LegacyVaultImportIssueCode;
  message: string;
  recordKind: LegacyVaultRecordKind;
  recordIndex?: number;
};

export type LegacyVaultInspection = {
  sourceKind: LegacyVaultSourceKind;
  sourceFingerprint: string;
  inventoryRevision: unknown;
  sourceSshKeyCount: number;
  importableSshKeyReferenceCount: number;
  duplicateSshKeyReferenceCount: number;
  conflictSshKeyReferenceCount: number;
  sourceManagedSshKeyCount: number;
  importableManagedSshKeyCount: number;
  duplicateManagedSshKeyCount: number;
  conflictManagedSshKeyCount: number;
  managedSshKeyRecoveryRequiredCount: number;
  managedPassphrasesDiscardedByPolicyCount: number;
  unsupportedSshKeyCount: number;
  sourceIdentityCount: number;
  importableIdentityReferenceCount: number;
  duplicateIdentityReferenceCount: number;
  conflictIdentityReferenceCount: number;
  sourcePasswordIdentityCount: number;
  importablePasswordIdentityCount: number;
  duplicatePasswordIdentityCount: number;
  conflictPasswordIdentityCount: number;
  recoverablePasswordIdentityCredentialCount: number;
  passwordIdentityCredentialReentryRequiredCount: number;
  recoverableTelnetCredentialCount: number;
  telnetCredentialReentryRequiredCount: number;
  sourceProxyProfileCount: number;
  sourceInlineProxyHostCount: number;
  importableProxyProfileCount: number;
  duplicateProxyProfileCount: number;
  conflictProxyProfileCount: number;
  recoverableProxyProfileCredentialCount: number;
  recoverableInlineProxyCredentialCount: number;
  proxyProfileCredentialReentryRequiredCount: number;
  inlineProxyCredentialReentryRequiredCount: number;
  unsupportedProxyProfileCount: number;
  unsupportedIdentityCount: number;
  sourceCustomGroupCount: number;
  importableCustomGroupCount: number;
  duplicateCustomGroupCount: number;
  conflictCustomGroupCount: number;
  sourceGroupConfigCount: number;
  importableGroupConfigCount: number;
  duplicateGroupConfigCount: number;
  conflictGroupConfigCount: number;
  sourceSnippetCount: number;
  importableSnippetCount: number;
  duplicateSnippetCount: number;
  conflictSnippetCount: number;
  sourceSnippetPackageCount: number;
  importableSnippetPackageCount: number;
  duplicateSnippetPackageCount: number;
  sourceNoteCount: number;
  importableNoteCount: number;
  duplicateNoteCount: number;
  conflictNoteCount: number;
  sourceNoteGroupCount: number;
  importableNoteGroupCount: number;
  duplicateNoteGroupCount: number;
  catalogScopeChangeCount: number;
  remappedSnippetIdCount: number;
  remappedNoteIdCount: number;
  remappedHostScriptEdgeCount: number;
  remappedGroupScriptEdgeCount: number;
  remappedEntityCount: number;
  sourceCount: number;
  importableCount: number;
  duplicateCount: number;
  conflictCount: number;
  recoverableCredentialCount: number;
  requiresCredentialReentryCount: number;
  unsupportedCount: number;
  issues: LegacyVaultImportIssue[];
  omittedIssueCount: number;
};

export type InspectLegacyVaultRequest = {
  path: string;
};

export type CommitLegacyVaultImportRequest = {
  path: string;
  sourceFingerprint: string;
  inventoryRevision: unknown;
};

export type LegacyVaultImportResult = {
  importedCount: number;
  sshKeyReferencesImportedCount: number;
  managedSshKeysImportedCount: number;
  managedSecretBlobsPublishedCount: number;
  identityReferencesImportedCount: number;
  passwordIdentitiesImportedCount: number;
  remappedEntityCount: number;
  duplicateCount: number;
  conflictCount: number;
  credentialsStoredCount: number;
  telnetCredentialsStoredCount: number;
  telnetCredentialReentryRequiredCount: number;
  passwordIdentityCredentialsStoredCount: number;
  passwordIdentityCredentialReentryRequiredCount: number;
  proxyProfilesImportedCount: number;
  proxyProfileCredentialsStoredCount: number;
  inlineProxyCredentialsStoredCount: number;
  proxyCredentialReentryRequiredCount: number;
  customGroupsImportedCount: number;
  groupConfigsImportedCount: number;
  snippetsImportedCount: number;
  snippetPackagesImportedCount: number;
  notesImportedCount: number;
  noteGroupsImportedCount: number;
  requiresCredentialReentryCount: number;
};

export type SftpEntryKind = "file" | "directory" | "symlink" | "other";

export type SftpMetadata = {
  kind: SftpEntryKind;
  size: number;
  uid?: number;
  user?: string;
  gid?: number;
  group?: string;
  permissions?: number;
  accessedAt?: number;
  modifiedAt?: number;
};

export type SftpEntry = {
  name: string;
  path: string;
  metadata: SftpMetadata;
};

export type SftpArtifactPlan = {
  version: number;
  artifactId: string;
  targetPath: string;
  workspacePath: string;
  ownerPath: string;
  stagedPath: string;
  backupPath: string;
};

export type SftpUploadPlan = {
  targetPath: string;
  stagedPath: string;
  backupPath: string;
  artifacts?: SftpArtifactPlan;
};

export type SftpDownloadPlan = {
  artifacts: SftpArtifactPlan;
};

export type SftpTransferCheckpoint = {
  direction: "upload" | "download";
  remotePath: string;
  bytesTransferred: number;
  totalBytes: number;
  sourceFingerprint?: string;
  remoteModifiedAt?: number;
};

export type DirectoryResumeCheckpoint = {
  version: number;
  coveredEntries: number;
  completedEntries: number;
  manifestHash: string;
};

export type LocalTreeOptions = {
  followDirectorySymlinks?: boolean;
  maxDirectories?: number;
  maxEntries?: number;
};

export type RemoteTreeOptions = {
  followDirectorySymlinks?: boolean;
  maxDirectories?: number;
  maxEntries?: number;
};

export type SftpTransferEvent =
  | { type: "queued" }
  | { type: "started" }
  | { type: "progress"; bytesTransferred: number; totalBytes: number }
  | { type: "paused"; checkpoint?: SftpTransferCheckpoint }
  | { type: "resumed" }
  | {
    type: "completed";
    checkpoint: SftpTransferCheckpoint;
    replacedExisting: boolean;
  }
  | { type: "cancelled"; checkpoint?: SftpTransferCheckpoint }
  | {
    type: "failed";
    code: string;
    message: string;
    checkpoint?: SftpTransferCheckpoint;
  }
  | { type: "directoryScanning" }
  | {
    type: "directoryProgress";
    filesCompleted: number;
    totalFiles: number;
    bytesTransferred: number;
    totalBytes: number;
    currentPath: string | null;
    checkpoint: DirectoryResumeCheckpoint;
  }
  | {
    type: "directoryCompleted";
    filesCompleted: number;
    totalBytes: number;
    skippedEntries: number;
    checkpoint: DirectoryResumeCheckpoint;
  }
  | { type: "directoryCancelled"; checkpoint: DirectoryResumeCheckpoint }
  | {
    type: "directoryFailed";
    message: string;
    failedFiles: number;
    checkpoint: DirectoryResumeCheckpoint;
  };

export type SftpTransferHandle = {
  transferId: string;
  plan: SftpUploadPlan;
  eventChannel: Channel<SftpTransferEvent>;
};

export type SftpDownloadHandle = {
  transferId: string;
  plan: SftpDownloadPlan;
  eventChannel: Channel<SftpTransferEvent>;
};

export type SftpDirectoryTransferHandle = {
  transferId: string;
  eventChannel: Channel<SftpTransferEvent>;
};

export type LocalTransferSourceKind = "file" | "directory";

export type StartSshSessionRequest = {
  clientAttemptId: string;
  config: SshConnectionConfig;
  credentialReference: string;
  knownHosts?: Array<{
    id: string;
    hostname: string;
    port?: number;
    keyType?: string;
    fingerprint?: string;
    publicKey?: string;
  }>;
  verifyHostKeys?: boolean;
  shell?: {
    terminal: string;
    size: TerminalSize;
    environment: Array<[string, string]>;
  };
};

export type StartSavedHostSessionRequest = {
  clientAttemptId: string;
  hostId: string;
  expectedRevision: number;
  credentialReference?: string;
  proxyCredentialReference?: string;
  keyPassphraseReference?: string;
  selectedIdentityFilePaths?: string[];
  knownHosts?: StartSshSessionRequest["knownHosts"];
  verifyHostKeys?: boolean;
  shell?: StartSshSessionRequest["shell"];
};

/**
 * Opens one independent shell over an already-authenticated SSH transport.
 * The native boundary intentionally accepts no host, revision, or credential
 * fields, so split panes cannot silently reconnect or repeat authentication.
 */
export type CloneSshSessionRequest = {
  sourceSessionId: string;
  shell?: StartSshSessionRequest["shell"];
};

export type StartSavedTelnetSessionRequest = {
  hostId: string;
  expectedRevision: number;
  credentialReference?: string;
  terminal?: string;
  size: TerminalSize;
};

export type StartTelnetSessionRequest = {
  hostname: string;
  port?: number;
  /** Omission enables manual login; an empty value remains an explicit username line. */
  username?: string;
  credentialReference?: string;
  terminal?: string;
  size: TerminalSize;
  charset?: string;
  startupCommand?: string;
};

export type StartSerialSessionRequest = {
  config: SerialConfig;
  size: TerminalSize;
  charset?: string;
};

export type StartSavedSerialSessionRequest = {
  hostId: string;
  expectedRevision: number;
  size: TerminalSize;
};

export type StartLocalPtySessionRequest = {
  shellId?: string;
  cwd?: string;
  columns: number;
  rows: number;
  environment?: {
    term?: string;
    colorTerm?: string;
  };
};

export type StartMoshSessionRequest = {
  config: SshConnectionConfig;
  credentialReference: string;
  knownHosts?: StartSshSessionRequest["knownHosts"];
  verifyHostKeys?: boolean;
  size: TerminalSize;
};

export type StartSavedMoshSessionRequest = {
  hostId: string;
  expectedRevision: number;
  credentialReference?: string;
  proxyCredentialReference?: string;
  keyPassphraseReference?: string;
  selectedIdentityFilePaths?: string[];
  knownHosts?: StartSshSessionRequest["knownHosts"];
  verifyHostKeys?: boolean;
  size: TerminalSize;
};

export type StartEtSessionRequest = {
  hostId: string;
  columns: number;
  rows: number;
};

export const getBackendStatus = (): Promise<BackendStatus> =>
  invoke<BackendStatus>("get_backend_status");

export const validateSshConnection = (
  config: SshConnectionConfig,
): Promise<SshValidationResult> =>
  invoke<SshValidationResult>("validate_ssh_connection", { config });

export const stageSshPassword = async (password: string): Promise<string> => {
  const payload = new TextEncoder().encode(password);
  try {
    return await invoke<string>("stage_ssh_password", payload);
  } finally {
    payload.fill(0);
  }
};

export const stageTelnetPassword = async (password: string): Promise<string> => {
  const payload = new TextEncoder().encode(password);
  try {
    return await invoke<string>("stage_telnet_password", payload);
  } finally {
    payload.fill(0);
  }
};

export const stageSshKeyPassphrase = async (passphrase: string): Promise<string> => {
  const payload = new TextEncoder().encode(passphrase);
  try {
    return await invoke<string>("stage_ssh_key_passphrase", payload);
  } finally {
    payload.fill(0);
  }
};

const stageRawGroupPassword = async (
  command:
    | "stage_group_ssh_password"
    | "stage_group_telnet_password"
    | "stage_group_proxy_password",
  password: string,
): Promise<string> => {
  const payload = new TextEncoder().encode(password);
  try {
    return await invoke<string>(command, payload);
  } finally {
    payload.fill(0);
  }
};

export const stageGroupSshPassword = (password: string): Promise<string> =>
  stageRawGroupPassword("stage_group_ssh_password", password);

export const stageGroupTelnetPassword = (password: string): Promise<string> =>
  stageRawGroupPassword("stage_group_telnet_password", password);

export const stageGroupProxyPassword = (password: string): Promise<string> =>
  stageRawGroupPassword("stage_group_proxy_password", password);

export const listSavedHosts = (): Promise<SavedHost[]> =>
  invoke<SavedHost[]>("list_saved_hosts");

export const listSerialPorts = (): Promise<SerialPortInfo[]> =>
  invoke<SerialPortInfo[]>("list_serial_ports");

export const listLocalShells = (): Promise<DiscoveredLocalShell[]> =>
  invoke<DiscoveredLocalShell[]>("list_local_shells");

export const createSavedHost = (request: CreateSavedHostRequest): Promise<SavedHost> =>
  invoke<SavedHost>("create_saved_host", { request });

export const updateSavedHost = (request: UpdateSavedHostRequest): Promise<SavedHost> =>
  invoke<SavedHost>("update_saved_host", { request });

export const deleteSavedHost = (request: DeleteSavedHostRequest): Promise<void> =>
  invoke("delete_saved_host", { request });

export const listManagedSshKeys = (): Promise<ManagedSshKeyCatalog> =>
  invoke<ManagedSshKeyCatalog>("list_managed_ssh_keys");

/**
 * Stages one private-key bundle through Tauri's raw request body. This is the
 * only frontend API that accepts key, certificate, or passphrase bytes.
 */
export const stageManagedSshKeyBundle = (
  bundle: ManagedSshKeyBundleBytes,
): Promise<string> => withZeroizedManagedSshKeyBundle(
  bundle,
  (envelope) => invoke<string>("stage_managed_ssh_key_bundle", envelope),
);

export const createManagedSshKey = (
  request: CreateManagedSshKeyRequest,
): Promise<ManagedSshKeyCatalog> =>
  invoke<ManagedSshKeyCatalog>("create_managed_ssh_key", { request });

export const updateManagedSshKey = (
  request: UpdateManagedSshKeyRequest,
): Promise<ManagedSshKeyCatalog> =>
  invoke<ManagedSshKeyCatalog>("update_managed_ssh_key", { request });

export const deleteManagedSshKey = (
  request: DeleteManagedSshKeyRequest,
): Promise<ManagedSshKeyCatalog> =>
  invoke<ManagedSshKeyCatalog>("delete_managed_ssh_key", { request });

export const listPasswordIdentities = (): Promise<PasswordIdentityCatalog> =>
  invoke<PasswordIdentityCatalog>("list_password_identities");

export const createPasswordIdentity = (
  request: CreatePasswordIdentityRequest,
): Promise<PasswordIdentityCatalog> =>
  invoke<PasswordIdentityCatalog>("create_password_identity", { request });

export const updatePasswordIdentity = (
  request: UpdatePasswordIdentityRequest,
): Promise<PasswordIdentityCatalog> =>
  invoke<PasswordIdentityCatalog>("update_password_identity", { request });

export const deletePasswordIdentity = (
  request: DeletePasswordIdentityRequest,
): Promise<PasswordIdentityCatalog> =>
  invoke<PasswordIdentityCatalog>("delete_password_identity", { request });

export const listProxyProfiles = (): Promise<ProxyProfileCatalog> =>
  invoke<ProxyProfileCatalog>("list_proxy_profiles");

export const createProxyProfile = (
  request: CreateProxyProfileRequest,
): Promise<ProxyProfileCatalog> =>
  invoke<ProxyProfileCatalog>("create_proxy_profile", { request });

export const updateProxyProfile = (
  request: UpdateProxyProfileRequest,
): Promise<ProxyProfileCatalog> =>
  invoke<ProxyProfileCatalog>("update_proxy_profile", { request });

export const deleteProxyProfile = (
  request: DeleteProxyProfileRequest,
): Promise<ProxyProfileCatalog> =>
  invoke<ProxyProfileCatalog>("delete_proxy_profile", { request });

export const listPortForwardRules = (): Promise<PortForwardCatalog> =>
  invoke<PortForwardCatalog>("list_port_forward_rules");

export const createPortForwardRule = (
  request: CreatePortForwardRuleRequest,
): Promise<PortForwardCatalog> =>
  invoke<PortForwardCatalog>("create_port_forward_rule", { request });

export const updatePortForwardRule = (
  request: UpdatePortForwardRuleRequest,
): Promise<PortForwardCatalog> =>
  invoke<PortForwardCatalog>("update_port_forward_rule", { request });

export const deletePortForwardRule = (
  request: DeletePortForwardRuleRequest,
): Promise<PortForwardCatalog> =>
  invoke<PortForwardCatalog>("delete_port_forward_rule", { request });

export const startPortForward = (
  request: StartPortForwardRequest,
): Promise<StartPortForwardResult> =>
  invoke<StartPortForwardResult>("start_port_forward", { request });

export const stopPortForward = (
  request: StopPortForwardRequest,
): Promise<PortForwardCatalog> =>
  invoke<PortForwardCatalog>("stop_port_forward", { request });

export const listGroupConfigs = (): Promise<GroupConfigCatalog> =>
  invoke<GroupConfigCatalog>("list_group_configs");

export const createGroupConfig = (
  request: CreateGroupConfigRequest,
): Promise<GroupConfigCatalog> =>
  invoke<GroupConfigCatalog>("create_group_config", { request });

export const updateGroupConfig = (
  request: UpdateGroupConfigRequest,
): Promise<GroupConfigCatalog> =>
  invoke<GroupConfigCatalog>("update_group_config", { request });

export const deleteGroupConfig = (
  request: DeleteGroupConfigRequest,
): Promise<GroupConfigCatalog> =>
  invoke<GroupConfigCatalog>("delete_group_config", { request });

export const rotateManagedSshMasterKey = (): Promise<ManagedSshMasterKeyRotationResult> =>
  invoke<ManagedSshMasterKeyRotationResult>("rotate_managed_ssh_master_key");

export const inspectLegacyVault = (
  request: InspectLegacyVaultRequest,
): Promise<LegacyVaultInspection> =>
  invoke<LegacyVaultInspection>("inspect_legacy_vault", { request });

export const commitLegacyVaultImport = (
  request: CommitLegacyVaultImportRequest,
): Promise<LegacyVaultImportResult> =>
  invoke<LegacyVaultImportResult>("commit_legacy_vault_import", { request });

const startSessionWithChannels = async (
  command:
    | "start_ssh_session"
    | "clone_ssh_session"
    | "start_saved_host_session"
    | "start_saved_telnet_session"
    | "start_telnet_session"
    | "start_saved_serial_session"
    | "start_serial_session"
    | "start_local_pty_session"
    | "start_mosh_session"
    | "start_saved_mosh_session"
    | "start_et_session",
  request:
    | StartSshSessionRequest
    | CloneSshSessionRequest
    | StartSavedHostSessionRequest
    | StartSavedTelnetSessionRequest
    | StartTelnetSessionRequest
    | StartSavedSerialSessionRequest
    | StartSerialSessionRequest
    | StartLocalPtySessionRequest
    | StartMoshSessionRequest
    | StartSavedMoshSessionRequest
    | StartEtSessionRequest,
  callbacks: SshSessionCallbacks,
): Promise<SshSessionHandle> => {
  const onControl = new Channel<SshControlEvent>();
  onControl.onmessage = callbacks.onControl;
  const onData = new Channel<ArrayBuffer>();
  onData.onmessage = (frame) => callbacks.onData(new Uint8Array(frame));
  const dispose = () => {
    onControl.onmessage = () => {};
    onData.onmessage = () => {};
  };
  let result: { sessionId: string };
  try {
    result = await invoke<{ sessionId: string }>(command, {
      request,
      onControl,
      onData,
    });
  } catch (reason) {
    dispose();
    throw reason;
  }
  return {
    sessionId: result.sessionId,
    controlChannel: onControl,
    dataChannel: onData,
    dispose,
  };
};

export const startSshSession = async (
  request: StartSshSessionRequest,
  callbacks: SshSessionCallbacks,
): Promise<SshSessionHandle> => startSessionWithChannels("start_ssh_session", request, callbacks);

export const cloneSshSession = async (
  request: CloneSshSessionRequest,
  callbacks: SshSessionCallbacks,
): Promise<SshSessionHandle> => startSessionWithChannels("clone_ssh_session", request, callbacks);

export const startSavedHostSession = async (
  request: StartSavedHostSessionRequest,
  callbacks: SshSessionCallbacks,
): Promise<SshSessionHandle> => (
  startSessionWithChannels("start_saved_host_session", request, callbacks)
);

export const startSavedTelnetSession = async (
  request: StartSavedTelnetSessionRequest,
  callbacks: SshSessionCallbacks,
): Promise<SshSessionHandle> => (
  startSessionWithChannels("start_saved_telnet_session", request, callbacks)
);

export const startTelnetSession = async (
  request: StartTelnetSessionRequest,
  callbacks: SshSessionCallbacks,
): Promise<SshSessionHandle> => startSessionWithChannels("start_telnet_session", request, callbacks);

export const startSavedSerialSession = async (
  request: StartSavedSerialSessionRequest,
  callbacks: SshSessionCallbacks,
): Promise<SshSessionHandle> => (
  startSessionWithChannels("start_saved_serial_session", request, callbacks)
);

export const startSerialSession = async (
  request: StartSerialSessionRequest,
  callbacks: SshSessionCallbacks,
): Promise<SshSessionHandle> => startSessionWithChannels("start_serial_session", request, callbacks);

export const startLocalPtySession = async (
  request: StartLocalPtySessionRequest,
  callbacks: SshSessionCallbacks,
): Promise<SshSessionHandle> => startSessionWithChannels("start_local_pty_session", request, callbacks);

export const startMoshSession = async (
  request: StartMoshSessionRequest,
  callbacks: SshSessionCallbacks,
): Promise<SshSessionHandle> => startSessionWithChannels("start_mosh_session", request, callbacks);

export const startSavedMoshSession = async (
  request: StartSavedMoshSessionRequest,
  callbacks: SshSessionCallbacks,
): Promise<SshSessionHandle> => (
  startSessionWithChannels("start_saved_mosh_session", request, callbacks)
);

export const startEtSession = async (
  request: StartEtSessionRequest,
  callbacks: SshSessionCallbacks,
): Promise<SshSessionHandle> => startSessionWithChannels("start_et_session", request, callbacks);

const sendRawSessionInput = (
  command:
    | "ssh_session_input_raw"
    | "telnet_session_input_raw"
    | "serial_session_input_raw"
    | "local_pty_session_input_raw"
    | "mosh_session_input_raw"
    | "et_session_input_raw",
  sessionId: string,
  data: Uint8Array,
): Promise<void> => {
  const id = new TextEncoder().encode(sessionId);
  const envelope = new Uint8Array(2 + id.length + data.length);
  new DataView(envelope.buffer).setUint16(0, id.length);
  envelope.set(id, 2);
  envelope.set(data, 2 + id.length);
  return invoke(command, envelope);
};

export const sendSshInput = (sessionId: string, data: Uint8Array): Promise<void> =>
  sendRawSessionInput("ssh_session_input_raw", sessionId, data);

export const sendTelnetInput = (sessionId: string, data: Uint8Array): Promise<void> =>
  sendRawSessionInput("telnet_session_input_raw", sessionId, data);

export const sendSerialInput = (sessionId: string, data: Uint8Array): Promise<void> =>
  sendRawSessionInput("serial_session_input_raw", sessionId, data);

export const sendLocalPtyInput = (sessionId: string, data: Uint8Array): Promise<void> =>
  sendRawSessionInput("local_pty_session_input_raw", sessionId, data);

export const sendMoshInput = (sessionId: string, data: Uint8Array): Promise<void> =>
  sendRawSessionInput("mosh_session_input_raw", sessionId, data);

export const sendEtInput = (sessionId: string, data: Uint8Array): Promise<void> =>
  sendRawSessionInput("et_session_input_raw", sessionId, data);

export const resizeSshSession = (sessionId: string, size: TerminalSize): Promise<void> =>
  invoke("resize_ssh_session", { sessionId, size });

export const closeSshSession = (sessionId: string): Promise<void> =>
  invoke("close_ssh_session", { sessionId });

export const cancelSshSession = (sessionId: string): Promise<void> =>
  invoke("cancel_ssh_session", { sessionId });

export const resizeTelnetSession = (sessionId: string, size: TerminalSize): Promise<void> =>
  invoke("resize_telnet_session", { sessionId, size });

export const closeTelnetSession = (sessionId: string): Promise<void> =>
  invoke("close_telnet_session", { sessionId });

export const cancelTelnetSession = (sessionId: string): Promise<void> =>
  invoke("cancel_telnet_session", { sessionId });

export const resizeSerialSession = (sessionId: string, size: TerminalSize): Promise<void> =>
  invoke("resize_serial_session", { sessionId, size });

export const closeSerialSession = (sessionId: string): Promise<void> =>
  invoke("close_serial_session", { sessionId });

export const cancelSerialSession = (sessionId: string): Promise<void> =>
  invoke("cancel_serial_session", { sessionId });

const runSerialYmodemCommand = async <T>(
  command: "send_serial_ymodem" | "receive_serial_ymodem",
  sessionId: string,
  locale: Locale,
  onProgress: (event: SerialYmodemProgressEvent) => void,
): Promise<T> => {
  const progressChannel = new Channel<SerialYmodemProgressEvent>();
  progressChannel.onmessage = onProgress;
  try {
    return await invoke<T>(command, { sessionId, locale, onProgress: progressChannel });
  } finally {
    progressChannel.onmessage = () => {};
  }
};

export const sendSerialYmodem = (
  sessionId: string,
  locale: Locale,
  onProgress: (event: SerialYmodemProgressEvent) => void,
): Promise<SendSerialYmodemResponse> => (
  runSerialYmodemCommand("send_serial_ymodem", sessionId, locale, onProgress)
);

export const receiveSerialYmodem = (
  sessionId: string,
  locale: Locale,
  onProgress: (event: SerialYmodemProgressEvent) => void,
): Promise<ReceiveSerialYmodemResponse> => (
  runSerialYmodemCommand("receive_serial_ymodem", sessionId, locale, onProgress)
);

export const cancelSerialYmodem = (sessionId: string, transferId: string): Promise<void> =>
  invoke("cancel_serial_ymodem", { sessionId, transferId });

export const startSerialZmodem = async (
  sessionId: string,
  transferId: string,
  direction: SerialZmodemDirection,
  locale: Locale,
  onControl: (event: SshControlEvent) => void,
): Promise<SerialZmodemResponse> => {
  const controlChannel = new Channel<SshControlEvent>();
  controlChannel.onmessage = onControl;
  try {
    return await invoke<SerialZmodemResponse>("start_serial_zmodem", {
      request: { sessionId, transferId, direction, locale },
      onControl: controlChannel,
    });
  } finally {
    controlChannel.onmessage = () => {};
  }
};

export const cancelSerialZmodem = (sessionId: string, transferId: string): Promise<void> =>
  invoke("cancel_serial_zmodem", { sessionId, transferId });

export const resizeLocalPtySession = (sessionId: string, size: TerminalSize): Promise<void> =>
  invoke("resize_local_pty_session", { sessionId, size });

export const closeLocalPtySession = (sessionId: string): Promise<void> =>
  invoke("close_local_pty_session", { sessionId });

export const cancelLocalPtySession = (sessionId: string): Promise<void> =>
  invoke("cancel_local_pty_session", { sessionId });

export const resizeMoshSession = (sessionId: string, size: TerminalSize): Promise<void> =>
  invoke("resize_mosh_session", { sessionId, size });

export const closeMoshSession = (sessionId: string): Promise<void> =>
  invoke("close_mosh_session", { sessionId });

export const cancelMoshSession = (sessionId: string): Promise<void> =>
  invoke("cancel_mosh_session", { sessionId });

export const resizeEtSession = (sessionId: string, size: TerminalSize): Promise<void> =>
  invoke("resize_et_session", { sessionId, size });

export const closeEtSession = (sessionId: string): Promise<void> =>
  invoke("close_et_session", { sessionId });

export const cancelEtSession = (sessionId: string): Promise<void> =>
  invoke("cancel_et_session", { sessionId });

export const readSftpDirectory = (sessionId: string, path: string): Promise<SftpEntry[]> =>
  invoke<SftpEntry[]>("sftp_read_dir", { sessionId, path });

export const getSftpMetadata = (sessionId: string, path: string): Promise<SftpMetadata> =>
  invoke<SftpMetadata>("sftp_metadata", { sessionId, path });

export const createSftpDirectory = (sessionId: string, path: string): Promise<void> =>
  invoke("sftp_create_dir", { sessionId, path });

export const removeSftpFile = (sessionId: string, path: string): Promise<void> =>
  invoke("sftp_remove_file", { sessionId, path });

export const removeSftpDirectory = (sessionId: string, path: string): Promise<void> =>
  invoke("sftp_remove_dir", { sessionId, path });

export const renameSftpPath = (
  sessionId: string,
  source: string,
  destination: string,
): Promise<void> => invoke("sftp_rename", { sessionId, source, destination });

export const readSftpFile = async (sessionId: string, path: string): Promise<Uint8Array> => {
  const response = await invoke<ArrayBuffer>("sftp_read_file", { sessionId, path });
  return new Uint8Array(response);
};

export const replaceSftpFileIfUnchanged = (
  sessionId: string,
  path: string,
  expected: Uint8Array,
  data: Uint8Array,
): Promise<void> => {
  const encoder = new TextEncoder();
  const id = encoder.encode(sessionId);
  const remotePath = encoder.encode(path);
  const envelope = new Uint8Array(
    2 + id.length + 4 + remotePath.length + 4 + expected.length + data.length,
  );
  const view = new DataView(envelope.buffer);
  let offset = 0;
  view.setUint16(offset, id.length);
  offset += 2;
  envelope.set(id, offset);
  offset += id.length;
  view.setUint32(offset, remotePath.length);
  offset += 4;
  envelope.set(remotePath, offset);
  offset += remotePath.length;
  view.setUint32(offset, expected.length);
  offset += 4;
  envelope.set(expected, offset);
  offset += expected.length;
  envelope.set(data, offset);
  return invoke("sftp_replace_file_if_unchanged_raw", envelope);
};

export const startSftpUpload = async (
  sessionId: string,
  localPath: string,
  remotePath: string,
  onEvent: (event: SftpTransferEvent) => void,
  resume?: { plan: SftpUploadPlan; checkpoint: SftpTransferCheckpoint },
): Promise<SftpTransferHandle> => {
  const onEventChannel = new Channel<SftpTransferEvent>();
  onEventChannel.onmessage = onEvent;
  const started = await invoke<{ transferId: string; plan: SftpUploadPlan }>(
    "start_sftp_upload",
    {
      sessionId,
      localPath,
      remotePath,
      plan: resume?.plan,
      checkpoint: resume?.checkpoint,
      onEvent: onEventChannel,
    },
  );
  return { ...started, eventChannel: onEventChannel };
};

export const classifyLocalTransferSource = (localPath: string): Promise<LocalTransferSourceKind> =>
  invoke("classify_local_transfer_source", { localPath });

export const startSftpUploadDirectory = async (
  sessionId: string,
  localRoot: string,
  remoteRoot: string,
  options: LocalTreeOptions | undefined,
  resume: DirectoryResumeCheckpoint | undefined,
  onEvent: (event: SftpTransferEvent) => void,
): Promise<SftpDirectoryTransferHandle> => {
  const onEventChannel = new Channel<SftpTransferEvent>();
  onEventChannel.onmessage = onEvent;
  const started = await invoke<{ transferId: string }>("start_sftp_upload_directory", {
    sessionId,
    localRoot,
    remoteRoot,
    options,
    resume,
    onEvent: onEventChannel,
  });
  return { ...started, eventChannel: onEventChannel };
};

export const startSftpDownload = async (
  sessionId: string,
  remotePath: string,
  localPath: string,
  onEvent: (event: SftpTransferEvent) => void,
  resume?: { plan: SftpDownloadPlan; checkpoint: SftpTransferCheckpoint },
): Promise<SftpDownloadHandle> => {
  const onEventChannel = new Channel<SftpTransferEvent>();
  onEventChannel.onmessage = onEvent;
  const started = await invoke<{ transferId: string; plan: SftpDownloadPlan }>(
    "start_sftp_download",
    {
      sessionId,
      remotePath,
      localPath,
      plan: resume?.plan,
      checkpoint: resume?.checkpoint,
      onEvent: onEventChannel,
    },
  );
  return { ...started, eventChannel: onEventChannel };
};

export const startSftpDownloadDirectory = async (
  sessionId: string,
  remoteRoot: string,
  localRoot: string,
  options: RemoteTreeOptions | undefined,
  resume: DirectoryResumeCheckpoint | undefined,
  onEvent: (event: SftpTransferEvent) => void,
): Promise<SftpDirectoryTransferHandle> => {
  const onEventChannel = new Channel<SftpTransferEvent>();
  onEventChannel.onmessage = onEvent;
  const started = await invoke<{ transferId: string }>("start_sftp_download_directory", {
    sessionId,
    remoteRoot,
    localRoot,
    options,
    resume,
    onEvent: onEventChannel,
  });
  return { ...started, eventChannel: onEventChannel };
};

export const pauseSftpTransfer = (transferId: string): Promise<void> =>
  invoke("pause_sftp_transfer", { transferId });

export const resumeSftpTransfer = (transferId: string): Promise<void> =>
  invoke("resume_sftp_transfer", { transferId });

export const cancelSftpTransfer = (transferId: string): Promise<void> =>
  invoke("cancel_sftp_transfer", { transferId });

export const subscribeHostKeyPrompts = async (
  listener: (prompt: HostKeyPrompt) => void,
): Promise<Channel<HostKeyPrompt>> => {
  const onPrompt = new Channel<HostKeyPrompt>();
  onPrompt.onmessage = listener;
  await invoke("subscribe_host_key_prompts", { onPrompt });
  return onPrompt;
};

export const respondToHostKey = (requestId: string, accept: boolean): Promise<void> =>
  invoke("respond_to_host_key", { requestId, accept });

export const subscribeInteractivePrompts = async (
  listener: (prompt: InteractivePrompt) => void,
): Promise<Channel<InteractivePrompt>> => {
  const onPrompt = new Channel<InteractivePrompt>();
  onPrompt.onmessage = listener;
  await invoke("subscribe_interactive_prompts", { onPrompt });
  return onPrompt;
};

export const respondToInteractiveAuth = (
  requestId: string,
  answers: string[],
): Promise<void> => {
  const encoder = new TextEncoder();
  const request = encoder.encode(requestId);
  const encodedAnswers = answers.map((answer) => encoder.encode(answer));
  const length = 2 + request.length + 2
    + encodedAnswers.reduce((total, answer) => total + 4 + answer.length, 0);
  const envelope = new Uint8Array(length);
  const view = new DataView(envelope.buffer);
  let offset = 0;
  view.setUint16(offset, request.length);
  offset += 2;
  envelope.set(request, offset);
  offset += request.length;
  view.setUint16(offset, encodedAnswers.length);
  offset += 2;
  for (const answer of encodedAnswers) {
    view.setUint32(offset, answer.length);
    offset += 4;
    envelope.set(answer, offset);
    offset += answer.length;
  }
  return invoke("respond_to_interactive_auth", envelope);
};

export const cancelInteractiveAuth = (requestId: string): Promise<void> =>
  invoke("cancel_interactive_auth", { requestId });

/* -----------------------------------------------------------------------
 * Remote system management
 *
 * Every call runs on a second channel of the session's existing SSH
 * connection, never by typing into the user's shell. Command construction,
 * privilege escalation and output parsing all live in Rust; the renderer
 * only names an operation and a target.
 * --------------------------------------------------------------------- */

export type DockerContainer = Readonly<{
  id: string;
  names: string;
  image: string;
  command: string;
  createdAt: string;
  status: string;
  state: string;
  ports: string;
  networks: string;
}>;

export type DockerImage = Readonly<{
  id: string;
  repository: string;
  tag: string;
  createdSince: string;
  size: string;
}>;

export type DockerStat = Readonly<{
  id: string;
  name: string;
  cpuPercent: string;
  memoryUsage: string;
  memoryPercent: string;
  netIo: string;
  blockIo: string;
  pids: string;
}>;

export type DockerInspectState = Readonly<{
  status: string;
  running: boolean;
  paused: boolean;
  restarting: boolean;
  oomKilled: boolean;
  dead: boolean;
  exitCode: number | null;
  startedAt: string;
  finishedAt: string;
}>;

export type DockerInspectRestart = Readonly<{
  policy: string;
  maximumRetryCount: number | null;
  currentRestartCount: number | null;
}>;

export type DockerInspectPortBinding = Readonly<{
  containerPort: string;
  hostIp: string;
  hostPort: string;
}>;

export type DockerInspectNetworkAttachment = Readonly<{
  name: string;
  networkId: string;
  endpointId: string;
  gateway: string;
  ipAddress: string;
  ipPrefixLen: number | null;
  globalIpv6Address: string;
  globalIpv6PrefixLen: number | null;
  macAddress: string;
}>;

export type DockerInspectNetwork = Readonly<{
  mode: string;
  ipAddress: string;
  gateway: string;
  macAddress: string;
  publishedPorts: readonly DockerInspectPortBinding[];
  attachments: readonly DockerInspectNetworkAttachment[];
}>;

export type DockerInspectMount = Readonly<{
  type: string;
  name: string;
  destination: string;
  mode: string;
  readOnly: boolean;
  propagation: string;
}>;

/** Strict renderer-safe allowlist; this is never Docker's raw inspect JSON. */
export type DockerContainerInspect = Readonly<{
  id: string;
  name: string;
  image: string;
  created: string;
  state: DockerInspectState;
  restart: DockerInspectRestart;
  network: DockerInspectNetwork;
  mounts: readonly DockerInspectMount[];
}>;

export type DockerContainerAction =
  | "start"
  | "stop"
  | "restart"
  | "pause"
  | "unpause"
  | "remove";

export const listDockerContainers = (sessionId: string): Promise<DockerContainer[]> =>
  invoke("list_docker_containers", { sessionId });

export const listDockerImages = (sessionId: string): Promise<DockerImage[]> =>
  invoke("list_docker_images", { sessionId });

export const getDockerStats = (sessionId: string, ids: readonly string[]): Promise<DockerStat[]> =>
  invoke("get_docker_stats", { sessionId, ids });

export const inspectDockerContainer = (
  sessionId: string,
  containerId: string,
): Promise<DockerContainerInspect> =>
  invoke("inspect_docker_container", { sessionId, containerId });

export const runDockerContainerAction = (
  sessionId: string,
  containerId: string,
  action: DockerContainerAction,
): Promise<void> => invoke("run_docker_container_action", { sessionId, containerId, action });

export type RemoteProcess = Readonly<{
  pid: number;
  parentPid: number;
  user: string;
  state: string;
  cpuPercent: string;
  memoryPercent: string;
  residentKib: number;
  elapsed: string;
  command: string;
  /** Opaque native-issued identity token; never display or modify it. */
  startTimeToken: string;
}>;

export type ListeningPort = Readonly<{
  protocol: string;
  localAddress: string;
  port: string;
  process: string;
}>;

export type SystemService = Readonly<{
  unit: string;
  loadState: string;
  activeState: string;
  subState: string;
  description: string;
}>;

export type ProcessSignal = "term" | "hup" | "kill";
export type ServiceAction = "start" | "stop" | "restart" | "enable" | "disable";

export type NvidiaGpu = Readonly<{
  index: number;
  uuid: string;
  name: string;
  utilizationPercent: number | null;
  memoryUsedMib: number | null;
  memoryTotalMib: number | null;
  temperatureC: number | null;
  powerDrawW: number | null;
  powerLimitW: number | null;
  fanPercent: number | null;
  driverVersion: string | null;
}>;

export type SystemOverview = Readonly<{
  hostname: string | null;
  osName: string | null;
  kernelRelease: string | null;
  uptimeSeconds: number | null;
  loadAverage: readonly [number, number, number] | null;
  cpuCount: number | null;
  memoryTotalBytes: number | null;
  memoryUsedBytes: number | null;
  rootDiskTotalBytes: number | null;
  rootDiskUsedBytes: number | null;
}>;

export type TmuxSession = Readonly<{
  name: string;
  windows: number;
  attached: boolean;
  created: number | null;
  lastActivity: number | null;
}>;

/**
 * Attaching requires a newly owned remote PTY and cannot run through the
 * bounded `exec_capture` channel used by System Manager. Keep that boundary
 * explicit until the terminal registry can own such a session end to end.
 */
export const listRemoteProcesses = (sessionId: string): Promise<RemoteProcess[]> =>
  invoke("list_remote_processes", { sessionId });

export const listListeningPorts = (sessionId: string): Promise<ListeningPort[]> =>
  invoke("list_listening_ports", { sessionId });

export const listSystemServices = (sessionId: string): Promise<SystemService[]> =>
  invoke("list_system_services", { sessionId });

export const listNvidiaGpus = (sessionId: string): Promise<NvidiaGpu[]> =>
  invoke("list_nvidia_gpus", { sessionId });

export const getSystemOverview = (sessionId: string): Promise<SystemOverview> =>
  invoke("get_system_overview", { sessionId });

export const listTmuxSessions = (sessionId: string): Promise<TmuxSession[]> =>
  invoke("list_tmux_sessions", { sessionId });

export const createTmuxSession = (sessionId: string, name: string): Promise<void> =>
  invoke("create_tmux_session", { sessionId, name });

export const renameTmuxSession = (
  sessionId: string,
  name: string,
  newName: string,
): Promise<void> => invoke("rename_tmux_session", { sessionId, name, newName });

export const killTmuxSession = (sessionId: string, name: string): Promise<void> =>
  invoke("kill_tmux_session", { sessionId, name });

export const signalRemoteProcess = (
  sessionId: string,
  pid: number,
  startTimeToken: string,
  signal: ProcessSignal,
): Promise<void> => invoke("signal_remote_process", {
  sessionId,
  pid,
  startTimeToken,
  signal,
});

export const runSystemServiceAction = (
  sessionId: string,
  unit: string,
  action: ServiceAction,
): Promise<void> => invoke("run_system_service_action", { sessionId, unit, action });
