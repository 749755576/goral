# Goral architecture

Goral is a Rust/Tauri 2 desktop application with a React/xterm.js renderer.
Electron and a Node main process are not part of the runtime. The old Netcatty
tree is consulted only for behavior, migration formats, and parity tests.

## Runtime layers

```text
React workspaces / xterm.js
        │ typed Tauri commands, raw bounded terminal frames
Tauri desktop adapters (`src-tauri`)
        │ validation, orchestration, renderer-safe DTOs
Domain crates (`crates/netcatty-*`)
        │ SSH/SFTP, serial, Telnet, PTY, Mosh, ET, Vault, migration
OS boundaries
        │ WebView2, PTY/ConPTY, sockets, keyring, native clients
```

The Tauri layer validates renderer requests, coordinates desktop state, and
delegates protocol work to the domain crates and native session modules.
Protocol credentials and runtime state do not belong in React.

## Main crates

- `netcatty-vault`: versioned A/B graph snapshots, inventory CAS, recovery, and
  renderer-safe SavedHost/catalog models.
- `netcatty-secret-store` and `netcatty-credentials`: encrypted secret blobs,
  OS-kept master keys, deterministic owner namespaces, zeroizing boundaries.
- `netcatty-ssh`: SSH authentication planning, host-key verification, proxies,
  jump chains, SFTP, and bounded transfer ownership.
- `netcatty-local-pty`, `netcatty-serial`, `netcatty-telnet`, `netcatty-mosh`,
  and `netcatty-et`: protocol-specific native runtimes and lifecycle events.
- `netcatty-migration`: bounded, secret-safe import parsing and graph planning.
- `netcatty-replay-store` and `netcatty-log-export`: encrypted replay custody
  and offline-safe TXT/RAW/HTML export formatting.

## Security invariants

- Passwords, private keys, API keys, terminal replay bodies, and native paths do
  not cross ordinary JSON renderer requests.
- Renderer requests carry opaque, bounded IDs or one-shot staging references;
  native code owns credential lookup and consumption.
- Persisted Vault snapshots and journals are versioned, checksummed, A/B
  recoverable, and guarded by complete-inventory compare-and-swap revisions.
- Errors exposed to the renderer use stable non-secret codes/messages and do
  not echo provider, filesystem, host, or credential details.
- Runtime sessions, SFTP transfers, callbacks, and retries are bound to exact
  session IDs and generations so one tab cannot control another.

## Development boundaries

Keep generated artifacts, downloaded clients, credentials, logs, and local
tooling state out of source history. Keep Rust/Node caches and temporary files
outside the repository. Read the subsystem documentation and security policy
before changing an authority boundary, and include focused tests with each
bounded change.
