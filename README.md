<div align="center">

<img src="public/logo-goral.svg" alt="Goral logo" width="88" height="88">

# Goral

**Navigate complexity. Reach every endpoint.**

An Electron-free native terminal workspace for SSH, Telnet, Serial, Mosh,
Eternal Terminal, local shells and SFTP.

[![License](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-lightgrey.svg)](#installation)
[![Runtime](https://img.shields.io/badge/runtime-Tauri%202-24C8DB.svg)](https://tauri.app)
[![Rust](https://img.shields.io/badge/rust-1.88%2B-CE422B.svg)](https://www.rust-lang.org)
[![Node](https://img.shields.io/badge/node-22%2B-5FA04E.svg)](https://nodejs.org)

**English** · [简体中文](README.zh-CN.md)

</div>

---

## What it is

Goral is a desktop terminal client for people who keep a lot of connections open. Every
protocol lives in the same window, every host is stored in one encrypted vault, and the
privileged work — sockets, PTYs, key material — happens in Rust rather than in a browser
process.

The goral is a sure-footed mountain antelope. It crosses steep, broken terrain by choosing
each foothold carefully; the product name carries the same promise for complex networks:
move reliably through the difficult parts and reach the endpoint that matters.

Goral is derived from [Netcatty](https://github.com/binaricat/Netcatty) and rewrites the
desktop runtime with Rust and Tauri 2 while retaining familiar terminal workflows. See
[Attribution](#attribution) for the project relationship and license details.

**Highlights**

| | |
|---|---|
| **One window, every protocol** | SSH, Telnet, Serial, Mosh, Eternal Terminal and local shells are managed from one workspace with a shared theme and consistent controls. |
| **Secrets stay under native custody** | Persisted private keys, passphrases and API keys stay outside settings JSON. Stored values are held by the platform credential store and are not returned to the renderer. |
| **Native and self-contained** | The desktop runtime is Rust/Tauri rather than a bundled Electron browser; optional Mosh and Eternal Terminal clients are fetched and verified by repository scripts. |
| **An AI assistant with explicit authority** | It reads terminal output only when you attach it. `observer` never executes, `confirm` asks for the exact command, and `auto` runs only commands accepted by the native safety policy after you deliberately select that mode. |

---

## Features

### Connections

- **SSH** — password, private key, certificate and keyboard-interactive authentication;
  SOCKS/HTTP proxies; ordered jump-host chains; host-key verification with a managed
  `known_hosts`.
- **SFTP** — browse, transfer, pause and resume, with atomic no-overwrite publication.
- **Telnet** — identity projection, per-host character sets, local echo and line mode.
- **Serial** — full port configuration, high baud rates, character sets, YMODEM and ZMODEM
  file transfer with cancellable streaming state machines.
- **Local shells** — Windows ConPTY and Unix PTY, with shell discovery and per-profile
  starting directories.
- **Mosh** and **Eternal Terminal** — roaming-tolerant sessions over the same saved-host
  configuration, using optional native clients fetched by repository scripts.

### Workspace

- Up to 64 concurrent sessions in one global tab catalog; switching tabs never remounts a
  terminal, so background output and scrollback survive.
- Live SSH/local-shell split panes, a dockable side panel, a separate Settings window, and
  a native system tray.
- Closing the main window (including `Alt+F4`) asks whether to exit, minimize to the tray,
  or cancel. Left-clicking the tray restores the main window; its menu can show or hide all
  application windows, open Settings, or exit without another prompt.
- Settings cover Application, Appearance, Terminal, SFTP, AI, and System.
- **Notes & Scripts** — operational notes and reusable snippets, attachable to hosts.
- **Connection Logs** — encrypted session capture with read-only replay and TXT/RAW/HTML
  export.
- **Port Forwarding** — local, remote and dynamic tunnels managed per host.
- Simplified Chinese is the fresh-install default, with English available immediately.

### AI assistant

An optional side panel that can read terminal context and propose commands.

- Supports configurable **OpenAI Chat Completions-compatible** endpoints (13 presets
  included) and direct **Anthropic Messages** transport.
- Responses stream incrementally over a cancellable SSE channel.
- Three permission modes: `observer` (never executes), `confirm` (every command needs
  explicit approval of its exact text), and `auto` (bounded by a native safety policy).
- Terminal output is sent **only** when you attach it — "add selection" or "add recent
  output" are deliberate actions, never implicit.
- Conversations, drafts and attachments are isolated per terminal session and generation;
  reconnecting or switching tabs never carries context across.

---

## Security model

This is a tool that holds credentials for machines you care about, so the boundaries are
worth stating plainly.

- **Credential custody.** Secrets live in the OS credential store under an account bound to
  the profile *and* its canonical endpoint. Stored key material never enters settings JSON
  and is never returned to the renderer.
- **Backend is the authority.** Native code treats the persisted settings snapshot as the
  source of truth for endpoints, models, protocols and command permissions, and revalidates
  renderer requests at the native boundary.
- **Fail closed.** Invalid host-key states, dangling script references and malformed
  provider responses abort before any side effect. Structural
  preflight runs before a master key or vault graph is ever created.
- **Redaction.** Backend errors and logs redact provider bodies, key material and host
  addresses.

Found something? See [SECURITY.md](SECURITY.md). Please don't attach keys, host addresses
or log bodies to a public issue.

---

## Installation

This repository does not distribute official prebuilt binaries. You can run Goral from
source using the instructions below.

The Windows portable build runs as `Goral.exe`. It uses no installer and makes no
installer-owned registry writes; application data lives in the standard per-user
application directory.

```
Goral.exe        the application
et/                  Eternal Terminal client (optional)
mosh/                Mosh client (optional)
MANIFEST.json        SHA-256 for every shipped file
```

Verify what you downloaded before running it:

```powershell
Get-FileHash .\Goral.exe -Algorithm SHA256
```

and compare it with the `MANIFEST.json` shipped beside that build.

---

## Building from source

**Prerequisites** — [Rust](https://rustup.rs) 1.88+, [Node.js](https://nodejs.org) 22+, and
the [Tauri 2 system dependencies](https://tauri.app/start/prerequisites/) for your platform.
On Windows that means the WebView2 runtime and the MSVC build tools.

On Windows PowerShell:

```powershell
git clone https://github.com/749755576/goral.git
cd goral
npm.cmd ci
npm.cmd run fetch:native-clients  # download locked Mosh/ET clients; verify SHA-256

npm.cmd run tauri:dev               # run the desktop app with hot reload
```

The native-client executables are intentionally not stored in Git. The fetch step is
therefore required in a clean clone before `tauri:dev`, `tauri:build`, or
`package:portable`; its versions, origins, and hashes are locked by the repository scripts.

### Verification

```powershell
cargo fmt --all -- --check
cargo test --workspace
npm.cmd run test:frontend
npm.cmd run build
```

### Release build

```powershell
npm.cmd run package:portable     # → output/portable/windows-x64/
```

This is the only supported release entry point; it always performs a formal `tauri build`
before publishing the portable tree.

> In shells where the executable is named `npm`, use the equivalent `npm` commands. The
> packaging step renames its output directory, so close any previously launched copy of the
> packaged executable first.

---

## Architecture

The Rust backend and React/xterm.js renderer communicate through typed commands. Crates
never depend on the frontend, and core crates never depend on Tauri.

```
crates/
├── netcatty-core            shared primitives and application-neutral models
├── netcatty-ssh             SSH config, auth planning, sessions, transport
├── netcatty-telnet          Telnet runtime and identity projection
├── netcatty-serial          serial transport, YMODEM/ZMODEM state machines
├── netcatty-local-pty       ConPTY and Unix PTY lifecycle
├── netcatty-mosh            Mosh bootstrap and session management
├── netcatty-et              Eternal Terminal integration
├── netcatty-vault           the versioned host/credential graph
├── netcatty-secret-store    OS credential-store custody
├── netcatty-credentials     credential resolution and projection
├── netcatty-replay-store    encrypted session capture
├── netcatty-log-export      TXT / RAW / HTML export
├── netcatty-migration       legacy vault import
├── netcatty-ai              provider transports, SSE streaming, tool policy
└── netcatty-sysmanager      bounded remote-system command planning and parsers

src-tauri/                   desktop lifecycle and renderer/native integration
src/                         React UI, xterm.js, and the typed backend client
```

The interface uses shared design tokens and supports both light and dark themes.

Deeper notes live in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Attribution

Goral is an Electron-free Rust/Tauri rewrite derived from the GPL-licensed
[binaricat/Netcatty](https://github.com/binaricat/Netcatty) project. It is **not** an
official Netcatty release and is not sponsored, approved or endorsed by its upstream
authors. The project preserves GPL provenance, upstream copyright attribution and
applicable third-party notices while using its own product identity and desktop runtime.

See [NOTICE.md](NOTICE.md), [SOURCE.md](SOURCE.md) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

---

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md) and the
[architecture guide](docs/ARCHITECTURE.md). Behaviour changes need Rust unit tests;
anything crossing the Tauri boundary also needs an integration or frontend contract test.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

---

## License

[GPL-3.0-or-later](LICENSE). Copyright © 749755576 and contributors.
