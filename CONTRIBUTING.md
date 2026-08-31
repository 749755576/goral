# Contributing to Goral

Goral is an Electron-free Rust/Tauri application with a React/xterm.js
renderer. It is derived from Netcatty; new changes belong in this repository.

Before changing code, read [the architecture guide](docs/ARCHITECTURE.md),
[the security policy](SECURITY.md), and the documentation for the subsystem you
plan to touch. Keep build caches and temporary files outside the source tree.
Do not add Electron or a Node main process.

## Checks

Run the relevant focused tests first, then the complete gates when practical:

```bash
cargo fmt --all -- --check
cargo test --workspace -j 2
npm run test:frontend
npm run build
```

On Windows PowerShell, use `npm.cmd` if the execution policy blocks `npm.ps1`.

Never commit `target/`, `node_modules/`, `dist/`, `output/`, downloaded native
clients, logs, screenshots containing private data, credentials, or generated
machine-specific files. Do not weaken secret-custody or renderer-boundary
tests to make a build pass.

## Provenance and patches

Preserve GPL-3.0-or-later notices, upstream attribution, and third-party
licenses. Describe behavior changes and compatibility boundaries honestly; do
not imply Netcatty sponsorship or present this rewrite as clean-room original
work.
