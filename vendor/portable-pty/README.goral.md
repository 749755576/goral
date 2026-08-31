# Goral portable-pty patch

This directory vendors `portable-pty` 0.9.0 from the published crates.io
package (SHA-256
`b4a596a2b3d2752d94f51fac2d4a96737b8705dddd311a32b9af47211f08671e`).
The upstream project is <https://github.com/wezterm/wezterm> and the original
MIT license is retained in `LICENSE.md`.

Goral carries one Windows-only behavior patch: ConPTY is created without
`PSEUDOCONSOLE_INHERIT_CURSOR`. Goral always creates a fresh terminal
viewport and has no parent console cursor position to inherit. Enabling that
flag starts a cursor-position query handshake; if the host does not answer it,
PowerShell startup output and `ClosePseudoConsole` can remain blocked and leave
the associated `conhost.exe` alive after a Local Terminal tab closes.

`PSEUDOCONSOLE_RESIZE_QUIRK` and `PSEUDOCONSOLE_WIN32_INPUT_MODE` remain
enabled. Before updating or removing this patch, re-run the Windows Local
Terminal regression tests and a packaged-app A/B session check that confirms:

1. both PowerShell prompts become visible;
2. closing A removes only A's `conhost.exe` and shell process;
3. B stays connected and interactive; and
4. closing B leaves no test-owned console processes behind.
