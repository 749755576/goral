# Goral packaged Mosh client

Goral loads only a packaged, SHA-256-locked MoshCatty 0.1.8 client from this
directory. MoshCatty is an upstream transport dependency, not the product
brand. Release assembly places the current build platform's native file directly
at:

- Windows: `mosh-client.exe`
- Linux/macOS: `mosh-client`

If the current platform file is absent or invalid, only Mosh is unavailable;
the desktop application still starts normally.
