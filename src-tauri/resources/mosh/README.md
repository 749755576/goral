# Goral packaged Mosh client

Goral loads only a packaged MoshCatty 0.1.7-or-newer client from this
directory. MoshCatty is an upstream transport dependency, not the product
brand. Release assembly places the current build platform's native file directly
at:

- Windows: `mosh-client.exe`
- Linux/macOS: `mosh-client`

If the current platform file is absent or invalid, only Mosh is unavailable;
the desktop application still starts normally.
