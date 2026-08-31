# Goral bundled native terminal clients

Goral bundles two transport clients as native Tauri resources. The binaries
are generated files and are intentionally ignored by Git; this document is the
source and license record retained in the repository. Netcatty references below
identify the upstream release source only; they are not the current product
name or a claim of upstream endorsement.

| Client | Locked release | Upstream/source | License | Staged host path |
|---|---|---|---|---|
| MoshCatty `mosh-client` | `moshcatty-0.1.8` | [binaricat/MoshCatty](https://github.com/binaricat/MoshCatty) | GPL-3.0-or-later | `mosh/mosh-client[.exe]` |
| Eternal Terminal `et` | `et-bin-6.2.10-1` (ET 6.2.10) | [binaricat/Netcatty-et-bin](https://github.com/binaricat/Netcatty-et-bin), built from [MisterTea/EternalTerminal](https://github.com/MisterTea/EternalTerminal) | Apache-2.0 | `et/et[.exe]` |

Apache-2.0 code may be redistributed in this GPL-3.0-or-later application.
MoshCatty and its Mosh protocol implementation are GPL-compatible. ET's
documented static dependencies retain their upstream Boost, ISC and BSD-style
licenses; release compliance must continue to ship all required notices.

Run from the repository root with Node.js 22 or newer:

```powershell
npm.cmd run fetch:native-clients
```

The fetcher downloads only the current platform. It obtains `SHA256SUMS` from
the locked release, verifies the compressed asset before caching, parses the
tar archive itself, and publishes only one expected executable. Absolute or
parent paths, backslashes, hard/symbolic links, unsupported entry types,
additional regular files, invalid executable formats and missing/mismatched
checksums all fail closed. There is no `PATH`, system-client or unverified
fallback.

By default, verified archives use the operating system's per-user cache and
temporary directories. Set `GORAL_DEV_SETTING_ROOT` to keep both locations
under an explicit development root. The former `LUMENDOCK_DEV_SETTING_ROOT` and legacy
`NETCATTY_DEV_SETTING_ROOT` spellings remain read-only compatibility aliases for
existing development setups. Release URLs and tags are source constants rather
than environment overrides.

`tauri.conf.json` maps only the current-platform client filenames into the
runtime `mosh/` and `et/` resource directories. Mosh also ships the committed
`moshcatty.version` manifest used by the native compatibility check. The
download cache and extraction workspace are never bundled.
