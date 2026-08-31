# Third-party notices

The locked manifests (`Cargo.lock` and `package-lock.json`) identify the exact
Rust and JavaScript dependency versions used by the project.

| Component | Version/source | License information |
| --- | --- | --- |
| Rust crates | See `Cargo.lock` | License metadata is published with each crate. |
| JavaScript packages | See `package-lock.json` | License metadata is published with each package. |
| MoshCatty client | `moshcatty-0.1.8`, `src-tauri/resources/mosh/` | GPL-3.0-or-later. Exact corresponding source and downstream build material apply to binary distribution. |
| Eternal Terminal client | `et-bin-6.2.10-1`, `src-tauri/resources/et/` | Apache-2.0, together with the licenses of its linked components. |
| Inter Variable | `@fontsource-variable/inter` 5.3.0 | OFL-1.1; the copyright and license text is included at `licenses/Inter-OFL-1.1.txt`. |
| Simple Icons artwork | 16.23.0; SVG marks under `public/distro/` sourced from Simple Icons | CC0-1.0; the license text is included at `licenses/Simple-Icons-CC0-1.0.txt`. Brand names and trademarks remain the property of their respective owners. |
| `portable-pty` | 0.9.0, vendored with the Goral Windows ConPTY patch under `vendor/portable-pty/` | MIT; copyright (c) 2018 Wez Furlong. The license text is retained with the vendored crate and included at `licenses/portable-pty-MIT.txt`. |
| Tauri/WebView runtime | Platform-provided | Covered by the applicable platform terms. |

Binary distributors must review the locked dependency graphs and include every
license, copyright statement, notice, and corresponding-source item required by
the exact components they ship. This source repository does not include a
prebuilt Goral binary.
