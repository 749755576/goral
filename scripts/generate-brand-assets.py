"""Generate Goral app icons from the original editable SVG mother asset.

The repository-locked Tauri CLI rasterizes the SVG for consistent Windows,
macOS, Linux, iOS, Android, and Appx exports. The application ships only the
generated assets and has no Python dependency at runtime.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
GORAL_SVG = ROOT / "public" / "logo-goral.svg"
PUBLIC_ICON = ROOT / "public" / "icon.png"
TAURI_ICONS = ROOT / "src-tauri" / "icons"


def tauri_cli() -> Path:
    executable = "tauri.cmd" if os.name == "nt" else "tauri"
    path = ROOT / "node_modules" / ".bin" / executable
    if not path.is_file():
        raise FileNotFoundError(
            "The repository-locked Tauri CLI is missing; run npm install first."
        )
    return path


def run_icon_export(*arguments: str) -> None:
    subprocess.run(
        [str(tauri_cli()), "icon", *arguments],
        cwd=ROOT,
        check=True,
    )


def main() -> None:
    source = GORAL_SVG.read_text(encoding="utf-8")
    if "<title id=\"title\">Goral mark</title>" not in source:
        raise ValueError("The Goral SVG mother asset is missing its identity marker.")

    TAURI_ICONS.mkdir(parents=True, exist_ok=True)
    run_icon_export(
        str(GORAL_SVG),
        "--output",
        str(TAURI_ICONS),
        "--ios-color",
        "#0B1220",
    )

    temp_root = Path(os.environ.get("TEMP", tempfile.gettempdir()))
    temp_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="goral-brand-", dir=temp_root) as temp:
        raster_dir = Path(temp)
        run_icon_export(
            str(GORAL_SVG),
            "--output",
            str(raster_dir),
            "--png",
            "1024",
        )
        generated = raster_dir / "1024x1024.png"
        if not generated.is_file():
            raise FileNotFoundError("Tauri did not emit the 1024px Goral mother PNG.")
        shutil.copyfile(generated, PUBLIC_ICON)


if __name__ == "__main__":
    main()
