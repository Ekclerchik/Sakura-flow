#!/usr/bin/env python3
"""Build dist/SakuraFlow: PyInstaller onedir + prune/layout fix + zip.

Usage (from the repo root):
    python src/build.py

Equivalent to running PyInstaller by hand and then `python src/prune_dist.py`
(and zipping dist/SakuraFlow), but with the arguments in one place so they
cannot drift. The zip lands at dist/SakuraFlow.zip.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PRUNE = Path(__file__).resolve().parent / "prune_dist.py"

PYINSTALLER_ARGS = [
    "--onedir",
    "--noconfirm",
    "--noconsole",
    "--name", "SakuraFlow",
    "--manifest", "manifest.xml",
    "--add-data", "icons;icons",
    "--add-data", "zapret;zapret",
    "--add-data", "src;src",
    "--icon", "icons/sakura.ico",
    "--version-file", "version.py",
    "src/main.py",
]


def run(cmd: list[str]) -> None:
    print(">", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=ROOT, check=True)


def main() -> int:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("PyInstaller is not installed. Run: python -m pip install -r requirements.txt", file=sys.stderr)
        return 1

    destination = ROOT / "dist" / "SakuraFlow"  # where the bundle lands
    archive = ROOT / "dist" / f"{destination.name}.zip"

    try:
        run([sys.executable, "-m", "PyInstaller", *PYINSTALLER_ARGS])
        run([sys.executable, str(PRUNE)])
    except subprocess.CalledProcessError as exc:
        print(f"\nBuild failed (exit code {exc.returncode}).", file=sys.stderr)
        return exc.returncode or 1

    if not destination.is_dir():
        print(f"\nerror: bundle not found: {destination}", file=sys.stderr)
        return 1

    if archive.exists():
        try:
            archive.unlink()
        except OSError as exc:
            print(f"\nerror: cannot remove old {archive}: {exc}", file=sys.stderr)
            return 1

    assert archive.parent == destination.parent
    try:
        shutil.make_archive(base_name=archive.with_suffix("").as_posix(),
                            format="zip",
                            root_dir=archive.parent.as_posix(),
                            base_dir=destination.name)
    except OSError as exc:
        print(f"\nArchiving failed: {exc}", file=sys.stderr)
        return 1
    print(f"Archive: {archive}")

    print("\nBuild complete: dist/SakuraFlow")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
