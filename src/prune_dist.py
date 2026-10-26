#!/usr/bin/env python3
"""Remove files from the PyInstaller onedir bundle that the app never loads.

Run right after PyInstaller (or just use `python src/build.py`):

    pyinstaller --onedir --noconfirm --noconsole --name SakuraFlow ... src/main.py
    python src/prune_dist.py            # prune + layout fix
    python src/prune_dist.py --dry-run  # only report what would go

The app is a pure PyQt5 QWidgets UI: no QML/Quick, no QtNetwork (HTTP goes
through `requests`), no printing, icons are PNG/ICO. Everything listed below
is unreachable at runtime; anything not listed is kept.

PyInstaller 6 puts `--add-data` under `_internal/`, while the app looks for
`zapret/`, `icons/` and `src/` next to the exe (`src/config.py`). They are
moved out of `_internal/` here (build scripts and `__pycache__` are dropped
from the relocated `src/`).

Note: cygwin1.dll / WinDivert.dll in `_internal` are duplicate copies of the
ones in `zapret/bin/` (winws loads its own). They are removed here as well.

Some antivirus products deny deleting specific Qt DLLs. In that case the file
is moved to %TEMP% instead (rename/move is allowed), so the bundle stays clean.
"""
from __future__ import annotations

import argparse
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INTERNAL = ROOT / "dist" / "SakuraFlow" / "_internal"
STASH_ROOT = Path(tempfile.gettempdir()) / "sakura-flow-prune"
STASH = STASH_ROOT / str(os.getpid())

# Files (relative to _internal) that nothing in the app loads.
DROP_FILES = (
    # --- Qt5/bin: ANGLE + QML + unused modules ---
    "PyQt5/Qt5/bin/opengl32sw.dll",      # software OpenGL fallback; QWidgets paints via raster
    "PyQt5/Qt5/bin/d3dcompiler_47.dll",  # only used by ANGLE
    "PyQt5/Qt5/bin/libGLESv2.dll",       # ANGLE
    "PyQt5/Qt5/bin/libEGL.dll",          # ANGLE
    "PyQt5/Qt5/bin/Qt5Quick.dll",        # QML/Quick not used
    "PyQt5/Qt5/bin/Qt5Qml.dll",
    "PyQt5/Qt5/bin/Qt5QmlModels.dll",
    "PyQt5/Qt5/bin/Qt5Network.dll",      # HTTP via requests, not QtNetwork
    "PyQt5/Qt5/bin/Qt5DBus.dll",         # Linux-only
    "PyQt5/Qt5/bin/Qt5Svg.dll",          # icons are .png/.ico
    "PyQt5/Qt5/bin/Qt5WebSockets.dll",
    # --- platform plugins: keep only qwindows ---
    "PyQt5/Qt5/plugins/platforms/qminimal.dll",
    "PyQt5/Qt5/plugins/platforms/qoffscreen.dll",
    "PyQt5/Qt5/plugins/platforms/qwebgl.dll",
    # --- image formats: keep qico/qjpeg/qgif ---
    "PyQt5/Qt5/plugins/imageformats/qicns.dll",
    "PyQt5/Qt5/plugins/imageformats/qsvg.dll",   # needs Qt5Svg
    "PyQt5/Qt5/plugins/imageformats/qtga.dll",
    "PyQt5/Qt5/plugins/imageformats/qtiff.dll",
    "PyQt5/Qt5/plugins/imageformats/qwbmp.dll",
    "PyQt5/Qt5/plugins/imageformats/qwebp.dll",
    # --- duplicates of zapret/bin/* ---
    "cygwin1.dll",
    "WinDivert.dll",
    # --- pywin32 WMI extension, never imported ---
    "_wmi.pyd",
)

# Whole directories (relative to _internal).
DROP_DIRS = (
    "PyQt5/Qt5/translations",              # stock Qt strings; the UI is custom
    "PyQt5/Qt5/plugins/generic",           # touch input
    "PyQt5/Qt5/plugins/platformthemes",    # only for GTK/KDE on Linux
    "PyQt5/Qt5/plugins/iconengines",       # qsvgicon -> needs Qt5Svg
    "pythonwin",                            # pywin32 IDE, not imported
)


# PyInstaller 6 puts --add-data under _internal/, but the app resolves
# "zapret", "icons" and "src" next to the exe (src/config.py: BASE_DIR).
RELOCATE = ("zapret", "icons", "src")

# Build tooling / stale bytecode that makes no sense in the shipped copy.
SHIPPED_SKIP = ("build.py", "prune_dist.py", "build.bat", "__pycache__")


def _size(path: Path) -> int:
    if path.is_dir():
        return sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
    return path.stat().st_size


def _make_writable(path: Path) -> None:
    try:
        if path.is_dir():
            for f in path.rglob("*"):
                if f.is_file():
                    os.chmod(f, stat.S_IWRITE)
        else:
            os.chmod(path, stat.S_IWRITE)
    except OSError:
        pass


def _prune_one(path: Path) -> str:
    """Delete the path; on Windows lock errors move it to %TEMP% instead."""
    rel = path.relative_to(INTERNAL)
    _make_writable(path)
    try:
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        return "deleted"
    except PermissionError:
        pass
    except OSError as exc:
        print(f"  warning: cannot delete {rel}: {exc}", file=sys.stderr)

    # Fallback: move out of the bundle (rename is allowed even when delete is not).
    try:
        dest = STASH / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(path), str(dest))
        return "moved to temp"
    except OSError as exc:
        print(f"  warning: cannot move {rel}: {exc}", file=sys.stderr)

    # Last resort: rename in place so the runtime never loads it.
    try:
        path.rename(path.with_name(path.name + ".pruned"))
        return "renamed"
    except OSError as exc:
        print(f"  warning: cannot rename {rel}: {exc}", file=sys.stderr)
        return "kept (locked)"


def main() -> int:
    parser = argparse.ArgumentParser(description="Trim the PyInstaller onedir bundle")
    parser.add_argument("--dry-run", action="store_true", help="report without touching files")
    args = parser.parse_args()

    if not INTERNAL.is_dir():
        print(f"error: {INTERNAL} not found — run PyInstaller first", file=sys.stderr)
        return 1

    before = _size(INTERNAL)
    freed = 0
    removed = 0
    kept = 0

    # Drop leftovers from earlier builds (locked files survive until AV releases them).
    if not args.dry_run and STASH_ROOT.is_dir():
        for old in STASH_ROOT.iterdir():
            if old != STASH:
                if old.is_dir():
                    shutil.rmtree(old, ignore_errors=True)
                else:
                    try:
                        old.unlink()
                    except OSError:
                        pass

    for rel in (*DROP_FILES, *DROP_DIRS):
        path = INTERNAL / rel
        if not path.exists():
            continue
        size = _size(path)
        if args.dry_run:
            action = "would remove"
        else:
            action = _prune_one(path)
            if action == "kept (locked)":
                kept += 1
            else:
                freed += size
                removed += 1
        print(f"{action}: {rel} ({size / 1048576:.2f} MB)")

    if args.dry_run:
        freed = sum(_size(INTERNAL / rel) for rel in (*DROP_FILES, *DROP_DIRS) if (INTERNAL / rel).exists())
        removed = sum(1 for rel in (*DROP_FILES, *DROP_DIRS) if (INTERNAL / rel).exists())
    else:
        for rel in RELOCATE:
            src = INTERNAL / rel
            dst = INTERNAL.parent / rel
            if not src.is_dir():
                continue
            if dst.exists():
                print(f"relocate: {rel}/ already next to exe, left as is", file=sys.stderr)
                continue
            try:
                shutil.move(str(src), str(dst))
                print(f"relocated: _internal/{rel}/ -> {rel}/")
            except OSError as exc:
                print(f"  warning: cannot relocate {rel}: {exc}", file=sys.stderr)

        shipped_src = INTERNAL.parent / "src"
        if shipped_src.is_dir():
            for name in SHIPPED_SKIP:
                path = shipped_src / name
                if path.is_dir():
                    shutil.rmtree(path, ignore_errors=True)
                elif path.exists():
                    try:
                        path.unlink()
                    except OSError:
                        pass

    # Best-effort cleanup of the stash; locked files may survive until reboot.
    if not args.dry_run and STASH.is_dir():
        shutil.rmtree(STASH, ignore_errors=True)

    after = _size(INTERNAL)
    print(
        f"\n{removed} paths, {freed / 1048576:.1f} MB freed: "
        f"{before / 1048576:.1f} MB -> {after / 1048576:.1f} MB"
        + (f" ({kept} locked, left in place)" if kept else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
