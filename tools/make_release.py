"""Assemble the CBOMScan distribution ZIP.

Collects the already-built artifacts into a staging folder and zips it. Every
artifact is *copied* - nothing is moved or deleted from its build location, so
`dist/` and `desktop/dist/` are left exactly as the builds produced them.

Layout inside the ZIP:

    CBOMScan-<version>-Setup/
        CBOMScan-Setup.exe      the wizard the user runs
        payload/
            CBOMScan-Setup-<version>.exe    Electron app installer
            cbomscan.exe                     engine + CLI
        README.txt

Usage:
    python tools/make_release.py [--output DIR] [--skip-verify]
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from cbomscan import __version__  # noqa: E402

STAGE_NAME = f"CBOMScan-{__version__}-Setup"

README = """CBOMScan {version} - Setup
=============================

CBOMScan inventories the cryptography in a codebase, scores each asset against
the quantum threat using Mosca's inequality, and exports a standards-compliant
CycloneDX 1.7 Cryptographic Bill of Materials (CBOM).


INSTALLING
----------

1. Extract this ZIP anywhere (keep CBOMScan-Setup.exe and the payload folder
   together - the wizard reads the payload folder next to itself).
2. Run CBOMScan-Setup.exe.
3. Follow the wizard. When it finishes it offers to open the app.

For unattended deployment:

    CBOMScan-Setup.exe --silent [--no-app] [--no-cli] [--no-path]
                       [--dir <folder>] [--log <file>]

  Exit code 0 on success, 1 on failure. The wizard is a windowed program, so
  pass --log to capture what happened.

Nothing else is required. Python, Node.js and an internet connection are all
unnecessary - the engine and the app are self-contained.


WHAT GETS INSTALLED
-------------------

  Desktop app    %LOCALAPPDATA%\\Programs\\CBOMScan
                 Start Menu and desktop shortcuts, and an entry in
                 Add or Remove Programs.

  Command line   %LOCALAPPDATA%\\CBOMScan\\bin\\cbomscan.exe
                 Added to your PATH, so `cbomscan` works from any terminal.
                 Open a NEW terminal after installing for PATH to apply.


USING IT
--------

Desktop app: launch CBOMScan from the Start Menu. Pick a folder on the Scan
page, adjust the quantum risk horizon, and review the results. The Diagnostic
Tools page explains what each detector inspects.

Command line:

    cbomscan scan .                     scan the current folder -> cbom.json
    cbomscan scan . -f md -o report.md  human-readable report
    cbomscan scan . --horizon-year 2035 move the quantum horizon
    cbomscan scan . --json              summary as JSON, for CI
    cbomscan detectors                  list the diagnostic tools
    cbomscan serve                      web dashboard on 127.0.0.1:8000
    cbomscan app                        open the desktop app
    cbomscan --help                     full reference

Exit codes: 0 success, 1 output error, 2 unreadable path, 130 interrupted.


UNINSTALLING
------------

Remove "CBOMScan" from Add or Remove Programs, then delete
%LOCALAPPDATA%\\CBOMScan and remove that bin folder from your PATH.
"""


def copy_into(source: Path, destination: Path, label: str) -> Path:
    """Copy a file or tree, leaving the original untouched."""
    if not source.exists():
        raise FileNotFoundError(f"{label} not found: {source}")

    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.is_dir():
        shutil.copytree(source, destination, dirs_exist_ok=True)
    else:
        shutil.copy2(source, destination)

    print(f"  copied {label}: {source.name} -> {destination.relative_to(destination.parents[1])}")
    return destination


def directory_size(path: Path) -> int:
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file())


def build_zip(stage: Path, output_zip: Path) -> None:
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    if output_zip.exists():
        output_zip.unlink()

    files = sorted(p for p in stage.rglob("*") if p.is_file())
    print(f"\nCompressing {len(files)} files...")

    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for index, file in enumerate(files, 1):
            archive.write(file, file.relative_to(stage.parent))
            if index % 5 == 0 or index == len(files):
                print(f"  {index}/{len(files)}", end="\r", flush=True)
    print()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(stage: Path) -> None:
    """Sanity-check the staged payload before it is sealed into a ZIP."""
    print("\nVerifying staged contents...")

    wizard = stage / "CBOMScan-Setup.exe"
    engine = stage / "payload" / "cbomscan.exe"
    app_installer = next((stage / "payload").glob("*Setup*.exe"), None)

    for label, path in [("wizard", wizard), ("engine", engine)]:
        assert path.is_file(), f"{label} missing from the staged folder"
        print(f"  {label:16} {path.stat().st_size / 1e6:7.1f} MB")

    assert app_installer, "desktop app installer missing from payload/"
    print(f"  {'app installer':16} {app_installer.stat().st_size / 1e6:7.1f} MB")

    # The engine is the CLI users will run - prove the copy actually works.
    result = subprocess.run([str(engine), "version"], capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, f"staged engine failed: {result.stderr}"
    print(f"  engine responds:  {result.stdout.strip()}")

    result = subprocess.run(
        [str(engine), "detectors", "--json"], capture_output=True, text=True, timeout=120
    )
    assert result.returncode == 0 and '"name"' in result.stdout, "staged engine detectors failed"
    print("  engine detectors: ok")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the CBOMScan distribution ZIP")
    parser.add_argument(
        "--output", default=str(REPO / "release"), help="Output directory (default: ./release)"
    )
    parser.add_argument("--skip-verify", action="store_true", help="Skip staged-payload checks")
    args = parser.parse_args()

    output_dir = Path(args.output)
    stage_root = output_dir / "_stage"
    stage = stage_root / STAGE_NAME

    sources = {
        "setup wizard": REPO / "dist" / "CBOMScan-Setup.exe",
        "engine": REPO / "dist" / "CBOMScan-Backend.exe",
        "app installer": REPO / "desktop" / "dist" / f"CBOMScan-Setup-{__version__}.exe",
    }

    missing = [name for name, path in sources.items() if not path.exists()]
    if missing:
        print(f"error: missing build artifacts: {', '.join(missing)}", file=sys.stderr)
        print("\nBuild them first:\n  make wizard\n  make app", file=sys.stderr)
        return 2

    print(f"Staging {STAGE_NAME}")
    if stage_root.exists():
        shutil.rmtree(stage_root)
    stage.mkdir(parents=True)

    copy_into(sources["setup wizard"], stage / "CBOMScan-Setup.exe", "setup wizard")
    # Named cbomscan.exe so the installed command matches the command users type.
    copy_into(sources["engine"], stage / "payload" / "cbomscan.exe", "engine")
    copy_into(
        sources["app installer"],
        stage / "payload" / sources["app installer"].name,
        "app installer",
    )

    (stage / "README.txt").write_text(README.format(version=__version__), encoding="utf-8")
    print("  wrote README.txt")

    if not args.skip_verify:
        verify(stage)

    output_zip = output_dir / f"{STAGE_NAME}.zip"
    build_zip(stage, output_zip)
    shutil.rmtree(stage_root)

    raw = directory_size(output_dir) if False else output_zip.stat().st_size
    print("\nRelease ready")
    print(f"  {output_zip}")
    print(f"  {raw / 1e6:.1f} MB")
    print(f"  sha256 {sha256(output_zip)}")

    # Nothing was moved: the originals are still where the builds left them.
    for name, path in sources.items():
        assert path.exists(), f"source {name} disappeared - it should only have been copied"
    print("\nAll source artifacts left in place (copied, not moved).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
