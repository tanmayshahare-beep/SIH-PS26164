"""Scan stage - file discovery and detector dispatch."""

import contextlib
from collections.abc import Iterator
from pathlib import Path

from cbomscan.detectors import RawFinding, registry

_SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".pytest_cache",
}


def scan_path(path: str) -> Iterator[tuple[str, str]]:
    """Walk a path and yield (file_path, content) for relevant files."""
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"Path not found: {path}")

    for file_path in root.rglob("*"):
        if file_path.is_file():
            if any(skip in file_path.parts for skip in _SKIP_DIRS):
                continue
            try:
                content = file_path.read_text(encoding="utf-8")
                yield str(file_path), content
            except UnicodeDecodeError:
                continue


def run_detectors(file_path: str, content: str) -> list[RawFinding]:
    """Run all applicable detectors on a file."""
    findings = []
    for detector in registry.for_file(file_path):
        with contextlib.suppress(Exception):
            findings.extend(detector.detect(file_path, content))
    return findings
