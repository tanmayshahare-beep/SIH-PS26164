"""Scan stage - file discovery and detector dispatch."""

import logging
from collections.abc import Iterator
from pathlib import Path

from cbomscan.detectors import RawFinding, registry

logger = logging.getLogger(__name__)

_SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "dist",
    "build",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    "site-packages",
}

# Certificates are binary (DER) or may carry non-UTF-8 bytes. latin-1 maps every
# byte 1:1 to a codepoint, so detectors can recover the exact bytes.
_BINARY_SUFFIXES = {".der", ".crt", ".cer", ".pem"}

# Files above this size are almost never hand-written crypto config, and reading
# them costs far more than any finding they'd yield.
MAX_FILE_BYTES = 2 * 1024 * 1024


def _is_relevant(file_path: Path) -> bool:
    """True if any registered detector claims this file."""
    lowered = file_path.name.lower()
    return any(lowered.endswith(ext) for ext in registry.suffixes())


def scan_path(path: str) -> Iterator[tuple[str, str]]:
    """Walk a path and yield (file_path, content) for relevant files."""
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"Path not found: {path}")

    candidates = [root] if root.is_file() else root.rglob("*")

    for file_path in candidates:
        if not file_path.is_file():
            continue

        # Only skip directories *inside* the scan root. Testing the absolute
        # path would skip everything when the root itself lives under a
        # directory named e.g. "build" or "dist".
        try:
            relative_parts = file_path.relative_to(root).parts[:-1]
        except ValueError:
            relative_parts = file_path.parts[:-1]
        if any(part in _SKIP_DIRS for part in relative_parts):
            continue

        if not _is_relevant(file_path):
            continue

        try:
            if file_path.stat().st_size > MAX_FILE_BYTES:
                logger.debug("Skipping %s: larger than %d bytes", file_path, MAX_FILE_BYTES)
                continue
            if file_path.suffix.lower() in _BINARY_SUFFIXES:
                # read_text() would apply universal-newline translation, which
                # rewrites lone \r bytes and corrupts binary DER.
                content = file_path.read_bytes().decode("latin-1")
            else:
                content = file_path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError) as exc:
            logger.debug("Skipping %s: %s", file_path, exc)
            continue

        yield str(file_path), content


def run_detectors(file_path: str, content: str) -> list[RawFinding]:
    """Run all applicable detectors on a file.

    A detector that raises must not abort the scan, but the failure is logged
    rather than silently swallowed.
    """
    findings: list[RawFinding] = []
    for detector in registry.for_file(file_path):
        try:
            findings.extend(detector.detect(file_path, content))
        except Exception:
            logger.warning("Detector %s failed on %s", detector.name, file_path, exc_info=True)
    return findings
