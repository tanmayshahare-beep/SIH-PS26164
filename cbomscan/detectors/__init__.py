"""Detector registry and base classes."""

from abc import ABC, abstractmethod

from cbomscan.detectors.cert import CertDetector
from cbomscan.detectors.config import ConfigDetector
from cbomscan.detectors.manifest import ManifestDetector
from cbomscan.detectors.source import JavaScriptSourceDetector, PythonSourceDetector
from cbomscan.models import Occurrence, RawFinding

__all__ = [
    "Detector",
    "DetectorRegistry",
    "Occurrence",
    "RawFinding",
    "registry",
]


class Detector(ABC):
    """Abstract base class for all detectors."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name for this detector."""

    @property
    @abstractmethod
    def supported_extensions(self) -> list[str]:
        """File extensions (or exact file names) this detector can process."""

    @abstractmethod
    def detect(self, file_path: str, content: str) -> list[RawFinding]:
        """Detect cryptographic artifacts in a file."""


class DetectorRegistry:
    """Registry for managing detectors.

    Detectors are indexed by suffix at registration time so that dispatching a
    file is a handful of dict lookups rather than a scan over every detector's
    extension list.
    """

    def __init__(self) -> None:
        self._detectors: dict[str, Detector] = {}
        self._by_suffix: dict[str, list[Detector]] = {}

    def register(self, detector: Detector) -> None:
        """Register a detector and index its supported suffixes."""
        self._detectors[detector.name] = detector
        for ext in detector.supported_extensions:
            self._by_suffix.setdefault(ext.lower(), []).append(detector)

    def get(self, name: str) -> Detector | None:
        """Get a detector by name."""
        return self._detectors.get(name)

    def all(self) -> list[Detector]:
        """Get all registered detectors."""
        return list(self._detectors.values())

    def describe(self) -> list[dict]:
        """Self-description of every registered detector.

        One source of truth for `cbomscan detectors`, the /api/detectors
        endpoint and the desktop app's Tools page.
        """
        return [
            {
                "name": d.name,
                "title": getattr(d, "title", d.name),
                "summary": getattr(d, "summary", ""),
                "detail": getattr(d, "detail", ""),
                "typical_confidence": getattr(d, "typical_confidence", "inferred"),
                "inputs": list(getattr(d, "inputs", d.supported_extensions)),
                "detects": list(getattr(d, "detects", [])),
                "extensions": list(d.supported_extensions),
            }
            for d in self._detectors.values()
        ]

    def suffixes(self) -> set[str]:
        """Every suffix/filename any registered detector claims."""
        return set(self._by_suffix)

    def for_file(self, file_path: str) -> list[Detector]:
        """Get detectors that can process a given file."""
        lowered = file_path.lower()
        matched: list[Detector] = []
        for ext, detectors in self._by_suffix.items():
            if lowered.endswith(ext):
                matched.extend(detectors)
        return matched


registry = DetectorRegistry()

# Register built-in detectors
registry.register(ManifestDetector())
registry.register(PythonSourceDetector())
registry.register(JavaScriptSourceDetector())
registry.register(CertDetector())
registry.register(ConfigDetector())
