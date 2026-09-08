"""Detector registry and base classes."""

from abc import ABC, abstractmethod
from typing import Any

from cbomscan.detectors.cert import CertDetector
from cbomscan.detectors.manifest import ManifestDetector
from cbomscan.detectors.source import PythonSourceDetector
from cbomscan.models import Occurrence


class RawFinding:
    """A raw finding from a detector before normalization."""

    def __init__(
        self,
        asset_type: str,
        name: str,
        occurrences: list[Occurrence],
        primitive: str | None = None,
        key_size: int | None = None,
        curve: str | None = None,
        confidence: str = "inferred",
        metadata: dict[str, Any] | None = None,
    ):
        self.asset_type = asset_type
        self.name = name
        self.occurrences = occurrences
        self.primitive = primitive
        self.key_size = key_size
        self.curve = curve
        self.confidence = confidence
        self.metadata = metadata or {}


class Detector(ABC):
    """Abstract base class for all detectors."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name for this detector."""
        pass

    @property
    @abstractmethod
    def supported_extensions(self) -> list[str]:
        """File extensions this detector can process."""
        pass

    @abstractmethod
    def detect(self, file_path: str, content: str) -> list[RawFinding]:
        """Detect cryptographic artifacts in a file."""
        pass


class DetectorRegistry:
    """Registry for managing detectors."""

    def __init__(self):
        self._detectors: dict[str, Detector] = {}

    def register(self, detector: Detector) -> None:
        """Register a detector."""
        self._detectors[detector.name] = detector

    def get(self, name: str) -> Detector | None:
        """Get a detector by name."""
        return self._detectors.get(name)

    def all(self) -> list[Detector]:
        """Get all registered detectors."""
        return list(self._detectors.values())

    def for_file(self, file_path: str) -> list[Detector]:
        """Get detectors that can process a given file."""
        return [
            d
            for d in self._detectors.values()
            if any(file_path.endswith(ext) for ext in d.supported_extensions)
        ]


registry = DetectorRegistry()

# Register built-in detectors
registry.register(ManifestDetector())
registry.register(PythonSourceDetector())
registry.register(CertDetector())
