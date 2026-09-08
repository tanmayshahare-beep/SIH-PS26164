"""Knowledge base loader and lookup."""

from pathlib import Path
from typing import Any

import yaml


class KnowledgeBase:
    """Crypto Knowledge Base loaded from YAML."""

    def __init__(self, data: list[dict[str, Any]]):
        self._entries = {entry["algorithm"].lower(): entry for entry in data}

    @classmethod
    def load(cls, path: str | Path) -> "KnowledgeBase":
        """Load knowledge base from YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(data)

    def lookup(self, algorithm: str) -> dict[str, Any] | None:
        """Look up an algorithm by name (case-insensitive)."""
        return self._entries.get(algorithm.lower())

    def all_entries(self) -> list[dict[str, Any]]:
        """Return all knowledge base entries."""
        return list(self._entries.values())


# Default path to knowledge base
DEFAULT_KB_PATH = Path(__file__).parent / "knowledge_base.yaml"
