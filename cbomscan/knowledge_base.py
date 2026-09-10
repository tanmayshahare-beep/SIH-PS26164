"""Knowledge base loader and lookup."""

from functools import lru_cache
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
        with open(path, encoding="utf-8") as f:
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


@lru_cache(maxsize=4)
def load_knowledge_base(path: str | Path = None) -> KnowledgeBase:
    """Load and cache a knowledge base by path.

    The KB is immutable at runtime and read on every scan, so parsing the YAML
    more than once per path is pure waste.
    """
    return KnowledgeBase.load(path or DEFAULT_KB_PATH)
