"""Tests for knowledge base loader."""

from cbomscan.knowledge_base import KnowledgeBase

REQUIRED_FIELDS = [
    "algorithm",
    "verdict",
    "reason",
    "replacement",
    "primitive",
    "maturity",
    "latency_note",
    "hybrid_ok",
]


def test_knowledge_base_loads():
    """Test that knowledge base loads without error."""
    kb = KnowledgeBase.load("cbomscan/knowledge_base.yaml")
    assert kb is not None
    entries = kb.all_entries()
    assert len(entries) > 0


def test_every_row_has_all_required_fields():
    """Test that every row in the knowledge base has all required fields."""
    kb = KnowledgeBase.load("cbomscan/knowledge_base.yaml")
    entries = kb.all_entries()

    for entry in entries:
        for field in REQUIRED_FIELDS:
            assert (
                field in entry
            ), f"Missing field '{field}' in entry: {entry.get('algorithm', 'unknown')}"
            assert (
                entry[field] is not None
            ), f"Field '{field}' is None in entry: {entry.get('algorithm', 'unknown')}"


def test_verdict_values_valid():
    """Test that all verdict values are valid."""
    kb = KnowledgeBase.load("cbomscan/knowledge_base.yaml")
    valid_verdicts = {"vulnerable", "weakened", "broken", "safe"}

    for entry in kb.all_entries():
        assert (
            entry["verdict"] in valid_verdicts
        ), f"Invalid verdict '{entry['verdict']}' for {entry['algorithm']}"


def test_maturity_values_valid():
    """Test that all maturity values are valid."""
    kb = KnowledgeBase.load("cbomscan/knowledge_base.yaml")
    valid_maturities = {"nist-standardized", "draft", "deprecated", "unknown"}

    for entry in kb.all_entries():
        assert (
            entry["maturity"] in valid_maturities
        ), f"Invalid maturity '{entry['maturity']}' for {entry['algorithm']}"


def test_hybrid_ok_is_boolean():
    """Test that hybrid_ok is a boolean."""
    kb = KnowledgeBase.load("cbomscan/knowledge_base.yaml")

    for entry in kb.all_entries():
        assert isinstance(
            entry["hybrid_ok"], bool
        ), f"hybrid_ok not boolean for {entry['algorithm']}"


def test_lookup_case_insensitive():
    """Test that lookup is case-insensitive."""
    kb = KnowledgeBase.load("cbomscan/knowledge_base.yaml")

    entry = kb.lookup("RSA")
    assert entry is not None
    assert entry["algorithm"] == "RSA"

    entry = kb.lookup("rsa")
    assert entry is not None
    assert entry["algorithm"] == "RSA"

    entry = kb.lookup("Rsa")
    assert entry is not None
    assert entry["algorithm"] == "RSA"


def test_lookup_unknown_returns_none():
    """Test that lookup returns None for unknown algorithms."""
    kb = KnowledgeBase.load("cbomscan/knowledge_base.yaml")
    entry = kb.lookup("NONEXISTENT")
    assert entry is None
