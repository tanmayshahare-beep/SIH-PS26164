"""Classify stage - assign asset type, criticality, and lifetime."""

from cbomscan.knowledge_base import KnowledgeBase
from cbomscan.models import CryptoArtifact, Verdict

# Default configuration
DEFAULT_MIGRATION_YEARS = 2.0
DEFAULT_DATA_LIFETIME_YEARS = 10
DEFAULT_HORIZON_YEAR = 2030


def classify(
    artifacts: list[CryptoArtifact],
    kb: KnowledgeBase,
    migration_years: float = DEFAULT_MIGRATION_YEARS,
    data_lifetime_years: int = DEFAULT_DATA_LIFETIME_YEARS,
) -> list[CryptoArtifact]:
    """Classify artifacts with type, verdict, criticality, and lifetime."""
    for artifact in artifacts:
        # Look up in knowledge base for verdict
        kb_entry = kb.lookup(artifact.name)
        if kb_entry:
            artifact.verdict = Verdict(kb_entry.get("verdict", "safe"))
            # Set primitive from KB if not already set
            if not artifact.primitive:
                artifact.primitive = kb_entry.get("primitive")
        else:
            # No KB entry - for flagged items, don't default to safe
            # They remain with default verdict (SAFE) but confidence=flagged indicates review needed
            pass

        # Set defaults for lifetime
        if artifact.migration_years is None:
            artifact.migration_years = migration_years
        if artifact.data_lifetime_years is None:
            artifact.data_lifetime_years = data_lifetime_years

        # Heuristic criticality based on verdict
        if artifact.verdict == Verdict.VULNERABLE:
            artifact.criticality = "high"
        elif artifact.verdict == Verdict.WEAKENED:
            artifact.criticality = "medium"
        elif artifact.verdict == Verdict.BROKEN:
            artifact.criticality = "high"
        else:
            artifact.criticality = "low"

    return artifacts
