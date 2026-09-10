"""Classify stage - assign asset type, criticality, and lifetime."""

from cbomscan.knowledge_base import KnowledgeBase
from cbomscan.models import Confidence, CryptoArtifact, Verdict

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

        # Set defaults for lifetime
        if artifact.migration_years is None:
            artifact.migration_years = migration_years
        if artifact.data_lifetime_years is None:
            artifact.data_lifetime_years = data_lifetime_years

        # Heuristic criticality based on verdict. A flagged artifact is an
        # unresolved reference, not a clean bill of health, so it never drops
        # to "low" on the strength of the default SAFE verdict.
        if artifact.verdict in (Verdict.VULNERABLE, Verdict.BROKEN):
            artifact.criticality = "high"
        elif artifact.verdict == Verdict.WEAKENED or artifact.confidence == Confidence.FLAGGED:
            artifact.criticality = "medium"
        else:
            artifact.criticality = "low"

    return artifacts
