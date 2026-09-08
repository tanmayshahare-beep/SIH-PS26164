"""Recommend stage - attach PQC/hybrid recommendations from KB."""

from cbomscan.knowledge_base import KnowledgeBase
from cbomscan.models import CryptoArtifact


def recommend(artifacts: list[CryptoArtifact], kb: KnowledgeBase) -> list[CryptoArtifact]:
    """Attach recommendations from knowledge base."""
    for artifact in artifacts:
        kb_entry = kb.lookup(artifact.name)
        if kb_entry:
            replacement = kb_entry.get("replacement")
            maturity = kb_entry.get("maturity", "unknown")
            latency_note = kb_entry.get("latency_note", "")
            hybrid_ok = kb_entry.get("hybrid_ok", False)

            parts = []
            if replacement:
                parts.append(f"Recommended: {replacement}")
            if maturity:
                parts.append(f"Maturity: {maturity}")
            if latency_note:
                parts.append(f"Note: {latency_note}")
            if hybrid_ok:
                parts.append("Hybrid mode supported during transition")

            artifact.recommendation = " | ".join(parts) if parts else None
            # Add maturity and hybrid info to notes for export
            if maturity != "unknown":
                artifact.notes = (artifact.notes or "") + f" | Maturity: {maturity}"
            if hybrid_ok:
                artifact.notes = (artifact.notes or "") + " | Hybrid OK"

    return artifacts
