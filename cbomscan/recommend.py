"""Recommend stage - attach PQC/hybrid recommendations from KB."""

from cbomscan.knowledge_base import KnowledgeBase
from cbomscan.models import CryptoArtifact, Verdict


def recommend(artifacts: list[CryptoArtifact], kb: KnowledgeBase) -> list[CryptoArtifact]:
    """Attach recommendations from knowledge base."""
    for artifact in artifacts:
        # Handle flagged confidence items first - they always need manual review
        if artifact.confidence.value == "flagged":
            artifact.recommendation = (
                "MANUAL REVIEW REQUIRED — This artifact references cryptographic infrastructure "
                "(cloud KMS/HSM, TLS configuration, or container base image) where the algorithm "
                "cannot be statically determined. Review the referenced service/configuration "
                "for quantum readiness and plan migration to PQC alternatives."
            )
            continue

        kb_entry = kb.lookup(artifact.name)
        if kb_entry:
            replacement = kb_entry.get("replacement")
            maturity = kb_entry.get("maturity", "unknown")
            latency_note = kb_entry.get("latency_note", "")
            hybrid_ok = kb_entry.get("hybrid_ok", False)
            reason = kb_entry.get("reason", "")

            parts = []
            if replacement:
                parts.append(f"Recommended: {replacement}")
            if maturity:
                parts.append(f"Maturity: {maturity}")
            if latency_note:
                parts.append(f"Note: {latency_note}")
            if hybrid_ok:
                parts.append("Hybrid mode supported during transition")
            if reason:
                parts.append(f"Reason: {reason}")

            artifact.recommendation = " | ".join(parts) if parts else None

            # Add maturity and hybrid info to notes for export
            if maturity != "unknown":
                artifact.notes = (artifact.notes or "") + f" | Maturity: {maturity}"
            if hybrid_ok:
                artifact.notes = (artifact.notes or "") + " | Hybrid OK"
        else:
            # No KB entry - handle based on verdict
            if artifact.verdict == Verdict.SAFE:
                artifact.recommendation = "No action — quantum-resistant"
            elif artifact.verdict in (Verdict.VULNERABLE, Verdict.WEAKENED, Verdict.BROKEN):
                artifact.recommendation = (
                    f"No specific recommendation in KB — migrate to NIST PQC standard "
                    f"(ML-KEM for KEX, ML-DSA for signatures, AES-256 for symmetric)"
                )
            else:
                artifact.recommendation = "Review required"

    return artifacts