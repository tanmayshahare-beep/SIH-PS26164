"""Normalize stage - deduplicate findings into CryptoArtifacts."""

from collections import defaultdict
from hashlib import sha256

from cbomscan.detectors import RawFinding
from cbomscan.models import AssetType, Confidence, CryptoArtifact


def _artifact_key(finding: RawFinding) -> str:
    """Generate a stable key for deduplication."""
    parts = [
        finding.asset_type,
        finding.name,
        str(finding.primitive or ""),
        str(finding.key_size or ""),
        str(finding.curve or ""),
    ]
    return sha256("|".join(parts).encode()).hexdigest()[:16]


def _merge_confidence(existing: Confidence, new: Confidence) -> Confidence:
    """Return the stronger confidence. FLAGGED is preserved as it indicates manual review needed."""
    # If either is FLAGGED, keep FLAGGED (it means manual review required)
    if existing == Confidence.FLAGGED or new == Confidence.FLAGGED:
        return Confidence.FLAGGED
    order = {Confidence.CONFIRMED: 3, Confidence.INFERRED: 2}
    return existing if order.get(existing, 0) >= order.get(new, 0) else new


def normalize(findings: list[RawFinding]) -> list[CryptoArtifact]:
    """Collapse RawFindings into deduplicated CryptoArtifacts."""
    groups: dict[str, list[RawFinding]] = defaultdict(list)
    for finding in findings:
        groups[_artifact_key(finding)].append(finding)

    artifacts = []
    for key, group in groups.items():
        first = group[0]
        # Merge occurrences
        all_occurrences = []
        all_metadata = {}
        for f in group:
            all_occurrences.extend(f.occurrences)
            # Merge metadata (later findings overwrite earlier for same keys)
            if f.metadata:
                all_metadata.update(f.metadata)

        # Determine strongest confidence
        confidence = Confidence.INFERRED
        for f in group:
            confidence = _merge_confidence(confidence, Confidence(f.confidence))

        artifact = CryptoArtifact(
            id=key,
            asset_type=AssetType(first.asset_type),
            name=first.name,
            primitive=first.primitive,
            key_size=first.key_size,
            curve=first.curve,
            confidence=confidence,
            occurrences=all_occurrences,
            metadata=all_metadata,
        )
        artifacts.append(artifact)

    return artifacts
