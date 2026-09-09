from dataclasses import dataclass, field
from enum import StrEnum


class AssetType(StrEnum):
    ALGORITHM = "algorithm"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    RELATED_MATERIAL = "related-crypto-material"


class Verdict(StrEnum):
    VULNERABLE = "vulnerable"
    WEAKENED = "weakened"
    BROKEN = "broken"
    SAFE = "safe"


class Confidence(StrEnum):
    CONFIRMED = "confirmed"
    INFERRED = "inferred"
    FLAGGED = "flagged"


@dataclass
class Occurrence:
    file: str
    line: int | None = None
    symbol: str | None = None


@dataclass
class CryptoArtifact:
    id: str
    asset_type: AssetType
    name: str
    primitive: str | None = None
    key_size: int | None = None
    curve: str | None = None
    verdict: Verdict = Verdict.SAFE
    confidence: Confidence = Confidence.INFERRED
    occurrences: list[Occurrence] = field(default_factory=list)
    criticality: str = "medium"
    data_lifetime_years: int | None = None
    migration_years: float | None = None
    recommendation: str | None = None
    notes: str | None = None
    metadata: dict = field(default_factory=dict)
