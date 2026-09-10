"""Export stage - serialize to CycloneDX 1.7 CBOM JSON and Markdown."""

import json
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

import jsonschema
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import (
    AlgorithmProperties,
    CryptoAssetType,
    CryptoExecutionEnvironment,
    CryptoFunction,
    CryptoPrimitive,
    CryptoProperties,
)
from cyclonedx.output.json import JsonV1Dot7
from referencing import Registry, Resource

from cbomscan.models import AssetType, Confidence, CryptoArtifact, Verdict

# The CycloneDX 1.7 schema (and the two schemas it references) ship with the
# package. Validation used to fetch them over the network on every run, which
# made it slow, and silently degraded to "no validation at all" whenever the
# machine was offline - so a CBOM could be reported as valid without ever
# having been checked.
SCHEMA_DIR = Path(__file__).parent / "schemas"
CYCLONEDX_SCHEMA = "bom-1.7.schema.json"


@lru_cache(maxsize=1)
def _schema_registry() -> tuple[dict, Registry]:
    """Load the bundled CycloneDX schema and its referenced schemas."""
    resources = []
    for path in SCHEMA_DIR.glob("*.json"):
        contents = json.loads(path.read_text(encoding="utf-8"))
        # Register under the schema's own $id so the relative $refs inside
        # bom-1.7 (spdx.schema.json, jsf-0.82.schema.json) resolve locally.
        resources.append((contents["$id"], Resource.from_contents(contents)))
    registry = Registry().with_resources(resources)
    root = json.loads((SCHEMA_DIR / CYCLONEDX_SCHEMA).read_text(encoding="utf-8"))
    return root, registry


def validate_cyclonedx(bom_dict: dict) -> None:
    """Validate a CBOM dict against the bundled CycloneDX 1.7 schema.

    Raises jsonschema.ValidationError if the document does not conform.
    """
    schema, registry = _schema_registry()
    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls(schema, registry=registry).validate(bom_dict)


def _bom_ref(artifact: CryptoArtifact) -> str:
    """Generate a bom-ref for the artifact."""
    return f"crypto/{artifact.asset_type.value}/{artifact.id}"


def _asset_type_cyclonedx(asset_type: AssetType) -> CryptoAssetType:
    """Map our AssetType to CycloneDX CryptoAssetType."""
    mapping = {
        AssetType.ALGORITHM: CryptoAssetType.ALGORITHM,
        AssetType.CERTIFICATE: CryptoAssetType.CERTIFICATE,
        AssetType.PROTOCOL: CryptoAssetType.PROTOCOL,
        AssetType.RELATED_MATERIAL: CryptoAssetType.RELATED_CRYPTO_MATERIAL,
    }
    return mapping[asset_type]


def _verdict_to_nist_quantum_level(verdict: Verdict) -> int:
    """Map our Verdict to NIST quantum security level."""
    mapping = {
        Verdict.VULNERABLE: 0,  # Quantum-broken
        Verdict.WEAKENED: 1,  # Weakened by Grover
        Verdict.BROKEN: 0,  # Already broken
        Verdict.SAFE: 3,  # Quantum-safe (Level 3+)
    }
    return mapping[verdict]


def _primitive_to_cyclonedx(primitive: str | None) -> CryptoPrimitive:
    """Map our primitive to CycloneDX CryptoPrimitive."""
    if not primitive:
        return CryptoPrimitive.UNKNOWN
    mapping = {
        "pke": CryptoPrimitive.PKE,
        "signature": CryptoPrimitive.SIGNATURE,
        "key-agree": CryptoPrimitive.KEY_AGREE,
        "hash": CryptoPrimitive.HASH,
        "block-cipher": CryptoPrimitive.BLOCK_CIPHER,
        "stream-cipher": CryptoPrimitive.STREAM_CIPHER,
        "mac": CryptoPrimitive.MAC,
        "kdf": CryptoPrimitive.KDF,
    }
    return mapping.get(primitive, CryptoPrimitive.UNKNOWN)


def _crypto_functions_to_cyclonedx(functions: list[str]) -> list[CryptoFunction]:
    """Map our crypto functions to CycloneDX CryptoFunction."""
    mapping = {
        "encrypt": CryptoFunction.ENCRYPT,
        "decrypt": CryptoFunction.DECRYPT,
        "sign": CryptoFunction.SIGN,
        "verify": CryptoFunction.VERIFY,
        "derive-bits": CryptoFunction.KEYDERIVE,
        "derive-key": CryptoFunction.KEYDERIVE,
        "hash": CryptoFunction.DIGEST,
        "mac-generate": CryptoFunction.TAG,
        "mac-verify": CryptoFunction.TAG,
        "kdf": CryptoFunction.KEYDERIVE,
        "key-wrap": CryptoFunction.ENCAPSULATE,
        "key-unwrap": CryptoFunction.DECAPSULATE,
        "random-generation": CryptoFunction.GENERATE,
    }
    return [mapping.get(f, CryptoFunction.ENCRYPT) for f in functions]


def _infer_crypto_functions(artifact: CryptoArtifact) -> list[str]:
    """Infer crypto functions from artifact."""
    if not artifact.primitive:
        return []

    mapping = {
        "pke": ["encrypt", "decrypt"],
        "signature": ["sign", "verify"],
        "key-agree": ["derive-bits", "derive-key"],
        "hash": ["hash"],
        "block-cipher": ["encrypt", "decrypt"],
        "stream-cipher": ["encrypt", "decrypt"],
        "mac": ["mac-generate", "mac-verify"],
        "kdf": ["kdf"],
    }
    return mapping.get(artifact.primitive, [])


def _estimate_classical_security(artifact: CryptoArtifact) -> int:
    """Estimate classical security level in bits."""
    if artifact.key_size:
        if artifact.primitive in ("pke", "signature", "key-agree"):
            # RSA/DH: rough estimate based on key size
            if artifact.key_size >= 3072:
                return 128
            elif artifact.key_size >= 2048:
                return 112
            elif artifact.key_size >= 1024:
                return 80
        elif artifact.primitive in ("block-cipher", "stream-cipher"):
            return artifact.key_size
    return 0


def _algorithm_oid(name: str) -> str | None:
    """Return OID for known algorithms."""
    oids = {
        "RSA": "1.2.840.113549.1.1.1",
        "RSA-2048": "1.2.840.113549.1.1.1",
        "RSA-3072": "1.2.840.113549.1.1.1",
        "RSA-4096": "1.2.840.113549.1.1.1",
        "ECDSA": "1.2.840.10045.4.3.2",
        "ECDH": "1.3.132.1.12",
        "Ed25519": "1.3.101.112",
        "X25519": "1.3.101.110",
        "AES-128": "2.16.840.1.101.3.4.1.2",
        "AES-256": "2.16.840.1.101.3.4.1.42",
        "SHA-256": "2.16.840.1.101.3.4.2.1",
        "SHA-384": "2.16.840.1.101.3.4.2.2",
        "SHA-512": "2.16.840.1.101.3.4.2.3",
        "SHA-1": "1.3.14.3.2.26",
        "MD5": "1.2.840.113549.2.5",
        "3DES": "1.2.840.113549.3.7",
    }
    return oids.get(name)


def _build_cyclonedx_component(artifact: CryptoArtifact) -> Component:
    """Build a CycloneDX Component for a CryptoArtifact."""
    asset_type = _asset_type_cyclonedx(artifact.asset_type)

    crypto_props = CryptoProperties(asset_type=asset_type)

    if asset_type == CryptoAssetType.ALGORITHM:
        algo_props = AlgorithmProperties(
            primitive=_primitive_to_cyclonedx(artifact.primitive),
            parameter_set_identifier=str(artifact.key_size) if artifact.key_size else "unknown",
            execution_environment=CryptoExecutionEnvironment.SOFTWARE_PLAIN_RAM,
            crypto_functions=_crypto_functions_to_cyclonedx(_infer_crypto_functions(artifact)),
            classical_security_level=_estimate_classical_security(artifact),
            nist_quantum_security_level=_verdict_to_nist_quantum_level(artifact.verdict),
        )
        crypto_props.algorithm_properties = algo_props

        oid = _algorithm_oid(artifact.name)
        if oid:
            crypto_props.oid = oid

    # Build evidence occurrences
    from cyclonedx.model.component_evidence import ComponentEvidence
    from cyclonedx.model.component_evidence import Occurrence as CycloneDxOccurrence

    evidence = None
    if artifact.occurrences:
        cyclo_occurrences = []
        for occ in artifact.occurrences:
            cyclo_occurrences.append(
                CycloneDxOccurrence(
                    location=occ.file.replace("\\", "/"),
                    line=occ.line,
                    symbol=occ.symbol,
                )
            )
        evidence = ComponentEvidence(occurrences=cyclo_occurrences)

    component = Component(
        type=ComponentType.CRYPTOGRAPHIC_ASSET,
        name=artifact.name,
        bom_ref=_bom_ref(artifact),
        crypto_properties=crypto_props,
        evidence=evidence,
    )
    return component


def to_cyclonedx(artifacts: list[CryptoArtifact], tool_name: str = "CBOMScan") -> Bom:
    """Convert artifacts to CycloneDX 1.7 BOM object."""
    components = [_build_cyclonedx_component(a) for a in artifacts]

    bom = Bom()
    bom.components = components
    bom.metadata.tools.components.add(
        Component(type=ComponentType.APPLICATION, name=tool_name, version="0.1.0")
    )
    root = Component(type=ComponentType.APPLICATION, name="scanned-repository")
    bom.metadata.component = root
    # Register the crypto assets as dependencies of the scanned repository so
    # the dependency graph is complete rather than a dangling root.
    bom.register_dependency(root, components)
    return bom


def to_cyclonedx_json(
    artifacts: list[CryptoArtifact],
    validate: bool = True,
) -> str:
    """Serialize artifacts to a CycloneDX 1.7 CBOM JSON string."""
    bom = to_cyclonedx(artifacts)
    json_str = JsonV1Dot7(bom).output_as_string(indent=2)

    if validate:
        validate_cyclonedx(json.loads(json_str))

    return json_str


def write_cyclonedx_json(
    artifacts: list[CryptoArtifact],
    output_path: str,
    validate: bool = True,
) -> None:
    """Write CBOM as JSON to file using cyclonedx-python-lib."""
    json_str = to_cyclonedx_json(artifacts, validate=validate)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(json_str)


def write_markdown_report(artifacts: list[CryptoArtifact], output_path: str) -> None:
    """Write human-readable Markdown report."""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(build_markdown_report(artifacts))


def build_markdown_report(artifacts: list[CryptoArtifact]) -> str:
    """Render the human-readable Markdown report as a string."""
    lines = [
        "# CBOMScan Report",
        f"Generated: {datetime.now(UTC).isoformat()}",
        f"Artifacts found: {len(artifacts)}",
        "",
        "## Summary by Verdict",
    ]

    # Count by verdict. Flagged artifacts hold a default SAFE verdict only
    # because their algorithm could not be resolved, so they are counted
    # separately rather than inflating the "safe" total.
    verdict_counts: dict[str, int] = {}
    needs_review = 0
    for a in artifacts:
        if a.confidence == Confidence.FLAGGED:
            needs_review += 1
            continue
        verdict_counts[a.verdict.value] = verdict_counts.get(a.verdict.value, 0) + 1

    for verdict, count in sorted(verdict_counts.items()):
        lines.append(f"- {verdict}: {count}")
    if needs_review:
        lines.append(f"- needs manual review (verdict undetermined): {needs_review}")

    # Count by confidence
    lines.append("")
    lines.append("## Summary by Confidence")
    confidence_counts = {}
    for a in artifacts:
        confidence_counts[a.confidence.value] = confidence_counts.get(a.confidence.value, 0) + 1
    for conf, count in sorted(confidence_counts.items()):
        lines.append(f"- {conf}: {count}")

    # Requires Manual Review section
    flagged_artifacts = [a for a in artifacts if a.confidence == Confidence.FLAGGED]
    if flagged_artifacts:
        lines.append("")
        lines.append("## [WARNING] Requires Manual Review")
        lines.append(
            "The following artifacts were detected with `flagged` confidence - "
            "they reference cryptographic infrastructure (cloud KMS/HSM, TLS config, "
            "container images) where the algorithm cannot be statically determined. "
            "Manual review is required to assess quantum readiness."
        )
        lines.append("")
        for artifact in sorted(flagged_artifacts, key=lambda a: a.name):
            lines.append(f"### {artifact.name} ({artifact.asset_type.value})")
            lines.append(f"- **ID**: {artifact.id}")
            lines.append(f"- **Verdict**: {artifact.verdict.value}")
            lines.append(f"- **Confidence**: {artifact.confidence.value} [FLAGGED]")
            if artifact.primitive:
                lines.append(f"- **Primitive**: {artifact.primitive}")
            if artifact.recommendation:
                lines.append(f"- **Recommendation**: {artifact.recommendation}")
            if artifact.notes:
                lines.append(f"- **Notes**: {artifact.notes}")
            if artifact.metadata:
                # Include relevant metadata for flagged items
                for key, value in artifact.metadata.items():
                    if key not in ("matched_pattern", "raw_line"):
                        lines.append(f"- **{key.replace('_', ' ').title()}**: {value}")
            if artifact.occurrences:
                lines.append("- **Occurrences**:")
                for occ in artifact.occurrences:
                    loc = f"{occ.file}"
                    if occ.line:
                        loc += f":{occ.line}"
                    if occ.symbol:
                        loc += f" ({occ.symbol})"
                    lines.append(f"  - {loc}")
            lines.append("")

    lines.append("## All Artifacts")

    for artifact in sorted(artifacts, key=lambda a: (a.verdict.value, a.name)):
        # Skip flagged artifacts as they're already in the manual review section
        if artifact.confidence == Confidence.FLAGGED:
            continue
        lines.append(f"### {artifact.name} ({artifact.asset_type.value})")
        lines.append(f"- **ID**: {artifact.id}")
        lines.append(f"- **Verdict**: {artifact.verdict.value}")
        lines.append(f"- **Confidence**: {artifact.confidence.value}")
        if artifact.primitive:
            lines.append(f"- **Primitive**: {artifact.primitive}")
        if artifact.key_size:
            lines.append(f"- **Key Size**: {artifact.key_size}")
        if artifact.curve:
            lines.append(f"- **Curve**: {artifact.curve}")
        if artifact.recommendation:
            lines.append(f"- **Recommendation**: {artifact.recommendation}")
        if artifact.notes:
            lines.append(f"- **Notes**: {artifact.notes}")
        if artifact.occurrences:
            lines.append("- **Occurrences**:")
            for occ in artifact.occurrences:
                loc = f"{occ.file}"
                if occ.line:
                    loc += f":{occ.line}"
                if occ.symbol:
                    loc += f" ({occ.symbol})"
                lines.append(f"  - {loc}")
        lines.append("")

    return "\n".join(lines)
