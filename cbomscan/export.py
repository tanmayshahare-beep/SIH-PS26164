"""Export stage - serialize to CycloneDX 1.7 CBOM JSON and Markdown."""

import json
import urllib.request
from datetime import UTC, datetime

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
from cyclonedx.model.tool import Tool
from cyclonedx.output.json import JsonV1Dot7

from cbomscan.models import AssetType, CryptoArtifact, Verdict

# CycloneDX 1.7 schema URL for validation
CYCLONEDX_SCHEMA_URL = "https://cyclonedx.org/schema/bom-1.7.schema.json"


def _fetch_schema() -> dict | None:
    """Fetch the CycloneDX 1.7 JSON schema. Returns None if fetch fails."""
    try:
        req = urllib.request.Request(
            CYCLONEDX_SCHEMA_URL,
            headers={"User-Agent": "CBOMScan/0.1.0"},
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.load(response)
    except Exception:
        return None


_CACHED_SCHEMA: dict | None = None


def _get_schema() -> dict | None:
    """Get the CycloneDX schema, caching it."""
    global _CACHED_SCHEMA
    if _CACHED_SCHEMA is None:
        _CACHED_SCHEMA = _fetch_schema()
    return _CACHED_SCHEMA


def validate_cyclonedx(bom_dict: dict) -> None:
    """Validate a CBOM dict against the CycloneDX 1.7 schema."""
    schema = _get_schema()
    if schema is None:
        # Skip validation if schema can't be fetched
        return
    jsonschema.validate(instance=bom_dict, schema=schema)


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
        Verdict.WEAKENED: 1,    # Weakened by Grover
        Verdict.BROKEN: 0,      # Already broken
        Verdict.SAFE: 3,        # Quantum-safe (Level 3+)
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
                    location=occ.file,
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
    bom.metadata.tools = [Tool(name=tool_name, version="0.1.0")]
    bom.metadata.component = Component(type=ComponentType.APPLICATION, name="scanned-repository")
    return bom


def write_cyclonedx_json(
    artifacts: list[CryptoArtifact],
    output_path: str,
    validate: bool = True,
) -> None:
    """Write CBOM as JSON to file using cyclonedx-python-lib."""
    bom = to_cyclonedx(artifacts)
    output = JsonV1Dot7(bom)
    json_str = output.output_as_string(indent=2)

    if validate:
        # Parse back to dict for validation
        bom_dict = json.loads(json_str)
        validate_cyclonedx(bom_dict)

    with open(output_path, "w") as f:
        f.write(json_str)


def write_markdown_report(artifacts: list[CryptoArtifact], output_path: str) -> None:
    """Write human-readable Markdown report."""
    lines = [
        "# CBOMScan Report",
        f"Generated: {datetime.now(UTC).isoformat()}",
        f"Artifacts found: {len(artifacts)}",
        "",
        "## Summary by Verdict",
    ]

    # Count by verdict
    verdict_counts = {}
    for a in artifacts:
        verdict_counts[a.verdict.value] = verdict_counts.get(a.verdict.value, 0) + 1

    for verdict, count in sorted(verdict_counts.items()):
        lines.append(f"- {verdict}: {count}")

    lines.append("")
    lines.append("## Artifacts")

    for artifact in sorted(artifacts, key=lambda a: (a.verdict.value, a.name)):
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

    with open(output_path, "w") as f:
        f.write("\n".join(lines))
