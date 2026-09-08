"""Export stage - serialize to CycloneDX 1.7 CBOM JSON and Markdown."""

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from cbomscan.models import AssetType, CryptoArtifact, Verdict

# CycloneDX 1.7 schema URL for validation
CYCLONEDX_SCHEMA_URL = "https://cyclonedx.org/schema/bom-1.7.schema.json"


def _bom_ref(artifact: CryptoArtifact) -> str:
    """Generate a bom-ref for the artifact."""
    return f"crypto/{artifact.asset_type.value}/{artifact.id}"


def _asset_type_cyclonedx(asset_type: AssetType) -> str:
    """Map our AssetType to CycloneDX assetType."""
    mapping = {
        AssetType.ALGORITHM: "algorithm",
        AssetType.CERTIFICATE: "certificate",
        AssetType.PROTOCOL: "protocol",
        AssetType.RELATED_MATERIAL: "related-crypto-material",
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


def _build_crypto_properties(artifact: CryptoArtifact) -> dict[str, Any]:
    """Build cryptoProperties dict for CycloneDX."""
    asset_type = _asset_type_cyclonedx(artifact.asset_type)
    props = {
        "assetType": asset_type,
    }

    if asset_type == "algorithm":
        props["algorithmProperties"] = {
            "primitive": artifact.primitive or "unknown",
            "parameterSetIdentifier": str(artifact.key_size) if artifact.key_size else "unknown",
            "executionEnvironment": "software-plain-ram",
            "cryptoFunctions": _infer_crypto_functions(artifact),
            "classicalSecurityLevel": _estimate_classical_security(artifact),
            "nistQuantumSecurityLevel": _verdict_to_nist_quantum_level(artifact.verdict),
        }
        # Add OID if known
        oid = _algorithm_oid(artifact.name)
        if oid:
            props["oid"] = oid

    elif asset_type == "certificate":
        props["certificateProperties"] = {
            "subject": artifact.name,
            "signatureAlgorithm": artifact.name,
            "keyAlgorithm": artifact.primitive or "unknown",
            "keySize": artifact.key_size or 0,
        }

    return props


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
    }
    return mapping.get(artifact.primitive, [])


def _estimate_classical_security(artifact: CryptoArtifact) -> int:
    """Estimate classical security level in bits."""
    if artifact.key_size:
        if artifact.primitive in ("pke", "signature", "key-agree"):
            # RSA/DH: ~log2(key_size) - rough estimate
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


def _build_evidence(artifact: CryptoArtifact) -> dict[str, Any]:
    """Build evidence.occurrences for CycloneDX."""
    occurrences = []
    for occ in artifact.occurrences:
        occurrences.append({
            "location": occ.file,
            "line": occ.line,
            "symbol": occ.symbol,
        })
    return {"occurrences": occurrences} if occurrences else {}


def to_cyclonedx(artifacts: list[CryptoArtifact], tool_name: str = "CBOMScan") -> dict[str, Any]:
    """Convert artifacts to CycloneDX 1.7 CBOM dict."""
    components = []
    for artifact in artifacts:
        component = {
            "type": "cryptographic-asset",
            "name": artifact.name,
            "bom-ref": _bom_ref(artifact),
            "cryptoProperties": _build_crypto_properties(artifact),
        }
        evidence = _build_evidence(artifact)
        if evidence:
            component["evidence"] = evidence
        components.append(component)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{sha256(str(datetime.now()).encode()).hexdigest()[:36]}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "tools": [
                {
                    "name": tool_name,
                    "version": "0.1.0",
                }
            ],
            "component": {
                "type": "application",
                "name": "scanned-repository",
            },
        },
        "components": components,
    }
    return bom


def write_cyclonedx_json(artifacts: list[CryptoArtifact], output_path: str) -> None:
    """Write CBOM as JSON to file."""
    bom = to_cyclonedx(artifacts)
    with open(output_path, "w") as f:
        json.dump(bom, f, indent=2)


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
