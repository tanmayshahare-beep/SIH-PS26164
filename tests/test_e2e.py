"""End-to-end tests for CBOMScan pipeline."""

import json
import tempfile
from pathlib import Path

import pytest

from cbomscan.__main__ import run_scan
from cbomscan.classify import classify
from cbomscan.detectors import registry
from cbomscan.export import to_cyclonedx, validate_cyclonedx
from cbomscan.knowledge_base import DEFAULT_KB_PATH, KnowledgeBase
from cbomscan.models import Verdict
from cbomscan.normalize import normalize
from cbomscan.recommend import recommend
from cbomscan.scan import scan_path
from cbomscan.score import score


def test_full_pipeline_on_fixture():
    """Test the full pipeline on the py-sample fixture."""
    fixture_path = Path(__file__).parent.parent / "fixtures" / "py-sample"
    assert fixture_path.exists()

    # Load knowledge base
    kb = KnowledgeBase.load(DEFAULT_KB_PATH)

    # SCAN + DETECT
    all_findings = []
    for file_path, content in scan_path(str(fixture_path)):
        for detector in registry.for_file(file_path):
            all_findings.extend(detector.detect(file_path, content))

    assert len(all_findings) > 0, "Should find crypto libraries in fixture"

    # NORMALIZE
    artifacts = normalize(all_findings)
    assert len(artifacts) > 0, "Should normalize to artifacts"

    # CLASSIFY
    artifacts = classify(artifacts, kb)

    # SCORE
    artifacts = score(artifacts)

    # RECOMMEND
    artifacts = recommend(artifacts, kb)

    # Check we have RSA marked as vulnerable
    rsa_artifacts = [a for a in artifacts if a.name == "RSA"]
    assert len(rsa_artifacts) == 1, "Should have exactly one RSA artifact"
    assert rsa_artifacts[0].verdict == Verdict.VULNERABLE, "RSA should be vulnerable"

    # EXPORT - generate CBOM
    bom = to_cyclonedx(artifacts)

    # Convert to dict for validation
    from cyclonedx.output.json import JsonV1Dot7
    output = JsonV1Dot7(bom)
    json_str = output.output_as_string(indent=2)
    bom_dict = json.loads(json_str)

    # Validate against CycloneDX schema
    validate_cyclonedx(bom_dict)

    # Verify CBOM structure
    assert bom_dict["bomFormat"] == "CycloneDX"
    assert bom_dict["specVersion"] == "1.7"
    assert "components" in bom_dict
    assert len(bom_dict["components"]) == len(artifacts)

    # Verify RSA component has correct properties
    rsa_components = [c for c in bom_dict["components"] if c["name"] == "RSA"]
    assert len(rsa_components) == 1
    rsa_comp = rsa_components[0]
    assert rsa_comp["type"] == "cryptographic-asset"
    assert "cryptoProperties" in rsa_comp
    assert rsa_comp["cryptoProperties"]["assetType"] == "algorithm"
    assert rsa_comp["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0
    assert rsa_comp["cryptoProperties"]["oid"] == "1.2.840.113549.1.1.1"
    assert "evidence" in rsa_comp
    assert "occurrences" in rsa_comp["evidence"]
    assert len(rsa_comp["evidence"]["occurrences"]) > 0


def test_cli_end_to_end():
    """Test the CLI end-to-end."""
    fixture_path = Path(__file__).parent.parent / "fixtures" / "py-sample"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        output_path = f.name

    try:
        # Run CLI
        import sys
        sys.argv = ["cbomscan", "scan", str(fixture_path), "-o", output_path, "-f", "json"]
        run_scan(type("Args", (), {
            "path": str(fixture_path),
            "output": output_path,
            "format": "json",
            "horizon_year": None,
            "migration_years": None,
            "data_lifetime": None,
            "kb": str(DEFAULT_KB_PATH),
            "config": str(Path(__file__).parent.parent / "cbomscan" / "config.yaml"),
            "no_validate": False,
        })())

        # Read and validate output
        with open(output_path) as f:
            bom_dict = json.load(f)

        validate_cyclonedx(bom_dict)

        # Verify structure
        assert bom_dict["bomFormat"] == "CycloneDX"
        assert bom_dict["specVersion"] == "1.7"
        assert "components" in bom_dict

        # Check for RSA
        rsa_components = [c for c in bom_dict["components"] if c["name"] == "RSA"]
        assert len(rsa_components) == 1
        rsa_comp = rsa_components[0]
        assert rsa_comp["cryptoProperties"]["algorithmProperties"][
            "nistQuantumSecurityLevel"
        ] == 0

    finally:
        Path(output_path).unlink(missing_ok=True)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
