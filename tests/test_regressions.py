"""Regression tests: each test here pins a bug that was found and fixed.

Every test names the defect it guards against so a future change that
reintroduces it fails loudly rather than silently.
"""

import json
from datetime import datetime
from pathlib import Path

import jsonschema
import pytest
from fastapi.testclient import TestClient

from cbomscan.api_server import app
from cbomscan.classify import classify
from cbomscan.export import build_markdown_report, validate_cyclonedx, write_markdown_report
from cbomscan.knowledge_base import DEFAULT_KB_PATH, load_knowledge_base
from cbomscan.models import AssetType, Confidence, CryptoArtifact, Occurrence, Verdict
from cbomscan.normalize import normalize
from cbomscan.recommend import recommend
from cbomscan.scan import run_detectors, scan_path
from cbomscan.score import score

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture(scope="module")
def scanned() -> dict:
    """Full pipeline output for the Python fixture, as the API returns it."""
    with TestClient(app) as c:
        response = c.post("/api/scan", json={"path": str(FIXTURES / "py-sample")})
    assert response.status_code == 200
    return response.json()


# --------------------------------------------------------------------------
# The export endpoints returned 500 on every call: pydantic had already
# coerced the request body into CryptoArtifact instances, but the handlers
# still subscripted them as dicts.
# --------------------------------------------------------------------------


def test_cbom_endpoint_returns_valid_cyclonedx(client, scanned):
    response = client.post("/api/cbom", json={"artifacts": scanned["artifacts"]})

    assert response.status_code == 200, response.text
    bom = json.loads(response.text)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.7"
    assert len(bom["components"]) == len(scanned["artifacts"])
    validate_cyclonedx(bom)


def test_report_endpoint_returns_markdown(client, scanned):
    response = client.post("/api/report", json={"artifacts": scanned["artifacts"]})

    assert response.status_code == 200, response.text
    assert response.text.startswith("# CBOMScan Report")
    assert "charset=utf-8" in response.headers["content-type"]


def test_export_endpoints_accept_raw_dicts(client):
    """The handlers must work whether or not pydantic coerced the payload."""
    artifact = {
        "id": "abc123",
        "asset_type": "algorithm",
        "name": "RSA",
        "primitive": "pke",
        "key_size": 2048,
        "curve": None,
        "verdict": "vulnerable",
        "confidence": "confirmed",
        "occurrences": [{"file": "a.py", "line": 1, "symbol": "generate_private_key"}],
        "criticality": "high",
        "data_lifetime_years": 10,
        "migration_years": 2.0,
        "recommendation": "ML-KEM",
        "notes": None,
        "metadata": {},
    }
    assert client.post("/api/cbom", json={"artifacts": [artifact]}).status_code == 200
    assert client.post("/api/report", json={"artifacts": [artifact]}).status_code == 200


def test_missing_path_is_404_not_500(client):
    response = client.post("/api/scan", json={"path": "no/such/directory"})
    assert response.status_code == 404


# --------------------------------------------------------------------------
# scan_path tested skip-directory names against the whole absolute path, so
# scanning a repo that happened to live under a directory called "build",
# "dist" or "venv" silently returned zero files.
# --------------------------------------------------------------------------


def test_scan_root_may_live_under_a_skipped_directory_name(tmp_path):
    root = tmp_path / "build" / "my-repo"
    root.mkdir(parents=True)
    (root / "crypto.py").write_text("import hashlib\nhashlib.md5()\n", encoding="utf-8")

    found = [f for f, _ in scan_path(str(root))]

    assert len(found) == 1, "files under a root named 'build' must still be scanned"


def test_skip_dirs_inside_the_root_are_still_skipped(tmp_path):
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "index.js").write_text("crypto.createHash()")
    (tmp_path / "app.js").write_text("crypto.createHash('sha256')", encoding="utf-8")

    found = [f for f, _ in scan_path(str(tmp_path))]

    assert len(found) == 1
    assert "node_modules" not in found[0]


# --------------------------------------------------------------------------
# Output files were written with the platform's default encoding (cp1252 on
# Windows), which mangled non-ASCII characters and would raise outright on
# anything cp1252 cannot represent.
# --------------------------------------------------------------------------


def test_markdown_report_is_written_as_utf8(tmp_path):
    artifact = CryptoArtifact(
        id="x1",
        asset_type=AssetType.ALGORITHM,
        # Characters outside cp1252 entirely - these used to raise.
        name="RSA — 你好 ✓",
        verdict=Verdict.VULNERABLE,
        confidence=Confidence.CONFIRMED,
        occurrences=[Occurrence(file="a.py", line=1)],
    )
    out = tmp_path / "report.md"

    write_markdown_report([artifact], str(out))

    assert "你好" in out.read_text(encoding="utf-8")


def test_cbom_json_is_written_as_utf8(tmp_path):
    from cbomscan.export import write_cyclonedx_json

    artifact = CryptoArtifact(
        id="x2",
        asset_type=AssetType.ALGORITHM,
        name="AES-256 — 你好",
        verdict=Verdict.SAFE,
        confidence=Confidence.CONFIRMED,
    )
    out = tmp_path / "cbom.json"

    write_cyclonedx_json([artifact], str(out), validate=True)

    assert "你好" in json.loads(out.read_text(encoding="utf-8"))["components"][0]["name"]


# --------------------------------------------------------------------------
# Schema validation fetched the CycloneDX schema over the network and
# silently degraded to a no-op when the fetch failed, so an invalid CBOM
# could be reported as valid on any offline machine.
# --------------------------------------------------------------------------


def test_validation_rejects_a_non_conforming_document():
    with pytest.raises(jsonschema.ValidationError):
        validate_cyclonedx({"bomFormat": "NotCycloneDX", "specVersion": "1.7"})


def test_validation_works_without_network(monkeypatch):
    """Nothing in the validation path may open a socket."""
    import socket

    def refuse(*args, **kwargs):
        raise AssertionError("validation attempted a network call")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)

    bom = json.loads(
        (Path(__file__).parent / "data" / "sample-cbom.json").read_text(encoding="utf-8")
    )
    validate_cyclonedx(bom)


# --------------------------------------------------------------------------
# score() hardcoded the current year to 2026, so Mosca's Z drifted by a full
# year every January.
# --------------------------------------------------------------------------


def test_mosca_horizon_uses_the_actual_current_year():
    artifact = CryptoArtifact(
        id="m1",
        asset_type=AssetType.ALGORITHM,
        name="RSA",
        verdict=Verdict.VULNERABLE,
        confidence=Confidence.CONFIRMED,
        migration_years=1.0,
        data_lifetime_years=1,
    )
    this_year = datetime.now().year

    # Horizon far enough out that X+Y stays under Z only if Z is computed
    # from the real current year.
    score([artifact], horizon_year=this_year + 10)

    assert "Z=10" in artifact.notes, artifact.notes


def test_explicit_current_year_still_honoured():
    artifact = CryptoArtifact(
        id="m2",
        asset_type=AssetType.ALGORITHM,
        name="RSA",
        verdict=Verdict.VULNERABLE,
        confidence=Confidence.CONFIRMED,
        migration_years=2.0,
        data_lifetime_years=10,
    )
    score([artifact], horizon_year=2030, current_year=2020)
    assert "Z=10" in artifact.notes


# --------------------------------------------------------------------------
# Flagged artifacts (KMS/HSM/TLS/base-image references whose algorithm cannot
# be resolved) carry a default SAFE verdict. The scorer used to annotate them
# "Quantum-safe" and classify dropped them to "low" criticality - asserting a
# clean bill of health the scan cannot support.
# --------------------------------------------------------------------------


def test_flagged_artifacts_are_never_declared_quantum_safe():
    kb = load_knowledge_base(DEFAULT_KB_PATH)
    findings = []
    for file_path, content in scan_path(str(FIXTURES / "config-sample")):
        findings.extend(run_detectors(file_path, content))

    artifacts = recommend(score(classify(normalize(findings), kb)), kb)
    flagged = [a for a in artifacts if a.confidence == Confidence.FLAGGED]

    assert flagged, "config-sample must produce flagged artifacts"
    for artifact in flagged:
        assert "Quantum-safe" not in (artifact.notes or ""), artifact.name
        assert "manual review required" in (artifact.notes or "")
        assert artifact.criticality != "low", artifact.name


def test_summaries_report_flagged_separately_from_safe(client):
    response = client.post("/api/scan", json={"path": str(FIXTURES / "config-sample")})
    summary = response.json()["summary"]

    assert summary["needs_review"] == summary["total"]


def test_markdown_summary_does_not_count_flagged_as_safe():
    flagged = CryptoArtifact(
        id="f1",
        asset_type=AssetType.PROTOCOL,
        name="Cloud KMS: AWS KMS",
        verdict=Verdict.SAFE,
        confidence=Confidence.FLAGGED,
    )

    report = build_markdown_report([flagged])

    assert "- safe: 1" not in report
    assert "needs manual review (verdict undetermined): 1" in report


# --------------------------------------------------------------------------
# CBOM occurrence locations carried Windows backslashes, which are not
# portable across the tools that consume a CBOM.
# --------------------------------------------------------------------------


def test_occurrence_locations_use_forward_slashes(client, scanned):
    bom = json.loads(client.post("/api/cbom", json={"artifacts": scanned["artifacts"]}).text)

    locations = [
        occ["location"]
        for component in bom["components"]
        for occ in component.get("evidence", {}).get("occurrences", [])
    ]

    assert locations
    assert not any("\\" in loc for loc in locations)


# --------------------------------------------------------------------------
# Detectors reached DER certificates as UTF-8-decoded text, which never
# round-trips binary - so .der files were silently unparseable.
# --------------------------------------------------------------------------


def test_der_certificates_are_detected(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    pem = (FIXTURES / "py-sample" / "test_cert.pem").read_bytes()
    cert = x509.load_pem_x509_certificate(pem)
    der_path = tmp_path / "server.der"
    der_path.write_bytes(cert.public_bytes(serialization.Encoding.DER))

    findings = []
    for file_path, content in scan_path(str(tmp_path)):
        findings.extend(run_detectors(file_path, content))

    assert findings, "DER certificate produced no findings"
    assert any(f.asset_type == "certificate" for f in findings)


# --------------------------------------------------------------------------
# An explicit 0 on the command line / in the API request was falsy, so it
# fell through to the config default instead of being used.
# --------------------------------------------------------------------------


def test_zero_migration_years_is_honoured_not_replaced_by_default(client):
    response = client.post(
        "/api/scan",
        json={"path": str(FIXTURES / "py-sample"), "migration_years": 0, "data_lifetime": 0},
    )

    artifacts = response.json()["artifacts"]
    assert artifacts
    assert all(a["migration_years"] == 0 for a in artifacts)
    assert all(a["data_lifetime_years"] == 0 for a in artifacts)


# --------------------------------------------------------------------------
# A detector raising used to be swallowed whole, hiding real breakage.
# --------------------------------------------------------------------------


def test_failing_detector_is_logged_and_does_not_abort_the_scan(monkeypatch, caplog):
    from cbomscan.detectors import registry

    broken = registry.get("python_source")

    def explode(file_path, content):
        raise RuntimeError("boom")

    monkeypatch.setattr(broken, "detect", explode)

    with caplog.at_level("WARNING"):
        findings = run_detectors("a.py", "import hashlib")

    assert findings == []
    assert "python_source" in caplog.text
