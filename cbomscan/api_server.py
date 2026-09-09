"""FastAPI server for CBOMScan GUI."""

import json
import tempfile
from pathlib import Path
from typing import List

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from cbomscan.classify import classify
from cbomscan.export import write_cyclonedx_json, write_markdown_report
from cbomscan.knowledge_base import DEFAULT_KB_PATH, KnowledgeBase
from cbomscan.models import CryptoArtifact as Artifact, AssetType, Confidence, Occurrence, Verdict
from cbomscan.normalize import normalize
from cbomscan.recommend import recommend
from cbomscan.scan import run_detectors, scan_path
from cbomscan.score import score

app = FastAPI(title="CBOMScan API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    path: str
    horizon_year: int | None = None
    migration_years: float | None = None
    data_lifetime: int | None = None


class ScanResponse(BaseModel):
    artifacts: List[Artifact]
    summary: dict


class ExportRequest(BaseModel):
    artifacts: List[Artifact]


DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"


@app.post("/api/scan", response_model=ScanResponse)
async def scan_endpoint(request: ScanRequest):
    """Scan a repository and return artifacts."""
    try:
        # Load knowledge base
        kb = KnowledgeBase.load(DEFAULT_KB_PATH)

        # Load config
        config = {}
        if DEFAULT_CONFIG_PATH.exists():
            import yaml
            with open(DEFAULT_CONFIG_PATH) as f:
                config = yaml.safe_load(f) or {}

        # SCAN + DETECT
        all_findings = []
        for file_path, content in scan_path(request.path):
            findings = run_detectors(file_path, content)
            all_findings.extend(findings)

        # NORMALIZE
        artifacts = normalize(all_findings)

        # CLASSIFY
        migration_years = request.migration_years or config.get("default_migration_years", 2.0)
        data_lifetime = request.data_lifetime or config.get("default_data_lifetime_years", 10)
        artifacts = classify(artifacts, kb, migration_years, data_lifetime)

        # SCORE
        horizon_year = request.horizon_year or config.get("horizon_year", 2030)
        artifacts = score(artifacts, horizon_year=horizon_year, config_path=DEFAULT_CONFIG_PATH)

        # RECOMMEND
        artifacts = recommend(artifacts, kb)

        # Convert artifacts to dict for JSON serialization
        artifacts_dict = [artifact_to_dict(a) for a in artifacts]

        # Summary
        verdict_counts = {}
        for a in artifacts:
            verdict_counts[a.verdict.value] = verdict_counts.get(a.verdict.value, 0) + 1

        confidence_counts = {}
        for a in artifacts:
            confidence_counts[a.confidence.value] = confidence_counts.get(a.confidence.value, 0) + 1

        summary = {
            "total": len(artifacts),
            "by_verdict": verdict_counts,
            "by_confidence": confidence_counts,
        }

        return ScanResponse(artifacts=artifacts_dict, summary=summary)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/cbom")
async def download_cbom(request: ExportRequest):
    """Generate and return CBOM JSON."""
    try:
        # Convert dict artifacts back to Artifact objects
        artifacts = [dict_to_artifact(a) for a in request.artifacts]

        # Write CBOM to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            write_cyclonedx_json(artifacts, f.name, validate=False)
            temp_path = f.name

        return FileResponse(
            temp_path,
            media_type='application/json',
            filename=f'cbom-{__import__("datetime").date.today()}.json'
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/report")
async def download_report(request: ExportRequest):
    """Generate and return Markdown report."""
    try:
        artifacts = [dict_to_artifact(a) for a in request.artifacts]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            write_markdown_report(artifacts, f.name)
            temp_path = f.name

        return FileResponse(
            temp_path,
            media_type='text/markdown',
            filename=f'report-{__import__("datetime").date.today()}.md'
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def artifact_to_dict(artifact: Artifact) -> dict:
    """Convert Artifact to dict for JSON serialization."""
    return {
        "id": artifact.id,
        "asset_type": artifact.asset_type.value,
        "name": artifact.name,
        "primitive": artifact.primitive,
        "key_size": artifact.key_size,
        "curve": artifact.curve,
        "verdict": artifact.verdict.value,
        "confidence": artifact.confidence.value,
        "occurrences": [
            {"file": o.file, "line": o.line, "symbol": o.symbol}
            for o in artifact.occurrences
        ],
        "criticality": artifact.criticality,
        "data_lifetime_years": artifact.data_lifetime_years,
        "migration_years": artifact.migration_years,
        "recommendation": artifact.recommendation,
        "notes": artifact.notes,
        "metadata": artifact.metadata,
    }


def dict_to_artifact(d: dict) -> Artifact:
    """Convert dict back to Artifact object."""
    return Artifact(
        id=d["id"],
        asset_type=AssetType(d["asset_type"]),
        name=d["name"],
        primitive=d.get("primitive"),
        key_size=d.get("key_size"),
        curve=d.get("curve"),
        verdict=Verdict(d["verdict"]),
        confidence=Confidence(d["confidence"]),
        occurrences=[Occurrence(**o) for o in d.get("occurrences", [])],
        criticality=d.get("criticality", "medium"),
        data_lifetime_years=d.get("data_lifetime_years"),
        migration_years=d.get("migration_years"),
        recommendation=d.get("recommendation"),
        notes=d.get("notes"),
        metadata=d.get("metadata", {}),
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)