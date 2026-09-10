"""FastAPI server for CBOMScan GUI."""

import logging
from datetime import date
from pathlib import Path

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from cbomscan import __version__
from cbomscan.classify import classify
from cbomscan.detectors import registry
from cbomscan.export import build_markdown_report, to_cyclonedx_json
from cbomscan.knowledge_base import DEFAULT_KB_PATH, load_knowledge_base
from cbomscan.models import AssetType, Confidence, Occurrence, Verdict
from cbomscan.models import CryptoArtifact as Artifact
from cbomscan.normalize import normalize
from cbomscan.recommend import recommend
from cbomscan.scan import run_detectors, scan_path
from cbomscan.score import score

logger = logging.getLogger(__name__)

app = FastAPI(title="CBOMScan API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"
FRONTEND_DIST = Path(__file__).parent.parent / "frontend" / "dist"


class ScanRequest(BaseModel):
    path: str
    horizon_year: int | None = None
    migration_years: float | None = None
    data_lifetime: int | None = None


class ScanResponse(BaseModel):
    artifacts: list[Artifact]
    summary: dict


class ExportRequest(BaseModel):
    artifacts: list[Artifact]


def _load_config() -> dict:
    if DEFAULT_CONFIG_PATH.exists():
        with open(DEFAULT_CONFIG_PATH, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


def _as_artifacts(artifacts: list) -> list[Artifact]:
    """Accept either dataclass instances or plain dicts.

    Pydantic already coerces the request body into CryptoArtifact instances, so
    the export endpoints must not assume they are still dicts.
    """
    return [a if isinstance(a, Artifact) else dict_to_artifact(a) for a in artifacts]


@app.get("/api/health")
async def health() -> dict:
    """Liveness probe - used by the launcher to know when the server is up."""
    return {"status": "ok", "version": __version__}


@app.get("/api/detectors")
async def detectors() -> list[dict]:
    """Self-description of every diagnostic tool, for the app's Tools page."""
    return registry.describe()


@app.get("/api/config")
async def get_config() -> dict:
    """Defaults the UI should start from, plus the knowledge base size."""
    config = _load_config()
    kb = load_knowledge_base(DEFAULT_KB_PATH)
    return {
        "version": __version__,
        "horizon_year": config.get("horizon_year", 2030),
        "default_migration_years": config.get("default_migration_years", 2.0),
        "default_data_lifetime_years": config.get("default_data_lifetime_years", 10),
        "knowledge_base_entries": len(kb.all_entries()),
    }


@app.get("/api/knowledge-base")
async def knowledge_base() -> list[dict]:
    """The algorithm knowledge base backing every verdict and recommendation."""
    return load_knowledge_base(DEFAULT_KB_PATH).all_entries()


@app.post("/api/scan", response_model=ScanResponse)
async def scan_endpoint(request: ScanRequest) -> ScanResponse:
    """Scan a repository and return artifacts."""
    kb = load_knowledge_base(DEFAULT_KB_PATH)
    config = _load_config()

    try:
        # SCAN + DETECT
        all_findings = []
        for file_path, content in scan_path(request.path):
            all_findings.extend(run_detectors(file_path, content))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"Cannot read path: {exc}") from exc

    # NORMALIZE
    artifacts = normalize(all_findings)

    # CLASSIFY - an explicit 0 from the client must not fall back to the default
    migration_years = (
        request.migration_years
        if request.migration_years is not None
        else config.get("default_migration_years", 2.0)
    )
    data_lifetime = (
        request.data_lifetime
        if request.data_lifetime is not None
        else config.get("default_data_lifetime_years", 10)
    )
    artifacts = classify(artifacts, kb, migration_years, data_lifetime)

    # SCORE
    horizon_year = (
        request.horizon_year
        if request.horizon_year is not None
        else config.get("horizon_year", 2030)
    )
    artifacts = score(artifacts, horizon_year=horizon_year, config_path=DEFAULT_CONFIG_PATH)

    # RECOMMEND
    artifacts = recommend(artifacts, kb)

    return ScanResponse(
        artifacts=[artifact_to_dict(a) for a in artifacts],
        summary=summarize(artifacts),
    )


@app.post("/api/cbom")
async def download_cbom(request: ExportRequest) -> Response:
    """Generate and return CBOM JSON."""
    try:
        json_str = to_cyclonedx_json(_as_artifacts(request.artifacts))
    except Exception as exc:
        logger.exception("CBOM export failed")
        raise HTTPException(status_code=500, detail=f"CBOM export failed: {exc}") from exc

    filename = f"cbom-{date.today()}.json"
    return Response(
        content=json_str,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/report")
async def download_report(request: ExportRequest) -> Response:
    """Generate and return Markdown report."""
    try:
        markdown = build_markdown_report(_as_artifacts(request.artifacts))
    except Exception as exc:
        logger.exception("Report export failed")
        raise HTTPException(status_code=500, detail=f"Report export failed: {exc}") from exc

    filename = f"report-{date.today()}.md"
    return Response(
        content=markdown,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def summarize(artifacts: list[Artifact]) -> dict:
    """Counts by verdict and confidence, plus the manual-review backlog."""
    verdict_counts: dict[str, int] = {}
    confidence_counts: dict[str, int] = {}
    for a in artifacts:
        verdict_counts[a.verdict.value] = verdict_counts.get(a.verdict.value, 0) + 1
        confidence_counts[a.confidence.value] = confidence_counts.get(a.confidence.value, 0) + 1

    return {
        "total": len(artifacts),
        "by_verdict": verdict_counts,
        "by_confidence": confidence_counts,
        # Flagged artifacts carry a default SAFE verdict only because the
        # algorithm could not be resolved - report them separately so the
        # summary never reads as a clean bill of health.
        "needs_review": confidence_counts.get(Confidence.FLAGGED.value, 0),
    }


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
            {"file": o.file, "line": o.line, "symbol": o.symbol} for o in artifact.occurrences
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


def mount_frontend(dist_dir: Path | None = None) -> bool:
    """Serve the built React app from the API server.

    The packaged desktop build has no Vite dev server to proxy /api, so the
    same origin has to serve both. Returns False if no build is present.
    """
    dist = dist_dir or FRONTEND_DIST
    index = dist / "index.html"
    if not index.is_file():
        logger.warning("No frontend build at %s - serving API only", dist)
        return False

    app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

    @app.get("/{full_path:path}")
    async def spa(full_path: str) -> FileResponse:
        candidate = dist / full_path
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(index)

    return True


if __name__ == "__main__":
    import uvicorn

    mount_frontend()
    uvicorn.run(app, host="127.0.0.1", port=8000)
