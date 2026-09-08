"""Score stage - apply Mosca's inequality for quantum risk."""

from pathlib import Path

import yaml

from cbomscan.models import CryptoArtifact, Verdict

DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"


def _load_config(path: Path | None = None) -> dict:
    """Load configuration from YAML file."""
    config_path = path or DEFAULT_CONFIG_PATH
    if config_path.exists():
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    return {}


def score(
    artifacts: list[CryptoArtifact],
    horizon_year: int | None = None,
    current_year: int = 2026,
    config_path: Path | None = None,
) -> list[CryptoArtifact]:
    """Apply Mosca's inequality: X + Y > Z means vulnerable.

    X = migration_years (time to replace)
    Y = data_lifetime_years (time data must stay secret)
    Z = horizon_year - current_year (years until CRQC)

    SAFE and BROKEN verdicts short-circuit Mosca.
    """
    config = _load_config(config_path)
    Z = (horizon_year or config.get("horizon_year", 2030)) - current_year
    default_migration = config.get("default_migration_years", 2.0)
    default_lifetime = config.get("default_data_lifetime_years", 10)

    for artifact in artifacts:
        # SAFE and BROKEN short-circuit Mosca
        if artifact.verdict == Verdict.SAFE:
            artifact.notes = (artifact.notes or "") + " | Quantum-safe"
            continue
        if artifact.verdict == Verdict.BROKEN:
            artifact.notes = (artifact.notes or "") + " | Pre-quantum broken, urgent"
            continue

        X = artifact.migration_years or default_migration
        Y = artifact.data_lifetime_years or default_lifetime

        if X + Y > Z:
            artifact.notes = (
                f"Mosca: X+Y={X+Y:.1f} > Z={Z} (X={X}, Y={Y}, Z={Z}) | "
                f"Quantum risk: URGENT"
            )
        else:
            artifact.notes = (
                f"Mosca: X+Y={X+Y:.1f} <= Z={Z} (X={X}, Y={Y}, Z={Z}) | "
                f"Quantum risk: within horizon"
            )

    return artifacts
