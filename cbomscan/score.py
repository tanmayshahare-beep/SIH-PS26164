"""Score stage - apply Mosca's inequality for quantum risk."""

from cbomscan.models import CryptoArtifact, Verdict


def score(
    artifacts: list[CryptoArtifact],
    horizon_year: int = 2030,
    current_year: int = 2026,
) -> list[CryptoArtifact]:
    """Apply Mosca's inequality: X + Y > Z means vulnerable.

    X = migration_years (time to replace)
    Y = data_lifetime_years (time data must stay secret)
    Z = horizon_year - current_year (years until CRQC)
    """
    Z = horizon_year - current_year

    for artifact in artifacts:
        # SAFE and BROKEN short-circuit Mosca
        if artifact.verdict == Verdict.SAFE:
            artifact.notes = (artifact.notes or "") + " | Quantum-safe"
            continue
        if artifact.verdict == Verdict.BROKEN:
            artifact.notes = (artifact.notes or "") + " | Pre-quantum broken, urgent"
            continue

        X = artifact.migration_years or 2.0
        Y = artifact.data_lifetime_years or 10

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
