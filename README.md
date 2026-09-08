# CBOMScan

**Cryptographic Bill of Materials Scanner** — A tool that scans Python & JavaScript repositories for cryptographic assets, scores their quantum risk via Mosca's inequality, recommends post-quantum replacements, and exports a standards-compliant CycloneDX 1.7 CBOM.

## Features

- **Manifest Detection** — Parses `requirements.txt`, `pyproject.toml`, `package.json` to identify crypto libraries
- **Source Detection** — AST-based detection of crypto API calls in Python/JS source (planned)
- **Certificate Parsing** — X.509 certificate analysis for signature algorithms (planned)
- **Config Detection** — IaC/Config reference detection for KMS/HSM/TLS (planned)
- **Quantum Risk Scoring** — Applies Mosca's inequality (X + Y > Z) with configurable horizon
- **PQC Recommendations** — Maps vulnerable algorithms to NIST-standardized replacements (ML-KEM, ML-DSA, SLH-DSA)
- **CycloneDX 1.7 CBOM Export** — Standards-compliant JSON output with schema validation
- **Markdown Reports** — Human-readable summaries with risk categorization
- **Confidence Model** — Every finding carries `confirmed` | `inferred` | `flagged` confidence

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/tanmayshahare-beep/SIH-PS26164
cd SIH-PS26164

# Install in development mode
pip install -e .[dev]
```

Requires Python 3.11+.

### Basic Usage

```bash
# Scan a local Python repository
python -m cbomscan scan ./path/to/repo -o cbom.json

# Scan and generate Markdown report
python -m cbomscan scan ./path/to/repo -o report.md -f md

# Custom quantum horizon (years until CRQC)
python -m cbomscan scan ./repo -o cbom.json --horizon-year 2035

# Custom migration time and data lifetime
python -m cbomscan scan ./repo -o cbom.json --migration-years 3.0 --data-lifetime 20

# Skip schema validation (faster)
python -m cbomscan scan ./repo -o cbom.json --no-validate
```

### Command Reference

```
usage: cbomscan [-h] [-o OUTPUT] [-f {json,md}] [--horizon-year HORIZON_YEAR]
                [--migration-years MIGRATION_YEARS] [--data-lifetime DATA_LIFETIME]
                [--kb KB] [--config CONFIG] [--no-validate]
                {scan} path

Cryptographic Bill of Materials Scanner

positional arguments:
  {scan}                Command to run
  path                  Path to scan (local directory)

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output file path (default: cbom.json)
  -f {json,md}, --format {json,md}
                        Output format (default: json)
  --horizon-year HORIZON_YEAR
                        Years until CRQC (default: from config.yaml)
  --migration-years MIGRATION_YEARS
                        Migration time in years (default: from config.yaml)
  --data-lifetime DATA_LIFETIME
                        Data lifetime in years (default: from config.yaml)
  --kb KB               Path to knowledge base YAML
  --config CONFIG       Path to config YAML
  --no-validate         Skip CBOM schema validation
```

## Configuration

### config.yaml

```yaml
# CBOMScan configuration
horizon_year: 2030           # Z = years until CRQC
default_migration_years: 2.0 # X = migration time in years
default_data_lifetime_years: 10 # Y = data lifetime in years
```

### knowledge_base.yaml

Contains ~25 algorithm entries with:
- **Verdict**: `vulnerable` | `weakened` | `broken` | `safe`
- **Replacement**: NIST FIPS PQC algorithm (ML-KEM, ML-DSA, SLH-DSA)
- **Maturity**: `nist-standardized` | `draft` | `deprecated`
- **Latency Note**: Performance characteristics
- **Hybrid OK**: Whether hybrid mode is supported during transition

## Output

### CycloneDX 1.7 CBOM (JSON)

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "components": [
    {
      "type": "cryptographic-asset",
      "name": "RSA-2048",
      "bom-ref": "crypto/algorithm/...",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "pke",
          "parameterSetIdentifier": "2048",
          "executionEnvironment": "software-plain-ram",
          "cryptoFunctions": ["encrypt", "decrypt"],
          "classicalSecurityLevel": 112,
          "nistQuantumSecurityLevel": 0
        },
        "oid": "1.2.840.113549.1.1.1"
      },
      "evidence": {
        "occurrences": [
          { "location": "requirements.txt", "line": null, "symbol": null }
        ]
      }
    }
  ]
}
```

- `nistQuantumSecurityLevel: 0` = quantum-vulnerable (broken by Shor's)
- `nistQuantumSecurityLevel: 1` = weakened by Grover's
- `nistQuantumSecurityLevel: 3` = quantum-safe

### Markdown Report

Human-readable summary with:
- Verdict counts (vulnerable/weakened/broken/safe)
- Per-artifact details: primitive, key size, recommendation, Mosca score, occurrences

## Architecture

Seven-stage pipeline:

```
SCAN → DETECT → NORMALIZE → CLASSIFY → SCORE → RECOMMEND → EXPORT
```

- **Detectors** plug into a registry — add coverage by adding a `Detector` subclass
- **CryptoArtifact** is the unified data model (see `cbomscan/models.py`)
- **Knowledge Base** drives both scoring (verdict) and recommendations

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=cbomscan

# Lint
ruff check cbomscan tests

# Type check
mypy cbomscan
```

## Project Structure

```
cbomscan/
├── __main__.py          # CLI entry point
├── models.py            # CryptoArtifact, Verdict, Confidence, AssetType
├── scan.py              # File discovery & detector dispatch
├── detectors/
│   ├── __init__.py      # Registry + base classes
│   └── manifest.py      # ManifestDetector (requirements.txt, pyproject.toml)
├── normalize.py         # Deduplication
├── classify.py          # Asset type, verdict, criticality
├── score.py             # Mosca inequality
├── recommend.py         # PQC/hybrid recommendations
├── export.py            # CycloneDX 1.7 + Markdown
├── knowledge_base.py    # KB loader
├── knowledge_base.yaml  # Algorithm database
└── config.yaml          # Default Z, X, Y values
```

## Scope

| Artifact Class | Fidelity | Method |
|---|---|---|
| Algorithms in dependencies | `inferred` | Manifest parsing |
| Algorithms in source | `confirmed` | AST + string literal proximity (planned) |
| Certificates | `confirmed` | X.509 parsing (planned) |
| Cloud KMS/HSM/TLS refs | `flagged` | IaC/config parsing (planned) |
| Container images | `flagged` | Dockerfile `FROM` references (planned) |

**Out of scope**: Deep container layer unpacking, compiled binary analysis, live network probing, languages beyond Python/JS.

## License

MIT License — see LICENSE file for details.

## References

- [CycloneDX 1.7 Specification](https://cyclonedx.org/specification/overview/)
- [NIST PQC Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Mosca's Inequality](https://eprint.iacr.org/2015/1075)
- [EO 14412](https://www.federalregister.gov/documents/2022/05/04/2022-09714/improving-the-cybersecurity-of-national-security-systems)