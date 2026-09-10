# CBOMScan

**Cryptographic Bill of Materials Scanner** — A tool that scans Python & JavaScript/TypeScript repositories for cryptographic assets, scores their quantum risk via Mosca's inequality, recommends post-quantum replacements, and exports a standards-compliant CycloneDX 1.7 CBOM.

## Features

- **Manifest Detection** — Parses `requirements.txt`, `pyproject.toml`, `package.json` to identify crypto libraries
- **Source Detection** — AST-based detection of crypto API calls in Python and JavaScript/TypeScript source using tree-sitter
- **Certificate Parsing** — X.509 certificate analysis for signature algorithms and key parameters
- **Config/Infrastructure Detection** — Detects cloud KMS/HSM references (Terraform, K8s, CloudFormation), TLS config (nginx, Apache), and Dockerfile base images with `flagged` confidence for manual review
- **Quantum Risk Scoring** — Applies Mosca's inequality (X + Y > Z) with configurable horizon
- **PQC Recommendations** — Maps vulnerable algorithms to NIST-standardized replacements (ML-KEM, ML-DSA, SLH-DSA) with hybrid options and latency notes
- **CycloneDX 1.7 CBOM Export** — Standards-compliant JSON output with schema validation
- **Markdown Reports** — Human-readable summaries with risk categorization and dedicated "Requires Manual Review" section
- **Confidence Model** — Every finding carries `confirmed` | `inferred` | `flagged` confidence
- **Interactive GUI** — React + Vite + TypeScript dashboard with artifact table, risk charts (Recharts), and live **Mosca Z-Slider** for real-time quantum risk recalculation

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
# Scan a local repository (Python or JavaScript/TypeScript)
cbomscan scan ./path/to/repo -o cbom.json

# Scan and generate Markdown report
cbomscan scan ./path/to/repo -o report.md -f md

# Custom quantum horizon (years until CRQC)
cbomscan scan ./repo -o cbom.json --horizon-year 2035

# Custom migration time and data lifetime
cbomscan scan ./repo -o cbom.json --migration-years 3.0 --data-lifetime 20

# Skip schema validation (faster)
cbomscan scan ./repo -o cbom.json --no-validate
```

### Command Reference

```
usage: cbomscan [-h] [-V] <command> ...

Cryptographic Bill of Materials Scanner - inventory the crypto in a codebase, score it against the quantum threat, and export a CycloneDX 1.7 CBOM.

positional arguments:
  <command>
    scan         Scan a path and write a CBOM or report
    detectors    List the diagnostic tools and what they find
    serve        Run the API and web dashboard
    app          Launch the CBOMScan desktop application
    wizard       Launch the step-by-step setup wizard
    version      Print the version

options:
  -h, --help     show this help message and exit
  -V, --version  show program's version number and exit

examples:
  cbomscan scan .                        scan the current directory
  cbomscan scan ./repo -f md -o out.md   write a Markdown report
  cbomscan scan ./repo --horizon-year 2035
  cbomscan detectors                     list the diagnostic tools
  cbomscan serve                         open the web dashboard
  cbomscan app                           open the desktop app
```

```
usage: cbomscan scan [-h] [-o OUTPUT] [-f {json,md}]
                     [--horizon-year HORIZON_YEAR]
                     [--migration-years MIGRATION_YEARS]
                     [--data-lifetime DATA_LIFETIME] [--kb KB]
                     [--config CONFIG] [--no-validate] [--json] [-q] [-v]
                     path

positional arguments:
  path                  Path to scan (directory or single file)

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output file path (default: cbom.json)
  -f {json,md}, --format {json,md}
                        Output format
  --horizon-year HORIZON_YEAR
                        Year a cryptographically relevant quantum computer is
                        assumed to exist (Z in Mosca's inequality; default:
                        from config.yaml)
  --migration-years MIGRATION_YEARS
                        Migration time in years (default: from config.yaml)
  --data-lifetime DATA_LIFETIME
                        Data lifetime in years (default: from config.yaml)
  --kb KB               Path to knowledge base YAML
  --config CONFIG       Path to config YAML
  --no-validate         Skip CBOM schema validation
  --json                Print the summary as JSON to stdout
  -q, --quiet           Only print the summary
  -v, --verbose         Verbose logging
```

### Command line

CBOMScan installs a global `cbomscan` command, so it works from any terminal
the way `git` or `npm` does:

```bash
pip install -e .            # puts `cbomscan` on PATH

cbomscan scan .             # scan the current directory -> cbom.json
cbomscan scan . -f md -o report.md
cbomscan scan . --horizon-year 2035 --migration-years 3 --data-lifetime 25
cbomscan scan . --json      # summary as JSON on stdout, for CI
cbomscan detectors          # list the diagnostic tools
cbomscan serve              # API + web dashboard on :8000
cbomscan app                # launch the desktop application
cbomscan wizard             # launch the setup wizard
cbomscan version
```

Exit codes: `0` success, `1` output write error, `2` unreadable path or knowledge
base, `130` interrupted.

### Desktop application (Electron)

A minimalist Windows app with switchable dark and light themes, covering
everything the CLI does:

| Page | What it does |
|---|---|
| **Scan** | Folder picker, live Mosca X/Y/Z sliders, recent repositories, open the repo in a terminal or in Explorer |
| **Results** | Summary tiles, verdict distribution, sortable/filterable asset table, per-artifact detail drawer, CBOM and Markdown export |
| **Diagnostic Tools** | Every detector, what it inspects, what it finds, and the confidence it reports |
| **Knowledge Base** | The full algorithm table backing every verdict and recommendation |
| **Command Line** | The equivalent CLI command for each feature, with copy buttons |
| **Settings** | Theme (light / dark / system), version info, backend log |

```bash
make app                    # build installer + portable exe into desktop/dist
cd desktop && npm start     # run against a source checkout
make app-smoke              # headless UI test of the real app
```

The build produces `CBOMScan-Setup-0.1.0.exe` (installer) and
`CBOMScan-Portable-0.1.0.exe`. Both embed the Python engine as
`CBOMScan-Backend.exe`, so the installed app needs **no Python, Node, or network
access**. The app spawns the engine on a free loopback port at launch and shuts
it down on exit.

### Desktop Wizard (packaged executable)

`dist/CBOMScan-Wizard.exe` is a single self-contained Windows executable — no Python,
Node or network access required on the target machine. It bundles the knowledge base,
the CycloneDX 1.7 schemas, the tree-sitter grammars and the built React dashboard.

```bash
make wizard          # build it (requires: pip install pyinstaller, npm install)
```

The wizard walks through four steps:

1. **Welcome** — what will be scanned
2. **Select a target** — folder picker for the repository
3. **Quantum risk horizon** — sliders for Mosca's X, Y and Z
4. **Scan & results** — verdict breakdown, highest-priority table, and buttons to
   save the CBOM (schema-validated on write), save the Markdown report, launch the
   full React dashboard, or open the CBOMScan desktop app

To verify a build without a display, run it headless:

```bash
dist/CBOMScan-Wizard.exe --selftest <path-to-scan> <report-file>
```

This exercises the bundled knowledge base, schemas and grammars exactly as the GUI
does and writes a PASS/FAIL report — the check that catches missing bundled data.

### GUI Usage (development)

```bash
# Terminal 1: Start the API server
python -m cbomscan.api_server  # Runs on http://localhost:8000

# Terminal 2: Start the frontend dev server
cd frontend && npm run dev     # Runs on http://localhost:5173 (proxies /api to :8000)
```

Then open http://localhost:5173 in your browser:

1. **Scan Form** — Enter a local repository path and click "Scan Repository"
2. **Results Dashboard** — View:
   - **Summary badges** — Total artifacts, by verdict, by confidence, at-risk count
   - **Mosca Z-Slider** — Drag the CRQC year (Z) to recompute X + Y > Z live; updates table + charts instantly
   - **Risk Charts** — Verdict pie, Confidence pie, At-risk stacked bar, Criticality × Verdict heatmap
   - **Artifact Table** — Filterable/sortable: name, type, verdict (color-coded), confidence, risk flag, criticality, occurrences, recommendation
   - **Download Buttons** — CBOM (JSON) and Markdown Report

## Configuration

### config.yaml

```yaml
# CBOMScan configuration
horizon_year: 2030           # Z = years until CRQC
default_migration_years: 2.0 # X = migration time in years
default_data_lifetime_years: 10 # Y = data lifetime in years
```

### knowledge_base.yaml

Contains ~30 algorithm entries with:
- **Verdict**: `vulnerable` | `weakened` | `broken` | `safe`
- **Replacement**: NIST FIPS PQC algorithm (ML-KEM, ML-DSA, SLH-DSA)
- **Maturity**: `nist-standardized` | `draft` | `deprecated`
- **Latency Note**: Performance characteristics
- **Hybrid OK**: Whether hybrid mode is supported during transition

## Supported Crypto Detection

### Python (`PythonSourceDetector`)

| Library | Algorithms Detected |
|---|---|
| `cryptography.hazmat` | RSA, ECDSA, ECDH, Ed25519, X25519, DH, AES, ChaCha20, 3DES, hashes (MD5, SHA-1/2/3, BLAKE2), PBKDF2, HKDF, Scrypt, HMAC |
| `hashlib` | MD5, SHA-1, SHA-224/256/384/512, SHA3-224/256/384/512, BLAKE2b/s |
| `ssl` | TLS protocol references |

### JavaScript/TypeScript (`JavaScriptSourceDetector`)

| API | Algorithms Detected |
|---|---|
| **Node.js `crypto`** | `generateKeyPair/generateKeyPairSync` (rsa, ec, ed25519, ed448, dh, x25519, x448), `createSign`, `createVerify`, `createECDH`, `createDiffieHellman`, `createHash`, `createHmac`, `pbkdf2`, `scrypt`, `hkdf` |
| **Web Crypto API** (`crypto.subtle`) | `generateKey` (RSA-OAEP, RSASSA-PKCS1-v1_5, RSA-PSS, ECDSA, ECDH, AES-*, HMAC, HKDF, PBKDF2), `sign`, `verify`, `deriveKey`, `encrypt`, `decrypt`, `wrapKey`, `unwrapKey`, `digest` |
| **JWT Libraries** (`jsonwebtoken`, `jose`) | Algorithm strings: RS256/384/512→RSA, ES256/385/512→ECDSA, PS256/384/512→RSA-PSS, HS256/384/512→HMAC, EdDSA→Ed25519 |

**Detection approach**: Proximity-based — finds crypto calls and extracts adjacent algorithm string literals in arguments. Emits `confirmed` when algorithm string is present, `inferred` otherwise.

### Manifest Detection (`ManifestDetector`)

**Python**: `cryptography`, `pycryptodome`, `rsa`, `ecdsa`, `pyopenssl`, `pynacl`, `paramiko`
**JavaScript/TypeScript**: `node-forge`, `elliptic`, `node-rsa`, `tweetnacl`, `jsonwebtoken`, `jose`, `@noble/hashes`, `@noble/secp256k1`, `@noble/ed25519`, `@noble/curves`, `webcrypto`

### Certificates (`CertDetector`)

X.509 PEM/DER parsing — extracts signature algorithm, key parameters, validity period, subject/issuer.

### Config & Infrastructure (`ConfigDetector`)

| Source | Patterns Detected | Confidence |
|---|---|---|
| **Terraform** (`.tf`, `.tfvars`) | AWS KMS/ACM/CloudHSM, Azure Key Vault, GCP KMS resource types | `flagged` |
| **Kubernetes** (`.yaml`, `.yml`) | KMS annotations, secret references, key vault integrations | `flagged` |
| **CloudFormation** (`.yaml`, `.yml`) | KMS resource types in `Resources` | `flagged` |
| **nginx** (`.conf`, `nginx.conf`) | `ssl_protocols`, `ssl_ciphers`, `ssl_prefer_server_ciphers`, `ssl_session_cache`, `ssl_session_timeout` — flags weak TLS/ciphers | `flagged` |
| **Apache** (`.conf`, `httpd.conf`) | `SSLProtocol`, `SSLCipherSuite`, `SSLHonorCipherOrder`, `SSLSessionCache` | `flagged` |
| **Dockerfile** | `FROM` base images | `flagged` |

All config findings emit `flagged` confidence with note: *"algorithm not statically determinable, manual review required"*

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
          { "location": "src/auth/tokens.js", "line": 42, "symbol": "jwt.sign" }
        ]
      }
    }
  ]
}
```

- `nistQuantumSecurityLevel: 0` = quantum-vulnerable (broken by Shor's)
- `nistQuantumSecurityLevel: 1` = weakened by Grover's
- `nistQuantumSecurityLevel: 3` = quantum-safe

Flagged artifacts (cloud KMS, TLS config, container images) are exported as `protocol` or `related-crypto-material` asset types with evidence marking them for manual review.

### Markdown Report

Human-readable summary with:
- Verdict counts (vulnerable/weakened/broken/safe)
- Confidence counts (confirmed/inferred/flagged)
- **⚠️ Requires Manual Review** section for all `flagged` artifacts with metadata
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

All 42 tests passing (Python, JS/TS, Cert, Manifest, E2E, Knowledge Base).

## Project Structure

```
cbomscan/
├── __main__.py              # CLI entry point
├── api_server.py            # FastAPI server for GUI
├── models.py                # CryptoArtifact, Verdict, Confidence, AssetType
├── scan.py                  # File discovery & detector dispatch
├── detectors/
│   ├── __init__.py          # Registry + base classes
│   ├── source.py            # PythonSourceDetector + JavaScriptSourceDetector
│   ├── manifest.py          # ManifestDetector (requirements.txt, pyproject.toml, package.json)
│   ├── cert.py              # CertDetector
│   └── config.py            # ConfigDetector (Terraform, K8s, CF, nginx, Apache, Dockerfile)
├── normalize.py             # Deduplication
├── classify.py              # Asset type, verdict, criticality
├── score.py                 # Mosca inequality
├── recommend.py             # PQC/hybrid recommendations
├── export.py                # CycloneDX 1.7 + Markdown
├── knowledge_base.py        # KB loader
├── knowledge_base.yaml      # Algorithm database (~30 entries)
└── config.yaml              # Default Z, X, Y values

frontend/
├── src/
│   ├── components/          # ScanForm, ResultsPage, ArtifactTable, RiskCharts, ZSlider
│   ├── hooks/useArtifacts.ts # Mosca calculator, filters, sorting
│   ├── api/client.ts        # API client (scan, download CBOM/report)
│   └── types/index.ts       # TypeScript interfaces
├── package.json
├── vite.config.ts
└── tsconfig.json
```

## Scope

| Artifact Class | Fidelity | Method |
|---|---|---|
| Algorithms in dependencies | `inferred` | Manifest parsing |
| Algorithms in Python source | `confirmed` | tree-sitter Python AST + string literal proximity |
| Algorithms in JS/TS source | `confirmed` | tree-sitter JavaScript AST + string literal proximity |
| Certificates | `confirmed` | X.509 parsing |
| Cloud KMS/HSM/TLS refs | `flagged` | IaC/config parsing (Terraform, K8s, CF, nginx, Apache) |
| Container images | `flagged` | Dockerfile `FROM` references |

**Out of scope**: Deep container layer unpacking, compiled binary analysis, live network probing, languages beyond Python/JS.

## License

MIT License — see LICENSE file for details.

## References

- [CycloneDX 1.7 Specification](https://cyclonedx.org/specification/overview/)
- [NIST PQC Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Mosca's Inequality](https://eprint.iacr.org/2015/1075)
- [EO 14412](https://www.federalregister.gov/documents/2022/05/04/2022-09714/improving-the-cybersecurity-of-national-security-systems)