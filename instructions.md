# CLAUDE.md — Project Context (read this first, every session)

You are building **CBOMScan**: a tool that scans Python & JavaScript repositories (plus
certs and config) for cryptographic assets, scores their quantum risk, recommends
post-quantum replacements, and exports a standards-compliant CBOM with an interactive GUI.

This file is the source of truth for architecture and conventions. `plan.md` is the source
of truth for schedule. Read both before writing code. Do not contradict either without the
maintainer explicitly changing them.

---

## Hard constraints (do not violate)

- **One developer, 11 days, judged on a live demo + pitch.** Optimize for a working
  end-to-end pipeline at every milestone, not breadth of half-finished features.
- **Every milestone must end runnable, tested, and committed.** No milestone leaves the
  repo in a broken state.
- **Output format is CycloneDX 1.7 CBOM** (JSON). This is verified and non-negotiable — see
  "Output contract". Do NOT invent your own schema or field names.

## Golden rules (these prevent the failure modes of an AI-driven solo build)

1. **Never guess the CBOM schema.** When emitting CycloneDX, follow the field names in the
   "Output contract" section and validate against the official JSON schema. If unsure of a
   field, fetch `https://cyclonedx.org/schema/` — do not improvise.
2. **All detection flows through the detector registry.** Adding coverage = adding a
   `Detector` subclass and registering it. Never bolt detection logic onto the pipeline,
   the API, or the exporter.
3. **Nothing is dropped; low-certainty findings are flagged, not deleted.** Every artifact
   carries a `confidence` of `confirmed | inferred | flagged`. This is a core feature, not a
   caveat.
4. **Write tests with every detector and scorer.** A detector without a fixture repo and a
   passing test is not done.
5. **Stay in scope.** Deep container-image and compiled-binary scanning is OUT (see
   "Scope"). Do not start it, even if it seems easy.
6. **Small commits, conventional messages.** One logical change per commit.

---

## Architecture (fixed)

Seven-stage pipeline. Each stage is a module with a single responsibility:

```
SCAN → DETECT → NORMALIZE → CLASSIFY → SCORE → RECOMMEND → EXPORT → (API → GUI)
```

- **SCAN** — resolve the input (git clone a URL, or read a local path), walk the file tree,
  hand relevant files to detectors. Respect `.gitignore`; skip `node_modules`, `.venv`,
  build dirs.
- **DETECT** — the **detector registry**. Each `Detector` implements
  `detect(path) -> list[RawFinding]`. Four detectors (see below).
- **NORMALIZE** — collapse `RawFinding`s into deduplicated `CryptoArtifact` objects, merging
  multiple `occurrence`s of the same primitive and carrying the strongest `confidence`.
- **CLASSIFY** — assign `assetType`, key lifetime (default or user-supplied), and business
  criticality (heuristic + override).
- **SCORE** — apply Mosca's inequality (see below) using the configurable horizon `Z`.
- **RECOMMEND** — look up each vulnerable artifact in the Crypto Knowledge Base and attach a
  PQC/hybrid recommendation.
- **EXPORT** — serialize to CycloneDX 1.7 CBOM JSON and a human-readable report (Markdown).
- **API / GUI** — FastAPI serves scan results; React renders them.

### Detector registry — the four detectors

| Detector | Inputs | Technique | Typical confidence |
|---|---|---|---|
| `ManifestDetector` | `requirements.txt`, `pyproject.toml`, `package.json`, lockfiles | dependency → known-crypto-library mapping | `inferred` (lib present) |
| `SourceDetector` | `.py`, `.js`, `.ts`, `.jsx` | tree-sitter AST; match crypto API calls + adjacent algorithm string literals (`'RS256'`, `'RSA-OAEP'`) | `confirmed` (call + algo found) |
| `CertDetector` | `.pem`, `.crt`, `.cer`, `.der` | parse X.509, read signature algorithm & key params | `confirmed` |
| `ConfigDetector` | Terraform, K8s YAML, CloudFormation, nginx conf, `Dockerfile` | detect KMS/HSM/TLS/base-image **references** | `flagged` (needs manual review) |

`SourceDetector` uses one tree-sitter engine with both the Python and JavaScript grammars —
do not spin up a Node subprocess. Python's stdlib `ast` is an acceptable fallback for
Python-only parsing, but the unified tree-sitter path is preferred so JS and Python share
one detector.

---

## Data model (the spine — everything reads/writes this)

```python
# models.py
from dataclasses import dataclass, field
from enum import Enum

class AssetType(str, Enum):
    ALGORITHM = "algorithm"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    RELATED_MATERIAL = "related-crypto-material"

class Verdict(str, Enum):
    VULNERABLE = "vulnerable"      # broken by Shor's (RSA, ECC, DH...)
    WEAKENED   = "weakened"        # halved by Grover's (AES-128...)
    BROKEN     = "broken"          # already broken pre-quantum (MD5, SHA-1, 3DES)
    SAFE       = "safe"            # quantum-resistant (AES-256, SHA-256/3, PQC)

class Confidence(str, Enum):
    CONFIRMED = "confirmed"        # exact primitive found at a source location
    INFERRED  = "inferred"         # strong signal (dependency present, algo string)
    FLAGGED   = "flagged"          # reference detected; algorithm not statically resolvable

@dataclass
class Occurrence:
    file: str
    line: int | None = None
    symbol: str | None = None      # function / import that triggered detection

@dataclass
class CryptoArtifact:
    id: str                        # stable hash of (asset_type, name, params)
    asset_type: AssetType
    name: str                      # "RSA", "ECDSA", "AES-256-GCM", "sha256WithRSAEncryption"
    primitive: str | None = None   # pke, signature, key-agree, hash, block-cipher
    key_size: int | None = None
    curve: str | None = None
    verdict: Verdict = Verdict.SAFE
    confidence: Confidence = Confidence.INFERRED
    occurrences: list[Occurrence] = field(default_factory=list)
    criticality: str = "medium"    # high | medium | low
    data_lifetime_years: int | None = None   # Y in Mosca; None = unknown
    migration_years: float | None = None      # X in Mosca (default from config)
    recommendation: str | None = None          # populated by RECOMMEND
    notes: str | None = None
```

Do not add fields ad hoc across the codebase. Extend this dataclass in `models.py` and let it
propagate.

---

## Quantum risk model — Mosca's inequality

For each artifact, flag it if:

```
X + Y > Z
```

- **X** = migration time (years to rip this crypto out and replace it) — default from config
  (e.g. 2.0), overridable per artifact.
- **Y** = data lifetime (years the protected data must stay confidential) — from
  `data_lifetime_years`, default from config.
- **Z** = years until a cryptographically relevant quantum computer (CRQC) exists — a single
  **configurable horizon**, NOT something the tool researches. Default to a policy anchor
  (e.g. 2030, aligned to the EO 14412 key-establishment deadline). The GUI exposes this as a
  live slider.

`SAFE` and `BROKEN` verdicts short-circuit Mosca (SAFE is never at quantum risk; BROKEN is
always urgent regardless of Z). Mosca decides urgency for `VULNERABLE`/`WEAKENED` artifacts.

---

## Crypto Knowledge Base (the highest-leverage asset — it's data, not code)

A single versioned file `knowledge_base.yaml`. Both SCORE (verdict) and RECOMMEND
(replacement) read from it. ~25–30 rows. Seed:

| Algorithm family | Verdict | Reason | Replacement (NIST FIPS) |
|---|---|---|---|
| RSA, DH | vulnerable | Shor's | ML-KEM (FIPS 203) for KEX; ML-DSA (FIPS 204) for sig |
| ECC / ECDSA / ECDH / Ed25519 / X25519 | vulnerable | Shor's | ML-KEM / ML-DSA; hybrid X25519+ML-KEM during transition |
| DSA | vulnerable | Shor's | ML-DSA (FIPS 204) |
| AES-128 | weakened | Grover halves → 64-bit | AES-256 |
| AES-256, ChaCha20 | safe | Grover → 128-bit effective | keep |
| SHA-256/384/512, SHA-3 | safe | — | keep |
| SHA-1, MD5 | broken | pre-quantum broken | SHA-256 / SHA-3 |
| 3DES, DES, RC4 | broken | pre-quantum broken | AES-256 |

Each row also carries: maturity (`nist-standardized` | `draft`), a latency/size note, and a
hybrid-mode flag, for the RECOMMEND stage to surface trade-offs (requirement iv).

---

## Output contract — CycloneDX 1.7 CBOM (verified against the spec)

Emit JSON with `"bomFormat": "CycloneDX"`, `"specVersion": "1.7"`. Each crypto artifact is a
component:

```json
{
  "type": "cryptographic-asset",
  "name": "RSA-2048",
  "bom-ref": "crypto/algorithm/rsa-2048",
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
      { "location": "src/auth/tokens.py", "line": 42, "symbol": "generate_private_key" }
    ]
  }
}
```

- `assetType` ∈ `algorithm | certificate | protocol | related-crypto-material`.
- Use `algorithmProperties`, `certificateProperties`, `protocolProperties`,
  `relatedCryptoMaterialProperties` per asset type.
- `nistQuantumSecurityLevel: 0` marks quantum-broken algorithms — this is how the standard
  itself encodes quantum risk. Use it.
- Map our internal `confidence` + `occurrences` onto CycloneDX `evidence.occurrences` (and
  detection context). Our confidence model mirrors the standard's — keep them aligned.
- Prefer `cyclonedx-python-lib` **only if the installed version models `cryptoProperties`**;
  otherwise build the dict directly and validate with `jsonschema` against the official
  CycloneDX 1.7 schema. Verify this in Milestone 0.

---

## Technology stack (fixed — don't substitute without reason)

**Backend (Python 3.11+):**
- `tree-sitter` + `tree-sitter-python` + `tree-sitter-javascript` — source parsing
- `packaging`, stdlib `tomllib` — manifest parsing
- `cryptography` — X.509 certificate parsing
- `python-hcl2`, `PyYAML` — Terraform / K8s / CloudFormation config parsing
- `fastapi` + `uvicorn` — API
- `jsonschema` — validate CBOM output; `cyclonedx-python-lib` if it supports crypto-assets
- `pytest` — tests
- CLI entry point: `python -m cbomscan scan <path> [-o cbom.json] [-f md|json]`

**Frontend:**
- React + Vite + TypeScript
- Recharts — risk heatmap / charts
- A range input for the Mosca **Z-slider** (recompute verdicts client-side on change)

---

## Session protocol

At the **start of every session**:
1. Read `plan.md` and this `CLAUDE.md`.
2. Read `cbomscan/models.py` (the data model) and the module you're about to change.
3. Run the test suite (`pytest`) to confirm a green baseline before editing.

At the **end of every milestone**:
1. All new code has tests; `pytest` is green.
2. The CLI still runs end-to-end on the fixture repos.
3. Commit with a conventional message; note the milestone in the message.

---

## Scope — in and out

**In (full fidelity, `confirmed`/`inferred`):** Python & JS source crypto, dependencies,
X.509 certificates committed to the repo.

**In (reference-only, `flagged`):** cloud KMS/ACM references, HSM references, TLS cipher
config, Dockerfile base images. Detected and catalogued, marked for manual review.

**Out (do not build):** deep container-image layer unpacking, compiled-binary crypto
detection, live network/TLS handshake probing, languages beyond Python/JS. If these come up,
add a `flagged` stub entry and move on — do not implement.

## Definition of done (maps to the problem statement)

- (i) catalogue all artifact classes → detector registry + confidence field
- (ii) quantum risk assessment → Mosca scorer + `nistQuantumSecurityLevel`
- (iii) classify by type/lifetime/criticality → `CryptoArtifact` fields + Mosca
- (iv) recommend PQC/hybrid alternatives → RECOMMEND + knowledge base
- deliverable: standardized CBOM → CycloneDX 1.7 JSON, schema-validated
- deliverable: interactive GUI → React dashboard + Mosca Z-slider
