# plan.md — CBOM Analytics Tool (PS26164)

**Mission:** A tool that scans Python/JS repos + related artifacts, catalogues every
cryptographic asset, scores quantum risk via Mosca's inequality, recommends PQC
alternatives, exports a standards-compliant CBOM, and visualizes it in an interactive GUI.

**Constraint:** 11 days, 1 developer. This plan is built around that, not around the
fantasy of full-fidelity coverage.

---

## 0. Assumptions (correct these before trusting the schedule)

1. Judged on a **working prototype demo + pitch**, not a code audit.
2. **CycloneDX 1.6 CBOM** is the output format (verify exact field names Day 1).
3. GUI **runs locally** for the demo — no public deployment required.
4. "Report" = CBOM (standard format) + GUI. No separate written assessment PDF owed.
5. GUI in **React/Next**.

If any of these is false, the day allocation changes.

---

## 1. The scope-reality table — what "no compromises" actually means here

Every artifact class in the PS is **represented**. Resolution varies by what static
analysis can physically extract. Nothing is silently dropped — unresolved artifacts are
emitted with a `confidence: flagged` field and a "needs manual review" note. That is a
*more* complete output than a tool that only reports what it's certain about.

| Artifact class | Fidelity | How | Est. effort |
|---|---|---|---|
| Algorithms/keys in code | **Full** (`confirmed`) | AST + proximity scan | Py 3d / JS 3–4d |
| Libraries | **Full** (`confirmed`) | Manifest + lockfile parse | 1d |
| Certificates | **Full** (`confirmed`) | X.509 signature-algo parse | 1d |
| Cloud services (KMS/ACM) | **Partial** (`flagged`) | IaC/config reference detection | ~1.5d |
| Protocols (TLS suites) | **Partial** (`flagged`) | Server-config parse | (in above) |
| HSM modules | **Reference-only** (`flagged`) | Detect the reference, flag | (in above) |
| Container images | **Reference-only** (`flagged`) | Dockerfile `FROM` / image ref | 0.5d |

**Deliberate cut:** deep container-image scanning (unpacking layers, binary crypto
detection) is **out of scope**. Doing it properly is a multi-week problem and would eat
4–6 days for marginal demo value. We detect the image/base reference and flag it. This is
the single biggest time-saver in the plan and it's defensible — real CBOM tools do this.

**Confidence field is the spine of the whole design.** Every artifact carries
`confidence: confirmed | inferred | flagged`. This is what lets you honestly claim "no
requirement dropped" while being truthful about static-analysis limits — and it's exactly
the sophistication a security-literate judge will look for.

---

## 2. Architecture

```
Input handler → Detector registry → Artifact model → Mosca scorer → Recommender → Exporter → API → GUI
   (repo/URL/     (pluggable per     (unified        (X+Y>Z)      (KB lookup)   (CycloneDX)
    files)         source type)       schema)
```

**Core data model — the `CryptoArtifact` object** (design this first, everything reads/writes it):

```
CryptoArtifact:
  id
  type            # public-key | symmetric | hash | certificate | protocol | key
  algorithm       # RSA, ECDSA, AES-256, SHA-1, ...
  key_size        # nullable
  source_location # file:line, or "IaC: main.tf:42", or "dependency"
  confidence      # confirmed | inferred | flagged
  quantum_status  # vulnerable | safe | broken-already
  criticality     # high | medium | low  (user-set or heuristic)
  data_lifetime   # years  (input to Mosca)
  recommendation  # populated by Recommender
```

**Detector registry pattern:** each detector (PythonManifest, PythonSource, JSSource, X509,
IaC, Dockerfile) implements `detect(path) -> list[CryptoArtifact]`. Adding coverage = adding
a detector, never touching the core. This is what makes the phased schedule safe — a slipped
detector doesn't break the pipeline.

**Parsers:** Python → stdlib `ast`. JS → `@babel/parser` / `acorn` / tree-sitter. No regex as
the primary engine (breaks on aliasing, false-positives on comments). Regex only as fallback.

---

## 3. The Crypto Knowledge Base — highest leverage, lowest effort, build it Day 1

A single versioned data file (JSON/YAML) that both the detector (what's vulnerable) and the
recommender (what to suggest) read from. ~25–30 rows. This is the crown jewel and it's *data*,
not code.

| Algorithm | Quantum status | Reason | PQC / hybrid replacement |
|---|---|---|---|
| RSA, ECC/ECDSA, DH, ECDH, ed25519 | vulnerable | Shor's | ML-KEM (Kyber), ML-DSA (Dilithium) |
| AES-256 | safe | Grover halves → 128-bit, fine | keep |
| AES-128 | weak-ish | Grover → 64-bit | AES-256 |
| SHA-256 / 384 / 512, SHA-3 | safe | — | keep |
| SHA-1, MD5 | broken-already | pre-quantum broken | SHA-256/3 |
| 3DES | weak | — | AES-256 |

Add per-row metadata for the recommender: latency class, maturity (NIST-standardized vs
draft), hybrid-mode note. This directly satisfies requirement (iv).

---

## 4. The 11-day schedule (always-shippable property)

**Invariant: at the end of every phase you have a working, demo-able tool.** Any phase can
slip without leaving you with nothing. This is the entire insurance policy of a solo build.

### Day 1 — Foundations
- Repo, pipeline skeleton, `CryptoArtifact` model, detector-registry interface.
- Build the Crypto Knowledge Base (data file).
- **CycloneDX CBOM schema spike** — confirm exact 1.6 field names for `cryptographic-asset`. Get this wrong and the standard-format requirement fails.

### Days 2–3 — Vertical slice → **Shippable v0**
- PythonManifest detector (`requirements.txt`, `pyproject.toml`) → map deps to algorithms.
- Mosca scorer: `X (migration time) + Y (data lifetime) > Z (config default, e.g. 2035)`.
- CycloneDX exporter.
- CLI/API endpoint: point at a Python repo → get a valid CBOM with risk flags.
- **v0 is your floor. If everything else burns down, you can still demo this.**

### Days 4–5 — Deepen Python + certs → **Shippable v1**
- PythonSource detector (AST): stdlib crypto (`hashlib.md5`, `ssl`), inline API calls, aliasing.
- Proximity scan for algorithm string literals.
- X509 detector: parse `.pem`/`.crt`/`.der` → pull signature algorithm (e.g. `sha256WithRSAEncryption`). High value, low effort — covers the certificates requirement at full fidelity.

### Days 6–7 — JS detection → **Shippable v2**
- JSSource detector (AST): Node `crypto`, Web Crypto `subtle.generateKey`, `jsonwebtoken`/`jose` algorithm strings (`RS256`=RSA, `ES256`=ECDSA).
- package.json parse for crypto libs (`node-forge`, `elliptic`, `node-rsa`, `tweetnacl`).
- **This is the highest-risk phase for overrun** — Web Crypto + AST is fiddly. See cut lines.

### Day 8 — Coverage + Recommender → **Shippable v3 (all requirements represented)**
- IaC/config detector: Terraform/CloudFormation/K8s → detect KMS/ACM/HSM references → emit `flagged` entries.
- Server-config parse (nginx etc.) for TLS suites → `flagged`.
- Dockerfile `FROM`/image reference → `flagged`.
- Recommender: populate `recommendation` on every vulnerable artifact from the KB, with latency/maturity/hybrid notes.
- **v3 = every PS artifact class present in output. This is the "no compromises" milestone.**

### Days 9–10 — GUI
- React dashboard: point at repo → artifact table (filter by type/confidence/criticality), risk heatmap, Mosca timeline, download CBOM + report.
- **Signature feature — the Mosca Z-slider** (see §5).

### Day 11 — Demo prep + buffer
- Prepare 3–4 **known demo repos** that each exercise a different path: Python+RSA, JS+RS256 JWT, a repo with a committed cert, one with Terraform KMS. Rehearse against these — never demo against an unknown repo live.
- Pitch deck, demo script, fix showstoppers only. **No new features after Day 10.**

---

## 5. Signature demo features (cheap, high-impact)

1. **Mosca Z-slider** — drag "year quantum breaks RSA" and watch risk categorization
   recompute live across all artifacts. Cheap if scoring is client-side. Visually proves you
   understand Mosca better than any slide could. **Build this even if you cut other things.**
2. **Confidence badges** — `confirmed`/`inferred`/`flagged` chips per artifact. Signals you
   understand static-analysis limits. Judges test for this.
3. **One-click CBOM download** in CycloneDX format — proves the standards-compliance box.

---

## 6. Risk register + cut lines

| Risk | Likelihood | Mitigation |
|---|---|---|
| JS source detection overruns (Days 6–7) | High | Cut line A below |
| CycloneDX schema wrong | Med | Verify Day 1, not later |
| GUI eats more than 2 days | Med | Cut line B; keep dashboard read-only |
| Scope creep back toward container deep-scan | Med | It's cut. Stay cut. |

**Cut lines, in order (pull these if behind, don't improvise):**
- **A:** JS drops to manifest-only detection (lose Web Crypto/Node built-in source coverage). JS still represented, just weaker — the confidence field absorbs it.
- **B:** GUI degrades to read-only dashboard, no Z-slider recompute (precompute a few Z scenarios instead).
- **C:** IaC/TLS/Docker flagging collapses to a single "external artifacts — manual review" section instead of typed detection.

**Never cut:** the vertical slice (v0), Mosca scorer, CycloneDX export, one polished demo path.

---

## 7. Definition of done — PS requirement → what satisfies it

| PS requirement | Satisfied by |
|---|---|
| (i) Identify & catalogue all artifact classes | Detector registry + confidence field (full where possible, flagged elsewhere) |
| (ii) Quantum risk assessment, flag vulnerable systems | Mosca scorer + `quantum_status` from KB |
| (iii) Classify by type/lifetime/criticality; Mosca framework | `CryptoArtifact` fields + Mosca inequality |
| (iv) Recommend PQC/hybrid alternatives | Recommender + KB replacement column |
| Deliverable: CBOM, standardised format | CycloneDX 1.6 exporter |
| Deliverable: interactive GUI | React dashboard + Z-slider |
| Scan repos/libraries/(binaries/containers) | Repos + libs + certs full; containers reference-flagged (documented cut) |

---

## Reference implementations to check Day 1 (don't reinvent the schema)
- IBM **CBOMkit** / Sonar Cryptography plugin — reference for CycloneDX CBOM output format.
- **Semgrep** — could collapse the DETECT stage into YAML rules across Python + JS (evaluate; may or may not be worth the dependency). *Verify current capabilities before committing.*
