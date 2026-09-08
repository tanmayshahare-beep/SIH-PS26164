"""CLI entry point for CBOMScan."""

import argparse
from pathlib import Path

from cbomscan.classify import classify
from cbomscan.export import write_cyclonedx_json, write_markdown_report
from cbomscan.knowledge_base import DEFAULT_KB_PATH, KnowledgeBase
from cbomscan.normalize import normalize
from cbomscan.recommend import recommend
from cbomscan.scan import run_detectors, scan_path
from cbomscan.score import score

DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"


def main():
    parser = argparse.ArgumentParser(
        prog="cbomscan",
        description="Cryptographic Bill of Materials Scanner",
    )
    parser.add_argument("command", choices=["scan"], help="Command to run")
    parser.add_argument("path", help="Path to scan (local directory)")
    parser.add_argument(
        "-o", "--output", default="cbom.json", help="Output file path (default: cbom.json)"
    )
    parser.add_argument(
        "-f", "--format", choices=["json", "md"], default="json", help="Output format"
    )
    parser.add_argument(
        "--horizon-year", type=int, help="Years until CRQC (default: from config.yaml)"
    )
    parser.add_argument(
        "--migration-years", type=float, help="Migration time in years (default: from config.yaml)"
    )
    parser.add_argument(
        "--data-lifetime", type=int, help="Data lifetime in years (default: from config.yaml)"
    )
    parser.add_argument(
        "--kb", default=str(DEFAULT_KB_PATH), help="Path to knowledge base YAML"
    )
    parser.add_argument(
        "--config", default=str(DEFAULT_CONFIG_PATH), help="Path to config YAML"
    )
    parser.add_argument(
        "--no-validate", action="store_true", help="Skip CBOM schema validation"
    )

    args = parser.parse_args()

    if args.command == "scan":
        run_scan(args)


def run_scan(args):
    """Run the scan pipeline."""
    print(f"Scanning: {args.path}")

    # Load knowledge base
    kb = KnowledgeBase.load(args.kb)
    print(f"Loaded knowledge base: {len(kb.all_entries())} entries")

    # SCAN + DETECT
    all_findings = []
    file_count = 0
    for file_path, content in scan_path(args.path):
        file_count += 1
        findings = run_detectors(file_path, content)
        all_findings.extend(findings)

    print(f"Scanned {file_count} files, found {len(all_findings)} raw findings")

    # NORMALIZE
    artifacts = normalize(all_findings)
    print(f"Normalized to {len(artifacts)} unique artifacts")

    # CLASSIFY - use config defaults for migration/lifetime if not provided
    config_path = Path(args.config)
    import yaml
    config = {}
    if config_path.exists():
        with open(config_path) as f:
            config = yaml.safe_load(f) or {}

    migration_years = args.migration_years or config.get("default_migration_years", 2.0)
    data_lifetime = args.data_lifetime or config.get("default_data_lifetime_years", 10)

    artifacts = classify(artifacts, kb, migration_years, data_lifetime)

    # SCORE - pass config for Z, X, Y defaults
    horizon_year = args.horizon_year or config.get("horizon_year", 2030)
    artifacts = score(artifacts, horizon_year=horizon_year, config_path=config_path)

    # RECOMMEND
    artifacts = recommend(artifacts, kb)

    # EXPORT
    if args.format == "json":
        write_cyclonedx_json(artifacts, args.output, validate=not args.no_validate)
        print(f"CBOM written to {args.output}")
    else:
        write_markdown_report(artifacts, args.output)
        print(f"Report written to {args.output}")

    # Print summary
    verdict_counts = {}
    for a in artifacts:
        verdict_counts[a.verdict.value] = verdict_counts.get(a.verdict.value, 0) + 1

    print("\nSummary:")
    for verdict, count in sorted(verdict_counts.items()):
        print(f"  {verdict}: {count}")


if __name__ == "__main__":
    main()
