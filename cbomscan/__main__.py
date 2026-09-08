"""CLI entry point for CBOMScan."""

import argparse

from cbomscan.classify import classify
from cbomscan.export import write_cyclonedx_json, write_markdown_report
from cbomscan.knowledge_base import DEFAULT_KB_PATH, KnowledgeBase
from cbomscan.normalize import normalize
from cbomscan.recommend import recommend
from cbomscan.scan import run_detectors, scan_path
from cbomscan.score import score


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
        "--horizon-year", type=int, default=2030, help="Years until CRQC (default: 2030)"
    )
    parser.add_argument(
        "--migration-years", type=float, default=2.0, help="Migration time in years (default: 2.0)"
    )
    parser.add_argument(
        "--data-lifetime", type=int, default=10, help="Data lifetime in years (default: 10)"
    )
    parser.add_argument(
        "--kb", default=str(DEFAULT_KB_PATH), help="Path to knowledge base YAML"
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

    # CLASSIFY
    artifacts = classify(artifacts, kb, args.migration_years, args.data_lifetime)

    # SCORE
    artifacts = score(artifacts, args.horizon_year)

    # RECOMMEND
    artifacts = recommend(artifacts, kb)

    # EXPORT
    if args.format == "json":
        write_cyclonedx_json(artifacts, args.output)
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
