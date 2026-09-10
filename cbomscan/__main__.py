"""CLI entry point for CBOMScan.

Subcommands:
    scan       inventory a repository and write a CBOM or Markdown report
    detectors  list the diagnostic tools and what each one finds
    serve      run the API + dashboard on a local port
    app        launch the desktop application
    wizard     launch the step-by-step setup wizard
    version    print the version
"""

import argparse
import contextlib
import json
import logging
import os
import shutil
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

import yaml

from cbomscan import __version__
from cbomscan.classify import classify
from cbomscan.detectors import registry
from cbomscan.export import write_cyclonedx_json, write_markdown_report
from cbomscan.knowledge_base import DEFAULT_KB_PATH, load_knowledge_base
from cbomscan.models import Confidence
from cbomscan.normalize import normalize
from cbomscan.recommend import recommend
from cbomscan.scan import run_detectors, scan_path
from cbomscan.score import score

DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"

# ANSI colour, suppressed when the stream is not a terminal or NO_COLOR is set.
_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


BOLD = "1"
DIM = "2"
RED = "31"
YELLOW = "33"
GREEN = "32"
CYAN = "36"

VERDICT_COLOR = {
    "broken": RED,
    "vulnerable": RED,
    "weakened": YELLOW,
    "safe": GREEN,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cbomscan",
        description="Cryptographic Bill of Materials Scanner - inventory the crypto in a "
        "codebase, score it against the quantum threat, and export a CycloneDX 1.7 CBOM.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  cbomscan scan .                        scan the current directory\n"
            "  cbomscan scan ./repo -f md -o out.md   write a Markdown report\n"
            "  cbomscan scan ./repo --horizon-year 2035\n"
            "  cbomscan detectors                     list the diagnostic tools\n"
            "  cbomscan serve                         open the web dashboard\n"
            "  cbomscan app                           open the desktop app\n"
        ),
    )
    parser.add_argument("-V", "--version", action="version", version=f"cbomscan {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    scan_p = sub.add_parser("scan", help="Scan a path and write a CBOM or report")
    scan_p.add_argument("path", help="Path to scan (directory or single file)")
    scan_p.add_argument(
        "-o", "--output", default="cbom.json", help="Output file path (default: cbom.json)"
    )
    scan_p.add_argument(
        "-f", "--format", choices=["json", "md"], default="json", help="Output format"
    )
    scan_p.add_argument(
        "--horizon-year",
        type=int,
        help="Year a cryptographically relevant quantum computer is assumed to exist "
        "(Z in Mosca's inequality; default: from config.yaml)",
    )
    scan_p.add_argument(
        "--migration-years", type=float, help="Migration time in years (default: from config.yaml)"
    )
    scan_p.add_argument(
        "--data-lifetime", type=int, help="Data lifetime in years (default: from config.yaml)"
    )
    scan_p.add_argument("--kb", default=str(DEFAULT_KB_PATH), help="Path to knowledge base YAML")
    scan_p.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to config YAML")
    scan_p.add_argument("--no-validate", action="store_true", help="Skip CBOM schema validation")
    scan_p.add_argument("--json", action="store_true", help="Print the summary as JSON to stdout")
    scan_p.add_argument("-q", "--quiet", action="store_true", help="Only print the summary")
    scan_p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")

    det_p = sub.add_parser("detectors", help="List the diagnostic tools and what they find")
    det_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    serve_p = sub.add_parser("serve", help="Run the API and web dashboard")
    serve_p.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    serve_p.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    serve_p.add_argument("--no-browser", action="store_true", help="Do not open a browser")
    serve_p.add_argument(
        "--exit-with-parent",
        action="store_true",
        help="Shut down when the launching process closes this server's stdin. "
        "Used by the desktop app so a force-killed app never orphans the engine.",
    )

    sub.add_parser("app", help="Launch the CBOMScan desktop application")
    sub.add_parser("wizard", help="Re-run the setup wizard (repair or change the install)")
    sub.add_parser("version", help="Print the version")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False) else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    handlers = {
        "scan": _cmd_scan,
        "detectors": _cmd_detectors,
        "serve": _cmd_serve,
        "app": _cmd_app,
        "wizard": _cmd_wizard,
        "version": _cmd_version,
    }
    try:
        return handlers[args.command](args)
    except FileNotFoundError as exc:
        print(_c(f"error: {exc}", RED), file=sys.stderr)
        return 2
    except PermissionError as exc:
        print(_c(f"error: permission denied: {exc}", RED), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except OSError as exc:
        print(_c(f"error: {exc}", RED), file=sys.stderr)
        return 1


# ------------------------------------------------------------------- scan --


def _cmd_scan(args) -> int:
    run_scan(args)
    return 0


def run_scan(args) -> list:
    """Run the full pipeline and write the requested output."""
    quiet = getattr(args, "quiet", False) or getattr(args, "json", False)

    def say(message: str) -> None:
        if not quiet:
            print(message)

    say(f"Scanning: {args.path}")

    kb = load_knowledge_base(args.kb)
    say(f"Loaded knowledge base: {len(kb.all_entries())} entries")

    # SCAN + DETECT
    all_findings = []
    file_count = 0
    for file_path, content in scan_path(args.path):
        file_count += 1
        all_findings.extend(run_detectors(file_path, content))

    say(f"Scanned {file_count} files, found {len(all_findings)} raw findings")

    # NORMALIZE
    artifacts = normalize(all_findings)
    say(f"Normalized to {len(artifacts)} unique artifacts")

    # CLASSIFY - config supplies the defaults; an explicit 0 on the command
    # line is a real value and must not fall through to the config default.
    config_path = Path(args.config)
    config = {}
    if config_path.exists():
        with open(config_path, encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}

    migration_years = (
        args.migration_years
        if args.migration_years is not None
        else config.get("default_migration_years", 2.0)
    )
    data_lifetime = (
        args.data_lifetime
        if args.data_lifetime is not None
        else config.get("default_data_lifetime_years", 10)
    )
    artifacts = classify(artifacts, kb, migration_years, data_lifetime)

    # SCORE
    horizon_year = (
        args.horizon_year if args.horizon_year is not None else config.get("horizon_year", 2030)
    )
    artifacts = score(artifacts, horizon_year=horizon_year, config_path=config_path)

    # RECOMMEND
    artifacts = recommend(artifacts, kb)

    # EXPORT
    if args.format == "json":
        write_cyclonedx_json(artifacts, args.output, validate=not args.no_validate)
        say(f"CBOM written to {args.output}")
    else:
        write_markdown_report(artifacts, args.output)
        say(f"Report written to {args.output}")

    if getattr(args, "json", False):
        print(json.dumps(summarize(artifacts, file_count, args.output), indent=2))
    else:
        print_summary(artifacts)

    return artifacts


def summarize(artifacts, file_count: int, output: str) -> dict:
    """Machine-readable summary, matching the API's shape."""
    by_verdict: dict[str, int] = {}
    by_confidence: dict[str, int] = {}
    for a in artifacts:
        by_verdict[a.verdict.value] = by_verdict.get(a.verdict.value, 0) + 1
        by_confidence[a.confidence.value] = by_confidence.get(a.confidence.value, 0) + 1
    return {
        "files_scanned": file_count,
        "total": len(artifacts),
        "by_verdict": by_verdict,
        "by_confidence": by_confidence,
        "needs_review": by_confidence.get(Confidence.FLAGGED.value, 0),
        "output": output,
    }


def print_summary(artifacts) -> None:
    """Print verdict counts, keeping unresolved references out of 'safe'."""
    verdict_counts: dict[str, int] = {}
    needs_review = 0
    for a in artifacts:
        if a.confidence == Confidence.FLAGGED:
            needs_review += 1
            continue
        verdict_counts[a.verdict.value] = verdict_counts.get(a.verdict.value, 0) + 1

    print("\n" + _c("Summary:", BOLD))
    for verdict, count in sorted(verdict_counts.items()):
        print(f"  {_c(verdict, VERDICT_COLOR.get(verdict, ''))}: {count}")
    if needs_review:
        print(f"  {_c('needs manual review', DIM)}: {needs_review}")


# -------------------------------------------------------------- detectors --


def _cmd_detectors(args) -> int:
    described = registry.describe()

    if args.json:
        print(json.dumps(described, indent=2))
        return 0

    print(_c("CBOMScan diagnostic tools", BOLD))
    print(_c(f"{len(described)} detectors registered\n", DIM))

    for tool in described:
        print(f"{_c(tool['title'], BOLD + ';' + CYAN)}  {_c('(' + tool['name'] + ')', DIM)}")
        print(f"  {tool['summary']}")
        print(f"  {_c('confidence', DIM)}  {tool['typical_confidence']}")
        print(f"  {_c('inputs', DIM)}      {', '.join(tool['inputs'])}")
        for item in tool["detects"]:
            print(f"    {_c('-', DIM)} {item}")
        print()

    print(_c("Every file is dispatched to each detector that claims its extension.", DIM))
    print(_c("Run `cbomscan scan <path>` to use them all at once.", DIM))
    return 0


# ------------------------------------------------------------------ serve --


def _watch_parent_stdin() -> None:
    """Exit when stdin reaches EOF.

    The desktop app holds this process's stdin pipe open. If the app is closed
    normally it kills us explicitly, but a crash or a force-kill runs no exit
    handler - and then the pipe closes, which is the signal we wait on here.
    Without it a force-killed app leaves the engine running and its port bound.
    """

    def wait() -> None:
        with contextlib.suppress(Exception):
            sys.stdin.read()
        os._exit(0)

    threading.Thread(target=wait, daemon=True, name="parent-watchdog").start()


def _cmd_serve(args) -> int:
    import uvicorn

    from cbomscan.api_server import app, mount_frontend

    if getattr(args, "exit_with_parent", False):
        _watch_parent_stdin()

    has_ui = mount_frontend()
    url = f"http://{args.host}:{args.port}"
    print(_c("CBOMScan server", BOLD))
    print(f"  API       {url}/api")
    print(f"  Dashboard {url}" if has_ui else _c("  Dashboard not built (run: make frontend)", DIM))
    print(_c("  Ctrl+C to stop\n", DIM))

    if has_ui and not args.no_browser:
        webbrowser.open(url)

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


# -------------------------------------------------------------------- app --


def _cmd_app(args) -> int:
    """Launch the packaged desktop app, or fall back to the browser dashboard."""
    launcher = find_desktop_app()
    if launcher:
        print(f"Launching {launcher.name}...")
        subprocess.Popen([str(launcher)], close_fds=True)
        return 0

    print(_c("Desktop app not found - falling back to the web dashboard.", YELLOW))
    print(_c("Build it with: cd desktop && npm install && npm run dist\n", DIM))
    return _cmd_serve(argparse.Namespace(host="127.0.0.1", port=8000, no_browser=False))


def find_desktop_app() -> Path | None:
    """Locate an installed or locally built CBOMScan desktop binary."""
    recorded = _recorded_app_path()
    if recorded:
        return recorded

    candidates = [
        Path(__file__).parent.parent / "desktop" / "dist" / "CBOMScan.exe",
        Path(__file__).parent.parent / "desktop" / "dist" / "win-unpacked" / "CBOMScan.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "CBOMScan" / "CBOMScan.exe",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    found = shutil.which("CBOMScan")
    return Path(found) if found else None


def _recorded_app_path() -> Path | None:
    """Read the install location the setup wizard recorded, if any."""
    if sys.platform != "win32":
        return None
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\CBOMScan") as key:
            value, _ = winreg.QueryValueEx(key, "AppExe")
    except OSError:
        return None
    path = Path(value)
    return path if path.is_file() else None


# ----------------------------------------------------------------- wizard --


def _cmd_wizard(args) -> int:
    """Re-run the setup wizard, which ships in the distribution ZIP."""
    wizard = find_setup_wizard()
    if not wizard:
        print(
            _c("The setup wizard is not on this machine.", YELLOW),
            file=sys.stderr,
        )
        print(
            _c(
                "It ships in the CBOMScan release ZIP as CBOMScan-Setup.exe, "
                "alongside its payload folder.",
                DIM,
            ),
            file=sys.stderr,
        )
        return 2

    print(f"Launching {wizard.name}...")
    subprocess.Popen([str(wizard)], close_fds=True)
    return 0


def find_setup_wizard() -> Path | None:
    """Locate the setup wizard next to this executable or in the repo."""
    candidates = [
        Path(sys.executable).parent / "CBOMScan-Setup.exe",
        Path(__file__).parent.parent / "dist" / "CBOMScan-Setup.exe",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    found = shutil.which("CBOMScan-Setup")
    return Path(found) if found else None


def _cmd_version(args) -> int:
    print(f"cbomscan {__version__}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
