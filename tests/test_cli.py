"""Tests for the command-line interface.

These drive the CLI the way a user does - through argument parsing and, for the
end-to-end cases, through a real subprocess - so that argument wiring, exit
codes and stdout contracts are all covered.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from cbomscan import __version__
from cbomscan.__main__ import build_parser, main

REPO = Path(__file__).parent.parent
FIXTURES = REPO / "fixtures"
PY_SAMPLE = FIXTURES / "py-sample"
CONFIG_SAMPLE = FIXTURES / "config-sample"


def run_cli(*argv: str) -> subprocess.CompletedProcess:
    """Invoke the CLI in a real subprocess, as a shell user would."""
    return subprocess.run(
        [sys.executable, "-m", "cbomscan", *argv],
        capture_output=True,
        text=True,
        cwd=REPO,
        env={"NO_COLOR": "1", "PATH": "", "SYSTEMROOT": "C:\\Windows"},
    )


# ------------------------------------------------------------ arg parsing --


def test_no_command_prints_help_and_succeeds(capsys):
    assert main([]) == 0
    assert "Cryptographic Bill of Materials Scanner" in capsys.readouterr().out


def test_scan_defaults():
    args = build_parser().parse_args(["scan", "somewhere"])

    assert args.command == "scan"
    assert args.path == "somewhere"
    assert args.output == "cbom.json"
    assert args.format == "json"
    assert args.horizon_year is None
    assert args.migration_years is None
    assert args.data_lifetime is None
    assert args.no_validate is False


def test_scan_accepts_every_documented_flag():
    args = build_parser().parse_args(
        [
            "scan",
            "repo",
            "-o",
            "out.md",
            "-f",
            "md",
            "--horizon-year",
            "2035",
            "--migration-years",
            "3.5",
            "--data-lifetime",
            "25",
            "--no-validate",
            "--quiet",
            "--verbose",
        ]
    )

    assert (args.output, args.format) == ("out.md", "md")
    assert (args.horizon_year, args.migration_years, args.data_lifetime) == (2035, 3.5, 25)
    assert args.no_validate and args.quiet and args.verbose


def test_zero_is_parsed_as_a_real_value_not_a_missing_one():
    args = build_parser().parse_args(
        ["scan", "r", "--migration-years", "0", "--data-lifetime", "0"]
    )
    assert args.migration_years == 0.0
    assert args.data_lifetime == 0


def test_invalid_format_is_rejected():
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["scan", "repo", "-f", "pdf"])
    assert exc.value.code == 2


def test_unknown_subcommand_is_rejected():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["frobnicate"])


def test_scan_requires_a_path():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["scan"])


# ---------------------------------------------------------------- version --


def test_version_subcommand(capsys):
    assert main(["version"]) == 0
    assert __version__ in capsys.readouterr().out


def test_version_flag():
    result = run_cli("--version")
    assert result.returncode == 0
    assert __version__ in result.stdout


# -------------------------------------------------------------- detectors --


def test_detectors_lists_all_five_tools(capsys):
    assert main(["detectors"]) == 0
    out = capsys.readouterr().out

    for title in (
        "Manifest Detector",
        "Python Source Detector",
        "JavaScript / TypeScript Source Detector",
        "Certificate Detector",
        "Config & Infrastructure Detector",
    ):
        assert title in out


def test_detectors_json_is_machine_readable(capsys):
    assert main(["detectors", "--json"]) == 0
    tools = json.loads(capsys.readouterr().out)

    assert len(tools) == 5
    for tool in tools:
        assert tool["name"] and tool["title"] and tool["summary"]
        assert tool["typical_confidence"] in {"confirmed", "inferred", "flagged"}
        assert tool["inputs"] and tool["detects"]


# ------------------------------------------------------------------- scan --


def test_scan_writes_a_valid_cbom(tmp_path, capsys):
    out = tmp_path / "cbom.json"

    assert main(["scan", str(PY_SAMPLE), "-o", str(out)]) == 0

    bom = json.loads(out.read_text(encoding="utf-8"))
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.7"
    assert bom["components"]
    assert "Summary:" in capsys.readouterr().out


def test_scan_writes_a_markdown_report(tmp_path):
    out = tmp_path / "report.md"

    assert main(["scan", str(PY_SAMPLE), "-o", str(out), "-f", "md"]) == 0

    assert out.read_text(encoding="utf-8").startswith("# CBOMScan Report")


def test_scan_json_summary_is_parseable(tmp_path, capsys):
    out = tmp_path / "cbom.json"

    assert main(["scan", str(PY_SAMPLE), "-o", str(out), "--json"]) == 0

    summary = json.loads(capsys.readouterr().out)
    assert summary["files_scanned"] == 3
    assert summary["total"] == len(json.loads(out.read_text(encoding="utf-8"))["components"])
    assert summary["by_verdict"]["vulnerable"] > 0
    assert summary["output"] == str(out)


def test_scan_quiet_prints_only_the_summary(tmp_path, capsys):
    main(["scan", str(PY_SAMPLE), "-o", str(tmp_path / "c.json"), "--quiet"])
    out = capsys.readouterr().out

    assert "Summary:" in out
    assert "Loaded knowledge base" not in out
    assert "Scanning:" not in out


def test_scan_reports_flagged_separately_from_safe(tmp_path, capsys):
    main(["scan", str(CONFIG_SAMPLE), "-o", str(tmp_path / "c.json"), "--json"])
    summary = json.loads(capsys.readouterr().out)

    assert summary["needs_review"] == summary["total"]


def test_horizon_year_changes_the_mosca_verdict(tmp_path):
    """Z is the whole point of the slider - moving it must move the notes."""
    near = tmp_path / "near.md"
    far = tmp_path / "far.md"

    main(["scan", str(PY_SAMPLE), "-o", str(near), "-f", "md", "--horizon-year", "2028"])
    main(["scan", str(PY_SAMPLE), "-o", str(far), "-f", "md", "--horizon-year", "2050"])

    assert "URGENT" in near.read_text(encoding="utf-8")
    assert "URGENT" not in far.read_text(encoding="utf-8")


def test_no_validate_skips_schema_validation(tmp_path, monkeypatch):
    import cbomscan.export as export

    def explode(_):
        raise AssertionError("validation should have been skipped")

    monkeypatch.setattr(export, "validate_cyclonedx", explode)
    assert main(["scan", str(PY_SAMPLE), "-o", str(tmp_path / "c.json"), "--no-validate"]) == 0


def test_scan_accepts_a_single_file(tmp_path):
    out = tmp_path / "cbom.json"

    assert main(["scan", str(PY_SAMPLE / "crypto_usage.py"), "-o", str(out)]) == 0

    assert json.loads(out.read_text(encoding="utf-8"))["components"]


# ----------------------------------------------------------- error paths --


def test_missing_path_exits_2_with_a_clean_message(capsys):
    assert main(["scan", "no/such/place"]) == 2

    captured = capsys.readouterr()
    assert "error:" in captured.err
    assert "Traceback" not in captured.err


def test_missing_knowledge_base_exits_2(capsys):
    assert main(["scan", str(PY_SAMPLE), "--kb", "no/such/kb.yaml"]) == 2
    assert "error:" in capsys.readouterr().err


# ------------------------------------------------- real subprocess checks --


def test_module_invocation_end_to_end(tmp_path):
    """python -m cbomscan must work as a standalone command."""
    out = tmp_path / "cbom.json"
    result = run_cli("scan", str(PY_SAMPLE), "-o", str(out), "--json")

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["total"] > 0
    assert out.is_file()


def test_missing_path_subprocess_exit_code():
    result = run_cli("scan", "no/such/place")

    assert result.returncode == 2
    assert "Traceback" not in result.stderr


def test_help_lists_every_subcommand():
    result = run_cli("--help")

    assert result.returncode == 0
    for command in ("scan", "detectors", "serve", "app", "wizard", "version"):
        assert command in result.stdout


def test_console_script_is_installed():
    """The `cbomscan` command must be on PATH after installation."""
    exe = Path(sys.executable).parent / "Scripts" / "cbomscan.exe"
    if not exe.is_file():
        pytest.skip("console script not installed in this environment")

    result = subprocess.run([str(exe), "version"], capture_output=True, text=True)

    assert result.returncode == 0
    assert __version__ in result.stdout


# --------------------------------------------------- parent watchdog --------
# A force-killed desktop app runs no exit handler, so the engine has to notice
# on its own that its launcher is gone - otherwise it orphans and holds a port.


def test_serve_exits_when_parent_closes_stdin():
    """`serve --exit-with-parent` must terminate on stdin EOF."""
    import socket
    import time

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    server = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "cbomscan",
            "serve",
            "--port",
            str(port),
            "--no-browser",
            "--exit-with-parent",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=REPO,
    )
    try:
        deadline = time.time() + 60
        while time.time() < deadline:
            with socket.socket() as probe:
                probe.settimeout(0.5)
                if probe.connect_ex(("127.0.0.1", port)) == 0:
                    break
            time.sleep(0.3)
        else:
            pytest.fail("server never started listening")

        # Closing stdin is exactly what happens when the launcher dies.
        server.stdin.close()
        assert server.wait(timeout=30) is not None, "server did not exit on stdin EOF"
    finally:
        if server.poll() is None:
            server.kill()
            server.wait(timeout=10)


def test_serve_without_the_flag_ignores_stdin():
    """A human running `cbomscan serve` in a terminal must not exit on EOF."""
    import socket
    import time

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    server = subprocess.Popen(
        [sys.executable, "-m", "cbomscan", "serve", "--port", str(port), "--no-browser"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=REPO,
    )
    try:
        deadline = time.time() + 60
        while time.time() < deadline:
            with socket.socket() as probe:
                probe.settimeout(0.5)
                if probe.connect_ex(("127.0.0.1", port)) == 0:
                    break
            time.sleep(0.3)
        else:
            pytest.fail("server never started listening")

        server.stdin.close()
        time.sleep(3)
        assert server.poll() is None, "server exited on stdin EOF without the flag"
    finally:
        server.kill()
        server.wait(timeout=10)
