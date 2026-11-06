import json
import subprocess
import re
from pathlib import Path


SEMGREP_TIMEOUT_SECONDS = 120

SEMGREP_RULES_PATH = (
    Path(__file__).resolve().parents[2]
    / "semgrep_rules"
    / "v1"
)


def has_django_evidence(repository_path):
    """Require a Python Django import, not a generic HTML form."""
    for path in Path(repository_path).rglob("*.py"):
        if any(part in {".venv", "venv", "node_modules", ".git"} for part in path.parts):
            continue
        try:
            if path.stat().st_size <= 2 * 1024 * 1024 and re.search(
                r"(?m)^\s*(?:from\s+django(?:\.|\s)|import\s+django\b)",
                path.read_text(encoding="utf-8"),
            ):
                return True
        except (OSError, UnicodeError):
            continue
    return False


def semgrep_failure(
    message,
    *,
    timed_out=False,
    exit_code=None,
):
    """
    Return a consistent Semgrep failure result.

    Scanner failures do not include repository
    contents or raw scanner stderr.
    """
    return {
        "success": False,
        "findings_count": 0,
        "findings": [],
        "error": message,
        "timed_out": timed_out,
        "exit_code": exit_code,
    }


def run_semgrep(repository_path: Path):
    """
    Run Semgrep against a repository using the
    frozen local TALGED production ruleset with
    controlled timeout and failure handling.
    """

    repository_path = Path(repository_path)

    if not SEMGREP_RULES_PATH.is_dir():
        return semgrep_failure(
            "Semgrep ruleset is unavailable."
        )

    command = [
        "semgrep",
        "--config",
        str(SEMGREP_RULES_PATH),
        "--json",
        str(repository_path),
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=SEMGREP_TIMEOUT_SECONDS,
            check=False,
        )

    except subprocess.TimeoutExpired:
        return semgrep_failure(
            (
                "Semgrep exceeded the "
                f"{SEMGREP_TIMEOUT_SECONDS}-second "
                "analysis timeout."
            ),
            timed_out=True,
        )

    except FileNotFoundError:
        return semgrep_failure(
            (
                "Semgrep is not installed or "
                "could not be found."
            ),
        )

    except OSError:
        return semgrep_failure(
            (
                "Semgrep could not be started "
                "by the assessment service."
            ),
        )

    if result.returncode != 0:
        return semgrep_failure(
            (
                "Semgrep terminated with a "
                "scanner execution error."
            ),
            exit_code=result.returncode,
        )

    if not result.stdout.strip():
        return semgrep_failure(
            "Semgrep produced no analysis output.",
            exit_code=result.returncode,
        )

    try:
        semgrep_output = json.loads(result.stdout)

    except json.JSONDecodeError:
        return semgrep_failure(
            (
                "Unable to parse Semgrep "
                "analysis output."
            ),
            exit_code=result.returncode,
        )

    findings = []
    django_evidence = has_django_evidence(repository_path)
    excluded_framework_matches = 0

    for finding in semgrep_output.get(
        "results",
        [],
    ):
        if (str(finding.get("check_id", "")).endswith("django-no-csrf-token")
                and not django_evidence):
            excluded_framework_matches += 1
            continue
        findings.append(
            {
                "rule_id": finding.get(
                    "check_id"
                ),
                "file": finding.get(
                    "path"
                ),
                "line": finding.get(
                    "start",
                    {},
                ).get(
                    "line"
                ),
                "match_start": [finding.get("start", {}).get("line"), finding.get("start", {}).get("col")],
                "match_end": [finding.get("end", {}).get("line"), finding.get("end", {}).get("col")],
                "severity": finding.get(
                    "extra",
                    {},
                ).get(
                    "severity"
                ),
                "message": finding.get(
                    "extra",
                    {},
                ).get(
                    "message"
                ),
            }
        )

    return {
        "success": True,
        "note": (f"{excluded_framework_matches} Django form-rule matches excluded: no Python Django import found in submitted files." if excluded_framework_matches else None),
        "findings_count": len(findings),
        "findings": findings,
        "error": None,
        "timed_out": False,
        "exit_code": result.returncode,
    }
