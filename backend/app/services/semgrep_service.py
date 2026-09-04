import json
import subprocess
from pathlib import Path


SEMGREP_TIMEOUT_SECONDS = 120

SEMGREP_RULES_PATH = (
    Path(__file__).resolve().parents[2]
    / "semgrep_rules"
    / "v1"
)


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
    frozen local Ligtask production ruleset with
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

    for finding in semgrep_output.get(
        "results",
        [],
    ):
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
        "findings_count": len(findings),
        "findings": findings,
        "error": None,
        "timed_out": False,
        "exit_code": result.returncode,
    }