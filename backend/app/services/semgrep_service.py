import json
import subprocess
from pathlib import Path


def run_semgrep(repository_path: Path):
    command = [
        "semgrep",
        "--config",
        "auto",
        "--json",
        str(repository_path),
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    if not result.stdout:
        return {
            "success": False,
            "findings": [],
            "error": result.stderr or "Semgrep produced no output."
        }

    try:
        semgrep_output = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "success": False,
            "findings": [],
            "error": "Unable to parse Semgrep JSON output."
        }

    findings = []

    for finding in semgrep_output.get("results", []):
        findings.append({
            "rule_id": finding.get("check_id"),
            "file": finding.get("path"),
            "line": finding.get("start", {}).get("line"),
            "severity": finding.get("extra", {}).get("severity"),
            "message": finding.get("extra", {}).get("message"),
        })

    return {
        "success": True,
        "findings_count": len(findings),
        "findings": findings,
    }