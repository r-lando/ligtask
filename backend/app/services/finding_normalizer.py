from pathlib import Path


VALID_SEVERITIES = {
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}


def normalize_severity(severity):
    if not severity:
        return "INFO"

    normalized = str(severity).upper()

    if normalized in VALID_SEVERITIES:
        return normalized

    return "INFO"


def create_title(rule_id):
    if not rule_id:
        return "Security Finding"

    rule_name = rule_id.split(".")[-1]

    return rule_name.replace("-", " ").title()


def normalize_semgrep_findings(semgrep_results, repository_path: Path):
    normalized_findings = []

    for finding in semgrep_results.get("findings", []):
        raw_path = finding.get("file")
        relative_path = raw_path

        if raw_path:
            try:
                relative_path = str(
                    Path(raw_path)
                    .resolve()
                    .relative_to(repository_path.resolve())
                )
            except ValueError:
                relative_path = Path(raw_path).name

        # Use forward slashes consistently in API responses
        if relative_path:
            relative_path = relative_path.replace("\\", "/")

        rule_id = finding.get("rule_id")

        normalized_findings.append({
            "scanner": "Semgrep",
            "category": "SAST",
            "rule_id": rule_id,
            "title": create_title(rule_id),
            "severity": normalize_severity(
                finding.get("severity")
            ),
            "file": relative_path,
            "line": finding.get("line"),
            "message": finding.get("message"),
        })

    return normalized_findings