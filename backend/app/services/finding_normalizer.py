from pathlib import Path


VALID_SEVERITIES = {
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
    "UNKNOWN",
}


def normalize_severity(severity):
    """
    Convert scanner severity values into Ligtask's
    standardized severity labels.
    """
    if not severity:
        return "UNKNOWN"

    normalized = str(severity).upper()

    if normalized in VALID_SEVERITIES:
        return normalized

    return "UNKNOWN"


def create_title(rule_id):
    """
    Create a readable title from a Semgrep rule ID.
    """
    if not rule_id:
        return "Security Finding"

    rule_name = rule_id.split(".")[-1]

    return rule_name.replace("-", " ").title()


def normalize_file_path(raw_path, repository_path: Path):
    """
    Convert temporary server paths into
    repository-relative paths.
    """
    if not raw_path:
        return None

    try:
        relative_path = str(
            Path(raw_path)
            .resolve()
            .relative_to(repository_path.resolve())
        )
    except ValueError:
        relative_path = Path(raw_path).name

    return relative_path.replace("\\", "/")


def normalize_semgrep_findings(
    semgrep_results,
    repository_path: Path
):
    """
    Convert Semgrep findings into Ligtask's
    common finding format.
    """
    normalized_findings = []

    for finding in semgrep_results.get("findings", []):
        rule_id = finding.get("rule_id")

        normalized_findings.append({
            "scanner": "Semgrep",
            "category": "SAST",
            "rule_id": rule_id,

            "title": create_title(rule_id),

            "severity": normalize_severity(
                finding.get("severity")
            ),

            "cvss_score": None,
            "cvss_vector": None,
            "cvss_version": None,

            "file": normalize_file_path(
                finding.get("file"),
                repository_path
            ),

            "line": finding.get("line"),

            "message": finding.get("message"),

            "package": None,
            "version": None,
            "ecosystem": None,
        })

    return normalized_findings


def normalize_osv_findings(
    dependency_results,
    repository_path: Path
):
    """
    Convert OSV dependency vulnerability findings
    into Ligtask's common finding format.
    """
    normalized_findings = []

    for finding in dependency_results.get("findings", []):
        vulnerability_id = finding.get(
            "vulnerability_id"
        )

        package = finding.get("package")
        version = finding.get("version")
        summary = finding.get("summary")

        severity = normalize_severity(
            finding.get("severity")
        )

        normalized_findings.append({
            "scanner": "OSV",
            "category": "DEPENDENCY",

            "rule_id": vulnerability_id,

            "title": (
                summary
                or f"Vulnerable Dependency: {package}"
            ),

            "severity": severity,

            "cvss_score": finding.get(
                "cvss_score"
            ),

            "cvss_vector": finding.get(
                "cvss_vector"
            ),

            "cvss_version": finding.get(
                "cvss_version"
            ),

            "file": normalize_file_path(
                finding.get("source_file"),
                repository_path
            ),

            "line": None,

            "message": (
                f"{package} {version} is affected by "
                f"{vulnerability_id}."
            ),

            "package": package,
            "version": version,
            "ecosystem": finding.get(
                "ecosystem"
            ),
        })

    return normalized_findings
def create_severity_summary(findings):
    """
    Count normalized findings by severity.
    """
    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "UNKNOWN": 0,
    }

    for finding in findings:
        severity = finding.get(
            "severity",
            "UNKNOWN"
        )

        if severity not in summary:
            severity = "UNKNOWN"

        summary[severity] += 1

    return summary