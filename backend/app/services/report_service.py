from html import escape

from app.services.database_service import (
    get_assessment_by_id,
)


SEVERITY_ORDER = (
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
    "UNKNOWN",
)


def safe_text(value):
    """
    Convert a value to escaped HTML text.
    """
    if value is None:
        return "N/A"

    return escape(str(value))


def format_cvss(finding):
    """
    Format CVSS information without
    inventing unavailable scores.
    """
    score = finding.get("cvss_score")
    version = finding.get("cvss_version")

    if score is None:
        return "Not available"

    if version:
        return (
            f"{safe_text(score)} "
            f"(CVSS {safe_text(version)})"
        )

    return safe_text(score)


def format_location(finding):
    """
    Build a safe affected-location string.
    """
    file_path = finding.get("file")
    line_number = finding.get("line")

    if not file_path:
        return "Not specified"

    if line_number:
        return (
            f"{safe_text(file_path)}"
            f":{safe_text(line_number)}"
        )

    return safe_text(file_path)


def build_severity_rows(
    severity_summary,
):
    rows = []

    for severity in SEVERITY_ORDER:
        count = severity_summary.get(
            severity,
            0,
        )

        rows.append(
            f"""
            <tr>
                <td>{safe_text(severity)}</td>
                <td>{safe_text(count)}</td>
            </tr>
            """
        )

    return "\n".join(rows)


def build_finding_rows(findings):
    rows = []

    for index, finding in enumerate(
        findings,
        start=1,
    ):
        sources = finding.get(
            "sources",
            [],
        )

        if sources:
            source_text = ", ".join(
                safe_text(source)
                for source in sources
            )
        else:
            source_text = safe_text(
                finding.get("scanner")
            )

        correlated = (
            "Yes"
            if finding.get("correlated")
            else "No"
        )

        rows.append(
            f"""
            <tr>
                <td>{index}</td>

                <td>
                    {safe_text(
                        finding.get("severity")
                    )}
                </td>

                <td>
                    {safe_text(
                        finding.get("category")
                    )}
                </td>

                <td>
                    {safe_text(
                        finding.get("title")
                    )}
                </td>

                <td>
                    {safe_text(
                        finding.get("rule_id")
                    )}
                </td>

                <td>
                    {format_cvss(finding)}
                </td>

                <td>
                    {format_location(finding)}
                </td>

                <td>
                    {source_text}
                </td>

                <td>
                    {correlated}
                </td>
            </tr>
            """
        )

    return "\n".join(rows)


def build_finding_details(findings):
    sections = []

    for index, finding in enumerate(
        findings,
        start=1,
    ):
        package = finding.get("package")
        version = finding.get("version")
        ecosystem = finding.get(
            "ecosystem"
        )

        package_information = ""

        if package:
            package_information = f"""
                <p>
                    <strong>Package:</strong>
                    {safe_text(package)}
                </p>

                <p>
                    <strong>Version:</strong>
                    {safe_text(version)}
                </p>

                <p>
                    <strong>Ecosystem:</strong>
                    {safe_text(ecosystem)}
                </p>
            """

        sources = finding.get(
            "sources",
            [],
        )

        source_rule_ids = finding.get(
            "source_rule_ids",
            [],
        )

        sections.append(
            f"""
            <section class="finding">
                <h3>
                    {index}.
                    {safe_text(
                        finding.get("title")
                    )}
                </h3>

                <p>
                    <strong>Severity:</strong>
                    {safe_text(
                        finding.get("severity")
                    )}
                </p>

                <p>
                    <strong>Category:</strong>
                    {safe_text(
                        finding.get("category")
                    )}
                </p>

                <p>
                    <strong>Rule ID:</strong>
                    {safe_text(
                        finding.get("rule_id")
                    )}
                </p>

                <p>
                    <strong>CVSS:</strong>
                    {format_cvss(finding)}
                </p>

                <p>
                    <strong>Affected Location:</strong>
                    {format_location(finding)}
                </p>

                {package_information}

                <p>
                    <strong>Description:</strong>
                    {safe_text(
                        finding.get(
                            "description"
                        )
                    )}
                </p>

                <p>
                    <strong>Recommendation:</strong>
                    {safe_text(
                        finding.get(
                            "recommendation"
                        )
                    )}
                </p>

                <p>
                    <strong>Assessment Source:</strong>
                    {safe_text(
                        ", ".join(sources)
                        if sources
                        else finding.get(
                            "scanner"
                        )
                    )}
                </p>

                <p>
                    <strong>Source Rule IDs:</strong>
                    {safe_text(
                        ", ".join(
                            source_rule_ids
                        )
                        if source_rule_ids
                        else finding.get(
                            "rule_id"
                        )
                    )}
                </p>

                <p>
                    <strong>Correlated:</strong>
                    {
                        "Yes"
                        if finding.get(
                            "correlated"
                        )
                        else "No"
                    }
                </p>

                <p>
                    <strong>Evidence Count:</strong>
                    {safe_text(
                        finding.get(
                            "evidence_count",
                            1,
                        )
                    )}
                </p>
            </section>
            """
        )

    return "\n".join(sections)


def generate_assessment_html(
    assessment_id,
):
    """
    Generate a complete HTML security
    assessment report from persisted data.

    Returns None when the assessment does
    not exist.
    """
    assessment = get_assessment_by_id(
        assessment_id
    )

    if assessment is None:
        return None

    severity_summary = assessment.get(
        "severity_summary",
        {},
    )

    findings = assessment.get(
        "findings",
        [],
    )

    repository_profile = assessment.get(
        "repository_profile",
        {},
    )

    languages = repository_profile.get(
        "languages",
        {},
    )

    language_text = (
        ", ".join(
            (
                f"{safe_text(language)} "
                f"({safe_text(count)})"
            )
            for language, count
            in languages.items()
        )
        if languages
        else "None detected"
    )

    severity_rows = build_severity_rows(
        severity_summary
    )

    finding_rows = build_finding_rows(
        findings
    )

    finding_details = (
        build_finding_details(
            findings
        )
    )

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width,
        initial-scale=1.0"
    >

    <title>
        Ligtask Security Assessment Report
    </title>

    <style>
        body {{
            font-family:
                Arial,
                Helvetica,
                sans-serif;
            margin: 40px;
            color: #222;
            line-height: 1.5;
        }}

        h1,
        h2,
        h3 {{
            margin-bottom: 8px;
        }}

        h1 {{
            border-bottom:
                2px solid #222;
            padding-bottom: 12px;
        }}

        h2 {{
            margin-top: 32px;
            border-bottom:
                1px solid #bbb;
            padding-bottom: 6px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 16px;
            margin-bottom: 24px;
        }}

        th,
        td {{
            border: 1px solid #ccc;
            padding: 8px;
            text-align: left;
            vertical-align: top;
        }}

        th {{
            background: #f1f1f1;
        }}

        .finding {{
            margin-top: 24px;
            padding-top: 12px;
            border-top:
                1px solid #ddd;
        }}

        .privacy-note {{
            margin-top: 32px;
            padding: 16px;
            border: 1px solid #bbb;
        }}

        .muted {{
            color: #555;
        }}
    </style>
</head>

<body>

    <h1>
        Ligtask Security Assessment Report
    </h1>

    <p class="muted">
        Privacy-Preserving Repository-Aware
        Security Assessment Platform
    </p>

    <h2>
        Assessment Information
    </h2>

    <table>
        <tr>
            <th>Assessment ID</th>
            <td>
                {safe_text(
                    assessment.get(
                        "assessment_id"
                    )
                )}
            </td>
        </tr>

        <tr>
            <th>Repository</th>
            <td>
                {safe_text(
                    assessment.get(
                        "repository_name"
                    )
                )}
            </td>
        </tr>

        <tr>
            <th>Input Type</th>
            <td>
                {safe_text(
                    assessment.get(
                        "input_type"
                    )
                )}
            </td>
        </tr>

        <tr>
            <th>Status</th>
            <td>
                {safe_text(
                    assessment.get(
                        "status"
                    )
                )}
            </td>
        </tr>

        <tr>
            <th>Assessment Started</th>
            <td>
                {safe_text(
                    assessment.get(
                        "created_at"
                    )
                )}
            </td>
        </tr>

        <tr>
            <th>Assessment Completed</th>
            <td>
                {safe_text(
                    assessment.get(
                        "completed_at"
                    )
                )}
            </td>
        </tr>

        <tr>
            <th>Processing Time</th>
            <td>
                {safe_text(
                    assessment.get(
                        "processing_time_ms"
                    )
                )}
                ms
            </td>
        </tr>
    </table>

    <h2>
        Repository Profile
    </h2>

    <table>
        <tr>
            <th>Total Files</th>
            <td>
                {safe_text(
                    repository_profile.get(
                        "total_files",
                        0,
                    )
                )}
            </td>
        </tr>

        <tr>
            <th>Detected Languages</th>
            <td>
                {language_text}
            </td>
        </tr>
    </table>

    <h2>
        Assessment Summary
    </h2>

    <table>
        <tr>
            <th>Raw Findings</th>
            <td>
                {safe_text(
                    assessment.get(
                        "raw_findings_count",
                        0,
                    )
                )}
            </td>
        </tr>

        <tr>
            <th>
                Consolidated Findings
            </th>
            <td>
                {safe_text(
                    assessment.get(
                        "consolidated_findings_count",
                        0,
                    )
                )}
            </td>
        </tr>

        <tr>
            <th>
                Correlated Groups
            </th>
            <td>
                {safe_text(
                    assessment.get(
                        "correlated_groups",
                        0,
                    )
                )}
            </td>
        </tr>

        <tr>
            <th>
                Duplicate Findings Merged
            </th>
            <td>
                {safe_text(
                    assessment.get(
                        "duplicate_findings_merged",
                        0,
                    )
                )}
            </td>
        </tr>
    </table>

    <h2>
        Severity Distribution
    </h2>

    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Findings</th>
            </tr>
        </thead>

        <tbody>
            {severity_rows}
        </tbody>
    </table>

    <h2>
        Consolidated Findings
    </h2>

    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>Severity</th>
                <th>Category</th>
                <th>Finding</th>
                <th>Rule ID</th>
                <th>CVSS</th>
                <th>Location</th>
                <th>Source</th>
                <th>Correlated</th>
            </tr>
        </thead>

        <tbody>
            {finding_rows}
        </tbody>
    </table>

    <h2>
        Finding Details
    </h2>

    {finding_details}

    <div class="privacy-note">
        <strong>Privacy Notice</strong>

        <p>
            Ligtask processes submitted
            repository contents temporarily
            for security assessment purposes.
            Repository source code and uploaded
            repository archives are not
            permanently stored by the platform.
            Persisted assessment records contain
            only security findings and
            assessment-related metadata needed
            for result retrieval and reporting.
        </p>

        <p>
            Detected secret values are excluded
            from assessment results and reports.
        </p>
    </div>

</body>
</html>
    """

    return html.strip()