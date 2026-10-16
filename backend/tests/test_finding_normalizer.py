from pathlib import Path

import pytest

from app.services.finding_normalizer import (
    normalize_severity,
    normalize_semgrep_findings,
    create_severity_summary,
)


@pytest.mark.parametrize("raw,expected", [
    ("ERROR", "HIGH"), ("WARNING", "MEDIUM"), ("INFO", "INFO"),
    (" error ", "HIGH"), ("warning", "MEDIUM"),
    ("CRITICAL", "CRITICAL"), ("HIGH", "HIGH"), ("MEDIUM", "MEDIUM"),
    ("LOW", "LOW"), ("UNKNOWN", "UNKNOWN"), (None, "UNKNOWN"),
    ("unrecognized", "UNKNOWN"),
])
def test_scanner_severity_normalization(raw, expected):
    assert normalize_severity(raw) == expected


def test_semgrep_sql_priority_and_csrf_audit_stay_distinct():
    findings = normalize_semgrep_findings({"findings": [
        {"rule_id": "tainted-sql-string", "severity": "ERROR", "file": "app.js", "line": 7},
        {"rule_id": "express-check-csurf-middleware-usage", "severity": "INFO", "file": "app.js", "line": 2},
    ]}, Path("."))
    summary = create_severity_summary(findings)
    assert summary["HIGH"] == 1
    assert summary["INFO"] == 1
    assert summary["UNKNOWN"] == 0
    assert all(finding["cvss_score"] is None for finding in findings)
