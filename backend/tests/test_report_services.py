from app.services.pdf_report_service import (
    generate_assessment_pdf,
)
from app.services.report_service import (
    generate_assessment_html,
)


def make_sample_assessment(*, status="completed", finding_overrides=None):
    findings = [
        {
            "id": 1,
            "scanner": "Semgrep",
            "category": "SAST",
            "rule_id": "javascript.express.security.audit.xss",
            "title": "Cross-Site Scripting <script>alert(1)</script>",
            "severity": "HIGH",
            "cvss_score": None,
            "cvss_vector": None,
            "cvss_version": None,
            "file": "src/routes.js",
            "line": 42,
            "message": "Potential XSS via <b>res.send()</b>",
            "package": None,
            "version": None,
            "ecosystem": None,
            "correlated": False,
            "evidence_count": 1,
            "sources": ["Semgrep"],
            "source_rule_ids": ["javascript.express.security.audit.xss"],
            "description": "User input is directly reflected in <b>res.send()</b>",
            "recommendation": "Encode or sanitize <script>output</script>.",
            "guidance_source": "Semgrep Community",
        },
        {
            "id": 2,
            "scanner": "OSV",
            "category": "DEPENDENCY",
            "rule_id": "GHSA-1234-5678",
            "title": "Vulnerable Dependency: lodash",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_version": "3.1",
            "file": "package-lock.json",
            "line": None,
            "message": "lodash 4.17.15 is affected by prototype pollution.",
            "package": "lodash",
            "version": "4.17.15",
            "ecosystem": "npm",
            "correlated": False,
            "evidence_count": 1,
            "sources": ["OSV"],
            "source_rule_ids": ["GHSA-1234-5678"],
            "description": "Prototype pollution vulnerability.",
            "recommendation": "Upgrade to lodash 4.17.21 or later.",
            "guidance_source": "OSV Advisory",
        },
        {
            "id": 3,
            "scanner": "TALGED Secret Detector",
            "category": "SECRET",
            "rule_id": "generic-secret-assignment",
            "title": "Potential Secret Detected",
            "severity": "HIGH",
            "cvss_score": None,
            "cvss_vector": None,
            "cvss_version": None,
            "file": ".env",
            "line": 1,
            "message": (
                "A potential secret or credential was detected. "
                "The detected value has not been included in the "
                "assessment result."
            ),
            "package": None,
            "version": None,
            "ecosystem": None,
            "correlated": False,
            "evidence_count": 1,
            "sources": ["TALGED Secret Detector"],
            "source_rule_ids": ["generic-secret-assignment"],
            "description": "Hardcoded secret detected.",
            "recommendation": "Move secret to secure environment configuration.",
            "guidance_source": "TALGED Guidance",
        },
    ]

    if finding_overrides is not None:
        findings = finding_overrides

    return {
        "assessment_id": "test-assessment-uuid",
        "repository_name": "sample-repo <script>",
        "input_type": "ZIP",
        "status": status,
        "created_at": "2026-09-11T12:00:00Z",
        "completed_at": "2026-09-11T12:01:04Z",
        "uploaded_size_bytes": 10240,
        "extracted_size_bytes": 25600,
        "total_files": 5,
        "processing_time_ms": 64000,
        "raw_findings_count": len(findings),
        "consolidated_findings_count": len(findings),
        "severity_summary": {
            "CRITICAL": 1,
            "HIGH": 2,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
            "UNKNOWN": 0,
        },
        "correlated_groups": 0,
        "duplicate_findings_merged": 0,
        "mechanism_statuses": {
            "sast": {
                "status": "completed",
                "scanner": "Semgrep",
                "findings_count": 1,
                "error": None,
            },
            "dependency": {
                "status": "completed",
                "scanner": "OSV",
                "findings_count": 1,
                "error": None,
            },
            "secret": {
                "status": "completed",
                "scanner": "TALGED",
                "findings_count": 1,
                "error": None,
            },
            "configuration": {
                "status": (
                    "partial" if status == "partial" else "completed"
                ),
                "scanner": "TALGED",
                "findings_count": 0,
                "error": (
                    "One file failed" if status == "partial" else None
                ),
            },
        },
        "repository_profile": {
            "total_files": 5,
            "languages": {"JavaScript": 2},
            "dependency_files": ["package-lock.json"],
            "configuration_files": [".env"],
        },
        "findings": findings,
    }


def test_html_report_returns_none_for_missing_assessment(
    monkeypatch,
):
    monkeypatch.setattr(
        "app.services.report_service.get_assessment_by_id",
        lambda assessment_id: None,
    )
    assert generate_assessment_html("nonexistent-id") is None


def test_pdf_report_returns_none_for_missing_assessment(
    monkeypatch,
):
    monkeypatch.setattr(
        "app.services.pdf_report_service.get_assessment_by_id",
        lambda assessment_id: None,
    )
    assert generate_assessment_pdf("nonexistent-id") is None


def test_html_report_escapes_untrusted_input(
    monkeypatch,
):
    assessment = make_sample_assessment()

    monkeypatch.setattr(
        "app.services.report_service.get_assessment_by_id",
        lambda assessment_id: assessment,
    )

    html = generate_assessment_html("test-assessment-uuid")

    assert html is not None
    assert "<!DOCTYPE html>" in html
    assert "sample-repo &lt;script&gt;" in html
    assert "<script>alert(1)</script>" not in html
    assert "<script>output</script>" not in html
    assert "Cross-Site Scripting &lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "User input is directly reflected in &lt;b&gt;res.send()&lt;/b&gt;" in html
    assert "Encode or sanitize &lt;script&gt;output&lt;/script&gt;." in html
    assert "src/routes.js:42" in html
    assert "package-lock.json" in html
    assert "dependency matches do not confirm exploitability" in html
    assert "Informational findings are audit observations" in html


def test_html_report_handles_partial_assessment(
    monkeypatch,
):
    assessment = make_sample_assessment(status="partial")

    monkeypatch.setattr(
        "app.services.report_service.get_assessment_by_id",
        lambda assessment_id: assessment,
    )

    html = generate_assessment_html("test-assessment-uuid")

    assert html is not None
    assert "Partial" in html


def test_pdf_report_generates_valid_pdf(
    monkeypatch,
):
    assessment = make_sample_assessment()

    monkeypatch.setattr(
        "app.services.pdf_report_service.get_assessment_by_id",
        lambda assessment_id: assessment,
    )

    pdf_bytes = generate_assessment_pdf("test-assessment-uuid")

    assert pdf_bytes is not None
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 1000


def test_pdf_report_handles_partial_and_missing_fields(
    monkeypatch,
):
    assessment = make_sample_assessment(
        status="partial",
        finding_overrides=[
            {
                "id": 1,
                "scanner": "Semgrep",
                "category": "SAST",
                "rule_id": "test-rule",
                "title": "Minimal Finding",
                "severity": "UNKNOWN",
                "cvss_score": None,
                "cvss_vector": None,
                "cvss_version": None,
                "file": None,
                "line": None,
                "message": None,
                "package": None,
                "version": None,
                "ecosystem": None,
                "correlated": False,
                "evidence_count": 1,
                "sources": [],
                "source_rule_ids": [],
                "description": None,
                "recommendation": None,
                "guidance_source": None,
            }
        ],
    )

    monkeypatch.setattr(
        "app.services.pdf_report_service.get_assessment_by_id",
        lambda assessment_id: assessment,
    )

    pdf_bytes = generate_assessment_pdf("test-assessment-uuid")

    assert pdf_bytes is not None
    assert pdf_bytes.startswith(b"%PDF-")
