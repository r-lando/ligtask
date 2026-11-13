ASSESSMENT_LIMITATION_NOTE = (
    "Findings indicate potential security issues; dependency matches do not "
    "confirm exploitability. Informational findings are audit observations "
    "and do not establish a vulnerability."
)


def source_revision_text(assessment):
    if assessment.get("input_type") != "GITHUB":
        return "Not applicable (ZIP upload)"
    revision = assessment.get("source_revision") or {}
    sha = revision.get("commit_sha")
    return f"{sha} (branch: {revision.get('branch') or 'Not recorded'})" if sha else "Not recorded (older assessment)"


def mechanism_report_status(key, mechanism):
    """Show lack of coverage without hiding failed or partial execution."""
    status = mechanism.get("status")
    if (key == "dependency" and status == "completed"
            and not mechanism.get("error")
            and str(mechanism.get("note") or "").startswith("No software libraries were checked.")):
        return "Not checked"
    return {"completed": "Completed", "failed": "Failed", "partial": "Partial",
            "skipped": "Skipped", "not_run": "Not Run"}.get(status, str(status or "Unknown").replace("_", " ").title())
