"""Path-based context hints, not exploitability or deployment judgments."""

CONTEXTS = ("Application / other", "Test / fixture", "Scanner rule")


def file_context(path):
    parts = str(path or "").replace("\\", "/").lower().split("/")
    if "semgrep_rules" in parts:
        return "Scanner rule"
    if any(part in {"evaluation", "tests", "test", "fixtures", "__tests__"}
           for part in parts) or any(
        part.startswith("test_") or part.endswith((".test.ts", ".spec.ts", ".test.js", ".spec.js"))
        for part in parts
    ):
        return "Test / fixture"
    return "Application / other"


def context_summary(findings):
    counts = dict.fromkeys(CONTEXTS, 0)
    for finding in findings:
        counts[file_context(finding.get("file"))] += 1
    return counts


def context_note(findings):
    totals = "; ".join(f"{label}: {count}" for label, count in context_summary(findings).items())
    return f"File context - {totals}. Path-based hints only; all findings remain included and require review."
