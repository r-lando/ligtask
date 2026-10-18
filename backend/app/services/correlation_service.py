from copy import deepcopy


SEVERITY_RANK = {
    "UNKNOWN": 0,
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}


# Explicit equivalence groups.
#
# Findings are correlated only when:
# 1. Their rule IDs belong to the same group.
# 2. They refer to the same repository file.
#
# This avoids fuzzy or probabilistic matching.
CORRELATION_RULES = {
    "overlapping-eval-warnings": {
        "title": "Request Input Evaluated as JavaScript",
        "category": "SAST",
        "rule_ids": {
            "semgrep_rules.v1.javascript.lang.security.audit.code-string-concat",
            "semgrep_rules.v1.javascript.browser.security.eval-detected",
        },
        "message": "Two rules identify the same eval call, including request-derived input flowing to it. Replace dynamic evaluation with parsing and validation appropriate to the expected data. Both rule IDs are retained; this is code evidence, not proof of a successful deployed attack.",
    },
    "overlapping-sql-warnings": {
        "title": "Overlapping SQL Construction Warnings",
        "category": "SAST",
        "rule_ids": {
            "semgrep_rules.v1.javascript.express.security.injection.tainted-sql-string",
            "semgrep_rules.v1.javascript.sequelize.security.audit.sequelize-raw-query",
        },
        "message": "Two rules report overlapping SQL-construction code starting on this line. Review request input and use parameterized queries. Grouping preserves both rule IDs and does not prove exploitability or that all SQL issues in this file are the same issue.",
    },
    "browser-html-write": {
        "title": "HTML Content Written by JavaScript",
        "category": "SAST",
        "rule_ids": {
            "semgrep_rules.v1.javascript.browser.security.insecure-document-method",
            "semgrep_rules.v1.javascript.browser.security.insecure-innerhtml",
        },
        "message": "JavaScript writes HTML at this location. Check where the value comes from and whether it is safely escaped. This does not by itself prove a script-injection vulnerability.",
    },
    "docker-container-root": {
        "title": "Container May Run as Root",
        "category": "CONFIGURATION",

        "rule_ids": {
            (
                "dockerfile.security.missing-user."
                "missing-user"
            ),
            "docker-root-user",
        },

        "message": (
            "Multiple assessment mechanisms detected "
            "that the container may run without an "
            "explicit non-root user."
        ),
    },
}


def get_severity_rank(severity):
    """
    Return the numeric ranking of a severity label.
    """
    return SEVERITY_RANK.get(
        severity,
        SEVERITY_RANK["UNKNOWN"],
    )


def choose_highest_severity(findings):
    """
    Select the highest severity reported by
    correlated findings.

    No new severity score is calculated.
    """
    highest = "UNKNOWN"

    for finding in findings:
        severity = finding.get(
            "severity",
            "UNKNOWN",
        )

        if (
            get_severity_rank(severity)
            > get_severity_rank(highest)
        ):
            highest = severity

    return highest


def find_correlation_group(rule_id):
    """
    Return the explicit correlation group for
    a rule ID, if one exists.
    """
    if not rule_id:
        return None

    # Semgrep includes the config's repository-relative prefix when invoked
    # from the repository root rather than backend/. Keep evidence IDs intact.
    lookup_id = rule_id.removeprefix("backend.") if rule_id.startswith("backend.semgrep_rules.v1.") else rule_id

    for group_id, group in (
        CORRELATION_RULES.items()
    ):
        if lookup_id in group["rule_ids"]:
            return group_id

    return None


def create_correlation_key(finding):
    """
    Create a deterministic key for findings that
    are eligible for explicit correlation.
    """
    if finding.get("category") == "DEPENDENCY":
        fields = ("rule_id", "package", "version", "ecosystem", "file")
        if all(finding.get(field) for field in fields):
            return ("dependency-occurrence", *(finding[field] for field in fields))
        return None

    group_id = find_correlation_group(
        finding.get("rule_id")
    )

    if not group_id:
        return None

    file_path = finding.get("file")

    if not file_path:
        return None

    if group_id == "overlapping-eval-warnings":
        # Require the exact call range, not just a shared or adjacent line.
        start, end = finding.get("match_start"), finding.get("match_end")
        if not all(isinstance(p, (list, tuple)) and len(p) == 2
                   and all(type(v) is int and v > 0 for v in p) for p in (start, end)):
            return None
        if tuple(start) >= tuple(end) or start[0] != finding.get("line"):
            return None
        return (group_id, file_path.replace("\\", "/"), tuple(start), tuple(end))

    if group_id in {"browser-html-write", "overlapping-sql-warnings"}:
        # Only the known overlapping pair at the exact same location.
        # Do not combine separate writes or case-distinct repository files.
        line = finding.get("line")
        if line is None:
            return None
        return (group_id, file_path.replace("\\", "/"), line)

    return (
        group_id,
        file_path.lower(),
    )


def build_single_finding(finding):
    """
    Convert a non-correlated finding into the
    consolidated finding format.
    """
    consolidated = deepcopy(finding)

    scanner = finding.get("scanner")
    rule_id = finding.get("rule_id")

    consolidated["sources"] = (
        [scanner]
        if scanner
        else []
    )

    consolidated["source_rule_ids"] = (
        [rule_id]
        if rule_id
        else []
    )

    consolidated["correlated"] = False
    consolidated["evidence_count"] = 1

    return consolidated


def build_correlated_finding(
    group_id,
    findings,
):
    """
    Merge explicitly equivalent findings into
    one consolidated issue while preserving
    scanner evidence.
    """
    if group_id == "dependency-occurrence":
        # Keep advisory and package identity intact. Do not collapse versions,
        # ecosystems or lockfiles, and do not fabricate cross-scanner evidence.
        selected = max(findings, key=lambda f: get_severity_rank(f.get("severity")))
        merged = build_single_finding(selected)
        merged["correlated"] = True
        merged["evidence_count"] = sum(f.get("evidence_count", 1) for f in findings)
        merged["sources"] = list(dict.fromkeys(f["scanner"] for f in findings if f.get("scanner")))
        merged["source_rule_ids"] = [selected["rule_id"]]
        return merged

    rule = CORRELATION_RULES[
        group_id
    ]

    highest_severity = (
        choose_highest_severity(
            findings
        )
    )

    sources = []
    source_rule_ids = []

    for finding in findings:
        scanner = finding.get(
            "scanner"
        )

        rule_id = finding.get(
            "rule_id"
        )

        if (
            scanner
            and scanner not in sources
        ):
            sources.append(scanner)

        if (
            rule_id
            and rule_id
            not in source_rule_ids
        ):
            source_rule_ids.append(
                rule_id
            )

    # Use the first available line number as
    # supporting location information.
    line = next(
        (
            finding.get("line")
            for finding in findings
            if finding.get("line")
            is not None
        ),
        None,
    )

    # CVSS is preserved only if one of the
    # original findings actually supplied it.
    cvss_finding = next(
        (
            finding
            for finding in findings
            if finding.get(
                "cvss_score"
            )
            is not None
        ),
        None,
    )

    return {
        "scanner": "Multiple",
        "category": rule["category"],

        "rule_id": group_id,

        "title": rule["title"],

        "severity": highest_severity,

        "cvss_score": (
            cvss_finding.get(
                "cvss_score"
            )
            if cvss_finding
            else None
        ),

        "cvss_vector": (
            cvss_finding.get(
                "cvss_vector"
            )
            if cvss_finding
            else None
        ),

        "cvss_version": (
            cvss_finding.get(
                "cvss_version"
            )
            if cvss_finding
            else None
        ),

        "file": findings[0].get(
            "file"
        ),

        "line": line,

        "message": rule["message"],

        "package": None,
        "version": None,
        "ecosystem": None,

        "sources": sources,

        "source_rule_ids": (
            source_rule_ids
        ),

        "correlated": True,

        "evidence_count": len(
            findings
        ),
    }


def paired_ranges_overlap(findings):
    """Only one occurrence of each known rule, with valid overlapping ranges.

    Missing legacy locations and ambiguous multiple occurrences stay separate.
    """
    if len(findings) != 2 or len({f.get("rule_id") for f in findings}) != 2:
        return False
    spans = []
    for finding in findings:
        start, end = finding.get("match_start"), finding.get("match_end")
        if not all(isinstance(p, (list, tuple)) and len(p) == 2
                   and all(type(v) is int and v > 0 for v in p) for p in (start, end)):
            return False
        start, end = tuple(start), tuple(end)
        if start >= end or start[0] != finding.get("line"):
            return False
        spans.append((start, end))
    return max(s[0] for s in spans) < min(s[1] for s in spans)


def correlate_findings(findings):
    """
    Correlate explicitly equivalent findings.

    Raw findings are not modified or deleted.
    A separate consolidated finding list is
    produced.
    """
    grouped_findings = {}
    ungrouped_findings = []

    for finding in findings:
        correlation_key = (
            create_correlation_key(
                finding
            )
        )

        if correlation_key is None:
            ungrouped_findings.append(
                finding
            )
            continue

        grouped_findings.setdefault(
            correlation_key,
            [],
        ).append(finding)

    consolidated_findings = []

    # Keep findings that do not participate in
    # an explicit equivalence rule.
    for finding in ungrouped_findings:
        consolidated_findings.append(
            build_single_finding(
                finding
            )
        )

    correlated_groups = 0
    duplicate_findings_removed = 0

    # Process findings that belong to known
    # equivalence groups.
    for (
        correlation_key,
        group_findings,
    ) in grouped_findings.items():

        group_id = correlation_key[0]

        if group_id in {"overlapping-sql-warnings", "overlapping-eval-warnings"} and not paired_ranges_overlap(group_findings):
            consolidated_findings.extend(build_single_finding(f) for f in group_findings)
            continue

        if len(group_findings) == 1:
            consolidated_findings.append(
                build_single_finding(
                    group_findings[0]
                )
            )
            continue

        consolidated_findings.append(
            build_correlated_finding(
                group_id,
                group_findings,
            )
        )

        correlated_groups += 1

        duplicate_findings_removed += (
            len(group_findings) - 1
        )

    return {
        "raw_findings_count": len(
            findings
        ),

        "consolidated_findings_count": len(
            consolidated_findings
        ),

        "correlated_groups": (
            correlated_groups
        ),

        "duplicate_findings_removed": (
            duplicate_findings_removed
        ),

        "findings": (
            consolidated_findings
        ),
    }
