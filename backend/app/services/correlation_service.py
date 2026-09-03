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

    for group_id, group in (
        CORRELATION_RULES.items()
    ):
        if rule_id in group["rule_ids"]:
            return group_id

    return None


def create_correlation_key(finding):
    """
    Create a deterministic key for findings that
    are eligible for explicit correlation.
    """
    group_id = find_correlation_group(
        finding.get("rule_id")
    )

    if not group_id:
        return None

    file_path = finding.get("file")

    if not file_path:
        return None

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