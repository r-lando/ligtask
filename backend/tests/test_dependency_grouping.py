from copy import deepcopy

from app.services.correlation_service import correlate_findings


def dependency(**changes):
    finding = dict(scanner="OSV", category="DEPENDENCY", rule_id="GHSA-one",
                   package="minimist", version="1.2.0", ecosystem="npm",
                   file="package-lock.json", severity="HIGH", cvss_score=7.5)
    finding.update(changes)
    return finding


def test_repeated_dependency_identity_groups_with_count_and_advisory():
    findings = [dependency(), dependency(), dependency()]
    original = deepcopy(findings)
    result = correlate_findings(findings)
    assert result["raw_findings_count"] == 3
    assert result["consolidated_findings_count"] == 1
    assert result["duplicate_findings_removed"] == 2
    merged = result["findings"][0]
    assert merged["evidence_count"] == 3
    assert merged["rule_id"] == "GHSA-one"
    assert merged["package"] == "minimist"
    assert merged["version"] == "1.2.0"
    assert merged["sources"] == ["OSV"]
    assert merged["source_rule_ids"] == ["GHSA-one"]
    assert merged["cvss_score"] == 7.5
    assert findings == original


def test_dependency_boundaries_and_missing_identity_are_preserved():
    findings = [dependency(), dependency(version="0.0.8"), dependency(rule_id="GHSA-two"),
                dependency(file="frontend/package-lock.json"), dependency(ecosystem="other"),
                dependency(package="other"), dependency(version=None), dependency(version=None),
                dependency(file="Package-lock.json")]
    result = correlate_findings(findings)
    assert result["consolidated_findings_count"] == len(findings)
