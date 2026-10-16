from app.services.correlation_service import correlate_findings
from app.services.enrichment_service import enrich_finding


PREFIX = "semgrep_rules.v1.javascript.browser.security."


def finding(rule, line=10, file="app.js"):
    return dict(scanner="Semgrep", category="SAST", rule_id=PREFIX + rule,
                title=rule, severity="HIGH", file=file, line=line)


def test_overlapping_html_rules_merge_only_at_exact_location():
    originals = [finding("insecure-innerhtml"), finding("insecure-document-method"),
                 finding("insecure-innerhtml", 11), finding("insecure-innerhtml", file="App.js")]
    result = correlate_findings(originals)
    assert result["raw_findings_count"] == 4
    assert result["consolidated_findings_count"] == 3
    merged = next(f for f in result["findings"] if f["correlated"])
    assert merged["evidence_count"] == 2
    assert set(merged["source_rule_ids"]) == {PREFIX + "insecure-innerhtml", PREFIX + "insecure-document-method"}
    assert merged["severity"] == "HIGH"
    assert "sources" not in originals[0]


def test_missing_location_and_unrelated_rules_not_merged():
    result = correlate_findings([finding("insecure-innerhtml", None),
                                 finding("insecure-document-method", None), finding("other")])
    assert result["consolidated_findings_count"] == 3


def test_html_guidance_is_evidence_based_not_exploit_claim():
    enriched = enrich_finding(finding("insecure-innerhtml"))
    assert "does not prove" in enriched["description"]
    assert "textContent" in enriched["recommendation"]
    assert "Multiple rules" not in enriched["description"]


def test_generic_key_guidance_does_not_claim_confirmed_credential():
    enriched = enrich_finding(dict(category="SECRET", rule_id="generic-secret-assignment"))
    assert "not confirmed" in enriched["description"]
    assert "API restrictions" in enriched["recommendation"]
    assert "automatically safe" in enriched["recommendation"]
