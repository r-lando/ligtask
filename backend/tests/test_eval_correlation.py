from copy import deepcopy

from app.services.correlation_service import correlate_findings
from app.services.semgrep_service import run_semgrep
from app.services.finding_normalizer import normalize_semgrep_findings

RULES = ["semgrep_rules.v1.javascript.lang.security.audit.code-string-concat",
         "semgrep_rules.v1.javascript.browser.security.eval-detected"]


def pair():
    return [dict(scanner="Semgrep", category="SAST", rule_id=rule, file="app.js", line=10,
                 match_start=[10, 12], match_end=[10, 35],
                 severity="HIGH" if i == 0 else "MEDIUM") for i, rule in enumerate(RULES)]


def test_eval_exact_pair_preserves_severity_evidence_and_raw_findings():
    rows = pair()
    before = deepcopy(rows)
    result = correlate_findings(rows)
    assert result["raw_findings_count"] == 2
    assert result["consolidated_findings_count"] == 1
    merged = result["findings"][0]
    assert merged["severity"] == "HIGH"
    assert merged["evidence_count"] == 2
    assert set(merged["source_rule_ids"]) == set(RULES)
    assert rows == before


def test_eval_missing_or_ambiguous_evidence_stays_separate():
    for field, value in [("file", "App.js"), ("file", "other.js"), ("line", 11),
                         ("match_start", None), ("match_start", [10, 13]),
                         ("match_end", [10, 36]), ("match_end", [10, 1]),
                         ("rule_id", "unrelated-eval-rule")]:
        rows = pair()
        rows[1][field] = value
        assert correlate_findings(rows)["consolidated_findings_count"] == 2
    rows = pair()
    rows.append(deepcopy(rows[0]))
    assert correlate_findings(rows)["consolidated_findings_count"] == 3


def test_real_eval_ranges_group_each_call_without_hiding_generic_warnings(tmp_path):
    (tmp_path / "app.js").write_text("""function handler(req, res, next) {
  const a = eval(req.body.a);
  const b = eval(req.body.b);
  const c = eval(req.body.c);
}
function sameLine(req, res) { eval(req.query.a); eval(req.query.b); }
function generic(value) { eval(value); }
function fixed() { eval('1 + 1'); }
""", encoding="utf-8")
    scan = run_semgrep(tmp_path)
    assert scan["success"], scan.get("error")
    normalized = normalize_semgrep_findings(scan, tmp_path)
    rows = [f for f in normalized if any(f["rule_id"].endswith(rule.rsplit('.', 1)[-1]) for rule in RULES)]
    assert len(rows) == 11
    before = deepcopy(rows)
    result = correlate_findings(rows)
    assert result["consolidated_findings_count"] == 6
    merged = [f for f in result["findings"] if f["correlated"]]
    assert len(merged) == 5
    assert all(f["severity"] == "HIGH" and f["evidence_count"] == 2 for f in merged)
    assert sum(f["line"] == 6 for f in merged) == 2
    generic = [f for f in result["findings"] if not f["correlated"]]
    assert len(generic) == 1 and generic[0]["line"] == 7
    assert rows == before
