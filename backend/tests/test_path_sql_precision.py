import json
import subprocess
from copy import deepcopy

from app.services.semgrep_service import SEMGREP_RULES_PATH
from app.services.correlation_service import correlate_findings
from app.services.semgrep_service import run_semgrep
from app.services.finding_normalizer import normalize_semgrep_findings


def test_request_paths_and_local_directory_names(tmp_path):
    cases = {
        "local.js": "const fs = require('fs'); const path = require('path'); fs.readdirSync(__dirname).forEach(function(file) { load(path.join(__dirname, file)); });",
        "query.js": "const path = require('path'); function route(req,res) { read(path.join('/uploads', req.query.file)); }",
        "body.js": "const path = require('path'); function route(req,res) { const file=req.body.file; read(path.resolve('/uploads', file)); }",
        "replace.js": "const path = require('path'); function route(req,res) { const file=req.params.file.replace('x','y'); read(path.join('/uploads', file)); }",
        "unrelated-check.js": "const path = require('path'); function route(req,res) { req.query.file.indexOf('ok'); read(path.join('/uploads', req.query.file)); }",
        "fixed.js": "const path = require('path'); function route(req,res) { read(path.join('/uploads', 'logo.png')); }",
    }
    for name, source in cases.items():
        (tmp_path / name).write_text(source, encoding="utf-8")
    rule = SEMGREP_RULES_PATH / "javascript/lang/security/audit/path-traversal/path-join-resolve-traversal.yaml"
    run = subprocess.run(["semgrep", "--config", str(rule), "--json", "--no-git-ignore", str(tmp_path)], capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert run.returncode == 0, run.stdout + run.stderr
    actual = {f["path"].replace("\\", "/").rsplit("/", 1)[-1] for f in json.loads(run.stdout)["results"]}
    assert actual == {"query.js", "body.js", "replace.js", "unrelated-check.js"}


SQL_RULES = ["semgrep_rules.v1.javascript.express.security.injection.tainted-sql-string",
             "semgrep_rules.v1.javascript.sequelize.security.audit.sequelize-raw-query"]


def pair():
    return [dict(scanner="Semgrep", category="SAST", rule_id=rule, file="routes.js", line=10,
                 match_start=[10, 10 if i == 0 else 1], match_end=[10, 60] if i == 0 else [12, 5],
                 severity="HIGH" if i == 0 else "MEDIUM") for i, rule in enumerate(SQL_RULES)]


def test_sql_overlap_preserves_originals_severity_and_rule_evidence():
    original = pair()
    before = deepcopy(original)
    result = correlate_findings(original)
    assert result["raw_findings_count"] == 2
    assert result["consolidated_findings_count"] == 1
    merged = result["findings"][0]
    assert merged["severity"] == "HIGH"
    assert merged["evidence_count"] == 2
    assert set(merged["source_rule_ids"]) == set(SQL_RULES)
    assert original == before


def test_sql_ambiguous_adjacent_and_nonoverlapping_locations_stay_separate():
    variants = []
    for field, value in [("file", "Routes.js"), ("file", "other.js"), ("line", 11),
                         ("match_start", None), ("match_start", [10, 65]),
                         ("rule_id", "unrelated-sql-rule")]:
        rows = pair()
        rows[1][field] = value
        variants.append(rows)
    rows = pair()
    rows.append(deepcopy(rows[0]))
    variants.append(rows)
    for rows in variants:
        assert correlate_findings(rows)["consolidated_findings_count"] == len(rows)


def test_real_sql_rules_supply_ranges_and_only_overlap_pair_is_grouped(tmp_path):
    (tmp_path / "app.js").write_text("""function route(req, res) {
  var query = "SELECT name FROM Users WHERE login='" + req.body.login + "'";
  db.sequelize.query(query, {model: db.User});
}
""", encoding="utf-8")
    raw = run_semgrep(tmp_path)
    assert raw["success"], raw.get("error")
    normalized = normalize_semgrep_findings(raw, tmp_path)
    sql = [f for f in normalized if any(f["rule_id"].endswith(suffix) for suffix in ("tainted-sql-string", "sequelize-raw-query", "express-sequelize-injection"))]
    assert len(sql) == 3
    result = correlate_findings(sql)
    assert result["consolidated_findings_count"] == 2
    merged = next(f for f in result["findings"] if f["correlated"])
    assert merged["rule_id"] == "overlapping-sql-warnings"
    assert merged["evidence_count"] == 2
    assert any(f["rule_id"].endswith("express-sequelize-injection") for f in result["findings"])
