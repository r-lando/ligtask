"""Controlled, case-level regression benchmark; never executes fixture code."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
from app.services.semgrep_service import run_semgrep, SEMGREP_RULES_PATH
from app.services.secret_service import scan_secrets

# Expected labels describe only the named issue, not the safety of the whole app.
# Negatives are deliberately paired with positives; do not infer deployed exploitability.
CASES = [
    ("sql-concat", "sql", True, "js", "function route(req,res) { db.query('SELECT * FROM users WHERE id=' + req.query.id); }", ["tainted-sql-string"]),
    ("sql-parameters", "sql", False, "js", "function route(req,res) { db.query('SELECT * FROM users WHERE id=?', [req.query.id]); }", ["tainted-sql-string"]),
    ("shell-direct", "command", True, "js", "const {exec} = require('child_process'); function route(req,res) { exec('ping ' + req.body.host); }", ["request-to-shell-exec"]),
    ("shell-argv", "command", False, "js", "const {execFile} = require('child_process'); function route(req,res) { execFile('ping', ['--', req.body.host]); }", ["request-to-shell-exec"]),
    ("shell-alias", "command", True, "js", "const run = require('child_process').exec; function route(req,res) { const host = req.query.host; run('ping ' + host); }", ["request-to-shell-exec"]),
    ("shell-fixed", "command", False, "js", "const {exec} = require('child_process'); function route(req,res) { exec('echo ready'); }", ["request-to-shell-exec"]),
    ("shell-helper", "command", True, "js", "const {exec} = require('child_process'); function ping(host) { exec('ping ' + host); } function route(req,res) { ping(req.body.host); }", ["request-to-shell-exec"]),
    ("html-dynamic", "xss", True, "js", "document.getElementById('out').innerHTML = location.hash.substring(1);", ["insecure-innerhtml", "insecure-document-method"]),
    ("html-text", "xss", False, "js", "document.getElementById('out').textContent = location.hash.substring(1);", ["insecure-innerhtml", "insecure-document-method"]),
    ("html-fixed", "xss", False, "js", "document.getElementById('out').innerHTML = 'Welcome';", ["insecure-innerhtml", "insecure-document-method"]),
    ("html-sanitized", "xss", False, "js", "import DOMPurify from 'dompurify'; document.getElementById('out').innerHTML = DOMPurify.sanitize(location.hash.substring(1));", ["insecure-innerhtml", "insecure-document-method"]),
    ("secret-literal", "secret", True, "js", "const password = 'benchmark-only-not-a-real-password';", ["generic-secret-assignment"]),
    ("secret-environment", "secret", False, "js", "const password = process.env.APP_PASSWORD;", ["generic-secret-assignment"]),
    ("secret-host-only", "secret", False, "js", "const database_url = 'postgresql://localhost/app';", ["database-connection-string"]),
]


def score(rows):
    counts = {key: sum(r["outcome"] == key for r in rows) for key in ("TP", "FP", "TN", "FN")}
    def ratio(n, d):
        return round(n / d, 4) if d else None
    return {**counts, "precision": ratio(counts["TP"], counts["TP"] + counts["FP"]),
            "recall": ratio(counts["TP"], counts["TP"] + counts["FN"])}


def evaluate():
    with tempfile.TemporaryDirectory(prefix="talged-benchmark-") as temp:
        folder = Path(temp)
        for name, _, _, extension, source, _ in CASES:
            (folder / f"{name}.{extension}").write_text(source + "\n", encoding="utf-8")
        sast = run_semgrep(folder)
        secrets = scan_secrets(folder)
        if not sast["success"] or secrets["scan_status"] != "completed":
            raise RuntimeError("Benchmark scanner failed; no clean result or accuracy score can be reported.")
        findings = sast["findings"] + secrets["findings"]
        rows = []
        for name, category, expected, extension, source, rules in CASES:
            observed = [f for f in findings if Path(f["file"]).name == f"{name}.{extension}"]
            matched = [f for f in observed if any(str(f["rule_id"]).endswith(rule) or (rule == "request-to-shell-exec" and str(f["rule_id"]).endswith("request-to-shell-exec-helper")) for rule in rules)]
            detected = bool(matched)
            rows.append({"case": name, "category": category, "expected_detection": expected,
                         "detected": detected, "outcome": ("TP" if detected else "FN") if expected else ("FP" if detected else "TN"),
                         "fixture_sha256": hashlib.sha256((source + "\n").encode()).hexdigest(),
                         "matched_rules": sorted({f["rule_id"] for f in matched}),
                         "other_rules": sorted({f["rule_id"] for f in observed if f not in matched})})
        digest = hashlib.sha256()
        for rule in sorted(SEMGREP_RULES_PATH.rglob("*.yaml")):
            digest.update(rule.relative_to(SEMGREP_RULES_PATH).as_posix().encode())
            digest.update(rule.read_bytes())
        return {"scope": "Controlled case-level SAST and secret regression, not real-world accuracy",
                "rules_sha256": digest.hexdigest(), "cases": rows, "summary": score(rows),
                "by_category": {category: score([r for r in rows if r["category"] == category]) for category in sorted({r["category"] for r in rows})},
                "dependency": "Not run. Use --dependencies for the separate live OSV evaluation.",
                "limitations": ["Authored examples are not an independent or representative sample.",
                                "Only named issue families are scored; additional rules are reported separately.",
                                "Multiple matches count as one detected case. Scanner failures invalidate the run.",
                                "No application code is executed and no deployed exploitability is proven."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dependencies", action="store_true", help="Also run existing live OSV evaluation; requires network and recorded ground truth.")
    args = parser.parse_args()
    try:
        result = evaluate()
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return 2
    dependency_exit = 0
    if args.dependencies:
        # Reuse the evaluator without calling its archival, no-overwrite main().
        spec = importlib.util.spec_from_file_location("dependency_evaluation", ROOT / "evaluation/dependency/run_formal_evaluation.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        rows = [module.evaluate_case(case) for case in module.load_ground_truth()]
        summary = module.build_summary(rows)
        invalid = any(row["scan_status"] != "completed" or row["request_errors"] for row in rows)
        dependency_exit = int(invalid or summary["case_counts"]["FN"] > 0 or summary["case_counts"]["REQUIRES_ADJUDICATION"] > 0 or summary["missing_unique_osv_ids"] > 0 or summary["unexpected_unique_osv_ids"] > 0)
        result["dependency"] = {"status": "invalid" if invalid else "needs_review" if dependency_exit else "matched_recorded_baseline",
                                "summary": summary, "cases": rows,
                                "note": "Live comparison with recorded 2026-09-04 OSV labels, not independent truth. New advisories require review, not automatic false-positive labels."}
    output = ROOT / "evaluation/results/mvp/accuracy-benchmark.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 1 if result["summary"]["FP"] or result["summary"]["FN"] or dependency_exit else 0


if __name__ == "__main__":
    raise SystemExit(main())
