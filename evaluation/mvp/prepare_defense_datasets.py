"""Package three pinned, labeled source-only demonstration sets. Never execute fixtures."""
import csv
import hashlib
import io
import json
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path
from urllib.request import urlopen

from run_external_validation import BASE, REVISION, ROOT, HASHES, DIRECTORY, labels

SQL = "javascript/ql/test/query-tests/Security/CWE-089/untyped/"
OUTPUT = ROOT / "tmp/defense-datasets-2026-11-06"
PINNED = {
    SQL + "mysql.js": "7dc8ee39ceeab816c1f398bd0f882935dfe572c8c832fc0343cb9322e131f1cc",
    SQL + "koarouter.js": "2698db29e61b26a1f1ed7c31bfb18e298c27ac65e31f2ccdd64d79c141ee70b8",
    SQL + "SqlInjection.expected": "e895462221c1c2e2891bdc004a8868d1b24dea2a9b2cb8321e7d6c823c6edfc2",
    **{DIRECTORY + "/" + name: digest for name, digest in HASHES.items()},
}
SAFE = b"""// Authored SQL-specific negative control; not an upstream CodeQL label.
const Router = require('koa-router');
const {Sequelize} = require('sequelize');
new Router().get('/demo', (ctx) => {
  const db = new Sequelize();
  db.query('SELECT * FROM t WHERE version = $version', {bind: {version: ctx.query.version}});
});
"""


def main():
    payloads = {}
    for path in [*PINNED, "LICENSE"]:
        with urlopen(BASE + path, timeout=30) as response:
            data = response.read(2_000_001)
        if len(data) > 2_000_000 or (path in PINNED and hashlib.sha256(data).hexdigest() != PINNED[path]):
            raise ValueError("Unverified upstream input: " + path)
        payloads[path] = data
    if "MIT License" not in payloads["LICENSE"].decode():
        raise ValueError("Review upstream license before packaging")
    sql_expected = payloads[SQL + "SqlInjection.expected"].decode()
    for filename, wanted in [("mysql.js", {15, 19}), ("koarouter.js", {17})]:
        annotated = {n for n, line in enumerate(payloads[SQL + filename].decode().splitlines(), 1)
                     if re.search(r"// \$ Alert(?:\s|$)", line)}
        selection = sql_expected.split("#select\n", 1)[1].split("\nnodes\n", 1)[0]
        diagnostic = {int(m.group(1)) for line in selection.splitlines()
                      if "This query string depends on" in line
                      if (m := re.match(r"^\| " + re.escape(filename) + r":(\d+):", line))}
        if annotated != wanted or diagnostic != wanted:
            raise ValueError(f"SQL annotation/diagnostic disagreement: {filename}: annotations={annotated}, diagnostics={diagnostic}")
    command_source = payloads[DIRECTORY + "/child_process-test.js"]
    positive_commands = labels(command_source.decode(), payloads[DIRECTORY + "/CommandInjection.expected"].decode())
    sets = [
        ("01-mysql-sql-injection", {"mysql.js": payloads[SQL + "mysql.js"]},
         [("mysql.js", n, n, True) for n in (15, 19)] + [("mysql.js", 8, 11, False)], "sql"),
        ("02-koa-sequelize-sql-injection", {"koarouter.js": payloads[SQL + "koarouter.js"], "koa-safe-control.js": SAFE},
         [("koarouter.js", 17, 17, True), ("koa-safe-control.js", 6, 6, False)], "sql|koa-request-sequelize-query"),
        ("03-node-command-injection", {"child_process-test.js": command_source},
         [("child_process-test.js", n, n, n in positive_commands) for n in sorted(positive_commands | set(range(8, 15)))],
         "command|shell|child-process|child_process"),
    ]
    rules = ROOT / "backend/semgrep_rules/v1"
    digest = hashlib.sha256()
    for path in sorted(rules.rglob("*.yaml")):
        digest.update(path.relative_to(rules).as_posix().encode())
        digest.update(path.read_bytes().replace(b"\r\n", b"\n"))
    version = subprocess.run(["semgrep", "--version"], capture_output=True, text=True, check=True, timeout=30).stdout.strip()
    head = subprocess.run(["git", "-c", "safe.directory=" + ROOT.as_posix(), "rev-parse", "HEAD"], cwd=ROOT,
                          capture_output=True, text=True, check=True).stdout.strip()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    summaries = []
    for name, sources, cases, family in sets:
        with tempfile.TemporaryDirectory(prefix="talged-defense-") as temp:
            for filename, data in sources.items():
                (Path(temp) / filename).write_bytes(data)
            result = subprocess.run(["semgrep", "--config", str(rules), "--json", "--no-git-ignore", temp],
                                    capture_output=True, text=True, encoding="utf-8", check=True, timeout=180)
            scan = json.loads(result.stdout)
            scanned = {Path(p).name for p in scan.get("paths", {}).get("scanned", [])}
            if scan.get("errors") or not set(sources).issubset(scanned):
                raise ValueError("Incomplete scan; no verified score: " + name)
        findings = scan["results"]
        rows = []
        scored = set()
        for filename, start, end, positive in cases:
            matches = [i for i, finding in enumerate(findings)
                       if Path(finding["path"]).name == filename and start <= finding["start"]["line"] <= end
                       and re.search(family, finding["check_id"], re.I)]
            scored.update(matches)
            rows.append({"file": filename, "start_line": start, "end_line": end,
                         "expected_warning": positive,
                         "label_origin": "upstream annotation + expected diagnostic" if positive else
                                         ("authored SQL-specific safe control" if filename == "koa-safe-control.js" else "manually reviewed issue-specific safe control"),
                         "outcome": ("TP" if matches else "FN") if positive else ("FP" if matches else "TN"),
                         "matched_rules": sorted({findings[i]["check_id"] for i in matches})})
        archive = OUTPUT / (name + ".zip")
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as package:
            for filename, data in {**sources, "LICENSE": payloads["LICENSE"]}.items():
                package.writestr(filename, data)
        report = {"dataset": name, "upstream_revision": REVISION, "talged_commit": head,
                  "semgrep_version": version, "normalized_rules_sha256": digest.hexdigest(),
                  "scored_rule_family_regex": family,
                  "zip_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                  "source_sha256": {filename: hashlib.sha256(data).hexdigest() for filename, data in sources.items()},
                  "cases": rows, "counts": {key: sum(row["outcome"] == key for row in rows) for key in ("TP", "FN", "FP", "TN")},
                  "unscored_findings": [{"file": Path(f["path"]).name, "line": f["start"]["line"], "rule": f["check_id"]}
                                        for i, f in enumerate(findings) if i not in scored],
                  "scope": "Source-only development regression examples; not independent overall accuracy or runtime exploit confirmation."}
        (OUTPUT / (name + "-verification.json")).write_text(json.dumps(report, indent=2), encoding="utf-8")
        buffer = io.StringIO(newline="")
        writer = csv.DictWriter(buffer, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
        (OUTPUT / (name + "-answer-key.csv")).write_text(buffer.getvalue(), encoding="utf-8")
        summaries.append({"dataset": name, **report["counts"], "unscored_warnings": len(report["unscored_findings"])})
    for path, data in payloads.items():
        if path.endswith(".expected"):
            (OUTPUT / Path(path).name).write_bytes(data)
    (OUTPUT / "provenance.json").write_text(json.dumps({"base_url": BASE, "sha256": {
        path: hashlib.sha256(data).hexdigest() for path, data in payloads.items()}}, indent=2), encoding="utf-8")
    (OUTPUT / "README.md").write_text("""# TALGED defense demonstration sets

These are three small test sets from ONE source: GitHub CodeQL, MIT licensed,
at immutable revision """ + REVISION + """. Original positive source files are unchanged.
Provenance URLs and SHA256 hashes are recorded in provenance.json. Upstream
positive annotations were cross-checked against the included expected diagnostics.
Negative controls are manually reviewed or authored: they are NOT upstream labels
certifying an entire application safe. The Koa control is explicitly authored.

Upload each numbered ZIP separately to TALGED. Do not run the JavaScript.
Compare file and line with the corresponding answer-key CSV and verification JSON.
TP = expected issue warned; FN = expected issue missed; FP = safe control warned;
TN = safe control unflagged. Multiple rules at one labeled call count once.
Other warnings remain separately recorded, not silently counted as false positives.
The JSON records this fresh direct full-ruleset Semgrep check, not a new browser
upload or PDF verification. A running backend with different rules may differ.

MySQL demonstrates unsafe SQL construction versus a separate-values query.
Koa demonstrates request input reaching Sequelize versus a bound-value query.
Node command injection includes its missed case at line 39; disclose it.

These examples have already been used in development. They demonstrate selected
behaviors, NOT blind validation, representative precision/recall, or an overall
accuracy percentage. All three come from one corpus, not three independent datasets.
Static warnings indicate code patterns; they do not prove successful exploitation.
No dependencies are installed and no fixture code is executed. These ZIPs have no
lockfile; dependency checking is outside their scope. Use new held-out labeled
cases for a defensible generalization study.

Fresh case counts:
""" + json.dumps(summaries, indent=2) + "\n", encoding="utf-8")
    bundle = OUTPUT.parent / "talged-defense-three-verified-test-sets.zip"
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as package:
        for path in sorted(OUTPUT.iterdir()):
            package.write(path, path.name)
    print(json.dumps({"output": str(OUTPUT), "bundle": str(bundle), "results": summaries}, indent=2))


if __name__ == "__main__":
    main()
