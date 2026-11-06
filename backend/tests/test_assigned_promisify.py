import json
from pathlib import Path
import subprocess

from app.services.semgrep_service import SEMGREP_RULES_PATH


def test_assigned_promisify_with_controls(tmp_path):
    prefix = "const cp=require('child_process'); const util=require('util'); "
    cases = {
        "direct": (True, "const run=util.promisify(cp.exec); function route(req) { run(req.body.command); }"),
        "in-route": (True, "function route(req) { const run=util.promisify(cp.exec); const command=req.query.command; run(command); }"),
        "whole-body": (True, "function route(req) { const run=util.promisify(cp.exec); const command=req.body; run(command); }"),
        "bound": (True, "const run=util.promisify(cp.exec.bind(cp)); function route(req) { run(req.params.command); }"),
        "fixed": (False, "const run=util.promisify(cp.exec); function route(req) { run('echo fixed'); }"),
        "unused": (False, "const run=util.promisify(cp.exec); function route(req) { const command=req.body; }"),
        "execfile": (False, "const run=util.promisify(cp.execFile); function route(req) { run('node', ['fixed.js', req.body.value]); }"),
        "bound-execfile": (False, "const run=util.promisify(cp.execFile.bind(cp)); function route(req) { run('node', ['fixed.js', req.body.value]); }"),
        "options-only": (False, "const run=util.promisify(cp.exec); function route(req) { run('echo fixed', {cwd:req.body.dir}); }"),
        "overwritten-data": (False, "const run=util.promisify(cp.exec); function route(req) { let command=req.body.command; command='echo fixed'; run(command); }"),
        "param-shadow": (False, "const run=util.promisify(cp.exec); function route(req, run) { run(req.body.command); }"),
        "arrow-shadow": (False, "const run=util.promisify(cp.exec); const route=(req,run)=>{run(req.body.command);};"),
        "local-shadow": (False, "const run=util.promisify(cp.exec); function route(req) { const run=x=>x; run(req.body.command); }"),
        "util-shadow": (False, "function route(req, util) { const run=util.promisify(cp.exec); run(req.body.command); }"),
        "cp-shadow": (False, "function route(req, cp) { const run=util.promisify(cp.exec); run(req.body.command); }"),
        "other-api": (False, "const run=util.promisify(cp.readFile); function route(req) { run(req.body.path); }"),
        "unrelated-function": (False, "const run=x=>x; function route(req) { run(req.body.command); }"),
    }
    for name, (_, code) in cases.items():
        (tmp_path / f"{name}.js").write_text(prefix + code, encoding="utf-8")
    for name, code in {
        "other-cp": "const cp=require('other'); const util=require('util'); const run=util.promisify(cp.exec); function route(req) {run(req.body.command);}",
        "other-util": "const cp=require('child_process'); const util=require('other'); const run=util.promisify(cp.exec); function route(req) {run(req.body.command);}",
    }.items():
        (tmp_path / f"{name}.js").write_text(code, encoding="utf-8")
    result = subprocess.run(["semgrep", "--config", str(SEMGREP_RULES_PATH / "javascript/express/security/injection/request-command-variants.yaml"),
                             "--json", "--no-git-ignore", str(tmp_path)], capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    output = json.loads(result.stdout)
    assert not output.get("errors")
    matches = [f for f in output["results"] if f["check_id"].endswith("request-to-assigned-promisified-shell-exec")]
    assert {Path(f["path"]).stem for f in matches} == {name for name, (expected, _) in cases.items() if expected}
