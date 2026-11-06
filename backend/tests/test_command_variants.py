import json
import subprocess
from pathlib import Path

from app.services.semgrep_service import SEMGREP_RULES_PATH


def test_command_variants_and_safe_controls(tmp_path):
    prefix = "const cp = require('child_process'); const util = require('util'); "
    cases = {
        "exec-file": (True, "function route(req) { cp.execFile(req.body.program); }"),
        "exec-file-sync": (True, "function route(req) { cp.execFileSync(req.query.program); }"),
        "fork": (True, "function route(req) { cp.fork(req.params.module); }"),
        "parsed-url": (True, "const url=require('url'); function route(req) { const cmd=url.parse(req.url,true).query.path; cp.execFile(cmd); }"),
        "promise": (True, "function route(req) { util.promisify(cp.exec)(req.body.command); }"),
        "windows-array": (True, "function route(req) { cp.spawn('cmd.exe', ['/C', 'echo'].concat(['hi', req.query.value])); }"),
        "windows-scalar": (True, "function route(req) { cp.spawn('cmd.exe', ['/c', 'echo'].concat(req.query.value)); }"),
        "fixed-program": (False, "function route(req) { cp.execFile('node', ['fixed.js', req.body.value]); }"),
        "fixed-fork": (False, "function route(req) { cp.fork('worker.js', [req.body.value]); }"),
        "fixed-promise": (False, "function route(req) { util.promisify(cp.exec)('echo ready'); }"),
        "promise-argv": (False, "function route(req) { util.promisify(cp.execFile)('node', ['fixed.js', req.body.value]); }"),
        "non-shell-tail": (False, "function route(req) { cp.spawn('node', ['fixed.js', '--'].concat(req.body.value)); }"),
        "windows-fixed": (False, "function route(req) { cp.spawn('cmd.exe', ['/C', 'echo'].concat(['ready'])); }"),
        "windows-wrong-flag": (False, "function route(req) { cp.spawn('cmd.exe', ['/Q', 'echo'].concat(req.body.value)); }"),
        "overwritten": (False, "function route(req) { let program=req.query.program; program='node'; cp.execFile(program); }"),
        "shadow-cp": (False, "function route(req, cp) { cp.execFile(req.body.program); }"),
        "shadow-util": (False, "function route(req, util) { util.promisify(cp.exec)(req.body.command); }"),
        "local-cp": (False, "function route(req) { const cp={execFile: x=>x}; cp.execFile(req.body.program); }"),
        "local-util": (False, "function route(req) { const util={promisify:x=>x}; util.promisify(cp.exec)(req.body.command); }"),
    }
    for name, (_, code) in cases.items():
        (tmp_path / f"{name}.js").write_text(prefix + code, encoding="utf-8")
    (tmp_path / "unrelated.js").write_text("const cp=require('other'); function route(req) { cp.execFile(req.body.program); }", encoding="utf-8")
    result = subprocess.run(["semgrep", "--config", str(SEMGREP_RULES_PATH / "javascript/express/security/injection/request-command-variants.yaml"),
                             "--json", "--no-git-ignore", str(tmp_path)], capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    output = json.loads(result.stdout)
    assert output.get("errors") == []
    assert {Path(f["path"]).stem for f in output["results"]} == {name for name, (expected, _) in cases.items() if expected}
