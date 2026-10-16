import json
import subprocess

from app.services.semgrep_service import SEMGREP_RULES_PATH


def test_request_shell_exec_aliases_and_safe_arguments(tmp_path):
    cases = {
        "property.js": "const exec = require('child_process').exec; module.exports.ping = function(req, res) { exec('ping -c 2 ' + req.body.address, function() {}); };",
        "destructure.js": "const {exec: run} = require('child_process'); function handler(req, res) { run('ping ' + req.query.host); }",
        "import.js": "import {exec as run} from 'child_process'; function handler(req, res) { run('ping ' + req.params.host); }",
        "constant.js": "const exec = require('child_process').exec; function handler(req, res) { exec('echo ready'); }",
        "argv.js": "const {execFile} = require('child_process'); function handler(req, res) { execFile('ping', ['-c', '2', req.body.address]); }",
        "unrelated.js": "function exec(value) { return value; } function handler(req, res) { exec(req.body.value); }",
    }
    for filename, content in cases.items():
        (tmp_path / filename).write_text(content, encoding="utf-8")
    result = subprocess.run([
        "semgrep", "--config", str(SEMGREP_RULES_PATH / "javascript/express/security/injection/request-to-shell-exec.yaml"),
        "--json", "--no-git-ignore", str(tmp_path),
    ], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    findings = json.loads(result.stdout)["results"]
    assert {f["path"].replace("\\", "/").rsplit("/", 1)[-1] for f in findings} == {"property.js", "destructure.js", "import.js"}
    assert len(findings) == 3
