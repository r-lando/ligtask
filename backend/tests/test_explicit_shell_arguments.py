import json
import subprocess
from pathlib import Path
from app.services.semgrep_service import SEMGREP_RULES_PATH


def test_explicit_shell_commands_and_safe_controls(tmp_path):
    cases = {
        "shell.js": "const cp = require('child_process'); function route(req,res) { cp.spawn('/bin/sh', ['-c', req.body.command]); }",
        "bash.js": "const cp = require('child_process'); function route(req,res) { const command = req.query.command; cp.execFile('/bin/bash', ['-c', command]); }",
        "sync.js": "const cp = require('child_process'); function route(req,res) { cp.spawnSync('sh', ['-c', req.params.command]); }",
        "indexed.js": "const cp = require('child_process'); function route(req,res) { let args = []; args[0] = '-c'; args[1] = req.body.command; cp.execFile('/bin/bash', args); }",
        "var.js": "var cp = require('child_process'), url = require('url'); function route(req,res) { let args = []; args[0] = '-c'; args[1] = url.parse(req.url,true).query.command; cp.execFile('/bin/bash', args); }",
        "overwritten.js": "const cp = require('child_process'); function route(req,res) { let args = []; args[0] = '-c'; args[1] = req.body.command; args[0] = 'script.sh'; cp.execFile('/bin/bash', args); }",
        "indexed-fixed.js": "const cp = require('child_process'); function route(req,res) { let args = []; args[0] = '-c'; args[1] = 'echo ready'; cp.execFile('/bin/bash', args); }",
        "shadow.js": "const cp = require('child_process'); function route(req,res,cp) { cp.spawn('/bin/sh', ['-c', req.body.command]); }",
        "url.js": "const cp = require('child_process'), url = require('url'); function route(req,res) { const command = url.parse(req.url,true).query.command; cp.execFile('bash', ['-c', command]); }",
        "argv.js": "const cp = require('child_process'); function route(req,res) { cp.execFile('ping', ['--', req.body.host]); }",
        "fixed.js": "const cp = require('child_process'); function route(req,res) { cp.spawn('/bin/sh', ['-c', 'echo ready']); }",
        "script-argument.js": "const cp = require('child_process'); function route(req,res) { cp.spawn('/bin/sh', ['script.sh', req.body.value]); }",
        "unrelated.js": "const cp = require('local-tool'); function route(req,res) { cp.spawn('/bin/sh', ['-c', req.body.command]); }",
    }
    for name, source in cases.items():
        (tmp_path / name).write_text(source, encoding='utf-8')
    result = subprocess.run(['semgrep', '--config', str(SEMGREP_RULES_PATH / 'javascript/express/security/injection/request-to-shell-exec.yaml'), '--json', '--no-git-ignore', str(tmp_path)], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60)
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert not output['errors']
    matches = [r for r in output['results'] if r['check_id'].endswith('request-to-explicit-shell-arguments')]
    assert {Path(r['path']).name for r in matches} == {'shell.js', 'bash.js', 'sync.js', 'url.js', 'indexed.js', 'var.js'}
