import json
from pathlib import Path
import subprocess
from app.services.semgrep_service import SEMGREP_RULES_PATH


def test_execa_request_patterns_and_safe_controls(tmp_path):
    cases = {
        "shell": (True, "const run=require('execa'); function route(req){run.shell(req.query.command);}"),
        "shell-sync": (True, "const run=require('execa'); function route(req){run.shellSync(req.body.command);}"),
        "inline-shell": (True, "function route(req){require('execa').shell(req.query.command);}"),
        "program": (True, "const run=require('execa'); function route(req){run(req.body.program);}"),
        "inline-program": (True, "function route(req){require('execa')(req.body.program);}"),
        "sync": (True, "var run=require('execa'); function route(req){run.sync(req.query.program);}"),
        "node": (True, "const run=require('execa'); function route(req){run.node(req.query.script);}"),
        "stdout": (True, "function route(req){require('execa').stdout(req.query.program);}"),
        "stderr": (True, "function route(req){require('execa').stderr(req.query.program);}"),
        "esm": (True, "import {execa as run} from 'execa'; function route(req){run(req.body.program);}"),
        "esm-default": (True, "import run from 'execa'; function route(req){run.shell(req.query.command);}"),
        "whole-body": (True, "const run=require('execa'); function route(req){run.shell(req.body);}"),
        "url": (True, "const run=require('execa'); const url=require('url'); function route(req){const cmd=url.parse(req.url,true).query.path;run.shell(cmd);}"),
        "fixed-shell": (False, "const run=require('execa'); function route(req){run.shell('echo fixed');}"),
        "fixed-program-argv": (False, "const run=require('execa'); function route(req){run('node',['fixed.js',req.body.value]);}"),
        "fixed-node": (False, "const run=require('execa'); function route(req){run.node('fixed.js',[req.body.value]);}"),
        "fixed-sync": (False, "const run=require('execa'); function route(req){run.sync('node',['fixed.js',req.body.value]);}"),
        "esm-argv": (False, "import {execa} from 'execa'; function route(req){execa('node',['fixed.js',req.body.value]);}"),
        "tagged-argv": (False, "import {execa} from 'execa'; function route(req){execa`echo ${req.body.value}`;}"),
        "options-only": (False, "const run=require('execa'); function route(req){run.shell('echo fixed',{input:req.body.value});}"),
        "wrong-module": (False, "const run=require('other'); function route(req){run.shell(req.body.command);}"),
        "wrong-api": (False, "const run=require('execa'); function route(req){run.log(req.body.command);}"),
        "parameter-shadow": (False, "const run=require('execa'); function route(req,run){run.shell(req.body.command);}"),
        "arrow-shadow": (False, "const run=require('execa'); const route=(req,run)=>{run(req.body.command);};"),
        "local-shadow": (False, "const run=require('execa'); function route(req){const run={shell:x=>x};run.shell(req.body.command);}"),
        "overwritten": (False, "const run=require('execa'); function route(req){let value=req.body.command;value='echo fixed';run.shell(value);}"),
    }
    for name, (_, source) in cases.items():
        (tmp_path / f"{name}.js").write_text(source, encoding="utf-8")
    rule = SEMGREP_RULES_PATH / "javascript/express/security/injection/execa-request.yaml"
    result = subprocess.run(["semgrep", "--config", str(rule), "--json", "--no-git-ignore", str(tmp_path)],
                            capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    output = json.loads(result.stdout)
    assert not output.get("errors")
    assert {Path(f["path"]).stem for f in output["results"]} == {name for name, (expected, _) in cases.items() if expected}
