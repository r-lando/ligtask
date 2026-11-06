import json
import subprocess
from app.services.semgrep_service import SEMGREP_RULES_PATH


def test_session_defaults_and_explicit_unsafe_settings(tmp_path):
    cases = {
        "defaults": "const session = require('express-session'); session({secret: process.env.SESSION_KEY});",
        "safe": "const session = require('express-session'); session({name:'sid', cookie:{secure:true,httpOnly:true}});",
        "false": "const session = require('express-session'); session({cookie:{secure:false,httpOnly:false}});",
        "cookie-safe": "const session = require('cookie-session'); session({name:'sid', secure:true,httpOnly:true});",
        "cookie-false": "const session = require('cookie-session'); session({secure:false,httpOnly:false});",
        "var-false": "const session = require('express-session'); const opts = {cookie:{secure:false,httpOnly:false}}; session(opts);",
        "cookie-var-false": "const session = require('cookie-session'); const opts = {secure:false,httpOnly:false}; session(opts);",
        "auto": "const session = require('express-session'); session({name:'sid', cookie:{secure:'auto'}});",
        "unrelated": "function session(x) {} session({cookie:{secure:false,httpOnly:false}});",
    }
    for name, source in cases.items():
        (tmp_path / f"{name}.js").write_text(source, encoding="utf-8")
    run = subprocess.run(["semgrep", "--config", str(SEMGREP_RULES_PATH / "javascript/express/security/audit/express-cookie-settings.yaml"), "--json", "--no-git-ignore", str(tmp_path)], capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert run.returncode == 0, run.stdout + run.stderr
    results = json.loads(run.stdout)["results"]
    rows = {name: [] for name in cases}
    for finding in results:
        name = finding["path"].replace("\\", "/").rsplit("/", 1)[-1][:-3]
        rows[name].append((finding["check_id"].rsplit(".", 1)[-1], finding["extra"]["severity"]))
    for name in ("safe", "cookie-safe", "auto", "unrelated"):
        assert rows[name] == []
    assert all(severity == "INFO" for _, severity in rows["defaults"])
    assert {rule for rule, _ in rows["defaults"]} == {"express-cookie-session-default-name", "express-session-secure-not-configured"}
    for name in ("false", "cookie-false", "var-false", "cookie-var-false"):
        assert ("express-session-httponly-disabled", "WARNING") in rows[name]
        assert ("express-session-secure-disabled", "WARNING") in rows[name]
