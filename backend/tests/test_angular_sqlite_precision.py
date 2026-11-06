import json
import subprocess
from app.services.semgrep_service import SEMGREP_RULES_PATH


def test_angular_sqlite_query_and_controls(tmp_path):
    prefix = "var sqlite = require('sqlite3').verbose(); var db = new sqlite.Database(':memory:'); "
    cases = {
        "unsafe": prefix + "angular.module('app', []).controller('Find', function($routeParams) { db.get('SELECT * FROM Post WHERE id=' + $routeParams.id); });",
        "parameterized": prefix + "angular.module('app', []).controller('Find', function($routeParams) { db.get('SELECT * FROM Post WHERE id=?', [$routeParams.id]); });",
        "fixed": prefix + "angular.module('app', []).controller('Find', function($routeParams) { db.get('SELECT * FROM Post'); });",
        "shadow-db": prefix + "angular.module('app', []).controller('Find', function($routeParams, db) { db.get('SELECT ' + $routeParams.id); });",
        "shadow-input": prefix + "angular.module('app', []).controller('Find', function($routeParams) { function inner($routeParams) { db.get('SELECT ' + $routeParams.id); } });",
        "unrelated": "var sqlite = require('other'); var db = new sqlite.Database(); angular.module('app', []).controller('Find', function($routeParams) { db.get('SELECT ' + $routeParams.id); });",
        "other-input": prefix + "angular.module('app', []).controller('Find', function(settings) { db.get('SELECT ' + settings.id); });",
        "arrow-shadow": prefix + "angular.module('app', []).controller('Find', function($routeParams) { const inner = ($routeParams) => { db.get('SELECT ' + $routeParams.id); }; });",
    }
    for name, source in cases.items():
        (tmp_path / f"{name}.js").write_text(source, encoding="utf-8")
    result = subprocess.run(["semgrep", "--config", str(SEMGREP_RULES_PATH / "javascript/express/security/injection/angular-sqlite-query.yaml"),
                             "--json", "--no-git-ignore", str(tmp_path)], capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    output = json.loads(result.stdout)
    assert output.get("errors") == []
    assert [finding["path"].replace("\\", "/").rsplit("/", 1)[-1] for finding in output["results"]] == ["unsafe.js"]
