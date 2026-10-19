import json
import subprocess
from pathlib import Path
from app.services.semgrep_service import SEMGREP_RULES_PATH


def test_open_values_respect_sql_quotes_and_parameter_names(tmp_path):
    prefix = "const pgp = require('pg-promise')(); const db = pgp(process.env.DB); function route(req,res) { "
    cases = {
        'open.js': 'db.one({text:"SELECT ${id}:value", values:{id:req.params.id}});',
        'double.js': r'db.one({text:"SELECT \"${id}:value\"", values:{id:req.params.id}});',
        'mixed.js': r'''db.one({text:"SELECT ${id}:value, '${safe}:value', \"${title}:value\"", values:{id:req.params.id,safe:req.params.safe,title:req.params.title}});''',
        'single-safe.js': 'db.one({text:"SELECT \'${id}:value\'", values:{id:req.params.id}});',
        'normal.js': 'db.one({text:"SELECT ${id}", values:{id:req.params.id}});',
        'other-key.js': 'db.one({text:"SELECT ${fixed}:value, ${id}", values:{fixed:1,id:req.params.id}});',
        'fixed.js': 'db.one({text:"SELECT ${id}:value", values:{id:1}});',
        'comment.js': 'db.one({text:"SELECT -- \' ${id}:value", values:{id:req.params.id}});',
        'escaped-quote.js': r'db.one({text:"SELECT \\x27${id}:value\\x27", values:{id:req.params.id}});',
        'spread.js': 'db.one({text:"SELECT ${id}:value", values:{id:req.params.id,...safe}});',
    }
    for name, source in cases.items():
        (tmp_path/name).write_text(prefix+source+' }',encoding='utf-8')
    (tmp_path/'unrelated.js').write_text(prefix.replace("require('pg-promise')", "require('unrelated')")+cases['open.js']+' }',encoding='utf-8')
    result = subprocess.run(['semgrep','--config',str(SEMGREP_RULES_PATH/'javascript/express/security/injection/pg-promise-raw-values.yaml'),'--json','--no-git-ignore',str(tmp_path)],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60)
    assert result.returncode == 0, result.stdout+result.stderr
    scan=json.loads(result.stdout)
    assert not scan['errors']
    matches=[r for r in scan['results'] if r['check_id'].endswith('pg-promise-request-open-value')]
    assert {Path(r['path']).name for r in matches} == {'open.js','double.js','mixed.js'}
    assert len(matches)==4
