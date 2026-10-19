import json
import subprocess
from pathlib import Path
from app.services.semgrep_service import SEMGREP_RULES_PATH


def test_raw_pg_values_and_safe_controls(tmp_path):
    prefix = "const pgp = require('pg-promise')(); const db = pgp(process.env.DB); function route(req,res) { "
    cases = {
        'raw.js': "db.one({text:'SELECT $1:raw', values:req.params.id});",
        'caret.js': "db.any({text:'SELECT $1^', values:req.body.id});",
        'first.js': "db.one({text:'SELECT $1:raw, $2', values:[req.query.id, req.query.name]});",
        'second.js': "db.one({text:'SELECT $1, $2:raw', values:['fixed', req.query.name]});",
        'alias.js': "const value=req.body.id; db.query({text:'SELECT $1:raw', values:value});",
        'normal.js': "db.one({text:'SELECT $1', values:req.params.id});",
        'wrong-index.js': "db.one({text:'SELECT $2:raw', values:[req.params.id, 'fixed']});",
        'wrong-index-two.js': "db.one({text:'SELECT $1:raw, $2', values:['fixed', req.params.id]});",
        'fixed.js': "db.one({text:'SELECT $1:raw', values:'CURRENT_DATE'});",
        'named.js': "db.one({text:'SELECT ${fixed}:raw, ${id}', values:{fixed:'CURRENT_DATE',id:req.params.id}});",
        'ten.js': "db.one({text:'SELECT $10:raw', values:req.params.id});",
        'ordinary-call.js': "db.one('SELECT $1', req.params.id);",
        'array-alias.js': "const values=['fixed',req.params.id]; db.one({text:'SELECT $1:raw, $2',values:values});",
        'named-raw.js': "db.one({text:'SELECT ${id}:raw, ${name}', values:{id:req.params.id,name:req.params.name}});",
        'named-caret.js': "db.one({text:'SELECT ${choice}^', values:{choice:req.body.choice}});",
        'named-fixed.js': "db.one({text:'SELECT ${id}:raw, ${name}', values:{id:'CURRENT_DATE',name:req.params.name}});",
        'named-prefix.js': "db.one({text:'SELECT ${identifier}:raw, ${id}', values:{identifier:'CURRENT_DATE',id:req.params.id}});",
        'named-spread.js': "db.one({text:'SELECT ${id}:raw', values:{id:req.params.id,...safeValues}});",
        'named-comment.js': "db.one({/* text: 'SELECT ${id}:raw', values: { */ text:'SELECT ${id}', values:{id:req.params.id}});",
    }
    for name, source in cases.items():
        (tmp_path / name).write_text(prefix + source + ' }', encoding='utf-8')
    (tmp_path / 'unrelated.js').write_text(prefix.replace("require('pg-promise')", "require('other-library')") + cases['raw.js'] + ' }', encoding='utf-8')
    (tmp_path / 'shadow.js').write_text(prefix.replace('function route(req,res)', 'function route(req,res,db)') + cases['raw.js'] + ' }', encoding='utf-8')
    result = subprocess.run(['semgrep', '--config', str(SEMGREP_RULES_PATH / 'javascript/express/security/injection/pg-promise-raw-values.yaml'), '--json', '--no-git-ignore', str(tmp_path)], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    scan = json.loads(result.stdout)
    assert not scan['errors']
    assert {Path(f['path']).name for f in scan['results']} == {'raw.js','caret.js','first.js','second.js','named-raw.js','named-caret.js'}
    assert len(scan['results']) == 6
