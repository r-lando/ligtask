import json
import subprocess
from pathlib import Path
from app.services.semgrep_service import SEMGREP_RULES_PATH


def test_koa_request_array_flow_and_safe_controls(tmp_path):
    prefix = "const Router = require('koa-router'); const {Sequelize} = require('sequelize'); "
    route = 'new Router().get("/test", (ctx) => { %s });'
    cases = {
        'push.js': "const {version}=ctx.query; const conditions=['1']; conditions.push(`version = ${version}`); new Sequelize().query(`SELECT * FROM t WHERE ${conditions.join(' and ')}`, null);",
        'direct.js': "new Sequelize().query('SELECT * FROM t WHERE id='+ctx.query.id);",
        'instance.js': "const db=new Sequelize(); db.query('SELECT * FROM t WHERE id='+ctx.query.id);",
        'checked.js': "const {version}=ctx.query; if (!/^[a-zA-Z0-9]+$/.test(version)) throw Error(); const conditions=['1']; conditions.push(`version = ${version}`); new Sequelize().query(`SELECT * FROM t WHERE ${conditions.join(' and ')}`);",
        'bound.js': "new Sequelize().query('SELECT * FROM t WHERE id=$id',{bind:{id:ctx.query.id}});",
        'replacements.js': "new Sequelize().query('SELECT * FROM t WHERE id=:id',{replacements:{id:ctx.query.id}});",
        'fixed.js': "const conditions=['1']; conditions.push('version = 1'); new Sequelize().query(`SELECT * FROM t WHERE ${conditions.join(' and ')}`);",
        'unused.js': "const {version}=ctx.query; const conditions=['1']; conditions.push(`version = ${version}`); new Sequelize().query('SELECT 1');",
        'reset.js': "let conditions=[]; conditions.push(ctx.query.id); conditions=[]; conditions.push('1'); new Sequelize().query(`SELECT ${conditions.join(' and ')}`);",
        'ctx-shadow.js': "function inner(ctx) { new Sequelize().query('SELECT '+ctx.query.id); }",
        'ctx-arrow-shadow.js': "const inner=(ctx)=>{new Sequelize().query('SELECT '+ctx.query.id);};",
        'shadow.js': "function helper(Sequelize) { new Sequelize().query('SELECT '+ctx.query.id); }",
    }
    for name,source in cases.items():
        (tmp_path/name).write_text(prefix+route % source,encoding='utf-8')
    (tmp_path/'other-router.js').write_text(prefix.replace("require('koa-router')","require('other-router')")+route % cases['push.js'],encoding='utf-8')
    (tmp_path/'other-db.js').write_text(prefix.replace("require('sequelize')","require('other-db')")+route % cases['push.js'],encoding='utf-8')
    result=subprocess.run(['semgrep','--config',str(SEMGREP_RULES_PATH/'javascript/express/security/injection/koa-sequelize-sql.yaml'),'--json','--no-git-ignore',str(tmp_path)],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60)
    assert result.returncode==0,result.stdout+result.stderr
    scan=json.loads(result.stdout)
    assert not scan['errors']
    assert {Path(r['path']).name for r in scan['results']} == {'push.js','direct.js','instance.js','checked.js'}
    assert len(scan['results'])==4
