import json
import subprocess
from app.services.semgrep_service import SEMGREP_RULES_PATH


def test_direct_sanitizer_does_not_hide_raw_or_modified_html(tmp_path):
    cases = {
        "clean.js": "import DOMPurify from 'dompurify'; el.innerHTML = DOMPurify.sanitize(input);",
        "alias.js": "import purify from 'dompurify'; el.outerHTML = purify.sanitize(input);",
        "raw.js": "import DOMPurify from 'dompurify'; el.innerHTML = input;",
        "mixed.js": "import DOMPurify from 'dompurify'; el.innerHTML = DOMPurify.sanitize(input) + other;",
        "fake.js": "const DOMPurify = {sanitize: x => x}; el.innerHTML = DOMPurify.sanitize(input);",
        "options.js": "import DOMPurify from 'dompurify'; el.innerHTML = DOMPurify.sanitize(input, options);",
        "config.js": "import DOMPurify from 'dompurify'; DOMPurify.setConfig(options); el.innerHTML = DOMPurify.sanitize(input);",
        "hook.js": "import DOMPurify from 'dompurify'; DOMPurify.addHook('uponSanitizeAttribute', handler); el.innerHTML = DOMPurify.sanitize(input);",
        "neighbor.js": "import DOMPurify from 'dompurify'; el.innerHTML = input; other.innerHTML = DOMPurify.sanitize(input);",
        "shadow.js": "import DOMPurify from 'dompurify'; function render(DOMPurify, input) { el.innerHTML = DOMPurify.sanitize(input); }",
        "arrow-shadow.js": "import DOMPurify from 'dompurify'; const render = (DOMPurify, input) => { el.innerHTML = DOMPurify.sanitize(input); };",
        "replaced.js": "import DOMPurify from 'dompurify'; DOMPurify.sanitize = x => x; el.innerHTML = DOMPurify.sanitize(input);",
        "local-const.js": "import DOMPurify from 'dompurify'; function render(input) { const DOMPurify = {sanitize: x => x}; el.innerHTML = DOMPurify.sanitize(input); }",
        "local-let.js": "import purify from 'dompurify'; function render(input) { let purify = {sanitize: x => x}; el.outerHTML = purify.sanitize(input); }",
        "local-var.js": "import DOMPurify from 'dompurify'; function render(input) { var DOMPurify = {sanitize: x => x}; document.write(DOMPurify.sanitize(input)); }",
        "nested-block.js": "import DOMPurify from 'dompurify'; function render(input) { { const DOMPurify = {sanitize: x => x}; el.innerHTML = DOMPurify.sanitize(input); } }",
    }
    for name, source in cases.items():
        (tmp_path / name).write_text(source, encoding="utf-8")
    args = ["semgrep", "--json", "--no-git-ignore"]
    for rule in ("insecure-innerhtml", "insecure-document-method"):
        args += ["--config", str(SEMGREP_RULES_PATH / f"javascript/browser/security/{rule}.yaml")]
    run = subprocess.run(args + [str(tmp_path)], capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert run.returncode == 0, run.stdout + run.stderr
    results = json.loads(run.stdout)["results"]
    assert {path_name(f["path"]) for f in results} == set(cases) - {"clean.js", "alias.js"}
    assert sum(path_name(f["path"]) == "neighbor.js" for f in results) == 2
    assert sum(path_name(f["path"]) == "local-const.js" for f in results) == 2
    assert sum(path_name(f["path"]) == "nested-block.js" for f in results) == 2


def path_name(value):
    return value.replace("\\", "/").rsplit("/", 1)[-1]
