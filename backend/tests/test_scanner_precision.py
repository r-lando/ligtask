"""Execute the real rule engine to guard XML and subprocess audit behavior."""
import json
import subprocess

from app.services.semgrep_service import SEMGREP_RULES_PATH


def test_xml_escape_exclusion_does_not_hide_parser_import(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text("from xml.sax.saxutils import escape\nimport xml.etree.ElementTree\n", encoding="utf-8")
    result = subprocess.run([
        "semgrep", "--config", str(SEMGREP_RULES_PATH / "python/lang/security/use-defused-xml.yaml"),
        "--json", "--no-git-ignore", str(source),
    ], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    findings = json.loads(result.stdout)["results"]
    assert [finding["start"]["line"] for finding in findings] == [2]
