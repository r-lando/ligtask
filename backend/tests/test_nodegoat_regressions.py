from app.services.dependency_service import query_osv_batch
from app.services.secret_service import scan_line
from app.services.semgrep_service import has_django_evidence


def test_large_osv_query_is_batched_in_order():
    sizes = []

    class Response:
        def __init__(self, queries):
            self.queries = queries
        def raise_for_status(self):
            pass
        def json(self):
            return {"results": [{"marker": q["package"]["name"]} for q in self.queries]}

    class Client:
        def post(self, url, json):
            sizes.append(len(json["queries"]))
            return Response(json["queries"])

    dependencies = [dict(name=f"package-{i}", version="1.0.0", ecosystem="npm") for i in range(1479)]
    result = query_osv_batch(Client(), dependencies)
    assert result["success"]
    assert max(sizes) == 100 and sum(sizes) == 1479
    assert [r["marker"] for r in result["results"]] == [d["name"] for d in dependencies]


def test_database_addresses_are_not_credentials_but_passwords_are():
    for url in ["mongodb://localhost:27017/nodegoat", "mongodb://mongo:27017/nodegoat"]:
        assert not scan_line(url, 1, "config.js")
    result = scan_line('const db = "postgresql://user:PrivatePass123@localhost/db";', 1, "config.js")
    assert any(f["rule_id"] == "database-connection-string" for f in result)
    assert "PrivatePass123" not in str(result)


def test_django_requires_framework_evidence_not_html_forms(tmp_path):
    (tmp_path / "index.html").write_text('<form method="post"></form>')
    assert not has_django_evidence(tmp_path)
    (tmp_path / "manage.py").write_text('from django.core.management import execute_from_command_line')
    assert has_django_evidence(tmp_path)
