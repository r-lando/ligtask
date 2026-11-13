import hashlib
import httpx
import pytest

from app.services import github_service as github, database_service as database
from app.services.report_notes import source_revision_text
from app.services.pdf_report_service import build_metadata_table, create_styles

SHA = "a" * 40


def test_retrieval_resolves_branch_then_downloads_exact_commit(monkeypatch):
    calls = []
    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(200, json={"default_branch": "feature/test", "private": False})
        if len(calls) == 2:
            assert request.url.raw_path.endswith(b"/commits/feature%2Ftest")
            return httpx.Response(200, json={"sha": SHA})
        assert str(request.url) == f"https://codeload.github.com/owner/repo/zip/{SHA}"
        return httpx.Response(200, content=b"PKfixture", headers={"content-type": "application/zip"})
    client = httpx.Client
    monkeypatch.setattr(github.httpx, "Client", lambda **kwargs: client(transport=httpx.MockTransport(handler), **kwargs))
    result = github.retrieve_public_repository("https://github.com/owner/repo")
    assert len(calls) == 3
    assert result["source_revision"] == dict(commit_sha=SHA, branch="feature/test", repository_url="https://github.com/owner/repo", archive_sha256=hashlib.sha256(b"PKfixture").hexdigest())


@pytest.mark.parametrize("status,payload", [(403, {}), (500, {}), (200, {"sha": "main"}), (200, []), (200, {"sha": "a" * 39})])
def test_resolution_failure_never_falls_back_to_branch_archive(monkeypatch, status, payload):
    monkeypatch.setattr(github, "get_repository_metadata", lambda *args: dict(owner="owner", repository="repo", default_branch="main"))
    client = httpx.Client
    monkeypatch.setattr(github.httpx, "Client", lambda **kwargs: client(transport=httpx.MockTransport(lambda request: httpx.Response(status, json=payload)), **kwargs))
    monkeypatch.setattr(github, "download_repository_archive", lambda *args: pytest.fail("must not download an unresolved branch"))
    with pytest.raises(github.GitHubRepositoryError):
        github.retrieve_public_repository("https://github.com/owner/repo")


def test_provenance_persists_and_legacy_migration_does_not_invent_commit(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "revision.db")
    database.initialize_database()
    with database.get_connection() as connection:
        connection.execute("ALTER TABLE assessments DROP COLUMN source_revision_json")
        connection.execute("INSERT INTO assessments (id, repository_name, input_type, status, created_at) VALUES ('legacy', 'owner/repo', 'GITHUB', 'completed', '2026-10-17')")
    database.initialize_database()
    database.initialize_database()  # Migration is idempotent.
    legacy = database.get_assessment_by_id("legacy")
    assert not legacy["source_revision"]
    assert source_revision_text(legacy) == "Not recorded (older assessment)"
    record = {"id": "new", "repository_name": "owner/repo", "input_type": "GITHUB", "status": "completed", "created_at": "2026-10-17", "source_revision": {"commit_sha": SHA, "branch": "main"}}
    database.save_assessment(record, [])
    restored = database.get_assessment_by_id("new")
    assert restored["source_revision"] == record["source_revision"]
    table = build_metadata_table(restored, create_styles())
    assert any(SHA in cell.getPlainText() for row in table._cellvalues for cell in row if hasattr(cell, "getPlainText"))
    assert source_revision_text({"input_type": "ZIP"}) == "Not applicable (ZIP upload)"
