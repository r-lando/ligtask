import time
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from threading import Event

import pytest
from fastapi import HTTPException, UploadFile
from fastapi.testclient import TestClient

from app.main import app
from app.services import database_service, job_service
from app.services.auth_service import User, require_user


@pytest.fixture(autouse=True)
def signed_in_job_user(monkeypatch):
    monkeypatch.setitem(app.dependency_overrides, require_user, lambda: User("test-user", "test@example.com"))


@pytest.fixture
def queue(monkeypatch, tmp_path):
    monkeypatch.setattr(database_service, "DATABASE_PATH", tmp_path / "test.db")
    database_service.initialize_database()
    job_service.initialize_jobs()
    return job_service


def test_queue_capacity_is_atomic_and_shared(queue, monkeypatch):
    monkeypatch.setattr(queue, "MAX_PENDING_JOBS", 2)

    def submit(_):
        try:
            return queue.reserve_job("GITHUB", "https://github.com/a/b")
        except HTTPException as exc:
            assert exc.status_code == 503
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(submit, range(8)))
    assert sum(result is not None for result in results) == 2


def test_job_can_only_be_claimed_once(queue):
    job_id = queue.reserve_job("GITHUB", "https://github.com/a/b")
    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(queue.claim_job, ["worker-a", "worker-b"]))
    assert [claim["id"] for claim in claims if claim] == [job_id]
    assert queue.get_job(job_id)["status"] == "running"


def test_queued_jobs_survive_store_reinitialization(queue):
    job_id = queue.reserve_job("GITHUB", "https://github.com/a/b")
    queue.initialize_jobs()
    assert queue.claim_job("new-worker")["id"] == job_id


def test_recovery_expires_only_abandoned_work(queue):
    queued = queue.reserve_job("GITHUB", "https://github.com/a/b")
    stale = queue.reserve_job("ZIP", "source.zip", "running")
    live = queue.reserve_job("GITHUB", "https://github.com/a/b", "running")
    path = queue.archive_path(stale)
    path.parent.mkdir()
    path.write_bytes(b"archive")
    with database_service.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_jobs SET updated_at = ? WHERE id = ?",
            (time.time() - queue.LEASE_SECONDS - 1, stale),
        )
    queue.recover_interrupted_jobs()
    assert queue.get_job(stale)["status"] == "failed"
    assert not path.exists()
    assert queue.get_job(live)["status"] == "running"
    assert queue.get_job(queued)["status"] == "queued"


def test_failed_upload_removes_staged_source_and_releases_capacity(queue, monkeypatch):
    monkeypatch.setattr(queue, "MAX_UPLOAD_SIZE", 2)
    upload = UploadFile(filename="source.zip", file=BytesIO(b"too large"))
    with pytest.raises(HTTPException) as error:
        queue.submit_upload(upload)
    assert error.value.status_code == 413
    assert list(queue.archive_path("unused").parent.glob("*.zip")) == []
    with database_service.get_connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM assessment_jobs").fetchone()[0] == 0


def test_upload_worker_uses_original_filename_and_cleans_source(queue, monkeypatch):
    upload = UploadFile(filename="../source.zip", file=BytesIO(b"archive"))
    submitted = queue.submit_upload(upload)
    job = queue.claim_job("worker")

    def process(file):
        assert file.filename == "../source.zip"
        assert file.file.read() == b"archive"
        return {"assessment_id": "result"}

    monkeypatch.setattr(queue, "_process_repository", process)
    assert queue.execute_job(job) == ("result", None)
    assert not queue.archive_path(submitted["job_id"]).exists()


def test_worker_error_is_sanitized_and_archive_removed(queue, monkeypatch):
    submitted = queue.submit_upload(UploadFile(filename="a.zip", file=BytesIO(b"zip")))

    def fail(_):
        raise RuntimeError("private repository contents")

    monkeypatch.setattr(queue, "_process_repository", fail)
    result, error = queue.execute_job(queue.claim_job("worker"))
    assert result is None
    assert "private" not in error
    assert not queue.archive_path(submitted["job_id"]).exists()


def test_api_returns_before_scan_finishes_and_worker_persists_result(queue, monkeypatch):
    started, release = Event(), Event()

    def process(_):
        started.set()
        assert release.wait(10)
        return {"assessment_id": "finished-assessment"}

    monkeypatch.setattr(queue, "process_github_repository", process)
    with TestClient(app) as client:
        try:
            submitted = client.post(
                "/assessments/github", json={"repository_url": "https://github.com/a/b"},
            )
            assert submitted.status_code == 202
            job_id = submitted.json()["job_id"]
            assert started.wait(5)
            assert client.get("/health").status_code == 200
            assert client.get(f"/assessments/jobs/{job_id}").json()["status"] == "running"
        finally:
            release.set()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            status = client.get(f"/assessments/jobs/{job_id}").json()
            if status["status"] == "completed":
                break
            time.sleep(0.05)
        assert status["status"] == "completed"
        assert status["assessment_id"] == "finished-assessment"


def test_unknown_job_returns_404(queue):
    with TestClient(app) as client:
        assert client.get("/assessments/jobs/missing").status_code == 404
