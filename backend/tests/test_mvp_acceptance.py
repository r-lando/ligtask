"""MVP acceptance checks with isolated storage and two provider-verified identities.

Provider HTTP responses are controlled by the imported store fixture. Scanners
are real except the explicitly simulated Semgrep timeout case below.
"""

from io import BytesIO
import subprocess
import time
import zipfile

from fastapi.testclient import TestClient

from app.main import app
from app.services import database_service, job_service, semgrep_service
from app.services.repository_service import MAX_UPLOAD_SIZE
from tests.test_auth_and_ownership import ALICE, ORIGIN, client_for, store


def wait_for_job(client, job_id):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        response = client.get(f"/assessments/jobs/{job_id}")
        assert response.status_code == 200
        job = response.json()
        if job["status"] in {"failed", "completed"}:
            return job
        time.sleep(0.05)
    raise AssertionError("Job did not finish within acceptance-test deadline")


def test_invalid_zip_fails_as_job_and_cleans_up(store):
    with TestClient(app):
        alice = client_for("alice-token")
        accepted = alice.post("/assessments/upload", headers=ORIGIN,
                              files={"file": ("invalid.zip", b"not a ZIP")})
        assert accepted.status_code == 202
        job_id = accepted.json()["job_id"]
        job = wait_for_job(alice, job_id)
        assert job["status"] == "failed"
        assert "valid ZIP" in job["error"]
        assert job["assessment_id"] is None
        assert not job_service.archive_path(job_id).exists()
        assert alice.get("/assessments").json()["total"] == 0


def test_real_50mb_upload_boundary_returns_413_and_releases_job(store):
    alice = client_for("alice-token")
    payload = BytesIO(b"x" * (MAX_UPLOAD_SIZE + 1))
    try:
        response = alice.post("/assessments/upload", headers=ORIGIN,
                              files={"file": ("oversized.zip", payload)})
    finally:
        payload.close()
    assert response.status_code == 413
    with job_service.job_connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM assessment_jobs").fetchone()[0] == 0
    assert list(job_service.archive_path("unused").parent.glob("*.zip")) == []


def test_daily_quota_is_enforced_on_both_submission_endpoints(store):
    for _ in range(5):
        job_service.reserve_job("GITHUB", "https://github.com/a/b", status="completed", user_id=ALICE)
    alice = client_for("alice-token")
    github = alice.post("/assessments/github", headers=ORIGIN,
                        json={"repository_url": "https://github.com/a/b"})
    upload = alice.post("/assessments/upload", headers=ORIGIN,
                        files={"file": ("repo.zip", b"zip")})
    for response in (github, upload):
        assert response.status_code == 429
        assert "daily" in response.json()["detail"]
    with job_service.job_connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM assessment_jobs").fetchone()[0] == 5


def test_timeout_preserves_results_reports_and_user_isolation(store, monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="semgrep", timeout=120)
    monkeypatch.setattr(semgrep_service.subprocess, "run", timeout)

    archive = BytesIO()
    with zipfile.ZipFile(archive, "w") as zip_file:
        zip_file.writestr("project/app.js", "console.log('fixture');")
        zip_file.writestr("project/Dockerfile", "FROM node:latest\nADD . /app\n")
    archive.seek(0)
    with TestClient(app):
        alice = client_for("alice-token")
        bob = client_for("bob-token")
        accepted = alice.post("/assessments/upload", headers=ORIGIN,
                              files={"file": ("timeout.zip", archive)})
        assert accepted.status_code == 202
        job_id = accepted.json()["job_id"]
        job = wait_for_job(alice, job_id)
        assert job["status"] == "completed"  # Job succeeded; assessment is partial.
        assessment_id = job["assessment_id"]
        assessment = alice.get(f"/assessments/{assessment_id}").json()
        assert assessment["status"] == "partial"
        assert assessment["mechanism_statuses"]["sast"]["status"] == "timed_out"
        assert len(assessment["findings"]) == 3
        assert all(item["category"] == "CONFIGURATION" for item in assessment["findings"])
        assert alice.get("/assessments").json()["total"] == 1
        assert bob.get("/assessments").json()["total"] == 0
        assert bob.get(f"/assessments/jobs/{job_id}").status_code == 404
        for suffix in ("", "/report", "/report.pdf"):
            assert bob.get(f"/assessments/{assessment_id}{suffix}").status_code == 404
        html = alice.get(f"/assessments/{assessment_id}/report")
        assert html.status_code == 200
        assert "dependency matches do not confirm exploitability" in html.text
        pdf = alice.get(f"/assessments/{assessment_id}/report.pdf")
        assert pdf.status_code == 200
        assert pdf.content.startswith(b"%PDF-")
        assert database_service.assessment_owned_by(assessment_id, ALICE)
        assert not job_service.archive_path(job_id).exists()
