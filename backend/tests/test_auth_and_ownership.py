import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.main import app
from app.services import auth_service, database_service, job_service

ALICE = "11111111-1111-4111-8111-111111111111"
BOB = "22222222-2222-4222-8222-222222222222"
ORIGIN = {"Origin": "http://127.0.0.1:5173"}


@pytest.fixture
def store(monkeypatch, tmp_path):
    monkeypatch.setattr(database_service, "DATABASE_PATH", tmp_path / "auth.db")
    monkeypatch.setenv("AUTH_ALLOWED_ORIGINS", ORIGIN["Origin"])
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "false")
    monkeypatch.setenv("ASSESSMENTS_PER_DAY", "5")
    monkeypatch.setenv("AUTH_ALLOWED_EMAILS", "alice@example.com,bob@example.com")
    database_service.initialize_database()
    job_service.initialize_jobs()
    # Authentication verifies provider tokens; tests fake only that HTTP boundary.
    def provider(method, path, *, token=None, payload=None):
        if path == "user" and token in {"alice-token", "bob-token"}:
            return {"id": ALICE if token == "alice-token" else BOB,
                    "email": "alice@example.com" if token == "alice-token" else "bob@example.com",
                    "email_confirmed_at": "2026-10-16T00:00:00Z"}
        raise HTTPException(status_code=401, detail="Invalid session.")
    monkeypatch.setattr(auth_service, "provider_request", provider)


def client_for(token=None):
    client = TestClient(app)
    if token:
        client.cookies.set(auth_service.ACCESS_COOKIE, token)
    return client


@pytest.mark.parametrize("path", [
    "/assessments", "/assessments/missing", "/assessments/jobs/missing",
    "/assessments/missing/report", "/assessments/missing/report.pdf",
])
def test_read_endpoints_require_authentication(store, path):
    assert client_for().get(path).status_code == 401


def test_submissions_require_authentication(store):
    client = client_for()
    assert client.post("/assessments/github", json={"repository_url": "https://github.com/a/b"}).status_code == 401
    assert client.post("/assessments/upload", files={"file": ("repo.zip", b"data")}).status_code == 401


def test_forged_session_is_rejected(store):
    assert client_for("forged-token").get("/assessments").status_code == 401


def test_job_status_is_private_and_client_cannot_choose_owner(store):
    alice, bob = client_for("alice-token"), client_for("bob-token")
    created = alice.post("/assessments/github", headers=ORIGIN, json={
        "repository_url": "https://github.com/a/b", "user_id": BOB,
    })
    assert created.status_code == 202
    job_id = created.json()["job_id"]
    assert alice.get(f"/assessments/jobs/{job_id}").status_code == 200
    assert bob.get(f"/assessments/jobs/{job_id}").status_code == 404
    with job_service.job_connection() as connection:
        assert connection.execute("SELECT user_id FROM assessment_jobs WHERE id = ?", (job_id,)).fetchone()[0] == ALICE


def seed_assessment(assessment_id, user_id=None):
    with job_service.job_connection() as connection:
        connection.execute(
            "INSERT INTO assessments (id, repository_name, input_type, status, created_at) VALUES (?, ?, 'ZIP', 'completed', ?)",
            (assessment_id, f"repo-{assessment_id}", "2026-10-16T00:00:00+00:00"),
        )
        if user_id:
            connection.execute("INSERT INTO assessment_owners VALUES (?, ?)", (assessment_id, user_id))


def test_results_history_and_reports_enforce_ownership(store, monkeypatch):
    seed_assessment("alice-assessment", ALICE)
    seed_assessment("bob-assessment", BOB)
    seed_assessment("legacy-unowned")
    monkeypatch.setattr("app.api.assessments.generate_assessment_html", lambda _: "<html>private</html>")
    monkeypatch.setattr("app.api.assessments.generate_assessment_pdf", lambda _: b"%PDF-private")
    for token, owned, other in [
        ("alice-token", "alice-assessment", "bob-assessment"),
        ("bob-token", "bob-assessment", "alice-assessment"),
    ]:
        client = client_for(token)
        history = client.get("/assessments").json()
        assert history["total"] == 1
        assert [row["assessment_id"] for row in history["assessments"]] == [owned]
        for suffix in ("", "/report", "/report.pdf"):
            assert client.get(f"/assessments/{owned}{suffix}").status_code == 200
            assert client.get(f"/assessments/{other}{suffix}").status_code == 404
            assert client.get(f"/assessments/legacy-unowned{suffix}").status_code == 404


def test_worker_associates_result_with_job_user(store, monkeypatch):
    seed_assessment("result")
    monkeypatch.setattr(job_service, "process_github_repository", lambda _: {"assessment_id": "result"})
    job_service.reserve_job("GITHUB", "https://github.com/a/b", user_id=ALICE)
    assert job_service.execute_job(job_service.claim_job("worker")) == ("result", None)
    assert database_service.assessment_owned_by("result", ALICE)
    assert not database_service.assessment_owned_by("result", BOB)


def test_per_user_active_limit_is_atomic_and_does_not_block_other_users(store):
    def submit(_):
        try:
            return job_service.reserve_job("GITHUB", "url", user_id=ALICE)
        except HTTPException as exc:
            assert exc.status_code == 429
            return None
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(submit, range(5)))
    assert sum(value is not None for value in results) == 1
    assert job_service.reserve_job("GITHUB", "url", user_id=BOB)


def test_daily_quota_counts_failed_jobs_and_expires_after_24_hours(store, monkeypatch):
    monkeypatch.setenv("ASSESSMENTS_PER_DAY", "2")
    first = job_service.reserve_job("GITHUB", "url", status="failed", user_id=ALICE)
    job_service.reserve_job("GITHUB", "url", status="completed", user_id=ALICE)
    with pytest.raises(HTTPException) as exc:
        job_service.reserve_job("GITHUB", "url", user_id=ALICE)
    assert exc.value.status_code == 429
    with job_service.job_connection() as connection:
        connection.execute("UPDATE assessment_jobs SET created_at = ? WHERE id = ?", (time.time() - 86401, first))
    assert job_service.reserve_job("GITHUB", "url", user_id=ALICE)


def test_cookie_mutations_reject_missing_or_untrusted_origin(store):
    client = client_for("alice-token")
    for headers in ({}, {"Origin": "https://attacker.example"}):
        response = client.post("/assessments/github", headers=headers, json={"repository_url": "https://github.com/a/b"})
        assert response.status_code == 403


def session_data():
    return {"access_token": "access-secret", "refresh_token": "refresh-secret", "expires_in": 3600,
            "user": {"id": ALICE, "email": "alice@example.com", "email_confirmed_at": "2026-10-16T00:00:00Z"}}


def test_login_sets_httponly_cookies_and_does_not_return_tokens(store, monkeypatch):
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "true")
    def provider(method, path, **kwargs):
        assert path == "token?grant_type=password"
        assert kwargs["payload"] == {"email": "alice@example.com", "password": "password-secret"}
        return session_data()
    monkeypatch.setattr("app.api.auth.provider_request", provider)
    response = client_for().post("/auth/login", headers=ORIGIN, json={"email": "alice@example.com", "password": "password-secret"})
    assert response.status_code == 200
    assert response.json() == {"id": ALICE, "email": "alice@example.com"}
    cookies = response.headers.get_list("set-cookie")
    assert len(cookies) == 2
    assert all("HttpOnly" in cookie and "Secure" in cookie and "SameSite=lax" in cookie for cookie in cookies)
    assert "Path=/auth" in cookies[1]


def test_refresh_rotates_session_cookies(store, monkeypatch):
    def provider(method, path, **kwargs):
        assert path == "token?grant_type=refresh_token"
        assert kwargs["payload"]["refresh_token"] == "old-refresh"
        return session_data()
    monkeypatch.setattr("app.api.auth.provider_request", provider)
    client = client_for()
    client.cookies.set(auth_service.REFRESH_COOKIE, "old-refresh")
    response = client.post("/auth/refresh", headers=ORIGIN)
    assert response.status_code == 200
    assert "refresh-secret" in response.headers.get_list("set-cookie")[1]


def test_logout_clears_cookies_even_if_provider_is_unavailable(store, monkeypatch):
    def fail(*args, **kwargs):
        raise HTTPException(status_code=503)
    monkeypatch.setattr("app.api.auth.provider_request", fail)
    response = client_for("alice-token").post("/auth/logout", headers=ORIGIN)
    assert response.status_code == 200
    assert all("Max-Age=0" in cookie for cookie in response.headers.get_list("set-cookie"))


def test_provider_is_fail_closed_when_configuration_is_missing(monkeypatch):
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    with pytest.raises(HTTPException) as exc:
        auth_service.provider_request("GET", "user", token="anything")
    assert exc.value.status_code == 503


def test_provider_network_errors_do_not_expose_secrets(monkeypatch):
    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_PUBLISHABLE_KEY", "public-key")
    def fail(*args, **kwargs):
        raise httpx.ConnectError("secret-token-in-error")
    monkeypatch.setattr(httpx.Client, "request", fail)
    with pytest.raises(HTTPException) as exc:
        auth_service.provider_request("GET", "user", token="secret-token")
    assert exc.value.status_code == 503
    assert "secret" not in exc.value.detail


def test_only_approved_confirmed_emails_can_access_app(store):
    user = session_data()["user"]
    assert auth_service.user_from_data(user).id == ALICE
    with pytest.raises(HTTPException) as exc:
        auth_service.user_from_data({**user, "email": "outsider@example.com"})
    assert exc.value.status_code == 403
    with pytest.raises(HTTPException) as exc:
        auth_service.user_from_data({**user, "email_confirmed_at": None})
    assert exc.value.status_code == 403


def test_empty_access_allowlist_fails_closed(store, monkeypatch):
    monkeypatch.setenv("AUTH_ALLOWED_EMAILS", "")
    with pytest.raises(HTTPException) as exc:
        auth_service.user_from_data(session_data()["user"])
    assert exc.value.status_code == 503
