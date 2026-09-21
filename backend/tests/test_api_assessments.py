from io import BytesIO

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_api_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {
        "name": "TALGED",
        "status": "running",
    }


def test_api_health_healthy(monkeypatch):
    monkeypatch.setattr(
        "app.main.database_health_check",
        lambda: True,
    )
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "database": "connected",
    }


def test_api_health_degraded(monkeypatch):
    monkeypatch.setattr(
        "app.main.database_health_check",
        lambda: False,
    )
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "degraded",
        "database": "unavailable",
    }


def test_api_list_assessments_pagination_valid(monkeypatch):
    monkeypatch.setattr(
        "app.api.assessments.get_assessments",
        lambda limit, offset: [{"assessment_id": "test-1"}],
    )
    monkeypatch.setattr(
        "app.api.assessments.get_assessment_count",
        lambda: 1,
    )

    response = client.get("/assessments?limit=10&offset=0")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["limit"] == 10
    assert data["offset"] == 0
    assert len(data["assessments"]) == 1


def test_api_list_assessments_limit_exceeded():
    response = client.get("/assessments?limit=101")
    assert response.status_code == 422


def test_api_retrieve_assessment_not_found(monkeypatch):
    monkeypatch.setattr(
        "app.api.assessments.get_assessment_by_id",
        lambda assessment_id: None,
    )

    response = client.get("/assessments/nonexistent-id")
    assert response.status_code == 404
    assert response.json()["detail"] == "Assessment not found."


def test_api_retrieve_assessment_success(monkeypatch):
    sample = {
        "assessment_id": "known-id",
        "repository_name": "demo-repo",
        "findings": [],
    }

    monkeypatch.setattr(
        "app.api.assessments.get_assessment_by_id",
        lambda assessment_id: sample,
    )

    response = client.get("/assessments/known-id")
    assert response.status_code == 200
    assert response.json()["assessment_id"] == "known-id"


def test_api_get_html_report_not_found(monkeypatch):
    monkeypatch.setattr(
        "app.api.assessments.generate_assessment_html",
        lambda assessment_id: None,
    )

    response = client.get("/assessments/nonexistent/report")
    assert response.status_code == 404


def test_api_get_html_report_success(monkeypatch):
    monkeypatch.setattr(
        "app.api.assessments.generate_assessment_html",
        lambda assessment_id: "<html><body>Report</body></html>",
    )

    response = client.get("/assessments/sample-id/report")
    assert response.status_code == 200
    assert "Report" in response.text
    assert "no-store" in response.headers.get(
        "cache-control", ""
    )


def test_api_get_pdf_report_not_found(monkeypatch):
    monkeypatch.setattr(
        "app.api.assessments.generate_assessment_pdf",
        lambda assessment_id: None,
    )

    response = client.get("/assessments/nonexistent/report.pdf")
    assert response.status_code == 404


def test_api_get_pdf_report_success(monkeypatch):
    fake_pdf = b"%PDF-1.4 sample content"

    monkeypatch.setattr(
        "app.api.assessments.generate_assessment_pdf",
        lambda assessment_id: fake_pdf,
    )

    response = client.get("/assessments/sample-id/report.pdf")
    assert response.status_code == 200
    assert response.content == fake_pdf
    assert "no-store" in response.headers.get(
        "cache-control", ""
    )
    assert (
        'attachment; filename="talged-assessment-sample-id.pdf"'
        in response.headers.get("content-disposition", "")
    )


def test_api_upload_non_zip_rejected():
    fake_file = BytesIO(b"not a zip file content")
    response = client.post(
        "/assessments/upload",
        files={"file": ("project.tar.gz", fake_file, "application/gzip")},
    )
    assert response.status_code == 400
    assert (
        "Only ZIP repository files are allowed."
        in response.json()["detail"]
    )


def test_api_github_invalid_url_rejected():
    response = client.post(
        "/assessments/github",
        json={"repository_url": "http://insecure.com/repo"},
    )
    assert response.status_code == 400
    assert (
        "GitHub repository URL must use HTTPS."
        in response.json()["detail"]
    )
