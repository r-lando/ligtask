from pathlib import Path

from app.services import config_service
from app.services import secret_service


def test_secret_read_oserror_returns_error(
    monkeypatch,
    tmp_path,
):
    file_path = tmp_path / "secret.txt"
    file_path.write_text("password=realvalue123")

    original_read_bytes = Path.read_bytes

    def failing_read_bytes(path):
        if path == file_path:
            raise OSError(
                "PRIVATE_SECRET_READ_ERROR"
            )

        return original_read_bytes(path)

    monkeypatch.setattr(
        Path,
        "read_bytes",
        failing_read_bytes,
    )

    result = secret_service.read_text_file(
        file_path
    )

    assert result == {
        "status": "error",
        "content": None,
    }

    assert (
        "PRIVATE_SECRET_READ_ERROR"
        not in str(result)
    )


def test_secret_scan_reports_partial_file_failure(
    monkeypatch,
    tmp_path,
):
    readable_file = tmp_path / "readable.env"
    unreadable_file = tmp_path / "unreadable.env"

    readable_file.write_text(
        "password=SuperSecretValue123"
    )
    unreadable_file.write_text(
        "password=AnotherSecretValue456"
    )

    original_read_bytes = Path.read_bytes

    def failing_read_bytes(path):
        if path == unreadable_file:
            raise OSError(
                "PRIVATE_SECRET_FILE_ERROR"
            )

        return original_read_bytes(path)

    monkeypatch.setattr(
        Path,
        "read_bytes",
        failing_read_bytes,
    )

    result = secret_service.scan_secrets(
        tmp_path
    )

    assert (
        result["scan_status"]
        == "completed_with_errors"
    )
    assert result["files_scanned"] == 1
    assert result["findings_count"] >= 1
    assert len(result["processing_errors"]) == 1

    assert (
        result["processing_errors"][0]["error"]
        ==
        "An eligible repository file could not "
        "be read during secret detection."
    )

    assert (
        "PRIVATE_SECRET_FILE_ERROR"
        not in str(result)
    )

    assert all(
        finding["file"] != "unreadable.env"
        for finding in result["findings"]
    )


def test_secret_scan_traversal_oserror_returns_failed(
    monkeypatch,
    tmp_path,
):
    def failing_rglob(
        path,
        pattern,
    ):
        raise OSError(
            "PRIVATE_SECRET_TRAVERSAL_ERROR"
        )

    monkeypatch.setattr(
        Path,
        "rglob",
        failing_rglob,
    )

    result = secret_service.scan_secrets(
        tmp_path
    )

    assert result["scan_status"] == "failed"
    assert result["files_scanned"] == 0
    assert result["findings_count"] == 0
    assert len(result["processing_errors"]) == 1

    assert (
        result["processing_errors"][0]["error"]
        ==
        "The repository could not be fully "
        "traversed during secret detection."
    )

    assert (
        "PRIVATE_SECRET_TRAVERSAL_ERROR"
        not in str(result)
    )


def test_config_read_oserror_returns_error(
    monkeypatch,
    tmp_path,
):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:latest"
    )

    original_read_text = Path.read_text

    def failing_read_text(
        path,
        *args,
        **kwargs,
    ):
        if path == dockerfile:
            raise OSError(
                "PRIVATE_CONFIG_READ_ERROR"
            )

        return original_read_text(
            path,
            *args,
            **kwargs,
        )

    monkeypatch.setattr(
        Path,
        "read_text",
        failing_read_text,
    )

    result = config_service.read_dockerfile(
        dockerfile
    )

    assert result == {
        "status": "error",
        "content": None,
    }

    assert (
        "PRIVATE_CONFIG_READ_ERROR"
        not in str(result)
    )


def test_config_scan_reports_partial_file_failure(
    monkeypatch,
    tmp_path,
):
    good_directory = tmp_path / "good"
    bad_directory = tmp_path / "bad"

    good_directory.mkdir()
    bad_directory.mkdir()

    good_dockerfile = (
        good_directory / "Dockerfile"
    )
    bad_dockerfile = (
        bad_directory / "Dockerfile"
    )

    good_dockerfile.write_text(
        "\n".join(
            [
                "FROM python:latest",
                "ADD . /app",
            ]
        )
    )

    bad_dockerfile.write_text(
        "FROM node:latest"
    )

    original_read_text = Path.read_text

    def failing_read_text(
        path,
        *args,
        **kwargs,
    ):
        if path == bad_dockerfile:
            raise OSError(
                "PRIVATE_CONFIG_FILE_ERROR"
            )

        return original_read_text(
            path,
            *args,
            **kwargs,
        )

    monkeypatch.setattr(
        Path,
        "read_text",
        failing_read_text,
    )

    result = (
        config_service.scan_configurations(
            tmp_path
        )
    )

    assert (
        result["scan_status"]
        == "completed_with_errors"
    )
    assert result["files_scanned"] == 1
    assert result["findings_count"] >= 1
    assert len(result["processing_errors"]) == 1

    assert (
        result["processing_errors"][0]["error"]
        ==
        "A supported configuration file could "
        "not be read during configuration "
        "assessment."
    )

    assert (
        "PRIVATE_CONFIG_FILE_ERROR"
        not in str(result)
    )

    assert all(
        finding["file"] != "bad/Dockerfile"
        for finding in result["findings"]
    )


def test_config_scan_traversal_oserror_returns_failed(
    monkeypatch,
    tmp_path,
):
    def failing_rglob(
        path,
        pattern,
    ):
        raise OSError(
            "PRIVATE_CONFIG_TRAVERSAL_ERROR"
        )

    monkeypatch.setattr(
        Path,
        "rglob",
        failing_rglob,
    )

    result = (
        config_service.scan_configurations(
            tmp_path
        )
    )

    assert result["scan_status"] == "failed"
    assert result["files_scanned"] == 0
    assert result["findings_count"] == 0
    assert len(result["processing_errors"]) == 1

    assert (
        result["processing_errors"][0]["error"]
        ==
        "The repository could not be fully "
        "traversed during configuration "
        "assessment."
    )

    assert (
        "PRIVATE_CONFIG_TRAVERSAL_ERROR"
        not in str(result)
    )
