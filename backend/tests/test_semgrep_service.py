import json
import subprocess
import pytest

from app.services import semgrep_service


class CompletedProcessStub:
    def __init__(
        self,
        *,
        returncode=0,
        stdout="",
        stderr="",
    ):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_run_semgrep_uses_frozen_local_ruleset(
    monkeypatch,
    tmp_path,
):
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs

        return CompletedProcessStub(
            returncode=0,
            stdout=json.dumps(
                {
                    "results": [],
                    "paths": {"scanned": ["app.js"]},
                }
            ),
        )

    monkeypatch.setattr(
        semgrep_service.subprocess,
        "run",
        fake_run,
    )

    result = semgrep_service.run_semgrep(tmp_path)

    command = captured["command"]

    assert result["success"] is True
    assert result["scan_status"] == "completed"
    assert command[0] == "semgrep"
    assert "--config" in command

    config_index = command.index("--config")

    assert (
        command[config_index + 1]
        == str(semgrep_service.SEMGREP_RULES_PATH)
    )

    assert "auto" not in command
    assert str(tmp_path) == command[-1]


def test_missing_ruleset_returns_controlled_failure(
    monkeypatch,
    tmp_path,
):
    missing_ruleset = (
        tmp_path
        / "missing-semgrep-rules"
    )

    monkeypatch.setattr(
        semgrep_service,
        "SEMGREP_RULES_PATH",
        missing_ruleset,
    )

    subprocess_called = False

    def fake_run(*args, **kwargs):
        nonlocal subprocess_called
        subprocess_called = True

        raise AssertionError(
            "Semgrep must not run without the ruleset."
        )

    monkeypatch.setattr(
        semgrep_service.subprocess,
        "run",
        fake_run,
    )

    result = semgrep_service.run_semgrep(tmp_path)

    assert subprocess_called is False
    assert result["success"] is False
    assert result["timed_out"] is False
    assert result["findings"] == []
    assert result["findings_count"] == 0
    assert (
        result["error"]
        == "Semgrep ruleset is unavailable."
    )


def test_semgrep_timeout_returns_controlled_failure(
    monkeypatch,
    tmp_path,
):
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd="semgrep",
            timeout=semgrep_service.SEMGREP_TIMEOUT_SECONDS,
        )

    monkeypatch.setattr(
        semgrep_service.subprocess,
        "run",
        fake_run,
    )

    result = semgrep_service.run_semgrep(tmp_path)

    assert result["success"] is False
    assert result["timed_out"] is True
    assert result["findings"] == []
    assert result["findings_count"] == 0
    assert str(
        semgrep_service.SEMGREP_TIMEOUT_SECONDS
    ) in result["error"]


def test_semgrep_execution_failure_does_not_expose_stderr(
    monkeypatch,
    tmp_path,
):
    sensitive_stderr = (
        "scanner error at "
        "C:\\Users\\example\\AppData\\Local\\Temp\\repo "
        "containing sensitive repository information"
    )

    def fake_run(*args, **kwargs):
        return CompletedProcessStub(
            returncode=2,
            stdout="",
            stderr=sensitive_stderr,
        )

    monkeypatch.setattr(
        semgrep_service.subprocess,
        "run",
        fake_run,
    )

    result = semgrep_service.run_semgrep(tmp_path)

    assert result["success"] is False
    assert result["exit_code"] == 2
    assert (
        result["error"]
        == (
            "Semgrep terminated with a "
            "scanner execution error."
        )
    )
    assert sensitive_stderr not in result["error"]


def test_invalid_json_returns_controlled_failure(
    monkeypatch,
    tmp_path,
):
    def fake_run(*args, **kwargs):
        return CompletedProcessStub(
            returncode=0,
            stdout="not valid json",
            stderr="",
        )

    monkeypatch.setattr(
        semgrep_service.subprocess,
        "run",
        fake_run,
    )

    result = semgrep_service.run_semgrep(tmp_path)

    assert result["success"] is False
    assert result["timed_out"] is False
    assert (
        result["error"]
        == "Unable to parse Semgrep analysis output."
    )


@pytest.mark.parametrize("metadata,status", [
    ({"paths": {"scanned": ["app.js"]}, "errors": [{"message": "PRIVATE source text"}]}, "partial"),
    ({"paths": {"scanned": ["app.js"], "skipped": [{"path": "PRIVATE/path"}]}}, "partial"),
    ({"paths": {"scanned": ["app.js"]}, "skipped_rules": [{"details": "PRIVATE"}]}, "partial"),
    ({"paths": {"scanned": []}}, "not_run"),
    ({}, "partial"),
])
def test_incomplete_execution_keeps_findings_without_exposing_diagnostics(monkeypatch, tmp_path, metadata, status):
    output = {"results": [{"check_id": "test-rule", "path": "app.js",
                          "start": {"line": 1, "col": 1}, "end": {"line": 1, "col": 5},
                          "extra": {"severity": "ERROR", "message": "Review this code"}}], **metadata}
    monkeypatch.setattr(semgrep_service.subprocess, "run",
                        lambda *args, **kwargs: CompletedProcessStub(stdout=json.dumps(output)))
    result = semgrep_service.run_semgrep(tmp_path)
    assert result["success"] is True
    assert result["scan_status"] == status
    assert result["findings_count"] == 1
    assert "PRIVATE" not in result["note"]
    assert "PRIVATE" not in json.dumps(result["coverage"])


@pytest.mark.parametrize("output", [[], {"results": None}, {"results": {}}])
def test_malformed_result_is_a_controlled_failure(monkeypatch, tmp_path, output):
    monkeypatch.setattr(semgrep_service.subprocess, "run",
                        lambda *args, **kwargs: CompletedProcessStub(stdout=json.dumps(output)))
    assert semgrep_service.run_semgrep(tmp_path)["success"] is False


def test_real_scanner_reports_parse_errors_and_preserves_other_findings(tmp_path):
    (tmp_path / "good.js").write_text("function route(req) { db.query('SELECT ' + req.query.id); }", encoding="utf-8")
    (tmp_path / "broken.js").write_text("function broken( {", encoding="utf-8")
    (tmp_path / "readme.txt").write_text("Unsupported text control.", encoding="utf-8")
    result = semgrep_service.run_semgrep(tmp_path)
    assert result["success"] is True, result.get("error")
    assert result["scan_status"] == "partial"
    assert result["coverage"]["errors_count"] > 0
    assert result["findings_count"] > 0
    assert "incomplete" in result["note"]
