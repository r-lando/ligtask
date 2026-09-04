import json
import subprocess

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