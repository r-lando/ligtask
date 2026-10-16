from pathlib import Path
import json

import httpx

from app.services import dependency_service


def test_nested_and_workspace_npm_packages_use_actual_names(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"packages": {
        "": {"name": "root", "version": "1.0.0"},
        "node_modules/parent/node_modules/@scope/child": {"version": "2.0.0"},
        "packages/web/node_modules/lodash": {"version": "4.17.20"},
    }}), encoding="utf-8")
    dependencies = dependency_service.extract_npm_dependencies(lock)
    assert [(item["name"], item["version"]) for item in dependencies] == [
        ("@scope/child", "2.0.0"), ("lodash", "4.17.20"),
    ]


def test_invalid_lockfile_shapes_do_not_crash(tmp_path):
    lock = tmp_path / "package-lock.json"
    for value in ([], None, {"packages": []}, {"packages": {"node_modules/a": None}}):
        lock.write_text(json.dumps(value), encoding="utf-8")
        assert dependency_service.extract_npm_dependencies(lock) == []


class FailingClient:
    """
    Minimal HTTP client stub that simulates
    a network failure without contacting OSV.
    """

    def post(self, *args, **kwargs):
        request = httpx.Request(
            "POST",
            dependency_service.OSV_BATCH_URL,
        )
        raise httpx.ConnectError(
            "PRIVATE_INTERNAL_NETWORK_ERROR",
            request=request,
        )

    def get(self, *args, **kwargs):
        request = httpx.Request(
            "GET",
            (
                f"{dependency_service.OSV_VULNERABILITY_URL}/"
                "TEST-VULNERABILITY"
            ),
        )
        raise httpx.ConnectError(
            "PRIVATE_INTERNAL_NETWORK_ERROR",
            request=request,
        )


class DummyClient:
    """
    Context-manager replacement for httpx.Client.

    The dependency service still receives a client object,
    but the mocked OSV functions below prevent real network
    requests from being made.
    """

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


def make_dependency():
    return {
        "name": "example-package",
        "version": "1.0.0",
        "ecosystem": "npm",
        "source_file": "package-lock.json",
    }


def make_vulnerability(vulnerability_id):
    return {
        "id": vulnerability_id,
        "summary": "Example vulnerability",
        "severity": [],
    }


def test_query_osv_batch_sanitizes_network_error():
    dependencies = [
        make_dependency(),
    ]

    result = dependency_service.query_osv_batch(
        FailingClient(),
        dependencies,
    )

    assert result["success"] is False
    assert result["results"] == []
    assert (
        result["error"]
        == "OSV vulnerability query failed."
    )

    serialized_result = str(result)

    assert "PRIVATE_INTERNAL_NETWORK_ERROR" not in serialized_result
    assert "ConnectError" not in serialized_result


def test_vulnerability_details_sanitizes_network_error():
    result = dependency_service.get_vulnerability_details(
        FailingClient(),
        "TEST-VULNERABILITY",
    )

    assert result["success"] is False
    assert result["data"] is None
    assert (
        result["error"]
        == (
            "OSV vulnerability details "
            "could not be retrieved."
        )
    )

    serialized_result = str(result)

    assert "PRIVATE_INTERNAL_NETWORK_ERROR" not in serialized_result
    assert "ConnectError" not in serialized_result


def test_scan_dependencies_completes_when_no_dependencies(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(
        dependency_service,
        "collect_dependencies",
        lambda repository_path: [],
    )

    result = dependency_service.scan_dependencies(
        Path(tmp_path),
    )

    assert result["scan_status"] == "completed"
    assert result["dependencies_checked"] == 0
    assert result["findings_count"] == 0
    assert result["findings"] == []
    assert result["request_errors"] == []


def test_scan_dependencies_fails_when_batch_query_fails(
    monkeypatch,
    tmp_path,
):
    dependencies = [
        make_dependency(),
    ]

    monkeypatch.setattr(
        dependency_service,
        "collect_dependencies",
        lambda repository_path: dependencies,
    )

    monkeypatch.setattr(
        dependency_service.httpx,
        "Client",
        DummyClient,
    )

    monkeypatch.setattr(
        dependency_service,
        "query_osv_batch",
        lambda client, dependency_list: {
            "success": False,
            "results": [],
            "error": "OSV vulnerability query failed.",
        },
    )

    result = dependency_service.scan_dependencies(
        Path(tmp_path),
    )

    assert result["scan_status"] == "failed"
    assert result["dependencies_checked"] == 1
    assert result["findings_count"] == 0
    assert result["findings"] == []

    assert len(result["request_errors"]) == 1

    error = result["request_errors"][0]

    assert error["stage"] == "batch_query"
    assert (
        error["error"]
        == "OSV vulnerability query failed."
    )


def test_scan_dependencies_completes_successfully(
    monkeypatch,
    tmp_path,
):
    dependencies = [
        make_dependency(),
    ]

    monkeypatch.setattr(
        dependency_service,
        "collect_dependencies",
        lambda repository_path: dependencies,
    )

    monkeypatch.setattr(
        dependency_service.httpx,
        "Client",
        DummyClient,
    )

    monkeypatch.setattr(
        dependency_service,
        "query_osv_batch",
        lambda client, dependency_list: {
            "success": True,
            "results": [
                {
                    "vulns": [
                        {
                            "id": "TEST-1",
                        }
                    ]
                }
            ],
            "error": None,
        },
    )

    monkeypatch.setattr(
        dependency_service,
        "get_vulnerability_details",
        lambda client, vulnerability_id: {
            "success": True,
            "data": make_vulnerability(
                vulnerability_id
            ),
            "error": None,
        },
    )

    result = dependency_service.scan_dependencies(
        Path(tmp_path),
    )

    assert result["scan_status"] == "completed"
    assert result["dependencies_checked"] == 1
    assert result["findings_count"] == 1
    assert len(result["findings"]) == 1
    assert result["request_errors"] == []

    finding = result["findings"][0]

    assert finding["scanner"] == "OSV"
    assert finding["category"] == "DEPENDENCY"
    assert finding["vulnerability_id"] == "TEST-1"
    assert finding["package"] == "example-package"
    assert finding["version"] == "1.0.0"
    assert finding["source_file"] == "package-lock.json"


def test_scan_dependencies_preserves_successful_findings_when_detail_fails(
    monkeypatch,
    tmp_path,
):
    dependencies = [
        make_dependency(),
    ]

    monkeypatch.setattr(
        dependency_service,
        "collect_dependencies",
        lambda repository_path: dependencies,
    )

    monkeypatch.setattr(
        dependency_service.httpx,
        "Client",
        DummyClient,
    )

    monkeypatch.setattr(
        dependency_service,
        "query_osv_batch",
        lambda client, dependency_list: {
            "success": True,
            "results": [
                {
                    "vulns": [
                        {
                            "id": "TEST-SUCCESS",
                        },
                        {
                            "id": "TEST-FAILURE",
                        },
                    ]
                }
            ],
            "error": None,
        },
    )

    def fake_get_vulnerability_details(
        client,
        vulnerability_id,
    ):
        if vulnerability_id == "TEST-FAILURE":
            return {
                "success": False,
                "data": None,
                "error": (
                    "OSV vulnerability details "
                    "could not be retrieved."
                ),
            }

        return {
            "success": True,
            "data": make_vulnerability(
                vulnerability_id
            ),
            "error": None,
        }

    monkeypatch.setattr(
        dependency_service,
        "get_vulnerability_details",
        fake_get_vulnerability_details,
    )

    result = dependency_service.scan_dependencies(
        Path(tmp_path),
    )

    assert (
        result["scan_status"]
        == "completed_with_errors"
    )

    assert result["dependencies_checked"] == 1

    # The successfully retrieved vulnerability must remain.
    assert result["findings_count"] == 1
    assert len(result["findings"]) == 1

    finding = result["findings"][0]

    assert (
        finding["vulnerability_id"]
        == "TEST-SUCCESS"
    )

    # The failed detail request must be recorded without
    # discarding successful results.
    assert len(result["request_errors"]) == 1

    error = result["request_errors"][0]

    assert (
        error["stage"]
        == "vulnerability_details"
    )
    assert (
        error["vulnerability_id"]
        == "TEST-FAILURE"
    )
    assert (
        error["error"]
        == (
            "OSV vulnerability details "
            "could not be retrieved."
        )
    )
