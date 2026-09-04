from app.services import repository_service


def make_finding(scanner, category, rule_id):
    return {
        "scanner": scanner,
        "category": category,
        "rule_id": rule_id,
        "severity": "MEDIUM",
    }


def configure_common_pipeline_mocks(
    monkeypatch,
    *,
    semgrep_result=None,
    dependency_result=None,
    secret_result=None,
    config_result=None,
    sast_findings=None,
    dependency_findings=None,
    secret_findings=None,
    config_findings=None,
):
    """
    Replace external scanners and downstream processing
    with deterministic test doubles.

    These tests exercise repository-service orchestration,
    not the scanners themselves.
    """

    if semgrep_result is None:
        semgrep_result = {
            "success": True,
            "timed_out": False,
            "findings": [],
            "error": None,
        }

    if dependency_result is None:
        dependency_result = {
            "scan_status": "completed",
            "findings": [],
            "request_errors": [],
        }

    if secret_result is None:
        secret_result = {
            "scan_status": "completed",
            "findings": [],
            "processing_errors": [],
        }

    if config_result is None:
        config_result = {
            "scan_status": "completed",
            "findings": [],
            "processing_errors": [],
        }

    if sast_findings is None:
        sast_findings = []

    if dependency_findings is None:
        dependency_findings = []

    if secret_findings is None:
        secret_findings = []

    if config_findings is None:
        config_findings = []

    monkeypatch.setattr(
        repository_service,
        "resolve_repository_root",
        lambda extract_dir: extract_dir,
    )

    monkeypatch.setattr(
        repository_service,
        "profile_repository",
        lambda repository_root: {
            "total_files": 1,
        },
    )

    monkeypatch.setattr(
        repository_service,
        "run_semgrep",
        lambda repository_root: semgrep_result,
    )

    monkeypatch.setattr(
        repository_service,
        "scan_dependencies",
        lambda repository_root: dependency_result,
    )

    monkeypatch.setattr(
        repository_service,
        "scan_secrets",
        lambda repository_root: secret_result,
    )

    monkeypatch.setattr(
        repository_service,
        "scan_configurations",
        lambda repository_root: config_result,
    )

    monkeypatch.setattr(
        repository_service,
        "normalize_semgrep_findings",
        lambda results, repository_root: list(
            sast_findings
        ),
    )

    monkeypatch.setattr(
        repository_service,
        "normalize_osv_findings",
        lambda results, repository_root: list(
            dependency_findings
        ),
    )

    monkeypatch.setattr(
        repository_service,
        "normalize_secret_findings",
        lambda results, repository_root: list(
            secret_findings
        ),
    )

    monkeypatch.setattr(
        repository_service,
        "normalize_config_findings",
        lambda results, repository_root: list(
            config_findings
        ),
    )

    monkeypatch.setattr(
        repository_service,
        "create_severity_summary",
        lambda findings: {
            "total": len(findings),
        },
    )

    monkeypatch.setattr(
        repository_service,
        "correlate_findings",
        lambda findings: {
            "findings": list(findings),
            "correlated_groups": 0,
            "findings_merged": 0,
        },
    )

    monkeypatch.setattr(
        repository_service,
        "enrich_findings",
        lambda findings: list(findings),
    )


def test_pipeline_is_completed_when_all_mechanisms_complete(
    monkeypatch,
    tmp_path,
):
    configure_common_pipeline_mocks(
        monkeypatch,
    )

    result = repository_service.run_assessment_pipeline(
        tmp_path
    )

    assert result["assessment_status"] == "completed"

    statuses = result["mechanism_statuses"]

    assert statuses["sast"]["status"] == "completed"
    assert statuses["dependency"]["status"] == "completed"
    assert statuses["secret"]["status"] == "completed"
    assert (
        statuses["configuration"]["status"]
        == "completed"
    )


def test_dependency_completed_with_errors_makes_assessment_partial(
    monkeypatch,
    tmp_path,
):
    dependency_finding = make_finding(
        "OSV",
        "DEPENDENCY",
        "TEST-DEPENDENCY",
    )

    configure_common_pipeline_mocks(
        monkeypatch,
        dependency_result={
            "scan_status": "completed_with_errors",
            "findings": [],
            "request_errors": [
                {
                    "stage": "vulnerability_details",
                    "error": (
                        "OSV vulnerability details "
                        "could not be retrieved."
                    ),
                }
            ],
        },
        dependency_findings=[
            dependency_finding,
        ],
    )

    result = repository_service.run_assessment_pipeline(
        tmp_path
    )

    assert result["assessment_status"] == "partial"

    dependency_status = (
        result["mechanism_statuses"]["dependency"]
    )

    assert dependency_status["status"] == "partial"
    assert dependency_status["scanner"] == "OSV"
    assert dependency_status["findings_count"] == 1

    assert (
        dependency_status["error"]
        == (
            "OSV dependency assessment completed "
            "with one or more request errors."
        )
    )

    assert dependency_finding in result["raw_findings"]


def test_dependency_failure_makes_assessment_partial(
    monkeypatch,
    tmp_path,
):
    configure_common_pipeline_mocks(
        monkeypatch,
        dependency_result={
            "scan_status": "failed",
            "findings": [],
            "request_errors": [
                {
                    "stage": "batch_query",
                    "error": (
                        "OSV vulnerability query failed."
                    ),
                }
            ],
        },
    )

    result = repository_service.run_assessment_pipeline(
        tmp_path
    )

    assert result["assessment_status"] == "partial"

    dependency_status = (
        result["mechanism_statuses"]["dependency"]
    )

    assert dependency_status["status"] == "failed"

    assert (
        dependency_status["error"]
        == "OSV vulnerability query failed."
    )


def test_successful_findings_survive_another_scanner_failure(
    monkeypatch,
    tmp_path,
):
    sast_finding = make_finding(
        "Semgrep",
        "SAST",
        "TEST-SAST",
    )

    secret_finding = make_finding(
        "Ligtask",
        "SECRET",
        "TEST-SECRET",
    )

    config_finding = make_finding(
        "Ligtask",
        "CONFIGURATION",
        "TEST-CONFIG",
    )

    configure_common_pipeline_mocks(
        monkeypatch,
        dependency_result={
            "scan_status": "failed",
            "findings": [],
            "request_errors": [
                {
                    "stage": "batch_query",
                    "error": (
                        "OSV vulnerability query failed."
                    ),
                }
            ],
        },
        sast_findings=[
            sast_finding,
        ],
        secret_findings=[
            secret_finding,
        ],
        config_findings=[
            config_finding,
        ],
    )

    result = repository_service.run_assessment_pipeline(
        tmp_path
    )

    assert result["assessment_status"] == "partial"

    assert len(result["raw_findings"]) == 3

    assert sast_finding in result["raw_findings"]
    assert secret_finding in result["raw_findings"]
    assert config_finding in result["raw_findings"]

    assert (
        result["mechanism_statuses"]["sast"]["status"]
        == "completed"
    )

    assert (
        result["mechanism_statuses"]["dependency"]["status"]
        == "failed"
    )

    assert (
        result["mechanism_statuses"]["secret"]["status"]
        == "completed"
    )

    assert (
        result["mechanism_statuses"][
            "configuration"
        ]["status"]
        == "completed"
    )


def test_secret_completed_with_errors_makes_assessment_partial(
    monkeypatch,
    tmp_path,
):
    secret_finding = make_finding(
        "Ligtask",
        "SECRET",
        "TEST-SECRET",
    )

    configure_common_pipeline_mocks(
        monkeypatch,
        secret_result={
            "scan_status": "completed_with_errors",
            "findings": [],
            "processing_errors": [
                {
                    "error": (
                        "A repository file could not "
                        "be processed."
                    ),
                }
            ],
        },
        secret_findings=[
            secret_finding,
        ],
    )

    result = repository_service.run_assessment_pipeline(
        tmp_path
    )

    assert result["assessment_status"] == "partial"

    secret_status = (
        result["mechanism_statuses"]["secret"]
    )

    assert secret_status["status"] == "partial"
    assert secret_status["findings_count"] == 1
    assert secret_finding in result["raw_findings"]


def test_configuration_completed_with_errors_makes_assessment_partial(
    monkeypatch,
    tmp_path,
):
    config_finding = make_finding(
        "Ligtask",
        "CONFIGURATION",
        "TEST-CONFIG",
    )

    configure_common_pipeline_mocks(
        monkeypatch,
        config_result={
            "scan_status": "completed_with_errors",
            "findings": [],
            "processing_errors": [
                {
                    "error": (
                        "A configuration file could "
                        "not be processed."
                    ),
                }
            ],
        },
        config_findings=[
            config_finding,
        ],
    )

    result = repository_service.run_assessment_pipeline(
        tmp_path
    )

    assert result["assessment_status"] == "partial"

    configuration_status = (
        result["mechanism_statuses"][
            "configuration"
        ]
    )

    assert configuration_status["status"] == "partial"
    assert configuration_status["findings_count"] == 1
    assert config_finding in result["raw_findings"]


def test_semgrep_timeout_makes_assessment_partial(
    monkeypatch,
    tmp_path,
):
    configure_common_pipeline_mocks(
        monkeypatch,
        semgrep_result={
            "success": False,
            "timed_out": True,
            "findings": [],
            "error": "Semgrep analysis timed out.",
        },
    )

    result = repository_service.run_assessment_pipeline(
        tmp_path
    )

    assert result["assessment_status"] == "partial"

    sast_status = result["mechanism_statuses"]["sast"]

    assert sast_status["status"] == "timed_out"
    assert sast_status["findings_count"] == 0
    assert (
        sast_status["error"]
        == "Semgrep analysis timed out."
    )