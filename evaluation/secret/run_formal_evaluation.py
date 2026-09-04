import csv
import hashlib
import json
import math
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"

CASES_PATH = SCRIPT_DIR / "cases.csv"
FIXTURES_DIR = SCRIPT_DIR / "fixtures"
RESULTS_DIR = SCRIPT_DIR / "results"
RESULT_PATH = RESULTS_DIR / "formal-results.json"

EXPECTED_CASE_COUNT = 15

sys.path.insert(
    0,
    str(BACKEND_DIR),
)

from app.services.secret_service import scan_secrets


PRIVACY_PROBES = {
    "SEC-001": (
        "AKIA"
        "ABCDEFGHIJKLMNOP"
    ),
    "SEC-002": (
        "ghp_"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    ),
    "SEC-003": (
        "-----BEGIN PRIVATE KEY-----"
    ),
    "SEC-004": (
        "postgresql://synthetic_user:"
        "synthetic_password@localhost/testdb"
    ),
    "SEC-005": (
        "SYNTHETICVALUE12345"
    ),
}


def load_cases():
    with CASES_PATH.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        rows = list(
            csv.DictReader(file)
        )

    if len(rows) != EXPECTED_CASE_COUNT:
        raise ValueError(
            f"Expected {EXPECTED_CASE_COUNT} "
            f"cases, found {len(rows)}."
        )

    ids = [
        row["case_id"]
        for row in rows
    ]

    if len(set(ids)) != EXPECTED_CASE_COUNT:
        raise ValueError(
            "Case IDs must be unique."
        )

    return rows


def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(
            lambda: file.read(65536),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest().upper()


def safe_divide(numerator, denominator):
    if denominator == 0:
        return None

    return numerator / denominator


def finite_or_none(value):
    if value is None:
        return None

    if not math.isfinite(value):
        return None

    return value


def evaluate_case(case):
    case_id = case["case_id"]
    case_group = case["case_group"]
    expected_finding = (
        case["expected_finding"].lower()
        == "true"
    )
    expected_rule_id = (
        case["expected_rule_id"]
    )

    fixture_dir = (
        FIXTURES_DIR / case_id
    )
    fixture_file = (
        fixture_dir / "sample.txt"
    )

    if not fixture_file.is_file():
        raise FileNotFoundError(
            f"Missing fixture for {case_id}: "
            f"{fixture_file}"
        )

    fixture_hash = sha256_file(
        fixture_file
    )

    started = time.perf_counter()

    result = scan_secrets(
        fixture_dir
    )

    elapsed = (
        time.perf_counter()
        - started
    )

    findings = result.get(
        "findings",
        [],
    )

    if not isinstance(findings, list):
        raise TypeError(
            f"{case_id}: findings must "
            "be a list."
        )

    observed_rule_ids = [
        finding.get("rule_id")
        for finding in findings
    ]

    observed_rule_ids = [
        rule_id
        for rule_id in observed_rule_ids
        if rule_id is not None
    ]

    if expected_finding:
        expected_rule_detected = (
            expected_rule_id
            in observed_rule_ids
        )

        unexpected_rule_ids = [
            rule_id
            for rule_id in observed_rule_ids
            if rule_id
            != expected_rule_id
        ]

        if expected_rule_detected:
            classification = "TP"
        else:
            classification = "FN"

    else:
        expected_rule_detected = False
        unexpected_rule_ids = list(
            observed_rule_ids
        )

        if findings:
            classification = "FP"
        else:
            classification = "TN"

    privacy_probe = (
        PRIVACY_PROBES.get(case_id)
    )

    privacy_passed = None

    if privacy_probe is not None:
        serialized_findings = json.dumps(
            findings,
            sort_keys=True,
            ensure_ascii=False,
        )

        privacy_passed = (
            privacy_probe
            not in serialized_findings
        )

    return {
        "case_id": case_id,
        "case_group": case_group,
        "target_rule": case["target_rule"],
        "expected_finding": (
            expected_finding
        ),
        "expected_rule_id": (
            expected_rule_id
        ),
        "classification": classification,
        "expected_rule_detected": (
            expected_rule_detected
        ),
        "findings_count": len(findings),
        "observed_rule_ids": (
            observed_rule_ids
        ),
        "unexpected_rule_ids": (
            unexpected_rule_ids
        ),
        "scan_status": result.get(
            "scan_status"
        ),
        "files_scanned": result.get(
            "files_scanned"
        ),
        "files_skipped": result.get(
            "files_skipped"
        ),
        "processing_errors": result.get(
            "processing_errors",
            [],
        ),
        "processing_time_seconds": (
            round(elapsed, 6)
        ),
        "fixture_sha256": fixture_hash,
        "privacy_probe_checked": (
            privacy_probe is not None
        ),
        "privacy_value_not_returned": (
            privacy_passed
        ),
    }


def main():
    if RESULT_PATH.exists():
        raise FileExistsError(
            "Formal result already exists. "
            "Refusing to overwrite it."
        )

    cases = load_cases()

    case_results = []

    total_started = time.perf_counter()

    for case in cases:
        case_result = evaluate_case(
            case
        )
        case_results.append(
            case_result
        )

    total_elapsed = (
        time.perf_counter()
        - total_started
    )

    tp = sum(
        result["classification"] == "TP"
        for result in case_results
    )
    fp = sum(
        result["classification"] == "FP"
        for result in case_results
    )
    fn = sum(
        result["classification"] == "FN"
        for result in case_results
    )
    tn = sum(
        result["classification"] == "TN"
        for result in case_results
    )

    precision = safe_divide(
        tp,
        tp + fp,
    )
    recall = safe_divide(
        tp,
        tp + fn,
    )
    specificity = safe_divide(
        tn,
        tn + fp,
    )
    accuracy = safe_divide(
        tp + tn,
        len(case_results),
    )

    if (
        precision is None
        or recall is None
        or precision + recall == 0
    ):
        f1 = None
    else:
        f1 = (
            2
            * precision
            * recall
            / (precision + recall)
        )

    privacy_results = [
        result
        for result in case_results
        if result[
            "privacy_probe_checked"
        ]
    ]

    privacy_pass_count = sum(
        result[
            "privacy_value_not_returned"
        ]
        is True
        for result in privacy_results
    )

    privacy_fail_count = sum(
        result[
            "privacy_value_not_returned"
        ]
        is False
        for result in privacy_results
    )

    unexpected_finding_cases = [
        result["case_id"]
        for result in case_results
        if result["unexpected_rule_ids"]
    ]

    non_completed_cases = [
        result["case_id"]
        for result in case_results
        if result["scan_status"]
        != "completed"
    ]

    cases_with_processing_errors = [
        result["case_id"]
        for result in case_results
        if result["processing_errors"]
    ]

    output = {
        "evaluation": (
            "Controlled secret-detection "
            "evaluation"
        ),
        "execution_timestamp_utc": (
            datetime.now(timezone.utc)
            .isoformat()
        ),
        "production_function": (
            "app.services.secret_service."
            "scan_secrets"
        ),
        "case_count": len(case_results),
        "summary": {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "precision": finite_or_none(
                precision
            ),
            "recall": finite_or_none(
                recall
            ),
            "specificity": finite_or_none(
                specificity
            ),
            "accuracy": finite_or_none(
                accuracy
            ),
            "f1_score": finite_or_none(
                f1
            ),
            "privacy_checks": len(
                privacy_results
            ),
            "privacy_passed": (
                privacy_pass_count
            ),
            "privacy_failed": (
                privacy_fail_count
            ),
            "unexpected_finding_cases": (
                unexpected_finding_cases
            ),
            "non_completed_cases": (
                non_completed_cases
            ),
            "cases_with_processing_errors": (
                cases_with_processing_errors
            ),
            "total_processing_time_seconds": (
                round(
                    total_elapsed,
                    6,
                )
            ),
        },
        "cases": case_results,
    }

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    RESULT_PATH.write_text(
        json.dumps(
            output,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )

    print(
        f"Cases: {len(case_results)}"
    )
    print(f"TP: {tp}")
    print(f"FP: {fp}")
    print(f"FN: {fn}")
    print(f"TN: {tn}")

    if precision is not None:
        print(
            f"Precision: {precision:.4f}"
        )

    if recall is not None:
        print(
            f"Recall: {recall:.4f}"
        )

    if specificity is not None:
        print(
            f"Specificity: "
            f"{specificity:.4f}"
        )

    if accuracy is not None:
        print(
            f"Accuracy: {accuracy:.4f}"
        )

    if f1 is not None:
        print(
            f"F1: {f1:.4f}"
        )

    print(
        "Privacy checks passed: "
        f"{privacy_pass_count}/"
        f"{len(privacy_results)}"
    )

    print(
        "Unexpected finding cases: "
        f"{len(unexpected_finding_cases)}"
    )

    print(
        "Non-completed cases: "
        f"{len(non_completed_cases)}"
    )

    print(
        "Cases with processing errors: "
        f"{len(cases_with_processing_errors)}"
    )

    print(
        "Total processing time: "
        f"{total_elapsed:.6f} seconds"
    )

    print(
        f"Result: {RESULT_PATH}"
    )


if __name__ == "__main__":
    main()
