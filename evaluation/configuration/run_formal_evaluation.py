import csv
import hashlib
import json
import sys
import time

from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parents[1]
BACKEND_DIR = PROJECT_ROOT / "backend"

CASES_PATH = BASE_DIR / "cases.csv"
FIXTURES_DIR = BASE_DIR / "fixtures"
RESULTS_DIR = BASE_DIR / "results"
RESULT_PATH = RESULTS_DIR / "formal-results.json"


if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


from app.services.config_service import scan_configurations


def calculate_sha256(path: Path):
    hasher = hashlib.sha256()

    with path.open("rb") as file_handle:
        for chunk in iter(
            lambda: file_handle.read(8192),
            b"",
        ):
            hasher.update(chunk)

    return hasher.hexdigest().upper()


def safe_divide(numerator, denominator):
    if denominator == 0:
        return None

    return numerator / denominator


def load_cases():
    with CASES_PATH.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file_handle:
        return list(
            csv.DictReader(file_handle)
        )


def validate_cases(cases):
    required_columns = {
        "case_id",
        "case_group",
        "target_rule",
        "expected_finding",
        "expected_rule_id",
        "description",
    }

    if not cases:
        raise RuntimeError(
            "No configuration evaluation cases were found."
        )

    missing_columns = (
        required_columns - set(cases[0].keys())
    )

    if missing_columns:
        raise RuntimeError(
            "The configuration cases file is missing "
            f"required columns: "
            f"{sorted(missing_columns)}"
        )

    case_ids = [
        case["case_id"]
        for case in cases
    ]

    if len(case_ids) != len(set(case_ids)):
        raise RuntimeError(
            "Duplicate configuration case IDs were found."
        )

    for case in cases:
        expected_finding = (
            case["expected_finding"]
            .strip()
            .lower()
        )

        if expected_finding not in {
            "true",
            "false",
        }:
            raise RuntimeError(
                f"{case['case_id']} has an invalid "
                "expected_finding value."
            )

        if expected_finding == "true":
            if (
                not case["expected_rule_id"].strip()
                or case["expected_rule_id"] == "NONE"
            ):
                raise RuntimeError(
                    f"{case['case_id']} requires an "
                    "expected rule ID."
                )


def classify_case(
    expected_finding,
    expected_rule_id,
    observed_rule_ids,
):
    if expected_finding:
        if expected_rule_id in observed_rule_ids:
            return "TP"

        return "FN"

    if observed_rule_ids:
        return "FP"

    return "TN"


def calculate_metrics(
    true_positives,
    false_positives,
    false_negatives,
    true_negatives,
):
    precision = safe_divide(
        true_positives,
        true_positives + false_positives,
    )

    recall = safe_divide(
        true_positives,
        true_positives + false_negatives,
    )

    specificity = safe_divide(
        true_negatives,
        true_negatives + false_positives,
    )

    accuracy = safe_divide(
        true_positives + true_negatives,
        (
            true_positives
            + false_positives
            + false_negatives
            + true_negatives
        ),
    )

    if (
        precision is None
        or recall is None
        or precision + recall == 0
    ):
        f1_score = None
    else:
        f1_score = (
            2
            * precision
            * recall
            / (precision + recall)
        )

    return {
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "accuracy": accuracy,
        "f1_score": f1_score,
    }


def main():
    if RESULT_PATH.exists():
        raise RuntimeError(
            "Formal configuration results already exist. "
            "Refusing to overwrite the frozen result."
        )

    cases = load_cases()
    validate_cases(cases)

    case_results = []

    true_positives = 0
    false_positives = 0
    false_negatives = 0
    true_negatives = 0

    unexpected_finding_cases = 0
    non_completed_cases = 0
    cases_with_processing_errors = 0

    total_processing_time_seconds = 0.0

    per_rule = {}

    for case in cases:
        case_id = case["case_id"]

        fixture_directory = (
            FIXTURES_DIR / case_id
        )

        dockerfile_path = (
            fixture_directory / "Dockerfile"
        )

        if not dockerfile_path.is_file():
            raise RuntimeError(
                f"Missing Dockerfile for {case_id}."
            )

        expected_finding = (
            case["expected_finding"]
            .strip()
            .lower()
            == "true"
        )

        expected_rule_id = (
            case["expected_rule_id"].strip()
        )

        start_time = time.perf_counter()

        scan_result = scan_configurations(
            fixture_directory
        )

        processing_time_seconds = (
            time.perf_counter() - start_time
        )

        total_processing_time_seconds += (
            processing_time_seconds
        )

        findings = scan_result.get(
            "findings",
            [],
        )

        observed_rule_ids = [
            finding.get("rule_id")
            for finding in findings
            if finding.get("rule_id")
        ]

        unique_observed_rule_ids = sorted(
            set(observed_rule_ids)
        )

        classification = classify_case(
            expected_finding,
            expected_rule_id,
            unique_observed_rule_ids,
        )

        if classification == "TP":
            true_positives += 1
        elif classification == "FP":
            false_positives += 1
        elif classification == "FN":
            false_negatives += 1
        elif classification == "TN":
            true_negatives += 1

        if expected_finding:
            unexpected_rule_ids = sorted(
                rule_id
                for rule_id
                in unique_observed_rule_ids
                if rule_id != expected_rule_id
            )
        else:
            unexpected_rule_ids = (
                unique_observed_rule_ids
            )

        if unexpected_rule_ids:
            unexpected_finding_cases += 1

        scan_status = scan_result.get(
            "scan_status"
        )

        processing_errors = scan_result.get(
            "processing_errors",
            [],
        )

        if scan_status != "completed":
            non_completed_cases += 1

        if processing_errors:
            cases_with_processing_errors += 1

        if expected_finding:
            rule_summary = per_rule.setdefault(
                expected_rule_id,
                {
                    "expected_positive_cases": 0,
                    "detected_cases": 0,
                    "missed_cases": 0,
                },
            )

            rule_summary[
                "expected_positive_cases"
            ] += 1

            if classification == "TP":
                rule_summary[
                    "detected_cases"
                ] += 1
            else:
                rule_summary[
                    "missed_cases"
                ] += 1

        case_results.append({
            "case_id": case_id,
            "case_group": case["case_group"],
            "target_rule": case["target_rule"],
            "description": case["description"],
            "expected_finding": expected_finding,
            "expected_rule_id": (
                expected_rule_id
                if expected_finding
                else None
            ),
            "classification": classification,
            "fixture_sha256": calculate_sha256(
                dockerfile_path
            ),
            "processing_time_seconds": (
                processing_time_seconds
            ),
            "scan_status": scan_status,
            "files_scanned": scan_result.get(
                "files_scanned"
            ),
            "findings_count": scan_result.get(
                "findings_count"
            ),
            "observed_rule_ids": (
                unique_observed_rule_ids
            ),
            "unexpected_rule_ids": (
                unexpected_rule_ids
            ),
            "processing_errors": (
                processing_errors
            ),
            "findings": findings,
        })

    metrics = calculate_metrics(
        true_positives,
        false_positives,
        false_negatives,
        true_negatives,
    )

    summary = {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "true_negatives": true_negatives,
        **metrics,
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
            total_processing_time_seconds
        ),
    }

    formal_result = {
        "evaluation": (
            "controlled_configuration_assessment"
        ),
        "execution_timestamp_utc": (
            datetime.now(timezone.utc).isoformat()
        ),
        "production_function": (
            "app.services.config_service."
            "scan_configurations"
        ),
        "case_count": len(cases),
        "summary": summary,
        "per_rule": per_rule,
        "cases": case_results,
    }

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    RESULT_PATH.write_text(
        json.dumps(
            formal_result,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )

    print(
        "Formal configuration evaluation completed."
    )
    print(f"Cases: {len(cases)}")
    print(
        "TP/FP/FN/TN: "
        f"{true_positives}/"
        f"{false_positives}/"
        f"{false_negatives}/"
        f"{true_negatives}"
    )

    for metric_name in (
        "precision",
        "recall",
        "specificity",
        "accuracy",
        "f1_score",
    ):
        metric_value = metrics[
            metric_name
        ]

        if metric_value is None:
            display_value = "N/A"
        else:
            display_value = (
                f"{metric_value:.4f}"
            )

        print(
            f"{metric_name}: "
            f"{display_value}"
        )

    print(
        "Unexpected finding cases: "
        f"{unexpected_finding_cases}"
    )
    print(
        "Non-completed cases: "
        f"{non_completed_cases}"
    )
    print(
        "Cases with processing errors: "
        f"{cases_with_processing_errors}"
    )
    print(
        "Total processing time: "
        f"{total_processing_time_seconds:.6f} "
        "seconds"
    )
    print(
        f"Raw result: {RESULT_PATH}"
    )


if __name__ == "__main__":
    main()
