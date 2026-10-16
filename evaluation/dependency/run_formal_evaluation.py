import csv
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent

BACKEND_DIR = PROJECT_ROOT / "backend"
FIXTURES_DIR = SCRIPT_DIR / "fixtures"
GROUND_TRUTH_PATH = (
    SCRIPT_DIR
    / "ground-truth"
    / "ground-truth-summary.csv"
)

RESULTS_DIR = SCRIPT_DIR / "results"
RESULT_PATH = RESULTS_DIR / "formal-results.json"

EXPECTED_CASE_COUNT = 10

sys.path.insert(
    0,
    str(BACKEND_DIR),
)

from app.services.dependency_service import (  # noqa: E402
    scan_dependencies,
)


def parse_osv_ids(value):
    value = (value or "").strip()

    if not value or value.upper() == "NONE":
        return set()

    return {
        item.strip()
        for item in value.split(";")
        if item.strip()
    }


def load_ground_truth():
    cases = []

    with GROUND_TRUTH_PATH.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        reader = csv.DictReader(file)

        required = {
            "case_id",
            "package",
            "version",
            "ecosystem",
            "intended_group",
            "ground_truth_state",
            "eligible",
            "osv_ids",
            "collected_at_utc",
            "source_endpoint",
            "artifact_sha256",
        }

        if set(reader.fieldnames or []) != required:
            raise ValueError(
                "Ground-truth CSV schema does not "
                "match the expected format."
            )

        for row in reader:
            cases.append({
                "case_id": row["case_id"].strip(),
                "package": row["package"].strip(),
                "version": row["version"].strip(),
                "ecosystem": row["ecosystem"].strip(),
                "ground_truth_state": (
                    row["ground_truth_state"].strip()
                ),
                "expected_osv_ids": parse_osv_ids(
                    row["osv_ids"]
                ),
            })

    if len(cases) != EXPECTED_CASE_COUNT:
        raise ValueError(
            f"Expected {EXPECTED_CASE_COUNT} "
            f"ground-truth cases, found "
            f"{len(cases)}."
        )

    return cases


def classify_case(
    ground_truth_state,
    expected_ids,
    observed_ids,
):
    expected_positive = (
        ground_truth_state == "vulnerable"
    )

    expected_detected = bool(
        expected_ids & observed_ids
    )

    unexpected_ids = (
        observed_ids - expected_ids
    )

    missing_ids = (
        expected_ids - observed_ids
    )

    if expected_positive:
        classification = (
            "TP"
            if expected_detected
            else "FN"
        )
    else:
        classification = (
            "TN"
            if not observed_ids
            else "REQUIRES_ADJUDICATION"
        )

    return {
        "classification": classification,
        "matched_osv_ids": sorted(
            expected_ids & observed_ids
        ),
        "missing_osv_ids": sorted(
            missing_ids
        ),
        "unexpected_osv_ids": sorted(
            unexpected_ids
        ),
    }


def evaluate_case(case):
    fixture_path = (
        FIXTURES_DIR
        / case["case_id"]
    )

    if not fixture_path.is_dir():
        raise FileNotFoundError(
            f"Missing fixture: "
            f"{case['case_id']}"
        )

    start = time.perf_counter()

    result = scan_dependencies(
        fixture_path
    )

    elapsed = (
        time.perf_counter() - start
    )

    findings = result.get(
        "findings",
        [],
    )

    relevant_findings = []

    for finding in findings:
        if (
            finding.get("package")
            == case["package"]
            and finding.get("version")
            == case["version"]
            and finding.get("ecosystem")
            == case["ecosystem"]
        ):
            relevant_findings.append(
                finding
            )

    observed_ids = {
        finding["vulnerability_id"]
        for finding in relevant_findings
        if finding.get("vulnerability_id")
    }

    scoring = classify_case(
        case["ground_truth_state"],
        case["expected_osv_ids"],
        observed_ids,
    )

    return {
        "case_id": case["case_id"],
        "package": case["package"],
        "version": case["version"],
        "ecosystem": case["ecosystem"],
        "ground_truth_state": (
            case["ground_truth_state"]
        ),
        "expected_osv_ids": sorted(
            case["expected_osv_ids"]
        ),
        "dependencies_checked": result.get(
            "dependencies_checked"
        ),
        "scan_status": result.get(
            "scan_status"
        ),
        "findings_count": result.get(
            "findings_count"
        ),
        "observed_osv_ids": sorted(
            observed_ids
        ),
        "matched_osv_ids": scoring[
            "matched_osv_ids"
        ],
        "missing_osv_ids": scoring[
            "missing_osv_ids"
        ],
        "unexpected_osv_ids": scoring[
            "unexpected_osv_ids"
        ],
        "classification": scoring[
            "classification"
        ],
        "request_errors": result.get(
            "request_errors",
            [],
        ),
        "processing_seconds": round(
            elapsed,
            6,
        ),
    }


def build_summary(results):
    counts = {
        "TP": 0,
        "FN": 0,
        "TN": 0,
        "REQUIRES_ADJUDICATION": 0,
    }

    expected_ids = set()
    observed_ids = set()
    matched_ids = set()
    missing_ids = set()
    unexpected_ids = set()

    for result in results:
        classification = result[
            "classification"
        ]

        counts[classification] += 1

        expected_ids.update(
            result["expected_osv_ids"]
        )
        observed_ids.update(
            result["observed_osv_ids"]
        )
        matched_ids.update(
            result["matched_osv_ids"]
        )
        missing_ids.update(
            result["missing_osv_ids"]
        )
        unexpected_ids.update(
            result["unexpected_osv_ids"]
        )

    positive_cases = (
        counts["TP"] + counts["FN"]
    )

    case_recall = (
        counts["TP"] / positive_cases
        if positive_cases
        else None
    )

    id_recall = (
        len(matched_ids) / len(expected_ids)
        if expected_ids
        else None
    )

    return {
        "case_counts": counts,
        "positive_cases": positive_cases,
        "case_recall": case_recall,
        "expected_unique_osv_ids": len(
            expected_ids
        ),
        "observed_unique_osv_ids": len(
            observed_ids
        ),
        "matched_unique_osv_ids": len(
            matched_ids
        ),
        "missing_unique_osv_ids": len(
            missing_ids
        ),
        "unexpected_unique_osv_ids": len(
            unexpected_ids
        ),
        "osv_id_recall": id_recall,
        "missing_osv_ids": sorted(
            missing_ids
        ),
        "unexpected_osv_ids": sorted(
            unexpected_ids
        ),
        "total_processing_seconds": round(
            sum(
                result["processing_seconds"]
                for result in results
            ),
            6,
        ),
    }


def main():
    if RESULT_PATH.exists():
        raise RuntimeError(
            "Formal result already exists. "
            "Refusing to overwrite it."
        )

    cases = load_ground_truth()

    results = []

    for case in cases:
        print(
            f"Running {case['case_id']}: "
            f"{case['package']}@"
            f"{case['version']}"
        )

        results.append(
            evaluate_case(case)
        )

    output = {
        "evaluation": (
            "TALGED dependency assessment"
        ),
        "scope": (
            "npm package-lock.json exact "
            "package/version OSV matching"
        ),
        "executed_at_utc": (
            datetime.now(timezone.utc)
            .isoformat()
        ),
        "case_count": len(results),
        "summary": build_summary(
            results
        ),
        "cases": results,
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
    )

    print()
    print(
        "FORMAL DEPENDENCY EVALUATION COMPLETE"
    )
    print("=" * 72)

    summary = output["summary"]

    print(
        f"Cases: {len(results)}"
    )
    print(
        f"TP: "
        f"{summary['case_counts']['TP']}"
    )
    print(
        f"FN: "
        f"{summary['case_counts']['FN']}"
    )
    print(
        f"TN: "
        f"{summary['case_counts']['TN']}"
    )
    print(
        "Requires adjudication: "
        f"{summary['case_counts']['REQUIRES_ADJUDICATION']}"
    )

    if summary["case_recall"] is not None:
        print(
            "Case recall: "
            f"{summary['case_recall']:.4f}"
        )

    if summary["osv_id_recall"] is not None:
        print(
            "OSV-ID recall: "
            f"{summary['osv_id_recall']:.4f}"
        )

    print(
        "Unexpected unique OSV IDs: "
        f"{summary['unexpected_unique_osv_ids']}"
    )

    print(
        "Result: "
        f"{RESULT_PATH.relative_to(PROJECT_ROOT)}"
    )


if __name__ == "__main__":
    main()
