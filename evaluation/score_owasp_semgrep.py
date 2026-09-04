import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

GROUND_TRUTH_PATH = (
    PROJECT_ROOT
    / "evaluation"
    / "benchmarks"
    / "BenchmarkJava"
    / "expectedresults-1.2.csv"
)

SEMGREP_RESULTS_PATH = (
    PROJECT_ROOT
    / "evaluation"
    / "results"
    / "owasp-semgrep-formal.json"
)


# OWASP Benchmark category -> accepted CWE identifiers from
# the frozen evaluation methodology.
#
# The crypto category intentionally accepts CWE-326 and CWE-327.
# See evaluation/README.md for the documented semantic rationale.
CATEGORY_TO_CWES = {
    "pathtraver": {"22"},
    "cmdi": {"78"},
    "xss": {"79"},
    "sqli": {"89"},
    "ldapi": {"90"},
    "crypto": {"326", "327"},
    "hash": {"328"},
    "weakrand": {"330"},
    "trustbound": {"501"},
    "securecookie": {"614"},
    "xpathi": {"643"},
}


TEST_ID_PATTERN = re.compile(r"(BenchmarkTest\d{5})")
CWE_PATTERN = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def load_ground_truth():
    cases = {}

    with GROUND_TRUTH_PATH.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        reader = csv.reader(
            line
            for line in file
            if not line.startswith("#")
        )

        for row in reader:
            if len(row) < 4:
                continue

            test_id = row[0].strip()
            category = row[1].strip()
            vulnerable_text = row[2].strip().lower()
            cwe = row[3].strip()

            if not TEST_ID_PATTERN.fullmatch(test_id):
                continue

            if vulnerable_text not in {"true", "false"}:
                raise ValueError(
                    f"Invalid vulnerability label for {test_id}: "
                    f"{row[2]}"
                )

            if category not in CATEGORY_TO_CWES:
                raise ValueError(
                    f"Unmapped benchmark category: {category}"
                )

            if test_id in cases:
                raise ValueError(
                    f"Duplicate benchmark test ID: {test_id}"
                )

            cases[test_id] = {
                "test_id": test_id,
                "category": category,
                "vulnerable": vulnerable_text == "true",
                "ground_truth_cwe": cwe,
            }

    return cases


def load_semgrep_results():
    # The preserved formal artifact was written by Windows
    # PowerShell redirection and is UTF-16. It is intentionally
    # read without modifying the original raw file.
    with SEMGREP_RESULTS_PATH.open(
        "r",
        encoding="utf-16",
    ) as file:
        data = json.load(file)

    return data


def extract_test_id(path):
    match = TEST_ID_PATTERN.search(path)

    if match is None:
        return None

    return match.group(1)


def extract_cwes(result):
    metadata = (
        result
        .get("extra", {})
        .get("metadata", {})
    )

    raw_cwes = metadata.get("cwe", [])

    if isinstance(raw_cwes, str):
        raw_cwes = [raw_cwes]

    cwes = set()

    for value in raw_cwes:
        for match in CWE_PATTERN.finditer(str(value)):
            cwes.add(match.group(1))

    return cwes


def corresponding_finding(category, finding_cwes):
    accepted_cwes = CATEGORY_TO_CWES[category]

    return bool(accepted_cwes & finding_cwes)


def safe_divide(numerator, denominator):
    if denominator == 0:
        return None

    return numerator / denominator


def calculate_metrics(counts):
    tp = counts["TP"]
    fp = counts["FP"]
    fn = counts["FN"]
    tn = counts["TN"]

    precision = safe_divide(tp, tp + fp)
    recall = safe_divide(tp, tp + fn)
    false_positive_rate = safe_divide(fp, fp + tn)
    accuracy = safe_divide(
        tp + tn,
        tp + fp + fn + tn,
    )

    if (
        precision is not None
        and recall is not None
        and precision + recall != 0
    ):
        f1 = (
            2
            * precision
            * recall
            / (precision + recall)
        )
    else:
        f1 = None

    return {
        "precision": precision,
        "recall": recall,
        "false_positive_rate": false_positive_rate,
        "accuracy": accuracy,
        "f1": f1,
    }


def format_metric(value):
    if value is None:
        return "N/A"

    return f"{value:.4f}"


def main():
    cases = load_ground_truth()
    semgrep_data = load_semgrep_results()

    results = semgrep_data.get("results", [])
    errors = semgrep_data.get("errors", [])
    skipped = (
        semgrep_data
        .get("paths", {})
        .get("skipped", [])
    )

    if len(cases) != 2740:
        raise ValueError(
            "Expected 2740 benchmark cases, "
            f"found {len(cases)}."
        )

    if errors:
        raise ValueError(
            f"Formal Semgrep artifact contains "
            f"{len(errors)} errors."
        )

    if skipped:
        raise ValueError(
            f"Formal Semgrep artifact contains "
            f"{len(skipped)} skipped targets."
        )

    matching_findings_by_test = defaultdict(list)

    unrelated_findings = []
    unknown_test_findings = []
    findings_without_cwe = []

    rule_counts = Counter()

    for result in results:
        path = str(result.get("path", ""))
        rule_id = str(result.get("check_id", ""))

        rule_counts[rule_id] += 1

        test_id = extract_test_id(path)
        finding_cwes = extract_cwes(result)

        if test_id is None or test_id not in cases:
            unknown_test_findings.append(result)
            continue

        if not finding_cwes:
            findings_without_cwe.append(result)
            continue

        category = cases[test_id]["category"]

        if corresponding_finding(
            category,
            finding_cwes,
        ):
            matching_findings_by_test[test_id].append(
                result
            )
        else:
            unrelated_findings.append(result)

    classifications = {}
    overall_counts = Counter()
    category_counts = defaultdict(Counter)

    for test_id, case in cases.items():
        detected = bool(
            matching_findings_by_test.get(test_id)
        )

        vulnerable = case["vulnerable"]

        if vulnerable and detected:
            classification = "TP"
        elif vulnerable and not detected:
            classification = "FN"
        elif not vulnerable and detected:
            classification = "FP"
        else:
            classification = "TN"

        classifications[test_id] = classification
        overall_counts[classification] += 1
        category_counts[
            case["category"]
        ][classification] += 1

    total_classified = sum(overall_counts.values())

    if total_classified != 2740:
        raise ValueError(
            "Classification count mismatch: "
            f"{total_classified}"
        )

    print("OWASP BENCHMARK SAST SCORING")
    print("=" * 72)

    print(f"Semgrep version: {semgrep_data.get('version')}")
    print(
        "Engine requested: "
        f"{semgrep_data.get('engine_requested')}"
    )
    print(f"Benchmark cases: {len(cases)}")
    print(f"Raw Semgrep findings: {len(results)}")
    print(f"Semgrep errors: {len(errors)}")
    print(f"Skipped targets: {len(skipped)}")
    print()

    print("OVERALL CONFUSION MATRIX")
    print("-" * 72)

    for label in ("TP", "FP", "FN", "TN"):
        print(
            f"{label}: "
            f"{overall_counts[label]}"
        )

    overall_metrics = calculate_metrics(
        overall_counts
    )

    print()
    print("OVERALL METRICS")
    print("-" * 72)
    print(
        "Precision: "
        f"{format_metric(overall_metrics['precision'])}"
    )
    print(
        "Recall: "
        f"{format_metric(overall_metrics['recall'])}"
    )
    print(
        "False-positive rate: "
        f"{format_metric(overall_metrics['false_positive_rate'])}"
    )
    print(
        "Accuracy: "
        f"{format_metric(overall_metrics['accuracy'])}"
    )
    print(
        "F1: "
        f"{format_metric(overall_metrics['f1'])}"
    )

    print()
    print("PER-CATEGORY RESULTS")
    print("=" * 72)

    for category in CATEGORY_TO_CWES:
        counts = category_counts[category]
        metrics = calculate_metrics(counts)

        total = sum(counts.values())

        print()
        print(f"[{category}]")
        print(f"Cases: {total}")
        print(
            "TP={tp} FP={fp} FN={fn} TN={tn}".format(
                tp=counts["TP"],
                fp=counts["FP"],
                fn=counts["FN"],
                tn=counts["TN"],
            )
        )
        print(
            "Precision="
            f"{format_metric(metrics['precision'])} "
            "Recall="
            f"{format_metric(metrics['recall'])} "
            "FPR="
            f"{format_metric(metrics['false_positive_rate'])} "
            "F1="
            f"{format_metric(metrics['f1'])}"
        )

    print()
    print("FINDING ACCOUNTING")
    print("=" * 72)

    matching_raw_count = sum(
        len(items)
        for items in matching_findings_by_test.values()
    )

    detected_case_count = len(
        matching_findings_by_test
    )

    print(
        "Raw findings matching benchmark category: "
        f"{matching_raw_count}"
    )
    print(
        "Benchmark cases with corresponding findings: "
        f"{detected_case_count}"
    )
    print(
        "Unrelated findings in benchmark files: "
        f"{len(unrelated_findings)}"
    )
    print(
        "Findings without CWE metadata: "
        f"{len(findings_without_cwe)}"
    )
    print(
        "Findings outside recognized benchmark cases: "
        f"{len(unknown_test_findings)}"
    )

    accounted_findings = (
        matching_raw_count
        + len(unrelated_findings)
        + len(findings_without_cwe)
        + len(unknown_test_findings)
    )

    print(
        "Total findings accounted for: "
        f"{accounted_findings}"
    )

    if accounted_findings != len(results):
        raise ValueError(
            "Finding accounting mismatch."
        )


if __name__ == "__main__":
    main()