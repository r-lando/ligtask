import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx


BASE_DIR = Path(__file__).resolve().parent

CANDIDATE_PATH = (
    BASE_DIR
    / "candidate-cases.csv"
)

OUTPUT_DIR = (
    BASE_DIR
    / "ground-truth"
)

SUMMARY_PATH = (
    OUTPUT_DIR
    / "ground-truth-summary.csv"
)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

REQUEST_TIMEOUT = 20.0

EXPECTED_CASE_COUNT = 10


def load_candidates():
    cases = []

    with CANDIDATE_PATH.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        reader = csv.DictReader(file)

        required_fields = {
            "case_id",
            "package",
            "version",
            "intended_group",
        }

        if set(reader.fieldnames or []) != required_fields:
            raise ValueError(
                "Candidate CSV columns do not match "
                "the expected schema."
            )

        seen_case_ids = set()

        for row in reader:
            case_id = row["case_id"].strip()
            package = row["package"].strip()
            version = row["version"].strip()
            intended_group = (
                row["intended_group"].strip()
            )

            if not case_id:
                raise ValueError(
                    "Candidate case ID is empty."
                )

            if case_id in seen_case_ids:
                raise ValueError(
                    f"Duplicate case ID: {case_id}"
                )

            if not package or not version:
                raise ValueError(
                    f"Incomplete package/version for "
                    f"{case_id}."
                )

            if intended_group not in {
                "vulnerable_candidate",
                "control_candidate",
            }:
                raise ValueError(
                    f"Invalid intended group for "
                    f"{case_id}: {intended_group}"
                )

            seen_case_ids.add(case_id)

            cases.append({
                "case_id": case_id,
                "package": package,
                "version": version,
                "ecosystem": "npm",
                "intended_group": intended_group,
            })

    if len(cases) != EXPECTED_CASE_COUNT:
        raise ValueError(
            f"Expected {EXPECTED_CASE_COUNT} cases, "
            f"found {len(cases)}."
        )

    return cases


def query_osv(client, case):
    payload = {
        "package": {
            "name": case["package"],
            "ecosystem": case["ecosystem"],
        },
        "version": case["version"],
    }

    response = client.post(
        OSV_QUERY_URL,
        json=payload,
    )

    response.raise_for_status()

    return response.json()


def canonical_json_bytes(data):
    text = json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )

    return text.encode("utf-8")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest().upper()


def write_json_artifact(path, data):
    encoded = canonical_json_bytes(data)

    path.write_bytes(encoded)

    return sha256_bytes(encoded)


def main():
    cases = load_candidates()

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    existing_artifacts = list(
        OUTPUT_DIR.glob("DEP-*.json")
    )

    if existing_artifacts or SUMMARY_PATH.exists():
        raise RuntimeError(
            "Ground-truth output already exists. "
            "Remove it intentionally before collecting "
            "a new ground-truth snapshot."
        )

    collected_at = datetime.now(
        timezone.utc
    ).isoformat()

    summary_rows = []

    with httpx.Client(
        timeout=REQUEST_TIMEOUT
    ) as client:

        for case in cases:
            response_data = query_osv(
                client,
                case,
            )

            vulnerability_ids = sorted({
                vulnerability["id"]
                for vulnerability
                in response_data.get("vulns", [])
                if vulnerability.get("id")
            })

            artifact = {
                "case_id": case["case_id"],
                "package": case["package"],
                "version": case["version"],
                "ecosystem": case["ecosystem"],
                "intended_group": (
                    case["intended_group"]
                ),
                "collected_at_utc": collected_at,
                "source_endpoint": OSV_QUERY_URL,
                "query": {
                    "package": {
                        "name": case["package"],
                        "ecosystem": (
                            case["ecosystem"]
                        ),
                    },
                    "version": case["version"],
                },
                "response": response_data,
            }

            artifact_path = (
                OUTPUT_DIR
                / f"{case['case_id']}.json"
            )

            artifact_sha256 = (
                write_json_artifact(
                    artifact_path,
                    artifact,
                )
            )

            expected_state = (
                "vulnerable"
                if vulnerability_ids
                else "non_vulnerable"
            )

            eligibility = (
                (
                    case["intended_group"]
                    == "vulnerable_candidate"
                    and expected_state
                    == "vulnerable"
                )
                or
                (
                    case["intended_group"]
                    == "control_candidate"
                    and expected_state
                    == "non_vulnerable"
                )
            )

            summary_rows.append({
                "case_id": case["case_id"],
                "package": case["package"],
                "version": case["version"],
                "ecosystem": case["ecosystem"],
                "intended_group": (
                    case["intended_group"]
                ),
                "ground_truth_state": (
                    expected_state
                ),
                "eligible": str(
                    eligibility
                ).lower(),
                "osv_ids": ";".join(
                    vulnerability_ids
                ),
                "collected_at_utc": collected_at,
                "source_endpoint": OSV_QUERY_URL,
                "artifact_sha256": (
                    artifact_sha256
                ),
            })

    with SUMMARY_PATH.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        fieldnames = [
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
        ]

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(summary_rows)

    vulnerable_count = sum(
        row["ground_truth_state"]
        == "vulnerable"
        for row in summary_rows
    )

    non_vulnerable_count = sum(
        row["ground_truth_state"]
        == "non_vulnerable"
        for row in summary_rows
    )

    eligible_count = sum(
        row["eligible"] == "true"
        for row in summary_rows
    )

    print("DEPENDENCY GROUND-TRUTH COLLECTION")
    print("=" * 72)
    print(f"Cases queried: {len(summary_rows)}")
    print(
        "Ground-truth vulnerable: "
        f"{vulnerable_count}"
    )
    print(
        "Ground-truth non-vulnerable: "
        f"{non_vulnerable_count}"
    )
    print(
        "Cases satisfying intended group: "
        f"{eligible_count}"
    )
    print(
        "Collection timestamp (UTC): "
        f"{collected_at}"
    )
    print()

    for row in summary_rows:
        ids = row["osv_ids"] or "NONE"

        print(
            f"{row['case_id']} "
            f"{row['package']}@{row['version']} "
            f"=> {row['ground_truth_state']} "
            f"| eligible={row['eligible']} "
            f"| OSV={ids}"
        )


if __name__ == "__main__":
    main()
