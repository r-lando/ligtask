import csv
import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

CANDIDATE_PATH = (
    BASE_DIR
    / "candidate-cases.csv"
)

FIXTURES_DIR = (
    BASE_DIR
    / "fixtures"
)

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

        for row in reader:
            cases.append({
                "case_id": row["case_id"].strip(),
                "package": row["package"].strip(),
                "version": row["version"].strip(),
            })

    if len(cases) != EXPECTED_CASE_COUNT:
        raise ValueError(
            f"Expected {EXPECTED_CASE_COUNT} cases, "
            f"found {len(cases)}."
        )

    return cases


def build_package_lock(case):
    package = case["package"]
    version = case["version"]

    return {
        "name": (
            f"talged-dependency-"
            f"{case['case_id'].lower()}"
        ),
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {
                "name": (
                    f"talged-dependency-"
                    f"{case['case_id'].lower()}"
                ),
                "version": "1.0.0",
                "dependencies": {
                    package: version,
                },
            },
            f"node_modules/{package}": {
                "name": package,
                "version": version,
            },
        },
    }


def write_fixture(case):
    case_directory = (
        FIXTURES_DIR
        / case["case_id"]
    )

    if case_directory.exists():
        raise RuntimeError(
            f"Fixture already exists: "
            f"{case['case_id']}"
        )

    case_directory.mkdir(
        parents=True,
        exist_ok=False,
    )

    package_lock = build_package_lock(case)

    package_lock_path = (
        case_directory
        / "package-lock.json"
    )

    package_lock_path.write_text(
        json.dumps(
            package_lock,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    return package_lock_path


def main():
    cases = load_candidates()

    FIXTURES_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    created = []

    for case in cases:
        path = write_fixture(case)
        created.append(path)

    print("DEPENDENCY FIXTURE GENERATION")
    print("=" * 72)
    print(f"Fixtures created: {len(created)}")
    print()

    for path in created:
        print(
            path.relative_to(BASE_DIR)
        )


if __name__ == "__main__":
    main()
