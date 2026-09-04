import csv
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
CASES_PATH = SCRIPT_DIR / "cases.csv"
FIXTURES_DIR = SCRIPT_DIR / "fixtures"

EXPECTED_CASE_COUNT = 15


FIXTURE_CONTENT = {
    "SEC-001": (
        "aws_key = AKIAABCDEFGHIJKLMNOP\n"
    ),
    "SEC-002": (
        "github_token = "
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456\n"
    ),
    "SEC-003": (
        "-----BEGIN PRIVATE KEY-----\n"
        "SYNTHETIC-TEST-CONTENT-ONLY\n"
        "-----END PRIVATE KEY-----\n"
    ),
    "SEC-004": (
        "database_url = "
        "postgresql://synthetic_user:"
        "synthetic_password@localhost/testdb\n"
    ),
    "SEC-005": (
        'api_key = "SYNTHETICVALUE12345"\n'
    ),
    "SEC-006": (
        "aws_key = BKIAABCDEFGHIJKLMNOP\n"
    ),
    "SEC-007": (
        "github_token = "
        "gxx_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456\n"
    ),
    "SEC-008": (
        "PRIVATE KEY MATERIAL FOR DOCUMENTATION ONLY\n"
    ),
    "SEC-009": (
        "database_url = "
        "sqlite://synthetic_user:"
        "synthetic_password@localhost/testdb\n"
    ),
    "SEC-010": (
        'application_name = "SyntheticApplication"\n'
    ),
    "SEC-011": (
        'api_key = "your_api_key"\n'
    ),
    "SEC-012": (
        'secret = "placeholder"\n'
    ),
    "SEC-013": (
        'password = "changeme"\n'
    ),
    "SEC-014": (
        'access_token = "dummy"\n'
    ),
    "SEC-015": (
        'client_secret = "your_secret"\n'
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

    case_ids = {
        row["case_id"]
        for row in rows
    }

    if len(case_ids) != EXPECTED_CASE_COUNT:
        raise ValueError(
            "Case IDs must be unique."
        )

    if case_ids != set(FIXTURE_CONTENT):
        raise ValueError(
            "Fixture definitions do not "
            "match frozen case IDs."
        )

    return rows


def create_fixture(case_id):
    case_dir = FIXTURES_DIR / case_id

    if case_dir.exists():
        raise FileExistsError(
            f"Fixture already exists: "
            f"{case_dir}"
        )

    case_dir.mkdir(
        parents=True,
        exist_ok=False,
    )

    fixture_path = (
        case_dir / "sample.txt"
    )

    fixture_path.write_text(
        FIXTURE_CONTENT[case_id],
        encoding="utf-8",
        newline="\n",
    )

    return fixture_path


def main():
    cases = load_cases()

    created = []

    for case in cases:
        case_id = case["case_id"]

        fixture_path = create_fixture(
            case_id
        )

        created.append(
            fixture_path
        )

        print(
            f"Created {case_id}: "
            f"{fixture_path.relative_to(SCRIPT_DIR)}"
        )

    print()
    print(
        f"Created {len(created)} "
        "secret-detection fixtures."
    )


if __name__ == "__main__":
    main()
