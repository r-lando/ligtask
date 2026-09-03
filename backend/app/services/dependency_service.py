import json
from pathlib import Path
from urllib.parse import quote

import httpx
from cvss import CVSS3, CVSS4


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULNERABILITY_URL = "https://api.osv.dev/v1/vulns"

REQUEST_TIMEOUT = 20.0


def extract_npm_dependencies(package_lock_path: Path):
    """
    Extract installed npm package names and versions
    from package-lock.json.
    """
    dependencies = []

    try:
        with package_lock_path.open(
            "r",
            encoding="utf-8"
        ) as file:
            lock_data = json.load(file)

    except (json.JSONDecodeError, OSError):
        return dependencies

    packages = lock_data.get("packages", {})

    for package_path, package_data in packages.items():
        if not package_path.startswith("node_modules/"):
            continue

        name = package_data.get("name")
        version = package_data.get("version")

        if not name:
            name = package_path.replace(
                "node_modules/",
                "",
                1
            )

        if not version:
            continue

        dependencies.append({
            "name": name,
            "version": version,
            "ecosystem": "npm",
            "source_file": str(package_lock_path),
        })

    return dependencies


def calculate_cvss(cvss_type, vector):
    """
    Calculate a CVSS score using an OSV-provided
    CVSS vector.

    No score is created when a valid supported
    vector is unavailable.
    """
    if not vector:
        return {
            "score": None,
            "severity": "UNKNOWN",
            "vector": None,
            "version": None,
        }

    try:
        if cvss_type == "CVSS_V4":
            cvss = CVSS4(vector)

            return {
                "score": float(cvss.base_score),
                "severity": str(
                    cvss.severity
                ).upper(),
                "vector": vector,
                "version": "4.0",
            }

        if cvss_type == "CVSS_V3":
            cvss = CVSS3(vector)

            scores = cvss.scores()
            severities = cvss.severities()

            return {
                "score": float(scores[0]),
                "severity": str(
                    severities[0]
                ).upper(),
                "vector": vector,
                "version": (
                    "3.1"
                    if vector.startswith("CVSS:3.1")
                    else "3.0"
                ),
            }

    except (ValueError, TypeError, IndexError):
        pass

    return {
        "score": None,
        "severity": "UNKNOWN",
        "vector": vector,
        "version": None,
    }


def extract_cvss(vulnerability):
    """
    Extract the preferred CVSS vector from an
    OSV vulnerability record.

    Preference:
    1. CVSS v4
    2. CVSS v3
    """
    severity_entries = vulnerability.get(
        "severity",
        []
    )

    for entry in severity_entries:
        if entry.get("type") == "CVSS_V4":
            return calculate_cvss(
                "CVSS_V4",
                entry.get("score")
            )

    for entry in severity_entries:
        if entry.get("type") == "CVSS_V3":
            return calculate_cvss(
                "CVSS_V3",
                entry.get("score")
            )

    return {
        "score": None,
        "severity": "UNKNOWN",
        "vector": None,
        "version": None,
    }


def query_osv_batch(client, dependencies):
    """
    Query OSV for multiple dependencies in a
    single batch request.

    OSV guarantees that result order corresponds
    to query order.
    """
    if not dependencies:
        return {
            "success": True,
            "results": [],
            "error": None,
        }

    queries = []

    for dependency in dependencies:
        queries.append({
            "package": {
                "name": dependency["name"],
                "ecosystem": dependency["ecosystem"],
            },
            "version": dependency["version"],
        })

    try:
        response = client.post(
            OSV_BATCH_URL,
            json={
                "queries": queries
            },
        )

        response.raise_for_status()

        data = response.json()

        return {
            "success": True,
            "results": data.get(
                "results",
                []
            ),
            "error": None,
        }

    except (
        httpx.HTTPError,
        ValueError
    ) as error:
        return {
            "success": False,
            "results": [],
            "error": str(error),
        }


def get_vulnerability_details(
    client,
    vulnerability_id
):
    """
    Retrieve the complete OSV record for a
    vulnerability ID.
    """
    encoded_id = quote(
        vulnerability_id,
        safe=""
    )

    url = (
        f"{OSV_VULNERABILITY_URL}/"
        f"{encoded_id}"
    )

    try:
        response = client.get(url)

        response.raise_for_status()

        return {
            "success": True,
            "data": response.json(),
            "error": None,
        }

    except (
        httpx.HTTPError,
        ValueError
    ) as error:
        return {
            "success": False,
            "data": None,
            "error": str(error),
        }


def collect_dependencies(repository_path: Path):
    """
    Collect supported dependencies from the
    repository.
    """
    dependencies = []

    for package_lock in repository_path.rglob(
        "package-lock.json"
    ):
        dependencies.extend(
            extract_npm_dependencies(
                package_lock
            )
        )

    return dependencies


def scan_dependencies(repository_path: Path):
    """
    Perform dependency vulnerability assessment
    using OSV batch queries.

    Package/version matching is performed using
    /v1/querybatch.

    Full vulnerability records are retrieved only
    once for each unique vulnerability ID.
    """
    dependencies = collect_dependencies(
        repository_path
    )

    findings = []
    request_errors = []

    if not dependencies:
        return {
            "dependencies_checked": 0,
            "findings_count": 0,
            "findings": [],
            "scan_status": "completed",
            "request_errors": [],
        }

    with httpx.Client(
        timeout=REQUEST_TIMEOUT
    ) as client:

        batch_result = query_osv_batch(
            client,
            dependencies
        )

        if not batch_result["success"]:
            return {
                "dependencies_checked": len(
                    dependencies
                ),
                "findings_count": 0,
                "findings": [],
                "scan_status": "failed",
                "request_errors": [
                    {
                        "stage": "batch_query",
                        "error": batch_result[
                            "error"
                        ],
                    }
                ],
            }

        batch_results = batch_result[
            "results"
        ]

        if len(batch_results) != len(
            dependencies
        ):
            return {
                "dependencies_checked": len(
                    dependencies
                ),
                "findings_count": 0,
                "findings": [],
                "scan_status": "failed",
                "request_errors": [
                    {
                        "stage": "batch_query",
                        "error": (
                            "OSV batch response count "
                            "did not match the number "
                            "of dependency queries."
                        ),
                    }
                ],
            }

        # Maps each vulnerability ID to every
        # dependency affected by that vulnerability.
        vulnerability_matches = {}

        for dependency, result in zip(
            dependencies,
            batch_results
        ):
            for vulnerability in result.get(
                "vulns",
                []
            ):
                vulnerability_id = (
                    vulnerability.get("id")
                )

                if not vulnerability_id:
                    continue

                vulnerability_matches.setdefault(
                    vulnerability_id,
                    []
                ).append(dependency)

        # Fetch each unique vulnerability record
        # only once.
        vulnerability_details = {}

        for vulnerability_id in (
            vulnerability_matches
        ):
            detail_result = (
                get_vulnerability_details(
                    client,
                    vulnerability_id
                )
            )

            if not detail_result["success"]:
                request_errors.append({
                    "stage": (
                        "vulnerability_details"
                    ),
                    "vulnerability_id": (
                        vulnerability_id
                    ),
                    "error": detail_result[
                        "error"
                    ],
                })

                continue

            vulnerability_details[
                vulnerability_id
            ] = detail_result["data"]

        # Build findings from the full records.
        for vulnerability_id, matched_dependencies in (
            vulnerability_matches.items()
        ):
            vulnerability = (
                vulnerability_details.get(
                    vulnerability_id
                )
            )

            if vulnerability is None:
                continue

            cvss = extract_cvss(
                vulnerability
            )

            for dependency in matched_dependencies:
                findings.append({
                    "scanner": "OSV",
                    "category": "DEPENDENCY",

                    "vulnerability_id": (
                        vulnerability_id
                    ),

                    "package": dependency[
                        "name"
                    ],

                    "version": dependency[
                        "version"
                    ],

                    "ecosystem": dependency[
                        "ecosystem"
                    ],

                    "summary": (
                        vulnerability.get(
                            "summary"
                        )
                    ),

                    "source_file": dependency[
                        "source_file"
                    ],

                    "severity": cvss[
                        "severity"
                    ],

                    "cvss_score": cvss[
                        "score"
                    ],

                    "cvss_vector": cvss[
                        "vector"
                    ],

                    "cvss_version": cvss[
                        "version"
                    ],
                })

    return {
        "dependencies_checked": len(
            dependencies
        ),

        "findings_count": len(
            findings
        ),

        "findings": findings,

        "scan_status": (
            "completed_with_errors"
            if request_errors
            else "completed"
        ),

        "request_errors": request_errors,
    }