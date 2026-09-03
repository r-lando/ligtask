import json
from pathlib import Path

import httpx
from cvss import CVSS3, CVSS4


OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def extract_npm_dependencies(package_lock_path: Path):
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


def query_osv(
    package_name: str,
    version: str,
    ecosystem: str
):
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem,
        },
        "version": version,
    }

    try:
        response = httpx.post(
            OSV_QUERY_URL,
            json=payload,
            timeout=10.0,
        )

        response.raise_for_status()

        return {
            "success": True,
            "data": response.json(),
            "error": None,
        }

    except httpx.HTTPError as error:
        return {
            "success": False,
            "data": {
                "vulns": []
            },
            "error": str(error),
        }


def calculate_cvss(cvss_type, vector):
    """
    Calculate a CVSS score and severity label
    from an OSV-provided CVSS vector.

    Returns UNKNOWN if the vector cannot be parsed.
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

            score = float(cvss.base_score)
            severity = str(cvss.severity).upper()

            return {
                "score": score,
                "severity": severity,
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
    Extract the best available CVSS score from
    an OSV vulnerability record.

    Preference:
    1. CVSS v4
    2. CVSS v3
    """

    severity_entries = vulnerability.get(
        "severity",
        []
    )

    # Prefer CVSS v4 when available
    for severity_entry in severity_entries:
        if severity_entry.get("type") == "CVSS_V4":
            return calculate_cvss(
                "CVSS_V4",
                severity_entry.get("score")
            )

    # Otherwise use CVSS v3
    for severity_entry in severity_entries:
        if severity_entry.get("type") == "CVSS_V3":
            return calculate_cvss(
                "CVSS_V3",
                severity_entry.get("score")
            )

    return {
        "score": None,
        "severity": "UNKNOWN",
        "vector": None,
        "version": None,
    }


def scan_dependencies(repository_path: Path):
    findings = []
    dependency_count = 0
    request_errors = []

    for package_lock in repository_path.rglob(
        "package-lock.json"
    ):
        dependencies = extract_npm_dependencies(
            package_lock
        )

        dependency_count += len(dependencies)

        for dependency in dependencies:
            osv_result = query_osv(
                dependency["name"],
                dependency["version"],
                dependency["ecosystem"],
            )

            if not osv_result["success"]:
                request_errors.append({
                    "package": dependency["name"],
                    "version": dependency["version"],
                    "error": osv_result["error"],
                })

                continue

            vulnerabilities = osv_result[
                "data"
            ].get(
                "vulns",
                []
            )

            for vulnerability in vulnerabilities:
                cvss = extract_cvss(
                    vulnerability
                )

                findings.append({
                    "scanner": "OSV",
                    "category": "DEPENDENCY",

                    "vulnerability_id": (
                        vulnerability.get("id")
                    ),

                    "package": dependency["name"],
                    "version": dependency["version"],
                    "ecosystem": (
                        dependency["ecosystem"]
                    ),

                    "summary": vulnerability.get(
                        "summary"
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
        "dependencies_checked": dependency_count,
        "findings_count": len(findings),
        "findings": findings,

        "scan_status": (
            "completed_with_errors"
            if request_errors
            else "completed"
        ),

        "request_errors": request_errors,
    }