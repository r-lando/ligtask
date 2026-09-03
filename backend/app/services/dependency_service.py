import json
from pathlib import Path

import httpx


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

        return response.json()

    except httpx.HTTPError:
        return {
            "vulns": []
        }


def scan_dependencies(repository_path: Path):
    findings = []
    dependency_count = 0

    for package_lock in repository_path.rglob(
        "package-lock.json"
    ):
        dependencies = extract_npm_dependencies(
            package_lock
        )

        dependency_count += len(dependencies)

        for dependency in dependencies:
            result = query_osv(
                dependency["name"],
                dependency["version"],
                dependency["ecosystem"],
            )

            for vulnerability in result.get("vulns", []):
                findings.append({
                    "scanner": "OSV",
                    "category": "DEPENDENCY",
                    "vulnerability_id": vulnerability.get("id"),
                    "package": dependency["name"],
                    "version": dependency["version"],
                    "ecosystem": dependency["ecosystem"],
                    "summary": vulnerability.get("summary"),
                    "source_file": dependency["source_file"],
                })

    return {
        "dependencies_checked": dependency_count,
        "findings_count": len(findings),
        "findings": findings,
    }