import re

from pathlib import Path


CONFIG_RULES = [
    {
        "id": "docker-root-user",
        "title": "Container May Run as Root",
        "severity": "MEDIUM",
        "message": (
            "The Dockerfile does not define a non-root USER. "
            "The container may therefore run with elevated "
            "privileges."
        ),
    },
    {
        "id": "docker-latest-tag",
        "title": "Unpinned Latest Docker Image",
        "severity": "LOW",
        "message": (
            "The Dockerfile uses the latest image tag. "
            "Using a specific image version improves build "
            "reproducibility."
        ),
    },
    {
        "id": "docker-add-instead-of-copy",
        "title": "Docker ADD Instruction Used",
        "severity": "LOW",
        "message": (
            "The Dockerfile uses ADD. COPY is generally "
            "preferred when ADD-specific behavior is not "
            "required."
        ),
    },
]


def read_dockerfile(path: Path):
    """
    Read a Dockerfile as UTF-8 text.

    Returns a structured result so an unreadable
    supported configuration file is not treated
    as a successful zero-finding scan.
    """
    try:
        content = path.read_text(
            encoding="utf-8"
        )
    except OSError:
        return {
            "status": "error",
            "content": None,
        }
    except UnicodeDecodeError:
        return {
            "status": "error",
            "content": None,
        }

    return {
        "status": "read",
        "content": content,
    }


def create_finding(
    rule,
    file_path,
    line=None,
):
    """
    Create a configuration-security finding
    without including repository contents.
    """
    return {
        "scanner": "Ligtask Config Scanner",
        "category": "CONFIGURATION",
        "rule_id": rule["id"],
        "title": rule["title"],
        "severity": rule["severity"],
        "file": str(file_path).replace(
            "\\",
            "/",
        ),
        "line": line,
        "message": rule["message"],
    }


def find_rule(rule_id):
    """
    Retrieve a configuration rule by ID.
    """
    for rule in CONFIG_RULES:
        if rule["id"] == rule_id:
            return rule

    return None


def analyze_dockerfile(
    dockerfile_path: Path,
    repository_path: Path,
):
    """
    Apply predefined security checks to one
    Dockerfile.
    """
    findings = []

    read_result = read_dockerfile(
        dockerfile_path
    )

    if read_result["status"] != "read":
        return {
            "status": "error",
            "findings": findings,
        }

    content = read_result["content"]

    try:
        relative_path = (
            dockerfile_path.relative_to(
                repository_path
            )
        )
    except ValueError:
        relative_path = Path(
            dockerfile_path.name
        )

    lines = content.splitlines()

    # -------------------------------------------------
    # Rule 1: Container may run as root
    # -------------------------------------------------

    user_instructions = []

    for line_number, line in enumerate(
        lines,
        start=1,
    ):
        stripped = line.strip()

        if (
            not stripped
            or stripped.startswith("#")
        ):
            continue

        match = re.match(
            r"^USER\s+(.+)$",
            stripped,
            re.IGNORECASE,
        )

        if match:
            user_instructions.append(
                (
                    line_number,
                    match.group(1).strip(),
                )
            )

    root_rule = find_rule(
        "docker-root-user"
    )

    if root_rule:
        if not user_instructions:
            findings.append(
                create_finding(
                    root_rule,
                    relative_path,
                    None,
                )
            )
        else:
            last_user_line, last_user = (
                user_instructions[-1]
            )

            normalized_user = (
                last_user
                .split()[0]
                .lower()
            )

            if normalized_user in {
                "root",
                "0",
                "0:0",
            }:
                findings.append(
                    create_finding(
                        root_rule,
                        relative_path,
                        last_user_line,
                    )
                )

    # -------------------------------------------------
    # Rule 2: FROM image uses :latest
    # -------------------------------------------------

    latest_rule = find_rule(
        "docker-latest-tag"
    )

    if latest_rule:
        for line_number, line in enumerate(
            lines,
            start=1,
        ):
            stripped = line.strip()

            if (
                not stripped
                or stripped.startswith("#")
            ):
                continue

            match = re.match(
                r"^FROM\s+([^\s]+)",
                stripped,
                re.IGNORECASE,
            )

            if not match:
                continue

            image = match.group(1)

            if image.lower().endswith(
                ":latest"
            ):
                findings.append(
                    create_finding(
                        latest_rule,
                        relative_path,
                        line_number,
                    )
                )

    # -------------------------------------------------
    # Rule 3: ADD instruction
    # -------------------------------------------------

    add_rule = find_rule(
        "docker-add-instead-of-copy"
    )

    if add_rule:
        for line_number, line in enumerate(
            lines,
            start=1,
        ):
            stripped = line.strip()

            if (
                not stripped
                or stripped.startswith("#")
            ):
                continue

            if re.match(
                r"^ADD\s+",
                stripped,
                re.IGNORECASE,
            ):
                findings.append(
                    create_finding(
                        add_rule,
                        relative_path,
                        line_number,
                    )
                )

    return {
        "status": "completed",
        "findings": findings,
    }


def scan_configurations(
    repository_path: Path,
):
    """
    Scan supported repository configuration files
    using predefined security rules.

    Initial implementation supports Dockerfiles.
    """

    findings = []
    files_scanned = 0
    processing_errors = []

    try:
        repository_entries = repository_path.rglob("*")

        for path in repository_entries:
            try:
                if not path.is_file():
                    continue
            except OSError:
                processing_errors.append({
                    "error": (
                        "A repository entry could not "
                        "be inspected during "
                        "configuration assessment."
                    ),
                })
                continue

            if path.name.lower() != "dockerfile":
                continue

            analysis_result = analyze_dockerfile(
                path,
                repository_path,
            )

            if analysis_result["status"] == "error":
                processing_errors.append({
                    "error": (
                        "A supported configuration file "
                        "could not be read during "
                        "configuration assessment."
                    ),
                })
                continue

            files_scanned += 1

            findings.extend(
                analysis_result["findings"]
            )

    except OSError:
        return {
            "files_scanned": files_scanned,
            "findings_count": len(findings),
            "findings": findings,
            "scan_status": "failed",
            "processing_errors": [
                {
                    "error": (
                        "The repository could not be "
                        "fully traversed during "
                        "configuration assessment."
                    ),
                }
            ],
        }

    if processing_errors:
        scan_status = "completed_with_errors"
    else:
        scan_status = "completed"

    return {
        "files_scanned": files_scanned,
        "findings_count": len(findings),
        "findings": findings,
        "scan_status": scan_status,
        "processing_errors": processing_errors,
    }
