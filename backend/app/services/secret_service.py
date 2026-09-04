import re

from pathlib import Path


# Files/directories that should not be scanned.

IGNORED_DIRECTORIES = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
}

IGNORED_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".rar",
    ".7z",
    ".exe",
    ".dll",
    ".so",
    ".bin",
    ".woff",
    ".woff2",
    ".ttf",
    ".mp3",
    ".mp4",
}

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB


SECRET_RULES = [
    {
        "id": "aws-access-key-id",
        "title": "Potential AWS Access Key Detected",
        "severity": "HIGH",
        "pattern": re.compile(
            r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
        ),
    },
    {
        "id": "github-token",
        "title": "Potential GitHub Token Detected",
        "severity": "HIGH",
        "pattern": re.compile(
            r"\b(?:ghp|gho|ghu|ghs|ghr)_"
            r"[A-Za-z0-9]{20,255}\b"
        ),
    },
    {
        "id": "private-key",
        "title": "Private Key Detected",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r"-----BEGIN "
            r"(?:RSA |EC |OPENSSH )?"
            r"PRIVATE KEY-----"
        ),
    },
    {
        "id": "database-connection-string",
        "title": (
            "Potential Database Connection "
            "String Detected"
        ),
        "severity": "HIGH",
        "pattern": re.compile(
            r"\b(?:mongodb(?:\+srv)?|"
            r"postgres(?:ql)?|mysql)"
            r"://[^\s\"'<>]+",
            re.IGNORECASE,
        ),
    },
    {
        "id": "generic-secret-assignment",
        "title": "Potential Secret Assignment Detected",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r"""(?ix)
            \b
            (
                api[_-]?key
                |
                secret
                |
                client[_-]?secret
                |
                access[_-]?token
                |
                auth[_-]?token
                |
                password
                |
                passwd
                |
                pwd
            )
            \s*
            [:=]
            \s*
            ["']?
            ([A-Za-z0-9_\-./+=]{8,})
            ["']?
            """
        ),
        "value_group": 2,
    },
]


PLACEHOLDER_VALUES = {
    "example",
    "sample",
    "placeholder",
    "changeme",
    "change_me",
    "your_api_key",
    "your-api-key",
    "your_secret",
    "your-secret",
    "your_password",
    "your-password",
    "password",
    "secret",
    "dummy",
    "test",
    "testing",
    "xxxxxxxx",
    "xxxxxxxxxx",
}


def should_ignore_path(path: Path):
    """
    Determine whether a repository file should
    be excluded from secret scanning.
    """
    if any(
        part.lower() in IGNORED_DIRECTORIES
        for part in path.parts
    ):
        return True

    if path.suffix.lower() in IGNORED_EXTENSIONS:
        return True

    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            return True
    except OSError:
        # Do not treat a stat failure as an
        # intentional ignore. The read stage
        # should record it as a processing error.
        return False

    return False


def is_placeholder(value):
    """
    Reduce obvious false positives caused by
    example or placeholder credentials.
    """
    if not value:
        return False

    normalized = (
        value.strip()
        .strip("\"'")
        .lower()
    )

    if normalized in PLACEHOLDER_VALUES:
        return True

    placeholder_fragments = (
        "your_",
        "your-",
        "example",
        "sample",
        "placeholder",
        "dummy",
        "changeme",
    )

    return any(
        fragment in normalized
        for fragment in placeholder_fragments
    )


def read_text_file(path: Path):
    """
    Read a file for secret scanning.

    Returns a status so intentionally skipped
    files can be distinguished from files that
    could not be read.
    """
    try:
        raw_data = path.read_bytes()
    except OSError:
        return {
            "status": "error",
            "content": None,
        }

    # Binary files are normal skips rather than
    # scanner failures.
    if b"\x00" in raw_data:
        return {
            "status": "skipped",
            "content": None,
        }

    try:
        content = raw_data.decode("utf-8")
    except UnicodeDecodeError:
        return {
            "status": "skipped",
            "content": None,
        }

    return {
        "status": "read",
        "content": content,
    }


def scan_line(
    line,
    line_number,
    file_path,
):
    """
    Apply all secret-detection rules to one line.
    """
    findings = []

    for rule in SECRET_RULES:
        for match in rule["pattern"].finditer(line):
            value_group = rule.get(
                "value_group"
            )

            if value_group is not None:
                candidate_value = match.group(
                    value_group
                )

                if is_placeholder(candidate_value):
                    continue

            findings.append({
                "scanner": "Ligtask Secret Detector",
                "category": "SECRET",
                "rule_id": rule["id"],
                "title": rule["title"],
                "severity": rule["severity"],
                "file": str(file_path),
                "line": line_number,
                "message": (
                    "A potential secret or credential "
                    "was detected. The detected value "
                    "has not been included in the "
                    "assessment result."
                ),
            })

    return findings


def scan_secrets(repository_path: Path):
    """
    Scan repository text files for potential
    exposed secrets and credentials.

    Secret values are used only for temporary
    matching and are never returned in findings.
    """

    findings = []
    files_scanned = 0
    files_skipped = 0
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
                        "be inspected during secret "
                        "detection."
                    ),
                })
                continue

            if should_ignore_path(path):
                continue

            read_result = read_text_file(path)
            read_status = read_result["status"]

            if read_status == "skipped":
                files_skipped += 1
                continue

            if read_status == "error":
                processing_errors.append({
                    "error": (
                        "An eligible repository file "
                        "could not be read during "
                        "secret detection."
                    ),
                })
                continue

            content = read_result["content"]
            files_scanned += 1

            try:
                relative_path = path.relative_to(
                    repository_path
                )
            except ValueError:
                relative_path = Path(path.name)

            relative_path = Path(
                str(relative_path).replace(
                    "\\",
                    "/",
                )
            )

            for line_number, line in enumerate(
                content.splitlines(),
                start=1,
            ):
                findings.extend(
                    scan_line(
                        line,
                        line_number,
                        relative_path,
                    )
                )

    except OSError:
        return {
            "files_scanned": files_scanned,
            "files_skipped": files_skipped,
            "findings_count": len(findings),
            "findings": findings,
            "scan_status": "failed",
            "processing_errors": [
                {
                    "error": (
                        "The repository could not be "
                        "fully traversed during secret "
                        "detection."
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
        "files_skipped": files_skipped,
        "findings_count": len(findings),
        "findings": findings,
        "scan_status": scan_status,
        "processing_errors": processing_errors,
    }
