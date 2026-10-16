import re
from urllib.parse import urlparse

import httpx


GITHUB_HOST = "github.com"
GITHUB_API_BASE = "https://api.github.com"
GITHUB_ARCHIVE_BASE = "https://codeload.github.com"

MAX_GITHUB_DOWNLOAD_BYTES = (
    50 * 1024 * 1024
)

REQUEST_TIMEOUT_SECONDS = 30.0

GITHUB_REPOSITORY_PATTERN = re.compile(
    r"^[A-Za-z0-9_.-]+$"
)


class GitHubRepositoryError(Exception):
    """
    Raised when a GitHub repository cannot
    be safely validated or retrieved.
    """


def validate_repository_component(
    value,
    component_name,
):
    """
    Validate GitHub owner and repository
    path components.
    """
    if not value:
        raise GitHubRepositoryError(
            f"GitHub {component_name} "
            "is missing."
        )

    if not GITHUB_REPOSITORY_PATTERN.fullmatch(
        value
    ):
        raise GitHubRepositoryError(
            f"Invalid GitHub "
            f"{component_name}."
        )

    return value


def parse_github_repository_url(
    repository_url,
):
    """
    Parse and strictly validate a public
    GitHub repository URL.

    Supported format:
    https://github.com/owner/repository
    """
    if not repository_url:
        raise GitHubRepositoryError(
            "GitHub repository URL "
            "is required."
        )

    try:
        parsed = urlparse(
            repository_url.strip()
        )
    except ValueError as exc:
        raise GitHubRepositoryError(
            "Invalid GitHub repository URL."
        ) from exc

    if parsed.scheme.lower() != "https":
        raise GitHubRepositoryError(
            "GitHub repository URL must "
            "use HTTPS."
        )

    hostname = (
        parsed.hostname or ""
    ).lower()

    if hostname != GITHUB_HOST:
        raise GitHubRepositoryError(
            "Only github.com repository "
            "URLs are supported."
        )

    if parsed.username or parsed.password:
        raise GitHubRepositoryError(
            "GitHub repository URL must "
            "not contain credentials."
        )

    try:
        port = parsed.port
    except ValueError as exc:
        raise GitHubRepositoryError(
            "Invalid GitHub URL port."
        ) from exc

    if port not in (
        None,
        443,
    ):
        raise GitHubRepositoryError(
            "Unsupported GitHub URL port."
        )

    if parsed.query or parsed.fragment:
        raise GitHubRepositoryError(
            "GitHub repository URL must "
            "not contain a query string "
            "or fragment."
        )

    path_parts = [
        part
        for part
        in parsed.path.split("/")
        if part
    ]

    if len(path_parts) != 2:
        raise GitHubRepositoryError(
            "GitHub URL must identify "
            "a repository in the format "
            "https://github.com/"
            "owner/repository."
        )

    owner = path_parts[0]
    repository = path_parts[1]

    if repository.lower().endswith(
        ".git"
    ):
        repository = repository[:-4]

    validate_repository_component(
        owner,
        "owner",
    )

    validate_repository_component(
        repository,
        "repository name",
    )

    canonical_url = (
        f"https://github.com/"
        f"{owner}/{repository}"
    )

    return {
        "owner": owner,
        "repository": repository,
        "canonical_url": canonical_url,
    }


def github_headers():
    """
    Return headers used for GitHub API
    requests.
    """
    return {
        "Accept": (
            "application/vnd.github+json"
        ),
        "User-Agent": "TALGED",
        "X-GitHub-Api-Version": (
            "2022-11-28"
        ),
    }


def get_repository_metadata(
    owner,
    repository,
):
    """
    Retrieve public repository metadata
    from GitHub.

    Private repositories are not supported.
    """
    api_url = (
        f"{GITHUB_API_BASE}/repos/"
        f"{owner}/{repository}"
    )

    try:
        with httpx.Client(
            timeout=REQUEST_TIMEOUT_SECONDS,
            follow_redirects=False,
            headers=github_headers(),
        ) as client:
            response = client.get(
                api_url
            )

    except httpx.RequestError as exc:
        raise GitHubRepositoryError(
            "Unable to connect to GitHub."
        ) from exc

    if response.status_code == 404:
        raise GitHubRepositoryError(
            "GitHub repository was not "
            "found or is not publicly "
            "accessible."
        )

    if response.status_code == 403:
        raise GitHubRepositoryError(
            "GitHub rejected the request. "
            "The API rate limit may have "
            "been reached."
        )

    if response.status_code != 200:
        raise GitHubRepositoryError(
            "GitHub repository metadata "
            "could not be retrieved."
        )

    try:
        metadata = response.json()
    except ValueError as exc:
        raise GitHubRepositoryError(
            "GitHub returned an invalid "
            "metadata response."
        ) from exc

    if metadata.get("private"):
        raise GitHubRepositoryError(
            "Private GitHub repositories "
            "are not supported through "
            "URL assessment."
        )

    default_branch = metadata.get(
        "default_branch"
    )

    if not default_branch:
        raise GitHubRepositoryError(
            "The repository default branch "
            "could not be determined."
        )

    return {
        "owner": owner,
        "repository": repository,
        "full_name": metadata.get(
            "full_name",
            f"{owner}/{repository}",
        ),
        "default_branch": default_branch,
        "html_url": metadata.get(
            "html_url",
            (
                f"https://github.com/"
                f"{owner}/{repository}"
            ),
        ),
    }


def download_repository_archive(
    owner,
    repository,
    branch,
):
    """
    Download a public GitHub repository
    ZIP archive while enforcing a maximum
    response size.

    The repository is held only as ZIP
    bytes for the next temporary processing
    stage and is not persisted here.
    """
    archive_url = (
        f"{GITHUB_ARCHIVE_BASE}/"
        f"{owner}/{repository}/zip/"
        f"refs/heads/{branch}"
    )

    chunks = []
    total_bytes = 0

    try:
        with httpx.Client(
            timeout=REQUEST_TIMEOUT_SECONDS,
            follow_redirects=False,
            headers={
                "User-Agent": "TALGED",
            },
        ) as client:
            with client.stream(
                "GET",
                archive_url,
            ) as response:

                if response.status_code == 404:
                    raise GitHubRepositoryError(
                        "GitHub repository "
                        "archive was not found."
                    )

                if response.status_code != 200:
                    raise GitHubRepositoryError(
                        "GitHub repository "
                        "archive could not "
                        "be downloaded."
                    )

                content_type = (
                    response.headers.get(
                        "content-type",
                        "",
                    ).lower()
                )

                if (
                    "zip" not in content_type
                    and
                    "octet-stream"
                    not in content_type
                ):
                    raise GitHubRepositoryError(
                        "GitHub returned an "
                        "unexpected archive "
                        "content type."
                    )

                content_length = (
                    response.headers.get(
                        "content-length"
                    )
                )

                if content_length:
                    try:
                        declared_size = int(
                            content_length
                        )
                    except ValueError:
                        declared_size = None

                    if (
                        declared_size is not None
                        and declared_size
                        > MAX_GITHUB_DOWNLOAD_BYTES
                    ):
                        raise GitHubRepositoryError(
                            "GitHub repository "
                            "archive exceeds the "
                            "maximum allowed "
                            "download size."
                        )

                for chunk in (
                    response.iter_bytes()
                ):
                    if not chunk:
                        continue

                    total_bytes += len(
                        chunk
                    )

                    if (
                        total_bytes
                        > MAX_GITHUB_DOWNLOAD_BYTES
                    ):
                        raise GitHubRepositoryError(
                            "GitHub repository "
                            "archive exceeds the "
                            "maximum allowed "
                            "download size."
                        )

                    chunks.append(
                        chunk
                    )

    except GitHubRepositoryError:
        raise

    except httpx.RequestError as exc:
        raise GitHubRepositoryError(
            "Unable to download the "
            "GitHub repository."
        ) from exc

    archive_bytes = b"".join(
        chunks
    )

    if not archive_bytes:
        raise GitHubRepositoryError(
            "GitHub returned an empty "
            "repository archive."
        )

    if not archive_bytes.startswith(
        b"PK"
    ):
        raise GitHubRepositoryError(
            "Downloaded repository data "
            "is not a valid ZIP archive."
        )

    return archive_bytes


def retrieve_public_repository(
    repository_url,
):
    """
    Validate a public GitHub URL, obtain
    repository metadata, and download its
    ZIP archive.

    Returns repository metadata together
    with the downloaded ZIP bytes.
    """
    parsed = (
        parse_github_repository_url(
            repository_url
        )
    )

    metadata = (
        get_repository_metadata(
            parsed["owner"],
            parsed["repository"],
        )
    )

    archive_bytes = (
        download_repository_archive(
            metadata["owner"],
            metadata["repository"],
            metadata["default_branch"],
        )
    )

    return {
        "owner": metadata["owner"],
        "repository": (
            metadata["repository"]
        ),
        "full_name": metadata[
            "full_name"
        ],
        "default_branch": metadata[
            "default_branch"
        ],
        "repository_url": parsed[
            "canonical_url"
        ],
        "archive_size_bytes": len(
            archive_bytes
        ),
        "archive_bytes": archive_bytes,
    }