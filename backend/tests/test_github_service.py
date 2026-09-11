import pytest

from app.services.github_service import (
    GitHubRepositoryError,
    download_repository_archive,
    get_repository_metadata,
    parse_github_repository_url,
    validate_repository_component,
)


def test_parse_valid_github_url():
    result = parse_github_repository_url(
        "https://github.com/owner/repo"
    )
    assert result["owner"] == "owner"
    assert result["repository"] == "repo"
    assert (
        result["canonical_url"]
        == "https://github.com/owner/repo"
    )


def test_parse_valid_github_url_with_dot_git():
    result = parse_github_repository_url(
        "https://github.com/owner/repo.git"
    )
    assert result["owner"] == "owner"
    assert result["repository"] == "repo"
    assert (
        result["canonical_url"]
        == "https://github.com/owner/repo"
    )


def test_parse_valid_github_url_with_trailing_slash():
    result = parse_github_repository_url(
        "https://github.com/owner/repo/"
    )
    assert result["owner"] == "owner"
    assert result["repository"] == "repo"


@pytest.mark.parametrize(
    "invalid_url,expected_error",
    [
        (
            "",
            "GitHub repository URL is required.",
        ),
        (
            "   ",
            "GitHub repository URL must use HTTPS.",
        ),
        (
            "http://github.com/owner/repo",
            "GitHub repository URL must use HTTPS.",
        ),
        (
            "ftp://github.com/owner/repo",
            "GitHub repository URL must use HTTPS.",
        ),
        (
            "https://gitlab.com/owner/repo",
            "Only github.com repository URLs are supported.",
        ),
        (
            "https://attacker.com/owner/repo",
            "Only github.com repository URLs are supported.",
        ),
        (
            "https://user:pass@github.com/owner/repo",
            "GitHub repository URL must not contain credentials.",
        ),
        (
            "https://github.com:8080/owner/repo",
            "Unsupported GitHub URL port.",
        ),
        (
            "https://github.com/owner/repo?ref=main",
            "GitHub repository URL must not contain a query string or fragment.",
        ),
        (
            "https://github.com/owner/repo#readme",
            "GitHub repository URL must not contain a query string or fragment.",
        ),
        (
            "https://github.com/owner",
            "GitHub URL must identify a repository in the format https://github.com/owner/repository.",
        ),
        (
            "https://github.com/owner/repo/subpath",
            "GitHub URL must identify a repository in the format https://github.com/owner/repository.",
        ),
    ],
)
def test_parse_github_url_rejections(
    invalid_url, expected_error
):
    with pytest.raises(GitHubRepositoryError) as exc_info:
        parse_github_repository_url(invalid_url)
    assert expected_error in str(exc_info.value)


@pytest.mark.parametrize(
    "component,component_name",
    [
        ("", "owner"),
        ("invalid/slash", "owner"),
        ("invalid space", "repository name"),
        ("invalid@char", "repository name"),
    ],
)
def test_validate_repository_component_invalid(
    component, component_name
):
    with pytest.raises(GitHubRepositoryError):
        validate_repository_component(
            component, component_name
        )


def test_get_repository_metadata_404_raises_controlled_error(
    monkeypatch,
):
    class FakeResponse:
        status_code = 404

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def get(self, url):
            return FakeResponse()

    monkeypatch.setattr(
        "httpx.Client",
        FakeClient,
    )

    with pytest.raises(GitHubRepositoryError) as exc_info:
        get_repository_metadata("owner", "repo")

    assert (
        "not found or is not publicly accessible"
        in str(exc_info.value)
    )


def test_get_repository_metadata_private_repo_rejected(
    monkeypatch,
):
    class FakeResponse:
        status_code = 200

        def json(self):
            return {
                "private": True,
                "default_branch": "main",
            }

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def get(self, url):
            return FakeResponse()

    monkeypatch.setattr(
        "httpx.Client",
        FakeClient,
    )

    with pytest.raises(GitHubRepositoryError) as exc_info:
        get_repository_metadata("owner", "repo")

    assert "Private GitHub repositories are not supported" in str(
        exc_info.value
    )


def test_download_repository_archive_unexpected_content_type(
    monkeypatch,
):
    class FakeStreamResponse:
        status_code = 200
        headers = {
            "content-type": "text/html",
        }

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def iter_bytes(self, chunk_size=None):
            yield b"<html>not a zip</html>"

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def stream(self, method, url):
            return FakeStreamResponse()

    monkeypatch.setattr(
        "httpx.Client",
        FakeClient,
    )

    with pytest.raises(GitHubRepositoryError) as exc_info:
        download_repository_archive(
            "owner", "repo", "main"
        )

    assert "unexpected archive content type" in str(
        exc_info.value
    )
