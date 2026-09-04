import zipfile

import pytest
from fastapi import HTTPException

from app.services import repository_service


def write_zip(zip_path, entries):
    """
    Create a normal ZIP archive from
    (filename, content) pairs.
    """
    with zipfile.ZipFile(
        zip_path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:
        for filename, content in entries:
            archive.writestr(
                filename,
                content,
            )


def assert_rejected(
    zip_path,
    extract_dir,
    expected_detail,
):
    with pytest.raises(HTTPException) as exc_info:
        repository_service.validate_and_extract_archive(
            zip_path,
            extract_dir,
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == expected_detail


def test_valid_zip_extracts_regular_files(
    tmp_path,
):
    zip_path = tmp_path / "repository.zip"
    extract_dir = tmp_path / "extracted"

    write_zip(
        zip_path,
        [
            (
                "project/app.py",
                "print('hello')",
            ),
            (
                "project/config/settings.txt",
                "safe=true",
            ),
        ],
    )

    extracted_size = (
        repository_service.validate_and_extract_archive(
            zip_path,
            extract_dir,
        )
    )

    assert (
        extract_dir / "project" / "app.py"
    ).read_text() == "print('hello')"

    assert (
        extract_dir
        / "project"
        / "config"
        / "settings.txt"
    ).read_text() == "safe=true"

    assert extracted_size > 0


def test_invalid_zip_is_rejected(
    tmp_path,
):
    zip_path = tmp_path / "not-a-zip.zip"
    extract_dir = tmp_path / "extracted"

    zip_path.write_text(
        "This is not a ZIP archive."
    )

    assert_rejected(
        zip_path,
        extract_dir,
        "Repository data is not a valid ZIP archive.",
    )


@pytest.mark.parametrize(
    (
        "member_name",
        "expected_detail",
    ),
    [
        (
            "../outside.txt",
            "Path traversal detected in ZIP archive.",
        ),
        (
            "project/../../outside.txt",
            "Path traversal detected in ZIP archive.",
        ),
        (
            "..\\outside.txt",
            "Path traversal detected in ZIP archive.",
        ),
        (
            "C:/Windows/test.txt",
            (
                "Drive-qualified paths are not "
                "allowed in ZIP archives."
            ),
        ),
        (
            "C:\\Windows\\test.txt",
            (
                "Drive-qualified paths are not "
                "allowed in ZIP archives."
            ),
        ),
    ],
)
def test_unsafe_member_paths_are_rejected(
    tmp_path,
    member_name,
    expected_detail,
):
    zip_path = tmp_path / "repository.zip"
    extract_dir = tmp_path / "extracted"

    write_zip(
        zip_path,
        [
            (
                member_name,
                "unsafe",
            ),
        ],
    )

    assert_rejected(
        zip_path,
        extract_dir,
        expected_detail,
    )


def test_absolute_path_is_rejected(
    tmp_path,
):
    zip_path = tmp_path / "repository.zip"
    extract_dir = tmp_path / "extracted"

    write_zip(
        zip_path,
        [
            (
                "/etc/passwd",
                "unsafe",
            ),
        ],
    )

    assert_rejected(
        zip_path,
        extract_dir,
        (
            "Absolute paths are not "
            "allowed in ZIP archives."
        ),
    )


def test_symbolic_link_is_rejected(
    tmp_path,
):
    zip_path = tmp_path / "repository.zip"
    extract_dir = tmp_path / "extracted"

    member = zipfile.ZipInfo(
        "project/link"
    )

    member.create_system = 3

    member.external_attr = (
        (0o120777 << 16)
    )

    with zipfile.ZipFile(
        zip_path,
        "w",
    ) as archive:
        archive.writestr(
            member,
            "target.txt",
        )

    assert_rejected(
        zip_path,
        extract_dir,
        (
            "Symbolic links are not "
            "allowed in repository ZIP archives."
        ),
    )


def test_encrypted_entry_is_rejected(
    monkeypatch,
    tmp_path,
):
    zip_path = tmp_path / "repository.zip"
    extract_dir = tmp_path / "extracted"

    write_zip(
        zip_path,
        [
            (
                "project/app.py",
                "print('hello')",
            ),
        ],
    )

    original_infolist = zipfile.ZipFile.infolist

    def encrypted_infolist(archive):
        members = original_infolist(archive)
        members[0].flag_bits |= 0x1
        return members

    monkeypatch.setattr(
        zipfile.ZipFile,
        "infolist",
        encrypted_infolist,
    )

    assert_rejected(
        zip_path,
        extract_dir,
        (
            "Encrypted ZIP entries are not "
            "allowed in repository archives."
        ),
    )


@pytest.mark.parametrize(
    "special_mode",
    [
        0o010000,  # FIFO
        0o020000,  # Character device
        0o060000,  # Block device
        0o140000,  # Socket
    ],
)
def test_unsupported_special_file_is_rejected(
    tmp_path,
    special_mode,
):
    zip_path = tmp_path / "repository.zip"
    extract_dir = tmp_path / "extracted"

    member = zipfile.ZipInfo(
        "project/special"
    )

    member.create_system = 3

    member.external_attr = (
        (special_mode | 0o644) << 16
    )

    with zipfile.ZipFile(
        zip_path,
        "w",
    ) as archive:
        archive.writestr(
            member,
            "special",
        )

    assert_rejected(
        zip_path,
        extract_dir,
        (
            "Unsupported special file type "
            "detected in ZIP archive."
        ),
    )


def test_archive_entry_count_limit_is_enforced(
    monkeypatch,
    tmp_path,
):
    zip_path = tmp_path / "repository.zip"
    extract_dir = tmp_path / "extracted"

    write_zip(
        zip_path,
        [
            ("one.txt", "1"),
            ("two.txt", "2"),
        ],
    )

    monkeypatch.setattr(
        repository_service,
        "MAX_FILE_COUNT",
        1,
    )

    assert_rejected(
        zip_path,
        extract_dir,
        (
            "Repository contains too "
            "many archive entries."
        ),
    )


def test_declared_extracted_size_limit_is_enforced(
    monkeypatch,
    tmp_path,
):
    zip_path = tmp_path / "repository.zip"
    extract_dir = tmp_path / "extracted"

    write_zip(
        zip_path,
        [
            (
                "project/data.txt",
                "1234567890",
            ),
        ],
    )

    monkeypatch.setattr(
        repository_service,
        "MAX_EXTRACTED_SIZE",
        5,
    )

    assert_rejected(
        zip_path,
        extract_dir,
        (
            "Extracted repository "
            "exceeds the allowed size."
        ),
    )
