import shutil
import tempfile
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from fastapi import HTTPException, UploadFile
from starlette.concurrency import run_in_threadpool

from app.services.config_service import (
    scan_configurations,
)
from app.services.correlation_service import (
    correlate_findings,
)
from app.services.database_service import (
    save_assessment,
)
from app.services.dependency_service import (
    scan_dependencies,
)
from app.services.enrichment_service import (
    enrich_findings,
)
from app.services.finding_normalizer import (
    create_severity_summary,
    normalize_config_findings,
    normalize_osv_findings,
    normalize_secret_findings,
    normalize_semgrep_findings,
)
from app.services.github_service import (
    GitHubRepositoryError,
    retrieve_public_repository,
)
from app.services.profiler import (
    profile_repository,
)
from app.services.secret_service import (
    scan_secrets,
)
from app.services.semgrep_service import (
    run_semgrep,
)


MAX_UPLOAD_SIZE = 50 * 1024 * 1024
MAX_EXTRACTED_SIZE = 200 * 1024 * 1024
MAX_FILE_COUNT = 5000


def utc_now_iso():
    """
    Return the current UTC timestamp in
    ISO 8601 format.
    """
    return datetime.now(
        timezone.utc
    ).isoformat()


def is_zip_symlink(member):
    """
    Return True when a ZIP member represents
    a symbolic link on Unix-like systems.
    """
    unix_mode = (
        member.external_attr >> 16
    )

    file_type = unix_mode & 0o170000

    return file_type == 0o120000

def is_unsupported_zip_special_file(member):
    """
    Return True when a ZIP member explicitly
    represents an unsupported Unix special file.

    Regular files, directories, and entries without
    Unix file-type metadata are allowed.
    """
    unix_mode = (
        member.external_attr >> 16
    )

    file_type = unix_mode & 0o170000

    allowed_file_types = {
        0,
        0o040000,  # Directory
        0o100000,  # Regular file
    }

    return file_type not in allowed_file_types


def validate_and_extract_archive(
    zip_path,
    extract_dir,
):
    """
    Validate and securely extract a repository ZIP archive.

    Security controls:
    - Valid ZIP verification
    - Maximum archive entry count
    - Maximum total extracted size
    - Path traversal prevention
    - Absolute path rejection
    - Windows-style path traversal rejection
    - Symbolic link rejection
    - Encrypted entry rejection
    - Unsupported special file rejection
    - Per-entry controlled extraction

    Returns the total number of bytes actually extracted.
    """

    if not zipfile.is_zipfile(zip_path):
        raise HTTPException(
            status_code=400,
            detail=(
                "Repository data is not "
                "a valid ZIP archive."
            ),
        )

    extract_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    root = extract_dir.resolve()

    try:
        with zipfile.ZipFile(
            zip_path,
            "r",
        ) as archive:
            members = archive.infolist()

            # -----------------------------------------
            # 1. Limit archive entry count
            # -----------------------------------------

            if len(members) > MAX_FILE_COUNT:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Repository contains too "
                        "many archive entries."
                    ),
                )

            # -----------------------------------------
            # 2. Validate declared extracted size
            # -----------------------------------------

            declared_size = sum(
                member.file_size
                for member in members
            )

            if declared_size > MAX_EXTRACTED_SIZE:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Extracted repository "
                        "exceeds the allowed size."
                    ),
                )

            actual_extracted_size = 0

            # -----------------------------------------
            # 3. Validate and extract each entry
            # -----------------------------------------

            for member in members:
                member_name = member.filename

                # ZIP entries should use forward slashes,
                # but normalize backslashes so Windows-style
                # traversal attempts are handled consistently.
                normalized_name = member_name.replace(
                    "\\",
                    "/",
                )

                # Reject empty or suspicious names.
                if not normalized_name:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            "Invalid empty path detected "
                            "in ZIP archive."
                        ),
                    )
                # Reject encrypted ZIP entries.
                if member.flag_bits & 0x1:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            "Encrypted ZIP entries are not "
                            "allowed in repository archives."
                        ),
                    )

                member_path = PurePosixPath(
                    normalized_name
                )

                # Reject Windows drive-style paths such as:
                # C:/Windows/file.txt
                if (
                    len(normalized_name) >= 2
                    and normalized_name[1] == ":"
                    and normalized_name[0].isalpha()
                ):
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            "Drive-qualified paths are not "
                            "allowed in ZIP archives."
                        ),
                    )

                # Reject absolute paths such as:
                # /etc/passwd
                if member_path.is_absolute():
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            "Absolute paths are not "
                            "allowed in ZIP archives."
                        ),
                    )

                # Explicitly reject traversal components.
                if ".." in member_path.parts:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            "Path traversal detected "
                            "in ZIP archive."
                        ),
                    )

                # Reject symbolic links.
                if is_zip_symlink(member):
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            "Symbolic links are not "
                            "allowed in repository ZIP "
                            "archives."
                        ),
                    )
                # Reject unsupported Unix special file types.
                if is_unsupported_zip_special_file(member):
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            "Unsupported special file type "
                            "detected in ZIP archive."
                        ),
                    )

                destination = (
                    extract_dir
                    / member_path
                ).resolve()

                # Defense-in-depth containment check.
                if (
                    destination != root
                    and root not in destination.parents
                ):
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            "Unsafe path detected "
                            "in ZIP archive."
                        ),
                    )

                # -------------------------------------
                # Directory entry
                # -------------------------------------

                if member.is_dir():
                    destination.mkdir(
                        parents=True,
                        exist_ok=True,
                    )
                    continue

                # -------------------------------------
                # File entry
                # -------------------------------------

                destination.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                try:
                    with archive.open(
                        member,
                        "r",
                    ) as source:
                        with destination.open(
                            "wb",
                        ) as target:
                            while True:
                                chunk = source.read(
                                    1024 * 1024
                                )

                                if not chunk:
                                    break

                                actual_extracted_size += len(
                                    chunk
                                )

                                if (
                                    actual_extracted_size
                                    > MAX_EXTRACTED_SIZE
                                ):
                                    raise HTTPException(
                                        status_code=400,
                                        detail=(
                                            "Extracted repository "
                                            "exceeds the allowed size."
                                        ),
                                    )

                                target.write(chunk)

                except (
                    RuntimeError,
                    zipfile.BadZipFile,
                    EOFError,
                ) as exc:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            "Repository ZIP contains an "
                            "invalid or corrupted entry."
                        ),
                    ) from exc

            return actual_extracted_size

    except HTTPException:
        raise

    except (
        zipfile.BadZipFile,
        RuntimeError,
        EOFError,
    ) as exc:
        raise HTTPException(
            status_code=400,
            detail=(
                "Repository ZIP archive is invalid "
                "or corrupted."
            ),
        ) from exc


def resolve_repository_root(
    extract_dir,
):
    """
    Return the effective repository root.

    ZIP archives, including GitHub source archives,
    commonly contain one wrapper directory around the
    actual repository contents. When the extraction
    directory contains exactly one top-level directory
    and no top-level files, treat that directory as the
    repository root. Otherwise, keep the extraction
    directory itself as the root.
    """
    extract_dir = Path(extract_dir)

    entries = list(
        extract_dir.iterdir()
    )

    top_level_directories = [
        entry
        for entry in entries
        if entry.is_dir()
    ]

    top_level_files = [
        entry
        for entry in entries
        if entry.is_file()
    ]

    if (
        len(top_level_directories) == 1
        and not top_level_files
    ):
        return top_level_directories[0]

    return extract_dir


def run_assessment_pipeline(
    extract_dir,
):
    """
    Run the common TALGED repository
    security assessment pipeline.

    Both ZIP uploads and public GitHub
    repositories use this same pipeline.

    The pipeline records the execution status
    of each assessment mechanism so scanner
    failures are not confused with zero findings.
    """

    repository_root = resolve_repository_root(
        extract_dir
    )

    # -----------------------------------------
    # 1. Repository profiling
    # -----------------------------------------

    profile = profile_repository(
        repository_root
    )

    # -----------------------------------------
    # 2. Semgrep SAST
    # -----------------------------------------

    semgrep_results = run_semgrep(
        repository_root
    )

    normalized_sast_findings = (
        normalize_semgrep_findings(
            semgrep_results,
            repository_root,
        )
    )

    if semgrep_results.get(
        "success"
    ):
        sast_status = {
            "status": "completed",
            "scanner": "Semgrep",
            "findings_count": len(
                normalized_sast_findings
            ),
            "error": None,
            "note": semgrep_results.get("note"),
        }

    elif semgrep_results.get(
        "timed_out"
    ):
        sast_status = {
            "status": "timed_out",
            "scanner": "Semgrep",
            "findings_count": 0,
            "error": semgrep_results.get(
                "error"
            ),
        }

    else:
        sast_status = {
            "status": "failed",
            "scanner": "Semgrep",
            "findings_count": 0,
            "error": semgrep_results.get(
                "error"
            ),
        }

    # -----------------------------------------
    # 3. Dependency assessment
    # -----------------------------------------

    dependency_results = (
        scan_dependencies(
            repository_root
        )
    )

    normalized_dependency_findings = (
        normalize_osv_findings(
            dependency_results,
            repository_root,
        )
    )

    dependency_scan_status = (
        dependency_results.get(
            "scan_status",
            "failed",
        )
    )

    dependency_request_errors = (
        dependency_results.get(
            "request_errors",
            [],
        )
    )

    if dependency_scan_status == "completed":
        dependency_status = {
            "status": "completed",
            "scanner": "OSV",
            "findings_count": len(
                normalized_dependency_findings
            ),
            "error": None,
            "note": (
                "No software libraries were checked. TALGED currently reads npm package-lock.json files."
                if dependency_results.get("dependencies_checked") == 0
                else "Checked software libraries listed in supported npm lockfiles only. Other library sources are not covered."
            ),
        }

    elif dependency_scan_status == "completed_with_errors":
        dependency_status = {
            "status": "partial",
            "scanner": "OSV",
            "findings_count": len(
                normalized_dependency_findings
            ),
            "error": (
                "OSV dependency assessment completed "
                "with one or more request errors."
            ),
        }

    else:
        dependency_status = {
            "status": "failed",
            "scanner": "OSV",
            "findings_count": len(
                normalized_dependency_findings
            ),
            "error": (
                dependency_request_errors[0].get(
                    "error"
                )
                if dependency_request_errors
                else (
                    "OSV dependency assessment "
                    "did not complete successfully."
                )
            ),
        }

    # -----------------------------------------
    # 4. Secret detection
    # -----------------------------------------

    secret_results = scan_secrets(
        repository_root
    )

    normalized_secret_findings = (
        normalize_secret_findings(
            secret_results,
            repository_root,
        )
    )

    secret_scan_status = secret_results.get(
        "scan_status",
        "failed",
    )

    secret_processing_errors = secret_results.get(
        "processing_errors",
        [],
    )

    if secret_scan_status == "completed":
        secret_status = {
            "status": "completed",
            "scanner": "TALGED",
            "findings_count": len(
                normalized_secret_findings
            ),
            "error": None,
        }

    elif secret_scan_status == "completed_with_errors":
        secret_status = {
            "status": "partial",
            "scanner": "TALGED",
            "findings_count": len(
                normalized_secret_findings
            ),
            "error": (
                "Secret detection completed with "
                "one or more file-processing errors."
            ),
        }

    else:
        secret_status = {
            "status": "failed",
            "scanner": "TALGED",
            "findings_count": len(
                normalized_secret_findings
            ),
            "error": (
                secret_processing_errors[0].get(
                    "error"
                )
                if secret_processing_errors
                else (
                    "Secret detection did not "
                    "complete successfully."
                )
            ),
        }

    # -----------------------------------------
    # 5. Configuration assessment
    # -----------------------------------------

    config_results = (
        scan_configurations(
            repository_root
        )
    )

    normalized_config_findings = (
        normalize_config_findings(
            config_results,
            repository_root,
        )
    )

    config_scan_status = config_results.get(
        "scan_status",
        "failed",
    )

    config_processing_errors = config_results.get(
        "processing_errors",
        [],
    )

    if config_scan_status == "completed":
        configuration_status = {
            "status": "completed",
            "scanner": "TALGED",
            "findings_count": len(
                normalized_config_findings
            ),
            "error": None,
        }

    elif config_scan_status == "completed_with_errors":
        configuration_status = {
            "status": "partial",
            "scanner": "TALGED",
            "findings_count": len(
                normalized_config_findings
            ),
            "error": (
                "Configuration assessment completed "
                "with one or more file-processing "
                "errors."
            ),
        }

    else:
        configuration_status = {
            "status": "failed",
            "scanner": "TALGED",
            "findings_count": len(
                normalized_config_findings
            ),
            "error": (
                config_processing_errors[0].get(
                    "error"
                )
                if config_processing_errors
                else (
                    "Configuration assessment did "
                    "not complete successfully."
                )
            ),
        }

    # -----------------------------------------
    # 6. Mechanism execution status
    # -----------------------------------------

    mechanism_statuses = {
        "sast": sast_status,
        "dependency": dependency_status,
        "secret": secret_status,
        "configuration": (
            configuration_status
        ),
    }

    assessment_status = "completed"

    if any(
        mechanism.get("status")
        != "completed"
        for mechanism
        in mechanism_statuses.values()
    ):
        assessment_status = "partial"

    # -----------------------------------------
    # 7. Combine available raw findings
    # -----------------------------------------

    raw_findings = (
        normalized_sast_findings
        + normalized_dependency_findings
        + normalized_secret_findings
        + normalized_config_findings
    )

    raw_severity_summary = (
        create_severity_summary(
            raw_findings
        )
    )

    # -----------------------------------------
    # 8. Correlation / deduplication
    # -----------------------------------------

    correlation_results = (
        correlate_findings(
            raw_findings
        )
    )

    consolidated_findings = (
        correlation_results.get(
            "findings",
            [],
        )
    )

    # -----------------------------------------
    # 9. Assessment enrichment
    # -----------------------------------------

    enriched_findings = (
        enrich_findings(
            consolidated_findings
        )
    )

    consolidated_severity_summary = (
        create_severity_summary(
            enriched_findings
        )
    )

    return {
        "profile": profile,

        "assessment_status": (
            assessment_status
        ),

        "mechanism_statuses": (
            mechanism_statuses
        ),

        "raw_findings": raw_findings,

        "raw_severity_summary": (
            raw_severity_summary
        ),

        "enriched_findings": (
            enriched_findings
        ),

        "consolidated_severity_summary": (
            consolidated_severity_summary
        ),

        "correlation_results": (
            correlation_results
        ),

        "normalized_sast_findings": (
            normalized_sast_findings
        ),

        "normalized_dependency_findings": (
            normalized_dependency_findings
        ),

        "normalized_secret_findings": (
            normalized_secret_findings
        ),

        "normalized_config_findings": (
            normalized_config_findings
        ),

        "dependency_results": (
            dependency_results
        ),

        "secret_results": (
            secret_results
        ),

        "config_results": (
            config_results
        ),
    }


def finalize_assessment(
    *,
    assessment_id,
    repository_name,
    input_type,
    created_at,
    start_time,
    input_size_bytes,
    extracted_size,
    pipeline_results,
):
    """
    Persist and return a completed or partial
    TALGED assessment using safe assessment data.
    """
    completed_at = utc_now_iso()

    processing_time_ms = round(
        (
            time.perf_counter()
            - start_time
        )
        * 1000
    )

    profile = pipeline_results[
        "profile"
    ]

    raw_findings = pipeline_results[
        "raw_findings"
    ]

    raw_severity_summary = (
        pipeline_results[
            "raw_severity_summary"
        ]
    )

    enriched_findings = (
        pipeline_results[
            "enriched_findings"
        ]
    )

    consolidated_severity_summary = (
        pipeline_results[
            "consolidated_severity_summary"
        ]
    )

    correlation_results = (
        pipeline_results[
            "correlation_results"
        ]
    )

    normalized_sast_findings = (
        pipeline_results[
            "normalized_sast_findings"
        ]
    )

    normalized_dependency_findings = (
        pipeline_results[
            "normalized_dependency_findings"
        ]
    )

    normalized_secret_findings = (
        pipeline_results[
            "normalized_secret_findings"
        ]
    )

    normalized_config_findings = (
        pipeline_results[
            "normalized_config_findings"
        ]
    )

    dependency_results = (
        pipeline_results[
            "dependency_results"
        ]
    )

    secret_results = (
        pipeline_results[
            "secret_results"
        ]
    )

    config_results = (
        pipeline_results[
            "config_results"
        ]
    )

    assessment_status = (
        pipeline_results.get(
            "assessment_status",
            "completed",
        )
    )

    mechanism_statuses = (
        pipeline_results.get(
            "mechanism_statuses",
            {},
        )
    )

    # -----------------------------------------
    # Prepare SAFE database metadata
    # -----------------------------------------

    assessment_record = {
        "id": assessment_id,

        "repository_name": (
            repository_name
        ),

        "input_type": input_type,

        "status": assessment_status,

        "created_at": created_at,

        "completed_at": completed_at,

        "uploaded_size_bytes": (
            input_size_bytes
        ),

        "extracted_size_bytes": (
            extracted_size
        ),

        "total_files": profile.get(
            "total_files",
            0,
        ),

        "processing_time_ms": (
            processing_time_ms
        ),

        "raw_findings_count": len(
            raw_findings
        ),

        "consolidated_findings_count": (
            len(
                enriched_findings
            )
        ),

        "critical_count": (
            consolidated_severity_summary.get(
                "CRITICAL",
                0,
            )
        ),

        "high_count": (
            consolidated_severity_summary.get(
                "HIGH",
                0,
            )
        ),

        "medium_count": (
            consolidated_severity_summary.get(
                "MEDIUM",
                0,
            )
        ),

        "low_count": (
            consolidated_severity_summary.get(
                "LOW",
                0,
            )
        ),

        "info_count": (
            consolidated_severity_summary.get(
                "INFO",
                0,
            )
        ),

        "unknown_count": (
            consolidated_severity_summary.get(
                "UNKNOWN",
                0,
            )
        ),

        "correlated_groups": (
            correlation_results.get(
                "correlated_groups",
                0,
            )
        ),

        "duplicate_findings_merged": (
            correlation_results.get(
                "duplicate_findings_removed",
                0,
            )
        ),

        "languages": profile.get(
            "languages",
            {},
        ),

        "dependency_files": profile.get(
            "dependency_files",
            [],
        ),

        "configuration_files": profile.get(
            "configuration_files",
            [],
        ),

        "mechanism_statuses": (
            mechanism_statuses
        ),
    }

    # -----------------------------------------
    # Store completed or partial assessment
    # -----------------------------------------

    save_assessment(
        assessment_record,
        enriched_findings,
    )

    # -----------------------------------------
    # Return assessment result
    # -----------------------------------------

    return {
        "assessment_id": (
            assessment_id
        ),

        "repository_name": (
            repository_name
        ),

        "input_type": input_type,

        "status": assessment_status,

        "created_at": created_at,

        "completed_at": completed_at,

        "processing_time_ms": (
            processing_time_ms
        ),

        "uploaded_size_bytes": (
            input_size_bytes
        ),

        "extracted_size_bytes": (
            extracted_size
        ),

        "repository_profile": (
            profile
        ),

        "mechanism_statuses": (
            mechanism_statuses
        ),

        "security_analysis": {

            # -----------------------------
            # Raw scanner evidence
            # -----------------------------

            "total_findings": len(
                raw_findings
            ),

            "severity_summary": (
                raw_severity_summary
            ),

            "findings": (
                raw_findings
            ),

            # -----------------------------
            # Consolidated TALGED analysis
            # -----------------------------

            "consolidated_analysis": {

                "total_findings": len(
                    enriched_findings
                ),

                "severity_summary": (
                    consolidated_severity_summary
                ),

                "correlated_groups": (
                    correlation_results.get(
                        "correlated_groups",
                        0,
                    )
                ),

                "duplicate_findings_merged": (
                    correlation_results.get(
                        "duplicate_findings_removed",
                        0,
                    )
                ),

                "findings": (
                    enriched_findings
                ),
            },

            # -----------------------------
            # Assessment statistics
            # -----------------------------

            "summary": {

                "sast_findings": len(
                    normalized_sast_findings
                ),

                "dependency_findings": len(
                    normalized_dependency_findings
                ),

                "secret_findings": len(
                    normalized_secret_findings
                ),

                "configuration_findings": len(
                    normalized_config_findings
                ),

                "dependencies_checked": (
                    dependency_results.get(
                        "dependencies_checked",
                        0,
                    )
                ),

                "secret_files_scanned": (
                    secret_results.get(
                        "files_scanned",
                        0,
                    )
                ),

                "configuration_files_scanned": (
                    config_results.get(
                        "files_scanned",
                        0,
                    )
                ),

                "raw_findings": len(
                    raw_findings
                ),

                "consolidated_findings": len(
                    enriched_findings
                ),

                "correlated_groups": (
                    correlation_results.get(
                        "correlated_groups",
                        0,
                    )
                ),

                "duplicate_findings_merged": (
                    correlation_results.get(
                        "duplicate_findings_removed",
                        0,
                    )
                ),
            },
        },
    }


async def process_repository(
    file: UploadFile,
):
    # Extraction, scanners, network calls and persistence are synchronous.
    # Keep the request alive until the worker finishes so its upload stays open.
    return await run_in_threadpool(_process_repository, file)


def _process_repository(file: UploadFile):
    """
    Process a repository submitted through
    ZIP upload.
    """
    assessment_id = str(
        uuid.uuid4()
    )

    created_at = utc_now_iso()

    start_time = time.perf_counter()

    temp_dir = Path(
        tempfile.mkdtemp(
            prefix="talged_"
        )
    )

    try:
        zip_path = (
            temp_dir
            / "repository.zip"
        )

        # -----------------------------------------
        # 1. Save uploaded ZIP temporarily
        # -----------------------------------------

        total_uploaded = 0

        with zip_path.open(
            "wb"
        ) as buffer:
            while chunk := file.file.read(
                1024 * 1024
            ):
                total_uploaded += len(
                    chunk
                )

                if (
                    total_uploaded
                    > MAX_UPLOAD_SIZE
                ):
                    raise HTTPException(
                        status_code=413,
                        detail=(
                            "Repository ZIP "
                            "exceeds the 50 MB "
                            "upload limit."
                        ),
                    )

                buffer.write(
                    chunk
                )

        # -----------------------------------------
        # 2. Securely validate/extract ZIP
        # -----------------------------------------

        extract_dir = (
            temp_dir
            / "repository"
        )

        extracted_size = (
            validate_and_extract_archive(
                zip_path,
                extract_dir,
            )
        )

        # -----------------------------------------
        # 3. Run common assessment pipeline
        # -----------------------------------------

        pipeline_results = (
            run_assessment_pipeline(
                extract_dir
            )
        )

        # -----------------------------------------
        # 4. Persist and return result
        # -----------------------------------------

        return finalize_assessment(
            assessment_id=assessment_id,
            repository_name=(
                file.filename
                or "repository.zip"
            ),
            input_type="ZIP",
            created_at=created_at,
            start_time=start_time,
            input_size_bytes=(
                total_uploaded
            ),
            extracted_size=(
                extracted_size
            ),
            pipeline_results=(
                pipeline_results
            ),
        )

    finally:
        # -----------------------------------------
        # Delete temporary repository
        # -----------------------------------------

        shutil.rmtree(
            temp_dir,
            ignore_errors=True,
        )


def process_github_repository(
    repository_url,
):
    """
    Retrieve and assess a public GitHub
    repository.

    The downloaded repository archive and
    extracted source code exist only in the
    temporary processing workspace and are
    deleted after processing.
    """
    assessment_id = str(
        uuid.uuid4()
    )

    created_at = utc_now_iso()

    start_time = time.perf_counter()

    temp_dir = Path(
        tempfile.mkdtemp(
            prefix="talged_github_"
        )
    )

    try:
        # -----------------------------------------
        # 1. Validate and retrieve GitHub repo
        # -----------------------------------------

        try:
            github_repository = (
                retrieve_public_repository(
                    repository_url
                )
            )

        except GitHubRepositoryError as exc:
            raise HTTPException(
                status_code=400,
                detail=str(exc),
            ) from exc

        archive_bytes = (
            github_repository[
                "archive_bytes"
            ]
        )

        if (
            len(archive_bytes)
            > MAX_UPLOAD_SIZE
        ):
            raise HTTPException(
                status_code=413,
                detail=(
                    "GitHub repository archive "
                    "exceeds the 50 MB "
                    "processing limit."
                ),
            )

        # -----------------------------------------
        # 2. Write archive temporarily
        # -----------------------------------------

        zip_path = (
            temp_dir
            / "repository.zip"
        )

        zip_path.write_bytes(
            archive_bytes
        )

        # Do not retain another reference to
        # repository archive bytes longer than
        # necessary.
        archive_size = len(
            archive_bytes
        )

        del archive_bytes

        github_repository.pop(
            "archive_bytes",
            None,
        )

        # -----------------------------------------
        # 3. Securely validate/extract archive
        # -----------------------------------------

        extract_dir = (
            temp_dir
            / "repository"
        )

        extracted_size = (
            validate_and_extract_archive(
                zip_path,
                extract_dir,
            )
        )

        # -----------------------------------------
        # 4. Run common assessment pipeline
        # -----------------------------------------

        pipeline_results = (
            run_assessment_pipeline(
                extract_dir
            )
        )

        # -----------------------------------------
        # 5. Persist and return result
        # -----------------------------------------

        result = finalize_assessment(
            assessment_id=assessment_id,
            repository_name=(
                github_repository[
                    "full_name"
                ]
            ),
            input_type="GITHUB",
            created_at=created_at,
            start_time=start_time,
            input_size_bytes=(
                archive_size
            ),
            extracted_size=(
                extracted_size
            ),
            pipeline_results=(
                pipeline_results
            ),
        )

        result["repository_url"] = (
            github_repository[
                "repository_url"
            ]
        )

        result["default_branch"] = (
            github_repository[
                "default_branch"
            ]
        )

        return result

    finally:
        # -----------------------------------------
        # Delete temporary GitHub repository
        # -----------------------------------------

        shutil.rmtree(
            temp_dir,
            ignore_errors=True,
        )
