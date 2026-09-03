import shutil
import tempfile
import zipfile
from pathlib import Path

from fastapi import HTTPException, UploadFile

from app.services.config_service import (
    scan_configurations,
)
from app.services.correlation_service import (
    correlate_findings,
)
from app.services.dependency_service import (
    scan_dependencies,
)
from app.services.finding_normalizer import (
    create_severity_summary,
    normalize_config_findings,
    normalize_osv_findings,
    normalize_secret_findings,
    normalize_semgrep_findings,
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


async def process_repository(
    file: UploadFile
):
    temp_dir = Path(
        tempfile.mkdtemp(
            prefix="ligtask_"
        )
    )

    try:
        zip_path = (
            temp_dir / "repository.zip"
        )

        # -----------------------------------------
        # 1. Save uploaded ZIP temporarily
        # -----------------------------------------

        total_uploaded = 0

        with zip_path.open("wb") as buffer:
            while chunk := await file.read(
                1024 * 1024
            ):
                total_uploaded += len(chunk)

                if (
                    total_uploaded
                    > MAX_UPLOAD_SIZE
                ):
                    raise HTTPException(
                        status_code=413,
                        detail=(
                            "Repository ZIP exceeds "
                            "the 50 MB upload limit."
                        ),
                    )

                buffer.write(chunk)

        # -----------------------------------------
        # 2. Verify ZIP
        # -----------------------------------------

        if not zipfile.is_zipfile(
            zip_path
        ):
            raise HTTPException(
                status_code=400,
                detail=(
                    "The uploaded file is not "
                    "a valid ZIP archive."
                ),
            )

        # -----------------------------------------
        # 3. Create extraction workspace
        # -----------------------------------------

        extract_dir = (
            temp_dir / "repository"
        )

        extract_dir.mkdir()

        # -----------------------------------------
        # 4. Validate and extract ZIP
        # -----------------------------------------

        with zipfile.ZipFile(
            zip_path,
            "r",
        ) as archive:
            members = archive.infolist()

            if (
                len(members)
                > MAX_FILE_COUNT
            ):
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Repository contains too "
                        "many files."
                    ),
                )

            extracted_size = sum(
                member.file_size
                for member in members
            )

            if (
                extracted_size
                > MAX_EXTRACTED_SIZE
            ):
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Extracted repository "
                        "exceeds the allowed size."
                    ),
                )

            root = extract_dir.resolve()

            for member in members:
                destination = (
                    extract_dir
                    / member.filename
                ).resolve()

                if (
                    root
                    not in destination.parents
                    and destination != root
                ):
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            "Unsafe path detected "
                            "in ZIP archive."
                        ),
                    )

            archive.extractall(
                extract_dir
            )

        # -----------------------------------------
        # 5. Repository profiling
        # -----------------------------------------

        profile = profile_repository(
            extract_dir
        )

        # -----------------------------------------
        # 6. Semgrep SAST
        # -----------------------------------------

        semgrep_results = run_semgrep(
            extract_dir
        )

        normalized_sast_findings = (
            normalize_semgrep_findings(
                semgrep_results,
                extract_dir,
            )
        )

        # -----------------------------------------
        # 7. Dependency assessment
        # -----------------------------------------

        dependency_results = (
            scan_dependencies(
                extract_dir
            )
        )

        normalized_dependency_findings = (
            normalize_osv_findings(
                dependency_results,
                extract_dir,
            )
        )

        # -----------------------------------------
        # 8. Secret detection
        # -----------------------------------------

        secret_results = scan_secrets(
            extract_dir
        )

        normalized_secret_findings = (
            normalize_secret_findings(
                secret_results,
                extract_dir,
            )
        )

        # -----------------------------------------
        # 9. Configuration assessment
        # -----------------------------------------

        config_results = (
            scan_configurations(
                extract_dir
            )
        )

        normalized_config_findings = (
            normalize_config_findings(
                config_results,
                extract_dir,
            )
        )

        # -----------------------------------------
        # 10. Combine RAW findings
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
        # 11. Correlation and deduplication
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

        consolidated_severity_summary = (
            create_severity_summary(
                consolidated_findings
            )
        )

        # -----------------------------------------
        # 12. Return assessment result
        # -----------------------------------------

        return {
            "filename": file.filename,

            "status": "processed",

            "uploaded_size_bytes": (
                total_uploaded
            ),

            "extracted_size_bytes": (
                extracted_size
            ),

            "repository_profile": profile,

            "security_analysis": {

                # -----------------------------
                # RAW scanner output
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
                # Consolidated Ligtask output
                # -----------------------------

                "consolidated_analysis": {

                    "total_findings": len(
                        consolidated_findings
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

                    "duplicate_findings_removed": (
                        correlation_results.get(
                            "duplicate_findings_removed",
                            0,
                        )
                    ),

                    "findings": (
                        consolidated_findings
                    ),
                },

                # -----------------------------
                # Scanner statistics
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
                        consolidated_findings
                    ),

                    "correlated_groups": (
                        correlation_results.get(
                            "correlated_groups",
                            0,
                        )
                    ),
                },
            },
        }

    finally:
        # -----------------------------------------
        # 13. Delete temporary repository
        # -----------------------------------------

        shutil.rmtree(
            temp_dir,
            ignore_errors=True,
        )