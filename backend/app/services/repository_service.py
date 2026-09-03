import shutil
import tempfile
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import HTTPException, UploadFile

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


async def process_repository(
    file: UploadFile,
):
    assessment_id = str(
        uuid.uuid4()
    )

    created_at = utc_now_iso()

    start_time = time.perf_counter()

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
        # 10. Combine raw findings
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
        # 11. Correlation / deduplication
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
        # 12. Assessment enrichment
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

        # -----------------------------------------
        # 13. Complete timing information
        # -----------------------------------------

        completed_at = utc_now_iso()

        processing_time_ms = round(
            (
                time.perf_counter()
                - start_time
            )
            * 1000
        )

        # -----------------------------------------
        # 14. Prepare SAFE database metadata
        # -----------------------------------------

        assessment_record = {
            "id": assessment_id,

            "repository_name": (
                file.filename
                or "repository.zip"
            ),

            "input_type": "ZIP",

            "status": "completed",

            "created_at": created_at,

            "completed_at": completed_at,

            "uploaded_size_bytes": (
                total_uploaded
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
        }

        # -----------------------------------------
        # 15. Store completed assessment
        # -----------------------------------------

        save_assessment(
            assessment_record,
            enriched_findings,
        )

        # -----------------------------------------
        # 16. Return assessment result
        # -----------------------------------------

        return {
            "assessment_id": (
                assessment_id
            ),

            "filename": file.filename,

            "status": "processed",

            "created_at": created_at,

            "completed_at": completed_at,

            "processing_time_ms": (
                processing_time_ms
            ),

            "uploaded_size_bytes": (
                total_uploaded
            ),

            "extracted_size_bytes": (
                extracted_size
            ),

            "repository_profile": (
                profile
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
                # Consolidated Ligtask analysis
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

    finally:
        # -----------------------------------------
        # 17. Delete temporary repository
        # -----------------------------------------

        shutil.rmtree(
            temp_dir,
            ignore_errors=True,
        )