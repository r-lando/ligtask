import shutil
import tempfile
import zipfile
from pathlib import Path

from fastapi import HTTPException, UploadFile

from app.services.dependency_service import scan_dependencies
from app.services.finding_normalizer import (
    normalize_osv_findings,
    normalize_semgrep_findings,
)
from app.services.profiler import profile_repository
from app.services.semgrep_service import run_semgrep


MAX_UPLOAD_SIZE = 50 * 1024 * 1024       # 50 MB
MAX_EXTRACTED_SIZE = 200 * 1024 * 1024  # 200 MB
MAX_FILE_COUNT = 5000


async def process_repository(file: UploadFile):
    temp_dir = Path(tempfile.mkdtemp(prefix="ligtask_"))

    try:
        zip_path = temp_dir / "repository.zip"

        # ---------------------------------------------------------
        # 1. Save uploaded ZIP temporarily
        # ---------------------------------------------------------
        total_uploaded = 0

        with zip_path.open("wb") as buffer:
            while chunk := await file.read(1024 * 1024):
                total_uploaded += len(chunk)

                if total_uploaded > MAX_UPLOAD_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="Repository ZIP exceeds the 50 MB upload limit."
                    )

                buffer.write(chunk)

        # ---------------------------------------------------------
        # 2. Verify that the uploaded file is a valid ZIP
        # ---------------------------------------------------------
        if not zipfile.is_zipfile(zip_path):
            raise HTTPException(
                status_code=400,
                detail="The uploaded file is not a valid ZIP archive."
            )

        # ---------------------------------------------------------
        # 3. Create temporary extraction directory
        # ---------------------------------------------------------
        extract_dir = temp_dir / "repository"
        extract_dir.mkdir()

        # ---------------------------------------------------------
        # 4. Validate and extract repository
        # ---------------------------------------------------------
        with zipfile.ZipFile(zip_path, "r") as archive:
            members = archive.infolist()

            # File-count protection
            if len(members) > MAX_FILE_COUNT:
                raise HTTPException(
                    status_code=400,
                    detail="Repository contains too many files."
                )

            # Extracted-size protection
            extracted_size = sum(
                member.file_size for member in members
            )

            if extracted_size > MAX_EXTRACTED_SIZE:
                raise HTTPException(
                    status_code=400,
                    detail="Extracted repository exceeds the allowed size."
                )

            # Zip Slip / path traversal protection
            root = extract_dir.resolve()

            for member in members:
                destination = (
                    extract_dir / member.filename
                ).resolve()

                if (
                    root not in destination.parents
                    and destination != root
                ):
                    raise HTTPException(
                        status_code=400,
                        detail="Unsafe path detected in ZIP archive."
                    )

            archive.extractall(extract_dir)

        # ---------------------------------------------------------
        # 5. Profile repository
        # ---------------------------------------------------------
        profile = profile_repository(extract_dir)

        # ---------------------------------------------------------
        # 6. Run Semgrep SAST
        # ---------------------------------------------------------
        semgrep_results = run_semgrep(extract_dir)

        normalized_sast_findings = normalize_semgrep_findings(
            semgrep_results,
            extract_dir
        )

        # ---------------------------------------------------------
        # 7. Run dependency vulnerability assessment
        # ---------------------------------------------------------
        dependency_results = scan_dependencies(
            extract_dir
        )

        normalized_dependency_findings = normalize_osv_findings(
            dependency_results,
            extract_dir
        )

        # ---------------------------------------------------------
        # 8. Combine normalized findings
        # ---------------------------------------------------------
        all_findings = (
            normalized_sast_findings
            + normalized_dependency_findings
        )

        # ---------------------------------------------------------
        # 9. Return consolidated Ligtask assessment
        # ---------------------------------------------------------
        return {
            "filename": file.filename,
            "status": "processed",
            "uploaded_size_bytes": total_uploaded,
            "extracted_size_bytes": extracted_size,

            "repository_profile": profile,

            "security_analysis": {
                "total_findings": len(all_findings),

                "findings": all_findings,

                "summary": {
                    "sast_findings": len(
                        normalized_sast_findings
                    ),
                    "dependency_findings": len(
                        normalized_dependency_findings
                    ),
                    "dependencies_checked": dependency_results.get(
                        "dependencies_checked",
                        0
                    ),
                }
            }
        }

    finally:
        # ---------------------------------------------------------
        # 10. Delete temporary repository
        # ---------------------------------------------------------
        shutil.rmtree(
            temp_dir,
            ignore_errors=True
        )