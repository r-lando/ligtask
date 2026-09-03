import shutil
import tempfile
import zipfile

from pathlib import Path
from fastapi import UploadFile, HTTPException
from app.services.profiler import profile_repository
from app.services.semgrep_service import run_semgrep
from app.services.finding_normalizer import normalize_semgrep_findings

MAX_UPLOAD_SIZE = 50 * 1024 * 1024       # 50 MB
MAX_EXTRACTED_SIZE = 200 * 1024 * 1024  # 200 MB
MAX_FILE_COUNT = 5000


async def process_repository(file: UploadFile):
    temp_dir = Path(tempfile.mkdtemp(prefix="ligtask_"))

    try:
        zip_path = temp_dir / "repository.zip"

        # Save uploaded ZIP temporarily
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

        # Verify that the uploaded file is actually a ZIP archive
        if not zipfile.is_zipfile(zip_path):
            raise HTTPException(
                status_code=400,
                detail="The uploaded file is not a valid ZIP archive."
            )

        extract_dir = temp_dir / "repository"
        extract_dir.mkdir()

        with zipfile.ZipFile(zip_path, "r") as archive:
            members = archive.infolist()

            # File-count protection
            if len(members) > MAX_FILE_COUNT:
                raise HTTPException(
                    status_code=400,
                    detail="Repository contains too many files."
                )

            # Extracted-size protection
            extracted_size = sum(member.file_size for member in members)

            if extracted_size > MAX_EXTRACTED_SIZE:
                raise HTTPException(
                    status_code=400,
                    detail="Extracted repository exceeds the allowed size."
                )

            # Zip Slip / path traversal protection
            root = extract_dir.resolve()

            for member in members:
                destination = (extract_dir / member.filename).resolve()

                if root not in destination.parents and destination != root:
                    raise HTTPException(
                        status_code=400,
                        detail="Unsafe path detected in ZIP archive."
                    )

            archive.extractall(extract_dir)

        # Profile repository contents
        profile = profile_repository(extract_dir)

        semgrep_results = run_semgrep(extract_dir)

        normalized_findings = normalize_semgrep_findings(
            semgrep_results,
            extract_dir
        )

        return {
            "filename": file.filename,
            "status": "processed",
            "uploaded_size_bytes": total_uploaded,
            "extracted_size_bytes": extracted_size,
            "repository_profile": profile,
            "security_analysis": {
                "total_findings": len(normalized_findings),
                "findings": normalized_findings
            }
        }

    finally:
        # Repository is deleted whether processing succeeds or fails
        shutil.rmtree(temp_dir, ignore_errors=True)