from fastapi import APIRouter, File, HTTPException, UploadFile

from app.services.repository_service import process_repository


router = APIRouter(
    prefix="/assessments",
    tags=["Assessments"]
)


@router.post("/upload")
async def upload_repository(file: UploadFile = File(...)):
    filename = file.filename or ""

    if not filename.lower().endswith(".zip"):
        raise HTTPException(
            status_code=400,
            detail="Only ZIP repository files are allowed."
        )

    return await process_repository(file)