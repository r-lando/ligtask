from fastapi import (
    APIRouter,
    File,
    HTTPException,
    Query,
    UploadFile,
)

from app.services.database_service import (
    get_assessment_by_id,
    get_assessment_count,
    get_assessments,
)
from app.services.repository_service import (
    process_repository,
)


router = APIRouter(
    prefix="/assessments",
    tags=["Assessments"],
)


@router.get("")
def list_assessments(
    limit: int = Query(
        default=50,
        ge=1,
        le=100,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
):
    """
    Retrieve stored assessment history.
    """
    assessments = get_assessments(
        limit=limit,
        offset=offset,
    )

    total = get_assessment_count()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "assessments": assessments,
    }


@router.get("/{assessment_id}")
def retrieve_assessment(
    assessment_id: str,
):
    """
    Retrieve one completed assessment and
    its consolidated security findings.
    """
    assessment = get_assessment_by_id(
        assessment_id
    )

    if assessment is None:
        raise HTTPException(
            status_code=404,
            detail="Assessment not found.",
        )

    return assessment


@router.post("/upload")
async def upload_repository(
    file: UploadFile = File(...),
):
    filename = file.filename or ""

    if not filename.lower().endswith(
        ".zip"
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Only ZIP repository files "
                "are allowed."
            ),
        )

    return await process_repository(
        file
    )