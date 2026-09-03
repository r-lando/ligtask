from io import BytesIO

from fastapi import (
    APIRouter,
    File,
    HTTPException,
    Query,
    UploadFile,
)
from fastapi.responses import (
    HTMLResponse,
    StreamingResponse,
)

from app.models.assessment_models import (
    GitHubAssessmentRequest,
)
from app.services.database_service import (
    get_assessment_by_id,
    get_assessment_count,
    get_assessments,
)
from app.services.pdf_report_service import (
    generate_assessment_pdf,
)
from app.services.report_service import (
    generate_assessment_html,
)
from app.services.repository_service import (
    process_github_repository,
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


@router.post("/github")
def assess_github_repository(
    request: GitHubAssessmentRequest,
):
    return process_github_repository(
        request.repository_url
    )


@router.get(
    "/{assessment_id}/report.pdf",
)
def download_assessment_pdf(
    assessment_id: str,
):
    pdf_bytes = generate_assessment_pdf(
        assessment_id
    )

    if pdf_bytes is None:
        raise HTTPException(
            status_code=404,
            detail="Assessment not found.",
        )

    filename = (
        f"ligtask-assessment-"
        f"{assessment_id}.pdf"
    )

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{filename}"'
            ),
            "Cache-Control": "no-store",
        },
    )


@router.get(
    "/{assessment_id}/report",
    response_class=HTMLResponse,
)
def get_assessment_report(
    assessment_id: str,
):
    html_report = generate_assessment_html(
        assessment_id
    )

    if html_report is None:
        raise HTTPException(
            status_code=404,
            detail="Assessment not found.",
        )

    return HTMLResponse(
        content=html_report,
        status_code=200,
        headers={
            "Cache-Control": "no-store",
        },
    )


@router.get("/{assessment_id}")
def retrieve_assessment(
    assessment_id: str,
):
    assessment = get_assessment_by_id(
        assessment_id
    )

    if assessment is None:
        raise HTTPException(
            status_code=404,
            detail="Assessment not found.",
        )

    return assessment