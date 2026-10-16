from io import BytesIO
from contextlib import contextmanager
from threading import BoundedSemaphore

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Query,
    Response,
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
    assessment_owned_by,
    get_assessment_by_id,
    get_assessment_count,
    get_assessments,
)
from app.services.auth_service import User, require_user
from app.services.pdf_report_service import (
    generate_assessment_pdf,
)
from app.services.report_service import (
    generate_assessment_html,
)
from app.services.job_service import (
    get_job,
    submit_github,
    submit_upload,
)


router = APIRouter(
    prefix="/assessments",
    tags=["Assessments"],
)

# Bound expensive work per API process. Reject excess requests instead of
# holding an unlimited queue of uploaded repositories in memory/on disk.
scan_slots = BoundedSemaphore(2)


@contextmanager
def assessment_slot():
    if not scan_slots.acquire(blocking=False):
        raise HTTPException(
            status_code=503,
            detail="Assessment capacity reached. Please retry shortly.",
            headers={"Retry-After": "10"},
        )
    try:
        yield
    finally:
        scan_slots.release()


@router.get("")
def list_assessments(
    user: User = Depends(require_user),
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
        user_id=user.id,
    )

    total = get_assessment_count(user_id=user.id)

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "assessments": assessments,
    }


@router.post("/upload", status_code=202)
def upload_repository(
    file: UploadFile = File(...),
    user: User = Depends(require_user),
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

    with assessment_slot():
        return submit_upload(file, user_id=user.id)


@router.post("/github", status_code=202)
def assess_github_repository(
    request: GitHubAssessmentRequest,
    user: User = Depends(require_user),
):
    with assessment_slot():
        return submit_github(request.repository_url, user_id=user.id)


@router.get("/jobs/{job_id}")
def retrieve_job(job_id: str, response: Response, user: User = Depends(require_user)):
    job = get_job(job_id, user_id=user.id)
    if job is None:
        raise HTTPException(status_code=404, detail="Assessment job not found.")
    response.headers["Cache-Control"] = "no-store"
    return job


@router.get(
    "/{assessment_id}/report.pdf",
)
def download_assessment_pdf(
    assessment_id: str,
    user: User = Depends(require_user),
):
    require_assessment_owner(assessment_id, user)
    pdf_bytes = generate_assessment_pdf(
        assessment_id
    )

    if pdf_bytes is None:
        raise HTTPException(
            status_code=404,
            detail="Assessment not found.",
        )

    filename = (
        f"talged-assessment-"
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
    user: User = Depends(require_user),
):
    require_assessment_owner(assessment_id, user)
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
    user: User = Depends(require_user),
):
    require_assessment_owner(assessment_id, user)
    assessment = get_assessment_by_id(
        assessment_id
    )

    if assessment is None:
        raise HTTPException(
            status_code=404,
            detail="Assessment not found.",
        )

    return assessment


def require_assessment_owner(assessment_id, user):
    if not assessment_owned_by(assessment_id, user.id):
        raise HTTPException(status_code=404, detail="Assessment not found.")
