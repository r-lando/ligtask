from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

from fastapi import FastAPI
from app.api.auth import router as auth_router
from app.services.auth_service import allowed_origins
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool
from app.services.job_service import AssessmentWorker, initialize_jobs

from app.api.assessments import (
    router as assessments_router,
)
from app.services.database_service import (
    database_health_check,
    initialize_database,
)


initialize_database()
initialize_jobs()


@asynccontextmanager
async def lifespan(app):
    worker = AssessmentWorker()
    worker.start()
    try:
        yield
    finally:
        await run_in_threadpool(worker.stop)


app = FastAPI(
    lifespan=lifespan,
    title="TALGED API",
    description=(
        "Repository-Aware Security "
        "Assessment Platform"
    ),
    version="0.1.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(
    assessments_router
)
app.include_router(auth_router)


@app.get("/")
def root():
    return {
        "name": "TALGED",
        "status": "running",
    }


@app.get("/health")
def health_check():
    database_healthy = (
        database_health_check()
    )

    return {
        "status": (
            "healthy"
            if database_healthy
            else "degraded"
        ),
        "database": (
            "connected"
            if database_healthy
            else "unavailable"
        ),
    }
