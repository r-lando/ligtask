from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.assessments import (
    router as assessments_router,
)
from app.services.database_service import (
    database_health_check,
    initialize_database,
)


initialize_database()


app = FastAPI(
    title="TALGED API",
    description=(
        "Repository-Aware Security "
        "Assessment Platform"
    ),
    version="0.1.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(
    assessments_router
)


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