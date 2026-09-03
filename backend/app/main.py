from fastapi import FastAPI
from app.api.assessments import router as assessments_router

app = FastAPI(
    title="Ligtask API",
    description="Repository-Aware Security Assessment Platform",
    version="0.1.0",
)
app.include_router(assessments_router)

@app.get("/")
def root():
    return {
        "name": "Ligtask",
        "status": "running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }