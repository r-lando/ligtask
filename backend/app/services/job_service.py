"""SQLite-backed assessment queue with bounded admission and worker leases."""

import logging
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from threading import Event, Thread

from fastapi import HTTPException, UploadFile

from app.services import database_service as database
from app.services.github_service import parse_github_repository_url, GitHubRepositoryError
from app.services.repository_service import (
    MAX_UPLOAD_SIZE,
    _process_repository,
    process_github_repository,
)

logger = logging.getLogger(__name__)
MAX_PENDING_JOBS = 10
LEASE_SECONDS = 60


@contextmanager
def job_connection():
    connection = database.get_connection()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_jobs():
    with job_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS assessment_jobs (
                id TEXT PRIMARY KEY,
                input_type TEXT NOT NULL,
                input_value TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                owner TEXT,
                assessment_id TEXT,
                error TEXT
            )
        """)
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(assessment_jobs)")}
        if "user_id" not in columns:
            connection.execute("ALTER TABLE assessment_jobs ADD COLUMN user_id TEXT")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_jobs_user_created ON assessment_jobs(user_id, created_at)")


def archive_path(job_id):
    # The path never incorporates the user-supplied filename.
    return Path(database.DATABASE_PATH).parent / "assessment_jobs" / f"{job_id}.zip"


def remove_archive(job_id):
    try:
        archive_path(job_id).unlink(missing_ok=True)
    except OSError:
        logger.exception("Could not remove queued archive %s", job_id)


def reserve_job(input_type, input_value, status="queued", user_id=None):
    job_id = str(uuid.uuid4())
    now = time.time()
    with job_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        if user_id is not None:
            active = connection.execute(
                "SELECT COUNT(*) FROM assessment_jobs WHERE user_id = ? AND status IN ('uploading', 'queued', 'running')",
                (user_id,),
            ).fetchone()[0]
            if active:
                raise HTTPException(status_code=429, detail="You already have an active assessment.", headers={"Retry-After": "10"})
            try:
                daily_limit = int(os.getenv("ASSESSMENTS_PER_DAY", "5"))
                if daily_limit < 1:
                    raise ValueError()
            except ValueError as exc:
                raise HTTPException(status_code=503, detail="Assessment quota is not configured correctly.") from exc
            recent = connection.execute(
                "SELECT COUNT(*) FROM assessment_jobs WHERE user_id = ? AND created_at >= ?",
                (user_id, now - 86400),
            ).fetchone()[0]
            if recent >= daily_limit:
                raise HTTPException(status_code=429, detail="Your daily assessment limit has been reached.")
        pending = connection.execute(
            "SELECT COUNT(*) FROM assessment_jobs WHERE status IN ('uploading', 'queued', 'running')"
        ).fetchone()[0]
        if pending >= MAX_PENDING_JOBS:
            raise HTTPException(
                status_code=503,
                detail="Assessment queue is full. Please retry shortly.",
                headers={"Retry-After": "10"},
            )
        connection.execute(
            "INSERT INTO assessment_jobs (id, input_type, input_value, status, created_at, updated_at, user_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (job_id, input_type, input_value, status, now, now, user_id),
        )
    return job_id


def get_job(job_id, user_id=None):
    with job_connection() as connection:
        row = connection.execute(
            "SELECT id AS job_id, status, assessment_id, error FROM assessment_jobs WHERE id = ? "
            "AND (? IS NULL OR user_id = ?)",
            (job_id, user_id, user_id),
        ).fetchone()
    return dict(row) if row else None


def submit_github(repository_url, user_id=None):
    try:
        parsed = parse_github_repository_url(repository_url)
    except GitHubRepositoryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    job_id = reserve_job("GITHUB", parsed["canonical_url"], user_id=user_id)
    return get_job(job_id)


def submit_upload(file, user_id=None):
    job_id = reserve_job("ZIP", file.filename or "repository.zip", "uploading", user_id=user_id)
    path = archive_path(job_id)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        size = 0
        with path.open("xb") as target:
            while chunk := file.file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD_SIZE:
                    raise HTTPException(status_code=413, detail="Repository ZIP exceeds the 50 MB upload limit.")
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        with job_connection() as connection:
            connection.execute(
                "UPDATE assessment_jobs SET status = 'queued', updated_at = ? WHERE id = ?",
                (time.time(), job_id),
            )
    except BaseException:
        remove_archive(job_id)
        with job_connection() as connection:
            connection.execute("DELETE FROM assessment_jobs WHERE id = ?", (job_id,))
        raise
    return get_job(job_id)


def recover_interrupted_jobs():
    """Only expired leases are recovered; another server may still be working."""
    with job_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        rows = connection.execute(
            "SELECT id FROM assessment_jobs WHERE status IN ('running', 'uploading') AND updated_at < ?",
            (time.time() - LEASE_SECONDS,),
        ).fetchall()
        for row in rows:
            connection.execute(
                "UPDATE assessment_jobs SET status = 'failed', error = ?, updated_at = ? WHERE id = ?",
                ("Assessment was interrupted. Please submit it again.", time.time(), row["id"]),
            )
    for row in rows:
        remove_archive(row["id"])


def claim_job(owner):
    with job_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT * FROM assessment_jobs WHERE status = 'queued' ORDER BY created_at, id LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        connection.execute(
            "UPDATE assessment_jobs SET status = 'running', owner = ?, updated_at = ? WHERE id = ?",
            (owner, time.time(), row["id"]),
        )
        return dict(row)


def execute_job(job):
    try:
        if job["input_type"] == "GITHUB":
            result = process_github_repository(job["input_value"])
        else:
            with archive_path(job["id"]).open("rb") as source:
                result = _process_repository(UploadFile(file=source, filename=job["input_value"]))
        if job.get("user_id"):
            with job_connection() as connection:
                connection.execute(
                    "INSERT INTO assessment_owners (assessment_id, user_id) VALUES (?, ?)",
                    (result["assessment_id"], job["user_id"]),
                )
        return result["assessment_id"], None
    except HTTPException as exc:
        return None, str(exc.detail)
    except Exception:
        logger.exception("Assessment job %s failed", job["id"])
        return None, "Assessment could not be completed. Please retry."
    finally:
        remove_archive(job["id"])


class AssessmentWorker:
    def __init__(self):
        self.owner = str(uuid.uuid4())
        self.stopping = Event()
        self.thread = Thread(target=self.run, name="assessment-queue", daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stopping.set()
        self.thread.join()

    def run(self):
        active = {}
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="assessment") as executor:
            while not self.stopping.is_set() or active:
                try:
                    recover_interrupted_jobs()
                    with job_connection() as connection:
                        connection.execute(
                            "UPDATE assessment_jobs SET updated_at = ? WHERE status = 'running' AND owner = ?",
                            (time.time(), self.owner),
                        )
                        for job_id, future in list(active.items()):
                            if future.done():
                                assessment_id, error = future.result()
                                connection.execute(
                                    "UPDATE assessment_jobs SET status = ?, assessment_id = ?, error = ?, updated_at = ? "
                                    "WHERE id = ? AND owner = ? AND status = 'running'",
                                    ("failed" if error else "completed", assessment_id, error,
                                     time.time(), job_id, self.owner),
                                )
                                del active[job_id]
                    while not self.stopping.is_set() and len(active) < 2:
                        job = claim_job(self.owner)
                        if job is None:
                            break
                        active[job["id"]] = executor.submit(execute_job, job)
                except Exception:
                    logger.exception("Assessment queue worker iteration failed")
                # Avoid a busy loop during graceful shutdown while scans finish.
                if self.stopping.is_set():
                    time.sleep(0.5)
                else:
                    self.stopping.wait(0.5)
