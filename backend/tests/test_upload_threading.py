import asyncio
import threading
from io import BytesIO

from fastapi import UploadFile

from app.services import repository_service


def test_upload_pipeline_runs_outside_event_loop(monkeypatch):
    loop_thread = threading.get_ident()
    upload = UploadFile(filename="repo.zip", file=BytesIO(b"archive"))

    def fake_process(file):
        assert threading.get_ident() != loop_thread
        assert file.file.read() == b"archive"
        return {"assessment_id": "test"}

    monkeypatch.setattr(repository_service, "_process_repository", fake_process)
    assert asyncio.run(repository_service.process_repository(upload)) == {
        "assessment_id": "test"
    }
