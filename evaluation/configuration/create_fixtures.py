from pathlib import Path
import shutil


BASE_DIR = Path(__file__).resolve().parent
FIXTURES_DIR = BASE_DIR / "fixtures"


FIXTURES = {
    "CFG-001": """\
FROM python:3.12
WORKDIR /app
COPY . /app
CMD ["python", "app.py"]
""",

    "CFG-002": """\
FROM python:3.12
WORKDIR /app
COPY . /app
USER root
CMD ["python", "app.py"]
""",

    "CFG-003": """\
FROM python:latest
WORKDIR /app
COPY . /app
USER appuser
CMD ["python", "app.py"]
""",

    "CFG-004": """\
FROM python:LATEST
WORKDIR /app
COPY . /app
USER appuser
CMD ["python", "app.py"]
""",

    "CFG-005": """\
FROM python:3.12
WORKDIR /app
ADD application.txt /app/application.txt
USER appuser
CMD ["python", "app.py"]
""",

    "CFG-006": """\
FROM python:3.12
WORKDIR /app
add application.txt /app/application.txt
USER appuser
CMD ["python", "app.py"]
""",

    "CFG-007": """\
FROM python:3.12
WORKDIR /app
COPY . /app
USER appuser
CMD ["python", "app.py"]
""",

    "CFG-008": """\
FROM python:3.12
WORKDIR /app
USER root
COPY . /app
USER appuser
CMD ["python", "app.py"]
""",

    "CFG-009": """\
FROM python:3.12
WORKDIR /app
COPY . /app
USER appuser
CMD ["python", "app.py"]
""",

    "CFG-010": """\
FROM python@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
WORKDIR /app
COPY . /app
USER appuser
CMD ["python", "app.py"]
""",

    "CFG-011": """\
FROM python:3.12
WORKDIR /app
COPY application.txt /app/application.txt
USER appuser
CMD ["python", "app.py"]
""",

    "CFG-012": """\
FROM python:3.12
WORKDIR /app
# FROM python:latest
# ADD secret.txt /app/secret.txt
# USER root
COPY . /app
USER appuser
CMD ["python", "app.py"]
""",
}


def main():
    if FIXTURES_DIR.exists():
        shutil.rmtree(FIXTURES_DIR)

    FIXTURES_DIR.mkdir(parents=True)

    for case_id, dockerfile_content in FIXTURES.items():
        case_directory = FIXTURES_DIR / case_id
        case_directory.mkdir()

        dockerfile_path = case_directory / "Dockerfile"
        dockerfile_path.write_text(
            dockerfile_content,
            encoding="utf-8",
            newline="\n",
        )

    print(
        f"Generated {len(FIXTURES)} "
        f"configuration benchmark fixtures."
    )


if __name__ == "__main__":
    main()
