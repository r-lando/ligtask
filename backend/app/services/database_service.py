import json
import sqlite3
from pathlib import Path


DATABASE_PATH = (
    Path(__file__)
    .resolve()
    .parents[2]
    / "ligtask.db"
)


def get_connection():
    """
    Create a SQLite connection.

    Rows are returned as dictionary-like
    sqlite3.Row objects.
    """
    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = (
        sqlite3.Row
    )

    connection.execute(
        "PRAGMA foreign_keys = ON;"
    )

    return connection


def initialize_database():
    """
    Create the Ligtask database tables if
    they do not already exist.

    The database stores assessment metadata
    and processed findings only.

    Repository source code, uploaded ZIP files,
    and detected secret values are not stored.
    """
    connection = get_connection()

    try:
        cursor = connection.cursor()

        # -------------------------------------
        # Assessments
        # -------------------------------------

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS assessments (
                id TEXT PRIMARY KEY,

                repository_name TEXT NOT NULL,

                input_type TEXT NOT NULL,

                status TEXT NOT NULL,

                created_at TEXT NOT NULL,

                completed_at TEXT,

                uploaded_size_bytes INTEGER,

                extracted_size_bytes INTEGER,

                total_files INTEGER,

                processing_time_ms INTEGER,

                raw_findings_count INTEGER NOT NULL
                    DEFAULT 0,

                consolidated_findings_count INTEGER
                    NOT NULL DEFAULT 0,

                critical_count INTEGER NOT NULL
                    DEFAULT 0,

                high_count INTEGER NOT NULL
                    DEFAULT 0,

                medium_count INTEGER NOT NULL
                    DEFAULT 0,

                low_count INTEGER NOT NULL
                    DEFAULT 0,

                info_count INTEGER NOT NULL
                    DEFAULT 0,

                unknown_count INTEGER NOT NULL
                    DEFAULT 0,

                correlated_groups INTEGER NOT NULL
                    DEFAULT 0,

                duplicate_findings_merged INTEGER
                    NOT NULL DEFAULT 0,

                languages_json TEXT,

                dependency_files_json TEXT,

                configuration_files_json TEXT
            );
            """
        )

        # -------------------------------------
        # Findings
        # -------------------------------------

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                assessment_id TEXT NOT NULL,

                scanner TEXT,

                category TEXT,

                rule_id TEXT,

                title TEXT NOT NULL,

                severity TEXT NOT NULL,

                cvss_score REAL,

                cvss_vector TEXT,

                cvss_version TEXT,

                file_path TEXT,

                line_number INTEGER,

                message TEXT,

                package_name TEXT,

                package_version TEXT,

                ecosystem TEXT,

                correlated INTEGER NOT NULL
                    DEFAULT 0,

                evidence_count INTEGER NOT NULL
                    DEFAULT 1,

                sources_json TEXT,

                source_rule_ids_json TEXT,

                description TEXT,

                recommendation TEXT,

                guidance_source TEXT,

                FOREIGN KEY (
                    assessment_id
                )
                REFERENCES assessments(id)
                ON DELETE CASCADE
            );
            """
        )

        # -------------------------------------
        # Useful indexes
        # -------------------------------------

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_findings_assessment_id
            ON findings(assessment_id);
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_findings_severity
            ON findings(severity);
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_assessments_created_at
            ON assessments(created_at);
            """
        )

        connection.commit()

    finally:
        connection.close()


def serialize_json(value):
    """
    Convert Python objects to JSON text for
    SQLite storage.
    """
    if value is None:
        return None

    return json.dumps(
        value,
        ensure_ascii=False,
    )


def deserialize_json(value):
    """
    Convert stored JSON text back to a
    Python object.
    """
    if not value:
        return None

    try:
        return json.loads(value)

    except json.JSONDecodeError:
        return None


def database_health_check():
    """
    Verify that the SQLite database can
    be opened successfully.
    """
    connection = get_connection()

    try:
        result = connection.execute(
            "SELECT 1 AS healthy;"
        ).fetchone()

        return bool(
            result
            and result["healthy"] == 1
        )

    finally:
        connection.close()