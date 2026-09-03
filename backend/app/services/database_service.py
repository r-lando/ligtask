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


def save_assessment(
    assessment,
    findings,
):
    """
    Store one completed assessment and its
    consolidated findings.

    Raw repository contents and detected
    secret values must never be passed to
    this function.

    The assessment and its findings are saved
    in a single database transaction.
    """
    connection = get_connection()

    try:
        cursor = connection.cursor()

        # -------------------------------------
        # Save assessment metadata
        # -------------------------------------

        cursor.execute(
            """
            INSERT INTO assessments (
                id,
                repository_name,
                input_type,
                status,
                created_at,
                completed_at,
                uploaded_size_bytes,
                extracted_size_bytes,
                total_files,
                processing_time_ms,
                raw_findings_count,
                consolidated_findings_count,
                critical_count,
                high_count,
                medium_count,
                low_count,
                info_count,
                unknown_count,
                correlated_groups,
                duplicate_findings_merged,
                languages_json,
                dependency_files_json,
                configuration_files_json
            )
            VALUES (
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?
            );
            """,
            (
                assessment.get("id"),
                assessment.get(
                    "repository_name"
                ),
                assessment.get(
                    "input_type"
                ),
                assessment.get("status"),
                assessment.get(
                    "created_at"
                ),
                assessment.get(
                    "completed_at"
                ),
                assessment.get(
                    "uploaded_size_bytes"
                ),
                assessment.get(
                    "extracted_size_bytes"
                ),
                assessment.get(
                    "total_files"
                ),
                assessment.get(
                    "processing_time_ms"
                ),
                assessment.get(
                    "raw_findings_count",
                    0,
                ),
                assessment.get(
                    "consolidated_findings_count",
                    0,
                ),
                assessment.get(
                    "critical_count",
                    0,
                ),
                assessment.get(
                    "high_count",
                    0,
                ),
                assessment.get(
                    "medium_count",
                    0,
                ),
                assessment.get(
                    "low_count",
                    0,
                ),
                assessment.get(
                    "info_count",
                    0,
                ),
                assessment.get(
                    "unknown_count",
                    0,
                ),
                assessment.get(
                    "correlated_groups",
                    0,
                ),
                assessment.get(
                    "duplicate_findings_merged",
                    0,
                ),
                serialize_json(
                    assessment.get(
                        "languages"
                    )
                ),
                serialize_json(
                    assessment.get(
                        "dependency_files"
                    )
                ),
                serialize_json(
                    assessment.get(
                        "configuration_files"
                    )
                ),
            ),
        )

        # -------------------------------------
        # Save consolidated findings
        # -------------------------------------

        for finding in findings:
            cursor.execute(
                """
                INSERT INTO findings (
                    assessment_id,
                    scanner,
                    category,
                    rule_id,
                    title,
                    severity,
                    cvss_score,
                    cvss_vector,
                    cvss_version,
                    file_path,
                    line_number,
                    message,
                    package_name,
                    package_version,
                    ecosystem,
                    correlated,
                    evidence_count,
                    sources_json,
                    source_rule_ids_json,
                    description,
                    recommendation,
                    guidance_source
                )
                VALUES (
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?
                );
                """,
                (
                    assessment.get("id"),
                    finding.get("scanner"),
                    finding.get("category"),
                    finding.get("rule_id"),
                    finding.get(
                        "title",
                        "Security Finding",
                    ),
                    finding.get(
                        "severity",
                        "UNKNOWN",
                    ),
                    finding.get(
                        "cvss_score"
                    ),
                    finding.get(
                        "cvss_vector"
                    ),
                    finding.get(
                        "cvss_version"
                    ),
                    finding.get("file"),
                    finding.get("line"),
                    finding.get("message"),
                    finding.get("package"),
                    finding.get("version"),
                    finding.get("ecosystem"),
                    1
                    if finding.get(
                        "correlated"
                    )
                    else 0,
                    finding.get(
                        "evidence_count",
                        1,
                    ),
                    serialize_json(
                        finding.get(
                            "sources",
                            [],
                        )
                    ),
                    serialize_json(
                        finding.get(
                            "source_rule_ids",
                            [],
                        )
                    ),
                    finding.get(
                        "description"
                    ),
                    finding.get(
                        "recommendation"
                    ),
                    finding.get(
                        "guidance_source"
                    ),
                ),
            )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_assessment_count():
    """
    Return the number of stored assessments.

    Primarily useful during development and
    database verification.
    """
    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM assessments;
            """
        ).fetchone()

        return row["total"]

    finally:
        connection.close()


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