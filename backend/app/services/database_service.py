import json
import sqlite3
from pathlib import Path


DATABASE_PATH = (
    Path(__file__)
    .resolve()
    .parents[2]
    / "talged.db"
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
    Create the TALGED database tables if
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

                configuration_files_json TEXT,

                mechanism_statuses_json TEXT
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

        # -------------------------------------
        # Backward-compatible schema migrations
        # -------------------------------------

        assessment_columns = {
            row["name"]
            for row in cursor.execute(
                """
                PRAGMA table_info(assessments);
                """
            ).fetchall()
        }

        if (
            "mechanism_statuses_json"
            not in assessment_columns
        ):
            cursor.execute(
                """
                ALTER TABLE assessments
                ADD COLUMN mechanism_statuses_json TEXT;
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
    Store one completed or partial assessment
    and its consolidated findings.

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
                configuration_files_json,
                mechanism_statuses_json
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
                serialize_json(
                    assessment.get(
                        "mechanism_statuses"
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

def row_to_assessment(row):
    """
    Convert an assessment database row into
    an API-friendly dictionary.
    """
    if row is None:
        return None

    return {
        "assessment_id": row["id"],
        "repository_name": (
            row["repository_name"]
        ),
        "input_type": row["input_type"],
        "status": row["status"],
        "created_at": row["created_at"],
        "completed_at": row["completed_at"],
        "uploaded_size_bytes": (
            row["uploaded_size_bytes"]
        ),
        "extracted_size_bytes": (
            row["extracted_size_bytes"]
        ),
        "total_files": row["total_files"],
        "processing_time_ms": (
            row["processing_time_ms"]
        ),
        "raw_findings_count": (
            row["raw_findings_count"]
        ),
        "consolidated_findings_count": (
            row[
                "consolidated_findings_count"
            ]
        ),
        "severity_summary": {
            "CRITICAL": (
                row["critical_count"]
            ),
            "HIGH": row["high_count"],
            "MEDIUM": row["medium_count"],
            "LOW": row["low_count"],
            "INFO": row["info_count"],
            "UNKNOWN": (
                row["unknown_count"]
            ),
        },
        "correlated_groups": (
            row["correlated_groups"]
        ),
        "duplicate_findings_merged": (
            row[
                "duplicate_findings_merged"
            ]
        ),
        "mechanism_statuses": (
            deserialize_json(
                row["mechanism_statuses_json"]
            )
            or {}
        ),
        "repository_profile": {
            "total_files": (
                row["total_files"]
            ),
            "languages": (
                deserialize_json(
                    row["languages_json"]
                )
                or {}
            ),
            "dependency_files": (
                deserialize_json(
                    row[
                        "dependency_files_json"
                    ]
                )
                or []
            ),
            "configuration_files": (
                deserialize_json(
                    row[
                        "configuration_files_json"
                    ]
                )
                or []
            ),
        },
    }


def row_to_finding(row):
    """
    Convert a stored consolidated finding into
    the same general structure used by the
    assessment pipeline.
    """
    return {
        "id": row["id"],
        "scanner": row["scanner"],
        "category": row["category"],
        "rule_id": row["rule_id"],
        "title": row["title"],
        "severity": row["severity"],
        "cvss_score": row["cvss_score"],
        "cvss_vector": row["cvss_vector"],
        "cvss_version": row["cvss_version"],
        "file": row["file_path"],
        "line": row["line_number"],
        "message": row["message"],
        "package": row["package_name"],
        "version": row["package_version"],
        "ecosystem": row["ecosystem"],
        "correlated": bool(
            row["correlated"]
        ),
        "evidence_count": (
            row["evidence_count"]
        ),
        "sources": (
            deserialize_json(
                row["sources_json"]
            )
            or []
        ),
        "source_rule_ids": (
            deserialize_json(
                row[
                    "source_rule_ids_json"
                ]
            )
            or []
        ),
        "description": row["description"],
        "recommendation": (
            row["recommendation"]
        ),
        "guidance_source": (
            row["guidance_source"]
        ),
    }


def get_assessments(
    limit=50,
    offset=0,
):
    """
    Retrieve stored assessment history with
    newest assessments first.

    Findings are not included in the history
    list to keep the response lightweight.
    """
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM assessments
            ORDER BY created_at DESC
            LIMIT ?
            OFFSET ?;
            """,
            (
                limit,
                offset,
            ),
        ).fetchall()

        return [
            row_to_assessment(row)
            for row in rows
        ]

    finally:
        connection.close()


def get_assessment_by_id(
    assessment_id,
):
    """
    Retrieve one stored assessment together
    with its consolidated findings.
    """
    connection = get_connection()

    try:
        assessment_row = (
            connection.execute(
                """
                SELECT *
                FROM assessments
                WHERE id = ?;
                """,
                (assessment_id,),
            ).fetchone()
        )

        if assessment_row is None:
            return None

        finding_rows = (
            connection.execute(
                """
                SELECT *
                FROM findings
                WHERE assessment_id = ?
                ORDER BY
                    CASE severity
                        WHEN 'CRITICAL' THEN 1
                        WHEN 'HIGH' THEN 2
                        WHEN 'MEDIUM' THEN 3
                        WHEN 'LOW' THEN 4
                        WHEN 'INFO' THEN 5
                        ELSE 6
                    END,
                    id ASC;
                """,
                (assessment_id,),
            ).fetchall()
        )

        assessment = (
            row_to_assessment(
                assessment_row
            )
        )

        assessment["findings"] = [
            row_to_finding(row)
            for row in finding_rows
        ]

        return assessment

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