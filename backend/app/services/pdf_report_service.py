from io import BytesIO
from app.services.finding_context import file_context, context_note
from xml.sax.saxutils import escape
from app.services.report_notes import ASSESSMENT_LIMITATION_NOTE

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    ParagraphStyle,
    getSampleStyleSheet,
)
from reportlab.lib.units import mm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.services.database_service import (
    get_assessment_by_id,
)


SEVERITY_ORDER = (
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
    "UNKNOWN",
)


def safe_text(value):
    """
    Convert values to safe printable text.
    """
    if value is None:
        return "N/A"

    return str(value)


def format_cvss(finding):
    """
    Format CVSS information without
    inventing unavailable values.
    """
    score = finding.get("cvss_score")
    version = finding.get("cvss_version")

    if score is None:
        return "Not available"

    if version:
        return (
            f"{score} "
            f"(CVSS {version})"
        )

    return str(score)


def format_location(finding):
    """
    Format file and line information.
    """
    file_path = finding.get("file")
    line_number = finding.get("line")

    if not file_path:
        return "Not specified"

    if line_number:
        return (
            f"{file_path}:{line_number} [{file_context(file_path)}]"
        )

    return f"{file_path} [{file_context(file_path)}]"


def format_sources(finding):
    """
    Format scanner provenance.
    """
    sources = finding.get(
        "sources",
        [],
    )

    if sources:
        return ", ".join(
            str(source)
            for source in sources
        )

    return safe_text(
        finding.get("scanner")
    )


def create_styles():
    """
    Create report-specific paragraph styles.
    """
    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="TALGEDTitle",
            parent=styles["Title"],
            fontSize=20,
            leading=24,
            alignment=TA_CENTER,
            spaceAfter=8,
        )
    )

    styles.add(
        ParagraphStyle(
            name="TALGEDSubtitle",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
            alignment=TA_CENTER,
            textColor=colors.HexColor(
                "#555555"
            ),
            spaceAfter=18,
        )
    )

    styles.add(
        ParagraphStyle(
            name="SectionHeading",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
            spaceBefore=10,
            spaceAfter=8,
        )
    )

    styles.add(
        ParagraphStyle(
            name="FindingTitle",
            parent=styles["Heading3"],
            fontSize=11,
            leading=14,
            spaceAfter=6,
        )
    )

    styles.add(
        ParagraphStyle(
            name="SmallText",
            parent=styles["Normal"],
            fontSize=8,
            leading=11,
        )
    )

    styles.add(
        ParagraphStyle(
            name="FindingBody",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
            spaceAfter=4,
        )
    )

    styles.add(
        ParagraphStyle(
            name="PrivacyText",
            parent=styles["Normal"],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor(
                "#444444"
            ),
        )
    )

    styles.add(
        ParagraphStyle(
            name="PartialWarning",
            parent=styles["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor(
                "#7C2D12"
            ),
        )
    )

    return styles


def paragraph(
    value,
    style,
    allow_markup=False,
):
    """
    Create a ReportLab Paragraph.

    Untrusted values are escaped by default.
    Trusted report markup can be enabled
    explicitly.
    """
    text = safe_text(value)

    if not allow_markup:
        text = escape(text)

    return Paragraph(
        text,
        style,
    )


def build_metadata_table(
    assessment,
    styles,
):
    """
    Build assessment information table.
    """
    data = [
        [
            paragraph(
                "Assessment ID",
                styles["SmallText"],
            ),
            paragraph(
                assessment.get(
                    "assessment_id"
                ),
                styles["SmallText"],
            ),
        ],
        [
            paragraph(
                "Repository",
                styles["SmallText"],
            ),
            paragraph(
                assessment.get(
                    "repository_name"
                ),
                styles["SmallText"],
            ),
        ],
        [
            paragraph(
                "Input Type",
                styles["SmallText"],
            ),
            paragraph(
                assessment.get(
                    "input_type"
                ),
                styles["SmallText"],
            ),
        ],
        [
            paragraph(
                "Status",
                styles["SmallText"],
            ),
            paragraph(
                assessment.get(
                    "status"
                ),
                styles["SmallText"],
            ),
        ],
        [
            paragraph(
                "Assessment Started",
                styles["SmallText"],
            ),
            paragraph(
                assessment.get(
                    "created_at"
                ),
                styles["SmallText"],
            ),
        ],
        [
            paragraph(
                "Assessment Completed",
                styles["SmallText"],
            ),
            paragraph(
                assessment.get(
                    "completed_at"
                ),
                styles["SmallText"],
            ),
        ],
        [
            paragraph(
                "Processing Time",
                styles["SmallText"],
            ),
            paragraph(
                (
                    f"{assessment.get(
                        'processing_time_ms',
                        0,
                    )} ms"
                ),
                styles["SmallText"],
            ),
        ],
    ]

    table = Table(
        data,
        colWidths=[
            48 * mm,
            122 * mm,
        ],
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor(
                        "#F2F2F2"
                    ),
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (0, -1),
                    "Helvetica-Bold",
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.HexColor(
                        "#CCCCCC"
                    ),
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
            ]
        )
    )

    return table


def format_mechanism_status(status):
    """
    Convert an internal mechanism status into
    a readable PDF label.
    """
    labels = {
        "completed": "Completed",
        "timed_out": "Timed out",
        "failed": "Failed",
    }

    return labels.get(
        status,
        str(status or "Unknown")
        .replace("_", " ")
        .title(),
    )


def build_partial_warning(
    assessment,
    styles,
):
    """
    Build a prominent warning for partial
    assessments only.
    """
    if assessment.get("status") != "partial":
        return None

    warning_text = (
        "<b>Partial Assessment</b><br/><br/>"
        "One or more security analysis mechanisms "
        "did not complete. Findings from mechanisms "
        "that completed remain valid, but this report "
        "does not represent a complete repository "
        "assessment."
    )

    warning = Table(
        [
            [
                paragraph(
                    warning_text,
                    styles["PartialWarning"],
                    allow_markup=True,
                )
            ]
        ],
        colWidths=[170 * mm],
    )

    warning.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    colors.HexColor(
                        "#FFF7ED"
                    ),
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.7,
                    colors.HexColor(
                        "#D97706"
                    ),
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    10,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    10,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
            ]
        )
    )

    return warning


def build_mechanism_status_table(
    assessment,
    styles,
):
    """
    Build the persisted mechanism execution
    status table.

    Returns None for historical assessments
    that do not contain mechanism statuses.
    """
    mechanism_statuses = assessment.get(
        "mechanism_statuses",
        {},
    ) or {}

    if not mechanism_statuses:
        return None

    labels = {
        "sast": "SAST",
        "dependency": "Dependency Assessment",
        "secret": "Secret Detection",
        "configuration": "Configuration Assessment",
    }

    data = [
        [
            paragraph(
                "Mechanism",
                styles["SmallText"],
            ),
            paragraph(
                "Scanner",
                styles["SmallText"],
            ),
            paragraph(
                "Status",
                styles["SmallText"],
            ),
            paragraph(
                "Findings",
                styles["SmallText"],
            ),
            paragraph(
                "Execution Note",
                styles["SmallText"],
            ),
        ]
    ]

    for key in (
        "sast",
        "dependency",
        "secret",
        "configuration",
    ):
        mechanism = mechanism_statuses.get(
            key
        )

        if not mechanism:
            continue

        data.append(
            [
                paragraph(
                    labels.get(
                        key,
                        key.replace(
                            "_",
                            " ",
                        ).title(),
                    ),
                    styles["SmallText"],
                ),
                paragraph(
                    mechanism.get(
                        "scanner"
                    ),
                    styles["SmallText"],
                ),
                paragraph(
                    format_mechanism_status(
                        mechanism.get(
                            "status"
                        )
                    ),
                    styles["SmallText"],
                ),
                paragraph(
                    mechanism.get(
                        "findings_count",
                        0,
                    ),
                    styles["SmallText"],
                ),
                paragraph(
                    mechanism.get(
                        "error"
                    )
                    or mechanism.get("note") or "None",
                    styles["SmallText"],
                ),
            ]
        )

    if len(data) == 1:
        return None

    table = Table(
        data,
        colWidths=[
            37 * mm,
            24 * mm,
            25 * mm,
            18 * mm,
            66 * mm,
        ],
        repeatRows=1,
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#E8E8E8"
                    ),
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.HexColor(
                        "#CCCCCC"
                    ),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
            ]
        )
    )

    return table


def build_repository_profile_table(
    assessment,
    styles,
):
    """
    Build repository profiling information.
    """
    profile = assessment.get(
        "repository_profile",
        {},
    )

    languages = profile.get(
        "languages",
        {},
    )

    if languages:
        language_text = ", ".join(
            (
                f"{language} ({count})"
            )
            for language, count
            in languages.items()
        )
    else:
        language_text = "None detected"

    dependency_files = profile.get(
        "dependency_files",
        [],
    )

    configuration_files = profile.get(
        "configuration_files",
        [],
    )

    data = [
        [
            paragraph(
                "Total Files",
                styles["SmallText"],
            ),
            paragraph(
                profile.get(
                    "total_files",
                    0,
                ),
                styles["SmallText"],
            ),
        ],
        [
            paragraph(
                "Detected Languages",
                styles["SmallText"],
            ),
            paragraph(
                language_text,
                styles["SmallText"],
            ),
        ],
        [
            paragraph(
                "Dependency Files",
                styles["SmallText"],
            ),
            paragraph(
                (
                    ", ".join(
                        dependency_files
                    )
                    if dependency_files
                    else "None detected"
                ),
                styles["SmallText"],
            ),
        ],
        [
            paragraph(
                "Configuration Files",
                styles["SmallText"],
            ),
            paragraph(
                (
                    ", ".join(
                        configuration_files
                    )
                    if configuration_files
                    else "None detected"
                ),
                styles["SmallText"],
            ),
        ],
    ]

    table = Table(
        data,
        colWidths=[
            48 * mm,
            122 * mm,
        ],
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor(
                        "#F2F2F2"
                    ),
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (0, -1),
                    "Helvetica-Bold",
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.HexColor(
                        "#CCCCCC"
                    ),
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
            ]
        )
    )

    return table


def build_summary_table(
    assessment,
    styles,
):
    """
    Build assessment finding summary.
    """
    data = [
        [
            paragraph(
                "Raw Findings",
                styles["SmallText"],
            ),
            paragraph(
                assessment.get(
                    "raw_findings_count",
                    0,
                ),
                styles["SmallText"],
            ),
        ],
        [
            paragraph(
                "Consolidated Findings",
                styles["SmallText"],
            ),
            paragraph(
                assessment.get(
                    "consolidated_findings_count",
                    0,
                ),
                styles["SmallText"],
            ),
        ],
        [
            paragraph(
                "Correlated Groups",
                styles["SmallText"],
            ),
            paragraph(
                assessment.get(
                    "correlated_groups",
                    0,
                ),
                styles["SmallText"],
            ),
        ],
        [
            paragraph(
                "Duplicate Findings Merged",
                styles["SmallText"],
            ),
            paragraph(
                assessment.get(
                    "duplicate_findings_merged",
                    0,
                ),
                styles["SmallText"],
            ),
        ],
    ]

    table = Table(
        data,
        colWidths=[
            85 * mm,
            85 * mm,
        ],
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor(
                        "#F2F2F2"
                    ),
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (0, -1),
                    "Helvetica-Bold",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.HexColor(
                        "#CCCCCC"
                    ),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
            ]
        )
    )

    return table


def build_severity_table(
    assessment,
    styles,
):
    """
    Build severity distribution table.
    """
    severity_summary = assessment.get(
        "severity_summary",
        {},
    )

    data = [
        [
            paragraph(
                "Severity",
                styles["SmallText"],
            ),
            paragraph(
                "Findings",
                styles["SmallText"],
            ),
        ]
    ]

    for severity in SEVERITY_ORDER:
        data.append(
            [
                paragraph(
                    severity,
                    styles["SmallText"],
                ),
                paragraph(
                    severity_summary.get(
                        severity,
                        0,
                    ),
                    styles["SmallText"],
                ),
            ]
        )

    table = Table(
        data,
        colWidths=[
            85 * mm,
            85 * mm,
        ],
        repeatRows=1,
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#E8E8E8"
                    ),
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.HexColor(
                        "#CCCCCC"
                    ),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
            ]
        )
    )

    return table


def build_finding_section(
    finding,
    index,
    styles,
):
    """
    Build one consolidated finding as a
    readable PDF section.
    """
    elements = []

    title = (
        f"{index}. "
        f"{safe_text(
            finding.get('title')
        )}"
    )

    elements.append(
        paragraph(
            title,
            styles["FindingTitle"],
        )
    )

    metadata = [
        [
            paragraph(
                "Severity",
                styles["SmallText"],
            ),
            paragraph(
                finding.get("severity"),
                styles["SmallText"],
            ),
            paragraph(
                "Category",
                styles["SmallText"],
            ),
            paragraph(
                finding.get("category"),
                styles["SmallText"],
            ),
        ],
        [
            paragraph(
                "Rule ID",
                styles["SmallText"],
            ),
            paragraph(
                finding.get("rule_id"),
                styles["SmallText"],
            ),
            paragraph(
                "CVSS",
                styles["SmallText"],
            ),
            paragraph(
                format_cvss(finding),
                styles["SmallText"],
            ),
        ],
        [
            paragraph(
                "Location",
                styles["SmallText"],
            ),
            paragraph(
                format_location(finding),
                styles["SmallText"],
            ),
            paragraph(
                "Source",
                styles["SmallText"],
            ),
            paragraph(
                format_sources(finding),
                styles["SmallText"],
            ),
        ],
    ]

    metadata_table = Table(
        metadata,
        colWidths=[
            24 * mm,
            61 * mm,
            24 * mm,
            61 * mm,
        ],
    )

    metadata_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor(
                        "#F2F2F2"
                    ),
                ),
                (
                    "BACKGROUND",
                    (2, 0),
                    (2, -1),
                    colors.HexColor(
                        "#F2F2F2"
                    ),
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (0, -1),
                    "Helvetica-Bold",
                ),
                (
                    "FONTNAME",
                    (2, 0),
                    (2, -1),
                    "Helvetica-Bold",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.35,
                    colors.HexColor(
                        "#D0D0D0"
                    ),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    4,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    4,
                ),
            ]
        )
    )

    elements.append(
        metadata_table
    )

    elements.append(
        Spacer(
            1,
            5,
        )
    )

    package = finding.get(
        "package"
    )

    if package:
        package_text = (
            "<b>Package:</b> "
            f"{escape(
                safe_text(package)
            )}"
            " | <b>Version:</b> "
            f"{escape(
                safe_text(
                    finding.get(
                        'version'
                    )
                )
            )}"
            " | <b>Ecosystem:</b> "
            f"{escape(
                safe_text(
                    finding.get(
                        'ecosystem'
                    )
                )
            )}"
        )

        elements.append(
            paragraph(
                package_text,
                styles["FindingBody"],
                allow_markup=True,
            )
        )

    description = escape(
        safe_text(
            finding.get(
                "description"
            )
        )
    )

    elements.append(
        paragraph(
            (
                "<b>Description:</b> "
                f"{description}"
            ),
            styles["FindingBody"],
            allow_markup=True,
        )
    )

    recommendation = escape(
        safe_text(
            finding.get(
                "recommendation"
            )
        )
    )

    elements.append(
        paragraph(
            (
                "<b>Recommendation:</b> "
                f"{recommendation}"
            ),
            styles["FindingBody"],
            allow_markup=True,
        )
    )

    source_rule_ids = finding.get(
        "source_rule_ids",
        [],
    )

    if source_rule_ids:
        provenance_text = ", ".join(
            safe_text(rule_id)
            for rule_id
            in source_rule_ids
        )
    else:
        provenance_text = safe_text(
            finding.get(
                "rule_id"
            )
        )

    provenance_text = escape(
        provenance_text
    )

    elements.append(
        paragraph(
            (
                "<b>Source Rule IDs:</b> "
                f"{provenance_text}"
            ),
            styles["FindingBody"],
            allow_markup=True,
        )
    )

    correlated_text = (
        "Yes"
        if finding.get(
            "correlated"
        )
        else "No"
    )

    evidence_count = escape(
        safe_text(
            finding.get(
                "evidence_count",
                1,
            )
        )
    )

    elements.append(
        paragraph(
            (
                "<b>Correlated:</b> "
                f"{correlated_text}"
                " | "
                f"<b>{'Occurrences' if finding.get('category') == 'DEPENDENCY' else 'Evidence Count'}:</b> "
                f"{evidence_count}"
            ),
            styles["FindingBody"],
            allow_markup=True,
        )
    )

    elements.append(
        Spacer(
            1,
            10,
        )
    )

    return elements


def add_page_number(
    canvas,
    document,
):
    """
    Add the report footer and page number.
    """
    canvas.saveState()

    canvas.setFont(
        "Helvetica",
        8,
    )

    canvas.drawString(
        20 * mm,
        10 * mm,
        (
            "TALGED Security "
            "Assessment Report"
        ),
    )

    canvas.drawRightString(
        A4[0] - 20 * mm,
        10 * mm,
        f"Page {document.page}",
    )

    canvas.restoreState()


def generate_assessment_pdf(
    assessment_id,
):
    """
    Generate a PDF report in memory using
    persisted assessment data.

    Repository source files are not required
    or accessed during report generation.

    Returns None if the assessment does not
    exist.
    """
    assessment = get_assessment_by_id(
        assessment_id
    )

    if assessment is None:
        return None

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=(
            "TALGED Security "
            "Assessment Report"
        ),
        author="TALGED",
    )

    styles = create_styles()

    story = []

    story.append(
        paragraph(
            (
                "TALGED Security "
                "Assessment Report"
            ),
            styles["TALGEDTitle"],
        )
    )

    story.append(
        paragraph(
            (
                "Security Assessment "
                "Platform for Web "
                "Application Repositories"
            ),
            styles[
                "TALGEDSubtitle"
            ],
        )
    )

    story.append(paragraph(ASSESSMENT_LIMITATION_NOTE, styles["FindingBody"]))
    story.append(paragraph(context_note(assessment.get("findings", [])), styles["FindingBody"]))
    story.append(Spacer(1, 8))

    partial_warning = build_partial_warning(
        assessment,
        styles,
    )

    if partial_warning is not None:
        story.append(
            partial_warning
        )

        story.append(
            Spacer(
                1,
                10,
            )
        )

    story.append(
        paragraph(
            "Assessment Information",
            styles[
                "SectionHeading"
            ],
        )
    )

    story.append(
        build_metadata_table(
            assessment,
            styles,
        )
    )

    story.append(
        Spacer(
            1,
            10,
        )
    )

    mechanism_status_table = (
        build_mechanism_status_table(
            assessment,
            styles,
        )
    )

    if mechanism_status_table is not None:
        story.append(
            paragraph(
                "Analysis Mechanism Status",
                styles[
                    "SectionHeading"
                ],
            )
        )

        story.append(
            mechanism_status_table
        )

        story.append(
            Spacer(
                1,
                10,
            )
        )

    story.append(
        paragraph(
            "Repository Profile",
            styles[
                "SectionHeading"
            ],
        )
    )

    story.append(
        build_repository_profile_table(
            assessment,
            styles,
        )
    )

    story.append(
        Spacer(
            1,
            10,
        )
    )

    story.append(
        paragraph(
            "Assessment Summary",
            styles[
                "SectionHeading"
            ],
        )
    )

    story.append(
        build_summary_table(
            assessment,
            styles,
        )
    )

    story.append(
        Spacer(
            1,
            10,
        )
    )

    story.append(
        paragraph(
            "Severity Distribution",
            styles[
                "SectionHeading"
            ],
        )
    )

    story.append(
        build_severity_table(
            assessment,
            styles,
        )
    )

    story.append(
        PageBreak()
    )

    story.append(
        paragraph(
            "Consolidated Findings",
            styles[
                "SectionHeading"
            ],
        )
    )

    findings = assessment.get(
        "findings",
        [],
    )

    if findings:
        for index, finding in enumerate(
            findings,
            start=1,
        ):
            story.extend(
                build_finding_section(
                    finding,
                    index,
                    styles,
                )
            )
    else:
        story.append(
            paragraph(
                (
                    "No consolidated "
                    "findings."
                ),
                styles[
                    "FindingBody"
                ],
            )
        )

    story.append(
        Spacer(
            1,
            12,
        )
    )

    story.append(
        paragraph(
            "Privacy Notice",
            styles[
                "SectionHeading"
            ],
        )
    )

    privacy_notice = (
        "TALGED processes submitted "
        "repository contents temporarily "
        "for security assessment purposes. "
        "Repository source code and uploaded "
        "repository archives are not "
        "permanently stored by the platform. "
        "Persisted assessment records contain "
        "only security findings and "
        "assessment-related metadata required "
        "for result retrieval and reporting. "
        "Detected secret values are excluded "
        "from assessment results and reports."
    )

    story.append(
        paragraph(
            privacy_notice,
            styles[
                "PrivacyText"
            ],
        )
    )

    document.build(
        story,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number,
    )

    pdf_bytes = (
        buffer.getvalue()
    )

    buffer.close()

    return pdf_bytes
