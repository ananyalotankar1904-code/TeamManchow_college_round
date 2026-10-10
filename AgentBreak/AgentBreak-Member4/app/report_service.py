"""
Reporting service providing JSON and PDF export for AgentBreak security scan reports.

This module is completely decoupled from any database, backend framework, or external APIs.
It provides two primary callable functions:
- generate_json_report(report_data, indent=2, redact_secrets=True) -> str
- generate_pdf_report(report_data, output_destination=None) -> bytes
"""

from __future__ import annotations

import html
import io
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.report_data import (
    DataProvenanceType,
    Finding,
    FindingOutcome,
    ScanReport,
    parse_scan_report,
)

# ---------------------------------------------------------------------------
# Sensitive Data / Secret Redaction
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    re.compile(r"sk-[a-zA-Z0-9_\-]{20,}"),                          # OpenAI / Generic API key
    re.compile(r"sk-ant-[a-zA-Z0-9_\-]{20,}"),                      # Anthropic key
    re.compile(r"AKIA[0-9A-Z]{16}"),                                # AWS Access Key
    re.compile(r"ghp_[a-zA-Z0-9]{36}"),                             # GitHub token
    re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]{20,}", re.IGNORECASE),   # Bearer token
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----"),
    re.compile(r'(?i)(password|passwd|api_key|apikey|secret)["\']?\s*[:=]\s*["\']([^"\'\s]{6,})["\']'),
]


def redact_sensitive_text(text: Optional[str]) -> Optional[str]:
    """
    Sanitizes arbitrary strings by replacing detected secret patterns with [REDACTED_SECRET].
    """
    if text is None:
        return None
    sanitized = text
    for pattern in SECRET_PATTERNS:
        sanitized = pattern.sub("[REDACTED_SECRET]", sanitized)
    return sanitized


def sanitize_dict_secrets(obj: Any) -> Any:
    """
    Recursively scans and sanitizes strings inside nested dictionaries and lists.
    """
    if isinstance(obj, str):
        return redact_sensitive_text(obj)
    if isinstance(obj, dict):
        return {k: sanitize_dict_secrets(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize_dict_secrets(item) for item in obj]
    return obj


# ---------------------------------------------------------------------------
# JSON Report Generation
# ---------------------------------------------------------------------------

def generate_report_dict(
    report_data: Union[ScanReport, Dict[str, Any], str],
    redact_secrets: bool = True
) -> Dict[str, Any]:
    """
    Validates report data and generates a clean, JSON-serializable dictionary.
    Includes scan metadata, data provenance, findings, and computed summary metrics.
    """
    report = parse_scan_report(report_data)

    # Calculate summary metrics directly from supplied findings
    outcome_counts = Counter(f.outcome.value if isinstance(f.outcome, FindingOutcome) else str(f.outcome) for f in report.findings)
    severity_counts = Counter(
        f.severity.lower() if f.severity else "unassigned" for f in report.findings
    )

    data = {
        "report_type": "AgentBreak Security Scan Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metadata": {
            "scan_id": report.metadata.scan_id,
            "agent_id": report.metadata.agent_id,
            "status": report.metadata.status,
            "started_at": report.metadata.started_at.isoformat() if report.metadata.started_at else None,
            "completed_at": report.metadata.completed_at.isoformat() if report.metadata.completed_at else None,
            "scanner_version": report.metadata.scanner_version,
            "target_environment": report.metadata.target_environment,
            "extra_metadata": report.metadata.extra_metadata or {},
        },
        "provenance": {
            "provenance_type": report.provenance.provenance_type.value if hasattr(report.provenance.provenance_type, "value") else str(report.provenance.provenance_type),
            "source_description": report.provenance.source_description,
            "generated_at": report.provenance.generated_at.isoformat() if report.provenance.generated_at else None,
        },
        "summary": {
            "total_findings": len(report.findings),
            "outcome_breakdown": {
                FindingOutcome.ATTEMPTED.value: outcome_counts.get(FindingOutcome.ATTEMPTED.value, 0),
                FindingOutcome.BLOCKED.value: outcome_counts.get(FindingOutcome.BLOCKED.value, 0),
                FindingOutcome.EXECUTED.value: outcome_counts.get(FindingOutcome.EXECUTED.value, 0),
                FindingOutcome.FAILED.value: outcome_counts.get(FindingOutcome.FAILED.value, 0),
                FindingOutcome.INCONCLUSIVE.value: outcome_counts.get(FindingOutcome.INCONCLUSIVE.value, 0),
            },
            "severity_breakdown": dict(severity_counts),
        },
        "findings": [
            {
                "finding_id": f.finding_id,
                "test_id": f.test_id,
                "category": f.category,
                "severity": f.severity,
                "execution_status": f.execution_status,
                "outcome": f.outcome.value if isinstance(f.outcome, FindingOutcome) else str(f.outcome),
                "expected_behavior": f.expected_behavior,
                "observed_behavior": f.observed_behavior,
                "evidence": f.evidence,
                "trace_id": f.trace_id,
                "trace_references": [
                    {
                        "trace_id": tr.trace_id,
                        "span_id": tr.span_id,
                        "event_name": tr.event_name,
                        "timestamp": tr.timestamp.isoformat() if tr.timestamp else None,
                        "details": tr.details or {},
                    }
                    for tr in (f.trace_references or [])
                ],
                "metadata": f.metadata or {},
            }
            for f in report.findings
        ],
        "summary_notes": report.summary_notes,
    }

    if redact_secrets:
        data = sanitize_dict_secrets(data)

    return data


def generate_json_report(
    report_data: Union[ScanReport, Dict[str, Any], str],
    indent: Optional[int] = 2,
    redact_secrets: bool = True
) -> str:
    """
    Accepts validated report data and returns a structured, valid JSON string.
    Preserves exact outcome distinctions and handles empty or multiple findings safely.
    """
    report_dict = generate_report_dict(report_data, redact_secrets=redact_secrets)
    return json.dumps(report_dict, indent=indent, ensure_ascii=False)


# ---------------------------------------------------------------------------
# PDF Report Generation (ReportLab)
# ---------------------------------------------------------------------------

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and draw total page numbers and running footers.
    """
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: List[Dict[str, Any]] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_footer(num_pages)
            super().showPage()
        super().save()

    def draw_footer(self, page_count: int) -> None:
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        
        # Top line above footer
        self.setStrokeColor(colors.HexColor("#E2E8F0"))
        self.setLineWidth(0.75)
        self.line(40, 42, 612 - 40, 42)

        # Left label
        self.drawString(40, 30, "AgentBreak Security Scan Report — Confidential Security Assessment")
        
        # Right page counter
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(612 - 40, 30, page_str)
        self.restoreState()


def _safe_xml_text(text: Optional[str]) -> str:
    """
    Safely escapes characters for ReportLab XML paragraph parsing and wraps long strings.
    """
    if text is None:
        return ""
    # Transliterate or filter out non-latin-1 characters that default fonts cannot render
    cleaned = text.encode("ascii", "xmlcharrefreplace").decode("ascii")
    # Replace newlines with <br/> tags
    escaped = html.escape(cleaned).replace("\n", "<br/>")
    return escaped


def _break_long_tokens(text: Optional[str], max_token_len: int = 50) -> str:
    """
    Inserts break points in long continuous strings without spaces (e.g. hash, long URL)
    to prevent text from overflowing PDF table cell boundaries.
    """
    if not text:
        return ""
    words = text.split(" ")
    broken_words = []
    for word in words:
        if len(word) > max_token_len:
            # Chunk the word
            chunks = [word[i:i + max_token_len] for i in range(0, len(word), max_token_len)]
            broken_words.append(" ".join(chunks))
        else:
            broken_words.append(word)
    return " ".join(broken_words)


def generate_pdf_report(
    report_data: Union[ScanReport, Dict[str, Any], str],
    output_destination: Optional[Union[str, Path, io.BytesIO]] = None,
    redact_secrets: bool = True
) -> bytes:
    """
    Uses ReportLab to generate a clean, resilient, professional PDF security report.

    Parameters:
    - report_data: Validated ScanReport instance, Python dictionary, or JSON string.
    - output_destination: Optional file path or BytesIO buffer to write the PDF to.
    - redact_secrets: Whether to redact sensitive tokens from findings and evidence.

    Returns:
    - Raw PDF content as bytes.
    """
    report = parse_scan_report(report_data)
    report_dict = generate_report_dict(report, redact_secrets=redact_secrets)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=40,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0F172A"),
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748B"),
    )
    section_h1 = ParagraphStyle(
        "SectionH1",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#1E293B"),
        spaceBefore=14,
        spaceAfter=6,
    )
    meta_label_style = ParagraphStyle(
        "MetaLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#475569"),
    )
    meta_val_style = ParagraphStyle(
        "MetaVal",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#0F172A"),
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1E293B"),
    )
    evidence_style = ParagraphStyle(
        "EvidenceStyle",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0F172A"),
    )
    badge_style = ParagraphStyle(
        "BadgeStyle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        alignment=1,  # Center
    )

    story: List[Any] = []

    # 1. Title & Header
    story.append(Paragraph("AgentBreak Security Scan Report", title_style))
    story.append(Paragraph("Automated Vulnerability & Behavioral Integrity Assessment for AI Agents", subtitle_style))
    story.append(Spacer(1, 10))

    # 2. Provenance Banner
    prov_type = report_dict["provenance"]["provenance_type"]
    prov_desc = report_dict["provenance"].get("source_description") or "Not specified"

    if prov_type in (DataProvenanceType.SYNTHETIC.value, DataProvenanceType.MOCK_DEMO.value):
        banner_bg = colors.HexColor("#FEF3C7")  # Amber-100
        banner_border = colors.HexColor("#F59E0B")  # Amber-500
        banner_title_color = "#92400E"  # Amber-800
        badge_label = f"DATA PROVENANCE: {prov_type.upper().replace('_', ' ')} (BENCHMARK / DEMO DATA)"
        banner_desc = (
            f"<b>NOTICE:</b> This report was generated from <b>{prov_type.upper()}</b> test data. "
            f"It does not represent a live, active agent deployment execution. Source: {prov_desc}."
        )
    else:
        banner_bg = colors.HexColor("#ECFDF5")  # Emerald-50
        banner_border = colors.HexColor("#10B981")  # Emerald-500
        banner_title_color = "#065F46"  # Emerald-800
        badge_label = "DATA PROVENANCE: REAL EXECUTION DATA"
        banner_desc = (
            f"<b>VERIFIED RUN:</b> Captured from live agent scan telemetry. Source: {prov_desc}."
        )

    banner_p = Paragraph(
        f"<font color='{banner_title_color}'><b>[{badge_label}]</b><br/>{banner_desc}</font>",
        body_style
    )
    banner_table = Table([[banner_p]], colWidths=[532])
    banner_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), banner_bg),
        ("BOX", (0, 0), (-1, -1), 1, banner_border),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(banner_table)
    story.append(Spacer(1, 12))

    # 3. Scan Metadata Table
    story.append(Paragraph("Scan Metadata", section_h1))
    meta = report_dict["metadata"]
    started = meta.get("started_at") or "Not Recorded"
    completed = meta.get("completed_at") or "Not Recorded"
    scanner_ver = meta.get("scanner_version") or "Not Recorded"
    target_env = meta.get("target_environment") or "Default"

    meta_table_data = [
        [
            Paragraph("Scan ID:", meta_label_style),
            Paragraph(str(meta.get("scan_id")), meta_val_style),
            Paragraph("Agent ID:", meta_label_style),
            Paragraph(str(meta.get("agent_id")), meta_val_style),
        ],
        [
            Paragraph("Status:", meta_label_style),
            Paragraph(str(meta.get("status")).upper(), meta_val_style),
            Paragraph("Environment:", meta_label_style),
            Paragraph(str(target_env), meta_val_style),
        ],
        [
            Paragraph("Started At:", meta_label_style),
            Paragraph(str(started), meta_val_style),
            Paragraph("Completed At:", meta_label_style),
            Paragraph(str(completed), meta_val_style),
        ],
        [
            Paragraph("Scanner Version:", meta_label_style),
            Paragraph(str(scanner_ver), meta_val_style),
            Paragraph("Generated At:", meta_label_style),
            Paragraph(report_dict.get("generated_at", "N/A"), meta_val_style),
        ],
    ]

    meta_table = Table(meta_table_data, colWidths=[95, 171, 95, 171])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 12))

    # 4. Summary & Findings Overview
    story.append(Paragraph("Findings Summary", section_h1))
    total_findings = report_dict["summary"]["total_findings"]
    outcomes = report_dict["summary"]["outcome_breakdown"]
    severities = report_dict["summary"]["severity_breakdown"]

    summary_cells = [
        [
            Paragraph(f"<b>Total Findings:</b> {total_findings}", body_style),
            Paragraph(f"<b>Attempted:</b> {outcomes.get('attempted', 0)}", body_style),
            Paragraph(f"<b>Blocked:</b> {outcomes.get('blocked', 0)}", body_style),
            Paragraph(f"<b>Executed:</b> {outcomes.get('executed', 0)}", body_style),
            Paragraph(f"<b>Failed:</b> {outcomes.get('failed', 0)}", body_style),
            Paragraph(f"<b>Inconclusive:</b> {outcomes.get('inconclusive', 0)}", body_style),
        ]
    ]
    summary_table = Table(summary_cells, colWidths=[90, 88, 88, 88, 88, 90])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(summary_table)

    if total_findings == 0:
        story.append(Spacer(1, 10))
        empty_box = Paragraph(
            "<b>No security findings reported for this scan.</b> All executed evaluation probes passed "
            "or no vulnerability signals were detected.",
            body_style
        )
        empty_table = Table([[empty_box]], colWidths=[532])
        empty_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F0FDF4")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#86EFAC")),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ]))
        story.append(empty_table)
    else:
        story.append(Spacer(1, 10))
        story.append(Paragraph("Detailed Security Findings", section_h1))

        # Outcome badge color helper
        outcome_colors = {
            "blocked": ("#15803D", "#DCFCE7"),       # Green
            "failed": ("#B91C1C", "#FEE2E2"),        # Red
            "executed": ("#6D28D9", "#EDE9FE"),      # Purple
            "attempted": ("#B45309", "#FEF3C7"),     # Amber
            "inconclusive": ("#374151", "#F3F4F6"),  # Gray
        }

        # Severity badge color helper
        severity_colors = {
            "critical": ("#991B1B", "#FEE2E2"),
            "high": ("#C2410C", "#FFEDD5"),
            "medium": ("#B45309", "#FEF3C7"),
            "low": ("#1D4ED8", "#DBEAFE"),
            "info": ("#374151", "#F3F4F6"),
            "unknown": ("#4B5563", "#F3F4F6"),
        }

        for idx, finding in enumerate(report_dict["findings"], 1):
            finding_elements: List[Any] = []
            
            outcome_val = str(finding.get("outcome", "inconclusive")).lower()
            fg_out, bg_out = outcome_colors.get(outcome_val, ("#374151", "#F3F4F6"))

            sev_val = str(finding.get("severity") or "unknown").lower()
            fg_sev, bg_sev = severity_colors.get(sev_val, ("#4B5563", "#F3F4F6"))

            # Header row for the finding card
            finding_header_text = (
                f"<b>#{idx} — Finding ID: {html.escape(finding['finding_id'])}</b> &nbsp;|&nbsp; "
                f"Test: {html.escape(finding['test_id'])} &nbsp;|&nbsp; "
                f"Category: <i>{html.escape(finding['category'])}</i>"
            )
            badge_html = (
                f"<font color='{fg_sev}'><b>[{sev_val.upper()}]</b></font> &nbsp; "
                f"<font color='{fg_out}'><b>[{outcome_val.upper()}]</b></font>"
            )

            header_table = Table(
                [[
                    Paragraph(finding_header_text, meta_label_style),
                    Paragraph(badge_html, badge_style),
                ]],
                colWidths=[420, 112]
            )
            header_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]))
            finding_elements.append(header_table)

            # Details table
            expected_clean = _safe_xml_text(_break_long_tokens(finding.get("expected_behavior", "")))
            observed_clean = _safe_xml_text(_break_long_tokens(finding.get("observed_behavior", "")))
            evidence_raw = finding.get("evidence")
            evidence_clean = _safe_xml_text(_break_long_tokens(evidence_raw)) if evidence_raw else "<i>No raw evidence captured</i>"
            
            trace_id_val = finding.get("trace_id") or "None"
            traces = finding.get("trace_references") or []
            if traces:
                trace_summary = "<br/>".join([
                    f"&bull; Trace: {html.escape(t.get('trace_id', 'N/A'))} | "
                    f"Span: {html.escape(str(t.get('span_id', 'N/A')))} | "
                    f"Event: {html.escape(str(t.get('event_name', 'N/A')))}"
                    for t in traces
                ])
            else:
                trace_summary = f"Trace ID: {html.escape(trace_id_val)} (No secondary trace spans attached)"

            card_body_data = [
                [
                    Paragraph("Execution Status:", meta_label_style),
                    Paragraph(html.escape(finding.get("execution_status", "unknown")), meta_val_style),
                ],
                [
                    Paragraph("Expected Behavior:", meta_label_style),
                    Paragraph(expected_clean, body_style),
                ],
                [
                    Paragraph("Observed Behavior:", meta_label_style),
                    Paragraph(observed_clean, body_style),
                ],
                [
                    Paragraph("Evidence / Payload:", meta_label_style),
                    Paragraph(evidence_clean, evidence_style),
                ],
                [
                    Paragraph("Telemetry / Traces:", meta_label_style),
                    Paragraph(trace_summary, body_style),
                ],
            ]

            card_table = Table(card_body_data, colWidths=[110, 422])
            card_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFFFFF")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            finding_elements.append(card_table)
            finding_elements.append(Spacer(1, 8))

            story.append(KeepTogether(finding_elements))

    # 5. Limitations Section
    story.append(Spacer(1, 10))
    story.append(Paragraph("Scope & Evaluation Limitations", section_h1))
    disclaimer_text = (
        "<b>Notice of Limitations:</b> This security assessment report reflects strictly the findings, telemetry, "
        "and behavioral evidence supplied during the specified evaluation run. Automated testing probes cannot "
        "guarantee absolute safety against all potential adversarial techniques or zero-day jailbreaks. "
        "AgentBreak results should be used alongside comprehensive threat modeling and human oversight."
    )
    disclaimer_p = Paragraph(disclaimer_text, body_style)
    disclaimer_table = Table([[disclaimer_p]], colWidths=[532])
    disclaimer_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(disclaimer_table)

    # Build PDF using NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)

    pdf_bytes = buffer.getvalue()

    # If destination specified, write output
    if output_destination is not None:
        if isinstance(output_destination, io.BytesIO):
            output_destination.write(pdf_bytes)
        else:
            dest_path = Path(output_destination)
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            with open(dest_path, "wb") as f:
                f.write(pdf_bytes)

    return pdf_bytes
