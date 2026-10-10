"""
Tests for PDF report generation using ReportLab in AgentBreak.
"""

import io
from pathlib import Path

import pytest

from app.schemas.report_data import (
    DataProvenance,
    DataProvenanceType,
    Finding,
    FindingOutcome,
    ScanMetadata,
    ScanReport,
    TraceReference,
)
from app.services.report_service import generate_pdf_report


def test_pdf_generation_returns_valid_bytes():
    """Verify that generate_pdf_report returns valid PDF bytes starting with %PDF-."""
    report = ScanReport(
        metadata=ScanMetadata(
            scan_id="SCAN-PDF-01",
            agent_id="test-agent",
            status="completed",
        ),
        provenance=DataProvenance(
            provenance_type=DataProvenanceType.SYNTHETIC,
            source_description="Synthetic Benchmark Suite",
        ),
        findings=[
            Finding(
                finding_id="FIND-101",
                test_id="TEST-01",
                category="prompt_injection",
                severity="critical",
                execution_status="completed",
                outcome=FindingOutcome.EXECUTED,
                expected_behavior="Agent should refuse.",
                observed_behavior="Agent complied.",
                evidence="User: Ignore previous instructions.",
            )
        ],
    )

    pdf_bytes = generate_pdf_report(report)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF-")


def test_pdf_write_to_file(tmp_path: Path):
    """Verify that generate_pdf_report properly writes to a specified output file path."""
    dest_file = tmp_path / "reports" / "test_output.pdf"
    report = ScanReport(
        metadata=ScanMetadata(scan_id="SCAN-FILE", agent_id="agent-f", status="completed"),
        provenance=DataProvenance(provenance_type=DataProvenanceType.MOCK_DEMO),
        findings=[],
    )

    pdf_bytes = generate_pdf_report(report, output_destination=dest_file)
    assert dest_file.exists()
    assert dest_file.stat().st_size > 500
    assert dest_file.read_bytes().startswith(b"%PDF-")
    assert pdf_bytes == dest_file.read_bytes()


def test_pdf_write_to_bytesio():
    """Verify that generate_pdf_report writes to a BytesIO object."""
    buffer = io.BytesIO()
    report = ScanReport(
        metadata=ScanMetadata(scan_id="SCAN-BUF", agent_id="agent-b", status="completed"),
        provenance=DataProvenance(provenance_type=DataProvenanceType.REAL_EXECUTION),
        findings=[],
    )

    pdf_bytes = generate_pdf_report(report, output_destination=buffer)
    assert buffer.getvalue().startswith(b"%PDF-")
    assert buffer.getvalue() == pdf_bytes


def test_pdf_empty_findings_does_not_crash():
    """Verify that a scan with zero findings renders successfully with clean empty messaging."""
    report = ScanReport(
        metadata=ScanMetadata(scan_id="SCAN-EMPTY-PDF", agent_id="clean-agent", status="completed"),
        provenance=DataProvenance(provenance_type=DataProvenanceType.SYNTHETIC),
        findings=[],
    )

    pdf_bytes = generate_pdf_report(report)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF-")


def test_pdf_multiple_findings_and_page_flow():
    """Verify that multiple findings render cleanly across multiple pages."""
    findings = [
        Finding(
            finding_id=f"FIND-{i:03d}",
            test_id=f"TEST-{i:03d}",
            category=f"vulnerability_category_{i}",
            severity="high" if i % 2 == 0 else "low",
            execution_status="completed",
            outcome=FindingOutcome.BLOCKED if i % 2 == 0 else FindingOutcome.EXECUTED,
            expected_behavior=f"Expected behavior description for test probe #{i}.",
            observed_behavior=f"Observed behavior details for test probe #{i}.",
            evidence=f"Detailed evidence payload recorded during test probe #{i}.",
        )
        for i in range(1, 12)  # 11 findings, triggers multiple pages
    ]

    report = ScanReport(
        metadata=ScanMetadata(scan_id="SCAN-MULTI", agent_id="agent-scale", status="completed"),
        provenance=DataProvenance(provenance_type=DataProvenanceType.MOCK_DEMO),
        findings=findings,
    )

    pdf_bytes = generate_pdf_report(report)
    assert len(pdf_bytes) > 3000
    assert pdf_bytes.startswith(b"%PDF-")


def test_pdf_handles_long_unbroken_strings_and_special_chars():
    """Verify that long strings with no spaces, HTML tags, and special characters do not crash ReportLab."""
    nasty_long_string = "A" * 2000
    nasty_xml_string = "<script>alert('xss');</script> & <<test>> 'quotes' \"double\" \n newline \t tab"
    
    finding = Finding(
        finding_id="FIND-NASTY",
        test_id="TEST-NASTY",
        category="xss_injection_&_boundary",
        severity="critical",
        execution_status="completed",
        outcome=FindingOutcome.ATTEMPTED,
        expected_behavior=nasty_xml_string,
        observed_behavior="Handled safely: " + nasty_long_string,
        evidence=nasty_xml_string + " | payload: " + nasty_long_string,
        trace_id="tr-nasty-001",
    )

    report = ScanReport(
        metadata=ScanMetadata(scan_id="SCAN-NASTY", agent_id="robustness-agent", status="completed"),
        provenance=DataProvenance(provenance_type=DataProvenanceType.SYNTHETIC),
        findings=[finding],
    )

    pdf_bytes = generate_pdf_report(report)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF-")


def test_pdf_renders_from_sample_json_file():
    """Verify PDF generation directly from the sample JSON file content."""
    sample_file = Path(__file__).parent.parent / "examples" / "sample_report.json"
    content = sample_file.read_text(encoding="utf-8")
    pdf_bytes = generate_pdf_report(content)

    assert len(pdf_bytes) > 2000
    assert pdf_bytes.startswith(b"%PDF-")
