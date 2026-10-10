"""
AgentBreak - Member 4 Reporting Module.
Standalone report generation module converting structured security scan results
into downloadable JSON and PDF reports.
"""

from app.report_data import (
    DataProvenance,
    DataProvenanceType,
    Finding,
    FindingOutcome,
    ScanMetadata,
    ScanReport,
    TraceReference,
)
from app.report_service import (
    generate_json_report,
    generate_pdf_report,
)

__all__ = [
    "ScanReport",
    "ScanMetadata",
    "Finding",
    "FindingOutcome",
    "TraceReference",
    "DataProvenance",
    "DataProvenanceType",
    "generate_json_report",
    "generate_pdf_report",
]
