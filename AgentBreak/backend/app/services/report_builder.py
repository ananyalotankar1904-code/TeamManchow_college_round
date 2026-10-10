import os
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from fastapi import HTTPException
from app.database.models import ScanModel, FindingModel, TraceModel
from app.schemas.report_data import (
    ScanReport,
    ScanMetadata,
    DataProvenance,
    DataProvenanceType,
    Finding,
    TraceReference
)

def build_report(db: Session, scan_id: str) -> ScanReport:
    scan = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.query(FindingModel).filter(FindingModel.scan_id == scan_id).all()

    # Determine provenance
    agent_adapter = os.getenv("AGENT_ADAPTER", "target")
    security_engine = os.getenv("SECURITY_ENGINE", "mock")

    if agent_adapter == "mock" or security_engine == "mock":
        prov_type = DataProvenanceType.MOCK_DEMO
        prov_desc = "Generated using mock engine or mock agent adapter."
    else:
        prov_type = DataProvenanceType.SYNTHETIC
        prov_desc = "Generated from synthetic security tests executed against a live target agent."

    provenance = DataProvenance(
        provenance_type=prov_type,
        source_description=prov_desc,
        generated_at=datetime.now(timezone.utc)
    )

    metadata = ScanMetadata(
        scan_id=scan.id,
        agent_id=scan.agent_id,
        status=scan.status,
        started_at=scan.created_at,
        completed_at=None,
        scanner_version="AgentBreak v1.0",
        target_environment=os.getenv("TARGET_ENV", "dev"),
        extra_metadata={}
    )

    report_findings = []
    for f in findings:
        trace_references = []
        if f.trace_id:
            trace = db.query(TraceModel).filter(TraceModel.id == f.trace_id).first()
            if trace and trace.events:
                for idx, event in enumerate(trace.events):
                    if isinstance(event, dict):
                        # Safely extract timestamp
                        ts_str = event.get("timestamp")
                        ts = None
                        if ts_str:
                            try:
                                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                            except ValueError:
                                pass
                        
                        trace_references.append(TraceReference(
                            trace_id=trace.id,
                            span_id=str(idx),
                            event_name=event.get("event_type", "unknown_event"),
                            timestamp=ts,
                            details=event
                        ))

        # f.category might not be perfectly mapped, but it's just a string in Finding
        report_findings.append(Finding(
            finding_id=f.id,
            test_id=f.test_id,
            category=f.category,
            severity="unknown", # Explicitly unassigned until database supports a severity field
            execution_status=f.execution_status,
            outcome=f.outcome if f.outcome else "inconclusive",
            expected_behavior=f.expected_behavior,
            observed_behavior=f.observed_behavior,
            evidence=f.evidence,
            trace_id=f.trace_id,
            trace_references=trace_references if trace_references else None,
            metadata={}
        ))

    report = ScanReport(
        metadata=metadata,
        provenance=provenance,
        findings=report_findings,
        summary_notes="Report generated successfully via AgentBreak API."
    )
    return report
