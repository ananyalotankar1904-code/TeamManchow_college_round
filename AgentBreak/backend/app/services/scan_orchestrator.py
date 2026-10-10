from typing import List, Dict, Any
import uuid
from app.services.agent_adapter import AgentAdapter
from app.services.security_engine_interface import SecurityEngine
from app.schemas.scan import ScanCreate, Scan
from app.schemas.finding import FindingCreate
from sqlalchemy.orm import Session
from app.database.models import ScanModel, FindingModel, TraceModel

class ScanOrchestrator:
    def __init__(self, agent_adapter: AgentAdapter, security_engine: SecurityEngine):
        self.agent_adapter = agent_adapter
        self.security_engine = security_engine
    
    def run_scan(self, db: Session, scan_request: ScanCreate, scan_id: str) -> Dict[str, Any]:
        test_cases = scan_request.test_cases or ["default_test"]
        db_scan = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
        
        try:
            findings, traces = self.security_engine.run_tests(test_cases, self.agent_adapter, scan_id)
            
            # Persist traces
            for trace in traces:
                db_trace = TraceModel(
                    id=str(uuid.uuid4()),
                    scan_id=trace.scan_id,
                    test_id=trace.test_id,
                    events=trace.events
                )
                # Update trace_id in findings if they match test_id and are not already set
                for finding in findings:
                    if finding.test_id == trace.test_id and not finding.trace_id:
                        finding.trace_id = db_trace.id
                db.add(db_trace)
                
            # Persist findings
            for finding in findings:
                db_finding = FindingModel(
                    id=str(uuid.uuid4()),
                    scan_id=finding.scan_id,
                    test_id=finding.test_id,
                    category=finding.category,
                    execution_status=finding.execution_status,
                    outcome=finding.outcome,
                    expected_behavior=finding.expected_behavior,
                    observed_behavior=finding.observed_behavior,
                    evidence=finding.evidence,
                    trace_id=finding.trace_id
                )
                db.add(db_finding)
                
            # Update scan status
            if db_scan:
                db_scan.status = "completed"
                
            db.commit()
            
            return {
                "scan_id": scan_id,
                "status": "completed",
                "findings": findings
            }
        except Exception as e:
            db.rollback()
            db_scan_refresh = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
            if db_scan_refresh:
                db_scan_refresh.status = "failed"
                db.commit()
            raise e
