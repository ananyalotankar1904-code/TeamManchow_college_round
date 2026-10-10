from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.schemas.fixloop import FixLoopSession
from app.services.fixloop_service import FixLoopService
from app.services.scan_orchestrator import ScanOrchestrator
from app.api.deps import get_agent_adapter, get_security_engine

router = APIRouter()

@router.post("/{finding_id}/recommendation", response_model=FixLoopSession)
def create_recommendation(finding_id: str, db: Session = Depends(get_db)):
    service = FixLoopService(db)
    return service.generate_recommendation(finding_id)

@router.get("/{finding_id}", response_model=FixLoopSession)
def get_fixloop_session(finding_id: str, db: Session = Depends(get_db)):
    service = FixLoopService(db)
    return service.get_session(finding_id)

@router.post("/{finding_id}/verify", response_model=FixLoopSession)
def verify_fix(
    finding_id: str, 
    db: Session = Depends(get_db),
    adapter = Depends(get_agent_adapter),
    engine = Depends(get_security_engine)
):
    service = FixLoopService(db)
    orchestrator = ScanOrchestrator(agent_adapter=adapter, security_engine=engine)
    return service.verify_fix(finding_id, orchestrator)
