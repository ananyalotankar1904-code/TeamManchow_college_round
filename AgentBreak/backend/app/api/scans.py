from fastapi import APIRouter, Depends, HTTPException
from typing import List
from sqlalchemy.orm import Session
from app.schemas.scan import Scan, ScanCreate
from app.services.scan_orchestrator import ScanOrchestrator
from app.api.deps import get_agent_adapter, get_security_engine
from app.database.connection import get_db
from app.database.models import AgentModel, ScanModel
import uuid

router = APIRouter()

@router.get("/", response_model=List[Scan])
def list_scans(db: Session = Depends(get_db)):
    return db.query(ScanModel).all()

@router.post("/", response_model=Scan)
def create_scan(
    scan: ScanCreate, 
    db: Session = Depends(get_db),
    adapter = Depends(get_agent_adapter),
    engine = Depends(get_security_engine)
):
    # Validate agent
    agent = db.query(AgentModel).filter(AgentModel.id == scan.agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    scan_id = str(uuid.uuid4())
    db_scan = ScanModel(id=scan_id, agent_id=scan.agent_id, status="running")
    db.add(db_scan)
    db.commit()
    
    orchestrator = ScanOrchestrator(agent_adapter=adapter, security_engine=engine)
    try:
        result = orchestrator.run_scan(db, scan, scan_id)
    except Exception as e:
        # DB rollback and status update are handled by orchestrator, or we do it here?
        # Let's just let the endpoint return 500. The orchestrator will handle the status update.
        raise HTTPException(status_code=500, detail=f"Scan execution failed: {str(e)}")
    
    db.refresh(db_scan)
    return db_scan

@router.get("/{scan_id}", response_model=Scan)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    db_scan = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return db_scan
