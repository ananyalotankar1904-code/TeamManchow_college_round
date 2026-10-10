from fastapi import APIRouter, Depends
from typing import List
from sqlalchemy.orm import Session
from app.schemas.finding import Finding
from app.database.connection import get_db
from app.database.models import FindingModel

router = APIRouter()

@router.get("/{scan_id}", response_model=List[Finding])
def get_findings_for_scan(scan_id: str, db: Session = Depends(get_db)):
    findings = db.query(FindingModel).filter(FindingModel.scan_id == scan_id).all()
    return findings
