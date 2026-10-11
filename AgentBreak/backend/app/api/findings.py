from fastapi import APIRouter, Depends, HTTPException
from typing import List
from sqlalchemy.orm import Session
from app.schemas.finding import Finding
from app.database.connection import get_db
from app.database.models import FindingModel

router = APIRouter()

@router.get("/", response_model=List[Finding])
def list_findings(db: Session = Depends(get_db)):
    """Retrieve all findings across scans."""
    return db.query(FindingModel).all()

@router.get("/detail/{finding_id}", response_model=Finding)
def get_finding_by_id(finding_id: str, db: Session = Depends(get_db)):
    """Retrieve a single finding by its finding ID."""
    finding = db.query(FindingModel).filter(FindingModel.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding

@router.get("/{scan_id}", response_model=List[Finding])
def get_findings_for_scan(scan_id: str, db: Session = Depends(get_db)):
    """Retrieve findings for a specific scan, or fallback to finding by ID."""
    findings = db.query(FindingModel).filter(FindingModel.scan_id == scan_id).all()
    if findings:
        return findings
    # Flexible fallback: if caller passed a finding_id instead of a scan_id
    finding = db.query(FindingModel).filter(FindingModel.id == scan_id).first()
    if finding:
        return [finding]
    return []
