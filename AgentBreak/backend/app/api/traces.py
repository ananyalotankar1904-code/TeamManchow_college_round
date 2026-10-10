from fastapi import APIRouter, Depends, HTTPException
from typing import List
from sqlalchemy.orm import Session
from app.schemas.trace import Trace
from app.database.connection import get_db
from app.database.models import TraceModel

router = APIRouter()

@router.get("/{trace_id}", response_model=Trace)
def get_trace(trace_id: str, db: Session = Depends(get_db)):
    trace = db.query(TraceModel).filter(TraceModel.id == trace_id).first()
    if not trace:
        raise HTTPException(status_code=404, detail="Trace not found")
    return trace
