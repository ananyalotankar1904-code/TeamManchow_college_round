from fastapi import APIRouter, Depends, HTTPException
from typing import List
from sqlalchemy.orm import Session
from app.schemas.agent import Agent, AgentCreate
from app.database.connection import get_db
from app.database.models import AgentModel
import uuid

router = APIRouter()

@router.get("/", response_model=List[Agent])
def list_agents(db: Session = Depends(get_db)):
    return db.query(AgentModel).all()

@router.post("/", response_model=Agent)
def register_agent(agent: AgentCreate, db: Session = Depends(get_db)):
    db_agent = AgentModel(id=str(uuid.uuid4()), name=agent.name, description=agent.description)
    db.add(db_agent)
    db.commit()
    db.refresh(db_agent)
    return db_agent

@router.get("/{agent_id}", response_model=Agent)
def get_agent(agent_id: str, db: Session = Depends(get_db)):
    db_agent = db.query(AgentModel).filter(AgentModel.id == agent_id).first()
    if not db_agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return db_agent
