from pydantic import BaseModel
from typing import Optional

class AgentBase(BaseModel):
    name: str
    description: Optional[str] = None

class AgentCreate(AgentBase):
    pass

class Agent(AgentBase):
    id: str
    class Config:
        from_attributes = True
