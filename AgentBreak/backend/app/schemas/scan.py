from pydantic import BaseModel
from typing import Optional

class ScanBase(BaseModel):
    agent_id: str

class ScanCreate(ScanBase):
    test_cases: Optional[list[str]] = None

class Scan(ScanBase):
    id: str
    status: str
    class Config:
        from_attributes = True
