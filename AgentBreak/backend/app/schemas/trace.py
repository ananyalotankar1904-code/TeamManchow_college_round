from pydantic import BaseModel, ConfigDict
from typing import Any

class TraceBase(BaseModel):
    scan_id: str
    test_id: str
    events: list[Any]

class TraceCreate(TraceBase):
    pass

class Trace(TraceBase):
    id: str
    model_config = ConfigDict(from_attributes=True)
