from pydantic import BaseModel, ConfigDict
from typing import Optional, Literal

class FindingBase(BaseModel):
    scan_id: str
    test_id: str
    category: str
    execution_status: str
    outcome: Literal["attempted", "blocked", "executed", "failed", "inconclusive"]
    expected_behavior: str
    observed_behavior: str
    evidence: str
    trace_id: Optional[str] = None

class FindingCreate(FindingBase):
    pass

class Finding(FindingBase):
    id: str
    model_config = ConfigDict(from_attributes=True)
