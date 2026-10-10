from pydantic import BaseModel, ConfigDict
from typing import Optional, List, Literal

class RegressionTest(BaseModel):
    name: str
    expected_outcome: str
    actual_outcome: str
    status: Literal["passed", "failed", "skipped", "inconclusive"]

class FixLoopSessionBase(BaseModel):
    finding_id: str
    proposed_mitigation: str
    mitigation_applied: bool = False
    retest_run_id: Optional[str] = None
    retest_outcome: Optional[str] = None
    regression_tests: List[RegressionTest] = []
    verdict: Literal["proposed", "verification_pending", "verified_fixed", "still_vulnerable", "regression_detected", "inconclusive", "verification_error"]
    comparison_notes: Optional[str] = None

class FixLoopSessionCreate(FixLoopSessionBase):
    pass

class FixLoopSession(FixLoopSessionBase):
    id: str
    model_config = ConfigDict(from_attributes=True)
