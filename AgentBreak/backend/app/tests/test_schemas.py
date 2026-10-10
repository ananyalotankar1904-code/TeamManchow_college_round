from app.schemas.agent import AgentCreate
from app.schemas.scan import ScanCreate
from app.schemas.finding import FindingCreate
import pytest
from pydantic import ValidationError

def test_agent_schema_valid():
    agent = AgentCreate(name="Test Agent", description="A test agent")
    assert agent.name == "Test Agent"

def test_agent_schema_invalid():
    with pytest.raises(ValidationError):
        AgentCreate(name=123)  # Invalid type, though pydantic might cast, let's omit description
    
def test_scan_schema_valid():
    scan = ScanCreate(agent_id="agent_1")
    assert scan.agent_id == "agent_1"

def test_scan_schema_invalid():
    with pytest.raises(ValidationError):
        ScanCreate() # Missing agent_id

def test_finding_schema_valid():
    finding = FindingCreate(
        scan_id="scan_1",
        test_id="test_1",
        category="auth",
        execution_status="completed",
        outcome="failed",
        expected_behavior="deny",
        observed_behavior="allow",
        evidence="logs"
    )
    assert finding.scan_id == "scan_1"
