import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database.connection import Base, engine, get_db
from app.database.models import FindingModel, ScanModel, AgentModel
from sqlalchemy.orm import Session
import uuid

client = TestClient(app)

@pytest.fixture(scope="module")
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = next(get_db())
    
    agent_id = f"test_ag_{uuid.uuid4()}"
    scan_id = f"test_scan_{uuid.uuid4()}"
    finding_id = f"test_fnd_{uuid.uuid4()}"
    
    agent = AgentModel(id=agent_id, name="Test Agent", description="Test")
    scan = ScanModel(id=scan_id, agent_id=agent_id, status="completed")
    finding = FindingModel(
        id=finding_id,
        scan_id=scan_id,
        test_id="test-1",
        category="direct_prompt_injection",
        execution_status="success",
        outcome="vulnerability_confirmed",
        expected_behavior="block",
        observed_behavior="execute",
        evidence="{}"
    )
    db.add(agent)
    db.add(scan)
    db.add(finding)
    db.commit()
    
    yield {"finding_id": finding_id}
    
    db.query(FindingModel).filter(FindingModel.id == finding_id).delete()
    db.query(ScanModel).filter(ScanModel.id == scan_id).delete()
    db.query(AgentModel).filter(AgentModel.id == agent_id).delete()
    db.commit()

def test_create_recommendation(setup_db):
    finding_id = setup_db["finding_id"]
    response = client.post(f"/api/v1/fixloop/{finding_id}/recommendation")
    assert response.status_code == 200
    data = response.json()
    assert data["finding_id"] == finding_id
    assert data["verdict"] == "proposed"
    assert "mitigation" in data["proposed_mitigation"].lower() or "isolate" in data["proposed_mitigation"].lower()
    assert data["mitigation_applied"] == False

def test_get_session(setup_db):
    finding_id = setup_db["finding_id"]
    response = client.get(f"/api/v1/fixloop/{finding_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["finding_id"] == finding_id

def test_handle_nonexistent_finding():
    response = client.post(f"/api/v1/fixloop/nonexistent/recommendation")
    assert response.status_code == 404

from unittest.mock import patch
from app.schemas.finding import FindingCreate
from app.schemas.trace import TraceCreate

def mock_run_tests_effective(test_cases, agent, scan_id):
    findings = []
    traces = []
    for t_id in test_cases:
        outcome = "executed" if t_id.startswith("BR-") else "blocked"
        f = FindingCreate(scan_id=scan_id, test_id=t_id, category="test", execution_status="completed", outcome=outcome, expected_behavior="", observed_behavior="", evidence="", trace_id="trace-123")
        findings.append(f)
        traces.append(TraceCreate(scan_id=scan_id, test_id=t_id, events=[]))
    return findings, traces

@patch("app.services.security_engine_interface.MockSecurityEngine.run_tests", side_effect=mock_run_tests_effective)
def test_verify_fix_effective(mock_run, setup_db):
    finding_id = setup_db["finding_id"]
    response = client.post(f"/api/v1/fixloop/{finding_id}/verify")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "verified_fixed"
    assert data["retest_outcome"] == "blocked"
    assert data["regression_tests"][0]["status"] == "passed"

def mock_run_tests_ineffective(test_cases, agent, scan_id):
    findings = []
    traces = []
    for t_id in test_cases:
        outcome = "executed" if t_id.startswith("BR-") else "failed"
        f = FindingCreate(scan_id=scan_id, test_id=t_id, category="test", execution_status="completed", outcome=outcome, expected_behavior="", observed_behavior="", evidence="", trace_id="trace-123")
        findings.append(f)
        traces.append(TraceCreate(scan_id=scan_id, test_id=t_id, events=[]))
    return findings, traces

@patch("app.services.security_engine_interface.MockSecurityEngine.run_tests", side_effect=mock_run_tests_ineffective)
def test_verify_fix_ineffective(mock_run, setup_db):
    finding_id = setup_db["finding_id"]
    response = client.post(f"/api/v1/fixloop/{finding_id}/verify")
    data = response.json()
    assert data["verdict"] == "still_vulnerable"
    assert data["retest_outcome"] == "failed"

def mock_run_tests_regression_failure(test_cases, agent, scan_id):
    findings = []
    traces = []
    for t_id in test_cases:
        outcome = "failed" if t_id.startswith("BR-") else "blocked"
        f = FindingCreate(scan_id=scan_id, test_id=t_id, category="test", execution_status="completed", outcome=outcome, expected_behavior="", observed_behavior="", evidence="", trace_id="trace-123")
        findings.append(f)
        traces.append(TraceCreate(scan_id=scan_id, test_id=t_id, events=[]))
    return findings, traces

@patch("app.services.security_engine_interface.MockSecurityEngine.run_tests", side_effect=mock_run_tests_regression_failure)
def test_verify_fix_regression_failure(mock_run, setup_db):
    finding_id = setup_db["finding_id"]
    response = client.post(f"/api/v1/fixloop/{finding_id}/verify")
    data = response.json()
    assert data["verdict"] == "regression_detected"
    assert data["regression_tests"][0]["status"] == "failed"

def mock_run_tests_missing_evidence(test_cases, agent, scan_id):
    findings = []
    traces = []
    for t_id in test_cases:
        outcome = "inconclusive"
        f = FindingCreate(scan_id=scan_id, test_id=t_id, category="test", execution_status="completed", outcome=outcome, expected_behavior="", observed_behavior="", evidence="", trace_id="trace-123")
        findings.append(f)
        traces.append(TraceCreate(scan_id=scan_id, test_id=t_id, events=[]))
    return findings, traces

@patch("app.services.security_engine_interface.MockSecurityEngine.run_tests", side_effect=mock_run_tests_missing_evidence)
def test_verify_fix_missing_evidence(mock_run, setup_db):
    finding_id = setup_db["finding_id"]
    response = client.post(f"/api/v1/fixloop/{finding_id}/verify")
    data = response.json()
    assert data["verdict"] == "inconclusive"

@patch("app.services.security_engine_interface.MockSecurityEngine.run_tests", side_effect=Exception("Timeout or Execution Error"))
def test_verify_fix_execution_error(mock_run, setup_db):
    finding_id = setup_db["finding_id"]
    response = client.post(f"/api/v1/fixloop/{finding_id}/verify")
    data = response.json()
    assert data["verdict"] == "inconclusive"
    assert data["retest_outcome"] == "error"
    assert "Execution error" in data["comparison_notes"]
