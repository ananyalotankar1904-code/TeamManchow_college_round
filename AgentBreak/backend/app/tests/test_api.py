from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import pytest
from app.main import app
from app.database.connection import Base, get_db

SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

from app.api.deps import get_agent_adapter, get_security_engine
from app.services.agent_adapter import MockAgentAdapter
from app.services.security_engine_interface import MockSecurityEngine

client = TestClient(app)

@pytest.fixture(autouse=True)
def run_around_tests():
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_agent_adapter] = lambda: MockAgentAdapter()
    app.dependency_overrides[get_security_engine] = lambda: MockSecurityEngine()
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.pop(get_db, None)
    app.dependency_overrides.pop(get_agent_adapter, None)
    app.dependency_overrides.pop(get_security_engine, None)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "project": "AgentBreak API"}

def test_agent_registration():
    response = client.post("/api/v1/agents/", json={"name": "TestAgent", "description": "Desc"})
    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    assert data["name"] == "TestAgent"

    # Get agent
    response = client.get(f"/api/v1/agents/{data['id']}")
    assert response.status_code == 200
    assert response.json()["name"] == "TestAgent"

def test_scan_invalid_agent():
    response = client.post("/api/v1/scans/", json={"agent_id": "invalid_id", "test_cases": ["t1"]})
    assert response.status_code == 404
    assert response.json()["detail"] == "Agent not found"

def test_full_scan_lifecycle():
    # 1. Register agent
    agent_response = client.post("/api/v1/agents/", json={"name": "TestAgent2", "description": "Desc"})
    agent_id = agent_response.json()["id"]

    # 2. Start scan
    scan_response = client.post("/api/v1/scans/", json={"agent_id": agent_id, "test_cases": ["t1"]})
    assert scan_response.status_code == 200
    scan_data = scan_response.json()
    scan_id = scan_data["id"]
    assert scan_data["status"] == "completed"

    # 3. Retrieve scan
    scan_get = client.get(f"/api/v1/scans/{scan_id}")
    assert scan_get.status_code == 200
    assert scan_get.json()["id"] == scan_id

    # 4. Retrieve findings
    findings_response = client.get(f"/api/v1/findings/{scan_id}")
    assert findings_response.status_code == 200
    findings = findings_response.json()
    assert len(findings) > 0
    finding = findings[0]
    assert finding["scan_id"] == scan_id
    assert finding["outcome"] == "failed"
    
    # 5. Retrieve trace
    trace_id = finding["trace_id"]
    assert trace_id is not None
    trace_response = client.get(f"/api/v1/traces/{trace_id}")
    assert trace_response.status_code == 200
    trace = trace_response.json()
    assert trace["id"] == trace_id
    assert trace["scan_id"] == scan_id

def test_invalid_trace_and_scan():
    assert client.get("/api/v1/scans/invalid").status_code == 404
    assert client.get("/api/v1/traces/invalid").status_code == 404

def test_scan_engine_failure():
    # Register agent
    agent_response = client.post("/api/v1/agents/", json={"name": "FailAgent", "description": "Desc"})
    agent_id = agent_response.json()["id"]

    # Override engine to raise Exception
    class FailingSecurityEngine:
        def run_tests(self, test_cases, agent, scan_id):
            raise Exception("Simulated Engine Failure")
            
    try:
        app.dependency_overrides[get_security_engine] = lambda: FailingSecurityEngine()
        
        # Start scan
        scan_response = client.post("/api/v1/scans/", json={"agent_id": agent_id, "test_cases": ["t1"]})
        assert scan_response.status_code == 500
    finally:
        app.dependency_overrides[get_security_engine] = lambda: MockSecurityEngine()

def test_list_endpoints():
    client.post("/api/v1/agents/", json={"name": "AgentListTest", "description": "Desc"})
    agents_res = client.get("/api/v1/agents/")
    assert agents_res.status_code == 200
    assert len(agents_res.json()) >= 1

    scans_res = client.get("/api/v1/scans/")
    assert scans_res.status_code == 200

    findings_res = client.get("/api/v1/findings/")
    assert findings_res.status_code == 200

def test_live_finding_details_flow():
    from app.database.models import FindingModel, ScanModel, AgentModel
    import uuid

    db = TestingSessionLocal()
    agent_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())
    finding_id = str(uuid.uuid4())

    db.add(AgentModel(id=agent_id, name="LiveAgent", description="Live test agent"))
    db.add(ScanModel(id=scan_id, agent_id=agent_id, status="completed"))
    db.add(FindingModel(
        id=finding_id,
        scan_id=scan_id,
        test_id="DI-001",
        category="direct_prompt_injection",
        execution_status="completed",
        outcome="vulnerability_confirmed",
        expected_behavior="Safe refusal",
        observed_behavior="Leaked internal canary",
        evidence="Observed secret canary in output trace",
        trace_id=None
    ))
    db.commit()
    db.close()

    # 1. Verify scan findings query doesn't fail with 500 ResponseValidationError
    res_scan = client.get(f"/api/v1/findings/{scan_id}")
    assert res_scan.status_code == 200
    findings = res_scan.json()
    assert len(findings) == 1
    assert findings[0]["id"] == finding_id
    assert findings[0]["outcome"] == "vulnerability_confirmed"

    # 2. Verify finding details endpoint
    res_detail = client.get(f"/api/v1/findings/detail/{finding_id}")
    assert res_detail.status_code == 200
    assert res_detail.json()["id"] == finding_id
    assert res_detail.json()["outcome"] == "vulnerability_confirmed"

    # 3. Verify finding lookup by ID fallback
    res_by_id = client.get(f"/api/v1/findings/{finding_id}")
    assert res_by_id.status_code == 200
    assert len(res_by_id.json()) == 1
    assert res_by_id.json()[0]["id"] == finding_id

