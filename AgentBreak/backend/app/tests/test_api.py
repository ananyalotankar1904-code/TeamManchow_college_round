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

app.dependency_overrides[get_db] = override_get_db

from app.api.deps import get_agent_adapter, get_security_engine
from app.services.agent_adapter import MockAgentAdapter
from app.services.security_engine_interface import MockSecurityEngine

app.dependency_overrides[get_agent_adapter] = lambda: MockAgentAdapter()
app.dependency_overrides[get_security_engine] = lambda: MockSecurityEngine()

client = TestClient(app)

@pytest.fixture(autouse=True)
def run_around_tests():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

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
        # Restore mock
        app.dependency_overrides[get_security_engine] = lambda: MockSecurityEngine()

