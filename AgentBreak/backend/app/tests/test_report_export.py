import pytest
import os
import uuid
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.main import app
from app.database.connection import engine, Base, SessionLocal, get_db
from app.database.models import AgentModel, ScanModel, FindingModel, TraceModel

Base.metadata.create_all(bind=engine)

def override_get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture
def sample_scan(db_session: Session):
    agent_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())
    
    agent = AgentModel(id=agent_id, name="Test Agent", description="Test")
    scan = ScanModel(id=scan_id, agent_id=agent_id, status="completed")
    
    db_session.add(agent)
    db_session.add(scan)
    db_session.commit()
    
    return scan_id

@pytest.fixture
def sample_scan_with_findings(db_session: Session, sample_scan):
    trace_id = str(uuid.uuid4())
    trace = TraceModel(
        id=trace_id,
        scan_id=sample_scan,
        test_id="test_1",
        events=[{"event_type": "tool_call", "tool": "test", "timestamp": "2023-10-10T10:00:00Z"}]
    )
    
    finding = FindingModel(
        id=str(uuid.uuid4()),
        scan_id=sample_scan,
        test_id="test_1",
        category="injection",
        execution_status="completed",
        outcome="vulnerability_confirmed",
        expected_behavior="Safe",
        observed_behavior="Unsafe SECRET: sk-12345678901234567890",
        evidence="Found secret sk-12345678901234567890",
        trace_id=trace_id
    )
    
    db_session.add(trace)
    db_session.add(finding)
    db_session.commit()
    
    return sample_scan

def test_json_export_existing_scan(sample_scan_with_findings):
    response = client.get(f"/api/v1/reports/{sample_scan_with_findings}/export?format=json")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    data = response.json()
    assert data["metadata"]["scan_id"] == sample_scan_with_findings
    assert len(data["findings"]) == 1
    
def test_pdf_export_existing_scan(sample_scan_with_findings):
    response = client.get(f"/api/v1/reports/{sample_scan_with_findings}/export?format=pdf")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert "attachment; filename" in response.headers["content-disposition"]
    assert len(response.content) > 1000  # valid PDF bytes

def test_scan_no_findings(sample_scan):
    response = client.get(f"/api/v1/reports/{sample_scan}/export?format=json")
    assert response.status_code == 200
    data = response.json()
    assert len(data["findings"]) == 0
    assert data["summary"]["total_findings"] == 0

def test_nonexistent_scan():
    response = client.get(f"/api/v1/reports/fake_scan/export?format=json")
    assert response.status_code == 404

def test_unsupported_format(sample_scan):
    response = client.get(f"/api/v1/reports/{sample_scan}/export?format=xml")
    assert response.status_code == 400

def test_correct_conversion(sample_scan_with_findings):
    response = client.get(f"/api/v1/reports/{sample_scan_with_findings}/export?format=json")
    assert response.status_code == 200
    data = response.json()
    assert data["findings"][0]["outcome"] == "vulnerability_confirmed"

def test_provenance_mock_demo(sample_scan_with_findings, monkeypatch):
    monkeypatch.setenv("AGENT_ADAPTER", "mock")
    monkeypatch.setenv("SECURITY_ENGINE", "real")
    response = client.get(f"/api/v1/reports/{sample_scan_with_findings}/export?format=json")
    data = response.json()
    assert data["provenance"]["provenance_type"] == "mock_demo"

def test_provenance_real_execution(sample_scan_with_findings, monkeypatch):
    monkeypatch.setenv("AGENT_ADAPTER", "target")
    monkeypatch.setenv("SECURITY_ENGINE", "real")
    response = client.get(f"/api/v1/reports/{sample_scan_with_findings}/export?format=json")
    data = response.json()
    # Mapped to synthetic since synthetic tests against real agent
    assert data["provenance"]["provenance_type"] == "synthetic"

def test_secret_redaction(sample_scan_with_findings):
    response = client.get(f"/api/v1/reports/{sample_scan_with_findings}/export?format=json")
    data = response.json()
    finding = data["findings"][0]
    assert "sk-12345678901234567890" not in finding["observed_behavior"]
    assert "sk-12345678901234567890" not in finding["evidence"]
    assert "[REDACTED_SECRET]" in finding["observed_behavior"]

def test_existing_endpoints_functional(sample_scan_with_findings):
    # Just verify that the scans endpoints didn't break
    response = client.get(f"/api/v1/scans/{sample_scan_with_findings}")
    assert response.status_code == 200

def test_pdf_secret_redaction(sample_scan_with_findings):
    response = client.get(f"/api/v1/reports/{sample_scan_with_findings}/export?format=pdf")
    assert response.status_code == 200
    
    import io
    from pypdf import PdfReader
    
    pdf_bytes = io.BytesIO(response.content)
    reader = PdfReader(pdf_bytes)
    
    text = ""
    for page in reader.pages:
        text += page.extract_text() or ""
        
    assert "sk-12345678901234567890" not in text
    assert "[REDACTED_SECRET]" in text
