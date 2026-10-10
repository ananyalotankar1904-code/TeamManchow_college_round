import os

def create_file(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

base_dir = "c:/Users/Dell/OneDrive/Desktop/TeamManchow_college_round/AgentBreak"

files = {
    f"{base_dir}/.env.example": """PROJECT_NAME="AgentBreak API"
VERSION="0.1.0"
API_V1_STR="/api/v1"
DATABASE_URL="sqlite:///./agentbreak.db"
# OPENAI_API_KEY=""
""",
    f"{base_dir}/.gitignore": """__pycache__/
*.py[cod]
*$py.class
.env
*.db
.pytest_cache/
""",
    f"{base_dir}/README.md": """# AgentBreak

AgentBreak tests an AI agent for security vulnerabilities, records observable execution evidence, presents findings, suggests mitigations, and verifies fixes by replaying attacks and benign regression tests.

## Setup
1. `cd AgentBreak/backend`
2. `pip install -r requirements.txt`
3. `cp ../.env.example .env` (if running from backend, adjust path)
4. `uvicorn app.main:app --reload`

## Testing
1. `cd AgentBreak/backend`
2. `pytest`
""",
    f"{base_dir}/backend/requirements.txt": """fastapi>=0.100.0
uvicorn>=0.23.0
pydantic>=2.0.0
pydantic-settings>=2.0.0
sqlalchemy>=2.0.0
pytest>=7.0.0
httpx>=0.24.0
""",
    f"{base_dir}/backend/app/__init__.py": "",
    f"{base_dir}/backend/app/core/__init__.py": "",
    f"{base_dir}/backend/app/core/config.py": """from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "AgentBreak API"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    DATABASE_URL: str = "sqlite:///./agentbreak.db"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()
""",
    f"{base_dir}/backend/app/database/__init__.py": "",
    f"{base_dir}/backend/app/database/connection.py": """from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from app.core.config import settings

engine = create_engine(
    settings.DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
""",
    f"{base_dir}/backend/app/database/models.py": """from sqlalchemy import Column, Integer, String, JSON, ForeignKey, DateTime
from sqlalchemy.sql import func
from app.database.connection import Base

class AgentModel(Base):
    __tablename__ = "agents"
    id = Column(String, primary_key=True, index=True)
    name = Column(String, index=True)
    description = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class ScanModel(Base):
    __tablename__ = "scans"
    id = Column(String, primary_key=True, index=True)
    agent_id = Column(String, ForeignKey("agents.id"))
    status = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class TraceModel(Base):
    __tablename__ = "traces"
    id = Column(String, primary_key=True, index=True)
    scan_id = Column(String, ForeignKey("scans.id"))
    test_id = Column(String)
    events = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class FindingModel(Base):
    __tablename__ = "findings"
    id = Column(String, primary_key=True, index=True)
    scan_id = Column(String, ForeignKey("scans.id"))
    test_id = Column(String)
    category = Column(String)
    status = Column(String)
    outcome = Column(String)
    expected_behavior = Column(String)
    observed_behavior = Column(String)
    evidence = Column(String)
    trace_id = Column(String, ForeignKey("traces.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
""",
    f"{base_dir}/backend/app/schemas/__init__.py": "",
    f"{base_dir}/backend/app/schemas/agent.py": """from pydantic import BaseModel
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
""",
    f"{base_dir}/backend/app/schemas/scan.py": """from pydantic import BaseModel
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
""",
    f"{base_dir}/backend/app/schemas/finding.py": """from pydantic import BaseModel
from typing import Optional

class FindingBase(BaseModel):
    scan_id: str
    test_id: str
    category: str
    status: str
    outcome: str
    expected_behavior: str
    observed_behavior: str
    evidence: str
    trace_id: Optional[str] = None

class FindingCreate(FindingBase):
    pass

class Finding(FindingBase):
    id: str
    class Config:
        from_attributes = True
""",
    f"{base_dir}/backend/app/schemas/trace.py": """from pydantic import BaseModel
from typing import Any

class TraceBase(BaseModel):
    scan_id: str
    test_id: str
    events: list[Any]

class TraceCreate(TraceBase):
    pass

class Trace(TraceBase):
    id: str
    class Config:
        from_attributes = True
""",
    f"{base_dir}/backend/app/services/__init__.py": "",
    f"{base_dir}/backend/app/services/agent_adapter.py": """from typing import Any, Dict, Protocol
from pydantic import BaseModel

class AgentResponse(BaseModel):
    output: str
    metadata: Dict[str, Any] = {}

class AgentAdapter(Protocol):
    def invoke(self, input_data: str) -> AgentResponse:
        ...

class MockAgentAdapter:
    def invoke(self, input_data: str) -> AgentResponse:
        return AgentResponse(output=f"Mock processed: {input_data}", metadata={"mock": True})
""",
    f"{base_dir}/backend/app/services/scan_orchestrator.py": """from typing import List, Dict, Any
import uuid
from app.services.agent_adapter import AgentAdapter
from app.schemas.scan import ScanCreate, Scan
from app.schemas.finding import FindingCreate

class ScanOrchestrator:
    def __init__(self, agent_adapter: AgentAdapter):
        self.agent_adapter = agent_adapter
    
    def run_scan(self, scan_request: ScanCreate) -> Dict[str, Any]:
        scan_id = str(uuid.uuid4())
        # Mocking scan process
        response = self.agent_adapter.invoke("test prompt")
        
        finding = FindingCreate(
            scan_id=scan_id,
            test_id="test_001",
            category="injection",
            status="completed",
            outcome="failed",
            expected_behavior="Reject prompt",
            observed_behavior=response.output,
            evidence="Output contains processed test prompt",
            trace_id=str(uuid.uuid4())
        )
        
        return {
            "scan_id": scan_id,
            "status": "completed",
            "findings": [finding]
        }
""",
    f"{base_dir}/backend/app/services/fixloop.py": """from typing import Protocol

class FixLoop(Protocol):
    def remediate_and_retest(self, scan_id: str, agent_id: str) -> bool:
        ...
        
class MockFixLoop:
    def remediate_and_retest(self, scan_id: str, agent_id: str) -> bool:
        # Do not claim a fix is verified unless replay tests have actually executed.
        # This is just a stub interface.
        return False
""",
    f"{base_dir}/backend/app/api/__init__.py": "",
    f"{base_dir}/backend/app/api/agents.py": """from fastapi import APIRouter
from app.schemas.agent import Agent, AgentCreate

router = APIRouter()

@router.post("/", response_model=Agent)
def register_agent(agent: AgentCreate):
    return Agent(id="agent_123", name=agent.name, description=agent.description)

@router.get("/{agent_id}", response_model=Agent)
def get_agent(agent_id: str):
    return Agent(id=agent_id, name="Test Agent", description="Stub")
""",
    f"{base_dir}/backend/app/api/scans.py": """from fastapi import APIRouter
from app.schemas.scan import Scan, ScanCreate
from app.services.scan_orchestrator import ScanOrchestrator
from app.services.agent_adapter import MockAgentAdapter
import uuid

router = APIRouter()

@router.post("/", response_model=Scan)
def create_scan(scan: ScanCreate):
    adapter = MockAgentAdapter()
    orchestrator = ScanOrchestrator(agent_adapter=adapter)
    result = orchestrator.run_scan(scan)
    return Scan(id=result["scan_id"], agent_id=scan.agent_id, status=result["status"])

@router.get("/{scan_id}", response_model=Scan)
def get_scan(scan_id: str):
    return Scan(id=scan_id, agent_id="agent_123", status="completed")
""",
    f"{base_dir}/backend/app/api/findings.py": """from fastapi import APIRouter
from typing import List
from app.schemas.finding import Finding

router = APIRouter()

@router.get("/{scan_id}", response_model=List[Finding])
def get_findings_for_scan(scan_id: str):
    return []
""",
    f"{base_dir}/backend/app/api/reports.py": """from fastapi import APIRouter

router = APIRouter()

@router.get("/{scan_id}/export")
def export_report(scan_id: str):
    return {"message": "Export functionality not yet implemented", "scan_id": scan_id}
""",
    f"{base_dir}/backend/app/main.py": """from fastapi import FastAPI
from app.core.config import settings
from app.api import agents, scans, findings, reports
from app.database.connection import engine, Base

# Create tables for initial setup
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

@app.get("/health")
def health_check():
    return {"status": "ok", "project": settings.PROJECT_NAME}

app.include_router(agents.router, prefix=f"{settings.API_V1_STR}/agents", tags=["agents"])
app.include_router(scans.router, prefix=f"{settings.API_V1_STR}/scans", tags=["scans"])
app.include_router(findings.router, prefix=f"{settings.API_V1_STR}/findings", tags=["findings"])
app.include_router(reports.router, prefix=f"{settings.API_V1_STR}/reports", tags=["reports"])
""",
    f"{base_dir}/backend/app/tests/__init__.py": "",
    f"{base_dir}/backend/app/tests/test_api.py": """from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "project": "AgentBreak API"}
""",
    f"{base_dir}/backend/app/tests/test_schemas.py": """from app.schemas.agent import AgentCreate
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
        status="completed",
        outcome="failed",
        expected_behavior="deny",
        observed_behavior="allow",
        evidence="logs"
    )
    assert finding.scan_id == "scan_1"
""",
    f"{base_dir}/backend/app/tests/test_database.py": """from app.database.connection import SessionLocal
from app.database.models import AgentModel

def test_db_connection():
    db = SessionLocal()
    # Simple query to ensure connection and tables work
    result = db.query(AgentModel).all()
    assert isinstance(result, list)
    db.close()
""",
    f"{base_dir}/backend/app/tests/test_agent_adapter.py": """from app.services.agent_adapter import MockAgentAdapter

def test_mock_agent_adapter():
    adapter = MockAgentAdapter()
    response = adapter.invoke("Hello")
    assert response.output == "Mock processed: Hello"
    assert response.metadata == {"mock": True}
""",
    f"{base_dir}/security_engine/__init__.py": "",
    f"{base_dir}/security_engine/attack_cases.py": "# Integration placeholder for attack cases",
    f"{base_dir}/security_engine/test_runner.py": "# Integration placeholder for test runner",
    f"{base_dir}/security_engine/trace_analyzer.py": "# Integration placeholder for trace analyzer",
    f"{base_dir}/security_engine/policy_checker.py": "# Integration placeholder for policy checker",
    f"{base_dir}/security_engine/finding_schema.py": "# Integration placeholder for finding schema",
    f"{base_dir}/security_engine/tests/__init__.py": "",
    f"{base_dir}/security_engine/README.md": "# Security Engine\\n\\nIntegration placeholder for the security engine module.",
    f"{base_dir}/reports/report_generator.py": "# Report generator implementation",
    f"{base_dir}/reports/templates/__init__.py": "",
    f"{base_dir}/docs/architecture.md": "# Architecture\\n\\nAgentBreak architecture documentation.",
    f"{base_dir}/docs/api_contract.md": "# API Contract\\n\\nAgentBreak API contract."
}

for path, content in files.items():
    create_file(path, content)

print("Files created successfully.")
