# API Contract

AgentBreak API contract.

## Base URL
`/api/v1`

## Endpoints

### 1. Agents
`POST /agents`
Register an agent for scanning.
**Request**: `{"name": "My Agent", "description": "LangGraph target"}`
**Response**: `{"id": "agent_123", "name": "My Agent", "description": "..."}`

`GET /agents/{agent_id}`
Retrieve an agent.

### 2. Scans
`POST /scans`
Initiate a security scan.
**Request**: `{"agent_id": "agent_123", "test_cases": ["injection_1"]}`
**Response**: `{"id": "scan_abc", "agent_id": "agent_123", "status": "completed"}`

`GET /scans/{scan_id}`
Retrieve scan status.

### 3. Findings
`GET /findings/{scan_id}`
Retrieve findings for a specific scan.
**Response Model `Finding`**:
- `id`: str
- `scan_id`: str
- `test_id`: str
- `category`: str
- `execution_status`: str
- `outcome`: "attempted" | "blocked" | "executed" | "failed" | "inconclusive"
- `expected_behavior`: str
- `observed_behavior`: str
- `evidence`: str
- `trace_id`: Optional[str]

### 4. Traces
`GET /traces/{trace_id}`
Retrieve the trace of an executed test.
**Response Model `Trace`**:
- `id`: str
- `scan_id`: str
- `test_id`: str
- `events`: List[Any]

### 5. Reports
`GET /reports/{scan_id}/export`
Export the scan results as a report.

## Integration Instructions
- **Wildcard Developer (Target Agent)**: Implement the `AgentAdapter` protocol (see `backend/app/services/agent_adapter.py`). It expects a single `invoke(request: AgentRequest) -> AgentResponse` method.
- **Member 2 (Security Engine)**: Implement the `SecurityEngine` protocol (see `backend/app/services/security_engine_interface.py`). It expects a `run_tests(test_cases: List[str], agent: AgentAdapter, scan_id: str) -> List[FindingCreate]` method.