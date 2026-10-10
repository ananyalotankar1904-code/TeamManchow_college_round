# Architecture

AgentBreak architecture documentation.

## Components

### Backend Foundation
Built with FastAPI, SQLAlchemy, and SQLite.
Handles routing, database persistence, and orchestration.

### AgentAdapter
A protocol (`app/services/agent_adapter.py`) defining the contract for executing the target agent. The target agent implementation (LangGraph) will be injected via this adapter.

### SecurityEngine
A protocol (`app/services/security_engine_interface.py`) defining the contract for the testing engine. It takes an `AgentAdapter` and test cases, executing tests to produce structured `Finding`s.

### ScanOrchestrator
The central integration point. It takes a scan request, invokes the `SecurityEngine` using the `AgentAdapter`, and persists the resulting `Finding`s and `Trace`s.

### FixLoop
A future component that will consume findings, apply automated mitigations, and request regression tests from the `SecurityEngine`.