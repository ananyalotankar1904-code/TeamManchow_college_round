import os
from fastapi import HTTPException
from app.services.agent_adapter import AgentAdapter, MockAgentAdapter, TargetAgentAdapter
from app.services.security_engine_interface import SecurityEngine, MockSecurityEngine

def get_agent_adapter() -> AgentAdapter:
    adapter_type = os.getenv("AGENT_ADAPTER", "target")
    if adapter_type == "mock":
        return MockAgentAdapter()
    return TargetAgentAdapter()

def get_security_engine() -> SecurityEngine:
    engine_type = os.getenv("SECURITY_ENGINE", "mock")
    if engine_type == "mock":
        return MockSecurityEngine()
    
    from app.services.security_engine_interface import RealSecurityEngine
    return RealSecurityEngine()
