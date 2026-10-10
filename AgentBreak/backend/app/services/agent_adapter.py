from typing import Any, Dict, Protocol, List
from pydantic import BaseModel

class AgentRequest(BaseModel):
    session_id: str
    input_text: str
    metadata: Dict[str, Any] = {}

class AgentResponse(BaseModel):
    output: str
    metadata: Dict[str, Any] = {}

class AgentAdapter(Protocol):
    def invoke(self, request: AgentRequest) -> AgentResponse:
        """
        Invoke the target agent with the given request.
        This provides a stable contract independent of LangGraph internals.
        """
        ...

class MockAgentAdapter:
    def invoke(self, request: AgentRequest) -> AgentResponse:
        return AgentResponse(
            output=f"Mock processed: {request.input_text} (session: {request.session_id})",
            metadata={"mock": True}
        )

class TargetAgentAdapter:
    """
    Concrete adapter that integrates with the target AI agent.
    """
    def invoke(self, request: AgentRequest) -> AgentResponse:
        import sys
        import os
        # Add the AgentBreak root to sys.path so target_agent can be imported
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../"))
        if root_dir not in sys.path:
            sys.path.insert(0, root_dir)
            
        try:
            from target_agent import run_agent, MockAgentModel
        except ImportError as e:
            return AgentResponse(
                output=f"ImportError: target_agent package not found: {e}",
                metadata={"status": "failed", "error": "ImportError"}
            )
            
        test_id = request.metadata.get("test_id", request.session_id)
        use_mock = request.metadata.get("use_mock", False)
        
        model_override = MockAgentModel() if use_mock else None
        
        try:
            result_dict = run_agent(
                user_input=request.input_text,
                test_id=test_id,
                model_override=model_override
            )
            
            output_text = result_dict.get("response")
            
            if not output_text and result_dict.get("status") == "failed":
                output_text = f"Agent failed: {result_dict.get('error', 'Unknown error')}"
                
            return AgentResponse(
                output=output_text or "",
                metadata={
                    "status": result_dict.get("status"),
                    "trace": result_dict.get("trace", []),
                    "run_id": result_dict.get("run_id"),
                    "error": result_dict.get("error")
                }
            )
        except Exception as e:
            return AgentResponse(
                output=f"Agent exception: {str(e)}",
                metadata={"status": "failed", "error": str(e), "trace": []}
            )
