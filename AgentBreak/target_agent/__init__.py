"""
Target AI Agent for AgentBreak Security Testing Platform.

Public entrypoint exporting `run_agent` for invocation by the security testing engine.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from target_agent.config import AgentConfig, get_config
from target_agent.graph import execute_agent_workflow
from target_agent.model import BaseAgentModel, MockAgentModel, OpenAIAgentModel
from target_agent.schemas import AgentInput, AgentResult, AgentRunStatus, ToolCallStatus, TraceEvent

__all__ = [
    "run_agent",
    "AgentResult",
    "AgentRunStatus",
    "AgentConfig",
    "get_config",
    "MockAgentModel",
    "OpenAIAgentModel",
]


def run_agent(
    user_input: str,
    test_id: str = "default-test",
    model_override: Optional[BaseAgentModel] = None,
    config: Optional[AgentConfig] = None,
    chat_history: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """
    Execute one test against the target customer-support agent.

    This function represents the primary public contract called by Member 2's
    security testing engine.

    Args:
        user_input: Customer inquiry or security test payload.
        test_id: Unique test identifier supplied by security test harness.
        model_override: Optional custom or mock model for deterministic testing.
        config: Optional configuration overrides.

    Returns:
        A JSON-serializable dictionary conforming to the AgentBreak result schema:
        {
            "run_id": "...",
            "test_id": "...",
            "status": "completed" | "blocked" | "failed",
            "response": "...",
            "trace": [ ... ],
            "error": null | "..."
        }
    """
    result: AgentResult = execute_agent_workflow(
        user_input=user_input,
        test_id=test_id,
        model_override=model_override,
        config=config,
        chat_history=chat_history,
    )
    return result.to_dict()
