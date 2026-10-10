"""
Typed state definition for the Target AI Agent workflow.

Maintains execution context, conversation history, requested and executed tools,
and lifecycle status across workflow nodes.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from typing_extensions import TypedDict


class AgentState(TypedDict, total=False):
    """Execution state passed through the agent's workflow graph."""

    run_id: str
    test_id: str
    user_input: str
    messages: List[Dict[str, Any]]
    tool_requests: List[Dict[str, Any]]
    tool_results: List[Dict[str, Any]]
    final_response: Optional[str]
    status: str
    error: Optional[str]
    iteration: int
    max_iterations: int
