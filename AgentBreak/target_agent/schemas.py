"""
Pydantic schemas and data validation models for Target AI Agent.

Defines validated, JSON-serializable data structures for input, output,
tool requests, execution traces, and permission records.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AgentRunStatus(str, Enum):
    """
    Standard status values for an agent run execution.

    - COMPLETED: Agent executed normally and delivered an answer.
    - BLOCKED: A critical security policy violation was detected and blocked.
    - FAILED: An unrecoverable runtime, configuration, or model error occurred.
    """
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"


class ToolCallStatus(str, Enum):
    """Execution status for a requested tool call."""
    ALLOWED = "allowed"
    DENIED = "denied"
    EXECUTED = "executed"
    FAILED = "failed"


class AgentInput(BaseModel):
    """Input payload accepted by the target agent."""
    user_input: str = Field(..., min_length=1, description="Customer inquiry or prompt")
    test_id: str = Field(default="default-test", description="Identifier provided by security testing engine")


class ToolRequest(BaseModel):
    """Represents a tool requested by the language model."""
    call_id: str = Field(..., description="Unique ID for this tool invocation request")
    tool_name: str = Field(..., description="Name of the requested tool")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Parsed arguments provided by the model")


class ToolExecutionResult(BaseModel):
    """Result of an attempted tool execution."""
    call_id: str = Field(..., description="Corresponds to ToolRequest call_id")
    tool_name: str = Field(..., description="Name of the tool")
    status: ToolCallStatus = Field(..., description="Outcome of the tool execution attempt")
    result: Optional[Dict[str, Any]] = Field(default=None, description="Output payload if executed safely")
    error: Optional[str] = Field(default=None, description="Error or policy denial message if not executed")


class TraceEvent(BaseModel):
    """A structured, sanitized event record within an agent run trace."""
    event_id: str = Field(..., description="Unique event identifier")
    run_id: str = Field(..., description="Agent run execution ID")
    test_id: str = Field(..., description="Associated security test identifier")
    event_type: str = Field(..., description="Lifecycle event name (e.g. tool_requested, permission_denied)")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 UTC timestamp of event recording"
    )
    details: Dict[str, Any] = Field(default_factory=dict, description="Sanitized event metadata")


class AgentResult(BaseModel):
    """
    Standard machine-readable result payload returned to callers.
    Designed for consumption by Member 2's AgentBreak security engine.
    """
    run_id: str = Field(..., description="Unique execution run identifier")
    test_id: str = Field(..., description="Test identifier supplied in request")
    status: AgentRunStatus = Field(..., description="Overall execution outcome: completed, blocked, or failed")
    response: Optional[str] = Field(default=None, description="Final natural-language response to the user")
    trace: List[TraceEvent] = Field(default_factory=list, description="Chronological audit trace of lifecycle events")
    error: Optional[str] = Field(default=None, description="High-level error description if status is failed")

    def to_dict(self) -> Dict[str, Any]:
        """Convert the AgentResult into a plain, JSON-serializable Python dictionary."""
        return self.model_dump(mode="json")
