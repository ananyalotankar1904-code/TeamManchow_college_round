"""
Structured execution tracing and audit logging for Target AI Agent.

Captures lifecycle events from user input to final response, distinguishing requested
actions from authorized executions, and strictly sanitizing sensitive canary values.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from target_agent.schemas import TraceEvent

# Patterns for sensitive credentials or synthetic canary values that must be redacted
SECRET_PATTERNS = [
    re.compile(r"sk-[a-zA-Z0-9_-]{20,}", re.IGNORECASE),
    re.compile(r"CANARY_[A-Z0-9_{}-]+", re.IGNORECASE),
    re.compile(r"FLAG\{[A-Z0-9_{}-]+\}", re.IGNORECASE),
]


def sanitize_value(value: Any) -> Any:
    """Recursively scrub sensitive tokens and secrets from logged data."""
    if isinstance(value, str):
        cleaned = value
        for pattern in SECRET_PATTERNS:
            cleaned = pattern.sub("[REDACTED_SECRET]", cleaned)
        return cleaned
    elif isinstance(value, dict):
        return {k: sanitize_value(v) for k, v in value.items() if not k.lower().endswith("key") or sanitize_value(v)}
    elif isinstance(value, list):
        return [sanitize_value(item) for item in value]
    return value


class Tracer:
    """Maintains a chronological, sanitized trace of an agent's execution lifecycle."""

    def __init__(self, run_id: str, test_id: str):
        self.run_id = run_id
        self.test_id = test_id
        self._events: List[TraceEvent] = []
        self._seq = 0

    def _next_event_id(self) -> str:
        self._seq += 1
        return f"evt-{self.run_id[:8]}-{self._seq:03d}"

    def record(self, event_type: str, details: Optional[Dict[str, Any]] = None) -> TraceEvent:
        """Add a sanitized event to the trace."""
        sanitized_details = sanitize_value(details or {})
        event = TraceEvent(
            event_id=self._next_event_id(),
            run_id=self.run_id,
            test_id=self.test_id,
            event_type=event_type,
            timestamp=datetime.now(timezone.utc).isoformat(),
            details=sanitized_details,
        )
        self._events.append(event)
        return event

    def record_run_started(self, initial_details: Optional[Dict[str, Any]] = None) -> TraceEvent:
        return self.record("run_started", initial_details or {})

    def record_user_input_received(self, user_input: str) -> TraceEvent:
        return self.record("user_input_received", {"user_input": user_input})

    def record_model_request(self, model: str, iteration: int, message_count: int, mock: bool = False) -> TraceEvent:
        return self.record(
            "model_request",
            {
                "model": model,
                "iteration": iteration,
                "message_count": message_count,
                "mock_mode": mock,
            },
        )

    def record_tool_requested(self, call_id: str, tool_name: str, arguments: Dict[str, Any]) -> TraceEvent:
        return self.record(
            "tool_requested",
            {
                "call_id": call_id,
                "tool_name": tool_name,
                "arguments": arguments,
                "action_status": "requested_not_yet_authorized",
            },
        )

    def record_permission_allowed(self, call_id: str, tool_name: str, reason: str) -> TraceEvent:
        return self.record(
            "permission_allowed",
            {
                "call_id": call_id,
                "tool_name": tool_name,
                "authorization": "allowed",
                "reason": reason,
            },
        )

    def record_permission_denied(self, call_id: str, tool_name: str, reason: str) -> TraceEvent:
        return self.record(
            "permission_denied",
            {
                "call_id": call_id,
                "tool_name": tool_name,
                "authorization": "denied",
                "reason": reason,
                "execution_prevented": True,
            },
        )

    def record_tool_execution_started(self, call_id: str, tool_name: str) -> TraceEvent:
        return self.record(
            "tool_execution_started",
            {
                "call_id": call_id,
                "tool_name": tool_name,
            },
        )

    def record_tool_execution_completed(
        self, call_id: str, tool_name: str, summary: Optional[Dict[str, Any]] = None
    ) -> TraceEvent:
        return self.record(
            "tool_execution_completed",
            {
                "call_id": call_id,
                "tool_name": tool_name,
                "execution_status": "success",
                "summary": summary or {},
            },
        )

    def record_tool_execution_failed(self, call_id: str, tool_name: str, error: str) -> TraceEvent:
        return self.record(
            "tool_execution_failed",
            {
                "call_id": call_id,
                "tool_name": tool_name,
                "error": error,
            },
        )

    def record_final_response_generated(self, response_length: int, preview: str) -> TraceEvent:
        return self.record(
            "final_response_generated",
            {
                "response_length": response_length,
                "preview": preview[:160] + "..." if len(preview) > 160 else preview,
            },
        )

    def record_run_completed(self, status: str) -> TraceEvent:
        return self.record("run_completed", {"final_status": status})

    def record_run_failed(self, error: str) -> TraceEvent:
        return self.record("run_failed", {"error": error})

    @property
    def events(self) -> List[TraceEvent]:
        return list(self._events)

    def to_dict_list(self) -> List[Dict[str, Any]]:
        return [evt.model_dump(mode="json") for evt in self._events]
