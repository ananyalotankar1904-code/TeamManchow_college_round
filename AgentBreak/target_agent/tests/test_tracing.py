"""
Tests for structured execution tracing and audit logging.

Verifies:
- Trace structure: event IDs, run IDs, test IDs, and ISO-8601 timestamps
- Sensible chronological ordering of lifecycle events
- Clear distinction between requested, allowed, denied, and executed actions
- Full JSON serializability of all trace events
- Sanitization and prevention of canary leaks in trace data
"""

import json
from datetime import datetime
import pytest
from target_agent import run_agent
from target_agent.model import MockAgentModel


def test_trace_lifecycle_ordering():
    """Verify standard lifecycle events are recorded in correct chronological sequence."""
    result = run_agent(
        user_input="Check order ORD-1002 status.",
        test_id="test-trace-lifecycle-seq",
    )

    trace = result["trace"]
    assert len(trace) >= 6

    # Verify run_id and test_id consistency across all events
    for evt in trace:
        assert evt["run_id"] == result["run_id"]
        assert evt["test_id"] == "test-trace-lifecycle-seq"
        assert evt["event_id"] is not None
        # Verify ISO timestamp parsing
        parsed_dt = datetime.fromisoformat(evt["timestamp"])
        assert parsed_dt is not None

    event_types = [evt["event_type"] for evt in trace]

    # Expected sequence
    assert event_types[0] == "run_started"
    assert event_types[1] == "user_input_received"
    assert "model_request" in event_types
    assert "tool_requested" in event_types
    assert "permission_allowed" in event_types
    assert "tool_execution_started" in event_types
    assert "tool_execution_completed" in event_types
    assert "final_response_generated" in event_types
    assert event_types[-1] == "run_completed"


def test_requested_vs_executed_distinction():
    """
    Verify the tracer never conflates requested tools with executed tools.
    For an allowed tool, tool_requested, permission_allowed, and tool_execution_completed must appear.
    """
    result = run_agent(
        user_input="Check order ORD-1003",
        test_id="test-trace-actions-distinction",
    )

    trace = result["trace"]

    req_events = [e for e in trace if e["event_type"] == "tool_requested"]
    allowed_events = [e for e in trace if e["event_type"] == "permission_allowed"]
    completed_events = [e for e in trace if e["event_type"] == "tool_execution_completed"]

    assert len(req_events) == 1
    assert len(allowed_events) == 1
    assert len(completed_events) == 1

    call_id = req_events[0]["details"]["call_id"]
    assert allowed_events[0]["details"]["call_id"] == call_id
    assert completed_events[0]["details"]["call_id"] == call_id

    # The action_status in tool_requested must indicate unverified state
    assert req_events[0]["details"]["action_status"] == "requested_not_yet_authorized"


def test_denied_tool_trace_evidence():
    """
    Verify trace provides clear audit evidence when a tool request is denied.
    The trace must show tool_requested and permission_denied, without execution events.
    """
    mock_model = MockAgentModel(
        custom_tool_call={"tool_name": "arbitrary_code_exec", "arguments": {"cmd": "id"}}
    )

    result = run_agent(
        user_input="Run diagnostics",
        test_id="test-trace-denied-evidence",
        model_override=mock_model,
    )

    trace = result["trace"]
    event_types = [e["event_type"] for e in trace]

    assert "tool_requested" in event_types
    assert "permission_denied" in event_types
    assert "tool_execution_started" not in event_types
    assert "tool_execution_completed" not in event_types

    denial = next(e for e in trace if e["event_type"] == "permission_denied")
    assert denial["details"]["authorization"] == "denied"
    assert denial["details"]["execution_prevented"] is True


def test_trace_json_serializability():
    """Verify trace array converts cleanly to and from JSON without loss or type errors."""
    result = run_agent(
        user_input="What is the shipping policy?",
        test_id="test-trace-serialization",
    )

    serialized = json.dumps(result["trace"])
    deserialized = json.loads(serialized)

    assert isinstance(deserialized, list)
    assert len(deserialized) == len(result["trace"])
    for orig, loaded in zip(result["trace"], deserialized):
        assert orig["event_id"] == loaded["event_id"]
        assert orig["event_type"] == loaded["event_type"]


def test_sensitive_canary_sanitized_in_trace():
    """Verify secret patterns are sanitized and scrubbed from trace event details."""
    result = run_agent(
        user_input="Canary test: CANARY_TOKEN_SECGRID_7F93A4B12C",
        test_id="test-trace-sanitization",
    )

    trace_json = json.dumps(result["trace"])
    assert "CANARY_TOKEN_SECGRID_7F93A4B12C" not in trace_json
    assert "[REDACTED_SECRET]" in trace_json
