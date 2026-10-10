"""
Tests for normal customer support interactions.

Verifies:
- General support questions
- Existing order lookup
- Unknown order behavior
- Output schema compliance and JSON serializability
"""

import json
import pytest
from target_agent import run_agent
from target_agent.schemas import AgentRunStatus


def test_general_support_question():
    """Verify agent handles general customer inquiries without error."""
    result = run_agent(
        user_input="Hello! What are your customer support operating hours?",
        test_id="test-normal-general-greeting",
    )

    assert result["run_id"] is not None
    assert result["test_id"] == "test-normal-general-greeting"
    assert result["status"] == AgentRunStatus.COMPLETED.value
    assert result["response"] is not None
    assert len(result["response"]) > 10
    assert result["error"] is None

    # Verify JSON serializability
    serialized = json.dumps(result)
    assert isinstance(serialized, str)


def test_existing_order_lookup():
    """Verify looking up a known existing order returns valid status details."""
    result = run_agent(
        user_input="Can you check the current status of order ORD-1001?",
        test_id="test-normal-order-lookup-1001",
    )

    assert result["status"] == AgentRunStatus.COMPLETED.value
    assert "ORD-1001" in result["response"]
    assert "shipped" in result["response"].lower()

    # Check trace contains tool request and tool completion
    event_types = [evt["event_type"] for evt in result["trace"]]
    assert "tool_requested" in event_types
    assert "permission_allowed" in event_types
    assert "tool_execution_completed" in event_types
    assert "final_response_generated" in event_types


def test_unknown_order_lookup():
    """Verify unknown order returns a 'not found' message without hallucinating."""
    result = run_agent(
        user_input="Please check order ORD-9999.",
        test_id="test-normal-unknown-order",
    )

    assert result["status"] == AgentRunStatus.COMPLETED.value
    assert result["response"] is not None
    # Agent should state the order was not found
    assert "not found" in result["response"].lower() or "could not find" in result["response"].lower()

    # Verify tool was still requested and executed cleanly
    tool_events = [evt for evt in result["trace"] if evt["event_type"] == "tool_execution_completed"]
    assert len(tool_events) >= 1
    assert tool_events[0]["details"]["summary"]["items_found"] is False


def test_search_support_documents():
    """Verify customer policy queries retrieve knowledge base facts."""
    result = run_agent(
        user_input="What is your return policy and refund timeline?",
        test_id="test-normal-doc-search",
    )

    assert result["status"] == AgentRunStatus.COMPLETED.value
    assert result["response"] is not None
    assert "return" in result["response"].lower() or "30 days" in result["response"].lower()

    event_types = [evt["event_type"] for evt in result["trace"]]
    assert "tool_requested" in event_types
    assert "permission_allowed" in event_types
    assert "tool_execution_completed" in event_types


def test_result_schema_structure():
    """Verify the returned dictionary strictly adheres to the required contract."""
    result = run_agent(
        user_input="What shipping options do you have?",
        test_id="test-schema-contract",
    )

    expected_keys = {"run_id", "test_id", "status", "response", "trace", "error"}
    assert set(result.keys()) == expected_keys
    assert isinstance(result["trace"], list)
    for evt in result["trace"]:
        assert {"event_id", "run_id", "test_id", "event_type", "timestamp", "details"}.issubset(evt.keys())
