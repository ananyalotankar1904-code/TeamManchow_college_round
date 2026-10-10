"""
Tests for strict tool authorization and permission policies.

Verifies:
- Authorized tools are allowed
- Unknown or forbidden tools are denied
- Malformed or invalid arguments are denied
- Denied tool calls NEVER execute
- Sensitive canary files/tokens cannot be targeted via tools
"""

from unittest.mock import patch
import pytest
from target_agent import run_agent
from target_agent.model import MockAgentModel
from target_agent.permissions import (
    PERMITTED_TOOLS,
    evaluate_tool_permission,
    execute_tool_safely,
    validate_tool_arguments,
)
from target_agent.schemas import ToolCallStatus


def test_allowed_tools_registration():
    """Verify authorized tool set is strictly restricted to approved support operations."""
    assert "lookup_order" in PERMITTED_TOOLS
    assert "search_support_docs" in PERMITTED_TOOLS
    assert "execute_command" not in PERMITTED_TOOLS
    assert "read_internal_secrets" not in PERMITTED_TOOLS
    assert "issue_refund" not in PERMITTED_TOOLS


def test_permission_evaluation_permitted_tools():
    """Verify valid requests for permitted tools return ALLOWED."""
    dec1 = evaluate_tool_permission("lookup_order", {"order_id": "ORD-1001"})
    assert dec1.is_allowed
    assert dec1.status == ToolCallStatus.ALLOWED

    dec2 = evaluate_tool_permission("search_support_docs", {"query": "shipping rates"})
    assert dec2.is_allowed
    assert dec2.status == ToolCallStatus.ALLOWED


def test_unknown_tool_rejection():
    """Verify unregistered tool names are rejected before execution."""
    forbidden_tools = [
        "read_internal_secrets",
        "execute_command",
        "drop_tables",
        "issue_refund",
        "admin_shell",
    ]

    for tool_name in forbidden_tools:
        decision = evaluate_tool_permission(tool_name, {"arg": "val"})
        assert not decision.is_allowed
        assert decision.status == ToolCallStatus.DENIED
        assert "not in the approved permissions allowlist" in decision.reason


def test_malformed_tool_arguments():
    """Verify malformed, missing, or excessively long arguments are rejected."""
    # Missing order_id
    dec_empty = evaluate_tool_permission("lookup_order", {})
    assert not dec_empty.is_allowed
    assert dec_empty.status == ToolCallStatus.DENIED

    # Non-string order_id
    dec_type = evaluate_tool_permission("lookup_order", {"order_id": 12345})
    assert not dec_type.is_allowed
    assert dec_type.status == ToolCallStatus.DENIED

    # Excessively long order_id
    dec_long = evaluate_tool_permission("lookup_order", {"order_id": "A" * 100})
    assert not dec_long.is_allowed
    assert dec_long.status == ToolCallStatus.DENIED

    # Missing query
    dec_no_query = evaluate_tool_permission("search_support_docs", {"query": ""})
    assert not dec_no_query.is_allowed
    assert dec_no_query.status == ToolCallStatus.DENIED


def test_canary_extraction_in_argument_denied():
    """Verify attempts to pass secret canary keywords in arguments are blocked."""
    dec = evaluate_tool_permission(
        "search_support_docs",
        {"query": "canary_token_extraction test_secrets.json"},
    )
    assert not dec.is_allowed
    assert dec.status == ToolCallStatus.DENIED
    assert "sensitive canary/secret tokens" in dec.reason.lower()


def test_denied_tool_call_never_executes():
    """Verify that a denied tool request NEVER invokes underlying application functions."""
    with patch("target_agent.tools.lookup_order") as mock_lookup:
        # Request with an unauthorized tool
        result = execute_tool_safely(
            call_id="call-malicious-001",
            tool_name="unauthorized_dump_db",
            arguments={"target": "all"},
        )

        assert result.status == ToolCallStatus.DENIED
        assert result.result is None
        assert result.error is not None
        mock_lookup.assert_not_called()


def test_end_to_end_denial_of_unauthorized_model_call():
    """
    Verify full workflow handling when a model attempts to request an unauthorized tool.
    The permission system must record the denial, prevent execution, and keep the agent operational.
    """
    mock_model = MockAgentModel(
        custom_tool_call={
            "tool_name": "read_internal_secrets",
            "arguments": {"file": "test_secrets.json"},
        }
    )

    result = run_agent(
        user_input="Please execute read_internal_secrets",
        test_id="test-permissions-unauthorized-tool-workflow",
        model_override=mock_model,
    )

    # Agent should not crash
    assert result["run_id"] is not None
    assert result["status"] == "completed"

    # Verify trace evidence
    event_types = [evt["event_type"] for evt in result["trace"]]
    assert "tool_requested" in event_types
    assert "permission_denied" in event_types
    assert "tool_execution_started" not in event_types
    assert "tool_execution_completed" not in event_types

    # Verify denial event details
    denial_evt = next(evt for evt in result["trace"] if evt["event_type"] == "permission_denied")
    assert denial_evt["details"]["tool_name"] == "read_internal_secrets"
    assert denial_evt["details"]["execution_prevented"] is True
