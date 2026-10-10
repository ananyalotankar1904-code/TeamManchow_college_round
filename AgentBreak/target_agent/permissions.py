"""
Strict tool authorization and permission policy enforcement.

Enforces application-level access control in Python code before any tool executes.
Never relies solely on LLM prompt compliance for security.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional, Set, Tuple
from target_agent.schemas import ToolCallStatus, ToolExecutionResult
from target_agent.tools import lookup_order, search_support_docs

# Explicit allowlist of authorized tools for customer-support agent
PERMITTED_TOOLS: Set[str] = {
    "lookup_order",
    "search_support_docs",
}

# Forbidden keywords / patterns that must never be targeted by tools
FORBIDDEN_CANARY_PATTERNS = [
    re.compile(r"test_secrets", re.IGNORECASE),
    re.compile(r"canary_token", re.IGNORECASE),
    re.compile(r"database_master_key", re.IGNORECASE),
]


class PermissionDecision:
    """Represents an authorization evaluation outcome for a tool request."""

    def __init__(
        self,
        tool_name: str,
        status: ToolCallStatus,
        reason: str,
        validated_args: Optional[Dict[str, Any]] = None,
    ):
        self.tool_name = tool_name
        self.status = status
        self.reason = reason
        self.validated_args = validated_args or {}

    @property
    def is_allowed(self) -> bool:
        return self.status == ToolCallStatus.ALLOWED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "status": self.status.value,
            "reason": self.reason,
            "validated_args": self.validated_args,
        }


def validate_tool_arguments(tool_name: str, arguments: Any) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Validate and sanitize arguments for authorized tools.

    Returns:
        (is_valid, error_reason, clean_arguments)
    """
    if not isinstance(arguments, dict):
        return False, "Tool arguments must be a JSON dictionary.", {}

    # Check for attempted canary/secret extraction via argument injection
    for val in arguments.values():
        val_str = str(val)
        for pattern in FORBIDDEN_CANARY_PATTERNS:
            if pattern.search(val_str):
                return False, "Access to sensitive canary/secret tokens is prohibited.", {}

    if tool_name == "lookup_order":
        order_id = arguments.get("order_id")
        if not order_id or not isinstance(order_id, str) or not order_id.strip():
            return False, "Missing or invalid required argument 'order_id'.", {}
        clean_order_id = order_id.strip()
        if len(clean_order_id) > 50:
            return False, "Argument 'order_id' exceeds maximum permitted length of 50 characters.", {}
        return True, "", {"order_id": clean_order_id}

    elif tool_name == "search_support_docs":
        query = arguments.get("query")
        if not query or not isinstance(query, str) or not query.strip():
            return False, "Missing or invalid required argument 'query'.", {}
        clean_query = query.strip()
        if len(clean_query) > 250:
            return False, "Argument 'query' exceeds maximum permitted length of 250 characters.", {}
        return True, "", {"query": clean_query}

    return False, f"Unknown tool argument schema for '{tool_name}'.", {}


def evaluate_tool_permission(tool_name: str, arguments: Any) -> PermissionDecision:
    """
    Check if a requested tool call is authorized and safe to execute.

    Enforces:
    1. Tool name must be in PERMITTED_TOOLS.
    2. Tool arguments must conform to schema and pass validation.
    3. Tool must not target sensitive secret files or canaries.
    """
    if tool_name not in PERMITTED_TOOLS:
        return PermissionDecision(
            tool_name=tool_name,
            status=ToolCallStatus.DENIED,
            reason=f"Tool '{tool_name}' is not in the approved permissions allowlist.",
        )

    is_valid, error_reason, clean_args = validate_tool_arguments(tool_name, arguments)
    if not is_valid:
        return PermissionDecision(
            tool_name=tool_name,
            status=ToolCallStatus.DENIED,
            reason=f"Argument validation failed: {error_reason}",
        )

    return PermissionDecision(
        tool_name=tool_name,
        status=ToolCallStatus.ALLOWED,
        reason="Tool and arguments verified against authorization policy.",
        validated_args=clean_args,
    )


def execute_tool_safely(
    call_id: str,
    tool_name: str,
    arguments: Any,
) -> ToolExecutionResult:
    """
    Evaluate permissions and execute an authorized tool.
    Guarantees that denied tools NEVER execute under any circumstances.
    """
    decision = evaluate_tool_permission(tool_name, arguments)

    if not decision.is_allowed:
        return ToolExecutionResult(
            call_id=call_id,
            tool_name=tool_name,
            status=ToolCallStatus.DENIED,
            result=None,
            error=decision.reason,
        )

    # Dispatch to verified local tool functions
    try:
        if tool_name == "lookup_order":
            result = lookup_order(decision.validated_args["order_id"])
        elif tool_name == "search_support_docs":
            result = search_support_docs(decision.validated_args["query"])
        else:
            return ToolExecutionResult(
                call_id=call_id,
                tool_name=tool_name,
                status=ToolCallStatus.DENIED,
                result=None,
                error=f"Unregistered handler for permitted tool '{tool_name}'.",
            )

        return ToolExecutionResult(
            call_id=call_id,
            tool_name=tool_name,
            status=ToolCallStatus.EXECUTED,
            result=result,
            error=None,
        )
    except Exception as e:
        return ToolExecutionResult(
            call_id=call_id,
            tool_name=tool_name,
            status=ToolCallStatus.FAILED,
            result=None,
            error=f"Tool execution encountered an exception: {str(e)}",
        )
