import pytest
from typing import Optional, Dict, Any, List

from security_engine.finding_schema import Outcome, EventStatus, EventType, TraceEvent
from security_engine.attack_cases import get_case, FixtureSetup
from security_engine.test_runner import AgentTestRunner, TargetAgentResponse, TargetAgentAdapter

class MissingTraceAdapter:
    def execute(self, user_input: str, fixture_setup: Optional[FixtureSetup] = None, context: Optional[Dict[str, Any]] = None) -> TargetAgentResponse:
        # Trace is completely empty
        return TargetAgentResponse(
            response_text="I processed your request.",
            trace_events=[],
            evidence_complete=True # Even if adapter says true, runner should override
        )

class MissingResponseAdapter:
    def execute(self, user_input: str, fixture_setup: Optional[FixtureSetup] = None, context: Optional[Dict[str, Any]] = None) -> TargetAgentResponse:
        # Response is completely empty
        return TargetAgentResponse(
            response_text="",
            trace_events=[
                TraceEvent(event_type=EventType.USER_INPUT, content=user_input, status=EventStatus.EXECUTED)
            ],
            evidence_complete=True
        )

class MissingUserInputEventAdapter:
    def execute(self, user_input: str, fixture_setup: Optional[FixtureSetup] = None, context: Optional[Dict[str, Any]] = None) -> TargetAgentResponse:
        # No USER_INPUT event
        return TargetAgentResponse(
            response_text="I processed your request.",
            trace_events=[
                TraceEvent(event_type=EventType.TOOL_CALL, tool_name="allowed_tool", status=EventStatus.EXECUTED)
            ],
            evidence_complete=True
        )

class CompleteSafeTraceAdapter:
    def execute(self, user_input: str, fixture_setup: Optional[FixtureSetup] = None, context: Optional[Dict[str, Any]] = None) -> TargetAgentResponse:
        return TargetAgentResponse(
            response_text="I will not do that.",
            trace_events=[
                TraceEvent(event_type=EventType.USER_INPUT, content=user_input, status=EventStatus.EXECUTED)
            ],
            evidence_complete=True
        )

class CompleteVulnerableTraceAdapter:
    def execute(self, user_input: str, fixture_setup: Optional[FixtureSetup] = None, context: Optional[Dict[str, Any]] = None) -> TargetAgentResponse:
        return TargetAgentResponse(
            response_text="I did it.",
            trace_events=[
                TraceEvent(event_type=EventType.USER_INPUT, content=user_input, status=EventStatus.EXECUTED),
                TraceEvent(event_type=EventType.TOOL_CALL, tool_name="admin_refund", status=EventStatus.EXECUTED)
            ],
            evidence_complete=True
        )

class ExecutionErrorAdapter:
    def execute(self, user_input: str, fixture_setup: Optional[FixtureSetup] = None, context: Optional[Dict[str, Any]] = None) -> TargetAgentResponse:
        return TargetAgentResponse(
            response_text="",
            trace_events=[],
            execution_error="API failure",
            evidence_complete=False
        )

def test_missing_trace_evidence():
    case = get_case("DI-001")
    runner = AgentTestRunner(adapter=MissingTraceAdapter())
    result = runner.run_case(case)
    
    assert result.evidence_complete is False
    assert result.outcome == Outcome.INCONCLUSIVE

def test_missing_user_input_evidence():
    case = get_case("DI-001")
    runner = AgentTestRunner(adapter=MissingUserInputEventAdapter())
    result = runner.run_case(case)
    
    assert result.evidence_complete is False
    assert result.outcome == Outcome.INCONCLUSIVE

def test_missing_response_evidence():
    case = get_case("DI-001")
    runner = AgentTestRunner(adapter=MissingResponseAdapter())
    result = runner.run_case(case)
    
    assert result.evidence_complete is False
    assert result.outcome == Outcome.INCONCLUSIVE

def test_complete_safe_trace():
    case = get_case("DI-001")
    runner = AgentTestRunner(adapter=CompleteSafeTraceAdapter())
    result = runner.run_case(case)
    
    assert result.evidence_complete is True
    assert result.outcome == Outcome.PASS

def test_complete_vulnerable_trace():
    case = get_case("DI-001")
    runner = AgentTestRunner(adapter=CompleteVulnerableTraceAdapter())
    result = runner.run_case(case)
    
    assert result.evidence_complete is True
    assert result.outcome == Outcome.VULNERABILITY_CONFIRMED

def test_execution_error():
    case = get_case("DI-001")
    runner = AgentTestRunner(adapter=ExecutionErrorAdapter())
    result = runner.run_case(case)
    
    assert result.evidence_complete is False
    assert result.outcome == Outcome.INCONCLUSIVE
