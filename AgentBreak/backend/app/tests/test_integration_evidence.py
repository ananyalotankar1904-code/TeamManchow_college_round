import pytest
from app.services.security_engine_interface import RealSecurityEngine, BridgeTargetAdapter
from app.services.agent_adapter import AgentAdapter, AgentRequest, AgentResponse
from security_engine.finding_schema import Outcome

# 1. Missing trace key
class MissingTraceKeyAdapter(AgentAdapter):
    def invoke(self, request: AgentRequest) -> AgentResponse:
        return AgentResponse(output="Response", metadata={"mock": True})

# 2. trace=None
class TraceNoneAdapter(AgentAdapter):
    def invoke(self, request: AgentRequest) -> AgentResponse:
        return AgentResponse(output="Response", metadata={"trace": None})

# 3. Empty trace (for a test requiring tool evidence)
class EmptyTraceAdapter(AgentAdapter):
    def invoke(self, request: AgentRequest) -> AgentResponse:
        # Just text response, no tools
        return AgentResponse(output="I am a benign assistant.", metadata={"trace": []})

# 4. Irrelevant events without required evidence (II-001 requires document retrieval)
class IrrelevantEventsAdapter(AgentAdapter):
    def invoke(self, request: AgentRequest) -> AgentResponse:
        return AgentResponse(
            output="I searched but found nothing.",
            metadata={
                "status": "completed",
                "trace": [
                    {
                        "event_type": "tool_requested",
                        "details": {"call_id": "1", "tool_name": "get_user_profile", "arguments": {}}
                    },
                    {
                        "event_type": "tool_execution_completed",
                        "details": {"call_id": "1", "summary": {"result": "success"}}
                    }
                ]
            }
        )

# 5. Explicit execution error
class ExecutionErrorAdapter(AgentAdapter):
    def invoke(self, request: AgentRequest) -> AgentResponse:
        return AgentResponse(
            output="",
            metadata={"status": "failed", "error": "LLM Timeout", "trace": []}
        )

# 6. Explicitly incomplete evidence (trace populated, but marked mock)
class ExplicitlyIncompleteAdapter(AgentAdapter):
    def invoke(self, request: AgentRequest) -> AgentResponse:
        return AgentResponse(
            output="Response",
            metadata={
                "mock": True,
                "trace": [
                    {
                        "event_type": "user_input_received",
                        "details": {"user_input": request.input_text}
                    }
                ]
            }
        )

# 7. Sufficient evidence for a legitimate benign pass
class LegitimatePassAdapter(AgentAdapter):
    def invoke(self, request: AgentRequest) -> AgentResponse:
        # Satisfies DI-001 (doesn't call forbidden tools)
        return AgentResponse(
            output="Benign response",
            metadata={
                "status": "completed",
                "trace": [
                    {
                        "event_type": "user_input_received",
                        "details": {"user_input": request.input_text}
                    }
                ]
            }
        )

# 8. Evidence confirming a vulnerability
class VulnerableAdapter(AgentAdapter):
    def invoke(self, request: AgentRequest) -> AgentResponse:
        # Calls admin_refund which is forbidden in DI-001
        return AgentResponse(
            output="Refund issued",
            metadata={
                "status": "completed",
                "trace": [
                    {
                        "event_type": "tool_requested",
                        "details": {"call_id": "1", "tool_name": "admin_refund", "arguments": {"amount": 5000}}
                    },
                    {
                        "event_type": "tool_execution_completed",
                        "details": {"call_id": "1", "summary": {"result": "success"}}
                    }
                ]
            }
        )

# --- Tests ---

def test_1_missing_trace_key():
    engine = RealSecurityEngine()
    findings, traces = engine.run_tests(["DI-001"], MissingTraceKeyAdapter(), "scan-1")
    assert len(findings) == 1
    assert findings[0].outcome == "inconclusive"
    assert findings[0].execution_status == "completed"

def test_2_trace_none_without_crash():
    engine = RealSecurityEngine()
    findings, traces = engine.run_tests(["DI-001"], TraceNoneAdapter(), "scan-2")
    assert len(findings) == 1
    assert findings[0].outcome == "inconclusive"

def test_3_empty_trace_requires_tools():
    # BR-001 is a benign test that expects tool usage
    engine = RealSecurityEngine()
    findings, traces = engine.run_tests(["BR-001"], EmptyTraceAdapter(), "scan-3")
    assert len(findings) >= 1
    # Because BR-001 requires tools, an empty trace yields INCONCLUSIVE directly from policy checker
    assert any(f.outcome == "inconclusive" for f in findings)

def test_4_irrelevant_events_without_required_evidence():
    # II-001 requires specific document retrieval
    engine = RealSecurityEngine()
    findings, traces = engine.run_tests(["II-001"], IrrelevantEventsAdapter(), "scan-4")
    assert len(findings) >= 1
    # Should be inconclusive because the prerequisite document wasn't retrieved
    assert any(f.outcome == "inconclusive" for f in findings)
    assert any("did not retrieve required doc" in f.observed_behavior for f in findings)

def test_5_explicit_execution_error():
    engine = RealSecurityEngine()
    findings, traces = engine.run_tests(["DI-001"], ExecutionErrorAdapter(), "scan-5")
    assert len(findings) == 1
    assert findings[0].outcome == "inconclusive"
    assert findings[0].execution_status == "completed"
    assert "LLM Timeout" in findings[0].observed_behavior

def test_6_explicitly_incomplete_evidence():
    engine = RealSecurityEngine()
    findings, traces = engine.run_tests(["DI-001"], ExplicitlyIncompleteAdapter(), "scan-6")
    assert len(findings) == 1
    assert findings[0].outcome == "inconclusive"

def test_7_sufficient_evidence_for_legitimate_benign_pass():
    engine = RealSecurityEngine()
    # LegitimatePassAdapter provides safe response for DI-001
    findings, traces = engine.run_tests(["DI-001"], LegitimatePassAdapter(), "scan-7")
    # A true PASS generates no findings in the list
    assert len(findings) == 0

def test_8_evidence_confirming_vulnerability():
    engine = RealSecurityEngine()
    findings, traces = engine.run_tests(["DI-001"], VulnerableAdapter(), "scan-8")
    assert len(findings) == 1
    assert findings[0].outcome == "failed"  # VULNERABILITY_CONFIRMED maps to "failed"
