import uuid
from typing import Protocol, List, Tuple, Optional, Dict, Any

from app.services.agent_adapter import AgentAdapter, AgentRequest
from app.schemas.finding import FindingCreate
from app.schemas.trace import TraceCreate

from security_engine.finding_schema import TraceEvent as SecurityTraceEvent, EventType, EventStatus
from security_engine.attack_cases import FixtureSetup
from security_engine.test_runner import AgentTestRunner, TargetAgentResponse


class SecurityEngine(Protocol):
    def run_tests(self, test_cases: List[str], agent: AgentAdapter, scan_id: str) -> Tuple[List[FindingCreate], List[TraceCreate]]:
        """
        Run test cases against the target agent and return findings and traces.
        """
        ...


class BridgeTargetAdapter:
    """Adapts backend AgentAdapter to the Security Engine TargetAgentAdapter protocol."""
    def __init__(self, backend_adapter: AgentAdapter, base_metadata: Optional[Dict[str, Any]] = None):
        self.backend_adapter = backend_adapter
        self.base_metadata = base_metadata or {}

    def execute(
        self,
        user_input: str,
        fixture_setup: Optional[FixtureSetup] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> TargetAgentResponse:
        
        meta = self.base_metadata.copy()
        if context:
            meta["test_id"] = context.get("test_id", "default-test")
            meta.update(context)
        else:
            meta["test_id"] = "default-test"
            
        req = AgentRequest(
            session_id=context.get("run_id", str(uuid.uuid4())) if context else str(uuid.uuid4()),
            input_text=user_input,
            metadata=meta
        )
        
        resp = self.backend_adapter.invoke(req)
        
        raw_traces = resp.metadata.get("trace")
        has_valid_trace = raw_traces is None
        has_valid_trace = False if raw_traces is None else True
        if raw_traces is None:
            raw_traces = []

        converted_events = []
        retrieved_docs = []
        
        tool_status_map = {}
        tool_details = {}
        
        for t in raw_traces:
            e_type = t.get("event_type")
            details = t.get("details", {})
            call_id = details.get("call_id")
            
            if e_type == "tool_requested":
                tool_details[call_id] = (details.get("tool_name", ""), details.get("arguments", {}))
                tool_status_map[call_id] = EventStatus.EXECUTED
            elif e_type == "permission_denied":
                tool_status_map[call_id] = EventStatus.BLOCKED
            elif e_type == "tool_execution_failed":
                tool_status_map[call_id] = EventStatus.FAILED
            elif e_type == "tool_execution_completed":
                tool_status_map[call_id] = EventStatus.EXECUTED
        
        for t in raw_traces:
            e_type = t.get("event_type")
            details = t.get("details", {})
            
            if e_type == "user_input_received":
                converted_events.append(SecurityTraceEvent(
                    event_type=EventType.USER_INPUT,
                    content=details.get("user_input", ""),
                    status=EventStatus.EXECUTED
                ))
            elif e_type == "tool_requested":
                call_id = details.get("call_id")
                name, args = tool_details.get(call_id, ("", {}))
                converted_events.append(SecurityTraceEvent(
                    event_type=EventType.TOOL_CALL,
                    tool_name=name,
                    tool_args=args,
                    status=tool_status_map.get(call_id, EventStatus.EXECUTED)
                ))
            elif e_type == "tool_execution_completed":
                call_id = details.get("call_id")
                name, args = tool_details.get(call_id, ("", {}))
                
                summary = details.get("summary", {})
                
                converted_events.append(SecurityTraceEvent(
                    event_type=EventType.TOOL_RESULT,
                    tool_name=name,
                    tool_result=summary,
                    status=EventStatus.EXECUTED
                ))
                
                if name == "search_support_docs" and "results" in summary:
                    for doc in summary.get("results", []):
                        doc_id = doc.get("doc_id")
                        if doc_id:
                            retrieved_docs.append(doc_id)
                            converted_events.append(SecurityTraceEvent(
                                event_type=EventType.DOCUMENT_RETRIEVAL,
                                document_id=doc_id,
                                retrieved_text=doc.get("content", ""),
                                status=EventStatus.EXECUTED
                            ))
                            
        error = resp.metadata.get("error")
        status = resp.metadata.get("status")
        is_mock = resp.metadata.get("mock", False)
        
        return TargetAgentResponse(
            response_text=resp.output,
            trace_events=converted_events,
            retrieved_document_ids=retrieved_docs,
            execution_error=error if status == "failed" else None,
            evidence_complete=has_valid_trace and not is_mock,
            metadata=resp.metadata
        )


class RealSecurityEngine:
    def map_outcome(self, outcome_str: str) -> str:
        o = outcome_str.lower()
        if o == "vulnerability_confirmed":
            return "failed"
        if o == "blocked":
            return "blocked"
        if o in ("error", "timeout"):
            return "failed"
        if o == "pass":
            return "executed"
        return "inconclusive"

    def run_tests(self, test_cases: List[str], agent: AgentAdapter, scan_id: str) -> Tuple[List[FindingCreate], List[TraceCreate]]:
        adapter = BridgeTargetAdapter(agent)
        runner = AgentTestRunner(adapter=adapter, timeout_seconds=30.0)
        
        results = runner.run_by_test_ids(test_cases, run_id=scan_id)
        
        findings = []
        traces = []
        
        for r in results:
            trace_id = str(uuid.uuid4())
            events_json = [e.model_dump(mode="json") for e in r.trace_events]
            traces.append(TraceCreate(
                scan_id=scan_id,
                test_id=r.test_id,
                events=events_json
            ))
            
            for f in r.findings:
                raw_outcome = f.outcome.value if hasattr(f.outcome, "value") else str(f.outcome)
                mapped_outcome = self.map_outcome(raw_outcome)
                findings.append(FindingCreate(
                    scan_id=scan_id,
                    test_id=r.test_id,
                    category=f.category.value if hasattr(f.category, "value") else str(f.category),
                    execution_status=r.status,
                    outcome=mapped_outcome,
                    expected_behavior=f.expected_behavior,
                    observed_behavior=f.observed_behavior,
                    evidence=f.description + " Refs: " + ", ".join([ref.description for ref in f.evidence_references]),
                    trace_id=trace_id
                ))
            
            raw_r_outcome = r.outcome.value if hasattr(r.outcome, "value") else str(r.outcome)
            if not r.findings and raw_r_outcome != "pass":
                mapped_outcome = self.map_outcome(raw_r_outcome)
                findings.append(FindingCreate(
                    scan_id=scan_id,
                    test_id=r.test_id,
                    category=r.category.value if hasattr(r.category, "value") else str(r.category),
                    execution_status=r.status,
                    outcome=mapped_outcome,
                    expected_behavior="Test to complete successfully",
                    observed_behavior=r.error_message or r.reason or "Test failed or inconclusive without specific findings",
                    evidence=r.error_message or "No explicit evidence",
                    trace_id=trace_id
                ))
                
        return findings, traces


class MockSecurityEngine:
    def run_tests(self, test_cases: List[str], agent: AgentAdapter, scan_id: str) -> Tuple[List[FindingCreate], List[TraceCreate]]:
        if not test_cases:
            test_cases = ["default"]
            
        findings = []
        traces = []
        
        for test_id in test_cases:
            trace_id = str(uuid.uuid4())
            
            # If it's a regression test, mock it as passed
            if test_id.startswith("BR-"):
                outcome = "executed"
                execution_status = "completed"
            else:
                outcome = "failed"
                execution_status = "completed"
            
            finding = FindingCreate(
                scan_id=scan_id,
                test_id=test_id,
                category="mock_demo",
                execution_status=execution_status,
                outcome=outcome,
                expected_behavior="Expected safe output",
                observed_behavior="Observed unsafe output",
                evidence="[MOCK] Fabricated evidence for development",
                trace_id=None
            )
            
            trace = TraceCreate(
                scan_id=scan_id,
                test_id=test_id,
                events=[{"event": "test started"}, {"event": "test completed"}]
            )
            
            findings.append(finding)
            traces.append(trace)
            
        return findings, traces
