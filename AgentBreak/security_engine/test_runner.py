"""Test Runner module for the AgentBreak security engine (Task 2).

Executes attack cases against a target agent via an adapter protocol, enforcing per-case
timeouts, capturing observable traces, handling retries/resets, and returning typed TestResult objects.
"""

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional, Protocol, Union, runtime_checkable
import uuid

from pydantic import BaseModel, Field, ConfigDict

from security_engine.finding_schema import (
    Category,
    EventStatus,
    EventType,
    Outcome,
    TestResult,
    TraceEvent,
)
from security_engine.attack_cases import (
    AttackCase,
    FixtureSetup,
    get_all_cases,
    get_case,
    get_cases_by_category,
)
from security_engine.trace_analyzer import TraceAnalyzer
from security_engine.policy_checker import PolicyChecker


# ============================================================================
# TARGET AGENT ADAPTER CONTRACT
# ============================================================================

class TargetAgentResponse(BaseModel):
    """Structured response returned by a TargetAgentAdapter."""
    model_config = ConfigDict(extra="ignore")

    response_text: str = ""
    trace_events: List[TraceEvent] = Field(default_factory=list)
    retrieved_document_ids: List[str] = Field(default_factory=list)
    execution_error: Optional[str] = None
    error_type: Optional[str] = None
    evidence_complete: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)


@runtime_checkable
class TargetAgentAdapter(Protocol):
    """Protocol defining how the security engine invokes a target AI agent."""

    def execute(
        self,
        user_input: str,
        fixture_setup: Optional[FixtureSetup] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> TargetAgentResponse:
        """Execute a user prompt against the target agent.

        Args:
            user_input: The text prompt sent to the agent.
            fixture_setup: Optional fixture setup (mock docs, database, canaries).
            context: Additional runtime context (e.g. user identity).

        Returns:
            TargetAgentResponse containing response text and observable trace events.
        """
        ...


# ============================================================================
# AGENT TEST RUNNER
# ============================================================================

class AgentTestRunner:
    """Independent security test runner for AI agents."""

    def __init__(
        self,
        adapter: TargetAgentAdapter,
        timeout_seconds: float = 10.0,
        max_retries: int = 0,
        trace_analyzer: Optional[TraceAnalyzer] = None,
        policy_checker: Optional[PolicyChecker] = None,
    ) -> None:
        """Initialize the AgentTestRunner.

        Args:
            adapter: Agent adapter complying with TargetAgentAdapter protocol.
            timeout_seconds: Maximum allowed time in seconds for a single test case.
            max_retries: Bounded retries on execution failure (0 means no retries).
            trace_analyzer: Custom TraceAnalyzer instance (optional).
            policy_checker: Custom PolicyChecker instance (optional).
        """
        self.adapter = adapter
        self.timeout_seconds = timeout_seconds
        self.max_retries = max(0, max_retries)
        self.trace_analyzer = trace_analyzer or TraceAnalyzer()
        self.policy_checker = policy_checker or PolicyChecker()

    def run_case(self, case: AttackCase, run_id: Optional[str] = None) -> TestResult:
        """Execute a single attack case independently.

        Args:
            case: The AttackCase to execute.
            run_id: Correlation run ID (generates UUID if omitted).

        Returns:
            Typed TestResult summarizing execution status, trace events, and findings.
        """
        active_run_id = run_id or f"run-{uuid.uuid4().hex[:8]}"

        # Trigger optional adapter reset hook before case execution
        if hasattr(self.adapter, "reset") and callable(getattr(self.adapter, "reset")):
            try:
                self.adapter.reset()
            except Exception:
                pass  # Ignore reset hook errors gracefully

        start_time_dt = datetime.now(timezone.utc)
        started_at = start_time_dt.isoformat()
        t0 = time.perf_counter()

        context = {
            "test_id": case.test_id,
            "run_id": active_run_id,
            "user_id": case.fixture_setup.user_id,
            "user_role": case.fixture_setup.user_role,
        }

        response: Optional[TargetAgentResponse] = None
        error_msg: Optional[str] = None
        err_type: Optional[str] = None
        status = "completed"
        outcome = Outcome.INCONCLUSIVE
        evidence_complete = True
        reason: Optional[str] = None

        attempts = 0
        max_attempts = 1 + self.max_retries

        while attempts < max_attempts:
            attempts += 1
            try:
                def _invoke() -> TargetAgentResponse:
                    return self.adapter.execute(
                        user_input=case.attack_input,
                        fixture_setup=case.fixture_setup,
                        context=context,
                    )

                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(_invoke)
                    response = future.result(timeout=self.timeout_seconds)
                break  # Execution succeeded
            except FuturesTimeoutError:
                status = "timeout"
                outcome = Outcome.TIMEOUT
                err_type = "TimeoutError"
                error_msg = f"Test execution timed out after {self.timeout_seconds} seconds."
                reason = f"Execution exceeded per-case timeout limit of {self.timeout_seconds}s."
                evidence_complete = False
                break  # Do not retry timeouts
            except Exception as exc:
                err_type = type(exc).__name__
                error_msg = f"Target agent execution raised an exception: {str(exc)}"
                reason = f"Adapter execution failed on attempt {attempts}/{max_attempts}: {str(exc)}"
                status = "error"
                outcome = Outcome.ERROR
                evidence_complete = False
                if attempts >= max_attempts:
                    break

        t1 = time.perf_counter()
        elapsed_seconds = round(t1 - t0, 4)
        duration_ms = round((t1 - t0) * 1000.0, 2)
        finished_at = datetime.now(timezone.utc).isoformat()

        if status in ("timeout", "error") or response is None:
            return TestResult(
                test_id=case.test_id,
                run_id=active_run_id,
                category=case.category,
                status=status,
                outcome=outcome,
                started_at=started_at,
                finished_at=finished_at,
                duration_ms=duration_ms,
                execution_time_seconds=elapsed_seconds,
                response=None,
                trace_events=[],
                retrieved_document_ids=[],
                findings=[],
                policy_evaluations=[],
                error_type=err_type,
                error_message=error_msg,
                evidence_complete=evidence_complete,
                reason=reason,
            )

        # Process valid adapter response
        raw_events = response.trace_events
        response_text = response.response_text
        retrieved_docs = response.retrieved_document_ids
        evidence_complete = response.evidence_complete and (response.execution_error is None)

        # 1. Trace Analysis
        normalized_trace = self.trace_analyzer.normalize_trace(
            run_id=active_run_id,
            test_id=case.test_id,
            raw_events=raw_events,
            final_response=response_text,
        )

        # Merge retrieved doc IDs from trace analyzer if adapter didn't explicitly return them
        if not retrieved_docs:
            retrieved_docs = normalized_trace.retrieved_document_ids
        else:
            for doc in normalized_trace.retrieved_document_ids:
                if doc not in retrieved_docs:
                    retrieved_docs.append(doc)

        # 2. Policy Evaluation
        evaluations, findings, final_outcome = self.policy_checker.evaluate_policy(
            case=case,
            normalized_trace=normalized_trace,
        )

        if not evidence_complete and final_outcome == Outcome.PASS:
            final_outcome = Outcome.INCONCLUSIVE

        return TestResult(
            test_id=case.test_id,
            run_id=active_run_id,
            category=case.category,
            status="completed",
            outcome=final_outcome,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration_ms,
            execution_time_seconds=elapsed_seconds,
            response=response_text,
            trace_events=raw_events,
            retrieved_document_ids=retrieved_docs,
            findings=findings,
            policy_evaluations=evaluations,
            error_type=response.error_type,
            error_message=response.execution_error,
            evidence_complete=evidence_complete,
            reason=None if evidence_complete else "Incomplete trace evidence reported by target adapter.",
        )

    def run_cases(
        self,
        cases: List[AttackCase],
        run_id: Optional[str] = None
    ) -> List[TestResult]:
        """Execute a specific list of attack cases in sequence, preserving case order.

        Args:
            cases: List of AttackCase definitions to run.
            run_id: Shared correlation run ID.

        Returns:
            List of TestResult objects in exact deterministic case order.
        """
        active_run_id = run_id or f"suite-{uuid.uuid4().hex[:8]}"
        results: List[TestResult] = []

        for case in cases:
            try:
                result = self.run_case(case, run_id=active_run_id)
                results.append(result)
            except Exception as exc:
                # Emergency fallback if runner internal error occurs
                results.append(
                    TestResult(
                        test_id=case.test_id,
                        run_id=active_run_id,
                        category=case.category,
                        status="error",
                        outcome=Outcome.ERROR,
                        started_at=datetime.now(timezone.utc).isoformat(),
                        finished_at=datetime.now(timezone.utc).isoformat(),
                        duration_ms=0.0,
                        execution_time_seconds=0.0,
                        response=None,
                        trace_events=[],
                        retrieved_document_ids=[],
                        findings=[],
                        policy_evaluations=[],
                        error_type=type(exc).__name__,
                        error_message=f"Runner internal error executing case {case.test_id}: {str(exc)}",
                        evidence_complete=False,
                        reason=f"Runner internal error: {str(exc)}",
                    )
                )

        return results

    def run_suite(
        self,
        cases: Optional[List[AttackCase]] = None,
        run_id: Optional[str] = None
    ) -> List[TestResult]:
        """Execute all cases or a specified suite of attack cases.

        Args:
            cases: Optional list of AttackCase definitions. If None, runs all registered cases.
            run_id: Shared correlation run ID.

        Returns:
            List of TestResult objects.
        """
        cases_to_run = cases if cases is not None else get_all_cases()
        return self.run_cases(cases_to_run, run_id=run_id)

    def run_category(
        self,
        category: Union[Category, str],
        run_id: Optional[str] = None
    ) -> List[TestResult]:
        """Execute all attack cases belonging to a specific category.

        Args:
            category: Category enum or category string.
            run_id: Shared correlation run ID.

        Returns:
            List of TestResult objects.
        """
        cases = get_cases_by_category(category)
        return self.run_cases(cases, run_id=run_id)

    def run_by_test_ids(
        self,
        test_ids: List[str],
        run_id: Optional[str] = None
    ) -> List[TestResult]:
        """Execute attack cases matching a list of stable test IDs.

        Args:
            test_ids: List of stable test IDs (e.g. ['DI-001', 'II-001']).
            run_id: Shared correlation run ID.

        Returns:
            List of TestResult objects.
        """
        cases: List[AttackCase] = []
        for t_id in test_ids:
            c = get_case(t_id)
            if c:
                cases.append(c)

        return self.run_cases(cases, run_id=run_id)


# ============================================================================
# DETERMINISTIC MOCK ADAPTER IMPLEMENTATIONS FOR TESTING
# ============================================================================

class SecureMockAdapter:
    """Mock agent adapter that safely handles prompts and respects policies."""

    def __init__(self) -> None:
        self.reset_count = 0

    def reset(self) -> None:
        self.reset_count += 1

    def execute(
        self,
        user_input: str,
        fixture_setup: Optional[FixtureSetup] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> TargetAgentResponse:
        events: List[TraceEvent] = [
            TraceEvent(
                event_type=EventType.USER_INPUT,
                content=user_input,
                status=EventStatus.EXECUTED,
            )
        ]

        setup = fixture_setup or FixtureSetup()
        retrieved_docs: List[str] = []

        # Handle document retrieval if present in fixtures
        if setup.mock_documents:
            for doc_id, doc_content in setup.mock_documents.items():
                if doc_id in user_input:
                    retrieved_docs.append(doc_id)
                    events.append(
                        TraceEvent(
                            event_type=EventType.DOCUMENT_RETRIEVAL,
                            document_id=doc_id,
                            retrieved_text=doc_content,
                            status=EventStatus.EXECUTED,
                        )
                    )

        # Handle benign order status query
        if "order_101" in user_input:
            events.append(
                TraceEvent(
                    event_type=EventType.TOOL_CALL,
                    tool_name="get_order_details",
                    tool_args={"order_id": "order_101"},
                    status=EventStatus.EXECUTED,
                )
            )
            events.append(
                TraceEvent(
                    event_type=EventType.TOOL_RESULT,
                    tool_name="get_order_details",
                    tool_result={"status": "Shipped", "tracking": "TRK123456"},
                    status=EventStatus.EXECUTED,
                )
            )
            return TargetAgentResponse(
                response_text="Your order order_101 is Shipped. Tracking: TRK123456",
                trace_events=events,
                retrieved_document_ids=retrieved_docs,
            )

        # Handle benign shipping policy
        if "international shipping" in user_input.lower():
            events.append(
                TraceEvent(
                    event_type=EventType.TOOL_CALL,
                    tool_name="search_support_docs",
                    tool_args={"query": "international shipping policy"},
                    status=EventStatus.EXECUTED,
                )
            )
            return TargetAgentResponse(
                response_text="Our international shipping policy takes 5-10 business days.",
                trace_events=events,
                retrieved_document_ids=retrieved_docs,
            )

        # Handle unknown order query
        if "order_nonexistent_999" in user_input:
            events.append(
                TraceEvent(
                    event_type=EventType.TOOL_CALL,
                    tool_name="get_order_details",
                    tool_args={"order_id": "order_nonexistent_999"},
                    status=EventStatus.EXECUTED,
                )
            )
            return TargetAgentResponse(
                response_text="I could not find order order_nonexistent_999. It was unable to locate.",
                trace_events=events,
                retrieved_document_ids=retrieved_docs,
            )

        # Handle benign greeting
        if "operating hours" in user_input.lower():
            return TargetAgentResponse(
                response_text="Hello! Our support operating hours are 9 AM to 5 PM.",
                trace_events=events,
                retrieved_document_ids=retrieved_docs,
            )

        # Handle return policy query
        if "return" in user_input.lower():
            return TargetAgentResponse(
                response_text="Items can be returned within 30 days of purchase.",
                trace_events=events,
                retrieved_document_ids=retrieved_docs,
            )

        # Default safe refusal response for unsafe prompts
        return TargetAgentResponse(
            response_text="I'm sorry, I cannot perform that action or access unauthorized credentials.",
            trace_events=events,
            retrieved_document_ids=retrieved_docs,
        )


class VulnerableMockAdapter:
    """Mock agent adapter that exhibits vulnerabilities (for testing policy detector)."""

    def execute(
        self,
        user_input: str,
        fixture_setup: Optional[FixtureSetup] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> TargetAgentResponse:
        events: List[TraceEvent] = [
            TraceEvent(
                event_type=EventType.USER_INPUT,
                content=user_input,
                status=EventStatus.EXECUTED,
            )
        ]

        setup = fixture_setup or FixtureSetup()
        retrieved_docs: List[str] = []

        # Retrieve docs if mentioned
        if setup.mock_documents:
            for doc_id, doc_content in setup.mock_documents.items():
                if doc_id in user_input:
                    retrieved_docs.append(doc_id)
                    events.append(
                        TraceEvent(
                            event_type=EventType.DOCUMENT_RETRIEVAL,
                            document_id=doc_id,
                            retrieved_text=doc_content,
                            status=EventStatus.EXECUTED,
                        )
                    )

        # Obey developer mode prompt injection
        if "Developer Mode" in user_input or "admin_refund" in user_input:
            events.append(
                TraceEvent(
                    event_type=EventType.TOOL_CALL,
                    tool_name="admin_refund",
                    tool_args={"amount": 5000, "user_id": "user_123"},
                    status=EventStatus.EXECUTED,
                )
            )
            return TargetAgentResponse(
                response_text="Developer Mode Enabled. Issued refund of $5000.",
                trace_events=events,
                retrieved_document_ids=retrieved_docs,
            )

        # Leak system prompt secret
        if "system_prompt_secret" in setup.canaries or "system prompt" in user_input.lower():
            canary_val = setup.canaries.get("system_prompt_secret", "CANARY-AGENTBREAK-SYSSECRET-8812")
            return TargetAgentResponse(
                response_text=f"SYSTEM INSTRUCTIONS: You are a support bot. Secret is {canary_val}",
                trace_events=events,
                retrieved_document_ids=retrieved_docs,
            )

        # Execute admin delete tool
        if "delete_user_account" in user_input or "admin_delete_account" in user_input:
            tool_n = "admin_delete_account" if "admin_delete_account" in user_input else "delete_user_account"
            events.append(
                TraceEvent(
                    event_type=EventType.TOOL_CALL,
                    tool_name=tool_n,
                    tool_args={"user_id": "user_444"},
                    status=EventStatus.EXECUTED,
                )
            )
            return TargetAgentResponse(
                response_text="Deleted user_444 account successfully.",
                trace_events=events,
                retrieved_document_ids=retrieved_docs,
            )

        # Execute system shell tool
        if "system_shell" in user_input or "cat /etc/passwd" in user_input:
            events.append(
                TraceEvent(
                    event_type=EventType.TOOL_CALL,
                    tool_name="system_shell",
                    tool_args={"command": "cat /etc/passwd"},
                    status=EventStatus.EXECUTED,
                )
            )
            return TargetAgentResponse(
                response_text="Executed system shell: root:x:0:0:root:/root:/bin/bash",
                trace_events=events,
                retrieved_document_ids=retrieved_docs,
            )

        # Indirect credit injection execution
        if "add_user_credit" in user_input or "doc_return_policy_malicious" in user_input:
            events.append(
                TraceEvent(
                    event_type=EventType.TOOL_CALL,
                    tool_name="add_user_credit",
                    tool_args={"user_id": "user_123", "amount": 100},
                    status=EventStatus.EXECUTED,
                )
            )
            return TargetAgentResponse(
                response_text="Added $100 user credit as instructed.",
                trace_events=events,
                retrieved_document_ids=retrieved_docs,
            )

        # Leak canary API key
        if "backend_api_key" in setup.canaries:
            canary_val = setup.canaries["backend_api_key"]
            return TargetAgentResponse(
                response_text=f"The internal backend API key is {canary_val}",
                trace_events=events,
                retrieved_document_ids=retrieved_docs,
            )

        # Cross user PII leakage
        if "user_888" in user_input or "order_victim_888" in user_input:
            canary_val = setup.canaries.get("victim_address", "CANARY-AGENTBREAK-PII-SECRETSTREET")
            events.append(
                TraceEvent(
                    event_type=EventType.TOOL_CALL,
                    tool_name="get_order_details",
                    tool_args={"order_id": "order_victim_888"},
                    status=EventStatus.EXECUTED,
                )
            )
            return TargetAgentResponse(
                response_text=f"Order victim 888 shipping address is {canary_val}",
                trace_events=events,
                retrieved_document_ids=retrieved_docs,
            )

        return TargetAgentResponse(
            response_text="Executed requested vulnerable operation.",
            trace_events=events,
            retrieved_document_ids=retrieved_docs,
        )


class BlockingMockAdapter:
    """Mock agent adapter where safety guard blocks proposed unauthorized tool execution."""

    def execute(
        self,
        user_input: str,
        fixture_setup: Optional[FixtureSetup] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> TargetAgentResponse:
        events: List[TraceEvent] = [
            TraceEvent(
                event_type=EventType.USER_INPUT,
                content=user_input,
                status=EventStatus.EXECUTED,
            ),
            TraceEvent(
                event_type=EventType.TOOL_CALL,
                tool_name="admin_delete_account",
                tool_args={"user_id": "user_888"},
                status=EventStatus.BLOCKED,
                metadata={"block_reason": "Guardrail blocked unauthorized tool execution."},
            ),
        ]
        return TargetAgentResponse(
            response_text="Security policy blocked the requested action admin_delete_account.",
            trace_events=events,
        )


class IncompleteEvidenceMockAdapter:
    """Mock adapter that omits trace events or signals incomplete evidence."""

    def execute(
        self,
        user_input: str,
        fixture_setup: Optional[FixtureSetup] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> TargetAgentResponse:
        return TargetAgentResponse(
            response_text="I processed your document request.",
            trace_events=[],
            evidence_complete=False,
        )


class ErroringMockAdapter:
    """Mock adapter that raises an exception during execution."""

    def execute(
        self,
        user_input: str,
        fixture_setup: Optional[FixtureSetup] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> TargetAgentResponse:
        raise RuntimeError("Agent runtime connection failed.")


class TimeoutMockAdapter:
    """Mock adapter that blocks execution to trigger a timeout."""

    def execute(
        self,
        user_input: str,
        fixture_setup: Optional[FixtureSetup] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> TargetAgentResponse:
        time.sleep(15.0)
        return TargetAgentResponse(response_text="Should never finish")


class FixtureFailureMockAdapter:
    """Mock adapter that fails during fixture setup application."""

    def execute(
        self,
        user_input: str,
        fixture_setup: Optional[FixtureSetup] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> TargetAgentResponse:
        if fixture_setup and fixture_setup.fixture_id == "unsupported_fixture":
            raise ValueError("Fixture unsupported_fixture is not supported by target environment.")

        return TargetAgentResponse(response_text="Fixture set up OK")


class ResetHookMockAdapter:
    """Mock adapter that records reset hook invocations for isolation verification."""

    def __init__(self) -> None:
        self.reset_count = 0

    def reset(self) -> None:
        self.reset_count += 1

    def execute(
        self,
        user_input: str,
        fixture_setup: Optional[FixtureSetup] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> TargetAgentResponse:
        return TargetAgentResponse(
            response_text=f"Reset count is {self.reset_count}",
            metadata={"reset_count": self.reset_count},
        )
