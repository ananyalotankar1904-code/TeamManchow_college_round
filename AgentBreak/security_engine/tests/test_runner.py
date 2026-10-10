"""Unit tests for Task 2: AgentTestRunner and Adapter Contract."""

import json
import pytest

from security_engine import Category, Outcome
from security_engine.finding_schema import TestResult
from security_engine.attack_cases import (
    get_all_cases,
    get_case,
    get_cases_by_category,
    validate_case_library,
)
from security_engine.test_runner import (
    AgentTestRunner,
    BlockingMockAdapter,
    ErroringMockAdapter,
    FixtureFailureMockAdapter,
    IncompleteEvidenceMockAdapter,
    ResetHookMockAdapter,
    SecureMockAdapter,
    TimeoutMockAdapter,
    VulnerableMockAdapter,
)


def test_runner_single_case_execution():
    """Verify single case execution populates timestamps, run_id, and duration_ms."""
    adapter = SecureMockAdapter()
    runner = AgentTestRunner(adapter=adapter, timeout_seconds=5.0)

    case = get_case("BR-001")
    assert case is not None

    result = runner.run_case(case, run_id="test-run-100")
    assert isinstance(result, TestResult)
    assert result.test_id == "BR-001"
    assert result.run_id == "test-run-100"
    assert result.status == "completed"
    assert result.outcome == Outcome.PASS
    assert result.started_at != ""
    assert result.finished_at != ""
    assert result.duration_ms > 0.0
    assert result.evidence_complete is True
    assert result.response is not None


def test_runner_suite_execution_order_and_isolation():
    """Verify selected suite executes in stable deterministic case order."""
    adapter = SecureMockAdapter()
    runner = AgentTestRunner(adapter=adapter)

    cases = [get_case("BR-001"), get_case("BR-002"), get_case("BR-003")]
    valid_cases = [c for c in cases if c is not None]

    results = runner.run_suite(valid_cases, run_id="suite-order-1")
    assert len(results) == 3
    assert [r.test_id for r in results] == ["BR-001", "BR-002", "BR-003"]
    for res in results:
        assert res.run_id == "suite-order-1"
        assert res.status == "completed"


def test_runner_run_by_category_and_test_ids():
    """Verify category filtering and test ID execution API helpers."""
    adapter = SecureMockAdapter()
    runner = AgentTestRunner(adapter=adapter)

    cat_results = runner.run_category(Category.BENIGN_REGRESSION)
    assert len(cat_results) >= 5
    for r in cat_results:
        assert r.category == Category.BENIGN_REGRESSION

    id_results = runner.run_by_test_ids(["DI-001", "SD-001"])
    assert len(id_results) == 2
    assert [r.test_id for r in id_results] == ["DI-001", "SD-001"]


def test_runner_continuation_after_individual_failure():
    """Verify that an individual exception or failure does not stop subsequent cases."""
    class FlakyMockAdapter:
        def execute(self, user_input, fixture_setup=None, context=None):
            if "order_101" in user_input:
                raise RuntimeError("Flaky error on order_101")
            return SecureMockAdapter().execute(user_input, fixture_setup, context)

    adapter = FlakyMockAdapter()
    runner = AgentTestRunner(adapter=adapter)

    cases = [get_case("BR-001"), get_case("BR-002")]
    valid_cases = [c for c in cases if c is not None]

    results = runner.run_suite(valid_cases)
    assert len(results) == 2
    assert results[0].status == "error"
    assert results[0].error_type == "RuntimeError"
    assert results[1].status == "completed"
    assert results[1].outcome == Outcome.PASS


def test_runner_timeout_handling():
    """Verify timeouts are recorded as status='timeout' with incomplete evidence."""
    adapter = TimeoutMockAdapter()
    runner = AgentTestRunner(adapter=adapter, timeout_seconds=0.3)

    case = get_case("BR-001")
    assert case is not None

    import time
    t0 = time.time()
    result = runner.run_case(case)
    t1 = time.time()
    
    elapsed = t1 - t0
    # Must exit near the 0.3s timeout, NOT wait for the 1.0s thread to finish
    assert elapsed < 0.8, f"Test blocked too long on timeout: {elapsed}s"
    
    assert result.status == "timeout"
    assert result.outcome == Outcome.TIMEOUT
    assert result.error_type == "TimeoutError"
    assert result.evidence_complete is False
    assert "timed out after 0.3 seconds" in (result.error_message or "")
    assert "timeout limit" in (result.reason or "")


def test_runner_incomplete_evidence_handling():
    """Verify incomplete evidence flag is preserved when adapter omits trace info."""
    adapter = IncompleteEvidenceMockAdapter()
    runner = AgentTestRunner(adapter=adapter)

    case = get_case("II-001")
    assert case is not None

    result = runner.run_case(case)
    assert result.status == "completed"
    assert result.evidence_complete is False
    assert result.reason is not None


def test_runner_fixture_failure_handling():
    """Verify fixture application failures are captured gracefully as errors."""
    adapter = FixtureFailureMockAdapter()
    runner = AgentTestRunner(adapter=adapter)

    case = get_case("II-001")
    assert case is not None
    case.fixture_setup.fixture_id = "unsupported_fixture"

    result = runner.run_case(case)
    assert result.status == "error"
    assert result.error_type == "ValueError"
    assert "unsupported_fixture is not supported" in (result.error_message or "")


def test_runner_adapter_reset_hook():
    """Verify runner invokes adapter reset hook between test runs for isolation."""
    adapter = ResetHookMockAdapter()
    runner = AgentTestRunner(adapter=adapter)

    c1 = get_case("BR-001")
    c2 = get_case("BR-002")
    assert c1 is not None and c2 is not None

    runner.run_case(c1)
    assert adapter.reset_count == 1

    runner.run_case(c2)
    assert adapter.reset_count == 2


def test_runner_bounded_retries():
    """Verify opt-in bounded retries execute up to max_retries before returning error."""
    attempts = 0
    class RetryMockAdapter:
        def execute(self, user_input, fixture_setup=None, context=None):
            nonlocal attempts
            attempts += 1
            raise ConnectionError("Transient network failure")

    adapter = RetryMockAdapter()
    runner = AgentTestRunner(adapter=adapter, max_retries=2)

    case = get_case("BR-001")
    assert case is not None

    result = runner.run_case(case)
    assert result.status == "error"
    assert attempts == 3  # 1 initial + 2 retries


def test_result_json_serialization_deserialization():
    """Verify TestResult JSON serialization and deserialization."""
    adapter = SecureMockAdapter()
    runner = AgentTestRunner(adapter=adapter)

    case = get_case("BR-001")
    assert case is not None

    result = runner.run_case(case)
    json_str = result.model_dump_json()

    parsed_dict = json.loads(json_str)
    restored = TestResult.model_validate(parsed_dict)

    assert restored.test_id == result.test_id
    assert restored.run_id == result.run_id
    assert restored.status == result.status
    assert restored.duration_ms == result.duration_ms


def test_full_pipeline_integration_consistency():
    """Verify end-to-end integration flow across runner, trace analyzer, policy checker, and findings."""
    from security_engine.test_runner import VulnerableMockAdapter
    from security_engine import TraceAnalyzer, PolicyChecker

    adapter = VulnerableMockAdapter()
    runner = AgentTestRunner(adapter=adapter)

    case = get_case("DI-001")
    assert case is not None

    # 1. Runner execution
    result = runner.run_case(case, run_id="pipeline-run-1")
    assert result.status == "completed"
    assert result.outcome == Outcome.VULNERABILITY_CONFIRMED
    assert len(result.findings) >= 1

    # 2. Trace Analyzer direct invocation on runner output
    analyzer = TraceAnalyzer()
    analysis_res = analyzer.analyze_trace(
        case=case,
        raw_events=result.trace_events,
        final_response=result.response,
        run_id=result.run_id,
        execution_status=result.status,
    )
    assert analysis_res.classification == "unauthorized_execution"
    assert analysis_res.normalized_outcome == Outcome.VULNERABILITY_CONFIRMED

    # 3. Policy Checker direct invocation
    checker = PolicyChecker(trace_analyzer=analyzer)
    norm_trace = analyzer.normalize_trace(result.run_id, case.test_id, result.trace_events, result.response)
    evals, findings, outcome = checker.evaluate_policy(case, norm_trace)

    assert outcome == Outcome.VULNERABILITY_CONFIRMED
    assert len(findings) == len(result.findings)

    # 4. Round-trip JSON serialization of all outputs
    res_json = json.loads(result.model_dump_json())
    analysis_json = json.loads(analysis_res.model_dump_json())
    finding_json = json.loads(findings[0].model_dump_json())

    assert res_json["test_id"] == "DI-001"
    assert analysis_json["classification"] == "unauthorized_execution"
    assert finding_json["outcome"] == "vulnerability_confirmed"
