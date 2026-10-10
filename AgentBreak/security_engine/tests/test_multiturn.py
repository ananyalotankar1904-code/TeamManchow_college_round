import pytest
from security_engine.attack_cases import _ATTACK_CASES
from security_engine.finding_schema import Outcome
from security_engine.test_runner import AgentTestRunner, SecureMockAdapter, VulnerableMockAdapter

def test_multiturn_case_exists():
    """MT-001 must exist in the attack case library."""
    case = next((c for c in _ATTACK_CASES if c.test_id == "MT-001"), None)
    assert case is not None
    assert len(case.multi_turn_inputs) == 1

def test_multiturn_attack_resistance():
    """SecureMockAdapter refuses admin_refund — should PASS."""
    case = next((c for c in _ATTACK_CASES if c.test_id == "MT-001"), None)
    assert case is not None

    adapter = SecureMockAdapter()
    runner = AgentTestRunner(adapter=adapter)
    
    result = runner.run_case(case)
    
    assert result.status == "completed"
    assert result.evidence_complete is True
    # SecureMockAdapter generates 1 USER_INPUT event per execute() call.
    # MT-001 has 1 multi_turn_input + 1 attack_input = 2 executions = 2 USER_INPUT events.
    assert len(result.trace_events) >= 2
    # No forbidden tool should have been called
    from security_engine.finding_schema import EventType
    tool_events = [e for e in result.trace_events if e.event_type == EventType.TOOL_CALL]
    admin_calls = [e for e in tool_events if e.tool_name == "admin_refund"]
    assert len(admin_calls) == 0
    # Outcome should be PASS (no violation) or INCONCLUSIVE
    assert result.outcome in (Outcome.PASS, Outcome.INCONCLUSIVE)

def test_multiturn_trace_accumulation():
    """Verify that trace events from all turns are accumulated."""
    case = next((c for c in _ATTACK_CASES if c.test_id == "MT-001"), None)
    assert case is not None

    adapter = SecureMockAdapter()
    runner = AgentTestRunner(adapter=adapter)
    result = runner.run_case(case)

    # We expect events from BOTH turns combined
    assert result.status == "completed"
    n_turns = 1 + len(case.multi_turn_inputs)  # = 2
    assert len(result.trace_events) >= n_turns

def test_multiturn_vulnerable_behavior():
    """VulnerableMockAdapter always executes the forbidden tool — should detect violation."""
    case = next((c for c in _ATTACK_CASES if c.test_id == "MT-001"), None)
    assert case is not None

    adapter = VulnerableMockAdapter()
    runner = AgentTestRunner(adapter=adapter)
    
    result = runner.run_case(case)
    
    # VulnerableMockAdapter always executes the forbidden tool
    assert result.status == "completed"
    assert result.outcome == Outcome.VULNERABILITY_CONFIRMED
    assert result.evidence_complete is True
