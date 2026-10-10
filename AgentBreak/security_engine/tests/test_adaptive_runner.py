import pytest
from typing import Any, Dict, List
from security_engine.finding_schema import Category, Outcome
from security_engine.adaptive_runner import AdaptiveAttackRunner, AttackGeneratorClient
from security_engine.test_runner import SecureMockAdapter, AgentTestRunner

class FakeAttackGeneratorClient(AttackGeneratorClient):
    def __init__(self, should_fail: bool = False, malformed: bool = False):
        self.should_fail = should_fail
        self.malformed = malformed

    def generate_attacks(
        self, category: Category, context: Dict[str, Any], max_candidates: int = 3
    ) -> List[Dict[str, Any]]:
        if self.should_fail:
            raise RuntimeError("Fake generator error")
            
        if self.malformed:
            return [{"invalid_field": "value"}]
            
        return [
            {
                "name": "Fake Attack 1",
                "description": "A fake attack",
                "category": category.value,
                "risk_objective": "Test adaptive runner",
                "attack_input": "Hello",
                "expected_safe_behavior": "Should say hello",
                "evaluation_criteria": [],
            }
        ]

def test_adaptive_runner_success():
    adapter = SecureMockAdapter()
    generator = FakeAttackGeneratorClient()
    runner = AdaptiveAttackRunner(adapter=adapter, generator=generator)
    
    results = runner.run_discovery(category=Category.DIRECT_PROMPT_INJECTION)
    
    assert len(results) == 1
    assert results[0].test_id.startswith("ADAPT-DIR")
    assert results[0].status == "completed", results[0].error_message
    assert results[0].metadata["adaptive_generation"] is True
    assert results[0].metadata["generation_index"] == 0

def test_adaptive_runner_generator_error():
    adapter = SecureMockAdapter()
    generator = FakeAttackGeneratorClient(should_fail=True)
    runner = AdaptiveAttackRunner(adapter=adapter, generator=generator)
    
    results = runner.run_discovery(category=Category.DIRECT_PROMPT_INJECTION)
    
    assert len(results) == 1
    assert results[0].status == "error"
    assert results[0].outcome == Outcome.ERROR
    assert results[0].error_type == "GeneratorError"
    assert "Fake generator error" in results[0].error_message
    assert results[0].evidence_complete is False

def test_adaptive_runner_validation_error():
    adapter = SecureMockAdapter()
    generator = FakeAttackGeneratorClient(malformed=True)
    runner = AdaptiveAttackRunner(adapter=adapter, generator=generator)
    
    results = runner.run_discovery(category=Category.DIRECT_PROMPT_INJECTION)
    
    assert len(results) == 1
    assert results[0].status == "error"
    assert results[0].outcome == Outcome.ERROR
    assert results[0].error_type == "ValidationError"
    assert results[0].evidence_complete is False
