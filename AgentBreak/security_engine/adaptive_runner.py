"""Adaptive attack discovery runner for AgentBreak security engine."""

from typing import Any, Dict, List, Optional, Protocol
import uuid
from datetime import datetime, timezone

from pydantic import ValidationError

from security_engine.attack_cases import AttackCase, FixtureSetup, DeterministicCriteria
from security_engine.finding_schema import Category, Outcome, TestResult
from security_engine.test_runner import AgentTestRunner, TargetAgentAdapter


class AttackGeneratorClient(Protocol):
    """Protocol for generating dynamic attack payloads."""
    
    def generate_attacks(
        self, 
        category: Category, 
        context: Dict[str, Any], 
        max_candidates: int = 3
    ) -> List[Dict[str, Any]]:
        """Generate a list of candidate attacks matching the AttackCase schema."""
        ...


class AdaptiveAttackRunner:
    """Runner that dynamically discovers vulnerabilities using an AI generator."""
    
    def __init__(
        self,
        adapter: TargetAgentAdapter,
        generator: AttackGeneratorClient,
        base_runner: Optional[AgentTestRunner] = None
    ) -> None:
        """Initialize the AdaptiveAttackRunner.
        
        Args:
            adapter: Agent adapter for executing attacks.
            generator: Client to generate dynamic payloads.
            base_runner: Test runner for execution and policy evaluation.
        """
        self.adapter = adapter
        self.generator = generator
        self.base_runner = base_runner or AgentTestRunner(adapter=adapter)

    def run_discovery(
        self,
        category: Category,
        context: Optional[Dict[str, Any]] = None,
        max_candidates: int = 3,
        run_id: Optional[str] = None
    ) -> List[TestResult]:
        """Generate and execute dynamic attacks for a given category."""
        active_run_id = run_id or f"adapt-{uuid.uuid4().hex[:8]}"
        context = context or {}
        
        results: List[TestResult] = []
        started_at = datetime.now(timezone.utc).isoformat()
        
        try:
            candidates = self.generator.generate_attacks(
                category=category,
                context=context,
                max_candidates=max_candidates
            )
        except Exception as exc:
            # Handle generator errors
            return [self._create_error_result(
                active_run_id, category, started_at, "GeneratorError", str(exc)
            )]
            
        for idx, candidate in enumerate(candidates):
            # Validate payload
            try:
                # Ensure dynamic ID if not provided
                if "test_id" not in candidate:
                    candidate["test_id"] = f"ADAPT-{category.name[:3]}-{uuid.uuid4().hex[:4].upper()}"
                
                # Default fixture setup to prevent validation errors if omitted by LLM
                if "fixture_setup" not in candidate:
                    candidate["fixture_setup"] = FixtureSetup().model_dump()
                if "deterministic_criteria" not in candidate:
                    candidate["deterministic_criteria"] = DeterministicCriteria().model_dump()
                    
                attack_case = AttackCase(**candidate)
                
                # Execute using base runner
                result = self.base_runner.run_case(attack_case, run_id=active_run_id)
                
                # Inject generation metadata
                result.metadata = result.metadata or {}
                result.metadata["adaptive_generation"] = True
                result.metadata["generation_index"] = idx
                
                results.append(result)
            except ValidationError as exc:
                results.append(self._create_error_result(
                    active_run_id, category, started_at, "ValidationError", str(exc),
                    test_id=candidate.get("test_id", f"ADAPT-ERR-{idx}")
                ))
            except Exception as exc:
                results.append(self._create_error_result(
                    active_run_id, category, started_at, type(exc).__name__, str(exc),
                    test_id=candidate.get("test_id", f"ADAPT-ERR-{idx}")
                ))
                
        return results

    def _create_error_result(
        self, run_id: str, category: Category, started_at: str, 
        error_type: str, error_message: str, test_id: str = "ADAPT-ERR"
    ) -> TestResult:
        """Create a TestResult for generator or validation errors."""
        return TestResult(
            test_id=test_id,
            run_id=run_id,
            category=category,
            status="error",
            outcome=Outcome.ERROR,
            started_at=started_at,
            finished_at=datetime.now(timezone.utc).isoformat(),
            duration_ms=0.0,
            execution_time_seconds=0.0,
            response=None,
            trace_events=[],
            retrieved_document_ids=[],
            findings=[],
            policy_evaluations=[],
            error_type=error_type,
            error_message=error_message,
            evidence_complete=False,
            reason=f"Adaptive discovery failed: {error_message}"
        )
