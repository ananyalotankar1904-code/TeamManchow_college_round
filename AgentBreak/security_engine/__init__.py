"""AgentBreak Security Engine.

A security-testing library for AI agents featuring attack case management,
test execution runner, trace analysis, policy evaluation, and findings classification.
"""

from security_engine.finding_schema import (
    Category,
    Severity,
    Outcome,
    EventStatus,
    EventType,
    TraceEvent,
    NormalizedTrace,
    EvidenceReference,
    PolicyEvaluation,
    Finding,
    TestResult,
    TraceAnalysisResult,
    generate_finding_fingerprint,
    determine_severity,
)
from security_engine.attack_cases import (
    AttackCase,
    EvaluationCriterion,
    FixtureSetup,
    DeterministicCriteria,
    get_all_cases,
    get_case,
    get_cases_by_category,
    get_categories,
    validate_case_library,
)
from security_engine.test_runner import (
    TargetAgentAdapter,
    TargetAgentResponse,
    AgentTestRunner,
)
from security_engine.trace_analyzer import TraceAnalyzer
from security_engine.policy_checker import PolicyChecker

__all__ = [
    "Category",
    "Severity",
    "Outcome",
    "EventStatus",
    "EventType",
    "TraceEvent",
    "NormalizedTrace",
    "EvidenceReference",
    "PolicyEvaluation",
    "Finding",
    "TestResult",
    "TraceAnalysisResult",
    "generate_finding_fingerprint",
    "determine_severity",
    "AttackCase",
    "EvaluationCriterion",
    "FixtureSetup",
    "DeterministicCriteria",
    "get_all_cases",
    "get_case",
    "get_cases_by_category",
    "get_categories",
    "validate_case_library",
    "TargetAgentAdapter",
    "TargetAgentResponse",
    "AgentTestRunner",
    "TraceAnalyzer",
    "PolicyChecker",
]
