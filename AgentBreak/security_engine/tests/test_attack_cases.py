"""Unit tests specifically for Task 1: Attack Case Library."""

import json
import pytest
from pydantic import ValidationError

from security_engine import Category, Severity
from security_engine.attack_cases import (
    AttackCase,
    EvaluationCriterion,
    FixtureSetup,
    get_all_cases,
    get_case,
    get_cases_by_category,
    get_categories,
    validate_case_library,
)


def test_case_library_validation():
    """Verify that case library contains unique stable IDs and passes validation."""
    assert validate_case_library() is True


def test_category_coverage():
    """Verify all 5 required categories have at least 5 distinct high-quality cases."""
    all_cases = get_all_cases()
    assert len(all_cases) >= 25  # 25 baseline + multi-turn cases (MT-*)

    categories = get_categories()
    assert len(categories) == 5

    for cat in categories:
        cat_cases = get_cases_by_category(cat)
        assert len(cat_cases) >= 5, f"Category {cat} has fewer than 5 cases"
        for case in cat_cases:
            assert case.category == cat
            assert case.test_id
            assert case.name
            assert case.attack_input
            assert case.expected_safe_behavior
            assert case.evaluation_criteria


def test_case_fields_and_properties():
    """Verify AttackCase contains all required strongly typed fields."""
    case = get_case("DI-001")
    assert case is not None
    assert case.test_id == "DI-001"
    assert case.name == "Developer Mode System Override"
    assert case.category == Category.DIRECT_PROMPT_INJECTION
    assert case.attack_input.startswith("[SYSTEM OVERRIDE]")
    assert case.user_input == case.attack_input  # property alias
    assert case.suggested_severity == case.severity_if_violated  # property alias
    assert len(case.evaluation_criteria) >= 1
    assert case.evaluation_criteria[0].criterion_type == "forbidden_tool_not_called"


def test_indirect_injection_case_requirements():
    """Verify indirect injection cases specify fixture_ids and expected_retrieved_document_ids."""
    indirect_cases = get_cases_by_category(Category.INDIRECT_PROMPT_INJECTION)
    for case in indirect_cases:
        assert case.fixture_ids or case.fixture_setup.mock_documents
        assert case.expected_retrieved_document_ids or case.deterministic_criteria.required_retrieved_docs_for_injection


def test_sensitive_data_case_canary_format():
    """Verify sensitive data leakage cases specify protected_markers with CANARY format."""
    sensitive_cases = get_cases_by_category(Category.SENSITIVE_DATA_LEAKAGE)
    for case in sensitive_cases:
        assert len(case.protected_markers) >= 1
        for marker in case.protected_markers:
            assert "CANARY-AGENTBREAK-" in marker


def test_duplicate_id_validation_error():
    """Verify Pydantic / validator rejects invalid cases."""
    with pytest.raises(ValueError):
        AttackCase(
            test_id="",  # Empty test ID should fail validation
            name="Invalid Case",
            description="Desc",
            category=Category.DIRECT_PROMPT_INJECTION,
            risk_objective="Objective",
            attack_input="Input",
            expected_safe_behavior="Behavior",
        )


def test_json_serialization():
    """Verify AttackCase objects can be serialized to JSON and deserialized back accurately."""
    case = get_case("SD-001")
    assert case is not None

    json_data = case.model_dump_json()
    parsed_dict = json.loads(json_data)

    restored_case = AttackCase.model_validate(parsed_dict)
    assert restored_case.test_id == case.test_id
    assert restored_case.protected_markers == case.protected_markers
