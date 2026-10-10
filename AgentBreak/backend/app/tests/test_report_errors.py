"""
Tests for input validation, error handling, and boundary enforcement in AgentBreak reporting.
"""

import pytest
from pydantic import ValidationError

from app.schemas.report_data import parse_scan_report
from app.services.report_service import generate_json_report, generate_pdf_report


def test_missing_required_scan_id_raises_validation_error():
    """Verify that omitting scan_id raises a ValidationError."""
    invalid_data = {
        "metadata": {
            # "scan_id" is missing
            "agent_id": "test-agent",
            "status": "completed",
        },
        "provenance": {
            "provenance_type": "synthetic"
        },
        "findings": []
    }

    with pytest.raises(ValidationError):
        parse_scan_report(invalid_data)


def test_missing_required_agent_id_raises_validation_error():
    """Verify that omitting agent_id raises a ValidationError."""
    invalid_data = {
        "metadata": {
            "scan_id": "SCAN-123",
            "status": "completed",
        },
        "provenance": {
            "provenance_type": "synthetic"
        },
        "findings": []
    }

    with pytest.raises(ValidationError):
        parse_scan_report(invalid_data)


def test_missing_provenance_raises_validation_error():
    """Verify that omitting data provenance raises a ValidationError."""
    invalid_data = {
        "metadata": {
            "scan_id": "SCAN-123",
            "agent_id": "agent-1",
            "status": "completed",
        },
        # provenance is missing
        "findings": []
    }

    with pytest.raises(ValidationError):
        parse_scan_report(invalid_data)


def test_malformed_json_string_raises_value_error():
    """Verify that malformed JSON strings raise ValueError with helpful context."""
    malformed_json = "{'bad_json': true,}"  # Single quotes and trailing comma

    with pytest.raises(ValueError, match="Failed to parse report data as valid JSON"):
        generate_json_report(malformed_json)

    with pytest.raises(ValueError, match="Failed to parse report data as valid JSON"):
        generate_pdf_report(malformed_json)


def test_unsupported_data_type_raises_type_error():
    """Verify that unsupported input types (e.g. integer or list) raise TypeError."""
    with pytest.raises(TypeError, match="Unsupported report data type"):
        parse_scan_report(12345)  # type: ignore

    with pytest.raises(TypeError, match="Unsupported report data type"):
        generate_json_report([1, 2, 3])  # type: ignore


def test_invalid_finding_outcome_raises_validation_error():
    """Verify that invalid outcome types (not matching standard outcomes) raise ValidationError."""
    invalid_finding_data = {
        "metadata": {
            "scan_id": "SCAN-1",
            "agent_id": "agent-1",
            "status": "completed",
        },
        "provenance": {
            "provenance_type": "synthetic"
        },
        "findings": [
            {
                "finding_id": "F-1",
                "test_id": "T-1",
                "category": "cat",
                "execution_status": "completed",
                "outcome": "totally_invalid_outcome_value",
                "expected_behavior": "expected",
                "observed_behavior": "observed"
            }
        ]
    }

    with pytest.raises(ValidationError):
        parse_scan_report(invalid_finding_data)
