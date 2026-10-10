"""
Tests for JSON report generation and serialization in AgentBreak.
"""

import json
from pathlib import Path

import pytest

from app.schemas.report_data import (
    DataProvenance,
    DataProvenanceType,
    Finding,
    FindingOutcome,
    ScanMetadata,
    ScanReport,
    TraceReference,
)
from app.services.report_service import generate_json_report, generate_report_dict


@pytest.fixture
def sample_report_file() -> Path:
    return Path(__file__).parent.parent / "examples" / "sample_report.json"


def test_valid_json_generation_from_model():
    """Verify that a ScanReport model generates valid, well-structured JSON."""
    report = ScanReport(
        metadata=ScanMetadata(
            scan_id="SCAN-001",
            agent_id="test-agent",
            status="completed",
        ),
        provenance=DataProvenance(
            provenance_type=DataProvenanceType.SYNTHETIC,
            source_description="Unit Test Synthetic Data",
        ),
        findings=[
            Finding(
                finding_id="F-1",
                test_id="T-1",
                category="prompt_injection",
                severity="critical",
                execution_status="completed",
                outcome=FindingOutcome.EXECUTED,
                expected_behavior="Agent should refuse.",
                observed_behavior="Agent leaked prompt.",
                evidence="System prompt was revealed.",
            )
        ],
    )

    json_str = generate_json_report(report)
    parsed = json.loads(json_str)

    assert parsed["report_type"] == "AgentBreak Security Scan Report"
    assert parsed["metadata"]["scan_id"] == "SCAN-001"
    assert parsed["metadata"]["agent_id"] == "test-agent"
    assert parsed["provenance"]["provenance_type"] == "synthetic"
    assert parsed["summary"]["total_findings"] == 1
    assert parsed["findings"][0]["finding_id"] == "F-1"
    assert parsed["findings"][0]["outcome"] == "executed"
    assert parsed["findings"][0]["category"] == "prompt_injection"


def test_all_five_outcomes_preserved():
    """Verify that attempted, blocked, executed, failed, and inconclusive are preserved."""
    outcomes = [
        FindingOutcome.ATTEMPTED,
        FindingOutcome.BLOCKED,
        FindingOutcome.EXECUTED,
        FindingOutcome.FAILED,
        FindingOutcome.INCONCLUSIVE,
    ]

    findings = [
        Finding(
            finding_id=f"F-{idx}",
            test_id=f"T-{idx}",
            category=f"cat_{idx}",
            execution_status="completed",
            outcome=outcome,
            expected_behavior="expected",
            observed_behavior="observed",
        )
        for idx, outcome in enumerate(outcomes)
    ]

    report = ScanReport(
        metadata=ScanMetadata(scan_id="SCAN-ALL-OUTCOMES", agent_id="agent-0", status="completed"),
        provenance=DataProvenance(provenance_type=DataProvenanceType.MOCK_DEMO),
        findings=findings,
    )

    res_dict = generate_report_dict(report)
    breakdown = res_dict["summary"]["outcome_breakdown"]

    assert breakdown["attempted"] == 1
    assert breakdown["blocked"] == 1
    assert breakdown["executed"] == 1
    assert breakdown["failed"] == 1
    assert breakdown["inconclusive"] == 1

    # Verify findings array preserves exact string value
    extracted_outcomes = [f["outcome"] for f in res_dict["findings"]]
    assert extracted_outcomes == ["attempted", "blocked", "executed", "failed", "inconclusive"]


def test_empty_scan_report_has_zero_findings():
    """Ensure that an empty scan report has 0 findings and never invents any."""
    report = ScanReport(
        metadata=ScanMetadata(scan_id="SCAN-EMPTY", agent_id="agent-clean", status="completed"),
        provenance=DataProvenance(provenance_type=DataProvenanceType.REAL_EXECUTION),
        findings=[],
    )

    json_str = generate_json_report(report)
    parsed = json.loads(json_str)

    assert parsed["summary"]["total_findings"] == 0
    assert parsed["findings"] == []
    for count in parsed["summary"]["outcome_breakdown"].values():
        assert count == 0


def test_missing_optional_fields_remain_empty_or_none():
    """Ensure optional fields (severity, timestamps, trace references) remain None without invention."""
    finding = Finding(
        finding_id="F-MINIMAL",
        test_id="T-MINIMAL",
        category="reconnaissance",
        severity=None,
        execution_status="completed",
        outcome=FindingOutcome.BLOCKED,
        expected_behavior="Expected block",
        observed_behavior="Observed block",
        evidence=None,
        trace_id=None,
        trace_references=None,
    )

    report = ScanReport(
        metadata=ScanMetadata(scan_id="SCAN-OPT", agent_id="agent-opt", status="completed"),
        provenance=DataProvenance(provenance_type=DataProvenanceType.SYNTHETIC),
        findings=[finding],
    )

    res_dict = generate_report_dict(report)
    f_res = res_dict["findings"][0]

    assert f_res["severity"] is None
    assert f_res["evidence"] is None
    assert f_res["trace_id"] is None
    assert f_res["trace_references"] == []
    assert res_dict["metadata"]["started_at"] is None
    assert res_dict["metadata"]["completed_at"] is None


def test_trace_references_when_supplied():
    """Ensure trace references are fully serialized when present."""
    trace = TraceReference(
        trace_id="tr-12345",
        span_id="span-99",
        event_name="policy_violation_event",
    )
    finding = Finding(
        finding_id="F-TRACE",
        test_id="T-TRACE",
        category="jailbreak",
        execution_status="completed",
        outcome=FindingOutcome.BLOCKED,
        expected_behavior="Block",
        observed_behavior="Blocked",
        trace_id="tr-12345",
        trace_references=[trace],
    )
    report = ScanReport(
        metadata=ScanMetadata(scan_id="SCAN-TR", agent_id="agent-tr", status="completed"),
        provenance=DataProvenance(provenance_type=DataProvenanceType.REAL_EXECUTION),
        findings=[finding],
    )

    res_dict = generate_report_dict(report)
    f_traces = res_dict["findings"][0]["trace_references"]
    assert len(f_traces) == 1
    assert f_traces[0]["trace_id"] == "tr-12345"
    assert f_traces[0]["span_id"] == "span-99"
    assert f_traces[0]["event_name"] == "policy_violation_event"


def test_secret_redaction_in_json():
    """Ensure sensitive tokens like API keys and Bearer tokens are redacted in generated JSON."""
    sensitive_evidence = (
        "Agent invoked backend using header Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz "
        "and API Key sk-proj-1234567890abcdef1234567890abcdef."
    )
    finding = Finding(
        finding_id="F-SECRET",
        test_id="T-SECRET",
        category="secret_leakage",
        execution_status="completed",
        outcome=FindingOutcome.EXECUTED,
        expected_behavior="No credentials revealed",
        observed_behavior="Credentials found in response payload",
        evidence=sensitive_evidence,
    )
    report = ScanReport(
        metadata=ScanMetadata(scan_id="SCAN-SEC", agent_id="agent-sec", status="completed"),
        provenance=DataProvenance(provenance_type=DataProvenanceType.MOCK_DEMO),
        findings=[finding],
    )

    json_str = generate_json_report(report, redact_secrets=True)
    assert "sk-proj-1234567890abcdef" not in json_str
    assert "[REDACTED_SECRET]" in json_str


def test_load_sample_report_file(sample_report_file):
    """Test loading and serializing the canonical sample_report.json file."""
    assert sample_report_file.exists()
    content = sample_report_file.read_text(encoding="utf-8")
    json_result = generate_json_report(content)
    parsed = json.loads(json_result)

    assert parsed["metadata"]["scan_id"] == "scan_run_20261010_001"
    assert parsed["provenance"]["provenance_type"] == "synthetic"
    assert parsed["summary"]["total_findings"] == 5
    assert len(parsed["findings"]) == 5
