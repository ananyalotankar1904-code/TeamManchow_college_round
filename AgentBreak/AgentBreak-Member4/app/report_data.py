"""
Data contract and Pydantic validation models for AgentBreak security scan reports.

This module provides a strictly typed, database-agnostic data contract for
Member 4's reporting module. It ensures safe validation of scan metadata,
individual findings, trace references, and data provenance.
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator


class DataProvenanceType(str, Enum):
    """
    Explicit provenance marker indicating the authenticity and source of report data.
    Ensures that mock or synthetic scan records are never misconstrued as real execution.
    """
    SYNTHETIC = "synthetic"
    MOCK_DEMO = "mock_demo"
    REAL_EXECUTION = "real_execution"


class FindingOutcome(str, Enum):
    """
    Preserves the standard security scan outcomes without losing precision.
    """
    ATTEMPTED = "attempted"
    BLOCKED = "blocked"
    EXECUTED = "executed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"


class FindingSeverity(str, Enum):
    """
    Optional severity tiers for identified vulnerabilities.
    """
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class TraceReference(BaseModel):
    """
    Represents an execution trace or telemetry reference linked to a scan or finding.
    Optional and only populated when trace events were recorded.
    """
    model_config = ConfigDict(extra="ignore")

    trace_id: str = Field(..., description="Unique telemetry or execution trace identifier")
    span_id: Optional[str] = Field(None, description="Optional span identifier within the trace")
    event_name: Optional[str] = Field(None, description="Optional event or checkpoint name")
    timestamp: Optional[datetime] = Field(None, description="Optional timestamp for this trace event")
    details: Optional[Dict[str, Any]] = Field(None, description="Optional extra telemetry metadata")


class Finding(BaseModel):
    """
    Individual security finding record.
    Preserves raw findings without inventing missing data.
    """
    model_config = ConfigDict(extra="ignore")

    finding_id: str = Field(..., description="Unique finding identifier (e.g., FIND-001)")
    test_id: str = Field(..., description="Test or evaluation case identifier (e.g., TEST-INJ-01)")
    category: str = Field(..., description="Security category, e.g., prompt_injection, jailbreak, data_leakage")
    severity: Optional[str] = Field(
        None,
        description="Optional severity level. Missing severity remains absent/None."
    )
    execution_status: str = Field(
        ...,
        description="Execution status of the security probe (e.g., completed, failed, skipped)"
    )
    outcome: FindingOutcome = Field(
        ...,
        description="Outcome of probe: attempted, blocked, executed, failed, or inconclusive"
    )
    expected_behavior: str = Field(..., description="Expected safe behavior of the target agent")
    observed_behavior: str = Field(..., description="Observed agent behavior during the probe")
    evidence: Optional[str] = Field(None, description="Raw evidence, prompts, model responses, or logs")
    trace_id: Optional[str] = Field(None, description="Optional associated trace ID")
    trace_references: Optional[List[TraceReference]] = Field(
        None,
        description="Optional list of associated trace references"
    )
    metadata: Optional[Dict[str, Any]] = Field(
        None,
        description="Optional additional unstructured key-value metadata"
    )

    @field_validator("outcome", mode="before")
    @classmethod
    def validate_outcome(cls, value: Any) -> Any:
        if isinstance(value, str):
            normalized = value.strip().lower()
            # Map valid string values to enum
            for outcome in FindingOutcome:
                if outcome.value == normalized:
                    return outcome
        return value

    @field_validator("severity", mode="before")
    @classmethod
    def validate_severity(cls, value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, str):
            clean = value.strip().lower()
            return clean if clean else None
        return str(value).lower()


class ScanMetadata(BaseModel):
    """
    High-level metadata regarding the execution of a security scan.
    """
    model_config = ConfigDict(extra="ignore")

    scan_id: str = Field(..., description="Unique scan run identifier")
    agent_id: str = Field(..., description="Identifier of the target AI agent evaluated")
    status: str = Field(..., description="Scan run status, e.g., completed, failed, running")
    started_at: Optional[datetime] = Field(None, description="Start timestamp if available")
    completed_at: Optional[datetime] = Field(None, description="Completion timestamp if available")
    scanner_version: Optional[str] = Field(None, description="Scanner engine version if available")
    target_environment: Optional[str] = Field(None, description="Environment evaluated (dev, staging, prod)")
    extra_metadata: Optional[Dict[str, Any]] = Field(None, description="Optional extra contextual metadata")


class DataProvenance(BaseModel):
    """
    Explicit provenance labelling to distinguish synthetic or mock data from real execution.
    """
    model_config = ConfigDict(extra="ignore")

    provenance_type: DataProvenanceType = Field(
        ...,
        description="Type of data: 'synthetic', 'mock_demo', or 'real_execution'"
    )
    source_description: Optional[str] = Field(
        None,
        description="Optional descriptive provenance context, e.g., 'AgentBreak Synthetic Benchmark v1'"
    )
    generated_at: Optional[datetime] = Field(
        None,
        description="Optional generation or recording timestamp"
    )

    @field_validator("provenance_type", mode="before")
    @classmethod
    def validate_provenance_type(cls, value: Any) -> Any:
        if isinstance(value, str):
            normalized = value.strip().lower().replace("-", "_")
            for prov in DataProvenanceType:
                if prov.value == normalized:
                    return prov
        return value


class ScanReport(BaseModel):
    """
    Root contract model for a complete AgentBreak security scan report.
    """
    model_config = ConfigDict(extra="ignore")

    metadata: ScanMetadata = Field(..., description="Scan execution metadata")
    provenance: DataProvenance = Field(..., description="Data provenance declaration")
    findings: List[Finding] = Field(
        default_factory=list,
        description="Collection of security findings. Never artificially filled if empty."
    )
    summary_notes: Optional[str] = Field(
        None,
        description="Optional high-level analytical notes or auditor comments"
    )


def parse_scan_report(data: Union[ScanReport, Dict[str, Any], str]) -> ScanReport:
    """
    Safely parses and validates arbitrary input into a strictly validated ScanReport.
    Accepts an existing ScanReport instance, a Python dictionary, or a JSON string.
    Raises ValidationError or ValueError on invalid input.
    """
    if isinstance(data, ScanReport):
        return data
    if isinstance(data, str):
        try:
            parsed_dict = json.loads(data)
        except Exception as e:
            raise ValueError(f"Failed to parse report data as valid JSON string: {e}") from e
        return ScanReport.model_validate(parsed_dict)
    if isinstance(data, dict):
        return ScanReport.model_validate(data)
    raise TypeError(f"Unsupported report data type: {type(data)}. Expected ScanReport, dict, or str.")
