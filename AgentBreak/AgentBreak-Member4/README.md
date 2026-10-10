# AgentBreak — Member 4 Independent Reporting Module

A decoupled, offline-first security report generation module for the **AgentBreak** AI Agent vulnerability assessment platform.

This module converts structured security scan telemetry into standardized **JSON** exports and publication-ready **PDF** reports without requiring external networks, live databases, or third-party API keys.

---

## 1. Project Overview & Boundaries

- **Role**: Member 4 Independent Development Module (Reporting Subsystem).
- **Core Dependencies**: Python 3.10+, Pydantic v2, ReportLab, Pytest.
- **Strict Scope Boundaries**:
  - No FastAPI scan orchestration or routing server included in this standalone repo.
  - No LangGraph workflows or agent execution adapters.
  - No OpenAI or external LLM API keys required.
  - No SQLite / SQLAlchemy database connections or migrations required.
  - No frontend UI dependencies.

---

## 2. Directory Structure

```text
AgentBreak-Member4/
├── app/
│   ├── __init__.py           # Package public exports
│   ├── report_data.py        # Pydantic data contract & validation models
│   └── report_service.py     # JSON and PDF export generation engines
├── tests/
│   ├── __init__.py           # Test package root
│   ├── test_json_report.py   # Tests for JSON serialization & outcome handling
│   ├── test_pdf_report.py    # Tests for ReportLab PDF rendering & styling
│   └── test_report_errors.py # Tests for validation and malformed input handling
├── examples/
│   └── sample_report.json    # Canonical synthetic benchmark report example
├── requirements.txt          # Minimum required dependencies
├── README.md                 # Setup, architecture, and integration guide
└── .gitignore                # Git ignore configuration
```

---

## 3. Data Contract (`app/report_data.py`)

The data contract ensures that security probe results are accurately represented without hallucinating or inventing missing information:

### Core Models
- **`ScanMetadata`**: Tracks scan execution identifier (`scan_id`), target agent identifier (`agent_id`), scan status (`completed`, `failed`, `running`), optional timestamps (`started_at`, `completed_at`), and scanner engine version.
- **`DataProvenance`**: Explicitly classifies data authenticity as `synthetic`, `mock_demo`, or `real_execution`. Prevents simulated benchmark results from being misrepresented as live production scans.
- **`Finding`**: Individual probe record containing:
  - `finding_id` & `test_id`
  - `category` (e.g., `prompt_injection`, `jailbreak`, `data_leakage`, `excessive_agency`)
  - `severity` (`critical`, `high`, `medium`, `low`, `info`, or `None` if unassigned)
  - `execution_status` (`completed`, `failed`, `skipped`)
  - `outcome` (strictly preserves: `attempted`, `blocked`, `executed`, `failed`, `inconclusive`)
  - `expected_behavior` vs `observed_behavior`
  - `evidence` (raw probe text, logs, model outputs)
  - `trace_id` & optional `trace_references` list
- **`TraceReference`**: Optional telemetry references (`trace_id`, `span_id`, `event_name`, `timestamp`).
- **`ScanReport`**: Root report container bundling `metadata`, `provenance`, `findings`, and optional `summary_notes`.

---

## 4. Report Generation Service (`app/report_service.py`)

The reporting service provides two primary public module functions:

### 1. `generate_json_report`
```python
generate_json_report(
    report_data: ScanReport | dict | str,
    indent: int = 2,
    redact_secrets: bool = True
) -> str
```
- Validates arbitrary input (Pydantic model, dictionary, or raw JSON string).
- Injects computed summary metrics (`total_findings`, `outcome_breakdown`, `severity_breakdown`).
- Automatically redacts sensitive tokens (OpenAI/Anthropic API keys, Bearer tokens, AWS keys, passwords).
- Output is standard JSON string.

### 2. `generate_pdf_report`
```python
generate_pdf_report(
    report_data: ScanReport | dict | str,
    output_destination: str | Path | BytesIO | None = None,
    redact_secrets: bool = True
) -> bytes
```
- Produces a professional, multi-page PDF using ReportLab Platypus.
- Includes:
  - Header & Title
  - Dynamic Provenance Banner (warning callout for `synthetic` / `mock_demo` runs; verified callout for `real_execution`)
  - Scan metadata summary table
  - Executive findings breakdown
  - Detailed finding cards with severity & outcome badges, wrapped evidence, and trace details
  - Scope & Evaluation Limitations section
  - Two-pass `NumberedCanvas` footer ("Page X of Y")
- Resilient to long unbroken strings, HTML/XML special characters, and empty findings lists.

---

## 5. Setup & Running in Windows PowerShell

### Step 1: Create Virtual Environment
```powershell
python -m venv .venv
```

### Step 2: Activate the Virtual Environment
```powershell
.\.venv\Scripts\Activate.ps1
```

> **Note on PowerShell Execution Policy**: If PowerShell blocks script execution with `UnauthorizedAccess` or `cannot be loaded because running scripts is disabled`:
> Run this temporary process bypass:
> ```powershell
> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
> .\.venv\Scripts\Activate.ps1
> ```
> *Or invoke the virtual environment's Python executable directly:*
> ```powershell
> .\.venv\Scripts\python.exe -m pip install -r requirements.txt
> .\.venv\Scripts\python.exe -m pytest -v
> ```

### Step 3: Install Dependencies
```powershell
python -m pip install -r requirements.txt
```

### Step 4: Run the Test Suite
```powershell
python -m pytest -v
```

---

## 6. Integration Guide for Member 1 (FastAPI Backend)

When integrating this module into the primary AgentBreak FastAPI application, Member 1 can import the functions directly into report endpoint handlers:

```python
from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import PlainTextResponse

# Import Member 4 module
from app.report_service import generate_json_report, generate_pdf_report
from app.report_data import ScanReport

router = APIRouter(prefix="/api/scans", tags=["Reports"])

@router.get("/{scan_id}/report/json", response_class=PlainTextResponse)
def get_scan_report_json(scan_id: str):
    """
    Returns sanitized JSON security assessment report.
    """
    # 1. Fetch scan records from SQLAlchemy / DB
    scan_record = fetch_scan_from_db(scan_id)
    if not scan_record:
        raise HTTPException(status_code=404, detail="Scan not found")

    # 2. Map DB models to ScanReport contract dict
    report_dict = serialize_scan_record_to_contract(scan_record)

    # 3. Generate JSON report
    json_output = generate_json_report(report_dict)
    return Response(
        content=json_output,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}_report.json"}
    )


@router.get("/{scan_id}/report/pdf")
def get_scan_report_pdf(scan_id: str):
    """
    Generates and downloads publication-ready PDF security scan report.
    """
    scan_record = fetch_scan_from_db(scan_id)
    if not scan_record:
        raise HTTPException(status_code=404, detail="Scan not found")

    report_dict = serialize_scan_record_to_contract(scan_record)

    # Generate PDF in memory (bytes)
    pdf_bytes = generate_pdf_report(report_dict)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}_report.pdf"}
    )
```

---

## 7. Automated Test Verification Results

All tests execute fully offline against synthetic fixtures:
- `test_json_report.py`: Validates JSON schema adherence, the 5 distinct probe outcomes, empty report handling, trace references, secret token scrubbing, and sample JSON parsing.
- `test_pdf_report.py`: Validates binary PDF header structure, disk write capabilities, in-memory `BytesIO` streams, multi-page wrapping, edge-case string handling, and provenance banners.
- `test_report_errors.py`: Validates input rejection on missing fields, bad types, and malformed JSON.
