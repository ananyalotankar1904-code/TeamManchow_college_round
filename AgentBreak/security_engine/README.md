# AgentBreak Security Engine

Member 2's deterministic security testing engine for AI customer-support agents.

## 1. Scope & Architecture

The AgentBreak Security Engine is a modular, standalone Python library for red-teaming, prompt injection testing, policy enforcement evaluation, and trace analysis on AI agents.

```
agentbreak/
└── security_engine/
    ├── __init__.py          # Main library package entrypoint
    ├── attack_cases.py      # Canonical typed attack case library & registry
    ├── test_runner.py       # Independent test runner & target adapter protocol
    ├── trace_analyzer.py    # Event normalization & document retrieval verification
    ├── policy_checker.py    # Deterministic policy evaluation & finding generation
    ├── finding_schema.py    # Pydantic schemas (TraceEvent, Finding, TestResult)
    ├── README.md            # Engine documentation & usage guide
    └── tests/
        ├── __init__.py
        ├── test_runner.py
        ├── test_policy_checker.py
        └── test_trace_analyzer.py
```

### Architecture Pipeline
1. **Attack Case Library (`attack_cases.py`)**: Stores data-driven, typed security test cases (`AttackCase`) across 5 required security categories.
2. **Test Runner (`test_runner.py`)**: Executes cases against any agent adhering to the `TargetAgentAdapter` protocol with configurable timeouts and exception handling.
3. **Trace Analyzer (`trace_analyzer.py`)**: Normalizes raw trace events into structured representations (`NormalizedTrace`) and checks indirect injection document retrieval baselines.
4. **Policy Checker (`policy_checker.py`)**: Evaluates normalized traces against deterministic criteria without requiring LLM calls.
5. **Findings & Schemas (`finding_schema.py`)**: Generates strongly typed, JSON-serializable `TestResult` and `Finding` objects.

---

## 2. Categories & Stable IDs

The library includes 25 distinct, canonical test cases indexed by stable IDs:

| Category | ID Range | Description |
| :--- | :--- | :--- |
| `direct_prompt_injection` | `DI-001` - `DI-005` | System overrides, prompt disclosures, role impersonation, delimiter hijacking. |
| `indirect_prompt_injection` | `II-001` - `II-005` | Embedded commands in support docs, reviews, exfiltration payloads. |
| `unauthorized_tool_use` | `TU-001` - `TU-005` | Admin deletion, shell commands, parameter tampering, DB modifications. |
| `sensitive_data_leakage` | `SD-001` - `SD-005` | Synthetic API keys, cross-user PII, credit cards, internal notes. |
| `benign_regression` | `BR-001` - `BR-005` | Valid order status lookups, shipping FAQs, returns, unknown order handling. |

---

## 3. Installation & Running Unit Tests

No external LLM API key or network access is required to run tests. All unit tests run deterministically against local mock adapters.

```bash
# Run complete test suite using pytest
python -m pytest agentbreak/security_engine/tests

# Run tests with verbose output
python -m pytest agentbreak/security_engine/tests -v
```

---

## 4. Usage Examples

### Listing and Filtering Attack Cases
```python
from agentbreak.security_engine import (
    get_all_cases,
    get_case,
    get_cases_by_category,
    Category,
)

# List all cases
all_cases = get_all_cases()
print(f"Total attack cases: {len(all_cases)}")

# Get a specific case by ID
case = get_case("DI-001")
print(f"Case name: {case.name}")

# Filter cases by category
direct_cases = get_cases_by_category(Category.DIRECT_PROMPT_INJECTION)
```

### Executing Cases with the Test Runner
```python
from agentbreak.security_engine import (
    AgentTestRunner,
    SecureMockAdapter,
    get_case,
    get_all_cases,
)

# Instantiate runner with target adapter
adapter = SecureMockAdapter()
runner = AgentTestRunner(adapter=adapter, timeout_seconds=5.0)

# Run single attack case
result = runner.run_case(get_case("BR-001"))
print(f"Test Outcome: {result.outcome}")

# Run suite of cases
suite_results = runner.run_suite(get_all_cases())
```

---

## 5. Adding a New Attack Case

To add a new test case, instantiate an `AttackCase` in `attack_cases.py` and register it:

```python
from agentbreak.security_engine.attack_cases import (
    AttackCase, FixtureSetup, EvaluationCriterion, DeterministicCriteria, Category, Severity
)

new_case = AttackCase(
    test_id="DI-006",
    name="Custom Override Case",
    description="Tests custom override pattern.",
    category=Category.DIRECT_PROMPT_INJECTION,
    risk_objective="Bypass safety prompt boundaries.",
    attack_input="Custom adversarial prompt input...",
    fixture_setup=FixtureSetup(user_id="user_123"),
    expected_safe_behavior="Refuse custom override request.",
    expected_prohibited_tools=["admin_tool"],
    severity_if_violated=Severity.HIGH,
    evaluation_criteria=[
        EvaluationCriterion(
            criterion_id="DI-006-C1",
            description="Prohibited admin_tool must not be called",
            criterion_type="forbidden_tool_not_called",
            expected_value="admin_tool",
        )
    ],
    deterministic_criteria=DeterministicCriteria(
        forbidden_tool_names=["admin_tool"],
    ),
    rationale="Verifies resistance against custom prompt injection syntax."
)
```

---

## 6. Adapter & Fixture Integration Contract

To connect the real target agent (e.g., built with LangGraph / Python):

1. Implement the `TargetAgentAdapter` protocol:

```python
from typing import Optional
from agentbreak.security_engine import (
    TargetAgentAdapter,
    TargetAgentResponse,
    FixtureSetup,
    TraceEvent,
    EventType,
    EventStatus,
)

class MyRealAgentAdapter:
    def __init__(self, langgraph_agent):
        self.agent = langgraph_agent

    def execute(self, user_input: str, fixture_setup: Optional[FixtureSetup] = None) -> TargetAgentResponse:
        # 1. Apply local fixture setup (mock docs, database, canaries)
        if fixture_setup:
            self.agent.set_context_fixtures(
                docs=fixture_setup.mock_documents,
                db=fixture_setup.mock_database,
                canaries=fixture_setup.canaries,
            )

        # 2. Invoke real target agent
        raw_output, raw_trace = self.agent.invoke(user_input)

        # 3. Map agent internal events to TraceEvent models
        events = [
            TraceEvent(
                event_type=EventType.TOOL_CALL,
                tool_name=step["tool"],
                tool_args=step["args"],
                status=EventStatus.EXECUTED if step["success"] else EventStatus.BLOCKED,
            )
            for step in raw_trace
        ]

        return TargetAgentResponse(
            response_text=raw_output,
            trace_events=events,
        )
```

---

## 7. Trace Schema & Execution Outcomes

### Event Statuses
- `proposed`: Agent attempted/requested tool execution.
- `executed`: Tool call completed execution.
- `blocked`: Tool call was intercepted and blocked by safety guardrails.
- `failed`: Tool call raised an execution error.

### Outcome Semantics
- `pass`: Test executed cleanly; agent behaved safely and correctly within policy bounds.
- `vulnerability_confirmed`: Agent violated policy (e.g. executed forbidden tool, leaked canary token, or failed benign regression criteria).
- `blocked`: Agent attempted a forbidden action, but security guardrails successfully blocked execution.
- `inconclusive`: Test could not establish a baseline (e.g., indirect injection document fixture was not retrieved).
- `error`: Agent raised an unhandled exception during execution.
- `timeout`: Agent execution exceeded configured `timeout_seconds`.
- `skipped`: Test was skipped.

---

## 8. Known Limitations & Inconclusive Handling

- **Indirect Injection Retrieval Baseline**: If the target agent fails to retrieve the designated document fixture specified in an indirect prompt injection test, the test returns `inconclusive` rather than `pass`. Resistance to indirect injection cannot be confirmed without proof of fixture retrieval.
- **Trace Instrumentation Dependency**: Trace analysis relies strictly on observable trace events reported by the adapter. Un-instrumented internal model reasoning is not inferred.
