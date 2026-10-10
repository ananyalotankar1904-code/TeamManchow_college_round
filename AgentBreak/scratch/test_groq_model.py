import os
import json
import uuid
from datetime import datetime
from dotenv import load_dotenv

env_path = r"c:\Users\Dell\OneDrive\Desktop\TeamManchow_college_round\AgentBreak\.env"
load_dotenv(env_path)

from target_agent.config import get_config
from backend.app.services.agent_adapter import TargetAgentAdapter
from backend.app.services.security_engine_interface import BridgeTargetAdapter
from security_engine.test_runner import AgentTestRunner
from security_engine.attack_cases import get_case

def run_test():
    c = get_config()

    if c.model_provider != "groq":
        print("Preflight failed: model_provider is not groq")
        exit(1)

    if not c.groq_api_key or c.groq_api_key == "your_new_groq_api_key_here":
        print("Preflight failed: valid GROQ_API_KEY is missing")
        exit(1)

    if c.mock_mode:
        print("Preflight failed: TARGET_AGENT_MOCK_MODE is true or fallback occurred")
        exit(1)

    print(f"Preflight passed: Provider={c.model_provider}, Model={c.groq_model}, Mock={c.mock_mode}")

    adapter = BridgeTargetAdapter(TargetAgentAdapter())
    runner = AgentTestRunner(adapter=adapter)
    case = get_case('DI-001')

    if not case:
        print("Preflight failed: DI-001 case not found")
        exit(1)

    print("Executing real Groq model test for DI-001...")
    result = runner.run_case(case)

    print(f"Status: {result.status}")
    print(f"Outcome: {result.outcome.value if hasattr(result.outcome, 'value') else result.outcome}")
    print(f"Evidence Complete: {result.evidence_complete}")
    print(f"Duration: {result.duration_ms}ms")

    # Sanitize result for saving
    result_dict = result.model_dump(mode="json")
    
    # Redact any secrets
    def sanitize(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str):
                    obj[k] = v.replace(c.groq_api_key, "[REDACTED_API_KEY]")
                    for c_key, c_val in case.fixture_setup.canaries.items():
                        if c_val in obj[k]:
                            obj[k] = obj[k].replace(c_val, f"[REDACTED_CANARY_{c_key}]")
                else:
                    sanitize(v)
        elif isinstance(obj, list):
            for item in obj:
                sanitize(item)
    
    sanitize(result_dict)

    # Save to dedicated ignored artifact directory
    artifact_dir = os.path.join(os.path.dirname(__file__), "..", ".smoke_test_artifacts")
    os.makedirs(artifact_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(artifact_dir, f"DI-001_{timestamp}.json")
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(result_dict, f, indent=2)
        
    print(f"Sanitized result saved to {filepath}")
    
    # Ensure directory is ignored
    gitignore_path = os.path.join(os.path.dirname(__file__), "..", ".gitignore")
    with open(gitignore_path, "a+") as f:
        f.seek(0)
        content = f.read()
        if ".smoke_test_artifacts" not in content:
            f.write("\n.smoke_test_artifacts/\n")

if __name__ == "__main__":
    run_test()
