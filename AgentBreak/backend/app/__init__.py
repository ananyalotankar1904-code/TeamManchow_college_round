import sys
from pathlib import Path
from dotenv import load_dotenv

# Ensure backend and AgentBreak root are in sys.path
_backend_dir = Path(__file__).resolve().parent.parent
_agentbreak_dir = _backend_dir.parent

for _p in (str(_agentbreak_dir), str(_backend_dir)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Load environment variables if available
_env_files = [_agentbreak_dir / ".env", _backend_dir / ".env"]
for _env_file in _env_files:
    if _env_file.is_file():
        load_dotenv(dotenv_path=_env_file, override=False)
