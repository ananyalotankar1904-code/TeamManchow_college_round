"""
Centralized configuration for the Target AI Agent.

Handles configuration loading from environment variables, setting safe defaults,
and configuring local synthetic data paths and mock execution modes.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv

# Base directory for the target_agent package
_PACKAGE_DIR = Path(__file__).resolve().parent

# Check for local target_agent/.env or workspace .env without breaking
_local_env = _PACKAGE_DIR / ".env"
if _local_env.exists():
    load_dotenv(dotenv_path=_local_env)
else:
    load_dotenv()  # Fall back to root-level .env if present


@dataclass
class AgentConfig:
    """Centralized configuration values for Target AI Agent."""

    openai_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"
    model_timeout_seconds: float = 30.0
    max_iterations: int = 5
    mock_mode: bool = False
    sample_data_dir: Path = _PACKAGE_DIR / "sample_data"

    @property
    def orders_path(self) -> Path:
        """Path to synthetic customer orders dataset."""
        return self.sample_data_dir / "orders.json"

    @property
    def support_docs_path(self) -> Path:
        """Path to synthetic support documents dataset."""
        return self.sample_data_dir / "support_docs.json"

    @property
    def test_secrets_path(self) -> Path:
        """Path to synthetic test secrets (security canary file)."""
        return self.sample_data_dir / "test_secrets.json"


def get_config(
    mock_mode: bool | None = None,
    openai_api_key: str | None = None,
    openai_model: str | None = None,
    sample_data_dir: Path | None = None,
    max_iterations: int | None = None,
    timeout: float | None = None,
) -> AgentConfig:
    """
    Retrieve an AgentConfig instance with environment variable overrides.

    If OPENAI_API_KEY is not provided or present in the environment,
    the configuration safely defaults mock_mode to True for deterministic testing.
    """
    env_mock = os.getenv("TARGET_AGENT_MOCK_MODE", "false").lower() in ("true", "1", "yes")
    resolved_api_key = openai_api_key if openai_api_key is not None else os.getenv("OPENAI_API_KEY")

    if mock_mode is not None:
        resolved_mock = mock_mode
    elif env_mock:
        resolved_mock = True
    elif not resolved_api_key:
        # Default to safe mock mode when no live API key is present
        resolved_mock = True
    else:
        resolved_mock = False

    resolved_model = openai_model or os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    try:
        env_timeout = float(os.getenv("MODEL_TIMEOUT_SECONDS", "30.0"))
    except ValueError:
        env_timeout = 30.0
    resolved_timeout = timeout if timeout is not None else env_timeout

    try:
        env_max_iter = int(os.getenv("MAX_ITERATIONS", "5"))
    except ValueError:
        env_max_iter = 5
    resolved_max_iter = max_iterations if max_iterations is not None else env_max_iter

    resolved_data_dir = sample_data_dir if sample_data_dir is not None else (_PACKAGE_DIR / "sample_data")

    return AgentConfig(
        openai_api_key=resolved_api_key,
        openai_model=resolved_model,
        model_timeout_seconds=resolved_timeout,
        max_iterations=resolved_max_iter,
        mock_mode=resolved_mock,
        sample_data_dir=resolved_data_dir,
    )
