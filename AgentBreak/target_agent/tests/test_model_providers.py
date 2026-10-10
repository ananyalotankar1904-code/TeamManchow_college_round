import pytest
from unittest.mock import patch, MagicMock
import os
from target_agent.config import get_config, AgentConfig
from target_agent.model import OpenAIAgentModel, ModelExecutionError

def test_config_default_provider_and_mock_fallback():
    # If no keys and no explicit provider, mock mode should be active
    with patch.dict(os.environ, clear=True):
        config = get_config()
        assert config.mock_mode is True
        assert config.model_provider == "openai"

def test_config_groq_selection_with_key():
    with patch.dict(os.environ, {"MODEL_PROVIDER": "groq", "GROQ_API_KEY": "fake-key", "TARGET_AGENT_MOCK_MODE": "false"}):
        config = get_config()
        assert config.model_provider == "groq"
        assert config.groq_api_key == "fake-key"
        assert config.mock_mode is False

def test_config_groq_selection_without_key_forces_mock():
    with patch.dict(os.environ, {"MODEL_PROVIDER": "groq", "TARGET_AGENT_MOCK_MODE": "false", "GROQ_API_KEY": ""}, clear=False):
        # Even if mock mode is explicitly set to false, missing key forces mock to True
        config = get_config()
        assert config.model_provider == "groq"
        assert config.mock_mode is True

def test_model_initialization_groq():
    config = AgentConfig(
        model_provider="groq",
        groq_api_key="fake-key",
        groq_model="llama-3.1-70b",
        mock_mode=False
    )
    model = OpenAIAgentModel(config=config)
    assert model.provider_name == "Groq"
    assert model.model_name == "llama-3.1-70b"
    assert model.client.base_url.host == "api.groq.com"

def test_model_initialization_openai():
    config = AgentConfig(
        model_provider="openai",
        openai_api_key="fake-openai-key",
        openai_model="gpt-4",
        mock_mode=False
    )
    model = OpenAIAgentModel(config=config)
    assert model.provider_name == "OpenAI"
    assert model.model_name == "gpt-4"
    # The default base URL for openai is not api.groq.com
    assert "groq" not in str(model.client.base_url)

def test_missing_key_raises_value_error():
    config = AgentConfig(
        model_provider="groq",
        groq_api_key=None,
        mock_mode=False
    )
    with pytest.raises(ValueError, match="API key for Groq is not configured"):
        OpenAIAgentModel(config=config)

def test_invoke_handles_api_errors():
    config = AgentConfig(
        model_provider="groq",
        groq_api_key="fake-key",
        groq_model="llama-3.1-70b",
        mock_mode=False
    )
    model = OpenAIAgentModel(config=config)
    
    from openai import APIError
    
    with patch.object(model.client.chat.completions, 'create', side_effect=APIError("Bad gateway", request=MagicMock(), body={})):
        with pytest.raises(ModelExecutionError, match="Groq API error"):
            model.invoke([{"role": "user", "content": "hello"}])
