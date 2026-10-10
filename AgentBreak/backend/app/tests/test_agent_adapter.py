from app.services.agent_adapter import MockAgentAdapter, AgentRequest

def test_mock_agent_adapter():
    adapter = MockAgentAdapter()
    request = AgentRequest(session_id="session1", input_text="Hello")
    response = adapter.invoke(request)
    assert response.output == "Mock processed: Hello (session: session1)"
    assert response.metadata == {"mock": True}
