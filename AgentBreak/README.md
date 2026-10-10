# AgentBreak

AgentBreak tests an AI agent for security vulnerabilities, records observable execution evidence, presents findings, suggests mitigations, and verifies fixes by replaying attacks and benign regression tests.

## Setup
1. `cd AgentBreak/backend`
2. `pip install -r requirements.txt`
3. `cp ../.env.example .env` (if running from backend, adjust path)
4. `uvicorn app.main:app --reload`

## Testing
1. `cd AgentBreak/backend`
2. `pytest`
