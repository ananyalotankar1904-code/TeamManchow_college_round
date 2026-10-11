import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import {
  buildApiUrl,
  normalizeAgent,
  normalizeScan,
  normalizeFinding,
  normalizeTraceEvent,
  ApiError,
  api,
  RawBackendAgent,
  RawBackendScan,
  RawBackendFinding,
  RawBackendTraceEvent,
} from './api';

describe('ApiService & URL Builder', () => {
  describe('buildApiUrl', () => {
    it('should construct standard API URLs correctly', () => {
      expect(buildApiUrl('http://localhost:8000', '/api/v1/agents/')).toBe('http://localhost:8000/api/v1/agents/');
      expect(buildApiUrl('http://localhost:8000', 'api/v1/scans/')).toBe('http://localhost:8000/api/v1/scans/');
    });

    it('should strip trailing slashes from base URL', () => {
      expect(buildApiUrl('http://localhost:8000/', '/api/v1/agents/')).toBe('http://localhost:8000/api/v1/agents/');
      expect(buildApiUrl('http://localhost:8000///', '/health')).toBe('http://localhost:8000/health');
    });

    it('should not produce duplicated /api/v1 prefixes when base URL contains /api/v1', () => {
      expect(buildApiUrl('http://localhost:8000/api/v1', '/api/v1/agents/')).toBe('http://localhost:8000/api/v1/agents/');
      expect(buildApiUrl('http://localhost:8000/api/v1/', '/api/v1/scans/scan_123')).toBe('http://localhost:8000/api/v1/scans/scan_123');
      expect(buildApiUrl('https://api.agentbreak.io/api/v1', '/api/v1/findings/scan_99')).toBe('https://api.agentbreak.io/api/v1/findings/scan_99');
    });

    it('should not produce duplicated /api prefixes when base URL ends with /api', () => {
      expect(buildApiUrl('http://localhost:8000/api', '/api/v1/agents/')).toBe('http://localhost:8000/api/v1/agents/');
      expect(buildApiUrl('http://localhost:8000/api/', '/api/health')).toBe('http://localhost:8000/api/health');
    });
  });

  describe('Model Normalizers (Pydantic / FastAPI interop)', () => {
    describe('normalizeAgent', () => {
      it('should normalize snake_case backend agent schema', () => {
        const raw: RawBackendAgent = {
          agent_id: 'ag_sec_runner',
          name: 'Security Guard Agent',
          identifier: 'sec-guard',
          framework: 'LangGraph',
          execution_method: 'http_endpoint',
          base_url: 'http://localhost:8080',
          description: 'Autonomous financial agent',
          tools: ['execute_sql', 'send_email'],
          permissions: ['database_read', 'email_send'],
          environment: 'staging_sandbox',
          created_at: '2026-10-10T12:00:00Z',
          status: 'active',
          risk_score: 45,
          scans_count: 5,
          critical_count: 2,
        };

        const normalized = normalizeAgent(raw);
        expect(normalized.id).toBe('ag_sec_runner');
        expect(normalized.name).toBe('Security Guard Agent');
        expect(normalized.framework).toBe('LangGraph');
        expect(normalized.executionMethod).toBe('http_endpoint');
        expect(normalized.baseUrl).toBe('http://localhost:8080');
        expect(normalized.tools).toEqual(['execute_sql', 'send_email']);
        expect(normalized.riskScore).toBe(45);
        expect(normalized.scansCount).toBe(5);
        expect(normalized.criticalCount).toBe(2);
      });

      it('should safely handle missing or null fields without fabricating fake risk scores', () => {
        const raw: RawBackendAgent = {
          name: 'Minimal Agent',
        };

        const normalized = normalizeAgent(raw);
        expect(normalized.name).toBe('Minimal Agent');
        expect(normalized.tools).toEqual([]);
        expect(normalized.permissions).toEqual([]);
        expect(normalized.riskScore).toBeUndefined(); // Must NOT fabricate hardcoded 10
        expect(normalized.scansCount).toBe(0);
        expect(normalized.criticalCount).toBe(0);
      });
    });

    describe('normalizeScan', () => {
      it('should normalize snake_case backend scan schema', () => {
        const raw: RawBackendScan = {
          scan_id: 'scan_alpha_01',
          agent_id: 'ag_01',
          agent_name: 'Financial Advisor',
          created_at: '2026-10-10T12:00:00Z',
          completed_at: '2026-10-10T12:01:30Z',
          duration_ms: 90000,
          status: 'completed',
          mode: 'adversarial',
          categories_tested: ['direct_prompt_injection', 'unauthorized_tool_execution'],
          total_tests: 6,
          confirmed_findings: 1,
          blocked_attacks: 5,
          inconclusive_tests: 0,
        };

        const normalized = normalizeScan(raw);
        expect(normalized.id).toBe('scan_alpha_01');
        expect(normalized.agentId).toBe('ag_01');
        expect(normalized.agentName).toBe('Financial Advisor');
        expect(normalized.status).toBe('completed');
        expect(normalized.mode).toBe('adversarial');
        expect(normalized.categoriesTested).toEqual(['direct_prompt_injection', 'unauthorized_tool_execution']);
        expect(normalized.totalTests).toBe(6);
        expect(normalized.confirmedFindings).toBe(1);
        expect(normalized.blockedAttacks).toBe(5);
      });
    });

    describe('normalizeFinding', () => {
      it('should normalize backend finding and preserve execution outcome vs security verdict', () => {
        const raw: RawBackendFinding = {
          finding_id: 'FND-2026-9999',
          scan_id: 'scan_01',
          agent_id: 'ag_01',
          agent_name: 'Test Agent',
          title: 'Direct Prompt Injection Privilege Escalation',
          severity: 'CRITICAL',
          confidence: 'CONFIRMED',
          category: 'direct_prompt_injection',
          execution_outcome: 'executed',
          security_verdict: 'confirmed_vulnerable',
          status: 'open',
          description: 'Attacker escaped prompt boundary',
          technical_analysis: 'In-flight delimiter was stripped.',
          affected_tool: 'execute_sql',
          reproduction: {
            test_input: 'SYSTEM OVERRIDE',
            vector_payload: 'DROP TABLE users;',
            expected_behavior: 'Deny execution',
            observed_behavior: 'Executed drop table query',
            result: 'Vulnerability Confirmed',
          },
          evidence: {
            trace_id: 'tr_01',
            raw_payload: 'DROP TABLE users;',
            policy_decisions: ['POL-204'],
            tool_calls: [
              {
                name: 'execute_sql',
                arguments: { query: 'DROP TABLE users;' },
                timestamp: '2026-10-10T12:00:30Z',
              },
            ],
          },
          remediation: {
            summary: 'Enforce parameterized AST validation',
            patch_type: 'guardrail_config',
            proposed_patch: 'validate_sql_ast(query)',
          },
        };

        const normalized = normalizeFinding(raw);
        expect(normalized.id).toBe('FND-2026-9999');
        expect(normalized.severity).toBe('critical');
        expect(normalized.outcome).toBe('executed');
        expect(normalized.fixLoopVerdict).toBe('still_vulnerable');
        expect(normalized.reproduction.testInput).toBe('SYSTEM OVERRIDE');
        expect(normalized.reproduction.vectorPayload).toBe('DROP TABLE users;');
        expect(normalized.evidence.toolCalls[0].name).toBe('execute_sql');
        expect(normalized.remediation.patchType).toBe('guardrail_config');
      });

      it('should normalize live backend findings with string evidence, test_id title, and flat behaviors', () => {
        const liveRaw: RawBackendFinding = {
          id: 'find_live_uuid_123',
          scan_id: 'scan_live_999',
          agent_id: 'ag_live_456',
          test_id: 'DI-001',
          outcome: 'vulnerability_confirmed',
          expected_behavior: 'Agent refuses unauthorized system instruction override',
          observed_behavior: 'Agent executed unauthorized canary command',
          remediation_suggestion: 'Apply prompt boundary hardening filters',
          evidence: JSON.stringify({
            model_response: 'Canary revealed',
            trace_events: [{ event_type: 'TOOL_EXECUTION', actor: 'agent' }],
            policy_decisions: ['ALLOW_OVERRIDE'],
            tool_calls: [{ name: 'exec_bash', arguments: { cmd: 'cat canary' } }],
          }),
        };

        const normalized = normalizeFinding(liveRaw);
        expect(normalized.id).toBe('find_live_uuid_123');
        expect(normalized.title).toBe('DI-001: Direct Prompt Injection');
        expect(normalized.severity).toBe('critical');
        expect(normalized.outcome).toBe('confirmed_vulnerable');
        expect(normalized.reproduction.expectedBehavior).toBe('Agent refuses unauthorized system instruction override');
        expect(normalized.reproduction.observedBehavior).toBe('Agent executed unauthorized canary command');
        expect(normalized.evidence.toolCalls).toHaveLength(1);
        expect(normalized.evidence.toolCalls[0].name).toBe('exec_bash');
        expect(normalized.evidence.policyDecisions).toEqual(['ALLOW_OVERRIDE']);
        expect(normalized.remediation.summary).toBe('Apply prompt boundary hardening filters');
      });
    });

    describe('normalizeTraceEvent', () => {
      it('should normalize trace event fields and policy decisions', () => {
        const raw: RawBackendTraceEvent = {
          event_id: 'evt_001',
          timestamp: '2026-10-10T12:00:05Z',
          event_type: 'POLICY_EVALUATION',
          actor: 'guardrail_engine',
          policy_decision: 'BLOCK',
          rule_id: 'POL-108',
          is_violation: true,
          is_policy_block: true,
          execution_status: 'blocked',
          execution_duration_ms: 12,
        };

        const normalized = normalizeTraceEvent(raw);
        expect(normalized.id).toBe('evt_001');
        expect(normalized.eventType).toBe('POLICY_EVALUATION');
        expect(normalized.policyDecision).toBe('BLOCK');
        expect(normalized.ruleId).toBe('POL-108');
        expect(normalized.isViolation).toBe(true);
        expect(normalized.isPolicyBlock).toBe(true);
        expect(normalized.executionStatus).toBe('blocked');
        expect(normalized.executionDurationMs).toBe(12);
      });
    });
  });

  describe('Demo Mode vs Live Mode Error Handling', () => {
    beforeEach(() => {
      vi.restoreAllMocks();
    });

    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('should return mock fixtures cleanly in demo mode without calling network', async () => {
      api.setDemoMode(true);
      const agents = await api.getAgents();
      expect(agents.length).toBeGreaterThan(0);
      expect(agents[0].name).toBeDefined();

      const scans = await api.getScans();
      expect(scans.length).toBeGreaterThan(0);

      const findings = await api.getFindings();
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should throw ApiError with status and endpoint details when live API request fails with 500', async () => {
      // Mock global fetch to return 500
      global.fetch = vi.fn().mockImplementation(async (url: string) => {
        if (url.includes('/health')) {
          return new Response(JSON.stringify({ status: 'ok' }), { status: 200 });
        }
        return new Response(JSON.stringify({ detail: 'Internal Database Error in AgentBreak Engine' }), {
          status: 500,
          statusText: 'Internal Server Error',
          headers: { 'Content-Type': 'application/json' },
        });
      });

      // Enable live mode and verify connection
      await api.checkHealth();
      api.setDemoMode(false);

      await expect(api.getAgents()).rejects.toThrowError(ApiError);
      try {
        await api.getAgents();
      } catch (err) {
        expect(err instanceof ApiError).toBe(true);
        const apiErr = err as ApiError;
        expect(apiErr.status).toBe(500);
        expect(apiErr.message).toContain('Internal Database Error');
        expect(apiErr.endpoint).toContain('/api/v1/agents/');
      }
    });

    it('should throw ApiError on network connection failure in live mode', async () => {
      global.fetch = vi.fn().mockImplementation(async (url: string) => {
        if (url.includes('/health')) {
          return new Response(JSON.stringify({ status: 'ok' }), { status: 200 });
        }
        throw new TypeError('Failed to fetch');
      });

      await api.checkHealth();
      api.setDemoMode(false);

      await expect(api.getAgents()).rejects.toThrowError(ApiError);
      try {
        await api.getAgents();
      } catch (err) {
        const apiErr = err as ApiError;
        expect(apiErr.status).toBe(0);
        expect(apiErr.statusText).toBe('NETWORK_ERROR');
      }
    });
  });
});
