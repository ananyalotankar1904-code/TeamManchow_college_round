import {
  Agent,
  SecurityScan,
  SecurityFinding,
  TraceEvent,
  FixLoopSession,
  AssessmentReport,
  ApiConnectionStatus,
  AttackCategory,
  AttackOutcome,
  Severity,
  AgentFramework,
  TraceEventType,
  FixLoopVerdict,
  RemediationSuggestion,
} from '../types';
import {
  MOCK_AGENTS,
  MOCK_SCANS,
  MOCK_FINDINGS,
  MOCK_TRACE_EVENTS_RAG,
  MOCK_FIXLOOP_SESSION_RAG,
  MOCK_REGRESSION_TESTS,
  MOCK_REPORT_DATA,
} from '../mocks/scanData';

export const DEFAULT_API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

export class ApiError extends Error {
  public status: number;
  public statusText: string;
  public endpoint: string;
  public data?: unknown;

  constructor(message: string, status: number, statusText: string, endpoint: string, data?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.statusText = statusText;
    this.endpoint = endpoint;
    this.data = data;
  }
}

/**
 * Builds a clean, fully-qualified URL without duplicated /api/v1 or /api prefixes or double slashes.
 */
export function buildApiUrl(baseUrl: string, endpointPath: string): string {
  const cleanBase = (baseUrl || 'http://localhost:8000').trim().replace(/\/+$/, '');
  const cleanPath = endpointPath.startsWith('/') ? endpointPath : `/${endpointPath}`;

  // Handle case where baseUrl already ends with /api/v1 and endpointPath begins with /api/v1
  if (cleanBase.endsWith('/api/v1') && cleanPath.startsWith('/api/v1')) {
    return `${cleanBase}${cleanPath.slice('/api/v1'.length)}`;
  }
  // Handle case where baseUrl ends with /api and endpointPath begins with /api
  if (cleanBase.endsWith('/api') && cleanPath.startsWith('/api/')) {
    return `${cleanBase}${cleanPath.slice('/api'.length)}`;
  }

  return `${cleanBase}${cleanPath}`;
}

// Raw backend Pydantic payload types
export interface RawBackendAgent {
  id?: string;
  agent_id?: string;
  name?: string;
  identifier?: string;
  framework?: string;
  execution_method?: string;
  executionMethod?: string;
  base_url?: string;
  baseUrl?: string;
  description?: string;
  tools?: string[];
  permissions?: string[];
  environment?: string;
  created_at?: string;
  createdAt?: string;
  status?: string;
  risk_score?: number | null;
  riskScore?: number | null;
  scans_count?: number;
  scansCount?: number;
  critical_count?: number;
  criticalCount?: number;
}

export interface RawBackendScan {
  id?: string;
  scan_id?: string;
  agent_id?: string;
  agentId?: string;
  agent_name?: string;
  agentName?: string;
  created_at?: string;
  createdAt?: string;
  completed_at?: string | null;
  completedAt?: string | null;
  duration_ms?: number | null;
  durationMs?: number | null;
  status?: string;
  mode?: string;
  categories_tested?: string[];
  categoriesTested?: string[];
  total_tests?: number;
  totalTests?: number;
  confirmed_findings?: number;
  confirmedFindings?: number;
  blocked_attacks?: number;
  blockedAttacks?: number;
  inconclusive_tests?: number;
  inconclusiveTests?: number;
  findings?: RawBackendFinding[];
}

export interface RawBackendFinding {
  id?: string;
  finding_id?: string;
  scan_id?: string;
  scanId?: string;
  agent_id?: string;
  agentId?: string;
  agent_name?: string;
  agentName?: string;
  title?: string;
  name?: string;
  severity?: string;
  confidence?: string;
  category?: string;
  attack_category?: string;
  outcome?: string;
  attack_outcome?: string;
  execution_outcome?: string;
  security_verdict?: string;
  fix_loop_verdict?: string;
  fixLoopVerdict?: string;
  status?: string;
  description?: string;
  technical_analysis?: string;
  technicalAnalysis?: string;
  affected_tool?: string;
  affectedTool?: string;
  affected_resource?: string;
  affectedResource?: string;
  reproduction?: {
    test_input?: string;
    testInput?: string;
    vector_payload?: string;
    vectorPayload?: string;
    expected_behavior?: string;
    expectedBehavior?: string;
    observed_behavior?: string;
    observedBehavior?: string;
    result?: string;
  };
  impact?: string;
  remediation?: {
    summary?: string;
    patch_type?: string;
    patchType?: string;
    proposed_patch?: string;
    proposedPatch?: string;
    applied_patch?: string;
    appliedPatch?: string;
    code_diff?: string;
    codeDiff?: string;
    reference_links?: string[];
    referenceLinks?: string[];
  };
  created_at?: string;
  createdAt?: string;
  // Flat fields emitted by live security_engine (no nested sub-objects)
  test_id?: string;
  expected_behavior?: string;
  observed_behavior?: string;
  remediation_suggestion?: string;
  trace_id?: string;
  // String-serialised evidence blob from live DB rows
  evidence?: string | {
    trace_id?: string;
    traceId?: string;
    trace_events?: RawBackendTraceEvent[];
    traceEvents?: RawBackendTraceEvent[];
    tool_calls?: Array<{
      name?: string;
      arguments?: Record<string, unknown>;
      response?: unknown;
      timestamp?: string;
    }>;
    toolCalls?: Array<{
      name?: string;
      arguments?: Record<string, unknown>;
      response?: unknown;
      timestamp?: string;
    }>;
    raw_payload?: string;
    rawPayload?: string;
    policy_decisions?: string[];
    policyDecisions?: string[];
    evidence_notes?: string;
    evidenceNotes?: string;
    model_response?: string;
  };
}

export interface RawBackendTraceEvent {
  id?: string;
  event_id?: string;
  timestamp?: string;
  event_type?: string;
  eventType?: string;
  actor?: string;
  tool_name?: string;
  toolName?: string;
  input?: string | Record<string, unknown>;
  output?: string | Record<string, unknown>;
  arguments?: Record<string, unknown>;
  policy_decision?: string;
  policyDecision?: string;
  rule_id?: string;
  ruleId?: string;
  is_violation?: boolean;
  isViolation?: boolean;
  is_policy_block?: boolean;
  isPolicyBlock?: boolean;
  execution_status?: string;
  executionStatus?: string;
  execution_duration_ms?: number;
  executionDurationMs?: number;
  correlation_id?: string;
  correlationId?: string;
  related_finding_id?: string;
  relatedFindingId?: string;
  details?: string;
}

/**
 * Normalizes a raw agent object from backend schemas to the frontend Agent interface.
 */
export function normalizeAgent(raw: RawBackendAgent): Agent {
  return {
    id: raw.agent_id || raw.id || `ag_${Date.now().toString(36)}`,
    name: raw.name || 'Unnamed Agent',
    identifier: raw.identifier || (raw.name ? raw.name.toLowerCase().replace(/\s+/g, '-') : 'agent'),
    framework: (raw.framework as AgentFramework) || 'Custom Adapter',
    executionMethod: (raw.execution_method || raw.executionMethod || 'http_endpoint') as 'local_adapter' | 'http_endpoint' | 'subagent_runner',
    baseUrl: raw.base_url || raw.baseUrl || '',
    description: raw.description || '',
    tools: Array.isArray(raw.tools) ? raw.tools : [],
    permissions: Array.isArray(raw.permissions) ? raw.permissions : [],
    environment: (raw.environment as 'local_lab' | 'staging_sandbox' | 'isolated_vm') || 'local_lab',
    createdAt: raw.created_at || raw.createdAt || new Date().toISOString(),
    status: (raw.status as 'active' | 'evaluating' | 'disabled') || 'active',
    riskScore: raw.risk_score !== undefined && raw.risk_score !== null ? raw.risk_score : (raw.riskScore !== undefined && raw.riskScore !== null ? raw.riskScore : undefined),
    scansCount: raw.scans_count ?? raw.scansCount ?? 0,
    criticalCount: raw.critical_count ?? raw.criticalCount ?? 0,
  };
}

/**
 * Normalizes a raw scan object from backend schemas to the frontend SecurityScan interface.
 */
export function normalizeScan(raw: RawBackendScan): SecurityScan {
  const categoriesTested = (raw.categories_tested || raw.categoriesTested || []) as AttackCategory[];
  const findings = Array.isArray(raw.findings) ? raw.findings.map(normalizeFinding) : [];

  return {
    id: raw.scan_id || raw.id || `scan_${Date.now().toString(36)}`,
    agentId: raw.agent_id || raw.agentId || '',
    agentName: raw.agent_name || raw.agentName || 'Target Agent',
    createdAt: raw.created_at || raw.createdAt || new Date().toISOString(),
    completedAt: raw.completed_at || raw.completedAt || undefined,
    durationMs: raw.duration_ms ?? raw.durationMs ?? undefined,
    status: (raw.status as SecurityScan['status']) || 'queued',
    mode: (raw.mode as 'fast' | 'comprehensive' | 'adversarial') || 'fast',
    categoriesTested,
    totalTests: raw.total_tests ?? raw.totalTests ?? (categoriesTested.length > 0 ? categoriesTested.length * 3 : 0),
    confirmedFindings: raw.confirmed_findings ?? raw.confirmedFindings ?? findings.filter((f) => f.outcome === 'confirmed_vulnerable').length,
    blockedAttacks: raw.blocked_attacks ?? raw.blockedAttacks ?? findings.filter((f) => f.outcome === 'blocked').length,
    inconclusiveTests: raw.inconclusive_tests ?? raw.inconclusiveTests ?? findings.filter((f) => f.outcome === 'inconclusive').length,
    findings,
  };
}

/**
 * Normalizes a raw finding object from backend schemas to the frontend SecurityFinding interface.
 */
/** Maps security engine test_id codes to human-readable attack category names. */
const TEST_ID_TITLE_MAP: Record<string, string> = {
  'DI-001': 'Direct Prompt Injection',
  'DI-002': 'Indirect Prompt Injection',
  'DI-003': 'System Prompt Exfiltration',
  'TI-001': 'Unauthorized Tool Invocation',
  'TI-002': 'Tool Parameter Tampering',
  'TI-003': 'Permission Boundary Escape',
  'MI-001': 'Memory Poisoning',
  'MI-002': 'Context Window Manipulation',
  'MS-001': 'Multi-Stage Attack Chain',
  'MS-002': 'Privilege Escalation Chain',
  'RA-001': 'RAG Data Exfiltration',
  'RA-002': 'RAG Poisoning',
};

export function normalizeFinding(raw: RawBackendFinding): SecurityFinding {
  const reproduction = raw.reproduction || {};
  const remediation = raw.remediation || {};

  let parsedEvidence: Record<string, any> = {};
  if (typeof raw.evidence === 'object' && raw.evidence !== null) {
    parsedEvidence = raw.evidence as Record<string, any>;
  } else if (typeof raw.evidence === 'string') {
    try {
      parsedEvidence = JSON.parse(raw.evidence);
    } catch {
      parsedEvidence = { rawPayload: raw.evidence, evidenceNotes: raw.evidence };
    }
  }

  // Preserve execution outcome and security verdicts cleanly
  const rawOutcome = (raw.outcome || raw.attack_outcome || raw.execution_outcome || 'attempted').toLowerCase();
  let normalizedOutcome: AttackOutcome = 'attempted';
  if (rawOutcome === 'confirmed_vulnerable' || rawOutcome === 'vulnerability_confirmed' || rawOutcome === 'vulnerable') normalizedOutcome = 'confirmed_vulnerable';
  else if (rawOutcome === 'blocked' || rawOutcome === 'prevented') normalizedOutcome = 'blocked';
  else if (rawOutcome === 'executed' || rawOutcome === 'successful') normalizedOutcome = 'executed';
  else if (rawOutcome === 'inconclusive' || rawOutcome === 'unknown') normalizedOutcome = 'inconclusive';

  const rawVerdict = (raw.fix_loop_verdict || raw.security_verdict || raw.fixLoopVerdict || '').toLowerCase();
  let normalizedVerdict: FixLoopVerdict = 'not_yet_tested';
  if (rawVerdict === 'mitigation_verified' || rawVerdict === 'verified_fixed') normalizedVerdict = 'mitigation_verified';
  else if (rawVerdict === 'still_vulnerable' || rawVerdict === 'confirmed_vulnerable' || rawVerdict === 'vulnerability_confirmed' || rawVerdict === 'vulnerable') normalizedVerdict = 'still_vulnerable';
  else if (rawVerdict === 'regression_failure') normalizedVerdict = 'regression_failure';
  else if (rawVerdict === 'inconclusive') normalizedVerdict = 'inconclusive';

  // Resolve title: prefer explicit title, then test_id lookup, then category-based fallback
  const testId = raw.test_id;
  const title =
    raw.title ||
    raw.name ||
    (testId
      ? `${testId}: ${TEST_ID_TITLE_MAP[testId] || (raw.category || 'Security Finding').replace(/_/g, ' ')}`
      : 'Security Finding');

  // Infer severity: confirmed vulnerabilities are at least critical when no explicit severity set
  let severity = (raw.severity?.toLowerCase() as Severity) || 'medium';
  if (!raw.severity) {
    if (normalizedOutcome === 'confirmed_vulnerable') {
      severity = 'critical';
    } else if (normalizedOutcome === 'executed') {
      severity = 'high';
    }
  }

  const expectedBehavior =
    reproduction.expected_behavior ||
    reproduction.expectedBehavior ||
    raw.expected_behavior ||
    '';
  const observedBehavior =
    reproduction.observed_behavior ||
    reproduction.observedBehavior ||
    raw.observed_behavior ||
    '';

  const description =
    raw.description ||
    observedBehavior ||
    expectedBehavior ||
    'Observed security evaluation behavior against target agent.';

  const technicalAnalysis =
    raw.technical_analysis ||
    raw.technicalAnalysis ||
    (typeof raw.evidence === 'string'
      ? raw.evidence
      : 'Deterministic attack vector execution record.');

  return {
    id: raw.finding_id || raw.id || `FND-${Date.now().toString(36)}`,
    scanId: raw.scan_id || raw.scanId || '',
    agentId: raw.agent_id || raw.agentId || '',
    agentName: raw.agent_name || raw.agentName || 'Target Agent',
    title,
    severity,
    confidence: (raw.confidence as SecurityFinding['confidence']) || 'CONFIRMED',
    category: (raw.category || raw.attack_category || 'direct_prompt_injection') as AttackCategory,
    outcome: normalizedOutcome,
    status: (raw.status as SecurityFinding['status']) || 'open',
    description,
    technicalAnalysis,
    affectedTool: raw.affected_tool || raw.affectedTool,
    affectedResource: raw.affected_resource || raw.affectedResource,
    reproduction: {
      testInput: reproduction.test_input || reproduction.testInput || (raw as any).test_id || '',
      vectorPayload: reproduction.vector_payload || reproduction.vectorPayload || '',
      expectedBehavior,
      observedBehavior,
      result: reproduction.result || `Outcome: ${normalizedOutcome}`,
    },
    evidence: {
      traceId: parsedEvidence.trace_id || parsedEvidence.traceId || (raw as any).trace_id || '',
      traceEvents: Array.isArray(parsedEvidence.trace_events || parsedEvidence.traceEvents)
        ? (parsedEvidence.trace_events || parsedEvidence.traceEvents)!.map(normalizeTraceEvent)
        : [],
      toolCalls: (parsedEvidence.tool_calls || parsedEvidence.toolCalls || []).map((tc: any) => ({
        name: tc.name || '',
        arguments: tc.arguments || {},
        response: tc.response,
        timestamp: tc.timestamp || new Date().toISOString(),
      })),
      rawPayload: parsedEvidence.raw_payload || parsedEvidence.rawPayload || (typeof raw.evidence === 'string' ? raw.evidence : ''),
      policyDecisions: parsedEvidence.policy_decisions || parsedEvidence.policyDecisions || [],
      evidenceNotes: parsedEvidence.evidence_notes || parsedEvidence.evidenceNotes,
    },
    impact: raw.impact || '',
    remediation: {
      summary: remediation.summary || raw.remediation_suggestion || 'Apply defensive guardrail to agent prompt and tool parameter boundaries.',
      patchType: (remediation.patch_type || remediation.patchType || 'system_prompt') as RemediationSuggestion['patchType'],
      proposedPatch: remediation.proposed_patch || remediation.proposedPatch || '',
      appliedPatch: remediation.applied_patch || remediation.appliedPatch,
      codeDiff: remediation.code_diff || remediation.codeDiff,
      referenceLinks: remediation.reference_links || remediation.referenceLinks,
    },
    fixLoopVerdict: normalizedVerdict,
    createdAt: raw.created_at || raw.createdAt || new Date().toISOString(),
    // Carry live trace_id so detail page can offer trace link
    ...(raw.trace_id ? { traceId: raw.trace_id } : {}),
  } as SecurityFinding;
}

/**
 * Normalizes a raw trace event from backend schemas to the frontend TraceEvent interface.
 */
export function normalizeTraceEvent(raw: RawBackendTraceEvent): TraceEvent {
  return {
    id: raw.event_id || raw.id || `evt_${Date.now().toString(36)}`,
    timestamp: raw.timestamp || new Date().toISOString(),
    eventType: (raw.event_type || raw.eventType || 'MODEL_DECISION') as TraceEventType,
    actor: raw.actor || 'agent',
    toolName: raw.tool_name || raw.toolName,
    input: raw.input,
    output: raw.output,
    arguments: raw.arguments,
    policyDecision: (raw.policy_decision || raw.policyDecision) as TraceEvent['policyDecision'],
    ruleId: raw.rule_id || raw.ruleId,
    isViolation: raw.is_violation ?? raw.isViolation ?? false,
    isPolicyBlock: raw.is_policy_block ?? raw.isPolicyBlock ?? false,
    executionStatus: (raw.execution_status || raw.executionStatus || 'success') as TraceEvent['executionStatus'],
    executionDurationMs: raw.execution_duration_ms ?? raw.executionDurationMs,
    correlationId: raw.correlation_id || raw.correlationId,
    relatedFindingId: raw.related_finding_id || raw.relatedFindingId,
    details: raw.details,
  };
}

class ApiService {
  private baseUrl: string = DEFAULT_API_BASE;
  private isDemoMode: boolean = false;
  private connectionStatus: ApiConnectionStatus = {
    connected: false,
    isDemoMode: true,
    endpoint: DEFAULT_API_BASE,
    lastChecked: new Date().toISOString(),
    message: 'Demo mode active. Using realistic offline evaluation fixtures.',
  };

  // In-memory state for demo mode
  private demoAgents: Agent[] = [...MOCK_AGENTS];
  private demoScans: SecurityScan[] = [...MOCK_SCANS];
  private demoFindings: SecurityFinding[] = [...MOCK_FINDINGS];
  private demoFixLoopSessions: Map<string, FixLoopSession> = new Map([
    ['FND-2026-0891', { ...MOCK_FIXLOOP_SESSION_RAG }],
  ]);

  constructor() {
    this.checkHealth();
  }

  public setBaseUrl(url: string): Promise<ApiConnectionStatus> {
    this.baseUrl = url.trim().replace(/\/+$/, '');
    this.connectionStatus.endpoint = this.baseUrl;
    return this.checkHealth();
  }

  public getBaseUrl(): string {
    return this.baseUrl;
  }

  public setDemoMode(enable: boolean) {
    this.isDemoMode = enable;
    this.connectionStatus.isDemoMode = enable;
    if (enable) {
      this.connectionStatus.message = 'Demo mode manually enabled. Using local security fixtures.';
    } else {
      this.checkHealth();
    }
  }

  public getStatus(): ApiConnectionStatus {
    return { ...this.connectionStatus };
  }

  /**
   * Health Check: tests FastAPI backend connectivity at /health or /api/v1/health.
   */
  public async checkHealth(): Promise<ApiConnectionStatus> {
    const startTime = performance.now();
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2500);

      // Try /health first, then /api/v1/health
      let response = await fetch(buildApiUrl(this.baseUrl, '/health'), {
        signal: controller.signal,
        headers: { Accept: 'application/json' },
      }).catch(async () => {
        return await fetch(buildApiUrl(this.baseUrl, '/api/v1/health'), {
          signal: controller.signal,
          headers: { Accept: 'application/json' },
        });
      });

      if (!response.ok) {
        response = await fetch(buildApiUrl(this.baseUrl, '/api/health'), {
          signal: controller.signal,
          headers: { Accept: 'application/json' },
        });
      }

      clearTimeout(timeoutId);
      const latencyMs = Math.round(performance.now() - startTime);

      if (response && response.ok) {
        this.connectionStatus = {
          connected: true,
          isDemoMode: this.isDemoMode,
          latencyMs,
          endpoint: this.baseUrl,
          lastChecked: new Date().toISOString(),
          message: `Connected · ${latencyMs} ms`,
        };
      } else {
        throw new Error(`HTTP ${response?.status || 'unreachable'}`);
      }
    } catch {
      this.connectionStatus = {
        connected: false,
        isDemoMode: true,
        endpoint: this.baseUrl,
        lastChecked: new Date().toISOString(),
        message: 'Backend unavailable · Running in local Demo Mode',
      };
    }

    return { ...this.connectionStatus };
  }

  /**
   * Helper for live requests.
   * Throws ApiError on non-2xx status in live mode.
   */
  private async liveFetch<T>(endpointPath: string, options?: RequestInit): Promise<T> {
    const url = buildApiUrl(this.baseUrl, endpointPath);
    let res: Response;
    try {
      res = await fetch(url, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          ...(options?.headers || {}),
        },
      });
    } catch (err: unknown) {
      const networkMsg = err instanceof Error ? err.message : 'Network request failed';
      throw new ApiError(`Network connection to ${url} failed: ${networkMsg}`, 0, 'NETWORK_ERROR', url);
    }

    if (!res.ok) {
      let errorData: unknown;
      try {
        errorData = await res.json();
      } catch {
        try {
          errorData = await res.text();
        } catch {
          errorData = undefined;
        }
      }
      const message = typeof errorData === 'object' && errorData && 'detail' in errorData
        ? String((errorData as { detail: unknown }).detail)
        : `Request to ${endpointPath} failed with HTTP ${res.status}: ${res.statusText}`;
      throw new ApiError(message, res.status, res.statusText, url, errorData);
    }

    return (await res.json()) as T;
  }

  // ==========================================
  // 1. Target Agents API
  // ==========================================

  /**
   * GET /api/v1/agents/ (or single agent fallback)
   */
  public async getAgents(): Promise<Agent[]> {
    if (!this.isDemoMode && this.connectionStatus.connected) {
      try {
        const rawList = await this.liveFetch<RawBackendAgent[] | { agents?: RawBackendAgent[]; items?: RawBackendAgent[] }>('/api/v1/agents/');
        const items = Array.isArray(rawList)
          ? rawList
          : (rawList.agents || rawList.items || []);
        return items.map(normalizeAgent);
      } catch (err) {
        throw err;
      }
    }
    return [...this.demoAgents];
  }

  /**
   * GET /api/v1/agents/{agent_id}
   */
  public async getAgent(agentId: string): Promise<Agent | undefined> {
    if (!this.isDemoMode && this.connectionStatus.connected) {
      try {
        const raw = await this.liveFetch<RawBackendAgent>(`/api/v1/agents/${agentId}`);
        return normalizeAgent(raw);
      } catch (err) {
        throw err;
      }
    }
    return this.demoAgents.find((a) => a.id === agentId);
  }

  /**
   * POST /api/v1/agents/
   */
  public async registerAgent(agentData: Omit<Agent, 'id' | 'createdAt' | 'scansCount' | 'criticalCount'>): Promise<Agent> {
    if (!this.isDemoMode && this.connectionStatus.connected) {
      const payload: RawBackendAgent = {
        name: agentData.name,
        identifier: agentData.identifier,
        framework: agentData.framework,
        execution_method: agentData.executionMethod,
        base_url: agentData.baseUrl,
        description: agentData.description,
        tools: agentData.tools,
        permissions: agentData.permissions,
        environment: agentData.environment,
        status: agentData.status,
      };

      const raw = await this.liveFetch<RawBackendAgent>('/api/v1/agents/', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      return normalizeAgent(raw);
    }

    // Demo Mode: Local registration
    const newAgent: Agent = {
      ...agentData,
      id: `ag_${Date.now().toString(36)}`,
      createdAt: new Date().toISOString(),
      scansCount: 0,
      criticalCount: 0,
      status: 'active',
      riskScore: undefined, // Honest: No fabricated default
    };
    this.demoAgents.unshift(newAgent);
    return newAgent;
  }

  // ==========================================
  // 2. Security Scans API
  // ==========================================

  /**
   * GET /api/v1/scans/ or GET /api/v1/scans/{scan_id}
   */
  public async getScans(): Promise<SecurityScan[]> {
    if (!this.isDemoMode && this.connectionStatus.connected) {
      try {
        const rawList = await this.liveFetch<RawBackendScan[] | { scans?: RawBackendScan[]; items?: RawBackendScan[] }>('/api/v1/scans/');
        const items = Array.isArray(rawList)
          ? rawList
          : (rawList.scans || rawList.items || []);
        return items.map(normalizeScan);
      } catch (err) {
        throw err;
      }
    }
    return [...this.demoScans];
  }

  /**
   * GET /api/v1/scans/{scan_id}
   */
  public async getScan(scanId: string): Promise<SecurityScan | undefined> {
    if (!this.isDemoMode && this.connectionStatus.connected) {
      try {
        const raw = await this.liveFetch<RawBackendScan>(`/api/v1/scans/${scanId}`);
        return normalizeScan(raw);
      } catch (err) {
        throw err;
      }
    }
    return this.demoScans.find((s) => s.id === scanId);
  }

  /**
   * POST /api/v1/scans/
   */
  public async startScan(config: {
    agentId: string;
    categories: AttackCategory[];
    mode: 'fast' | 'comprehensive' | 'adversarial';
  }): Promise<SecurityScan> {
    if (!this.isDemoMode && this.connectionStatus.connected) {
      const payload = {
        agent_id: config.agentId,
        categories: config.categories,
        mode: config.mode,
      };

      const raw = await this.liveFetch<RawBackendScan>('/api/v1/scans/', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      return normalizeScan(raw);
    }

    // Demo Mode: Simulate scan creation
    const agent = this.demoAgents.find((a) => a.id === config.agentId);
    const agentName = agent ? agent.name : 'Target Agent';

    const newScan: SecurityScan = {
      id: `scan_${Date.now().toString(36)}`,
      agentId: config.agentId,
      agentName,
      createdAt: new Date().toISOString(),
      status: 'running',
      mode: config.mode,
      categoriesTested: config.categories,
      totalTests: config.categories.length * 3,
      confirmedFindings: 0,
      blockedAttacks: 0,
      inconclusiveTests: 0,
      findings: [],
    };

    this.demoScans.unshift(newScan);
    return newScan;
  }

  /**
   * Real Polling Mechanism: Polls GET /api/v1/scans/{scan_id} until terminal state.
   */
  public async pollScanUntilDone(
    scanId: string,
    onProgress?: (scan: SecurityScan) => void,
    intervalMs = 2000,
    maxAttempts = 60
  ): Promise<SecurityScan> {
    if (this.isDemoMode || !this.connectionStatus.connected) {
      const scan = this.demoScans.find((s) => s.id === scanId);
      if (scan) {
        scan.status = 'completed';
        scan.completedAt = new Date().toISOString();
        if (onProgress) onProgress(scan);
        return scan;
      }
    }

    let attempts = 0;
    while (attempts < maxAttempts) {
      const scan = await this.getScan(scanId);
      if (!scan) throw new ApiError(`Scan ${scanId} not found`, 404, 'NOT_FOUND', `/api/v1/scans/${scanId}`);

      if (onProgress) onProgress(scan);

      if (scan.status === 'completed' || scan.status === 'failed' || scan.status === 'cancelled') {
        return scan;
      }

      await new Promise((resolve) => setTimeout(resolve, intervalMs));
      attempts++;
    }

    throw new ApiError(`Scan polling for ${scanId} timed out after ${maxAttempts * intervalMs / 1000}s`, 408, 'TIMEOUT', `/api/v1/scans/${scanId}`);
  }

  // ==========================================
  // 3. Security Findings API
  // ==========================================

  /**
   * GET /api/v1/findings/{scan_id}
   */
  public async getFindings(scanId?: string): Promise<SecurityFinding[]> {
    if (!this.isDemoMode && this.connectionStatus.connected) {
      try {
        const endpoint = scanId ? `/api/v1/findings/${scanId}` : '/api/v1/findings/';
        const raw = await this.liveFetch<RawBackendFinding[] | { findings?: RawBackendFinding[]; items?: RawBackendFinding[] }>(endpoint);
        const items = Array.isArray(raw) ? raw : (raw.findings || raw.items || []);
        return items.map(normalizeFinding);
      } catch (err) {
        throw err;
      }
    }

    if (scanId) {
      return this.demoFindings.filter((f) => f.scanId === scanId);
    }
    return [...this.demoFindings];
  }

  public async getFinding(findingId: string): Promise<SecurityFinding | undefined> {
    if (!this.isDemoMode && this.connectionStatus.connected) {
      try {
        const raw = await this.liveFetch<RawBackendFinding | RawBackendFinding[]>(`/api/v1/findings/detail/${findingId}`);
        if (raw && !Array.isArray(raw) && (raw.id || raw.finding_id)) {
          return normalizeFinding(raw);
        }
      } catch {
        try {
          const raw = await this.liveFetch<RawBackendFinding | RawBackendFinding[]>(`/api/v1/findings/${findingId}`);
          if (Array.isArray(raw)) {
            if (raw.length > 0) return normalizeFinding(raw[0]);
          } else if (raw && (raw.id || raw.finding_id)) {
            return normalizeFinding(raw);
          }
        } catch {
          // Fallback to getFindings
        }
      }
      const findings = await this.getFindings();
      return findings.find((f) => f.id === findingId || (f as any).testId === findingId || (f as any).test_id === findingId);
    }
    return this.demoFindings.find((f) => f.id === findingId || (f as any).testId === findingId || (f as any).test_id === findingId);
  }

  // ==========================================
  // 4. Attack Traces API
  // ==========================================

  /**
   * GET /api/v1/traces/{trace_id}
   * In live mode: fetches real trace events from backend. Returns empty array (not mock) if not found.
   * In demo mode: returns mock events so demo flow is unaffected.
   */
  public async getTraceEvents(traceId: string): Promise<TraceEvent[]> {
    if (!this.isDemoMode && this.connectionStatus.connected) {
      // Live mode: call real backend; throw so caller can show 'unavailable' state
      const raw = await this.liveFetch<{ id?: string; events?: unknown[]; trace_events?: unknown[] } | unknown[]>(`/api/v1/traces/${traceId}`);
      const items: unknown[] = Array.isArray(raw)
        ? raw
        : ((raw as any).events || (raw as any).trace_events || []);
      return items.map((item) => normalizeTraceEvent(item as RawBackendTraceEvent));
    }
    return [...MOCK_TRACE_EVENTS_RAG];
  }

  // ==========================================
  // 5. FixLoop Verification Service (Pending on Backend)
  // ==========================================

  public async getFixLoopSession(findingId: string): Promise<FixLoopSession> {
    if (!this.isDemoMode && this.connectionStatus.connected) {
      try {
        let raw;
        try {
          raw = await this.liveFetch<any>(`/api/v1/fixloop/${findingId}`);
        } catch {
          raw = await this.liveFetch<any>(`/api/v1/fixloop/${findingId}/recommendation`, { method: 'POST' });
        }
        const finding = await this.getFinding(findingId);
        return {
          findingId: raw.finding_id || raw.findingId,
          finding: finding!,
          step: raw.verdict === 'proposed' ? 1 : raw.verdict === 'verification_pending' ? 3 : 5,
          proposedMitigation: raw.proposed_mitigation || raw.proposedMitigation,
          mitigationApplied: raw.mitigation_applied ?? raw.mitigationApplied ?? false,
          retestRunId: raw.retest_run_id || raw.retestRunId,
          retestOutcome: raw.retest_outcome || raw.retestOutcome,
          regressionTests: raw.regression_tests || raw.regressionTests || [],
          verdict: raw.verdict,
          comparisonNotes: raw.comparison_notes || raw.comparisonNotes,
        };
      } catch (err) {
        throw err;
      }
    }

    if (this.demoFixLoopSessions.has(findingId)) {
      return { ...this.demoFixLoopSessions.get(findingId)! };
    }

    const finding = (await this.getFinding(findingId)) || this.demoFindings[0];
    const session: FixLoopSession = {
      findingId: finding.id,
      finding,
      step: 1,
      proposedMitigation: finding.remediation.proposedPatch,
      mitigationApplied: false,
      regressionTests: MOCK_REGRESSION_TESTS.map((t) => ({ ...t, status: 'skipped' })),
      verdict: 'not_yet_tested',
    };
    this.demoFixLoopSessions.set(findingId, session);
    return session;
  }

  public async applyMitigation(findingId: string, customPatch?: string): Promise<FixLoopSession> {
    // In our backend API, applying mitigation isn't an explicit endpoint, it's just a state. 
    // We can simulate it here in the frontend state even for live connections until a backend route is made, 
    // or just assume verify_fix does it. Actually, verify_fix runs the scan. 
    // For now we just update local state.
    const session = await this.getFixLoopSession(findingId);
    session.mitigationApplied = true;
    session.appliedTimestamp = new Date().toISOString();
    if (customPatch) session.proposedMitigation = customPatch;
    session.step = 3;
    if (this.isDemoMode) {
      this.demoFixLoopSessions.set(findingId, session);
    }
    return { ...session };
  }

  public async runFixLoopRetest(findingId: string): Promise<FixLoopSession> {
    if (!this.isDemoMode && this.connectionStatus.connected) {
      try {
        const raw = await this.liveFetch<any>(`/api/v1/fixloop/${findingId}/verify`, { method: 'POST' });
        const finding = await this.getFinding(findingId);
        return {
          findingId: raw.finding_id || raw.findingId,
          finding: finding!,
          step: 5, // Jump to step 5 as backend verification simulates full run
          proposedMitigation: raw.proposed_mitigation || raw.proposedMitigation,
          mitigationApplied: raw.mitigation_applied ?? raw.mitigationApplied ?? false,
          retestRunId: raw.retest_run_id || raw.retestRunId,
          retestOutcome: raw.retest_outcome || raw.retestOutcome,
          regressionTests: raw.regression_tests || raw.regressionTests || [],
          verdict: raw.verdict,
          comparisonNotes: raw.comparison_notes || raw.comparisonNotes,
        };
      } catch (err) {
        throw err;
      }
    }

    const session = await this.getFixLoopSession(findingId);
    session.retestRunId = `retest_${Date.now().toString(36)}`;
    session.retestTimestamp = new Date().toISOString();
    session.retestOutcome = 'blocked';
    session.retestEvidence =
      `Retest executed against sandbox at ${session.retestTimestamp}. Original adversarial vector was injected. Guardrail prompt boundary held and prevented unauthorized tool invocation. Result: ATTACK BLOCKED.`;
    session.step = 4;
    this.demoFixLoopSessions.set(findingId, session);
    return { ...session };
  }

  public async runRegressionSuite(findingId: string): Promise<FixLoopSession> {
    // Backend verify_fix already simulates regression. We can just return getFixLoopSession or re-call verify.
    if (!this.isDemoMode && this.connectionStatus.connected) {
      return this.getFixLoopSession(findingId);
    }

    const session = await this.getFixLoopSession(findingId);
    session.regressionTests = MOCK_REGRESSION_TESTS.map((t) => ({
      ...t,
      status: 'passed',
    }));
    session.verdict = 'mitigation_verified';
    session.step = 5;
    session.lastRunTimestamp = new Date().toISOString();
    session.comparisonNotes =
      'Before mitigation: Agent executed unauthorized egress tool with credentials.\nAfter mitigation: Retest showed prompt boundary held, attack was blocked, and 12/12 benign tasks passed without regression.';

    const finding = this.demoFindings.find((f) => f.id === findingId);
    if (finding) {
      finding.status = 'verified_fixed';
      finding.fixLoopVerdict = 'mitigation_verified';
    }

    this.demoFixLoopSessions.set(findingId, session);
    return { ...session };
  }

  // ==========================================
  // 6. Security Reports API
  // ==========================================

  public async getReport(scanId: string): Promise<AssessmentReport> {
    if (!this.isDemoMode && this.connectionStatus.connected) {
      try {
        const raw = await this.liveFetch<any>(`/api/v1/reports/${scanId}/export?format=json`);
        // Backend returns ScanReport schema — normalize to AssessmentReport
        return this._normalizeScanReport(raw, scanId);
      } catch (err) {
        // Backend report 404 or 500: fall back to assembled report from live findings
        console.warn(`[AgentBreak] Report endpoint failed for ${scanId}, assembling from findings:`, err);
      }
    }

    // Demo mode OR live fallback: assemble from actual findings (not MOCK_REPORT_DATA for live)
    const scan = await this.getScan(scanId);
    const agent = scan ? await this.getAgent(scan.agentId) : this.demoAgents[0];
    const findings = await this.getFindings(scanId);
    const isLive = !this.isDemoMode && this.connectionStatus.connected;

    return {
      // Only spread MOCK_REPORT_DATA in demo mode; in live mode use real values
      ...(isLive ? {} : MOCK_REPORT_DATA),
      id: `report_${scanId}`,
      generatedAt: new Date().toISOString(),
      scanId,
      agent: agent || (isLive ? { id: scan?.agentId || '', name: 'Registered Agent', identifier: 'live-agent', framework: 'Custom Adapter', executionMethod: 'http_endpoint', baseUrl: '', description: '', tools: [], permissions: [], environment: 'local_lab', createdAt: new Date().toISOString(), status: 'active', scansCount: 1, criticalCount: 0 } : this.demoAgents[0]),
      assessmentScope: scan?.categoriesTested || (isLive ? ['direct_prompt_injection'] : MOCK_REPORT_DATA.assessmentScope),
      executiveSummary: isLive
        ? `Live security assessment of agent ${scan?.agentName || scanId}. ${findings.length} finding(s) recorded. This report was assembled from live scan data.`
        : MOCK_REPORT_DATA.executiveSummary,
      severitySummary: {
        critical: findings.filter((f) => f.severity === 'critical').length,
        high: findings.filter((f) => f.severity === 'high').length,
        medium: findings.filter((f) => f.severity === 'medium').length,
        low: findings.filter((f) => f.severity === 'low').length,
        info: findings.filter((f) => f.severity === 'info').length,
      },
      totalVulnerabilities: findings.filter((f) => f.outcome === 'confirmed_vulnerable' || f.outcome === 'executed').length,
      totalBlocked: findings.filter((f) => f.outcome === 'blocked').length,
      fixLoopVerifiedCount: findings.filter((f) => f.fixLoopVerdict === 'mitigation_verified').length,
      findings: findings.length > 0 ? findings : (isLive ? [] : this.demoFindings),
      methodology: isLive
        ? 'Automated adversarial evaluation using AgentBreak security engine. Attack vectors were injected against the live target agent and responses were evaluated against expected safety boundaries.'
        : MOCK_REPORT_DATA.methodology,
      limitations: isLive
        ? ['Severity is inferred from outcome; DB does not store explicit severity field.', 'Trace events may be sparse depending on agent adapter verbosity.', 'FixLoop verification requires agent endpoint to be reachable at time of retest.']
        : MOCK_REPORT_DATA.limitations,
    };
  }

  /** Converts backend ScanReport JSON schema to frontend AssessmentReport shape. */
  private _normalizeScanReport(raw: any, scanId: string): AssessmentReport {
    const meta = raw.metadata || {};
    const findings: SecurityFinding[] = (raw.findings || []).map((f: any) => {
      const outcome = f.outcome || 'attempted';
      const normalizedOutcome: AttackOutcome =
        outcome === 'vulnerability_confirmed' || outcome === 'confirmed_vulnerable' || outcome === 'vulnerable' ? 'confirmed_vulnerable'
        : outcome === 'blocked' || outcome === 'prevented' ? 'blocked'
        : outcome === 'executed' || outcome === 'successful' ? 'executed'
        : outcome === 'failed' ? 'attempted'
        : 'inconclusive';
      return {
        id: f.finding_id || f.id || '',
        scanId: meta.scan_id || scanId,
        agentId: meta.agent_id || '',
        agentName: 'Target Agent',
        title: f.test_id ? `${f.test_id}: ${TEST_ID_TITLE_MAP[f.test_id] || (f.category || 'Security Finding').replace(/_/g, ' ')}` : 'Security Finding',
        severity: (f.severity === 'unknown' || !f.severity) ? (normalizedOutcome === 'confirmed_vulnerable' ? 'critical' : 'medium') : f.severity,
        confidence: 'CONFIRMED',
        category: (f.category || 'direct_prompt_injection') as AttackCategory,
        outcome: normalizedOutcome,
        status: 'open',
        description: f.observed_behavior || '',
        technicalAnalysis: f.evidence || '',
        reproduction: { testInput: f.test_id || '', vectorPayload: '', expectedBehavior: f.expected_behavior || '', observedBehavior: f.observed_behavior || '', result: `Outcome: ${normalizedOutcome}` },
        evidence: { traceId: f.trace_id || '', traceEvents: [], toolCalls: [], rawPayload: f.evidence || '', policyDecisions: [] },
        impact: '',
        remediation: { summary: 'Apply security guardrails.', patchType: 'system_prompt', proposedPatch: '' },
        fixLoopVerdict: 'not_yet_tested',
        createdAt: new Date().toISOString(),
      } as SecurityFinding;
    });

    const confirmedCount = findings.filter((f) => f.outcome === 'confirmed_vulnerable' || f.outcome === 'executed').length;
    const blockedCount = findings.filter((f) => f.outcome === 'blocked').length;

    return {
      id: `report_${scanId}`,
      generatedAt: raw.generated_at || new Date().toISOString(),
      scanId: meta.scan_id || scanId,
      agent: {
        id: meta.agent_id || '',
        name: 'Target Agent',
        identifier: 'live-target',
        framework: 'Custom Adapter',
        executionMethod: 'http_endpoint',
        baseUrl: '',
        description: raw.provenance?.source_description || '',
        tools: [],
        permissions: [],
        environment: (meta.target_environment as any) || 'local_lab',
        createdAt: meta.started_at || new Date().toISOString(),
        status: 'active',
        scansCount: 1,
        criticalCount: findings.filter((f) => f.severity === 'critical').length,
      },
      assessmentScope: ['direct_prompt_injection'],
      executiveSummary: `${raw.summary_notes || 'AgentBreak security assessment completed.'} Total findings: ${findings.length}. Confirmed vulnerabilities: ${confirmedCount}. Attacks blocked: ${blockedCount}. Data provenance: ${raw.provenance?.provenance_type || 'live'}.`,
      severitySummary: {
        critical: findings.filter((f) => f.severity === 'critical').length,
        high: findings.filter((f) => f.severity === 'high').length,
        medium: findings.filter((f) => f.severity === 'medium').length,
        low: findings.filter((f) => f.severity === 'low').length,
        info: 0,
      },
      totalVulnerabilities: confirmedCount,
      totalBlocked: blockedCount,
      fixLoopVerifiedCount: 0,
      findings,
      methodology: 'Automated adversarial evaluation using AgentBreak security engine against a live target agent.',
      limitations: [
        raw.provenance?.provenance_type === 'mock_demo' ? 'WARNING: This report was generated with a mock agent or mock security engine — data is not from a real target.' : 'Severity inferred from outcome; DB does not store explicit severity.',
        'Trace events may be sparse depending on agent adapter verbosity.',
        'FixLoop verification requires the registered agent endpoint to be reachable.',
      ],
    };
  }
}

export const api = new ApiService();
