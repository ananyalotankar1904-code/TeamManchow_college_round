export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type AttackCategory =
  | 'direct_prompt_injection'
  | 'indirect_rag_injection'
  | 'unauthorized_tool_execution'
  | 'sensitive_data_leakage'
  | 'unsafe_action_execution'
  | 'permission_policy_violation';

export type AttackOutcome =
  | 'attempted'
  | 'blocked'
  | 'executed'
  | 'confirmed_vulnerable'
  | 'inconclusive';

export type ScanStatus =
  | 'idle'
  | 'queued'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled';

export type AgentFramework =
  | 'LangGraph'
  | 'LlamaIndex'
  | 'CrewAI'
  | 'AutoGen'
  | 'Custom Adapter'
  | 'Direct API / OpenAI'
  | 'Anthropic Tool-Calling';

export type TraceEventType =
  | 'USER_INPUT'
  | 'RETRIEVAL'
  | 'MODEL_DECISION'
  | 'TOOL_INVOCATION'
  | 'POLICY_EVALUATION'
  | 'TOOL_RESULT'
  | 'SECURITY_FINDING';

export interface Agent {
  id: string;
  name: string;
  identifier: string;
  framework: AgentFramework;
  executionMethod: 'local_adapter' | 'http_endpoint' | 'subagent_runner';
  baseUrl?: string;
  description: string;
  tools: string[];
  permissions: string[];
  environment: 'local_lab' | 'staging_sandbox' | 'isolated_vm';
  createdAt: string;
  status: 'active' | 'evaluating' | 'disabled';
  riskScore?: number; // 0-100
  scansCount: number;
  criticalCount: number;
}

export interface TraceEvent {
  id: string;
  timestamp: string; // ISO 8601 UTC
  eventType: TraceEventType;
  actor: string;
  toolName?: string;
  input?: string | Record<string, unknown>;
  output?: string | Record<string, unknown>;
  arguments?: Record<string, unknown>;
  policyDecision?: 'ALLOW' | 'BLOCK' | 'WARN' | 'INTERVENE';
  ruleId?: string;
  isViolation?: boolean;
  isPolicyBlock?: boolean;
  executionStatus: 'success' | 'failed' | 'blocked' | 'pending';
  executionDurationMs?: number;
  correlationId?: string;
  relatedFindingId?: string;
  details?: string;
}

export interface ReproductionData {
  testInput: string;
  vectorPayload: string;
  expectedBehavior: string;
  observedBehavior: string;
  result: string;
}

export interface EvidenceData {
  traceId: string;
  traceEvents: TraceEvent[];
  toolCalls: Array<{
    name: string;
    arguments: Record<string, unknown>;
    response: unknown;
    timestamp: string;
  }>;
  rawPayload: string;
  policyDecisions: string[];
  evidenceNotes?: string;
}

export interface RemediationSuggestion {
  summary: string;
  patchType: 'system_prompt' | 'guardrail_config' | 'tool_constraint' | 'policy_rule';
  proposedPatch: string;
  appliedPatch?: string;
  codeDiff?: string;
  referenceLinks?: string[];
}

export type FixLoopVerdict =
  | 'mitigation_verified'
  | 'still_vulnerable'
  | 'inconclusive'
  | 'regression_failure'
  | 'not_yet_tested';

export interface SecurityFinding {
  id: string;
  scanId: string;
  agentId: string;
  agentName: string;
  title: string;
  severity: Severity;
  confidence?: 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'EXPERIMENTAL';
  category: AttackCategory;
  outcome: AttackOutcome;
  status: 'open' | 'remediated' | 'under_review' | 'verified_fixed';
  description: string;
  technicalAnalysis: string;
  affectedTool?: string;
  affectedResource?: string;
  reproduction: ReproductionData;
  evidence: EvidenceData;
  impact: string;
  remediation: RemediationSuggestion;
  fixLoopVerdict?: FixLoopVerdict;
  createdAt: string;
}

export interface SecurityScan {
  id: string;
  agentId: string;
  agentName: string;
  createdAt: string;
  completedAt?: string;
  durationMs?: number;
  status: ScanStatus;
  mode: 'fast' | 'comprehensive' | 'adversarial';
  categoriesTested: AttackCategory[];
  totalTests: number;
  confirmedFindings: number;
  blockedAttacks: number;
  inconclusiveTests: number;
  findings: SecurityFinding[];
}

export interface RegressionTest {
  id: string;
  name: string;
  category: string;
  description: string;
  input: string;
  expectedOutcome: string;
  actualOutcome: string;
  status: 'passed' | 'failed' | 'skipped' | 'inconclusive';
  executionMs: number;
}

export interface FixLoopSession {
  findingId: string;
  finding: SecurityFinding;
  step: 1 | 2 | 3 | 4 | 5;
  proposedMitigation: string;
  mitigationApplied: boolean;
  appliedTimestamp?: string;
  retestRunId?: string;
  retestOutcome?: AttackOutcome;
  retestTimestamp?: string;
  retestEvidence?: string;
  regressionTests: RegressionTest[];
  verdict: FixLoopVerdict;
  comparisonNotes?: string;
  lastRunTimestamp?: string;
}

export interface AssessmentReport {
  id: string;
  generatedAt: string;
  scanId: string;
  agent: Agent;
  assessmentScope: AttackCategory[];
  executiveSummary: string;
  severitySummary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  totalVulnerabilities: number;
  totalBlocked: number;
  fixLoopVerifiedCount: number;
  findings: SecurityFinding[];
  methodology: string;
  limitations: string[];
}

export interface ApiConnectionStatus {
  connected: boolean;
  isDemoMode: boolean;
  latencyMs?: number;
  endpoint: string;
  message?: string;
  lastChecked: string;
}

export interface FilterState {
  severity: Severity | 'all';
  category: AttackCategory | 'all';
  outcome: AttackOutcome | 'all';
  searchQuery: string;
}
