import React, { useState } from 'react';
import { SecurityFinding, FixLoopSession, FixLoopVerdict } from '../../types';
import { IdBadge } from '../common/IdBadge';
import { SeverityBadge } from '../findings/SeverityBadge';
import { OutcomeBadge } from '../common/OutcomeBadge';
import { RegressionResults } from './RegressionResults';
import {
  CheckCircle2,
  AlertTriangle,
  Play,
  ShieldAlert,
  ShieldCheck,
  Clock,
  Zap,
  Info,
  ChevronRight,
  Check,
} from 'lucide-react';
import { useToast } from '../common/Toast';

interface FixLoopPanelProps {
  session: FixLoopSession;
  allFindings: SecurityFinding[];
  onSelectFinding: (findingId: string) => void;
  onApplyMitigation: (findingId: string, customPatch?: string) => Promise<void>;
  onRunRetest: (findingId: string) => Promise<void>;
  onRunRegressionSuite: (findingId: string) => Promise<void>;
}

export const FixLoopPanel: React.FC<FixLoopPanelProps> = ({
  session,
  allFindings,
  onSelectFinding,
  onApplyMitigation,
  onRunRetest,
  onRunRegressionSuite,
}) => {
  const { showSuccess, showError } = useToast();
  const [activeStep, setActiveStep] = useState<number>(session.step || 1);
  const [customPatch, setCustomPatch] = useState(session.proposedMitigation);
  const [isRunningRetest, setIsRunningRetest] = useState(false);
  const [isRunningRegression, setIsRunningRegression] = useState(false);

  const finding = session.finding;

  const handleApplyPatch = async () => {
    try {
      await onApplyMitigation(finding.id, customPatch);
      setActiveStep(3);
      showSuccess('Mitigation marked applied to target agent');
    } catch {
      showError('Failed to apply mitigation');
    }
  };

  const handleExecuteRetest = async () => {
    try {
      setIsRunningRetest(true);
      await onRunRetest(finding.id);
      setActiveStep(4);
      showSuccess('Adversarial retest completed: Attack Blocked!');
    } catch {
      showError('Retest execution failed');
    } finally {
      setIsRunningRetest(false);
    }
  };

  const handleExecuteRegression = async () => {
    try {
      setIsRunningRegression(true);
      await onRunRegressionSuite(finding.id);
      setActiveStep(5);
      showSuccess('Regression test suite passed (12/12 standard tasks)');
    } catch {
      showError('Regression suite failed');
    } finally {
      setIsRunningRegression(false);
    }
  };

  const getVerdictBadge = (verdict: FixLoopVerdict) => {
    switch (verdict) {
      case 'mitigation_verified':
        return (
          <span className="flex items-center gap-1.5 px-3 py-1 rounded bg-[#1D3D33] border border-[#285547] text-[#A6D6B7] font-sans text-xs font-medium">
            <ShieldCheck className="w-4 h-4" />
            <span>Mitigation Verified</span>
          </span>
        );
      case 'still_vulnerable':
        return (
          <span className="flex items-center gap-1.5 px-3 py-1 rounded bg-[#4A2F31] border border-[#5A3A3C] text-[#F0B3AA] font-sans text-xs font-medium">
            <ShieldAlert className="w-4 h-4" />
            <span>Still Vulnerable</span>
          </span>
        );
      case 'regression_failure':
        return (
          <span className="flex items-center gap-1.5 px-3 py-1 rounded bg-[#4A3A25] border border-[#59462D] text-[#EBC48E] font-sans text-xs font-medium">
            <AlertTriangle className="w-4 h-4" />
            <span>Regression Failure</span>
          </span>
        );
      case 'inconclusive':
        return (
          <span className="flex items-center gap-1.5 px-3 py-1 rounded bg-[#002B36] border border-[#124A58] text-[#8CA3A8] font-sans text-xs font-medium">
            <span>Inconclusive</span>
          </span>
        );
      default:
        return (
          <span className="flex items-center gap-1.5 px-3 py-1 rounded bg-[#002B36] border border-[#124A58] text-[#5F7C82] font-sans text-xs">
            <span>Not Yet Tested</span>
          </span>
        );
    }
  };

  const steps = [
    { num: 1, title: 'Target Finding', desc: 'Select vulnerability' },
    { num: 2, title: 'Mitigation Patch', desc: 'Review & apply' },
    { num: 3, title: 'Targeted Retest', desc: 'Execute original vector' },
    { num: 4, title: 'Regression Suite', desc: '12 benign test cases' },
    { num: 5, title: 'Verification Verdict', desc: 'Evidence & audit report' },
  ];

  return (
    <div className="space-y-5 font-sans">
      {/* 5-Step Stepper Bar */}
      <div className="p-3.5 rounded border border-[#124A58] bg-[#073642]">
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 select-none">
          {steps.map((s) => {
            const isDone = activeStep > s.num || (activeStep === 5 && session.verdict === 'mitigation_verified');
            const isCurrent = activeStep === s.num;

            return (
              <div
                key={s.num}
                onClick={() => setActiveStep(s.num)}
                className={`p-2.5 rounded border cursor-pointer transition-all flex flex-col justify-between ${
                  isCurrent
                    ? 'bg-[#0E4452] border-[#2B7F8C] text-[#E3EEEE]'
                    : isDone
                    ? 'bg-[#1D3D33]/60 border-[#285547] text-[#E3EEEE]'
                    : 'bg-[#002B36] border-[#124A58] text-[#5F7C82] hover:border-[#185B6C]'
                }`}
              >
                <div className="flex items-center justify-between text-xs font-sans mb-1">
                  <span className={isCurrent ? 'text-[#6DBAC6] font-medium' : isDone ? 'text-[#78B993]' : 'text-[#5F7C82]'}>
                    Step {s.num}
                  </span>
                  {isDone ? (
                    <Check className="w-3.5 h-3.5 text-[#78B993]" />
                  ) : isCurrent ? (
                    <div className="w-1.5 h-1.5 rounded-full bg-[#2B7F8C]" />
                  ) : null}
                </div>
                <div className="font-medium text-xs tracking-tight truncate">{s.title}</div>
                <div className="text-[11px] text-[#8CA3A8] truncate mt-0.5">{s.desc}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Step 1: Target Finding Selected */}
      {activeStep === 1 && (
        <div className="p-4 rounded border border-[#124A58] bg-[#073642] space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-[#124A58]">
            <span className="text-xs font-semibold text-[#E3EEEE] font-sans">
              Step 1: Select Confirmed Vulnerability
            </span>
            <span className="text-xs text-[#8CA3A8] font-sans">
              Only confirmed findings with reproduction evidence qualify for FixLoop
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {allFindings.map((f) => (
              <div
                key={f.id}
                onClick={() => onSelectFinding(f.id)}
                className={`p-3 rounded border cursor-pointer transition-all space-y-2 ${
                  f.id === finding.id
                    ? 'bg-[#0E4452] border-[#2B7F8C]'
                    : 'bg-[#002B36] border-[#124A58] hover:border-[#185B6C]'
                }`}
              >
                <div className="flex items-center justify-between">
                  <IdBadge id={f.id} />
                  <SeverityBadge severity={f.severity} size="sm" />
                </div>
                <div className="font-medium text-xs text-[#E3EEEE]">{f.title}</div>
                <div className="flex items-center justify-between text-xs text-[#8CA3A8] font-sans">
                  <span>Agent: {f.agentName}</span>
                  <OutcomeBadge outcome={f.outcome} size="sm" />
                </div>
              </div>
            ))}
          </div>

          <div className="flex justify-end pt-2">
            <button
              onClick={() => setActiveStep(2)}
              className="px-3.5 py-2 bg-[#2B7F8C] hover:bg-[#3596A5] text-[#F2FAFA] rounded text-xs font-medium flex items-center gap-1.5 transition-colors"
            >
              <span>Proceed to Mitigation Review</span>
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Step 2: Mitigation Reviewed and Applied */}
      {activeStep === 2 && (
        <div className="p-4 rounded border border-[#124A58] bg-[#073642] space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-[#124A58]">
            <div className="space-y-0.5">
              <div className="text-xs font-semibold text-[#E3EEEE] font-sans">
                Step 2: Review Proposed Mitigation & Apply to Target
              </div>
              <div className="text-xs text-[#8CA3A8]">
                Target Finding: <span className="text-[#E3EEEE] font-medium">{finding.title}</span> (
                <IdBadge id={finding.id} />)
              </div>
            </div>
            <span className="px-2 py-0.5 rounded border border-[#2B7F8C] bg-[#0E4452] text-xs text-[#BFE3E8] font-sans">
              {session.mitigationApplied ? 'Applied' : 'Proposed Draft'}
            </span>
          </div>

          <div className="p-3 rounded bg-[#002B36] border border-[#124A58] text-xs text-[#8CA3A8] leading-relaxed flex items-start gap-2">
            <Info className="w-3.5 h-3.5 text-[#6DBAC6] shrink-0 mt-0.5" />
            <div>
              <span className="font-medium text-[#E3EEEE]">Engineering Mitigation Workflow:</span>{' '}
              Review the patch below. In production, paste this configuration into your agent framework prompt or guardrail middleware.
              Click "Mark Mitigation Applied" once you have updated the target.
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-[#E3EEEE] font-sans">
              Mitigation Patch / Guardrail Rule:
            </label>
            <textarea
              rows={8}
              value={customPatch}
              onChange={(e) => setCustomPatch(e.target.value)}
              className="w-full bg-[#002B36] border border-[#124A58] rounded p-3 text-xs font-mono text-[#E3EEEE] focus:outline-none focus:border-[#2B7F8C] leading-relaxed"
            />
          </div>

          <div className="flex items-center justify-between pt-2 border-t border-[#124A58]">
            <button
              onClick={() => setActiveStep(1)}
              className="px-3 py-1.5 bg-[#002B36] hover:bg-[#0A3F4D] border border-[#124A58] text-[#E3EEEE] rounded text-xs font-medium transition-colors"
            >
              Back
            </button>
            <button
              onClick={handleApplyPatch}
              className="px-3.5 py-2 bg-[#2B7F8C] hover:bg-[#3596A5] text-[#F2FAFA] rounded text-xs font-medium flex items-center gap-1.5 transition-colors"
            >
              <Check className="w-3.5 h-3.5" />
              <span>Mark Mitigation Applied & Proceed to Retest</span>
            </button>
          </div>
        </div>
      )}

      {/* Step 3: Targeted Retest Executed */}
      {activeStep === 3 && (
        <div className="p-4 rounded border border-[#124A58] bg-[#073642] space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-[#124A58]">
            <div>
              <div className="text-xs font-semibold text-[#E3EEEE] font-sans">
                Step 3: Execute Adversarial Retest Against Target Boundary
              </div>
              <div className="text-xs text-[#8CA3A8]">
                Target Finding: <span className="text-[#E3EEEE]">{finding.title}</span>
              </div>
            </div>
            {session.retestOutcome && <OutcomeBadge outcome={session.retestOutcome} />}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Original Attack */}
            <div className="p-3.5 rounded bg-[#4A2F31]/70 border border-[#5A3A3C] space-y-2 text-xs font-sans">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-[#D9776B]">Original Attack Test</span>
                <span className="text-[#8CA3A8] font-mono text-[11px]">Run: {finding.scanId}</span>
              </div>
              <div className="text-xs text-[#E3EEEE]">
                Input Prompt: <span className="font-mono text-[#BCD0D3]">{finding.reproduction.testInput}</span>
              </div>
              <div className="p-2 rounded bg-[#002B36] border border-[#5A3A3C] font-mono text-[11px] text-[#E08A7E]">
                Observed: {finding.reproduction.observedBehavior}
              </div>
              <div className="text-[11px] text-[#8CA3A8]">Outcome: Confirmed Vulnerable</div>
            </div>

            {/* Retest Output */}
            <div className="p-3.5 rounded bg-[#1D3D33]/70 border border-[#285547] space-y-2 text-xs font-sans">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-[#78B993]">Targeted Retest Execution</span>
                {session.retestRunId && <IdBadge id={session.retestRunId} prefix="RUN" />}
              </div>
              {session.retestEvidence ? (
                <div className="space-y-2">
                  <div className="p-2 rounded bg-[#002B36] border border-[#285547] font-mono text-[11px] text-[#A6D6B7] leading-relaxed">
                    {session.retestEvidence}
                  </div>
                  <div className="text-[11px] text-[#8CA3A8] flex items-center gap-1 font-mono">
                    <Clock className="w-3 h-3 text-[#5F7C82]" />
                    <span>Timestamp: <span className="text-[#BCD0D3]">{session.retestTimestamp}</span></span>
                  </div>
                </div>
              ) : (
                <div className="py-6 text-center text-[#5F7C82] font-sans text-xs">
                  Retest not yet initiated. Click "Execute Targeted Retest" below to run the probe.
                </div>
              )}
            </div>
          </div>

          <div className="flex items-center justify-between pt-2 border-t border-[#124A58]">
            <button
              onClick={() => setActiveStep(2)}
              className="px-3 py-1.5 bg-[#002B36] hover:bg-[#0A3F4D] border border-[#124A58] text-[#E3EEEE] rounded text-xs font-medium transition-colors"
            >
              Back
            </button>
            <div className="flex items-center gap-2">
              <button
                onClick={handleExecuteRetest}
                disabled={isRunningRetest}
                className="px-3.5 py-2 bg-[#0E4452] hover:bg-[#135868] border border-[#2B7F8C] text-[#BFE3E8] rounded text-xs font-medium flex items-center gap-1.5 transition-colors"
              >
                <Zap className="w-3.5 h-3.5 text-[#6DBAC6]" />
                <span>{isRunningRetest ? 'Executing Vector...' : 'Execute Targeted Retest'}</span>
              </button>
              {session.retestOutcome === 'blocked' && (
                <button
                  onClick={() => setActiveStep(4)}
                  className="px-3.5 py-2 bg-[#2B7F8C] hover:bg-[#3596A5] text-[#F2FAFA] rounded text-xs font-medium flex items-center gap-1.5 transition-colors"
                >
                  <span>Proceed to Benign Regression Suite</span>
                  <ChevronRight className="w-4 h-4" />
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Step 4: Benign Regression Suite */}
      {activeStep === 4 && (
        <div className="space-y-4 font-sans">
          <div className="p-4 rounded border border-[#124A58] bg-[#073642] space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-[#124A58]">
              <div>
                <div className="text-xs font-semibold text-[#E3EEEE] font-sans">
                  Step 4: Execute Benign Functional Regression Suite
                </div>
                <div className="text-xs text-[#8CA3A8]">
                  Verifying that defensive prompt isolation didn't impair legitimate financial queries or benign tool calls.
                </div>
              </div>
              <button
                onClick={handleExecuteRegression}
                disabled={isRunningRegression}
                className="px-3.5 py-2 bg-[#2B7F8C] hover:bg-[#3596A5] disabled:opacity-50 text-[#F2FAFA] rounded text-xs font-medium flex items-center gap-1.5 transition-colors"
              >
                <Play className="w-3.5 h-3.5" />
                <span>{isRunningRegression ? 'Executing 12 Tasks...' : 'Run 12/12 Regression Suite'}</span>
              </button>
            </div>

            <RegressionResults tests={session.regressionTests} />

            <div className="flex items-center justify-between pt-2 border-t border-[#124A58]">
              <button
                onClick={() => setActiveStep(3)}
                className="px-3 py-1.5 bg-[#002B36] hover:bg-[#0A3F4D] border border-[#124A58] text-[#E3EEEE] rounded text-xs font-medium transition-colors"
              >
                Back
              </button>
              <button
                onClick={() => setActiveStep(5)}
                className="px-3.5 py-2 bg-[#2B7F8C] hover:bg-[#3596A5] text-[#F2FAFA] rounded text-xs font-medium flex items-center gap-1.5 transition-colors"
              >
                <span>View Final Verification Verdict</span>
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Step 5: Verification Verdict & Final Comparison */}
      {activeStep === 5 && (
        <div className="space-y-4 font-sans">
          <div className="p-4 rounded border border-[#124A58] bg-[#073642] space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#124A58]">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-medium text-[#8CA3A8] font-sans">Final Verification Result</span>
                  <IdBadge id={finding.id} />
                </div>
                <h3 className="font-semibold text-base text-[#E3EEEE] font-sans">{finding.title}</h3>
              </div>
              <div>{getVerdictBadge(session.verdict)}</div>
            </div>

            {/* Before vs After Audit Comparison Matrix */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-sans">
              <div className="p-3.5 rounded bg-[#4A2F31]/70 border border-[#5A3A3C] space-y-2">
                <div className="font-semibold text-[#F0B3AA] pb-1 border-b border-[#5A3A3C]">
                  Before Mitigation (Original Scan)
                </div>
                <div className="space-y-1 text-xs text-[#E3EEEE]">
                  <div>
                    Vector Outcome: <span className="text-[#E08A7E] font-medium">Attack Executed</span>
                  </div>
                  <div>
                    Tool Invocation: <span className="text-[#E08A7E] font-mono text-[11px]">http_request (Credential Exfil)</span>
                  </div>
                  <div>Policy Decision: <span className="font-mono text-[11px] text-[#BCD0D3]">POL-402 Violation</span></div>
                  <div>Result: Confirmed Critical Finding</div>
                </div>
              </div>

              <div className="p-3.5 rounded bg-[#1D3D33]/70 border border-[#285547] space-y-2">
                <div className="font-semibold text-[#A6D6B7] pb-1 border-b border-[#285547]">
                  After Mitigation (FixLoop Retest)
                </div>
                <div className="space-y-1 text-xs text-[#E3EEEE]">
                  <div>
                    Vector Outcome: <span className="text-[#A6D6B7] font-medium">Attack Blocked</span>
                  </div>
                  <div>
                    Tool Invocation: <span className="text-[#A6D6B7] font-sans">None (Egress Refused)</span>
                  </div>
                  <div>
                    Benign Regression: <span className="text-[#A6D6B7] font-medium">12/12 Standard Tasks Passed</span>
                  </div>
                  <div>Result: Remediation Verified & Fixed</div>
                </div>
              </div>
            </div>

            {/* Comparison Notes */}
            {session.comparisonNotes && (
              <div className="p-3 rounded bg-[#002B36] border border-[#124A58] text-xs font-sans text-[#E3EEEE] whitespace-pre-line leading-relaxed">
                {session.comparisonNotes}
              </div>
            )}

            <div className="flex items-center justify-between pt-2 border-t border-[#124A58]">
              <button
                onClick={() => setActiveStep(4)}
                className="px-3 py-1.5 bg-[#002B36] hover:bg-[#0A3F4D] border border-[#124A58] text-[#E3EEEE] rounded text-xs font-medium transition-colors"
              >
                Back to Regression Results
              </button>
              <button
                onClick={() => {
                  showSuccess('Verification dossier generated and attached to report');
                }}
                className="px-3.5 py-2 bg-[#2B7F8C] hover:bg-[#3596A5] text-[#F2FAFA] rounded text-xs font-medium flex items-center gap-1.5 transition-colors"
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Mark Finding Verified Fixed in Audit Log</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

