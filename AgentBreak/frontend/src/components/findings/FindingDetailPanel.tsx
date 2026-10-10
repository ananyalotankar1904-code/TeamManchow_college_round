import React, { useState } from 'react';
import { SecurityFinding } from '../../types';
import { IdBadge } from '../common/IdBadge';
import { SeverityBadge } from './SeverityBadge';
import { OutcomeBadge } from '../common/OutcomeBadge';
import { EvidenceViewer } from './EvidenceViewer';
import { RemediationPanel } from './RemediationPanel';
import { CodeBlock } from '../common/CodeBlock';
import {
  Copy,
  Check,
  Activity,
  RotateCcw,
  AlertTriangle,
  ArrowLeft,
  Zap,
} from 'lucide-react';
import { useToast } from '../common/Toast';

interface FindingDetailPanelProps {
  finding: SecurityFinding;
  onBack?: () => void;
  onJumpToTrace?: (traceId: string) => void;
  onOpenFixLoop?: (findingId: string) => void;
  onViewReport?: (scanId: string) => void;
}

export const FindingDetailPanel: React.FC<FindingDetailPanelProps> = ({
  finding,
  onBack,
  onJumpToTrace,
  onOpenFixLoop,
}) => {
  const { showSuccess } = useToast();
  const [copiedSummary, setCopiedSummary] = useState(false);

  const handleCopySummary = () => {
    const text = `[AgentBreak Finding] ${finding.id}: ${finding.title}\nSeverity: ${finding.severity.toUpperCase()}\nCategory: ${finding.category}\nAgent: ${finding.agentName}\nOutcome: ${finding.outcome}\n\nDescription:\n${finding.description}\n\nReproduction:\nInput: ${finding.reproduction.testInput}\nObserved: ${finding.reproduction.observedBehavior}\n\nRemediation:\n${finding.remediation.summary}\n${finding.remediation.proposedPatch}`;
    navigator.clipboard.writeText(text).then(() => {
      setCopiedSummary(true);
      showSuccess('Full finding summary copied to clipboard');
      setTimeout(() => setCopiedSummary(false), 2000);
    });
  };

  return (
    <div className="space-y-5 font-sans">
      {/* Top Action & Navigation Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#124A58] select-none">
        <div className="flex items-center gap-2.5">
          {onBack && (
            <button
              onClick={onBack}
              className="p-1.5 rounded bg-[#002B36] border border-[#124A58] text-[#8CA3A8] hover:text-[#E3EEEE] hover:bg-[#0A3F4D] transition-colors"
              title="Back to findings list"
            >
              <ArrowLeft className="w-4 h-4" />
            </button>
          )}
          <div className="flex items-center gap-2">
            <span className="text-xs font-sans text-[#8CA3A8] font-medium">Finding Dossier</span>
            <IdBadge id={finding.id} prefix="ID" />
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 font-sans text-xs">
          <button
            onClick={handleCopySummary}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#002B36] hover:bg-[#0A3F4D] text-[#E3EEEE] hover:text-[#F2FAFA] rounded border border-[#124A58] transition-colors font-medium"
          >
            {copiedSummary ? <Check className="w-3.5 h-3.5 text-[#78B993]" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedSummary ? 'Copied' : 'Copy Finding Dossier'}</span>
          </button>

          {onJumpToTrace && finding.evidence?.traceId && (
            <button
              onClick={() => onJumpToTrace(finding.evidence.traceId)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[#0E4452] hover:bg-[#135868] text-[#BFE3E8] hover:text-[#F2FAFA] rounded border border-[#2B7F8C] transition-colors font-medium"
            >
              <Activity className="w-3.5 h-3.5 text-[#6DBAC6]" />
              <span>Inspect Attack Trace</span>
            </button>
          )}

          {onOpenFixLoop && (
            <button
              onClick={() => onOpenFixLoop(finding.id)}
              className="flex items-center gap-1.5 px-3.5 py-1.5 bg-[#2B7F8C] hover:bg-[#3596A5] text-[#F2FAFA] rounded font-medium transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Verify in FixLoop</span>
            </button>
          )}
        </div>
      </div>

      {/* Main Overview Card */}
      <div className="p-4 rounded border border-[#124A58] bg-[#073642] space-y-3.5">
        <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-3">
          <div className="space-y-1.5 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} size="lg" />
              <OutcomeBadge outcome={finding.outcome} />
              {finding.confidence && (
                <span className="px-2 py-0.5 rounded border border-[#124A58] bg-[#002B36] font-sans text-xs text-[#8CA3A8]">
                  Confidence: <span className="text-[#E3EEEE] font-medium">{finding.confidence}</span>
                </span>
              )}
              <span className="px-2 py-0.5 rounded border border-[#124A58] bg-[#002B36] font-sans text-xs text-[#8CA3A8] capitalize">
                Status: {finding.status.replace('_', ' ')}
              </span>
            </div>
            <h2 className="text-lg font-semibold text-[#E3EEEE] font-sans tracking-tight pt-1">
              {finding.title}
            </h2>
          </div>

          <div className="flex flex-col gap-1.5 text-xs text-[#8CA3A8] lg:items-end shrink-0 font-sans">
            <div>
              Target Agent: <span className="text-[#6DBAC6] font-medium">{finding.agentName}</span>
            </div>
            <div className="flex items-center gap-1">
              <span>Scan Ref:</span> <IdBadge id={finding.scanId} truncateLength={12} />
            </div>
            {finding.affectedTool && (
              <div>
                Affected Tool: <span className="text-[#D9A468] font-mono">{finding.affectedTool}</span>
              </div>
            )}
          </div>
        </div>

        {/* Description & Technical Analysis */}
        <div className="pt-3 border-t border-[#124A58] space-y-2 text-xs font-sans">
          <div className="text-[#E3EEEE] leading-relaxed">{finding.description}</div>
          <div className="p-3 rounded bg-[#002B36] border border-[#124A58] text-xs text-[#8CA3A8] space-y-1">
            <span className="text-[#E3EEEE] font-semibold block font-sans">
              Technical Root Cause Analysis:
            </span>
            <p className="leading-relaxed text-[11px]">{finding.technicalAnalysis}</p>
          </div>
        </div>
      </div>

      {/* Attack Reproduction Section */}
      <div className="p-4 rounded border border-[#124A58] bg-[#073642] space-y-3 font-sans text-xs">
        <div className="flex items-center gap-2 pb-2 border-b border-[#124A58] text-xs font-semibold text-[#E3EEEE] font-sans">
          <Zap className="w-4 h-4 text-[#D9A468]" />
          <span>Attack Reproduction Vector & Observed Results</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
          <div className="space-y-1.5">
            <div className="text-xs text-[#8CA3A8] font-medium">Test Input Prompt:</div>
            <CodeBlock
              code={finding.reproduction.testInput}
              language="text"
              showLineNumbers={false}
              maxHeight="120px"
            />
          </div>

          <div className="space-y-1.5">
            <div className="text-xs text-[#8CA3A8] font-medium">Embedded Adversarial Payload:</div>
            <CodeBlock
              code={finding.reproduction.vectorPayload}
              language="html"
              showLineNumbers={false}
              maxHeight="120px"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
          <div className="p-2.5 rounded bg-[#002B36] border border-[#124A58] space-y-1">
            <span className="text-xs text-[#8CA3A8] font-medium block">
              Expected Safe Behavior:
            </span>
            <div className="text-[#78B993] text-xs leading-relaxed">
              {finding.reproduction.expectedBehavior}
            </div>
          </div>

          <div className="p-2.5 rounded bg-[#002B36] border border-[#124A58] space-y-1">
            <span className="text-xs text-[#8CA3A8] font-medium block">
              Observed Unsafe Behavior:
            </span>
            <div className="text-[#D9776B] text-xs leading-relaxed">
              {finding.reproduction.observedBehavior}
            </div>
          </div>
        </div>
      </div>

      {/* Evidence Viewer */}
      <div className="space-y-2">
        <div className="flex items-center gap-2 text-xs font-semibold text-[#E3EEEE] font-sans">
          <Activity className="w-4 h-4 text-[#6DBAC6]" />
          <span>Recorded Execution Evidence & Audit Logs</span>
        </div>
        <EvidenceViewer evidence={finding.evidence} />
      </div>

      {/* Impact Assessment */}
      <div className="p-4 rounded border border-[#124A58] bg-[#073642] space-y-2 font-sans text-xs">
        <div className="flex items-center gap-2 pb-1 border-b border-[#124A58] text-xs font-semibold text-[#E3EEEE] font-sans">
          <AlertTriangle className="w-4 h-4 text-[#D9A468]" />
          <span>Security Impact & Threat Scope</span>
        </div>
        <p className="text-[#E3EEEE] leading-relaxed text-xs">{finding.impact}</p>
      </div>

      {/* Remediation Panel */}
      <div className="space-y-2">
        <div className="flex items-center gap-2 text-xs font-semibold text-[#E3EEEE] font-sans">
          <AlertTriangle className="w-4 h-4 text-[#6DBAC6]" />
          <span>Recommended Remediation & FixLoop Verification</span>
        </div>
        <RemediationPanel
          remediation={finding.remediation}
          findingId={finding.id}
          onOpenFixLoop={onOpenFixLoop}
        />
      </div>
    </div>
  );
};

