import React, { useState } from 'react';
import { RemediationSuggestion } from '../../types';
import { CodeBlock } from '../common/CodeBlock';
import { Shield, Copy, Check, RotateCcw, ExternalLink, Info } from 'lucide-react';
import { useToast } from '../common/Toast';

interface RemediationPanelProps {
  remediation: RemediationSuggestion;
  findingId: string;
  onOpenFixLoop?: (findingId: string) => void;
}

export const RemediationPanel: React.FC<RemediationPanelProps> = ({
  remediation,
  findingId,
  onOpenFixLoop,
}) => {
  const { showSuccess } = useToast();
  const [copied, setCopied] = useState(false);

  const handleCopyPatch = () => {
    navigator.clipboard.writeText(remediation.proposedPatch).then(() => {
      setCopied(true);
      showSuccess('Remediation patch copied to clipboard');
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div className="rounded border border-[#124A58] bg-[#073642] p-4 space-y-4 text-xs font-sans">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-[#124A58]">
        <div className="flex items-center gap-2">
          <div className="p-1 rounded bg-[#002B36] border border-[#124A58] text-[#6DBAC6]">
            <Shield className="w-4 h-4" />
          </div>
          <div>
            <div className="font-semibold text-[#E3EEEE] text-sm font-sans">{remediation.summary}</div>
            <div className="text-xs text-[#8CA3A8] font-sans">
              Patch Type:{' '}
              <span className="text-[#6DBAC6] font-medium capitalize">
                {remediation.patchType.replace('_', ' ')}
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 font-sans text-xs">
          <button
            onClick={handleCopyPatch}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#002B36] hover:bg-[#0A3F4D] text-[#E3EEEE] hover:text-[#F2FAFA] rounded border border-[#124A58] transition-colors font-medium"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-[#78B993]" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy Proposed Patch'}</span>
          </button>

          {onOpenFixLoop && (
            <button
              onClick={() => onOpenFixLoop(findingId)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[#2B7F8C] hover:bg-[#3596A5] text-[#F2FAFA] rounded font-medium transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Verify in FixLoop</span>
            </button>
          )}
        </div>
      </div>

      {/* Guidance Alert */}
      <div className="p-3 rounded bg-[#002B36] border border-[#124A58] text-xs text-[#8CA3A8] leading-relaxed flex items-start gap-2">
        <Info className="w-3.5 h-3.5 text-[#6DBAC6] shrink-0 mt-0.5" />
        <div>
          <span className="font-medium text-[#E3EEEE]">Explicit User-Controlled Remediation:</span>{' '}
          AgentBreak provides verified mitigation patches to be applied by engineering teams. The
          security dashboard does not silently alter or inject code into your target agent.
        </div>
      </div>

      {/* Proposed Patch Code Block */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between text-xs text-[#8CA3A8] font-medium">
          <span>Proposed Mitigation Patch / Guardrail Definition:</span>
        </div>
        <CodeBlock
          code={remediation.proposedPatch}
          language="typescript"
          showLineNumbers={true}
          maxHeight="250px"
        />
      </div>

      {/* Code Diff if available */}
      {remediation.codeDiff && (
        <div className="space-y-1.5">
          <div className="text-xs text-[#8CA3A8] font-medium">Target Source Code Diff:</div>
          <CodeBlock
            code={remediation.codeDiff}
            language="diff"
            showLineNumbers={true}
            maxHeight="220px"
          />
        </div>
      )}

      {/* References */}
      {remediation.referenceLinks && remediation.referenceLinks.length > 0 && (
        <div className="pt-2 border-t border-[#124A58] space-y-1">
          <div className="text-xs text-[#5F7C82] font-medium">
            Security Standards & CWE References:
          </div>
          <div className="flex flex-wrap gap-2">
            {remediation.referenceLinks.map((link, idx) => (
              <a
                key={idx}
                href={link}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 text-xs text-[#6DBAC6] hover:text-[#BFE3E8] hover:underline"
              >
                <span>{link}</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

