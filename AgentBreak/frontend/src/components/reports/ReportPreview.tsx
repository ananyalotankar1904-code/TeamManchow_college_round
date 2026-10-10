import React, { useState } from 'react';
import { AssessmentReport } from '../../types';
import { IdBadge } from '../common/IdBadge';
import { SeverityBadge } from '../findings/SeverityBadge';
import { OutcomeBadge } from '../common/OutcomeBadge';
import { CodeBlock } from '../common/CodeBlock';
import {
  FileText,
  Copy,
  Check,
  Printer,
  Calendar,
} from 'lucide-react';
import { useToast } from '../common/Toast';

interface ReportPreviewProps {
  report: AssessmentReport;
}

export const ReportPreview: React.FC<ReportPreviewProps> = ({ report }) => {
  const { showSuccess } = useToast();
  const [copiedFull, setCopiedFull] = useState(false);
  const [copiedExec, setCopiedExec] = useState(false);

  const generateMarkdownReport = () => {
    return `# AGENTBREAK SECURITY ASSESSMENT REPORT
**Report ID:** ${report.id}
**Target Agent:** ${report.agent.name} (${report.agent.identifier})
**Framework:** ${report.agent.framework}
**Generated Date:** ${report.generatedAt}
**Scan ID:** ${report.scanId}

---

## 1. Executive Summary
${report.executiveSummary}

---

## 2. Vulnerability Breakdown
- **Critical Severity:** ${report.severitySummary.critical}
- **High Severity:** ${report.severitySummary.high}
- **Medium Severity:** ${report.severitySummary.medium}
- **Low / Info:** ${report.severitySummary.low + report.severitySummary.info}
- **Attacks Blocked by Policy:** ${report.totalBlocked}
- **FixLoop Verified Remediations:** ${report.fixLoopVerifiedCount}

---

## 3. Findings Dossiers
${report.findings
  .map(
    (f, idx) => `
### 3.${idx + 1}. [${f.severity.toUpperCase()}] ${f.id}: ${f.title}
- **Category:** ${f.category}
- **Outcome:** ${f.outcome}
- **Affected Tool:** ${f.affectedTool || 'None'}
- **Status:** ${f.status}

**Description:**
${f.description}

**Attack Reproduction:**
- **Test Input:** \`${f.reproduction.testInput}\`
- **Observed Behavior:** ${f.reproduction.observedBehavior}
- **Expected Safe Behavior:** ${f.reproduction.expectedBehavior}

**Recommended Mitigation:**
\`\`\`
${f.remediation.proposedPatch}
\`\`\`
`
  )
  .join('\n')}

---

## 4. Methodology & Scope
${report.methodology}

---

## 5. Assessment Limitations & Disclaimers
${report.limitations.map((lim) => `- ${lim}`).join('\n')}
`;
  };

  const handleCopyFull = () => {
    navigator.clipboard.writeText(generateMarkdownReport()).then(() => {
      setCopiedFull(true);
      showSuccess('Full Markdown security report copied to clipboard');
      setTimeout(() => setCopiedFull(false), 2000);
    });
  };

  const handleCopyExec = () => {
    navigator.clipboard.writeText(report.executiveSummary).then(() => {
      setCopiedExec(true);
      showSuccess('Executive summary copied to clipboard');
      setTimeout(() => setCopiedExec(false), 2000);
    });
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="space-y-5 font-sans">
      {/* Top Action Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3.5 rounded border border-[#124A58] bg-[#073642] select-none">
        <div className="flex items-center gap-2 text-xs font-sans">
          <FileText className="w-4 h-4 text-[#6DBAC6]" />
          <span className="font-semibold text-[#E3EEEE]">Assessment Report</span>
          <IdBadge id={report.id} prefix="REP" />
        </div>

        <div className="flex flex-wrap items-center gap-2 font-sans text-xs">
          <button
            onClick={handleCopyExec}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#002B36] hover:bg-[#0A3F4D] text-[#E3EEEE] hover:text-[#F2FAFA] rounded border border-[#124A58] transition-colors font-medium"
          >
            {copiedExec ? <Check className="w-3.5 h-3.5 text-[#78B993]" /> : <Copy className="w-3.5 h-3.5" />}
            <span>Copy Exec Summary</span>
          </button>

          <button
            onClick={handleCopyFull}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#002B36] hover:bg-[#0A3F4D] text-[#E3EEEE] hover:text-[#F2FAFA] rounded border border-[#124A58] transition-colors font-medium"
          >
            {copiedFull ? <Check className="w-3.5 h-3.5 text-[#78B993]" /> : <Copy className="w-3.5 h-3.5" />}
            <span>Copy Full Markdown</span>
          </button>

          <button
            onClick={handlePrint}
            className="flex items-center gap-1.5 px-3.5 py-1.5 bg-[#2B7F8C] hover:bg-[#3596A5] text-[#F2FAFA] rounded font-medium transition-colors"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print / Export PDF</span>
          </button>
        </div>
      </div>

      {/* Report Document Canvas */}
      <div className="p-6 md:p-8 rounded border border-[#124A58] bg-[#002B36] space-y-6 text-xs text-[#E3EEEE] font-sans">
        {/* Document Header */}
        <div className="border-b border-[#124A58] pb-6 space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
            <div className="space-y-1">
              <div className="text-xs text-[#6DBAC6] font-medium">
                AgentBreak Security Advisory Report
              </div>
              <h1 className="text-xl font-semibold text-[#E3EEEE] tracking-tight">
                AI Agent Red-Team Vulnerability Assessment
              </h1>
              <div className="text-[#8CA3A8] text-xs">
                Target: <span className="text-[#E3EEEE] font-medium">{report.agent.name}</span> (
                <span className="font-mono text-[#BCD0D3]">{report.agent.identifier}</span>)
              </div>
            </div>

            <div className="flex flex-col items-start sm:items-end gap-1 text-xs text-[#8CA3A8]">
              <div className="flex items-center gap-1.5">
                <Calendar className="w-3.5 h-3.5 text-[#5F7C82]" />
                <span className="font-mono text-[#BCD0D3]">{report.generatedAt.replace('T', ' ').substring(0, 19)} UTC</span>
              </div>
              <div>
                Report ID: <span className="text-[#BCD0D3] font-mono">{report.id}</span>
              </div>
              <div className="flex items-center gap-1">
                <span>Scan Ref:</span> <IdBadge id={report.scanId} />
              </div>
            </div>
          </div>

          {/* Quick Metrics Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-3 font-sans">
            <div className="p-2.5 rounded bg-[#073642] border border-[#124A58]">
              <div className="text-xs text-[#8CA3A8]">Critical Vulns</div>
              <div className="text-lg font-bold font-mono text-[#E08A7E]">{report.severitySummary.critical}</div>
            </div>
            <div className="p-2.5 rounded bg-[#073642] border border-[#124A58]">
              <div className="text-xs text-[#8CA3A8]">High Vulns</div>
              <div className="text-lg font-bold font-mono text-[#D9A468]">{report.severitySummary.high}</div>
            </div>
            <div className="p-2.5 rounded bg-[#073642] border border-[#124A58]">
              <div className="text-xs text-[#8CA3A8]">Attacks Blocked</div>
              <div className="text-lg font-bold font-mono text-[#78B993]">{report.totalBlocked}</div>
            </div>
            <div className="p-2.5 rounded bg-[#073642] border border-[#124A58]">
              <div className="text-xs text-[#8CA3A8]">FixLoop Verified</div>
              <div className="text-lg font-bold font-mono text-[#6DBAC6]">{report.fixLoopVerifiedCount}</div>
            </div>
          </div>
        </div>

        {/* Section 1: Executive Summary */}
        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-[#E3EEEE] border-b border-[#124A58] pb-1">
            1. Executive Summary
          </h2>
          <p className="text-xs text-[#E3EEEE] leading-relaxed font-sans">{report.executiveSummary}</p>
        </section>

        {/* Section 2: Target Agent Profile */}
        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-[#E3EEEE] border-b border-[#124A58] pb-1">
            2. Target Agent Architecture & Bound Tools
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            <div className="p-3 rounded bg-[#073642] border border-[#124A58] space-y-1.5">
              <div className="text-[#8CA3A8]">Framework: <span className="text-[#E3EEEE] font-medium">{report.agent.framework}</span></div>
              <div className="text-[#8CA3A8]">Environment: <span className="text-[#E3EEEE] font-medium">{report.agent.environment}</span></div>
              <div className="text-[#8CA3A8]">Execution Method: <span className="text-[#E3EEEE] font-medium">{report.agent.executionMethod}</span></div>
            </div>
            <div className="p-3 rounded bg-[#073642] border border-[#124A58] space-y-1.5">
              <div className="text-[#8CA3A8]">Exposed Tools: <span className="text-[#6DBAC6] font-mono">{report.agent.tools.join(', ')}</span></div>
              <div className="text-[#8CA3A8]">Permissions: <span className="text-[#78B993] font-mono">{report.agent.permissions.join(', ')}</span></div>
            </div>
          </div>
        </section>

        {/* Section 3: Detailed Findings */}
        <section className="space-y-4">
          <h2 className="text-sm font-semibold text-[#E3EEEE] border-b border-[#124A58] pb-1">
            3. Detailed Vulnerability Dossiers
          </h2>

          <div className="space-y-4">
            {report.findings.map((finding, idx) => (
              <div
                key={finding.id}
                className="p-4 rounded border border-[#124A58] bg-[#073642] space-y-3 font-sans"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-[#5F7C82] text-xs">3.{idx + 1}</span>
                    <SeverityBadge severity={finding.severity} size="sm" />
                    <span className="font-medium text-[#E3EEEE] text-xs">{finding.title}</span>
                  </div>
                  <OutcomeBadge outcome={finding.outcome} size="sm" />
                </div>

                <p className="text-xs text-[#8CA3A8] leading-relaxed">{finding.description}</p>

                <div className="p-2.5 rounded bg-[#002B36] border border-[#124A58] space-y-1 text-xs">
                  <div className="text-[#8CA3A8] font-medium">Reproduction Test Prompt:</div>
                  <div className="text-[#BCD0D3] font-mono text-[11px]">{finding.reproduction.testInput}</div>
                  <div className="text-[#8CA3A8] font-medium pt-1">Observed Outcome:</div>
                  <div className="text-[#D9776B] font-mono text-[11px]">{finding.reproduction.observedBehavior}</div>
                </div>

                <div className="space-y-1">
                  <div className="text-[#8CA3A8] font-medium">Recommended Remediation:</div>
                  <CodeBlock
                    code={finding.remediation.proposedPatch}
                    language="typescript"
                    showLineNumbers={false}
                    maxHeight="160px"
                  />
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Section 4: Methodology & Limitations */}
        <section className="space-y-3 pt-2 border-t border-[#124A58]">
          <h2 className="text-sm font-semibold text-[#E3EEEE] border-b border-[#124A58] pb-1">
            4. Methodology, Scope & Known Limitations
          </h2>
          <p className="text-xs text-[#8CA3A8] leading-relaxed">{report.methodology}</p>
          <div className="space-y-1 text-xs">
            <div className="text-[#8CA3A8] font-medium">Audit Constraints:</div>
            <ul className="list-disc list-inside space-y-1 text-[#8CA3A8]">
              {report.limitations.map((lim, idx) => (
                <li key={idx}>{lim}</li>
              ))}
            </ul>
          </div>
        </section>
      </div>
    </div>
  );
};

