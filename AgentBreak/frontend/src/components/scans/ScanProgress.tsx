import React, { useState, useEffect } from 'react';
import { SecurityScan } from '../../types';
import { Loader2, ShieldAlert, ShieldCheck, HelpCircle, StopCircle, Terminal } from 'lucide-react';
import { IdBadge } from '../common/IdBadge';

interface ScanProgressProps {
  scan: SecurityScan;
  onComplete: () => void;
  onCancel: () => void;
}

export const ScanProgress: React.FC<ScanProgressProps> = ({
  scan,
  onComplete,
  onCancel,
}) => {
  const [currentStep, setCurrentStep] = useState(1);
  const [logs, setLogs] = useState<string[]>([
    `[INIT] Initialized test session against agent "${scan.agentName}"`,
    `[SCOPE] Loaded ${scan.categoriesTested.length} attack vector modules (${scan.mode.toUpperCase()} profile)`,
    `[ADAPTER] Handshake established with target runner adapter`,
  ]);

  const [simulatedVulns, setSimulatedVulns] = useState(0);
  const [simulatedBlocked, setSimulatedBlocked] = useState(0);

  useEffect(() => {
    const totalSteps = 6;
    const interval = setInterval(() => {
      setCurrentStep((prev) => {
        if (prev >= totalSteps) {
          clearInterval(interval);
          onComplete();
          return prev;
        }

        const next = prev + 1;
        if (next === 2) {
          setLogs((l) => [
            ...l,
            `[RUN] Executing Indirect RAG injection probe with embedded delimiter tokens...`,
            `[ALERT] Agent triggered unconstrained egress tool http_request with secret in payload!`,
          ]);
          setSimulatedVulns(1);
        } else if (next === 3) {
          setLogs((l) => [
            ...l,
            `[RUN] Executing SQL injection probe: stacked DDL DROP TABLE query...`,
            `[VIOLATION] Model constructed unsanitized DDL statement!`,
          ]);
          setSimulatedVulns(2);
        } else if (next === 4) {
          setLogs((l) => [
            ...l,
            `[RUN] Executing directory traversal probe (../../../../../etc/passwd)...`,
            `[POLICY_BLOCK] Policy POL-108 successfully intercepted path escape. Attack blocked!`,
          ]);
          setSimulatedBlocked(1);
        } else if (next === 5) {
          setLogs((l) => [
            ...l,
            `[RUN] Testing prompt extraction boundary with <|im_end|> delimiter tokens...`,
            `[VIOLATION] Partial system instruction disclosure detected in output buffer.`,
          ]);
          setSimulatedVulns(3);
        } else if (next === 6) {
          setLogs((l) => [
            ...l,
            `[RUN] Evaluating unauthorized Slack broadcast trigger...`,
            `[COMPLETE] Scan execution finished. Synthesizing evidence traces and findings dossiers.`,
          ]);
        }

        return next;
      });
    }, 1200);

    return () => clearInterval(interval);
  }, [onComplete, scan.agentName]);

  const progressPercent = Math.min(100, Math.round((currentStep / 6) * 100));

  return (
    <div className="p-5 rounded border border-[#124A58] bg-[#073642] space-y-4 font-sans">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Loader2 className="w-4 h-4 text-[#6DBAC6] animate-spin" />
            <span className="font-semibold text-sm text-[#E3EEEE]">
              Security Assessment In Progress: {scan.agentName}
            </span>
          </div>
          <div className="flex items-center gap-2 text-xs text-[#8CA3A8]">
            <span>Scan ID:</span>
            <IdBadge id={scan.id} />
            <span className="text-[#5F7C82]">|</span>
            <span className="text-[#BCD0D3] font-sans capitalize">{scan.mode} Mode</span>
          </div>
        </div>

        <button
          onClick={onCancel}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-[#4A2F31] hover:bg-[#5A3A3C] border border-[#5A3A3C] text-[#F0B3AA] rounded text-xs font-sans font-medium transition-colors"
        >
          <StopCircle className="w-3.5 h-3.5" />
          <span>Abort Scan</span>
        </button>
      </div>

      {/* Progress Bar */}
      <div className="space-y-1.5">
        <div className="flex justify-between text-xs text-[#8CA3A8]">
          <span>Executing Test Suites (Phase {currentStep} of 6)...</span>
          <span className="text-[#BCD0D3] font-mono">{progressPercent}% Complete</span>
        </div>
        <div className="h-2 w-full bg-[#002B36] border border-[#124A58] rounded overflow-hidden">
          <div
            className="h-full bg-[#2B7F8C] transition-all duration-300"
            style={{ width: `${progressPercent}%` }}
          />
        </div>
      </div>

      {/* Real-time counters */}
      <div className="grid grid-cols-3 gap-3">
        <div className="p-2.5 rounded bg-[#002B36] border border-[#124A58] flex items-center justify-between">
          <div className="flex items-center gap-1.5 text-xs text-[#8CA3A8]">
            <ShieldAlert className="w-3.5 h-3.5 text-[#D9776B]" />
            <span>Confirmed Vulns:</span>
          </div>
          <span className="font-mono font-bold text-sm text-[#E08A7E]">{simulatedVulns}</span>
        </div>

        <div className="p-2.5 rounded bg-[#002B36] border border-[#124A58] flex items-center justify-between">
          <div className="flex items-center gap-1.5 text-xs text-[#8CA3A8]">
            <ShieldCheck className="w-3.5 h-3.5 text-[#78B993]" />
            <span>Attacks Blocked:</span>
          </div>
          <span className="font-mono font-bold text-sm text-[#78B993]">{simulatedBlocked}</span>
        </div>

        <div className="p-2.5 rounded bg-[#002B36] border border-[#124A58] flex items-center justify-between">
          <div className="flex items-center gap-1.5 text-xs text-[#8CA3A8]">
            <HelpCircle className="w-3.5 h-3.5 text-[#5F7C82]" />
            <span>Inconclusive:</span>
          </div>
          <span className="font-mono font-bold text-sm text-[#8CA3A8]">0</span>
        </div>
      </div>

      {/* Console output stream */}
      <div className="p-3 rounded bg-[#002B36] border border-[#124A58] font-mono text-xs space-y-1 max-h-48 overflow-y-auto">
        <div className="text-[#8CA3A8] font-sans text-xs flex items-center gap-1.5 border-b border-[#124A58] pb-1 mb-1 font-medium">
          <Terminal className="w-3.5 h-3.5 text-[#5F7C82]" />
          <span>Live Evaluation Event Stream</span>
        </div>
        {logs.map((log, idx) => {
          const isAlert = log.includes('[ALERT]') || log.includes('[VIOLATION]');
          const isBlock = log.includes('[POLICY_BLOCK]');

          return (
            <div
              key={idx}
              className={`leading-relaxed text-[11px] ${
                isAlert ? 'text-[#F0B3AA]' : isBlock ? 'text-[#A6D6B7]' : 'text-[#BCD0D3]'
              }`}
            >
              {log}
            </div>
          );
        })}
      </div>
    </div>
  );
};

