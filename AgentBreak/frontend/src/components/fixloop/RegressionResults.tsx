import React, { useState } from 'react';
import { RegressionTest } from '../../types';
import { CheckCircle2, XCircle, Clock, ChevronDown, ChevronRight, ShieldCheck } from 'lucide-react';

interface RegressionResultsProps {
  tests: RegressionTest[];
}

export const RegressionResults: React.FC<RegressionResultsProps> = ({ tests }) => {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const passedCount = tests.filter((t) => t.status === 'passed').length;
  const failedCount = tests.filter((t) => t.status === 'failed').length;
  const totalCount = tests.length;

  return (
    <div className="rounded border border-[#124A58] bg-[#073642] overflow-hidden space-y-3 p-4 font-sans">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-[#124A58]">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-[#78B993]" />
          <span className="text-xs font-semibold text-[#E3EEEE] font-sans">
            Benign Functional Regression Suite
          </span>
        </div>
        <div className="flex items-center gap-2 font-sans text-xs">
          <span className="px-2 py-0.5 rounded bg-[#1D3D33] border border-[#285547] text-[#A6D6B7] font-medium">
            {passedCount} / {totalCount} Passed
          </span>
          {failedCount > 0 && (
            <span className="px-2 py-0.5 rounded bg-[#4A2F31] border border-[#5A3A3C] text-[#F0B3AA] font-medium">
              {failedCount} Regressions
            </span>
          )}
        </div>
      </div>

      <div className="space-y-1.5">
        {tests.map((test) => {
          const isPassed = test.status === 'passed';
          const isExpanded = expandedId === test.id;

          return (
            <div
              key={test.id}
              className={`rounded border transition-colors ${
                isPassed
                  ? 'border-[#285547] bg-[#1D3D33]/40'
                  : test.status === 'failed'
                  ? 'border-[#5A3A3C] bg-[#4A2F31]/40'
                  : 'border-[#124A58] bg-[#002B36]'
              }`}
            >
              <div
                onClick={() => setExpandedId(isExpanded ? null : test.id)}
                className="px-3 py-2 flex items-center justify-between gap-3 cursor-pointer text-xs select-none"
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  {isPassed ? (
                    <CheckCircle2 className="w-4 h-4 text-[#78B993] shrink-0" />
                  ) : (
                    <XCircle className="w-4 h-4 text-[#D9776B] shrink-0" />
                  )}
                  <span className="font-medium text-[#E3EEEE] font-sans truncate">{test.name}</span>
                  <span className="px-1.5 py-0.2 rounded bg-[#002B36] border border-[#124A58] text-[11px] text-[#8CA3A8] hidden sm:inline font-sans">
                    {test.category}
                  </span>
                </div>

                <div className="flex items-center gap-2 shrink-0 text-xs text-[#8CA3A8]">
                  <span className="flex items-center gap-1 text-[#5F7C82] font-mono text-[11px]">
                    <Clock className="w-3 h-3" />
                    <span>{test.executionMs}ms</span>
                  </span>
                  {isExpanded ? <ChevronDown className="w-3.5 h-3.5 text-[#8CA3A8]" /> : <ChevronRight className="w-3.5 h-3.5 text-[#8CA3A8]" />}
                </div>
              </div>

              {isExpanded && (
                <div className="p-3 border-t border-[#124A58] bg-[#002B36] text-xs font-sans space-y-2">
                  <div className="text-[#8CA3A8] text-xs">{test.description}</div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 pt-1">
                    <div className="space-y-1">
                      <div className="text-xs text-[#8CA3A8] font-medium">Input:</div>
                      <div className="p-2 rounded bg-[#073642] border border-[#124A58] text-[#E3EEEE] text-xs font-mono">
                        {test.input}
                      </div>
                    </div>
                    <div className="space-y-1">
                      <div className="text-xs text-[#8CA3A8] font-medium">Actual Safe Output:</div>
                      <div className="p-2 rounded bg-[#1D3D33]/40 border border-[#285547] text-[#A6D6B7] text-xs font-mono">
                        {test.actualOutcome}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

