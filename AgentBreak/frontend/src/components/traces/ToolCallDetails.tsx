import React from 'react';
import { CodeBlock } from '../common/CodeBlock';
import { Wrench, Clock, CheckCircle2, XCircle } from 'lucide-react';

interface ToolCallDetailsProps {
  toolName: string;
  argumentsPayload: Record<string, unknown>;
  responsePayload?: unknown;
  status?: 'success' | 'failed' | 'blocked';
  durationMs?: number;
  timestamp?: string;
}

export const ToolCallDetails: React.FC<ToolCallDetailsProps> = ({
  toolName,
  argumentsPayload,
  responsePayload,
  status = 'success',
  durationMs,
  timestamp,
}) => {
  return (
    <div className="p-4 rounded border border-[#124A58] bg-[#073642] space-y-3 text-xs">
      <div className="flex items-center justify-between pb-2 border-b border-[#124A58]">
        <div className="flex items-center gap-2">
          <div className="p-1 rounded bg-[#002B36] border border-[#124A58] text-[#6DBAC6]">
            <Wrench className="w-3.5 h-3.5" />
          </div>
          <span className="font-mono text-[#E3EEEE] text-sm font-medium">{toolName}</span>
        </div>

        <div className="flex items-center gap-2 text-[11px]">
          {status === 'success' ? (
            <span className="flex items-center gap-1 text-[#A6D6B7] bg-[#1D3D33] border border-[#285547] px-1.5 py-0.5 rounded font-sans text-[11px] font-medium">
              <CheckCircle2 className="w-3 h-3" />
              <span>Success</span>
            </span>
          ) : (
            <span className="flex items-center gap-1 text-[#F0B3AA] bg-[#4A2F31] border border-[#5A3A3C] px-1.5 py-0.5 rounded font-sans text-[11px] font-medium">
              <XCircle className="w-3 h-3" />
              <span>Blocked / Error</span>
            </span>
          )}
          {durationMs !== undefined && <span className="font-mono text-[#8CA3A8]">{durationMs} ms</span>}
        </div>
      </div>

      <div className="space-y-1">
        <div className="text-[11px] text-[#8CA3A8] font-sans font-medium">Arguments:</div>
        <CodeBlock
          code={JSON.stringify(argumentsPayload, null, 2)}
          language="json"
          showLineNumbers={false}
          maxHeight="200px"
        />
      </div>

      {responsePayload !== undefined && (
        <div className="space-y-1">
          <div className="text-[11px] text-[#8CA3A8] font-sans font-medium">Return Value:</div>
          <CodeBlock
            code={typeof responsePayload === 'string' ? responsePayload : JSON.stringify(responsePayload, null, 2)}
            language="json"
            showLineNumbers={false}
            maxHeight="200px"
          />
        </div>
      )}

      {timestamp && (
        <div className="text-[11px] font-sans text-[#8CA3A8] flex items-center gap-1 pt-1">
          <Clock className="w-3 h-3 text-[#5F7C82]" />
          <span>Timestamp: <span className="font-mono text-[#BCD0D3]">{timestamp}</span></span>
        </div>
      )}
    </div>
  );
};
