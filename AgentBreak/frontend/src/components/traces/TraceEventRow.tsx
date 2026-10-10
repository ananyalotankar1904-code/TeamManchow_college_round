import React, { useState } from 'react';
import { TraceEvent } from '../../types';
import { IdBadge } from '../common/IdBadge';
import { CodeBlock } from '../common/CodeBlock';
import {
  User,
  Database,
  Brain,
  Wrench,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';

interface TraceEventRowProps {
  event: TraceEvent;
  defaultExpanded?: boolean;
  onSelectEvent?: (event: TraceEvent) => void;
  isSelected?: boolean;
}

export const TraceEventRow: React.FC<TraceEventRowProps> = ({
  event,
  defaultExpanded = false,
  onSelectEvent,
  isSelected = false,
}) => {
  const [expanded, setExpanded] = useState(defaultExpanded);

  const getEventIcon = (type: string) => {
    switch (type) {
      case 'USER_INPUT':
        return <User className="w-3.5 h-3.5 text-[#6DBAC6]" />;
      case 'RETRIEVAL':
        return <Database className="w-3.5 h-3.5 text-[#6DBAC6]" />;
      case 'MODEL_DECISION':
        return <Brain className="w-3.5 h-3.5 text-[#6DBAC6]" />;
      case 'TOOL_INVOCATION':
        return <Wrench className="w-3.5 h-3.5 text-[#D9A468]" />;
      case 'POLICY_EVALUATION':
        return event.isViolation ? (
          <ShieldAlert className="w-3.5 h-3.5 text-[#D9776B]" />
        ) : (
          <ShieldCheck className="w-3.5 h-3.5 text-[#78B993]" />
        );
      case 'TOOL_RESULT':
        return <CheckCircle2 className="w-3.5 h-3.5 text-[#8CA3A8]" />;
      case 'SECURITY_FINDING':
        return <ShieldAlert className="w-3.5 h-3.5 text-[#D9776B]" />;
      default:
        return <Brain className="w-3.5 h-3.5 text-[#8CA3A8]" />;
    }
  };

  const isViolation = event.isViolation;
  const isPolicyBlock = event.isPolicyBlock;

  return (
    <div
      onClick={() => onSelectEvent && onSelectEvent(event)}
      className={`rounded border transition-all select-none font-sans ${
        isViolation
          ? 'border-[#5A3A3C] bg-[#4A2F31]/70'
          : isPolicyBlock
          ? 'border-[#285547] bg-[#1D3D33]/70'
          : isSelected
          ? 'border-[#2B7F8C] bg-[#0E4452]'
          : 'border-[#124A58] bg-[#073642] hover:border-[#185B6C]'
      }`}
    >
      {/* Main Bar */}
      <div
        onClick={(e) => {
          e.stopPropagation();
          setExpanded(!expanded);
        }}
        className="px-3 py-2 flex items-center justify-between gap-3 cursor-pointer"
      >
        <div className="flex items-center gap-2.5 min-w-0">
          <button className="text-[#5F7C82] hover:text-[#E3EEEE] shrink-0">
            {expanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
          </button>

          <div className="p-1 rounded bg-[#002B36] border border-[#124A58] shrink-0">
            {getEventIcon(event.eventType)}
          </div>

          <div className="flex items-center gap-2 truncate">
            <span className="font-mono text-xs text-[#E3EEEE] font-medium">
              {event.eventType}
            </span>
            <span className="text-[#5F7C82]">·</span>
            <span className="text-xs text-[#8CA3A8] font-sans truncate">{event.actor}</span>
            {event.toolName && (
              <span className="px-1.5 py-0.2 rounded bg-[#002B36] border border-[#124A58] font-mono text-[11px] text-[#E2C98F]">
                tool: {event.toolName}
              </span>
            )}
          </div>
        </div>

        {/* Right Badges */}
        <div className="flex items-center gap-2 shrink-0 text-xs">
          {isViolation && (
            <span className="px-1.5 py-0.5 rounded bg-[#4A2F31] border border-[#5A3A3C] text-[#F0B3AA] font-sans font-medium text-[11px]">
              {event.ruleId || 'Security Violation'}
            </span>
          )}
          {isPolicyBlock && (
            <span className="px-1.5 py-0.5 rounded bg-[#1D3D33] border border-[#285547] text-[#A6D6B7] font-sans font-medium text-[11px]">
              Policy Block
            </span>
          )}
          {event.executionDurationMs !== undefined && (
            <span className="text-[#5F7C82] text-[11px] font-mono">{event.executionDurationMs}ms</span>
          )}
          <span className="text-[#5F7C82] text-[11px] font-mono hidden sm:inline">
            {event.timestamp.replace('T', ' ').substring(11, 23)}Z
          </span>
          <IdBadge id={event.id} truncateLength={8} />
        </div>
      </div>

      {/* Expanded Details */}
      {expanded && (
        <div
          className="p-3.5 border-t border-[#124A58] bg-[#002B36] text-xs space-y-3 font-sans"
          onClick={(e) => e.stopPropagation()}
        >
          {event.details && (
            <div
              className={`p-2.5 rounded border text-xs leading-relaxed ${
                isViolation
                  ? 'bg-[#4A2F31]/80 border-[#5A3A3C] text-[#F0B3AA]'
                  : isPolicyBlock
                  ? 'bg-[#1D3D33]/80 border-[#285547] text-[#A6D6B7]'
                  : 'bg-[#073642] border-[#124A58] text-[#E3EEEE]'
              }`}
            >
              <span className="font-semibold font-sans">Decision / Notice:</span> {event.details}
            </div>
          )}

          {event.input && (
            <div className="space-y-1">
              <div className="text-xs text-[#8CA3A8] font-medium">Input / Prompt Vector:</div>
              <CodeBlock
                code={typeof event.input === 'string' ? event.input : JSON.stringify(event.input, null, 2)}
                language={typeof event.input === 'string' ? 'text' : 'json'}
                showLineNumbers={false}
                maxHeight="160px"
              />
            </div>
          )}

          {event.arguments && (
            <div className="space-y-1">
              <div className="text-xs text-[#8CA3A8] font-medium">
                Tool Parameters & Arguments:
              </div>
              <CodeBlock
                code={JSON.stringify(event.arguments, null, 2)}
                language="json"
                showLineNumbers={false}
                maxHeight="180px"
              />
            </div>
          )}

          {event.output && (
            <div className="space-y-1">
              <div className="text-xs text-[#8CA3A8] font-medium">Output / Return Payload:</div>
              <CodeBlock
                code={typeof event.output === 'string' ? event.output : JSON.stringify(event.output, null, 2)}
                language={typeof event.output === 'string' ? 'text' : 'json'}
                showLineNumbers={false}
                maxHeight="180px"
              />
            </div>
          )}

          <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-[#124A58] text-xs text-[#5F7C82] font-mono">
            <div>
              Correlation ID: <span className="text-[#BCD0D3]">{event.correlationId || 'N/A'}</span>
            </div>
            <div>
              Status: <span className="text-[#BCD0D3] capitalize font-sans">{event.executionStatus}</span>
            </div>
            <div>
              Exact UTC: <span className="text-[#BCD0D3]">{event.timestamp}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

