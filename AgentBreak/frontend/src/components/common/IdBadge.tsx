import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';
import { useToast } from './Toast';

interface IdBadgeProps {
  id: string;
  prefix?: string;
  truncateLength?: number;
  showCopy?: boolean;
  className?: string;
}

export const IdBadge: React.FC<IdBadgeProps> = ({
  id,
  prefix,
  truncateLength = 12,
  showCopy = true,
  className = '',
}) => {
  const [copied, setCopied] = useState(false);
  const { showSuccess } = useToast();

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(id).then(
      () => {
        setCopied(true);
        showSuccess(`Copied ${id} to clipboard`);
        setTimeout(() => setCopied(false), 2000);
      },
      () => {
        // Fallback
        showSuccess(`Selected: ${id}`);
      }
    );
  };

  const displayText =
    id.length > truncateLength ? `${id.substring(0, truncateLength)}…` : id;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-1.5 py-0.5 rounded bg-[#002B36] border border-[#124A58] font-mono text-[11px] text-[#BCD0D3] group hover:border-[#2B7F8C] transition-colors ${className}`}
      title={`Full identifier: ${id} (Click to copy)`}
      onClick={showCopy ? handleCopy : undefined}
      role={showCopy ? 'button' : undefined}
      tabIndex={showCopy ? 0 : undefined}
      onKeyDown={(e) => {
        if (showCopy && (e.key === 'Enter' || e.key === ' ')) {
          e.preventDefault();
          handleCopy(e as unknown as React.MouseEvent);
        }
      }}
    >
      {prefix && <span className="text-[#5F7C82]">{prefix}:</span>}
      <span className="select-all tracking-tight">{displayText}</span>
      {showCopy && (
        <span className="text-[#5F7C82] group-hover:text-[#6DBAC6] transition-colors shrink-0">
          {copied ? <Check className="w-3 h-3 text-[#78B993]" /> : <Copy className="w-3 h-3" />}
        </span>
      )}
    </span>
  );
};
