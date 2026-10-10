import React from 'react';
import { ScanStatus } from '../../types';
import { Loader2 } from 'lucide-react';

interface StatusBadgeProps {
  status: ScanStatus | string;
  size?: 'sm' | 'md';
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  status,
  size = 'md',
  className = '',
}) => {
  const norm = (status || 'idle').toLowerCase() as ScanStatus;

  let bg = 'bg-[#002B36]';
  let border = 'border-[#124A58]';
  let text = 'text-[#8CA3A8]';
  let dotColor = 'bg-[#5F7C82]';
  let label = 'Idle';
  let isRunning = false;

  switch (norm) {
    case 'running':
      bg = 'bg-[#0E3D48]';
      border = 'border-[#185260]';
      text = 'text-[#A5C7CF]';
      dotColor = 'bg-[#6DBAC6]';
      label = 'Running';
      isRunning = true;
      break;
    case 'completed':
      bg = 'bg-[#1D3D33]';
      border = 'border-[#285547]';
      text = 'text-[#A6D6B7]';
      dotColor = 'bg-[#78B993]';
      label = 'Completed';
      break;
    case 'queued':
      bg = 'bg-[#3D3620]';
      border = 'border-[#544A2C]';
      text = 'text-[#E2C98F]';
      dotColor = 'bg-[#C8AE5A]';
      label = 'Queued';
      break;
    case 'failed':
      bg = 'bg-[#4A2F31]';
      border = 'border-[#5A3A3C]';
      text = 'text-[#F0B3AA]';
      dotColor = 'bg-[#D9776B]';
      label = 'Failed';
      break;
    case 'cancelled':
      bg = 'bg-[#002B36]';
      border = 'border-[#124A58]';
      text = 'text-[#8CA3A8]';
      dotColor = 'bg-[#5F7C82]';
      label = 'Cancelled';
      break;
    case 'idle':
    default:
      bg = 'bg-[#002B36]';
      border = 'border-[#124A58]';
      text = 'text-[#8CA3A8]';
      dotColor = 'bg-[#5F7C82]';
      label = 'Idle';
      break;
  }

  const sizeClasses = {
    sm: 'px-2 py-0.5 text-[11px] gap-1.5',
    md: 'px-2.5 py-0.5 text-xs gap-1.5',
  };

  return (
    <span
      className={`inline-flex items-center font-sans font-medium rounded border select-none ${bg} ${border} ${text} ${sizeClasses[size]} ${className}`}
    >
      {isRunning ? (
        <Loader2 className="w-3 h-3 text-[#6DBAC6] animate-spin shrink-0" />
      ) : (
        <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dotColor}`} />
      )}
      <span>{label}</span>
    </span>
  );
};

