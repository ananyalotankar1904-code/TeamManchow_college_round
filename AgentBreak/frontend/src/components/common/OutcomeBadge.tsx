import React from 'react';
import { AttackOutcome } from '../../types';
import { ShieldAlert, ShieldCheck, PlayCircle, HelpCircle, AlertOctagon } from 'lucide-react';

interface OutcomeBadgeProps {
  outcome: AttackOutcome | string;
  size?: 'sm' | 'md';
  className?: string;
}

export const OutcomeBadge: React.FC<OutcomeBadgeProps> = ({
  outcome,
  size = 'md',
  className = '',
}) => {
  const norm = (outcome || 'inconclusive').toLowerCase() as AttackOutcome;

  let bg = 'bg-[#002B36]';
  let border = 'border-[#124A58]';
  let text = 'text-[#8CA3A8]';
  let label = 'Inconclusive';
  let Icon = HelpCircle;

  switch (norm) {
    case 'confirmed_vulnerable':
      bg = 'bg-[#4A2F31]';
      border = 'border-[#5A3A3C]';
      text = 'text-[#F0B3AA]';
      label = 'Confirmed Vulnerable';
      Icon = ShieldAlert;
      break;
    case 'blocked':
      bg = 'bg-[#1D3D33]';
      border = 'border-[#285547]';
      text = 'text-[#A6D6B7]';
      label = 'Attack Blocked';
      Icon = ShieldCheck;
      break;
    case 'executed':
      bg = 'bg-[#4A3A25]';
      border = 'border-[#59462D]';
      text = 'text-[#EBC48E]';
      label = 'Action Executed';
      Icon = AlertOctagon;
      break;
    case 'attempted':
      bg = 'bg-[#0E3D48]';
      border = 'border-[#185260]';
      text = 'text-[#A5C7CF]';
      label = 'Attempted';
      Icon = PlayCircle;
      break;
    case 'inconclusive':
    default:
      bg = 'bg-[#002B36]';
      border = 'border-[#124A58]';
      text = 'text-[#8CA3A8]';
      label = 'Inconclusive';
      Icon = HelpCircle;
      break;
  }

  const sizeClasses = {
    sm: 'px-1.5 py-0.5 text-[11px] gap-1',
    md: 'px-2 py-0.5 text-xs gap-1.5',
  };

  return (
    <span
      className={`inline-flex items-center font-sans font-medium rounded border select-none ${bg} ${border} ${text} ${sizeClasses[size]} ${className}`}
    >
      <Icon className="w-3 h-3 shrink-0" />
      <span>{label}</span>
    </span>
  );
};

