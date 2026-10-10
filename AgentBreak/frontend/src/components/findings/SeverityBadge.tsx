import React from 'react';
import { Severity } from '../../types';
import { ShieldAlert, AlertTriangle, AlertCircle, Info, ShieldCheck } from 'lucide-react';

interface SeverityBadgeProps {
  severity: Severity | string;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
  className?: string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = 'md',
  showIcon = true,
  className = '',
}) => {
  const normSeverity = (severity || 'info').toLowerCase();

  let bgClass = 'bg-[#0E3D48]';
  let borderClass = 'border-[#185260]';
  let textClass = 'text-[#A5C7CF]';
  let label = 'Info';
  let Icon = Info;

  switch (normSeverity) {
    case 'critical':
      bgClass = 'bg-[#4A2F31]';
      borderClass = 'border-[#5A3A3C]';
      textClass = 'text-[#F0B3AA]';
      label = 'Critical';
      Icon = ShieldAlert;
      break;
    case 'high':
      bgClass = 'bg-[#4A3A25]';
      borderClass = 'border-[#59462D]';
      textClass = 'text-[#EBC48E]';
      label = 'High';
      Icon = AlertTriangle;
      break;
    case 'medium':
      bgClass = 'bg-[#3D3620]';
      borderClass = 'border-[#544A2C]';
      textClass = 'text-[#E2C98F]';
      label = 'Medium';
      Icon = AlertCircle;
      break;
    case 'low':
      bgClass = 'bg-[#0E3D48]';
      borderClass = 'border-[#185260]';
      textClass = 'text-[#A5C7CF]';
      label = 'Low';
      Icon = Info;
      break;
    case 'passed':
    case 'success':
      bgClass = 'bg-[#1D3D33]';
      borderClass = 'border-[#285547]';
      textClass = 'text-[#A6D6B7]';
      label = 'Passed';
      Icon = ShieldCheck;
      break;
    default:
      break;
  }

  const sizeClasses = {
    sm: 'px-1.5 py-0.5 text-[11px] gap-1',
    md: 'px-2 py-0.5 text-xs gap-1.5',
    lg: 'px-2.5 py-1 text-xs gap-1.5 font-medium',
  };

  const iconSizes = {
    sm: 'w-3 h-3',
    md: 'w-3.5 h-3.5',
    lg: 'w-4 h-4',
  };

  return (
    <span
      className={`inline-flex items-center font-sans font-medium rounded border select-none ${bgClass} ${borderClass} ${textClass} ${sizeClasses[size]} ${className}`}
    >
      {showIcon && <Icon className={`${iconSizes[size]} shrink-0`} />}
      <span>{label}</span>
    </span>
  );
};

