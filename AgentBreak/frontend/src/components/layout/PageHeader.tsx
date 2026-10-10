import React from 'react';

interface PageHeaderProps {
  title: string;
  subtitle?: string;
  badge?: React.ReactNode;
  actions?: React.ReactNode;
  className?: string;
}

export const PageHeader: React.FC<PageHeaderProps> = ({
  title,
  subtitle,
  badge,
  actions,
  className = '',
}) => {
  return (
    <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-cyber-border ${className}`}>
      <div className="space-y-1">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-bold tracking-tight text-[#E3EEEE] font-sans">{title}</h1>
          {badge}
        </div>
        {subtitle && <p className="text-xs text-[#8CA3A8] font-sans leading-relaxed">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2.5 shrink-0">{actions}</div>}
    </div>
  );
};
