import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';
import { useToast } from './Toast';

interface CodeBlockProps {
  code: string;
  language?: string;
  filename?: string;
  showLineNumbers?: boolean;
  maxHeight?: string;
  className?: string;
}

export const CodeBlock: React.FC<CodeBlockProps> = ({
  code,
  language = 'text',
  filename,
  showLineNumbers = true,
  maxHeight = '400px',
  className = '',
}) => {
  const [copied, setCopied] = useState(false);
  const { showSuccess } = useToast();

  const handleCopy = () => {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true);
      showSuccess('Code copied to clipboard');
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const lines = code.trim().split('\n');

  return (
    <div className={`rounded border border-[#124A58] bg-[#002B36] overflow-hidden text-xs font-mono ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-1.5 bg-[#01212A] border-b border-[#124A58]">
        <div className="flex items-center gap-2 text-[#8CA3A8] font-mono text-[11px]">
          {filename ? (
            <span className="text-[#E3EEEE] font-medium">{filename}</span>
          ) : (
            <span className="uppercase tracking-wider text-[10px] text-[#5F7C82]">{language}</span>
          )}
        </div>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1 text-[11px] text-[#8CA3A8] hover:text-[#E3EEEE] px-2 py-0.5 rounded hover:bg-[#073642] transition-colors"
          title="Copy content"
        >
          {copied ? (
            <>
              <Check className="w-3 h-3 text-[#78B993]" />
              <span className="text-[#78B993]">Copied</span>
            </>
          ) : (
            <>
              <Copy className="w-3 h-3" />
              <span>Copy</span>
            </>
          )}
        </button>
      </div>

      {/* Code body */}
      <div className="overflow-x-auto overflow-y-auto p-3" style={{ maxHeight }}>
        <table className="w-full border-collapse">
          <tbody>
            {lines.map((line, idx) => {
              const isAdded = line.startsWith('+');
              const isRemoved = line.startsWith('-');
              const isHeader = line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++');

              let lineBg = '';
              let lineText = 'text-[#BCD0D3]';

              if (isAdded) {
                lineBg = 'bg-[#1D3D33]/60';
                lineText = 'text-[#A6D6B7] font-medium';
              } else if (isRemoved) {
                lineBg = 'bg-[#4A2F31]/60';
                lineText = 'text-[#F0B3AA]';
              } else if (isHeader) {
                lineBg = 'bg-[#0E4452]/40';
                lineText = 'text-[#6DBAC6] font-medium';
              }

              return (
                <tr key={idx} className={`${lineBg} leading-5`}>
                  {showLineNumbers && (
                    <td className="w-10 pr-3 text-right select-none text-[#5F7C82] border-r border-[#124A58]/40 font-mono text-[11px] align-top">
                      {idx + 1}
                    </td>
                  )}
                  <td className={`pl-3 whitespace-pre font-mono text-[12px] ${lineText}`}>
                    {line || ' '}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
