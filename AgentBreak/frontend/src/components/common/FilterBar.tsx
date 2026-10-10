import React from 'react';
import { Search, X } from 'lucide-react';
import { FilterState, Severity, AttackCategory, AttackOutcome } from '../../types';

interface FilterBarProps {
  filterState: FilterState;
  onFilterChange: (newState: FilterState) => void;
  totalCount: number;
  filteredCount: number;
  showCategoryFilter?: boolean;
  showOutcomeFilter?: boolean;
  className?: string;
}

export const FilterBar: React.FC<FilterBarProps> = ({
  filterState,
  onFilterChange,
  totalCount,
  filteredCount,
  showCategoryFilter = true,
  showOutcomeFilter = true,
  className = '',
}) => {
  const handleSearch = (e: React.ChangeEvent<HTMLInputElement>) => {
    onFilterChange({ ...filterState, searchQuery: e.target.value });
  };

  const handleSeverityChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    onFilterChange({ ...filterState, severity: e.target.value as Severity | 'all' });
  };

  const handleCategoryChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    onFilterChange({ ...filterState, category: e.target.value as AttackCategory | 'all' });
  };

  const handleOutcomeChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    onFilterChange({ ...filterState, outcome: e.target.value as AttackOutcome | 'all' });
  };

  const handleClearFilters = () => {
    onFilterChange({
      severity: 'all',
      category: 'all',
      outcome: 'all',
      searchQuery: '',
    });
  };

  const isFiltered =
    filterState.severity !== 'all' ||
    filterState.category !== 'all' ||
    filterState.outcome !== 'all' ||
    filterState.searchQuery.trim() !== '';

  return (
    <div
      className={`flex flex-col md:flex-row md:items-center justify-between gap-3 p-3 bg-[#073642] border border-[#124A58] rounded text-xs font-sans ${className}`}
    >
      {/* Left: Search input */}
      <div className="flex-1 relative min-w-[220px]">
        <Search className="w-3.5 h-3.5 text-[#5F7C82] absolute left-2.5 top-1/2 -translate-y-1/2" />
        <input
          type="text"
          value={filterState.searchQuery}
          onChange={handleSearch}
          placeholder="Filter by ID, title, agent, tool, or keyword..."
          className="w-full bg-[#002B36] border border-[#124A58] rounded pl-8 pr-3 py-1.5 text-xs text-[#E3EEEE] placeholder-[#5F7C82] focus:outline-none focus:border-[#2B7F8C] font-sans"
        />
        {filterState.searchQuery && (
          <button
            onClick={() => onFilterChange({ ...filterState, searchQuery: '' })}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[#5F7C82] hover:text-[#E3EEEE]"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* Right: Dropdowns and Clear button */}
      <div className="flex flex-wrap items-center gap-2">
        {/* Severity */}
        <div className="flex items-center gap-1.5">
          <label htmlFor="filter-severity" className="text-[#8CA3A8] text-xs">Severity:</label>
          <select
            id="filter-severity"
            value={filterState.severity}
            onChange={handleSeverityChange}
            className="bg-[#002B36] border border-[#124A58] text-[#E3EEEE] rounded px-2 py-1 text-xs focus:outline-none focus:border-[#2B7F8C] font-sans"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>

        {/* Category */}
        {showCategoryFilter && (
          <div className="flex items-center gap-1.5">
            <label htmlFor="filter-category" className="text-[#8CA3A8] text-xs">Category:</label>
            <select
              id="filter-category"
              value={filterState.category}
              onChange={handleCategoryChange}
              className="bg-[#002B36] border border-[#124A58] text-[#E3EEEE] rounded px-2 py-1 text-xs focus:outline-none focus:border-[#2B7F8C] font-sans max-w-[160px] truncate"
            >
              <option value="all">All Categories</option>
              <option value="direct_prompt_injection">Direct Prompt Injection</option>
              <option value="indirect_rag_injection">Indirect RAG Injection</option>
              <option value="unauthorized_tool_execution">Unauthorized Tool Exec</option>
              <option value="sensitive_data_leakage">Sensitive Data Leakage</option>
              <option value="unsafe_action_execution">Unsafe Action Exec</option>
              <option value="permission_policy_violation">Policy Violation</option>
            </select>
          </div>
        )}

        {/* Outcome */}
        {showOutcomeFilter && (
          <div className="flex items-center gap-1.5">
            <label htmlFor="filter-outcome" className="text-[#8CA3A8] text-xs">Outcome:</label>
            <select
              id="filter-outcome"
              value={filterState.outcome}
              onChange={handleOutcomeChange}
              className="bg-[#002B36] border border-[#124A58] text-[#E3EEEE] rounded px-2 py-1 text-xs focus:outline-none focus:border-[#2B7F8C] font-sans"
            >
              <option value="all">All Outcomes</option>
              <option value="confirmed_vulnerable">Confirmed Vulnerable</option>
              <option value="blocked">Attack Blocked</option>
              <option value="executed">Action Executed</option>
              <option value="attempted">Attempted</option>
              <option value="inconclusive">Inconclusive</option>
            </select>
          </div>
        )}

        {/* Clear Filters */}
        {isFiltered && (
          <button
            onClick={handleClearFilters}
            className="flex items-center gap-1.5 px-2 py-1 rounded bg-[#0E4452] hover:bg-[#155A6B] text-[#BFE3E8] text-xs font-sans transition-colors"
            title="Reset all filters"
          >
            <X className="w-3 h-3 text-[#8CA3A8]" />
            <span>Clear</span>
          </button>
        )}

        {/* Count Counter */}
        <div className="text-xs text-[#8CA3A8] pl-1 font-sans">
          Showing <span className="text-[#E3EEEE] font-medium">{filteredCount}</span> of {totalCount}
        </div>
      </div>
    </div>
  );
};

