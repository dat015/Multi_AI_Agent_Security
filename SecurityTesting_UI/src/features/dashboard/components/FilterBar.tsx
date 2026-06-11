import React, { useState, useEffect } from 'react';
import { Filter, Search } from 'lucide-react';

interface FilterBarProps {
  onFilterChange: (filters: { vulnType: string; severity: string; role: string; endpoint: string }) => void;
}

const FilterBar: React.FC<FilterBarProps> = ({ onFilterChange }) => {
  const [vulnType, setVulnType] = useState('');
  const [severity, setSeverity] = useState('');
  const [role, setRole] = useState('');
  const [endpoint, setEndpoint] = useState('');

  // Call parent whenever a filter changes
  useEffect(() => {
    onFilterChange({ vulnType, severity, role, endpoint });
  }, [vulnType, severity, role, endpoint]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm flex flex-col md:flex-row gap-4 items-center mb-6">
      <div className="flex items-center gap-2 text-slate-700 mr-2">
        <Filter size={18} />
        <span className="font-medium">Lọc theo:</span>
      </div>
      
      <div className="w-full md:w-auto flex-1 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
        <select 
          className="bg-slate-50 border border-slate-200 text-slate-700 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5"
          value={vulnType}
          onChange={(e) => setVulnType(e.target.value)}
        >
          <option value="">Vuln type (Tất cả)</option>
          <option value="API1">API1: BOLA</option>
          <option value="API2">API2: Broken Auth</option>
          <option value="API3">API3: Mass Assignment</option>
          <option value="API4">API4: Resource Exhaustion</option>
          <option value="API8">API8: Misconfiguration</option>
        </select>
        
        <select 
          className="bg-slate-50 border border-slate-200 text-slate-700 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5"
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
        >
          <option value="">Severity (Tất cả)</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Safe">Safe</option>
        </select>

        <select 
          className="bg-slate-50 border border-slate-200 text-slate-700 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5"
          value={role}
          onChange={(e) => setRole(e.target.value)}
        >
          <option value="">Role (Tất cả)</option>
          <option value="attacker">Attacker</option>
          <option value="admin">Admin</option>
          <option value="victim">Victim</option>
        </select>

        <div className="relative">
          <div className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none">
            <Search size={16} className="text-slate-500" />
          </div>
          <input 
            type="text" 
            className="bg-slate-50 border border-slate-200 text-slate-700 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full pl-10 p-2.5" 
            placeholder="Tìm theo Endpoint..." 
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
          />
        </div>
      </div>
    </div>
  );
};

export default FilterBar;
