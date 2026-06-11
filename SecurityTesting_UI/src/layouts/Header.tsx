import React from 'react';
import { ShieldCheck, Download, FileJson, FileText, Bug } from 'lucide-react';
import { API } from '../lib/api';
import { cn } from '../lib/utils';

interface HeaderProps {
  sessionId?: string | null;
}

const Header: React.FC<HeaderProps> = ({ sessionId }) => {
  const handleDownloadJson = () => {
    if (sessionId) {
      window.open(API.getDownloadUrl(sessionId), '_blank');
    }
  };

  return (
    <header className="bg-slate-800 border-b border-slate-700 py-4 px-6 shadow-sm sticky top-0 z-10">
      <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-500/10 text-blue-400 rounded-lg">
            <ShieldCheck size={24} />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white tracking-tight uppercase flex items-center gap-2">
              Kết Quả Kiểm Thử Bảo Mật API
            </h1>
            <p className="text-sm text-slate-400">Security Dashboard & Report</p>
          </div>
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <button 
            disabled={!sessionId}
            className={cn("flex items-center gap-2 px-3 py-1.5 text-sm font-medium rounded-md transition-colors border",
              sessionId 
                ? "text-slate-300 bg-slate-700/50 hover:bg-slate-700 hover:text-white border-slate-600" 
                : "text-slate-500 bg-slate-800 border-slate-700 cursor-not-allowed"
            )}
          >
            <FileText size={16} />
            PDF
          </button>
          <button 
            disabled={!sessionId}
            onClick={handleDownloadJson}
            className={cn("flex items-center gap-2 px-3 py-1.5 text-sm font-medium rounded-md transition-colors border",
              sessionId 
                ? "text-slate-300 bg-slate-700/50 hover:bg-slate-700 hover:text-white border-slate-600" 
                : "text-slate-500 bg-slate-800 border-slate-700 cursor-not-allowed"
            )}
          >
            <FileJson size={16} />
            JSON
          </button>
          <button 
            disabled={!sessionId}
            className={cn("flex items-center gap-2 px-3 py-1.5 text-sm font-medium rounded-md transition-colors border",
              sessionId 
                ? "text-slate-300 bg-slate-700/50 hover:bg-slate-700 hover:text-white border-slate-600" 
                : "text-slate-500 bg-slate-800 border-slate-700 cursor-not-allowed"
            )}
          >
            <Download size={16} />
            CSV
          </button>
          <button 
            disabled={!sessionId}
            className={cn("flex items-center gap-2 px-3 py-1.5 text-sm font-medium rounded-md transition-colors ml-2",
              sessionId
                ? "text-white bg-blue-600 hover:bg-blue-700"
                : "text-slate-400 bg-slate-700 cursor-not-allowed"
            )}
          >
            <Bug size={16} />
            Jira Ticket
          </button>
        </div>
      </div>
    </header>
  );
};

export default Header;
