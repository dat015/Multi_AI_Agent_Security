import React, { useState } from 'react';
import { ShieldCheck, Download, FileJson, FileText, Bug, History } from 'lucide-react';
import { API } from '../lib/api';
import { cn } from '../lib/utils';
import HistoryModal from '../components/HistoryModal';

interface HeaderProps {
  sessionId?: string | null;
  onSelectSession?: (sessionId: string) => void;
}

const Header: React.FC<HeaderProps> = ({ sessionId, onSelectSession }) => {
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);

  const handleDownloadJson = () => {
    if (sessionId) {
      window.open(API.getDownloadUrl(sessionId), '_blank');
    }
  };

  return (
    <header className="bg-white border-b border-slate-200 py-4 px-6 shadow-sm sticky top-0 z-10">
      <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-500/10 text-blue-400 rounded-lg">
            <ShieldCheck size={24} />
          </div>
          <div>
            <h1 className="text-xl font-bold text-slate-900 tracking-tight uppercase flex items-center gap-2">
              Kết Quả Kiểm Thử Bảo Mật API
            </h1>
            <p className="text-sm text-slate-600">Security Dashboard & Report</p>
          </div>
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <button
            onClick={() => setIsHistoryOpen(true)}
            className="flex items-center gap-2 px-3 py-1.5 text-sm font-medium rounded-md transition-colors border text-slate-700 bg-white hover:bg-slate-50 border-slate-300 mr-2"
          >
            <History size={16} />
            Lịch sử
          </button>


        </div>
      </div>

      <HistoryModal
        isOpen={isHistoryOpen}
        onClose={() => setIsHistoryOpen(false)}
        onSelectSession={(id) => {
          if (onSelectSession) onSelectSession(id);
        }}
      />
    </header>
  );
};

export default Header;
