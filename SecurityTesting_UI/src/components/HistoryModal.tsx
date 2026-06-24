import React, { useEffect, useState } from 'react';
import { API, type ScanHistoryItem } from '../lib/api';
import { X, Clock, AlertCircle, CheckCircle } from 'lucide-react';
import { cn } from '../lib/utils';

interface HistoryModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectSession: (sessionId: string) => void;
}

const HistoryModal: React.FC<HistoryModalProps> = ({ isOpen, onClose, onSelectSession }) => {
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      fetchHistory();
    }
  }, [isOpen]);

  const fetchHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await API.getHistory();
      setHistory(data);
    } catch (err: any) {
      setError(err.message || 'Không thể tải lịch sử');
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-2xl flex flex-col max-h-[80vh]">
        <div className="flex items-center justify-between p-4 border-b border-slate-200">
          <h2 className="text-lg font-bold text-slate-800 flex items-center gap-2">
            <Clock size={20} className="text-blue-500" />
            Lịch Sử Kiểm Thử
          </h2>
          <button onClick={onClose} className="p-1 hover:bg-slate-100 rounded-lg transition-colors">
            <X size={20} className="text-slate-500" />
          </button>
        </div>

        <div className="p-4 flex-1 overflow-y-auto">
          {loading ? (
            <div className="text-center text-slate-500 py-8">Đang tải...</div>
          ) : error ? (
            <div className="text-center text-red-500 py-8 flex flex-col items-center gap-2">
              <AlertCircle size={24} />
              {error}
            </div>
          ) : history.length === 0 ? (
            <div className="text-center text-slate-500 py-8">Chưa có lịch sử kiểm thử nào.</div>
          ) : (
            <div className="space-y-3">
              {history.map((item) => (
                <div 
                  key={item.session_id}
                  onClick={() => {
                    onSelectSession(item.session_id);
                    onClose();
                  }}
                  className="p-4 border border-slate-200 rounded-lg hover:border-blue-400 hover:shadow-md cursor-pointer transition-all bg-slate-50 flex justify-between items-center"
                >
                  <div>
                    <div className="font-mono text-xs text-slate-500 mb-1">ID: {item.session_id.substring(0, 8)}...</div>
                    <div className="text-sm text-slate-700">
                      {new Date(item.created_at).toLocaleString('vi-VN')}
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    <div className="text-sm font-medium text-slate-700">
                      <span className="text-red-500">{item.endpoints_found || 0}</span> lỗ hổng
                    </div>
                    {item.status === 'done' ? (
                      <span className="flex items-center gap-1 text-xs font-medium text-green-600 bg-green-100 px-2 py-1 rounded-md">
                        <CheckCircle size={14} /> Hoàn thành
                      </span>
                    ) : item.status === 'error' ? (
                      <span className="flex items-center gap-1 text-xs font-medium text-red-600 bg-red-100 px-2 py-1 rounded-md">
                        <AlertCircle size={14} /> Lỗi
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-xs font-medium text-blue-600 bg-blue-100 px-2 py-1 rounded-md">
                        <Clock size={14} /> Đang chạy
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default HistoryModal;
