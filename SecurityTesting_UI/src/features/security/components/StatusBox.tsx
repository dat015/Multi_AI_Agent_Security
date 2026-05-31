// src/components/StatusBox.tsx
import React from 'react';

interface StatusBoxProps {
  status: 'idle' | 'running' | 'done' | 'error';
  message: string;
}

const StatusBox: React.FC<StatusBoxProps> = ({ status, message }) => {
  if (status === 'idle') return null;

  const getBadgeStyles = () => {
    switch (status) {
      case 'running':
        return 'bg-blue-900/50 text-blue-400 border border-blue-500/30';
      case 'done':
        return 'bg-green-900/50 text-green-400 border border-green-500/30';
      case 'error':
        return 'bg-red-900/50 text-red-400 border border-red-500/30';
      default:
        return 'bg-gray-800 text-gray-400';
    }
  };

  const getBadgeText = () => {
    switch (status) {
      case 'running':
        return 'Đang chạy...';
      case 'done':
        return 'Hoàn thành';
      case 'error':
        return 'Lỗi';
      default:
        return '';
    }
  };

  return (
    <div className="bg-gray-800/50 backdrop-blur-sm rounded-xl p-5 mb-6 border border-gray-700">
      <div className="text-xs text-gray-400 uppercase tracking-wide mb-2">Trạng thái</div>
      <div className="flex items-center gap-3">
        {status === 'running' && (
          <div className="w-4 h-4 border-2 border-gray-600 border-t-blue-500 rounded-full animate-spin"></div>
        )}
        <span className={`px-3 py-1 rounded-full text-xs font-medium ${getBadgeStyles()}`}>
          {getBadgeText()}
        </span>
      </div>
      <div className="mt-3 text-sm text-gray-300">{message}</div>
    </div>
  );
};

export default StatusBox;