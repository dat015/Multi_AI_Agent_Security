import React from 'react';
import { Activity } from 'lucide-react';

const ScanProgress: React.FC = () => {
  return (
    <div className="max-w-2xl mx-auto mt-20 p-8 bg-slate-800 border border-slate-700 rounded-2xl shadow-lg flex flex-col items-center justify-center min-h-[300px]">
      <div className="relative mb-8">
        <div className="w-24 h-24 rounded-full border-4 border-slate-700 border-t-blue-500 animate-spin flex items-center justify-center">
        </div>
        <div className="absolute inset-0 flex items-center justify-center">
          <Activity className="text-blue-500 animate-pulse" size={32} />
        </div>
      </div>
      <h2 className="text-2xl font-bold text-white mb-3">Đang quét bảo mật...</h2>
      <p className="text-slate-400 text-center max-w-md">
        Hệ thống đang phân tích API Specification và thực hiện các kịch bản tấn công giả lập. Vui lòng không đóng trang web.
      </p>
      
      {/* Fake progress bar for visual effect */}
      <div className="w-full max-w-md mt-8 h-2 bg-slate-700 rounded-full overflow-hidden relative">
        <div className="absolute top-0 left-0 h-full bg-blue-500 rounded-full animate-progress" style={{ width: '60%' }}></div>
      </div>
    </div>
  );
};

export default ScanProgress;
