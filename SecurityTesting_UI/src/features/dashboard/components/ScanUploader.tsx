import React, { useState } from 'react';
import { Upload, FileCode, FileJson, AlertCircle } from 'lucide-react';
import { cn } from '../../../lib/utils';
import { API } from '../../../lib/api';

interface ScanUploaderProps {
  onScanStarted: (sessionId: string) => void;
}

const ScanUploader: React.FC<ScanUploaderProps> = ({ onScanStarted }) => {
  const [configFile, setConfigFile] = useState<File | null>(null);
  const [specFile, setSpecFile] = useState<File | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleStartScan = async () => {
    if (!specFile) {
      setError('Vui lòng chọn file OpenAPI Specification.');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      let configId: string | undefined = undefined;

      // 1. Upload config if provided
      if (configFile) {
        const configRes = await API.uploadConfig(configFile);
        if (configRes.status === 'ok' && configRes.config_id) {
          configId = configRes.config_id;
        } else {
          throw new Error(configRes.message || 'Lỗi khi upload config file.');
        }
      }

      // 2. Start analysis
      const phase = configId ? 'full' : 'recon';
      const analysisRes = await API.startAnalysis(specFile, phase, configId);
      if (analysisRes.session_id) {
        onScanStarted(analysisRes.session_id);
      } else {
        throw new Error('Không nhận được session_id từ server.');
      }
    } catch (err: any) {
      setError(err.response?.data?.message || err.message || 'Có lỗi xảy ra khi bắt đầu quét.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto mt-10 p-8 bg-slate-800 border border-slate-700 rounded-2xl shadow-lg">
      <div className="text-center mb-8">
        <h2 className="text-2xl font-bold text-white mb-2">Khởi tạo Quét Bảo mật API</h2>
        <p className="text-slate-400">Tải lên tài liệu đặc tả OpenAPI và cấu hình để bắt đầu phân tích.</p>
      </div>

      <div className="space-y-6">
        {/* Spec File Upload (Required) */}
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">
            OpenAPI Specification <span className="text-red-500">*</span>
          </label>
          <div className="relative">
            <input
              type="file"
              id="spec-upload"
              className="hidden"
              accept=".yaml,.yml,.json"
              onChange={(e) => setSpecFile(e.target.files?.[0] || null)}
            />
            <label
              htmlFor="spec-upload"
              className={cn(
                "flex items-center justify-center w-full px-4 py-6 border-2 border-dashed rounded-xl cursor-pointer transition-colors",
                specFile ? "border-blue-500 bg-blue-500/5" : "border-slate-600 hover:border-slate-500 bg-slate-900/50"
              )}
            >
              <div className="flex flex-col items-center gap-2">
                <FileCode className={specFile ? "text-blue-400" : "text-slate-400"} size={32} />
                {specFile ? (
                  <span className="text-sm font-medium text-blue-300">{specFile.name}</span>
                ) : (
                  <span className="text-sm text-slate-400">Kéo thả hoặc Click để tải lên file .yaml, .json</span>
                )}
              </div>
            </label>
          </div>
        </div>

        {/* Config File Upload (Optional) */}
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">
            File Cấu hình (Tùy chọn)
          </label>
          <div className="relative">
            <input
              type="file"
              id="config-upload"
              className="hidden"
              accept=".json"
              onChange={(e) => setConfigFile(e.target.files?.[0] || null)}
            />
            <label
              htmlFor="config-upload"
              className={cn(
                "flex items-center justify-center w-full px-4 py-4 border-2 border-dashed rounded-xl cursor-pointer transition-colors",
                configFile ? "border-green-500 bg-green-500/5" : "border-slate-600 hover:border-slate-500 bg-slate-900/50"
              )}
            >
              <div className="flex items-center gap-3">
                <FileJson className={configFile ? "text-green-400" : "text-slate-400"} size={24} />
                {configFile ? (
                  <span className="text-sm font-medium text-green-300">{configFile.name}</span>
                ) : (
                  <span className="text-sm text-slate-400">Tải lên file config.json</span>
                )}
              </div>
            </label>
          </div>
        </div>

        {error && (
          <div className="flex items-center gap-2 p-4 text-sm text-red-200 bg-red-500/10 border border-red-500/20 rounded-lg">
            <AlertCircle size={18} className="text-red-400" />
            {error}
          </div>
        )}

        <button
          onClick={handleStartScan}
          disabled={!specFile || isLoading}
          className="w-full flex items-center justify-center gap-2 py-3 px-4 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-700 disabled:text-slate-500 text-white font-medium rounded-xl transition-colors"
        >
          {isLoading ? (
            <span className="animate-spin w-5 h-5 border-2 border-white/30 border-t-white rounded-full"></span>
          ) : (
            <Upload size={20} />
          )}
          {isLoading ? 'Đang khởi tạo...' : 'Bắt đầu quét'}
        </button>
      </div>
    </div>
  );
};

export default ScanUploader;
