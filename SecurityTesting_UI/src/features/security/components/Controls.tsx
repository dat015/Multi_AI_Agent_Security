import React, { useRef } from "react";

interface ControlsProps {
  phase: string;
  onPhaseChange: (phase: string) => void;
  maxIter: number;
  onMaxIterChange: (iter: number) => void;
  configId: string;
  onConfigIdChange: (id: string) => void;
  onRunAnalysis: () => void;
  isRunning: boolean;
  isFileSelected: boolean;
  onDownloadTemplate: () => void;
  onUploadConfig: (file: File) => void;
  onExportConfig: () => void;
}

const Controls: React.FC<ControlsProps> = ({
  phase,
  onPhaseChange,
  maxIter,
  onMaxIterChange,
  configId,
  onConfigIdChange,
  onRunAnalysis,
  isRunning,
  isFileSelected,
  onDownloadTemplate,
  onUploadConfig,
  onExportConfig,
}) => {
  const configFileInputRef = useRef<HTMLInputElement>(null);

  const handleUploadClick = () => {
    configFileInputRef.current?.click();
  };

  const handleConfigFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      onUploadConfig(e.target.files[0]);
    }
    // Reset input value để cho phép upload lại cùng file
    e.target.value = "";
  };

  return (
    <div className="space-y-5">
      {/* === KHU VỰC CẤU HÌNH === */}
      <div className="bg-gray-800/30 rounded-xl border border-gray-700/50 p-4">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-gray-400">Phase</span>
            <select
              value={phase}
              onChange={(e) => onPhaseChange(e.target.value)}
              className="bg-gray-900 border border-gray-600 text-gray-200 px-3 py-1.5 rounded-lg text-sm focus:ring-2 focus:ring-blue-500/60"
            >
              <option value="phase1">Phase 1 — Recon + Planning</option>
              <option value="phase2">
                Phase 2 — Recon + Planning + Execution + Analyzer
              </option>
              <option value="full">Full Pipeline (Vòng lặp)</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-gray-400">Max Iter</span>
            <input
              type="number"
              value={maxIter}
              onChange={(e) =>
                onMaxIterChange(
                  Math.min(10, Math.max(1, parseInt(e.target.value) || 1))
                )
              }
              min={1}
              max={10}
              className="bg-gray-900 border border-gray-600 text-gray-200 px-3 py-1.5 rounded-lg text-sm w-20 text-center"
              title="Số vòng lặp tối đa"
            />
          </div>

          <div className="flex items-center gap-2 flex-1 min-w-[200px]">
            <span className="text-xs font-mono text-gray-400">Config ID</span>
            <input
              type="text"
              value={configId}
              onChange={(e) => onConfigIdChange(e.target.value)}
              placeholder="config_id (dùng để export)"
              className="bg-gray-900 border border-gray-600 text-gray-200 px-3 py-1.5 rounded-lg text-sm w-full"
            />
          </div>
        </div>
      </div>

      {/* === KHU VỰC NÚT THAO TÁC === */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        {/* Nút chính */}
        <button
          onClick={onRunAnalysis}
          disabled={isRunning || !isFileSelected}
          className={`
            px-6 py-2.5 rounded-xl font-semibold text-sm shadow-md transition-all duration-200
            flex items-center gap-2
            ${
              isRunning || !isFileSelected
                ? "bg-gray-700 text-gray-400 cursor-not-allowed shadow-none"
                : "bg-gradient-to-r from-blue-600 to-blue-500 hover:from-blue-500 hover:to-blue-400 text-white hover:scale-105 active:scale-95"
            }
          `}
        >
          <span>{isRunning ? "⏳" : "▶"}</span>
          <span>{isRunning ? "Đang chạy..." : "Chạy phân tích"}</span>
        </button>

        {/* Nhóm nút phụ */}
        <div className="flex flex-wrap gap-2">
          <button
            onClick={onDownloadTemplate}
            className="px-4 py-2 rounded-lg text-sm font-medium border border-gray-600 bg-gray-800/60 text-gray-300 hover:bg-gray-700 hover:border-gray-500 transition-all flex items-center gap-1.5"
          >
            📥 Tải mẫu config
          </button>

          <button
            onClick={handleUploadClick}
            className="px-4 py-2 rounded-lg text-sm font-medium border border-gray-600 bg-gray-800/60 text-gray-300 hover:bg-gray-700 hover:border-gray-500 transition-all flex items-center gap-1.5"
          >
            ⬆ Import config
          </button>

          <button
            onClick={onExportConfig}
            className="px-4 py-2 rounded-lg text-sm font-medium border border-amber-600/60 bg-gray-800/60 text-amber-400 hover:bg-amber-900/30 hover:border-amber-500 transition-all flex items-center gap-1.5"
          >
            ⬇ Export config
          </button>
        </div>
      </div>

      {/* Input file ẩn - không bao giờ hiển thị */}
      <input
        ref={configFileInputRef}
        type="file"
        accept=".json"
        onChange={handleConfigFileChange}
        className="hidden"
      />
    </div>
  );
};

export default Controls;