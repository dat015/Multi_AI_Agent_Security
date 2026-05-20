import React from "react";

type Props = {
  phase: string;
  setPhase: (p: string) => void;
  maxIter: number;
  setMaxIter: (n: number) => void;
  runAnalysis: () => void;
  downloadTemplate: () => void;
  configId: string;
  setConfigId: (s: string) => void;
  configInputRef: React.RefObject<HTMLInputElement | null>;
  onConfigUploadClick: () => void;
  disabledRun?: boolean;
};

export const ControlsBar: React.FC<Props> = ({
  phase,
  setPhase,
  maxIter,
  setMaxIter,
  runAnalysis,
  downloadTemplate,
  configId,
  setConfigId,
  configInputRef,
  onConfigUploadClick,
  disabledRun,
}) => {
  const handleExport = () => {
    if (!configId) {
      alert("Vui lòng nhập config_id");
      return;
    }

    window.location.href = `/config/download/${configId}`;
  };

  return (
    <div className="rounded-3xl border border-slate-800/80 bg-slate-950/60 p-5 shadow-[0_0_0_1px_rgba(255,255,255,0.02)] backdrop-blur-xl">
      <div className="flex flex-col gap-5 xl:flex-row xl:items-center xl:justify-between">
        {/* Left section */}
        <div className="flex flex-col gap-4 lg:flex-row lg:flex-wrap lg:items-center">
          {/* Phase */}
          <div className="space-y-1">
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">
              Analysis Mode
            </label>

            <select
              value={phase}
              onChange={(e) =>
                setPhase(e.target.value)
              }
              className="
                h-11 min-w-[260px]
                rounded-2xl
                border border-slate-800
                bg-slate-900
                px-4
                text-sm
                text-slate-200
                outline-none
                transition-all
                duration-200
                hover:border-slate-700
                focus:border-blue-500
                focus:ring-4
                focus:ring-blue-500/15
              "
            >
              <option value="phase1">
                Phase 1 — Recon + Planning
              </option>

              <option value="full">
                Full Pipeline (5 agents)
              </option>
            </select>
          </div>

          {/* Max iteration */}
          <div className="space-y-1">
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">
              Max Iterations
            </label>

            <input
              type="number"
              min={1}
              max={10}
              value={maxIter}
              onChange={(e) =>
                setMaxIter(Number(e.target.value))
              }
              className="
                h-11 w-28
                rounded-2xl
                border border-slate-800
                bg-slate-900
                px-4
                text-sm
                text-slate-200
                outline-none
                transition-all
                hover:border-slate-700
                focus:border-blue-500
                focus:ring-4
                focus:ring-blue-500/15
              "
            />
          </div>

          {/* Primary actions */}
          <div className="flex gap-3 pt-5 lg:pt-0">
            <button
              onClick={runAnalysis}
              disabled={disabledRun}
              className="
                flex h-11 items-center gap-2
                rounded-2xl
                bg-blue-600
                px-5
                text-sm
                font-medium
                text-white
                shadow-lg shadow-blue-600/20
                transition-all
                duration-200
                hover:-translate-y-[1px]
                hover:bg-blue-500
                hover:shadow-blue-500/30
                disabled:cursor-not-allowed
                disabled:bg-slate-800
                disabled:text-slate-500
                disabled:shadow-none
              "
            >
              <span>▶</span>
              Run Analysis
            </button>

            <button
              onClick={downloadTemplate}
              className="
                h-11 rounded-2xl
                border border-slate-800
                bg-slate-900
                px-5
                text-sm
                font-medium
                text-slate-300
                transition-all
                duration-200
                hover:border-slate-700
                hover:bg-slate-800
                hover:text-white
              "
            >
              Download Template
            </button>
          </div>
        </div>

        {/* Right section */}
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end">
          <div className="space-y-1">
            <label className="text-xs font-medium uppercase tracking-wide text-slate-500">
              Configuration
            </label>

            <div className="flex flex-wrap gap-3">
              <input
                type="file"
                ref={configInputRef}
                className="hidden"
                accept=".json"
              />

              <button
                onClick={
                  onConfigUploadClick
                }
                className="
                  h-11 rounded-2xl
                  border border-slate-800
                  bg-slate-900
                  px-5
                  text-sm
                  font-medium
                  text-slate-300
                  transition-all
                  duration-200
                  hover:border-slate-700
                  hover:bg-slate-800
                  hover:text-white
                "
              >
                Import Config
              </button>

              <input
                type="text"
                value={configId}
                onChange={(e) =>
                  setConfigId(e.target.value)
                }
                placeholder="config_id"
                className="
                  h-11 w-52
                  rounded-2xl
                  border border-slate-800
                  bg-slate-900
                  px-4
                  text-sm
                  text-slate-200
                  placeholder:text-slate-500
                  outline-none
                  transition-all
                  hover:border-slate-700
                  focus:border-blue-500
                  focus:ring-4
                  focus:ring-blue-500/15
                "
              />

              <button
                onClick={handleExport}
                className="
                  h-11 rounded-2xl
                  border border-emerald-500/30
                  bg-emerald-500/10
                  px-5
                  text-sm
                  font-medium
                  text-emerald-400
                  transition-all
                  duration-200
                  hover:bg-emerald-500/20
                  hover:text-emerald-300
                "
              >
                Export Config
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};