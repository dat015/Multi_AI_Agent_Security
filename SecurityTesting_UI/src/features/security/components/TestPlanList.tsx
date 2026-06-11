// src/components/TestPlanList.tsx
import React from 'react';
import type { TestPlanItem } from '../types';

interface TestPlanListProps {
  testPlan: TestPlanItem[];
  onDownload: () => void;
  showDownloadButton: boolean;
}

const TestPlanList: React.FC<TestPlanListProps> = ({ testPlan, onDownload, showDownloadButton }) => {
  if (!testPlan.length) {
    return (
      <div className="bg-gray-800/30 rounded-xl p-8 text-center">
        <p className="text-gray-400">Không sinh được test case nào.</p>
      </div>
    );
  }

  return (
    <div className="mt-6">
      <h2 className="text-lg font-semibold text-slate-900 mb-4 flex items-center gap-2">
        📋 Test Plan sinh ra
        <span className="text-xs bg-gray-700 px-2 py-1 rounded-full">{testPlan.length} cases</span>
      </h2>
      <div className="space-y-4">
        {testPlan.map((item, idx) => (
          <div key={idx} className="bg-gray-800/50 rounded-xl p-5 border-l-4 border-blue-500 hover:bg-gray-800/70 transition-all">
            <div className="font-mono text-sm text-blue-400 mb-2">
              {item.method} {item.endpoint}
            </div>
            <span className="inline-block bg-yellow-900/40 text-yellow-500 text-xs px-2 py-1 rounded-md mb-3">
              {item.vuln_type}
            </span>
            <div className="space-y-2">
              {(item.test_steps || []).map((step, stepIdx) => (
                <div key={stepIdx} className="text-xs text-gray-400 border-t border-gray-700 pt-2">
                  <span className="text-gray-300 font-medium">Bước {step.step || stepIdx + 1}:</span>{' '}
                  {step.description}
                  {step.expected_indicator && (
                    <div className="text-gray-500 mt-1 ml-4">
                      → Dấu hiệu: {step.expected_indicator}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
      {showDownloadButton && (
        <button
          onClick={onDownload}
          className="mt-6 bg-gray-800 border border-blue-500 text-blue-400 px-6 py-2 rounded-lg text-sm hover:bg-gray-700 transition-colors"
        >
          ⬇ Tải test_plan.json
        </button>
      )}
    </div>
  );
};

export default TestPlanList;