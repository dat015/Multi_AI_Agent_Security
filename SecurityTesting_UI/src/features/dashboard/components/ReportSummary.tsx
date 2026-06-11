import React from 'react';
import { ShieldAlert, ShieldCheck, Shield, AlertTriangle } from 'lucide-react';

interface ReportSummaryProps {
  reportSummary?: {
    executive_summary: string;
    overall_risk_level: string;
    recommendations: string[];
  };
}

const getRiskColor = (riskLevel: string) => {
  const level = riskLevel.toLowerCase();
  if (level.includes('critical')) return 'text-red-500 bg-red-500/10 border-red-500/20';
  if (level.includes('high')) return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
  if (level.includes('medium')) return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
  if (level.includes('low')) return 'text-blue-500 bg-blue-500/10 border-blue-500/20';
  return 'text-green-500 bg-green-500/10 border-green-500/20';
};

const getRiskIcon = (riskLevel: string) => {
  const level = riskLevel.toLowerCase();
  if (level.includes('critical')) return <ShieldAlert size={24} />;
  if (level.includes('high')) return <AlertTriangle size={24} />;
  if (level.includes('medium')) return <AlertTriangle size={24} />;
  if (level.includes('safe') || level.includes('none')) return <ShieldCheck size={24} />;
  return <Shield size={24} />;
};

const ReportSummary: React.FC<ReportSummaryProps> = ({ reportSummary }) => {
  if (!reportSummary) return null;

  const { executive_summary, overall_risk_level, recommendations } = reportSummary;

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden shadow-lg mb-6">
      <div className="border-b border-slate-700 bg-slate-800/50 px-6 py-4 flex items-center justify-between">
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Shield className="text-blue-400" size={24} />
          Executive Security Report
        </h2>
        <div className={`flex items-center gap-2 px-4 py-1.5 rounded-full border font-semibold ${getRiskColor(overall_risk_level)}`}>
          {getRiskIcon(overall_risk_level)}
          <span>{overall_risk_level.toUpperCase()} RISK</span>
        </div>
      </div>
      
      <div className="p-6 grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2 space-y-6">
          <div>
            <h3 className="text-lg font-semibold text-slate-300 mb-3">Executive Summary</h3>
            <p className="text-slate-400 leading-relaxed">
              {executive_summary}
            </p>
          </div>
        </div>

        <div className="bg-slate-900/50 border border-slate-700/50 rounded-lg p-5">
          <h3 className="text-lg font-semibold text-slate-300 mb-4 flex items-center gap-2">
            <ShieldCheck className="text-emerald-400" size={20} />
            Recommendations
          </h3>
          <ul className="space-y-3">
            {recommendations && recommendations.length > 0 ? (
              recommendations.map((rec, idx) => (
                <li key={idx} className="flex items-start gap-3 text-slate-400 text-sm">
                  <span className="w-1.5 h-1.5 rounded-full bg-blue-400 mt-2 flex-shrink-0"></span>
                  <span>{rec}</span>
                </li>
              ))
            ) : (
              <li className="text-slate-500 italic text-sm">Không có khuyến nghị nào.</li>
            )}
          </ul>
        </div>
      </div>
    </div>
  );
};

export default ReportSummary;
