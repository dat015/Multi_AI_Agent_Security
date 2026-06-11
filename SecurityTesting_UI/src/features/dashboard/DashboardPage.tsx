import React, { useState, useEffect } from 'react';
import SummaryCards from './components/SummaryCards';
import VulnerabilityChart from './components/VulnerabilityChart';
import FilterBar from './components/FilterBar';
import VulnerabilityTable from './components/VulnerabilityTable';
import ScanUploader from './components/ScanUploader';
import ScanProgress from './components/ScanProgress';
import type { Vulnerability, Severity } from '../../data/mockData';
import { API } from '../../lib/api';
import type { AgentAnalysisResponse } from '../../lib/api';
import { AlertCircle } from 'lucide-react';
import ReportSummary from './components/ReportSummary';

interface DashboardPageProps {
  onSessionIdUpdate: (sessionId: string | null) => void;
}

// Hàm map dữ liệu từ Backend sang Frontend model
const mapVulnFindingsToVulnerabilities = (findings: any[]): Vulnerability[] => {
  if (!findings || !Array.isArray(findings)) return [];
  
  return findings.map((item, index) => {
    // Xác định isVulnerable
    const isVuln = item.is_vulnerable === true || item.status === 'vulnerable';
    // Xác định Severity
    let severity: Severity = 'Safe';
    if (isVuln) {
       const sevString = String(item.severity).toLowerCase();
       if (sevString.includes('high')) severity = 'High';
       else if (sevString.includes('medium')) severity = 'Medium';
       else if (sevString.includes('low')) severity = 'Low';
       else severity = 'Low'; // fallback for vulnerable
    }

    return {
      id: item.id || `VULN-${index + 1}`,
      endpoint: item.endpoint || item.path || 'Unknown',
      method: (item.method || 'GET').toUpperCase(),
      vulnType: item.vulnerability_type || item.vuln_type || 'Unknown',
      role: item.role || 'attacker',
      isVulnerable: isVuln,
      severity: severity,
      confidenceScore: item.confidence_score || item.confidence || (isVuln ? 80 : 100),
      reasoning: item.reasoning || item.description || '',
      evidence: item.evidence ? {
        statusCode: item.evidence.status_code || item.evidence.statusCode || (isVuln ? 200 : 403),
        responseBody: typeof item.evidence.response_body === 'string' 
          ? item.evidence.response_body 
          : JSON.stringify(item.evidence.response_body || item.evidence.responseBody || item.evidence, null, 2)
      } : undefined,
      recommendation: item.recommendation || '',
      expectedIndicator: item.expected_indicator || item.expectedIndicator || '',
      tags: item.tags || []
    };
  });
};

const DashboardPage: React.FC<DashboardPageProps> = ({ onSessionIdUpdate }) => {
  const [status, setStatus] = useState<'idle' | 'running' | 'done' | 'error'>('idle');
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [data, setData] = useState<Vulnerability[]>([]);
  const [filteredData, setFilteredData] = useState<Vulnerability[]>([]);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [reportSummary, setReportSummary] = useState<any>(null);

  // Polling Effect
  useEffect(() => {
    let intervalId: ReturnType<typeof setInterval>;

    const poll = async () => {
      if (!sessionId) return;
      try {
        const res = await API.pollResult(sessionId);
        if (res.status === 'done') {
          clearInterval(intervalId);
          // Gọi API phụ để lấy vuln_findings
          try {
            const analyzerRes = await API.getAnalyzerResult(sessionId);
            const mappedData = mapVulnFindingsToVulnerabilities(analyzerRes.vuln_findings || []);
            setData(mappedData);
            setFilteredData(mappedData);
            if (analyzerRes.report_summary) {
              setReportSummary(analyzerRes.report_summary);
            }
            setStatus('done');
          } catch (analyzerErr: any) {
            console.error("Lỗi khi lấy analyzer result:", analyzerErr);
            setStatus('error');
            setErrorMsg("Không thể tải danh sách lỗ hổng bảo mật.");
          }
        } else if (res.status === 'error') {
          setStatus('error');
          setErrorMsg(res.error || 'Đã xảy ra lỗi trong quá trình phân tích.');
          clearInterval(intervalId);
        }
      } catch (err: any) {
        console.error("Polling error:", err);
        // Có thể không clear interval ngay vì đôi khi mạng chập chờn,
        // nhưng nếu lỗi liên tục thì nên clear. Ở đây tạm thời báo lỗi nhẹ.
      }
    };

    if (status === 'running' && sessionId) {
      poll(); // Gọi ngay lần đầu
      intervalId = setInterval(poll, 3000); // Polling mỗi 3 giây
    }

    return () => {
      if (intervalId) clearInterval(intervalId);
    };
  }, [status, sessionId]);

  const handleScanStarted = (newSessionId: string) => {
    setSessionId(newSessionId);
    onSessionIdUpdate(newSessionId);
    setStatus('running');
    setErrorMsg(null);
    setReportSummary(null);
  };

  const handleFilterChange = (filters: any) => {
    // Lọc theo các tiêu chí (filters.vulnType, filters.severity, filters.role, filters.endpoint)
    let result = [...data];

    if (filters.vulnType) {
      result = result.filter(v => v.vulnType.includes(filters.vulnType));
    }
    if (filters.severity) {
      result = result.filter(v => v.severity === filters.severity);
    }
    if (filters.role) {
      result = result.filter(v => v.role === filters.role);
    }
    if (filters.endpoint) {
      result = result.filter(v => v.endpoint.toLowerCase().includes(filters.endpoint.toLowerCase()));
    }

    setFilteredData(result);
  };

  if (status === 'idle') {
    return <ScanUploader onScanStarted={handleScanStarted} />;
  }

  if (status === 'running') {
    return <ScanProgress />;
  }

  if (status === 'error') {
    return (
      <div className="max-w-2xl mx-auto mt-10 p-8 bg-slate-800 border border-slate-700 rounded-2xl shadow-lg flex flex-col items-center">
        <AlertCircle size={48} className="text-red-500 mb-4" />
        <h2 className="text-2xl font-bold text-white mb-2">Lỗi quá trình quét</h2>
        <p className="text-red-400 mb-6 text-center">{errorMsg}</p>
        <button 
          onClick={() => {
            setStatus('idle');
            setSessionId(null);
            onSessionIdUpdate(null);
          }}
          className="px-6 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-colors"
        >
          Thử lại
        </button>
      </div>
    );
  }

  // Calculate summary metrics based on original un-filtered data
  const total = data.length;
  const vulnerable = data.filter(v => v.isVulnerable).length;
  const safe = total - vulnerable;
  const ratio = total > 0 ? Math.round((vulnerable / total) * 100) + '%' : '0%';

  return (
    <div className="space-y-6">
      {reportSummary && <ReportSummary reportSummary={reportSummary} />}
      <SummaryCards 
        total={total}
        vulnerable={vulnerable}
        safe={safe}
        ratio={ratio}
      />
      
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-1">
          <VulnerabilityChart safeCount={safe} vulnerableCount={vulnerable} />
        </div>
        <div className="lg:col-span-3">
          <FilterBar onFilterChange={handleFilterChange} />
          <VulnerabilityTable data={filteredData} />
        </div>
      </div>
    </div>
  );
};

export default DashboardPage;
