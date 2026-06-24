import axios from "axios";

// Base URL cho backend
const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

const api = axios.create({
  baseURL: API_URL,
});

export interface ConfigUploadResponse {
  status: "ok" | "parse_error" | "invalid";
  config_id?: string;
  roles_loaded?: string[];
  warnings?: string[];
  message?: string;
  hint?: string;
}

export interface VulnerabilityFinding {
  id?: string;
  endpoint?: string;
  path?: string;
  method?: string;
  vuln_type?: string;
  vulnerability_type?: string;
  role?: string;
  is_vulnerable?: boolean;
  status?: string;
  severity?: "High" | "Medium" | "Low" | "Safe" | string;
  confidence_score?: number;
  confidence?: number;
  reasoning?: string;
  description?: string;
  evidence?: {
    status_code?: number;
    statusCode?: number;
    response_body?: any;
    responseBody?: any;
  };
  recommendation?: string;
  expected_indicator?: string;
  expectedIndicator?: string;
  tags?: string[];
}

export interface AgentAnalysisResponse {
  session_id: string;
  status: "running" | "done" | "error";
  recon_summary: string | null;
  endpoints_found: number | null;
  test_plan: any[] | null;
  vuln_findings?: VulnerabilityFinding[] | null;
  report_summary?: {
    executive_summary: string;
    overall_risk_level: string;
    recommendations: string[];
  };
  error: string | null;
}

export interface ScanHistoryItem {
  session_id: string;
  status: string;
  endpoints_found: number;
  created_at: string;
  error: string | null;
}

export const API = {
  // 1. Quản lý cấu hình
  async uploadConfig(file: File): Promise<ConfigUploadResponse> {
    const formData = new FormData();
    formData.append("file", file);
    const response = await api.post<ConfigUploadResponse>(
      "/upload-config",
      formData,
      {
        headers: { "Content-Type": "multipart/form-data" },
      },
    );
    return response.data;
  },

  getConfigDownloadUrl(configId: string): string {
    return `${API_URL}/config/download/${configId}`;
  },

  // 2. Phân tích & Quét
  async startAnalysis(
    file: File,
    phase: string = "full",
    configId?: string,
    maxIter: number = 5,
  ): Promise<AgentAnalysisResponse> {
    const formData = new FormData();
    formData.append("file", file);

    // FastAPI (backend) đang mong đợi các tham số này qua Query URL chứ không phải Form Data
    const params = new URLSearchParams();
    params.append("phase", phase);
    params.append("max_iter", maxIter.toString());
    if (configId) {
      params.append("config_id", configId);
    }

    const response = await api.post<AgentAnalysisResponse>(
      `/api/agent/analyze?${params.toString()}`,
      formData,
      {
        headers: { "Content-Type": "multipart/form-data" },
      },
    );
    return response.data;
  },

  async pollResult(sessionId: string): Promise<AgentAnalysisResponse> {
    const response = await api.get<AgentAnalysisResponse>(
      `/api/agent/result/${sessionId}`,
    );
    return response.data;
  },

  async getAnalyzerResult(sessionId: string): Promise<AgentAnalysisResponse> {
    const response = await api.get<AgentAnalysisResponse>(
      `/api/agent/analyzer-result/${sessionId}`,
    );
    return response.data;
  },

  getDownloadUrl(sessionId: string): string {
    return `${API_URL}/api/agent/download/${sessionId}`;
  },

  // 3. Lịch sử
  async getHistory(): Promise<ScanHistoryItem[]> {
    const response = await api.get<ScanHistoryItem[]>("/api/agent/history");
    return response.data;
  },

  async getHistoryDetail(sessionId: string): Promise<AgentAnalysisResponse> {
    const response = await api.get<AgentAnalysisResponse>(
      `/api/agent/history/${sessionId}`,
    );
    return response.data;
  },
};
