// src/types/index.ts
export interface TestStep {
  step: number;
  description: string;
  expected_indicator?: string;
}

export interface TestPlanItem {
  method: string;
  endpoint: string;
  vuln_type: string;
  test_steps: TestStep[];
}

export interface AnalysisResult {
  status: 'running' | 'done' | 'error';
  session_id?: string;
  endpoints_found?: number;
  test_plan?: TestPlanItem[];
  error?: string;
}

export interface ConfigUploadResponse {
  status: 'ok' | 'error';
  config_id?: string;
  message?: string;
  error?: string;
}