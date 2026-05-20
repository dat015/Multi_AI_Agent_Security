export interface TestStep {
  step?: number;
  description: string;
  expected_indicator?: string;
}

export interface TestCase {
  method: string;
  endpoint: string;
  vuln_type: string;
  test_steps: TestStep[];
}

export interface PollResponse {
  status: 'running' | 'done' | 'error';
  endpoints_found?: number;
  test_plan?: TestCase[];
  error?: string;
}