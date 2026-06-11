export type Severity = 'High' | 'Medium' | 'Low' | 'Safe';

export interface Vulnerability {
  id: string;
  endpoint: string;
  method: string;
  vulnType: string;
  role: string;
  isVulnerable: boolean;
  severity: Severity;
  confidenceScore: number;
  reasoning?: string;
  evidence?: {
    statusCode: number;
    responseBody: string;
  };
  recommendation?: string;
  expectedIndicator?: string;
  tags?: string[];
}

export const mockVulnerabilities: Vulnerability[] = [
  {
    id: 'VULN-001',
    endpoint: '/Category/{id}',
    method: 'PUT',
    vulnType: 'BOLA (API1:2023)',
    role: 'attacker',
    isVulnerable: true,
    severity: 'High',
    confidenceScore: 90,
    reasoning: 'Attacker without authorization can modify category details belonging to another tenant.',
    evidence: {
      statusCode: 200,
      responseBody: '{"success": true, "message": "Category updated successfully", "data": {"id": 5, "name": "Hacked Category"}}'
    },
    recommendation: 'Implement strict authorization checks. Verify that the user has permissions to access and modify the specific resource ID requested.',
    expectedIndicator: 'Status Code 403 Forbidden or 404 Not Found',
    tags: ['confirmed']
  },
  {
    id: 'VULN-002',
    endpoint: '/Product/{id}',
    method: 'GET',
    vulnType: 'BOLA (API1:2023)',
    role: 'attacker',
    isVulnerable: true,
    severity: 'High',
    confidenceScore: 95,
    reasoning: 'Attacker can read product details of another user by enumerating IDs.',
    evidence: {
      statusCode: 200,
      responseBody: '{"id": 1024, "name": "Private Internal Product", "price": 0}'
    },
    recommendation: 'Use non-predictable IDs (e.g., UUIDs) and enforce authorization checks.',
    expectedIndicator: 'Status Code 403 or 404'
  },
  {
    id: 'VULN-003',
    endpoint: '/User/profile',
    method: 'POST',
    vulnType: 'Mass Assignment (API3:2023)',
    role: 'attacker',
    isVulnerable: true,
    severity: 'Medium',
    confidenceScore: 75,
    reasoning: 'Endpoint allows updating "isAdmin" property if supplied in the payload.',
    evidence: {
      statusCode: 200,
      responseBody: '{"id": 88, "username": "hacker", "isAdmin": true}'
    },
    recommendation: 'Define explicit DTOs (Data Transfer Objects) and ignore unexpected fields in the request body.',
    expectedIndicator: '"isAdmin": false in response or Status 400',
    tags: ['false positive']
  },
  {
    id: 'VULN-004',
    endpoint: '/Category/get-all',
    method: 'GET',
    vulnType: 'Resource Exhaustion (API4:2023)',
    role: 'attacker',
    isVulnerable: false,
    severity: 'Safe',
    confidenceScore: 80,
    reasoning: 'Rate limiting and pagination are properly implemented.',
    evidence: {
      statusCode: 429,
      responseBody: '{"error": "Too many requests. Please try again later."}'
    },
    recommendation: 'Continue monitoring rate limits.',
    expectedIndicator: 'Status Code 429 Too Many Requests'
  },
  {
    id: 'VULN-005',
    endpoint: '/Auth/login',
    method: 'POST',
    vulnType: 'Broken Authentication (API2:2023)',
    role: 'attacker',
    isVulnerable: false,
    severity: 'Safe',
    confidenceScore: 98,
    reasoning: 'Account lockout mechanism prevents brute-force attacks after 5 failed attempts.',
  },
  {
    id: 'VULN-006',
    endpoint: '/System/logs',
    method: 'GET',
    vulnType: 'Security Misconfiguration (API8:2023)',
    role: 'admin',
    isVulnerable: true,
    severity: 'Low',
    confidenceScore: 60,
    reasoning: 'Debug headers are exposed in the response.',
    evidence: {
      statusCode: 200,
      responseBody: '{"logs": [...]}\n\nHeaders: X-Debug-Token: 12345'
    },
    recommendation: 'Disable debug modes and verbose error messages in production.',
  }
];
