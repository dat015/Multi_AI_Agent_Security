MODEL_NAME = "gpt-4o-mini"

DEFAULT_TEMPERATURE = 0.3
CHUNK_SIZE = 10

SWAGGER_DEFAULT_PATH = "swagger/api.json"
KNOWLEDGE_DEFAULT_PATH = "knowledge/owasp_kb.json"

AGENT_SYSTEM_PROMPT = """
ROLE:
You are a Senior API Security Auditor specialized in OWASP API Security Top 10 (2023).

GOAL:
A static analyzer has already scanned the API and assigned candidate security risks.

You SHOULD prioritize verifying pre-assigned OWASP risks.

However, if strong endpoint evidence clearly suggests another OWASP API risk,
you MAY add additional vulnerabilities.

DO NOT invent unsupported findings.

IMPORTANT:
Your task is NOT to prove exploitability.

Your task is to identify and verify PLAUSIBLE OWASP API SECURITY INDICATORS
based on endpoint metadata.

You MUST evaluate findings based on:

- Endpoint path and HTTP method
- Authentication requirements
- Parameters (Path, Query)
- Request body fields
- Endpoint summary
- Business context

IMPORTANT RULES (STRICT COMPLIANCE):

1.
An endpoint MAY contain MULTIPLE OWASP indicators.

You MUST evaluate EACH candidate tag independently.

ONE endpoint MUST produce EXACTLY ONE audit object.

If MULTIPLE risks are valid for the SAME endpoint,
MERGE them into a SINGLE audit object.

Include all verified risks in the vuln array.

DO NOT create duplicate audit objects for the same endpoint.

Example:
"vuln": ["API1", "API3"]

2.
DO NOT blindly trust pre-assigned tags.

Weak signals alone SHOULD NOT automatically confirm a vulnerability.

However, plausible OWASP risk indicators SHOULD be preserved.

3.
Missing authentication ALONE does NOT automatically indicate API2 (Broken Authentication).

Public endpoints are NOT automatically vulnerable.

Example:
GET /products/{id}

If the endpoint is intended for public catalog access,
lack of authentication alone is NOT sufficient evidence of a vulnerability.

4.
For API1 (BOLA / IDOR):

Path parameters referencing user-controlled resources
ARE VALID SECURITY INDICATORS.

Confidence SHOULD increase when combined with:

- authenticated access
- state-changing methods (PUT, PATCH, DELETE)
- sensitive resources (wallet, user, card, transaction)

Examples:

GET /wallets/{walletId}
→ possible API1 indicator

PUT /users/{userId}
→ likely API1 indicator

DELETE /transactions/{transactionId}
→ strong API1 indicator

5.
Clearly distinguish between:

- Path parameter manipulation
→ typically API1 (BOLA / IDOR)

- Sensitive request body fields
→ typically API3 (Mass Assignment / BOPLA)

Examples of sensitive fields:
role, balance, permission, status, isAdmin

6.
DO NOT claim a vulnerability is fully confirmed
unless exploit evidence exists.

For metadata-only evidence, prefer wording such as:

- possible risk
- may be vulnerable
- potentially vulnerable
- likely vulnerable

Avoid:
- definitely vulnerable
- confirmed exploit

7.
Reasoning MUST be grounded ONLY in provided endpoint metadata.

DO NOT invent implementation details
(e.g., JWT validation flaws, missing ownership checks,
database queries, authorization logic).

8.
Keep reasoning concise:
Maximum ONE sentence per vulnerability.

SCORING RULES:

9–10:
Strong security indicator with severe potential impact
and strong endpoint evidence
(e.g., debug/env exposure, sensitive admin actions).

7–8:
Likely vulnerability pattern
(e.g., API1 with authenticated state-changing access,
API3 with sensitive writable fields).

4–6:
Moderate security indicator
(e.g., object IDs in path, missing pagination signals).

1–3:
Weak signal or low-confidence indicator.

If multiple vulnerabilities exist,
score MUST represent the HIGHEST risk score.

OUTPUT RULES (STRICTLY ENFORCED):

- Return ONLY valid JSON.
- DO NOT return markdown.
- DO NOT include explanations before or after JSON.

If ALL candidates are FALSE_POSITIVE:

{
  "audits": []
}

For valid findings, return EXACTLY:

{
  "audits": [
    {
      "summary": {
        "method": "GET",
        "path": "/users/{id}",
        "vuln": ["API1", "API3"],
        "score": 7
      },
      "reasoning": {
        "API1": "User-controlled identifier may indicate object-level authorization risk.",
        "API3": "Sensitive writable field may allow mass assignment."
      },
      "evidence": {
        "auth_required": true,
        "path_params": ["id"],
        "body_fields": ["role"]
      }
    }
  ]
}
"""

CONFIG_TEMPLATE = {
    "target": {
        "base_url":         "http://localhost:8888",
        "login_endpoint":   "/identity/api/auth/login",
        "refresh_endpoint": "/identity/api/auth/refresh"
    },
    "users": [
        {
            "role":     "admin",
            "email":    "admin@yourapp.com",
            "password": "YourPassword123"
        },
        {
            "role":     "attacker",
            "email":    "attacker@yourapp.com",
            "password": "YourPassword123",
            "token":    "(optional) paste token nếu có sẵn"
        },
        {
            "role":     "victim",
            "email":    "victim@yourapp.com",
            "password": "YourPassword123"
        }
    ]
}
AUTH_CONFIG_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title":   "API Security Tester — Auth Config",
    "type":    "object",
    "required": ["target", "users"],
    "additionalProperties": False,

    "properties": {

        "target": {
            "type": "object",
            "required": ["base_url"],
            "additionalProperties": False,
            "properties": {
                "base_url": {
                    "type":    "string",
                    "pattern": "^https?://.+",
                    "description": "Base URL của API server, VD: http://localhost:8888"
                },
                "login_endpoint": {
                    "type":    "string",
                    "pattern": "^/",
                    "default": "/identity/api/auth/login",
                    "description": "Endpoint login, bắt đầu bằng /"
                },
                "refresh_endpoint": {
                    "type":    "string",
                    "pattern": "^/",
                    "default": "/identity/api/auth/refresh",
                    "description": "Endpoint refresh token, bắt đầu bằng /"
                }
            }
        },

        "users": {
            "type":     "array",
            "minItems": 1,
            "items": {
                "type":     "object",
                "required": ["role", "email", "password"],
                "additionalProperties": False,
                "properties": {
                    "role": {
                        "type":      "string",
                        "minLength": 1,
                        "pattern":   "^[a-zA-Z0-9_-]+$",
                        "description": "Tên role tự đặt: admin, attacker, victim, moderator..."
                    },
                    "email": {
                        "type":   "string",
                        "format": "email",
                        "description": "Email đăng nhập"
                    },
                    "password": {
                        "type":      "string",
                        "minLength": 6,
                        "description": "Mật khẩu (tối thiểu 6 ký tự)"
                    },
                    "token": {
                        "type":        "string",
                        "description": "JWT token (optional — nếu có thì dùng ngay)"
                    },
                    "refresh_token": {
                        "type":        "string",
                        "description": "Refresh token (optional)"
                    },
                    "token_expires_at": {
                        "type":        "string",
                        "description": "ISO 8601 timestamp hết hạn token, VD: 2025-12-31T23:59:59"
                    },
                    "user_id": {
                        "type":        "string",
                        "description": "User ID (optional — hệ thống tự lấy sau login nếu không có)"
                    }
                }
            }
        }
    }
}