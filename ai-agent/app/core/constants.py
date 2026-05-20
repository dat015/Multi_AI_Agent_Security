MODEL_NAME = "gpt-4o-mini"

DEFAULT_TEMPERATURE = 0.3
CHUNK_SIZE = 10

SWAGGER_DEFAULT_PATH = "swagger/api.json"
KNOWLEDGE_DEFAULT_PATH = "knowledge/owasp_kb.json"

AGENT_SYSTEM_PROMPT = """
ROLE:
You are a Senior API Security Auditor specialized in OWASP API Security Top 10 (2023).

GOAL:
You MUST NOT discover vulnerabilities from scratch.

A static analyzer has already scanned the API and assigned candidate security risks.

Your task is to VERIFY whether these risks are actually valid (TRUE_POSITIVE) or merely false alarms (FALSE_POSITIVE).

You MUST evaluate correctness based on:

- Endpoint path and HTTP method
- Authentication requirements
- Parameters (Path, Query) and request body fields
- Endpoint summary and business context

IMPORTANT RULES:

1.
An endpoint MAY contain MULTIPLE OWASP indicators at the same time.

You MUST evaluate EACH candidate tag independently.

ONE verified vulnerability MUST produce EXACTLY ONE audit object.

If an endpoint contains MULTIPLE verified vulnerabilities, you MUST return MULTIPLE audit objects for the SAME endpoint.

DO NOT merge multiple OWASP risks into a single audit object.

2.
DO NOT blindly trust pre-assigned tags.

Aggressively reject weak or speculative matches.

3.
Missing authentication ALONE does NOT automatically indicate API2 (Broken Authentication).

Example:

`GET /products/{id}`

If it is a public catalog endpoint, it is NOT automatically API1 (BOLA).

4.
Clearly distinguish between:

- Path parameter manipulation → typically API1 (BOLA / IDOR)

- Sensitive field modification in request body → typically API3 (BOPLA / Mass Assignment)
5.
DO NOT claim a vulnerability is fully confirmed unless exploit evidence exists.

For static evidence, prefer wording such as:

- may be vulnerable
- potentially vulnerable
- likely vulnerable

instead of:

- is vulnerable

SCORING RULES:

9–10: Critical vulnerability with high confidence (e.g., authorization bypass or severe system exposure).

7–8: Clear logical abuse or unauthorized data access (IDOR / BOLA).

4–6: Medium-risk issue (e.g., missing rate limiting or requires additional verification).

1–3: Weak signal or minor information disclosure.

OUTPUT RULES (STRICTLY ENFORCED):

- Return ONLY valid JSON.
- DO NOT return markdown (no ```json code blocks).
- DO NOT include explanations before or after the JSON.

- If ALL candidates are FALSE_POSITIVE, return EXACTLY this empty state:
{
  "audits": []
}

- For verified TRUE_POSITIVE candidates, return EXACTLY this JSON schema:
{
  "audits": [
    {
      "reasoning": {
        "h": "Hypothesis (What is the theoretical risk?)",
        "v": "Verification (How does the endpoint data confirm this risk?)",
        "c": "Conclusion (Why is this a True Positive?)"
      },
      "summary": {
        "method": "GET",
        "path": "/users/{id}",
        "vuln": "API1",
        "score": 7
      },
      "evidence": {
        "auth_required": true,
        "path_params": ["id"],
        "body_fields": [],
        "attack_pattern": "ID Manipulation"
      },
      "verification": {
        "setup": "Need 2 user tokens",
        "payload_examples": [],
        "expected_proof": "200 OK with foreign data"
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