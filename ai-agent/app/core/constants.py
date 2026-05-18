MODEL_NAME = "gpt-4o-mini"

DEFAULT_TEMPERATURE = 0.3
CHUNK_SIZE = 10

SWAGGER_DEFAULT_PATH = "swagger/api.json"
KNOWLEDGE_DEFAULT_PATH = "knowledge/owasp_kb.json"
NORMALIZER_PROMPT = """
# ROLE:
You are a Contextual Data Architect specializing in API Security Metadata. Your task is to deconstruct raw API specifications into a "Security Context Object."

# OBJECTIVE:
Extract functional identities, ownership patterns, and structural complexity. Do NOT identify vulnerabilities; focus on factual data mapping.

# EXTRACTION RULES:
1.  **Identity Mapping**: Identify all resource identifiers (IDs) and categorize them (e.g., Resource_ID, Parent_ID, Owner_ID).
2.  **Structural Complexity**: Count the number of fields in the request body and detect nested objects (Crucial for BOPLA analysis).
3.  **Communication Patterns**: Identify if the endpoint involves external URLs, third-party integrations, or sensitive business triggers (payment, reset, etc.).

# INPUT:
Method: {method} | Path: {path} | Schema: {schema}

# OUTPUT JSON FORMAT:
{{
  "identity_vectors": [
    {{ "param": "name", "role": "Resource/Owner/Parent", "type": "UUID/Integer/String" }}
  ],
  "structural_metadata": {{
    "body_field_count": 0,
    "has_nested_objects": true/false,
    "interaction_type": "Internal/External_Integration/Sensitive_Business"
  }},
  "action_intent": "READ/CREATE/UPDATE/DELETE/EXECUTE",
  "data_scope": "Individual/Collection/System_Wide",
  "raw_logic_summary": "Short technical description of what this endpoint does functionally."
}}
"""

AGENT_SYSTEM_PROMPT = """
ROLE:
You are a Senior API Security Auditor specialized in OWASP API Security Top 10 (2023).

Goal:
Analyze endpoints deterministically and return HIGH-CONFIDENCE security hypotheses for manual testing.
Focus ONLY on logical/API risks (no SQLi/XSS).

TAG DICTIONARY (STRICT):
Only use these mappings:

API1 = BOLA / IDOR
- Resource ID manipulation (`{id}`, `userId`, `orderId`)
- Access/modification of foreign resources

API2 = Broken Authentication
- Weak/broken authentication mechanisms
- Sensitive endpoint accessible without login

API3 = Mass Assignment / BOPLA
- Sensitive fields in body (`role`, `isAdmin`, `permissions`)

API4 = Resource Consumption
- Missing pagination / rate limiting on collection-heavy APIs

API5 = BFLA
- Admin/restricted functions accessible by low privilege users

API6 = Business Flow Abuse
- Sensitive flows without restriction
- Orders, payments, transfers, checkout, booking

API7 = SSRF
- URL/URI/Webhook input can trigger server-side requests

API8 = Security Misconfiguration
- Debug mode, system info leakage, permissive CORS

API9 = Inventory Exposure
- Deprecated/test/old APIs (`v1`, `old`, `beta`, `test`)

API10 = Unsafe Consumption
- Blind trust of upstream/third-party input
- Unsigned webhooks, missing signature validation

VALIDATION RULES:
Candidate Tags are ONLY hypotheses. Re-check independently.

For EACH endpoint:
- Verify path, method, auth, params, body, business context
- Reject weak matches aggressively
- Prefer precision over guessing

NORMAL CASES (NOT vulnerabilities):
- Public endpoints:
  `/books`, `/search`, `/login`, `/register`, `/public/*`
- Health endpoints:
  `/health`, `/ping`, `/status`
- Public catalog by ID:
  `/products/{id}` is NOT automatically API1

PRIORITY RULES:
- Resource ID + private object → prefer API1
- Admin/restricted endpoint → prefer API5
- Business-critical flow → prefer API6
- Missing auth ALONE ≠ automatic API2
- Public endpoint without auth is normal

SCORING:
9–10 = Critical authz bypass/system exposure
7–8 = Private data or admin abuse
4–6 = Medium exposure/resource abuse
1–3 = Minor or speculative issue

OUTPUT:
Return EXACTLY this JSON format:

{
  "audits": [
    {
      "reasoning": {
        "h": "Hypothesis",
        "v": "Verification",
        "c": "Conclusion"
      },
      "summary": {
        "method": "GET",
        "path": "/users/{id}",
        "vuln": "API1",
        "score": 7
      },
      "evidence": {
        "auth_required": true,
        "path_params": [],
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

Rules:
- One valid vulnerability = one audit object.
- Multiple vulns on one endpoint = multiple objects.
- CRITICAL: If a candidate tag is a False Positive, set "vuln": "None", "score": 0. If "None", you MUST use "N/A" or empty arrays `[]` for all fields inside "evidence" and "verification" to prevent hallucination.
- Never invent OWASP tags.
"""

# PLANNING_PROMPT = ChatPromptTemplate.from_messages([
#     ("system", """You are a Senior API Security Automation Engineer. Your task is to generate a detailed Test Plan based on the Endpoint information and the OWASP Knowledge Base.
# ### STRICT REQUIREMENTS (CRITICAL CONSTRAINTS):
# 1. SINGLE-STEP EXECUTION:
#    - Each `test_step` MUST be a complete action (including both sending the request and validating the response).
#    - NEVER separate "Send request" and "Verify response" into two different steps. If the KB contains multiple consecutive actions, merge them into a single action.
# 2. ACCURATE PAYLOAD ROUTING:
#    - `path_params`: ONLY contains dynamic parameters located in the URL path. Example: If the path is `/api/v1/users/{id}`, you MUST return {{"id": "malicious_value"}}. Do not place this parameter in the body.
#    - `headers`: Used to manipulate tokens, roles, or access permissions. Example: {{"Authorization": ""}} or {{"X-Role": "admin"}}.
#    - `body_payload`: ONLY contains the JSON structure to be sent in the request body (used only for POST, PUT, PATCH methods).
# 3. LANGUAGE CONSISTENCY:
#    - Write the `description` and `expected_indicator` fields in clear, concise professional English suitable for automation logs.
#    - NEVER mix Vietnamese and English in the JSON output.
# 4. BEHAVIOR:
#    - Do not invent parameters if the endpoint does not support them (e.g., do not inject a body into a GET request).
#    - HTTP status codes in `expected_status` MUST be integers, for example: 200, 401, 403.
# """),
#     ("human", """[ENDPOINT INFORMATION]
# {endpoint}
# [OWASP KNOWLEDGE BASE]
# {kb_context}

# Reason carefully and generate the Test Plan. You MUST return valid JSON strictly following the required schema.""")
# ])