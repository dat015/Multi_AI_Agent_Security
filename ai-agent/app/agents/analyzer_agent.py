# agents/analyzer_agent.py
"""
Secure-CoVe Analyzer — Chain-of-Verification cho OWASP API Top 10.

Pipeline:
  Tier 1: Deterministic Evidence Filter (không tốn token)
  Tier 2: LLM Hypothesis + Fact Extraction (không bias)
  Tier 3: Weighted Predicate Scoring → 4-state verdict

Cải tiến so với bản cũ:
  - Tier 1 phân biệt attack_step vs baseline_step
  - BOLA P2/P4 không còn trùng lặp
  - Thêm API3, API5, API6, API7, API9, API10
  - step_role metadata để filter đúng
"""

from __future__ import annotations
import json, os, logging
from typing import Any
from pydantic import BaseModel, Field
from langchain_core.messages import SystemMessage, HumanMessage

logger = logging.getLogger(__name__)

class BOLAFacts(BaseModel):
    requested_resource_owner: str = Field(
        description="Who owns the requested resource? 'attacker'|'victim'|'unknown'"
    )
    returned_data_owner: str = Field(
        description="Who does the RESPONSE DATA belong to? 'attacker'|'victim'|'none'|'unknown'"
    )
    http_status_code: int = Field(
        description="HTTP status code of the ATTACK step (not baseline)"
    )
    sensitive_fields_exposed: list[str] = Field(
        description="Sensitive fields in response: email, token, balance, id of another user, etc."
    )
    access_control_error_present: bool = Field(
        description="True if response contains 401/403 or explicit 'forbidden'/'unauthorized' message"
    )
    cross_user_data_confirmed: bool = Field(
        description="True if response data provably belongs to a DIFFERENT user than the requester"
    )


class BrokenAuthFacts(BaseModel):
    token_used: str = Field(
        description="Type of token used: 'valid'|'expired'|'tampered'|'missing'|'other_user'"
    )
    action_succeeded: bool = Field(
        description="True if action succeeded despite invalid/missing/other-user token"
    )
    http_status_code: int = Field(description="HTTP status code")
    error_indicates_auth_failure: bool = Field(
        description="True if 401/403 or JWT error was returned"
    )


class MassAssignmentFacts(BaseModel):
    privileged_field_in_request: list[str] = Field(
        description="Privileged fields sent in request body: role, is_admin, balance, verified, etc."
    )
    privileged_field_reflected_in_response: list[str] = Field(
        description="Which of those privileged fields appear in the response with the attacker-supplied value"
    )
    http_status_code: int = Field(description="HTTP status code")


class ResourceConsumptionFacts(BaseModel):
    request_count_sent: int = Field(
        description="Total number of rapid requests sent in this test"
    )
    rate_limit_triggered: bool = Field(
        description="True if 429/503 or explicit rate-limit header was observed"
    )
    server_degraded: bool = Field(
        description="True if response times increased >5x or connection errors appeared"
    )
    http_status_code: int = Field(description="Last observed HTTP status code")


class BFLAFacts(BaseModel):
    function_requires_privilege: str = Field(
        description="Expected privilege level for this function: 'admin'|'manager'|'owner'|'unknown'"
    )
    caller_privilege: str = Field(
        description="Actual privilege of the caller: 'regular_user'|'attacker'|'admin'|'unknown'"
    )
    action_succeeded: bool = Field(
        description="True if privileged action succeeded for low-privilege caller"
    )
    http_status_code: int = Field(description="HTTP status code")


class SSRFFacts(BaseModel):
    external_url_in_request: bool = Field(
        description="True if an attacker-controlled URL was sent in request body/params"
    )
    outbound_request_evidence: bool = Field(
        description="True if response or timing indicates server made outbound request to external URL"
    )
    internal_data_leaked: bool = Field(
        description="True if response contains internal network data (169.254.x, 10.x, metadata, etc.)"
    )
    http_status_code: int = Field(description="HTTP status code")


class SecurityMisconfigFacts(BaseModel):
    server_banner_exposed: bool = Field(
        description="True if exact server software version leaked in headers (e.g. nginx/1.14.0, ASP.NET/4.x)"
    )
    stack_trace_exposed: bool = Field(
        description="True if exception stack trace or internal file paths are in response body"
    )
    debug_info_exposed: bool = Field(
        description="True if debug flags, verbose SQL errors, or internal config values are in response"
    )
    cors_wildcard: bool = Field(
        description="True if Access-Control-Allow-Origin: * is returned on sensitive endpoint"
    )


class InventoryFacts(BaseModel):
    deprecated_endpoint_accessible: bool = Field(
        description="True if the endpoint is versioned (v1/v2) and returns same data as current version"
    )
    undocumented_endpoint_responds: bool = Field(
        description="True if an endpoint not in official docs responds successfully"
    )
    http_status_code: int = Field(description="HTTP status code")


class FallbackFacts(BaseModel):
    action_bypassed_restriction: bool = Field(
        description="True if the attack successfully bypassed the intended restriction"
    )
    http_status_code: int = Field(description="HTTP status code")
    sensitive_data_in_response: bool = Field(
        description="True if sensitive data (credentials, PII, internal config) is in response"
    )

def truncate_payload(data: Any, max_list_len=2, max_str_len=300) -> Any:
    """
    Recursively truncates lists, strings, and dicts to keep prompt payload small.
    """
    if isinstance(data, list):
        if len(data) > max_list_len:
            return [truncate_payload(x, max_list_len, max_str_len) for x in data[:max_list_len]] + ["... [truncated]"]
        else:
            return [truncate_payload(x, max_list_len, max_str_len) for x in data]
    elif isinstance(data, dict):
        return {k: truncate_payload(v, max_list_len, max_str_len) for k, v in data.items()}
    elif isinstance(data, str):
        if len(data) > max_str_len:
            return data[:max_str_len] + "... [truncated]"
        return data
    else:
        return data


def build_id_owner_map(execution_results: list[dict]) -> dict[str, str]:
    """
    Scans execution results to dynamically map created resource IDs to owner roles.
    Only extracts from non-attack setup nodes (is_attack == False) to avoid overwriting.
    """
    id_owners = {}
    for res in execution_results:
        if res.get("is_attack"):
            continue
        role = res.get("role")
        if not role:
            continue
        for step in res.get("steps_executed", []):
            resp = step.get("response") or {}
            data = resp.get("data") or {}
            if isinstance(data, dict) and "id" in data:
                id_owners[str(data["id"])] = role
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and "id" in item:
                        id_owners[str(item["id"])] = role
    return id_owners


def is_bola_attack_step(step: dict, current_role: str, id_owners: dict[str, str]) -> bool:
    """
    Dynamically checks if a step targets a victim's resource ID in URL or body.
    """
    if not id_owners:
        return True
    
    # Check URL path segments
    url = step.get("request_sent", {}).get("url", "") or ""
    parts = url.split('/')
    for resource_id, owner in id_owners.items():
        if owner == "victim":
            if resource_id in parts or any(part.split('?')[0] == resource_id for part in parts):
                return True
                
    # Check request body values
    req_sent = step.get("request_sent") or {}
    body = req_sent.get("body") or {}
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except Exception:
            body = {}
    if isinstance(body, dict):
        for k, v in body.items():
            if str(v) in id_owners and id_owners[str(v)] == "victim":
                return True
                
    return False


# ══════════════════════════════════════════════════════════════════════
# BASE + PLUGIN ANALYZERS
# ══════════════════════════════════════════════════════════════════════

class BaseVulnerabilityAnalyzer:
    vuln_type  = "None"
    cwe_info   = "CWE-000"
    ground_truth = ""

    def get_extraction_schema(self) -> type[BaseModel]:
        raise NotImplementedError

    def get_extraction_prompt(self) -> str:
        raise NotImplementedError

    def evaluate_predicates(self, facts: Any, evidence: dict) -> dict[str, bool]:
        raise NotImplementedError

    def calculate_confidence(self, predicates: dict[str, bool]) -> float:
        raise NotImplementedError

    def tier1_is_suspicious(self, steps: list[dict], id_owners: dict[str, str] = None) -> tuple[bool, str]:
        """
        Tier 1 nhanh — không tốn token.
        Trả về (is_suspicious, reason).
        Override trong subclass để có logic chuyên biệt.
        """
        has_200 = any(int(s.get("status_code", 0) or 0) in (200, 201, 204)
                      for s in steps)
        if has_200:
            return True, "Step returned 2xx — potential bypass detected"
        return False, ""


class BOLAAnalyzer(BaseVulnerabilityAnalyzer):
    vuln_type    = "API1"
    cwe_info     = "CWE-639: Authorization Bypass Through User-Controlled Key"
    ground_truth = (
        "BOLA/IDOR occurs when the server does not validate that the authenticated user "
        "has permission to access the specific object ID being requested."
    )

    def get_extraction_schema(self):
        return BOLAFacts

    def get_extraction_prompt(self):
        return (
            "You are extracting raw facts from API attack logs. "
            "Focus ONLY on the ATTACK steps (not baseline). "
            "Determine: who owns the resource being accessed, who owns the data returned, "
            "what sensitive fields are exposed, and whether cross-user data is confirmed."
        )

    def tier1_is_suspicious(self, steps, id_owners=None):
        # Chỉ xét attack steps có path param / body param thuộc victim
        attack_steps = [s for s in steps if is_bola_attack_step(s, "attacker", id_owners)]
        has_bypass = any(int(s.get("status_code", 0) or 0) in (200, 201, 204)
                         for s in attack_steps)
        if has_bypass:
            return True, "Attacker received 2xx accessing victim-owned resource ID"
        return False, ""

    def evaluate_predicates(self, facts: BOLAFacts, evidence: dict):
        """
        BOLA formula: P1 ∧ P2 ∧ P3 ∧ P4

        P1 (0.35): Resource thuộc victim — điều kiện cơ bản nhất
        P2 (0.30): Cross-user data được confirm trong response
                   ← thay P2 cũ (chỉ check status code)
        P3 (0.25): Sensitive fields lộ ra ngoài
        P4 (0.10): Không có access control error
        """
        p1 = facts.requested_resource_owner == "victim"
        # P2 mới: confirm cross-user data, không trùng với P4
        p2 = facts.cross_user_data_confirmed
        p3 = (len(facts.sensitive_fields_exposed) > 0
              and facts.returned_data_owner == "victim")
        p4 = not facts.access_control_error_present

        return {"P1": p1, "P2": p2, "P3": p3, "P4": p4}

    def calculate_confidence(self, predicates):
        weights = {"P1": 0.35, "P2": 0.30, "P3": 0.25, "P4": 0.10}
        return sum(weights[p] for p, v in predicates.items() if v)


class BrokenAuthAnalyzer(BaseVulnerabilityAnalyzer):
    vuln_type    = "API2"
    cwe_info     = "CWE-287: Improper Authentication"
    ground_truth = (
        "Broken Authentication: token reuse, bypass, weak secret, or missing validation "
        "allows unauthenticated or wrong-user actions to succeed."
    )

    def get_extraction_schema(self): return BrokenAuthFacts
    def get_extraction_prompt(self):
        return (
            "Extract facts about the token used (valid/expired/tampered/missing/other-user), "
            "whether the action succeeded despite bad auth, and if the server signaled auth failure."
        )

    def tier1_is_suspicious(self, steps, id_owners=None):
        for s in steps:
            desc = s.get("description", "").lower()
            status = int(s.get("status_code", 0) or 0)
            if any(k in desc for k in ["auth", "token", "jwt", "login", "expired", "tampered", "missing", "unauthenticated"]):
                if status in (200, 201, 204):
                    return True, "Auth bypass or invalid auth request returned 2xx"
        return False, ""

    def evaluate_predicates(self, facts: BrokenAuthFacts, evidence: dict):
        p1 = facts.token_used in ("expired", "tampered", "missing", "other_user")
        p2 = facts.action_succeeded
        p3 = facts.http_status_code in (200, 201, 204)
        p4 = not facts.error_indicates_auth_failure

        return {"P1": p1, "P2": p2, "P3": p3, "P4": p4}

    def calculate_confidence(self, predicates):
        weights = {"P1": 0.25, "P2": 0.35, "P3": 0.25, "P4": 0.15}
        return sum(weights[p] for p, v in predicates.items() if v)


class MassAssignmentAnalyzer(BaseVulnerabilityAnalyzer):
    vuln_type    = "API3"
    cwe_info     = "CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes"
    ground_truth = (
        "Mass Assignment: server binds user-supplied fields to internal model without whitelist, "
        "allowing privilege escalation via fields like role, is_admin, balance."
    )

    def get_extraction_schema(self): return MassAssignmentFacts
    def get_extraction_prompt(self):
        return (
            "List privileged fields sent in request body (role, is_admin, balance, verified...) "
            "and which of these are reflected back in the response with attacker-supplied values."
        )

    def tier1_is_suspicious(self, steps, id_owners=None):
        for s in steps:
            req_sent = s.get("request_sent") or {}
            body = req_sent.get("body")
            status = int(s.get("status_code", 0) or 0)
            if body and status in (200, 201, 204):
                return True, "Write request with request body returned 2xx status"
        return False, ""

    def evaluate_predicates(self, facts: MassAssignmentFacts, evidence: dict):
        p1 = len(facts.privileged_field_in_request) > 0
        p2 = len(facts.privileged_field_reflected_in_response) > 0
        p3 = facts.http_status_code in (200, 201)

        return {"P1": p1, "P2": p2, "P3": p3}

    def calculate_confidence(self, predicates):
        # P2 quan trọng nhất — reflection confirm vulnerability
        weights = {"P1": 0.20, "P2": 0.55, "P3": 0.25}
        return sum(weights[p] for p, v in predicates.items() if v)


class ResourceConsumptionAnalyzer(BaseVulnerabilityAnalyzer):
    vuln_type    = "API4"
    cwe_info     = "CWE-400: Uncontrolled Resource Consumption"
    ground_truth = (
        "Unrestricted Resource Consumption: no rate limiting, quota, or throttle "
        "prevents clients from exhausting server resources."
    )

    def get_extraction_schema(self): return ResourceConsumptionFacts
    def get_extraction_prompt(self):
        return (
            "Count total requests sent. Check if 429/503 or rate-limit headers were triggered. "
            "Note if response times degraded significantly."
        )

    def tier1_is_suspicious(self, steps, id_owners=None):
        # Always escalate resource/rate limit tests to verify summary
        return True, "Escalating rate-limit/burst node for facts analysis"

    def evaluate_predicates(self, facts: ResourceConsumptionFacts, evidence: dict):
        p1 = facts.request_count_sent >= 10
        p2 = not facts.rate_limit_triggered
        p3 = facts.server_degraded

        return {"P1": p1, "P2": p2, "P3": p3}

    def calculate_confidence(self, predicates):
        # P2 trọng tâm — không có rate limiting = chắc chắn vulnerable
        weights = {"P1": 0.25, "P2": 0.50, "P3": 0.25}
        return sum(weights[p] for p, v in predicates.items() if v)


class BFLAAnalyzer(BaseVulnerabilityAnalyzer):
    vuln_type    = "API5"
    cwe_info     = "CWE-285: Improper Authorization"
    ground_truth = (
        "BFLA: regular users can call admin/privileged functions "
        "that should be restricted by role/permission."
    )

    def get_extraction_schema(self): return BFLAFacts
    def get_extraction_prompt(self):
        return (
            "Identify the required privilege level for this function and the caller's actual privilege. "
            "Determine if the action succeeded for a low-privilege caller."
        )

    def tier1_is_suspicious(self, steps, id_owners=None):
        for s in steps:
            desc = s.get("description", "").lower()
            status = int(s.get("status_code", 0) or 0)
            if any(k in desc for k in ["admin", "privilege", "unauthorized", "attacker", "low-privilege"]):
                if status in (200, 201, 204):
                    return True, "Privileged action returned 2xx for lower privilege role"
        return False, ""

    def evaluate_predicates(self, facts: BFLAFacts, evidence: dict):
        p1 = facts.function_requires_privilege in ("admin", "manager", "owner")
        p2 = facts.caller_privilege in ("regular_user", "attacker")
        p3 = facts.action_succeeded
        p4 = facts.http_status_code in (200, 201, 204)

        return {"P1": p1, "P2": p2, "P3": p3, "P4": p4}

    def calculate_confidence(self, predicates):
        weights = {"P1": 0.20, "P2": 0.20, "P3": 0.40, "P4": 0.20}
        return sum(weights[p] for p, v in predicates.items() if v)


class SSRFAnalyzer(BaseVulnerabilityAnalyzer):
    vuln_type    = "API7"
    cwe_info     = "CWE-918: Server-Side Request Forgery (SSRF)"
    ground_truth = (
        "SSRF: server fetches attacker-supplied URL, potentially reaching "
        "internal services, cloud metadata, or localhost."
    )

    def get_extraction_schema(self): return SSRFFacts
    def get_extraction_prompt(self):
        return (
            "Check if an external/attacker-controlled URL was in request. "
            "Check if response timing/content suggests server made outbound call. "
            "Check for internal network data in response."
        )

    def tier1_is_suspicious(self, steps, id_owners=None):
        URL_KEYWORDS = ("http://", "https://", "ftp://", "127.", "169.254", "10.", "192.168", "localhost")
        for s in steps:
            req_sent = s.get("request_sent") or {}
            body = json.dumps(req_sent.get("body") or {})
            params = json.dumps(req_sent.get("params") or {})
            url = req_sent.get("url", "") or ""
            combined = (body + params + url).lower()
            if any(kw in combined for kw in URL_KEYWORDS):
                return True, "Attacker-controlled URL/keyword detected in request"
        return False, ""

    def evaluate_predicates(self, facts: SSRFFacts, evidence: dict):
        p1 = facts.external_url_in_request
        p2 = facts.outbound_request_evidence
        p3 = facts.internal_data_leaked

        return {"P1": p1, "P2": p2, "P3": p3}

    def calculate_confidence(self, predicates):
        # P2 + P3 = strong evidence, P1 alone = just attempt
        weights = {"P1": 0.20, "P2": 0.45, "P3": 0.35}
        return sum(weights[p] for p, v in predicates.items() if v)


class SecurityMisconfigAnalyzer(BaseVulnerabilityAnalyzer):
    vuln_type    = "API8"
    cwe_info     = "CWE-16: Configuration / CWE-200: Exposure of Sensitive Information"
    ground_truth = (
        "Security Misconfiguration: server leaks version banners, stack traces, "
        "debug info, or uses wildcard CORS on sensitive endpoints."
    )

    def get_extraction_schema(self): return SecurityMisconfigFacts
    def get_extraction_prompt(self):
        return (
            "Check response headers for exact server version banners. "
            "Check response body for stack traces, SQL errors, internal paths. "
            "Check CORS header for wildcard on sensitive endpoints."
        )

    def tier1_is_suspicious(self, steps, id_owners=None):
        LEAK_KEYWORDS = ("stack trace", "traceback", "exception",
                         "at line", "sql error", "nginx/", "apache/", "asp.net/")
        for s in steps:
            resp = s.get("response") or {}
            body = (str(resp.get("data", "")) + str(resp.get("errors", "")) + str(resp.get("message", ""))).lower()
            headers = str(resp.get("headers", "")).lower()
            if any(kw in body or kw in headers for kw in LEAK_KEYWORDS):
                return True, "Potential information leak in response"
            if "access-control-allow-origin" in headers and "*" in headers:
                return True, "CORS wildcard detected"
        return False, ""

    def evaluate_predicates(self, facts: SecurityMisconfigFacts, evidence: dict):
        p1 = facts.server_banner_exposed
        p2 = facts.stack_trace_exposed
        p3 = facts.debug_info_exposed
        p4 = facts.cors_wildcard

        return {"P1": p1, "P2": p2, "P3": p3, "P4": p4}

    def calculate_confidence(self, predicates):
        # Stack trace > debug info > banner > CORS
        weights = {"P1": 0.20, "P2": 0.40, "P3": 0.30, "P4": 0.10}
        return sum(weights[p] for p, v in predicates.items() if v)


class InventoryAnalyzer(BaseVulnerabilityAnalyzer):
    vuln_type    = "API9"
    cwe_info     = "CWE-1059: Insufficient Technical Documentation"
    ground_truth = (
        "Improper Inventory: deprecated API versions remain accessible and return "
        "same data as current version, expanding attack surface."
    )

    def get_extraction_schema(self): return InventoryFacts
    def get_extraction_prompt(self):
        return (
            "Check if the versioned endpoint (v1/v2/beta) still responds successfully. "
            "Check if it returns same data as current version."
        )

    def tier1_is_suspicious(self, steps, id_owners=None):
        for s in steps:
            if int(s.get("status_code", 0) or 0) in (200, 201):
                url = s.get("request_sent", {}).get("url", "") or ""
                if any(v in url.lower() for v in ("/v1/", "/v2/", "/beta/", "/deprecated/")):
                    return True, f"Deprecated endpoint accessible: {url}"
        return False, ""

    def evaluate_predicates(self, facts: InventoryFacts, evidence: dict):
        p1 = facts.deprecated_endpoint_accessible
        p2 = facts.undocumented_endpoint_responds
        p3 = facts.http_status_code in (200, 201)

        return {"P1": p1, "P2": p2, "P3": p3}

    def calculate_confidence(self, predicates):
        weights = {"P1": 0.50, "P2": 0.30, "P3": 0.20}
        return sum(weights[p] for p, v in predicates.items() if v)


class FallbackAnalyzer(BaseVulnerabilityAnalyzer):
    vuln_type    = "Generic"
    cwe_info     = "CWE-200: Exposure of Sensitive Information"
    ground_truth = "Generic security evaluation based on access bypass and data leak."

    def get_extraction_schema(self): return FallbackFacts
    def get_extraction_prompt(self):
        return (
            "Did the attack bypass restrictions? What HTTP status was returned? "
            "Was sensitive data exposed in the response?"
        )

    def evaluate_predicates(self, facts: FallbackFacts, evidence: dict):
        return {
            "P1": facts.action_bypassed_restriction,
            "P2": facts.http_status_code in (200, 201, 204),
            "P3": facts.sensitive_data_in_response,
        }

    def calculate_confidence(self, predicates):
        weights = {"P1": 0.40, "P2": 0.30, "P3": 0.30}
        return sum(weights[p] for p, v in predicates.items() if v)


# ══════════════════════════════════════════════════════════════════════
# ROUTER
# ══════════════════════════════════════════════════════════════════════

_PLUGIN_MAP: dict[str, type[BaseVulnerabilityAnalyzer]] = {
    "API1": BOLAAnalyzer,
    "BOLA": BOLAAnalyzer,
    "API2": BrokenAuthAnalyzer,
    "AUTH": BrokenAuthAnalyzer,
    "API3": MassAssignmentAnalyzer,
    "MASS": MassAssignmentAnalyzer,
    "API4": ResourceConsumptionAnalyzer,
    "API5": BFLAAnalyzer,
    "BFLA": BFLAAnalyzer,
    "API7": SSRFAnalyzer,
    "SSRF": SSRFAnalyzer,
    "API8": SecurityMisconfigAnalyzer,
    "MISCONFIG": SecurityMisconfigAnalyzer,
    "API9": InventoryAnalyzer,
    "INVENTORY": InventoryAnalyzer,
}


def get_analyzer_plugin(vuln_type: str) -> BaseVulnerabilityAnalyzer:
    vt = str(vuln_type).upper().replace("-", "").replace("_", "")
    for key, cls in _PLUGIN_MAP.items():
        if key in vt:
            return cls()
    return FallbackAnalyzer()


# ══════════════════════════════════════════════════════════════════════
# VERDICT MAPPING
# ══════════════════════════════════════════════════════════════════════

def score_to_verdict(score: float, vuln_type: str) -> tuple[str, str]:
    """
    Trả về (verdict, severity).

    Ngưỡng cố định — không thay đổi theo vuln_type
    để kết quả nhất quán và có thể so sánh.
    """
    if score >= 0.90:
        severity = "Critical" if "API1" in vuln_type.upper() else "High"
        return "VULNERABLE", severity
    if score >= 0.65:
        return "SUSPICIOUS", "Medium"
    if score >= 0.40:
        return "INCONCLUSIVE", "Low"
    return "SAFE", "Safe"


# ══════════════════════════════════════════════════════════════════════
# LANGGRAPH NODE
# ══════════════════════════════════════════════════════════════════════

def analyzer_node(state: dict) -> dict:
    from app.agents.planning_agent import load_owasp_kb
    from app.services.llm_service import LLMService
    from app.services.llm_scheduler import LLMTaskScheduler
    from app.core.config import settings, get_groq_keys

    execution_results = state.get("execution_results", [])
    id_owners = build_id_owner_map(execution_results)
    logger.info("--- CHẠY SECURE-COVE ANALYZER NODE ---")

    attack_results = [r for r in execution_results if r.get("is_attack")]
    if not attack_results:
        return {**state, "final_report": [], "confidence_score": 1.0,
                "iteration_count": state.get("iteration_count", 0) + 1}

    api_keys  = get_groq_keys(settings.LLM_PARALLEL_KEYS)
    scheduler = LLMTaskScheduler(
        api_keys=api_keys,
        concurrency_per_key=settings.LLM_CONCURRENCY_PER_KEY,
        logger=logger,
    )

    final_reports: list[dict] = []
    llm_tasks:     list       = []
    llm_meta:      list[dict] = []

    for result in attack_results:
        node_id   = result.get("node_id", "")
        vuln_type = result.get("vuln_type", "")
        role      = result.get("role", "attacker")
        steps     = result.get("steps_executed", [])
        analyzer  = get_analyzer_plugin(vuln_type)

        logger.info(f"  Analyzing {node_id} [{vuln_type}]")

        # ── Tier 1: Deterministic fast filter ─────────────────────
        is_suspicious, t1_reason = analyzer.tier1_is_suspicious(steps, id_owners=id_owners)

        if not is_suspicious:
            logger.info(f"    [Tier 1] SAFE — {t1_reason or 'no suspicious signal'}")
            final_reports.append(_build_report(
                node_id, vuln_type, role, steps,
                verdict="SAFE", severity="Safe", score=0.0,
                reasoning="Tier 1 Evidence Engine: no attack signal detected.",
                predicates={}, cwe=analyzer.cwe_info,
            ))
            continue

        logger.info(f"    [Tier 1] Suspicious — {t1_reason} → escalate to Tier 2/3")

        # ── Tier 2 + 3: LLM extraction → predicate scoring ────────
        kb  = load_owasp_kb(vuln_type)
        sys = (
            f"You are a security fact-extraction tool. Do NOT make vulnerability judgments.\n"
            f"CWE: {analyzer.cwe_info}\n"
            f"Definition: {analyzer.ground_truth}\n"
            f"OWASP KB: {json.dumps(kb, ensure_ascii=False)[:800]}\n\n"
            f"Extract ONLY raw observable facts from the execution evidence below."
        )
        # Truncate large data arrays in steps to keep prompt size small
        truncated_steps = truncate_payload(steps)

        human = (
            f"Evidence:\n{json.dumps({'node_id': node_id, 'vuln_type': vuln_type, 'steps': truncated_steps}, ensure_ascii=False, indent=2)}\n\n"
            f"Task: {analyzer.get_extraction_prompt()}"
        )

        def _make_task(msgs, ana):
            def _task(api_key, key_index):
                svc = LLMService(
                    api_key=api_key,
                    model=settings.GPT_OOS_20B,
                    base_url=settings.URL_LLM,
                )
                return svc.generate_structured(
                    prompt_messages=msgs,
                    input_variables={},
                    pydantic_schema=ana.get_extraction_schema(),
                    fallback_method="function_calling",
                )
            return _task

        llm_tasks.append(_make_task(
            [SystemMessage(content=sys), HumanMessage(content=human)],
            analyzer
        ))
        llm_meta.append({
            "node_id": node_id, "vuln_type": vuln_type,
            "role": role, "steps": steps, "analyzer": analyzer,
        })

    # ── Execute parallel LLM calls ─────────────────────────────────
    if llm_tasks:
        results, errors = scheduler.map(llm_tasks, fail_soft=True)

        for idx, facts in enumerate(results):
            info     = llm_meta[idx]
            analyzer = info["analyzer"]

            if errors[idx] or facts is None:
                logger.error(f"  LLM error for {info['node_id']}: {errors[idx]}")
                continue

            predicates = analyzer.evaluate_predicates(facts, info)
            score      = analyzer.calculate_confidence(predicates)
            verdict, severity = score_to_verdict(score, info["vuln_type"])

            reasoning = (
                f"CoVe Predicates [{analyzer.cwe_info}]: "
                + ", ".join(f"{p}={v}" for p, v in predicates.items())
                + f" -> confidence {score:.0%}"
            )

            final_reports.append(_build_report(
                info["node_id"], info["vuln_type"], info["role"], info["steps"],
                verdict=verdict, severity=severity, score=score,
                reasoning=reasoning, predicates=predicates,
                cwe=analyzer.cwe_info,
            ))

    # ── Save ───────────────────────────────────────────────────────
    os.makedirs("outputs", exist_ok=True)
    with open("outputs/final_security_report.json", "w", encoding="utf-8") as f:
        json.dump(final_reports, f, ensure_ascii=False, indent=2)

    avg = (sum(r["assessment"]["confidence_score"] for r in final_reports)
           / len(final_reports) / 100) if final_reports else 0.0

    return {
        **state,
        "final_report":     final_reports,
        "confidence_score": avg,
        "iteration_count":  state.get("iteration_count", 0) + 1,
    }


def _build_report(
    node_id, vuln_type, role, steps,
    verdict, severity, score, reasoning, predicates, cwe
) -> dict:
    return {
        "node_id":  node_id,
        "vuln_type": vuln_type,
        "role":     role,
        "assessment": {
            "verdict":          verdict,
            "is_vulnerable":    verdict in ("VULNERABLE", "SUSPICIOUS"),
            "confidence_score": int(score * 100),
            "reasoning":        reasoning,
            "severity":         severity,
            "cwe":              cwe,
            "predicates":       predicates,
        },
        "evidence": {"steps": steps},
    }