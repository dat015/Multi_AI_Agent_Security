import re

class SecurityAnalyzer:
    # 1. Danh sách từ khóa lọc rác (Dành cho API4)
    FILTER_KEYWORDS = {"page", "limit", "offset", "sort", "search", "order", "size"}
    
    # 2. Danh sách từ khóa nhạy cảm (Dành cho API5, API6, API9)
    SENSITIVE_KEYWORDS = {
        "admin": "API5_BFLA",
        "internal": "API5_BFLA",
        "config": "API8_Misconfig",
        "debug": "API9_Inventory",
        "v1": "API9_Inventory",
        "deprecated": "API9_Inventory",
        "checkout": "API6_BusinessFlow",
        "payment": "API6_BusinessFlow",
        "transfer": "API6_BusinessFlow",
        "password-reset": "API2_BrokenAuth"
    }

    # 3. Danh sách từ khóa SSRF (Dành cho API7)
    SSRF_KEYWORDS = {"url", "uri", "webhook", "callback", "source", "dest", "target"}

    @staticmethod
    def analyze(endpoints):
        findings = []
        for ep in endpoints:
            score = 0
            reasons = []
            tags = set()
            path_lower = ep.path.lower()

            # --- API1: BOLA & API5: BFLA (Method & Path) ---
            if ep.method in ["PUT", "DELETE", "PATCH"]:
                score += 2
                reasons.append(f"Dangerous Method: {ep.method}")
            
            for param in ep.parameters:
                # Check Path Params (API1)
                if param.location == "path":
                    score += 5
                    tags.add("API1_BOLA")
                    reasons.append(f"Resource ID in Path: {param.name}")
                
                # Check Query Params (API1 & API7)
                elif param.location == "query":
                    p_name = param.name.lower()
                    # Nhận diện ID trong Query (API1)
                    if not any(k in p_name for k in SecurityAnalyzer.FILTER_KEYWORDS):
                        if "id" in p_name or param.type == "integer":
                            score += 3
                            tags.add("API1_BOLA")
                            reasons.append(f"Potential ID in Query: {param.name}")
                    
                    # Nhận diện tham số URL (API7)
                    if any(k in p_name for k in SecurityAnalyzer.SSRF_KEYWORDS):
                        score += 4
                        tags.add("API7_SSRF")
                        reasons.append(f"URL parameter detected: {param.name}")

            # --- API5, API6, API9: Keyword-based Detection ---
            for key, tag in SecurityAnalyzer.SENSITIVE_KEYWORDS.items():
                if key in path_lower:
                    score += 4
                    tags.add(tag)
                    reasons.append(f"Sensitive keyword in path: {key}")

            # --- API2 & API8: Authentication & Config ---
            if not ep.requires_auth:
                # Nếu không yêu cầu auth mà không phải là login/register
                if not any(k in path_lower for k in ["login", "register", "public"]):
                    score += 5
                    tags.add("API2_BrokenAuth")
                    reasons.append("Endpoint missing authentication")

            # --- API4: Unrestricted Resource Consumption ---
            if ep.method == "GET" and "/api/" in path_lower:
                # Nếu trả về danh sách mà không có tham số phân trang
                has_pagination = any(p.name.lower() in SecurityAnalyzer.FILTER_KEYWORDS for p in ep.parameters)
                if not has_pagination:
                    score += 2
                    tags.add("API4_Consumption")
                    reasons.append("GET list might lack pagination")

            # --- API3: BOPLA (Mass Assignment) ---
            # Nếu phương thức là POST/PUT và có body, AI cần soi kỹ trường nhạy cảm
            if ep.method in ["POST", "PUT", "PATCH"]:
                score += 1
                tags.add("API3_BOPLA")
                reasons.append("Data mutation method - potential Mass Assignment")

            # --- KẾT LUẬN ---
            if score >= 5 or tags:
                findings.append({
                    "endpoint": f"{ep.method} {ep.path}",
                    "score": score,
                    "tags": list(tags),
                    "reasons": reasons,
                    "requires_auth": ep.requires_auth,
                    "summary": ep.summary
                })
        return findings