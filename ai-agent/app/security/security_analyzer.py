# utils/security_analyzer.py
import re
from typing import List, Dict, Any
from app.core.enum import THIRD_PARTY_KEYWORDS, SENSITIVE_BODY_FIELDS, SSRF_PARAM_KEYWORDS, SENSITIVE_PATH_KEYWORDS, PAGINATION_KEYWORDS

class SecurityAnalyzer:
    @staticmethod
    def _extract_body_fields(endpoint) -> set:
        """
        Trích xuất tên field từ requestBody schema.
        Hỗ trợ cả schema dạng object properties và allOf/anyOf.
        """
        fields = set()
        body = getattr(endpoint, "request_body", None) or {}

        schema = {}
        if isinstance(body, dict):
            schema = (
                body
                .get("content", {})
                .get("application/json", {})
                .get("schema", {})
            )

        def extract_props(s):
            if not isinstance(s, dict):
                return
            for field in s.get("properties", {}).keys():
                fields.add(field.lower())
            # Xử lý allOf / anyOf / oneOf
            for combiner in ["allOf", "anyOf", "oneOf"]:
                for sub in s.get(combiner, []):
                    extract_props(sub)

        extract_props(schema)
        return fields

    @staticmethod
    def analyze(endpoints) -> List[Dict[str, Any]]:
        findings = []

        for ep in endpoints:
            score = 0
            reasons = []
            tags: Dict[str, List[str]] = {}  # tag → list of reasons

            def add_tag(tag: str, reason: str, points: int):
                """Helper để thêm tag + reason + điểm cùng lúc."""
                nonlocal score
                score += points
                if tag not in tags:
                    tags[tag] = []
                tags[tag].append(reason)
                reasons.append(f"[{tag}] {reason}")

            path_lower = ep.path.lower()
            method = ep.method.upper()

            # ── API1: BOLA ────────────────────────────────────────────
            # Dấu hiệu chính: path param (truy cập resource theo ID)
            path_params = [
                p for p in ep.parameters if p.location == "path"
            ]
            for param in path_params:
                add_tag(
                    "API1",
                    f"Path param '{param.name}' → truy cập resource theo ID",
                    5,
                )

            # ID trong query param cũng có thể là BOLA
            for param in ep.parameters:
                if param.location != "query":
                    continue
                p_name = param.name.lower()
                is_filter_param = any(
                    k in p_name
                    for k in PAGINATION_KEYWORDS
                )
                if not is_filter_param:
                    is_id = (
                        p_name.endswith("_id")
                        or p_name.endswith("id")
                        or p_name == "id"
                        or getattr(param, "type", "") == "integer"
                    )
                    if is_id:
                        add_tag(
                            "API1",
                            f"Query param '{param.name}' có thể là resource ID",
                            3,
                        )

            # Phương thức nguy hiểm đi kèm path param → BOLA nghiêm trọng hơn
            if path_params and method in ["PUT", "DELETE", "PATCH"]:
                add_tag(
                    "API1",
                    f"Method {method} + path param → có thể sửa/xóa resource người khác",
                    2,
                )

            # ── API2: Broken Authentication ───────────────────────────
            # Không có auth mà không phải public endpoint
            PUBLIC_PATHS = {"login", "register", "signup", "public",
                            "health", "ping", "docs", "swagger"}
            is_public = any(k in path_lower for k in PUBLIC_PATHS)

            if not ep.requires_auth and not is_public:
                add_tag(
                    "API2",
                    "Endpoint không yêu cầu authentication",
                    5,
                )

            # Auth endpoint nhạy cảm (brute-force, token abuse)
            AUTH_SENSITIVE = {
                "password-reset", "forgot-password", "reset-password",
                "change-password", "verify", "otp", "2fa",
                "token", "refresh",
            }
            for kw in AUTH_SENSITIVE:
                if kw in path_lower:
                    add_tag(
                        "API2",
                        f"Auth-sensitive path '{kw}' → nguy cơ brute-force/token abuse",
                        3,
                    )
                    break  # Chỉ cộng 1 lần dù match nhiều keyword

            # ── API3: Broken Object Property Level Auth ───────────────
            # Kiểm tra requestBody schema có field nhạy cảm không
            if method in ["POST", "PUT", "PATCH"]:
                body_fields = SecurityAnalyzer._extract_body_fields(ep)
                dangerous_fields = body_fields & SENSITIVE_BODY_FIELDS
                if dangerous_fields:
                    add_tag(
                        "API3",
                        f"RequestBody chứa field nhạy cảm: {dangerous_fields} "
                        f"→ nguy cơ mass assignment / over-posting",
                        4,
                    )
                elif method in ["PUT", "PATCH"]:
                    # PUT/PATCH không có body field nhạy cảm rõ ràng
                    # vẫn đáng nghi vì có thể update property không được phép
                    add_tag(
                        "API3",
                        f"Method {method} có thể cho phép update field không được phép",
                        2,
                    )

            # ── API4: Unrestricted Resource Consumption ───────────────
            if method == "GET":
                has_pagination = any(
                    p.name.lower() in PAGINATION_KEYWORDS
                    for p in ep.parameters
                )
                # List endpoint (path không kết thúc bằng ID param)
                is_list = not path_lower.rstrip("/").endswith("}")
                if is_list and not has_pagination:
                    add_tag(
                        "API4",
                        "GET list không có pagination → có thể trả về toàn bộ data",
                        3,
                    )

            # Upload endpoint không giới hạn size
            if method in ["POST", "PUT"] and any(
                k in path_lower for k in ["upload", "file", "import", "attachment"]
            ):
                add_tag(
                    "API4",
                    "Upload endpoint → cần kiểm tra giới hạn file size / rate limit",
                    3,
                )

            # ── API5: BFLA ────────────────────────────────────────────
            BFLA_KEYWORDS = {
                "admin", "internal", "manage", "management",
                "superuser", "moderator", "impersonate",
            }
            for kw in BFLA_KEYWORDS:
                if kw in path_lower:
                    add_tag(
                        "API5",
                        f"Path chứa '{kw}' → endpoint có thể dành cho role cao hơn",
                        4,
                    )

            # ── API6: Unrestricted Access to Sensitive Business Flows ─
            BUSINESS_KEYWORDS = {
                "checkout", "payment", "transfer", "withdraw",
                "refund", "purchase", "subscribe", "promo",
                "coupon", "redeem", "vote", "review", "order",
            }
            matched_business = [k for k in BUSINESS_KEYWORDS if k in path_lower]
            if matched_business:
                add_tag(
                    "API6",
                    f"Business-critical flow: {matched_business} "
                    f"→ cần kiểm tra rate limit / bot protection",
                    4,
                )

            # ── API7: SSRF ────────────────────────────────────────────
            for param in ep.parameters:
                p_name = param.name.lower()
                matched_ssrf = [
                    k for k in SSRF_PARAM_KEYWORDS
                    if k in p_name
                ]
                if matched_ssrf:
                    add_tag(
                        "API7",
                        f"Param '{param.name}' có thể chứa URL "
                        f"→ nguy cơ SSRF ({matched_ssrf})",
                        5,
                    )

            # Kiểm tra body field chứa URL
            if method in ["POST", "PUT", "PATCH"]:
                body_fields = SecurityAnalyzer._extract_body_fields(ep)
                ssrf_body = body_fields & SSRF_PARAM_KEYWORDS
                if ssrf_body:
                    add_tag(
                        "API7",
                        f"RequestBody field '{ssrf_body}' có thể nhận URL → SSRF",
                        4,
                    )

            # ── API8: Security Misconfiguration ──────────────────────
            MISCONFIG_KEYWORDS = {
                "config", "settings", "env", "debug",
                "swagger", "openapi", "actuator", "metrics",
            }
            for kw in MISCONFIG_KEYWORDS:
                if kw in path_lower:
                    add_tag(
                        "API8",
                        f"Path '{kw}' → endpoint có thể lộ thông tin cấu hình",
                        4,
                    )

            # ── API9: Improper Inventory Management ──────────────────
            # Phiên bản cũ trong path
            version_match = re.search(r"/v(\d+)/", path_lower)
            if version_match:
                version_num = int(version_match.group(1))
                # v1 khi đã có v2+ thường là deprecated
                # Heuristic: v1 luôn flag, v2+ chỉ flag nếu có "deprecated"/"legacy"
                if version_num == 1:
                    add_tag(
                        "API9",
                        f"Endpoint v{version_num} → có thể là version cũ/deprecated",
                        2,
                    )

            INVENTORY_KEYWORDS = {"deprecated", "legacy", "old", "beta", "test"}
            for kw in INVENTORY_KEYWORDS:
                if kw in path_lower:
                    add_tag(
                        "API9",
                        f"Path chứa '{kw}' → endpoint chưa được quản lý đúng",
                        3,
                    )

            # ── API10: Unsafe Consumption of APIs ────────────────────
            # Endpoint tích hợp bên ngoài / third-party
            matched_third = [
                k for k in THIRD_PARTY_KEYWORDS
                if k in path_lower
            ]
            if matched_third:
                add_tag(
                    "API10",
                    f"Path liên quan đến external/third-party: {matched_third} "
                    f"→ cần kiểm tra validate input từ nguồn ngoài",
                    3,
                )
            # Param nhận URL bên ngoài cũng là dấu hiệu API10
            for param in ep.parameters:
                p_name = param.name.lower()
                if any(k in p_name for k in {"provider", "source", "feed", "external"}):
                    add_tag(
                        "API10",
                        f"Param '{param.name}' → có thể tiêu thụ data từ API ngoài",
                        2,
                    )

            # ── Kết luận: giữ endpoint nếu có ít nhất 1 tag ─────────
            # Tại sao không dùng score threshold?
            # → Một endpoint có API7_SSRF (score 5) quan trọng hơn
            #   3 endpoint mỗi cái score 2. Tag-based đảm bảo
            #   không bỏ sót lỗ hổng nghiêm trọng dù score thấp.
            if tags:
                # Tính severity tổng thể
                if score >= 10:
                    severity = "CRITICAL"
                elif score >= 7:
                    severity = "HIGH"
                elif score >= 4:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

                findings.append({
                    # ── Thông tin đầy đủ để Planning Agent dùng ──────
                    "path":         ep.path,          # path riêng lẻ
                    "method":       method,            # method riêng lẻ
                    "summary":      ep.summary,
                    "requires_auth": ep.requires_auth,
                    "parameters": [
                        {
                            "name":     p.name,
                            "location": p.location,   # path/query/header/cookie
                            "type":     getattr(p, "type", "string"),
                            "required": getattr(p, "required", False),
                        }
                        for p in ep.parameters
                    ],
                    "has_request_body": method in ["POST", "PUT", "PATCH"],

                    # ── Thông tin phân tích bảo mật ──────────────────
                    "score":    score,
                    "severity": severity,
                    "tags":     list(tags.keys()),
                    "tag_details": {
                        tag: reasons_list
                        for tag, reasons_list in tags.items()
                    },
                    "reasons":  reasons,
                })

        # Sắp xếp theo score giảm dần: endpoint nguy hiểm nhất lên đầu
        findings.sort(key=lambda x: x["score"], reverse=True)
        return findings