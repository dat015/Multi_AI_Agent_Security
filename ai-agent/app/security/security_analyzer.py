class SecurityAnalyzer:
    # Blacklist các từ khóa chắc chắn là filter, không phải ID
    FILTER_KEYWORDS = {"page", "limit", "offset", "sort", "search", "order"}

    @staticmethod
    def analyze(endpoints):
        findings = []
        for ep in endpoints:
            score = 0
            reasons = []

            # 1. Check Method (PUT/DELETE/PATCH mặc định +2 điểm)
            if ep.method in ["PUT", "DELETE", "PATCH"]:
                score += 2
                reasons.append("Dangerous Method")

            # 2. Check Path Parameters (Mặc định +5 điểm vì chắc chắn là ID)
            for param in ep.parameters:
                if param.location == "path":
                    score += 5
                    reasons.append(f"ID in Path: {param.name}")
                
                # Check Query ID (Loại trừ filter)
                elif param.location == "query":
                    if not any(k in param.name.lower() for k in SecurityAnalyzer.FILTER_KEYWORDS):
                        if "id" in param.name.lower() or param.type == "integer":
                            score += 3
                            reasons.append(f"Potential ID in Query: {param.name}")

            # 3. Kết luận: Chỉ những endpoint > 3 điểm mới gửi cho AI
            if score >= 5:
                findings.append({
                    "endpoint": f"{ep.method} {ep.path}",
                    "score": score,
                    "raw_context": reasons, # Gửi dữ liệu thô này cho AI-Lite dịch
                    "requires_auth": ep.requires_auth
                })
        return findings