@staticmethod
def normalize_recon_output(parsed):
    normalized = []

    # Nếu LLM trả list → dùng luôn
    if isinstance(parsed, list):
        items = parsed
    else:
        items = parsed.get("audit_results", [])

    for item in items:
        summary = item.get("assessment_summary", {})

        vuln = summary.get("primary_vulnerability")

        # bỏ qua None
        if not vuln or vuln == "None":
            continue

        normalized.append({
            "path": summary.get("path"),
            "method": summary.get("method"),
            "potential_vulns": [vuln],
            "confidence": summary.get("confidence_score", 0),
        })

    return normalized