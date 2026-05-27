import re

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

@staticmethod
def singularize(word: str) -> str:
    """
    users -> user
    wallets -> wallet
    classes -> class
    """

    irregular = {
        "people": "person",
        "children": "child",
    }

    if word in irregular:
        return irregular[word]

    if word.endswith("ies"):
        return word[:-3] + "y"

    if word.endswith("ses"):
        return word[:-2]

    if word.endswith("s") and not word.endswith("ss"):
        return word[:-1]

    return word

@staticmethod
def extract_domain(path: str) -> str:
    """
    /api/v1/users/{id}
        -> user

    /wallets/{walletId}
        -> wallet

    /users/{userId}/wallets
        -> wallet
    """

    path = path.strip("/")

    # bỏ api/version prefix
    path = re.sub(
        r"^(api/)?v\d+/",
        "",
        path
    )

    segments = []

    for s in path.split("/"):

        # bỏ path param
        if s.startswith("{"):
            continue

        s = s.lower()

        if s in {"api", "v1", "v2", "v3"}:
            continue

        segments.append(s)

    if not segments:
        return "unknown"

    # lấy resource cuối
    return singularize(segments[-1])
    
