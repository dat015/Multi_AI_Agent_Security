import re

INJECTION_PATTERNS = [
    r"ignore previous instructions",
    r"you are now",
    r"system prompt",
    r"forget your",
    r"act as",
    r"jailbreak",
]

def sanitize_text(text: str, max_length: int = 500) -> str:
    if not text:
        return ""
    
    text = text[:max_length]
    
    for pattern in INJECTION_PATTERNS:
        text = re.sub(pattern, "[REMOVED]", text, flags=re.IGNORECASE)
    
    text = re.sub(r"[^\w\s\-\_\.\,\:\;\(\)\[\]\{\}\/\#\@\!\?]", "", text)
    
    return text.strip()

def sanitize_endpoint(endpoint: dict) -> dict:
    safe = {}
    safe["path"] = sanitize_text(endpoint.get("path", ""), max_length=200)
    safe["method"] = endpoint.get("method", "GET").upper()
    safe["summary"] = sanitize_text(endpoint.get("summary", ""), max_length=300)
    safe["description"] = sanitize_text(endpoint.get("description", ""), max_length=500)
    safe["parameters"] = endpoint.get("parameters", [])
    safe["security"] = endpoint.get("security", [])
    return safe