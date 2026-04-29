import json
import yaml
from typing import List, Dict

def load_spec(file_path: str) -> dict:
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    try:
        return json.loads(content), "json"
    except json.JSONDecodeError:
        return yaml.safe_load(content), "yaml"

def extract_endpoints(spec: dict) -> List[Dict]:
    """Trích xuất tất cả endpoint từ OpenAPI spec."""
    endpoints = []
    paths = spec.get("paths", {})
    
    for path, methods in paths.items():
        for method, details in methods.items():
            if method.lower() not in ["get","post","put","patch","delete","options"]:
                continue
            
            endpoints.append({
                "path": path,
                "method": method.upper(),
                "summary": details.get("summary", ""),
                "description": details.get("description", ""),
                "parameters": details.get("parameters", []),
                "requestBody": details.get("requestBody", {}),
                "responses": list(details.get("responses", {}).keys()),
                "security": details.get("security", 
                            spec.get("security", [])),  # fallback lên global security
                "tags": details.get("tags", []),
            })
    
    return endpoints