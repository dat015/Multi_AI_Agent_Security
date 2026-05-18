from typing import List, Dict, Any

def endpoint_to_markdown(ep: Dict[str, Any]) -> str:
  
    method = ep.get("method", "UNKNOWN").upper()
    path = ep.get("path", "/")
    summary = ep.get("summary") or "No description available"
    severity = ep.get("severity", "UNKNOWN")
    score = ep.get("score", 0)
    requires_auth = "required (with Auth)" if ep.get("requires_auth") else "optional (public)"

    # Xây dựng header của Endpoint
    md = f"### [{method}] {path}\n"
    md += f"- **Summary:** {summary}\n"
    md += f"- **Severity:** **{severity}** (Score: {score})\n"
    md += f"- **Authentication:** {requires_auth}\n\n"

    # Xử lý Parameters & Request Body
    params = ep.get("parameters", [])
    if params:
        md += "**Parameters & Payload:**\n"
        for p in params:
            req_status = "required" if p.get("required") else "optional"
            location = p.get("location")
            name = p.get("name")
            p_type = p.get("type", "unknown")
            
            if location == "body":
                md += f"  - `[Request Body]`: Type `{p_type}` [{req_status}]\n"
            else:
                md += f"  - `{name}` (in {location}): Type `{p_type}` [{req_status}]\n"
        md += "\n"
    has_request_body = ep.get("has_request_body", False)
    body_fields = ep.get("body_fields", [])
    if has_request_body:
        md += "**Payload:**\n"
        if body_fields:
            md += f"  - **Fields:** `{', '.join(body_fields)}`\n\n"
        else:
            md += "  - Body accepted, no explicit fields (file/raw)\n\n"
    # Xử lý Tags và Lỗi bảo mật
    tags = ep.get("tags", [])
    if tags:
        md += f"**Vulnerability Tags:** {', '.join(tags)}\n"

    reasons = ep.get("reasons", [])
    if reasons:
        md += "**Reasons:**\n"
        for reason in reasons:
            md += f"  - {reason}\n"

    return md

def chunk_endpoints_to_markdown(endpoints: List[Dict[str, Any]], chunk_size: int = 10) -> List[Dict[str, Any]]:

    chunks = []
    current_chunk_texts = []
    current_metadata = {
        "endpoints": [],
        "severities": set(),
        "tags": set()
    }

    for i, ep in enumerate(endpoints):
        # 1. Chuyển endpoint này thành Markdown
        md_text = endpoint_to_markdown(ep)
        current_chunk_texts.append(md_text)
        
        # 2. Thu thập metadata cho chunk này
        current_metadata["endpoints"].append(f"{ep.get('method')} {ep.get('path')}")
        current_metadata["severities"].add(ep.get("severity"))
        current_metadata["tags"].update(ep.get("tags", []))

        # 3. Nếu đã gom đủ chunk_size (10) hoặc đang ở endpoint cuối cùng của list
        if (i + 1) % chunk_size == 0 or i == len(endpoints) - 1:
            # Ghép các endpoint lại bằng dấu phân cách (Horizontal Rule)
            chunk_content = "\n---\n\n".join(current_chunk_texts)
            
            # Đóng gói chunk
            chunks.append({
                "page_content": chunk_content,
                "metadata": {
                    "chunk_size": len(current_chunk_texts),
                    "endpoints": current_metadata["endpoints"],
                    "severities": list(current_metadata["severities"]),
                    "tags": list(current_metadata["tags"])
                }
            })
            
            # Reset dữ liệu để đón chunk tiếp theo
            current_chunk_texts = []
            current_metadata = {"endpoints": [], "severities": set(), "tags": set()}

    return chunks