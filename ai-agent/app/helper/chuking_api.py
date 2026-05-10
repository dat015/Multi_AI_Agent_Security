import json
import yaml
import jsonref

def structural_chunking(resolved_spec, base_url_override=None):
    chunks = []
    
    api_title = resolved_spec.get('info', {}).get('title', 'Hệ thống API')
    base_url = base_url_override
    global_security = resolved_spec.get('security', [])
    
    paths = resolved_spec.get('paths', {})
    
    for path, methods in paths.items():
        for method, details in methods.items():
            
            if method.lower() not in ['get', 'post', 'put', 'delete', 'patch']:
                continue
            
            endpoint_security = details.get('security', global_security)
            
            chunk_text = f"# System: {api_title}\n"
            chunk_text += f"## API: {details.get('summary', 'No summary')}\n"
            chunk_text += f"**Method:** {method.upper()}\n"
            chunk_text += f"**Endpoint:** {base_url}{path}\n"
            chunk_text += f"**Security Requirement:** {endpoint_security}\n\n"
            
            parameters = details.get('parameters', [])
            if parameters:
                chunk_text += "**Tham số đầu vào (Parameters):**\n"
                for param in parameters:
                    req_status = "Bắt buộc" if param.get('required') else "Tùy chọn"
                    desc = param.get('description', '')
                    chunk_text += f"- `{param.get('name')}` (in {param.get('in')}): {desc} [{req_status}]\n"
            
            request_body = details.get('requestBody', {})
            if request_body:
                chunk_text += "\n**Body Payload (JSON Schema):**\n"
                schema = request_body.get('content', {}).get('application/json', {}).get('schema', {})
                chunk_text += f"```json\n{json.dumps(schema, ensure_ascii=False, indent=2)}\n```\n"
            
            metadata = {
                "path": path,
                "method": method.upper(),
                "tags": details.get('tags', [])
            }
            
            chunks.append({
                "page_content": chunk_text,
                "metadata": metadata
            })
            
    return chunks