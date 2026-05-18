import os

from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import json
import logging
from app.services.llm_service import LLMService
from app.core.config import settings 
from app.core.constants import AGENT_SYSTEM_PROMPT

# Định nghĩa cấu trúc dữ liệu đầu ra bắt buộc bằng Pydantic
class TestStep(BaseModel):
    step: int
    description: str
    payload: Dict[str, Any]
    expected_indicator: str

class TestPlan(BaseModel):
    node_id: Optional[str] = Field(default=None, description="Định danh của API, VD: POST:/users")
    endpoint: Optional[str] = Field(default=None)
    method: Optional[str] = Field(default=None)
    is_attack: Optional[bool] = Field(default=False, description="True nếu là test bảo mật, False nếu chỉ là API mồi tạo data")
    vuln_type: Optional[str] = Field(default="None")
    test_steps: List[TestStep]
    max_iterations: int = Field(default=5)

llm = ChatOpenAI(
    api_key=settings.GROQ_API_KEY,
    base_url=settings.URL_LLM,
    model=settings.LARGE_MODEL_NAME,
    temperature=0.1
)

# Ép kiểu đầu ra bằng Pydantic (Groq hỗ trợ tốt tính năng này qua API của OpenAI)
structured_llm = llm.with_structured_output(TestPlan)

def load_owasp_kb(owasp_id: str) -> dict:
    try:
        with open("knowledge/owasp_kb.json", "r", encoding="utf-8") as f:
            kb_list = json.load(f)
        
        if isinstance(kb_list, list):
            for item in kb_list:
                if isinstance(item, dict) and item.get("owasp_id") == owasp_id:
                    return item
                    
        return {}
        
    except Exception as e:
        print(f"Lỗi khi đọc file owasp_kb.json: {e}")
        return {}

def plan_for_endpoint(node_id: str, node_info: dict, recon_item: dict = None) -> list:
    """
    Sinh kịch bản cho một API endpoint.
    - Nếu có recon_item (có lỗ hổng): Sinh kịch bản tấn công.
    - Nếu không (chỉ là Producer an toàn): Sinh kịch bản hợp lệ để lấy data.
    """
    path = node_info.get("path")
    method = node_info.get("method")
    consumes = node_info.get("consumes", [])
    produces = node_info.get("produces", [])
    
    is_vulnerable = recon_item is not None
    
    # Lấy thông tin lỗ hổng nếu có
    vuln_type = "None"
    verification_plan = {}
    kb_context = {}
    
    if is_vulnerable:
        summary = recon_item.get("summary", {})
        vuln_type = summary.get("vuln", "None")
        verification_plan = recon_item.get("verification", {})
        kb_context = load_owasp_kb(vuln_type)

    endpoint_context = {
        "node_id": node_id,
        "path": path,
        "method": method,
        "parameters": node_info.get("parameters"),
        "request_body": node_info.get("request_body"),
        "consumes_variables": consumes,
        "produces_variables": produces
    }

    if is_vulnerable:
        sys_prompt = """You are a professional security tester. Based on the endpoint information and the OWASP knowledge base, generate a detailed security testing plan.
        CRITICAL RULES:
        1. The endpoint needs dynamic IDs from previous steps: {consumes_variables}. You MUST use `{{variable_name}}` EXACTLY as a string placeholder in your payloads/paths so the Execution Engine can replace it (e.g., "walletId": "{{walletId}}").
        2. Focus on testing the specified vulnerability.
        You MUST return the result in valid JSON format matching the schema."""
    else:
        sys_prompt = """You are an automated API tester. This endpoint is NOT vulnerable, but it MUST be executed to generate prerequisite data ({produces_variables}) for subsequent tests.
        CRITICAL RULES:
        1. Generate exactly ONE test step with a VALID, BENIGN payload that will return a 200/201 success response. Do NOT generate attacks.
        2. The endpoint needs dynamic IDs from previous steps: {consumes_variables}. Use `{{variable_name}}` as a placeholder in your payloads.
        You MUST return the result in valid JSON format matching the schema."""

    prompt_messages = [
        ("system", sys_prompt),
        ("human", "Endpoint Details: {endpoint}\nVulnerability Info: {vuln_info}\nOWASP KB: {kb_context}")
    ]

    input_vars = {
        "consumes_variables": str(consumes),
        "produces_variables": str(produces),
        "endpoint": json.dumps(endpoint_context, ensure_ascii=False),
        "vuln_info": json.dumps({"vuln_type": vuln_type, "plan": verification_plan}, ensure_ascii=False),
        "kb_context": json.dumps(kb_context, ensure_ascii=False)
    }

    try:
        print(f"> Đang Planning cho: {node_id} (Tấn công: {is_vulnerable})")
        result = LLMService.generate_structured(
            self=LLMService(),
            prompt_messages=prompt_messages,
            input_variables=input_vars,
            pydantic_schema=TestPlan,
            fallback_method="function_calling" 
        )

        if isinstance(result, list):
            result = result[0] if len(result) > 0 else None
        if isinstance(result, dict):
            result = TestPlan(**result)
             
        if result and isinstance(result, TestPlan):
            result.node_id = node_id
            result.endpoint = path
            result.method = method
            result.vuln_type = vuln_type
            result.is_attack = is_vulnerable
            return [result.model_dump()]
            
    except Exception as e:
        logging.error(f"Lỗi khi sinh plan cho {node_id}: {e}")
            
    return []

def planning_node(state: dict) -> dict:
    audits_list = state.get("filtered_endpoints", [])
    dependency_data = state.get("dependency_graph", {})
    
    execution_order = dependency_data.get("execution_order", [])
    graph_nodes = dependency_data.get("graph", {}).get("nodes", {})
    
    print(f"\n--- CHẠY PLANNING NODE ---")
    print(f"Tổng số API cần lên kịch bản (kể cả API mồi): {len(execution_order)}")
    
    # Map các audits theo node_id để dễ truy xuất
    audit_map = {}
    for item in audits_list:
        method = item.get("summary", {}).get("method", "").upper()
        path = item.get("summary", {}).get("path", "")
        if method and path:
            node_id = f"{method}:{path}"
            audit_map[node_id] = item

    full_test_plan = []
    
    # 💥 DUYỆT THEO ĐÚNG THỨ TỰ DEPENDENCY GRAPH 
    for node_id in execution_order:
        node_info = graph_nodes.get(node_id, {})
        
        # Nếu có trong audit_map => API bị lỗi => Sinh kịch bản tấn công
        # Nếu không có => API mồi => Sinh kịch bản hợp lệ
        recon_item = audit_map.get(node_id)
        
        plans = plan_for_endpoint(node_id, node_info, recon_item)
        if plans:
            full_test_plan.extend(plans)
            
    output_dir = "outputs"
    os.makedirs(output_dir, exist_ok=True)
    file_path = os.path.join(output_dir, "test_plan.json")
    
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(full_test_plan, f, ensure_ascii=False, indent=2)
    
    print(f"Đã sinh test plan thành công. Lưu tại: {file_path}")
    
    return {
        **state,
        "test_plan": full_test_plan
    }