import os

from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import json
import logging
from app.services.llm_service import LLMService
from app.core.config import settings 
from app.core.constants import AGENT_SYSTEM_PROMPT
from typing import Union

# Định nghĩa cấu trúc dữ liệu đầu ra bắt buộc bằng Pydantic
class TestStep(BaseModel):
    step: int
    description: str
    path_params: Optional[Dict[str, str]] = Field(default_factory=dict, description="Các biến trên URL path, VD: {'walletId': '{{wallet.id}}'}")
    query_params: Optional[Dict[str, str]] = Field(default_factory=dict, description="Các tham số sau dấu ?, VD: {'limit': '10'}")
    headers: Optional[Dict[str, str]] = Field(default_factory=dict, description="HTTP Headers, bắt buộc chứa Authorization token nếu cần")
    body: Optional[Union[Dict[str, Any], str]] = Field(default=None, description="HTTP Request Body (JSON hoặc Text)")
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
    - Nếu có recon_item (có lỗ hổng): Lặp qua từng loại lỗi và sinh các kịch bản tấn công riêng biệt.
    - Nếu không (chỉ là Producer an toàn): Sinh 1 kịch bản hợp lệ để lấy data.
    """
    path = node_info.get("path")
    method = node_info.get("method")
    
    # --- XỬ LÝ FORMAT MỚI CỦA DEPENDENCY GRAPH ---
    raw_consumes = node_info.get("consumes", [])
    raw_produces = node_info.get("produces", [])
    
    # Chuyển consumes thành mapping dict: {"walletId": "wallet.id"}
    consumes_mapping = {}
    for c in raw_consumes:
        if "raw_name" in c and "tuple" in c and len(c["tuple"]) == 2:
            consumes_mapping[c["raw_name"]] = f"{c['tuple'][0]}.{c['tuple'][1]}"
            
    # Chuyển produces thành list string: ["wallet.id", "wallet.status"]
    produces_list = [f"{p[0]}.{p[1]}" for p in raw_produces if len(p) == 2]

    is_vulnerable = recon_item is not None
    generated_plans = [] 
    
    endpoint_context = {
        "node_id": node_id,
        "path": path,
        "method": method,
        "parameters": node_info.get("parameters"),
        "request_body": node_info.get("request_body"),
        "consumes_mapping": consumes_mapping,
        "produces_list": produces_list
    }

    if is_vulnerable:
        summary = recon_item.get("summary", {})
        vulns = summary.get("vuln", [])
        
        if isinstance(vulns, str):
            vulns = [vulns]
            
        reasoning_dict = recon_item.get("reasoning", {})
        verification_plan = recon_item.get("verification", {})

        for vuln_type in vulns:
            kb_context = load_owasp_kb(vuln_type)
            vuln_reasoning = reasoning_dict.get(vuln_type, "No specific reasoning provided.")
            
            sys_prompt = """You are a professional security tester. Based on the endpoint information and the OWASP KB, generate a detailed security testing plan.
                            RULES:
                        1. DYNAMIC VARIABLES FORMAT: The endpoint consumes variables according to this mapping: {consumes_mapping} (Format is 'parameter_name': 'semantic_variable').
                        - You MUST ALWAYS use DOUBLE BRACES around the 'semantic_variable' for placeholders (e.g., `{{{{user.id}}}}`).
                        - If the test requires multiple users (e.g., BOLA/IDOR testing), you MUST strictly append `_A` and `_B` to the semantic variable name. 
                        - EXACT ALLOWED FORMAT: `{{{{wallet.id_A}}}}`, `{{{{wallet.id_B}}}}`, `{{{{login.token_A}}}}`.
                        - DO NOT invent new naming conventions. Use EXACTLY the semantic variables provided in the mapping.
                        2. HTTP STRUCTURE: Strictly separate your request data into `path_params`, `query_params`, `headers`, and `body`. Do NOT put headers or path parameters inside the `body`.
                        3. Focus strictly on testing the specified vulnerability: {vuln_type}. Reason: {vuln_reasoning}.
                        4. STRICT JSON COMPLIANCE: Valid JSON only. Do not use JS functions like .repeat() or concatenation. Use string placeholders like "[LARGE_PAYLOAD]" if needed.
                        5. Limit to a maximum of 3 highly effective test steps.
                        """
            prompt_messages = [
                ("system", sys_prompt),
                ("human", "Endpoint Details: {endpoint}\nVulnerability Info: {vuln_info}\nOWASP KB: {kb_context}")
            ]

            input_vars = {
                "consumes_mapping": json.dumps(consumes_mapping, ensure_ascii=False),
                "vuln_type": vuln_type,
                "vuln_reasoning": vuln_reasoning,
                "endpoint": json.dumps(endpoint_context, ensure_ascii=False),
                "vuln_info": json.dumps({
                    "vuln_type": vuln_type, 
                    "reasoning": vuln_reasoning,
                    "plan": verification_plan
                }, ensure_ascii=False),
                "kb_context": json.dumps(kb_context, ensure_ascii=False)
            }
            print('data', input_vars)

            print(f"> Đang Planning cho: {node_id} (Tấn công lỗi: {vuln_type})")
            try:
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
                    result.is_attack = True
                    generated_plans.append(result.model_dump())
                    
            except Exception as e:
                logging.error(f"Lỗi khi sinh plan cho {node_id} (Vuln: {vuln_type}): {e}")

    else:
        sys_prompt = """You are an automated API tester. This endpoint is NOT vulnerable, but it MUST be executed to generate prerequisite data ({produces_list}) for subsequent tests.
                    CRITICAL RULES:
                    1. Generate exactly ONE test step with a VALID, BENIGN payload that will return a 200/201 success response. Do NOT generate attacks.
                    2. DYNAMIC VARIABLES: The endpoint needs dynamic variables from previous steps based on this mapping: {consumes_mapping} (Format is 'parameter_name': 'semantic_variable'). 
                    - You MUST use DOUBLE BRACES around the 'semantic_variable' for placeholders. 
                    - Example: If the mapping is "walletId": "wallet.id", you MUST write `{{{{wallet.id}}}}` when assigning a value to walletId. DO NOT use single braces.
                    3. You MUST return the result in valid JSON format matching the schema."""

        prompt_messages = [
            ("system", sys_prompt),
            ("human", "Endpoint Details: {endpoint}")
        ]

        input_vars = {
            "consumes_mapping": json.dumps(consumes_mapping, ensure_ascii=False),
            "produces_list": json.dumps(produces_list, ensure_ascii=False),
            "endpoint": json.dumps(endpoint_context, ensure_ascii=False)
        }
        print('data', input_vars)

        print(f"> Đang Planning cho: {node_id} (API mồi an toàn)")
        try:
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
                result.vuln_type = "None"
                result.is_attack = False
                generated_plans.append(result.model_dump())
                
        except Exception as e:
            logging.error(f"Lỗi khi sinh plan cho {node_id} (API mồi): {e}")

    return generated_plans

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
    
    for node_id in execution_order:
        node_info = graph_nodes.get(node_id, {})
        
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