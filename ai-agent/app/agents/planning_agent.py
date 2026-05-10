import os

from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field
from typing import List, Dict, Any
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
    endpoint: str
    method: str
    vuln_type: str
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

def plan_for_endpoint(recon_item: dict) -> list:
    print('plan for', recon_item)
    summary = recon_item.get("assessment_summary", {})
    path = summary.get("path")
    method = summary.get("method")
    vuln_type = summary.get("primary_vulnerability")
    
    if not vuln_type or vuln_type.lower() == "none":
        return []

    verification_plan = recon_item.get("verification_plan", {})
    kb_context = load_owasp_kb(vuln_type)
    all_steps = []

    try:
        endpoint_info = {
            "path": path,
            "method": method,
            "vuln_type": vuln_type,
            "recon_verification_plan": verification_plan
        }

        prompt_messages = [
            ("system", """You are a professional security tester. Based on the endpoint information and the OWASP knowledge base, generate a detailed security testing plan.
        Focus on creating payloads to test authorization controls and business logic integrity.
        You MUST return the result in valid JSON format."""),
            ("human", "Endpoint: {endpoint}\nOWASP KB: {kb_context}")
        ]

        input_vars = {
            "endpoint": json.dumps(endpoint_info, ensure_ascii=False),
            "kb_context": json.dumps(kb_context, ensure_ascii=False)
        }

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
            result.endpoint = path
            result.method = method
            result.vuln_type = vuln_type
            all_steps.append(result.model_dump()) 
        
    except Exception as e:
        logging.error(f"Lỗi khi sinh plan cho {path} với {vuln_type}: {e}")
            
    return all_steps

def planning_node(state: dict) -> dict:
    audits_list = state.get("filtered_endpoints", [])
    
    print(f"Planning Agent nhận được {len(audits_list)} endpoint objects từ Recon.")
    
    if audits_list:
        print(f"Sample endpoint object: {json.dumps(audits_list[0], ensure_ascii=False, indent=2)}")
    
    full_test_plan = []
    
    for item in audits_list:
        plans = plan_for_endpoint(item) 
        print(f"Đã sinh được {len(plans)} test steps cho endpoint {item.get('assessment_summary', {}).get('path')}")
        if plans:
             full_test_plan.extend(plans)
        
    output_dir = "outputs"
    os.makedirs(output_dir, exist_ok=True)
    
    file_path = os.path.join(output_dir, "test_plan.json")
    
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(full_test_plan, f, ensure_ascii=False, indent=2)
    
    print(f"Đã sinh test plan thành công. Tổng {len(full_test_plan)} test scenarios.")
    
    return {
        **state,
        "test_plan": full_test_plan
    }