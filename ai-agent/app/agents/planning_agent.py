import os

from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field
from typing import List, Dict, Any
import json
import logging
from app.services.llm_service import LLMService
# 1. IMPORT THÊM SETTINGS (Giống file recon)
from app.core.config import settings 

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

# 2. KHỞI TẠO LLM TRỎ VỀ GROQ
# Thay vì dùng gpt-4o, ta truyền base_url và api_key của Groq vào
llm = ChatOpenAI(
    api_key=settings.GROQ_API_KEY,
    base_url=settings.URL_LLM,
    model=settings.LARGE_MODEL_NAME, # Đảm bảo model này hỗ trợ tool calling (ví dụ: llama3-70b-8192)
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

# 3. CẬP NHẬT PROMPT
# Lưu ý: Khi dùng LLM mã nguồn mở qua Groq, bạn CẦN nhắc nhở nó trả về JSON rõ ràng hơn GPT-4.
PLANNING_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """Bạn là security tester chuyên nghiệp. Dựa trên thông tin endpoint và knowledge base OWASP, hãy sinh kế hoạch kiểm thử chi tiết.
Tập trung vào việc tạo các payload để kiểm tra quyền truy cập hoặc logic nghiệp vụ.
BẮT BUỘC trả về kết quả dưới định dạng chuẩn JSON."""),
    ("human", "Endpoint: {endpoint}\nOWASP KB: {kb_context}")
])

def plan_for_endpoint(recon_item: dict) -> list:
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

        # Khai báo messages cho prompt
        prompt_messages = [
            ("system", """Bạn là security tester chuyên nghiệp. Dựa trên thông tin endpoint và knowledge base OWASP, hãy sinh kế hoạch kiểm thử chi tiết.
            Tập trung vào việc tạo các payload để kiểm tra quyền truy cập hoặc logic nghiệp vụ.
            BẮT BUỘC trả về kết quả dưới định dạng chuẩn JSON."""),
            ("human", "Endpoint: {endpoint}\nOWASP KB: {kb_context}")
        ]

        input_vars = {
            "endpoint": json.dumps(endpoint_info, ensure_ascii=False),
            "kb_context": json.dumps(kb_context, ensure_ascii=False)
        }

        # GỌI LLM QUA SERVICE
        result = LLMService.generate_structured(
            self=LLMService(),
            prompt_messages=prompt_messages,
            input_variables=input_vars,
            pydantic_schema=TestPlan,
            fallback_method="function_calling" # Xử lý lỗi 400 json_schema của Groq
        )

        # Xử lý kết quả Pydantic (Đã fix lỗi list/dict trước đó)
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
    # State này chứa output từ Recon Node
    filtered = state.get("filtered_endpoints", {})
    full_test_plan = []
    
    # Lấy mảng audits bằng .get() an toàn thay vì dot notation
    audits_list = filtered.get("audits", [])
    
    print(f"Planning Agent nhận {len(audits_list)} endpoint objects từ Recon.")
    
    for item in audits_list:
        # item lúc này tương ứng với 1 object trong mảng của Recon
        plans = plan_for_endpoint(item)
        full_test_plan.extend(plans)
    output_dir = "outputs"
    os.makedirs(output_dir, exist_ok=True)
    
    file_path = os.path.join(output_dir, "test_plan.json")
    # Lưu file backup
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(full_test_plan, f, ensure_ascii=False, indent=2)
        
    print(f"Đã sinh test plan thành công. Tổng {len(full_test_plan)} test scenarios.")
    
    return {
        **state,
        "test_plan": full_test_plan
    }