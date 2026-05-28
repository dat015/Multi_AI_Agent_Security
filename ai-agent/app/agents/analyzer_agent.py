import json
import os
import logging
from typing import List, Dict, Any
from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI

from app.core.constants import ANALYZER_SYSTEM_PROMPT
from app.services.llm_service import LLMService
from app.core.config import settings

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════
# SCHEMA ĐẦU RA CHO LLM (JSON Format)
# ══════════════════════════════════════════════════════════════════════

class VulnerabilityAssessment(BaseModel):
    is_vulnerable: bool = Field(..., description="True nếu cuộc tấn công thành công (hệ thống có lỗi). False nếu hệ thống an toàn chặn được.")
    confidence_score: int = Field(..., description="Độ tự tin của kết luận từ 1 đến 100")
    reasoning: str = Field(..., description="Giải thích chi tiết: Tại sao response này chứng minh có lỗi hoặc không có lỗi?")
    severity: str = Field(..., description="Mức độ nghiêm trọng: Critical, High, Medium, Low, hoặc Safe")

class FinalReport(BaseModel):
    assessments: List[VulnerabilityAssessment]


# ══════════════════════════════════════════════════════════════════════
# ANALYZER NODE
# ══════════════════════════════════════════════════════════════════════

def analyzer_node(state: dict) -> dict:
    execution_results = state.get("execution_results", [])
    
    logger.info("\n--- CHẠY ANALYZER NODE (Đánh giá Lỗ hổng) ---")
    
    # Chỉ lọc ra các request có is_attack == True (Bỏ qua các API mồi)
    attack_results = [res for res in execution_results if res.get("is_attack") == True]
    
    if not attack_results:
        logger.info("Không có kịch bản tấn công nào để phân tích.")
        return {**state, "final_report": []}

    final_reports = []

    # System Prompt huấn luyện LLM trở thành một chuyên gia bảo mật
    sys_prompt = ANALYZER_SYSTEM_PROMPT

    for result in attack_results:
        node_id = result.get("node_id")
        vuln_type = result.get("vuln_type")
        status_code = result.get("status_code")
        response_body = result.get("response")
        expected_indicator = result.get("expected_indicator")
        role = result.get("role")
        
        logger.info(f">> Đang phân tích kết quả tấn công: {node_id} - Lỗi: {vuln_type}")
        
        # Bọc data gửi cho LLM
        evidence = {
            "API_Endpoint": node_id,
            "Attack_Type": vuln_type,
            "Attacker_Role": role,
            "Expected_Success_Indicator": expected_indicator,
            "Actual_HTTP_Status": status_code,
            "Actual_Response_Body": response_body
        }
        
        prompt_messages = [
            ("system", sys_prompt),
            ("human", f"Please evaluate this attack execution evidence:\n{json.dumps(evidence, ensure_ascii=False, indent=2)}")
        ]
        
        try:
            # Gọi LLM Service
            assessment = LLMService.generate_structured(
                self=LLMService(),
                prompt_messages=prompt_messages,
                input_variables={},
                pydantic_schema=VulnerabilityAssessment,
                fallback_method="function_calling"
            )
            
            # Tiền xử lý kết quả trả về
            if isinstance(assessment, list):
                assessment = assessment[0] if len(assessment) > 0 else None
            if isinstance(assessment, dict):
                assessment = VulnerabilityAssessment(**assessment)
                
            if assessment and isinstance(assessment, VulnerabilityAssessment):
                # Gộp thông tin raw và kết luận của LLM
                report_item = {
                    "node_id": node_id,
                    "vuln_type": vuln_type,
                    "role": role,
                    "evidence": {
                        "status_code": status_code,
                        "response": response_body
                    },
                    "assessment": assessment.model_dump()
                }
                final_reports.append(report_item)
                
                # In ra log để dễ theo dõi
                status_text = "VULNERABLE (CÓ LỖI)" if assessment.is_vulnerable else "SAFE (AN TOÀN)"
                logger.info(f"   => Kết luận: {status_text} | Conf: {assessment.confidence_score}%")
                logger.info(f"   => Lý do: {assessment.reasoning}")
                
        except Exception as e:
            logger.error(f"   => Lỗi khi gọi LLM phân tích: {e}")

    # Ghi báo cáo ra file
    output_dir = "outputs"
    os.makedirs(output_dir, exist_ok=True)
    file_path = os.path.join(output_dir, "final_security_report.json")
    
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(final_reports, f, ensure_ascii=False, indent=2)
        
    logger.info(f"Hoàn tất đánh giá. Báo cáo lưu tại: {file_path}")

    avg_confidence = sum(r["assessment"]["confidence_score"] for r in final_reports) / len(final_reports) / 100.0 if final_reports else 0.0
    return {
        **state,
        "final_report": final_reports,
        "iteration_count": state.get("iteration_count", 0) + 1,   # ← THÊM
        "confidence_score": avg_confidence,                         # ← THÊM
    }   