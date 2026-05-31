import json
import os
import logging
from typing import List, Dict, Any
from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI

from app.agents.planning_agent import load_owasp_kb
from app.core.constants import ANALYZER_SYSTEM_PROMPT
from app.services.llm_service import LLMService
from app.services.llm_scheduler import LLMTaskScheduler
from app.core.config import settings, get_groq_keys

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════
# SCHEMA ĐẦU RA CHO LLM (JSON Format)
# ══════════════════════════════════════════════════════════════════════

class VulnerabilityAssessment(BaseModel):
    is_vulnerable: bool = Field(..., description="True nếu cuộc tấn công thành công (hệ thống có lỗi). False nếu hệ thống an toàn chặn được.")
    confidence_score: int = Field(..., description="Độ tự tự tin của kết luận từ 1 đến 100")
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
        return {
            **state,
            "final_report": [],
            "iteration_count": state.get("iteration_count", 0) + 1,
            "confidence_score": 1.0,
        }

    final_reports = []

    # System Prompt huấn luyện LLM trở thành một chuyên gia bảo mật
    sys_prompt = ANALYZER_SYSTEM_PROMPT

    api_keys = get_groq_keys(settings.LLM_PARALLEL_KEYS)
    scheduler = LLMTaskScheduler(
        api_keys=api_keys,
        concurrency_per_key=settings.LLM_CONCURRENCY_PER_KEY,
        logger=logger,
    )

    tasks = []
    meta = []
    for result in attack_results:
        node_id = result.get("node_id")
        vuln_type = result.get("vuln_type")
        expected_indicator = result.get("expected_indicator")
        role = result.get("role")
        
        is_load_test = result.get("is_load_test", False)
        status_code = result.get("status_code")
        response_body = result.get("response")
        summary = result.get("summary")

        logger.info(f">> Đang phân tích kết quả tấn công: {node_id} - Lỗi: {vuln_type}")
        kb_context = load_owasp_kb(vuln_type)
        if is_load_test:
            # Truyền summary cho LLM thay vì single request
            evidence = {
                "API_Endpoint": node_id,
                "Attack_Type": vuln_type,
                "Attacker_Role": role,
                "Expected_Success_Indicator": expected_indicator,
                "Test_Type": "Load Test / Rate-Limit Test",
                "Load_Test_Summary": summary
            }
        else:
            evidence = {
                "API_Endpoint": node_id,
                "Attack_Type": vuln_type,
                "Attacker_Role": role,
                "Expected_Success_Indicator": expected_indicator,
                "Test_Type": "Single Request",
                "Actual_HTTP_Status": status_code,
                "Actual_Response_Body": response_body,
            }
        # --- KẾT THÚC SỬA ---

        prompt_messages = [
    ("system", sys_prompt),
    (
        "human",
        f"""
            You are provided with OWASP security knowledge base
            for this vulnerability.

            === OWASP Knowledge Base ===
            {kb_context}

            === Attack Execution Evidence ===
            {json.dumps(evidence, ensure_ascii=False, indent=2)}

            Please evaluate:
            1. Is the API vulnerable?
            2. Why?
            3. Does the evidence satisfy OWASP criteria?
            """
                ),
    ]

        def _make_task(messages):
            def _task(api_key: str, key_index: int):
                service = LLMService(
                    api_key=api_key,
                    model=settings.GPT_OOS_20B,
                    base_url=settings.URL_LLM,
                )
                return service.generate_structured(
                    prompt_messages=messages,
                    input_variables={},
                    pydantic_schema=VulnerabilityAssessment,
                    fallback_method="function_calling",
                )
            return _task

        tasks.append(_make_task(prompt_messages))
        
        meta.append(
            {
                "node_id": node_id,
                "vuln_type": vuln_type,
                "role": role,
                "is_load_test": is_load_test,
                "status_code": status_code,
                "response_body": response_body,
                "summary": summary
            }
        )

    results, errors = scheduler.map(tasks, fail_soft=True)

    for idx, assessment in enumerate(results):
        info = meta[idx]
        if errors[idx] is not None or assessment is None:
            logger.error(
                "   => Lỗi khi gọi LLM phân tích: node_id=%s, vuln=%s",
                info["node_id"],
                info["vuln_type"],
            )
            continue

        if isinstance(assessment, list):
            assessment = assessment[0] if len(assessment) > 0 else None
        if isinstance(assessment, dict):
            assessment = VulnerabilityAssessment(**assessment)

        if assessment and isinstance(assessment, VulnerabilityAssessment):
            # --- BẮT ĐẦU SỬA: Định dạng lại output report dựa vào loại test ---
            report_item = {
                "node_id": info["node_id"],
                "vuln_type": info["vuln_type"],
                "role": info["role"],
                "assessment": assessment.model_dump(),
            }
            
            if info["is_load_test"]:
                report_item["evidence"] = {"load_test_summary": info["summary"]}
            else:
                report_item["evidence"] = {
                    "status_code": info["status_code"],
                    "response": info["response_body"],
                }
            
            final_reports.append(report_item)
            # --- KẾT THÚC SỬA ---

            status_text = (
                "VULNERABLE (CÓ LỖI)" if assessment.is_vulnerable else "SAFE (AN TOÀN)"
            )
            logger.info(
                "   => Kết luận: %s | Conf: %s%%",
                status_text,
                assessment.confidence_score,
            )
            logger.info("   => Lý do: %s", assessment.reasoning)

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
        "iteration_count": state.get("iteration_count", 0) + 1,
        "confidence_score": avg_confidence,
    }