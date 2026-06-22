import json
import logging
from typing import Dict, Any, List
from pydantic import BaseModel, Field
from app.core.state import SystemState
from app.services.llm_service import LLMService
from langchain_core.messages import SystemMessage, HumanMessage

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a Senior Security Architect.
Your task is to review the results of an automated API security scan and generate an executive summary report.
You must return a structured JSON conforming to the requested schema.
Rules:
1. 'executive_summary': A clear, professional summary of what was tested, how many endpoints were found, and an overview of the vulnerabilities discovered. Keep it under 200 words. Write in Vietnamese.
2. 'overall_risk_level': Assign a single severity (Critical, High, Medium, Low, Safe) based on the highest severity vulnerability found. If no vulnerabilities, output Safe.
3. 'recommendations': A list of actionable remediation steps based on the vulnerabilities found. Write in Vietnamese."""

class ReportSummaryOutput(BaseModel):
    executive_summary: str = Field(description="Đoạn văn tóm tắt quá trình quét và kết quả tổng thể.")
    overall_risk_level: str = Field(description="Mức độ rủi ro tổng thể: Critical, High, Medium, Low, hoặc Safe")
    recommendations: List[str] = Field(description="Danh sách các khuyến nghị khắc phục")

def reporting_node(state: SystemState) -> Dict[str, Any]:
    print(">>> RUNNING REPORTING NODE")
    
    recon_summary = state.get("recon_summary", "")
    endpoints_found = len(state.get("filtered_endpoints", []))
    final_reports = state.get("final_report", [])
    
    # Chuẩn bị context
    context = {
        "recon_summary": recon_summary,
        "endpoints_found": endpoints_found,
        "vulnerability_findings": []
    }
    
    for r in final_reports:
        # Lấy một số field quan trọng để tránh quá tải token
        assessment = r.get("assessment", {})
        if assessment.get("is_vulnerable"):
            context["vulnerability_findings"].append({
                "endpoint": r.get("node_id"),
                "vuln_type": r.get("vuln_type"),
                "severity": assessment.get("severity"),
                "reasoning": assessment.get("reasoning")
            })
            
    user_prompt = f"Here is the data from the recent API security scan:\n{json.dumps(context, ensure_ascii=False)}"
    
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=user_prompt)
    ]
    
    service = LLMService()
    try:
        result = service.generate_structured(
            prompt_messages=messages,
            input_variables={},
            pydantic_schema=ReportSummaryOutput
        )
        
        # Parse result
        if hasattr(result, "model_dump"):
            report_summary = result.model_dump()
        elif hasattr(result, "dict"):
            report_summary = result.dict()
        else:
            report_summary = dict(result)
            
        logger.info(f"Report generated with risk level: {report_summary.get('overall_risk_level')}")
        
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        report_summary = {
            "executive_summary": f"Đã quét xong {endpoints_found} endpoints nhưng gặp lỗi khi sinh báo cáo tổng hợp (do lỗi LLM hoặc Rate Limit).",
            "overall_risk_level": "Unknown",
            "recommendations": ["Kiểm tra lại log hệ thống để biết thêm chi tiết."]
        }
        
    return {**state, "report_summary": report_summary}
