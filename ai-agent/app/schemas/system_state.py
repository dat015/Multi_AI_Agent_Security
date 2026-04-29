from typing import TypedDict
class SystemState(TypedDict):
    session_id: str
    openapi_spec: dict            # Spec gốc đã được parse
    filtered_endpoints: list      # Danh sách endpoint sau khi Recon Agent lọc
    current_endpoint: dict        # Endpoint đang được test trong vòng lặp
    test_plan: list               # Danh sách các test steps từ Planning Agent
    raw_traffic: list             # Lịch sử request/response
    iteration_count: int          # Đếm số vòng lặp (max = 5)
    confidence_score: float       # Điểm tự tin của Analyzer
    vuln_findings: list           # Danh sách các lỗ hổng đã được xác nhận (TP)