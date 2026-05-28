from typing import TypedDict, List, Optional, Dict, Any

class SystemState(TypedDict):
    # Input
    raw_spec: str                    # Nội dung file OpenAPI gốc
    spec_format: str                 # "json" hoặc "yaml"
    config: Dict[str, Any]           # Config người dùng: target URL + credentials

    # Recon Agent output
    filtered_endpoints: List[Dict]   # Danh sách endpoint sau lọc
    recon_summary: str               # Giải thích sơ bộ từ LLM
    dependency_graph: Dict[str, Any]
    markdown_chunks: List[Dict]

    # Planning Agent output
    test_plan: List[Dict]            # Kế hoạch test JSON

    # Execution Agent output
    execution_results: List[Dict]    # Kết quả HTTP thực tế từng request

    # Analyzer (dùng sau)
    current_endpoint: Optional[Dict]
    raw_traffic: List[Dict]          # Log request/response
    vuln_findings: List[Dict]        # Kết quả lỗ hổng
    iteration_count: int
    confidence_score: float
    max_iterations: int

    # Reporting
    final_report: Optional[str]

    # Control
    error: Optional[str]