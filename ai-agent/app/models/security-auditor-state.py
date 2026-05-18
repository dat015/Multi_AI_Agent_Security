from typing import TypedDict, List, Dict, Any

class SecurityAuditorState(TypedDict):
    api_spec_path: str            # Đường dẫn đến file Swagger/OpenAPI đầu vào
    compile_output_dir: str       # Thư mục chứa kết quả của RESTler
    dependency_graph: Dict[str, Any] # Đồ thị phụ thuộc dạng JSON để LLM đọc
    recon_data: Dict[str, Any]    # Dữ liệu phase Recon sau này
    errors: List[str]             # Lưu các lỗi trong quá trình chạy pipeline