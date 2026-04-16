import re

class StaticFilter:
    # Quét pattern ID: {id}, :id, <id>
    ID_PATTERN = re.compile(r"\{[a-zA-Z0-9_-]+\}|:[a-zA-Z0-9_-]+")
    
    @staticmethod
    def is_candidate(endpoint):
        path = endpoint.path.lower()
        method = endpoint.method.upper()
        
        # 1. Mặc định giữ lại các phương thức thay đổi dữ liệu
        if method in ["POST", "PUT", "PATCH", "DELETE"]:
            return True
        
        # 2. Giữ lại các GET có chứa tham số ID trong Path
        if method == "GET" and StaticFilter.ID_PATTERN.search(path):
            return True
            
        # 3. Lọc theo các trường nhạy cảm trong Schema (Stage 1: Deep Traversal)
        # Nếu body có trường UUID hoặc Required Integer -> Giữ lại
        return False