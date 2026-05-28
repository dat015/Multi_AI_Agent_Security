import re
import httpx
import logging
from typing import Any

# Import các class bạn đã viết
from app.core.credential_store import CredentialStore
from app.core.auth_manager import AuthManager

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════
# VARIABLE STORE - Quản lý Context và Nội suy dữ liệu
# ══════════════════════════════════════════════════════════════════════

class VariableStore:
    def __init__(self, config: dict):
        self.config = config
        self.base_url = config.get("target", {}).get("base_url", "").rstrip("/")
        # Tự động tạo namespace cho tất cả các role định nghĩa trong config
        self.store = { user["role"]: {} for user in config.get("users", []) }
        # Đảm bảo luôn có 2 role cơ bản nếu config thiếu
        if "attacker" not in self.store: self.store["attacker"] = {}
        if "victim" not in self.store: self.store["victim"] = {}
        
    def set(self, role: str, semantic_key: str, value: Any):
        if role in self.store:
            self.store[role][semantic_key] = value

    def get(self, semantic_key: str) -> str:
        """
        Lấy biến dựa trên hậu tố. 
        VD: wallet.id_A -> tìm wallet.id trong attacker
            wallet.id_B -> tìm wallet.id trong victim
        """
        role = "attacker" # Default
        clean_key = semantic_key

        if semantic_key.endswith("_A"):
            role = "attacker"
            clean_key = semantic_key[:-2]
        elif semantic_key.endswith("_B"):
            role = "victim"
            clean_key = semantic_key[:-2]
        elif semantic_key.endswith("_Admin"):
            role = "admin"
            clean_key = semantic_key[:-6]

        return str(self.store.get(role, {}).get(clean_key, f"<{semantic_key}_NOT_FOUND>"))

    def resolve_string(self, text: str) -> str:
        if not isinstance(text, str):
            return text
        pattern = r"\{\{(.*?)\}\}"
        return re.sub(pattern, lambda m: self.get(m.group(1)), text)

    def resolve_payload(self, data: Any) -> Any:
        if isinstance(data, dict):
            return {k: self.resolve_payload(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.resolve_payload(i) for i in data]
        elif isinstance(data, str):
            return self.resolve_string(data)
        return data


def extract_value_from_response(response_data: Any, target_key: str) -> Any:
    """Tìm đệ quy một key trong JSON Response (Hỗ trợ parse ID sau khi tạo mới)."""
    if isinstance(response_data, dict):
        if target_key in response_data:
            return response_data[target_key]
        for v in response_data.values():
            res = extract_value_from_response(v, target_key)
            if res is not None:
                return res
    elif isinstance(response_data, list):
        for item in response_data:
            res = extract_value_from_response(item, target_key)
            if res is not None:
                return res
    return None

# ══════════════════════════════════════════════════════════════════════
# MAIN EXECUTOR NODE
# ══════════════════════════════════════════════════════════════════════

def execution_node(state: dict) -> dict:
    test_plans = state.get("test_plan", [])
    config = state.get("config", {}) 
    
    logger.info("\n--- CHẠY EXECUTOR NODE ---")

    # 1. Khởi tạo Auth System
    cred_store = CredentialStore()
    cred_store.load(config)
    auth_manager = AuthManager(cred_store)
    
    # 2. Khởi tạo Variable Store
    var_store = VariableStore(config)
    
    # 3. Bootstrap Authentication
    # Ép AuthManager lấy token cho tất cả các user và nạp vào VariableStore
    logger.info(">> Đồng bộ Token vào Context...")
    for role in cred_store.all_roles():
        try:
            token = auth_manager.get_token(role)
            var_store.set(role, "login.token", token)
            
            # Lấy luôn user_id nếu có
            user_id = auth_manager.get_user_id(role)
            if user_id:
                var_store.set(role, "user.id", user_id)
                
            logger.info(f"   [+] '{role}': Đã nạp token thành công.")
        except Exception as e:
            logger.error(f"   [-] '{role}': Lỗi Auth - {e}")
            
    execution_results = []
    
    # Dùng httpx Client để reuse connection (nhanh hơn requests)
    with httpx.Client(verify=False, timeout=15.0) as client:
        
        # 4. Vòng lặp thực thi
        for plan in test_plans:
            node_id = plan.get("node_id")
            method = plan.get("method", "GET").upper()
            is_attack = plan.get("is_attack", False)
            steps = plan.get("test_steps", [])
            
            logger.info(f"\n>> Thực thi {node_id} (Attack: {is_attack})")
            
            # API Setup Data chạy cho cả 2 để lấy đủ ID (BOLA cross-check)
            roles_to_run = ["attacker", "victim"] if not is_attack else ["attacker"]
            
            for role in roles_to_run:
                # Bỏ qua nếu role không tồn tại trong config
                if role not in cred_store.all_roles():
                    continue

                for step in steps:
                    # Resolve toàn bộ payload qua VariableStore
                    path_params = var_store.resolve_payload(step.get("path_params", {}))
                    query_params = var_store.resolve_payload(step.get("query_params", {}))
                    headers = var_store.resolve_payload(step.get("headers", {}))
                    body = var_store.resolve_payload(step.get("body"))
                    
                    # Cứu cánh: Nếu step không định nghĩa header Authorization, lấy từ AuthManager
                    if "Authorization" not in headers:
                        try:
                            auth_headers = auth_manager.get_headers(role)
                            headers.update(auth_headers)
                        except Exception:
                            pass # Chấp nhận test API public
                            
                    # Lắp ráp URL
                    url_path = plan.get("endpoint", "")
                    for k, v in path_params.items():
                        url_path = url_path.replace(f"{{{k}}}", str(v))
                        
                    full_url = var_store.base_url + url_path
                    
                    # Gửi Request
                    logger.info(f"[{role}] {method} {full_url}")
                    try:
                        response = client.request(
                            method=method,
                            url=full_url,
                            params=query_params,
                            headers=headers,
                            json=body if isinstance(body, dict) else None,
                            data=body if isinstance(body, str) else None,
                        )
                        
                        try:
                            response_json = response.json()
                        except Exception:
                            response_json = {"raw_text": response.text}
                        
                        # Trích xuất biến nếu là API mồi
                        if not is_attack and response.status_code in (200, 201):
                            possible_keys = ["id", "walletId", "transactionId", "userId", "cardId"]
                            for key in possible_keys:
                                extracted_val = extract_value_from_response(response_json, key)
                                if extracted_val:
                                    semantic_namespace = key.replace("Id", "").lower()
                                    if semantic_namespace == "id": semantic_namespace = "item"
                                    
                                    var_store.set(role, f"{semantic_namespace}.id", extracted_val)
                                    logger.info(f"   => [Lưu] {semantic_namespace}.id = {extracted_val} cho {role}")
                        
                        execution_results.append({
                            "node_id": node_id,
                            "role": role,
                            "is_attack": is_attack,
                            "vuln_type": plan.get("vuln_type"),
                            "status_code": response.status_code,
                            "response": response_json,
                            "expected_indicator": step.get("expected_indicator")
                        })
                        
                    except Exception as e:
                        logger.error(f"   => Lỗi kết nối HTTP: {e}")
                        
    return {
        **state,
        "execution_results": execution_results
    }