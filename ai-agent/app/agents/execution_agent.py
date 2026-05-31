from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import json
import threading
import httpx
import logging
import time
from datetime import datetime
from typing import Any

# Import các class bạn đã viết
from app.core.credential_store import CredentialStore
from app.core.auth_manager import AuthManager

logger = logging.getLogger(__name__)

LOG_FILE_PATH = "outputs/execution_requests.jsonl"

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
class VariableStore:
    def __init__(self, config: dict):
        self.config = config
        self.base_url = config.get("target", {}).get("base_url", "").rstrip("/")
        self.store = { user["role"]: {} for user in config.get("users", []) }
        if "attacker" not in self.store: self.store["attacker"] = {}
        if "victim" not in self.store: self.store["victim"] = {}
        
    def set(self, role: str, semantic_key: str, value: Any):
        if role in self.store:
            self.store[role][semantic_key] = value

    def get(self, semantic_key: str) -> str:
        role = "attacker"
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

    try:
        import os
        os.makedirs("outputs", exist_ok=True)
    except Exception:
        pass

    cred_store = CredentialStore()
    cred_store.load(config)
    auth_manager = AuthManager(cred_store)
    var_store = VariableStore(config)
    
    logger.info(">>Đồng bộ Token vào Context...")
    for role in cred_store.all_roles():
        try:
            token = auth_manager.get_token(role)
            var_store.set(role, "login.token", token)
            cred = cred_store.get(role)
            if cred:
                var_store.set(role, "login.email", cred.email)
                var_store.set(role, "login.password", cred.password)
            user_id = auth_manager.get_user_id(role)
            if user_id:
                var_store.set(role, "user.id", user_id)
            logger.info(f"   [+] '{role}': Đã nạp token thành công.")
        except Exception as e:
            logger.error(f"   [-] '{role}': Lỗi Auth - {e}")
            
    execution_results = []

    setup_plans  = [p for p in test_plans if not p.get("is_attack", False)]
    attack_plans = [p for p in test_plans if     p.get("is_attack", False)]
    ordered_plans = setup_plans + attack_plans
    logger.info(f">> Thứ tự: {len(setup_plans)} setup step chạy trước, {len(attack_plans)} attack step chạy sau")

    with httpx.Client(verify=False, timeout=15.0) as client:
        for plan in ordered_plans:
            node_id   = plan.get("node_id")
            method    = plan.get("method", "GET").upper()
            is_attack = plan.get("is_attack", False)
            steps     = plan.get("test_steps", [])

            logger.info(f"\n>> Thực thi {node_id} (Attack: {is_attack})")
            
            roles_to_run = ["attacker", "victim"] if not is_attack else ["attacker"]
            
            for role in roles_to_run:
                if role not in cred_store.all_roles():
                    continue

                for step in steps:
                    path_params  = var_store.resolve_payload(step.get("path_params")  or {}) or {}
                    query_params = var_store.resolve_payload(step.get("query_params") or {}) or {}
                    headers      = var_store.resolve_payload(step.get("headers")      or {}) or {}
                    body         = var_store.resolve_payload(step.get("body"))
                    
                    auth_val = headers.get("Authorization", "")
                    _auth_invalid = (
                        "Authorization" not in headers
                        or not auth_val
                        or "<" in auth_val
                        or auth_val.strip() in ("Bearer", "Bearer ")
                    )
                    if _auth_invalid:
                        try:
                            auth_headers = auth_manager.get_headers(role)
                            headers.update(auth_headers)
                        except Exception:
                            pass 

                    token = var_store.store.get(role, {}).get("login.token")
                    if token:
                        headers["Authorization"] = f"Bearer {token}"
                            
                    url_path = plan.get("endpoint", "")
                    for k, v in path_params.items():
                        url_path = url_path.replace(f"{{{k}}}", str(v))
                        
                    full_url = var_store.base_url + url_path
                    
                    def redact_payload(value: Any) -> Any:
                        if isinstance(value, dict):
                            redacted = {}
                            for k, v in value.items():
                                key_lower = str(k).lower()
                                if any(t in key_lower for t in ("password", "token", "secret", "refresh")):
                                    redacted[k] = "***"
                                else:
                                    redacted[k] = redact_payload(v)
                            return redacted
                        if isinstance(value, list):
                            return [redact_payload(i) for i in value]
                        return value

                    def redact_headers(hdrs: dict) -> dict:
                        if not isinstance(hdrs, dict): return {}
                        safe = dict(hdrs)
                        if "Authorization" in safe: safe["Authorization"] = "Bearer ***"
                        return redact_payload(safe)

                    def write_request_log(payload: dict) -> None:
                        try:
                            with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
                                f.write(json.dumps(payload, ensure_ascii=True) + "\n")
                        except Exception:
                            pass

                    # -------------------------------------------------------------
                    # KIỂM TRA ĐIỀU KIỆN LOAD TEST (Rate-Limit / API4)
                    # -------------------------------------------------------------
                    repeat = step.get("repeat", 1)
                    rate_per_minute = step.get("rate_per_minute", 0)
                    concurrency = step.get("concurrency", 1)
                    is_load_test = repeat > 1 or rate_per_minute > 0 or concurrency > 1

                    if is_load_test:
                        logger.info(f"[{role}] Bắt đầu Load Test {method} {full_url} | N={repeat} RPM={rate_per_minute} Concurrency={concurrency}")
                        
                        status_counts = Counter()
                        errors = []
                        sample_responses = [] # Lưu vài sample
                        lock = threading.Lock()
                        start_time = time.time()
                        
                        def _load_worker():
                            try:
                                resp = client.request(
                                    method=method,
                                    url=full_url,
                                    params=query_params,
                                    headers=headers,
                                    json=body if isinstance(body, dict) else None,
                                    data=body if isinstance(body, str) else None,
                                )
                                try:
                                    resp_json = resp.json()
                                except Exception:
                                    resp_json = {"raw_text": resp.text}
                                    
                                with lock:
                                    status_counts[str(resp.status_code)] += 1
                                    # Thu thập sample response đặc biệt (lỗi 4xx, 5xx, hoặc 200) để Analyzer có cái nhìn tổng quan
                                    if len(sample_responses) < 2 or resp.status_code >= 400 and len(sample_responses) < 5:
                                        sample_responses.append({
                                            "status": resp.status_code,
                                            "data": redact_payload(resp_json)
                                        })
                            except Exception as e:
                                with lock:
                                    status_counts["connection_error"] += 1
                                    if len(errors) < 5: errors.append(str(e))

                        # Thực thi bằng ThreadPoolExecutor với Throttle (Delay)
                        with ThreadPoolExecutor(max_workers=concurrency) as executor:
                            futures = []
                            expected_interval = 60.0 / rate_per_minute if rate_per_minute > 0 else 0
                            next_req_time = time.time()
                            
                            for i in range(repeat):
                                now = time.time()
                                if expected_interval > 0 and now < next_req_time:
                                    time.sleep(next_req_time - now)
                                next_req_time = time.time() + expected_interval
                                futures.append(executor.submit(_load_worker))
                                
                            # Chờ hoàn thành batch
                            for future in as_completed(futures):
                                pass

                        duration = time.time() - start_time
                        actual_rpm = (repeat / duration) * 60 if duration > 0 else 0
                        logger.info(f"[{role}] Load Test xong. Time: {duration:.2f}s | Actual RPM: {actual_rpm:.2f} | Statuses: {dict(status_counts)}")
                        
                        # Chỉ log file bản tóm tắt để tránh quá tải I/O
                        write_request_log({
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                            "node_id": node_id,
                            "role": role,
                            "is_attack": is_attack,
                            "is_load_test": True,
                            "url": full_url,
                            "summary": dict(status_counts),
                            "actual_rpm": round(actual_rpm, 2)
                        })

                        execution_results.append({
                            "node_id": node_id,
                            "role": role,
                            "is_attack": is_attack,
                            "is_load_test": True,
                            "vuln_type": plan.get("vuln_type"),
                            "summary": {
                                "total_requests": repeat,
                                "duration_seconds": round(duration, 2),
                                "actual_rpm": round(actual_rpm, 2),
                                "target_rpm": rate_per_minute,
                                "concurrency": concurrency,
                                "status_counts": dict(status_counts),
                                "errors": errors,
                                "sample_responses": sample_responses
                            },
                            "expected_indicator": step.get("expected_indicator")
                        })
                        
                    else:
                        # -------------------------------------------------------------
                        # EXECUTION REQUEST BÌNH THƯỜNG CỦA BẠN (Single request)
                        # -------------------------------------------------------------
                        logger.info(f"[{role}] {method} {full_url}")
                        try:
                            write_request_log({
                                "timestamp": datetime.utcnow().isoformat() + "Z",
                                "node_id": node_id,
                                "role": role,
                                "is_attack": is_attack,
                                "method": method,
                                "url": full_url,
                                "path_params": redact_payload(path_params),
                                "query_params": redact_payload(query_params),
                                "headers": redact_headers(headers),
                                "body": redact_payload(body),
                            })

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

                            write_request_log({
                                "timestamp": datetime.utcnow().isoformat() + "Z",
                                "node_id": node_id,
                                "role": role,
                                "is_attack": is_attack,
                                "status_code": response.status_code,
                                "response": redact_payload(response_json),
                            })
                            
                            if not is_attack and response.status_code in (200, 201):
                                endpoint_path = plan.get("endpoint", "").strip("/")
                                path_segs = [s for s in endpoint_path.split("/") if s and not s.startswith("{")]
                                resource_name = path_segs[-1].lower() if path_segs else "item"

                                def find_id_fields(data, found=None):
                                    if found is None: found = {}
                                    if isinstance(data, dict):
                                        for k, v in data.items():
                                            if k.lower() == "id" or k.lower().endswith("id"):
                                                if v is not None:
                                                    found[k] = v
                                            elif isinstance(v, (dict, list)):
                                                find_id_fields(v, found)
                                    elif isinstance(data, list) and data:
                                        find_id_fields(data[0], found)
                                    return found

                                id_fields = find_id_fields(response_json)

                                for key, val in id_fields.items():
                                    k_lower = key.lower()
                                    if k_lower == "id":
                                        sem_key = f"{resource_name}.id"
                                    else:
                                        sem_key = f"{k_lower[:-2]}.id"

                                    var_store.set(role, sem_key, val)
                                    logger.info(f"   => [Lưu] {sem_key} = {val} cho '{role}'")

                                    if role == "attacker" and "victim" not in cred_store.all_roles():
                                        var_store.set("victim", sem_key, val)
                                        logger.info(f"   => [Fallback victim] {sem_key} = {val}")

                            execution_results.append({
                                "node_id": node_id,
                                "role": role,
                                "is_attack": is_attack,
                                "is_load_test": False,
                                "vuln_type": plan.get("vuln_type"),
                                "status_code": response.status_code,
                                "response": response_json,
                                "expected_indicator": step.get("expected_indicator")
                            })
                            
                        except Exception as e:
                            write_request_log({
                                "timestamp": datetime.utcnow().isoformat() + "Z",
                                "node_id": node_id,
                                "role": role,
                                "is_attack": is_attack,
                                "error": str(e),
                            })
                            logger.error(f"   => Lỗi kết nối HTTP: {e}")
                        
    return {
        **state,
        "execution_results": execution_results
    }