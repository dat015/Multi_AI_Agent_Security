import os
import re

from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import json
import logging
from app.services.llm_service import LLMService
from app.services.llm_scheduler import LLMTaskScheduler
from app.core.config import settings, get_groq_keys
from app.core.constants import AGENT_SYSTEM_PROMPT, LARGE_PAYLOAD_SIZE_BYTES, LARGE_INT_VALUE, LARGE_INT_THRESHOLD
from app.core.restler_parser import (
    build_setup_body,
    build_setup_path_params,
    build_setup_query_params,
)
from typing import Union

# ══════════════════════════════════════════════════════════════════════
# CHUẨN PLACEHOLDER — dùng chung toàn hệ thống
# ══════════════════════════════════════════════════════════════════════
#
# Token:       {{login.token_A}}   (attacker)    {{login.token_B}}   (victim)
# Resource ID: {{wallets.id_A}}    (attacker)    {{wallets.id_B}}    (victim)
#              {{transactions.id_A}}             {{users.id_A}}
#
# Quy tắc suffix:
#   _A  → namespace "attacker"  trong VariableStore
#   _B  → namespace "victim"    trong VariableStore
#
# Execution agent lưu:
#   var_store.set(role, "login.token", token)           → {{login.token_A/B}}
#   var_store.set(role, "{resource_name}.id", val)      → {{wallets.id_A/B}}
#   var_store.set(role, "{base}.id", val)               → {{transaction.id_A/B}}  (từ transactionId)
# ══════════════════════════════════════════════════════════════════════


# ── Pydantic models ──────────────────────────────────────────────────

class TestStep(BaseModel):
    step: int
    description: str
    path_params: Optional[Dict[str, Union[str, int]]] = Field(
        default_factory=dict,
        description="Các biến trên URL path, có thể là string hoặc số"
    )
    query_params: Optional[Dict[str, Union[str, int]]] = Field(
        default_factory=dict,
        description="Các tham số sau dấu ?, có thể là string hoặc số"
    )
    headers: Optional[Dict[str, str]] = Field(
        default_factory=dict,
        description="HTTP Headers, bắt buộc chứa Authorization token nếu cần"
    )
    body: Optional[Union[Dict[str, Any], str]] = Field(
        default=None,
        description="HTTP Request Body (JSON hoặc Text)"
    )
    expected_indicator: str
    repeat: int = Field(
        default=1,
        description=(
            "Tổng số request sẽ được gửi. Mỗi request được xử lý bởi ThreadPool có kích thước 'concurrency'. "
            "Ví dụ: repeat=100, concurrency=10 → 100 request tổng, tối đa 10 request chạy song song cùng lúc. "
            "CHỈ đặt > 1 cho API4 (Unrestricted Resource Consumption) hoặc Rate Limit test. "
            "Giữ ở mức hợp lý (50–200) để tránh gây quá tải thực sự lên môi trường test."
        )
    )
    rate_per_minute: int = Field(
        default=0,
        description=(
            "Tốc độ tối đa tính bằng request/phút. Chỉ có tác dụng khi concurrency=1 (throttle tuần tự). "
            "Khi concurrency > 1 thì rate_per_minute bị bỏ qua vì requests được dispatch song song. "
            "Mặc định là 0 (không kiểm soát tốc độ). "
            "CHỈ thiết lập khi cần kiểm tra khả năng chặn Rate Limit của server."
        )
    )
    concurrency: int = Field(
        default=1,
        description=(
            "Số worker thread song song tối đa trong ThreadPool. KHÔNG phải số request/giây. "
            "Ví dụ: concurrency=10 → tối đa 10 request chạy đồng thời, không phải 10 request/giây. "
            "CHỈ đặt > 1 để test burst/race condition. "
            "Giữ ở mức hợp lý (10–100) để tránh tạo DoS thực sự lên môi trường test."
        )
    )


class TestPlan(BaseModel):
    node_id: Optional[str] = Field(default=None, description="Định danh của API, VD: POST:/users")
    endpoint: Optional[str] = Field(default=None)
    method: Optional[str] = Field(default=None)
    is_attack: Optional[bool] = Field(
        default=False,
        description="True nếu là test bảo mật, False nếu chỉ là API mồi tạo data"
    )
    vuln_type: Optional[str] = Field(default="None")
    run_as_role: Optional[str] = Field(default=None, description="Role cụ thể để chạy plan này (VD: attacker, victim)")
    test_steps: List[TestStep]
    max_iterations: int = Field(default=5)


llm = ChatOpenAI(
    api_key=settings.GROQ_API_KEY,
    base_url=settings.URL_LLM,
    model=settings.LARGE_MODEL_NAME,
    temperature=0.1
)

structured_llm = llm.with_structured_output(TestPlan)

logger = logging.getLogger(__name__)


@staticmethod
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


# ══════════════════════════════════════════════════════════════════════
# PLACEHOLDER HELPERS
# ══════════════════════════════════════════════════════════════════════

def simplify_consume_mapping(consumes_mapping: dict) -> str:
    """
    Chuyen consumes_mapping thanh chuoi mo ta de hieu cho LLM.
    Moi param liet ke placeholder dung chuan cung vi du cu the.
    Su dung ASCII thuan tuy de tranh Unicode encoding error.
    """
    if not consumes_mapping:
        return "No dynamic parameters."

    lines = ["DYNAMIC PARAMETERS (MUST use exactly these placeholders):"]
    for param, info in consumes_mapping.items():
        if not isinstance(info, dict):
            continue
        loc          = info.get("location", "unknown")
        placeholders = info.get("allowed_placeholders", [])
        if len(placeholders) >= 2:
            lines.append(
                f'  - "{param}" (in {loc}):'
                f'\n      User A (attacker) -> use: {placeholders[0]}'
                f'\n      User B (victim)   -> use: {placeholders[1]}'
                f'\n      Example JSON: "{param}": "{placeholders[0]}"'
            )
    return "\n".join(lines)


def _build_available_keys_hint(
    node_id: str,
    execution_order: list,
    graph_nodes: dict,
) -> str:
    """
    Tính danh sách semantic_key nào đã có sẵn trong VariableStore
    tại thời điểm node_id này chạy, dựa trên các node chạy trước nó.

    Returns: chuỗi mô tả các key có thể dùng trong placeholder.
    """
    try:
        idx = execution_order.index(node_id)
    except ValueError:
        idx = len(execution_order)

    prior_nodes = execution_order[:idx]
    keys: list[str] = ["login.token"]  # luôn có sẵn từ auth

    for prior_id in prior_nodes:
        prior_node = graph_nodes.get(prior_id, {})
        for p in prior_node.get("produces", []):
            if isinstance(p, dict):
                sk = p.get("semantic_key", "")
            else:
                sk = str(p)
            if sk and sk not in keys:
                keys.append(sk)

    if not keys:
        return "No prior keys available yet."

    lines = ["AVAILABLE KEYS IN VARIABLE STORE at this step (use {{KEY_A}} or {{KEY_B}}):"]
    for k in keys:
        lines.append(f"  - {{{{  {k}_A  }}}}  (attacker)   /   {{{{  {k}_B  }}}}  (victim)")
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════
# CONSTANTS DÙNG BỞi _sanitize_plan
# ══════════════════════════════════════════════════════════════════════

# HTTP method cần body — dùng để auto-inject Content-Type trong _sanitize_plan
# Là nguồn duy nhất — không hardcode string method set ở nơi khác
_METHODS_WITH_BODY: frozenset[str] = frozenset({"POST", "PUT", "PATCH"})

# Tên param pagination phổ biến — dùng để phát hiện large int hardcode
# và thay bằng {{$large_int}} trong _sanitize_plan
_PAGINATION_PARAMS: frozenset[str] = frozenset({
    "limit", "pagesize", "size", "top", "take", "count", "maxresults", "maxitems",
})

_ID_PARAM_RE = re.compile(r"(.+)[Ii]d$")


def _sanitize_plan(plan: TestPlan, consumes_mapping: dict) -> TestPlan:
    """
    Post-process kết quả LLM để đảm bảo placeholder đúng chuẩn:
    1. Fix single-brace {xxx} → double-brace {{xxx}}
    2. Chuẩn hóa auth.token_X → login.token_X
    3. Đảm bảo path_params dùng placeholder từ consumes_mapping
    4. Normalize None → {} cho path_params và query_params
    5. Thay [LARGE_PAYLOAD] bằng chuỗi kích thước từ LARGE_PAYLOAD_SIZE_BYTES constant
    6. Fix hardcode integer ID trong query_params (heuristic: param tên *Id) → placeholder
    """

    # Giá trị thay thế [LARGE_PAYLOAD] — kích thước đọc từ constant, không hardcode
    _large_payload_value = "A" * LARGE_PAYLOAD_SIZE_BYTES

    def fix_string(s: str) -> str:
        if not isinstance(s, str):
            return s
        # Thay [LARGE_PAYLOAD] trước khi xử lý brace — tránh confuse với {{...}}
        s = s.replace("[LARGE_PAYLOAD]", _large_payload_value)

        # Fix single-brace: {xxx} → {{xxx}} nhưng không ảnh hưởng {{xxx}} đã đúng
        # Chiến lược: tạm thay {{xxx}} → sentinel, fix {xxx}, restore
        sentinel_map: dict[str, str] = {}
        counter = [0]

        def protect_double(m):
            key = f"__SENTINEL_{counter[0]}__"
            counter[0] += 1
            sentinel_map[key] = m.group(0)
            return key

        # Bảo vệ double-brace đã đúng
        s = re.sub(r"\{\{.*?\}\}", protect_double, s)
        # Fix single-brace còn lại
        s = re.sub(r"\{([^{}]+)\}", r"{{\1}}", s)
        # Restore sentinel
        for key, val in sentinel_map.items():
            s = s.replace(key, val)

        # Chuẩn hóa: auth.token → login.token
        s = re.sub(r"\{\{\s*auth\.token_(A|B|Admin)\s*\}\}", r"{{login.token_\1}}", s)

        return s

    def fix_payload(data: Any) -> Any:
        if isinstance(data, dict):
            return {k: fix_payload(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [fix_payload(i) for i in data]
        elif isinstance(data, str):
            return fix_string(data)
        return data

    def _infer_placeholder_for_id_param(param: str, consumes_mapping: dict) -> str | None:
        """
        Nếu LLM hardcode integer vào một query/body param có tên dạng *Id/*id,
        cố gắng suy ra placeholder đúng dựa vào tên resource.

        Ví dụ: customerId → tìm 'customer' trong consumes_mapping hoặc
               suy ra {{customer.id_B}} theo convention.

        Trả về placeholder string nếu suy ra được, None nếu không.
        """
        m = _ID_PARAM_RE.match(param)
        if not m:
            return None
        resource = m.group(1).lower()  # "customer", "supplier", "product"...

        # 1. Tìm trong consumes_mapping trước
        for cmap_param, info in consumes_mapping.items():
            if not isinstance(info, dict):
                continue
            sem_key = info.get("semantic_key", "")
            if sem_key.startswith(resource + "."):
                placeholders = info.get("allowed_placeholders", [])
                if placeholders:
                    return placeholders[1] if len(placeholders) > 1 else placeholders[0]

        # 2. Không tìm thấy trong consumes_mapping → dùng convention {{resource.id_B}}
        #    _B vì thường đây là ID của victim (attacker muốn truy cập resource của victim)
        return f"{{{{{resource}.id_B}}}}"

    for step in plan.test_steps:
        # ── Normalize None → {} cho path_params và query_params ──────────
        if step.path_params is None:
            step.path_params = {}
        if step.query_params is None:
            step.query_params = {}

        # Fix headers
        if step.headers:
            step.headers = {k: fix_string(v) for k, v in step.headers.items()}

        # ── Auto-inject Content-Type nếu step có body và method cần body ──────
        # Nguồn method list: _METHODS_WITH_BODY constant — không hardcode inline
        if (
            step.body is not None
            and (plan.method or "").upper() in _METHODS_WITH_BODY
            and "Content-Type" not in (step.headers or {})
        ):
            step.headers = step.headers or {}
            step.headers["Content-Type"] = "application/json"

        # Fix body
        if step.body is not None:
            step.body = fix_payload(step.body)

        # Fix path_params: nếu có consumes_mapping cho path, đảm bảo đúng placeholder
        if step.path_params:
            fixed_pp = {}
            for param, val in step.path_params.items():
                if param in consumes_mapping:
                    info = consumes_mapping[param]
                    sem_key = info.get("semantic_key", "")
                    placeholders = info.get("allowed_placeholders", [])
                    # Nếu LLM sinh hardcode int/string thay vì placeholder
                    if sem_key and placeholders and not (
                        isinstance(val, str) and "{{" in val
                    ):
                        # Fallback về placeholder _A (attacker)
                        fixed_pp[param] = placeholders[0]
                    else:
                        fixed_pp[param] = fix_string(val) if isinstance(val, str) else val
                else:
                    fixed_pp[param] = fix_string(val) if isinstance(val, str) else val
            step.path_params = fixed_pp

        # Fix query_params
        if step.query_params:
            fixed_qp = {}
            for param, val in step.query_params.items():
                # ── Phát hiện pagination param có large int hardcode ───────────
                # Nguồn: _PAGINATION_PARAMS + LARGE_INT_THRESHOLD constant
                if param.lower().replace("_", "").replace("-", "") in _PAGINATION_PARAMS:
                    int_val = val if isinstance(val, int) else (
                        int(val) if isinstance(val, str) and val.isdigit() else None
                    )
                    if int_val is not None and int_val > LARGE_INT_THRESHOLD:
                        fixed_qp[param] = "{{$large_int}}"
                        continue

                if param in consumes_mapping:
                    info = consumes_mapping[param]
                    sem_key = info.get("semantic_key", "")
                    placeholders = info.get("allowed_placeholders", [])
                    if sem_key and placeholders and not (
                        isinstance(val, str) and "{{" in val
                    ):
                        fixed_qp[param] = placeholders[0]
                    else:
                        fixed_qp[param] = fix_string(val) if isinstance(val, str) else val
                else:
                    # Heuristic: param tên *Id/*id có giá trị hardcode integer → suy ra placeholder
                    if isinstance(val, int) or (
                        isinstance(val, str) and val.isdigit() and "{{" not in val
                    ):
                        inferred = _infer_placeholder_for_id_param(param, consumes_mapping)
                        if inferred:
                            fixed_qp[param] = inferred
                            continue
                    fixed_qp[param] = fix_string(val) if isinstance(val, str) else val
            step.query_params = fixed_qp

    return plan


# ══════════════════════════════════════════════════════════════════════
# ENDPOINT CONTEXT BUILDER
# ══════════════════════════════════════════════════════════════════════

def _build_endpoint_context(node_id: str, node_info: dict) -> tuple[dict, dict, list, str, str]:
    path = node_info.get("path")
    method = node_info.get("method")

    raw_consumes = node_info.get("consumes", [])
    raw_produces = node_info.get("produces", [])

    consumes_mapping: dict = {}
    for c in raw_consumes:
        if "param" in c and "semantic_key" in c:
            # Format mới từ RestlerParser
            sem_key = c["semantic_key"]
            consumes_mapping[c["param"]] = {
                "semantic_key": sem_key,
                "variable_name": c.get("variable_name"),
                "location": c.get("location"),
                "producer_endpoint": c.get("producer_endpoint"),
                "producer_method": c.get("producer_method"),
                # Placeholder chuẩn dùng login.token cho auth, sem_key cho resource
                "allowed_placeholders": [
                    "{{" + sem_key + "_A}}",
                    "{{" + sem_key + "_B}}",
                ],
                "examples": {
                    "valid_A": "{{" + sem_key + "_A}}",
                    "valid_B": "{{" + sem_key + "_B}}",
                    "invalid":  "12345"
                }
            }
        elif "raw_name" in c and "tuple" in c and len(c["tuple"]) == 2:
            # Format cũ từ DependencyResolver (fallback)
            consumes_mapping[c["raw_name"]] = f"{c['tuple'][0]}.{c['tuple'][1]}"

    # ── produces_list: ["category.id", "order.id", ...] ─────────────
    produces_list: list = []
    for p in raw_produces:
        if isinstance(p, dict) and "semantic_key" in p:
            produces_list.append(p["semantic_key"])
        elif isinstance(p, (list, tuple)) and len(p) == 2:
            produces_list.append(f"{p[0]}.{p[1]}")

    endpoint_context = {
        "node_id": node_id,
        "path": path,
        "method": method,

        # Raw OpenAPI info
        "parameters":    node_info.get("parameters", []),
        "request_body":  node_info.get("request_body", {}),

        # Explicit schemas
        "path_schema":   node_info.get("path_schema", {}),
        "query_schema":  node_info.get("query_schema", {}),
        "body_schema":   node_info.get("body_schema", {}),

        # Dependency graph
        "consumes_mapping": consumes_mapping,
        "produces_list":    produces_list,
    }

    return endpoint_context, consumes_mapping, produces_list, path, method


# ══════════════════════════════════════════════════════════════════════
# SETUP PLAN (deterministic, no LLM)
# ══════════════════════════════════════════════════════════════════════
def _inject_role_suffix(data: Any, suffix: str) -> Any:
    """
    Đệ quy duyệt qua dict/list/string và tiêm suffix vào các placeholder.
    Ví dụ: {{category.id}} -> {{category.id_A}}
    Bỏ qua các biến hệ thống bắt đầu bằng $ (VD: {{$timestamp}}, {{$role}}, {{$large_int}})
    """
    if isinstance(data, dict):
        return {k: _inject_role_suffix(v, suffix) for k, v in data.items()}
    elif isinstance(data, list):
        return [_inject_role_suffix(i, suffix) for i in data]
    elif isinstance(data, str):
        def replace_match(m):
            inner = m.group(1).strip()
            
            # 1. Bỏ qua các system variables (được định nghĩa riêng bắt đầu bằng dấu $)
            if inner.startswith("$"):
                return m.group(0)
            
            # 2. Nếu đã có suffix đúng chuẩn của role hiện tại thì giữ nguyên
            if inner.endswith(f"_{suffix}"):
                return m.group(0)
                
            # 3. Làm sạch các suffix rác/cũ (nếu parser lỡ sinh ra) và gắn suffix chuẩn
            # Regex này xóa phần đuôi dạng _A, _B, _Admin... trước khi gắn cái mới
            inner = re.sub(r"_[a-zA-Z0-9]+$", "", inner)
            return f"{{{{{inner}_{suffix}}}}}"
            
        # Tìm và xử lý tất cả các chuỗi nằm trong {{ ... }}
        return re.sub(r"\{\{([^}]+)\}\}", replace_match, data)
    
    return data

def _build_setup_headers(body: dict | None, suffix: str) -> dict:
    """
    Xây dựng headers cho setup step từ convention.
    Sử dụng suffix động thay vì hardcode "A".
    """
    auth_token_key = "login.token"
    headers: dict = {
        "Authorization": f"Bearer {{{{{auth_token_key}_{suffix}}}}}"
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    return headers


def plan_for_endpoint(
    node_id: str,
    node_info: dict,
    recon_item: dict = None,
    users: list = None,
) -> list:
    """
    Sinh setup plan deterministic cho API endpoint không có lỗ hổng.
    Tạo riêng kịch bản cho từng role (attacker, victim, admin...) để tránh đụng độ dữ liệu.
    """
    endpoint_context, _, produces_list, path, method = _build_endpoint_context(
        node_id, node_info
    )

    # 1. Lấy base payload từ parser (chứa placeholder thô chưa có suffix)
    raw_body         = build_setup_body(node_info)
    raw_path_params  = build_setup_path_params(node_info)
    raw_query_params = build_setup_query_params(node_info)

    generated_plans = []
    
    # 2. Đảm bảo luôn có tối thiểu 1 role để chạy nếu config bị thiếu
    users_list = users if (users and len(users) > 0) else [{"role": "attacker"}]

    # 3. Multiplexing: Tạo setup plan cho từng user role
    for index, user_info in enumerate(users_list):
        # Hỗ trợ trường hợp user_info trong config là string hoặc dict
        role = user_info if isinstance(user_info, str) else user_info.get("role", "attacker")
        role = role.lower()
        
        # Lấy suffix chuẩn (A, B, Admin...) từ hàm có sẵn của bạn
        suffix = get_suffix_for_role(role, index)

        # Tiêm suffix động vào toàn bộ payload
        body         = _inject_role_suffix(raw_body, suffix)
        path_params  = _inject_role_suffix(raw_path_params, suffix)
        query_params = _inject_role_suffix(raw_query_params, suffix)

        # Cấp đúng Header Authorization cho role
        headers = _build_setup_headers(body, suffix)

        # Định danh mảng produces để ghi log mô tả cho rõ ràng
        produces_with_suffix = [f"{p}_{suffix}" for p in produces_list]

        result = TestPlan(
            node_id=node_id,
            endpoint=path,
            method=method,
            vuln_type="None",
            is_attack=False,
            run_as_role=role,
            max_iterations=1,
            test_steps=[
                TestStep(
                    step=1,
                    description=(
                        f"Setup [{role.upper()}]: tạo resource '{path}' bằng {method} "
                        f"để lấy {produces_with_suffix} cho các bước test sau."
                    ),
                    path_params=path_params,
                    query_params=query_params,
                    headers=headers,
                    body=body,
                    expected_indicator="status_code in [200, 201]",
                )
            ],
        )
        generated_plans.append(result.model_dump())

    roles_logged = [u if isinstance(u, str) else u.get("role", "attacker") for u in users_list]
    print(f"> Setup plan cho {node_id}: Đã phân thân {len(generated_plans)} kịch bản cho roles: {roles_logged}")
    
    return generated_plans

def get_suffix_for_role(role: str, index: int) -> str:
    role_suffix = {
        "attacker": "A",
        "victim": "B",
        "admin": "Admin",  
    }
    if role in role_suffix:
        return role_suffix[role]
    return chr(ord('A') + index)
# ══════════════════════════════════════════════════════════════════════
# ATTACK PLAN JOBS (LLM)
# ══════════════════════════════════════════════════════════════════════

# ── System prompt tách riêng (KHÔNG dùng f-string) để tránh brace nhầm ──
# Quy tắc escape trong _SYSTEM_PROMPT_TEMPLATE khi dùng str.format():
#   {{{{X}}}}  → sau .format() → {{X}}   ← LLM thấy double-brace (đúng)
#   {KEY}       → sau .format() → <giá trị thực>   ← inject biến
_SYSTEM_PROMPT_TEMPLATE = """\
You are a professional API security tester. Your job is to generate a structured \
security test plan for a specific API endpoint and vulnerability type.

=== STRICT PLACEHOLDER RULES ===

1. DYNAMIC VARIABLES:
   The endpoint consumes the following parameters (from dependency graph):

{consumes_hint}

   You MUST use ONLY these exact placeholder strings — copied verbatim.
   DO NOT invent or shorten variable names.

2. AVAILABLE DATA IN STORE:
   These keys are guaranteed to exist in VariableStore at test runtime:

{available_keys_hint}

   Role suffix convention:

   - _Admin = admin user
   - _A     = attacker user
   - _B     = victim user

   Examples:
   {{wallets.id_Admin}}
   {{wallets.id_A}}
   {{wallets.id_B}}

   {{login.token_Admin}}
   {{login.token_A}}
   {{login.token_B}}

   You MUST preserve suffix names exactly.
   NEVER generate placeholders for missing roles.
   Only use placeholders for roles explicitly provided.

3. AUTHENTICATION — use ONLY these two placeholders:
   - Attacker token: {{{{login.token_A}}}}
   - Victim token:   {{{{login.token_B}}}}
   Format in headers: "Authorization": "Bearer {{{{login.token_A}}}}"

4. DOUBLE BRACES are MANDATORY in your JSON output:
   CORRECT:   "walletId": "{{{{wallets.id_A}}}}"
   WRONG:     "walletId": "{{wallets.id_A}}"   <- single brace NOT allowed
   WRONG:     "walletId": "wallet_A"           <- plain string NOT allowed

5. HTTP STRUCTURE — strictly separate:
   - path_params:  only URL path variables like {{{{wallets.id_A}}}}
   - query_params: only query string parameters
   - headers:      only HTTP headers (Authorization, Content-Type, etc.)
   - body:         only request body fields

   DO NOT put headers or path params inside body.

6. VULNERABILITY FOCUS:
   Test ONLY for: {vuln_type}
   Reasoning: {vuln_reasoning}

7. STRICT JSON COMPLIANCE:
   Valid JSON only. No JS functions.

8. Limit to maximum 3 highly effective test steps.

9. NO HARDCODE IDs — MANDATORY:
   NEVER use raw integer or string literals for ID fields (path params, query params, body).
   If you need a resource ID (customerId, orderId, productId, supplierId, etc.),
   you MUST use a placeholder from AVAILABLE KEYS IN VARIABLE STORE (rule 2).
   Examples:
     CORRECT: "customerId": "{{{{customer.id_B}}}}"
     CORRECT: "orderId":    "{{{{order.id_A}}}}"
     WRONG:   "customerId": 2        <- hardcoded integer NOT allowed
     WRONG:   "orderId":    999      <- hardcoded integer NOT allowed
   If the resource key is NOT listed in AVAILABLE KEYS, still use the pattern
   {{{{<resource>.id_B}}}} where <resource> is the lowercase resource name.

10. CONTENT-TYPE HEADER:
    If a test step has a non-null body, you MUST include:
      "Content-Type": "application/json"
    in the headers of that step.

11. EXPECTED INDICATOR — use ONLY these machine-evaluable formats:
    - "status_code == 200"
    - "status_code in [200, 201]"
    - "status_code == 403"
    - "status_code == 204"
    - "status_code != 200"
    - "response_body_contains: <field>=<value>"   (e.g. "response_body_contains: isAdmin=true")
    - "status_code in [200, 201] and response_body_contains: <field>=<value>"

    Rules by HTTP method:
    - DELETE: use "status_code in [200, 204]" — NEVER expect response_body_contains_data
    - GET:    can check response body data presence
    - POST/PUT/PATCH: can check created or updated fields in response body
    For API3 mass assignment: "status_code in [200, 201] and response_body_contains: isAdmin=true"

12. UNIQUE FIELD VALUES — use dynamic tokens:
    For fields requiring uniqueness across runs (orderNumber, code, invoiceNumber, email, etc.),
    use the special token {{{{$timestamp}}}} which will be replaced with current Unix timestamp
    at runtime, and {{{{$role}}}} which will be replaced with the current user role name.
    Examples:
      "orderNumber": "ORD-{{{{$timestamp}}}}-{{{{$role}}}}"
      "code":        "CODE-{{{{$timestamp}}}}-{{{{$role}}}}"
      "email":       "test-{{{{$timestamp}}}}@example.com"
    This ensures each role (attacker, victim) creates a resource with a distinct identifier.

13. REPEAT / CONCURRENCY — match to vuln_type:
    Choose values appropriate for the vulnerability being tested:
    - API1 (BOLA/IDOR):            repeat=1, concurrency=1  — single cross-user request
    - API2 (Broken Auth):          repeat=1, concurrency=1  — single token manipulation
    - API3 (Mass Assignment):      repeat=1, concurrency=1  — single payload injection
    - API4 (Resource Consumption): repeat=50–100, concurrency=5–10  — burst needed
    - API5 (BFLA):                 repeat=1, concurrency=1  — single privilege check
    - API6 (Business Flow Abuse):  repeat=10–30, concurrency=2–5  — moderate repetition
    For API4/rate-limit tests: use {{{{$large_int}}}} token for limit/pageSize params
    instead of hardcoded integers like 1000000.
14. BODY FIELDS – MANDATORY INCLUSION:
    When generating a test step with a non‑null body, you MUST include ALL fields that are marked as required
    in the endpoint's body_schema, using their default values if provided, or using appropriate placeholders.
    If you need to omit a field for testing (e.g., mass assignment), still include it with a valid default value
    and add the extra unauthorized field.
15. ENUM COMPLIANCE — MANDATORY:

If a field has enum values in schema, you MUST use ONLY valid enum values exactly as defined.

* NEVER invent enum values.
* Respect enum type strictly:

  * numeric enum → send raw numbers (e.g., 1, never "1")
  * string enum → send exact enum strings
* If default exists and is a valid enum value, use it; otherwise use the first valid enum value.

Enum correctness takes priority over guessing to avoid 400 validation/deserialization errors.

"""


def build_plan_jobs_for_endpoint(
    node_id: str,
    node_info: dict,
    recon_item: dict,
    users: list,
    job_index_start: int,
    execution_order: list = None,
    graph_nodes: dict = None,
) -> list[dict]:
    if not recon_item:
        return []

    endpoint_context, consumes_mapping, _, path, method = _build_endpoint_context(
        node_id, node_info
    )

    summary          = recon_item.get("summary", {})
    vulns            = summary.get("vuln", [])
    if isinstance(vulns, str):
        vulns = [vulns]

    reasoning_dict   = recon_item.get("reasoning", {})
    verification_plan = recon_item.get("verification", {})

    jobs: list[dict] = []
    job_index = job_index_start

    # Tính available keys hint một lần cho node này
    available_keys_hint = _build_available_keys_hint(
        node_id,
        execution_order or [],
        graph_nodes or {},
    )

    for vuln_type in vulns:
        kb_context     = load_owasp_kb(vuln_type)
        vuln_reasoning = reasoning_dict.get(vuln_type, "No specific reasoning provided.")

        # Build consumes hint
        consumes_hint = simplify_consume_mapping(consumes_mapping)

        # Format sys_prompt hoàn chỉnh — inject tất cả biến ngay tại đây.
        # SAU ĐÓ format nốt human message cũng ngay tại đây.
        # Lý do: ChatPromptTemplate.from_messages() parse tất cả {xxx} và {{xxx}}
        # trong chuỗi như LangChain template. Bất kỳ {{wallets.id_A}} nào
        # (sau escape → {wallets.id_A}) đều bị LangChain coi là invalid variable
        # vì tên có dấu '.'. Giải pháp: format xong 100% rồi truyền input_vars={}
        # → LLMService sẽ dùng nhánh invoke trực tiếp, bỏ qua ChatPromptTemplate.
        sys_prompt = _SYSTEM_PROMPT_TEMPLATE.format(
            consumes_hint=consumes_hint,
            available_keys_hint=available_keys_hint,
            vuln_type=vuln_type,
            vuln_reasoning=vuln_reasoning,
        )

        human_message = (
            f"Endpoint Details: {json.dumps(endpoint_context, ensure_ascii=False)}\n"
            f"Vulnerability Info: {json.dumps({'vuln_type': vuln_type, 'reasoning': vuln_reasoning, 'plan': verification_plan}, ensure_ascii=False)}\n"
            f"OWASP KB: {json.dumps(kb_context, ensure_ascii=False)}"
        )

        # Messages đã format hoàn chỉnh — không còn {placeholder} nào
        prompt_messages = [
            SystemMessage(content=sys_prompt),
            HumanMessage(content=human_message),
        ]

        jobs.append(
            {
                "job_index":        job_index,
                "node_id":          node_id,
                "endpoint":         path,
                "method":           method,
                "vuln_type":        vuln_type,
                "consumes_mapping": consumes_mapping,  # dùng cho _sanitize_plan
                "prompt_messages":  prompt_messages,
                "input_vars":       {},                # {} → LLMService invoke trực tiếp
            }
        )
        job_index += 1

    return jobs


# ══════════════════════════════════════════════════════════════════════
# PLANNING NODE
# ══════════════════════════════════════════════════════════════════════

def planning_node(state: dict) -> dict:
    audits_list    = state.get("filtered_endpoints", [])
    dependency_data = state.get("dependency_graph", {})
    config         = state.get("config", {})
    users          = config.get("users", [])
    execution_order = dependency_data.get("execution_order", [])
    graph_nodes    = dependency_data.get("graph", {}).get("nodes", {})

    print(f"\n--- CHẠY PLANNING NODE ---")
    print(f"Tổng số API cần lên kịch bản: {len(execution_order)}")

    # Build audit_map: node_id → recon_item
    audit_map: dict = {}
    for item in audits_list:
        if not isinstance(item, dict):
            continue
        method = item.get("summary", {}).get("method", "").upper()
        path   = item.get("summary", {}).get("path", "")
        if method and path:
            node_id = f"{method}:{path}"
            audit_map[node_id] = item

    _AUTH_MANAGED_PATHS = {"login", "register", "refresh"}

    plan_entries: list[dict] = []
    llm_jobs:    list[dict]  = []
    job_index = 0

    for node_id in execution_order:
        node_info   = graph_nodes.get(node_id, {})
        recon_item  = audit_map.get(node_id)

        # Bỏ qua auth endpoints không phải attack target
        node_path = node_info.get("path", "")
        if not recon_item and any(kw in node_path for kw in _AUTH_MANAGED_PATHS):
            print(f"> Bỏ qua auth endpoint: {node_id}")
            continue

        produces = node_info.get("produces", [])
        if not recon_item or len(produces) > 0:
            # Setup plan (deterministic)
            plans = plan_for_endpoint(node_id, node_info, None, users)
            for plan in plans:
                plan_entries.append({"kind": "plan", "plan": plan})

        if recon_item:
            jobs = build_plan_jobs_for_endpoint(
                node_id=node_id,
                node_info=node_info,
                recon_item=recon_item,
                users=users,
                job_index_start=job_index,
                execution_order=execution_order,
                graph_nodes=graph_nodes,
            )
            for job in jobs:
                plan_entries.append({"kind": "job", "job_index": job["job_index"]})
            llm_jobs.extend(jobs)
            job_index += len(jobs)
            continue

    # ── Chạy LLM jobs song song ──────────────────────────────────────
    job_results: dict[int, dict] = {}

    if llm_jobs:
        api_keys  = get_groq_keys(settings.LLM_PARALLEL_KEYS)
        scheduler = LLMTaskScheduler(
            api_keys=api_keys,
            concurrency_per_key=settings.LLM_CONCURRENCY_PER_KEY,
            logger=logger,
        )

        tasks = []
        for job in llm_jobs:
            def _make_task(job_payload: dict):
                def _task(api_key: str, key_index: int):
                    debug_dir  = "outputs"
                    os.makedirs(debug_dir, exist_ok=True)
                    debug_file = os.path.join(debug_dir, "llm_debug.log")

                    log_data = {
                        "node_id":        job_payload.get("node_id"),
                        "endpoint":       job_payload.get("endpoint"),
                        "method":         job_payload.get("method"),
                        "vuln_type":      job_payload.get("vuln_type"),
                        "prompt_messages": [{"type": m.type, "content": m.content} if hasattr(m, 'type') else m for m in job_payload["prompt_messages"]],
                        "input_variables": job_payload["input_vars"],
                    }

                    with open(debug_file, "a", encoding="utf-8") as f:
                        f.write("\n" + "=" * 100 + "\n")
                        json.dump(log_data, f, indent=2, ensure_ascii=False)
                        f.write("\n")

                    service = LLMService(
                        api_key=api_key,
                        model=settings.LARGE_MODEL_NAME,
                        base_url=settings.URL_LLM,
                    )

                    return service.generate_structured(
                        prompt_messages=job_payload["prompt_messages"],
                        input_variables=job_payload["input_vars"],
                        pydantic_schema=TestPlan,
                        fallback_method="function_calling",
                    )

                return _task

            tasks.append(_make_task(job))

        results, errors = scheduler.map(tasks, fail_soft=True)

        for idx, result in enumerate(results):
            job = llm_jobs[idx]
            if errors[idx] is not None or result is None:
                logger.warning(
                    "Planning job failed (node_id=%s, vuln_type=%s)",
                    job["node_id"],
                    job["vuln_type"],
                )
                continue

            if isinstance(result, list):
                result = result[0] if len(result) > 0 else None
            if isinstance(result, dict):
                result = TestPlan(**result)

            if result and isinstance(result, TestPlan):
                # Gán metadata
                result.node_id   = job["node_id"]
                result.endpoint  = job["endpoint"]
                result.method    = job["method"]
                result.vuln_type = job["vuln_type"]
                result.is_attack = True

                # ── Sanitize placeholder sau khi nhận từ LLM ────────
                result = _sanitize_plan(result, job.get("consumes_mapping", {}))

                job_results[job["job_index"]] = result.model_dump()

    # ── Ghép kết quả theo thứ tự plan_entries ────────────────────────
    full_test_plan: list = []
    for entry in plan_entries:
        if entry["kind"] == "plan":
            full_test_plan.append(entry["plan"])
            continue

        plan = job_results.get(entry["job_index"])
        if plan:
            full_test_plan.append(plan)

    # ── Lưu test_plan.json ───────────────────────────────────────────
    output_dir = "outputs"
    os.makedirs(output_dir, exist_ok=True)
    file_path  = os.path.join(output_dir, "test_plan.json")

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(full_test_plan, f, ensure_ascii=False, indent=2)

    print(f"Đã sinh test plan thành công. Lưu tại: {file_path}")

    return {
        **state,
        "test_plan": full_test_plan
    }