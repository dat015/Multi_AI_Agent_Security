import os

from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import json
import logging
from app.services.llm_service import LLMService
from app.services.llm_scheduler import LLMTaskScheduler
from app.core.config import settings, get_groq_keys
from app.core.constants import AGENT_SYSTEM_PROMPT
from app.core.restler_parser import (
    build_setup_body,
    build_setup_path_params,
    build_setup_query_params,
)
from typing import Union

# Định nghĩa cấu trúc dữ liệu đầu ra bắt buộc bằng Pydantic
class TestStep(BaseModel):
    step: int
    description: str
    path_params: Optional[Dict[str, str]] = Field(default_factory=dict, description="Các biến trên URL path, VD: {'walletId': '{{wallet.id}}'}")
    query_params: Optional[Dict[str, str]] = Field(default_factory=dict, description="Các tham số sau dấu ?, VD: {'limit': '10'}")
    headers: Optional[Dict[str, str]] = Field(default_factory=dict, description="HTTP Headers, bắt buộc chứa Authorization token nếu cần")
    body: Optional[Union[Dict[str, Any], str]] = Field(default=None, description="HTTP Request Body (JSON hoặc Text)")
    expected_indicator: str
    repeat: int = Field(
        default=1, 
        description="Mặc định là 1. CHỈ đặt giá trị lớn (ví dụ: 50-100) khi vuln_type là API4 (Unrestricted Resource Consumption) hoặc khi cần test Rate Limit."
    )
    rate_per_minute: int = Field(
        default=0, 
        description="Mặc định là 0 (không giới hạn). CHỈ thiết lập (ví dụ: 600) khi cần test khả năng chặn Rate Limit."
    )
    concurrency: int = Field(
        default=1, 
        description="Mặc định là 1. CHỈ đặt > 1 (ví dụ: 5-10) để giả lập request đồng thời khi test Rate Limit hoặc Race Condition."
    )
class TestPlan(BaseModel):
    node_id: Optional[str] = Field(default=None, description="Định danh của API, VD: POST:/users")
    endpoint: Optional[str] = Field(default=None)
    method: Optional[str] = Field(default=None)
    is_attack: Optional[bool] = Field(default=False, description="True nếu là test bảo mật, False nếu chỉ là API mồi tạo data")
    vuln_type: Optional[str] = Field(default="None")
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

def _build_endpoint_context(node_id: str, node_info: dict) -> tuple[dict, dict, list, str, str]:
    path = node_info.get("path")
    method = node_info.get("method")

    raw_consumes = node_info.get("consumes", [])
    raw_produces = node_info.get("produces", [])

    # ── consumes_mapping: {param_name: semantic_key} ───────────────────────
    # Hỗ trợ cả format mới (RESTler) lẫn format cũ (DependencyResolver)
    consumes_mapping: dict = {}
    for c in raw_consumes:
        if "param" in c and "semantic_key" in c:
            # Format mới từ RestlerParser
            consumes_mapping[c["param"]] = c["semantic_key"]
        elif "raw_name" in c and "tuple" in c and len(c["tuple"]) == 2:
            # Format cũ từ DependencyResolver (fallback)
            consumes_mapping[c["raw_name"]] = f"{c['tuple'][0]}.{c['tuple'][1]}"

    # ── produces_list: ["category.id", "order.id", ...] ───────────────────
    produces_list: list = []
    for p in raw_produces:
        if isinstance(p, dict) and "semantic_key" in p:
            # Format mới từ RestlerParser
            produces_list.append(p["semantic_key"])
        elif isinstance(p, (list, tuple)) and len(p) == 2:
            # Format cũ
            produces_list.append(f"{p[0]}.{p[1]}")

    endpoint_context = {
        "node_id": node_id,
        "path": path,
        "method": method,
        "parameters": node_info.get("parameters"),
        "request_body": node_info.get("request_body"),
        "body_schema": node_info.get("body_schema", {}),
        "consumes_mapping": consumes_mapping,
        "produces_list": produces_list,
    }

    return endpoint_context, consumes_mapping, produces_list, path, method


def plan_for_endpoint(node_id: str, node_info: dict, recon_item: dict = None, users: list = None) -> list:
    """
    Sinh kịch bản cho một API endpoint.
    - Nếu có recon_item (có lỗ hổng): Lặp qua từng loại lỗi và sinh các kịch bản tấn công riêng biệt.
    - Nếu không (API mồi an toàn): Build body deterministically từ RESTler body_schema.
    """
    endpoint_context, _, produces_list, path, method = _build_endpoint_context(
        node_id, node_info
    )

    if recon_item is not None:
        return []

    generated_plans: list = []

    # ── API MồI (SETUP STEP): Build body deterministically từ RESTler schema ──
    # Không gọi LLM — nhanh hơn và chính xác hơn.
    body = build_setup_body(node_info)  # None nếu endpoint không có body
    path_params = build_setup_path_params(node_info)
    query_params = build_setup_query_params(node_info)

    result = TestPlan(
        node_id=node_id,
        endpoint=path,
        method=method,
        vuln_type="None",
        is_attack=False,
        max_iterations=1,
        test_steps=[
            TestStep(
                step=1,
                description=(
                    f"Setup: tạo resource '{path}' bằng {method} "
                    f"để lấy {produces_list} cho các bước test sau."
                ),
                path_params=path_params,
                query_params=query_params,
                headers={},
                body=body,
                expected_indicator="status_code in [200, 201]",
            )
        ],
    )
    generated_plans.append(result.model_dump())
    print(f"> Setup plan cho: {node_id} (body: {list(body.keys()) if body else 'none'})")

    return generated_plans


def build_plan_jobs_for_endpoint(
    node_id: str,
    node_info: dict,
    recon_item: dict,
    users: list,
    job_index_start: int,
) -> list[dict]:
    if not recon_item:
        return []

    endpoint_context, consumes_mapping, _, path, method = _build_endpoint_context(
        node_id, node_info
    )

    summary = recon_item.get("summary", {})
    vulns = summary.get("vuln", [])
    if isinstance(vulns, str):
        vulns = [vulns]

    reasoning_dict = recon_item.get("reasoning", {})
    verification_plan = recon_item.get("verification", {})

    jobs: list[dict] = []
    job_index = job_index_start

    for vuln_type in vulns:
        kb_context = load_owasp_kb(vuln_type)
        vuln_reasoning = reasoning_dict.get(vuln_type, "No specific reasoning provided.")

        sys_prompt = """You are a professional security tester. Based on the endpoint information and the OWASP KB, generate a detailed security testing plan.
                        RULES:
                    1. DYNAMIC VARIABLES FORMAT: The endpoint consumes variables according to this mapping: {consumes_mapping} (Format is 'parameter_name': 'semantic_variable').
                    - You MUST ALWAYS use DOUBLE BRACES around the 'semantic_variable' for placeholders (e.g., `{{{{user.id}}}}`).
                    - If the test requires multiple users (e.g., BOLA/IDOR testing), you MUST strictly append `_A` and `_B` or `_Admin` (attact role -> _A, victim role -> _B, admin role -> _Admin) to the semantic variable name. This is all user `{users}`
                    - EXACT ALLOWED FORMAT: `{{{{wallet.id_A}}}}`, `{{{{wallet.id_B}}}}`, `{{{{login.token_A}}}}` and no spaces.
                    - DO NOT invent new naming conventions. Use EXACTLY the semantic variables provided in the mapping.
                    2. HTTP STRUCTURE: Strictly separate your request data into `path_params`, `query_params`, `headers`, and `body`. Do NOT put headers or path parameters inside the `body`.
                    3. Focus strictly on testing the specified vulnerability: {vuln_type}. Reason: {vuln_reasoning}.
                    4. STRICT JSON COMPLIANCE: Valid JSON only. Do not use JS functions like .repeat() or concatenation. Use string placeholders like "[LARGE_PAYLOAD]" if needed.
                    5. Limit to a maximum of 3 highly effective test steps.
                    """
        prompt_messages = [
            ("system", sys_prompt),
            ("human", "Endpoint Details: {endpoint}\nVulnerability Info: {vuln_info}\nOWASP KB: {kb_context}"),
        ]

        input_vars = {
            "consumes_mapping": json.dumps(consumes_mapping, ensure_ascii=False),
            "vuln_type": vuln_type,
            "vuln_reasoning": vuln_reasoning,
            "users": users,
            "endpoint": json.dumps(endpoint_context, ensure_ascii=False),
            "vuln_info": json.dumps(
                {
                    "vuln_type": vuln_type,
                    "reasoning": vuln_reasoning,
                    "plan": verification_plan,
                },
                ensure_ascii=False,
            ),
            "kb_context": json.dumps(kb_context, ensure_ascii=False),
        }

        jobs.append(
            {
                "job_index": job_index,
                "node_id": node_id,
                "endpoint": path,
                "method": method,
                "vuln_type": vuln_type,
                "prompt_messages": prompt_messages,
                "input_vars": input_vars,
            }
        )
        job_index += 1

    return jobs

def planning_node(state: dict) -> dict:
    audits_list = state.get("filtered_endpoints", [])
    dependency_data = state.get("dependency_graph", {})
    config = state.get("config", {})
    users = config.get("users", [])
    execution_order = dependency_data.get("execution_order", [])
    graph_nodes = dependency_data.get("graph", {}).get("nodes", {})
    
    print(f"\n--- CHẠY PLANNING NODE ---")
    print(f"Tổng số API cần lên kịch bản (kể cả API mồi): {len(execution_order)}")
    
    # Map các audits theo node_id để dễ truy xuất
    audit_map = {}
    for item in audits_list:
        method = item.get("summary", {}).get("method", "").upper()
        path = item.get("summary", {}).get("path", "")
        if method and path:
            node_id = f"{method}:{path}"
            audit_map[node_id] = item

    _AUTH_MANAGED_PATHS = {
        "login",
        "register",
        "refresh",
    }

    plan_entries = []
    llm_jobs: list[dict] = []
    job_index = 0

    for node_id in execution_order:
        node_info = graph_nodes.get(node_id, {})

        recon_item = audit_map.get(node_id)

        # Bỏ qua auth endpoints không phải attack target
        node_path = node_info.get("path", "")
        if not recon_item and any(keyword in node_path for keyword in _AUTH_MANAGED_PATHS):
            print(f"> Bỏ qua auth endpoint: {node_id}")
            continue

        if recon_item:
            jobs = build_plan_jobs_for_endpoint(
                node_id=node_id,
                node_info=node_info,
                recon_item=recon_item,
                users=users,
                job_index_start=job_index,
            )
            for job in jobs:
                plan_entries.append({"kind": "job", "job_index": job["job_index"]})
            llm_jobs.extend(jobs)
            job_index += len(jobs)
            continue

        plans = plan_for_endpoint(node_id, node_info, recon_item, users)
        for plan in plans:
            plan_entries.append({"kind": "plan", "plan": plan})

    job_results: dict[int, dict] = {}
    if llm_jobs:
        api_keys = get_groq_keys(settings.LLM_PARALLEL_KEYS)
        scheduler = LLMTaskScheduler(
            api_keys=api_keys,
            concurrency_per_key=settings.LLM_CONCURRENCY_PER_KEY,
            logger=logger,
        )

        tasks = []
        for job in llm_jobs:
            def _make_task(job_payload: dict):
                def _task(api_key: str, key_index: int):
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
                result.node_id = job["node_id"]
                result.endpoint = job["endpoint"]
                result.method = job["method"]
                result.vuln_type = job["vuln_type"]
                result.is_attack = True
                job_results[job["job_index"]] = result.model_dump()

    full_test_plan = []
    for entry in plan_entries:
        if entry["kind"] == "plan":
            full_test_plan.append(entry["plan"])
            continue

        plan = job_results.get(entry["job_index"])
        if plan:
            full_test_plan.append(plan)
            
    output_dir = "outputs"
    os.makedirs(output_dir, exist_ok=True)
    file_path = os.path.join(output_dir, "test_plan.json")
    
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(full_test_plan, f, ensure_ascii=False, indent=2)
    
    print(f"Đã sinh test plan thành công. Lưu tại: {file_path}")
    
    return {
        **state,
        "test_plan": full_test_plan
    }