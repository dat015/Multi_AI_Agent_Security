# core/dependency_resolver.py
"""
Dependency Resolver — xây dựng đồ thị phụ thuộc giữa các API endpoint.

Nền tảng lý thuyết: RESTler (Atlidakis et al., ICSE 2019)
Mở rộng: xử lý synonym, ambiguous ID, multi-level dependency bằng
          kết hợp rule-based + LLM fallback.

Implement (scope đồ án):
  ✅ Edge case 1: Synonym Problem     — alias dictionary + schema matching
  ✅ Edge case 2: Ambiguous ID        — contextual inference từ path segment
  ✅ Edge case 3: Multi-level Deps    — DFS với max_depth + cycle detection

Hướng phát triển (không implement):
  ⏭ Edge case 4: Missing Producers   — GET list fallback
  ⏭ Edge case 5: Stateful Constraints — Business workflow planning
  ⏭ Edge case 6: External IDs        — Third-party token handling
"""

from __future__ import annotations
import heapq
import re
import json
from dataclasses import dataclass, field
from typing import Optional
import logging
from langchain_openai import ChatOpenAI

from app.schemas.api_schema import APIEndpoint
from collections import defaultdict
from app.helper.make_graph_image import visualize_dependency_graph
llm = ChatOpenAI(model="gpt-4o", temperature=0)
logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════════

@dataclass
class EndpointNode:
    """
    Đại diện cho 1 endpoint trong đồ thị.
    Chứa đủ thông tin để Execution Agent gọi API không cần lookup thêm.
    """
    node_id:      str            # unique key: "POST:/api/users"
    method:       str
    path:         str
    summary:      str
    requires_auth: bool
    parameters:   list[dict]     # [{name, location, type, required}]
    request_body: dict           # schema đầy đủ (đã resolve $ref)
    response_schema: dict        # schema của response 2xx
    tags:         list[str]      # OWASP tags từ Recon Agent
    produces:     list[tuple[str, str]]      # field names endpoint này trả về
    consumes:     list[dict]      # parameter names endpoint này cần


@dataclass
class DependencyEdge:
    """
    Cạnh trong đồ thị: producer → consumer.
    
    Ví dụ: POST /users --[produces: user_id]--> GET /users/{user_id}
    """
    producer_id:    str          # node_id của endpoint sinh ra giá trị
    consumer_id:    str          # node_id của endpoint cần giá trị
    param_name:     str          # tên param trong consumer (gốc)
    resolved_name:  str          # tên field trong response producer
    resolution_type: str         # "exact" | "synonym" | "contextual" | "llm"
    param_tuple:    tuple[str, str]

@dataclass
class DependencyGraph:
    """
    Đồ thị phụ thuộc hoàn chỉnh.
    nodes: dict[node_id → EndpointNode]
    edges: list[DependencyEdge]
    """
    nodes: dict[str, EndpointNode] = field(default_factory=dict)
    edges: list[DependencyEdge]    = field(default_factory=list)

    def get_producers(self, consumer_id: str) -> list[DependencyEdge]:
        """Tìm tất cả producer cần thiết cho 1 consumer."""
        return [e for e in self.edges if e.consumer_id == consumer_id]

    def get_consumers(self, producer_id: str) -> list[DependencyEdge]:
        """Tìm tất cả consumer phụ thuộc vào 1 producer."""
        return [e for e in self.edges if e.producer_id == producer_id]

    def to_dict(self) -> dict:
        """Serialize để lưu vào SystemState."""
        return {
            "nodes": {
                nid: {
                    "node_id":       n.node_id,
                    "method":        n.method,
                    "path":          n.path,
                    "summary":       n.summary,
                    "requires_auth": n.requires_auth,
                    "parameters":    n.parameters,
                    "tags":          n.tags,
                    "produces":      n.produces,
                    "consumes":      n.consumes,
                    "request_body":  n.request_body,
                }
                for nid, n in self.nodes.items()
            },
            "edges": [
                {
                    "producer_id":    e.producer_id,
                    "consumer_id":    e.consumer_id,
                    "param_name":     e.param_name,
                    "resolved_name":  e.resolved_name,
                    "resolution_type": e.resolution_type,
                }
                for e in self.edges
            ],
        }

def singularize(word: str) -> str:
    """Helper đơn giản để chuyển số nhiều thành số ít."""
    word = word.lower()
    if word.endswith("ies"): return word[:-3] + "y"
    if word.endswith("ses") or word.endswith("xes"): return word[:-2]
    if word.endswith("s") and len(word) > 3: return word[:-1]
    return word

def extract_owner(path: str) -> str:
    """Step 1 - Infer endpoint owner từ path (VD: /users/{id}/wallets -> wallet)"""
    clean_path = path.split("?")[0]
    segments = [s for s in clean_path.split("/") if s and not s.startswith("{")]
    if not segments:
        return "unknown"
    return singularize(segments[-1])

def infer_ownership_tuple(field_name: str, endpoint_owner: str) -> tuple[str, str]:
    """
    Step 2 - Trích xuất (owner, field) từ tên field và context của endpoint.
    Xử lý Nested Object, Explicit Resource Field và Generic Field.
    """
    # Case 3: Nested object (data.user.id -> nearest object là user)
    if "." in field_name:
        parts = field_name.split(".")
        nearest_owner = singularize(parts[-2])
        leaf_field = parts[-1]
        return infer_ownership_tuple(leaf_field, nearest_owner)

    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", field_name).lower()
    
    # Clean up "{id}" brackets if present
    clean_snake = snake.replace("{", "").replace("}", "")

    # Case 1: Generic field (id, name, status)
    if clean_snake == "id":
        return (endpoint_owner, "id")
        
    # Case 2: Explicit resource field (user_id, wallet_id)
    if clean_snake.endswith("_id"):
        resource = clean_snake[:-3]
        return (singularize(resource), "id")

    # Generic properties
    return (endpoint_owner, clean_snake)

# ══════════════════════════════════════════════════════════════════════
# RESPONSE SCHEMA PARSER — trích xuất field names từ schema
# ══════════════════════════════════════════════════════════════════════

def extract_response_fields(endpoint_data: dict, endpoint_owner: str) -> list[tuple[str, str]]:
    fields = []
    responses = endpoint_data.get("responses", {})

    for status in ["200", "201", "202"]:
        if status not in responses:
            continue
        schema = responses[status].get("content", {}).get("application/json", {}).get("schema", {})
        _collect_fields(schema, fields)
        if fields:
            break

    # Convert tất cả raw path (data.user.id) thành Tuple
    tuples = set()
    for f in fields:
        tuples.add(infer_ownership_tuple(f, endpoint_owner))
        
    return list(tuples)


def _collect_fields(schema: dict, result: list, depth: int = 0, parent: str = ""):
    if depth > 6 or not isinstance(schema, dict): return
    properties = schema.get("properties", {})

    for fname, details in properties.items():
        # CHỈ TẠO full_path (VD: "data.user.id")
        full_name = f"{parent}.{fname}" if parent else fname

        if full_name not in result:
            result.append(full_name)

        if details.get("type") == "object":
            _collect_fields(details, result, depth + 1, full_name)
        
        items = details.get("items")
        if items:
            _collect_fields(items, result, depth + 1, full_name)

    for combiner in ["allOf", "anyOf", "oneOf"]:
        for sub in schema.get(combiner, []):
            _collect_fields(sub, result, depth + 1, parent)


# ══════════════════════════════════════════════════════════════════════
# PRODUCER FINDER
# ══════════════════════════════════════════════════════════════════════

def find_producer(
    consumer_tuple: tuple[str, str],
    all_nodes: dict[str, EndpointNode],
    exclude_id: str,
) -> Optional[tuple[str, str, str]]:
    priority_methods = ["POST", "PUT", "GET"]
    
    for method in priority_methods:
        for node_id, node in all_nodes.items():
            if node_id == exclude_id or node.method != method:
                continue
            
            # Semantic Matching: Compare Tuple vs Tuple
            if consumer_tuple in node.produces:
                resolved_field_name = f"{consumer_tuple[0]}.{consumer_tuple[1]}"
                return (node_id, resolved_field_name, "semantic_tuple")
                
    return None


# ══════════════════════════════════════════════════════════════════════
# EDGE CASE 3: MULTI-LEVEL DEPENDENCY — DFS với cycle detection
# ══════════════════════════════════════════════════════════════════════

def resolve_chain(
    start_node_id: str, all_nodes: dict[str, EndpointNode],
    graph: DependencyGraph, visited: set[str],
    depth: int = 0, max_depth: int = 3,
) -> None:
    if depth >= max_depth or start_node_id in visited: return
    visited.add(start_node_id)
    node = all_nodes.get(start_node_id)
    if not node: return

    for consume_item in node.consumes:
        param_name = consume_item["raw_name"]
        consumer_tuple = consume_item["tuple"]

        result = find_producer(
            consumer_tuple=consumer_tuple,
            all_nodes=all_nodes,
            exclude_id=start_node_id
        )

        if result:
            producer_id, resolved_field, res_type = result
            existing = {(e.producer_id, e.consumer_id, e.param_name) for e in graph.edges}
            
            if (producer_id, start_node_id, param_name) not in existing:
                graph.edges.append(DependencyEdge(
                    producer_id=producer_id,
                    consumer_id=start_node_id,
                    param_name=param_name,
                    param_tuple=consumer_tuple,
                    resolved_name=resolved_field,
                    resolution_type=res_type,
                ))
            resolve_chain(producer_id, all_nodes, graph, visited, depth + 1, max_depth)


# ══════════════════════════════════════════════════════════════════════
# LLM FALLBACK — cho những dependency không rule nào giải được
# ══════════════════════════════════════════════════════════════════════

LLM_DEPENDENCY_PROMPT = """Bạn là chuyên gia phân tích REST API.

Endpoint đang cần test:
{target_endpoint}

Danh sách tất cả endpoint có trong hệ thống:
{available_endpoints}

Nhiệm vụ: Với mỗi parameter trong target endpoint, hãy tìm endpoint nào 
có thể sinh ra giá trị đó (producer). 

Trả về JSON array:
[
  {{
    "param_name": "tên param cần tìm",
    "producer_endpoint": "METHOD /path/to/producer",
    "produced_field": "tên field trong response của producer",
    "confidence": 0.0-1.0,
    "reasoning": "Giải thích ngắn"
  }}
]

Nếu không tìm được producer, bỏ param đó khỏi kết quả.
Chỉ trả JSON array, không có text khác."""


def llm_resolve_dependencies(
    target: EndpointNode,
    all_nodes: dict[str, EndpointNode],
    unresolved_params: list[str],
) -> list[dict]:
    """
    Gọi LLM để resolve những param mà rule-based không xử lý được.
    
    Tại sao chỉ gọi cho unresolved?
    → Tiết kiệm token: chỉ hỏi LLM khi thực sự cần.
    → LLM giỏi hiểu ngữ nghĩa (VD: "orderId" trong context
      payment service thực ra là "transaction_id" ở user service).
    """
    if not unresolved_params:
        return []

    # Tóm tắt available endpoints để không vượt context limit
    available = []
    for node in all_nodes.values():
        if node.node_id == target.node_id:
            continue
        available.append({
            "endpoint": f"{node.method} {node.path}",
            "summary": node.summary,
            "produces": node.produces[:10],  # giới hạn để tránh token bloat
        })

    target_summary = {
        "endpoint": f"{target.method} {target.path}",
        "summary": target.summary,
        "unresolved_params": unresolved_params,
    }

    prompt = LLM_DEPENDENCY_PROMPT.format(
        target_endpoint=json.dumps(target_summary, ensure_ascii=False),
        available_endpoints=json.dumps(available[:30], ensure_ascii=False),
        # Giới hạn 30 endpoint để tránh context quá lớn
    )

    try:
        result = llm.invoke(prompt)
        parsed = json.loads(result.content)
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []

def topological_sort(graph: DependencyGraph) -> list[str]:
    """
    Priority-aware Kahn Topological Sort

    Improvements:
    - deterministic ordering
    - auth-first
    - producer-first
    - benign-before-attack
    - cycle warning

    producer luôn chạy trước consumer.
    """

    in_degree: dict[str, int] = defaultdict(int)
    adjacency: dict[str, list[str]] = defaultdict(list)

    # --------------------------
    # Helper: node priority
    # --------------------------
    def node_priority(node) -> tuple:
        """
        Lower tuple = higher priority
        """

        return (
            # 1. auth/login endpoint trước
            0 if getattr(node, "is_auth_endpoint", False) else 1,

            # 2. producer endpoint trước
            -len(
                getattr(
                    node,
                    "produces_variables",
                    []
                )
            ),

            # 3. benign trước attack
            0 if not getattr(
                node,
                "is_attack",
                False
            ) else 1,

            # 4. deterministic ordering
            node.node_id
        )

    # --------------------------
    # Init indegree
    # --------------------------
    for node_id in graph.nodes:
        in_degree[node_id] = 0

    # --------------------------
    # Build adjacency + indegree
    # --------------------------
    for edge in graph.edges:

        adjacency[
            edge.producer_id
        ].append(
            edge.consumer_id
        )

        in_degree[
            edge.consumer_id
        ] += 1

    # --------------------------
    # Deterministic ordering
    # --------------------------
    for node_id in adjacency:
        adjacency[node_id].sort()

    # --------------------------
    # Priority queue
    # --------------------------
    heap = []

    for node_id in sorted(graph.nodes):

        if in_degree[node_id] == 0:

            heapq.heappush(
                heap,
                (
                    node_priority(
                        graph.nodes[node_id]
                    ),
                    node_id
                )
            )

    sorted_nodes = []

    # --------------------------
    # Kahn Topological Sort
    # --------------------------
    while heap:

        _, node_id = heapq.heappop(heap)

        sorted_nodes.append(node_id)

        for neighbor in adjacency[node_id]:

            in_degree[neighbor] -= 1

            if in_degree[neighbor] == 0:

                heapq.heappush(
                    heap,
                    (
                        node_priority(
                            graph.nodes[neighbor]
                        ),
                        neighbor
                    )
                )

    # --------------------------
    # Cycle detection
    # --------------------------
    remaining = [
        n
        for n in graph.nodes
        if n not in sorted_nodes
    ]

    if remaining:
        logger.warning(
            "Cycle detected: %s",
            remaining
        )

    # Best-effort mode:
    # append cyclic nodes cuối
    return sorted_nodes + sorted(remaining)


# ══════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

class DependencyResolver:

    def build(self, audits: list[dict], parsed_endpoints: list[APIEndpoint]) -> dict:
        graph = DependencyGraph()

        # 1. Map kết quả từ LLM (audits) theo node_id để lấy vuln (tags)
        audit_map = {}
        for audit in audits:
            summary = audit.get("summary", {})
            method = summary.get("method", "").upper()
            path = summary.get("path", "")
            if method and path:
                node_id = f"{method}:{path}"
                audit_map[node_id] = audit

        # 2. Xây dựng EndpointNode từ parsed_endpoints
        for ep in parsed_endpoints:
            node_id = f"{ep.method}:{ep.path}"
            
            # --- BƯỚC MỚI: Trích xuất Owner của endpoint hiện tại ---
            endpoint_owner = extract_owner(ep.path)

            # A. Tìm Consumes (những tham số cần truyền)
            consumes_raw_list = []
            
            # A1. Lấy từ Path và Query parameters
            for p in ep.parameters:
                if p.location in ["path", "query"] or (p.location == "body" and p.required):
                    consumes_raw_list.append(p.name)
            
            # A2. Trích xuất SÂU từ request_body
            if ep.request_body and isinstance(ep.request_body, dict):
                schema = ep.request_body.get("content", {}).get("application/json", {}).get("schema", {})
                
                def _extract_consumes_from_schema(s, result_list):
                    if not isinstance(s, dict): return
                    
                    # Nếu là object, duyệt qua các properties
                    for field_name, details in s.get("properties", {}).items():
                        if field_name not in result_list:
                            result_list.append(field_name)
                            
                        # Gọi đệ quy nếu bên trong field này lại là 1 object khác
                        if details.get("type") == "object":
                            _extract_consumes_from_schema(details, result_list)
                            
                    # Nếu là mảng (array), duyệt vào items của mảng đó
                    items = s.get("items", {})
                    if items:
                        _extract_consumes_from_schema(items, result_list)

                # Kích hoạt hàm đệ quy để gom tất cả keys vào list `consumes_raw_list`
                _extract_consumes_from_schema(schema, consumes_raw_list)

            # --- BƯỚC MỚI: Ánh xạ biến thô sang Semantic Tuple ---
            consumes = []
            for raw_name in set(consumes_raw_list):
                consumes.append({
                    "raw_name": raw_name,
                    "tuple": infer_ownership_tuple(raw_name, endpoint_owner)
                })

            # B. Tìm Produces (những trường API này trả về - đã chuyển sang list[tuple])
            produces = extract_response_fields(
                {"responses": ep.raw_details.get("responses", {})},
                endpoint_owner
            )

            # Lấy thông tin audit từ LLM gán làm tag
            llm_audit = audit_map.get(node_id, {})
            vuln_tag = llm_audit.get("summary", {}).get("vuln")
            tags = [vuln_tag] if vuln_tag else []

            node = EndpointNode(
                node_id=node_id,
                method=ep.method,
                path=ep.path,
                summary=ep.summary,
                requires_auth=ep.requires_auth,
                parameters=[{"name": p.name, "location": p.location, "type": p.type, "required": p.required} for p in ep.parameters],
                request_body=ep.request_body or {},
                response_schema={}, 
                tags=tags,
                produces=produces,
                consumes=consumes, # Gán list of dict đã chứa tuple
            )
            graph.nodes[node_id] = node

        # 3. Chạy đệ quy tìm dependency cho tất cả các node trong graph
        unresolved = {}
        for node_id, node in graph.nodes.items():
            visited = set()
            resolve_chain(node_id, graph.nodes, graph, visited, depth=0, max_depth=3)

            # Check xem còn param nào thiếu
            resolved_params = {e.param_name for e in graph.get_producers(node_id)}
            
            # Trích xuất lại raw_name từ consumes để check thiếu
            all_consumes_names = [c["raw_name"] for c in node.consumes]
            still_unresolved = [p for p in all_consumes_names if p not in resolved_params]
            
            # LLM Fallback cho những param còn lại
            if still_unresolved:
                llm_results = llm_resolve_dependencies(node, graph.nodes, still_unresolved)
                
                for res in llm_results:
                    producer_id = res.get("producer_endpoint", "")
                    produced_field = res.get("produced_field", "")
                    param_name = res.get("param_name", "")
                    
                    if producer_id and produced_field and param_name and (producer_id in graph.nodes):
                        # Sinh tuple fallback để Data Class đồng bộ
                        fallback_tuple = infer_ownership_tuple(param_name, extract_owner(node.path))

                        graph.edges.append(DependencyEdge(
                            producer_id=producer_id,
                            consumer_id=node_id,
                            param_name=param_name,
                            param_tuple=fallback_tuple, # Đã cập nhật thuộc tính mới này ở DependencyEdge
                            resolved_name=produced_field,
                            resolution_type="llm_fallback",
                        ))
                        
                        if param_name in still_unresolved:
                            still_unresolved.remove(param_name)
                            
                if still_unresolved:
                    unresolved[node_id] = still_unresolved

        # 4. Sắp xếp thứ tự chạy
        execution_order = topological_sort(graph)
        visualize_dependency_graph(
            graph,
            save_path="output/dependency_graph.png"
        )
        return {
            "graph": graph.to_dict(),
            "execution_order": execution_order,
            "unresolved": unresolved,
            "stats": {"total_nodes": len(graph.nodes), "total_edges": len(graph.edges)}
        }