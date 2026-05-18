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
import re
import json
from dataclasses import dataclass, field
from typing import Optional
from langchain_openai import ChatOpenAI

from app.schemas.api_schema import APIEndpoint

llm = ChatOpenAI(model="gpt-4o", temperature=0)


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
    produces:     list[str]      # field names endpoint này trả về
    consumes:     list[str]      # parameter names endpoint này cần


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


# ══════════════════════════════════════════════════════════════════════
# EDGE CASE 1: SYNONYM DICTIONARY
# ══════════════════════════════════════════════════════════════════════

# Mapping: canonical name → list of known aliases
# Khi normalize, tất cả alias đều được đưa về canonical name
SYNONYM_MAP: dict[str, list[str]] = {
    "user_id": [
        "userid", "user_id", "uid", "account_id", "accountid",
        "participant_id", "participantid", "customer_id", "customerid",
        "member_id", "memberid", "person_id", "personid",
        "owner_id", "ownerid", "author_id", "authorid",
        "created_by", "createdby", "requester_id",
    ],
    "order_id": [
        "orderid", "order_id", "transaction_id", "transactionid",
        "purchase_id", "purchaseid", "booking_id", "bookingid",
    ],
    "vehicle_id": [
        "vehicleid", "vehicle_id", "car_id", "carid",
        "product_id", "productid",
    ],
    "conversation_id": [
        "conversationid", "conversation_id", "chat_id", "chatid",
        "thread_id", "threadid", "session_id", "sessionid",
    ],
    "message_id": [
        "messageid", "message_id", "msg_id", "msgid",
        "comment_id", "commentid", "post_id", "postid",
    ],
    "role_id": [
        "roleid", "role_id", "permission_id", "permissionid",
        "group_id", "groupid",
    ],
    "coupon_id": [
        "couponid", "coupon_id", "promo_id", "promoid",
        "voucher_id", "voucherid", "discount_id",
    ],
}

# Reverse map: alias → canonical
_REVERSE_SYNONYM: dict[str, str] = {}
for canonical, aliases in SYNONYM_MAP.items():
    for alias in aliases:
        _REVERSE_SYNONYM[alias.lower()] = canonical


def normalize_param_name(raw: str) -> str:
    """
    Chuẩn hóa tên parameter về canonical form.
    
    Ví dụ:
      "userId"        → "user_id"
      "participantId" → "user_id"   (qua synonym map)
      "id"            → "id"        (ambiguous, xử lý riêng)
    
    Tại sao cần bước này?
    → Developer đặt tên không nhất quán. Nếu so khớp string thô,
      "userId" và "user_id" sẽ không match dù cùng ý nghĩa.
    """
    # camelCase → snake_case
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", raw).lower()
    # Tra synonym map
    return _REVERSE_SYNONYM.get(snake, snake)


# ══════════════════════════════════════════════════════════════════════
# EDGE CASE 2: AMBIGUOUS ID — CONTEXTUAL INFERENCE
# ══════════════════════════════════════════════════════════════════════

def resolve_ambiguous_id(param_name: str, path: str) -> str:
    """
    Xử lý trường hợp tham số chỉ tên là "id" — rất phổ biến.
    
    Thuật toán:
      1. Tìm path segment ngay trước {id} trong URL
      2. Singularize segment đó (bỏ 's' cuối nếu là plural)  
      3. Ghép thành {resource}_id
    
    Ví dụ:
      /api/conversations/{id}  →  conversation_id
      /api/orders/{id}         →  order_id
      /api/users/{id}/profile  →  user_id
    
    Tại sao không dùng LLM ở đây?
    → Rule đơn giản, chạy nhanh, không tốn token.
    → LLM chỉ được gọi khi rule không đủ (trong _llm_resolve_param).
    """
    if param_name.lower() not in ("id", "{id}"):
        return param_name

    # Tách path thành segments, bỏ query string
    clean_path = path.split("?")[0]
    segments = [s for s in clean_path.split("/") if s and not s.startswith("{")]

    if not segments:
        return param_name

    # Lấy segment gần nhất (ngay trước placeholder)
    resource = segments[-1].lower()

    # Singularize đơn giản: bỏ 's' cuối nếu có
    # Đủ dùng cho các trường hợp phổ biến: users→user, orders→order
    if resource.endswith("ies"):
        resource = resource[:-3] + "y"   # categories → category
    elif resource.endswith("ses") or resource.endswith("xes"):
        resource = resource[:-2]          # addresses → address
    elif resource.endswith("s") and len(resource) > 3:
        resource = resource[:-1]          # orders → order

    return f"{resource}_id"


# ══════════════════════════════════════════════════════════════════════
# RESPONSE SCHEMA PARSER — trích xuất field names từ schema
# ══════════════════════════════════════════════════════════════════════

def extract_response_fields(endpoint_data: dict) -> list[str]:
    """
    Trích xuất tất cả field names từ response schema của endpoint.
    Hỗ trợ: object properties, array of objects, allOf/anyOf.
    
    Tại sao cần hàm này?
    → Producer được nhận diện qua response schema, không chỉ qua URL.
    → POST /users trả về {"id": ..., "email": ..., "role": ...}
      → produces = ["id", "email", "role", "user_id" (normalized)]
    """
    fields = []
    responses = endpoint_data.get("responses", {})

    # Ưu tiên 200, 201, 202
    for status in ["200", "201", "202"]:
        if status not in responses:
            continue
        schema = (
            responses[status]
            .get("content", {})
            .get("application/json", {})
            .get("schema", {})
        )
        _collect_fields(schema, fields)
        if fields:
            break

    return list(set(fields))


def _collect_fields(schema: dict, result: list, depth: int = 0):
    """Đệ quy trích xuất field names từ JSON Schema."""
    if depth > 4 or not isinstance(schema, dict):
        return

    # Object với properties
    for fname in schema.get("properties", {}).keys():
        # 1. Lưu tên gốc (VD: transactionId)
        if fname not in result:
            result.append(fname)
            
        # 2. Lưu dạng snake_case (VD: transaction_id)
        snake = re.sub(r"(?<!^)(?=[A-Z])", "_", fname).lower()
        if snake not in result:
            result.append(snake)
            
        # 3. Lưu dạng Canonical/Synonym (VD: order_id)
        canonical = normalize_param_name(fname)
        if canonical not in result:
            result.append(canonical)

    # Array of objects: items → properties
    items = schema.get("items", {})
    if items:
        _collect_fields(items, result, depth + 1)

    # Combiners
    for combiner in ["allOf", "anyOf", "oneOf"]:
        for sub in schema.get(combiner, []):
            _collect_fields(sub, result, depth + 1)


# ══════════════════════════════════════════════════════════════════════
# PRODUCER FINDER
# ══════════════════════════════════════════════════════════════════════

def find_producer(
    param_name: str,
    param_canonical: str,
    all_nodes: dict[str, EndpointNode],
    exclude_id: str,
) -> Optional[tuple[str, str, str]]:
    """
    Tìm endpoint nào sinh ra giá trị cho param_canonical.
    
    Trả về: (producer_node_id, resolved_field_name, resolution_type)
    hoặc None nếu không tìm được.
    
    Chiến lược tìm (theo thứ tự ưu tiên):
      1. Exact match: producer.produces chứa đúng param_canonical
      2. Synonym match: canonical của producer field == canonical của param
      3. Path-based: endpoint POST có path liên quan đến resource
    """
    resource = param_canonical.replace("_id", "").replace("_", "")

    # Ưu tiên POST/PUT (create operations) trước
    priority_methods = ["POST", "PUT", "GET"]
    snake_name = re.sub(r"(?<!^)(?=[A-Z])", "_", param_name).lower()
    for method in priority_methods:
        for node_id, node in all_nodes.items():
            if node_id == exclude_id or node.method != method:
                continue
            if param_name in node.produces:
                return (node_id, param_name, "exact")
            # 1. Exact match trong produces list
            if param_canonical in node.produces:
                return (node_id, param_canonical, "exact")
            if snake_name in node.produces:
                return (node_id, snake_name, "exact_snake")
            # 2. Synonym match
            for produced_field in node.produces:
                if normalize_param_name(produced_field) == param_canonical:
                    return (node_id, produced_field, "synonym")

            # 3. Path-based heuristic: POST /users → produces user_id
            if method == "POST":
                path_lower = node.path.lower().replace("/", " ").replace("-", " ")
                if resource in path_lower:
                    # Endpoint này likely sinh ra resource_id
                    return (node_id, "id", "contextual")

    return None


# ══════════════════════════════════════════════════════════════════════
# EDGE CASE 3: MULTI-LEVEL DEPENDENCY — DFS với cycle detection
# ══════════════════════════════════════════════════════════════════════

def resolve_chain(
    start_node_id: str,
    all_nodes:     dict[str, EndpointNode],
    graph:         DependencyGraph,
    visited:       set[str],
    depth:         int = 0,
    max_depth:     int = 3,
) -> None:
    """
    DFS từ start_node, tìm tất cả dependency và thêm edge vào graph.
    
    max_depth = 3: giới hạn độ sâu tối đa.
    Tại sao 3?
    → Đủ cho hầu hết real-world API chains:
      POST /users → POST /orders → POST /payments
    → Sâu hơn thường là data model quá phức tạp, không
      phù hợp test tự động trong thời gian ngắn.
    
    visited: tránh cycle (A → B → A → vòng lặp vô tận)
    """
    if depth >= max_depth or start_node_id in visited:
        return

    visited.add(start_node_id)
    node = all_nodes.get(start_node_id)
    if not node:
        return

    for param_name in node.consumes:
        # Normalize param name (xử lý edge case 1 + 2)
        if param_name.lower() in ("id", "{id}"):
            canonical = resolve_ambiguous_id(param_name, node.path)
        else:
            canonical = normalize_param_name(param_name)

        # Tìm producer cho param này
        result = find_producer(
            param_name=param_name, 
            param_canonical=canonical, 
            all_nodes=all_nodes, 
            exclude_id=start_node_id
        )

        if result:
            producer_id, resolved_field, res_type = result
            # Tránh thêm edge trùng lặp
            existing = {(e.producer_id, e.consumer_id, e.param_name)
                        for e in graph.edges}
            if (producer_id, start_node_id, param_name) not in existing:
                graph.edges.append(DependencyEdge(
                    producer_id=    producer_id,
                    consumer_id=    start_node_id,
                    param_name=     param_name,
                    resolved_name=  resolved_field,
                    resolution_type=res_type,
                ))
            # Đệ quy: producer này có phụ thuộc gì không?
            resolve_chain(
                producer_id, all_nodes, graph, visited,
                depth + 1, max_depth
            )


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
    Kahn's algorithm — sắp xếp endpoint theo thứ tự:
    producer luôn chạy trước consumer.
    
    Ví dụ kết quả:
      [POST /users, POST /orders, POST /payments, GET /orders/refund]
    
    Tại sao cần bước này?
    → Execution Agent không cần "suy nghĩ" về thứ tự nữa.
    → Cứ chạy theo list từ trên xuống là đúng.
    
    Xử lý cycle: node trong cycle được thêm vào cuối
    (tránh infinite loop khi topo sort gặp cycle).
    """
    from collections import deque, defaultdict

    in_degree: dict[str, int] = defaultdict(int)
    adjacency: dict[str, list[str]] = defaultdict(list)

    for node_id in graph.nodes:
        in_degree[node_id] = in_degree.get(node_id, 0)

    for edge in graph.edges:
        adjacency[edge.producer_id].append(edge.consumer_id)
        in_degree[edge.consumer_id] = in_degree.get(edge.consumer_id, 0) + 1

    # Bắt đầu từ node không có dependency (in_degree = 0)
    queue = deque([n for n in graph.nodes if in_degree[n] == 0])
    sorted_nodes = []

    while queue:
        node_id = queue.popleft()
        sorted_nodes.append(node_id)
        for neighbor in adjacency[node_id]:
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)

    # Nodes còn lại (trong cycle) → thêm vào cuối
    remaining = [n for n in graph.nodes if n not in sorted_nodes]
    return sorted_nodes + remaining


# ══════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

class DependencyResolver:
    """
    Điểm vào duy nhất. Planning Agent gọi:
      graph = DependencyResolver().build(filtered_endpoints, all_chunks)
    """

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
            
            # Chỉ test những endpoint mà LLM Recon đã chọn (có trong audits)
            # Nếu bạn muốn dựng graph cho TẤT CẢ endpoint thì bỏ dòng if này
            # if node_id not in audit_map:
            #     continue

            # A. Tìm Consumes (những tham số cần truyền)
            consumes = [
                p.name for p in ep.parameters 
                if p.location in ["path", "query"] or (p.location == "body" and p.required)
            ]

            # B. Tìm Produces (những trường API này trả về)
            # Tái sử dụng hàm extract_response_fields gốc của bạn truyền vào raw_details
            produces = extract_response_fields({"responses": ep.raw_details.get("responses", {})})

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
                consumes=consumes,
            )
            graph.nodes[node_id] = node

        # 3. Chạy đệ quy tìm dependency cho tất cả các node trong graph
        unresolved = {}
        for node_id, node in graph.nodes.items():
            visited = set()
            resolve_chain(node_id, graph.nodes, graph, visited, depth=0, max_depth=3)

            # Check xem còn param nào thiếu
            resolved_params = {e.param_name for e in graph.get_producers(node_id)}
            still_unresolved = [p for p in node.consumes if p not in resolved_params]
            
            # (Bạn có thể gọi LLM Fallback ở đây như code gốc nếu muốn)
            if still_unresolved:
                unresolved[node_id] = still_unresolved

        # 4. Sắp xếp thứ tự chạy
        execution_order = topological_sort(graph)

        return {
            "graph": graph.to_dict(),
            "execution_order": execution_order,
            "unresolved": unresolved,
            "stats": {"total_nodes": len(graph.nodes), "total_edges": len(graph.edges)}
        }