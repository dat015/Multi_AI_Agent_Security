# core/dependency_resolver.py
"""
Dependency Resolver — xây dựng đồ thị phụ thuộc giữa các API endpoint bằng LLM.

Nền tảng lý thuyết: RESTler (Atlidakis et al., ICSE 2019)
Cải tiến: Sử dụng LLM (gpt-4o) làm core engine để phân tích toàn bộ 
          synonym, ambiguous ID và multi-level dependency thông qua ngữ nghĩa.
"""

from __future__ import annotations
import heapq
import re
import json
import logging
from dataclasses import dataclass, field
from typing import Optional, List
from collections import defaultdict

from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field
from openai import OpenAI
from langchain_core.prompts import ChatPromptTemplate

from app.schemas.api_schema import APIEndpoint
from app.helper.make_graph_image import visualize_dependency_graph
from app.core.config import settings

    
llm = ChatOpenAI(
    model=settings.LLAMA_3_3_70B,
    temperature=0,
    api_key=settings.GROQ_API_KEY,
    base_url=settings.URL_LLM
)
logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════════

@dataclass
class EndpointNode:
    node_id:       str            # unique key: "POST:/api/users"
    method:        str
    path:          str
    summary:       str
    requires_auth: bool
    parameters:    list[dict]
    request_body:  dict
    response_schema: dict
    tags:          list[str]
    produces:      list[str]
    consumes:      list[str]

@dataclass
class DependencyEdge:
    producer_id:     str
    consumer_id:     str
    param_name:      str
    resolved_name:   str
    resolution_type: str

@dataclass
class DependencyGraph:
    nodes: dict[str, EndpointNode] = field(default_factory=dict)
    edges: list[DependencyEdge]    = field(default_factory=list)

    def get_producers(self, consumer_id: str) -> list[DependencyEdge]:
        return [e for e in self.edges if e.consumer_id == consumer_id]

    def get_consumers(self, producer_id: str) -> list[DependencyEdge]:
        return [e for e in self.edges if e.producer_id == producer_id]

    def to_dict(self) -> dict:
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
                    "producer_id":     e.producer_id,
                    "consumer_id":     e.consumer_id,
                    "param_name":      e.param_name,
                    "resolved_name":   e.resolved_name,
                    "resolution_type": e.resolution_type,
                }
                for e in self.edges
            ],
        }

# ══════════════════════════════════════════════════════════════════════
# LLM STRUCTURED OUTPUT SCHEMAS
# ══════════════════════════════════════════════════════════════════════

class PredictedEdge(BaseModel):
    """Đại diện cho một cạnh phụ thuộc được LLM dự đoán"""
    producer_id: str = Field(description="node_id của endpoint sinh ra dữ liệu (VD: POST:/api/users)")
    consumer_id: str = Field(description="node_id của endpoint tiêu thụ dữ liệu (VD: GET:/api/users/{id})")
    param_name: str = Field(description="Tên tham số gốc mà consumer yêu cầu")
    resolved_name: str = Field(description="Tên trường dữ liệu thực tế mà producer trả về")
    resolution_type: str = Field(description="Loại suy luận (ví dụ: 'llm_exact', 'llm_synonym', 'llm_contextual')")
    reasoning: str = Field(description="Giải thích ngắn gọn tại sao lại có sự phụ thuộc này")

class PredictedGraph(BaseModel):
    """Toàn bộ đồ thị phụ thuộc do LLM trả về"""
    edges: List[PredictedEdge] = Field(description="Danh sách tất cả các phụ thuộc giữa các API endpoints")

# ══════════════════════════════════════════════════════════════════════
# SCHEMA PARSING (Giữ lại để chuẩn bị data sạch cho LLM)
# ══════════════════════════════════════════════════════════════════════

def extract_response_fields(endpoint_data: dict) -> list[str]:
    # (Giữ nguyên logic hàm cũ vì đây chỉ là parse OpenAPI, không phải suy luận phụ thuộc)
    fields = []
    responses = endpoint_data.get("responses", {})
    for status in ["200", "201", "202"]:
        if status not in responses:
            continue
        schema = responses[status].get("content", {}).get("application/json", {}).get("schema", {})
        _collect_fields(schema, fields)
        if fields:
            break
    return list(set(fields))

def _collect_fields(schema: dict, result: list, depth: int = 0, parent: str = ""):
    # (Giữ nguyên hàm đệ quy gom field cũ của bạn)
    if depth > 6 or not isinstance(schema, dict): return
    properties = schema.get("properties", {})
    for fname, details in properties.items():
        if fname not in result: result.append(fname)
        if details.get("type") == "object":
            _collect_fields(details, result, depth + 1, fname)
        if details.get("items"):
            _collect_fields(details.get("items"), result, depth + 1, fname)

# ══════════════════════════════════════════════════════════════════════
# LLM GRAPH GENERATOR
# ══════════════════════════════════════════════════════════════════════

GRAPH_GENERATION_PROMPT = """Bạn là chuyên gia phân tích hệ thống REST API.
Nhiệm vụ của bạn là xây dựng đồ thị phụ thuộc (dependency graph) giữa các API endpoints.

Dưới đây là danh sách tất cả các API có trong hệ thống, bao gồm những dữ liệu chúng CẦN (consumes) và những dữ liệu chúng TRẢ VỀ (produces):
{endpoints_json}

YÊU CẦU PHÂN TÍCH:
1. Với mỗi endpoint, hãy kiểm tra danh sách `consumes`.
2. Tìm kiếm trong toàn bộ các endpoint khác xem endpoint nào có khả năng sinh ra (produce) tham số đó.
3. Chú ý xử lý các trường hợp:
   - Từ đồng nghĩa (Synonyms): "userId" có thể được cung cấp bởi "id" từ POST /users.
   - Ambiguous IDs: Nếu tham số chỉ là "id", hãy nhìn vào URL path (VD: /api/orders/{{id}}) để tự hiểu nó là "order_id" và tìm producer tương ứng.
   - Ưu tiên các endpoint mang tính khởi tạo (POST, PUT) làm Producer.
4. KHÔNG tạo phụ thuộc nếu không đủ căn cứ logic.

Hãy trả về danh sách các phụ thuộc (edges) tuân thủ đúng schema được yêu cầu."""

def generate_dependencies_with_llm(nodes_dict: dict[str, EndpointNode]) -> List[PredictedEdge]:
    """Sử dụng GPT-4o với Structured Output để sinh toàn bộ graph"""
    
    # Rút gọn data gửi cho LLM để tiết kiệm context window
    simplified_nodes = []
    for nid, node in nodes_dict.items():
        simplified_nodes.append({
            "node_id": node.node_id,
            "path": node.path,
            "method": node.method,
            "consumes": node.consumes,
            "produces": node.produces[:20] # Giới hạn số lượng produces để tránh nhiễu
        })

    prompt = ChatPromptTemplate.from_messages([
        ("system", GRAPH_GENERATION_PROMPT),
    ])
    
    # Ép kiểu LLM trả về đúng Pydantic model
    structured_llm = llm.with_structured_output(PredictedGraph)
    chain = prompt | structured_llm
    
    try:
        result: PredictedGraph = chain.invoke({
            "endpoints_json": json.dumps(simplified_nodes, ensure_ascii=False, indent=2)
        })
        return result.edges
    except Exception as e:
        logger.error(f"Lỗi khi gọi LLM generate graph: {e}")
        return []

# ══════════════════════════════════════════════════════════════════════
# TOPOLOGICAL SORT (Giữ nguyên)
# ══════════════════════════════════════════════════════════════════════

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

class DependencyResolverLLM:

    def build(self, audits: list[dict], parsed_endpoints: list[APIEndpoint]) -> dict:
        graph = DependencyGraph()

        # 1. Map kết quả audits
        audit_map = {}
        for audit in audits:
            summary = audit.get("summary", {})
            method = summary.get("method", "").upper()
            path = summary.get("path", "")
            if method and path:
                node_id = f"{method}:{path}"
                audit_map[node_id] = audit

        # 2. Xây dựng EndpointNode (Chỉ parse data, không chạy rule dò tìm)
        for ep in parsed_endpoints:
            node_id = f"{ep.method}:{ep.path}"
            consumes = []
            
            for p in ep.parameters:
                if p.location in ["path", "query"] or (p.location == "body" and p.required):
                    consumes.append(p.name)
            
            if ep.request_body and isinstance(ep.request_body, dict):
                schema = ep.request_body.get("content", {}).get("application/json", {}).get("schema", {})
                def _extract_consumes_from_schema(s, result_list):
                    if not isinstance(s, dict): return
                    for field_name, details in s.get("properties", {}).items():
                        if field_name not in result_list: result_list.append(field_name)
                        if details.get("type") == "object": _extract_consumes_from_schema(details, result_list)
                    if s.get("items"): _extract_consumes_from_schema(s.get("items"), result_list)
                _extract_consumes_from_schema(schema, consumes)

            produces = extract_response_fields({"responses": ep.raw_details.get("responses", {})})

            llm_audit = audit_map.get(node_id, {})
            vuln_tag = llm_audit.get("summary", {}).get("vuln")

            node = EndpointNode(
                node_id=node_id, method=ep.method, path=ep.path, summary=ep.summary,
                requires_auth=ep.requires_auth,
                parameters=[{"name": p.name, "location": p.location, "type": p.type, "required": p.required} for p in ep.parameters],
                request_body=ep.request_body or {}, response_schema={}, 
                tags=[vuln_tag] if vuln_tag else [], produces=produces, consumes=consumes,
            )
            graph.nodes[node_id] = node

        # 3. GỌI LLM ĐỂ BUILD TOÀN BỘ EDGES
        if graph.nodes:
            logger.info("Đang gọi LLM để phân tích Dependency Graph...")
            llm_edges = generate_dependencies_with_llm(graph.nodes)
            
            for edge in llm_edges:
                # Kiểm tra lại một chút để đảm bảo LLM không hallucinate node_id
                if edge.producer_id in graph.nodes and edge.consumer_id in graph.nodes:
                    graph.edges.append(DependencyEdge(
                        producer_id=edge.producer_id,
                        consumer_id=edge.consumer_id,
                        param_name=edge.param_name,
                        resolved_name=edge.resolved_name,
                        resolution_type=edge.resolution_type
                    ))
                    logger.debug(f"LLM Edge: {edge.producer_id} -> {edge.consumer_id} (Lý do: {edge.reasoning})")

        # 4. Sắp xếp thứ tự chạy
        execution_order = topological_sort(graph)
        
        # visualize_dependency_graph(graph, save_path="output/dependency_graph.png") # Uncomment khi chạy thực tế
        
        return {
            "graph": graph.to_dict(),
            "execution_order": execution_order,
            "unresolved": {}, # Khái niệm này không còn quá quan trọng khi LLM đã xử lý toàn bộ
            "stats": {"total_nodes": len(graph.nodes), "total_edges": len(graph.edges)}
        }