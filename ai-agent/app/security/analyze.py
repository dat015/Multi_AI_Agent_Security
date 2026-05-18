# dependency_resolver.py
import json
import os
import re
from typing import List, Dict, Any, Set, Tuple, Optional
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum

from app.core.constants import SWAGGER_DEFAULT_PATH

class ParamLocation(Enum):
    PATH = "path"
    QUERY = "query"
    HEADER = "header"
    COOKIE = "cookie"
    BODY = "body"

@dataclass
class Parameter:
    name: str
    location: ParamLocation
    type: str = "string"
    required: bool = False
    description: str = ""

@dataclass
class Endpoint:
    path: str
    method: str  # GET, POST, PUT, DELETE, PATCH
    summary: str = ""
    description: str = ""
    parameters: List[Parameter] = field(default_factory=list)
    request_body_schema: Dict[str, Any] = field(default_factory=dict)  # JSON schema
    response_schema: Dict[str, Any] = field(default_factory=dict)     # JSON schema
    requires_auth: bool = True
    tags: List[str] = field(default_factory=list)

    def __hash__(self):
        return hash((self.path, self.method))

    def __eq__(self, other):
        return self.path == other.path and self.method == other.method


# ============== 2. SecurityAnalyzer (giản lược, dựa trên code bạn đã viết) ==============
# Giả sử đã có module security_analyzer với method analyze trả về list findings
# Ở đây tôi viết lại một phiên bản đủ dùng cho demo
class SecurityAnalyzer:
    @staticmethod
    def analyze(endpoints: List[Endpoint]) -> List[Dict[str, Any]]:
        """
        Trả về danh sách các endpoint nguy hiểm (có tag).
        Mỗi phần tử chứa 'endpoint' (Endpoint object) và các thông tin: score, tags, ...
        """
        # Trong thực tế, bạn dùng code đã viết. Tôi chỉ tạo mock.
        findings = []
        for ep in endpoints:
            # Giả lập: coi tất cả endpoint có chứa "user" hoặc "admin" là nguy hiểm
            if "user" in ep.path.lower() or "admin" in ep.path.lower():
                findings.append({
                    "endpoint": ep,
                    "score": 7,
                    "severity": "HIGH",
                    "tags": ["API1_BOLA"] if "{" in ep.path else ["API2_AUTH"],
                    "reasons": ["Path param or admin path"]
                })
        return findings


# ============== 3. DependencyResolver ==============
class DependencyResolver:
    def __init__(self, alias_dict: Dict[str, List[str]] = None):
        """
        alias_dict: mapping từ tên tham số chuẩn -> list các tên đồng nghĩa.
        Ví dụ: {"userId": ["user", "account", "participant", "member"]}
        """
        self.alias_dict = alias_dict or {}
        self._normalized_cache = {}

    def _normalize_param_name(self, param_name: str, path: str = "") -> str:
        """
        Chuẩn hóa tên tham số: loại bỏ hậu tố _id, id, chuyển về camelCase/snake_case?
        Kết hợp với path để suy luận resource (xử lý trường hợp ambiguous "id").
        Ví dụ: path "/api/conversations/{id}" -> "conversation_id"
        """
        key = (param_name, path)
        if key in self._normalized_cache:
            return self._normalized_cache[key]

        name_lower = param_name.lower()
        # Xử lý trường hợp tên là "id" -> lấy resource từ path
        if name_lower == "id" or name_lower == "identifier":
            # Tìm resource cuối cùng trong path trước {}
            match = re.search(r"/([^/]+)/\{[^}]+\}$", path.rstrip('/'))
            if match:
                resource = match.group(1).rstrip('s')  # conversations -> conversation
                normalized = f"{resource}_id"
            else:
                normalized = "id"
        else:
            # Bỏ hậu tố _id, id nếu có
            normalized = re.sub(r'(_id|_i d|id)$', '', name_lower)
        self._normalized_cache[key] = normalized
        return normalized

    def _get_possible_producer_keys(self, param_name: str, path: str) -> Set[str]:
        """
        Từ tên tham số đã chuẩn hóa, sinh ra các key để tìm producer.
        Bao gồm: chính nó, các từ đồng nghĩa từ alias_dict, và dạng số nhiều.
        """
        norm = self._normalize_param_name(param_name, path)
        candidates = {norm, param_name.lower()}
        # Thêm alias
        for canonical, aliases in self.alias_dict.items():
            if norm == canonical or param_name.lower() in aliases:
                candidates.add(canonical)
                candidates.update(aliases)
        # Thêm dạng số nhiều đơn giản
        if not norm.endswith('s'):
            candidates.add(norm + 's')
        return candidates

    def _extract_output_fields(self, endpoint: Endpoint) -> Dict[str, Set[str]]:
        """
        Trích xuất các trường có khả năng là ID từ response schema.
        Trả về dict: { "field_name": set of các giá trị có thể (nếu có example) }.
        Trong thực tế, cần parse response_schema hoặc gọi thử endpoint.
        Ở đây tôi giả định endpoint có response_schema chứa properties.
        """
        fields = set()
        schema = endpoint.response_schema
        if not schema:
            return {"fields": fields, "examples": {}}
        # Tìm tất cả các property có tên chứa 'id' hoặc kết thúc bằng 'id'
        def extract(obj, prefix=""):
            if isinstance(obj, dict):
                for key, val in obj.items():
                    if key == "properties":
                        for prop_name, prop_schema in val.items():
                            if any(x in prop_name.lower() for x in ("id", "key", "uuid")):
                                fields.add(prop_name)
                            # Đệ quy cho nested objects
                            if prop_schema.get("type") == "object":
                                extract(prop_schema, f"{prop_name}.")
                    else:
                        extract(val, prefix)
        extract(schema)
        return {"fields": fields, "examples": {}}

    def _extract_input_params(self, endpoint: Endpoint) -> Set[Tuple[str, ParamLocation]]:
        """
        Trích xuất tất cả tham số đầu vào (path, query, body fields) cần được cung cấp.
        Trả về set các (param_name, location).
        """
        params = set()
        for p in endpoint.parameters:
            params.add((p.name, p.location))
        # Body fields: đơn giản lấy từ request_body_schema
        if endpoint.request_body_schema:
            props = endpoint.request_body_schema.get("properties", {})
            for field in props.keys():
                params.add((field, ParamLocation.BODY))
        return params

    def find_producers(self, target: Endpoint, all_endpoints: List[Endpoint],
                       max_depth: int = 2, visited: Set[Endpoint] = None) -> List[Endpoint]:
        """
        Tìm tất cả endpoint có thể cung cấp giá trị cho tham số của target.
        Trả về danh sách producer (có thể là POST tạo mới, GET list, ...).
        Thực hiện BFS để xử lý multi-level dependency.
        """
        visited = visited or set()
        if target in visited:
            return []
        visited.add(target)

        producers = []
        input_params = self._extract_input_params(target)

        for param_name, location in input_params:
            # Tìm các endpoint có output chứa trường tương ứng
            candidate_keys = self._get_possible_producer_keys(param_name, target.path)
            for ep in all_endpoints:
                if ep == target:
                    continue
                output_info = self._extract_output_fields(ep)
                output_fields = output_info["fields"]
                # Kiểm tra xem output_fields có khớp với candidate_keys không
                for out_field in output_fields:
                    norm_out = self._normalize_param_name(out_field, ep.path)
                    if norm_out in candidate_keys or out_field.lower() in candidate_keys:
                        producers.append(ep)
                        # Nếu producer này cũng cần tham số, đệ quy tìm tiếp (multi-level)
                        if max_depth > 0:
                            deeper = self.find_producers(ep, all_endpoints, max_depth-1, visited)
                            producers.extend(deeper)
                        break  # đã tìm thấy cho param này

        # Loại bỏ trùng lặp theo endpoint
        unique = []
        seen = set()
        for ep in producers:
            if ep not in seen:
                seen.add(ep)
                unique.append(ep)
        return unique

    def build_dependency_graph(self, endpoints: List[Endpoint]) -> Dict[Endpoint, List[Endpoint]]:
        """
        Xây dựng đồ thị phụ thuộc: key là consumer, value là list producer.
        """
        graph = defaultdict(list)
        for consumer in endpoints:
            producers = self.find_producers(consumer, endpoints, max_depth=2)
            graph[consumer] = producers
        return graph

    def cluster_by_parameter(self, endpoints: List[Endpoint]) -> List[List[Endpoint]]:
        """
        Gom cụm các endpoint có quan hệ output-input thành chuỗi (cụm).
        Mỗi cụm là một danh sách các endpoint theo thứ tự từ producer đến consumer.
        Sử dụng đồ thị và tìm các connected components, sau đó sắp xếp topo.
        """
        graph = self.build_dependency_graph(endpoints)
        # Xây dựng đồ thị ngược (producer -> consumer)
        reverse_graph = defaultdict(list)
        for consumer, producers in graph.items():
            for prod in producers:
                reverse_graph[prod].append(consumer)

        # Tìm tất cả các node
        all_nodes = set(graph.keys()) | set(reverse_graph.keys())

        # DFS để tìm các thành phần liên thông (undirected)
        visited = set()
        components = []

        def dfs(node, component):
            visited.add(node)
            component.append(node)
            for neighbor in graph.get(node, []):
                if neighbor not in visited:
                    dfs(neighbor, component)
            for neighbor in reverse_graph.get(node, []):
                if neighbor not in visited:
                    dfs(neighbor, component)

        for node in all_nodes:
            if node not in visited:
                comp = []
                dfs(node, comp)
                components.append(comp)

        # Với mỗi component, sắp xếp topo để tạo chuỗi (producer -> consumer)
        clusters = []
        for comp in components:
            # Tính bậc vào (in-degree) trong đồ thị có hướng
            in_degree = defaultdict(int)
            for node in comp:
                for prod in graph.get(node, []):
                    if prod in comp:
                        in_degree[node] += 1   # node là consumer, nhận cạnh từ prod
            # Tìm các node có in-degree = 0 (producers đầu tiên)
            queue = [n for n in comp if in_degree[n] == 0]
            ordered = []
            while queue:
                node = queue.pop(0)
                ordered.append(node)
                for consumer in reverse_graph.get(node, []):
                    if consumer in comp:
                        in_degree[consumer] -= 1
                        if in_degree[consumer] == 0:
                            queue.append(consumer)
            # Nếu có chu trình, thêm phần còn lại vào cuối
            if len(ordered) != len(comp):
                ordered.extend([n for n in comp if n not in ordered])
            clusters.append(ordered)
        return clusters

def load_swagger_to_endpoints(file_path: str = SWAGGER_DEFAULT_PATH) -> List[Endpoint]:
        with open(file_path, 'r', encoding='utf-8') as f:
            spec = json.load(f)

        endpoints = []
        paths = spec.get("paths", {})

        for path, methods in paths.items():
            for method, details in methods.items():
                method = method.upper()

                # 1. Parameters (path, query, header, cookie)
                parameters = []
                for p in details.get("parameters", []):
                    location = p.get("in", "query")
                    parameters.append(Parameter(
                        name=p["name"],
                        location=ParamLocation(location),
                        type=p.get("schema", {}).get("type", "string"),
                        required=p.get("required", False),
                        description=p.get("description", "")
                    ))

                # 2. Request body schema
                request_body_schema = {}
                if "requestBody" in details:
                    content = details["requestBody"].get("content", {})
                    if "application/json" in content:
                        request_body_schema = content["application/json"].get("schema", {})

                # 3. Response schema (lấy từ mã 200 OK)
                response_schema = {}
                responses = details.get("responses", {})
                if "200" in responses:
                    content = responses["200"].get("content", {})
                    if "application/json" in content:
                        response_schema = content["application/json"].get("schema", {})

                # 4. Xác định requires_auth (dựa trên security requirements)
                requires_auth = "security" in details and len(details.get("security", [])) > 0

                ep = Endpoint(
                    path=path,
                    method=method,
                    summary=details.get("summary", ""),
                    description=details.get("description", ""),
                    parameters=parameters,
                    request_body_schema=request_body_schema,
                    response_schema=response_schema,
                    requires_auth=requires_auth,
                    tags=details.get("tags", [])
                )
                endpoints.append(ep)

        return endpoints



# ============== 4. Tích hợp với SecurityAnalyzer: chỉ giữ dangerous endpoints + producers ==============
def filter_endpoints_by_security(all_endpoints: List[Endpoint],
                                 security_analyzer: SecurityAnalyzer,
                                 resolver: DependencyResolver) -> List[Endpoint]:
    """
    1. Dùng SecurityAnalyzer để tìm các endpoint nguy hiểm (có tag).
    2. Với mỗi endpoint nguy hiểm, tìm tất cả producer (bao gồm cả endpoint không nguy hiểm).
    3. Trả về tập hợp (dangerous + producers).
    """
    findings = security_analyzer.analyze(all_endpoints)
    dangerous = [f["endpoint"] for f in findings]

    # Tìm producers cho từng dangerous endpoint
    needed_producers = set()
    for ep in dangerous:
        producers = resolver.find_producers(ep, all_endpoints, max_depth=2)
        needed_producers.update(producers)

    final_set = set(dangerous) | needed_producers
    return list(final_set)


# ============== 5. Ví dụ sử dụng ==============
def main():
    # Kiểm tra file tồn tại
    if not os.path.exists(SWAGGER_DEFAULT_PATH):
        print(f"❌ File Swagger không tồn tại: {SWAGGER_DEFAULT_PATH}")
        print("👉 Hãy set biến môi trường SWAGGER_DEFAULT_PATH hoặc tạo file ./swagger.json")
        return

    # Đọc endpoints từ Swagger
    endpoints = load_swagger_to_endpoints(SWAGGER_DEFAULT_PATH)
    print(f"✅ Đã tải {len(endpoints)} endpoints từ {SWAGGER_DEFAULT_PATH}")

    # Khởi tạo DependencyResolver với từ điển đồng nghĩa
    alias_dict = {
        "userId": ["user", "account", "participant", "member", "customer"],
        "orderId": ["order", "cart", "transaction", "purchase"],
        "conversationId": ["conversation", "chat", "room", "group"],
        "productId": ["product", "item", "sku"],
        "roleId": ["role", "permission", "group"]
    }
    resolver = DependencyResolver(alias_dict=alias_dict)

    # Phân tích bảo mật (SecurityAnalyzer của bạn)
    security_analyzer = SecurityAnalyzer()

    # Lọc: chỉ giữ các endpoint nguy hiểm + tất cả producer liên quan
    filtered_endpoints = filter_endpoints_by_security(endpoints, security_analyzer, resolver)
    print(f"🔍 Sau lọc: {len(filtered_endpoints)} endpoints (dangerous + producers)")

    # In danh sách đã lọc
    print("\n📋 DANH SÁCH ENDPOINT ĐƯỢC GIỮ LẠI:")
    for ep in filtered_endpoints:
        print(f"  {ep.method} {ep.path}")

    # Gom cụm theo quan hệ output-input
    clusters = resolver.cluster_by_parameter(filtered_endpoints)
    print(f"\n🧩 CỤM (CHUỖI TẤN CÔNG) - Tổng số: {len(clusters)}")

    for i, cluster in enumerate(clusters, 1):
        print(f"\n🔹 Cluster {i}:")
        for ep in cluster:
            print(f"    → {ep.method} {ep.path}")


if __name__ == "__main__":
    main()
