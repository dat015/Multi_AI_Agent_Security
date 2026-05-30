"""
app/core/restler_parser.py

Đọc output của RESTler Compile (grammar.json + dependencies.json) và
chuyển đổi thành dependency_graph format tương thích SystemState.

Thay thế DependencyResolver cũ (string-matching, không có faker data).

RESTler đã giải quyết:
  ✅ Execution order (topo-sorted)
  ✅ Producer-consumer links chính xác (không cần heuristic)
  ✅ Field schema + default values (Fuzzable.defaultValue)
  ✅ Response extraction path (writerVariables.accessPathParts)
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════
# FAKER TABLE — giá trị mặc định ngữ nghĩa theo tên field
# ══════════════════════════════════════════════════════════════════════

# Key: field name (lowercase, stripped dấu _/-)
# Value: giá trị mặc định phù hợp với API
FIELD_NAME_FAKER: dict[str, Any] = {
    "email":          "testuser@example.com",
    "password":       "Test@1234",
    "username":       "testuser001",
    "firstname":      "John",
    "lastname":       "Doe",
    "fullname":       "John Doe",
    "name":           "Test-Item-001",
    "displayname":    "Test Item",
    "description":    "Auto-generated for testing",
    "address":        "123 Test Street",
    "phone":          "0901234567",
    "phonenumber":    "0901234567",
    "mobile":         "0901234567",
    "code":           "CODE-001",
    "taxcode":        "TAX-001",
    "taxnumber":      "TAX-001",
    "ordernumber":    "ORD-001",
    "invoicenumber":  "INV-001",
    "notes":          "auto note",
    "note":           "auto note",
    "reason":         "test reason",
    "comment":        "auto comment",
    "role":           "user",
    "status":         "active",
    "isactive":       True,
    "isadmin":        False,
    "enabled":        True,
    "title":          "Test Title",
    "subject":        "Test Subject",
    "content":        "Test content body",
    "url":            "https://example.com",
    "imageurl":       "https://example.com/image.png",
    "updatedat":      "2024-01-01T00:00:00Z",
    "createdat":      "2024-01-01T00:00:00Z",
    "createdby":      "system",
    "updatedby":      "system",
    "startdate":      "2024-01-01",
    "enddate":        "2024-12-31",
    "orderdate":      "2024-01-01T00:00:00Z",
    "duedate":        "2024-12-31",
    "birthdate":      "1990-01-01",
    "quantity":       1,
    "price":          10.0,
    "amount":         100.0,
    "totalamount":    100.0,
    "grandtotal":     100.0,
    "taxamount":      10.0,
    "discountamount": 0.0,
    "parentid":       0,
    "parentcategory": 0,
    "sortorder":      0,
    "priority":       1,
    "maxquantity":    100,
    "minquantity":    0,
    "updatedby":      "system",
}

# Fallback theo kiểu dữ liệu RESTler
TYPE_DEFAULTS: dict[str, Any] = {
    "String":   "fuzzstring",
    "Int":      1,
    "Bool":     True,
    "Number":   1.23,
    "DateTime": "2024-01-01T00:00:00Z",
    "Date":     "2024-01-01",
    "Uuid":     "566048da-ed19-4cd3-8e0a-b7e0e1ec4d72",
    "Object":   {},
    "Array":    [],
}


# ══════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════

def variable_name_to_semantic_key(var_name: str) -> str:
    """
    Chuyển đổi tên biến RESTler → semantic key dùng trong VariableStore.

    Convention RESTler: _{Resource}_{method}_{field}
    VD:
        _Category_post_id       → category.id
        _Order_post_id          → order.id
        _PurchaseOrder_post_id  → purchaseorder.id
        _Employee_post_id       → employee.id
    """
    clean = var_name.lstrip("_")
    parts = clean.split("_")
    if len(parts) < 3:
        return clean.lower()

    # parts[-1] = field (id, token, name, ...)
    # parts[-2] = method (post, get, put, ...)
    # parts[:-2] = resource name (có thể nhiều từ: ["Purchase", "Order"])
    resource = "_".join(parts[:-2]).lower()   # "purchaseorder" hoặc "category"
    field    = parts[-1].lower()              # "id"
    return f"{resource}.{field}"


def coerce_to_type(value: Any, type_str: str) -> Any:
    """Ép kiểu value sang đúng Python type."""
    try:
        if type_str == "Int":    return int(value)
        if type_str == "Bool":   return str(value).lower() in ("true", "1", "yes")
        if type_str == "Number": return float(value)
    except (ValueError, TypeError):
        pass
    return value


def get_default_for_field(field_name: str, type_str: str, restler_default: str | None = None) -> Any:
    """
    Chọn giá trị mặc định thông minh cho 1 field:
      1. Semantic lookup (FIELD_NAME_FAKER theo tên field)
      2. RESTler default (nếu không phải "fuzzstring")
      3. TYPE_DEFAULTS theo kiểu dữ liệu

    field_name: tên field gốc (VD: "isactive", "parentid", "email")
    type_str:   "String" | "Int" | "Bool" | "Number" | "DateTime" | ...
    """
    # Normalize key để lookup
    fname_key = field_name.lower().replace("-", "").replace("_", "")

    # 1. Semantic lookup
    for key, val in FIELD_NAME_FAKER.items():
        if fname_key == key.lower().replace("_", ""):
            return coerce_to_type(val, type_str)

    # 2. RESTler default (bỏ qua "fuzzstring" vì quá generic)
    if restler_default is not None and str(restler_default) != "fuzzstring":
        return coerce_to_type(restler_default, type_str)

    # 3. Type default
    return TYPE_DEFAULTS.get(type_str, "test-value")


# ══════════════════════════════════════════════════════════════════════
# GRAMMAR.JSON PARSERS
# ══════════════════════════════════════════════════════════════════════

def _extract_fuzzable_fields(data: Any, result: dict, prefix: str = "") -> None:
    """
    Duyệt đệ quy cấu trúc bodyParameters/queryParameters để lấy:
      - Fuzzable fields: {name: {type, default}}
      - DynamicObject fields: {name: {type, variable_name, is_dynamic: True}}

    Xử lý:
      - LeafNode → leaf field trực tiếp
      - InternalNode → nested object, đệ quy xuống children
      - list/dict → tiếp tục duyệt
    """
    if isinstance(data, dict):
        if "LeafNode" in data:
            leaf = data["LeafNode"]
            name = leaf.get("name", "")
            if not name:
                return
            full_name = f"{prefix}.{name}" if prefix else name
            payload = leaf.get("payload", {})

            if "Fuzzable" in payload:
                fuzz = payload["Fuzzable"]
                result[full_name] = {
                    "type":    fuzz.get("primitiveType", "String"),
                    "default": fuzz.get("defaultValue", "fuzzstring"),
                }
            elif "DynamicObject" in payload:
                dyn = payload["DynamicObject"]
                result[full_name] = {
                    "type":          dyn.get("primitiveType", "Int"),
                    "default":       None,
                    "variable_name": dyn.get("variableName", ""),
                    "is_dynamic":    True,
                }
            # Nếu là Constant hoặc kiểu khác → bỏ qua (không cần test)

        elif "InternalNode" in data:
            # InternalNode = [metadata_dict, [children_list]]
            internal = data["InternalNode"]
            if isinstance(internal, list) and len(internal) == 2:
                meta, children = internal
                node_name = meta.get("name", "")
                # Nếu meta.name rỗng (root object), không thêm prefix
                if node_name:
                    new_prefix = f"{prefix}.{node_name}" if prefix else node_name
                else:
                    new_prefix = prefix
                if isinstance(children, list):
                    for child in children:
                        _extract_fuzzable_fields(child, result, new_prefix)
        else:
            # Dict thông thường → duyệt values
            for val in data.values():
                _extract_fuzzable_fields(val, result, prefix)

    elif isinstance(data, list):
        for item in data:
            _extract_fuzzable_fields(item, result, prefix)


def parse_body_schema(body_parameters: list) -> dict:
    """
    Parse bodyParameters từ grammar.json.

    Returns:
        {
          "name":     {"type": "String", "default": "fuzzstring"},
          "parentid": {"type": "Int",    "default": 1},
          "isactive": {"type": "Bool",   "default": True},
          ...
          "someId":   {"type": "Int", "variable_name": "_Order_post_id",
                       "default": None, "is_dynamic": True},
        }
    """
    raw: dict = {}
    _extract_fuzzable_fields(body_parameters, raw)
    return raw


def _extract_dynamic_objects(data: Any, found: list) -> None:
    """Đệ quy tìm tất cả DynamicObject dict trong cấu trúc JSON."""
    if isinstance(data, dict):
        if "DynamicObject" in data:
            found.append(data["DynamicObject"])
        for val in data.values():
            _extract_dynamic_objects(val, found)
    elif isinstance(data, list):
        for item in data:
            _extract_dynamic_objects(item, found)


def parse_path_dynamic_vars(path: list) -> list[dict]:
    """
    Tìm DynamicObject trong path array của grammar.json request.

    Returns:
        [{"variable_name": "_Category_post_id", "type": "Int", "semantic_key": "category.id"}]
    """
    found: list[dict] = []
    _extract_dynamic_objects(path, found)
    result = []
    for dyn in found:
        var_name = dyn.get("variableName", "")
        if var_name:
            result.append({
                "variable_name": var_name,
                "type":          dyn.get("primitiveType", "Int"),
                "semantic_key":  variable_name_to_semantic_key(var_name),
            })
    return result


def parse_writer_vars(dependency_data: dict) -> list[dict]:
    """
    Đọc writerVariables từ dependencyData.responseParser.
    Đây là thông tin về field nào cần extract từ response sau khi gọi API.

    RESTler format:
        "writerVariables": [{
          "requestId": {"endpoint": "/Category", "method": "Post"},
          "accessPathParts": {"path": ["id"]},
          "primitiveType": "Int",
          "kind": "BodyResponseProperty"
        }]

    Returns:
        [{
          "response_path":  ["id"],
          "variable_name":  "_Category_post_id",
          "semantic_key":   "category.id",
          "type":           "Int",
        }]
    """
    if not dependency_data:
        return []

    writer_vars = (
        dependency_data
        .get("responseParser", {})
        .get("writerVariables", [])
    )
    result = []

    for wv in writer_vars:
        req_id     = wv.get("requestId", {})
        endpoint   = req_id.get("endpoint", "")
        method     = req_id.get("method", "Post").lower()
        path_parts = wv.get("accessPathParts", {}).get("path", [])
        field_name = path_parts[-1] if path_parts else "id"

        # Xây variable_name theo convention RESTler: _<Resource>_<method>_<field>
        # "/Category" → "Category", "/api/auth/login" → "api_auth_login"
        resource = endpoint.strip("/").replace("/", "_")
        var_name = f"_{resource}_{method}_{field_name}"

        result.append({
            "response_path": path_parts,
            "variable_name": var_name,
            "semantic_key":  variable_name_to_semantic_key(var_name),
            "type":          wv.get("primitiveType", "Int"),
        })

    return result


# ══════════════════════════════════════════════════════════════════════
# TOPO-SORT
# ══════════════════════════════════════════════════════════════════════

def _topo_sort(node_ids: list[str], node_dependencies: dict[str, list[str]]) -> list[str]:
    """
    Kahn's algorithm topo-sort.

    node_dependencies: {node_id: [list of node_ids nó phụ thuộc (phải chạy trước nó)]}

    Returns danh sách node theo thứ tự execution hợp lệ.
    """
    from collections import defaultdict, deque

    # Bước 1: Xây successors: producer → [consumers]
    successors: dict[str, list[str]] = defaultdict(list)
    in_degree:  dict[str, int]       = {n: 0 for n in node_ids}

    for consumer, producers in node_dependencies.items():
        for producer in producers:
            if producer in in_degree and consumer in in_degree and producer != consumer:
                successors[producer].append(consumer)
                in_degree[consumer] += 1

    # Bước 2: Khởi tạo queue với các node không có dependency
    queue: deque[str] = deque(
        sorted(n for n in node_ids if in_degree[n] == 0)
    )
    result: list[str] = []

    while queue:
        node = queue.popleft()
        result.append(node)
        for succ in sorted(successors[node]):
            in_degree[succ] -= 1
            if in_degree[succ] == 0:
                queue.append(succ)

    # Xử lý các node còn lại (vòng lặp hoặc chưa được xử lý)
    remaining = [n for n in node_ids if n not in result]
    if remaining:
        logger.warning(f"[RestlerParser] Cycle / leftover nodes: {remaining}")
        result.extend(sorted(remaining))

    return result


# ══════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

def build_dependency_graph_from_restler(grammar_path: str, deps_path: str) -> dict:
    """
    Parse RESTler Compile output → dependency_graph compatible với SystemState.

    Args:
        grammar_path: đường dẫn Compile/grammar.json
        deps_path:    đường dẫn Compile/dependencies.json

    Returns dict có format:
    {
        "execution_order": ["POST:/Category", "DELETE:/Category/{id}", ...],
        "graph": {
            "nodes": {
                "POST:/Category": {
                    "node_id":     "POST:/Category",
                    "method":      "POST",
                    "path":        "/Category",
                    "body_schema": {
                        "name": {"type": "String", "default": "Test-Item-001"},
                        "parentid": {"type": "Int", "default": 0},
                        ...
                    },
                    "path_schema": {},
                    "consumes": [],
                    "produces": [
                        {
                          "response_path": ["id"],
                          "variable_name": "_Category_post_id",
                          "semantic_key":  "category.id",
                          "type":          "Int"
                        }
                    ],
                    ...
                },
                "DELETE:/Category/{id}": {
                    ...
                    "path_schema": {
                        "id": {"type": "Int", "variable_name": "_Category_post_id",
                               "semantic_key": "category.id"}
                    },
                    "consumes": [{
                        "location":          "Path",
                        "param":             "id",
                        "variable_name":     "_Category_post_id",
                        "semantic_key":      "category.id",
                        "producer_endpoint": "/Category",
                        "producer_method":   "POST",
                    }],
                    "produces": [],
                }
            }
        },
        "stats": {"total_nodes": N, "source": "restler"}
    }
    """
    # ── Load files ──────────────────────────────────────────────────
    logger.info(f"[RestlerParser] Đọc grammar: {grammar_path}")
    logger.info(f"[RestlerParser] Đọc deps:    {deps_path}")

    with open(grammar_path, "r", encoding="utf-8") as f:
        grammar = json.load(f)
    with open(deps_path, "r", encoding="utf-8") as f:
        deps = json.load(f)

    requests      = grammar.get("Requests", [])
    nodes:  dict  = {}
    restler_order: list[str] = []

    for req in requests:
        endpoint  = req["id"]["endpoint"]
        method    = req["id"]["method"].upper()
        node_id   = f"{method}:{endpoint}"

        # ── 1. Track RESTler request order (grammar.json order) ───
        if node_id not in restler_order:
            restler_order.append(node_id)

        # ── 2. Body schema ─────────────────────────────────────────
        raw_body = parse_body_schema(req.get("bodyParameters", []))
        body_schema: dict = {}

        for fname, fdata in raw_body.items():
            if fdata.get("is_dynamic"):
                # Field lấy từ endpoint khác (DynamicObject)
                body_schema[fname] = {
                    "type":          fdata["type"],
                    "default":       None,
                    "variable_name": fdata.get("variable_name", ""),
                    "is_dynamic":    True,
                }
            else:
                # Field tĩnh → tính default thông minh
                body_schema[fname] = {
                    "type":    fdata["type"],
                    "default": get_default_for_field(
                        fname,
                        fdata["type"],
                        fdata.get("default"),
                    ),
                }

        # ── 3. Path dynamic vars ───────────────────────────────────
        path_dynamic = parse_path_dynamic_vars(req.get("path", []))

        # ── 4. Writer vars (produces) ──────────────────────────────
        writer_vars = parse_writer_vars(req.get("dependencyData", {}))

        # ── 5. Enrich với dependencies.json ───────────────────────
        dep_entry = deps.get(endpoint, {}).get(method, {})
        consumes: list[dict] = []

        # Helper nội bộ
        def _make_consume(location: str, consumer_p: str,
                          producer_ep: str, producer_m: str) -> dict | None:
            if not producer_ep:
                return None
            resource = producer_ep.strip("/").replace("/", "_")
            var_name = f"_{resource}_{producer_m.lower()}_id"
            return {
                "location":          location,
                "param":             consumer_p,
                "variable_name":     var_name,
                "semantic_key":      variable_name_to_semantic_key(var_name),
                "producer_endpoint": producer_ep,
                "producer_method":   producer_m.upper(),
            }

        for dep in dep_entry.get("Path", []):
            c = _make_consume("Path",
                              dep.get("consumer_param", ""),
                              dep.get("producer_endpoint", ""),
                              dep.get("producer_method", ""))
            if c:
                consumes.append(c)

        for dep in dep_entry.get("Query", []):
            c = _make_consume("Query",
                              dep.get("consumer_param", ""),
                              dep.get("producer_endpoint", ""),
                              dep.get("producer_method", ""))
            if c:
                consumes.append(c)

        for dep in dep_entry.get("Body", []):
            c = _make_consume("Body",
                              dep.get("consumer_param", ""),
                              dep.get("producer_endpoint", ""),
                              dep.get("producer_method", ""))
            if c:
                consumes.append(c)

        # Cross-check với DynamicObject trong path
        # (đảm bảo không bỏ sót khi dependencies.json thiếu)
        existing_path_params = {c["param"] for c in consumes if c["location"] == "Path"}
        url_path_params = re.findall(r"\{(\w+)\}", endpoint)

        for pdv in path_dynamic:
            for pp in url_path_params:
                if pp not in existing_path_params:
                    consumes.append({
                        "location":          "Path",
                        "param":             pp,
                        "variable_name":     pdv["variable_name"],
                        "semantic_key":      pdv["semantic_key"],
                        "producer_endpoint": "",
                        "producer_method":   "",
                    })
                    existing_path_params.add(pp)

        # ── 6. Path schema (dành cho execution_agent) ──────────────
        path_schema: dict = {}
        for pdv in path_dynamic:
            for pp in url_path_params:
                path_schema[pp] = {
                    "type":          pdv["type"],
                    "variable_name": pdv["variable_name"],
                    "semantic_key":  pdv["semantic_key"],
                }

        # ── 7. Lưu node ───────────────────────────────────────────
        nodes[node_id] = {
            "node_id":     node_id,
            "method":      method,
            "path":        endpoint,
            "body_schema": body_schema,
            "path_schema": path_schema,
            "query_schema": {},
            "consumes":    consumes,
            "produces":    writer_vars,
            # Legacy fields (dùng cho planning_agent prompt context)
            "parameters":    [],
            "request_body":  {},
            "tags":          [],
            "summary":       "",
        }

        logger.debug(
            f"[RestlerParser] {node_id}: "
            f"body={len(body_schema)} fields, "
            f"consumes={len(consumes)}, "
            f"produces={len(writer_vars)}"
        )

    # ── 8. Compute execution_order from dependencies (topo-sort) ──
    # Build: consumer_node_id -> [producer_node_ids]
    node_dependencies: dict[str, list[str]] = {}
    for node_id, node_info in nodes.items():
        producers: set[str] = set()
        for c in node_info.get("consumes", []):
            prod_ep = c.get("producer_endpoint")
            prod_m  = c.get("producer_method")
            if not prod_ep or not prod_m:
                continue
            producer_node_id = f"{str(prod_m).upper()}:{prod_ep}"
            # Only keep edges to nodes we actually have in this grammar.
            if producer_node_id in nodes and producer_node_id != node_id:
                producers.add(producer_node_id)
        node_dependencies[node_id] = sorted(producers)

    execution_order = _topo_sort(list(nodes.keys()), node_dependencies)

    logger.info(
        f"[RestlerParser] Hoàn thành: {len(nodes)} nodes, "
        f"execution_order có {len(execution_order)} bước (topo from dependencies.json)"
    )

    return {
        "execution_order": execution_order,
        "graph": {"nodes": nodes},
        "stats": {
            "total_nodes": len(nodes),
            "source":      "restler",
        },
    }


# ══════════════════════════════════════════════════════════════════════
# SETUP BODY BUILDER — dùng bởi planning_agent
# ══════════════════════════════════════════════════════════════════════

def build_setup_body(node_info: dict) -> dict | None:
    """
    Sinh HTTP request body cụ thể cho setup step dựa trên RESTler body_schema.

    Không cần LLM. Không có template variable cho field tĩnh.
    Chỉ dùng {{semantic_key}} cho field cần ID từ endpoint khác.

    Returns None nếu endpoint không có body.
    """
    body_schema = node_info.get("body_schema", {})
    if not body_schema:
        return None

    # Build lookup: field_name → semantic_key (chỉ cho body dynamic IDs)
    dynamic_by_param: dict[str, str] = {}
    for c in node_info.get("consumes", []):
        if c.get("location") == "Body" and c.get("semantic_key") and c.get("param"):
            dynamic_by_param[c["param"]] = c["semantic_key"]

    body: dict = {}
    for fname, schema in body_schema.items():
        # Bỏ nested fields (prefix.leafname) — sẽ không flat vào body dict
        # Chỉ lấy top-level field (không có dấu chấm)
        if "." in fname:
            # TODO: handle nested body nếu API yêu cầu
            continue

        if fname in dynamic_by_param:
            # Field này cần ID từ endpoint khác → dùng template
            sem_key = dynamic_by_param[fname]
            body[fname] = f"{{{{ {sem_key} }}}}"

        elif schema.get("is_dynamic") and schema.get("variable_name"):
            # Field có DynamicObject payload (referenced từ grammar.json)
            sem_key = variable_name_to_semantic_key(schema["variable_name"])
            body[fname] = f"{{{{ {sem_key} }}}}"

        else:
            # Field tĩnh → dùng default value từ RESTler / FIELD_NAME_FAKER
            body[fname] = schema.get("default")

    return body if body else None


def build_setup_path_params(node_info: dict) -> dict:
    """
    Sinh path_params template cho setup step dựa trên consumes của node.

    VD: PUT:/Category/{id}
        consumes = [{"location": "Path", "param": "id", "semantic_key": "category.id"}]
        → path_params = {"id": "{{ category.id }}"}
    """
    path_params: dict = {}
    for c in node_info.get("consumes", []):
        if c.get("location") == "Path" and c.get("param") and c.get("semantic_key"):
            param    = c["param"]
            sem_key  = c["semantic_key"]
            path_params[param] = f"{{{{ {sem_key} }}}}"
    return path_params


def build_setup_query_params(node_info: dict) -> dict:
    """
    Sinh query_params template cho setup step dựa trên consumes của node.
    """
    query_params: dict = {}
    for c in node_info.get("consumes", []):
        if c.get("location") == "Query" and c.get("param") and c.get("semantic_key"):
            param    = c["param"]
            sem_key  = c["semantic_key"]
            query_params[param] = f"{{{{ {sem_key} }}}}"
    return query_params
