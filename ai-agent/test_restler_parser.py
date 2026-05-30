from app.core.restler_parser import (
    build_dependency_graph_from_restler,
    build_setup_body,
    variable_name_to_semantic_key,
)

# Test 1: semantic key conversion
tests = [
    ("_Category_post_id",       "category.id"),
    ("_Order_post_id",          "order.id"),
    ("_Employee_post_id",       "employee.id"),
    ("_PurchaseOrder_post_id",  "purchaseorder.id"),
    ("_api_auth_login_post_token", "api_auth_login.token"),
]
print("=== Test variable_name_to_semantic_key ===")
for var, expected in tests:
    result = variable_name_to_semantic_key(var)
    status = "OK" if result == expected else f"FAIL (got {result!r})"
    print(f"  {var!r} -> {result!r} [{status}]")

# Test 2: build dependency graph
print("\n=== Test build_dependency_graph_from_restler ===")
graph = build_dependency_graph_from_restler("Compile/grammar.json", "Compile/dependencies.json")
print(f"  Nodes: {graph['stats']['total_nodes']}")
print(f"  Source: {graph['stats']['source']}")
print(f"  First 5 execution_order: {graph['execution_order'][:5]}")

# Test 3: inspect POST:/Category node
print("\n=== Test POST:/Category node ===")
cat_node = graph["graph"]["nodes"].get("POST:/Category")
if cat_node:
    print(f"  body_schema: {cat_node['body_schema']}")
    print(f"  produces: {cat_node['produces']}")
    print(f"  consumes: {cat_node['consumes']}")
else:
    print("  WARN: POST:/Category not found in graph!")

# Test 4: inspect DELETE:/Category/{id} node
print("\n=== Test DELETE:/Category/{id} node ===")
del_node = graph["graph"]["nodes"].get("DELETE:/Category/{id}")
if del_node:
    print(f"  path_schema: {del_node['path_schema']}")
    print(f"  consumes: {del_node['consumes']}")
else:
    print("  WARN: DELETE:/Category/{id} not found in graph!")

# Test 5: build_setup_body
print("\n=== Test build_setup_body ===")
if cat_node:
    body = build_setup_body(cat_node)
    print(f"  POST:/Category body: {body}")

print("\nAll tests passed!")
