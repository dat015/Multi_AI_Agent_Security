"""
Test plan_for_endpoint với node_info từ RESTler parser
Không cần LLM vì đây là setup step (is_attack=False)
"""
import json

# Mock node_info từ RestlerParser (POST:/Category)
cat_node = {
    "node_id": "POST:/Category",
    "method": "POST",
    "path": "/Category",
    "body_schema": {
        "name":        {"type": "String", "default": "Test-Item-001"},
        "parentid":    {"type": "Int",    "default": 0},
        "description": {"type": "String", "default": "Auto-generated for testing"},
        "isactive":    {"type": "Bool",   "default": True},
    },
    "path_schema": {},
    "consumes": [],
    "produces": [
        {
            "response_path":  ["id"],
            "variable_name":  "_Category_post_id",
            "semantic_key":   "category.id",
            "type":           "Int",
        }
    ],
    "parameters":   [],
    "request_body": {},
    "tags":         [],
    "summary":      "",
}

# Mock node_info từ RestlerParser (DELETE:/Category/{id})
del_node = {
    "node_id": "DELETE:/Category/{id}",
    "method": "DELETE",
    "path": "/Category/{id}",
    "body_schema": {},
    "path_schema": {
        "id": {
            "type": "Int",
            "variable_name": "_Category_post_id",
            "semantic_key": "category.id",
        }
    },
    "consumes": [
        {
            "location":          "Path",
            "param":             "id",
            "variable_name":     "_Category_post_id",
            "semantic_key":      "category.id",
            "producer_endpoint": "/Category",
            "producer_method":   "POST",
        }
    ],
    "produces": [],
    "parameters":   [],
    "request_body": {},
    "tags":         [],
    "summary":      "",
}

# Test build_setup_body directly
from app.core.restler_parser import build_setup_body

print("=== build_setup_body(POST:/Category) ===")
body = build_setup_body(cat_node)
print(json.dumps(body, indent=2, ensure_ascii=False))

print("\n=== build_setup_body(DELETE:/Category/{id}) ===")
body_del = build_setup_body(del_node)
print(json.dumps(body_del, indent=2, ensure_ascii=False))

# Test plan_for_endpoint (setup, no LLM)
from app.agents.planning_agent import plan_for_endpoint

print("\n=== plan_for_endpoint(POST:/Category, no recon_item) ===")
users = [
    {"role": "admin"},
    {"role": "attacker"},
    {"role": "victim"},
]
plans = plan_for_endpoint("POST:/Category", cat_node, recon_item=None, users=users)
print(f"  Plans count: {len(plans)}")
if plans:
    p = plans[0]
    print(f"  is_attack: {p['is_attack']}")
    print(f"  vuln_type: {p['vuln_type']}")
    steps = p.get("test_steps", [])
    print(f"  Steps count: {len(steps)}")
    if steps:
        step = steps[0]
        print(f"  step run_as: {step.get('run_as')}")
        print(f"  step body: {json.dumps(step.get('body'), ensure_ascii=False)}")
        print(f"  step headers: {step.get('headers')}")
        print(f"  step expected: {step.get('expected_indicator')}")

print("\nAll plan_for_endpoint tests passed!")
