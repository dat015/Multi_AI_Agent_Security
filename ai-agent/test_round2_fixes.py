"""
Test Round 2 fixes (no hardcode):
A. build_setup_body() dynamic field: {{category.id_A}} thay vi {{category.id}}
B. build_setup_body() unique string field: append {{$timestamp}}-{{$role}}
C. _sanitize_plan() auto-inject Content-Type cho POST/PUT/PATCH khi co body
D. _sanitize_plan() thay limit=1000000 bang {{$large_int}}
E. VariableStore resolve {{$large_int}} tu constant LARGE_INT_VALUE
"""
import sys
sys.path.insert(0, ".")

# ─── Test A: dynamic field phai co suffix _A ───────────────────────────
print("=== Test A: build_setup_body() dynamic field suffix _A ===")
from app.core.restler_parser import build_setup_body

# Node_info gia lap POST:/Product co consumes categoryid tu body
node_info_product = {
    "body_schema": {
        "categoryid": {"type": "integer", "default": None},
        "name":       {"type": "string",  "default": "Test-Product-001"},
    },
    "consumes": [
        {
            "location":   "Body",
            "param":      "categoryid",
            "semantic_key": "category.id",
        }
    ],
}
body_a = build_setup_body(node_info_product)
assert body_a is not None, "FAIL A: body is None"
assert body_a.get("categoryid") == "{{category.id_A}}", (
    f"FAIL A: categoryid = {body_a.get('categoryid')!r}, expected '{{{{category.id_A}}}}'"
)
print(f"  PASS: categoryid = {body_a['categoryid']}")

# ─── Test B: unique string field phai co {{$timestamp}}-{{$role}} ──────
print("=== Test B: build_setup_body() unique field append tokens ===")

node_info_cat = {
    "body_schema": {
        "name":        {"type": "string",  "default": "Test-Cat-001"},
        "description": {"type": "string",  "default": "Auto-generated"},
        "isactive":    {"type": "boolean", "default": True},
    },
    "consumes": [],
}
body_b = build_setup_body(node_info_cat)
assert body_b is not None, "FAIL B: body is None"
# 'name' is a unique field keyword -> must have token appended
assert "{{$timestamp}}" in body_b.get("name", ""), (
    f"FAIL B: 'name' should contain {{{{$timestamp}}}}, got: {body_b.get('name')!r}"
)
assert "{{$role}}" in body_b.get("name", ""), (
    f"FAIL B: 'name' should contain {{{{$role}}}}, got: {body_b.get('name')!r}"
)
# description is NOT a unique keyword -> keep original
assert body_b.get("description") == "Auto-generated", (
    f"FAIL B: 'description' should be unchanged, got: {body_b.get('description')!r}"
)
# boolean should be unchanged
assert body_b.get("isactive") is True, f"FAIL B: isactive wrong: {body_b.get('isactive')}"
print(f"  PASS: name = {body_b['name']!r}")
print(f"  PASS: description = {body_b['description']!r} (unchanged)")

# code field also needs uniqueness
node_info_code = {
    "body_schema": {
        "code": {"type": "string", "default": "CODE-001"},
        "price": {"type": "number", "default": 9.99},
    },
    "consumes": [],
}
body_code = build_setup_body(node_info_code)
assert "{{$timestamp}}" in body_code.get("code", ""), (
    f"FAIL B2: 'code' should contain timestamp token, got: {body_code.get('code')!r}"
)
assert body_code.get("price") == 9.99, "FAIL B2: price should be unchanged"
print(f"  PASS: code = {body_code['code']!r}")
print(f"  PASS: price = {body_code['price']!r} (unchanged)")

# ─── Test C: _sanitize_plan auto-inject Content-Type ──────────────────
print("=== Test C: _sanitize_plan() auto-inject Content-Type ===")
from app.agents.planning_agent import _sanitize_plan, TestPlan, TestStep

# POST plan WITHOUT Content-Type in headers -> should be injected
plan_c = TestPlan(
    node_id="POST:/Employee",
    endpoint="/Employee",
    method="POST",
    is_attack=True,
    vuln_type="API3",
    test_steps=[
        TestStep(
            step=1,
            description="Mass assignment test",
            headers={"Authorization": "Bearer {{login.token_A}}"},
            body={"name": "test", "isAdmin": True},
            expected_indicator="status_code in [200, 201]",
        )
    ],
)
fixed_c = _sanitize_plan(plan_c, {})
step_c = fixed_c.test_steps[0]
assert step_c.headers.get("Content-Type") == "application/json", (
    f"FAIL C: Content-Type not injected, headers = {step_c.headers}"
)
print(f"  PASS (POST with body): Content-Type injected -> {step_c.headers.get('Content-Type')!r}")

# GET plan -> Content-Type should NOT be injected (no body typically)
plan_c2 = TestPlan(
    node_id="GET:/Category",
    endpoint="/Category",
    method="GET",
    is_attack=True,
    vuln_type="API1",
    test_steps=[
        TestStep(
            step=1,
            description="BOLA test",
            headers={"Authorization": "Bearer {{login.token_A}}"},
            body=None,
            expected_indicator="status_code == 403",
        )
    ],
)
fixed_c2 = _sanitize_plan(plan_c2, {})
step_c2 = fixed_c2.test_steps[0]
assert "Content-Type" not in step_c2.headers, (
    f"FAIL C2: Content-Type should NOT be in GET headers, got {step_c2.headers}"
)
print(f"  PASS (GET, no body): Content-Type NOT injected")

# PUT plan WITH Content-Type already -> should NOT duplicate
plan_c3 = TestPlan(
    node_id="PUT:/Category/{id}",
    endpoint="/Category/{id}",
    method="PUT",
    is_attack=True,
    vuln_type="API1",
    test_steps=[
        TestStep(
            step=1,
            description="BOLA update",
            headers={
                "Authorization": "Bearer {{login.token_A}}",
                "Content-Type": "application/json",
            },
            body={"name": "hijacked"},
            expected_indicator="status_code == 403",
        )
    ],
)
fixed_c3 = _sanitize_plan(plan_c3, {})
step_c3 = fixed_c3.test_steps[0]
ct_vals = [v for k, v in step_c3.headers.items() if k == "Content-Type"]
assert len(ct_vals) == 1, f"FAIL C3: duplicate Content-Type? headers = {step_c3.headers}"
print(f"  PASS (PUT already has Content-Type): no duplicate")

# ─── Test D: _sanitize_plan thay large int trong pagination param ─────
print("=== Test D: _sanitize_plan() replace large int in pagination params ===")
from app.core.constants import LARGE_INT_THRESHOLD

plan_d = TestPlan(
    node_id="GET:/Category",
    endpoint="/Category",
    method="GET",
    is_attack=True,
    vuln_type="API4",
    test_steps=[
        TestStep(
            step=1,
            description="Rate limit test",
            query_params={"limit": 1_000_000, "page": 1},
            expected_indicator="status_code == 429",
        )
    ],
)
fixed_d = _sanitize_plan(plan_d, {})
qp_d = fixed_d.test_steps[0].query_params
assert qp_d.get("limit") == "{{$large_int}}", (
    f"FAIL D: limit should be {{{{$large_int}}}}, got {qp_d.get('limit')!r}"
)
# page=1 is NOT > LARGE_INT_THRESHOLD -> should be kept
assert qp_d.get("page") == 1, (
    f"FAIL D: page=1 should be unchanged, got {qp_d.get('page')!r}"
)
print(f"  PASS: limit=1000000 -> {qp_d['limit']!r}  (threshold={LARGE_INT_THRESHOLD})")
print(f"  PASS: page=1 unchanged -> {qp_d['page']!r}")

# Also test 'pageSize' and 'size' variants
plan_d2 = TestPlan(
    node_id="GET:/Product",
    endpoint="/Product",
    method="GET",
    is_attack=True,
    vuln_type="API4",
    test_steps=[
        TestStep(
            step=1,
            description="Rate limit test 2",
            query_params={"pageSize": "999999", "size": 50000},
            expected_indicator="status_code == 429",
        )
    ],
)
fixed_d2 = _sanitize_plan(plan_d2, {})
qp_d2 = fixed_d2.test_steps[0].query_params
assert qp_d2.get("pageSize") == "{{$large_int}}", (
    f"FAIL D2: pageSize should be {{{{$large_int}}}}, got {qp_d2.get('pageSize')!r}"
)
assert qp_d2.get("size") == "{{$large_int}}", (
    f"FAIL D2: size=50000 should be {{{{$large_int}}}}, got {qp_d2.get('size')!r}"
)
print(f"  PASS: pageSize='999999' -> {qp_d2['pageSize']!r}")
print(f"  PASS: size=50000 -> {qp_d2['size']!r}")

# ─── Test E: VariableStore resolve {{$large_int}} tu constant ─────────
print("=== Test E: VariableStore resolve {{$large_int}} ===")
from app.agents.execution_agent import VariableStore
from app.core.constants import LARGE_INT_VALUE

config = {
    "target": {"base_url": "http://localhost"},
    "users": [
        {"role": "attacker", "email": "a@a.com", "password": "p"},
    ],
}
vs = VariableStore(config)

result_li = vs.resolve_string("{{$large_int}}", role="attacker")
assert result_li == str(LARGE_INT_VALUE), (
    f"FAIL E: got {result_li!r}, expected {str(LARGE_INT_VALUE)!r}"
)
print(f"  PASS: {{{{$large_int}}}} -> {result_li!r}  (LARGE_INT_VALUE={LARGE_INT_VALUE})")

# Also in query_params payload
payload_e = vs.resolve_payload({"limit": "{{$large_int}}", "page": "1"}, role="attacker")
assert payload_e["limit"] == str(LARGE_INT_VALUE)
assert payload_e["page"] == "1"
print(f"  PASS: resolve_payload limit -> {payload_e['limit']!r}")

print()
print("=" * 55)
print("ALL ROUND-2 TESTS PASSED")
print("=" * 55)
