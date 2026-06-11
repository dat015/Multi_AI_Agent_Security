"""
Test các fix mới (không hardcode):
A. [LARGE_PAYLOAD] được thay trong _sanitize_plan
B. null path_params/query_params normalize về {}
C. hardcode integer ID trong query_params → placeholder suy ra từ tên field
D. VariableStore resolve {{$timestamp}} và {{$role}}
E. VariableStore resolve [LARGE_PAYLOAD]
F. _build_setup_headers trả về Authorization + Content-Type từ convention
"""
import sys
import time

sys.path.insert(0, ".")

# ─── Test A: [LARGE_PAYLOAD] được thay trong _sanitize_plan ─────────
print("=== Test A: [LARGE_PAYLOAD] in _sanitize_plan ===")
from app.agents.planning_agent import _sanitize_plan, TestPlan, TestStep
from app.core.constants import LARGE_PAYLOAD_SIZE_BYTES

plan_a = TestPlan(
    node_id="GET:/items",
    endpoint="/items",
    method="GET",
    is_attack=True,
    vuln_type="API4",
    test_steps=[
        TestStep(
            step=1,
            description="Large payload test",
            query_params={"dummy": "[LARGE_PAYLOAD]"},
            expected_indicator="should reject 414",
        )
    ],
)
fixed_a = _sanitize_plan(plan_a, {})
qp_a = fixed_a.test_steps[0].query_params
expected_len = LARGE_PAYLOAD_SIZE_BYTES
assert qp_a["dummy"] == "A" * expected_len, (
    f"FAIL A: got len={len(qp_a['dummy'])}, expected {expected_len}"
)
print(f"  PASS: [LARGE_PAYLOAD] → {len(qp_a['dummy'])} chars (constant={LARGE_PAYLOAD_SIZE_BYTES})")


# ─── Test B: null path_params/query_params normalize về {} ──────────
print("=== Test B: null normalize ===")
plan_b = TestPlan(
    node_id="GET:/items",
    endpoint="/items",
    method="GET",
    is_attack=True,
    vuln_type="API1",
    test_steps=[
        TestStep(
            step=1,
            description="null params test",
            path_params=None,
            query_params=None,
            expected_indicator="ok",
        )
    ],
)
fixed_b = _sanitize_plan(plan_b, {})
step_b = fixed_b.test_steps[0]
assert step_b.path_params == {}, f"FAIL B path_params: got {step_b.path_params!r}"
assert step_b.query_params == {}, f"FAIL B query_params: got {step_b.query_params!r}"
print("  PASS: None path_params/query_params → {}")


# ─── Test C: hardcode integer ID trong query_params → placeholder ────
print("=== Test C: hardcode ID heuristic ===")
plan_c = TestPlan(
    node_id="GET:/Order",
    endpoint="/Order",
    method="GET",
    is_attack=True,
    vuln_type="API1",
    test_steps=[
        TestStep(
            step=1,
            description="hardcode customerId",
            query_params={"customerId": 2, "status": "active"},
            expected_indicator="ok",
        )
    ],
)
# consumes_mapping không chứa customerId → heuristic suy ra
fixed_c = _sanitize_plan(plan_c, {})
qp_c = fixed_c.test_steps[0].query_params
assert qp_c.get("customerId") == "{{customer.id_B}}", (
    f"FAIL C: customerId got {qp_c.get('customerId')!r}"
)
# status là string không phải ID → giữ nguyên
assert qp_c.get("status") == "active", f"FAIL C: status got {qp_c.get('status')!r}"
print(f"  PASS: customerId=2 → {qp_c['customerId']}, status preserved={qp_c['status']}")

# Thêm test với supplierId=999 (string digit)
plan_c2 = TestPlan(
    node_id="GET:/PurchaseOrder",
    endpoint="/PurchaseOrder",
    method="GET",
    is_attack=True,
    vuln_type="API1",
    test_steps=[
        TestStep(
            step=1,
            description="hardcode supplierId string digit",
            query_params={"supplierId": "999"},
            expected_indicator="ok",
        )
    ],
)
fixed_c2 = _sanitize_plan(plan_c2, {})
qp_c2 = fixed_c2.test_steps[0].query_params
assert qp_c2.get("supplierId") == "{{supplier.id_B}}", (
    f"FAIL C2: supplierId got {qp_c2.get('supplierId')!r}"
)
print(f"  PASS: supplierId='999' → {qp_c2['supplierId']}")

# Test với consumes_mapping có customer → dùng placeholder từ mapping thay vì fallback
plan_c3 = TestPlan(
    node_id="GET:/Order",
    endpoint="/Order",
    method="GET",
    is_attack=True,
    vuln_type="API1",
    test_steps=[
        TestStep(
            step=1,
            description="hardcode with consumes_mapping",
            query_params={"customerId": 5},
            expected_indicator="ok",
        )
    ],
)
consumes_c3 = {
    "customerId": {
        "semantic_key": "customer.id",
        "location": "Query",
        "allowed_placeholders": ["{{customer.id_A}}", "{{customer.id_B}}"],
    }
}
fixed_c3 = _sanitize_plan(plan_c3, consumes_c3)
qp_c3 = fixed_c3.test_steps[0].query_params
# Khi trong consumes_mapping → dùng allowed_placeholders[0]
assert qp_c3.get("customerId") == "{{customer.id_A}}", (
    f"FAIL C3 (consumes_mapping): customerId got {qp_c3.get('customerId')!r}"
)
print(f"  PASS: customerId=5 + consumes_mapping → {qp_c3['customerId']}")


# ─── Test D: VariableStore resolve {{$timestamp}} và {{$role}} ───────
print("=== Test D: {{$timestamp}} and {{$role}} tokens ===")
from app.agents.execution_agent import VariableStore

config = {
    "target": {"base_url": "http://localhost"},
    "users": [
        {"role": "attacker", "email": "a@a.com", "password": "p"},
        {"role": "victim", "email": "v@v.com", "password": "p"},
    ],
}
vs = VariableStore(config)

# Test $timestamp: kết quả phải là integer trong khoảng [now-2, now+2]
before = int(time.time())
result_ts = vs.resolve_string("ORD-{{$timestamp}}-{{$role}}", role="attacker")
after = int(time.time())

parts = result_ts.split("-")
ts_val = int(parts[1])
assert before <= ts_val <= after, (
    f"FAIL D timestamp out of range: {ts_val} not in [{before},{after}]"
)
assert result_ts.endswith("-attacker"), f"FAIL D role: got {result_ts!r}"
print(f"  PASS (attacker): '{result_ts}'")

# victim role
result_victim = vs.resolve_string("CODE-{{$timestamp}}-{{$role}}", role="victim")
assert result_victim.endswith("-victim"), f"FAIL D victim: got {result_victim!r}"
print(f"  PASS (victim): '{result_victim}'")

# $timestamp trong resolve_payload dict
before2 = int(time.time())
payload = vs.resolve_payload(
    {"orderNumber": "ORD-{{$timestamp}}-{{$role}}", "name": "test"},
    role="attacker",
)
after2 = int(time.time())
parts2 = payload["orderNumber"].split("-")
ts2 = int(parts2[1])
assert before2 <= ts2 <= after2
assert payload["orderNumber"].endswith("-attacker")
print(f"  PASS (resolve_payload): {payload['orderNumber']}")


# ─── Test E: VariableStore resolve [LARGE_PAYLOAD] ──────────────────
print("=== Test E: [LARGE_PAYLOAD] in VariableStore ===")
result_lp = vs.resolve_string("[LARGE_PAYLOAD]", role="attacker")
assert len(result_lp) == LARGE_PAYLOAD_SIZE_BYTES, (
    f"FAIL E: len={len(result_lp)}, expected={LARGE_PAYLOAD_SIZE_BYTES}"
)
assert result_lp == "A" * LARGE_PAYLOAD_SIZE_BYTES
print(f"  PASS: [LARGE_PAYLOAD] → {len(result_lp)} chars (constant={LARGE_PAYLOAD_SIZE_BYTES})")

# [LARGE_PAYLOAD] trong payload dict
payload_lp = vs.resolve_payload({"dummy": "[LARGE_PAYLOAD]"}, role="attacker")
assert len(payload_lp["dummy"]) == LARGE_PAYLOAD_SIZE_BYTES
print(f"  PASS (resolve_payload): dummy → {len(payload_lp['dummy'])} chars")


# ─── Test F: _build_setup_headers — không hardcode ──────────────────
print("=== Test F: _build_setup_headers ===")
from app.agents.planning_agent import _build_setup_headers

# Với body
h_with_body = _build_setup_headers({"name": "test"})
assert "Authorization" in h_with_body
assert "{{login.token_A}}" in h_with_body["Authorization"], (
    f"FAIL F auth: {h_with_body['Authorization']!r}"
)
assert h_with_body.get("Content-Type") == "application/json", (
    f"FAIL F content-type: {h_with_body!r}"
)
print(f"  PASS (with body): {h_with_body}")

# Không có body (GET/DELETE)
h_no_body = _build_setup_headers(None)
assert "Authorization" in h_no_body
assert "Content-Type" not in h_no_body, f"FAIL F: Content-Type should be absent for no-body, got {h_no_body}"
print(f"  PASS (no body): {h_no_body}")


print()
print("=" * 50)
print("ALL NEW TESTS PASSED")
print("=" * 50)
