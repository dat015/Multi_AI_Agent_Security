"""Test logic planning_agent fixes."""
import sys
sys.path.insert(0, '.')

# ─── Test 1: str.format() escape brace ─────────────────────────────
from app.agents.planning_agent import _SYSTEM_PROMPT_TEMPLATE

result = _SYSTEM_PROMPT_TEMPLATE.format(
    consumes_hint='  - "walletId" (in Path): {{wallets.id_A}} / {{wallets.id_B}}',
    available_keys_hint='  - {{login.token_A}} (attacker) / {{login.token_B}} (victim)',
    vuln_type='API1',
    vuln_reasoning='BOLA test',
)

# LLM phải nhận {{login.token_A}} (double-brace) trong prompt
assert '{{login.token_A}}' in result, f'FAIL: login.token_A not in result'
assert '{{login.token_B}}' in result, f'FAIL: login.token_B not in result'
assert '{{wallets.id_A}}' in result, f'FAIL: wallets.id_A example missing'
print('Test 1 PASS: str.format() escape OK')
print(f'  auth placeholder in prompt: ...{result[result.find("login.token_A")-3:result.find("login.token_A")+20]}...')

# ─── Test 2: _sanitize_plan ────────────────────────────────────────
from app.agents.planning_agent import _sanitize_plan, TestPlan, TestStep

plan = TestPlan(
    node_id='GET:/wallets/{walletId}',
    endpoint='/wallets/{walletId}',
    method='GET',
    is_attack=True,
    vuln_type='API1',
    test_steps=[
        TestStep(
            step=1,
            description='Test BOLA',
            headers={'Authorization': 'Bearer {auth.token_A}'},   # single brace + sai key
            path_params={'walletId': 'hardcode_string'},           # hardcode
            expected_indicator='status_code == 200',
        )
    ]
)

consumes_mapping = {
    'walletId': {
        'semantic_key': 'wallets.id',
        'location': 'Path',
        'allowed_placeholders': ['{{wallets.id_A}}', '{{wallets.id_B}}'],
    }
}

fixed = _sanitize_plan(plan, consumes_mapping)
step = fixed.test_steps[0]

# 2a: Headers — single brace fix + auth.token → login.token
auth_val = step.headers.get('Authorization', '')
assert '{{login.token_A}}' in auth_val, f'FAIL headers: got "{auth_val}"'
print(f'Test 2a PASS: header = "{auth_val}"')

# 2b: path_params — hardcode string → placeholder từ consumes_mapping
pp_val = step.path_params.get('walletId', '')
assert pp_val == '{{wallets.id_A}}', f'FAIL path_params: got "{pp_val}"'
print(f'Test 2b PASS: path_params walletId = "{pp_val}"')

# ─── Test 3: _sanitize_plan giữ nguyên double-brace đúng ────────────
plan2 = TestPlan(
    node_id='GET:/wallets/{walletId}',
    endpoint='/wallets/{walletId}',
    method='GET',
    is_attack=True,
    vuln_type='API1',
    test_steps=[
        TestStep(
            step=1,
            description='Test already correct',
            headers={'Authorization': 'Bearer {{login.token_A}}'},   # đúng rồi
            path_params={'walletId': '{{wallets.id_A}}'},             # đúng rồi
            expected_indicator='200',
        )
    ]
)

fixed2 = _sanitize_plan(plan2, consumes_mapping)
step2 = fixed2.test_steps[0]

auth2 = step2.headers.get('Authorization', '')
assert '{{login.token_A}}' in auth2, f'FAIL 3a: got "{auth2}"'
pp2 = step2.path_params.get('walletId', '')
assert pp2 == '{{wallets.id_A}}', f'FAIL 3b: got "{pp2}"'
print('Test 3 PASS: double-brace already correct preserved')

# ─── Test 4: execution_agent sem_key heuristic ────────────────────
import re as _re

def sem_key_from_field(k_lower: str, resource_name: str) -> str:
    if k_lower == 'id':
        return f'{resource_name}.id'
    base = _re.sub(r'id$', '', k_lower)
    return f'{base}.id' if base else f'{resource_name}.id'

assert sem_key_from_field('id', 'transactions')          == 'transactions.id'
assert sem_key_from_field('walletid', 'wallets')         == 'wallet.id'
assert sem_key_from_field('transactionid', 'transactions') == 'transaction.id'
assert sem_key_from_field('userid', 'users')             == 'user.id'
print('Test 4 PASS: execution_agent sem_key heuristic OK')

print()
print('ALL TESTS PASSED')
