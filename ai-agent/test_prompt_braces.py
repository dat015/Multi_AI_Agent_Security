"""
Verify: sau khi format xong, prompt không còn {single.brace} nào
khiến LangChain validate fail.
"""
import sys, re, json
sys.path.insert(0, '.')

from app.agents.planning_agent import (
    _SYSTEM_PROMPT_TEMPLATE,
    simplify_consume_mapping,
    _build_available_keys_hint,
)

consumes_mapping = {
    'walletId': {
        'semantic_key': 'wallets.id',
        'location': 'Path',
        'allowed_placeholders': ['{{wallets.id_A}}', '{{wallets.id_B}}'],
    },
    'orderId': {
        'semantic_key': 'order.id',
        'location': 'Path',
        'allowed_placeholders': ['{{order.id_A}}', '{{order.id_B}}'],
    },
}

consumes_hint = simplify_consume_mapping(consumes_mapping)

execution_order = ['POST:/wallets', 'POST:/Order', 'GET:/wallets/{walletId}']
graph_nodes = {
    'POST:/wallets': {'produces': [{'semantic_key': 'wallets.id'}]},
    'POST:/Order':   {'produces': [{'semantic_key': 'order.id'}]},
}

available_keys_hint = _build_available_keys_hint(
    'GET:/wallets/{walletId}',
    execution_order,
    graph_nodes,
)

sys_prompt = _SYSTEM_PROMPT_TEMPLATE.format(
    consumes_hint=consumes_hint,
    available_keys_hint=available_keys_hint,
    vuln_type='API1',
    vuln_reasoning='BOLA test reasoning',
)

endpoint_ctx = {
    'node_id': 'GET:/wallets/{walletId}',
    'path': '/wallets/{walletId}',
    'method': 'GET',
    'body_schema': {},
    'consumes_mapping': consumes_mapping,
}

vuln_info = {'vuln_type': 'API1', 'reasoning': 'BOLA test', 'plan': {}}
kb_context = {}

human_message = "\n".join([
    "Endpoint Details: " + json.dumps(endpoint_ctx, ensure_ascii=False),
    "Vulnerability Info: " + json.dumps(vuln_info, ensure_ascii=False),
    "OWASP KB: " + json.dumps(kb_context, ensure_ascii=False),
])

all_text = sys_prompt + "\n" + human_message

# Check for problematic {xxx.yyy} single-brace
# Strategy: temporarily remove {{...}} → then look for {something.with.dot}
temp = re.sub(r'\{\{.*?\}\}', '__ESC__', all_text, flags=re.DOTALL)
problematic = re.findall(r'\{([^{}]+)\}', temp)
# Filter: only flag patterns with dots (these are the ones LangChain rejects)
bad = [p for p in problematic if '.' in p or '[' in p]

print("=== Brace analysis ===")
if bad:
    print(f"FAIL: Found problematic single-brace patterns: {bad}")
else:
    print("PASS: No problematic {dot.var} single-brace patterns found")

# Show what double-brace placeholders remain (what LLM will see)
doubles = re.findall(r'\{\{([^{}]+)\}\}', all_text)
print(f"\nDouble-brace placeholders in prompt (LLM will see these as {{{{X}}}}): {list(set(doubles))}")

# Show auth placeholder context
print("\n--- Auth section ---")
for line in sys_prompt.split('\n'):
    if 'login.token' in line or 'AUTHENTICATION' in line:
        print(' ', repr(line))

# Show consumes section
print("\n--- Consumes hint injected ---")
idx = sys_prompt.find('DYNAMIC PARAMETERS')
if idx >= 0:
    print(sys_prompt[idx:idx+400])

print("\n--- Available keys injected ---")
idx2 = sys_prompt.find('AVAILABLE KEYS')
if idx2 >= 0:
    print(sys_prompt[idx2:idx2+400])
