"""Find the real source of {wallets.id_A} single-brace."""
import sys, re
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
}

consumes_hint = simplify_consume_mapping(consumes_mapping)
print("=== consumes_hint ===")
print(repr(consumes_hint))
print()

available_keys_hint = _build_available_keys_hint(
    'GET:/wallets/{walletId}',
    ['POST:/wallets', 'GET:/wallets/{walletId}'],
    {'POST:/wallets': {'produces': [{'semantic_key': 'wallets.id'}]}},
)
print("=== available_keys_hint ===")
print(repr(available_keys_hint))
print()

sys_prompt = _SYSTEM_PROMPT_TEMPLATE.format(
    consumes_hint=consumes_hint,
    available_keys_hint=available_keys_hint,
    vuln_type='API1',
    vuln_reasoning='BOLA',
)

# Find all {single-brace} occurrences with dots
temp = re.sub(r'\{\{[^{}]*\}\}', '__ESC__', sys_prompt)
bad = re.findall(r'\{([^{}]+)\}', temp)
bad_with_dots = [b for b in bad if '.' in b or '[' in b]
print("=== Single-brace with dots in sys_prompt ===")
if bad_with_dots:
    print("FOUND:", bad_with_dots)
    # Find context
    for b in bad_with_dots:
        idx = sys_prompt.find('{' + b + '}')
        if idx >= 0:
            print(f"  Context: ...{repr(sys_prompt[max(0,idx-30):idx+len(b)+32])}...")
else:
    print("NONE - sys_prompt is clean")
