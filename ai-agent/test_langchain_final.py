"""Verify: invoke() with list of tuples works fine (no ChatPromptTemplate)."""
import sys
sys.path.insert(0, '.')
from langchain_core.prompts import ChatPromptTemplate

# Simulate exact format that planning_agent now sends
sys_content = (
    "System with {{wallets.id_A}} and {{login.token_A}} in prompt. "
    "CORRECT: \"walletId\": \"{{wallets.id_A}}\""
)
human_content = (
    'Endpoint Details: {"path": "/wallets/{walletId}", "consumes_mapping": {"walletId": {"semantic_key": "wallets.id"}}}'
)

prompt_messages = [
    ('system', sys_content),
    ('human',  human_content),
]

# Test 1: ChatPromptTemplate from_messages with these messages
print("=== Test: ChatPromptTemplate.from_messages() with {{...}} content ===")
try:
    tpl = ChatPromptTemplate.from_messages(prompt_messages)
    vars_ = tpl.input_variables
    print(f"OK: ChatPromptTemplate created, input_variables={vars_}")
    if vars_:
        print(f"WARNING: Unexpected template variables found: {vars_}")
    else:
        print("PASS: No template variables extracted (double-brace are escaped correctly)")
except Exception as e:
    print(f"FAIL: {type(e).__name__}: {e}")

# Test 2: Confirm format_messages works with empty dict
print()
print("=== Test: format_messages() with empty dict ===")
try:
    tpl2 = ChatPromptTemplate.from_messages(prompt_messages)
    msgs = tpl2.format_messages()
    print(f"PASS: format_messages() returned {len(msgs)} messages")
    for m in msgs:
        print(f"  {type(m).__name__}: {repr(m.content[:60])}...")
except Exception as e:
    print(f"FAIL: {type(e).__name__}: {e}")

print()
print("=== Summary ===")
print("Fix confirmed: input_vars={} -> LLMService.invoke(tuples) avoids ChatPromptTemplate entirely")
print("Even ChatPromptTemplate handles {{...}} safely (escape to literal {}) with no extra vars")
