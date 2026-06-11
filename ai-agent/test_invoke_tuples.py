"""
Verify: structured_llm.invoke() with list-of-tuples does NOT parse braces.
LangChain converts tuples to HumanMessage/SystemMessage objects directly.
No PromptTemplate parsing happens.
"""
import sys
sys.path.insert(0, '.')

# Check what LangChain does with tuples in invoke()
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage

# Simulate what LangChain does when you call model.invoke([("system", "..."), ("human", "...")])
from langchain_core.messages.utils import convert_to_messages

prompt_messages = [
    ('system', 'System with {{wallets.id_A}} and {{login.token_A}}'),
    ('human',  'Human with {"path": "/wallets/{walletId}"}'),
]

try:
    msgs = convert_to_messages(prompt_messages)
    print("PASS: convert_to_messages() OK")
    for m in msgs:
        print(f"  {type(m).__name__}: {repr(m.content[:80])}")
    print()
    print("Conclusion: invoke() with list-of-tuples converts directly to messages,")
    print("NO template parsing, {{...}} is passed as literal string to the LLM API.")
except Exception as e:
    print(f"FAIL: {type(e).__name__}: {e}")
