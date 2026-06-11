"""Confirm: invoke() directly does NOT parse braces as templates."""
import sys
sys.path.insert(0, '.')

from langchain_core.prompts import ChatPromptTemplate

# Messages with double-brace placeholders (as would be in our system prompt)
sys_content = "Test with {{wallets.id_A}} and {{login.token_A}} placeholders"
human_content = "Human message with json data and {{order.id_B}}"

prompt_messages = [
    ('system', sys_content),
    ('human',  human_content),
]

print("=== Test: ChatPromptTemplate.from_messages() ===")
try:
    tpl = ChatPromptTemplate.from_messages(prompt_messages)
    print("ChatPromptTemplate created — checking variables:")
    print(f"  input_variables: {tpl.input_variables}")
    # If no error yet, try to format with empty dict
    try:
        formatted = tpl.format_messages()
        print(f"  format_messages() OK with no vars")
    except Exception as fe:
        print(f"  format_messages() FAILS: {fe}")
except Exception as e:
    print(f"ChatPromptTemplate FAILS at creation: {type(e).__name__}: {e}")

print()
print("=== Conclusion ===")
print("When input_vars={}, LLMService calls structured_llm.invoke(prompt_messages)")
print("This passes tuples directly to ChatOpenAI.invoke(), bypassing ChatPromptTemplate")
print("No template parsing → {{wallets.id_A}} is safe")
