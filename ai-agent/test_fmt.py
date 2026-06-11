import json

fmt = '{x: "...",\n "arguments": Ellipsis}'
print("Testing format...")
try:
    fmt.format(x='test')
except Exception as e:
    print(repr(e))
