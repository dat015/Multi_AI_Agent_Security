import json, collections

with open('outputs/final_security_report.json', encoding='utf-8') as f:
    data = json.load(f)

total = len(data)
verdicts = collections.Counter(d['assessment']['verdict'] for d in data)
vuln_types = collections.Counter(d['vuln_type'] for d in data)
severities = collections.Counter(d['assessment']['severity'] for d in data)
is_vuln = sum(1 for d in data if d['assessment']['is_vulnerable'])
is_safe = sum(1 for d in data if not d['assessment']['is_vulnerable'])

scores = [d['assessment']['confidence_score'] for d in data]
avg_score = sum(scores)/len(scores) if scores else 0

print(f'Total records: {total}')
print(f'Vulnerable: {is_vuln}')
print(f'Safe: {is_safe}')
print(f'Avg confidence: {avg_score:.1f}%')
print(f'Verdicts: {dict(verdicts)}')
print(f'Vuln types: {dict(vuln_types)}')
print(f'Severities: {dict(severities)}')

print()
print('=== VULNERABLE CASES ===')
for d in data:
    if d['assessment']['is_vulnerable']:
        print(f"  [{d['vuln_type']}] {d['node_id']} - Score:{d['assessment']['confidence_score']}% - {d['assessment']['severity']} - {d['assessment']['verdict']}")

print()
print('=== SAFE CASES ===')
for d in data:
    if not d['assessment']['is_vulnerable']:
        print(f"  [{d['vuln_type']}] {d['node_id']} - Score:{d['assessment']['confidence_score']}% - {d['assessment']['verdict']}")
