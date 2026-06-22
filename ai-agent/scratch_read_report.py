import json
import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('outputs/final_security_report.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

print(f'TOTAL: {len(data)} findings\n')

for item in data:
    node = item.get('node_id','')
    vuln = item.get('vuln_type','')
    a = item.get('assessment',{})
    verdict = a.get('verdict','')
    score = a.get('confidence_score', 0)
    preds = a.get('predicates',{})
    cwe = a.get('cwe','')
    sev = a.get('severity','')
    reasoning = a.get('reasoning','')
    is_vuln = a.get('is_vulnerable', False)
    steps = item.get('evidence',{}).get('steps',[])
    
    print(f'[{vuln}] {node}')
    print(f'  verdict={verdict} | score={score}% | sev={sev} | is_vuln={is_vuln}')
    print(f'  CWE: {cwe}')
    print(f'  Predicates: {preds}')
    print(f'  Reasoning: {reasoning[:200]}')
    for s in steps:
        sc = s.get('status_code','N/A')
        desc = str(s.get('description',''))[:80]
        req = s.get('request_sent') or {}
        url = req.get('url','')
        body = req.get('body')
        resp = s.get('response',{})
        # Get key response fields
        if isinstance(resp, dict):
            resp_str = f"success={resp.get('success')} msg={str(resp.get('message',''))[:50]} data={str(resp.get('data',''))[:80]}"
        else:
            resp_str = str(resp)[:120]
        print(f'  Step{s.get("step_number",0)}: HTTP={sc} | {desc}')
        if url:
            print(f'    URL: {url}')
        if body:
            print(f'    Body: {str(body)[:100]}')
        print(f'    Resp: {resp_str}')
    print()
