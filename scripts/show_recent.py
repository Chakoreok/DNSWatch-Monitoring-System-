import requests

res = requests.get('http://127.0.0.1:5000/api/dns/recent?limit=15')
data = res.json()

print(f"{'Time':<12} | {'Status':<10} | {'Client IP':<24} | {'Query Type':<6} | {'Domain':<30} | {'Response IP':<20}")
print("-" * 115)

for log in data.get('logs', []):
    time_str = log.get('time_only', '')
    status = log.get('status', 'SAFE')
    ip = log.get('client_ip', 'Unknown')
    qtype = log.get('query_type', 'A')
    domain = log.get('domain', '')
    resp = log.get('response_ip', '-')
    print(f"{time_str:<12} | {status:<10} | {ip:<24} | {qtype:<6} | {domain:<30} | {resp:<20}")
