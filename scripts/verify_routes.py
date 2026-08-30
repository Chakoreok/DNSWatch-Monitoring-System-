import requests

routes = [
    '/', 
    '/login', 
    '/dashboard', 
    '/website-activity', 
    '/devices',
    '/dns-logs', 
    '/security-alerts', 
    '/threat-detection', 
    '/reports', 
    '/settings',
    '/api/monitoring/status', 
    '/api/monitoring/interfaces',
    '/api/dns/logs', 
    '/api/dns/recent', 
    '/api/dns/stats',
    '/api/alerts', 
    '/api/alerts/recent', 
    '/api/alerts/counts',
    '/api/threats/summary', 
    '/api/threats/domains', 
    '/api/threats/rules', 
    '/api/threats/frequency-rule',
    '/api/devices', 
    '/api/reports/summary', 
    '/api/reports/export',
    '/api/website-activity'
]

base = 'http://127.0.0.1:5000'
all_ok = True

print(f"{'Route':<32} | {'Status':<8} | {'Content Type':<28}")
print("-" * 75)

for r in routes:
    try:
        res = requests.get(base + r, timeout=3)
        ct = res.headers.get('Content-Type', '').split(';')[0]
        status_str = f"{res.status_code} OK" if res.status_code == 200 else f"FAIL ({res.status_code})"
        print(f"{r:<32} | {status_str:<8} | {ct:<28}")
        if res.status_code != 200:
            all_ok = False
    except Exception as e:
        print(f"{r:<32} | ERROR: {e}")
        all_ok = False

print("-" * 75)
print("All routes operational:", all_ok)
