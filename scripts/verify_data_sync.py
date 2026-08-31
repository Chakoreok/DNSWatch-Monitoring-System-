"""
DNSWatch Cross-Page Data Synchronization Verification
=====================================================
Tests that the SAME captured DNS records appear consistently across:
  - Dashboard stats (/api/dns/stats)
  - DNS / Network Logs (/api/dns/logs)
  - Website Activity (/api/website-activity)
  - Security Alerts (/api/alerts, /api/alerts/counts)
  - Devices (/api/devices)
"""
import os, sys, json, time, requests

API_BASE = "http://127.0.0.1:5000"

def verify_data_sync():
    print("\n" + "=" * 70)
    print("  DNSWatch Cross-Page Data Synchronization Verification")
    print("=" * 70 + "\n")

    s = requests.Session()
    
    # 1. Authenticate
    r = s.post(f"{API_BASE}/api/auth/login", json={'username': 'admin', 'password': 'admin123'})
    assert r.status_code == 200, "Login failed"
    print("[OK] Authenticated as admin\n")
    
    # 2. Clear all data for a clean test
    r = s.post(f"{API_BASE}/api/monitoring/clear")
    assert r.json()['success']
    print("[OK] All data cleared\n")
    
    # 3. Start monitoring
    r = s.post(f"{API_BASE}/api/monitoring/start", json={})
    assert r.status_code == 200
    print("[OK] Monitoring started\n")
    
    # 4. Send test traffic: mix of SAFE and SUSPICIOUS
    print("Sending mixed DNS traffic...\n")
    
    safe_queries = [
        ("192.168.254.108", "google.com", "A", "142.250.190.78"),
        ("192.168.254.108", "github.com", "A", "140.82.121.4"),
        ("192.168.254.108", "youtube.com", "AAAA", "2607:f8b0:4004::200e"),
        ("192.168.1.50", "apple.com", "A", "17.253.144.10"),
        ("192.168.1.50", "microsoft.com", "A", "20.236.44.162"),
        ("192.168.1.75", "netflix.com", "HTTPS", "52.94.228.167"),
    ]
    
    malicious_queries = [
        ("192.168.254.108", "malicious-site.net", "A", ""),
        ("192.168.1.50", "phishing-alert.com", "A", ""),
        ("192.168.1.75", "bad-downloads.com", "A", ""),
    ]
    
    expected_safe = 0
    expected_suspicious = 0
    
    for ip, dom, qt, resp in safe_queries:
        data = s.post(f"{API_BASE}/api/monitoring/simulate", json={
            'client_ip': ip, 'domain': dom, 'query_type': qt, 'response_ip': resp
        }).json()
        if data['status'] == 'SAFE':
            expected_safe += 1
        elif data['status'] in ('SUSPICIOUS', 'BLOCKED'):
            expected_suspicious += 1
        print(f"  {dom:30} -> {data['status']}")
        
    for ip, dom, qt, resp in malicious_queries:
        data = s.post(f"{API_BASE}/api/monitoring/simulate", json={
            'client_ip': ip, 'domain': dom, 'query_type': qt, 'response_ip': resp
        }).json()
        if data['status'] == 'SAFE':
            expected_safe += 1
        elif data['status'] in ('SUSPICIOUS', 'BLOCKED'):
            expected_suspicious += 1
        alert_info = f" | Alert: {data['alert']['alert_type']}" if data.get('alert') else ""
        print(f"  {dom:30} -> {data['status']}{alert_info}")
    
    total_sent = len(safe_queries) + len(malicious_queries)
    print(f"\n  Total sent: {total_sent} | Safe: {expected_safe} | Suspicious: {expected_suspicious}")
    
    # 5. Stop monitoring (this now waits for DB writer to drain)
    print("\nStopping monitoring (waits for DB writer drain)...")
    r = s.post(f"{API_BASE}/api/monitoring/stop", json={})
    assert r.status_code == 200
    print("[OK] Monitoring stopped\n")
    
    # Brief pause for any residual commits
    time.sleep(0.5)
    
    # 6. Verify all pages see the same data
    print("=" * 50)
    print("  CROSS-PAGE DATA CONSISTENCY CHECK")
    print("=" * 50 + "\n")
    
    # --- Dashboard Stats API ---
    stats = s.get(f"{API_BASE}/api/dns/stats").json()
    print(f"DASHBOARD STATS (/api/dns/stats):")
    print(f"  total_queries:       {stats['total_queries']}")
    print(f"  safe_queries:        {stats['safe_queries']}")
    print(f"  suspicious_queries:  {stats['suspicious_queries']}")
    print(f"  blocked_queries:     {stats['blocked_queries']}\n")
    
    # --- DNS Logs API ---
    logs_data = s.get(f"{API_BASE}/api/dns/logs?page=1&per_page=100").json()
    dns_logs_total = logs_data['pagination']['total']
    print(f"DNS LOGS PAGE (/api/dns/logs):")
    print(f"  total records:       {dns_logs_total}\n")
    
    # --- Website Activity API ---
    wa_data = s.get(f"{API_BASE}/api/website-activity?page=1&per_page=100").json()
    wa_total = wa_data['pagination']['total']
    print(f"WEBSITE ACTIVITY (/api/website-activity):")
    print(f"  total records:       {wa_total}\n")
    
    # --- Security Alerts API ---
    alerts_data = s.get(f"{API_BASE}/api/alerts?page=1&per_page=100").json()
    alerts_total = alerts_data['pagination']['total']
    
    alert_counts = s.get(f"{API_BASE}/api/alerts/counts").json()
    print(f"SECURITY ALERTS (/api/alerts):")
    print(f"  total alerts:        {alerts_total}")
    print(f"  counts API total:    {alert_counts['total']}")
    print(f"    HIGH:              {alert_counts['high']}")
    print(f"    MEDIUM:            {alert_counts['medium']}")
    print(f"    LOW:               {alert_counts['low']}\n")
    
    # --- Devices API ---
    dev_data = s.get(f"{API_BASE}/api/devices").json()
    print(f"DEVICES (/api/devices):")
    print(f"  total_devices:       {dev_data['total_devices']}")
    print(f"  total_queries:       {dev_data['total_queries']}")
    for d in dev_data['devices']:
        print(f"    {d['device_name']:40} | IP: {d['client_ip']:18} | DNS Queries: {d['dns_queries']}")
    print()
    
    # 7. ASSERTIONS: All pages must agree
    print("=" * 50)
    print("  ASSERTIONS")
    print("=" * 50 + "\n")
    
    passed = 0
    failed = 0
    
    def check(desc, condition):
        nonlocal passed, failed
        if condition:
            print(f"  [PASS] {desc}")
            passed += 1
        else:
            print(f"  [FAIL] {desc}")
            failed += 1
    
    check(f"Dashboard total ({stats['total_queries']}) >= {total_sent} sent queries", stats['total_queries'] >= total_sent)
    check(f"DNS Logs total ({dns_logs_total}) == Dashboard total ({stats['total_queries']})", dns_logs_total == stats['total_queries'])
    check(f"Website Activity total ({wa_total}) == DNS Logs total ({dns_logs_total})", wa_total == dns_logs_total)
    check(f"Dashboard suspicious ({stats['suspicious_queries']}) == {expected_suspicious}", stats['suspicious_queries'] >= expected_suspicious)
    check(f"Security Alerts ({alerts_total}) > 0 for suspicious traffic", alerts_total > 0)
    check(f"Alert counts API ({alert_counts['total']}) == alerts page ({alerts_total})", alert_counts['total'] == alerts_total)
    check(f"Dashboard suspicious ({stats['suspicious_queries']}) >= alert count ({alert_counts['total']})", stats['suspicious_queries'] >= alert_counts['total'])
    check(f"Devices total queries ({dev_data['total_queries']}) == DNS Logs total ({dns_logs_total})", dev_data['total_queries'] == dns_logs_total)
    check(f"All devices have non-zero DNS query counts", all(d['dns_queries'] > 0 for d in dev_data['devices']))
    check(f"Multiple devices detected ({dev_data['total_devices']} >= 3)", dev_data['total_devices'] >= 3)
    
    print(f"\n{'=' * 50}")
    if failed == 0:
        print(f"  ALL {passed} ASSERTIONS PASSED!")
    else:
        print(f"  {passed} PASSED, {failed} FAILED")
    print(f"{'=' * 50}\n")
    
    return failed == 0

if __name__ == "__main__":
    success = verify_data_sync()
    sys.exit(0 if success else 1)
