import os
import sys
import time
import requests

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

BASE_URL = "http://127.0.0.1:5000"

def test_data_consistency():
    print("\n" + "=" * 70)
    print("  DNSWatch Comprehensive Multi-Page Data Consistency Test")
    print("=" * 70 + "\n")
    
    # 1. Clear database to start clean
    print("Step 1: Clearing database...")
    res = requests.post(f"{BASE_URL}/api/monitoring/clear", json={})
    assert res.status_code == 200, f"Failed to clear data: {res.text}"
    print(" -> Database cleared successfully.\n")
    
    # 2. Ingest known test queries across different client IPs
    print("Step 2: Ingesting verified DNS traffic across multiple client IPs...")
    test_traffic = [
        # Client 1: 5 Safe Queries
        ("192.168.1.50", "wikipedia.org", "A", "208.80.154.224"),
        ("192.168.1.50", "github.com", "A", "20.205.243.166"),
        ("192.168.1.50", "apple.com", "A", "17.253.144.10"),
        ("192.168.1.50", "google.com", "A", "142.250.190.78"),
        ("192.168.1.50", "mozilla.org", "A", "104.18.22.126"),
        
        # Client 2: 2 Malicious Domain Queries
        ("192.168.1.60", "malicious-site.net", "A", None),
        ("192.168.1.60", "bad-downloads.com", "A", None),
        
        # Client 3: 1 Compound Phishing Rule Query
        ("192.168.1.70", "login-verify-portal.net", "A", None)
    ]
    
    for ip, domain, qtype, resp in test_traffic:
        r = requests.post(f"{BASE_URL}/api/monitoring/simulate", json={
            'client_ip': ip,
            'domain': domain,
            'query_type': qtype,
            'response_ip': resp or '-'
        })
        assert r.status_code == 200, f"Simulate failed: {r.text}"
        
    time.sleep(1.0)  # Allow async DB batch writer to flush
    print(f" -> Successfully ingested {len(test_traffic)} test queries.\n")
    
    # 3. Check Dashboard / DNS Stats endpoint
    print("Step 3: Verifying Dashboard Stats (/api/dns/stats)...")
    r_stats = requests.get(f"{BASE_URL}/api/dns/stats").json()
    print(" Stats payload:", r_stats)
    assert r_stats['total_queries'] == 8, f"Expected 8 total, got {r_stats['total_queries']}"
    assert r_stats['safe_queries'] == 5, f"Expected 5 safe, got {r_stats['safe_queries']}"
    assert r_stats['suspicious_queries'] == 3, f"Expected 3 suspicious, got {r_stats['suspicious_queries']}"
    assert r_stats['blocked_queries'] == 0, f"Expected 0 blocked, got {r_stats['blocked_queries']}"
    print(" -> PASS: Dashboard stats match exact counts.\n")
    
    # 4. Check DNS Logs endpoint (/api/dns/logs)
    print("Step 4: Verifying DNS Network Logs (/api/dns/logs)...")
    r_logs = requests.get(f"{BASE_URL}/api/dns/logs?per_page=50").json()
    assert r_logs['pagination']['total'] == 8, f"Expected 8 logs, got {r_logs['pagination']['total']}"
    logged_domains = [l['query_domain'] for l in r_logs['logs']]
    for _, dom, _, _ in test_traffic:
        assert dom in logged_domains, f"Domain {dom} missing from DNS Logs"
    print(" -> PASS: DNS logs contain all 8 captured records with correct fields.\n")
    
    # 5. Check Website Activity endpoint (/api/website-activity)
    print("Step 5: Verifying Website Activity (/api/website-activity)...")
    r_web = requests.get(f"{BASE_URL}/api/website-activity?per_page=50").json()
    assert r_web['pagination']['total'] == 8, f"Expected 8 website activities, got {r_web['pagination']['total']}"
    web_domains = [w['domain'] for w in r_web['activities']]
    web_ips = [w['client_ip'] for w in r_web['activities']]
    assert "wikipedia.org" in web_domains
    assert "malicious-site.net" in web_domains
    assert "192.168.1.50" in web_ips
    assert "192.168.1.60" in web_ips
    print(" -> PASS: Website activity reads directly from same 8 DNS logs without fake data.\n")
    
    # 6. Check Devices endpoint (/api/devices)
    print("Step 6: Verifying Devices Inventory (/api/devices)...")
    r_dev = requests.get(f"{BASE_URL}/api/devices").json()
    print(f" Total devices: {r_dev['total_devices']}, Total queries: {r_dev['total_queries']}")
    assert r_dev['total_devices'] == 3, f"Expected 3 devices, got {r_dev['total_devices']}"
    assert r_dev['total_queries'] == 8, f"Expected 8 queries, got {r_dev['total_queries']}"
    
    dev_map = {d['ip_address']: d['dns_queries'] for d in r_dev['devices']}
    assert dev_map.get("192.168.1.50") == 5, f"Expected 5 queries for 192.168.1.50, got {dev_map.get('192.168.1.50')}"
    assert dev_map.get("192.168.1.60") == 2, f"Expected 2 queries for 192.168.1.60, got {dev_map.get('192.168.1.60')}"
    assert dev_map.get("192.168.1.70") == 1, f"Expected 1 query for 192.168.1.70, got {dev_map.get('192.168.1.70')}"
    print(" -> PASS: Devices inventory accurately synced with real client IPs and exact query counts.\n")
    
    # 7. Check Security Alerts endpoint (/api/alerts)
    print("Step 7: Verifying Security Alerts (/api/alerts)...")
    r_alerts = requests.get(f"{BASE_URL}/api/alerts").json()
    assert r_alerts['pagination']['total'] == 3, f"Expected 3 alerts, got {r_alerts['pagination']['total']}"
    alert_types = [a['alert_type'] for a in r_alerts['alerts']]
    alert_domains = [a['domain'] for a in r_alerts['alerts']]
    assert "malicious-site.net" in alert_domains
    assert "bad-downloads.com" in alert_domains
    assert "login-verify-portal.net" in alert_domains
    print(" -> PASS: Security alerts match real detection events.\n")
    
    # 8. Check Reports Summary endpoint (/api/reports/summary)
    print("Step 8: Verifying Reports Summary & Analytics (/api/reports/summary)...")
    r_rep = requests.get(f"{BASE_URL}/api/reports/summary").json()
    rep_sum = r_rep['summary']
    assert rep_sum['total_queries'] == 8, f"Expected 8 total in reports, got {rep_sum['total_queries']}"
    assert rep_sum['safe_requests'] == 5, f"Expected 5 safe in reports, got {rep_sum['safe_requests']}"
    assert rep_sum['suspicious_requests'] == 3, f"Expected 3 suspicious in reports, got {rep_sum['suspicious_requests']}"
    
    queries_series = r_rep['charts']['queries_over_time']
    series_sum = sum(queries_series)
    print(f" Timeline series values: {queries_series} (Sum = {series_sum})")
    assert series_sum == 8, f"Expected queries_over_time sum to be 8, got {series_sum}"
    
    top_devices_rep = {d['ip_address']: d['queries'] for d in r_rep['top_devices']}
    assert top_devices_rep.get("192.168.1.50") == 5, f"Expected top device to have 5 queries"
    print(" -> PASS: Reports summary accurately calculates all metrics and timeline series from DB.\n")
    
    print("=" * 70)
    print("  ALL 8 DATA CONSISTENCY TESTS PASSED 100% ACROSS ALL PAGES!")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    test_data_consistency()
