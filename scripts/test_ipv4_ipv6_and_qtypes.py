import os
import sys
import time
import requests

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

BASE_URL = "http://127.0.0.1:5000"

def test_ipv4_ipv6_and_query_types():
    print("\n" + "=" * 70)
    print("  DNSWatch IPv4/IPv6 Client Handling & Repeated QType Test Suite")
    print("=" * 70 + "\n")
    
    # 1. Clear database to start clean
    print("Step 1: Clearing database...")
    res = requests.post(f"{BASE_URL}/api/monitoring/clear", json={})
    assert res.status_code == 200, f"Failed to clear data: {res.text}"
    print(" -> Database cleared.\n")
    
    # 2. Ingest repeated A, AAAA, and HTTPS (type 65) queries from local IPv4 and local IPv6
    print("Step 2: Sending repeated A, AAAA, and HTTPS (type 65) queries...")
    queries = [
        # Local IPv4 queries
        ("192.168.254.108", "google.com", "A", "142.250.190.78"),
        ("192.168.254.108", "google.com", "AAAA", "2404:6800:4017:80a::200e"),
        ("192.168.254.108", "google.com", "HTTPS", "-"),
        ("192.168.254.108", "google.com", "65", "-"),
        
        # Local IPv6 queries for same domain
        ("2001:fd8:c82e:d100:bc56:db59:7153:62f9", "google.com", "A", "142.250.190.78"),
        ("2001:fd8:c82e:d100:bc56:db59:7153:62f9", "google.com", "AAAA", "2404:6800:4017:80a::200e"),
        ("2001:fd8:c82e:d100:bc56:db59:7153:62f9", "google.com", "HTTPS", "-"),
        
        # Another LAN Client (192.168.1.99)
        ("192.168.1.99", "wikipedia.org", "A", "208.80.154.224"),
        ("192.168.1.99", "wikipedia.org", "AAAA", "2620:0:860:ed1a::1")
    ]
    
    for ip, dom, qtype, resp in queries:
        r = requests.post(f"{BASE_URL}/api/monitoring/simulate", json={
            'client_ip': ip,
            'domain': dom,
            'query_type': qtype,
            'response_ip': resp
        })
        assert r.status_code == 200, f"Simulate error: {r.text}"
        
    time.sleep(1.0)
    print(f" -> Sent {len(queries)} individual DNS queries.\n")
    
    # 3. Verify that ALL 9 queries remain separate individual log entries in DNS Logs
    print("Step 3: Checking DNS Network Logs (/api/dns/logs)...")
    r_logs = requests.get(f"{BASE_URL}/api/dns/logs?per_page=50").json()
    total_logs = r_logs['pagination']['total']
    print(f" Total DNS Logs: {total_logs}")
    assert total_logs == len(queries), f"Expected {len(queries)} logs, got {total_logs}"
    
    # Check that query types A, AAAA, HTTPS are preserved accurately
    qtypes_recorded = [l['query_type'] for l in r_logs['logs']]
    print(f" Query types recorded: {qtypes_recorded}")
    assert "A" in qtypes_recorded
    assert "AAAA" in qtypes_recorded
    assert "HTTPS" in qtypes_recorded
    print(" -> PASS: Every single repeated DNS packet (A, AAAA, HTTPS) is preserved as an individual log entry.\n")
    
    # 4. Verify Website Activity preserves all 9 entries
    print("Step 4: Checking Website Activity (/api/website-activity)...")
    r_web = requests.get(f"{BASE_URL}/api/website-activity?per_page=50").json()
    assert r_web['pagination']['total'] == len(queries), f"Expected {len(queries)} in Website Activity, got {r_web['pagination']['total']}"
    print(" -> PASS: Website Activity correctly lists all 9 individual requests.\n")
    
    # 5. Verify Device Correlation (IPv4 + IPv6 of local host correlated to 1 device)
    print("Step 5: Checking Devices Inventory (/api/devices)...")
    r_dev = requests.get(f"{BASE_URL}/api/devices").json()
    devices = r_dev['devices']
    print(f" Total Devices registered: {r_dev['total_devices']}")
    for d in devices:
        print(f"  Device: {d['device_name']} | IP: {d['ip_address']} | Queries: {d['dns_queries']} | Status: {d['status']}")
        
    # We should have exactly 2 devices:
    # 1) Local Workstation (handling 7 queries across its IPv4 and IPv6 addresses)
    # 2) LAN Client 192.168.1.99 (handling 2 queries)
    assert r_dev['total_devices'] == 2, f"Expected 2 devices, got {r_dev['total_devices']}"
    
    local_dev = next((d for d in devices if "Local Workstation" in d['device_name']), None)
    assert local_dev is not None, "Local Workstation device not found"
    assert local_dev['dns_queries'] == 7, f"Expected 7 queries for Local Workstation, got {local_dev['dns_queries']}"
    
    lan_dev = next((d for d in devices if d['ip_address'] == "192.168.1.99"), None)
    assert lan_dev is not None, "LAN device 192.168.1.99 not found"
    assert lan_dev['dns_queries'] == 2, f"Expected 2 queries for LAN device, got {lan_dev['dns_queries']}"
    
    print(" -> PASS: Local workstation's IPv4 and IPv6 traffic correctly unified into 1 device without duplication.\n")
    
    print("=" * 70)
    print("  ALL TESTS PASSED SUCCESSFULLY!")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    test_ipv4_ipv6_and_query_types()
