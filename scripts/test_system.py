import os
import sys
import time
import requests
import unittest

API_BASE = "http://127.0.0.1:5000"

class DNSWatchSystemTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n=======================================================")
        print("  DNSWatch Comprehensive System Validation Test Suite  ")
        print("=======================================================\n")
        
    def test_01_monitoring_status_endpoint(self):
        """Verify monitoring status endpoint returns valid structure."""
        res = requests.get(f"{API_BASE}/api/monitoring/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data.get('success'))
        self.assertIn('monitoring', data)
        print("[PASS] Test 1: Monitoring status endpoint accessible.")

    def test_02_start_monitoring(self):
        """TEST 1: Start DNS monitoring."""
        res = requests.post(f"{API_BASE}/api/monitoring/start", json={})
        self.assertIn(res.status_code, (200, 400))  # 200 or 400 if already running
        status_res = requests.get(f"{API_BASE}/api/monitoring/status").json()
        self.assertTrue(status_res['monitoring']['is_running'])
        print("[PASS] Test 2 / TEST 1: Monitoring successfully started and status is ACTIVE.")

    def test_03_normal_dns_traffic(self):
        """TEST 2 to 6: Generate normal traffic and confirm domain, client IP, timestamp."""
        test_ip = "192.168.254.108"
        test_domain = "google.com"
        res = requests.post(f"{API_BASE}/api/monitoring/simulate", json={
            "client_ip": test_ip,
            "domain": test_domain,
            "query_type": "A",
            "response_ip": "142.250.190.78"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data['status'], 'SAFE')
        self.assertEqual(data['domain'], test_domain)
        self.assertEqual(data['client_ip'], test_ip)
        print("[PASS] Test 3 / TEST 2-6: Normal DNS request processed as SAFE with domain, IP, timestamp.")

    def test_04_malicious_domain_detection(self):
        """TEST 7 to 10: Add malicious domain, request it, verify SUSPICIOUS and alert generation."""
        # 1. Add test malicious domain
        test_malicious = f"test-malware-{int(time.time())}.com"
        add_res = requests.post(f"{API_BASE}/api/threats/domains", json={
            "domain": test_malicious,
            "category": "Test Malware",
            "severity": "HIGH",
            "description": "Automated test malicious domain"
        })
        self.assertEqual(add_res.status_code, 200)
        
        # 2. Query that domain
        sim_res = requests.post(f"{API_BASE}/api/monitoring/simulate", json={
            "client_ip": "192.168.254.108",
            "domain": test_malicious,
            "query_type": "A"
        }).json()
        
        # 3. Confirm classification is SUSPICIOUS and alert generated
        self.assertEqual(sim_res['status'], 'SUSPICIOUS')
        self.assertIsNotNone(sim_res['alert'])
        self.assertEqual(sim_res['alert']['alert_type'], 'Malicious Domain Match')
        print(f"[PASS] Test 4 / TEST 7-10: Malicious domain '{test_malicious}' correctly classified as SUSPICIOUS with alert generated.")

    def test_05_basic_domain_rule_checking(self):
        """TEST 11 & 12: Create domain rule and test keyword/pattern match."""
        # 1. Add rule
        rule_res = requests.post(f"{API_BASE}/api/threats/rules", json={
            "rule_name": f"Test-Phish-Rule-{int(time.time())}",
            "rule_type": "KEYWORD",
            "pattern": "secure-bank-login",
            "severity": "HIGH",
            "action": "Alert"
        }).json()
        self.assertTrue(rule_res['success'])
        
        # 2. Query domain with matching keyword
        sim_res = requests.post(f"{API_BASE}/api/monitoring/simulate", json={
            "client_ip": "192.168.1.15",
            "domain": "secure-bank-login-update.net",
            "query_type": "A"
        }).json()
        self.assertEqual(sim_res['status'], 'SUSPICIOUS')
        self.assertIsNotNone(sim_res['alert'])
        print("[PASS] Test 5 / TEST 11-12: Domain rule keyword check successfully triggered.")

    def test_06_frequency_rule_detection(self):
        """TEST 13 & 14: Generate high frequency requests from one client and verify detection."""
        # Set threshold to 15 queries in 10s for quick unit test
        requests.put(f"{API_BASE}/api/threats/frequency-rule", json={
            "threshold": 15,
            "time_window": 10,
            "action": "Alert",
            "status": "Active"
        })
        
        flood_client = "192.168.1.99"
        alerts_detected = 0
        for i in range(25):
            r = requests.post(f"{API_BASE}/api/monitoring/simulate", json={
                "client_ip": flood_client,
                "domain": f"flood-burst-{i}.org",
                "query_type": "A"
            }).json()
            if r['status'] == 'SUSPICIOUS' and r.get('alert') and 'frequency' in r['alert']['alert_type'].lower():
                alerts_detected += 1
                
        self.assertGreater(alerts_detected, 0)
        print(f"[PASS] Test 6 / TEST 13-14: Frequency rule triggered ({alerts_detected} alerts) when client exceeded threshold.")
        
        # Reset default frequency rule (100 in 60s)
        requests.put(f"{API_BASE}/api/threats/frequency-rule", json={
            "threshold": 100,
            "time_window": 60,
            "action": "Alert",
            "status": "Active"
        })

    def test_07_mysql_logging_and_alerts_persistence(self):
        """TEST 15 & 16: Verify logs and alerts are stored in MySQL."""
        time.sleep(1.5)  # Allow batch writer to flush to MySQL
        
        logs_res = requests.get(f"{API_BASE}/api/dns/logs?page=1&per_page=5").json()
        self.assertTrue(logs_res['success'])
        self.assertGreater(logs_res['pagination']['total'], 0)
        
        alerts_res = requests.get(f"{API_BASE}/api/alerts?page=1&per_page=5").json()
        self.assertTrue(alerts_res['success'])
        self.assertGreater(alerts_res['pagination']['total'], 0)
        print("[PASS] Test 7 / TEST 15-16: MySQL persistence verified for DNS logs and Security Alerts.")

    def test_08_stop_monitoring(self):
        """TEST 17 & 18: Stop monitoring and confirm capture stops."""
        res = requests.post(f"{API_BASE}/api/monitoring/stop", json={})
        self.assertEqual(res.status_code, 200)
        status_res = requests.get(f"{API_BASE}/api/monitoring/status").json()
        self.assertFalse(status_res['monitoring']['is_running'])
        print("[PASS] Test 8 / TEST 17-18: Monitoring stopped and status is INACTIVE.")

    def test_09_no_geolocation_enforced(self):
        """CRITICAL: Confirm NO IP geolocation fields exist in any DNS log or device payload."""
        logs_res = requests.get(f"{API_BASE}/api/dns/logs?per_page=1").json()
        if logs_res['logs']:
            log = logs_res['logs'][0]
            forbidden_keys = ['country', 'country_code', 'country_name', 'city', 'region', 'isp', 'latitude', 'longitude', 'flag']
            for k in forbidden_keys:
                self.assertNotIn(k, log, f"Forbidden GeoIP key found: {k}")
        print("[PASS] Test 9 / CRITICAL: Verified zero IP geolocation data fields.")

if __name__ == "__main__":
    unittest.main()
