import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask
from config import Config
from database import db
from services.detection_engine import detection_engine
from models import MaliciousDomain, DetectionRule, FrequencyRuleConfig

def run_tests():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    
    with app.app_context():
        # Reload cache from MySQL
        detection_engine.reload_cache()
        
        print("\n" + "=" * 60)
        print("  DNSWatch False Positive & Alert Deduplication Test Suite")
        print("=" * 60 + "\n")
        
        # TEST 1: accounts.google.com (CRITICAL FALSE POSITIVE TEST)
        status, reason, rule_id, alert, cat = detection_engine.evaluate_dns_request("192.168.254.108", "accounts.google.com")
        print(f"[TEST 1] accounts.google.com -> Status: {status} | Alert: {alert} | Reason: {reason}")
        assert status == "SAFE", f"Expected SAFE, got {status} ({reason})"
        assert alert is None, f"Expected no alert, got {alert}"
        print(" -> PASS: accounts.google.com correctly evaluated as SAFE.\n")
        
        # TEST 2: Other legitimate domains with common words
        legit_domains = [
            "mail.google.com",
            "cloud.google.com",
            "support.microsoft.com",
            "update.microsoft.com",
            "windowsupdate.com",
            "api.github.com",
            "secure.bankofamerica.com"
        ]
        for d in legit_domains:
            status, reason, rule_id, alert, cat = detection_engine.evaluate_dns_request("192.168.254.108", d)
            print(f"[TEST 2] {d:<30} -> Status: {status} | Alert: {alert is not None}")
            assert status == "SAFE", f"Domain {d} falsely flagged as {status} ({reason})"
        print(" -> PASS: Common legitimate domains evaluated as SAFE.\n")
        
        # TEST 3: Malicious Domain List Match
        status, reason, rule_id, alert, cat = detection_engine.evaluate_dns_request("192.168.254.108", "malicious-site.net")
        print(f"[TEST 3] malicious-site.net -> Status: {status} | Reason: {reason} | Severity: {alert['severity'] if alert else None}")
        assert status == "SUSPICIOUS", f"Expected SUSPICIOUS, got {status}"
        assert alert is not None and alert['alert_type'] == "Malicious Domain Match"
        print(" -> PASS: Malicious domain list match working correctly.\n")
        
        # TEST 4: Configured Domain Rule Match (Compound Phishing Pattern)
        status, reason, rule_id, alert, cat = detection_engine.evaluate_dns_request("192.168.1.15", "login-verify-account.com")
        print(f"[TEST 4] login-verify-account.com -> Status: {status} | Reason: {reason} | Severity: {alert['severity'] if alert else None}")
        assert status == "SUSPICIOUS", f"Expected SUSPICIOUS, got {status}"
        assert alert is not None and alert['alert_type'] == "Suspicious Domain Rule"
        print(" -> PASS: Domain rule checking working correctly.\n")
        
        # TEST 5: Alert Deduplication Test (10 repeated queries in 1 second)
        print("[TEST 5] Testing Alert Deduplication on 10 repeated queries for dedup-test.net...")
        detection_engine.malicious_domains["dedup-test.net"] = {
            'id': 999, 'domain': 'dedup-test.net', 'category': 'Threat', 'severity': 'HIGH'
        }
        alerts_generated = 0
        for i in range(10):
            st, reas, rid, al, c = detection_engine.evaluate_dns_request("192.168.254.108", "dedup-test.net")
            assert st == "SUSPICIOUS"  # Every request is still classified as SUSPICIOUS
            if al is not None:
                alerts_generated += 1
                
        print(f" -> Generated {alerts_generated} alert(s) for 10 consecutive requests.")
        assert alerts_generated == 1, f"Expected exactly 1 deduplicated alert, got {alerts_generated}"
        print(" -> PASS: Alert deduplication working (1 alert created, zero spam).\n")
        
        # TEST 6: DNS Query Frequency Rule
        print("[TEST 6] Testing Frequency Rule...")
        detection_engine.frequency_threshold = 10
        detection_engine.frequency_window = 5
        detection_engine.frequency_status = "Active"
        freq_client = "192.168.1.200"
        
        freq_alerts = 0
        for i in range(15):
            st, reas, rid, al, c = detection_engine.evaluate_dns_request(freq_client, f"test-query-{i}.org")
            if al and "Frequency" in al.get('alert_type', ''):
                freq_alerts += 1
                
        assert freq_alerts >= 1, "Expected frequency alert"
        print(f" -> PASS: Frequency rule triggered correctly ({freq_alerts} alert(s)).\n")
        
        print("=" * 60)
        print("  ALL FALSE POSITIVE AND DEDUPLICATION TESTS PASSED!")
        print("=" * 60)

if __name__ == "__main__":
    run_tests()
