import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import create_app
from database import db
from services.detection_engine import detection_engine
from services.threat_feed_service import threat_feed_service
from models import MaliciousDomain, DetectionRule, ThreatFeed

def run_tests():
    app = create_app()
    with app.app_context():
        client = app.test_client()

        print("\n" + "=" * 70)
        print("  DNSWatch Real-World Threat Detection & Sandbox Verification Suite")
        print("=" * 70 + "\n")

        # -------------------------------------------------------------
        # TEST 1: Threat Intelligence Feeds API
        # -------------------------------------------------------------
        print("[TEST 1] Verifying Threat Intelligence Feeds...")
        res = client.get('/api/threats/feeds')
        assert res.status_code == 200, f"Expected 200, got {res.status_code}"
        feed_data = res.get_json()
        assert feed_data['success'] is True
        feeds = feed_data['feeds']
        print(f" -> Found {len(feeds)} configured threat intelligence feeds:")
        for f in feeds:
            print(f"    - {f['name']} ({f['feed_type']}) | Status: {f['sync_status']} | Domains: {f['domain_count']}")
        assert len(feeds) >= 4, f"Expected at least 4 default feeds, found {len(feeds)}"
        print(" -> PASS: Threat intelligence feeds active and queryable.\n")

        # -------------------------------------------------------------
        # TEST 2: Threat Summary API
        # -------------------------------------------------------------
        print("[TEST 2] Verifying Threat Summary Telemetry...")
        res = client.get('/api/threats/summary')
        assert res.status_code == 200
        summary = res.get_json()
        print(f" -> Malicious Domains: {summary['malicious_domains_count']}")
        print(f" -> Active Domain Rules: {summary['domain_rules_count']}")
        print(f" -> Active Threat Feeds: {summary['threat_feeds_count']}")
        assert summary['malicious_domains_count'] > 0
        assert summary['domain_rules_count'] > 0
        print(" -> PASS: Telemetry summary operational.\n")

        # -------------------------------------------------------------
        # TEST 3: Domain Rule Testing Sandbox - Clean Domain (Whitelist Immunity)
        # -------------------------------------------------------------
        print("[TEST 3] Testing Sandbox against Clean Corporate Domain (accounts.google.com)...")
        res = client.post('/api/threats/sandbox/evaluate', json={'domain': 'accounts.google.com'})
        assert res.status_code == 200
        report = res.get_json()
        print(f" -> Verdict: {report['verdict']} | Score: {report['threat_score']} | Whitelist: {report['diagnostics']['is_whitelisted']}")
        assert report['verdict'] == 'SAFE', f"Expected SAFE, got {report['verdict']}"
        assert report['threat_score'] == 0, f"Expected score 0, got {report['threat_score']}"
        assert report['diagnostics']['is_whitelisted'] is True
        print(" -> PASS: Clean domain correctly given whitelist immunity with 0 score.\n")

        # -------------------------------------------------------------
        # TEST 4: Domain Rule Testing Sandbox - Malicious Feed Match
        # -------------------------------------------------------------
        print("[TEST 4] Testing Sandbox against Known Malware Feed Domain (malicious-site.net)...")
        res = client.post('/api/threats/sandbox/evaluate', json={'domain': 'malicious-site.net'})
        assert res.status_code == 200
        report = res.get_json()
        print(f" -> Verdict: {report['verdict']} | Score: {report['threat_score']} | Action: {report['action']}")
        print(f" -> Breakdown: {report['score_breakdown']}")
        assert report['verdict'] in ('SUSPICIOUS', 'BLOCKED')
        assert report['threat_score'] >= 70
        assert report['diagnostics']['threat_feed']['matched'] is True
        print(" -> PASS: Malware feed match recognized with high threat score.\n")

        # -------------------------------------------------------------
        # TEST 5: Domain Rule Testing Sandbox - Brand Impersonation Phishing
        # -------------------------------------------------------------
        print("[TEST 5] Testing Sandbox against Phishing Lure (login-verify-paypal-security.xyz)...")
        res = client.post('/api/threats/sandbox/evaluate', json={'domain': 'login-verify-paypal-security.xyz'})
        assert res.status_code == 200
        report = res.get_json()
        print(f" -> Verdict: {report['verdict']} | Score: {report['threat_score']} | Targeted Brand: {report['diagnostics']['brand_impersonation']['targeted_brand']}")
        print(f" -> Lures Detected: {report['diagnostics']['brand_impersonation']['lures']}")
        assert report['verdict'] in ('SUSPICIOUS', 'BLOCKED')
        assert report['threat_score'] >= 70
        assert report['diagnostics']['brand_impersonation']['detected'] is True
        assert report['diagnostics']['brand_impersonation']['targeted_brand'] == 'Paypal'
        print(" -> PASS: Brand impersonation heuristic accurately caught phishing domain.\n")

        # -------------------------------------------------------------
        # TEST 6: Domain Rule Testing Sandbox - Algorithmic DGA (Shannon Entropy)
        # -------------------------------------------------------------
        print("[TEST 6] Testing Sandbox against Algorithmic DGA (x8fk29pvm10zq91.top)...")
        res = client.post('/api/threats/sandbox/evaluate', json={'domain': 'x8fk29pvm10zq91.top'})
        assert res.status_code == 200
        report = res.get_json()
        entropy = report['diagnostics']['lexical']['entropy']
        print(f" -> Verdict: {report['verdict']} | Score: {report['threat_score']} | Shannon Entropy: {entropy}")
        print(f" -> DGA Candidate: {report['diagnostics']['lexical']['is_dga_candidate']}")
        assert report['threat_score'] >= 50
        assert entropy >= 3.5
        assert report['diagnostics']['lexical']['is_dga_candidate'] is True
        print(" -> PASS: Shannon entropy model successfully identified DGA characteristics.\n")

        # -------------------------------------------------------------
        # TEST 7: Domain Rule Testing Sandbox - Batch Stress Evaluation
        # -------------------------------------------------------------
        print("[TEST 7] Testing Batch Sandbox Evaluation...")
        batch_domains = [
            "accounts.google.com",
            "wikipedia.org",
            "malicious-site.net",
            "login-verify-paypal-security.xyz",
            "x8fk29pvm10zq91.top"
        ]
        res = client.post('/api/threats/sandbox/batch', json={'domains': batch_domains})
        assert res.status_code == 200
        batch_report = res.get_json()
        print(f" -> Processed: {batch_report['total']} domains | Clean: {batch_report['clean_count']} | Suspicious: {batch_report['suspicious_count']} | Blocked: {batch_report['blocked_count']}")
        assert batch_report['total'] == 5
        assert batch_report['clean_count'] >= 2
        assert batch_report['blocked_count'] >= 1
        print(" -> PASS: Batch stress evaluation executed successfully.\n")

        # -------------------------------------------------------------
        # TEST 8: Real-Time DNS Packet Ingestion Through Sniffer
        # -------------------------------------------------------------
        print("[TEST 8] Verifying Real-Time Packet Sniffer Ingestion with Enhanced Engine...")
        status, reason, rule_id, alert, cat = detection_engine.evaluate_dns_request("192.168.1.50", "login-verify-paypal-security.xyz")
        print(f" -> Packet evaluation for 'login-verify-paypal-security.xyz' -> Status: {status} | Reason: {reason}")
        assert status in ("SUSPICIOUS", "BLOCKED")
        assert alert is not None
        print(" -> PASS: Real-time sniffer packet evaluation triggers alerts appropriately.\n")

        print("=" * 70)
        print("  ALL REAL-WORLD THREAT DETECTION & SANDBOX TESTS PASSED!")
        print("=" * 70 + "\n")

if __name__ == "__main__":
    run_tests()
