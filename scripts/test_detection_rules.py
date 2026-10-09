import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from services.detection_engine import DetectionEngine

def test_rules():
    engine = DetectionEngine()
    
    print("=" * 70)
    print("   Testing 12 Comprehensive Domain Heuristic & Pattern Rules")
    print("=" * 70)
    
    rules = engine.domain_rules
    print(f"[+] Loaded {len(rules)} detection rules into DetectionEngine memory.\n")
    assert len(rules) >= 12, f"Expected at least 12 rules, got {len(rules)}"
    
    test_cases = [
        # (domain, expected_status, expected_rule_name)
        ("01af82c90e21a8b112233445566778899.tunnel.attacker-exfil.net", "BLOCKED", "DNS Tunneling"),
        ("pool.supportxmr.com", "BLOCKED", "Cryptomining"),
        ("ransom-payment-portal.onion.ws", "BLOCKED", "Ransomware"),
        ("attacker-c2.duckdns.org", "SUSPICIOUS", "Dynamic DNS"),
        ("secure-banking-alert.com", "SUSPICIOUS", "Banking"),
        ("wallet-connect-airdrop.net", "SUSPICIOUS", "Crypto Wallet"),
        ("agent-heartbeat.badc2.org", "BLOCKED", "Malware C2"),
        ("192-168-1-1.nip.io", "BLOCKED", "IP Literal"),
        ("paypal-security-login.org", "SUSPICIOUS", "Targeted Brand"),
        ("payload.quest", "SUSPICIOUS", "Suspicious TLDs"),
        ("admin@portal.net", "BLOCKED", "Blocked IP"),
        ("login-verify-account.com", "SUSPICIOUS", "Phishing Keywords"),
        
        # Legitimate domains (Immunity and false positive check)
        ("accounts.google.com", "SAFE", "Safe Whitelist"),
        ("www.microsoft.com", "SAFE", "Safe Whitelist"),
        ("github.com", "SAFE", "Safe Whitelist"),
        ("render.com", "SAFE", "Safe Whitelist"),
        ("wikipedia.org", "SAFE", "Safe Whitelist"),
        ("chase.com", "SAFE", "Safe Whitelist"),
        ("paypal.com", "SAFE", "Safe Whitelist")
    ]
    
    passed = 0
    for domain, expected_status, desc in test_cases:
        status, reason, rule_id, alert, cat = engine.evaluate_dns_request("192.168.1.100", domain)
        print(f"[*] {domain:<62} -> {status:<10} (Expected: {expected_status}) | Reason: {reason or 'None'}")
        assert status == expected_status, f"Failed for {domain}: got {status}, expected {expected_status}"
        passed += 1
        
    print("\n" + "=" * 70)
    print(f" ALL {passed} TESTS PASSED SUCCESSFULLY! ZERO FALSE POSITIVES.")
    print("=" * 70)

if __name__ == "__main__":
    test_rules()
