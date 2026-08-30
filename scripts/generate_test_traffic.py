import os
import sys
import time
import requests
import random

# Base API URL
API_BASE = "http://127.0.0.1:5000"

SAFE_DOMAINS = [
    ("google.com", "142.250.190.78", "A"),
    ("facebook.com", "157.240.22.35", "A"),
    ("youtube.com", "142.250.190.78", "A"),
    ("update.windows.com", "13.107.42.16", "A"),
    ("netflix.com", "54.230.156.13", "A"),
    ("discord.com", "162.159.136.232", "A"),
    ("wikipedia.org", "208.80.154.224", "A"),
    ("github.com", "140.82.121.4", "A"),
    ("microsoft.com", "20.190.128.18", "A"),
    ("instagram.com", "157.240.22.174", "A")
]

MALICIOUS_DOMAINS = [
    ("malicious-site.net", "185.199.111.153", "A"),
    ("phishing-alert.com", "104.21.64.1", "A"),
    ("bad-downloads.com", "172.67.141.45", "A"),
    ("tracker.badsite.org", "172.67.141.45", "A"),
    ("malware-hosting.net", "198.51.100.22", "A")
]

RULE_TRIGGER_DOMAINS = [
    ("login-verify-account.com", "203.0.113.10", "A"),     # Keyword: login, verify, account
    ("secure-banking-portal.org", "203.0.113.11", "A"),   # Keyword: secure, banking
    ("phishing-test-domain.xyz", "203.0.113.12", "A"),    # TLD: .xyz
    ("malware-drop.top", "203.0.113.13", "A"),            # TLD: .top
    ("update-wallet-auth.net", "203.0.113.14", "A")       # Keyword: wallet, update
]

CLIENT_IPS = [
    "192.168.254.108",
    "192.168.1.10",
    "192.168.1.15",
    "192.168.1.18",
    "192.168.1.12",
    "192.168.1.8",
    "192.168.1.20"
]

def simulate_query(client_ip, domain, query_type="A", response_ip=None):
    try:
        res = requests.post(f"{API_BASE}/api/monitoring/simulate", json={
            "client_ip": client_ip,
            "domain": domain,
            "query_type": query_type,
            "response_ip": response_ip
        }, timeout=2)
        if res.status_code == 200:
            d = res.json()
            status = d.get('status', 'SAFE')
            alert = d.get('alert')
            alert_str = f" -> ALERT: {alert['alert_type']}" if alert else ""
            print(f"[{status}] {client_ip} queried {domain} ({query_type}){alert_str}")
            return d
    except Exception as e:
        print(f"Failed to send query: {e}")
    return None

def run_simulation(duration_seconds=30, delay_between=0.5):
    print(f"Starting DNSWatch Traffic Generator ({duration_seconds}s)...")
    end_time = time.time() + duration_seconds
    
    count = 0
    while time.time() < end_time:
        count += 1
        client = random.choice(CLIENT_IPS)
        roll = random.random()
        
        if roll < 0.65:
            # 65% Normal safe traffic
            dom, ip, qtype = random.choice(SAFE_DOMAINS)
            simulate_query(client, dom, qtype, ip)
        elif roll < 0.85:
            # 20% Malicious domain blacklist match
            dom, ip, qtype = random.choice(MALICIOUS_DOMAINS)
            simulate_query(client, dom, qtype, ip)
        else:
            # 15% Domain rule triggers (keywords, suspicious TLDs)
            dom, ip, qtype = random.choice(RULE_TRIGGER_DOMAINS)
            simulate_query(client, dom, qtype, ip)
            
        time.sleep(delay_between)
        
    print(f"Simulation finished: {count} queries sent.")

def trigger_frequency_flood(client_ip="192.168.254.108", count=105):
    print(f"Simulating DNS query frequency burst ({count} queries from {client_ip})...")
    triggered = 0
    for i in range(count):
        d = simulate_query(client_ip, f"burst-query-{i}.example.org", "A", "93.184.216.34")
        if d and d.get('alert'):
            triggered += 1
    print(f"Frequency burst complete. Alerts generated: {triggered}")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--flood":
        trigger_frequency_flood()
    else:
        run_simulation(duration_seconds=15, delay_between=0.3)
