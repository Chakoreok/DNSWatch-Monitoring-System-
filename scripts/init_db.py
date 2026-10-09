import os
import sys

# Ensure d:\DNS is on python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pymysql
from flask import Flask
from config import Config
from database import db
from models import Role, User, DetectionRule, MaliciousDomain, FrequencyRuleConfig

def migrate_missing_columns():
    """Ensure existing tables have all required columns without dropping existing data."""
    conn = pymysql.connect(
        host=Config.DB_HOST,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
        port=int(Config.DB_PORT),
        database=Config.DB_NAME
    )
    with conn.cursor() as cur:
        # Check detection_rules columns
        cur.execute("DESCRIBE detection_rules;")
        cols = [c[0] for c in cur.fetchall()]
        if 'action' not in cols:
            print("Adding 'action' column to detection_rules...")
            cur.execute("ALTER TABLE detection_rules ADD COLUMN action VARCHAR(20) NOT NULL DEFAULT 'Alert';")
            
        # Check dns_logs columns
        cur.execute("DESCRIBE dns_logs;")
        cols = [c[0] for c in cur.fetchall()]
        if 'activity_category' not in cols:
            print("Adding 'activity_category' column to dns_logs...")
            cur.execute("ALTER TABLE dns_logs ADD COLUMN activity_category VARCHAR(30) NOT NULL DEFAULT 'Standard query';")
            
        conn.commit()
    conn.close()

def init_database():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    
    migrate_missing_columns()
    
    with app.app_context():
        print("Creating MySQL tables in dnswatch_db if not exist...")
        db.create_all()
        
        # 1. Ensure Roles
        roles_data = [
            ("Administrator", "Full system administrator access"),
            ("Security Analyst", "Monitor real-time activity and investigate alerts"),
            ("Viewer", "Read-only dashboard access")
        ]
        for name, desc in roles_data:
            role = Role.query.filter_by(name=name).first()
            if not role:
                role = Role(name=name, description=desc)
                db.session.add(role)
        db.session.commit()
        
        admin_role = Role.query.filter_by(name="Administrator").first()
        analyst_role = Role.query.filter_by(name="Security Analyst").first()
        viewer_role = Role.query.filter_by(name="Viewer").first()
        
        # 2. Ensure Users
        users_data = [
            ("admin", "admin@dnswatch.local", "admin123", admin_role.id, "Administrator", "ACTIVE"),
            ("analyst", "analyst@dnswatch.local", "analyst123", analyst_role.id, "Security Analyst", "ACTIVE"),
            ("viewer", "viewer@dnswatch.local", "viewer123", viewer_role.id, "System Viewer", "ACTIVE")
        ]
        for username, email, pwd, role_id, full_name, status in users_data:
            user = User.query.filter_by(username=username).first()
            if not user:
                user = User(username=username, email=email, role_id=role_id, full_name=full_name, status=status)
                user.set_password(pwd)
                db.session.add(user)
            else:
                user.set_password(pwd)
        db.session.commit()
        
        # 3. Ensure Frequency Rule Config
        freq_config = FrequencyRuleConfig.query.first()
        if not freq_config:
            freq_config = FrequencyRuleConfig(
                threshold=Config.DEFAULT_FREQUENCY_THRESHOLD,
                time_window=Config.DEFAULT_FREQUENCY_WINDOW,
                action="Alert",
                status="Active"
            )
            db.session.add(freq_config)
            db.session.commit()
            print("Initialized default Frequency Rule Configuration (100 queries / 60 seconds).")
            
        # 4. Ensure Default Malicious Domains (from UI mockup)
        seed_malicious_domains = [
            ("malicious-site.net", "Malware / Phishing", "HIGH", "Known malicious domain delivering trojans", "Active", "admin"),
            ("phishing-alert.com", "Phishing", "HIGH", "Credential harvesting login portal", "Active", "admin"),
            ("bad-downloads.com", "Malware Distribution", "HIGH", "Hosts malicious executable payloads", "Active", "admin"),
            ("tracker.badsite.org", "Spyware / Tracker", "MEDIUM", "Telemetry tracker and ad injection", "Active", "admin"),
            ("malware-hosting.net", "C2 Infrastructure", "HIGH", "Command and Control server", "Active", "admin"),
            ("suspicious-domain.xyz", "Phishing", "MEDIUM", "Newly registered suspicious domain", "Active", "admin")
        ]
        for domain, cat, sev, desc, stat, added_by in seed_malicious_domains:
            exists = MaliciousDomain.query.filter_by(domain=domain).first()
            if not exists:
                db.session.add(MaliciousDomain(
                    domain=domain,
                    category=cat,
                    severity=sev,
                    description=desc,
                    status=stat,
                    added_by=added_by
                ))
        db.session.commit()
        print("Initialized Malicious Domains.")
        
        # 5. Ensure Default Domain Rules
        seed_rules = [
            (
                "Phishing Keywords Pattern",
                "KEYWORD",
                "login-verify, account-update, secure-banking, auth-portal, wallet-connect, verify-account, password-reset, security-challenge, credential-check",
                "Phishing / Social Engineering",
                "MEDIUM",
                "Alert",
                "Flags domains containing high-risk compound phishing keywords (e.g. login-verify, account-update, password-reset)."
            ),
            (
                "Suspicious TLDs",
                "TLD_BLACKLIST",
                ".xyz, .top, .club, .online, .info, .tk, .ml, .ga, .cf, .gq, .buzz, .fit, .country, .loan, .work, .click, .surf, .rest, .cam, .quest",
                "Suspicious Pattern",
                "MEDIUM",
                "Alert",
                "Flags domains using top-level domains statistically abused in bulk malware and automated phishing campaigns."
            ),
            (
                "Blocked IP in Domain",
                "PATTERN",
                "@*, *:*, */*",
                "DNS Spoofing / Malformed",
                "HIGH",
                "Block",
                "Blocks queries formatted with suspicious embedded IP patterns, credentials, or illegal URL injection symbols."
            ),
            (
                "DNS Tunneling & Data Exfiltration",
                "REGEX",
                "^[a-f0-9]{24,}\\..+|^[a-z0-9_-]{32,}\\..+",
                "Data Exfiltration / C2 Tunnel",
                "HIGH",
                "Block",
                "Detects abnormally long hex or base64-encoded subdomains characteristic of DNS tunneling utilities (iodine, dnscat2, Cobalt Strike)."
            ),
            (
                "Cryptomining & Mining Pools",
                "KEYWORD",
                "supportxmr, xmrpool, minexmr, nanopool, ethermine, monerohash, coinhive, crypto-loot, cryptonight",
                "Cryptomining / Malware",
                "HIGH",
                "Block",
                "Blocks DNS lookups to known cryptocurrency mining pools and unauthorized web miner infrastructure."
            ),
            (
                "Ransomware C2 & Darknet Gateways",
                "KEYWORD",
                "tor2web, onion.pet, onion.ws, onion.ly, decrypt-files, restore-files, ransom-payment, lockbit, blackcat",
                "Ransomware / Extortion",
                "HIGH",
                "Block",
                "Identifies ransomware command and control channels, extortion payment portals, and public Tor clearweb gateways."
            ),
            (
                "Dynamic DNS & Ephemeral Tunneling",
                "PATTERN",
                "*.duckdns.org, *.ngrok-free.app, *.ngrok.io, *.localtunnel.me, *.hopto.org, *.zapto.org, *.bounceme.net, *.ddns.net, *.no-ip.org",
                "Dynamic DNS / C2 Rendezvous",
                "MEDIUM",
                "Alert",
                "Flags dynamic DNS providers frequently abused for ephemeral C2 hosting and malicious fast-flux redirection."
            ),
            (
                "Banking & Financial Fraud Lures",
                "KEYWORD",
                "secure-banking, ebanking-login, bank-security-update, kyc-verification, claims-refund, tax-refund-portal, id-verification-login",
                "Financial Phishing",
                "HIGH",
                "Alert",
                "Flags aggressive compound phishing lures targeting online banking, KYC identity submission, and fake tax refunds."
            ),
            (
                "Crypto Wallet Drainer & Phishing",
                "KEYWORD",
                "wallet-connect, claim-airdrop, sync-wallet, validate-seed, metamask-recovery, ledger-support, binance-security",
                "Crypto Theft / Social Engineering",
                "HIGH",
                "Alert",
                "Detects malicious Web3 crypto drainers and deceptive wallet seed phrase harvesting portals."
            ),
            (
                "Malware C2 & Reverse Shell Indicators",
                "KEYWORD",
                "c2-server, beacon-connect, payload-delivery, rat-connect, agent-heartbeat, shell-connect, reverse-tcp",
                "Malware C2 / Backdoor",
                "HIGH",
                "Block",
                "Blocks domain indicators used by Remote Access Trojans (RATs) and interactive reverse shell listeners."
            ),
            (
                "IP Literal Wildcard DNS Evasion",
                "REGEX",
                "^(?:[0-9]{1,3}[-._]){3}[0-9]{1,3}\\.(?:nip\\.io|sslip\\.io|xip\\.io)$",
                "Evasion / Proxy Bypass",
                "HIGH",
                "Block",
                "Blocks wildcard DNS resolving services (nip.io, sslip.io) weaponized by threat actors to route directly to attacker IP literals."
            ),
            (
                "Targeted Brand Impersonation Compounds",
                "REGEX",
                ".*(?:paypal|microsoft|google|apple|amazon|netflix|chase|binance|coinbase|metamask|steam)-(?:[a-z0-9_-]*-)?(?:login|verify|account|security|support|portal|banking|wallet).*",
                "Phishing / Brand Impersonation",
                "HIGH",
                "Alert",
                "Catches deceptive brand compounds impersonating major tech and banking platforms paired with credential-stealing actions."
            )
        ]
        for name, rtype, pattern, cat, sev, action, desc in seed_rules:
            exists = DetectionRule.query.filter_by(rule_name=name).first()
            if not exists:
                db.session.add(DetectionRule(
                    rule_name=name,
                    rule_type=rtype,
                    pattern=pattern,
                    category=cat,
                    severity=sev,
                    action=action,
                    description=desc,
                    is_active=True
                ))
            elif name in ("Phishing Keywords Pattern", "Suspicious TLDs", "Blocked IP in Domain"):
                exists.pattern = pattern
                exists.description = desc
        db.session.commit()
        print("Initialized Comprehensive Domain Detection Rules.")
        
        print("Database initialization complete successfully!")

if __name__ == "__main__":
    init_database()
