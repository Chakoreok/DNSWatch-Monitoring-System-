import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from database import db
from models import DetectionRule
from services.detection_engine import detection_engine

app = create_app()

with app.app_context():
    print("Updating detection_rules table with comprehensive cybersecurity heuristic rules...")
    
    rules_data = [
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

    for name, rtype, pattern, cat, sev, action, desc in rules_data:
        rule = DetectionRule.query.filter_by(rule_name=name).first()
        if not rule:
            rule = DetectionRule(
                rule_name=name,
                rule_type=rtype,
                pattern=pattern,
                category=cat,
                severity=sev,
                action=action,
                description=desc,
                is_active=True
            )
            db.session.add(rule)
            print(f" [+] Added rule: {name} ({rtype})")
        else:
            rule.pattern = pattern
            rule.rule_type = rtype
            rule.category = cat
            rule.severity = sev
            rule.action = action
            rule.description = desc
            rule.is_active = True
            print(f" [*] Updated rule: {name} ({rtype})")

    db.session.commit()
    detection_engine.reload_cache()

    print("\n" + "=" * 95)
    print(f"{'ID':<4} | {'Rule Name':<38} | {'Type':<14} | {'Action':<6} | {'Severity':<6}")
    print("=" * 95)
    for r in DetectionRule.query.order_by(DetectionRule.id.asc()).all():
        print(f"{r.id:<4} | {r.rule_name:<38} | {r.rule_type:<14} | {r.action:<6} | {r.severity:<6}")
    print("=" * 95)
    print(f"\nSuccessfully synchronized {DetectionRule.query.count()} detection rules in the database!")
