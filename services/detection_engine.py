import re
import math
import time
import uuid
import socket
import threading
from collections import defaultdict, deque, Counter
from datetime import datetime
from flask import has_app_context
from models import MaliciousDomain, DetectionRule, FrequencyRuleConfig, ManualBlockRule, DomainWhitelist

# List of generic words that must never trigger broad substring matching on legitimate domains
GENERIC_SAFE_WORDS = {
    'account', 'accounts', 'login', 'secure', 'verify', 'mail', 'service',
    'cloud', 'support', 'update', 'api', 'app', 'auth', 'portal', 'connect',
    'admin', 'home', 'shop', 'store', 'news', 'blog', 'static', 'cdn'
}

# Real-world trusted top domains & CDNs (Protected from heuristic false positives)
SAFE_TOP_DOMAINS = {
    'google.com', 'google.co.uk', 'google.ca', 'googleapis.com', 'gstatic.com', 'googleusercontent.com',
    'microsoft.com', 'windows.com', 'live.com', 'office.com', 'office365.com', 'azure.com',
    'microsoftonline.com', 'msftconnecttest.com', 'windowsupdate.com', 'apple.com', 'icloud.com', 'apple-dns.net',
    'amazon.com', 'amazonaws.com', 'cloudfront.net', 'cloudflare.com', 'cloudflare-dns.com',
    'github.com', 'github.io', 'githubusercontent.com', 'railway.app', 'railway.com', 'render.com',
    'fastly.net', 'akamaized.net', 'akamai.net', 'facebook.com', 'fbcdn.net', 'whatsapp.com',
    'twitter.com', 'x.com', 'linkedin.com', 'wikipedia.org', 'youtube.com', 'yahoo.com',
    'netflix.com', 'nflxvideo.net', 'spotify.com', 'zoom.us', 'slack.com', 'discord.com',
    'discord.gg', 'steamcommunity.com', 'steampowered.com', 'dropbox.com', 'adobe.com',
    'salesforce.com', 'bankofamerica.com', 'chase.com', 'wellsfargo.com', 'paypal.com'
}

# High-profile brands frequently targeted by phishing and typosquatting attacks
PROTECTED_BRANDS = {
    'paypal': ['paypal.com', 'paypal.me'],
    'google': ['google.com', 'googleapis.com', 'gstatic.com'],
    'microsoft': ['microsoft.com', 'windows.com', 'live.com', 'office.com', 'azure.com', 'microsoftonline.com'],
    'apple': ['apple.com', 'icloud.com'],
    'amazon': ['amazon.com', 'amazonaws.com'],
    'netflix': ['netflix.com'],
    'chase': ['chase.com'],
    'bankofamerica': ['bankofamerica.com'],
    'wellsfargo': ['wellsfargo.com'],
    'binance': ['binance.com'],
    'coinbase': ['coinbase.com'],
    'metamask': ['metamask.io'],
    'steamcommunity': ['steamcommunity.com', 'steampowered.com'],
    'facebook': ['facebook.com', 'fb.com'],
    'instagram': ['instagram.com'],
    'discord': ['discord.com', 'discord.gg'],
    'telegram': ['telegram.org', 't.me']
}

PHISHING_LURES = {
    'login', 'signin', 'verify', 'verification', 'security', 'account',
    'update', 'auth', 'portal', 'wallet', 'support', 'billing', 'recover',
    'recovery', 'password', 'session', 'claim', 'kyc', 'validate', 'unlock'
}

HIGH_RISK_TLDS = {
    'top', 'xyz', 'buzz', 'fit', 'country', 'loan', 'work', 'click',
    'surf', 'tk', 'ml', 'cf', 'ga', 'gq', 'rest', 'cam', 'quest'
}


def calculate_shannon_entropy(text):
    """Calculates mathematical Shannon entropy: H(S) = -sum(p * log2(p))."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def analyze_domain_lexical(domain):
    """Extracts lexical and entropy features for Algorithmic DGA detection."""
    parts = domain.lower().strip('.').split('.')
    sld = parts[-2] if len(parts) >= 2 else parts[0]
    
    entropy = calculate_shannon_entropy(sld)
    vowels = set('aeiou')
    alpha_chars = [c for c in sld if c.isalpha()]
    vowel_count = sum(1 for c in alpha_chars if c in vowels)
    vowel_ratio = round(vowel_count / len(alpha_chars), 3) if alpha_chars else 0.0
    
    digit_count = sum(1 for c in sld if c.isdigit())
    digit_ratio = round(digit_count / len(sld), 3) if sld else 0.0
    
    max_consonants = 0
    current_consonants = 0
    for c in sld:
        if c.isalpha() and c not in vowels:
            current_consonants += 1
            if current_consonants > max_consonants:
                max_consonants = current_consonants
        else:
            current_consonants = 0
            
    is_dga = False
    if len(sld) >= 9:
        if entropy >= 3.8:
            is_dga = True
        elif entropy >= 3.4 and (max_consonants >= 4 or vowel_ratio <= 0.15 or digit_ratio >= 0.25):
            is_dga = True
            
    return {
        'sld': sld,
        'entropy': entropy,
        'vowel_ratio': vowel_ratio,
        'digit_ratio': digit_ratio,
        'max_consonant_cluster': max_consonants,
        'is_dga_candidate': is_dga
    }


def analyze_brand_impersonation(domain):
    """Detects brand typosquatting, deceptive subdomains, and lure combinations."""
    domain_clean = domain.lower().strip('.')
    tokens = set(re.split(r'[.\-_]', domain_clean))
    
    for brand, legit_domains in PROTECTED_BRANDS.items():
        # Check if domain belongs to official brand
        is_official = any(domain_clean == leg or domain_clean.endswith('.' + leg) for leg in legit_domains)
        if is_official:
            continue
            
        has_brand = (brand in tokens) or (brand in domain_clean)
        is_typo = False
        if not has_brand:
            # Common homoglyph typo substitutions
            typo_variants = [
                brand.replace('o', '0'),
                brand.replace('l', '1'),
                brand.replace('i', '1'),
                brand.replace('e', '3'),
                brand.replace('s', '5')
            ]
            for variant in typo_variants:
                if variant != brand and (variant in tokens or variant in domain_clean):
                    has_brand = True
                    is_typo = True
                    break
                    
        if has_brand:
            matched_lures = [lure for lure in PHISHING_LURES if lure in tokens or lure in domain_clean]
            if matched_lures or is_typo:
                return {
                    'detected': True,
                    'targeted_brand': brand.capitalize(),
                    'is_typosquat': is_typo,
                    'lures': matched_lures,
                    'confidence': 'HIGH' if (matched_lures and is_typo) or len(matched_lures) >= 2 or '-' in domain_clean else 'MEDIUM'
                }
    return {'detected': False, 'targeted_brand': None, 'is_typosquat': False, 'lures': [], 'confidence': 'NONE'}


def analyze_dns_tunneling(domain):
    """Detects deep subdomain nesting and high-entropy base32/hex exfiltration queries."""
    parts = domain.lower().strip('.').split('.')
    subdomains = parts[:-2] if len(parts) > 2 else []
    
    max_label_len = max((len(p) for p in parts), default=0)
    subdomain_depth = len(subdomains)
    
    is_tunnel = False
    hex_chars = set('0123456789abcdef')
    for label in subdomains:
        if len(label) >= 30:
            hex_ratio = sum(1 for c in label if c in hex_chars) / len(label)
            if hex_ratio >= 0.85:
                is_tunnel = True
                break
                
    if subdomain_depth >= 4 and max_label_len >= 20:
        is_tunnel = True
        
    return {
        'subdomain_depth': subdomain_depth,
        'max_label_length': max_label_len,
        'is_tunnel_candidate': is_tunnel
    }


def resolve_domain_dns(domain):
    """Executes socket-level DNS A-record resolution to determine if domain is live on public internet."""
    clean = domain.strip().lower().rstrip('.')
    res = {'resolved': False, 'ips': [], 'status': 'Unknown', 'error': None}
    try:
        addr_info = socket.getaddrinfo(clean, None, socket.AF_INET, socket.SOCK_STREAM)
        ips = list(set([item[4][0] for item in addr_info]))
        if ips:
            res['resolved'] = True
            res['ips'] = ips[:4]
            res['status'] = f"Active ({len(ips)} IP resolved)"
        else:
            res['status'] = "No A-records returned"
    except socket.gaierror:
        res['resolved'] = False
        res['error'] = 'NXDOMAIN'
        res['status'] = 'NXDOMAIN (Unresolved / Dead or Sinkholed)'
    except Exception as e:
        res['resolved'] = False
        res['error'] = str(e)
        res['status'] = f"Lookup error: {e}"
    return res


class DetectionEngine:
    """
    DNSWatch Multi-Tier Cybersecurity Detection & Heuristic Engine:
    - Tier 0: Manual Admin Blocks & Dynamic Sinkhole Enforcement
    - Immunity: Trusted Corporate & Top-Tier Domain Whitelist
    - Tier 1: Real-World Malicious Threat Feeds (URLhaus, OpenPhish, ThreatFox)
    - Tier 2: Heuristic & Pattern Rules (Keywords, TLDs, Regex, Shannon Entropy DGA, Typosquatting)
    - Tier 3: DNS Query Burst Rate Limiting
    """
    
    def __init__(self):
        self._lock = threading.RLock()
        self.app = None
        
        # In-memory caches for high-throughput packet processing
        self.malicious_domains = {}  # domain.lower() -> MaliciousDomain dict
        self.domain_rules = self._get_default_compiled_rules()  # Pre-populated defaults
        self.custom_whitelist = set()  # Set of normalized whitelisted domains
        
        # Frequency rule state
        self.frequency_threshold = 100
        self.frequency_window = 60  # seconds
        self.frequency_action = "Alert"
        self.frequency_status = "Active"
        
        # Per-client IP query timestamp queues: client_ip -> deque([timestamp, ...])
        self.client_query_history = defaultdict(deque)
        
        # Alert deduplication tracker: (client_ip, domain, alert_type) -> last_alert_time
        self.alert_throttling = {}
        self.alert_cooldown = 15.0  # seconds cooldown between identical alerts
        
        self.last_cache_reload = 0
        self.cache_ttl = 15  # seconds

        # Manual block rules (Tier 0 — admin-approved, highest priority)
        self.manual_block_rules = {}  # normalized_domain -> {'domain':..., 'reason':...}

    def _get_default_compiled_rules(self):
        """Returns standard pre-compiled cybersecurity heuristic rules when DB is not yet seeded."""
        default_defs = [
            (1, "Phishing Keywords Pattern", "KEYWORD", "login-verify, account-update, secure-banking, auth-portal, wallet-connect, verify-account, password-reset, security-challenge, credential-check", "Phishing / Social Engineering", "MEDIUM", "Alert", "Flags domains containing high-risk compound phishing keywords (e.g. login-verify, account-update)."),
            (2, "Suspicious TLDs", "TLD_BLACKLIST", ".xyz, .top, .club, .online, .info, .tk, .ml, .ga, .cf, .gq, .buzz, .fit, .country, .loan, .work, .click, .surf, .rest, .cam, .quest", "Suspicious Pattern", "MEDIUM", "Alert", "Flags domains using top-level domains statistically abused in bulk malware and automated phishing campaigns."),
            (3, "Blocked IP in Domain", "PATTERN", "*@*, @*, *:*, */*", "DNS Spoofing / Malformed", "HIGH", "Block", "Blocks queries formatted with suspicious embedded IP patterns, credentials, or illegal URL injection symbols."),
            (4, "DNS Tunneling & Data Exfiltration", "REGEX", r"^[a-f0-9]{24,}\..+|^[a-z0-9_-]{32,}\..+", "Data Exfiltration / C2 Tunnel", "HIGH", "Block", "Detects abnormally long hex or base64-encoded subdomains characteristic of DNS tunneling utilities (iodine, dnscat2, Cobalt Strike)."),
            (5, "Cryptomining & Mining Pools", "KEYWORD", "supportxmr, xmrpool, minexmr, nanopool, ethermine, monerohash, coinhive, crypto-loot, cryptonight", "Cryptomining / Malware", "HIGH", "Block", "Blocks DNS lookups to known cryptocurrency mining pools and unauthorized web miner infrastructure."),
            (6, "Ransomware C2 & Darknet Gateways", "KEYWORD", "tor2web, onion.pet, onion.ws, onion.ly, decrypt-files, restore-files, ransom-payment, lockbit, blackcat", "Ransomware / Extortion", "HIGH", "Block", "Identifies ransomware command and control channels, extortion payment portals, and public Tor clearweb gateways."),
            (7, "Dynamic DNS & Ephemeral Tunneling", "PATTERN", "*.duckdns.org, *.ngrok-free.app, *.ngrok.io, *.localtunnel.me, *.hopto.org, *.zapto.org, *.bounceme.net, *.ddns.net, *.no-ip.org", "Dynamic DNS / C2 Rendezvous", "MEDIUM", "Alert", "Flags dynamic DNS providers frequently abused for ephemeral C2 hosting and malicious fast-flux redirection."),
            (8, "Banking & Financial Fraud Lures", "KEYWORD", "secure-banking, ebanking-login, bank-security-update, kyc-verification, claims-refund, tax-refund-portal, id-verification-login", "Financial Phishing", "HIGH", "Alert", "Flags aggressive compound phishing lures targeting online banking, KYC identity submission, and fake tax refunds."),
            (9, "Crypto Wallet Drainer & Phishing", "KEYWORD", "wallet-connect, claim-airdrop, sync-wallet, validate-seed, metamask-recovery, ledger-support, binance-security", "Crypto Theft / Social Engineering", "HIGH", "Alert", "Detects malicious Web3 crypto drainers and deceptive wallet seed phrase harvesting portals."),
            (10, "Malware C2 & Reverse Shell Indicators", "KEYWORD", "c2-server, beacon-connect, payload-delivery, rat-connect, agent-heartbeat, shell-connect, reverse-tcp", "Malware C2 / Backdoor", "HIGH", "Block", "Blocks domain indicators used by Remote Access Trojans (RATs) and interactive reverse shell listeners."),
            (11, "IP Literal Wildcard DNS Evasion", "REGEX", r"^(?:[0-9]{1,3}[-._]){3}[0-9]{1,3}\.(?:nip\.io|sslip\.io|xip\.io)$", "Evasion / Proxy Bypass", "HIGH", "Block", "Blocks wildcard DNS resolving services (nip.io, sslip.io) weaponized by threat actors to route directly to attacker IP literals."),
            (12, "Targeted Brand Impersonation Compounds", "REGEX", r".*(?:paypal|microsoft|google|apple|amazon|netflix|chase|binance|coinbase|metamask|steam)-(?:[a-z0-9_-]*-)?(?:login|verify|account|security|support|portal|banking|wallet).*", "Phishing / Brand Impersonation", "HIGH", "Alert", "Catches deceptive brand compounds impersonating major tech and banking platforms paired with credential-stealing actions.")
        ]
        compiled = []
        for rid, name, rtype, pat, cat, sev, action, desc in default_defs:
            rule_dict = {
                'id': rid,
                'rule_name': name,
                'rule_type': rtype,
                'pattern': pat,
                'category': cat,
                'severity': sev,
                'action': action,
                'description': desc
            }
            if rtype == 'KEYWORD':
                rule_dict['keywords'] = [k.strip().lower() for k in pat.split(',') if k.strip()]
            elif rtype == 'TLD_BLACKLIST':
                rule_dict['tlds'] = [t.strip().lower().lstrip('.') for t in pat.split(',') if t.strip()]
            elif rtype == 'REGEX':
                try:
                    rule_dict['compiled_regex'] = re.compile(pat.strip(), re.IGNORECASE)
                except Exception:
                    rule_dict['compiled_regex'] = None
            elif rtype == 'PATTERN':
                raw_patterns = [p.strip() for p in pat.split(',') if p.strip()]
                regex_parts = ['^' + re.escape(p).replace(r'\*', '.*').replace(r'\?', '.') + '$' for p in raw_patterns]
                try:
                    rule_dict['compiled_regex'] = re.compile('(?:' + '|'.join(regex_parts) + ')', re.IGNORECASE) if regex_parts else None
                except Exception:
                    rule_dict['compiled_regex'] = None
            compiled.append(rule_dict)
        return compiled

    def init_app(self, app):
        self.app = app
        
    def reload_cache(self, app=None):
        """Loads malicious domains, whitelist, and detection rules from DB into memory."""
        target_app = app or self.app
        if not has_app_context():
            if target_app:
                with target_app.app_context():
                    self._do_reload_cache()
            return
        self._do_reload_cache()

    def _do_reload_cache(self):
        try:
            with self._lock:
                # 1. Load Malicious Domains
                active_domains = MaliciousDomain.query.filter_by(status='Active').all()
                self.malicious_domains = {
                    d.domain.strip().lower().rstrip('.'): {
                        'id': d.id,
                        'domain': d.domain.strip().lower().rstrip('.'),
                        'category': d.category,
                        'severity': d.severity,
                        'description': d.description,
                        'feed_source': getattr(d, 'feed_source', 'Manual') or 'Manual'
                    }
                    for d in active_domains
                }
                
                # 2. Load Whitelisted Domains
                try:
                    active_whitelist = DomainWhitelist.query.filter_by(is_active=True).all()
                    self.custom_whitelist = {w.domain.strip().lower().rstrip('.') for w in active_whitelist}
                except Exception:
                    self.custom_whitelist = set()
                
                # 3. Load Domain Detection Rules
                active_rules = DetectionRule.query.filter_by(is_active=True).all()
                compiled_rules = []
                for r in active_rules:
                    rule_dict = {
                        'id': r.id,
                        'rule_name': r.rule_name,
                        'rule_type': r.rule_type.upper(),
                        'pattern': r.pattern.strip(),
                        'category': r.category,
                        'severity': r.severity,
                        'action': r.action or 'Alert',
                        'description': r.description
                    }
                    
                    # Pre-compile patterns
                    if rule_dict['rule_type'] == 'KEYWORD':
                        keywords = [k.strip().lower() for k in r.pattern.split(',') if k.strip()]
                        rule_dict['keywords'] = keywords
                    elif rule_dict['rule_type'] == 'TLD_BLACKLIST':
                        tlds = [t.strip().lower().lstrip('.') for t in r.pattern.split(',') if t.strip()]
                        rule_dict['tlds'] = tlds
                    elif rule_dict['rule_type'] == 'REGEX':
                        try:
                            rule_dict['compiled_regex'] = re.compile(r.pattern.strip(), re.IGNORECASE)
                        except Exception:
                            rule_dict['compiled_regex'] = None
                    elif rule_dict['rule_type'] == 'PATTERN':
                        raw_patterns = [p.strip() for p in r.pattern.split(',') if p.strip()]
                        regex_parts = []
                        for pat in raw_patterns:
                            regex_parts.append('^' + re.escape(pat).replace('\\*', '.*').replace('\\?', '.') + '$')
                        if regex_parts:
                            try:
                                combined = '(?:' + '|'.join(regex_parts) + ')'
                                rule_dict['compiled_regex'] = re.compile(combined, re.IGNORECASE)
                            except Exception:
                                rule_dict['compiled_regex'] = None
                        else:
                            rule_dict['compiled_regex'] = None
                            
                    compiled_rules.append(rule_dict)
                self.domain_rules = compiled_rules if compiled_rules else self._get_default_compiled_rules()
                
                # 4. Load Frequency Rule Config
                freq_config = FrequencyRuleConfig.query.first()
                if freq_config:
                    self.frequency_threshold = freq_config.threshold
                    self.frequency_window = freq_config.time_window
                    self.frequency_action = freq_config.action
                    self.frequency_status = freq_config.status
                    
                self.last_cache_reload = time.time()
                # Also load manual block rules (Tier 0)
                self._load_manual_block_rules()
        except Exception as e:
            print(f"[DetectionEngine] Cache reload error: {e}")

    def _load_manual_block_rules(self):
        """Internal: load active ManualBlockRule records (call inside _lock)."""
        try:
            active = ManualBlockRule.query.filter_by(is_active=True).all()
            self.manual_block_rules = {
                r.domain.strip().lower().rstrip('.'): {
                    'domain': r.domain.strip().lower().rstrip('.'),
                    'reason': r.reason or ''
                }
                for r in active
            }
        except Exception:
            self.manual_block_rules = {}

    def reload_manual_blocks(self):
        """Public method called by blocking routes after every rule change."""
        with self._lock:
            self._load_manual_block_rules()

    def normalize_domain(self, domain_name):
        """Standardizes domain format for accurate rule matching."""
        if not domain_name:
            return ""
        domain = domain_name.strip().lower().rstrip('.')
        if domain.endswith('.'):
            domain = domain[:-1]
        return domain

    def is_domain_whitelisted(self, raw_domain):
        """
        Evaluates domain against the trusted whitelist.
        Guarantees strict immunity against false positive heuristic flags.
        """
        domain = self.normalize_domain(raw_domain)
        if not domain:
            return False
        with self._lock:
            # Check exact match
            if domain in SAFE_TOP_DOMAINS or domain in self.custom_whitelist:
                return True
            # Check subdomain match
            parts = domain.split('.')
            for i in range(1, len(parts)):
                parent = '.'.join(parts[i:])
                if parent in SAFE_TOP_DOMAINS or parent in self.custom_whitelist:
                    return True
        return False

    def _should_generate_alert(self, client_ip, domain, alert_type):
        """Deduplicates security alerts within cooldown window per (client_ip, domain, alert_type)."""
        now = time.time()
        throttle_key = (client_ip, domain, alert_type)
        with self._lock:
            last_alert_time = self.alert_throttling.get(throttle_key, 0)
            if now - last_alert_time >= self.alert_cooldown:
                self.alert_throttling[throttle_key] = now
                return True
            return False

    def evaluate_dns_request(self, client_ip, raw_domain, query_type="A"):
        """
        Runs the full detection pipeline on captured DNS requests.
        Returns:
            status: 'SAFE', 'SUSPICIOUS', or 'BLOCKED'
            detection_reason: String explanation or None
            matched_rule_id: Integer rule ID or None
            alert_dict: Dict with alert details if triggered (and not rate-limited), or None
            activity_category: Label for display
        """
        now = time.time()
        now_dt = datetime.now()
        
        domain = self.normalize_domain(raw_domain)
        client_ip = client_ip or "Unknown"
        
        status = "SAFE"
        detection_reason = None
        matched_rule_id = None
        alert_dict = None
        activity_category = "Standard query"
        
        if not domain:
            return status, detection_reason, matched_rule_id, alert_dict, activity_category

        # Auto-refresh cache if TTL expired
        if now - self.last_cache_reload > self.cache_ttl:
            try:
                self.reload_cache()
            except Exception:
                pass

        # =============================================================
        # TIER 0: Manual Block Rules (highest priority)
        # =============================================================
        with self._lock:
            manual_match = None
            if domain in self.manual_block_rules:
                manual_match = self.manual_block_rules[domain]
            else:
                parts = domain.split('.')
                for i in range(1, len(parts)):
                    candidate = '.'.join(parts[i:])
                    if candidate in self.manual_block_rules:
                        manual_match = self.manual_block_rules[candidate]
                        break

            if manual_match:
                status = 'BLOCKED'
                detection_reason = f"Manual Block Rule: {manual_match['domain']}"
                activity_category = 'Manually blocked'
                if self._should_generate_alert(client_ip, domain, 'Blocked domain request'):
                    alert_dict = {
                        'alert_id': f"ALT-BLK-{int(now)}-{uuid.uuid4().hex[:6].upper()}",
                        'timestamp': now_dt,
                        'severity': 'HIGH',
                        'domain': domain,
                        'client_ip': client_ip,
                        'alert_type': 'Blocked domain request',
                        'description': (
                            f"DNS query for '{domain}' was blocked by the manual block rule "
                            f"for '{manual_match['domain']}'. "
                            f"Reason: {manual_match.get('reason') or 'No reason specified'}."
                        ),
                        'status': 'New'
                    }
                return status, detection_reason, None, alert_dict, activity_category

        # =============================================================
        # IMMUNITY SHIELD: Whitelist & False Positive Immunity
        # =============================================================
        if self.is_domain_whitelisted(domain):
            return "SAFE", None, None, None, "Verified safe domain"

        # =============================================================
        # TIER 1: Malicious Domain Feed Matching
        # =============================================================
        with self._lock:
            matched_malicious = None
            if domain in self.malicious_domains:
                matched_malicious = self.malicious_domains[domain]
            else:
                parts = domain.split('.')
                for i in range(1, len(parts) - 1):
                    parent_domain = '.'.join(parts[i:])
                    if parent_domain in self.malicious_domains:
                        matched_malicious = self.malicious_domains[parent_domain]
                        break
                        
            if matched_malicious:
                status = "SUSPICIOUS"
                detection_reason = f"Malicious Domain Feed Match: {matched_malicious['domain']}"
                activity_category = "Matched blacklist"
                
                if self._should_generate_alert(client_ip, domain, "Malicious Domain Match"):
                    alert_dict = {
                        'alert_id': f"ALT-MAL-{int(now)}-{uuid.uuid4().hex[:6].upper()}",
                        'timestamp': now_dt,
                        'severity': matched_malicious.get('severity', 'HIGH'),
                        'domain': domain,
                        'client_ip': client_ip,
                        'alert_type': "Malicious Domain Match",
                        'description': f"DNS query for known malicious domain '{domain}' matched blacklisted entry '{matched_malicious['domain']}' ({matched_malicious.get('category', 'Threat')}).",
                        'status': 'New'
                    }
                return status, detection_reason, matched_rule_id, alert_dict, activity_category

        # =============================================================
        # TIER 2: Domain Heuristic & Pattern Rules
        # =============================================================
        with self._lock:
            domain_tokens = set(re.split(r'[.\-_]', domain))
            
            for rule in self.domain_rules:
                matched = False
                rtype = rule['rule_type']
                
                if rtype == 'KEYWORD':
                    for kw in rule.get('keywords', []):
                        if not kw:
                            continue
                        if '-' in kw or '_' in kw or '.' in kw:
                            if kw in domain:
                                matched = True
                                break
                        else:
                            if kw in GENERIC_SAFE_WORDS:
                                if kw in domain_tokens and (f"{kw}-" in domain or f"-{kw}" in domain):
                                    matched = True
                                    break
                            else:
                                if kw in domain_tokens or kw in domain:
                                    matched = True
                                    break
                                    
                elif rtype == 'TLD_BLACKLIST':
                    for tld in rule.get('tlds', []):
                        if tld and (domain.endswith(f".{tld}") or domain == tld):
                            matched = True
                            break
                            
                elif rtype in ('REGEX', 'PATTERN'):
                    cregex = rule.get('compiled_regex')
                    if cregex and cregex.search(domain):
                        matched = True
                        
                if matched:
                    is_block = rule.get('action', 'Alert').lower() == 'block'
                    status = "BLOCKED" if is_block else "SUSPICIOUS"
                    matched_rule_id = rule['id']
                    rule_sev = rule.get('severity', 'MEDIUM')
                    
                    alert_type_name = "Blocked domain request" if is_block else "Suspicious Domain Rule"
                    detection_reason = f"Suspicious Domain Rule: {rule['rule_name']} ({rule['rule_type']})"
                    activity_category = "Blocked by rule" if is_block else "Rule matched"
                    
                    if self._should_generate_alert(client_ip, domain, alert_type_name):
                        alert_dict = {
                            'alert_id': f"ALT-RUL-{int(now)}-{uuid.uuid4().hex[:6].upper()}",
                            'timestamp': now_dt,
                            'severity': rule_sev,
                            'domain': domain,
                            'client_ip': client_ip,
                            'alert_type': alert_type_name,
                            'description': f"DNS request for domain '{domain}' triggered detection rule '{rule['rule_name']}' ({rule['rule_type']}: {rule['pattern']}). Action: {rule.get('action', 'Alert')}.",
                            'status': 'New'
                        }
                    return status, detection_reason, matched_rule_id, alert_dict, activity_category

            # Built-in Heuristic: Brand Typosquatting & Phishing
            brand_eval = analyze_brand_impersonation(domain)
            if brand_eval['detected'] and brand_eval['confidence'] == 'HIGH':
                status = "SUSPICIOUS"
                detection_reason = f"Brand Phishing Impersonation: {brand_eval['targeted_brand']}"
                activity_category = "Phishing lure"
                if self._should_generate_alert(client_ip, domain, "Brand Phishing Heuristic"):
                    alert_dict = {
                        'alert_id': f"ALT-PHS-{int(now)}-{uuid.uuid4().hex[:6].upper()}",
                        'timestamp': now_dt,
                        'severity': "HIGH",
                        'domain': domain,
                        'client_ip': client_ip,
                        'alert_type': "Brand Phishing Heuristic",
                        'description': f"Domain '{domain}' exhibits brand impersonation targeting {brand_eval['targeted_brand']} with phishing indicators {brand_eval.get('lures', [])}.",
                        'status': 'New'
                    }
                return status, detection_reason, None, alert_dict, activity_category

            # Built-in Heuristic: Algorithmic DGA on high-risk TLD
            lex_eval = analyze_domain_lexical(domain)
            tld_part = domain.split('.')[-1] if '.' in domain else ''
            if lex_eval['is_dga_candidate'] and (tld_part in HIGH_RISK_TLDS or lex_eval['entropy'] >= 3.9):
                status = "SUSPICIOUS"
                detection_reason = f"Algorithmic DGA Heuristic (Entropy: {lex_eval['entropy']:.2f})"
                activity_category = "DGA suspect"
                if self._should_generate_alert(client_ip, domain, "Algorithmic DGA"):
                    alert_dict = {
                        'alert_id': f"ALT-DGA-{int(now)}-{uuid.uuid4().hex[:6].upper()}",
                        'timestamp': now_dt,
                        'severity': "HIGH",
                        'domain': domain,
                        'client_ip': client_ip,
                        'alert_type': "Algorithmic DGA",
                        'description': f"Domain '{domain}' exhibits high Shannon entropy ({lex_eval['entropy']}) and pseudo-random consonant clustering indicative of malware DGA rendezvous.",
                        'status': 'New'
                    }
                return status, detection_reason, None, alert_dict, activity_category

        # =============================================================
        # TIER 3: DNS Query Frequency Rate Limiting
        # =============================================================
        if self.frequency_status.lower() == 'active' and client_ip not in ("Unknown", "127.0.0.1", "::1"):
            with self._lock:
                q_history = self.client_query_history[client_ip]
                q_history.append(now)
                
                window_cutoff = now - self.frequency_window
                while q_history and q_history[0] < window_cutoff:
                    q_history.popleft()
                    
                current_query_count = len(q_history)
                if current_query_count > self.frequency_threshold:
                    is_block = self.frequency_action.lower() == 'block'
                    status = "BLOCKED" if is_block else "SUSPICIOUS"
                    detection_reason = f"DNS Query Frequency Threshold Exceeded ({current_query_count} queries in {self.frequency_window}s)"
                    activity_category = "High frequency"
                    
                    if self._should_generate_alert(client_ip, client_ip, "High DNS Query Frequency"):
                        alert_dict = {
                            'alert_id': f"ALT-FRQ-{int(now)}-{uuid.uuid4().hex[:6].upper()}",
                            'timestamp': now_dt,
                            'severity': "HIGH" if current_query_count > self.frequency_threshold * 2 else "MEDIUM",
                            'domain': domain,
                            'client_ip': client_ip,
                            'alert_type': "High DNS Query Frequency",
                            'description': f"Client {client_ip} exceeded DNS query threshold ({current_query_count} queries in {self.frequency_window}s, threshold={self.frequency_threshold}).",
                            'status': 'New'
                        }
                    return status, detection_reason, None, alert_dict, activity_category
        else:
            if client_ip not in ("Unknown", "127.0.0.1", "::1"):
                with self._lock:
                    q_history = self.client_query_history[client_ip]
                    q_history.append(now)
                    window_cutoff = now - self.frequency_window
                    while q_history and q_history[0] < window_cutoff:
                        q_history.popleft()

        return status, detection_reason, matched_rule_id, alert_dict, activity_category

    def evaluate_domain_diagnostics(self, raw_domain, client_ip="127.0.0.1", query_type="A"):
        """
        Deep diagnostic inspection method for the Domain Rule Testing Sandbox.
        Returns composite threat score (0-100), layer breakdown, and live DNS resolution.
        """
        domain = self.normalize_domain(raw_domain)
        if not domain:
            return {'success': False, 'message': 'Empty domain provided'}

        # 1. Whitelist Check
        is_whitelisted = self.is_domain_whitelisted(domain)
        
        # 2. Manual Block Check (Tier 0)
        manual_match = None
        with self._lock:
            if domain in self.manual_block_rules:
                manual_match = self.manual_block_rules[domain]
            else:
                parts = domain.split('.')
                for i in range(1, len(parts)):
                    candidate = '.'.join(parts[i:])
                    if candidate in self.manual_block_rules:
                        manual_match = self.manual_block_rules[candidate]
                        break

        # 3. Malicious Domain Feed Match (Tier 1)
        feed_match = None
        with self._lock:
            if domain in self.malicious_domains:
                feed_match = self.malicious_domains[domain]
            else:
                parts = domain.split('.')
                for i in range(1, len(parts) - 1):
                    parent_domain = '.'.join(parts[i:])
                    if parent_domain in self.malicious_domains:
                        feed_match = self.malicious_domains[parent_domain]
                        break

        # 4. Configured Rules Match (Tier 2)
        rules_hit = []
        domain_tokens = set(re.split(r'[.\-_]', domain))
        with self._lock:
            for rule in self.domain_rules:
                matched = False
                rtype = rule['rule_type']
                matched_detail = ''
                
                if rtype == 'KEYWORD':
                    for kw in rule.get('keywords', []):
                        if not kw:
                            continue
                        if '-' in kw or '_' in kw or '.' in kw:
                            if kw in domain:
                                matched = True
                                matched_detail = f"Keyword pattern '{kw}'"
                                break
                        else:
                            if kw in GENERIC_SAFE_WORDS:
                                if kw in domain_tokens and (f"{kw}-" in domain or f"-{kw}" in domain):
                                    matched = True
                                    matched_detail = f"Compound keyword '{kw}'"
                                    break
                            else:
                                if kw in domain_tokens or kw in domain:
                                    matched = True
                                    matched_detail = f"Keyword '{kw}'"
                                    break
                elif rtype == 'TLD_BLACKLIST':
                    for tld in rule.get('tlds', []):
                        clean_tld = tld.lstrip('.')
                        if domain.endswith(f".{clean_tld}") or domain == clean_tld:
                            matched = True
                            matched_detail = f"Blacklisted extension '.{clean_tld}'"
                            break
                elif rtype in ('REGEX', 'PATTERN'):
                    cregex = rule.get('compiled_regex')
                    if cregex and cregex.search(domain):
                        matched = True
                        matched_detail = f"Matched pattern '{rule['pattern']}'"

                if matched:
                    rules_hit.append({
                        'id': rule['id'],
                        'name': rule['rule_name'],
                        'type': rule['rule_type'],
                        'action': rule['action'],
                        'severity': rule['severity'],
                        'matched_condition': matched_detail
                    })

        # 5. Shannon Entropy & Lexical Analysis
        lexical = analyze_domain_lexical(domain)
        
        # 6. Brand Impersonation & Typosquatting
        brand_info = analyze_brand_impersonation(domain)
        
        # 7. DNS Tunneling Analysis
        tunneling = analyze_dns_tunneling(domain)
        
        # 8. TLD Reputation
        tld = domain.split('.')[-1] if '.' in domain else ''
        is_high_risk_tld = tld in HIGH_RISK_TLDS

        # 9. Real-time Live DNS Resolution
        dns_res = resolve_domain_dns(domain)

        # Composite Threat Score Calculation (0 - 100)
        threat_score = 0
        score_reasons = []

        if is_whitelisted:
            threat_score = 0
            score_reasons.append("Whitelisted legitimate domain (-100 pts immunity)")
        else:
            if manual_match:
                threat_score += 100
                score_reasons.append("Enforced in Tier-0 Manual Blocklist (+100)")
            if feed_match:
                threat_score += 90
                score_reasons.append(f"Matched Threat Feed [{feed_match.get('category')}] (+90)")
            if brand_info['detected']:
                pts = 75 if brand_info['confidence'] == 'HIGH' else 50
                threat_score += pts
                score_reasons.append(f"Targeting brand '{brand_info['targeted_brand']}' (+{pts})")
            if lexical['is_dga_candidate']:
                threat_score += 65
                score_reasons.append(f"High Shannon entropy / DGA pattern ({lexical['entropy']}) (+65)")
            if tunneling['is_tunnel_candidate']:
                threat_score += 70
                score_reasons.append("DNS Tunneling / Data Exfiltration indicators (+70)")
            if rules_hit:
                rule_pts = 60 if any(r['action'].lower() == 'block' for r in rules_hit) else 40
                threat_score += rule_pts
                score_reasons.append(f"Triggered {len(rules_hit)} active detection rules (+{rule_pts})")
            if is_high_risk_tld and not is_whitelisted:
                threat_score += 25
                score_reasons.append(f"Suspicious high-abuse TLD '.{tld}' (+25)")

        threat_score = min(max(threat_score, 0), 100)

        # Verdict assignment
        if threat_score >= 70 or manual_match:
            verdict = "BLOCKED"
            severity = "HIGH"
            action = "Block"
            recommendation = "Malicious domain confirmed. Traffic should be sinkholed immediately."
        elif threat_score >= 25 or rules_hit or brand_info['detected']:
            verdict = "SUSPICIOUS"
            severity = "MEDIUM"
            action = "Alert"
            recommendation = "Suspicious heuristics triggered. Flagged for security analyst triage."
        else:
            verdict = "SAFE"
            severity = "LOW"
            action = "Allow"
            recommendation = "Domain evaluated as clean with zero detected risk factors."

        return {
            'success': True,
            'domain': domain,
            'verdict': verdict,
            'threat_score': threat_score,
            'severity': severity,
            'action': action,
            'recommendation': recommendation,
            'score_breakdown': score_reasons,
            'diagnostics': {
                'is_whitelisted': is_whitelisted,
                'manual_block': {
                    'matched': bool(manual_match),
                    'rule': manual_match
                },
                'threat_feed': {
                    'matched': bool(feed_match),
                    'entry': feed_match
                },
                'rules_hit': rules_hit,
                'lexical': lexical,
                'brand_impersonation': brand_info,
                'tunneling': tunneling,
                'tld_reputation': {
                    'tld': tld,
                    'is_high_risk': is_high_risk_tld
                },
                'dns_resolution': dns_res
            }
        }

# Singleton instance
detection_engine = DetectionEngine()
