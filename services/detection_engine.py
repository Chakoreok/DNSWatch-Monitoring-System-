import re
import time
import uuid
import threading
from collections import defaultdict, deque
from datetime import datetime
from flask import has_app_context
from database import db
from models import MaliciousDomain, DetectionRule, FrequencyRuleConfig, SecurityAlert, ManualBlockRule

# List of generic words that must never trigger broad substring matching on legitimate domains
GENERIC_SAFE_WORDS = {
    'account', 'accounts', 'login', 'secure', 'verify', 'mail', 'service',
    'cloud', 'support', 'update', 'api', 'app', 'auth', 'portal', 'connect',
    'admin', 'home', 'shop', 'store', 'news', 'blog', 'static', 'cdn'
}

class DetectionEngine:
    """
    DNSWatch 3-Tier Detection Engine:
    1. Malicious Domain List Matching
    2. Basic Domain Rule Checking (Keywords, TLDs, Patterns, Regex)
    3. DNS Query Frequency Rule (Per-client sliding window)
    """
    
    def __init__(self):
        self._lock = threading.RLock()
        self.app = None
        
        # In-memory caches for fast local matching
        self.malicious_domains = {}  # domain.lower() -> MaliciousDomain dict
        self.domain_rules = []       # List of compiled rule dicts
        
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
        
    def init_app(self, app):
        self.app = app
        
    def reload_cache(self, app=None):
        """Loads malicious domains and detection rules from MySQL into memory."""
        target_app = app or self.app
        if not has_app_context() and target_app:
            with target_app.app_context():
                self._do_reload_cache()
        else:
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
                        'description': d.description
                    }
                    for d in active_domains
                }
                
                # 2. Load Domain Detection Rules
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
                        regex_pat = '^' + re.escape(r.pattern.strip()).replace('\\*', '.*').replace('\\?', '.') + '$'
                        try:
                            rule_dict['compiled_regex'] = re.compile(regex_pat, re.IGNORECASE)
                        except Exception:
                            rule_dict['compiled_regex'] = None
                            
                    compiled_rules.append(rule_dict)
                self.domain_rules = compiled_rules
                
                # 3. Load Frequency Rule Config
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
            # Table may not exist yet (pre-migration). Silently skip.
            self.manual_block_rules = {}


    def reload_manual_blocks(self):
        """
        Public method called by blocking routes after every rule change.
        Refreshes the Tier-0 in-memory cache without touching other caches.
        """
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
        Runs the 3-Tier Detection Engine on captured DNS request.
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
        # Admin-approved explicit blocks. The DNS sinkhole returns
        # NXDOMAIN; the detection engine labels the log entry BLOCKED.
        # =============================================================
        with self._lock:
            manual_match = None
            if domain in self.manual_block_rules:
                manual_match = self.manual_block_rules[domain]
            else:
                # Subdomain check (boundary-safe)
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

        # -------------------------------------------------------------
        # DETECTION METHOD 1: Malicious Domain List Matching
        # -------------------------------------------------------------
        with self._lock:
            matched_malicious = None
            if domain in self.malicious_domains:
                matched_malicious = self.malicious_domains[domain]
            else:
                # Match full subdomain of blacklisted root (e.g. bad.malicious-site.net -> malicious-site.net)
                parts = domain.split('.')
                for i in range(1, len(parts) - 1):
                    parent_domain = '.'.join(parts[i:])
                    if parent_domain in self.malicious_domains:
                        matched_malicious = self.malicious_domains[parent_domain]
                        break
                        
            if matched_malicious:
                status = "SUSPICIOUS"
                detection_reason = f"Malicious Domain List Match: {matched_malicious['domain']}"
                activity_category = "Matched blacklist"
                
                # Check alert deduplication
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

        # -------------------------------------------------------------
        # DETECTION METHOD 2: Basic Domain Rule Checking
        # -------------------------------------------------------------
        with self._lock:
            domain_tokens = set(re.split(r'[.\-_]', domain))
            
            for rule in self.domain_rules:
                matched = False
                rtype = rule['rule_type']
                
                if rtype == 'KEYWORD':
                    for kw in rule.get('keywords', []):
                        if not kw:
                            continue
                            
                        # If keyword is a compound pattern (e.g. login-verify, account-update, secure-banking)
                        if '-' in kw or '_' in kw or '.' in kw:
                            if kw in domain:
                                matched = True
                                break
                        else:
                            # If single keyword, do NOT do broad substring match for generic words (e.g. 'account' in 'accounts.google.com')
                            if kw in GENERIC_SAFE_WORDS:
                                # Only match if it is an exact token AND domain has suspicious delimiters (e.g. 'login-something' or 'verify-something')
                                if kw in domain_tokens and (f"{kw}-" in domain or f"-{kw}" in domain):
                                    matched = True
                                    break
                            else:
                                # Non-generic specific keyword: match full token
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
                    
                    # Check alert deduplication
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

        # -------------------------------------------------------------
        # DETECTION METHOD 3: DNS Query Frequency Rule
        # -------------------------------------------------------------
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

# Singleton instance
detection_engine = DetectionEngine()
