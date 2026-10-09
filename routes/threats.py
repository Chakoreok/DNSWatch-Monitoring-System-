from flask import Blueprint, request, jsonify, Response
from flask_login import current_user
from database import db
from models import MaliciousDomain, DetectionRule, FrequencyRuleConfig, SecurityAlert, ThreatFeed, DomainWhitelist, ManualBlockRule
from services.detection_engine import detection_engine
from services.threat_feed_service import threat_feed_service
from datetime import datetime

threats_bp = Blueprint('threats', __name__)

# =========================================================================
# Threat Summary Counts & Telemetry
# =========================================================================
@threats_bp.route('/api/threats/summary', methods=['GET'])
def get_threats_summary():
    blocked_domains = [r[0] for r in db.session.query(ManualBlockRule.domain).filter(ManualBlockRule.is_active == True).all()]
    if blocked_domains:
        malicious_count = MaliciousDomain.query.filter(~MaliciousDomain.domain.in_(blocked_domains)).count()
    else:
        malicious_count = MaliciousDomain.query.count()
    rules_count = DetectionRule.query.count()
    freq_rule = FrequencyRuleConfig.query.first()
    freq_count = 1 if (freq_rule and freq_rule.status == 'Active') else 0
    feeds_count = ThreatFeed.query.count()
    
    # Threats detected today
    today = datetime.utcnow().date()
    threats_today = SecurityAlert.query.filter(db.func.date(SecurityAlert.timestamp) == today).count()
    
    return jsonify({
        'success': True,
        'malicious_domains_count': malicious_count,
        'domain_rules_count': rules_count,
        'frequency_rules_count': freq_count,
        'threats_detected_today': threats_today,
        'threat_feeds_count': feeds_count
    })

# =========================================================================
# 1. Domain Rule Testing Sandbox & Deep Threat Analyzer APIs
# =========================================================================
@threats_bp.route('/api/threats/sandbox/evaluate', methods=['POST'])
def sandbox_evaluate_domain():
    """
    Evaluates a single domain against the full multi-tier detection engine,
    running Shannon entropy analysis, brand typosquatting heuristics,
    blacklist matching, and live socket DNS resolution.
    """
    data = request.get_json() or {}
    domain = data.get('domain', '').strip()
    client_ip = data.get('client_ip', '192.168.1.100').strip()
    
    if not domain:
        return jsonify({'success': False, 'message': 'Domain name is required for sandbox analysis.'}), 400

    report = detection_engine.evaluate_domain_diagnostics(domain, client_ip=client_ip)
    return jsonify(report)

@threats_bp.route('/api/threats/sandbox/batch', methods=['POST'])
def sandbox_batch_evaluate():
    """
    Evaluates a batch of domains (up to 25 at a time) for threat simulation.
    """
    data = request.get_json() or {}
    domains = data.get('domains', [])
    if isinstance(domains, str):
        import re
        domains = [d.strip() for d in re.split(r'[\r\n,]+', domains) if d.strip()]
        
    if not domains:
        return jsonify({'success': False, 'message': 'No domains provided for batch evaluation.'}), 400

    domains = domains[:25]  # Cap batch to 25 items
    results = []
    clean_count = 0
    suspicious_count = 0
    blocked_count = 0

    for dom in domains:
        report = detection_engine.evaluate_domain_diagnostics(dom)
        if report.get('success'):
            v = report.get('verdict', 'SAFE')
            if v == 'SAFE':
                clean_count += 1
            elif v == 'SUSPICIOUS':
                suspicious_count += 1
            else:
                blocked_count += 1
            results.append({
                'domain': dom,
                'verdict': report.get('verdict'),
                'threat_score': report.get('threat_score'),
                'action': report.get('action'),
                'severity': report.get('severity'),
                'recommendation': report.get('recommendation'),
                'primary_reason': report.get('score_breakdown', ['Clean'])[0] if report.get('score_breakdown') else 'Clean',
                'dns_resolved': report.get('diagnostics', {}).get('dns_resolution', {}).get('resolved', False)
            })

    return jsonify({
        'success': True,
        'total': len(results),
        'clean_count': clean_count,
        'suspicious_count': suspicious_count,
        'blocked_count': blocked_count,
        'results': results
    })

# =========================================================================
# 2. Threat Intelligence Feeds API
# =========================================================================
@threats_bp.route('/api/threats/feeds', methods=['GET'])
def get_threat_feeds():
    """Returns list of configured threat intelligence feeds and their sync status."""
    threat_feed_service.init_default_feeds()
    feeds = ThreatFeed.query.order_by(ThreatFeed.id.asc()).all()
    return jsonify({
        'success': True,
        'feeds': [f.to_dict() for f in feeds]
    })

@threats_bp.route('/api/threats/feeds', methods=['POST'])
def add_custom_threat_feed():
    """Registers a new custom threat feed URL."""
    data = request.get_json() or {}
    name = data.get('name', '').strip()
    source_url = data.get('source_url', '').strip()
    category = data.get('category', 'Malware / Phishing').strip()
    severity = data.get('severity', 'HIGH').strip().upper()
    description = data.get('description', '').strip()

    if not name or not source_url:
        return jsonify({'success': False, 'message': 'Feed name and source URL are required.'}), 400

    existing = ThreatFeed.query.filter_by(name=name).first()
    if existing:
        return jsonify({'success': False, 'message': f"Threat feed '{name}' already exists."}), 400

    new_feed = ThreatFeed(
        name=name,
        source_url=source_url,
        feed_type='CUSTOM',
        category=category,
        severity=severity,
        description=description,
        is_active=True,
        sync_status='IDLE'
    )
    db.session.add(new_feed)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': f"Custom threat feed '{name}' added successfully.",
        'feed': new_feed.to_dict()
    })

@threats_bp.route('/api/threats/feeds/sync', methods=['POST'])
def sync_all_threat_feeds():
    """Triggers live synchronization of all active threat feeds."""
    res = threat_feed_service.sync_all_active_feeds()
    return jsonify(res)

@threats_bp.route('/api/threats/feeds/<int:id>/sync', methods=['POST'])
def sync_individual_threat_feed(id):
    """Triggers synchronization for a specific threat feed."""
    feed = ThreatFeed.query.get_or_404(id)
    processed, added = threat_feed_service.sync_feed(feed)
    return jsonify({
        'success': True,
        'message': f"Feed '{feed.name}' synced successfully: {added} new domains ingested.",
        'feed': feed.to_dict(),
        'processed': processed,
        'added': added
    })

@threats_bp.route('/api/threats/feeds/<int:id>/toggle', methods=['POST'])
def toggle_threat_feed(id):
    """Toggles feed active / inactive state."""
    feed = ThreatFeed.query.get_or_404(id)
    feed.is_active = not feed.is_active
    db.session.commit()
    return jsonify({
        'success': True,
        'message': f"Feed '{feed.name}' is now {'Active' if feed.is_active else 'Inactive'}.",
        'is_active': feed.is_active
    })

# =========================================================================
# 3. Malicious Domain Feed (Blacklist) API
# =========================================================================
@threats_bp.route('/api/threats/domains', methods=['GET'])
def get_malicious_domains():
    search = request.args.get('search', '').strip()
    status = request.args.get('status', '').strip()
    source = request.args.get('source', '').strip()
    
    query = MaliciousDomain.query

    # Automatically exclude domains that have already been moved to Blocked DNS
    blocked_domains = [r[0] for r in db.session.query(ManualBlockRule.domain).filter(ManualBlockRule.is_active == True).all()]
    if blocked_domains:
        query = query.filter(~MaliciousDomain.domain.in_(blocked_domains))

    if search:
        query = query.filter(
            (MaliciousDomain.domain.ilike(f"%{search}%")) |
            (MaliciousDomain.category.ilike(f"%{search}%")) |
            (MaliciousDomain.description.ilike(f"%{search}%")) |
            (MaliciousDomain.feed_source.ilike(f"%{search}%"))
        )
    if status and status != 'ALL':
        query = query.filter(MaliciousDomain.status == status)
    if source and source != 'ALL':
        query = query.filter(MaliciousDomain.feed_source == source)
        
    # Cap to 500 records for responsive UI rendering
    domains = query.order_by(MaliciousDomain.created_at.desc()).limit(500).all()
    return jsonify({
        'success': True,
        'total_count': query.count(),
        'domains': [d.to_dict() for d in domains]
    })

@threats_bp.route('/api/threats/domains', methods=['POST'])
def add_malicious_domain():
    data = request.get_json() or {}
    raw_domain = data.get('domain', '').strip().lower().rstrip('.')
    category = data.get('category', 'Malware / Phishing').strip()
    severity = data.get('severity', 'HIGH').strip().upper()
    description = data.get('description', '').strip()
    feed_source = data.get('feed_source', 'Manual').strip()
    status = data.get('status', 'Active').strip()
    
    if not raw_domain:
        return jsonify({'success': False, 'message': 'Domain name is required.'}), 400
        
    existing = MaliciousDomain.query.filter_by(domain=raw_domain).first()
    if existing:
        return jsonify({'success': False, 'message': f"Domain '{raw_domain}' already exists in the malicious list."}), 400
        
    added_by = current_user.username if current_user.is_authenticated else 'admin'
    
    new_domain = MaliciousDomain(
        domain=raw_domain,
        category=category,
        severity=severity,
        description=description,
        feed_source=feed_source,
        status=status,
        added_by=added_by
    )
    db.session.add(new_domain)
    db.session.commit()
    
    detection_engine.reload_cache()
    
    return jsonify({
        'success': True,
        'message': f"Domain '{raw_domain}' added to malicious domain list.",
        'domain': new_domain.to_dict()
    })

@threats_bp.route('/api/threats/domains/bulk-import', methods=['POST'])
def bulk_import_domains():
    """Bulk imports a batch of domains from text or CSV paste."""
    data = request.get_json() or {}
    text_input = data.get('text_data', '')
    category = data.get('category', 'Malware / Phishing')
    severity = data.get('severity', 'HIGH')
    feed_source = data.get('feed_source', 'Bulk Import')
    added_by = current_user.username if current_user.is_authenticated else 'admin'

    total, added, msg = threat_feed_service.bulk_import_domains(
        text_input=text_input,
        category=category,
        severity=severity,
        feed_source=feed_source,
        added_by=added_by
    )
    return jsonify({
        'success': True,
        'message': msg,
        'total_processed': total,
        'new_added': added
    })

@threats_bp.route('/api/threats/domains/export', methods=['GET'])
def export_domains():
    """Exports all malicious domains in CSV format."""
    csv_data = threat_feed_service.export_domains_csv()
    filename = f"dnswatch_threat_feed_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename={filename}"}
    )

@threats_bp.route('/api/threats/domains/<int:id>', methods=['PUT'])
def update_malicious_domain(id):
    domain_rec = MaliciousDomain.query.get_or_404(id)
    data = request.get_json() or {}
    
    if 'domain' in data:
        domain_rec.domain = data['domain'].strip().lower().rstrip('.')
    if 'category' in data:
        domain_rec.category = data['category'].strip()
    if 'severity' in data:
        domain_rec.severity = data['severity'].strip().upper()
    if 'description' in data:
        domain_rec.description = data['description'].strip()
    if 'status' in data:
        domain_rec.status = data['status'].strip()
        
    domain_rec.updated_at = datetime.utcnow()
    db.session.commit()
    detection_engine.reload_cache()
    
    return jsonify({
        'success': True,
        'message': 'Domain updated successfully.',
        'domain': domain_rec.to_dict()
    })

@threats_bp.route('/api/threats/domains/<int:id>', methods=['DELETE'])
def delete_malicious_domain(id):
    domain_rec = MaliciousDomain.query.get_or_404(id)
    domain_name = domain_rec.domain
    db.session.delete(domain_rec)
    db.session.commit()
    detection_engine.reload_cache()
    
    return jsonify({
        'success': True,
        'message': f"Domain '{domain_name}' removed from malicious domain list."
    })

# =========================================================================
# 4. Domain Detection & Heuristic Rules API
# =========================================================================
@threats_bp.route('/api/threats/rules', methods=['GET'])
def get_domain_rules():
    search = request.args.get('search', '').strip()
    query = DetectionRule.query
    if search:
        query = query.filter(
            (DetectionRule.rule_name.ilike(f"%{search}%")) |
            (DetectionRule.pattern.ilike(f"%{search}%")) |
            (DetectionRule.category.ilike(f"%{search}%"))
        )
    rules = query.order_by(DetectionRule.created_at.desc()).all()
    return jsonify({
        'success': True,
        'rules': [r.to_dict() for r in rules]
    })

@threats_bp.route('/api/threats/rules', methods=['POST'])
def add_domain_rule():
    data = request.get_json() or {}
    rule_name = data.get('rule_name', '').strip()
    rule_type = data.get('rule_type', 'KEYWORD').strip().upper()
    pattern = data.get('pattern', '').strip()
    category = data.get('category', 'Suspicious Pattern').strip()
    severity = data.get('severity', 'MEDIUM').strip().upper()
    action = data.get('action', 'Alert').strip()
    description = data.get('description', '').strip()
    is_active = data.get('is_active', True)
    
    if not rule_name or not pattern:
        return jsonify({'success': False, 'message': 'Rule name and pattern are required.'}), 400
        
    rule = DetectionRule(
        rule_name=rule_name,
        rule_type=rule_type,
        pattern=pattern,
        category=category,
        severity=severity,
        action=action,
        description=description,
        is_active=bool(is_active)
    )
    db.session.add(rule)
    db.session.commit()
    detection_engine.reload_cache()
    
    return jsonify({
        'success': True,
        'message': f"Detection rule '{rule_name}' created successfully.",
        'rule': rule.to_dict()
    })

@threats_bp.route('/api/threats/rules/<int:id>', methods=['PUT'])
def update_domain_rule(id):
    rule = DetectionRule.query.get_or_404(id)
    data = request.get_json() or {}
    
    if 'rule_name' in data:
        rule.rule_name = data['rule_name'].strip()
    if 'rule_type' in data:
        rule.rule_type = data['rule_type'].strip().upper()
    if 'pattern' in data:
        rule.pattern = data['pattern'].strip()
    if 'category' in data:
        rule.category = data['category'].strip()
    if 'severity' in data:
        rule.severity = data['severity'].strip().upper()
    if 'action' in data:
        rule.action = data['action'].strip()
    if 'description' in data:
        rule.description = data['description'].strip()
    if 'is_active' in data:
        rule.is_active = bool(data['is_active'])
        
    rule.updated_at = datetime.utcnow()
    db.session.commit()
    detection_engine.reload_cache()
    
    return jsonify({
        'success': True,
        'message': f"Rule '{rule.rule_name}' updated successfully.",
        'rule': rule.to_dict()
    })

@threats_bp.route('/api/threats/rules/<int:id>', methods=['DELETE'])
def delete_domain_rule(id):
    rule = DetectionRule.query.get_or_404(id)
    name = rule.rule_name
    db.session.delete(rule)
    db.session.commit()
    detection_engine.reload_cache()
    
    return jsonify({
        'success': True,
        'message': f"Detection rule '{name}' deleted successfully."
    })

# =========================================================================
# 5. DNS Query Frequency Rule API
# =========================================================================
@threats_bp.route('/api/threats/frequency-rule', methods=['GET'])
def get_frequency_rule():
    freq = FrequencyRuleConfig.query.first()
    if not freq:
        freq = FrequencyRuleConfig(threshold=100, time_window=60, action='Alert', status='Active')
        db.session.add(freq)
        db.session.commit()
        
    return jsonify({
        'success': True,
        'frequency_rule': freq.to_dict()
    })

@threats_bp.route('/api/threats/frequency-rule', methods=['PUT'])
def update_frequency_rule():
    freq = FrequencyRuleConfig.query.first()
    if not freq:
        freq = FrequencyRuleConfig()
        db.session.add(freq)
        
    data = request.get_json() or {}
    if 'threshold' in data:
        freq.threshold = max(int(data['threshold']), 1)
    if 'time_window' in data:
        freq.time_window = max(int(data['time_window']), 1)
    if 'action' in data:
        freq.action = data['action'].strip()
    if 'status' in data:
        freq.status = data['status'].strip()
        
    freq.updated_at = datetime.utcnow()
    db.session.commit()
    detection_engine.reload_cache()
    
    return jsonify({
        'success': True,
        'message': 'DNS query frequency rule updated successfully.',
        'frequency_rule': freq.to_dict()
    })

# =========================================================================
# 6. Trusted Whitelist API
# =========================================================================
@threats_bp.route('/api/threats/whitelist', methods=['GET'])
def get_whitelist():
    """Returns custom whitelisted domains."""
    items = DomainWhitelist.query.order_by(DomainWhitelist.created_at.desc()).all()
    return jsonify({
        'success': True,
        'whitelist': [item.to_dict() for item in items]
    })

@threats_bp.route('/api/threats/whitelist', methods=['POST'])
def add_to_whitelist():
    """Adds a domain to the custom whitelist for false-positive immunity."""
    data = request.get_json() or {}
    domain = data.get('domain', '').strip().lower().rstrip('.')
    reason = data.get('reason', 'Enterprise approved service / CDN').strip()

    if not domain:
        return jsonify({'success': False, 'message': 'Domain is required.'}), 400

    existing = DomainWhitelist.query.filter_by(domain=domain).first()
    if existing:
        return jsonify({'success': False, 'message': f"Domain '{domain}' is already on the whitelist."}), 400

    added_by = current_user.username if current_user.is_authenticated else 'admin'
    new_entry = DomainWhitelist(domain=domain, reason=reason, added_by=added_by)
    db.session.add(new_entry)
    db.session.commit()
    detection_engine.reload_cache()

    return jsonify({
        'success': True,
        'message': f"Domain '{domain}' added to whitelist immunity.",
        'entry': new_entry.to_dict()
    })

@threats_bp.route('/api/threats/whitelist/<int:id>', methods=['DELETE'])
def delete_from_whitelist(id):
    entry = DomainWhitelist.query.get_or_404(id)
    dom = entry.domain
    db.session.delete(entry)
    db.session.commit()
    detection_engine.reload_cache()
    return jsonify({'success': True, 'message': f"Domain '{dom}' removed from whitelist."})
