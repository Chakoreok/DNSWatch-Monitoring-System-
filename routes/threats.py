from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from database import db
from models import MaliciousDomain, DetectionRule, FrequencyRuleConfig, SecurityAlert
from services.detection_engine import detection_engine
from datetime import datetime

threats_bp = Blueprint('threats', __name__)

# =========================================================================
# Threat Summary Counts
# =========================================================================
@threats_bp.route('/api/threats/summary', methods=['GET'])
def get_threats_summary():
    malicious_count = MaliciousDomain.query.count()
    rules_count = DetectionRule.query.count()
    freq_rule = FrequencyRuleConfig.query.first()
    freq_count = 1 if (freq_rule and freq_rule.status == 'Active') else 0
    
    # Threats detected today
    today = datetime.utcnow().date()
    threats_today = SecurityAlert.query.filter(db.func.date(SecurityAlert.timestamp) == today).count()
    
    return jsonify({
        'success': True,
        'malicious_domains_count': malicious_count,
        'domain_rules_count': rules_count,
        'frequency_rules_count': freq_count,
        'threats_detected_today': threats_today
    })

# =========================================================================
# 1. Malicious Domain List API
# =========================================================================
@threats_bp.route('/api/threats/domains', methods=['GET'])
def get_malicious_domains():
    search = request.args.get('search', '').strip()
    status = request.args.get('status', '').strip()
    
    query = MaliciousDomain.query
    if search:
        query = query.filter(
            (MaliciousDomain.domain.ilike(f"%{search}%")) |
            (MaliciousDomain.category.ilike(f"%{search}%")) |
            (MaliciousDomain.description.ilike(f"%{search}%"))
        )
    if status and status != 'ALL':
        query = query.filter(MaliciousDomain.status == status)
        
    domains = query.order_by(MaliciousDomain.created_at.desc()).all()
    return jsonify({
        'success': True,
        'domains': [d.to_dict() for d in domains]
    })

@threats_bp.route('/api/threats/domains', methods=['POST'])
def add_malicious_domain():
    data = request.get_json() or {}
    raw_domain = data.get('domain', '').strip().lower().rstrip('.')
    category = data.get('category', 'Malware / Phishing').strip()
    severity = data.get('severity', 'HIGH').strip().upper()
    description = data.get('description', '').strip()
    status = data.get('status', 'Active').strip()
    
    if not raw_domain:
        return jsonify({'success': False, 'message': 'Domain name is required.'}), 400
        
    # Check duplicate
    existing = MaliciousDomain.query.filter_by(domain=raw_domain).first()
    if existing:
        return jsonify({'success': False, 'message': f"Domain '{raw_domain}' already exists in the malicious list."}), 400
        
    added_by = current_user.username if current_user.is_authenticated else 'admin'
    
    new_domain = MaliciousDomain(
        domain=raw_domain,
        category=category,
        severity=severity,
        description=description,
        status=status,
        added_by=added_by
    )
    db.session.add(new_domain)
    db.session.commit()
    
    # Reload engine memory cache
    detection_engine.reload_cache()
    
    return jsonify({
        'success': True,
        'message': f"Domain '{raw_domain}' added to malicious domain list.",
        'domain': new_domain.to_dict()
    })

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
# 2. Basic Domain Rules API
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
# 3. DNS Query Frequency Rule API
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
