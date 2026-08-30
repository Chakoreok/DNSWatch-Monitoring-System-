from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from database import db
from models import SecurityAlert
from services.sniffer import sniffer_service
from datetime import datetime

alerts_bp = Blueprint('alerts', __name__)

@alerts_bp.route('/api/alerts/recent', methods=['GET'])
def get_recent_alerts():
    limit = min(int(request.args.get('limit', 5)), 20)
    
    # Check live circular buffer
    live_alerts = list(sniffer_service.recent_alerts_buffer)
    if live_alerts:
        return jsonify({
            'success': True,
            'alerts': live_alerts[:limit]
        })
        
    alerts = SecurityAlert.query.order_by(SecurityAlert.timestamp.desc()).limit(limit).all()
    return jsonify({
        'success': True,
        'alerts': [a.to_dict() for a in alerts]
    })

@alerts_bp.route('/api/alerts', methods=['GET'])
def get_alerts():
    page = max(int(request.args.get('page', 1)), 1)
    per_page = min(max(int(request.args.get('per_page', 10)), 5), 100)
    
    search = request.args.get('search', '').strip()
    severity = request.args.get('severity', '').strip().upper()
    status = request.args.get('status', '').strip()
    date_filter = request.args.get('date', '').strip()
    
    query = SecurityAlert.query
    
    if search:
        pattern = f"%{search}%"
        query = query.filter(
            (SecurityAlert.domain.ilike(pattern)) |
            (SecurityAlert.client_ip.ilike(pattern)) |
            (SecurityAlert.alert_type.ilike(pattern)) |
            (SecurityAlert.alert_id.ilike(pattern)) |
            (SecurityAlert.description.ilike(pattern))
        )
        
    if severity and severity != 'ALL':
        query = query.filter(SecurityAlert.severity == severity)
        
    if status and status != 'ALL':
        query = query.filter(SecurityAlert.status.ilike(status))
        
    if date_filter:
        try:
            target_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
            query = query.filter(db.func.date(SecurityAlert.timestamp) == target_date)
        except Exception:
            pass
            
    total = query.count()
    alerts_page = query.order_by(SecurityAlert.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'success': True,
        'alerts': [a.to_dict() for a in alerts_page.items],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': alerts_page.pages or 1
        }
    })

@alerts_bp.route('/api/alerts/counts', methods=['GET'])
def get_alert_counts():
    high_count = SecurityAlert.query.filter(SecurityAlert.severity.ilike('HIGH')).count()
    medium_count = SecurityAlert.query.filter(SecurityAlert.severity.ilike('MEDIUM')).count()
    low_count = SecurityAlert.query.filter(SecurityAlert.severity.ilike('LOW')).count()
    total_count = SecurityAlert.query.count()
    
    return jsonify({
        'success': True,
        'high': high_count,
        'medium': medium_count,
        'low': low_count,
        'total': total_count
    })

@alerts_bp.route('/api/alerts/<id>/status', methods=['PUT'])
def update_alert_status(id):
    data = request.get_json() or {}
    new_status = data.get('status', 'Acknowledged')
    
    alert = SecurityAlert.query.filter((SecurityAlert.id == id) | (SecurityAlert.alert_id == str(id))).first()
    if not alert:
        return jsonify({'success': False, 'message': 'Alert not found.'}), 404
        
    alert.status = new_status
    if new_status.lower() == 'resolved':
        alert.resolved_at = datetime.utcnow()
        if current_user.is_authenticated:
            alert.resolved_by = current_user.id
            
    db.session.commit()
    return jsonify({'success': True, 'message': f'Alert status updated to {new_status}.', 'alert': alert.to_dict()})
