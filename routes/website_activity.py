from flask import Blueprint, request, jsonify
from database import db
from models import WebsiteActivity, MaliciousDomain
from datetime import datetime

website_activity_bp = Blueprint('website_activity', __name__)

@website_activity_bp.route('/api/website-activity', methods=['GET'])
def get_website_activity():
    page = max(int(request.args.get('page', 1)), 1)
    per_page = min(max(int(request.args.get('per_page', 10)), 5), 100)
    search = request.args.get('search', '').strip()
    status_filter = request.args.get('status', '').strip().upper()
    date_filter = request.args.get('date', '').strip()
    
    query = WebsiteActivity.query
    if search:
        query = query.filter(
            (WebsiteActivity.domain.ilike(f"%{search}%")) |
            (WebsiteActivity.client_ip.ilike(f"%{search}%")) |
            (WebsiteActivity.device_name.ilike(f"%{search}%"))
        )
    if status_filter and status_filter != 'ALL':
        query = query.filter(WebsiteActivity.status == status_filter)
        
    if date_filter:
        try:
            target_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
            query = query.filter(db.func.date(WebsiteActivity.timestamp) == target_date)
        except Exception:
            pass
            
    # If no records exist yet, seed initial representative rows from UI mockup
    if WebsiteActivity.query.count() == 0:
        seed_data = [
            ("google.com", "192.168.1.10", "DESKTOP-7F3K2", "Windows", "SAFE"),
            ("facebook.com", "192.168.1.15", "LAPTOP-3HJ9D", "Windows", "SAFE"),
            ("youtube.com", "192.168.1.18", "PHONE-9A2BC", "Android", "SAFE"),
            ("update.windows.com", "192.168.1.10", "DESKTOP-7F3K2", "Windows", "SAFE"),
            ("malicious-site.net", "192.168.1.8", "LAPTOP-3HJ9D", "Windows", "SUSPICIOUS"),
            ("discord.com", "192.168.1.18", "PHONE-9A2BC", "Android", "SAFE"),
            ("phishing-alert.com", "192.168.1.10", "DESKTOP-7F3K2", "Windows", "BLOCKED"),
            ("netflix.com", "192.168.1.15", "LAPTOP-3HJ9D", "Windows", "SAFE"),
            ("login.microsoftonline.com", "192.168.1.10", "DESKTOP-7F3K2", "Windows", "SAFE"),
            ("tracker.badsite.org", "192.168.1.18", "PHONE-9A2BC", "Android", "SUSPICIOUS")
        ]
        for dom, ip, dev, dtype, stat in seed_data:
            db.session.add(WebsiteActivity(
                timestamp=datetime.utcnow(),
                domain=dom,
                client_ip=ip,
                device_name=dev,
                device_type=dtype,
                status=stat
            ))
        db.session.commit()
        query = WebsiteActivity.query
        
    total = query.count()
    items_page = query.order_by(WebsiteActivity.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'success': True,
        'activities': [act.to_dict() for act in items_page.items],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': items_page.pages or 1
        }
    })

@website_activity_bp.route('/api/website-activity', methods=['POST'])
def add_website_activity():
    data = request.get_json() or {}
    domain = data.get('domain', '').strip().lower()
    client_ip = data.get('client_ip', request.remote_addr)
    device_name = data.get('device_name', f"DESKTOP-{client_ip.split('.')[-1]}")
    device_type = data.get('device_type', 'Windows')
    
    if not domain:
        return jsonify({'success': False, 'message': 'Domain is required.'}), 400
        
    # Check status against malicious domains
    status = "SAFE"
    if MaliciousDomain.query.filter_by(domain=domain, status='Active').first():
        status = "SUSPICIOUS"
        
    act = WebsiteActivity(
        domain=domain,
        client_ip=client_ip,
        device_name=device_name,
        device_type=device_type,
        status=status,
        timestamp=datetime.utcnow()
    )
    db.session.add(act)
    db.session.commit()
    
    return jsonify({'success': True, 'activity': act.to_dict()})
