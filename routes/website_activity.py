from flask import Blueprint, request, jsonify
from database import db
from models import DNSLog, Device
from services.device_tracker import device_tracker
from datetime import datetime

website_activity_bp = Blueprint('website_activity', __name__)

@website_activity_bp.route('/api/website-activity', methods=['GET'])
def get_website_activity():
    """
    Populates Website Activity directly from actual DNS logs (joined with observed devices).
    No mock or fake data.
    """
    page = max(int(request.args.get('page', 1)), 1)
    per_page = min(max(int(request.args.get('per_page', 10)), 5), 100)
    search = request.args.get('search', '').strip()
    status_filter = request.args.get('status', '').strip().upper()
    date_filter = request.args.get('date', '').strip()
    
    # Query directly from DNSLog
    query = DNSLog.query
    
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            (DNSLog.query_domain.ilike(search_pattern)) |
            (DNSLog.client_ip.ilike(search_pattern)) |
            (DNSLog.activity_category.ilike(search_pattern))
        )
        
    if status_filter and status_filter != 'ALL':
        query = query.filter(DNSLog.status == status_filter)
        
    if date_filter:
        try:
            target_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
            query = query.filter(db.func.date(DNSLog.timestamp) == target_date)
        except Exception:
            pass
            
    total = query.count()
    logs_page = query.order_by(DNSLog.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    # Known devices and local IPs for accurate device name display
    local_ips = device_tracker.get_local_system_ips()
    primary_local_ip = device_tracker.get_primary_local_ip()
    devices_by_ip = {d.client_ip: d for d in Device.query.all()}
    
    local_dev = Device.query.filter(
        (Device.client_ip == primary_local_ip) | 
        (Device.device_name.ilike("%Local Workstation%"))
    ).first()
    
    activities = []
    for log in logs_page.items:
        if log.client_ip and log.client_ip.lower() in local_ips:
            dev_name = local_dev.device_name if local_dev else "Local Workstation (Monitored Host)"
            dev_type = local_dev.device_type if local_dev else "Workstation / PC"
        else:
            dev = devices_by_ip.get(log.client_ip)
            dev_name = dev.device_name if dev else f"Host-{log.client_ip.replace(':', '-').replace('.', '-')}"
            dev_type = dev.device_type if dev else "Network Client"
            
        activities.append({
            'id': log.id,
            'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S') if log.timestamp else '',
            'domain': log.query_domain,
            'client_ip': log.client_ip,
            'device_name': dev_name,
            'device_type': dev_type,
            'status': log.status,
            'category': log.activity_category or 'Web Browsing',
            'query_type': log.query_type
        })
        
    return jsonify({
        'success': True,
        'activities': activities,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': logs_page.pages or 1
        }
    })
