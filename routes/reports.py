import csv
import io
from flask import Blueprint, request, jsonify, Response
from database import db
from models import DNSLog, SecurityAlert, Device
from datetime import datetime, timedelta

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/api/reports/summary', methods=['GET'])
def get_reports_summary():
    device_filter = request.args.get('device', '').strip()
    status_filter = request.args.get('status', '').strip()
    
    # Base query for logs
    log_query = DNSLog.query
    if device_filter and device_filter != 'ALL':
        log_query = log_query.filter(DNSLog.client_ip == device_filter)
    if status_filter and status_filter != 'ALL':
        log_query = log_query.filter(DNSLog.status == status_filter)
        
    total_queries = log_query.count()
    safe_requests = log_query.filter(DNSLog.status == 'SAFE').count()
    suspicious_requests = log_query.filter(DNSLog.status == 'SUSPICIOUS').count()
    blocked_requests = log_query.filter(DNSLog.status == 'BLOCKED').count()
    active_devices = Device.query.filter_by(status='Active').count()
    
    # Time series queries (last 7 days)
    today = datetime.utcnow().date()
    days_data = []
    labels = []
    for i in range(6, -1, -1):
        d = today - timedelta(days=i)
        day_str = d.strftime('%b %d')
        labels.append(day_str)
        day_count = DNSLog.query.filter(db.func.date(DNSLog.timestamp) == d).count()
        days_data.append(day_count)
        
    # Top queried domains
    top_domains = db.session.query(
        DNSLog.query_domain,
        db.func.count(DNSLog.id).label('queries')
    ).group_by(DNSLog.query_domain).order_by(db.desc('queries')).limit(5).all()
    
    top_domains_list = [
        {'domain': d[0], 'queries': d[1]} for d in top_domains
    ]
    
    # Top devices by queries
    top_devices = db.session.query(
        DNSLog.client_ip,
        db.func.count(DNSLog.id).label('queries')
    ).group_by(DNSLog.client_ip).order_by(db.desc('queries')).limit(5).all()
    
    top_devices_list = [
        {'ip_address': dev[0], 'queries': dev[1], 'device_name': f"DESKTOP-{dev[0].split('.')[-1]}"} for dev in top_devices
    ]
    
    # Alerts summary breakdown
    high_alerts = SecurityAlert.query.filter(SecurityAlert.severity.ilike('HIGH')).count()
    med_alerts = SecurityAlert.query.filter(SecurityAlert.severity.ilike('MEDIUM')).count()
    low_alerts = SecurityAlert.query.filter(SecurityAlert.severity.ilike('LOW')).count()
    
    alerts_summary = [
        {'severity': 'High', 'alerts': high_alerts, 'trend': '+ 40%'},
        {'severity': 'Medium', 'alerts': med_alerts, 'trend': '+ 15%'},
        {'severity': 'Low', 'alerts': low_alerts, 'trend': '+ 20%'}
    ]
    
    return jsonify({
        'success': True,
        'summary': {
            'total_queries': total_queries,
            'safe_requests': safe_requests,
            'suspicious_requests': suspicious_requests,
            'blocked_requests': blocked_requests,
            'active_devices': active_devices
        },
        'charts': {
            'labels': labels,
            'queries_over_time': days_data,
            'status_distribution': {
                'safe': safe_requests,
                'suspicious': suspicious_requests,
                'blocked': blocked_requests
            }
        },
        'top_domains': top_domains_list,
        'top_devices': top_devices_list,
        'alerts_summary': alerts_summary
    })

@reports_bp.route('/api/reports/export', methods=['GET'])
def export_reports_csv():
    logs = DNSLog.query.order_by(DNSLog.timestamp.desc()).limit(2000).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Timestamp', 'Client IP', 'Domain', 'Query Type', 'Response IP', 'TTL', 'Status', 'Info'])
    
    for l in logs:
        writer.writerow([
            l.id,
            l.timestamp.strftime('%Y-%m-%d %H:%M:%S') if l.timestamp else '',
            l.client_ip,
            l.query_domain,
            l.query_type,
            l.response_ip or '-',
            l.ttl,
            l.status,
            l.activity_category or 'Standard query'
        ])
        
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=dnswatch_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
    )
