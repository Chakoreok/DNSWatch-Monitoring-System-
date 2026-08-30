import csv
import io
from flask import Blueprint, request, jsonify, Response
from database import db
from models import DNSLog, SecurityAlert, Device
from datetime import datetime, timedelta

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/api/reports/summary', methods=['GET'])
def get_reports_summary():
    """
    Returns analytics and metrics calculated directly from MySQL dns_logs and security_alerts.
    Dynamically generates time-series for today (hourly) or multi-day (daily).
    """
    device_filter = request.args.get('device', '').strip()
    status_filter = request.args.get('status', '').strip().upper()
    date_from_str = request.args.get('date_from', '').strip()
    date_to_str = request.args.get('date_to', '').strip()
    
    # 1. Base log query with dynamic filtering
    log_query = DNSLog.query
    alert_query = SecurityAlert.query
    
    if device_filter and device_filter != 'ALL':
        log_query = log_query.filter(DNSLog.client_ip == device_filter)
        alert_query = alert_query.filter(SecurityAlert.client_ip == device_filter)
        
    if status_filter and status_filter != 'ALL':
        log_query = log_query.filter(DNSLog.status == status_filter)
        
    now = datetime.now()
    today_date = now.date()
    
    start_date = None
    end_date = None
    
    if date_from_str:
        try:
            start_date = datetime.strptime(date_from_str, '%Y-%m-%d').date()
            log_query = log_query.filter(db.func.date(DNSLog.timestamp) >= start_date)
            alert_query = alert_query.filter(db.func.date(SecurityAlert.timestamp) >= start_date)
        except Exception:
            pass
            
    if date_to_str:
        try:
            end_date = datetime.strptime(date_to_str, '%Y-%m-%d').date()
            log_query = log_query.filter(db.func.date(DNSLog.timestamp) <= end_date)
            alert_query = alert_query.filter(db.func.date(SecurityAlert.timestamp) <= end_date)
        except Exception:
            pass

    # 2. Metric Calculations
    total_queries = log_query.count()
    safe_requests = log_query.filter(DNSLog.status == 'SAFE').count()
    suspicious_requests = log_query.filter(DNSLog.status == 'SUSPICIOUS').count()
    blocked_requests = log_query.filter(DNSLog.status == 'BLOCKED').count()
    
    active_window = timedelta(minutes=15)
    active_devices = Device.query.filter(
        Device.last_seen >= (now - active_window),
        Device.status == 'Active'
    ).count()
    
    # Fallback to total devices if no recent active window
    if active_devices == 0:
        active_devices = Device.query.filter_by(status='Active').count()
        
    # 3. Time Series Data Calculation
    # Determine whether to group by Hour (if 1 day range / today) or Day (multi-day)
    is_single_day = False
    if start_date and end_date and start_date == end_date:
        is_single_day = True
    elif not start_date and not end_date:
        # Default view: past 7 days
        pass
        
    labels = []
    queries_data = []
    
    if is_single_day or (start_date == today_date and not end_date):
        # Hourly breakdown for today (24 hours)
        target_d = start_date or today_date
        for hour in range(24):
            hour_label = f"{hour:02d}:00"
            labels.append(hour_label)
            
            # Count queries for this specific date and hour
            cnt = log_query.filter(
                db.func.date(DNSLog.timestamp) == target_d,
                db.func.hour(DNSLog.timestamp) == hour
            ).count()
            queries_data.append(cnt)
    else:
        # Multi-day breakdown (default: last 7 days)
        range_end = end_date or today_date
        range_start = start_date or (range_end - timedelta(days=6))
        
        # Calculate days delta (cap at 30 for chart clarity)
        delta_days = (range_end - range_start).days
        if delta_days < 0:
            delta_days = 6
            range_start = range_end - timedelta(days=6)
        elif delta_days > 30:
            delta_days = 30
            range_start = range_end - timedelta(days=30)
            
        for i in range(delta_days, -1, -1):
            d = range_end - timedelta(days=i)
            labels.append(d.strftime('%b %d'))
            
            cnt = log_query.filter(db.func.date(DNSLog.timestamp) == d).count()
            queries_data.append(cnt)
            
    # 4. Top Queried Domains
    top_domains_query = db.session.query(
        DNSLog.query_domain,
        db.func.count(DNSLog.id).label('queries')
    )
    if device_filter and device_filter != 'ALL':
        top_domains_query = top_domains_query.filter(DNSLog.client_ip == device_filter)
    if status_filter and status_filter != 'ALL':
        top_domains_query = top_domains_query.filter(DNSLog.status == status_filter)
    if start_date:
        top_domains_query = top_domains_query.filter(db.func.date(DNSLog.timestamp) >= start_date)
    if end_date:
        top_domains_query = top_domains_query.filter(db.func.date(DNSLog.timestamp) <= end_date)
        
    top_domains = top_domains_query.group_by(DNSLog.query_domain).order_by(db.desc('queries')).limit(5).all()
    top_domains_list = [{'domain': d[0], 'queries': d[1]} for d in top_domains]
    
    # 5. Top Devices by Query Count
    devices_by_ip = {d.client_ip: d.device_name for d in Device.query.all()}
    
    top_devices_query = db.session.query(
        DNSLog.client_ip,
        db.func.count(DNSLog.id).label('queries')
    )
    if status_filter and status_filter != 'ALL':
        top_devices_query = top_devices_query.filter(DNSLog.status == status_filter)
    if start_date:
        top_devices_query = top_devices_query.filter(db.func.date(DNSLog.timestamp) >= start_date)
    if end_date:
        top_devices_query = top_devices_query.filter(db.func.date(DNSLog.timestamp) <= end_date)
        
    top_devices = top_devices_query.group_by(DNSLog.client_ip).order_by(db.desc('queries')).limit(5).all()
    top_devices_list = []
    for dev_ip, count in top_devices:
        dev_name = devices_by_ip.get(dev_ip, f"Host-{dev_ip.replace(':', '-').replace('.', '-')}")
        top_devices_list.append({
            'ip_address': dev_ip,
            'queries': count,
            'device_name': dev_name
        })
        
    # 6. Real Security Alerts Breakdown
    high_alerts = alert_query.filter(SecurityAlert.severity.ilike('HIGH')).count()
    med_alerts = alert_query.filter(SecurityAlert.severity.ilike('MEDIUM')).count()
    low_alerts = alert_query.filter(SecurityAlert.severity.ilike('LOW')).count()
    total_alerts = high_alerts + med_alerts + low_alerts
    
    def get_pct_str(cnt):
        if total_alerts == 0:
            return "0%"
        return f"{round((cnt / total_alerts) * 100, 1)}%"
        
    alerts_summary = [
        {'severity': 'High', 'alerts': high_alerts, 'trend': get_pct_str(high_alerts)},
        {'severity': 'Medium', 'alerts': med_alerts, 'trend': get_pct_str(med_alerts)},
        {'severity': 'Low', 'alerts': low_alerts, 'trend': get_pct_str(low_alerts)}
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
            'queries_over_time': queries_data,
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
    """Exports actual filtered DNSLog records to CSV."""
    device_filter = request.args.get('device', '').strip()
    status_filter = request.args.get('status', '').strip().upper()
    date_from_str = request.args.get('date_from', '').strip()
    date_to_str = request.args.get('date_to', '').strip()
    
    query = DNSLog.query
    if device_filter and device_filter != 'ALL':
        query = query.filter(DNSLog.client_ip == device_filter)
    if status_filter and status_filter != 'ALL':
        query = query.filter(DNSLog.status == status_filter)
    if date_from_str:
        try:
            query = query.filter(db.func.date(DNSLog.timestamp) >= datetime.strptime(date_from_str, '%Y-%m-%d').date())
        except Exception:
            pass
    if date_to_str:
        try:
            query = query.filter(db.func.date(DNSLog.timestamp) <= datetime.strptime(date_to_str, '%Y-%m-%d').date())
        except Exception:
            pass
            
    logs = query.order_by(DNSLog.timestamp.desc()).limit(5000).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Timestamp', 'Client IP', 'Domain', 'Query Type', 'Response IP', 'TTL', 'Status', 'Detection Info'])
    
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
            l.detection_reason or l.activity_category or 'Standard query'
        ])
        
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=dnswatch_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
    )
