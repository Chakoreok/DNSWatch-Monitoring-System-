from flask import Blueprint, request, jsonify
from database import db
from models import DNSLog
from services.sniffer import sniffer_service
from datetime import datetime, date

dns_bp = Blueprint('dns', __name__)

@dns_bp.route('/api/dns/recent', methods=['GET'])
def get_recent_dns():
    limit = min(int(request.args.get('limit', 10)), 100)
    
    # Check live circular buffer first
    live_buffer = list(sniffer_service.live_logs_buffer)
    if live_buffer:
        return jsonify({
            'success': True,
            'logs': live_buffer[:limit]
        })
        
    # Fallback to database
    logs = DNSLog.query.order_by(DNSLog.timestamp.desc()).limit(limit).all()
    return jsonify({
        'success': True,
        'logs': [log.to_dict() for log in logs]
    })

@dns_bp.route('/api/dns/logs', methods=['GET'])
def get_dns_logs():
    page = max(int(request.args.get('page', 1)), 1)
    per_page = min(max(int(request.args.get('per_page', 10)), 5), 100)
    
    query_str = request.args.get('search', '').strip()
    status_filter = request.args.get('status', '').strip().upper()
    query_type_filter = request.args.get('query_type', '').strip().upper()
    date_filter = request.args.get('date', '').strip()
    
    query = DNSLog.query
    
    if query_str:
        search_pattern = f"%{query_str}%"
        query = query.filter(
            (DNSLog.query_domain.ilike(search_pattern)) | 
            (DNSLog.client_ip.ilike(search_pattern)) |
            (DNSLog.response_ip.ilike(search_pattern)) |
            (DNSLog.activity_category.ilike(search_pattern))
        )
        
    if status_filter and status_filter != 'ALL':
        query = query.filter(DNSLog.status == status_filter)
        
    if query_type_filter and query_type_filter != 'ALL':
        query = query.filter(DNSLog.query_type == query_type_filter)
        
    if date_filter:
        try:
            target_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
            query = query.filter(db.func.date(DNSLog.timestamp) == target_date)
        except Exception:
            pass
            
    total = query.count()
    logs_page = query.order_by(DNSLog.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'success': True,
        'logs': [l.to_dict() for l in logs_page.items],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': logs_page.pages or 1
        }
    })

@dns_bp.route('/api/dns/stats', methods=['GET'])
def get_dns_stats():
    total_queries = DNSLog.query.count()
    suspicious_count = DNSLog.query.filter_by(status='SUSPICIOUS').count()
    blocked_count = DNSLog.query.filter_by(status='BLOCKED').count()
    safe_count = DNSLog.query.filter_by(status='SAFE').count()
    
    # If sniffer is currently active, take current max between in-memory and db
    mon_status = sniffer_service.get_status()
    if mon_status['is_running']:
        total_queries = max(total_queries, mon_status['total_queries'])
        suspicious_count = max(suspicious_count, mon_status['suspicious_queries'])
        blocked_count = max(blocked_count, mon_status['blocked_queries'])
        safe_count = max(safe_count, mon_status['safe_queries'])
        
    return jsonify({
        'success': True,
        'total_queries': total_queries,
        'safe_queries': safe_count,
        'suspicious_queries': suspicious_count,
        'blocked_queries': blocked_count
    })
