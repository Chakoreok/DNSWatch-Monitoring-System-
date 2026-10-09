from flask import Blueprint, request, jsonify
from database import db
from models import DNSLog
from services.sniffer import sniffer_service
from datetime import datetime

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

from sqlalchemy import func
import time

_stats_cache = {'timestamp': 0, 'data': None}

@dns_bp.route('/api/dns/stats', methods=['GET'])
def get_dns_stats():
    now = time.time()
    if _stats_cache['data'] and (now - _stats_cache['timestamp'] < 3.0):
        return jsonify(_stats_cache['data'])

    try:
        counts = dict(db.session.query(DNSLog.status, func.count(DNSLog.id)).group_by(DNSLog.status).all())
    except Exception:
        counts = {}

    total_queries = sum(counts.values())
    suspicious_count = counts.get('SUSPICIOUS', 0)
    blocked_count = counts.get('BLOCKED', 0)
    safe_count = counts.get('SAFE', 0)

    # If sniffer is currently active, take current max between in-memory and db
    mon_status = sniffer_service.get_status()
    if mon_status.get('is_running'):
        total_queries = max(total_queries, mon_status.get('total_queries', 0))
        suspicious_count = max(suspicious_count, mon_status.get('suspicious_queries', 0))
        blocked_count = max(blocked_count, mon_status.get('blocked_queries', 0))
        safe_count = max(safe_count, mon_status.get('safe_queries', 0))

    payload = {
        'success': True,
        'total_queries': total_queries,
        'safe_queries': safe_count,
        'suspicious_queries': suspicious_count,
        'blocked_queries': blocked_count
    }
    _stats_cache['timestamp'] = now
    _stats_cache['data'] = payload
    return jsonify(payload)
