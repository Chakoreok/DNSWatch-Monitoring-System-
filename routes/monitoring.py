from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from database import db
from models import DNSLog, SecurityAlert, Device, WebsiteActivity, MonitoringSession
from services.sniffer import sniffer_service

monitoring_bp = Blueprint('monitoring', __name__)

@monitoring_bp.route('/api/monitoring/status', methods=['GET'])
def get_monitoring_status():
    status = sniffer_service.get_status()
    return jsonify({
        'success': True,
        'monitoring': status
    })

@monitoring_bp.route('/api/monitoring/start', methods=['POST'])
def start_monitoring():
    data = request.get_json() or {}
    interface = data.get('interface', None)
    user_id = current_user.id if current_user.is_authenticated else None
    
    success, msg = sniffer_service.start_monitoring(interface=interface, user_id=user_id)
    status = sniffer_service.get_status()
    
    return jsonify({
        'success': success,
        'message': msg,
        'monitoring': status
    }), (200 if success else 400)

@monitoring_bp.route('/api/monitoring/stop', methods=['POST'])
def stop_monitoring():
    success, msg = sniffer_service.stop_monitoring()
    status = sniffer_service.get_status()
    
    return jsonify({
        'success': success,
        'message': msg,
        'monitoring': status
    }), (200 if success else 400)

@monitoring_bp.route('/api/monitoring/clear', methods=['POST'])
def clear_all_data():
    """Wipes all historical sample DNS logs, security alerts, devices, and website activity."""
    try:
        # Clear database records
        db.session.query(SecurityAlert).delete()
        db.session.query(DNSLog).delete()
        db.session.query(Device).delete()
        db.session.query(WebsiteActivity).delete()
        db.session.query(MonitoringSession).delete()
        db.session.commit()
        
        # Reset in-memory buffers & counters
        sniffer_service.reset_in_memory_metrics()
        
        return jsonify({
            'success': True,
            'message': 'All sample logs, alerts, devices, and activity history have been completely cleared.'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@monitoring_bp.route('/api/monitoring/interfaces', methods=['GET'])
def get_interfaces():
    interfaces = sniffer_service.get_available_interfaces()
    return jsonify({
        'success': True,
        'interfaces': interfaces
    })

@monitoring_bp.route('/api/monitoring/simulate', methods=['POST'])
def simulate_traffic():
    """Testing helper endpoint to send test query through exact detection pipeline."""
    data = request.get_json() or {}
    client_ip = data.get('client_ip', '192.168.254.108')
    domain = data.get('domain', 'google.com')
    query_type = data.get('query_type', 'A')
    response_ip = data.get('response_ip', '142.250.190.78')
    
    status, alert = sniffer_service.ingest_simulated_packet(client_ip, domain, query_type, response_ip)
    
    return jsonify({
        'success': True,
        'domain': domain,
        'client_ip': client_ip,
        'status': status,
        'alert': alert
    })
