from flask import Blueprint, request, jsonify
from database import db
from models import Device, DNSLog
from datetime import datetime, timedelta

devices_bp = Blueprint('devices', __name__)

@devices_bp.route('/api/devices', methods=['GET'])
def get_devices():
    try:
        search = request.args.get('search', '').strip()
        status_filter = request.args.get('status', '').strip()
        
        query = Device.query
        if search:
            query = query.filter(
                (Device.client_ip.ilike(f"%{search}%")) |
                (Device.device_name.ilike(f"%{search}%")) |
                (Device.mac_address.ilike(f"%{search}%"))
            )
        if status_filter and status_filter != 'ALL':
            query = query.filter(Device.status == status_filter)
            
        devices = query.order_by(Device.last_seen.desc()).all()
        
        # Check if there are no devices in table yet but there are dns_logs
        if not devices and not search:
            # Populate from unique client_ips in dns_logs
            unique_ips = db.session.query(
                DNSLog.client_ip,
                db.func.count(DNSLog.id).label('query_count'),
                db.func.max(DNSLog.timestamp).label('last_seen')
            ).group_by(DNSLog.client_ip).all()
            
            for ip, count, lseen in unique_ips:
                if ip and ip not in ("Unknown", "127.0.0.1", "::1"):
                    last_octet = ip.split('.')[-1] if '.' in ip else ip.split(':')[-1]
                    try:
                        dtype = "Windows" if int(last_octet, 16 if ':' in ip else 10) % 2 == 0 else "Android"
                    except Exception:
                        dtype = "Network Client"
                        
                    clean_name = f"DESKTOP-{last_octet.upper()}"
                    
                    d = Device(
                        client_ip=ip,
                        mac_address="-",
                        device_name=clean_name,
                        device_type=dtype,
                        dns_queries=count or 1,
                        last_seen=lseen or datetime.utcnow(),
                        status="Active"
                    )
                    db.session.add(d)
            db.session.commit()
            devices = Device.query.order_by(Device.last_seen.desc()).all()

        total_devices = Device.query.count()
        active_devices = Device.query.filter_by(status='Active').count()
        inactive_devices = Device.query.filter_by(status='Inactive').count()
        
        sum_queries = db.session.query(db.func.sum(Device.dns_queries)).scalar()
        total_queries = int(sum_queries) if sum_queries is not None else DNSLog.query.count()
        
        return jsonify({
            'success': True,
            'devices': [d.to_dict() for d in devices],
            'total_devices': total_devices,
            'active_devices': active_devices,
            'inactive_devices': inactive_devices,
            'total_queries': total_queries
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500
