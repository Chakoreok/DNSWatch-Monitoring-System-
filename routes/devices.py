from flask import Blueprint, request, jsonify
from database import db
from models import Device, DNSLog
from datetime import datetime, timedelta

devices_bp = Blueprint('devices', __name__)

@devices_bp.route('/api/devices', methods=['GET'])
def get_devices():
    """
    Returns observed device inventory derived directly from real captured DNS query logs.
    No fabricated MAC addresses or fake device records.
    """
    try:
        search = request.args.get('search', '').strip()
        status_filter = request.args.get('status', '').strip().upper()
        
        # 1. Ensure all unique client IPs present in dns_logs exist in the devices table
        unique_ips = db.session.query(
            DNSLog.client_ip,
            db.func.count(DNSLog.id).label('query_count'),
            db.func.max(DNSLog.timestamp).label('last_seen')
        ).filter(
            DNSLog.client_ip.isnot(None),
            ~DNSLog.client_ip.in_(["Unknown", "127.0.0.1", "::1"])
        ).group_by(DNSLog.client_ip).all()
        
        now = datetime.now()
        active_window = timedelta(minutes=15)
        
        existing_devices = {d.client_ip: d for d in Device.query.all()}
        
        for ip, count, lseen in unique_ips:
            is_active = (lseen and (now - lseen) <= active_window)
            stat = "Active" if is_active else "Inactive"
            
            if ip in existing_devices:
                dev = existing_devices[ip]
                dev.dns_queries = count or 0
                dev.last_seen = lseen
                dev.status = stat
            else:
                clean_ip = ip.replace(':', '-').replace('.', '-')
                dev_name = f"Host-{clean_ip}"
                dev_type = "Local Host" if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("fe80:") else "Network Client"
                
                dev = Device(
                    client_ip=ip,
                    mac_address="-",
                    device_name=dev_name,
                    device_type=dev_type,
                    dns_queries=count or 0,
                    last_seen=lseen or now,
                    status=stat
                )
                db.session.add(dev)
                existing_devices[ip] = dev
                
        db.session.commit()
        
        # 2. Query devices with optional filters
        query = Device.query
        if search:
            query = query.filter(
                (Device.client_ip.ilike(f"%{search}%")) |
                (Device.device_name.ilike(f"%{search}%")) |
                (Device.device_type.ilike(f"%{search}%"))
            )
        if status_filter and status_filter != 'ALL':
            query = query.filter(Device.status == status_filter)
            
        devices = query.order_by(Device.last_seen.desc()).all()
        
        total_devices = Device.query.count()
        active_devices = Device.query.filter_by(status='Active').count()
        inactive_devices = Device.query.filter_by(status='Inactive').count()
        total_queries = DNSLog.query.count()
        
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

@devices_bp.route('/api/devices/<int:id>', methods=['PUT'])
def update_device(id):
    """Allows updating device custom name or type."""
    dev = Device.query.get_or_404(id)
    data = request.get_json() or {}
    
    if 'device_name' in data:
        dev.device_name = data['device_name'].strip()
    if 'device_type' in data:
        dev.device_type = data['device_type'].strip()
        
    db.session.commit()
    return jsonify({'success': True, 'device': dev.to_dict()})
