from flask import Blueprint, request, jsonify
from database import db
from models import Device, DNSLog
from services.device_tracker import device_tracker
from datetime import datetime, timedelta

devices_bp = Blueprint('devices', __name__)

@devices_bp.route('/api/devices', methods=['GET'])
def get_devices():
    """
    Returns observed device inventory derived directly from real captured DNS query logs.
    Correctly correlates IPv4 and IPv6 addresses belonging to the same client host without duplicate device entries.
    """
    try:
        search = request.args.get('search', '').strip()
        status_filter = request.args.get('status', '').strip().upper()
        
        local_ips = device_tracker.get_local_system_ips()
        primary_local_ip = device_tracker.get_primary_local_ip()
        
        now = datetime.utcnow()
        active_window = timedelta(minutes=15)
        
        # 1. Query unique client IPs from DNSLog
        unique_ips = db.session.query(
            DNSLog.client_ip,
            db.func.count(DNSLog.id).label('query_count'),
            db.func.max(DNSLog.timestamp).label('last_seen')
        ).filter(
            DNSLog.client_ip.isnot(None),
            DNSLog.client_ip != "Unknown"
        ).group_by(DNSLog.client_ip).all()
        
        # Group entries: local machine IPs are aggregated under primary local IP
        local_total_queries = 0
        local_latest_seen = None
        lan_clients = {}  # ip -> {'count': ..., 'last_seen': ...}
        
        for ip, count, lseen in unique_ips:
            if ip.lower() in local_ips:
                local_total_queries += (count or 0)
                if lseen:
                    if local_latest_seen is None or lseen > local_latest_seen:
                        local_latest_seen = lseen
            else:
                lan_clients[ip] = {
                    'count': count or 0,
                    'last_seen': lseen
                }
                
        # 2. Sync Local Workstation Device
        if local_total_queries > 0 or len(unique_ips) == 0:
            is_active = (local_latest_seen and (now - local_latest_seen) <= active_window)
            stat = "Active" if is_active or local_latest_seen is None else "Inactive"
            
            local_dev = Device.query.filter(
                (Device.client_ip == primary_local_ip) | 
                (Device.device_name.ilike("%Local Workstation%"))
            ).first()
            
            if not local_dev:
                local_dev = Device(
                    client_ip=primary_local_ip,
                    mac_address="-",
                    device_name="Local Workstation (Monitored Host)",
                    device_type="Workstation / PC",
                    dns_queries=local_total_queries,
                    last_seen=local_latest_seen or now,
                    status=stat
                )
                db.session.add(local_dev)
            else:
                local_dev.client_ip = primary_local_ip
                local_dev.dns_queries = local_total_queries
                if local_latest_seen:
                    local_dev.last_seen = local_latest_seen
                local_dev.status = stat
                
        # 3. Sync LAN Client Devices
        for ip, data in lan_clients.items():
            is_active = (data['last_seen'] and (now - data['last_seen']) <= active_window)
            stat = "Active" if is_active else "Inactive"
            
            dev = Device.query.filter_by(client_ip=ip).first()
            if not dev:
                clean_ip = ip.replace(':', '-').replace('.', '-')
                dev_name = f"Host-{clean_ip}"
                dev_type = "Local Host" if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("fe80:") else "Network Client"
                
                dev = Device(
                    client_ip=ip,
                    mac_address="-",
                    device_name=dev_name,
                    device_type=dev_type,
                    dns_queries=data['count'],
                    last_seen=data['last_seen'] or now,
                    status=stat
                )
                db.session.add(dev)
            else:
                dev.dns_queries = data['count']
                if data['last_seen']:
                    dev.last_seen = data['last_seen']
                # Don't downgrade status if it's already Active from portal session
                if dev.status != "Active":
                    dev.status = stat

        # 4. Sync WebPortalSessions into Device table
        from models import WebPortalSession
        try:
            portal_sessions = WebPortalSession.query.filter(
                WebPortalSession.ip_address.isnot(None),
                WebPortalSession.ip_address != ""
            ).order_by(WebPortalSession.last_heartbeat.desc()).all()

            seen_p_ips = set()
            for ps in portal_sessions:
                if ps.ip_address in seen_p_ips:
                    continue
                seen_p_ips.add(ps.ip_address)
                
                is_p_active = bool(ps.is_active and ps.last_heartbeat and (now - ps.last_heartbeat) <= timedelta(minutes=5))
                p_dev = Device.query.filter_by(client_ip=ps.ip_address).first()
                if not p_dev:
                    os_label = "Browser / Web Portal"
                    ua = (ps.user_agent or '').lower()
                    if 'windows' in ua: os_label = 'Windows'
                    elif 'android' in ua: os_label = 'Android'
                    elif 'iphone' in ua or 'ipad' in ua or 'ios' in ua: os_label = 'iOS'
                    elif 'mac' in ua: os_label = 'macOS'
                    elif 'linux' in ua: os_label = 'Linux'
                    
                    p_dev = Device(
                        client_ip=ps.ip_address,
                        mac_address="-",
                        device_name=f"Portal-{ps.username or 'Visitor'} ({os_label})",
                        device_type=f"Web Portal Visitor ({os_label})",
                        dns_queries=0,
                        last_seen=ps.last_heartbeat or now,
                        status="Active" if is_p_active else "Inactive"
                    )
                    db.session.add(p_dev)
                elif is_p_active:
                    p_dev.status = "Active"
                    if ps.last_heartbeat:
                        p_dev.last_seen = ps.last_heartbeat
        except Exception as p_err:
            print(f"[Devices] Portal sync note: {p_err}")
                
        db.session.commit()
        
        # 4. Return filtered devices list
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
