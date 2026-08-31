import socket
import threading
from datetime import datetime, timedelta
from scapy.all import conf
from database import db
from models import Device

class DeviceTracker:
    def __init__(self):
        self._lock = threading.RLock()
        self.device_cache = {}  # device_key -> dict
        self._local_ips_cache = set()
        self._last_local_ips_refresh = 0
        
    def get_local_system_ips(self):
        """Returns set of all IPv4 and IPv6 addresses assigned to this local machine."""
        now = datetime.now().timestamp()
        if self._local_ips_cache and (now - self._last_local_ips_refresh) < 60:
            return self._local_ips_cache
            
        ips = {'127.0.0.1', '::1'}
        try:
            for iface in conf.ifaces.values():
                ip = getattr(iface, 'ip', '') or ''
                if ip:
                    ips.add(ip.lower())
                    
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None):
                addr = info[4][0]
                if addr:
                    ips.add(addr.lower().split('%')[0])
        except Exception:
            pass
            
        self._local_ips_cache = ips
        self._last_local_ips_refresh = now
        return ips

    def get_primary_local_ip(self):
        """Returns the primary non-loopback IPv4 address of the local workstation."""
        for iface in conf.ifaces.values():
            ip = getattr(iface, 'ip', '') or ''
            desc = (getattr(iface, 'description', '') or '').lower()
            name = (getattr(iface, 'name', '') or '').lower()
            if ip and not ip.startswith('127.') and not ip.startswith('169.254.') and 'virtualbox' not in desc and 'virtualbox' not in name:
                return ip
        for iface in conf.ifaces.values():
            ip = getattr(iface, 'ip', '') or ''
            if ip and not ip.startswith('127.') and not ip.startswith('169.254.'):
                return ip
        return "127.0.0.1"

    def record_device_activity(self, client_ip, query_time=None, client_mac=None):
        """Records DNS query from client IP in local cache, mapping IPv4/IPv6 of same host together."""
        if not client_ip or client_ip == "Unknown":
            return
            
        now = query_time or datetime.now()
        local_ips = self.get_local_system_ips()
        
        # Check if this query is from the local monitoring workstation
        is_local_host = client_ip.lower() in local_ips
        
        if is_local_host:
            primary_ip = self.get_primary_local_ip()
            dev_key = f"LOCAL_{primary_ip}"
            ip_to_store = primary_ip
            dev_name = "Local Workstation (Monitored Host)"
            dev_type = "Workstation / PC"
            mac_to_store = client_mac or "-"
        elif client_mac and client_mac != "-":
            dev_key = f"MAC_{client_mac.lower()}"
            ip_to_store = client_ip
            clean_ip = client_ip.replace(':', '-').replace('.', '-')
            dev_name = f"Client-{clean_ip}"
            dev_type = "Network Client"
            mac_to_store = client_mac.lower()
        else:
            dev_key = f"IP_{client_ip.lower()}"
            ip_to_store = client_ip
            clean_ip = client_ip.replace(':', '-').replace('.', '-')
            dev_name = f"Host-{clean_ip}"
            dev_type = "Network Client"
            mac_to_store = "-"

        with self._lock:
            if dev_key not in self.device_cache:
                self.device_cache[dev_key] = {
                    'client_ip': ip_to_store,
                    'device_name': dev_name,
                    'device_type': dev_type,
                    'mac_address': mac_to_store,
                    'query_count': 1,
                    'last_seen': now
                }
            else:
                self.device_cache[dev_key]['query_count'] += 1
                self.device_cache[dev_key]['last_seen'] = now
                if mac_to_store != "-" and self.device_cache[dev_key]['mac_address'] == "-":
                    self.device_cache[dev_key]['mac_address'] = mac_to_store

    def flush_devices_to_db(self, app):
        """Flushes in-memory device counts to MySQL database."""
        with app.app_context():
            with self._lock:
                for dev_key, data in list(self.device_cache.items()):
                    try:
                        ip = data['client_ip']
                        mac = data['mac_address']
                        
                        # Find existing device by MAC or IP
                        dev = None
                        if mac and mac != "-":
                            dev = Device.query.filter_by(mac_address=mac).first()
                        if not dev:
                            dev = Device.query.filter_by(client_ip=ip).first()
                            
                        if not dev:
                            dev = Device(
                                client_ip=ip,
                                mac_address=mac,
                                device_name=data['device_name'],
                                device_type=data['device_type'],
                                dns_queries=data['query_count'],
                                last_seen=data['last_seen'],
                                status="Active"
                            )
                            db.session.add(dev)
                        else:
                            dev.dns_queries += data['query_count']
                            dev.last_seen = data['last_seen']
                            dev.status = "Active"
                            if mac != "-" and (not dev.mac_address or dev.mac_address == "-"):
                                dev.mac_address = mac
                                
                        db.session.commit()
                        self.device_cache[dev_key]['query_count'] = 0
                    except Exception as e:
                        db.session.rollback()
                        print(f"[DeviceTracker] Error updating device {dev_key}: {e}")

device_tracker = DeviceTracker()
