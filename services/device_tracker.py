import threading
from datetime import datetime
from database import db
from models import Device

class DeviceTracker:
    def __init__(self):
        self._lock = threading.RLock()
        self.device_cache = {}  # ip -> dict
        
    def record_device_activity(self, client_ip, query_time=None):
        """Records DNS query from client IP in local cache."""
        if not client_ip or client_ip in ("Unknown", "127.0.0.1", "::1"):
            return
            
        now = query_time or datetime.utcnow()
        with self._lock:
            if client_ip not in self.device_cache:
                self.device_cache[client_ip] = {
                    'query_count': 1,
                    'last_seen': now
                }
            else:
                self.device_cache[client_ip]['query_count'] += 1
                self.device_cache[client_ip]['last_seen'] = now

    def flush_devices_to_db(self, app):
        """Flushes in-memory device counts to MySQL database."""
        with app.app_context():
            with self._lock:
                for ip, data in list(self.device_cache.items()):
                    try:
                        dev = Device.query.filter_by(client_ip=ip).first()
                        if not dev:
                            dev = Device(
                                client_ip=ip,
                                mac_address="-",
                                device_name=f"Host-{ip.replace('.', '-')}",
                                device_type="Network Client",
                                dns_queries=data['query_count'],
                                last_seen=data['last_seen'],
                                status="Active"
                            )
                            db.session.add(dev)
                        else:
                            dev.dns_queries += data['query_count']
                            dev.last_seen = data['last_seen']
                            dev.status = "Active"
                        db.session.commit()
                        # Reset cache counter after flush
                        self.device_cache[ip]['query_count'] = 0
                    except Exception as e:
                        db.session.rollback()
                        print(f"[DeviceTracker] Error updating device {ip}: {e}")

device_tracker = DeviceTracker()
